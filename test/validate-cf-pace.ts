// Prove the Cloudflare account-API rate-limit handling: withRetry now honours a server Retry-After and
// classifies a 429/5xx in BOTH error vocabularies ("status NNN" and "HTTP NNN") as transient, and the
// CfPacer token bucket throttles a crawl below the account limit. In-memory only, no network. Run:
//   node test/validate-cf-pace.ts

import { withRetry, isTransient, parseRetryAfter, retryAfterMsOf, rateLimitError, API_READ_RETRY } from "../src/seal/retry.ts";
import { CfPacer, pacerFromEnv, DEFAULT_CF_API_RATE_PER_SEC } from "../src/cf-pace.ts";
import { makeCfApi } from "../src/sources/cf-config-surfaces.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  console.log("parseRetryAfter (delta-seconds + HTTP-date + invalid):");
  ok("delta-seconds '120' -> 120000ms", parseRetryAfter("120") === 120000);
  ok("'0' -> 0ms (retry now)", parseRetryAfter("0") === 0);
  ok("empty/null/garbage -> null", parseRetryAfter("") === null && parseRetryAfter(null) === null && parseRetryAfter("not-a-date") === null);
  {
    // An HTTP-date a known delta in the future parses to roughly that delta (allow scheduling slop).
    const ms = parseRetryAfter(new Date(Date.now() + 30_000).toUTCString());
    ok("HTTP-date ~30s in the future -> ~30000ms", ms !== null && ms > 25_000 && ms <= 31_000);
    ok("HTTP-date in the PAST clamps to 0 (never negative)", parseRetryAfter(new Date(Date.now() - 60_000).toUTCString()) === 0);
  }

  console.log("\nrateLimitError carries Retry-After; retryAfterMsOf reads it:");
  ok("rateLimitError(msg, 5000) carries retryAfterMs", retryAfterMsOf(rateLimitError("Cloudflare API GET /x: HTTP 429", 5000)) === 5000);
  ok("rateLimitError(msg, null) carries no retryAfterMs", retryAfterMsOf(rateLimitError("Cloudflare API GET /x: HTTP 429", null)) === null);
  ok("retryAfterMsOf on a plain error is null", retryAfterMsOf(new Error("nope")) === null);

  console.log("\nisTransient classifies a 429/5xx in BOTH vocabularies + the Retry-After marker:");
  ok("dest form 'status 503' is transient", isTransient(new Error("PUT k failed: status 503")));
  ok("CF-API form 'HTTP 429' is transient (was NOT before the fix)", isTransient(new Error("Cloudflare API GET /x: HTTP 429")));
  ok("CF-API form 'HTTP 500' is transient", isTransient(new Error("Cloudflare API GET /x: HTTP 500")));
  ok("a rateLimitError is always transient (carries Retry-After)", isTransient(rateLimitError("Cloudflare API GET /x: HTTP 429", 1000)));
  ok("a 4xx that is NOT 429 is NOT transient (e.g. 403)", !isTransient(new Error("Cloudflare API GET /x: HTTP 403")));
  ok("dest form 'status 400' is NOT transient", !isTransient(new Error("PUT k failed: status 400")));
  ok("CF-API form 'HTTP 404' is NOT transient", !isTransient(new Error("Cloudflare API GET /x: HTTP 404")));
  ok("a 2xx code is NOT transient (e.g. HTTP 200)", !isTransient(new Error("Cloudflare API GET /x: HTTP 200")));
  ok("a validation error is NOT transient", !isTransient(new Error("the Workers scripts source needs an accountId")));

  console.log("\nwithRetry: retries transient (incl. 429 with Retry-After:0 so no real sleep), throws non-transient at once:");
  {
    let calls = 0;
    const v = await withRetry(async () => {
      calls++;
      if (calls < 3) throw rateLimitError("Cloudflare API GET /x: HTTP 429", 0); // 0ms => retries without sleeping
      return "done";
    }, { attempts: 5, baseMs: 0 });
    ok("a 429 (Retry-After:0) is retried then succeeds", v === "done" && calls === 3);
  }
  {
    let calls = 0;
    let threw = false;
    try {
      await withRetry(async () => {
        calls++;
        throw new Error("Cloudflare API GET /x: HTTP 403"); // not transient
      }, { attempts: 5, baseMs: 0 });
    } catch {
      threw = true;
    }
    ok("a non-transient error throws immediately (one call, no retry)", threw && calls === 1);
  }
  ok("API_READ_RETRY is deeper than the default (>=6 attempts)", API_READ_RETRY.attempts >= 6 && API_READ_RETRY.baseMs >= 250);

  console.log("\nCfPacer token bucket: burst is free, then it paces:");
  {
    // A burst-sized run of take() resolves promptly (tokens available); none throws.
    const pacer = new CfPacer({ ratePerSec: 1000, burst: 5 });
    const t0 = Date.now();
    for (let i = 0; i < 5; i++) await pacer.take();
    // Upper bound is generous (500ms) so a heavily loaded CI host does not flake; a real
    // failure (the burst being paced) would still blow well past this.
    ok("burst of 5 take() within burst is prompt (<500ms)", Date.now() - t0 < 500);
  }
  {
    // With a 1-token burst at a slow rate, the 2nd take() must wait for a refill (measurably delayed).
    const pacer = new CfPacer({ ratePerSec: 20, burst: 1 }); // 20/s => ~50ms per token
    await pacer.take(); // consumes the single burst token
    const t0 = Date.now();
    await pacer.take(); // must wait for a refill
    ok("a second take() past the burst waits for a refill (>=25ms)", Date.now() - t0 >= 25);
  }
  ok("pacerFromEnv falls back to the default on an absent/invalid knob", pacerFromEnv({}) instanceof CfPacer && pacerFromEnv({ CF_API_RATE_PER_SEC: "nonsense" }) instanceof CfPacer);
  ok("pacerFromEnv accepts a valid knob", pacerFromEnv({ CF_API_RATE_PER_SEC: "2" }) instanceof CfPacer);
  ok("DEFAULT_CF_API_RATE_PER_SEC is conservative (<= 4/s, under the account ~1200/5min)", DEFAULT_CF_API_RATE_PER_SEC <= 4);

  console.log("\nmakeCfApi(token, fetch, pacer): a media metadata client both PACES a burst and still does a working get():");
  {
    // The Stream/Images/Artifacts metadata clients are built by mediaMetadataApi via
    // makeCfApi(token, fetch, pacerFromEnv(env)) with ALL THREE positional args. Reproduce that exact
    // construction here with a stub fetch and a slow 1-burst pacer to catch a mis-positioned arg: if the
    // pacer ever landed in the fetchImpl slot, get() would not pace AND would not return the result.
    let fetchCalls = 0;
    const stubFetch = (async (_url: string | URL | Request, _init?: RequestInit) => {
      fetchCalls++;
      return new Response(JSON.stringify({ success: true, result: { id: "vid-1", status: "ready" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    const pacer = new CfPacer({ ratePerSec: 5, burst: 1 }); // 5/s => ~200ms per token, 1-token burst
    const api = makeCfApi("tok", stubFetch, pacer);

    // (a) Working get(): the result is unwrapped from the Cloudflare envelope (proves fetch is in the
    // fetch slot and is actually invoked).
    const first = (await api.get("/accounts/a/stream/vid-1")) as { id?: string; status?: string } | null;
    ok("media client get() returns the unwrapped result (fetch in the fetch slot)", first?.id === "vid-1" && first?.status === "ready");
    ok("media client get() actually called the fetch impl", fetchCalls === 1);

    // (b) Paces a burst: the single burst token is gone, so the next get() must wait for a refill.
    //
    // THE BUCKET REFILLS ON WALL CLOCK, so every millisecond between (a) taking the burst token and t0
    // being read is a millisecond of refill. Draining the burst token immediately before reading the
    // clock closes that window to microseconds, so a LOWER bound of 50ms against an expected 200ms wait
    // stays deterministic without weakening the bound or needing a clock seam in production code.
    await pacer.take();
    const t0 = Date.now();
    await api.get("/accounts/a/stream/vid-1");
    ok("a second media client get() past the burst is paced (>=50ms refill wait)", Date.now() - t0 >= 50);
    ok("the paced second get() still completed via fetch", fetchCalls === 2);
  }

  // The RESTORE legs must be paced too, not just the backup crawl.
  //
  // Structural, because the alternative is standing up a whole restore to observe a delay. It pins the
  // actual CALL rather than a mention of it: "accountPacer(env)" also appears in the comment above those
  // lines explaining why they exist, so the check must confirm the pacer is actually passed into the
  // factory call, not merely mentioned nearby.
  {
    const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("../src/admin/restore.ts", import.meta.url), "utf8"));
    console.log("\n-- the restore legs are paced --");
    ok(
      "the default cf-config API factory is built WITH a pacer",
      /makeCfApi\(\s*token\s*,\s*fetch\s*,\s*accountPacer\(env\)\s*\)/.test(src),
    );
    ok(
      "the default media uploader factory is built WITH a pacer",
      /makeMediaUploader\(\s*token\s*,\s*fetch\s*,\s*accountPacer\(env\)\s*\)/.test(src),
    );
    ok(
      "the pacer comes from the SHARED accountPacer, not a locally-constructed one",
      /import \{[^}]*accountPacer[^}]*\} from "\.\.\/cf-pace\.ts";/.test(src) && !/new CfPacer\(/.test(src),
    );
  }

  console.log(failures === 0 ? "\nCF RATE-LIMIT / PACER VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
