// Branch-coverage validator for src/admin/router-keys.ts: the in-product key-ceremony route group
// (POST /keys/install, /keys/rotate, /keys/break-glass-only and /setup/acknowledge), driven through the
// REAL handleAdmin dispatch over an in-memory SchedulerDO. It exercises, via genuine request/state, every
// branch the route bodies own: the owner-exclusive keys.ceremony gate (denied vs allowed, with the
// denied-path audit row actually recorded), the per-caller rate limiter tripping to 429 (the real DO
// fixed-window counter, hammered past its cap), the absent-engine-account refusals (config-null and
// CF_ACCOUNT_ID present vs absent), the WORKER_NAME-vs-default script-name resolution, the
// validate-before-write install failures (malformed body and a missing token), the install/rotate/posture
// success paths (good keys + a stubbed Cloudflare secrets endpoint), the operational-pair-present vs absent
// audit-name branch, the server-enforced acknowledge gate (keys present vs not), the best-effort
// audit-append and demo-marker-clear catch arms (a fault-injected DO whose /audit and /demo POSTs throw, so
// the route still answers 200), and the no-match default. No real network and no real deploy: the only
// network is the harness JWKS stub plus a Cloudflare-API stub that records the secret PUT/DELETE calls.
//
// Run: node test/validate-cov-admin-router-keys.ts

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { makeScheduler, makeSigner, MockStorage, TEAM, AUD } from "./validate-rbac-harness.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { POSTURE_ACK_STATEMENTS } from "../src/admin/posture-ack-statements.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- A VALID ceremony key set (the exact encodings the in-browser ceremony emits) ----------------
// signer private = ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes; the PUBLIC the route returns is
// ed25519 public(32) || ML-DSA-87 public, derived from the same seeds, so the route's signerPublic is an
// asserted real outcome (the recovery-sheet pin), not just a status code.
const edSeed = randomBytes(32);
const mldsaSeed = randomBytes(32);
const SIGNER_PRIVATE = b64urlEncode(concat(edSeed, mldsaSeed));
const SIGNER_PUBLIC_EXPECTED = b64urlEncode(concat(ed25519.getPublicKey(edSeed), ml_dsa87.keygen(mldsaSeed).publicKey));
const bgKp = x25519.keygen();
const BREAK_GLASS_PUBLIC = b64urlEncode(concat(bgKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const opKp = x25519.keygen();
const OPERATIONAL_PUBLIC = b64urlEncode(concat(opKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const OPERATIONAL_PRIVATE = b64urlEncode(concat(randomBytes(32), randomBytes(64)));

const TOKEN = "cfat-test-edit-workers-token-1234567890";
const BARE = "cov-keys-admin-break-glass-token";

type Stack = ReturnType<typeof makeScheduler>;

// makeFailingStack builds a SchedulerDO over MockStorage whose stub THROWS on the named POST paths (and
// delegates everything else to the real DO), so the route's best-effort try/catch arms around the audit
// append and the demo first-run clear can be driven by a genuine backing-store fault, exactly as the
// harness's failRateCheck option simulates an unavailable rate-limit store. The logic under test (the
// route) is unchanged; only the DO it forwards a best-effort write to is made to fail.
function makeFailingStack(failSuffixes: string[]): Stack {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const method = init?.method ?? "GET";
      if (method === "POST" && failSuffixes.some((sfx) => url.endsWith(sfx))) {
        throw new Error(`simulated DO ${url} unavailable`);
      }
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, stub };
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor } = signer;

  // Wrap the harness JWKS stub: a Cloudflare-API call (the secret PUT/DELETE the success paths make via
  // the engine's default global fetch) is recorded and answered success; everything else falls through to
  // the JWKS stub (which serves the Access certs and throws on any other stray call). cfCalls lets a
  // success scenario assert the engine actually hit the secrets endpoint the right number of times.
  const innerFetch = globalThis.fetch;
  const cfCalls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith("https://api.cloudflare.com")) {
      cfCalls.push(`${init?.method ?? "GET"} ${url}`);
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return innerFetch(input, init);
  }) as typeof fetch;

  const envFor = (s: Stack, extra: Record<string, unknown> = {}): Env =>
    ({ ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: BARE, ...extra }) as unknown as Env;

  const reqBare = (method: string, path: string, body?: unknown, raw = false): Request =>
    new Request(`https://engine.example${path}`, {
      method,
      headers: { authorization: `Bearer ${BARE}`, "content-type": "application/json", origin: "https://engine.example" },
      ...(body !== undefined ? { body: raw ? (body as string) : JSON.stringify(body) } : {}),
    });

  const reqAccess = async (email: string, method: string, path: string, body?: unknown): Promise<Request> =>
    new Request(`https://engine.example${path}`, {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(email), "content-type": "application/json", origin: "https://engine.example" },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

  const callBare = (s: Stack, method: string, path: string, body?: unknown, extra?: Record<string, unknown>, raw = false): Promise<Response> =>
    handleAdmin(reqBare(method, path, body, raw), envFor(s, extra));
  const callAccess = async (s: Stack, email: string, method: string, path: string, body?: unknown, extra?: Record<string, unknown>): Promise<Response> =>
    handleAdmin(await reqAccess(email, method, path, body), envFor(s, extra));

  const seedDiscovery = async (s: Stack, engineAccountId: string | null): Promise<void> => {
    await s.storage.put(DISCOVERY_KEY, {
      token: "cfat_seeded_discovery_token_value_1234567890",
      setAt: 1,
      setBy: "owner@x.example",
      accountsSeen: [{ id: engineAccountId ?? "acct-seen", name: "Seen" }],
      selected: engineAccountId ? [engineAccountId] : [],
      engineAccountId,
    });
  };

  // ============================ DENIED (owner-exclusive keys.ceremony gate) ============================
  // A non-owner Access caller is refused 403 at the gate, and the refused attempt is AUDITED (a real,
  // persisted effect): the route records a denied key-ceremony row before returning. Bootstrap a distinct
  // Access owner first so the install-attempting email resolves to a plain viewer, not the bootstrap owner.
  const deniedCase = async (label: string, path: string, body: unknown, expectAction: string): Promise<void> => {
    const s = makeScheduler();
    await callAccess(s, `owner-${label}@x.example`, "GET", "/admin/whoami");
    const denied = await callAccess(s, `viewer-${label}@x.example`, "POST", path, body);
    ok(`${label}: a non-owner is refused 403`, denied.status === 403);
    const db = await denied.text();
    ok(`${label}: the refusal names the keys.ceremony capability`, /forbidden/.test(db) && /keys\.ceremony/.test(db));
    const auditResp = await callBare(s, "GET", "/admin/audit?limit=50");
    const j = (await auditResp.json()) as { events?: Array<{ action?: string; outcome?: string }> };
    ok(`${label}: a denied ${expectAction} audit row was persisted`, (j.events ?? []).some((e) => e.action === expectAction && e.outcome === "denied"));
  };

  console.log("-- the keys.ceremony gate refuses a non-owner and audits the denial --");
  await deniedCase("keys/install", "/admin/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }, "keys-installed");
  await deniedCase("keys/rotate", "/admin/keys/rotate", { token: TOKEN, breakGlassPublic: BREAK_GLASS_PUBLIC }, "break-glass-rotated");
  await deniedCase("keys/break-glass-only", "/admin/keys/break-glass-only", { token: TOKEN }, "operational-removed");
  {
    // /setup/acknowledge is owner-gated too, but records NO audit on the denial (it changes no secret).
    const s = makeScheduler();
    await callAccess(s, "owner-ack@x.example", "GET", "/admin/whoami");
    const denied = await callAccess(s, "viewer-ack@x.example", "POST", "/admin/setup/acknowledge", {});
    ok("setup/acknowledge: a non-owner is refused 403", denied.status === 403);
    ok("setup/acknowledge: the refusal names keys.ceremony", /keys\.ceremony/.test(await denied.text()));
  }

  // ============================ ABSENT ENGINE ACCOUNT (the honest 400 guidance) ========================
  console.log("\n-- a key ceremony with no resolvable engine account refuses 400 with guidance --");
  {
    const s = makeScheduler(); // no DISCOVERY_KEY, no CF_ACCOUNT_ID, no DISCOVERY_API_TOKEN
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC });
    ok("install refuses 400 when the engine account is unresolvable", r.status === 400);
    ok("the install refusal carries the account-not-set guidance", /account is not set/.test((await r.json() as { error?: string }).error ?? ""));
    ok("the unresolvable-account install made ZERO Cloudflare calls", cfCalls.length === before);
  }
  {
    const s = makeScheduler(); // CF_ACCOUNT_ID unset -> typeof guard false -> null
    const r = await callBare(s, "POST", "/admin/keys/rotate", { token: TOKEN, breakGlassPublic: BREAK_GLASS_PUBLIC });
    ok("rotate refuses 400 when the engine account is not marked", r.status === 400);
  }
  {
    const s = makeScheduler();
    const r = await callBare(s, "POST", "/admin/keys/break-glass-only", { token: TOKEN });
    ok("break-glass-only refuses 400 when the engine account is not marked", r.status === 400);
  }

  // ============================ INSTALL: validate-before-write failures (400) ==========================
  console.log("\n-- install validate-before-write: a bad body / missing token refuses 400, no CF write --");
  {
    // Malformed JSON body -> the route's catch degrades it to {} (so the gate still applies); the owner
    // falls through to installEngineSecrets, which throws on the empty signer before any network call. The
    // account resolves via CF_ACCOUNT_ID and WORKER_NAME is read for the script name (the set branch).
    const s = makeScheduler();
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/install", "{ this is not json", { CF_ACCOUNT_ID: "acct-a3", WORKER_NAME: "engine-prod" }, true);
    ok("install with a malformed body refuses 400 (validate before write)", r.status === 400);
    ok("the malformed-body install made ZERO Cloudflare calls", cfCalls.length === before);
  }
  {
    // Valid keys but NO token field (the typeof-string guard coerces it to "") -> the token-required throw
    // fires after validation passes. WORKER_NAME is whitespace-only, so the script name falls back to the
    // default (the trim-empty branch of the name resolution).
    const s = makeScheduler();
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/install", { signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }, { CF_ACCOUNT_ID: "acct-a3b", WORKER_NAME: "   " });
    ok("install with valid keys but no token refuses 400", r.status === 400);
    ok("the deploy-token-required reason is surfaced", /deploy token/.test((await r.json() as { error?: string }).error ?? ""));
    ok("the missing-token install made ZERO Cloudflare calls", cfCalls.length === before);
  }

  // ============================ INSTALL: success paths (200) ==========================================
  console.log("\n-- install success: good keys land the secrets and return the public + configured set --");
  {
    // Operational pair PRESENT, account via CF_ACCOUNT_ID, WORKER_NAME UNSET (default script name) -> four
    // PUTs, configured.operational true.
    const s = makeScheduler();
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/install", {
      token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE,
    }, { CF_ACCOUNT_ID: "acct-a4" });
    const b = (await r.json()) as { ok?: boolean; signerPublic?: string; configured?: { operational?: boolean } };
    ok("install (operational pair) returns 200", r.status === 200);
    ok("the returned signerPublic equals the recovery-sheet pin", b.signerPublic === SIGNER_PUBLIC_EXPECTED);
    ok("configured.operational is true when the pair is supplied", b.configured?.operational === true);
    // Supplying the operational pair also clears the OPERATIONAL_RETIRED marker (best-effort), a 5th call.
    ok("the engine PUT four secrets and cleared the OPERATIONAL_RETIRED marker (5 calls)", cfCalls.length - before === 5);
  }
  {
    // Operational pair ABSENT, account via the marked discovery engineAccountId (the config-non-null
    // branch), WORKER_NAME set -> two PUTs, configured.operational false.
    const s = makeScheduler();
    await seedDiscovery(s, "acct-disc-a5");
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC }, { WORKER_NAME: "engine-prod" });
    const b = (await r.json()) as { ok?: boolean; signerPublic?: string; configured?: { operational?: boolean } };
    ok("install (no operational pair, discovery account) returns 200", r.status === 200);
    ok("configured.operational is false when the pair is omitted", b.configured?.operational === false);
    ok("the engine PUT exactly two secrets (signer + break-glass)", cfCalls.length - before === 2);
  }

  // ============================ ROTATE: success + failure ============================================
  console.log("\n-- rotate: a good public lands one PUT (200); a bad body refuses (400) --");
  {
    const s = makeScheduler();
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/rotate", { token: TOKEN, breakGlassPublic: BREAK_GLASS_PUBLIC }, { CF_ACCOUNT_ID: "acct-b3", WORKER_NAME: "engine-prod" });
    ok("rotate returns 200 for a good public", r.status === 200 && ((await r.json()) as { ok?: boolean }).ok === true);
    ok("rotate PUT exactly one secret (BREAK_GLASS_PUBLIC)", cfCalls.length - before === 1);
  }
  {
    // Malformed body -> {} -> empty token -> rotateBreakGlassPublic throws -> 400. Account via the marked
    // discovery engineAccountId (the ?? left branch), WORKER_NAME unset (default name).
    const s = makeScheduler();
    await seedDiscovery(s, "acct-disc-b4");
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/rotate", "}{not json", {}, true);
    ok("rotate with a malformed body refuses 400", r.status === 400);
    ok("the failed rotate made ZERO Cloudflare calls", cfCalls.length === before);
  }

  // ============================ BREAK-GLASS-ONLY: success + failure ===================================
  console.log("\n-- break-glass-only: a good token deletes both operational secrets (200); bad body (400) --");
  {
    const s = makeScheduler();
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/break-glass-only", { token: TOKEN }, { CF_ACCOUNT_ID: "acct-c3", WORKER_NAME: "engine-prod" });
    ok("break-glass-only returns 200 for a good token", r.status === 200 && ((await r.json()) as { ok?: boolean }).ok === true);
    // The switch also SETS the durable OPERATIONAL_RETIRED marker (a PUT, before either delete): 3 calls.
    ok("break-glass-only set the OPERATIONAL_RETIRED marker and DELETEd both operational secrets (3 calls)", cfCalls.length - before === 3);
  }
  {
    const s = makeScheduler();
    await seedDiscovery(s, "acct-disc-c4");
    const before = cfCalls.length;
    const r = await callBare(s, "POST", "/admin/keys/break-glass-only", "not-json", {}, true);
    ok("break-glass-only with a malformed body refuses 400", r.status === 400);
    ok("the failed break-glass-only made ZERO Cloudflare calls", cfCalls.length === before);
  }

  // ============================ SETUP/ACKNOWLEDGE: server-enforced clear ==============================
  console.log("\n-- setup/acknowledge is server-enforced: only clears when keys are actually present --");
  {
    const s = makeScheduler(); // no SIGNER_PRIVATE / BREAK_GLASS_PUBLIC in env
    const r = await callBare(s, "POST", "/admin/setup/acknowledge", {});
    const b = (await r.json()) as { ok?: boolean; reason?: string };
    ok("acknowledge with no keys present returns ok:false keys-not-present", r.status === 200 && b.ok === false && b.reason === "keys-not-present");
  }
  {
    const s = makeScheduler(); // signer present but break-glass absent -> still not acknowledgeable
    const r = await callBare(s, "POST", "/admin/setup/acknowledge", {}, { SIGNER_PRIVATE: "x" });
    ok("acknowledge with only the signer present still returns ok:false", r.status === 200 && ((await r.json()) as { ok?: boolean }).ok === false);
  }
  {
    const s = makeScheduler(); // both present -> ok:true
    const r = await callBare(s, "POST", "/admin/setup/acknowledge", {}, { SIGNER_PRIVATE: "x", BREAK_GLASS_PUBLIC: "y" });
    ok("acknowledge with both keys present returns ok:true", r.status === 200 && ((await r.json()) as { ok?: boolean }).ok === true);
  }

  // ============================ BEST-EFFORT CATCH ARMS (audit + demo clear fail open) =================
  // A DO whose /audit and /demo/first-run/clear POSTs throw must NOT turn a landed key ceremony into a
  // failure: the route logs and still answers 200. This drives the try/catch arms around the success-path
  // audit append (install/rotate/break-glass-only) and the demo first-run clear (install + acknowledge).
  console.log("\n-- a down audit / demo-marker DO never turns a landed ceremony into a failure --");
  {
    const f = makeFailingStack(["/audit", "/demo/first-run/clear"]);
    const ri = await callBare(f, "POST", "/admin/keys/install", {
      token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS_PUBLIC, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE,
    }, { CF_ACCOUNT_ID: "acct-f-install", WORKER_NAME: "engine-prod" });
    ok("install still returns 200 when the audit + demo DO writes throw", ri.status === 200 && ((await ri.json()) as { ok?: boolean }).ok === true);

    const rr = await callBare(f, "POST", "/admin/keys/rotate", { token: TOKEN, breakGlassPublic: BREAK_GLASS_PUBLIC }, { CF_ACCOUNT_ID: "acct-f-rotate", WORKER_NAME: "engine-prod" });
    ok("rotate still returns 200 when the audit DO write throws", rr.status === 200 && ((await rr.json()) as { ok?: boolean }).ok === true);

    const rb = await callBare(f, "POST", "/admin/keys/break-glass-only", { token: TOKEN }, { CF_ACCOUNT_ID: "acct-f-bgo", WORKER_NAME: "engine-prod" });
    ok("break-glass-only still returns 200 when the audit DO write throws", rb.status === 200 && ((await rb.json()) as { ok?: boolean }).ok === true);

    const ra = await callBare(f, "POST", "/admin/setup/acknowledge", {}, { SIGNER_PRIVATE: "x", BREAK_GLASS_PUBLIC: "y" });
    ok("acknowledge still returns ok:true when the demo-marker DO write throws", ra.status === 200 && ((await ra.json()) as { ok?: boolean }).ok === true);
  }

  // ============================ RATE LIMIT (the real DO fixed-window counter trips) ===================
  // Hammer the per-caller limiter on an isolated stack past its cap; once tripped, every key-ceremony
  // route returns 429 for that caller. No account is set, so each pre-trip request is a cheap 400.
  console.log("\n-- the per-caller rate limiter trips to 429 across every key-ceremony route --");
  {
    const e = makeScheduler();
    let saw429 = false;
    for (let i = 0; i < 130 && !saw429; i++) {
      const r = await callBare(e, "POST", "/admin/keys/install", { token: TOKEN });
      if (r.status === 429) saw429 = true;
    }
    ok("install trips the real per-caller limiter to 429 past the cap", saw429);
    ok("rotate returns 429 for the now-throttled caller", (await callBare(e, "POST", "/admin/keys/rotate", { token: TOKEN })).status === 429);
    ok("break-glass-only returns 429 for the now-throttled caller", (await callBare(e, "POST", "/admin/keys/break-glass-only", { token: TOKEN })).status === 429);
    ok("setup/acknowledge returns 429 for the now-throttled caller", (await callBare(e, "POST", "/admin/setup/acknowledge", {})).status === 429);
  }

  // ===== THE POSTURE-ACK CHANNEL IS REFUSED OUT OF ENUM, NOT FILED AS "onboarding". =====
  //
  // `channel` was
  // `body.channel === "keys-rekey" ? "keys-rekey" : "onboarding"`, so ANY other value recorded the
  // acknowledgement against the onboarding ceremony and answered 200. This record IS the compliance
  // evidence that a customer accepted a key-posture statement, so filing it against a ceremony that did not
  // happen is a false entry in exactly the register somebody will later read as proof. `posture` two lines
  // above it already refused out of enum; this is the same rule on the field beside it.
  console.log("\n-- posture acknowledgement: the channel enum is refused, not coerced --");
  {
    const s = makeScheduler();
    const version = POSTURE_ACK_STATEMENTS.operational.version;
    const bad = await callBare(s, "POST", "/admin/keys/posture-acknowledgement", { posture: "operational", statementVersion: version, channel: "quarterly-review" });
    ok("an out-of-enum posture-ack channel is REFUSED 400, not filed as onboarding", bad.status === 400);
    const badBody = String(((await bad.json()) as { error?: string }).error);
    ok("the refusal names BOTH accepted channels, so the operator does not have to guess", badBody.includes("onboarding") && badBody.includes("keys-rekey"));
    // DISCRIMINATING CONTROLS: the two real channels still record, and an OMITTED channel still defaults to
    // onboarding. Without these a route that 400'd every acknowledgement would pass the refusal above.
    for (const ch of ["onboarding", "keys-rekey"]) {
      const r = await callBare(s, "POST", "/admin/keys/posture-acknowledgement", { posture: "operational", statementVersion: version, channel: ch });
      ok(`posture-ack CONTROL: channel "${ch}" is still accepted (200)`, r.status === 200);
    }
    const omitted = await callBare(s, "POST", "/admin/keys/posture-acknowledgement", { posture: "operational", statementVersion: version });
    ok("posture-ack CONTROL: an OMITTED channel still defaults to onboarding (200)", omitted.status === 200);
  }

  // ============================ DEFAULT (no case matched -> the hub falls through to 404) =============
  console.log("\n-- a method/path the spoke does not own falls through (default arm) to 404 --");
  {
    const s = makeScheduler();
    const r = await callBare(s, "GET", "/admin/keys/install"); // GET, not POST -> no case matches
    ok("GET /admin/keys/install is not owned by the keys spoke (404)", r.status === 404);
  }

  signer.restoreFetch();
  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
