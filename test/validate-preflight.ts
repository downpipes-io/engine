// Prove the onboarding preflight VERIFIES prerequisites instead of assuming them: a
// healthy environment reports verified items with live evidence (Durable Object
// round-trip, recorded cron-tick recency, destination probe, Zero Trust JWKS proof, key
// parsing, the seal DO, the licence tier); a missing prerequisite reports unconfigured
// with the remediation naming the Cloudflare product; a stale cron and a dead Zero
// Trust team domain report FAILED (the validated-not-hoped contract); and no probe
// ever leaks a secret value into the report.
// Run: node test/validate-preflight.ts

import { runPreflight } from "../src/admin/preflight.ts";
import type { Env } from "../src/env.d.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner } from "../src/keys-env.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function schedulerDouble(lastTickAt: number | null): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/tick-info") return new Response(JSON.stringify({ lastTickAt }));
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
}

// counts (optional): when passed, counts.downpipes is bumped on every /downpipes read, so a
// caller can prove how many times the roster was actually fetched across a whole runPreflight() run
// (the source-bindings/source-liveness/api-discovery-token probes now share ONE fetch, not three).
function schedulerWithDownpipes(lastTickAt: number | null, downpipes: unknown[], counts?: { downpipes: number }): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/tick-info") return new Response(JSON.stringify({ lastTickAt }));
      if (url.pathname === "/downpipes") {
        if (counts) counts.downpipes++;
        return new Response(JSON.stringify(downpipes));
      }
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
}

function runsealDouble(ok: boolean): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        async fetch(): Promise<Response> {
          if (!ok) throw new Error("no such class");
          return new Response(JSON.stringify({ active: false }));
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

// runsealActiveDouble: the seal Durable Object reports an ACTIVE run in flight, so the
// sliced-runs evidence takes the "active run: yes" arm.
function runsealActiveDouble(): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        async fetch(): Promise<Response> {
          return new Response(JSON.stringify({ active: true }));
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

// A scheduler whose every fetch rejects: the Durable Object round-trip itself fails, which is
// the loud no-DOs-on-this-account path (and, downstream, the unreadable-downpipes path).
function schedulerDead(): DurableObjectStub {
  return {
    async fetch(): Promise<Response> {
      throw new Error("Network connection lost while reaching the Durable Object");
    },
  } as unknown as DurableObjectStub;
}

// A scheduler that answers the DO round-trip and cron tick but whose /downpipes read fails,
// so only the source-bindings probe sees the failure (the DO item above stays verified).
function schedulerDownpipesUnreadable(lastTickAt: number | null): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/tick-info") return new Response(JSON.stringify({ lastTickAt }));
      if (url.pathname === "/downpipes") throw new Error("the downpipes read failed");
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
}

// A scheduler that ALSO serves a console-set destination (/dest-config) and an activated licence
// token (/licence-token), so preflight resolves the console-set destination and the licence tier a
// run would actually use. destConfigStatus lets a test force a non-ok /dest-config response, which
// is the stored-config-unreadable path (fetchDestConfig throws).
function schedulerRich(opts: {
  lastTickAt: number | null;
  downpipes?: unknown[];
  destConfig?: unknown;
  destConfigStatus?: number;
  licenceToken?: string | null;
}): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/tick-info") return new Response(JSON.stringify({ lastTickAt: opts.lastTickAt }));
      if (url.pathname === "/downpipes") return new Response(JSON.stringify(opts.downpipes ?? []));
      if (url.pathname === "/dest-config") {
        if (opts.destConfigStatus !== undefined && opts.destConfigStatus !== 200) {
          return new Response("nope", { status: opts.destConfigStatus });
        }
        return new Response(JSON.stringify({ config: opts.destConfig ?? null }));
      }
      if (url.pathname === "/licence-token") {
        return new Response(JSON.stringify(opts.licenceToken ? { token: opts.licenceToken, setAt: Date.now(), setBy: "owner@example.com.au" } : {}));
      }
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
}

function item(report: Awaited<ReturnType<typeof runPreflight>>, id: string) {
  return report.items.find((i) => i.id === id)!;
}

// mintLicence signs a claims body EXACTLY as the vendor issuer does (canonicalise, hybrid-sign the
// bytes, join base64url(body).base64url(sig)) so readLicence verifies it against the pinned key and
// resolves the granted tier, which is what drives the licence item's verified arm.
async function mintLicence(signerB64: string, claims: unknown): Promise<string> {
  const signer = await loadSigner(signerB64);
  const body = canonicalJSON(claims);
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, body);
  return `${b64urlEncode(body)}.${b64urlEncode(sig)}`;
}

async function main(): Promise<void> {
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const xk = x25519.keygen();
  const bgB64 = b64urlEncode(concat(xk.publicKey, mlkemKeygen(rand(64)).encapKey));
  const r2Facade = {
    async head(): Promise<unknown> {
      return {}; // the RUNLOG exists: reachable and authorised
    },
    async put(): Promise<unknown> {
      return {};
    },
    async get(): Promise<unknown> {
      return null;
    },
  };

  const realFetch = globalThis.fetch;
  try {
    // JWKS double: a live Zero Trust team domain answering with two signing keys.
    globalThis.fetch = (async (input: URL | RequestInfo): Promise<Response> => {
      const u = String(input instanceof URL ? input.href : input);
      if (u.includes("/cdn-cgi/access/certs")) return new Response(JSON.stringify({ keys: [{}, {}] }));
      return new Response("unexpected", { status: 500 });
    }) as typeof fetch;

    console.log("healthy environment:");
    {
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        RUNSEAL: runsealDouble(true),
        SIGNER_PRIVATE: signerB64,
        BREAK_GLASS_PUBLIC: bgB64,
        DEST_KIND: "r2",
        DEST_R2: r2Facade,
        CF_ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
        CF_ACCESS_AUD: "aud123",
        EMAIL: { send: async () => ({}) },
        EMAIL_FROM: "alerts@example.com.au",
      } as unknown as Env;
      const report = await runPreflight(env, schedulerDouble(Date.now() - 5 * 60_000));
      ok("durable-objects verified by a live round-trip", item(report, "durable-objects").status === "verified");
      ok("cron-tick verified from RECORDED tick recency", item(report, "cron-tick").status === "verified" && /minutes ago/.test(item(report, "cron-tick").evidence));
      ok("destination verified by a read-only probe", item(report, "destination").status === "verified");
      ok("signer verified by parsing (no value in evidence)", item(report, "signer").status === "verified" && !report.items.some((i) => JSON.stringify(i).includes(signerB64)));
      ok("recipients verified by parsing", item(report, "recipients").status === "verified");
      ok("Zero Trust PROVEN live via the team JWKS", item(report, "access-zero-trust").status === "verified" && /2 signing key/.test(item(report, "access-zero-trust").evidence));
      ok("email is configured-unproven with the test-send remediation", item(report, "email-sending").status === "configured" && /test-send/.test(item(report, "email-sending").remediation ?? ""));
      ok("sliced runs verified via the seal DO", item(report, "sliced-runs").status === "verified");
      ok("the workers-plan item names the deploy-time gate", /wrangler deploy/.test(item(report, "workers-plan").evidence));
      ok("summary counts the required items", report.summary.required >= 6 && report.summary.failed === 0);
    }

    console.log("\nsource-binding drift (the deploy-dropped-a-source probe):");
    {
      const downpipes = [
        { config: { id: "dp1", name: "uploads", enabled: true, source: { type: "kv", binding: "SRC_KV_uploads", include: [], exclude: [] } } },
        { config: { id: "dp2", name: "media", enabled: true, source: { type: "r2", binding: "SRC_R2_media", include: [], exclude: [] } } },
      ];
      // Both configured bindings present in env -> verified.
      const envOk = { SCHEDULER: {} as DurableObjectNamespace, SRC_KV_uploads: {}, SRC_R2_media: {} } as unknown as Env;
      const okReport = await runPreflight(envOk, schedulerWithDownpipes(Date.now() - 60_000, downpipes));
      ok("source-bindings VERIFIED when every configured binding is present", item(okReport, "source-bindings").status === "verified");

      // SRC_R2_media missing from env (a deploy dropped it) -> failed, naming the binding + downpipe.
      const envDrift = { SCHEDULER: {} as DurableObjectNamespace, SRC_KV_uploads: {} } as unknown as Env;
      const driftReport = await runPreflight(envDrift, schedulerWithDownpipes(Date.now() - 60_000, downpipes));
      const sb = item(driftReport, "source-bindings");
      ok("source-bindings FAILS when a configured binding is missing from env", sb.status === "failed");
      ok("the failure names the missing binding and the downpipe it breaks", sb.evidence.includes("SRC_R2_media") && sb.evidence.includes("media"));
      ok("the remediation points at re-attach / the reconcile", /[Rr]e-attach|reconcile/.test(sb.remediation ?? ""));
      ok("a present binding is NOT named as missing", !sb.evidence.includes("SRC_KV_uploads"));
      ok("the drift failure is counted in the summary", driftReport.summary.failed >= 1);
      ok("no binding values leak (names only, which are operator labels)", !JSON.stringify(sb).includes("namespace_id"));

      // A reserved name configured as a source -> surfaced as broken even though it 'exists' in env.
      const reservedDp = [{ config: { id: "dp3", name: "oops", enabled: true, source: { type: "kv", binding: "SCHEDULER", include: [], exclude: [] } } }];
      const reservedReport = await runPreflight({ SCHEDULER: {} as DurableObjectNamespace } as unknown as Env, schedulerWithDownpipes(Date.now() - 60_000, reservedDp));
      ok("a reserved binding name configured as a source FAILS (cannot be a source)", item(reservedReport, "source-bindings").status === "failed" && /reserved/.test(item(reservedReport, "source-bindings").evidence));

      // No binding-backed downpipes -> unconfigured (cf-config sources read a token, not a binding).
      const cfOnly = [{ config: { id: "dp4", name: "cfg", enabled: true, source: { type: "cf-config", accountId: "a", include: [], exclude: [] } } }];
      const cfReport = await runPreflight({ SCHEDULER: {} as DurableObjectNamespace } as unknown as Env, schedulerWithDownpipes(Date.now() - 60_000, cfOnly));
      ok("a cf-config-only fleet is unconfigured (no binding-backed source)", item(cfReport, "source-bindings").status === "unconfigured");

      // The roster is read ONCE per runPreflight() and shared by source-bindings,
      // source-liveness and api-source-discovery-token, instead of each of those three probes
      // independently re-fetching /downpipes (three DO round trips collapsed into one). A roster
      // mixing a binding-backed source with an API-discovery-type source exercises all three probes
      // in the same run, so a regression back to per-probe fetching would show up as more than one call.
      const mixedRoster = [
        { config: { id: "dp1", name: "uploads", enabled: true, source: { type: "kv", binding: "SRC_KV_uploads", include: [], exclude: [] } } },
        { config: { id: "dp5", name: "cfg", enabled: true, source: { type: "cf-config", accountId: "a", include: [], exclude: [] } } },
      ];
      const counts = { downpipes: 0 };
      const mixedReport = await runPreflight(
        { SCHEDULER: {} as DurableObjectNamespace, SRC_KV_uploads: {} } as unknown as Env,
        schedulerWithDownpipes(Date.now() - 60_000, mixedRoster, counts),
      );
      ok("source-bindings still verified off the shared roster", item(mixedReport, "source-bindings").status === "verified");
      ok("api-source-discovery-token still evaluated off the shared roster (no token configured -> failed, not skipped)", item(mixedReport, "api-source-discovery-token").status === "failed");
      ok("the /downpipes roster is fetched EXACTLY ONCE for the whole preflight run, not once per probe", counts.downpipes === 1);
    }

    console.log("\nmissing and failing prerequisites:");
    {
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        CF_ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
        CF_ACCESS_AUD: "aud123",
      } as unknown as Env;
      // The JWKS now fails (Zero Trust disabled), and the cron tick is stale.
      globalThis.fetch = (async (): Promise<Response> => new Response("nope", { status: 530 })) as typeof fetch;
      const report = await runPreflight(env, schedulerDouble(Date.now() - 3 * 3600_000));
      ok("a stale cron tick FAILS (not hoped past)", item(report, "cron-tick").status === "failed");
      ok("a dead Zero Trust team domain FAILS with the enable remediation", item(report, "access-zero-trust").status === "failed" && /Zero Trust/.test(item(report, "access-zero-trust").remediation ?? ""));
      ok("an absent destination is unconfigured with the R2/S3 remediation", item(report, "destination").status === "unconfigured" && /R2|S3/.test(item(report, "destination").remediation ?? ""));
      ok("an absent signer is unconfigured with the ceremony remediation", item(report, "signer").status === "unconfigured" && /ceremony/.test(item(report, "signer").remediation ?? ""));
      ok("an absent seal DO is unconfigured with the migration remediation", item(report, "sliced-runs").status === "unconfigured" && /migration v2/.test(item(report, "sliced-runs").remediation ?? ""));
      ok("failures are counted in the summary", report.summary.failed >= 2);
    }

    console.log("\nnever-ticked deployment:");
    {
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      const report = await runPreflight(env, schedulerDouble(null));
      ok("a never-observed cron is unconfigured (await one interval)", item(report, "cron-tick").status === "unconfigured");
    }

    console.log("\ndestination evidence redaction:");
    {
      // A malformed S3 endpoint makes the builder throw a message that echoes the
      // configured value verbatim; the preflight evidence (which flows into the
      // vendor-bound support bundle) must carry the placeholder, never the value.
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        DEST_KIND: "s3",
        DEST_ENDPOINT: "ht!tp://secret-host.internal:9000",
        DEST_BUCKET: "secret-bucket-name",
        DEST_REGION: "auto",
        DEST_ACCESS_KEY_ID: "AKIAEXAMPLE",
        DEST_SECRET_ACCESS_KEY: "S3CR3TVALUE",
      } as unknown as Env;
      const report = await runPreflight(env, schedulerDouble(null));
      const d = item(report, "destination");
      ok("a malformed endpoint FAILS the destination probe", d.status === "failed");
      ok("the configured endpoint VALUE never reaches the evidence", !d.evidence.includes("secret-host.internal"));
      ok("the configured bucket VALUE never reaches the evidence", !d.evidence.includes("secret-bucket-name"));
      ok("the evidence carries the redaction placeholder instead", /<configured value>|<url>/.test(d.evidence));
    }

    console.log("\nthe Durable Object round-trip itself fails (no DOs on the account):");
    {
      // A scheduler whose fetch rejects exercises the catch around the DO round-trip: the
      // durable-objects item must FAIL (not be assumed healthy) and name the enable remediation,
      // and the downstream source-bindings probe (which also reads the scheduler) must FAIL too.
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      const report = await runPreflight(env, schedulerDead());
      const dobj = item(report, "durable-objects");
      ok("a dead scheduler FAILS the Durable Objects item", dobj.status === "failed");
      ok("the DO failure names the enable-Durable-Objects remediation", /Durable Objects/.test(dobj.remediation ?? ""));
      ok("the DO failure evidence carries the (truncated) observed error", /did not respond/.test(dobj.evidence));
      // No cron-tick item is pushed when the round-trip throws (the tick recency was never read).
      ok("no cron-tick item is recorded when the round-trip itself failed", report.items.find((i) => i.id === "cron-tick") === undefined);
      const sb = item(report, "source-bindings");
      ok("source-bindings FAILS when the downpipes read is unreachable", sb.status === "failed" && /could not be read/.test(sb.evidence));
      ok("the unreadable-downpipes remediation points back at the Durable Objects item", /Durable Object/.test(sb.remediation ?? ""));
    }

    console.log("\nthe configured downpipes are unreadable but the DO is alive:");
    {
      // The DO round-trip succeeds (durable-objects verified) but /downpipes throws: only the
      // source-bindings probe sees the failure, isolating the catch on the /downpipes read.
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      const report = await runPreflight(env, schedulerDownpipesUnreadable(Date.now() - 60_000));
      ok("the Durable Objects item stays VERIFIED when only /downpipes fails", item(report, "durable-objects").status === "verified");
      ok("source-bindings FAILS on the unreadable /downpipes read", item(report, "source-bindings").status === "failed" && /could not be read/.test(item(report, "source-bindings").evidence));
    }

    console.log("\nkeys are set but do not parse, and an operational recipient is present:");
    {
      // SIGNER_PRIVATE present but not a valid 64-byte seed -> the loadSigner catch -> FAILED
      // (set-but-broken), distinct from the absent (unconfigured) case, with no value echoed.
      const badEnv = {
        SCHEDULER: {} as DurableObjectNamespace,
        SIGNER_PRIVATE: "not-a-valid-seed",
        BREAK_GLASS_PUBLIC: "also-not-a-key",
      } as unknown as Env;
      const badReport = await runPreflight(badEnv, schedulerDouble(Date.now() - 60_000));
      const signer = item(badReport, "signer");
      ok("a set-but-unparseable signer FAILS (not unconfigured)", signer.status === "failed" && /does not parse/.test(signer.evidence));
      ok("the unparseable signer still names the ceremony remediation", /ceremony/.test(signer.remediation ?? ""));
      ok("the unparseable signer VALUE is never echoed into the evidence", !signer.evidence.includes("not-a-valid-seed"));
      const rec = item(badReport, "recipients");
      // The evidence NAMES the failing slot ("BREAK_GLASS_PUBLIC is set but does not parse") rather than a
      // generic "recipient keys are set but do not parse", so an operator knows WHICH of the two env vars to
      // re-paste. The load-bearing check is the CLOSED discriminator beside the prose, which no truncation
      // can ever cut off.
      ok("set-but-unparseable recipient keys FAIL (not unconfigured)", rec.status === "failed" && /does not parse/.test(rec.evidence));
      ok("the failing recipient SLOT is named as a closed enum, not left to a truncated message", rec.whichRecipient === "break-glass" && rec.probeErrorClass === "key-unparseable");
      ok("the unparseable recipient VALUE is never echoed into the evidence", !rec.evidence.includes("also-not-a-key"));

      // Both a break-glass AND an operational recipient parse -> the evidence takes the
      // "break-glass + operational" plural arm (r.length > 1).
      const bgKey = b64urlEncode(concat(x25519.keygen().publicKey, mlkemKeygen(rand(64)).encapKey));
      const opKey = b64urlEncode(concat(x25519.keygen().publicKey, mlkemKeygen(rand(64)).encapKey));
      const opEnv = {
        SCHEDULER: {} as DurableObjectNamespace,
        BREAK_GLASS_PUBLIC: bgKey,
        OPERATIONAL_PUBLIC: opKey,
      } as unknown as Env;
      const opReport = await runPreflight(opEnv, schedulerDouble(Date.now() - 60_000));
      const opRec = item(opReport, "recipients");
      ok("two parsing recipients are VERIFIED and named break-glass + operational", opRec.status === "verified" && /operational/.test(opRec.evidence) && /2 recipient/.test(opRec.evidence));
    }

    console.log("\nZero Trust answers without usable signing keys:");
    {
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        CF_ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
        CF_ACCESS_AUD: "aud123",
      } as unknown as Env;
      // The team domain is live (200) but the JWKS has a non-array keys field, so the parsed key
      // count is 0: Access is configured here but not actually serving keys -> FAILED with n===0.
      globalThis.fetch = (async (input: URL | RequestInfo): Promise<Response> => {
        const u = String(input instanceof URL ? input.href : input);
        if (u.includes("/cdn-cgi/access/certs")) return new Response(JSON.stringify({ keys: "broken" }));
        return new Response("unexpected", { status: 500 });
      }) as typeof fetch;
      const report = await runPreflight(env, schedulerDouble(Date.now() - 60_000));
      const az = item(report, "access-zero-trust");
      ok("a team domain that answers without keys FAILS", az.status === "failed" && /without signing keys/.test(az.evidence));
      ok("the no-keys failure names the create-the-Access-application remediation", /Access application/.test(az.remediation ?? ""));
    }

    console.log("\nemail binding is bound but EMAIL_FROM is unset:");
    {
      // The EMAIL binding exists but EMAIL_FROM is missing: still unconfigured (a send would have
      // no envelope sender), with the evidence naming the unset EMAIL_FROM specifically.
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        EMAIL: { send: async () => ({}) },
      } as unknown as Env;
      globalThis.fetch = (async (): Promise<Response> => new Response("x", { status: 500 })) as typeof fetch;
      const report = await runPreflight(env, schedulerDouble(Date.now() - 60_000));
      const em = item(report, "email-sending");
      ok("a bound EMAIL with no EMAIL_FROM is unconfigured", em.status === "unconfigured");
      ok("the evidence names the unset EMAIL_FROM (not 'not bound')", /EMAIL_FROM is not set/.test(em.evidence));
      // Email SENDING, not Email Routing: Routing is the separate inbound product, and naming it here
      // sent operators to the wrong dashboard screen. The sender domain is onboarded under Compute,
      // Email Service, Email Sending (console/src/screens/settings/support.ts says the same).
      ok("the remediation names the Email Sending onboarding", /Email Sending/.test(em.remediation ?? ""));
    }

    console.log("\nthe seal Durable Object is bound but does not respond:");
    {
      // The RUNSEAL binding exists (idFromName is a function) but the stub fetch throws: this is
      // the migration-present-but-broken path -> FAILED with the redeploy-migration-v2 remediation,
      // distinct from the absent-binding (unconfigured) case.
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        RUNSEAL: runsealDouble(false),
      } as unknown as Env;
      globalThis.fetch = (async (): Promise<Response> => new Response("x", { status: 500 })) as typeof fetch;
      const report = await runPreflight(env, schedulerDouble(Date.now() - 60_000));
      const sr = item(report, "sliced-runs");
      ok("a bound-but-unresponsive seal DO FAILS (not unconfigured)", sr.status === "failed" && /did not respond/.test(sr.evidence));
      ok("the seal-DO failure names the redeploy-migration-v2 remediation", /migration v2/.test(sr.remediation ?? ""));
    }

    console.log("\nan activated licence resolves a non-community tier, and a run is in flight:");
    {
      // A real vendor-signed token, pinned under LICENCE_SIGNER_PUBLIC and delivered through the
      // scheduler's /licence-token record, resolves to its granted tier so the licence item takes
      // the VERIFIED arm (not the community 'configured' default). The same env reports an ACTIVE
      // seal run so the sliced-runs evidence takes the "active run: yes" arm.
      const vendorB64 = b64urlEncode(concat(rand(32), rand(32)));
      const vendor = await loadSigner(vendorB64);
      const pinnedPublic = b64urlEncode(concat(vendor.edPublic, vendor.mldsaPublic));
      const future = new Date(Date.now() + 365 * 86400_000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
      const token = await mintLicence(vendorB64, { account: "acme", tier: "enterprise", notAfter: future, features: ["dashboard"] });

      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        RUNSEAL: runsealActiveDouble(),
        LICENCE_SIGNER_PUBLIC: pinnedPublic,
      } as unknown as Env;
      globalThis.fetch = (async (): Promise<Response> => new Response("x", { status: 500 })) as typeof fetch;
      const report = await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, licenceToken: token }));
      const lic = item(report, "licence");
      ok("an activated enterprise licence resolves the VERIFIED tier", lic.status === "verified" && /tier enterprise/.test(lic.evidence));
      ok("the licence token bytes never appear anywhere in the report", !JSON.stringify(report).includes(token));
      ok("an in-flight run shows 'active run: yes' on the seal item", item(report, "sliced-runs").status === "verified" && /active run: yes/.test(item(report, "sliced-runs").evidence));
    }

    console.log("\nthe console-set destination wins and is verified by a live probe:");
    {
      // fetchDestConfig returns a non-null console-set config; buildDestination builds an S3
      // destination over it and exists() does a HEAD, which the global fetch answers 200 (RUNLOG
      // present). This drives the destOverride !== null requires/evidence arms (console-set), and
      // proves preflight probes the destination a run would actually resolve.
      globalThis.fetch = (async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
        if ((init?.method ?? "GET") === "HEAD") return new Response(null, { status: 200 });
        return new Response("unexpected", { status: 500 });
      }) as typeof fetch;
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      const destConfig = {
        endpoint: "https://bucket.console-set.example.com",
        bucket: "archive",
        region: "auto",
        accessKeyId: "AKIACONSOLE",
        secretAccessKey: "consolesecret",
      };
      const report = await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, destConfig }));
      const d = item(report, "destination");
      ok("a reachable console-set destination is VERIFIED", d.status === "verified");
      ok("the requires line names the console-set bucket (override path)", /console/.test(d.requires));
      ok("the evidence says the RUNLOG is present and set from the console", /RUNLOG present/.test(d.evidence) && /set from the console/.test(d.evidence));
    }

    console.log("\nthe destination preflight is NOT a false-green on a 403/503 (headStatus classification):");
    {
      // exists() collapsed every non-200 to false, so a 403/503 on the RUNLOG HEAD read as "absent" and
      // the probe reported a FALSE-GREEN "verified" on a broken/down credentialed store. headStatus surfaces
      // the status: 404 => absent (verified, first run pending); 403 => auth failure; 5xx/429 => transient.
      const destConfig = { endpoint: "https://bucket.console-set.example.com", bucket: "archive", region: "auto", accessKeyId: "AKIACONSOLE", secretAccessKey: "consolesecret" };
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      const headWith = (status: number): void => {
        globalThis.fetch = (async (_i: URL | RequestInfo, init?: RequestInit): Promise<Response> =>
          (init?.method ?? "GET") === "HEAD" ? new Response(null, { status }) : new Response("x", { status: 500 })) as typeof fetch;
      };
      headWith(403);
      let d = item(await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, destConfig })), "destination");
      ok("a 403 on the RUNLOG HEAD FAILS the destination probe (no false-green)", d.status === "failed");
      ok("a 403 is classed as an AUTH failure", d.failureClass === "auth");
      headWith(503);
      d = item(await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, destConfig })), "destination");
      ok("a 503 on the RUNLOG HEAD FAILS the destination probe", d.status === "failed");
      ok("a 503 is classed as TRANSIENT (throttle/unavailable), never auth", d.failureClass === "transient");
      headWith(404);
      d = item(await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, destConfig })), "destination");
      ok("a 404 on the RUNLOG HEAD is VERIFIED (absent: a fresh bucket, first run pending)", d.status === "verified");
      ok("a 404 reports the RUNLOG absent / first run pending", /absent; first run pending/.test(d.evidence));
    }

    console.log("\nthe stored destination configuration cannot be read:");
    {
      // /dest-config answers non-ok, so fetchDestConfig throws and destOverrideError is set. Rather than
      // condemning the whole destination, preflight falls back to probing the env/binding destination. With
      // no DEST_* configured here that probe reports 'unconfigured', and the override read fault is noted in
      // the evidence so a transient DO read fault does not mask the deploy-configured destination.
      globalThis.fetch = (async (): Promise<Response> => new Response("x", { status: 500 })) as typeof fetch;
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      const report = await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, destConfigStatus: 503 }));
      const d = item(report, "destination");
      ok("an unreadable stored destination config falls back to probing the env/binding destination (not a hard failure)", d.status === "unconfigured");
      ok("the fall-back reports the env/binding destination is unconfigured here", /no destination is configured/.test(d.evidence));
    }

    console.log("\nsource-binding edge shapes (id fallback, secrets, non-binding source, many missing):");
    {
      const env = { SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
      globalThis.fetch = (async (): Promise<Response> => new Response("x", { status: 500 })) as typeof fetch;

      // A downpipe with NO name falls back to its id in the broken-binding label; a Secrets Store
      // binding under source.secrets is also collected; a non-binding source type (cf-config)
      // contributes nothing. SRC_KV_a is present; the secret binding SEC_a is missing -> named.
      const mixed = [
        { config: { id: "dp-noname", source: { type: "kv", binding: "SRC_KV_a", secrets: [{ binding: "SEC_a" }], include: [], exclude: [] } } },
        { config: { id: "dp-cfg", name: "cfgsource", source: { type: "cf-config", accountId: "acc", include: [], exclude: [] } } },
      ];
      const mixedEnv = { SCHEDULER: {} as DurableObjectNamespace, SRC_KV_a: {} } as unknown as Env;
      const mixedReport = await runPreflight(mixedEnv, schedulerRich({ lastTickAt: Date.now() - 60_000, downpipes: mixed }));
      const sbMixed = item(mixedReport, "source-bindings");
      ok("a missing SECRETS-store binding is surfaced as broken", sbMixed.status === "failed" && sbMixed.evidence.includes("SEC_a"));
      ok("the nameless downpipe is labelled by its id (name fell back to id)", sbMixed.evidence.includes("dp-noname"));
      ok("a non-binding (cf-config) source contributes no required binding", !sbMixed.evidence.includes("cfgsource"));
      ok("the present source binding is NOT named as missing", !sbMixed.evidence.includes("SRC_KV_a ->") && !/SRC_KV_a \(/.test(sbMixed.evidence));

      // More than six missing bindings: the evidence caps the list at six and appends "(+N more)".
      const many = Array.from({ length: 9 }, (_, n) => ({
        config: { id: `dp${n}`, name: `dp${n}`, source: { type: "kv", binding: `SRC_MISSING_${n}`, include: [], exclude: [] } },
      }));
      const manyReport = await runPreflight(env, schedulerRich({ lastTickAt: Date.now() - 60_000, downpipes: many }));
      const sbMany = item(manyReport, "source-bindings");
      ok("nine missing bindings FAIL the source-bindings item", sbMany.status === "failed" && /9 of 9/.test(sbMany.evidence));
      ok("the evidence caps the named list and appends a (+N more) tail", /\(\+3 more\)/.test(sbMany.evidence));
    }

    console.log("\na deploy-time S3 destination is verified but the RUNLOG is absent (first run pending):");
    {
      // The destination is configured at DEPLOY (DEST_KIND s3 + DEST_* credentials, no console
      // override and no DEST_R2 binding), so buildDestination takes the S3 env arm. The exists()
      // HEAD on _RECOVERY/RUNLOG answers 404, so the probe is authorised but the RUNLOG is absent:
      // this drives the deploy-set S3 requires arm and the "absent; first run pending" evidence arm,
      // which the console-set and R2 healthy cases never reach.
      globalThis.fetch = (async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
        if ((init?.method ?? "GET") === "HEAD") return new Response(null, { status: 404 });
        return new Response("unexpected", { status: 500 });
      }) as typeof fetch;
      const env = {
        SCHEDULER: {} as DurableObjectNamespace,
        DEST_KIND: "s3",
        DEST_ENDPOINT: "https://bucket.s3.example.com",
        DEST_BUCKET: "archive",
        DEST_REGION: "auto",
        DEST_ACCESS_KEY_ID: "AKIADEPLOY",
        DEST_SECRET_ACCESS_KEY: "deploysecret",
      } as unknown as Env;
      const report = await runPreflight(env, schedulerDouble(Date.now() - 60_000));
      const d = item(report, "destination");
      ok("a reachable deploy-set S3 destination is VERIFIED even with no RUNLOG", d.status === "verified");
      ok("the requires line names the deploy-set S3 bucket (not R2, not console)", /S3-compatible bucket and credentials/.test(d.requires) && !/console/.test(d.requires));
      ok("the evidence reports the RUNLOG absent and the first run pending", /RUNLOG absent; first run pending/.test(d.evidence) && /set at deploy/.test(d.evidence));
      ok("the deploy-set S3 credential values never reach the evidence", !d.evidence.includes("AKIADEPLOY") && !d.evidence.includes("deploysecret"));
    }

    console.log("\na configured source with an empty binding name contributes no required binding:");
    {
      // The collector's add() guards against a non-string or empty binding: a kv source whose binding
      // is the empty string, and a secret whose binding is undefined, must both be skipped rather than
      // recorded as a needed binding. With the only real binding present, the item is VERIFIED and the
      // empty/undefined bindings are absent from the report entirely (no blank "-> downpipe" entry).
      globalThis.fetch = (async (): Promise<Response> => new Response("x", { status: 500 })) as typeof fetch;
      const blanks = [
        { config: { id: "dp-blank", name: "blank", source: { type: "kv", binding: "", secrets: [{ binding: undefined }], include: [], exclude: [] } } },
        { config: { id: "dp-real", name: "real", source: { type: "kv", binding: "SRC_KV_real", include: [], exclude: [] } } },
      ];
      const blankEnv = { SCHEDULER: {} as DurableObjectNamespace, SRC_KV_real: {} } as unknown as Env;
      const blankReport = await runPreflight(blankEnv, schedulerRich({ lastTickAt: Date.now() - 60_000, downpipes: blanks }));
      const sbBlank = item(blankReport, "source-bindings");
      ok("an empty/undefined source binding is not counted as a needed binding", sbBlank.status === "verified" && /all 1 configured source binding/.test(sbBlank.evidence));
      ok("the empty-binding downpipe is not named as a broken dependency", !sbBlank.evidence.includes("blank ->") && !JSON.stringify(sbBlank).includes('"" ->'));
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nPREFLIGHT ENTITLEMENT PROBES PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
