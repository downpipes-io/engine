// Dual control ONLY for RISKY releases. The owner-action dual-control gate over the engine self-update
// (update/apply, update/settle, update/ramp) is consulted ONLY when the signed manifest flags the release
// "migration"/"breaking" AND dual control (requireConfigApproval) is ON. A "routine" release applies without
// a second approver even when dual control is ON; a DRY-RUN is never gated; and with dual control OFF the
// gate is never consulted regardless of risk. This drives the REAL /admin/update/apply route through the
// production handleAdmin (forged-but-correctly-signed Access JWT + in-memory SchedulerDO + a configured,
// SIGNED update channel served by a stubbed fetch), so the route's risk logic is exercised end to end with
// no network and no deploy. Run: node test/validate-update-risk-dualcontrol.ts
//
// HOW THE PROOF AVOIDS A REAL DEPLOY: the apply route's order is account -> load+verify channel -> download
// artefact -> RISK GATE -> (token check) -> deploy. So:
//   - GATED path (migration + ON, first call, NO token): the gate records a pending approval and the route
//     returns 202 ownerActionQueued BEFORE the token check or any deploy: the desired proof.
//   - UNGATED path (routine + ON, OR any risk + OFF, with NO token): the gate is skipped, so the route falls
//     through to the token check and returns 400 "paste the token", NOT a 202, and still no deploy.
// The 202-vs-400 distinction cleanly proves whether the gate was consulted, with zero Cloudflare calls.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { concat, utf8, b64urlEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode } from "../src/crypto/bytes.ts";
import { compareSemver } from "../src/admin/updates.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ----
const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "update-risk-test-aud";
const KID = "update-risk-kid-1";
const OWNER = "owner1@example.com";
const OWNER2 = "owner2@example.com";
const jwtPart = (obj: unknown): string => b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));

// ---- The signed update channel (the engine verifies it under the pinned signer) ----
// The fixture version is coupled to ENGINE_VERSION and the coupling is silent: updateAvailable is
// recommendedVersion !== ENGINE_VERSION, so a fixture version that ever equals the running one turns every
// gate case below into a vacuous pass, so the fixture version is asserted strictly newer than
// ENGINE_VERSION at the top of main().
const CHANNEL_URL = "https://update.example.com/stable.json";
const ARTEFACT_URL = "https://update.example.com/engine-0.4.0.mjs";
const ARTEFACT = utf8("downpipe-engine-bundle-v0.4.0-content");

async function main(): Promise<void> {
  ok(`the fixture update version 0.4.0 is strictly newer than the running ENGINE_VERSION (${ENGINE_VERSION})`, compareSemver("0.4.0", ENGINE_VERSION) === 1);

  // RSA keypair for the Access JWT.
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  // Ed25519 + ML-DSA signer for the channel; pin its public as UPDATE_SIGNER_PUBLIC.
  const edSeed = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSeed);
  const edPrivate = await crypto.subtle.importKey("pkcs8", concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), edSeed), "Ed25519", false, ["sign"]);
  const mldsa = mldsaKeygen();
  const signerPublic = b64urlEncode(concat(edPublic, new Uint8Array(mldsa.publicKey)));

  const artefactHash = hexEncode(await sha384(ARTEFACT));

  // Build + sign a channel for a given risk class.
  async function signedChannel(riskClass: string): Promise<{ channel: Uint8Array; sig: Uint8Array }> {
    const channel = utf8(JSON.stringify({
      channel: "stable",
      recommendedVersion: "0.4.0",
      artefacts: [{ version: "0.4.0", url: ARTEFACT_URL, sha384: artefactHash, riskClass }],
    }));
    const sig = await hybridSign(edPrivate, mldsa.secretKey, channel);
    return { channel, sig };
  }

  // The stubbed network: serves the Access JWKS, the signed channel (+ .sig), the artefact bytes, and a
  // benign Cloudflare deployments LIST (so a DRY-RUN, which records a rollback target via
  // currentLiveVersionId, succeeds without escaping). The CF deployments-CREATE (the actual promote) is
  // never reached by these proofs (the gate 202s, or the token check 400s, before any deploy); if it ever
  // were, the stub would surface it as an unexpected fetch. currentRisk lets each test swap the channel's
  // risk class without rebuilding the env.
  let current: { channel: Uint8Array; sig: Uint8Array } = await signedChannel("migration");
  // Record any unexpected outbound fetch so a future route round-trip is a NAMED gap rather than an opaque
  // crash swallowed by main().catch. Unexpected URLs get a structured 404 diagnostic, not a throw.
  const unexpectedFetches: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? "GET";
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    if (url === CHANNEL_URL) return new Response(new Uint8Array(current.channel), { status: 200 });
    if (url === CHANNEL_URL + ".sig") return new Response(b64urlEncode(current.sig) + "\n", { status: 200 });
    if (url === ARTEFACT_URL) return new Response(ARTEFACT, { status: 200 });
    // GET deployments (record the rollback target on dry-run): newest-first, the live version is v-live.
    if (method === "GET" && /\/workers\/scripts\/.+\/deployments$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { deployments: [{ id: "d-1", versions: [{ version_id: "v-live" }] }] } }), { status: 200 });
    }
    unexpectedFetches.push(`${method} ${url}`);
    return new Response(JSON.stringify({ error: "unexpected network fetch in test", method, url }), { status: 404, headers: { "content-type": "application/json" } });
  }) as typeof fetch;

  try {

  const sched = makeScheduler();
  // CF_ACCOUNT_ID satisfies resolveEngineAccount without a DO discovery config. The channel vars make the
  // engine "configured + verified". WORKER_NAME is the script the (never-reached) deploy would target.
  // DEST_R2 is a MINIMAL fake binding (0.1.5 destination gate, design §4): its presence alone satisfies
  // "a destination is configured" (buildDestination constructs an R2Destination over it without ever
  // calling a method on it here -- this suite never reaches the canary/preflight machinery that would),
  // so the risk-gate proofs below are undisturbed by the new pre-token destination check. RESERVED_BINDINGS
  // excludes it from ever being offered as a downpipe source.
  const baseEnv = (): Env => ({
    ...sched.env,
    CF_ACCESS_TEAM_DOMAIN: TEAM,
    CF_ACCESS_AUD: AUD,
    CF_ACCOUNT_ID: "acct-test",
    WORKER_NAME: "downpipe-engine",
    UPDATE_CHANNEL_URL: CHANNEL_URL,
    UPDATE_SIGNER_PUBLIC: signerPublic,
    DEST_R2: {},
  }) as unknown as Env;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  async function apply(email: string, body: unknown): Promise<Response> {
    const assertion = await tokenFor(email);
    return handleAdmin(new Request("https://engine.example/admin/update/apply", { method: "POST", headers: { "cf-access-jwt-assertion": assertion, "content-type": "application/json" }, body: JSON.stringify(body) }), baseEnv());
  }
  // setGate: arm (true) is immediate; disarm (false) when ON takes a second-owner approval (the dual-control
  // off switch is itself gated). The helper does the full disarm dance so it leaves the gate OFF.
  async function setGate(on: boolean): Promise<void> {
    const assertion = await tokenFor(OWNER);
    const resp = await handleAdmin(new Request("https://engine.example/admin/config/approval-policy", { method: "POST", headers: { "cf-access-jwt-assertion": assertion, "content-type": "application/json" }, body: JSON.stringify({ requireConfigApproval: on }) }), baseEnv());
    if (on) return;
    if (resp.status !== 202) return; // already off
    const id = ((await resp.json()) as { id?: string }).id ?? "";
    const a2 = await tokenFor(OWNER2);
    await handleAdmin(new Request(`https://engine.example/admin/owner-actions/${id}/approve`, { method: "POST", headers: { "cf-access-jwt-assertion": a2 } }), baseEnv());
  }
  const ownerActionCount = (): number => sched.storage.keysWithPrefix("owneraction:").length;

  // Bootstrap OWNER (first Access caller) + grant OWNER2 the owner role so it can approve a disarm (the
  // dual-control off switch is itself gated and needs a DISTINCT owner approver).
  {
    const a = await tokenFor(OWNER);
    await handleAdmin(new Request("https://engine.example/admin/roles", { method: "POST", headers: { "cf-access-jwt-assertion": a, "content-type": "application/json" }, body: JSON.stringify({ email: OWNER2, role: "owner" }) }), baseEnv());
  }

  // ============================ PROOFS ============================

  // ---- 0. Sanity: with the gate OFF, a DRY-RUN of a migration release verifies + plans (never gated) ----
  current = await signedChannel("migration");
  await setGate(false);
  {
    const r = await apply(OWNER, { dryRun: true });
    const j = (await r.json()) as { outcome?: string };
    ok("dry-run (gate OFF) -> a dry-run outcome (verified + planned, never gated, no deploy)", r.status === 200 && j.outcome === "dry-run");
  }

  // ---- 1. MIGRATION + gate ON + no token -> 202 ownerActionQueued (GATED) ----
  current = await signedChannel("migration");
  await setGate(true);
  {
    const before = ownerActionCount();
    const r = await apply(OWNER, { dryRun: false }); // NO token
    ok("MIGRATION + dual-control ON + no token -> 202 (second-owner approval required)", r.status === 202);
    const j = (await r.json()) as { ownerActionQueued?: boolean };
    ok("the 202 is an ownerActionQueued (a pending approval was recorded)", j.ownerActionQueued === true && ownerActionCount() === before + 1);
  }

  // ---- 2. BREAKING + gate ON + no token -> 202 (also gated) ----
  current = await signedChannel("breaking");
  {
    const r = await apply(OWNER, { dryRun: false });
    ok("BREAKING + dual-control ON + no token -> 202 (gated)", r.status === 202);
  }

  // ---- 3. ROUTINE + gate ON + no token -> 400 token-required, NOT 202 (gate SKIPPED) ----
  current = await signedChannel("routine");
  {
    const before = ownerActionCount();
    const r = await apply(OWNER, { dryRun: false }); // NO token
    ok("ROUTINE + dual-control ON + no token -> NOT 202 (gate skipped for routine)", r.status !== 202);
    ok("ROUTINE + dual-control ON falls through to the token requirement (400)", r.status === 400);
    const j = (await r.json()) as { error?: string };
    ok("the routine 400 is the token prompt (the deploy would proceed once tokened, un-gated)", /one-shot|deploy token/i.test(j.error ?? ""));
    ok("ROUTINE recorded NO pending owner action (the gate was never consulted)", ownerActionCount() === before);
  }

  // ---- 4. DRY-RUN of a MIGRATION release with the gate ON -> never 202 (dry-run is never gated) ----
  current = await signedChannel("migration");
  {
    const r = await apply(OWNER, { dryRun: true });
    const j = (await r.json()) as { outcome?: string };
    ok("MIGRATION dry-run with gate ON -> NOT 202 (a dry-run is never gated)", r.status !== 202);
    ok("MIGRATION dry-run with gate ON -> a dry-run outcome (verify + plan only)", r.status === 200 && j.outcome === "dry-run");
  }

  // ---- 5. MIGRATION + gate OFF + no token -> 400 token-required, NOT 202 (gate never consulted when OFF) ----
  current = await signedChannel("migration");
  await setGate(false);
  {
    const before = ownerActionCount();
    const r = await apply(OWNER, { dryRun: false }); // NO token
    ok("MIGRATION + dual-control OFF + no token -> NOT 202 (gate never consulted when OFF)", r.status !== 202);
    ok("MIGRATION + dual-control OFF -> token prompt (400), inline path", r.status === 400);
    ok("dual-control OFF records NO pending owner action", ownerActionCount() === before);
  }

  ok("no unexpected outbound fetch occurred during the proofs", unexpectedFetches.length === 0);
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log(failures === 0 ? "\nRISK-DUAL-CONTROL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
