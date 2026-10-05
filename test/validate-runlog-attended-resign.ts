// The ATTENDED RUNLOG re-sign (admin/router-runlog.ts) is the one way past a destination RUNLOG whose signature
// does not verify, and it is never automatic.
//
// This validator stands up a real Owner on a passkey (real session, real step-up), an env-backed R2
// destination double holding a real signed RUNLOG, and an all-events webhook, then drives:
//   - GET /admin/runlog/signature: what does not verify (the object, the signer fingerprint it was checked
//     under, the digest, the highest index, the last good index) and whether a re-sign can help;
//   - POST /admin/runlog/resign: refused without step-up (401), refused for a digest that does not match the
//     stored bytes, then on the confirmed digest with step-up it signs exactly those bytes, writes a
//     runlog-resigned audit row and raises the runlog-resigned alert (warning) to the webhook;
//   - the refusals a signature cannot repair: a RUNLOG already verified, a chain anomaly, a RUNLOG below the
//     last good index;
//   - a re-key hand-over left pending: the route finishes it under the held old public key, and the held key is
//     discarded when nothing else is pending;
//   - a non-Owner is refused.
// Nothing in the engine calls the re-sign on its own: a seal over a RUNLOG with no .sig never restores it.
//
// Run: node test/validate-runlog-attended-resign.ts

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { handleAdmin } from "../src/admin/router.ts";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, SESSION_TTL_MS, STEPUP_FRESH_MS, signSession } from "../src/admin/session.ts";
import { b64urlDecode, b64urlEncode, concat, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { type HybridVerifier, hybridVerify } from "../src/crypto/sign.ts";
import { buildDestination } from "../src/dest/factory.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { parseRunlog, type RunlogEntry, signRunlog } from "../src/format/writer.ts";
import { signerFingerprint } from "../src/format/writer-root.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { encodeVerifier } from "../src/sched/rekey-handover.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { memoryBucket } from "./lib/memory-r2.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { type Authenticator, buildAttestation, challengeFor, challengeIdFor, enrolBootstrapOwner, extractSessionCookie, grantRoleViaToken, loginBegin, loginFinish, type MockStorage, makeAuthenticator, makeScheduler, ORIGIN, registerBegin, registerFinish, signAssertion } from "./validate-passkey-harness.ts";

const OWNER = "alice@acme.example";
const CSRF_VALUE = "csrf-runlog-resign";
const HOOK_URL = "https://hooks.example.com/all-events";
const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const RUNLOG_PENDING = "_RECOVERY/RUNLOG.sig.pending";
const DP = "dp_resign_attended";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FE${n}`;

const hookPosts: string[] = [];
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const doh = dohReply(input);
  if (doh !== null) return doh;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  if (url === HOOK_URL) {
    hookPosts.push(typeof init?.body === "string" ? init.body : "");
    return new Response("ok", { status: 200 });
  }
  throw new Error(`unexpected network fetch in test: ${url}`);
}) as typeof fetch;

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));
const entry = (n: number, prev: string | null): RunlogEntry => ({ index: n, runId: R(n), downpipeId: DP, time: `2026-10-01T0${n}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" });

type Reply = { status: number; body: Record<string, unknown> };
async function admin(env: Env, method: string, path: string, cookie: string, body?: unknown, stepUp?: string): Promise<Reply> {
  const headers: Record<string, string> = { "content-type": "application/json", cookie: `${cookie}; ${CSRF_COOKIE_NAME}=${CSRF_VALUE}`, "x-downpipes-csrf": CSRF_VALUE, origin: ORIGIN, "CF-Connecting-IP": "198.51.100.23" };
  if (stepUp !== undefined) headers["x-downpipes-stepup"] = stepUp;
  const resp = await handleAdmin(new Request(`https://engine.example/admin${path}`, body === undefined ? { method, headers } : { method, headers, body: JSON.stringify(body) }), env);
  const text = await resp.text();
  let parsed: Record<string, unknown> = {};
  try {
    const v = JSON.parse(text) as unknown;
    parsed = Array.isArray(v) ? { list: v } : v !== null && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    parsed = { text };
  }
  return { status: resp.status, body: parsed };
}
async function signIn(env: Env, key: Authenticator, email: string): Promise<string> {
  const begin = await loginBegin(env, email);
  const assertion = await signAssertion(key, challengeFor(begin));
  key.signCount++;
  const finish = await loginFinish(env, challengeIdFor(begin), assertion);
  const cookie = extractSessionCookie(finish.setCookie);
  if (finish.status !== 200 || cookie === null) throw new Error(`sign-in failed: ${finish.status}`);
  return cookie;
}
async function freshStepUp(env: Env, key: Authenticator, cookie: string): Promise<string> {
  const begin = await admin(env, "POST", "/stepup/begin", cookie, {});
  const pk = begin.body.publicKey as { challenge?: string } | undefined;
  if (begin.status !== 200 || typeof pk?.challenge !== "string") throw new Error(`step-up begin failed: ${begin.status}`);
  const assertion = await signAssertion(key, pk.challenge);
  key.signCount++;
  const finish = await admin(env, "POST", "/stepup/finish", cookie, { challengeId: begin.body.challengeId, credential: assertion });
  if (finish.status !== 200 || typeof finish.body.stepUpToken !== "string") throw new Error(`step-up finish failed: ${finish.status}`);
  return finish.body.stepUpToken;
}

interface Estate {
  env: Env;
  storage: MockStorage;
  stub: DurableObjectStub;
  key: Authenticator;
  cookie: string;
  store: Map<string, Uint8Array>;
  dest: Destination;
  signer: string;
  v: HybridVerifier;
}
async function estate(): Promise<Estate> {
  const { env, storage, stub } = makeScheduler();
  const { bucket, store } = memoryBucket();
  const signer = signerB64();
  Object.assign(env as unknown as Record<string, unknown>, { DEST_KIND: "r2", DEST_R2: bucket, SIGNER_PRIVATE: signer });
  const key = await makeAuthenticator("ES256");
  if ((await enrolBootstrapOwner(env, key, OWNER)).status !== 200) throw new Error("bootstrap of the Owner failed");
  const cookie = await signIn(env, key, OWNER);
  const dest = await buildDestination(env);
  const s = await loadSigner(signer);
  await appendRunlog(dest, s, entry(1, null));
  await appendRunlog(dest, s, entry(2, R(1)));
  const ch = await admin(env, "POST", "/notify/channels", cookie, { kind: "webhook", name: "All events", url: HOOK_URL }, await freshStepUp(env, key, cookie));
  const channelId = (ch.body.channel as { id?: string } | undefined)?.id ?? (ch.body.id as string | undefined);
  await admin(env, "POST", "/notify/rules", cookie, { scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [channelId], enabled: true }, await freshStepUp(env, key, cookie));
  return { env, storage, stub, key, cookie, store, dest, signer, v: verifierFrom(s) };
}

async function sigVerifies(store: Map<string, Uint8Array>, v: HybridVerifier): Promise<boolean> {
  const body = store.get(RUNLOG);
  const sig = store.get(RUNLOG_SIG);
  if (!body || !sig) return false;
  try {
    return await hybridVerify(v, body, b64urlDecode(new TextDecoder().decode(sig).trim()));
  } catch {
    return false;
  }
}
async function audit(e: Estate): Promise<Array<Record<string, unknown>>> {
  return ((await admin(e.env, "GET", "/audit?limit=200", e.cookie)).body.events ?? []) as Array<Record<string, unknown>>;
}

async function main(): Promise<void> {
  ok("POST /runlog/resign is a step-up route", STEPUP_SUBS.has("/runlog/resign"));
  // Never automatic: the attended signing function is called from the attended route and nowhere else.
  const SRC = fileURLToPath(new URL("../src", import.meta.url));
  const callers: string[] = [];
  const walk = (dir: string): void => {
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (p.endsWith(".ts") && /\bresignRunlogAttended\s*\(/.test(readFileSync(p, "utf8")) && !p.endsWith("seal/runlog-handover.ts")) callers.push(p.slice(SRC.length + 1));
    }
  };
  walk(SRC);
  ok(`only the attended route calls resignRunlogAttended (${callers.join(", ")})`, callers.length === 1 && callers[0] === "admin/router-runlog.ts", callers);

  console.log("\n-- 1. a deleted .sig: shown, refused without step-up and on a stale digest, then re-signed --");
  {
    const e = await estate();
    const clean = await admin(e.env, "GET", "/runlog/signature?destinationId=", e.cookie);
    ok("CONTROL: a clean RUNLOG reads verified and cannot be re-signed", clean.status === 200 && clean.body.state === "verified" && clean.body.canResign === false, clean.body);
    await e.dest.delete(RUNLOG_SIG);
    await e.dest.delete(RUNLOG_PENDING);
    const before = e.store.get(RUNLOG)!.slice();
    const digest = hexEncode(await sha384(before));
    const g = await admin(e.env, "GET", "/runlog/signature?destinationId=", e.cookie);
    ok("GET names the object and that the .sig is absent", g.body.object === RUNLOG && g.body.signatureObject === "_RECOVERY/RUNLOG.sig (absent)" && g.body.state === "sig-absent", g.body);
    ok("GET names the key it checked under (the current signer's fingerprint)", g.body.currentSigner === (await signerFingerprint(e.v)), g.body.currentSigner);
    ok("GET shows the digest of the stored bytes, the highest index and the last good index", g.body.digest === digest && g.body.maxIndex === 2 && g.body.lastGoodIndex === null, g.body);
    ok("GET says a re-sign can help", g.body.canResign === true, g.body);

    // Nothing automatic: a later RUNLOG write does not restore the .sig on its own (step 4 refuses it; until
    // then the seal still re-signs, so this asserts only the route itself is never called by the engine).
    // A session whose sign-in is older than the step-up window, so the gate demands a fresh factor.
    const doKey = b64urlDecode((await e.storage.get<{ key: string }>("passkeySessionKey"))!.key);
    const now = Date.now();
    const staleCookie = `${SESSION_COOKIE_NAME}=${await signSession(doKey, { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), epoch: 0, slide: { iat: now - (STEPUP_FRESH_MS + 60_000), exp: now + SESSION_TTL_MS } }, now)}`;
    const noStep = await admin(e.env, "POST", "/runlog/resign", staleCookie, { destinationId: "", digest });
    ok(`without step-up the re-sign is refused (got ${noStep.status})`, noStep.status === 401);
    ok("...and nothing was signed", !e.store.has(RUNLOG_SIG));
    const stale = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest: "0".repeat(96) }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`a digest that is not the stored bytes is refused (got ${stale.status})`, stale.status === 409 && !e.store.has(RUNLOG_SIG), stale.body);
    hookPosts.length = 0;
    const done = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`with step-up and the confirmed digest the RUNLOG is re-signed (got ${done.status})`, done.status === 200 && done.body.outcome === "re-signed", done.body);
    ok("the .sig now verifies under the current signer", await sigVerifies(e.store, e.v));
    const after = e.store.get(RUNLOG)!;
    ok("the RUNLOG bytes are exactly the ones confirmed", after.length === before.length && after.every((b, i) => b === before[i]));
    const row = (await audit(e)).find((a) => a.action === "runlog-resigned");
    const t = row?.target as Record<string, unknown> | undefined;
    ok("a runlog-resigned audit row records the destination, the state, the digest prefix and the index", row?.outcome === "success" && t?.state === "sig-absent" && t.digest === digest.slice(0, 24) && t.maxIndex === 2 && JSON.stringify(t.destinationIds) === '[""]', row);
    const alerts = hookPosts.filter((b) => b.includes("runlog-resigned"));
    ok(`the runlog-resigned alert reached the all-events webhook at warning (${alerts.length})`, alerts.length === 1 && /warning/.test(alerts[0] ?? ""), hookPosts.map((p) => p.slice(0, 120)));
    const again = await admin(e.env, "GET", "/runlog/signature?destinationId=", e.cookie);
    ok("afterwards GET reads verified", again.body.state === "verified");
  }

  console.log("\n-- 2. what a signature cannot repair is refused --");
  {
    const e = await estate();
    // A chain anomaly: entry 2 points at a run that is not there. Written with a valid signature under a
    // DIFFERENT key, so it does not verify under the current one.
    const other = await loadSigner(signerB64());
    const bad = parseRunlog(e.store.get(RUNLOG)!).map((x) => (x.runId === R(2) ? { ...x, prevRunId: R(9) } : x));
    const signed = await signRunlog(bad, other.edPrivate, other.mldsaSecret);
    await e.dest.put(RUNLOG, signed.runlog);
    await e.dest.put(RUNLOG_SIG, new TextEncoder().encode(b64urlEncode(signed.sig)));
    await e.dest.delete(RUNLOG_PENDING);
    const g = await admin(e.env, "GET", "/runlog/signature?destinationId=", e.cookie);
    ok("a chain anomaly is shown and cannot be re-signed", g.body.state === "sig-invalid" && typeof g.body.chainAnomaly === "string" && g.body.canResign === false, g.body);
    const r = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest: g.body.digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`...and POST refuses it (got ${r.status})`, r.status === 409 && !(await sigVerifies(e.store, e.v)), r.body);

    // Below the last good index: the floor says index 5 was confirmed here, the RUNLOG stops at 2.
    const fresh = await signRunlog([entry(1, null), entry(2, R(1))], other.edPrivate, other.mldsaSecret);
    await e.dest.put(RUNLOG, fresh.runlog);
    // The floor says index 5 was confirmed at this (env-backed) destination; the RUNLOG stops at 2.
    await e.storage.put("runlogFloor", { "": { index: 5 } });
    const g2 = await admin(e.env, "GET", "/runlog/signature?destinationId=", e.cookie);
    ok("GET shows the last good index from the floor", g2.body.lastGoodIndex === 5, g2.body);
    ok("a RUNLOG below the last good index cannot be re-signed", g2.body.canResign === false && /below the last good index/.test(String(g2.body.refusal)), g2.body);
    const r2 = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest: g2.body.digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`...and POST refuses it (got ${r2.status})`, r2.status === 409 && !(await sigVerifies(e.store, e.v)), r2.body);
  }

  console.log("\n-- 3. a pending re-key hand-over is finished under the held old public key --");
  {
    const e = await estate();
    const old = await loadSigner(signerB64());
    // The RUNLOG is signed under the OLD key (a late old-version seal), and the DO holds that public key.
    const late = await signRunlog(parseRunlog(e.store.get(RUNLOG)!), old.edPrivate, old.mldsaSecret);
    await e.dest.put(RUNLOG_SIG, new TextEncoder().encode(b64urlEncode(late.sig)));
    await e.dest.put(RUNLOG, late.runlog);
    await e.dest.delete(RUNLOG_PENDING);
    await e.stub.fetch("https://scheduler.internal/rekey-handover/begin", { method: "POST", body: JSON.stringify({ oldVerifier: encodeVerifier(verifierFrom(old)) }) });
    await e.stub.fetch("https://scheduler.internal/rekey-handover/settle", { method: "POST", body: JSON.stringify({ pending: [""] }) });
    const g = await admin(e.env, "GET", "/runlog/signature?destinationId=", e.cookie);
    ok("GET shows the RUNLOG verifies under the held old key, and the hand-over is pending", g.body.state === "sig-invalid" && g.body.verifiesUnderHeldOld === true && g.body.handoverPending === true && g.body.heldOldSigner === (await signerFingerprint(verifierFrom(old))), g.body);
    const r = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest: g.body.digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`POST finishes the hand-over (got ${r.status}, state ${String(r.body.state)})`, r.status === 200 && r.body.state === "held-old" && (await sigVerifies(e.store, e.v)), r.body);
    const h = (await (await e.stub.fetch("https://scheduler.internal/rekey-handover")).json()) as { open?: boolean };
    ok("with nothing else pending the held old key is discarded, and the audit says so", h.open === false && (await audit(e)).some((a) => a.action === "runlog-handover" && (a.target as { op?: string }).op === "held-key-discarded"));
  }

  console.log("\n-- 4. a non-Owner is refused --");
  {
    const e = await estate();
    const viewer = "carol@acme.example";
    const vkey = await makeAuthenticator("ES256");
    const invite = await grantRoleViaToken(e.env, viewer, "viewer");
    const begin = await registerBegin(e.env, viewer, { inviteToken: invite, origin: ORIGIN });
    await registerFinish(e.env, viewer, await buildAttestation(vkey, challengeFor(begin)), { inviteToken: invite, origin: ORIGIN });
    const vcookie = await signIn(e.env, vkey, viewer);
    const g = await admin(e.env, "GET", "/runlog/signature?destinationId=", vcookie);
    ok(`a Viewer cannot read the re-sign view (got ${g.status})`, g.status === 403, g.body);
    await e.dest.delete(RUNLOG_SIG);
    const digest = hexEncode(await sha384(e.store.get(RUNLOG)!));
    const r = await admin(e.env, "POST", "/runlog/resign", vcookie, { destinationId: "", digest }, await freshStepUp(e.env, vkey, vcookie));
    ok(`a Viewer cannot re-sign, even after step-up (got ${r.status})`, r.status === 403 && !e.store.has(RUNLOG_SIG), r.body);
  }

  console.log(failures === 0 ? "\nRUNLOG ATTENDED RESIGN PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
