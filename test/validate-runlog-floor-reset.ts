// The ATTENDED floor reset (admin/router-runlog.ts GET /runlog/floor, POST /runlog/floor/reset) is the way out
// for an env destination repointed by redeploy: the scheduler cannot see the repoint, keeps the old floor, and
// the RUNLOG writers then refuse the new bucket (absent-above-floor, or below-floor for an older RUNLOG).
//
// This validator stands up a real Owner and Viewer on passkeys (real step-up), an env-backed R2 destination
// double and an all-events webhook, then drives:
//   - without the action the seal stays refused, for an empty bucket and for one with an older RUNLOG;
//   - the evidence: the old floor, the bucket it points at, and why the fresh log is refused;
//   - refused without step-up, for a Viewer, and for a floor that is not the one shown;
//   - the reset writes its audit row and alert, and unblocks exactly the stuck case; to 0 for an empty bucket, and
//     to the RUNLOG's own highest index for an older one, so a later replay below that is still refused;
//   - a RUNLOG that does not verify is never helped, and nothing is signed;
//   - CONTROL: a destination the floor does not block offers no reset;
//   - an S3 env destination is named by its endpoint host and bucket, with no credential.
//
// Run: node test/validate-runlog-floor-reset.ts

import { handleAdmin } from "../src/admin/router.ts";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, SESSION_TTL_MS, STEPUP_FRESH_MS, signSession } from "../src/admin/session.ts";
import { b64urlDecode, b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { type HybridVerifier, hybridVerify } from "../src/crypto/sign.ts";
import { buildDestination } from "../src/dest/factory.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { parseRunlog, type RunlogEntry, signRunlog } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { appendRunlog, RunlogIntegrityError, type RunlogLock } from "../src/seal/pipeline.ts";
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
const DP = "dp_floor_reset";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FJ${n}`;

const hookPosts: string[] = [];
const S3_HOST = "s3.floor.example";
const S3_KEY_ID = "AKIAFLOORRESETKEYID01";
const s3Reads: string[] = [];
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const doh = dohReply(input);
  if (doh !== null) return doh;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  if (url === HOOK_URL) {
    hookPosts.push(typeof init?.body === "string" ? init.body : "");
    return new Response("ok", { status: 200 });
  }
  // The S3 bucket of section 5 holds no object: every read is a 404.
  if (new URL(url).host === S3_HOST) {
    s3Reads.push(url);
    return new Response("<Error><Code>NoSuchKey</Code></Error>", { status: 404, headers: { "content-type": "application/xml" } });
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


// The writers read the destination's floor through their lock, as runlogLockVia does from the scheduler DO.
function lockOf(e: Estate): RunlogLock {
  return {
    acquire: async () => "tok",
    release: async () => {},
    floor: async () => {
      const r = (await (await e.stub.fetch("https://scheduler.internal/runlog-floor")).json()) as { floor?: number | null };
      return typeof r.floor === "number" ? r.floor : undefined;
    },
  };
}
async function sealNext(e: Estate, n: number, prev: string | null): Promise<string> {
  try {
    await appendRunlog(e.dest, await loadSigner(e.signer), entry(n, prev), lockOf(e), { relinkLocalPrev: true });
    return "ok";
  } catch (err) {
    return err instanceof RunlogIntegrityError ? `refused ${err.reason}` : `threw ${(err as Error).message.slice(0, 80)}`;
  }
}
// repoint simulates an env destination repointed by redeploy to another bucket: the floor (5) stays, and the new
// bucket holds no RUNLOG ("empty") or an older, validly signed one of two entries ("older").
async function repoint(e: Estate, to: "empty" | "older"): Promise<void> {
  await e.storage.put("runlogFloor", { "": { index: 5 } });
  for (const k of [...e.store.keys()]) if (k.startsWith("_RECOVERY/RUNLOG")) await e.dest.delete(k);
  if (to === "older") {
    const s = await loadSigner(e.signer);
    await appendRunlog(e.dest, s, entry(1, null));
    await appendRunlog(e.dest, s, entry(2, R(1)));
  }
}
function staleCookieFor(e: Estate): Promise<string> {
  return (async () => {
    const doKey = b64urlDecode((await e.storage.get<{ key: string }>("passkeySessionKey"))!.key);
    const now = Date.now();
    return `${SESSION_COOKIE_NAME}=${await signSession(doKey, { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), epoch: 0, slide: { iat: now - (STEPUP_FRESH_MS + 60_000), exp: now + SESSION_TTL_MS } }, now)}`;
  })();
}
async function viewerCookie(e: Estate): Promise<{ cookie: string; key: Authenticator }> {
  const viewer = "carol@acme.example";
  const vkey = await makeAuthenticator("ES256");
  const invite = await grantRoleViaToken(e.env, viewer, "viewer");
  const begin = await registerBegin(e.env, viewer, { inviteToken: invite, origin: ORIGIN });
  await registerFinish(e.env, viewer, await buildAttestation(vkey, challengeFor(begin)), { inviteToken: invite, origin: ORIGIN });
  return { cookie: await signIn(e.env, vkey, viewer), key: vkey };
}

async function main(): Promise<void> {
  ok("POST /runlog/floor/reset is a step-up route", STEPUP_SUBS.has("/runlog/floor/reset"));

  console.log("\n-- 1. an env destination repointed to an EMPTY bucket --");
  {
    const e = await estate();
    await repoint(e, "empty");
    const before = await sealNext(e, 6, null);
    ok(`without the action the seal stays refused (${before})`, before === "refused absent-above-floor");
    const g = await admin(e.env, "GET", "/runlog/floor?destinationId=", e.cookie);
    ok("GET shows the old floor, the bucket it points at, and why the fresh log is refused", g.status === 200 && g.body.floor === 5 && /R2 binding DEST_R2/.test(String(g.body.bucket)) && /absent while index 5/.test(String(g.body.refusal)) && g.body.canReset === true && g.body.resetTo === 0, g.body);
    const stale = await staleCookieFor(e);
    const noStep = await admin(e.env, "POST", "/runlog/floor/reset", stale, { destinationId: "", expectFloor: 5, digest: "absent" });
    ok(`without step-up it is refused (got ${noStep.status}) and the floor is unchanged`, noStep.status === 401 && (await lockOf(e).floor!()) === 5);
    const v = await viewerCookie(e);
    const vr = await admin(e.env, "POST", "/runlog/floor/reset", v.cookie, { destinationId: "", expectFloor: 5, digest: "absent" }, await freshStepUp(e.env, v.key, v.cookie));
    ok(`a Viewer is refused even after step-up (got ${vr.status})`, vr.status === 403 && (await lockOf(e).floor!()) === 5);
    const wrong = await admin(e.env, "POST", "/runlog/floor/reset", e.cookie, { destinationId: "", expectFloor: 4, digest: "absent" }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`a floor that is not the one shown is refused (got ${wrong.status})`, wrong.status === 409 && (await lockOf(e).floor!()) === 5);
    hookPosts.length = 0;
    const r = await admin(e.env, "POST", "/runlog/floor/reset", e.cookie, { destinationId: "", expectFloor: 5, digest: "absent" }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`the Owner resets it after step-up (got ${r.status})`, r.status === 200 && r.body.oldFloor === 5 && r.body.newFloor === 0, r.body);
    ok("the floor is now 0 (no pin)", (await lockOf(e).floor!()) === undefined);
    const row = (await audit(e)).find((a) => a.action === "runlog-floor-reset");
    const t = row?.target as Record<string, unknown> | undefined;
    ok("a runlog-floor-reset audit row records the old and new floor and the reason", t?.op === "floor-reset" && t.lastGoodIndex === 5 && t.maxIndex === 0 && t.state === "absent-above-floor", row);
    const alerts = hookPosts.filter((b) => b.includes("runlog-floor-reset"));
    ok(`the runlog-floor-reset alert reached the all-events webhook at warning (${alerts.length})`, alerts.length === 1 && /warning/.test(alerts[0] ?? ""));
    const after = await sealNext(e, 6, null);
    ok(`the stuck case is unblocked: the seal creates the RUNLOG (${after})`, after === "ok" && (await sigVerifies(e.store, e.v)) && parseRunlog(e.store.get(RUNLOG)!).some((x) => x.runId === R(6)));
  }

  console.log("\n-- 2. an env destination repointed to a bucket with an OLDER RUNLOG --");
  {
    const e = await estate();
    await repoint(e, "older");
    ok("without the action the seal stays refused (below-floor)", (await sealNext(e, 6, R(2))) === "refused below-floor");
    const g = await admin(e.env, "GET", "/runlog/floor?destinationId=", e.cookie);
    ok("GET says the RUNLOG's highest index (2) is below the floor (5) and offers a reset to 2", g.body.maxIndex === 2 && /below the 5/.test(String(g.body.refusal)) && g.body.resetTo === 2, g.body);
    const r = await admin(e.env, "POST", "/runlog/floor/reset", e.cookie, { destinationId: "", expectFloor: 5, digest: g.body.digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`the reset moves the floor to the RUNLOG's own highest index, not to 0 (got ${String(r.body.newFloor)})`, r.status === 200 && (await lockOf(e).floor!()) === 2, r.body);
    ok("the seal now appends", (await sealNext(e, 6, R(2))) === "ok");
    ok("...and a RUNLOG later replayed below the new floor is still refused", await (async () => {
      const older = await signRunlog([entry(1, null)], (await loadSigner(e.signer)).edPrivate, (await loadSigner(e.signer)).mldsaSecret);
      await e.dest.put(RUNLOG, older.runlog);
      await e.dest.put(RUNLOG_SIG, new TextEncoder().encode(b64urlEncode(older.sig)));
      await e.dest.delete(RUNLOG_PENDING);
      return (await sealNext(e, 7, R(6))) === "refused below-floor";
    })());
  }

  console.log("\n-- 3. it never helps a RUNLOG that does not verify, and never signs --");
  {
    const e = await estate();
    await repoint(e, "older");
    const before = e.store.get(RUNLOG)!.slice();
    await e.dest.delete(RUNLOG_SIG);
    await e.dest.delete(RUNLOG_PENDING);
    const g = await admin(e.env, "GET", "/runlog/floor?destinationId=", e.cookie);
    ok("GET offers no reset, and points to the signature view", g.body.canReset === false && /does not verify/.test(String(g.body.note)), g.body);
    const r = await admin(e.env, "POST", "/runlog/floor/reset", e.cookie, { destinationId: "", expectFloor: 5, digest: g.body.digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`POST refuses (got ${r.status}); the floor is unchanged and nothing is signed`, r.status === 409 && (await lockOf(e).floor!()) === 5 && !e.store.has(RUNLOG_SIG) && e.store.get(RUNLOG)!.every((b, i) => b === before[i]));
  }

  console.log("\n-- 4. CONTROL: a destination the floor does not block offers no reset --");
  {
    const e = await estate();
    await e.storage.put("runlogFloor", { "": { index: 2 } });
    const g = await admin(e.env, "GET", "/runlog/floor?destinationId=", e.cookie);
    ok("GET reports no refusal and no reset", g.body.canReset === false && g.body.refusal === null, g.body);
    const r = await admin(e.env, "POST", "/runlog/floor/reset", e.cookie, { destinationId: "", expectFloor: 2, digest: g.body.digest }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`POST refuses (got ${r.status}) and the floor stays 2`, r.status === 409 && (await lockOf(e).floor!()) === 2);
  }

  console.log("\n-- 5. the bucket an S3 env destination points at is named by its endpoint host, with no credential --");
  {
    const { env } = makeScheduler();
    Object.assign(env as unknown as Record<string, unknown>, { DEST_KIND: "s3", DEST_ENDPOINT: `https://${S3_HOST}/tenant/path`, DEST_BUCKET: "archive-bkt", DEST_REGION: "auto", DEST_ACCESS_KEY_ID: S3_KEY_ID, DEST_SECRET_ACCESS_KEY: "floor-reset-secret-access-key-0123456789", SIGNER_PRIVATE: signerB64() });
    const key = await makeAuthenticator("ES256");
    if ((await enrolBootstrapOwner(env, key, OWNER)).status !== 200) throw new Error("bootstrap of the Owner failed");
    const cookie = await signIn(env, key, OWNER);
    const g = await admin(env, "GET", "/runlog/floor?destinationId=", cookie);
    ok("GET names the endpoint host and bucket, not the path", g.status === 200 && g.body.bucket === `${S3_HOST}/archive-bkt (deploy-time destination)`, g.body);
    ok("the bucket was read for the RUNLOG", s3Reads.some((u) => u.includes("_RECOVERY/RUNLOG")), s3Reads);
    ok("no credential is in the answer", !JSON.stringify(g.body).includes(S3_KEY_ID) && !JSON.stringify(g.body).includes("floor-reset-secret"));
    ok("with no floor, an absent RUNLOG offers no reset", g.body.runlogPresent === false && g.body.floor === null && g.body.canReset === false, g.body);
  }

  console.log(failures === 0 ? "\nRUNLOG FLOOR RESET PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
