// The ATTENDED relink (admin/router-runlog.ts GET /runlog/chain, POST /runlog/relink) is the way out for a
// RUNLOG that VERIFIES under the engine's signer but whose own downpipe chain has an anomaly (for example after a
// control-plane loss). The append refuses to relink an anomalous chain on its own, so that downpipe's seals stop.
//
// This validator stands up a real Owner and Viewer on passkeys (real step-up), an env-backed R2 destination
// double and an all-events webhook, then drives:
//   - without the action the seal stays refused;
//   - the evidence: whether the RUNLOG verifies, the anomaly (kind, indices, reason), whether a relink clears it;
//   - refused without step-up, for a Viewer, and for an anomaly or digest that is not the one shown;
//   - the relink writes its audit row (what was acknowledged) and alert, relinks exactly that one chain (another
//     downpipe's entries are unchanged), and unblocks the seal;
//   - refused when the RUNLOG does not verify (nothing is signed), when it is below its floor, when a relink does
//     not clear the anomaly (a duplicate index), and when the chain has no anomaly.
//
// Run: node test/validate-runlog-relink.ts

import { handleAdmin } from "../src/admin/router.ts";
import { buildSupportBundle } from "../src/admin/support.ts";
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
const DP = "dp_relink";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FK${n}`;

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


// The writers read the destination's floor through their lock, as runlogLockVia does from the scheduler DO.
// refusedRows returns the failed runlog-relinked audit rows' targets (the refusals), oldest first.
async function refusedRows(e: Estate): Promise<Array<Record<string, unknown>>> {
  return (await audit(e)).filter((a) => a.action === "runlog-relinked" && a.outcome === "failed").map((a) => (a.target ?? {}) as Record<string, unknown>).reverse();
}
// packRunlogEvents returns the support pack's configEvents rows for the RUNLOG actions.
async function packRunlogEvents(e: Estate): Promise<Array<Record<string, unknown>>> {
  const pack = await buildSupportBundle(e.env, e.stub);
  return ((pack.configEvents ?? []) as Array<Record<string, unknown>>).filter((c) => c.action === "runlog-relinked" || c.action === "runlog-handover");
}
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


const OTHER = "dp_other";
const O = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FM${n}`;
// stuck writes a RUNLOG signed by the CURRENT signer (it verifies) in which DP's chain is anomalous: "dangling"
// (its first entry points at a run that is not there) or "duplicate" (two entries share an index). Another
// downpipe's chain is there too, deliberately unlinked, so the test can see a relink leaves it alone.
async function stuck(e: Estate, kind: "dangling" | "duplicate" | "clean"): Promise<RunlogEntry[]> {
  const mk = (index: number, runId: string, dp: string, prev: string | null): RunlogEntry => ({ index, runId, downpipeId: dp, time: `2026-10-01T0${index}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" });
  const entries: RunlogEntry[] =
    kind === "dangling"
      ? [mk(1, R(1), DP, R(9)), mk(2, O(2), OTHER, null), mk(3, R(3), DP, R(1)), mk(4, O(4), OTHER, null)]
      : kind === "duplicate"
        ? [mk(1, R(1), DP, null), mk(2, O(2), OTHER, null), mk(3, R(3), DP, R(1)), mk(3, R(4), DP, R(3))]
        : [mk(1, R(1), DP, null), mk(2, O(2), OTHER, null), mk(3, R(3), DP, R(1))];
  const s = await loadSigner(e.signer);
  const signed = await signRunlog(entries, s.edPrivate, s.mldsaSecret);
  await e.dest.put(RUNLOG, signed.runlog);
  await e.dest.put(RUNLOG_SIG, new TextEncoder().encode(b64urlEncode(signed.sig)));
  await e.dest.delete(RUNLOG_PENDING);
  return entries;
}
const relinkBody = (g: Reply): Record<string, unknown> => ({ destinationId: "", downpipeId: DP, digest: g.body.digest, anomalyKind: (g.body.anomaly as { kind?: string } | undefined)?.kind });

async function main(): Promise<void> {
  ok("POST /runlog/relink is a step-up route", STEPUP_SUBS.has("/runlog/relink"));

  console.log("\n-- 1. a verified RUNLOG whose own downpipe chain dangles --");
  {
    const e = await estate();
    await stuck(e, "dangling");
    const before = await sealNext(e, 5, R(3));
    ok(`without the action the seal stays refused (${before})`, before === "refused chain-anomaly");
    const g = await admin(e.env, "GET", `/runlog/chain?destinationId=&downpipeId=${DP}`, e.cookie);
    const an = g.body.anomaly as { kind?: string; reason?: string } | undefined;
    ok("GET shows the RUNLOG verifies, the anomaly and that a relink clears it", g.status === 200 && g.body.verifies === true && an?.kind === "dangling-prev" && typeof an.reason === "string" && g.body.relinkClears === true && g.body.canRelink === true && g.body.chainEntries === 2, g.body);
    const stale = await staleCookieFor(e);
    const noStep = await admin(e.env, "POST", "/runlog/relink", stale, relinkBody(g));
    ok(`without step-up it is refused (got ${noStep.status})`, noStep.status === 401 && (await sealNext(e, 5, R(3))) === "refused chain-anomaly");
    const v = await viewerCookie(e);
    const vr = await admin(e.env, "POST", "/runlog/relink", v.cookie, relinkBody(g), await freshStepUp(e.env, v.key, v.cookie));
    ok(`a Viewer is refused even after step-up (got ${vr.status})`, vr.status === 403);
    const wrong = await admin(e.env, "POST", "/runlog/relink", e.cookie, { ...relinkBody(g), anomalyKind: "forked-prev" }, await freshStepUp(e.env, e.key, e.cookie));
    ok(`an anomaly that is not the one shown is refused (got ${wrong.status})`, wrong.status === 409);
    ok("...and the refusal is audited as relink-refused, changed-since-read", (await refusedRows(e)).some((x) => x.op === "relink-refused" && JSON.stringify(x.reasons) === '["changed-since-read"]' && x.downpipeId === DP), await refusedRows(e));
    const otherBefore = parseRunlog(e.store.get(RUNLOG)!).filter((x) => x.downpipeId === OTHER);
    hookPosts.length = 0;
    const r = await admin(e.env, "POST", "/runlog/relink", e.cookie, relinkBody(g), await freshStepUp(e.env, e.key, e.cookie));
    ok(`the Owner relinks it after step-up (got ${r.status})`, r.status === 200 && r.body.acknowledged === "dangling-prev", r.body);
    const after = parseRunlog(e.store.get(RUNLOG)!);
    ok("the RUNLOG verifies, DP's chain is linear (first entry has no predecessor)", (await sigVerifies(e.store, e.v)) && after.find((x) => x.runId === R(1))?.prevRunId === null && after.find((x) => x.runId === R(3))?.prevRunId === R(1));
    ok("another downpipe's entries are unchanged", JSON.stringify(after.filter((x) => x.downpipeId === OTHER)) === JSON.stringify(otherBefore));
    const row = (await audit(e)).find((a) => a.action === "runlog-relinked" && a.outcome === "success");
    const t = row?.target as Record<string, unknown> | undefined;
    ok("a runlog-relinked audit row records what was acknowledged", t?.op === "relink" && t.downpipeId === DP && t.state === "dangling-prev" && t.chainEntries === 2 && typeof t.digest === "string", row);
    const alerts = hookPosts.filter((b) => b.includes("runlog-relinked"));
    ok(`the runlog-relinked alert reached the all-events webhook at warning (${alerts.length})`, alerts.length === 1 && /warning/.test(alerts[0] ?? ""));
    const unblocked = await sealNext(e, 5, R(3));
    ok(`the stuck case is unblocked: the seal appends (${unblocked})`, unblocked === "ok");
    const again = await admin(e.env, "POST", "/runlog/relink", e.cookie, relinkBody(g), await freshStepUp(e.env, e.key, e.cookie));
    ok(`once only: the same request again is refused (got ${again.status})`, again.status === 409);
    const ev = await packRunlogEvents(e);
    ok("the support pack's configEvents carries the relink: runlogOp relink, anomalyKind dangling-prev", ev.some((c) => c.action === "runlog-relinked" && c.runlogOp === "relink" && c.anomalyKind === "dangling-prev"), ev);
    ok("...and the refused one: runlogOp relink-refused, reasons changed-since-read", ev.some((c) => c.runlogOp === "relink-refused" && JSON.stringify(c.reasons) === '["changed-since-read"]'), ev);
    ok("the pack rows carry no downpipe id, destination id, digest or index", ev.every((c) => !("downpipeId" in c) && !("destinationIds" in c) && !("digest" in c) && !("indexA" in c) && !JSON.stringify(c).includes(DP)), ev);
  }

  console.log("\n-- 2. a RUNLOG that does not verify is never relinked or signed --");
  {
    const e = await estate();
    await stuck(e, "dangling");
    await e.dest.delete(RUNLOG_SIG);
    const g = await admin(e.env, "GET", `/runlog/chain?destinationId=&downpipeId=${DP}`, e.cookie);
    ok("GET says it does not verify and offers no relink", g.body.verifies === false && g.body.canRelink === false && /does not verify/.test(String(g.body.refusal)), g.body);
    const r = await admin(e.env, "POST", "/runlog/relink", e.cookie, relinkBody(g), await freshStepUp(e.env, e.key, e.cookie));
    ok(`POST refuses (got ${r.status}) and nothing is signed`, r.status === 409 && !e.store.has(RUNLOG_SIG));
    ok("...and the refusal is audited as relink-refused, not-verified", (await refusedRows(e)).some((x) => x.op === "relink-refused" && JSON.stringify(x.reasons) === '["not-verified"]'), await refusedRows(e));
    ok("...and the pack names it", (await packRunlogEvents(e)).some((c) => c.runlogOp === "relink-refused" && JSON.stringify(c.reasons) === '["not-verified"]'));
  }

  console.log("\n-- 3. what a relink cannot clear, or must not touch, is refused --");
  {
    const e = await estate();
    await stuck(e, "duplicate");
    const g = await admin(e.env, "GET", `/runlog/chain?destinationId=&downpipeId=${DP}`, e.cookie);
    ok("a duplicate index: GET says a relink does not clear it", (g.body.anomaly as { kind?: string } | undefined)?.kind === "duplicate-index" && g.body.relinkClears === false && g.body.canRelink === false, g.body);
    const r = await admin(e.env, "POST", "/runlog/relink", e.cookie, relinkBody(g), await freshStepUp(e.env, e.key, e.cookie));
    ok(`...and POST refuses it (got ${r.status})`, r.status === 409);
    ok("...and the refusal names the way out: attach the downpipe to a fresh destination", /fresh destination/.test(String(g.body.refusal)), g.body);
    ok("...and it is audited as not-cleared, with the anomaly kind", (await refusedRows(e)).some((x) => JSON.stringify(x.reasons) === '["not-cleared"]' && x.state === "duplicate-index"), await refusedRows(e));

    const f = await estate();
    await stuck(f, "dangling");
    await f.storage.put("runlogFloor", { "": { index: 9 } });
    const gf = await admin(f.env, "GET", `/runlog/chain?destinationId=&downpipeId=${DP}`, f.cookie);
    ok("below its floor: GET offers no relink and points to the floor view", gf.body.canRelink === false && /below the last good index/.test(String(gf.body.refusal)), gf.body);
    const rf = await admin(f.env, "POST", "/runlog/relink", f.cookie, relinkBody(gf), await freshStepUp(f.env, f.key, f.cookie));
    ok(`...and POST refuses it (got ${rf.status})`, rf.status === 409);
    ok("...and it is audited as below-floor", (await refusedRows(f)).some((x) => JSON.stringify(x.reasons) === '["below-floor"]'), await refusedRows(f));

    const c = await estate();
    await stuck(c, "clean");
    const gc = await admin(c.env, "GET", `/runlog/chain?destinationId=&downpipeId=${DP}`, c.cookie);
    ok("CONTROL: a clean chain shows no anomaly and offers no relink", gc.body.anomaly === undefined && gc.body.canRelink === false, gc.body);
    ok("CONTROL: and the seal on it appends without any action", (await sealNext(c, 5, R(3))) === "ok");
    ok("CONTROL: with no relink attempted there is no refusal row and no pack row", (await refusedRows(c)).length === 0 && (await packRunlogEvents(c)).length === 0);
  }

  console.log(failures === 0 ? "\nRUNLOG RELINK PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
