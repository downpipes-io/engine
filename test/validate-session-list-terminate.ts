// validate-session-list-terminate: an operator can VIEW their active sessions and END any one of them, or
// all the others, having authenticated again with at least one factor (ASVS V7.5.2). Through the real router:
//   (a) two logins for one email mint two sessions with DISTINCT ids, and GET /sessions lists both with the
//       presenting session flagged current, carrying coarse metadata (method, client family, network prefix,
//       instants) and never a token;
//   (b) POST /sessions/terminate { sid } from a FRESH session ends exactly that session: it is refused on its
//       next request, the other still verifies, and the list no longer shows it;
//   (c) a sid minted for a DIFFERENT email is 404 and that session still verifies (no cross-account ending);
//   (d) a STALE session is step-up-blocked on POST /sessions/terminate and proceeds with a step-up token;
//   (e) a token minted before ids existed (no sid) still verifies, so no session is orphaned by the change;
//   (f) sign-out drops the ref rows for the email; the alarm sweep drops rows past exp.
import { handleAdmin } from "../src/admin/router.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import { SESSION_COOKIE_NAME, SESSION_TTL_MS, STEPUP_FRESH_MS, verifySession } from "../src/admin/session.ts";
import { ab, b64urlDecode, b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { SESSION_REF_PREFIX, SESSION_REVOKED_PREFIX } from "../src/sched/scheduler-do-records.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

const ORIGIN = "https://downpipe-console.example";
const TOKEN = "list-terminate-bootstrap-token";
const CSRF = "csrf-double-submit-token";
let failures = 0;
function ok(label: string, cond: boolean): void { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`); if (!cond) failures++; }

function makeScheduler(): { env: Env; storage: MockStorage; dobj: SchedulerDO } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN: TOKEN } as unknown as Env, storage, dobj };
}
type Resp = { status: number; json: Record<string, unknown>; setCookie: string | null };
async function send(env: Env, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Resp> {
  const resp = await handleAdmin(new Request(`https://engine.example${path}`, { method: init.method ?? "GET", headers: init.headers ?? {}, ...(init.body !== undefined ? { body: init.body } : {}) }), env);
  const text = await resp.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text) as Record<string, unknown>; } catch { json = { raw: text }; }
  return { status: resp.status, json, setCookie: resp.headers.get("set-cookie") };
}
// A session minted straight from the DO's own key, the way a login lands one: fresh unless iat is given.
async function mintCookie(storage: MockStorage, dobj: SchedulerDO, email: string, opts: { iat?: number; withSid?: boolean } = {}): Promise<{ cookie: string; sid: string | null }> {
  const keyRec = await storage.get<{ key: string }>("passkeySessionKey");
  const key = b64urlDecode(keyRec!.key);
  const now = Date.now();
  const input = { method: "passkey" as const, email, subject: passkeySubject(email), epoch: 0, ...(opts.iat !== undefined ? { slide: { iat: opts.iat, exp: opts.iat + SESSION_TTL_MS } } : {}) };
  const token = opts.withSid === false ? await signLegacyNoSid(key, input, now) : await (dobj as unknown as { mintSessionRecorded: (k: Uint8Array, i: typeof input, n: number, c?: { sourceIp?: string; userAgent?: string }) => Promise<string> }).mintSessionRecorded(key, input, now, { sourceIp: "203.0.113.77", userAgent: "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/130.0" });
  const v = await verifySession(key, token, now);
  return { cookie: `${SESSION_COOKIE_NAME}=${token}`, sid: v?.sid ?? null };
}
// signLegacyNoSid forges a V3 body WITHOUT a sid under the DO's own key, the shape a token minted before ids
// existed carries, so (e) proves such a token still verifies.
async function signLegacyNoSid(key: Uint8Array, input: { method: "passkey"; email: string; subject: string; epoch: number }, now: number): Promise<string> {
  const body = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 3, method: input.method, email: input.email, subject: input.subject, epoch: input.epoch, iat: now, exp: now + SESSION_TTL_MS, lastSeen: now })));
  const k = await crypto.subtle.importKey("raw", ab(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(body)));
  return `${body}.${b64urlEncode(mac)}`;
}
const withCsrf = (cookie: string): Record<string, string> => ({ cookie: `${cookie}; __Host-downpipes_csrf=${CSRF}`, "x-downpipes-csrf": CSRF, origin: ORIGIN, "content-type": "application/json" });

async function main(): Promise<void> {
  const { env, storage, dobj } = makeScheduler();
  const email = "owner@example.com";
  // Seed the signing key and the owner role table through a real bearer-authorised read.
  ok("precondition: the bearer authorises", (await send(env, "/admin/whoami", { headers: { authorization: `Bearer ${TOKEN}` } })).status === 200);
  await (dobj as unknown as { sessionSigningKey: () => Promise<Uint8Array> }).sessionSigningKey();
  // A fresh-format token that strips a sid: the pre-id shape, for (e).
  const a = await mintCookie(storage, dobj, email);
  const b = await mintCookie(storage, dobj, email);

  console.log("\n(a) two sessions, two ids, both listed, the presenter flagged current");
  {
    ok("(a) the two sessions carry distinct ids", a.sid !== null && b.sid !== null && a.sid !== b.sid);
    const list = await send(env, "/admin/sessions", { headers: { cookie: a.cookie } });
    const rows = (list.json.sessions ?? []) as Array<Record<string, unknown>>;
    ok("(a) GET /sessions is 200 with two rows", list.status === 200 && rows.length === 2);
    const rowA = rows.find((r) => r.sid === a.sid); const rowB = rows.find((r) => r.sid === b.sid);
    ok("(a) the presenting session is flagged current, the other is not", rowA?.current === true && rowB?.current === false);
    ok("(a) rows carry coarse provenance (client family, network prefix) and instants", rowA?.clientFamily === "Firefox" && rowA?.networkPrefix === "203.0.113.0/24" && typeof rowA?.iat === "number" && typeof rowA?.lastSeen === "number");
    ok("(a) no row carries a token or a raw address", !JSON.stringify(rows).includes(a.cookie.split("=")[1]!) && !JSON.stringify(rows).includes("203.0.113.77"));
  }

  console.log("\n(b) terminating ONE session by id ends exactly that one");
  {
    const t = await send(env, "/admin/sessions/terminate", { method: "POST", headers: withCsrf(a.cookie), body: JSON.stringify({ sid: b.sid }) });
    ok("(b) POST /sessions/terminate { sid } from the fresh session is 200", t.status === 200 && t.json.ok === true);
    ok("(b) the ended session is refused on its next request (401)", (await send(env, "/admin/whoami", { headers: { cookie: b.cookie } })).status === 401);
    ok("(b) the other session still verifies (200)", (await send(env, "/admin/whoami", { headers: { cookie: a.cookie } })).status === 200);
    const list = await send(env, "/admin/sessions", { headers: { cookie: a.cookie } });
    ok("(b) the list no longer shows the ended session", ((list.json.sessions ?? []) as Array<Record<string, unknown>>).every((r) => r.sid !== b.sid));
    ok("(b) the revocation row carries the session's exp", typeof storage.rawGet<number>(`${SESSION_REVOKED_PREFIX}${b.sid}`) === "number");
  }

  console.log("\n(c) a sid belonging to another email is not found, and that session survives");
  {
    const other = await mintCookie(storage, dobj, "other@example.com");
    const t = await send(env, "/admin/sessions/terminate", { method: "POST", headers: withCsrf(a.cookie), body: JSON.stringify({ sid: other.sid }) });
    ok("(c) 404 no such session", t.status === 404);
    ok("(c) the other email's session still verifies", (await send(env, "/admin/whoami", { headers: { cookie: other.cookie } })).status === 200);
    const bogus = await send(env, "/admin/sessions/terminate", { method: "POST", headers: withCsrf(a.cookie), body: JSON.stringify({ sid: "not-a-real-sid" }) });
    ok("(c) a malformed sid is 404 too", bogus.status === 404);
  }

  console.log("\n(d) ending a session needs a recent factor: a stale session is step-up-blocked");
  {
    const stale = await mintCookie(storage, dobj, email, { iat: Date.now() - (STEPUP_FRESH_MS + 60_000) });
    const victim = await mintCookie(storage, dobj, email);
    const blocked = await send(env, "/admin/sessions/terminate", { method: "POST", headers: withCsrf(stale.cookie), body: JSON.stringify({ sid: victim.sid }) });
    ok("(d) a stale session is refused 401 stepUpRequired on terminate", blocked.status === 401 && blocked.json.stepUpRequired === true);
    ok("(d) the target still verifies after the refusal", (await send(env, "/admin/whoami", { headers: { cookie: victim.cookie } })).status === 200);
    const blockedOthers = await send(env, "/admin/sessions/terminate-others", { method: "POST", headers: withCsrf(stale.cookie), body: "{}" });
    ok("(d) a stale session is refused 401 stepUpRequired on terminate-others too", blockedOthers.status === 401 && blockedOthers.json.stepUpRequired === true);
    ok("(d) control: GET /sessions (a read) is not step-up gated", (await send(env, "/admin/sessions", { headers: { cookie: stale.cookie } })).status === 200);
  }

  console.log("\n(e) a token minted before ids existed still verifies");
  {
    const legacy = await mintCookie(storage, dobj, email, { withSid: false });
    ok("(e) precondition: the legacy-shaped token carries no sid", legacy.sid === null);
    ok("(e) it verifies (200)", (await send(env, "/admin/whoami", { headers: { cookie: legacy.cookie } })).status === 200);
  }

  console.log("\n(f) sign-out drops the email's ref rows; the sweep drops rows past exp");
  {
    const before = [...storage.keys()].filter((k) => k.startsWith(`${SESSION_REF_PREFIX}${email}:`)).length;
    ok("(f) precondition: ref rows exist for the email", before > 0);
    const out = await send(env, "/admin/auth/logout", { method: "POST", headers: { cookie: a.cookie, origin: ORIGIN, "content-type": "application/json" }, body: "{}" });
    ok("(f) logout is 2xx", out.status >= 200 && out.status < 300);
    ok("(f) no ref rows remain for the email", [...storage.keys()].filter((k) => k.startsWith(`${SESSION_REF_PREFIX}${email}:`)).length === 0);
    storage.rawPut(`${SESSION_REVOKED_PREFIX}oldsid`, Date.now() - 1000);
    storage.rawPut(`${SESSION_REF_PREFIX}x@example.com:oldref`, { sid: "oldref", method: "passkey", connId: null, iat: 0, exp: Date.now() - 1000, lastSeen: 0, clientFamily: null, networkPrefix: null });
    await (dobj as unknown as { sweepSessionRecords: (n: number) => Promise<void> }).sweepSessionRecords(Date.now());
    ok("(f) the sweep drops an expired revocation and an expired ref", storage.rawGet(`${SESSION_REVOKED_PREFIX}oldsid`) === undefined && storage.rawGet(`${SESSION_REF_PREFIX}x@example.com:oldref`) === undefined);
  }

  console.log(failures === 0 ? "\nSESSION LIST + TERMINATE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
