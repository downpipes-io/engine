// Prove the passkey SESSION layer end to end, SERVER-SIDE, driving the REAL session core (src/admin/
// session.ts), the REAL precedence gate (src/admin/auth.ts authorise), the REAL passkey verifier
// (src/admin/passkey.ts) and the REAL scheduler DO (src/sched/scheduler-do.ts), with in-memory doubles
// only. No network, no deploy, no cost. Run:
//   node test/validate-session.ts
//
// The engine is its own identity provider; a successful WebAuthn login/registration issues a signed,
// short-TTL session cookie that the subsequent /admin calls present as the THIRD auth method (alongside a
// verified Cloudflare Access JWT and the ADMIN_TOKEN break-glass). What this proves (claims a later adversarial review will hammer):
//   - the session core signs + verifies a token round-trip (the verified email comes back), and a TAMPERED
//     body, a TAMPERED MAC, a WRONG-KEY MAC, an EXPIRED token and a malformed token are ALL rejected;
//   - a full register -> login through the real router mints a Set-Cookie, and presenting that cookie
//     AUTHORISES as method:passkey and resolves the bootstrapped Owner role from the same role table;
//   - an INVALID / EXPIRED / TAMPERED session cookie is rejected AND does NOT fall through to the token
//     path (the anti-downgrade rule), even with ADMIN_TOKEN configured;
//   - the EMAILLESS guard: a validly-signed session whose body carries no email is refused;
//   - logout clears the cookie (Max-Age=0), after which the same request is unauthorised;
//   - the CSRF guard refuses a cross-origin (or Origin-less) MUTATING passkey-authenticated POST, and
//     admits one carrying the exact CONSOLE_ORIGIN;
//   - PRECEDENCE access > passkey > token: a valid Access JWT wins over a present session cookie, and a
//     present session cookie wins over the token even when ADMIN_TOKEN is set;
//   - INVITE -> REGISTER: a role granted to an email that has not registered applies once they register +
//     log in (the grant table is the source of roles), and registering NEVER self-escalates (a fresh
//     second registrant with no grant resolves to viewer);
//   - ADMIN_TOKEN_DISABLED still blocks the token path, while a passkey session still authorises.
// The negative controls are written so they would FAIL if the corresponding check were removed.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { authorise } from "../src/admin/auth.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { requireStepUp, STEPUP_SUBS } from "../src/admin/router-core.ts";
import {
  CSRF_COOKIE_NAME,
  originAllowed,
  readSessionCookie,
  SESSION_COOKIE_NAME,
  SESSION_IDLE_MS,
  SESSION_KEY_BYTES,
  SESSION_SLIDE_MS,
  SESSION_TTL_MS,
  STEPUP_FRESH_MS,
  sessionClearCookie,
  sessionSetCookie,
  signSession,
  slideDue,
  verifySession,
} from "../src/admin/session.ts";
import { b64urlDecode, b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { blankComments } from "./lib/blank-comments.mjs";

// ---- STRUCTURAL step-up coverage: derive the router's ACTUAL dispatched POST set FROM THE SOURCE ----------
// The step-up gate (router-core.ts requireStepUp + STEPUP_SUBS) protects the sensitive owner/operator
// mutations behind a fresh re-auth. A coverage check that listed the routes by hand could only re-check
// routes a human already typed, so an OMITTED sensitive route (e.g. an RBAC /delete sibling of a gated
// GRANT route) was invisible to it. This block instead ENUMERATES the real POST routes the dispatch
// spokes carry by parsing their `case "POST /<sub>"` labels out of the spoke source (the read-the-source
// technique the cf-config drift validator uses on the engine's own source), classifies each as a sensitive
// identity/auth-lifecycle/keys/posture/destination/restore mutation or not, and asserts every sensitive
// route is in STEPUP_SUBS. A NEW sensitive route that is neither gated nor explicitly allowlisted FAILS.
const HERE = dirname(fileURLToPath(import.meta.url));
const ROUTER_SPOKE_DIR = join(HERE, "..", "src", "admin");

// dispatchedPostSubs reads every router spoke (router.ts + router-*.ts) and returns the SET of `<sub>`
// strings that appear in a `case "POST /<sub>":` (or `{`) dispatch label. These are the exact strings the
// step-up gate keys on (handleAdmin computes `sub = pathname without /admin` and the spokes switch on
// `${method} ${sub}`), so the derived set is what the gate actually sees.
//
// COMMENTS ARE STRIPPED FIRST, because a comment that QUOTES the `case "POST ` literal (router-notify.ts
// describes the DO's own POST /notify/record route that way) would otherwise be matched exactly like code,
// and the derived set would then carry a sub the router never dispatches. Reading only code avoids that.
function dispatchedPostSubs(): Set<string> {
  const subs = new Set<string>();
  const files = readdirSync(ROUTER_SPOKE_DIR).filter((f) => f === "router.ts" || (f.startsWith("router-") && f.endsWith(".ts")));
  const caseRe = /case\s+"POST\s+(\/[^"]*)"/g;
  for (const f of files) {
    // blankComments is used rather than a pair of hand-rolled regexes, because a naive block-comment regex can
    // read a comment that merely NAMES a `/*`-shaped path (like `/admin/test-fault/*`) as an opening delimiter
    // and a later comment mentioning a cron expression like `*/15` as its close, deleting live code between
    // them and hiding real dispatched routes from this file's structural coverage. A whole-line `//` filter has
    // the mirror hole: a TRAILING `// ... case "POST /x"` comment is left in place, so a stale STEPUP_SUBS entry
    // naming a route the router no longer dispatches could be made to look real by a comment alone.
    // blankComments is quote-aware and offset-preserving, so neither direction survives, and it is the same
    // shared stripper the other gates in this repo use.
    const src = blankComments(readFileSync(join(ROUTER_SPOKE_DIR, f), "utf8"));
    for (const m of src.matchAll(caseRe)) subs.add(m[1]!);
  }
  return subs;
}

// isSensitiveMutationSub classifies a dispatched POST sub as a HIGH-CONSEQUENCE identity / auth-lifecycle /
// keys / posture / destination / restore-apply mutation that MUST sit behind the step-up gate. It matches by
// SECURITY DOMAIN (a prefix family), not a hand-typed exact list, so a NEW sibling route in a sensitive
// family (e.g. a future /idp/connections/* or /roles/* mutation) is automatically classified sensitive and
// must be gated or explicitly allowlisted. The deliberate within-a-sensitive-family EXEMPTIONS
// (STEPUP_DOMAIN_EXEMPT below) are read probes / self-service / the maker-side request, never a mutation of
// the trust roots; a route that matches a sensitive family and is NOT exempt MUST be in STEPUP_SUBS.
function isSensitiveMutationSub(sub: string): boolean {
  if (STEPUP_DOMAIN_EXEMPT.has(sub)) return false;
  // keys: install / rotate / break-glass-only (custody-grade); /setup/acknowledge is NOT under /keys/.
  if (sub.startsWith("/keys/")) return true;
  // posture: the two risk-accept mutations (GET /posture is a read and never reaches this POST set).
  if (sub === "/posture/accept" || sub === "/posture/unaccept") return true;
  // destination: repoint / add / remove / make-default (a stolen session could redirect or delete backups).
  if (sub === "/destination" || sub.startsWith("/destinations")) return true;
  // identity, the IdP trust roots: wire / remove / enable a sign-in source.
  if (sub.startsWith("/idp/connections")) return true;
  // identity, RBAC grant AND revoke: the built-in role table, the group->role mapping, the custom-role
  // definitions. Both the grant and the /delete (offboarding / mapping-removal) siblings are sensitive.
  if (sub === "/roles" || sub.startsWith("/roles/") || sub.startsWith("/group-roles") || sub.startsWith("/custom-roles")) return true;
  // auth-lifecycle: retiring the break-glass bearer (an irreversible lockout) + revoking a passkey credential.
  if (sub === "/policy/retire-break-glass-token" || sub === "/passkey/credentials/delete") return true;
  // restore: the APPLY-approval (approving a pending request writes data back), AND the apply route itself
  // (POST /restore, which carries both the read-only dry-run and the actual data-overwriting apply on one
  // static sub, gated on the PARSED confirm:true action rather than Set membership -- see STEPUP_DOMAIN_EXEMPT
  // below). The maker-side /restore/request + /restore/reject, and the no-write /restore/verify + /restore/
  // attest are NOT here (they are exempt in the restore family below).
  if (sub === "/restore/approve" || sub === "/restore") return true;
  // session lifecycle: evicting ANOTHER operator or every
  // operator. /sessions/terminate-others is exempt below (self-scoped only).
  if (sub.startsWith("/sessions/")) return true;
  // custody: emailing a Shamir share to a custodian.
  if (sub === "/custody/send-share") return true;
  // CREDENTIAL MINTING: a route that hands the caller a NEW bearer
  // secret. /support/credentials mints one over the sealed support bundle's pull surface; naming the family
  // (not the one route) is what makes a future /support/credentials/* or sibling mint auto-classified rather
  // than needing someone to notice it.
  // The /delete sibling is exempt below (revoking closes the surface; it is the safe direction).
  if (sub === "/support/credentials" || sub.startsWith("/support/credentials/")) return true;
  // DETECTION AND EVIDENCE EGRESS: the controls that decide whether
  // any of the acts above is ever SEEN. The notify rules and channels carry recovery-code-abuse (critical),
  // owner-role-grant, offboard, credential-change, idp-change, dest-change and posture-regression; the SIEM
  // and OTLP push destinations carry the audit and telemetry egress. Deleting the rule that carries a signal,
  // or repointing the channel it delivers to, is what an attacker does BEFORE the act, and it leaves no
  // visible effect. Naming the family is what makes a future
  // /notify/* or /push/* sibling auto-classified. /notify/test is exempt below.
  if (sub.startsWith("/notify/") || sub === "/push" || sub.startsWith("/push/") || sub === "/otlp-push" || sub.startsWith("/otlp-push/")) return true;
  // THE SIGN-IN NOTIFY TOGGLE, named EXACTLY rather than by a /config/ prefix.
  // It belongs to the family directly above: it
  // silences a signal about ACCESS ITSELF, it has no undo prompt and no visible effect, and turning it off
  // is what an attacker does BEFORE the attempt.
  //
  // Named exactly, and NOT as `sub.startsWith("/config/")`, because the other four dispatched POST /config/
  // routes are deliberately ungated on per-route grounds and a prefix would drag them in as violations. The
  // strongest of them, /config/approval-policy, is not a step-up candidate: arming is immediate,
  // an attributable owner's DISARM queues for a second owner at 202, a real-time disarm alert fires on any
  // immediate disarm, and the only caller who can disarm outright is the bare-token break-glass owner, who
  // is exempt from step-up anyway.
  //
  // Naming this route individually, rather than relying on the STEPUP_SUBS presence alone, is what makes
  // removing it from STEPUP_SUBS fail this file.
  if (sub === "/config/signin-context-policy") return true;
  return false;
}

// STEPUP_DOMAIN_EXEMPT records the routes that PATTERN-match a sensitive family above but are deliberately
// NOT step-up gated, each with the reason it is low-consequence. A route in a sensitive family that is NOT
// listed here MUST be in STEPUP_SUBS, so this set is the explicit, reviewed escape hatch (it cannot quietly
// grow: every entry is also asserted to be a real dispatched route, so a stale name fails the test).
const STEPUP_DOMAIN_EXEMPT = new Set<string>([
  "/keys/posture-acknowledgement", // records an ADVISORY key-posture acknowledgement (an audit event only); it touches NO key, secret or posture (unlike /keys/install|rotate|break-glass-only) and MUST work during bootstrap, before a passkey is enrolled, so step-up cannot be required. Its evidentiary weight comes from the audit attribution (who/when/method + statement hash), not a step-up ceremony.
  "/destination/verify", // a READ-ONLY live re-probe of the effective destination; writes nothing to the DO.
  "/restore/request", // the MAKER side (raise a restore request); writes no data, the apply is /restore/approve.
  "/restore/reject", // the approver-side REJECT (discards a pending request); writes no data back.
  "/restore/verify", // a BLIND restore test (decrypt to a discard sink); surfaces no plaintext, writes nothing.
  "/restore/attest", // a KEYLESS attestation (signature/completeness only); no key, no data, no write-back.
  "/sessions/terminate-others", // SELF-scoped only (bumps the CALLER's own epoch); never touches another operator's session, so it is housekeeping, not the STEPUP-SESSION-TERMINATION-GAP threat model.
  "/notify/test", // sends ONE fixed, redaction-safe info-severity line ("downpipe test notification, no action required") to an ALREADY-CONFIGURED channel; it carries no caller-supplied content, changes no rule, channel or destination, and cannot silence anything. Its dangerous siblings (choosing WHERE a channel points, and WHICH events reach it) are the gated ones.
  "/support/credentials/delete", // REVOKES a minted support credential: it CLOSES the pull surface the mint opened, so it is the safe direction of the pair (the convention this Set already applies to restore and prune). Requiring a fresh re-auth to shut off a credential the operator believes is stolen would put friction on exactly the action they need to take fastest.
]);

// STEPUP_INLINE_GATED is the /restore counterpart of the HI-04 dynamic-<id>-approve exception: a route that
// IS step-up gated, but not via literal STEPUP_SUBS membership, because a plain Set keyed on `sub` cannot see
// the request BODY. POST /restore multiplexes the read-only dry-run and the actual data-overwriting apply on
// ONE static sub (never a path segment, unlike the HI-04 pair), so router-restore.ts calls requireStepUp()
// directly inside the `body.confirm === true` branch instead (router-core.ts's STEPUP_SUBS comment explains
// both exceptions side by side). Unlike STEPUP_DOMAIN_EXEMPT (genuinely NOT gated), every entry here MUST be
// proven gated by the structural source-read below, mirroring matcherGatesApproveOnly for the HI-04 pair.
const STEPUP_INLINE_GATED = new Set<string>(["/restore"]);

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

const ORIGIN = "https://downpipe-console.example";
const RP_ID = "downpipe-console.example"; // host of ORIGIN (the default rp.id)

// BOOTSTRAP_TOKEN is the deploy-time operator secret the account-takeover fix requires to enrol the FIRST
// Owner passkey (the bootstrap path). makeScheduler defaults env.ADMIN_TOKEN to it (so a first registration
// can bootstrap), and the register() helper presents it as the bearer for the bootstrap path. A block that
// needs a specific token (or the token-disabled posture) overrides ADMIN_TOKEN via extraEnv.
const BOOTSTRAP_TOKEN = "session-bootstrap-token-deadbeef";

function makeScheduler(extraEnv: Partial<Env> = {}): { env: Env; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  // Default an ADMIN_TOKEN so a first (bootstrap) registration can present it; a block overrides it (or
  // adds ADMIN_TOKEN_DISABLED) via extraEnv when it needs a different posture.
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN: BOOTSTRAP_TOKEN, ...extraEnv } as unknown as Env;
  return { env, storage, stub };
}

// ---- A minimal CBOR encoder + fake-but-REAL authenticator (mirrors validate-passkey) ----------
type CborInput =
  | { int: number }
  | { bytes: Uint8Array }
  | { text: string }
  | { map: Array<[CborInput, CborInput]> }
  | { array: CborInput[] };

function encHead(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 0x100) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 0x10000) return new Uint8Array([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
  return new Uint8Array([(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}
function cat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function cborEncode(v: CborInput): Uint8Array {
  if ("int" in v) return v.int >= 0 ? encHead(0, v.int) : encHead(1, -1 - v.int);
  if ("bytes" in v) return cat(encHead(2, v.bytes.length), v.bytes);
  if ("text" in v) { const b = new TextEncoder().encode(v.text); return cat(encHead(3, b.length), b); }
  if ("array" in v) return cat(encHead(4, v.array.length), ...v.array.map(cborEncode));
  const pairs = v.map.map(([k, val]) => cat(cborEncode(k), cborEncode(val)));
  return cat(encHead(5, v.map.length), ...pairs);
}

interface Authenticator {
  credentialId: Uint8Array;
  aaguid: Uint8Array;
  signCount: number;
  privateKey: CryptoKey;
  cosePublicKey: Uint8Array;
}
async function makeAuthenticator(): Promise<Authenticator> {
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const aaguid = crypto.getRandomValues(new Uint8Array(16));
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { x: string; y: string };
  const cose = cborEncode({
    map: [
      [{ int: 1 }, { int: 2 }],
      [{ int: 3 }, { int: -7 }],
      [{ int: -1 }, { int: 1 }],
      [{ int: -2 }, { bytes: b64urlDecode(jwk.x) }],
      [{ int: -3 }, { bytes: b64urlDecode(jwk.y) }],
    ],
  });
  return { credentialId, aaguid, signCount: 0, privateKey: kp.privateKey, cosePublicKey: cose };
}
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
}
async function buildAuthData(auth: Authenticator, rpId: string, opts: { attested: boolean; up: boolean; signCount: number }): Promise<Uint8Array> {
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));
  let flags = 0;
  if (opts.up) flags |= 0x01;
  flags |= 0x04; // UV
  if (opts.attested) flags |= 0x40;
  const sc = new Uint8Array(4);
  new DataView(sc.buffer).setUint32(0, opts.signCount, false);
  if (!opts.attested) return cat(rpIdHash, new Uint8Array([flags]), sc);
  const credIdLen = new Uint8Array(2);
  new DataView(credIdLen.buffer).setUint16(0, auth.credentialId.length, false);
  return cat(rpIdHash, new Uint8Array([flags]), sc, auth.aaguid, credIdLen, auth.credentialId, auth.cosePublicKey);
}
function clientDataJSON(type: string, challengeB64: string, origin: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ type, challenge: challengeB64, origin, crossOrigin: false }));
}
function rawToDer(raw: Uint8Array): Uint8Array {
  const r = raw.subarray(0, 32);
  const s = raw.subarray(32, 64);
  const enc = (b: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0x00) i++;
    let v = b.subarray(i);
    if ((v[0]! & 0x80) !== 0) v = cat(new Uint8Array([0x00]), v);
    return cat(new Uint8Array([0x02, v.length]), v);
  };
  const body = cat(enc(r), enc(s));
  return cat(new Uint8Array([0x30, body.length]), body);
}
async function buildAttestation(auth: Authenticator, challengeB64: string): Promise<unknown> {
  const authData = await buildAuthData(auth, RP_ID, { attested: true, up: true, signCount: auth.signCount });
  const attObj = cborEncode({
    map: [
      [{ text: "fmt" }, { text: "none" }],
      [{ text: "attStmt" }, { map: [] }],
      [{ text: "authData" }, { bytes: authData }],
    ],
  });
  const cd = clientDataJSON("webauthn.create", challengeB64, ORIGIN);
  return {
    id: b64urlEncode(auth.credentialId),
    rawId: b64urlEncode(auth.credentialId),
    type: "public-key",
    response: { clientDataJSON: b64urlEncode(cd), attestationObject: b64urlEncode(attObj) },
  };
}
async function signAssertion(auth: Authenticator, challengeB64: string): Promise<unknown> {
  const signCount = auth.signCount + 1;
  const authData = await buildAuthData(auth, RP_ID, { attested: false, up: true, signCount });
  const cd = clientDataJSON("webauthn.get", challengeB64, ORIGIN);
  const signed = cat(authData, await sha256(cd));
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, auth.privateKey, signed as Uint8Array<ArrayBuffer>));
  return {
    id: b64urlEncode(auth.credentialId),
    rawId: b64urlEncode(auth.credentialId),
    type: "public-key",
    response: { clientDataJSON: b64urlEncode(cd), authenticatorData: b64urlEncode(authData), signature: b64urlEncode(rawToDer(raw)) },
  };
}

// ---- HTTP-ish drivers over the FULL router (handleAdmin) --------------------------------------
// A response wrapper that captures the parsed body, the status, and the Set-Cookie header (the session).
// The parsed response body. JSON object responses index to unknown (callers narrow via their own
// runtime checks); a parse failure stores the raw text under a reserved key so the field stays typed.
// The named fields are the subsets these tests read directly: a begin returns publicKey (absent on a
// refused begin), an error response carries a string error, and the credentials listing returns an array
// of credential entries (each with its credentialId). Everything else stays unknown under the index.
interface RespJson {
  [k: string]: unknown;
  publicKey?: { challenge: string; [k: string]: unknown };
  error?: string;
  credentials?: Array<{ credentialId: string; [k: string]: unknown }>;
}
interface Resp { status: number; json: RespJson; setCookie: string | null; csrfCookie: string | null; }
async function send(env: Env, req: Request): Promise<Resp> {
  // Mirror index.ts: pass the idle-slide cookie sink so a slid session surfaces a refreshed Set-Cookie
  // exactly as production does (a route's own Set-Cookie, e.g. login/terminate, still takes precedence).
  const slide: { cookie: string | null } = { cookie: null };
  const resp = await handleAdmin(req, env, undefined, slide);
  const text = await resp.text();
  let json: RespJson;
  try {
    const parsed: unknown = JSON.parse(text);
    json = parsed !== null && typeof parsed === "object" ? (parsed as RespJson) : { raw: parsed };
  } catch {
    json = { raw: text };
  }
  // A whoami by a cookie-borne caller now ALSO emits the readable double-submit CSRF cookie (R2), so a
  // response can carry TWO Set-Cookie headers. Read them all and split: `setCookie` stays the SESSION cookie
  // (what the login / terminate / idle-slide flows observe), falling back to the slide sink (which carries
  // the slid session cookie in production, applied by index.ts); `csrfCookie` is the CSRF token cookie.
  const respCookies: string[] = typeof resp.headers.getSetCookie === "function"
    ? resp.headers.getSetCookie()
    : (resp.headers.get("set-cookie") !== null ? [resp.headers.get("set-cookie")!] : []);
  const setCookie = respCookies.find((c) => c.startsWith(`${SESSION_COOKIE_NAME}=`)) ?? slide.cookie;
  const csrfCookie = respCookies.find((c) => c.startsWith(`${CSRF_COOKIE_NAME}=`)) ?? null;
  return { status: resp.status, json, setCookie, csrfCookie };
}
// postAuth drives an /admin/auth/* route. opts carry the proven-registration inputs the takeover fix needs:
// a bearer (the ADMIN_TOKEN bootstrap / token self-add) and a session cookie (a passkey-session self-add).
// The Origin defaults to CONSOLE_ORIGIN (a real browser fetch always sends it). A per-IP header is set so
// the per-IP auth limiter has a key on the happy path.
async function postAuth(env: Env, path: string, body: unknown, opts: { bearer?: string; cookie?: string } = {}): Promise<Resp> {
  const headers: Record<string, string> = { "content-type": "application/json", origin: ORIGIN, "CF-Connecting-IP": "203.0.113.50" };
  if (opts.bearer !== undefined) headers["authorization"] = `Bearer ${opts.bearer}`;
  if (opts.cookie !== undefined) headers["cookie"] = opts.cookie;
  return send(env, new Request(`https://engine.example${path}`, { method: "POST", body: JSON.stringify(body), headers }));
}
// getAdmin drives an authenticated GET /admin route, presenting the session cookie when supplied.
async function getAdmin(env: Env, path: string, opts: { cookie?: string; bearer?: string; origin?: string; accessJwt?: string } = {}): Promise<Resp> {
  const headers: Record<string, string> = {};
  if (opts.cookie !== undefined) headers["cookie"] = opts.cookie;
  if (opts.bearer !== undefined) headers["authorization"] = `Bearer ${opts.bearer}`;
  if (opts.origin !== undefined) headers["origin"] = opts.origin;
  if (opts.accessJwt !== undefined) headers["cf-access-jwt-assertion"] = opts.accessJwt;
  return send(env, new Request(`https://engine.example${path}`, { method: "GET", headers }));
}
// postAdmin drives an authenticated POST /admin route (a mutating request), for the CSRF tests. The optional
// `csrf` opt simulates the console's double-submit token on the session-termination routes (ML-02): it sets
// the x-downpipes-csrf header AND appends a matching __Host-downpipes_csrf cookie, so header === cookie (the
// check is a pure double-submit, independent of any server-issued value). Omitting it drives the no-token
// negative case; passing a distinct `csrfCookie` drives the header != cookie mismatch case.
async function postAdmin(env: Env, path: string, body: unknown, opts: { cookie?: string; bearer?: string; origin?: string; csrf?: string; csrfCookie?: string } = {}): Promise<Resp> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  let cookie = opts.cookie;
  if (opts.csrf !== undefined) headers["x-downpipes-csrf"] = opts.csrf;
  const csrfCookieVal = opts.csrfCookie ?? opts.csrf;
  if (csrfCookieVal !== undefined) cookie = cookie !== undefined ? `${cookie}; ${CSRF_COOKIE_NAME}=${csrfCookieVal}` : `${CSRF_COOKIE_NAME}=${csrfCookieVal}`;
  if (cookie !== undefined) headers["cookie"] = cookie;
  if (opts.bearer !== undefined) headers["authorization"] = `Bearer ${opts.bearer}`;
  if (opts.origin !== undefined) headers["origin"] = opts.origin;
  return send(env, new Request(`https://engine.example${path}`, { method: "POST", body: JSON.stringify(body), headers }));
}

// registerAndLogin runs the full ceremony for an email and returns the session cookie a successful login
// minted (the exact "name=value" pair the browser would echo back). It drives the REAL router + DO + the
// fake-but-real authenticator end to end, so the cookie is signed by the DO's real session key.
// register runs the full registration ceremony for an email over a PROVEN path (the account-takeover fix):
//  - default (no opts): the BOOTSTRAP path, presenting env.ADMIN_TOKEN as the bearer (the first-Owner claim
//    on an empty table). This is the common setup for the first registrant in a fresh scheduler.
//  - { inviteToken }: the INVITE path (the email comes from the invite the DO minted on a role grant).
//  - { cookie }: the SELF-ADD path (an authenticated session adding a credential to its own email).
// It returns the finish Resp (carrying the minted session cookie on success).
async function register(env: Env, auth: Authenticator, email: string, opts: { inviteToken?: string; cookie?: string; bearer?: string } = {}): Promise<Resp> {
  // Default to the bootstrap bearer (env.ADMIN_TOKEN) when no explicit proof is supplied.
  const bearer = opts.bearer ?? (opts.inviteToken === undefined && opts.cookie === undefined ? (typeof env.ADMIN_TOKEN === "string" ? env.ADMIN_TOKEN : undefined) : undefined);
  const authOpts = { ...(bearer !== undefined ? { bearer } : {}), ...(opts.cookie !== undefined ? { cookie: opts.cookie } : {}) };
  const beginBody = { email, ...(opts.inviteToken !== undefined ? { inviteToken: opts.inviteToken } : {}) };
  const begin = await postAuth(env, "/admin/auth/register/begin", beginBody, authOpts);
  // A refused begin has no publicKey; return it so the caller can assert the refusal.
  if (begin.json?.ok !== true) return begin;
  // ok === true here, so the begin succeeded and the options (publicKey) are present.
  const att = await buildAttestation(auth, begin.json.publicKey!.challenge);
  return postAuth(env, "/admin/auth/register/finish", { email, credential: att, ...(opts.inviteToken !== undefined ? { inviteToken: opts.inviteToken } : {}) }, authOpts);
}
async function login(env: Env, auth: Authenticator, email: string): Promise<Resp> {
  const begin = await postAuth(env, "/admin/auth/login/begin", { email });
  // login/begin always returns the request options (publicKey) for an enrolled email.
  const asr = await signAssertion(auth, begin.json.publicKey!.challenge);
  return postAuth(env, "/admin/auth/login/finish", { challengeId: begin.json.challengeId, credential: asr });
}
// cookiePair turns a Set-Cookie header value into the "name=value" the browser would send back on Cookie.
function cookiePair(setCookie: string | null): string | null {
  if (setCookie === null) return null;
  const first = setCookie.split(";")[0]!;
  return first.trim();
}

// ---- A real RS256 Access JWT + a global fetch stub for the JWKS (for the precedence test) ------
// To drive the REAL Access path through authorise(), we stand up a real RSA key, publish its JWK at the
// account's Access certs URL, and stub globalThis.fetch so authorise()'s internal fetchCertsCached returns
// it. This exercises the genuine verifyAccessJWT inside authorise(), so the precedence test is real.
const ACCESS_TEAM = "maelstrom";
const ACCESS_AUD = "test-aud-tag";
const ACCESS_KID = "sess-test-kid";
function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}
async function makeAccessSetup(): Promise<{ env: Partial<Env>; makeToken: (email: string) => Promise<string>; restoreFetch: () => void }> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: ACCESS_KID, kty: "RSA", n: pub.n, e: pub.e }] };
  const certsUrl = `https://${ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`;
  const origFetch = globalThis.fetch;
  // Stub fetch ONLY for the certs URL; anything else throws so a stray fetch is caught loudly.
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (u === certsUrl) return new Response(JSON.stringify(jwks), { status: 200, headers: { "content-type": "application/json" } });
    throw new Error(`unexpected fetch in test: ${u}`);
  }) as typeof fetch;
  const makeToken = async (email: string): Promise<string> => {
    const now = Math.floor(Date.now() / 1000);
    const header = jwtPart({ alg: "RS256", kid: ACCESS_KID, typ: "JWT" });
    // The Access verdict now requires a stable subject (iss+"|"+sub), so the forged token carries a sub.
    const body = jwtPart({ iss: `https://${ACCESS_TEAM}.cloudflareaccess.com`, aud: ACCESS_AUD, exp: now + 3600, iat: now, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  };
  return { env: { CF_ACCESS_TEAM_DOMAIN: ACCESS_TEAM, CF_ACCESS_AUD: ACCESS_AUD }, makeToken, restoreFetch: () => { globalThis.fetch = origFetch; } };
}

async function run(): Promise<void> {
  console.log("validate-session: the passkey session layer + the access>passkey>token precedence gate");

  // ============================================================================================
  // 1. The PURE session core: sign + verify round-trip, and every tamper/expiry negative control.
  // ============================================================================================
  {
    const key = crypto.getRandomValues(new Uint8Array(SESSION_KEY_BYTES));
    const now = 1_780_000_000_000;
    const email = "alice@example.com";
    const token = await signSession(key, { method: "passkey", email, subject: passkeySubject(email), epoch: 0 }, now);

    ok("session token is body.mac shaped (one dot)", token.split(".").length === 2);
    const v = await verifySession(key, token, now + 1000);
    ok("verifySession returns the signed email", v !== null && v.email === email);
    ok("verifySession round-trips the epoch", v !== null && v.epoch === 0);
    ok("verifySession (V3) returns the signed subject + method + null connId", v !== null && v.subject === passkeySubject(email) && v.method === "passkey" && v.connId === null);

    // A reusable HMAC-with-the-real-key helper to forge SIGNED bodies for the version/consistency vectors.
    const macWithKey = async (b: string): Promise<string> =>
      b64urlEncode(new Uint8Array(await crypto.subtle.sign(
        "HMAC",
        await crypto.subtle.importKey("raw", key as Uint8Array<ArrayBuffer>, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
        new TextEncoder().encode(b) as Uint8Array<ArrayBuffer>,
      )));

    // V2 (legacy) graceful acceptance: a v2-shaped token (no method/subject) still verifies, as method
    // "passkey" with the subject RE-DERIVED as passkeySubject(email) and connId null (no forced re-auth at
    // the v2->v3 cutover). A v2 token can never be oidc/saml, which preserves the anti-forge property.
    const v2Body = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 2, email, epoch: 0, iat: now, exp: now + SESSION_TTL_MS })));
    const v2 = await verifySession(key, `${v2Body}.${await macWithKey(v2Body)}`, now + 1000);
    ok("a legacy V2 token verifies as passkey with the re-derived subject", v2 !== null && v2.method === "passkey" && v2.subject === passkeySubject(email) && v2.connId === null && v2.email === email);

    // AUTH-25: a legacy V2 token carries NO lastSeen, so the V7.3.1 IDLE bound does NOT apply to it -
    // verifyV2Body keeps it valid on its absolute exp alone (the graceful v2->v3 cutover, no forced re-auth),
    // whereas a V3 token at the SAME idle is rejected. This locks the differential the existing tests above
    // (which only verify a FRESH v2 at now+1000) never asserted. Pick an idle point well past SESSION_IDLE_MS
    // but still INSIDE the 12h absolute cap, so the only thing that could reject the V2 token is an idle check
    // (and there is none for v2). `token` is the V3 passkey token minted at `now` (lastSeen = now).
    const idleNow = now + SESSION_IDLE_MS + 60 * 60 * 1000; // 1h past the idle bound
    ok("AUTH-25: the idle probe point is past SESSION_IDLE_MS but within the absolute cap", idleNow - now >= SESSION_IDLE_MS && idleNow < now + SESSION_TTL_MS);
    const v2Idle = await verifySession(key, `${v2Body}.${await macWithKey(v2Body)}`, idleNow);
    ok("AUTH-25: a legacy V2 token (no lastSeen) STILL verifies when idle for hours (< 12h absolute)", v2Idle !== null && v2Idle.method === "passkey" && v2Idle.email === email);
    ok("AUTH-25: an equivalent V3 token at the SAME idle is REJECTED (the idle bound applies to v3 only)", (await verifySession(key, token, idleNow)) === null);

    // V3 anti-forge: an oidc session carries its OWN signed subject + connId; verifySession returns them
    // VERBATIM (never re-derived to passkeySubject), so a native session can never collapse onto a passkey
    // principal even when its email matches a passkey user's.
    const oidcSub = "oidc:entra|https://login.microsoftonline.com/t/v2.0|abc-123";
    const oidcTok = await signSession(key, { method: "oidc", email, subject: oidcSub, connId: "entra", epoch: 0 }, now);
    const ov = await verifySession(key, oidcTok, now + 1000);
    ok("a V3 oidc token keeps its SIGNED subject + connId (anti-forge)", ov !== null && ov.method === "oidc" && ov.subject === oidcSub && ov.connId === "entra" && ov.email === email);
    // Consistency guard: a v3 'oidc' token with NO connId is rejected.
    const oidcNoConnBody = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 3, method: "oidc", email, subject: oidcSub, epoch: 0, iat: now, exp: now + SESSION_TTL_MS })));
    ok("a V3 oidc token with NO connId is rejected (consistency guard)", (await verifySession(key, `${oidcNoConnBody}.${await macWithKey(oidcNoConnBody)}`, now + 1000)) === null);
    // Consistency guard: a v3 'passkey' token WITH a connId is rejected.
    const pkConnBody = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 3, method: "passkey", email, subject: passkeySubject(email), connId: "entra", epoch: 0, iat: now, exp: now + SESSION_TTL_MS })));
    ok("a V3 passkey token WITH a connId is rejected (consistency guard)", (await verifySession(key, `${pkConnBody}.${await macWithKey(pkConnBody)}`, now + 1000)) === null);

    // IDLE TIMEOUT (ASVS V7.3.1): a token is rejected after SESSION_IDLE_MS of inactivity, INDEPENDENT of the
    // far-off absolute exp. `token` carries lastSeen = now (its mint instant), so the idle clock runs from now.
    ok("verifySession accepts a token within the idle window", (await verifySession(key, token, now + SESSION_IDLE_MS - 1000)) !== null);
    ok("verifySession rejects a token idle == SESSION_IDLE_MS (V7.3.1)", (await verifySession(key, token, now + SESSION_IDLE_MS)) === null);
    ok(
      "verifySession idle-rejects even though the absolute exp is far off",
      now + SESSION_IDLE_MS + 1000 < now + SESSION_TTL_MS && (await verifySession(key, token, now + SESSION_IDLE_MS + 1000)) === null,
    );

    // ABSOLUTE EXPIRY (independent of activity): even a freshly-SLID session dies at its absolute exp. A slid
    // re-mint preserves iat + exp and moves lastSeen to the slide instant, so lastSeen is FRESH near exp and
    // the idle bound is not the reason for rejection here - the absolute cap is.
    const absExp = now + SESSION_TTL_MS;
    const slidNearExp = await signSession(key, { method: "passkey", email, subject: passkeySubject(email), epoch: 0, slide: { iat: now, exp: absExp } }, absExp - 1000);
    ok("a slid token preserves its absolute exp (accepted just before exp, lastSeen fresh)", (await verifySession(key, slidNearExp, absExp - 1)) !== null);
    ok("verifySession rejects at the absolute exp (now == exp)", (await verifySession(key, slidNearExp, absExp)) === null);
    ok("verifySession rejects past the absolute exp (now > exp)", (await verifySession(key, slidNearExp, absExp + 1)) === null);
    // The slide did NOT extend the cap: a token minted-then-slid at mint+11h still dies at the original mint+12h.
    const slidAt11h = await signSession(key, { method: "passkey", email, subject: passkeySubject(email), epoch: 0, slide: { iat: now, exp: absExp } }, now + 11 * 60 * 60 * 1000);
    ok("a token re-minted (slid) at mint+11h still expires at the original mint+12h (no unbounded window)", (await verifySession(key, slidAt11h, absExp + 1)) === null);

    // Wrong key: a token signed by a DIFFERENT key must not verify (the MAC binds to the key).
    const otherKey = crypto.getRandomValues(new Uint8Array(SESSION_KEY_BYTES));
    ok("verifySession rejects a token signed with a different key", (await verifySession(otherKey, token, now + 1000)) === null);

    // Tampered MAC: flip a byte in the mac segment -> reject.
    const [body, mac] = token.split(".") as [string, string];
    const macBytes = b64urlDecode(mac);
    macBytes[0] = macBytes[0]! ^ 0x01;
    ok("verifySession rejects a tampered MAC", (await verifySession(key, `${body}.${b64urlEncode(macBytes)}`, now + 1000)) === null);

    // Tampered body: re-encode the body with a DIFFERENT email but keep the ORIGINAL mac -> reject (the
    // MAC no longer matches the body, and the body is never trusted without a matching MAC).
    const forgedBody = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 2, email: "evil@example.com", epoch: 0, iat: now, exp: now + SESSION_TTL_MS })));
    ok("verifySession rejects a tampered body kept with the old MAC", (await verifySession(key, `${forgedBody}.${mac}`, now + 1000)) === null);

    // A body forged AND self-MAC'd with the WRONG key cannot verify under the real key (covers the
    // "attacker mints their own token" case): the email is attacker-chosen but the MAC is under otherKey.
    const evilToken = await signSession(otherKey, { method: "passkey", email: "evil@example.com", subject: passkeySubject("evil@example.com"), epoch: 0 }, now);
    ok("verifySession rejects an attacker-self-signed token", (await verifySession(key, evilToken, now + 1000)) === null);

    // EMAILLESS guard at the core: a body with an empty email, self-MAC'd with the REAL key, is refused.
    // This proves the guard is in verifySession (not only upstream): even a perfectly-signed token with no
    // email yields null, so an email-less session can never be minted into an identity.
    const emaillessBody = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 2, email: "", epoch: 0, iat: now, exp: now + SESSION_TTL_MS })));
    const emaillessMac = b64urlEncode(new Uint8Array(await crypto.subtle.sign(
      "HMAC",
      await crypto.subtle.importKey("raw", key as Uint8Array<ArrayBuffer>, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
      new TextEncoder().encode(emaillessBody) as Uint8Array<ArrayBuffer>,
    )));
    ok("verifySession rejects a validly-signed but EMAILLESS token (emailless guard)", (await verifySession(key, `${emaillessBody}.${emaillessMac}`, now + 1000)) === null);

    // A wrong VERSION (validly signed) is rejected (forward-safe format pinning).
    const wrongVerBody = b64urlEncode(new TextEncoder().encode(JSON.stringify({ v: 99, email, iat: now, exp: now + SESSION_TTL_MS })));
    const wrongVerMac = b64urlEncode(new Uint8Array(await crypto.subtle.sign(
      "HMAC",
      await crypto.subtle.importKey("raw", key as Uint8Array<ArrayBuffer>, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
      new TextEncoder().encode(wrongVerBody) as Uint8Array<ArrayBuffer>,
    )));
    ok("verifySession rejects an unknown version", (await verifySession(key, `${wrongVerBody}.${wrongVerMac}`, now + 1000)) === null);

    // Malformed shapes: empty, no dot, multi-dot, non-base64url mac.
    ok("verifySession rejects an empty token", (await verifySession(key, "", now)) === null);
    ok("verifySession rejects a token with no dot", (await verifySession(key, "abcdef", now)) === null);
    ok("verifySession rejects a multi-dot token", (await verifySession(key, `${body}.${mac}.extra`, now)) === null);
    ok("verifySession rejects a non-base64url MAC", (await verifySession(key, `${body}.****`, now)) === null);
  }

  // ============================================================================================
  // 2. The cookie helpers: the hardened attributes, the clear, and the Cookie-header parse.
  // ============================================================================================
  {
    const sc = sessionSetCookie("tok123");
    ok("Set-Cookie names the __Host- session cookie", sc.startsWith(`${SESSION_COOKIE_NAME}=tok123;`));
    ok("Set-Cookie is HttpOnly", /;\s*HttpOnly(;|$)/.test(sc));
    ok("Set-Cookie is Secure", /;\s*Secure(;|$)/.test(sc));
    ok("Set-Cookie is SameSite=Strict", /;\s*SameSite=Strict(;|$)/.test(sc));
    ok("Set-Cookie is Path=/", /;\s*Path=\/(;|$)/.test(sc));
    ok("Set-Cookie has Max-Age = TTL seconds", sc.includes(`Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`));
    ok("Set-Cookie has NO Domain (required by __Host-)", !/;\s*Domain=/i.test(sc));

    const clear = sessionClearCookie();
    ok("clear cookie has Max-Age=0", /;\s*Max-Age=0(;|$)/.test(clear));
    ok("clear cookie keeps HttpOnly+Secure+SameSite", /HttpOnly/.test(clear) && /Secure/.test(clear) && /SameSite=Strict/.test(clear));

    // readSessionCookie locates the session value among other cookies, trims, and ignores others.
    const reqWith = new Request("https://e.example/admin/x", { headers: { cookie: `other=1; ${SESSION_COOKIE_NAME}=theTok ; foo=bar` } });
    ok("readSessionCookie extracts the session value", readSessionCookie(reqWith) === "theTok");
    ok("readSessionCookie returns null with no cookie header", readSessionCookie(new Request("https://e.example/admin/x")) === null);
    ok("readSessionCookie returns null when the session cookie is absent", readSessionCookie(new Request("https://e.example/admin/x", { headers: { cookie: "other=1" } })) === null);

    // originAllowed: strict match only.
    ok("originAllowed true on exact CONSOLE_ORIGIN", originAllowed(new Request("https://e/x", { headers: { origin: ORIGIN } }), ORIGIN));
    ok("originAllowed false on a foreign origin", !originAllowed(new Request("https://e/x", { headers: { origin: "https://evil.example" } }), ORIGIN));
    ok("originAllowed false on a missing Origin header", !originAllowed(new Request("https://e/x"), ORIGIN));
    ok("originAllowed false when CONSOLE_ORIGIN is unset", !originAllowed(new Request("https://e/x", { headers: { origin: ORIGIN } }), undefined));
  }

  // ============================================================================================
  // 3. END TO END through the REAL router: register -> login -> a Set-Cookie that AUTHORISES.
  // ============================================================================================
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";

    const reg = await register(env, auth, email);
    ok("register/finish verifies + bootstraps the first registrant to Owner", reg.status === 200 && reg.json.ok === true && reg.json.bootstrapped === true && reg.json.role === "owner");
    ok("register/finish mints a session cookie (registration signs you in)", reg.setCookie !== null && reg.setCookie.startsWith(`${SESSION_COOKIE_NAME}=`));
    ok("a session signing key was generated + persisted in the DO", storage.countPrefix("passkeySessionKey") === 1);

    const lgn = await login(env, auth, email);
    ok("login/finish verifies the assertion + returns the email", lgn.status === 200 && lgn.json.ok === true && lgn.json.email === email);
    ok("login/finish mints a session cookie", lgn.setCookie !== null);

    // Present the login cookie to an authenticated read: it AUTHORISES as method:passkey + Owner.
    const cookie = cookiePair(lgn.setCookie)!;
    const who = await getAdmin(env, "/admin/whoami", { cookie });
    ok("a valid session cookie authorises GET /admin/whoami", who.status === 200);
    ok("the session resolves method:passkey", who.json.method === "passkey");
    ok("the session resolves the bootstrapped Owner role", who.json.role === "owner");
    ok("the session resolves the verified email", who.json.email === email);

    // No cookie at all -> 401 (no Access, no token configured here).
    const none = await getAdmin(env, "/admin/whoami", {});
    ok("no credential at all is 401", none.status === 401);
  }

  // ============================================================================================
  // 3d. AUTH-30: SESSION-KEY COLD-START. On a COLD DO (no key persisted) the first sessionSigningKey()
  //     caller GENERATES + persists the key inside blockConcurrencyWhile, RE-READING inside the gate so a
  //     single key wins; every later caller takes the fast-path read of that same persisted key. Deleting
  //     the key (terminate-all) regenerates a fresh one on the next call (the global sign-out lever).
  //
  //     OFFLINE LIMIT (documented honestly): the validator's storage double has NO blockConcurrencyWhile, so
  //     the gate FALLS BACK to running fn DIRECTLY and the DO is driven SERIALLY (scheduler-do-session.ts
  //     :79-83). This cannot reproduce a TRUE two-callers-at-once cold-start race (the input-gate atomicity
  //     that makes one writer win) - that needs a live DO / workerd concurrency harness. The closest faithful
  //     offline assertions below: the key is generated exactly ONCE, is STABLE across calls, two OVERLAPPING
  //     (Promise.all) cold-start calls resolve to the SAME key, and the key + epoch ROUND-TRIP through a
  //     minted-then-verified token (and an epoch bump then rejects the pre-bump session).
  // ============================================================================================
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    ok("AUTH-30: the DO starts cold (no session signing key persisted)", storage.countPrefix("passkeySessionKey") === 0);
    // First cold-start caller GENERATES + persists exactly one key (the read-generate-write inside the gate).
    const k1 = await dobj.sessionSigningKey();
    ok("AUTH-30: the first cold-start caller persists exactly ONE session signing key", storage.countPrefix("passkeySessionKey") === 1);
    // A later (serial) caller reads the SAME persisted key (the fast path; a present valid key is never
    // rewritten), and still exactly one key exists. This is the property the offline serial driver CAN prove.
    const k3 = await dobj.sessionSigningKey();
    ok("AUTH-30: a later caller reads the SAME persisted key (stable, never regenerated)", b64urlEncode(k3) === b64urlEncode(k1) && storage.countPrefix("passkeySessionKey") === 1);
    // RESIDUAL (honest): the TRUE cold-start race - two callers hitting an empty DO AT ONCE, where the input
    // gate must make a single writer win - is NOT reproducible here: the storage double has no
    // blockConcurrencyWhile, so the gate runs fn DIRECTLY and the DO is driven serially (scheduler-do-session
    // .ts:79-87). Under that double, Promise.all([sessionSigningKey(), sessionSigningKey()]) on a cold DO can
    // legitimately DIVERGE (both fast-read undefined, both generate, last write wins), which is exactly why we
    // assert the serial-stability invariant above rather than a concurrent one. The atomic one-key-wins
    // property needs a live DO / workerd concurrency harness (the chaos tier).
    // KEY ROUND-TRIP: a token minted with the cold-started key verifies; EPOCH ROUND-TRIP: it carries the
    // email's stored epoch, and bumping that epoch rejects the pre-bump session.
    const cse = "coldstart@example.com";
    const issued = await dobj.passkeySessionIssue({ email: cse });
    const issuedTok = issued.ok ? issued.token : "";
    ok("AUTH-30: a session minted with the cold-started key verifies (key round-trip)", issued.ok === true && (await dobj.passkeySessionVerify({ token: issuedTok })).email === cse);
    ok("AUTH-30: the cold-started session is at the stored epoch 0 (epoch round-trip)", (await dobj.getSessionEpoch(cse)) === 0);
    await dobj.bumpSessionEpoch(cse);
    ok("AUTH-30: bumping the epoch rejects the pre-bump cold-started session (epoch round-trip)", (await dobj.passkeySessionVerify({ token: issuedTok })).email === null);
    // Deleting the key (the terminate-all lever) regenerates a DIFFERENT fresh key on the next call.
    await storage.delete("passkeySessionKey");
    const k4b64 = b64urlEncode(await dobj.sessionSigningKey());
    ok("AUTH-30: deleting the key regenerates a fresh, DIFFERENT key (the global sign-out lever)", k4b64 !== b64urlEncode(k1) && storage.countPrefix("passkeySessionKey") === 1);
  }

  // ============================================================================================
  // 3b. SESSION EPOCH + TERMINATION (ASVS V7.4.3 / V7.4.5 / V7.5.2) + PASSKEY REVOKE (V6.5.6)
  //     Two concurrent sessions for one Owner; terminate-others keeps the current one and kills the
  //     other; admin terminate-user kills by email; terminate-all rotates the key (global sign-out);
  //     the sole-Owner's last passkey cannot be revoked.
  // ============================================================================================
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";
    await register(env, auth, email); // bootstrap Owner + first credential
    // signAssertion sends auth.signCount + 1 but does not persist it, so advance the authenticator's own
    // counter between assertions or the WebAuthn clone-detection (signCount must strictly increase) would
    // reject the second login. freshLogin bumps it so each login carries a higher counter.
    let sc = 0;
    const freshLogin = async (): Promise<Resp> => { auth.signCount = sc; const r = await login(env, auth, email); sc++; return r; };
    const a = await freshLogin();
    const b = await freshLogin();
    const cookieA = cookiePair(a.setCookie)!;
    const cookieB = cookiePair(b.setCookie)!;
    ok("two concurrent sessions both authorise", (await getAdmin(env, "/admin/whoami", { cookie: cookieA })).status === 200 && (await getAdmin(env, "/admin/whoami", { cookie: cookieB })).status === 200);

    // Passkey credential management: list shows the one enrolled key; revoking the SOLE Owner's LAST
    // passkey is refused (availability guard), and the credential survives.
    const creds = await getAdmin(env, "/admin/passkey/credentials", { cookie: cookieA });
    ok("GET passkey credentials lists the enrolled key", creds.status === 200 && Array.isArray(creds.json.credentials) && creds.json.credentials.length === 1);
    const credId = creds.json.credentials![0]!.credentialId;
    const delLast = await postAdmin(env, "/admin/passkey/credentials/delete", { credentialId: credId }, { cookie: cookieA, origin: ORIGIN });
    ok("revoking the sole Owner's last passkey is refused", delLast.status >= 400 && /last passkey/.test(delLast.json.error ?? ""));
    ok("the credential survives the refused revoke", (await getAdmin(env, "/admin/passkey/credentials", { cookie: cookieA })).json.credentials!.length === 1);

    // CSRF double-submit is enforced server-side on the termination routes, ON TOP of the Origin
    // guard. A cookie-borne caller with a correct Origin but NO/ WRONG csrf token is refused 403 (fail closed).
    {
      const noTok = await postAdmin(env, "/admin/sessions/terminate-others", {}, { cookie: cookieB, origin: ORIGIN });
      ok("terminate-others: correct Origin but NO csrf token -> 403", noTok.status === 403);
      const badTok = await postAdmin(env, "/admin/sessions/terminate-others", {}, { cookie: cookieB, origin: ORIGIN, csrf: "header-value", csrfCookie: "different-cookie-value" });
      ok("terminate-others: csrf header != cookie -> 403", badTok.status === 403);
    }
    // terminate-others (V7.5.2): called with cookieB + a matching csrf double-submit; bumps the epoch (killing
    // cookieA) and re-issues a fresh cookie for THIS session.
    const term = await postAdmin(env, "/admin/sessions/terminate-others", {}, { cookie: cookieB, origin: ORIGIN, csrf: "csrf-tok-a" });
    ok("terminate-others succeeds and re-issues a cookie", term.status === 200 && term.setCookie !== null);
    const cookieBnew = cookiePair(term.setCookie)!;
    ok("the OTHER session (cookieA) is now invalid (stale epoch)", (await getAdmin(env, "/admin/whoami", { cookie: cookieA })).status === 401);
    ok("the re-issued current session still authorises", (await getAdmin(env, "/admin/whoami", { cookie: cookieBnew })).status === 200);
    ok("the pre-terminate cookieB (stale epoch) is invalid", (await getAdmin(env, "/admin/whoami", { cookie: cookieB })).status === 401);

    // admin terminate-user (V7.4.5): the Owner terminates their own email's sessions -> the current one dies.
    const tu = await postAdmin(env, "/admin/sessions/terminate-user", { email }, { cookie: cookieBnew, origin: ORIGIN, csrf: "csrf-tok-b" });
    ok("terminate-user succeeds (200)", tu.status === 200);
    ok("the session is invalid after terminate-user bumped the epoch", (await getAdmin(env, "/admin/whoami", { cookie: cookieBnew })).status === 401);

    // A fresh login carries the new epoch and works; terminate-all (V7.4.5 all-users) then rotates the
    // signing key, so even that fresh session dies (global sign-out).
    const c = await freshLogin();
    const cookieC = cookiePair(c.setCookie)!;
    ok("a fresh login after the bumps authorises (new epoch)", (await getAdmin(env, "/admin/whoami", { cookie: cookieC })).status === 200);
    const all = await postAdmin(env, "/admin/sessions/terminate-all", {}, { cookie: cookieC, origin: ORIGIN, csrf: "csrf-tok-c" });
    ok("terminate-all succeeds for the Owner (200)", all.status === 200);
    ok("every session is invalid after terminate-all rotated the key", (await getAdmin(env, "/admin/whoami", { cookie: cookieC })).status === 401);
  }

  // ============================================================================================
  // 3b2. TERMINATE-OTHERS MUST NOT RE-MINT AS A FRESH LOGIN (ASVS V7.3 / V7.5.1). Self-service
  //      "terminate my other sessions" is housekeeping on an ALREADY-established session, not a fresh
  //      authentication: the re-mint must be a SLIDE (preserve the caller's presented iat/exp), exactly
  //      like the idle-slide, so a stale-but-valid session cannot use this one benign endpoint to silently
  //      reset the step-up freshness clock or extend the absolute 12h cap.
  // ============================================================================================
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";
    await register(env, auth, email);
    await login(env, auth, email); // ensures the signing key exists

    // Forge a STALE-but-ACTIVE session with the DO's OWN key: iat/exp are 10h old (well past the 5-minute
    // STEPUP_FRESH_MS window, still inside the 12h TTL) while lastSeen is minted fresh (a slide re-mint, as
    // an idle-active session would carry) - exactly the exploit's precondition (a stolen 10h-old cookie).
    const keyRec = await storage.get<{ key: string }>("passkeySessionKey");
    const doKey = b64urlDecode(keyRec!.key);
    const now = Date.now();
    const staleIat = now - 10 * 60 * 60 * 1000;
    const staleExp = staleIat + SESSION_TTL_MS;
    const staleToken = await signSession(doKey, { method: "passkey", email, subject: passkeySubject(email), epoch: 0, slide: { iat: staleIat, exp: staleExp } }, now);
    const staleCookie = `${SESSION_COOKIE_NAME}=${staleToken}`;

    // Precondition: this stale session is already step-up-blocked (proves the harness, not just the fix).
    const pre = await postAdmin(env, "/admin/posture/accept", {}, { cookie: staleCookie, origin: ORIGIN });
    ok("a stale (10h-old) session is step-up-blocked before terminate-others", pre.status === 401 && pre.json?.stepUpRequired === true);

    // Self-service terminate-others with the STALE cookie: no fresh login, no WebAuthn assertion. Carries a
    // matching csrf double-submit (ML-02), which is orthogonal to the step-up-freshness property under test.
    const term = await postAdmin(env, "/admin/sessions/terminate-others", {}, { cookie: staleCookie, origin: ORIGIN, csrf: "csrf-tok-stale" });
    ok("terminate-others succeeds and re-issues a cookie", term.status === 200 && term.setCookie !== null);
    const reissuedCookie = cookiePair(term.setCookie)!;

    // The re-issued cookie must STILL be step-up-blocked, or a fresh re-mint with iat=now would make a
    // 10h-old session look freshly authenticated for 5 minutes with zero WebAuthn proof.
    const post = await postAdmin(env, "/admin/posture/accept", {}, { cookie: reissuedCookie, origin: ORIGIN });
    ok("the re-minted cookie is STILL step-up-blocked (iat preserved, not reset to now)", post.status === 401 && post.json?.stepUpRequired === true);

    // And directly: the re-minted token's iat/exp are BYTE-IDENTICAL to the presented stale token's (a
    // slide, never a fresh mint), so the absolute 12h cap is never silently extended either.
    const reissuedTok = readSessionCookie(new Request("https://engine.example/", { headers: { cookie: reissuedCookie } }));
    const verified = reissuedTok !== null ? await verifySession(doKey, reissuedTok, now) : null;
    ok("the re-mint preserves the ORIGINAL iat (a slide, never a fresh login)", verified !== null && verified.iat === staleIat);
    ok("the re-mint preserves the ORIGINAL absolute exp (the 12h cap is never silently extended)", verified !== null && verified.exp === staleExp);
  }

  // ============================================================================================
  // 3c. LOGOUT TERMINATES THE SESSION SERVER-SIDE (ASVS V7.4.1 / V7.4.2). A clear-only logout left a
  //     captured/exfiltrated COPY of the bearer token valid until exp; the engine bumps the identity's
  //     epoch on logout so the just-logged-out token (and any copy) dies on its next request. The
  //     cross-origin CSRF guard still protects, and a REFUSED logout terminates nothing.
  // ============================================================================================
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";
    await register(env, auth, email);
    // Advance the authenticator's signCount between assertions (WebAuthn clone-detection requires a strictly
    // increasing counter), exactly as block 3b does.
    let sc = 0;
    const freshLogin = async (): Promise<Resp> => { auth.signCount = sc; const r = await login(env, auth, email); sc++; return r; };
    const l1 = await freshLogin();
    const cookie1 = cookiePair(l1.setCookie)!;
    ok("session authorises before logout", (await getAdmin(env, "/admin/whoami", { cookie: cookie1 })).status === 200);
    const out = await postAdmin(env, "/admin/auth/logout", {}, { cookie: cookie1, origin: ORIGIN });
    ok("logout returns 200", out.status === 200);
    ok("the SAME token is rejected after logout (server-side epoch bump, not just a cleared cookie)", (await getAdmin(env, "/admin/whoami", { cookie: cookie1 })).status === 401);

    // A fresh login carries the new epoch and authorises; a CROSS-ORIGIN logout is refused 403 (CSRF) and
    // must NOT terminate the session (no bump on a refused request).
    const l2 = await freshLogin();
    const cookie2 = cookiePair(l2.setCookie)!;
    ok("a fresh login after logout authorises (new epoch)", (await getAdmin(env, "/admin/whoami", { cookie: cookie2 })).status === 200);
    const xo = await postAdmin(env, "/admin/auth/logout", {}, { cookie: cookie2, origin: "https://evil.example" });
    ok("a cross-origin logout is refused 403", xo.status === 403);
    ok("a refused cross-origin logout does NOT terminate the session", (await getAdmin(env, "/admin/whoami", { cookie: cookie2 })).status === 200);
  }

  // ============================================================================================
  // 4. ANTI-DOWNGRADE: an INVALID / EXPIRED / TAMPERED session cookie is rejected AND never falls
  //    through to the token path, even with ADMIN_TOKEN configured.
  // ============================================================================================
  {
    const TOKEN = "break-glass-token-value";
    const { env } = makeScheduler({ ADMIN_TOKEN: TOKEN });
    const auth = await makeAuthenticator();
    await register(env, auth, "owner@example.com");
    const lgn = await login(env, auth, "owner@example.com");
    const goodCookie = cookiePair(lgn.setCookie)!;

    // Sanity: the bare token DOES authorise when presented alone (no cookie) -> owner.
    const tokWho = await getAdmin(env, "/admin/whoami", { bearer: TOKEN });
    ok("the bare ADMIN_TOKEN authorises when presented alone", tokWho.status === 200 && tokWho.json.method === "token" && tokWho.json.role === "owner");

    // A TAMPERED cookie (flip a char in the value) presented ALONGSIDE the valid bearer must FAIL CLOSED
    // (401), NOT downgrade to the token. This is the core anti-downgrade property.
    const tampered = goodCookie.slice(0, -1) + (goodCookie.endsWith("A") ? "B" : "A");
    const downgrade = await getAdmin(env, "/admin/whoami", { cookie: tampered, bearer: TOKEN });
    ok("a tampered session cookie does NOT downgrade to the token (401)", downgrade.status === 401);

    // A GARBAGE cookie value alongside the bearer: same fail-closed.
    const garbage = `${SESSION_COOKIE_NAME}=not-a-real-token`;
    const downgrade2 = await getAdmin(env, "/admin/whoami", { cookie: garbage, bearer: TOKEN });
    ok("a garbage session cookie does NOT downgrade to the token (401)", downgrade2.status === 401);

    // An EXPIRED-but-validly-signed cookie: mint one directly with the DO's real key at a past time, so
    // the MAC is valid but exp is in the past. It must be rejected and not downgrade. We reach the DO key
    // via the issue route is now-stamped, so instead craft using the stored key.
    // (The stored key is the source of truth; read it out of storage to mint a past-dated token.)
  }

  // ============================================================================================
  // 4b. EXPIRED session: mint a valid-MAC past-exp token with the DO's real key and prove it 401s and
  //     does not downgrade to the token.
  // ============================================================================================
  {
    const TOKEN = "break-glass-token-value";
    const { env, storage } = makeScheduler({ ADMIN_TOKEN: TOKEN });
    const auth = await makeAuthenticator();
    await register(env, auth, "owner@example.com");
    await login(env, auth, "owner@example.com"); // ensures the key exists
    const keyRec = await storage.get<{ key: string }>("passkeySessionKey");
    const key = b64urlDecode(keyRec!.key);
    // Sign a token whose exp is already in the past (iat far back so exp = iat + TTL is also past).
    const pastNow = Date.now() - SESSION_TTL_MS - 60_000;
    const expiredToken = await signSession(key, { method: "passkey", email: "owner@example.com", subject: passkeySubject("owner@example.com"), epoch: 0 }, pastNow);
    const expiredCookie = `${SESSION_COOKIE_NAME}=${expiredToken}`;
    const r = await getAdmin(env, "/admin/whoami", { cookie: expiredCookie, bearer: TOKEN });
    ok("an EXPIRED (valid-MAC) session is 401 and does not downgrade to the token", r.status === 401);
    // And a FRESH token with the same key authorises (proves the rejection above was the expiry, not the key).
    const freshToken = await signSession(key, { method: "passkey", email: "owner@example.com", subject: passkeySubject("owner@example.com"), epoch: 0 }, Date.now());
    const fresh = await getAdmin(env, "/admin/whoami", { cookie: `${SESSION_COOKIE_NAME}=${freshToken}` });
    ok("a fresh token minted with the SAME key authorises (rejection above was the expiry)", fresh.status === 200 && fresh.json.method === "passkey");
  }

  // ============================================================================================
  // 4c. IDLE-SLIDE (ASVS V7.3.1). slideDue is a pure threshold; end to end, an authenticated request on a
  //     session whose lastSeen is older than SESSION_SLIDE_MS re-issues a refreshed cookie (lastSeen moved to
  //     now, iat + absolute exp preserved); a FRESH session does not slide.
  // ============================================================================================
  ok("slideDue: false when lastSeen is recent (< SESSION_SLIDE_MS)", slideDue(Date.now() - (SESSION_SLIDE_MS - 1000), Date.now()) === false);
  ok("slideDue: true when lastSeen is older than SESSION_SLIDE_MS", slideDue(Date.now() - (SESSION_SLIDE_MS + 1000), Date.now()) === true);
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";
    await register(env, auth, email);
    const lgn = await login(env, auth, email);
    const freshCookie = cookiePair(lgn.setCookie)!;
    // A fresh session (lastSeen = now) does NOT slide: the GET returns no refreshed cookie.
    const noSlide = await getAdmin(env, "/admin/whoami", { cookie: freshCookie });
    ok("a fresh session is not slid (no refreshed cookie)", noSlide.status === 200 && noSlide.setCookie === null);
    // Forge a stale-lastSeen token with the DO's OWN signing key: slide-mint at (now - 20min) so lastSeen is
    // 20 min old (>= SESSION_SLIDE_MS) while iat/exp are now/now+TTL (valid). epoch 0 = the bootstrap owner.
    const keyRec = await storage.get<{ key: string }>("passkeySessionKey");
    const doKey = b64urlDecode(keyRec!.key);
    const now = Date.now();
    const staleToken = await signSession(doKey, { method: "passkey", email, subject: passkeySubject(email), epoch: 0, slide: { iat: now, exp: now + SESSION_TTL_MS } }, now - 20 * 60 * 1000);
    const slid = await getAdmin(env, "/admin/whoami", { cookie: `${SESSION_COOKIE_NAME}=${staleToken}` });
    ok("a stale-lastSeen session still authorises (not idle)", slid.status === 200);
    ok("a stale-lastSeen session is SLID: a refreshed cookie is issued (V7.3.1)", slid.setCookie !== null && slid.setCookie.includes(SESSION_COOKIE_NAME));
    // The refreshed (slid) cookie is valid and, verified again immediately, is NOT itself re-slid (lastSeen fresh).
    const refreshed = cookiePair(slid.setCookie)!;
    const after = await getAdmin(env, "/admin/whoami", { cookie: refreshed });
    ok("the refreshed slid cookie authorises and is not re-slid", after.status === 200 && after.setCookie === null);
  }

  // ============================================================================================
  // 3d. GET /whoami ISSUES the double-submit CSRF token for a COOKIE-BORNE session. The readable
  //     __Host-downpipes_csrf cookie and the whoami-body csrfToken are the SAME value (the console reads one,
  //     the browser holds the other, and they match on a terminate request). A token/access caller carries no
  //     ambient cookie, so it gets NEITHER (exempt, exactly like the strict-Origin guard).
  // ============================================================================================
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";
    await register(env, auth, email);
    const lgn = await login(env, auth, email);
    const cookie = cookiePair(lgn.setCookie)!;
    const who = await getAdmin(env, "/admin/whoami", { cookie });
    ok("whoami (cookie session): 200", who.status === 200);
    ok("whoami (cookie session): issues the readable __Host- CSRF cookie", who.csrfCookie !== null && who.csrfCookie.startsWith(`${CSRF_COOKIE_NAME}=`));
    const cookieToken = who.csrfCookie!.slice(who.csrfCookie!.indexOf("=") + 1).split(";")[0]!;
    ok("whoami (cookie session): surfaces a non-empty csrfToken in the body", typeof who.json.csrfToken === "string" && (who.json.csrfToken as string).length > 0);
    ok("whoami (cookie session): body token === cookie token (a matching double-submit pair)", who.json.csrfToken === cookieToken);
    // Readable by the SPA (NOT HttpOnly, so it can echo it) but still Secure + SameSite=Strict.
    ok("whoami: CSRF cookie is readable (no HttpOnly) yet Secure + SameSite=Strict", !/HttpOnly/i.test(who.csrfCookie!) && /Secure/i.test(who.csrfCookie!) && /SameSite=Strict/i.test(who.csrfCookie!));
    // Re-fetching whoami with the token already present REUSES it (stable across the session, not rotated).
    const who2 = await getAdmin(env, "/admin/whoami", { cookie: `${cookie}; ${CSRF_COOKIE_NAME}=${cookieToken}` });
    ok("whoami: an existing CSRF token is reused, not rotated", who2.json.csrfToken === cookieToken);
    // The token break-glass method is not cookie-borne -> no CSRF cookie, no body token.
    if (typeof env.ADMIN_TOKEN === "string") {
      const tokWho = await getAdmin(env, "/admin/whoami", { bearer: env.ADMIN_TOKEN });
      ok("whoami (token method): 200 and NO CSRF cookie/token (exempt, not cookie-borne)", tokWho.status === 200 && tokWho.csrfCookie === null && tokWho.json.csrfToken === undefined);
    }
  }

  // ============================================================================================
  // 4d. STEP-UP RE-AUTH (ASVS V7.5.1 / V7.5.3). A sensitive action (POST /admin/posture/accept) requires a
  //     FRESH re-authentication. A fresh owner session passes; a STALE session (iat older than STEPUP_FRESH_MS)
  //     is blocked 401 stepUpRequired; a fresh single-use passkey assertion mints a step-up token that
  //     unblocks it (and the token is single-use). A bare-token (ADMIN_TOKEN) caller is exempt.
  // ============================================================================================
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator();
    const email = "owner@example.com";
    await register(env, auth, email);
    let sc = 0;
    const freshLogin = async (): Promise<Resp> => { auth.signCount = sc; const r = await login(env, auth, email); sc++; return r; };
    const lgn = await freshLogin();
    const freshCookie = cookiePair(lgn.setCookie)!;
    // A FRESH owner session reaches the sensitive action (the step-up gate does not block a recent auth).
    const freshAccept = await postAdmin(env, "/admin/posture/accept", {}, { cookie: freshCookie, origin: ORIGIN });
    ok("a fresh session is NOT step-up-blocked on a sensitive action", !(freshAccept.status === 401 && freshAccept.json?.stepUpRequired === true));

    // A STALE session: iat older than STEPUP_FRESH_MS (lastSeen fresh, so it is not idle, only un-fresh for step-up).
    const keyRec = await storage.get<{ key: string }>("passkeySessionKey");
    const doKey = b64urlDecode(keyRec!.key);
    const now = Date.now();
    const staleToken = await signSession(doKey, { method: "passkey", email, subject: passkeySubject(email), epoch: 0, slide: { iat: now - (STEPUP_FRESH_MS + 60_000), exp: now + SESSION_TTL_MS } }, now);
    const staleCookie = `${SESSION_COOKIE_NAME}=${staleToken}`;
    const staleAccept = await postAdmin(env, "/admin/posture/accept", {}, { cookie: staleCookie, origin: ORIGIN });
    ok("a STALE session is step-up-blocked (401 stepUpRequired) on a sensitive action (V7.5.1)", staleAccept.status === 401 && staleAccept.json?.stepUpRequired === true);

    // Step-up ceremony: the stale session asserts a fresh passkey -> a single-use step-up token.
    const suBegin = await postAdmin(env, "/admin/stepup/begin", {}, { cookie: staleCookie, origin: ORIGIN });
    ok("stepup/begin issues a challenge for the caller's passkeys", suBegin.status === 200 && suBegin.json.ok === true && typeof suBegin.json.challengeId === "string");
    auth.signCount = sc; sc++;
    // stepup/begin succeeded above, so the request options (publicKey) are present.
    const suAsr = await signAssertion(auth, suBegin.json.publicKey!.challenge);
    const suFinish = await postAdmin(env, "/admin/stepup/finish", { challengeId: suBegin.json.challengeId, credential: suAsr }, { cookie: staleCookie, origin: ORIGIN });
    ok("stepup/finish verifies the fresh assertion and mints a step-up token", suFinish.status === 200 && suFinish.json.ok === true && typeof suFinish.json.stepUpToken === "string");
    const stepUpToken = suFinish.json.stepUpToken as string;

    const stepUpReq = (): Request => new Request("https://engine.example/admin/posture/accept", { method: "POST", body: JSON.stringify({}), headers: { "content-type": "application/json", cookie: staleCookie, origin: ORIGIN, "x-downpipes-stepup": stepUpToken } });
    const unblocked = await send(env, stepUpReq());
    ok("a valid single-use step-up token unblocks the sensitive action", !(unblocked.status === 401 && unblocked.json?.stepUpRequired === true));
    const reuse = await send(env, stepUpReq());
    ok("the step-up token is SINGLE-USE (a reuse is step-up-blocked again)", reuse.status === 401 && reuse.json?.stepUpRequired === true);

    // A bare-token (ADMIN_TOKEN) caller is EXEMPT (the all-or-nothing break-glass).
    const { env: tokEnv } = makeScheduler({ ADMIN_TOKEN: "bg-token-value" });
    const tokAccept = await postAdmin(tokEnv, "/admin/posture/accept", {}, { bearer: "bg-token-value" });
    ok("a bare-token (ADMIN_TOKEN) caller is exempt from step-up", !(tokAccept.status === 401 && tokAccept.json?.stepUpRequired === true));

    // ----------------------------------------------------------------------------------------
    // The HIGH-BLAST-RADIUS data/identity ops (repoint/remove a destination, change the IdP trust roots)
    // are step-up-gated too: a stolen ambient session must not be able to redirect every backup, delete an
    // archive copy, or rewire authentication without a fresh re-auth. We drive each one THROUGH the real
    // dispatch with the SAME stale cookie session (step-up unsatisfied) and assert a 401 stepUpRequired -
    // proving the sub string matches a real POST case and the gate actually fires (a sub with no matching
    // case would be a silent no-op the set-membership check below cannot catch). The bare-token break-glass
    // is exempt (it never hits the cookie path), confirmed against the same routes.
    const highBlastSubs = ["/destination", "/destinations", "/destinations/remove", "/destinations/default", "/idp/connections", "/idp/connections/delete", "/idp/connections/enabled"] as const;
    for (const sub of highBlastSubs) {
      const blocked = await postAdmin(env, `/admin${sub}`, {}, { cookie: staleCookie, origin: ORIGIN });
      ok(`a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST ${sub} (V7.5.1)`, blocked.status === 401 && blocked.json?.stepUpRequired === true);
      const exempt = await postAdmin(tokEnv, `/admin${sub}`, {}, { bearer: "bg-token-value" });
      ok(`a bare-token caller is exempt from step-up on POST ${sub}`, !(exempt.status === 401 && exempt.json?.stepUpRequired === true));
      // The exempt (token) caller skips step-up and reaches the SWITCH. A real dispatch case returns
      // something other than the default 404, so a sub string with no matching case (a silent no-op the
      // step-up gate would still 401 the cookie path on) is caught HERE rather than passing unnoticed.
      ok(`POST ${sub} reaches a real dispatch case (not the 404 default)`, exempt.status !== 404);
    }

    // /keys/break-glass-only is step-up gated too: it permanently DELETES both operational worker
    // secrets - an IRREVERSIBLE custody change - so a stale ambient Owner cookie must not trigger it without a
    // fresh re-auth. Drive it through the real dispatch with the stale cookie (step-up unsatisfied) and assert
    // 401 stepUpRequired; the bare-token break-glass is exempt and reaches a real case (not the 404 default,
    // and the no-account 400 means no secret is actually deleted in the test).
    {
      const blocked = await postAdmin(env, "/admin/keys/break-glass-only", {}, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /keys/break-glass-only (V7.5.1)", blocked.status === 401 && blocked.json?.stepUpRequired === true);
      const exempt = await postAdmin(tokEnv, "/admin/keys/break-glass-only", {}, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /keys/break-glass-only", !(exempt.status === 401 && exempt.json?.stepUpRequired === true));
      ok("POST /keys/break-glass-only reaches a real dispatch case (not the 404 default)", exempt.status !== 404);
    }

    // The IDENTITY / AUTH-LIFECYCLE mutations a stale ambient cookie could otherwise reach without a
    // fresh re-auth are step-up gated too: granting a role (/roles can mint a brand-new Owner = a persistent
    // backdoor), retiring the break-glass bearer (/policy/retire-break-glass-token, an IRREVERSIBLE latch that
    // disables the operator fallback = a lockout), and deleting a passkey credential (/passkey/credentials/
    // delete, an auth-credential-lifecycle mutation). Drive each THROUGH the real dispatch with the SAME stale
    // cookie (step-up unsatisfied) and assert 401 stepUpRequired - proving the sub matches a real POST case and
    // the gate fires. The bare-token break-glass is exempt (it never hits the cookie path). retire is driven
    // against a FRESH token env so retiring its bearer cannot pollute the shared tokEnv used by the coverage
    // loop below.
    {
      const rolesBlocked = await postAdmin(env, "/admin/roles", { email: "x@e.example", role: "owner" }, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /roles (grant-a-new-Owner backdoor)", rolesBlocked.status === 401 && rolesBlocked.json?.stepUpRequired === true);
      const rolesExempt = await postAdmin(tokEnv, "/admin/roles", { email: "x@e.example", role: "viewer" }, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /roles", !(rolesExempt.status === 401 && rolesExempt.json?.stepUpRequired === true));

      const passkeyDelBlocked = await postAdmin(env, "/admin/passkey/credentials/delete", { credentialId: "none" }, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /passkey/credentials/delete (auth-credential lifecycle)", passkeyDelBlocked.status === 401 && passkeyDelBlocked.json?.stepUpRequired === true);
      const passkeyDelExempt = await postAdmin(tokEnv, "/admin/passkey/credentials/delete", { credentialId: "none" }, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /passkey/credentials/delete", !(passkeyDelExempt.status === 401 && passkeyDelExempt.json?.stepUpRequired === true));

      const retireBlocked = await postAdmin(env, "/admin/policy/retire-break-glass-token", {}, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /policy/retire-break-glass-token (IRREVERSIBLE bearer-fallback lockout)", retireBlocked.status === 401 && retireBlocked.json?.stepUpRequired === true);
      const { env: retireTokEnv } = makeScheduler({ ADMIN_TOKEN: "retire-bg-token" });
      const retireExempt = await postAdmin(retireTokEnv, "/admin/policy/retire-break-glass-token", {}, { bearer: "retire-bg-token" });
      ok("a bare-token caller is exempt from step-up on POST /policy/retire-break-glass-token", !(retireExempt.status === 401 && retireExempt.json?.stepUpRequired === true));
    }

    // STEPUP-SUPPORT-CREDENTIAL-MINT (the fifth gap). Minting a support credential hands the caller
    // a NEW bearer over a read-only pull surface, which the route's own comment calls "the same custody weight
    // as granting a role" - and /roles was gated while this was not. The earlier sweep cleared it believing a
    // second owner's approval covered it; it does not by default (support-credential-mint is absent from
    // HIGH_BLAST_ALWAYS_GATED and requireConfigApproval defaults false, so ownerActionGate answers "off").
    //
    // Driven with a VALID scope so the refusal cannot be the route's own 400 scope check wearing a 401's
    // clothes, and asserted on BOTH sides: the stale cookie is refused, and the DO holds NO credential record
    // afterwards. That second assertion is the one that matters for a mint route - a gate that 401s the caller
    // but has already written the grant would be worse than no gate, because the operator would not know a
    // live bearer exists.
    {
      const mintBlocked = await postAdmin(env, "/admin/support/credentials", { scope: "diagnostics" }, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /support/credentials (the fifth gap)", mintBlocked.status === 401 && mintBlocked.json?.stepUpRequired === true);
      ok("the refused mint wrote NO credential to the DO (the gate fires before the mint, so no live bearer is left behind)", (await storage.get("ingestcred:diagnostics")) === undefined);
      // The revoke sibling is deliberately NOT gated: it CLOSES the surface, and an operator who suspects a
      // credential is stolen must be able to kill it without a passkey ceremony first.
      const revoke = await postAdmin(env, "/admin/support/credentials/delete", { scope: "diagnostics" }, { cookie: staleCookie, origin: ORIGIN });
      ok("POST /support/credentials/delete is deliberately NOT step-up-blocked (revoking is the safe direction)", !(revoke.status === 401 && revoke.json?.stepUpRequired === true));
    }

    // Evicting ANOTHER operator's sessions, evicting EVERY
    // operator's sessions, and emailing a custody share are step-up gated too: an
    // attacker holding a live-but-stale session must not be able to evict every other operator or exfiltrate a
    // key share with no fresh re-auth. Drive each THROUGH the real dispatch with the SAME stale cookie
    // (step-up unsatisfied) and assert 401 stepUpRequired; the bare-token break-glass is exempt (it never
    // hits the cookie path). /sessions/terminate-others is proven EXEMPT (self-scoped only, never another
    // operator's session), matching the "only gate the dangerous direction" convention.
    {
      const termUserBlocked = await postAdmin(env, "/admin/sessions/terminate-user", { email: "someone@example.com" }, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /sessions/terminate-user (evicts ANOTHER operator)", termUserBlocked.status === 401 && termUserBlocked.json?.stepUpRequired === true);
      const termUserExempt = await postAdmin(tokEnv, "/admin/sessions/terminate-user", { email: "someone@example.com" }, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /sessions/terminate-user", !(termUserExempt.status === 401 && termUserExempt.json?.stepUpRequired === true));
      ok("POST /sessions/terminate-user reaches a real dispatch case (not the 404 default)", termUserExempt.status !== 404);

      const termAllBlocked = await postAdmin(env, "/admin/sessions/terminate-all", {}, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /sessions/terminate-all (evicts EVERY operator)", termAllBlocked.status === 401 && termAllBlocked.json?.stepUpRequired === true);
      const termAllExempt = await postAdmin(tokEnv, "/admin/sessions/terminate-all", {}, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /sessions/terminate-all", !(termAllExempt.status === 401 && termAllExempt.json?.stepUpRequired === true));
      ok("POST /sessions/terminate-all reaches a real dispatch case (not the 404 default)", termAllExempt.status !== 404);

      const shareBlocked = await postAdmin(env, "/admin/custody/send-share", { toEmail: "custodian@example.com", shareB64: "x", n: 3, m: 2 }, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /custody/send-share (emails a key share)", shareBlocked.status === 401 && shareBlocked.json?.stepUpRequired === true);
      const shareExempt = await postAdmin(tokEnv, "/admin/custody/send-share", { toEmail: "custodian@example.com", shareB64: "x", n: 3, m: 2 }, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /custody/send-share", !(shareExempt.status === 401 && shareExempt.json?.stepUpRequired === true));
      ok("POST /custody/send-share reaches a real dispatch case (not the 404 default)", shareExempt.status !== 404);

      // Deliberately NO csrf option: this only needs to prove the request is not the step-up 401 (it is a
      // real CSRF 403 instead, since terminate-others still enforces the double-submit guard inside its own
      // case). Supplying a matching CSRF pair would let it actually EXECUTE against the shared staleCookie
      // session (bumping its epoch) and corrupt every assertion after it in this block.
      const termOthersBlocked = await postAdmin(env, "/admin/sessions/terminate-others", {}, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is NOT step-up-blocked on POST /sessions/terminate-others (self-scoped only, deliberately exempt)", !(termOthersBlocked.status === 401 && termOthersBlocked.json?.stepUpRequired === true));

      // A fresh passkey re-assertion mints a NEW single-use step-up token (the shared
      // ceremony proven generically above for /posture/accept is re-run here so THIS route's own unblock is
      // live-proven, not merely inferred from the shared requireStepUp code path) that unblocks the SAME
      // /custody/send-share call the stale cookie above was refused on: the response is no longer 401
      // stepUpRequired, so the request proceeded past the gate into the route's own body validation.
      const m2Begin = await postAdmin(env, "/admin/stepup/begin", {}, { cookie: staleCookie, origin: ORIGIN });
      ok("stepup/begin issues a fresh challenge for the caller's passkeys", m2Begin.status === 200 && m2Begin.json.ok === true);
      auth.signCount = sc; sc++;
      const m2Asr = await signAssertion(auth, m2Begin.json.publicKey!.challenge);
      const m2Finish = await postAdmin(env, "/admin/stepup/finish", { challengeId: m2Begin.json.challengeId, credential: m2Asr }, { cookie: staleCookie, origin: ORIGIN });
      ok("stepup/finish mints a fresh single-use step-up token", m2Finish.status === 200 && m2Finish.json.ok === true);
      const m2Token = m2Finish.json.stepUpToken as string;
      const m2Req = (): Request => new Request("https://engine.example/admin/custody/send-share", { method: "POST", body: JSON.stringify({ toEmail: "custodian@example.com", shareB64: "x", n: 3, m: 2 }), headers: { "content-type": "application/json", cookie: staleCookie, origin: ORIGIN, "x-downpipes-stepup": m2Token } });
      const m2Unblocked = await send(env, m2Req());
      ok("a valid single-use step-up token unblocks POST /custody/send-share (proceeds past the gate)", !(m2Unblocked.status === 401 && m2Unblocked.json?.stepUpRequired === true));
    }

    // POST /restore's confirm:true apply
    // leg (router-restore.ts) is gated INLINE (STEPUP_INLINE_GATED), not by literal Set membership; drive it
    // live to prove the inline call actually fires, mirroring the stale-blocked / token-exempt shape used above.
    // A well-formed-but-nonexistent ULID is enough: requireStepUp runs right after the role gate and
    // before any DO/dual-control/data access, so the 401 (or its absence) is decided before the run's
    // existence is ever checked.
    {
      const restoreBody = { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true };
      const applyBlocked = await postAdmin(env, "/admin/restore", restoreBody, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is step-up-blocked (401 stepUpRequired) on POST /restore with confirm:true (data-overwriting apply)", applyBlocked.status === 401 && applyBlocked.json?.stepUpRequired === true);
      const applyExempt = await postAdmin(tokEnv, "/admin/restore", restoreBody, { bearer: "bg-token-value" });
      ok("a bare-token caller is exempt from step-up on POST /restore confirm:true", !(applyExempt.status === 401 && applyExempt.json?.stepUpRequired === true));
      ok("POST /restore confirm:true reaches a real dispatch case (not the 404 default)", applyExempt.status !== 404);
      // The harmless dry-run leg (confirm omitted) is NOT step-up-blocked on the SAME stale cookie: only the
      // dangerous apply direction is gated, matching this codebase's "only gate the dangerous direction"
      // convention (restore/reject vs restore/approve, retention-prune/reject vs /approve).
      const dryRun = await postAdmin(env, "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" }, { cookie: staleCookie, origin: ORIGIN });
      ok("a STALE cookie session is NOT step-up-blocked on POST /restore dry-run (confirm omitted, writes nothing)", !(dryRun.status === 401 && dryRun.json?.stepUpRequired === true));
    }

    // Set-membership sanity: every gated sub (the original six incl. break-glass-only, the seven data/identity
    // subs, and the M1 identity/auth-lifecycle subs INCLUDING the RBAC /delete siblings) is present. This is
    // the cheap invariant; the dispatch drive above is what proves each string is wired to a real case.
    const m1Subs = ["/roles", "/roles/delete", "/group-roles", "/group-roles/delete", "/custom-roles", "/custom-roles/delete", "/policy/retire-break-glass-token", "/passkey/credentials/delete"];
    const m2Subs = ["/sessions/terminate-user", "/sessions/terminate-all", "/custody/send-share"];
    for (const sub of ["/restore/approve", "/keys/install", "/keys/rotate", "/keys/break-glass-only", "/posture/accept", "/posture/unaccept", ...highBlastSubs, ...m1Subs, ...m2Subs]) {
      ok(`STEPUP_SUBS includes ${sub}`, STEPUP_SUBS.has(sub));
    }

    // STRUCTURAL COVERAGE ASSERTION (the anti-recurrence property): instead of a hand-typed list of sensitive
    // routes (which only re-checks routes a human already wrote down, so an OMITTED sibling like /roles/delete
    // was invisible), DERIVE the router's ACTUAL dispatched POST set from the spoke source and classify each
    // by security domain (isSensitiveMutationSub). The invariants:
    //   (1) every SENSITIVE dispatched route is in STEPUP_SUBS (an omission is a custody/data-loss/identity gap);
    //   (2) every STEPUP_SUBS entry is a real dispatched POST case (no string drifts to a silent no-op);
    //   (3) every dispatched POST route is EITHER step-up gated OR explicitly accounted for (gated, or a
    //       reviewed domain-exemption, or a non-sensitive route) - so a brand-new sensitive route that is
    //       neither gated nor allowlisted FAILS here, which is exactly the recurrence this closes.
    // Each sensitive route is also DRIVEN through the real dispatch (token-exempt, not the 404 default) so the
    // derived set cannot drift from a real case. Routes whose token-exempt drive could MUTATE durable state
    // (the bearer/credential/identity posture) get a FRESH token env per drive so a successful mutation cannot
    // pollute the shared loop; a pre-auth route the early-edge handles (/demo/reset under DEMO_MODE) is not in
    // the post-auth dispatch set and so never appears here.
    const dispatchedPost = dispatchedPostSubs();
    // The dispatched set is non-trivial (a parse that silently found nothing must fail, not vacuously pass).
    ok("structural: the dispatched POST set parsed from the spoke source is non-empty", dispatchedPost.size > 20);
    // A SIZE FLOOR CANNOT CATCH THIS, which is why these four are pinned BY NAME: a comment-stripping regression
    // that deletes live code between two comments (see blankComments above) can shrink the derived set while
    // still passing a `> 20` floor, leaving real dispatched routes invisible to every check in this block. These
    // four are named individually so a future regression fails HERE, naming the routes, rather than quietly
    // shrinking the set again.
    for (const sub of ["/restore/approve", "/keys/install", "/keys/rotate", "/posture/accept"]) {
      ok(`structural: the comment strip does not eat live code (${sub} is still in the dispatched set)`, dispatchedPost.has(sub));
    }
    // The routes whose token-exempt dispatch drive could mutate durable state: a fresh env keeps each drive
    // self-contained. The RBAC writes (role grant/revoke, group + custom-role mapping) and the bearer/credential
    // retire/revoke all persist through the bare-token owner, so they each get an isolated env.
    const FRESH_ENV_ROUTES = new Set<string>([
      "/policy/retire-break-glass-token", "/passkey/credentials/delete",
      "/roles", "/roles/delete", "/group-roles", "/group-roles/delete", "/custom-roles", "/custom-roles/delete",
    ]);
    for (const sub of [...dispatchedPost].sort()) {
      if (!isSensitiveMutationSub(sub)) continue;
      // STEPUP_INLINE_GATED entries (currently just /restore) are gated on a PARSED body action, not literal
      // Set membership (a plain sub-string cannot see `confirm`), so the "is it in STEPUP_SUBS" assertion does
      // not apply to them; the structural source-read block below (4d1a) is what proves THEY are gated.
      if (!STEPUP_INLINE_GATED.has(sub)) {
        ok(`structural coverage: sensitive mutation route ${sub} is in STEPUP_SUBS (omission is a custody/data-loss/identity gap)`, STEPUP_SUBS.has(sub));
      }
      const driveEnv = FRESH_ENV_ROUTES.has(sub) ? makeScheduler({ ADMIN_TOKEN: "cov-bg-token" }).env : tokEnv;
      const bearer = FRESH_ENV_ROUTES.has(sub) ? "cov-bg-token" : "bg-token-value";
      const reached = await postAdmin(driveEnv, `/admin${sub}`, {}, { bearer });
      ok(`structural coverage: ${sub} is a real dispatch case (not the 404 default)`, reached.status !== 404);
    }
    // (2) every STEPUP_SUBS entry is a REAL dispatched POST case (it must appear in the parsed source set), so
    // no gated string can silently become a no-op the gate keys on but the switch never matches.
    for (const sub of STEPUP_SUBS) {
      ok(`structural: STEPUP_SUBS entry ${sub} is a real dispatched POST case (not a silent no-op)`, dispatchedPost.has(sub));
    }
    // (3) NOTHING falls between the cracks: every dispatched POST route is EITHER step-up gated (by Set
    // membership OR the proven inline exception) OR a reviewed sensitive-domain exemption OR a non-sensitive
    // route. The only way to fail this is to add a route that isSensitiveMutationSub flags as sensitive but
    // that is in none of those three buckets - i.e. the recurrence itself.
    for (const sub of dispatchedPost) {
      const accountedFor = STEPUP_SUBS.has(sub) || STEPUP_INLINE_GATED.has(sub) || STEPUP_DOMAIN_EXEMPT.has(sub) || !isSensitiveMutationSub(sub);
      ok(`structural: dispatched POST ${sub} is accounted for (gated, inline-gated, a reviewed exemption, or non-sensitive)`, accountedFor);
    }
    // The domain-exemptions are REAL, currently-dispatched routes (so the exempt set cannot rot into naming a
    // route that no longer exists) and are deliberately NOT step-up gated.
    for (const sub of STEPUP_DOMAIN_EXEMPT) {
      ok(`structural: exempt route ${sub} is a real dispatched POST case`, dispatchedPost.has(sub));
      ok(`structural: exempt route ${sub} is deliberately NOT in STEPUP_SUBS`, !STEPUP_SUBS.has(sub));
    }
    // The inline-gated entries are REAL, currently-dispatched routes too, and are deliberately absent from
    // the literal Set for the reason recorded on STEPUP_INLINE_GATED (never because nobody checked).
    for (const sub of STEPUP_INLINE_GATED) {
      ok(`structural: inline-gated route ${sub} is a real dispatched POST case`, dispatchedPost.has(sub));
      ok(`structural: inline-gated route ${sub} is deliberately NOT in STEPUP_SUBS (gated on a parsed body action instead)`, !STEPUP_SUBS.has(sub));
    }
  }

  // ============================================================================================
  // 4d1a. STRUCTURAL: POST /restore is matched via a literal `case "POST /restore":` label (unlike the
  //      dynamic-<id> routes covered below), so dispatchedPostSubs() DOES see it and the 4d1 structural loop above
  //      DOES classify it sensitive - but it is deliberately absent from STEPUP_SUBS (STEPUP_INLINE_GATED),
  //      so nothing there proves requireStepUp is actually CALLED on the confirm:true leg. Read
  //      router-restore.ts's OWN source directly and assert the POST /restore case's body still calls
  //      requireStepUp( inside the `confirm === true` branch, so a future refactor that drops the call (or
  //      moves it outside the branch, gating the harmless dry-run too) fails HERE.
  // ============================================================================================
  {
    const restoreSrc = readFileSync(join(ROUTER_SPOKE_DIR, "router-restore.ts"), "utf8");
    const caseIdx = restoreSrc.indexOf('case "POST /restore":');
    ok("structural (STEPUP-SESSION-TERMINATION-GAP): router-restore.ts still has a POST /restore case", caseIdx !== -1);
    const nextCaseIdx = restoreSrc.indexOf('\n    case "', caseIdx + 1);
    const restoreBlock = caseIdx === -1 ? "" : nextCaseIdx === -1 ? restoreSrc.slice(caseIdx) : restoreSrc.slice(caseIdx, nextCaseIdx);
    const confirmIdx = restoreBlock.indexOf("body.confirm === true");
    ok("structural: the POST /restore case still branches on body.confirm === true", confirmIdx !== -1);
    const confirmBranch = confirmIdx === -1 ? "" : restoreBlock.slice(confirmIdx);
    ok("structural: the confirm:true branch calls requireStepUp( before it writes data", /requireStepUp\(/.test(confirmBranch));
  }

  // ============================================================================================
  // 4d2. ASVS V7.5.1 / V7.5.3: the DYNAMIC <id> APPROVE ROUTES (POST /config/changes/<id>/approve,
  //      POST /owner-actions/<id>/approve) must be step-up gated too. Their <id> is a per-request ULID path
  //      segment, so `sub` can never equal a literal STEPUP_SUBS member - no set-membership check could ever
  //      cover them (the 4d block above, keyed entirely on literal subs, cannot see these routes at all).
  //      TWO DISTINCT owners drive both routes through the REAL router + DO: Owner A (fresh) proposes a
  //      dual-controlled action, Owner B's STALE ambient session must be step-up-blocked on approve (a stale-
  //      but-valid second-owner session is exactly the exploit's precondition: an idle tab, a lifted cookie, a
  //      shared workstation) and unblocked only by a fresh passkey re-assertion; reject is proven EXEMPT on
  //      both (it only discards a pending record, matching the codebase's "gate only the dangerous direction"
  //      convention already used elsewhere, e.g. restore/reject vs restore/approve).
  // ============================================================================================
  {
    const { env, storage } = makeScheduler();
    const authA = await makeAuthenticator();
    const emailA = "hi04-owner-a@example.com";
    await register(env, authA, emailA); // bootstraps to Owner
    let scA = 0;
    const freshLoginA = async (): Promise<Resp> => { authA.signCount = scA; const r = await login(env, authA, emailA); scA++; return r; };
    const loginA = await freshLoginA();
    const cookieA = cookiePair(loginA.setCookie)!;

    // A grants a SECOND owner (a direct-route STEPUP_SUBS entry, so this needs A's fresh session too -
    // proven generally in 4d above; here it is just the setup, reusing the SAME fresh cookie throughout this
    // block since every call below happens well inside STEPUP_FRESH_MS of the single login above).
    const emailB = "hi04-owner-b@example.com";
    const grantB = await postAdmin(env, "/admin/roles", { email: emailB, role: "owner" }, { cookie: cookieA, origin: ORIGIN });
    ok("Owner A (fresh) grants Owner B", grantB.status === 200);
    const inviteTokenB = grantB.json.inviteToken as string | undefined;
    if (inviteTokenB === undefined) throw new Error("expected an invite token granting the second owner");
    const authB = await makeAuthenticator();
    const regB = await register(env, authB, emailB, { inviteToken: inviteTokenB });
    ok("Owner B registers with the invite (no bootstrap)", regB.status === 200 && regB.json.ok === true);

    // Arm the OPT-IN dual-control toggle (Owner-only, immediate, not itself step-up gated), so a config-change
    // (role-set) AND an owner-action (break-glass-retire, which is NOT in HIGH_BLAST_ALWAYS_GATED and so has
    // no live-network propose precondition, unlike the finding's own dest-remove example) both queue below.
    const arm = await postAdmin(env, "/admin/config/approval-policy", { requireConfigApproval: true }, { cookie: cookieA, origin: ORIGIN });
    ok("requireConfigApproval arms immediately for the proposer owner", arm.status === 200);

    // Owner B's STALE session: iat older than STEPUP_FRESH_MS, forged with the DO's real signing key exactly
    // as the 4d block above does (the exploit's precondition: a valid-but-non-fresh ambient second-owner
    // session). stepUpFor drives B's own fresh passkey re-assertion end to end and returns the minted
    // single-use step-up token (proven single-use generally in 4d; not re-proven per route here).
    const doKey = b64urlDecode((await storage.get<{ key: string }>("passkeySessionKey"))!.key);
    const nowB = Date.now();
    const staleTokenB = await signSession(doKey, { method: "passkey", email: emailB, subject: passkeySubject(emailB), epoch: 0, slide: { iat: nowB - (STEPUP_FRESH_MS + 60_000), exp: nowB + SESSION_TTL_MS } }, nowB);
    const staleB = `${SESSION_COOKIE_NAME}=${staleTokenB}`;
    let scB = 0;
    const stepUpFor = async (cookie: string): Promise<string> => {
      const begin = await postAdmin(env, "/admin/stepup/begin", {}, { cookie, origin: ORIGIN });
      ok("stepup/begin issues a challenge for Owner B's passkey", begin.status === 200 && begin.json.ok === true);
      authB.signCount = scB; scB++;
      const asr = await signAssertion(authB, begin.json.publicKey!.challenge);
      const finish = await postAdmin(env, "/admin/stepup/finish", { challengeId: begin.json.challengeId, credential: asr }, { cookie, origin: ORIGIN });
      ok("stepup/finish mints a fresh single-use step-up token for Owner B", finish.status === 200 && finish.json.ok === true);
      return finish.json.stepUpToken as string;
    };

    // ---- (a) OWNER-ACTION approve: POST /admin/owner-actions/<id>/approve -----------------------------
    {
      const p1 = await postAdmin(env, "/admin/policy/retire-break-glass-token", {}, { cookie: cookieA, origin: ORIGIN });
      ok("A's fresh session proposes break-glass-retire (202, queued for a second owner)", p1.status === 202 && p1.json.ownerActionQueued === true);
      const id1 = p1.json.id as string;
      // A second, independent proposal so reject (below) cannot interfere with the approve flow on id1.
      const p2 = await postAdmin(env, "/admin/policy/retire-break-glass-token", {}, { cookie: cookieA, origin: ORIGIN });
      ok("a second, independent break-glass-retire proposal is queued too", p2.status === 202 && p2.json.ownerActionQueued === true);
      const id2 = p2.json.id as string;

      // Owner B's STALE session must be step-up-blocked on the dynamic owner-actions/<id>/approve route.
      const blocked = await postAdmin(env, `/admin/owner-actions/${id1}/approve`, {}, { cookie: staleB, origin: ORIGIN });
      ok("a STALE second-owner session is step-up-blocked on POST /owner-actions/<id>/approve", blocked.status === 401 && blocked.json?.stepUpRequired === true);

      // reject is NOT step-up-blocked (the deliberate exemption; a DIFFERENT pending id, id2).
      const rejected = await postAdmin(env, `/admin/owner-actions/${id2}/reject`, {}, { cookie: staleB, origin: ORIGIN });
      ok("reject on a STALE session is NOT step-up-blocked (only approve is gated)", !(rejected.status === 401 && rejected.json?.stepUpRequired === true));
      ok("the reject actually took effect (200)", rejected.status === 200 && rejected.json.status === "rejected");

      // A fresh step-up token unblocks the SAME approve call, and the DO actually executes it: a DO-executed
      // kind (break-glass-retire) runs atomically inside approve, so the record lands "executed" with B
      // recorded as the approver - proving this is a REAL unblock, not merely a status-code coincidence.
      const token1 = await stepUpFor(staleB);
      const approveReq1 = (): Request => new Request(`https://engine.example/admin/owner-actions/${id1}/approve`, { method: "POST", body: JSON.stringify({}), headers: { "content-type": "application/json", cookie: staleB, origin: ORIGIN, "x-downpipes-stepup": token1 } });
      const approved = await send(env, approveReq1());
      ok("a fresh step-up token unblocks the SAME approve call (not 401 stepUpRequired)", !(approved.status === 401 && approved.json?.stepUpRequired === true));
      ok("the owner-action ACTUALLY executed (a DO-executed kind runs atomically inside approve)", approved.status === 200 && approved.json.status === "executed");
      ok("the DO recorded the SECOND owner as the approver (maker A != checker B)", approved.json.approvedBy === emailB);
    }

    // ---- (b) CONFIG-CHANGE approve: POST /admin/config/changes/<id>/approve ---------------------------
    {
      const c1 = await postAdmin(env, "/admin/roles", { email: "hi04-cfg-a@example.com", role: "viewer" }, { cookie: cookieA, origin: ORIGIN });
      ok("A's fresh session proposes a /roles change (202, queued: requireConfigApproval is ON)", c1.status === 202 && c1.json.queued === true);
      const cid1 = c1.json.id as string;
      const c2 = await postAdmin(env, "/admin/roles", { email: "hi04-cfg-b@example.com", role: "viewer" }, { cookie: cookieA, origin: ORIGIN });
      ok("a second, independent /roles change is queued too", c2.status === 202 && c2.json.queued === true);
      const cid2 = c2.json.id as string;

      // Owner B's STALE session must be step-up-blocked on the dynamic config/changes/<id>/approve route.
      const blocked = await postAdmin(env, `/admin/config/changes/${cid1}/approve`, {}, { cookie: staleB, origin: ORIGIN });
      ok("a STALE second-owner session is step-up-blocked on POST /config/changes/<id>/approve", blocked.status === 401 && blocked.json?.stepUpRequired === true);

      // reject is NOT step-up-blocked (a DIFFERENT pending id, cid2).
      const rejected = await postAdmin(env, `/admin/config/changes/${cid2}/reject`, {}, { cookie: staleB, origin: ORIGIN });
      ok("reject on a STALE session is NOT step-up-blocked (only approve is gated)", !(rejected.status === 401 && rejected.json?.stepUpRequired === true));
      ok("the reject actually took effect (200)", rejected.status === 200 && rejected.json.status === "rejected");

      // A fresh step-up token unblocks approve, and the change actually applies with B recorded as approver.
      const token2 = await stepUpFor(staleB);
      const approveReq2 = (): Request => new Request(`https://engine.example/admin/config/changes/${cid1}/approve`, { method: "POST", body: JSON.stringify({}), headers: { "content-type": "application/json", cookie: staleB, origin: ORIGIN, "x-downpipes-stepup": token2 } });
      const approved = await send(env, approveReq2());
      ok("a fresh step-up token unblocks the SAME approve call (not 401 stepUpRequired)", !(approved.status === 401 && approved.json?.stepUpRequired === true));
      ok("the config change ACTUALLY applied", approved.status === 200 && approved.json.status === "applied");
      ok("the DO recorded the SECOND owner as the approver (maker A != checker B)", approved.json.approvedBy === emailB);
    }
  }

  // ============================================================================================
  // 4d3. STRUCTURAL: the two dynamic <id> approve routes above are matched via
  //      matchConfigChangeAction/matchOwnerActionAction, never a literal `case "POST ..."` label, so
  //      dispatchedPostSubs()'s case-label parse (the 4d structural coverage above) cannot see them at all -
  //      exactly why this gap could recur silently. Read router.ts's OWN source directly and assert each
  //      matcher's dispatch block still calls requireStepUp on its "approve" leg, so a future refactor that
  //      drops the call (or a new dynamic-<id> route that never gets one) fails HERE.
  // ============================================================================================
  {
    const routerSrc = readFileSync(join(ROUTER_SPOKE_DIR, "router.ts"), "utf8");
    // The span between a matcher's call and the FIRST scheduler.fetch(doURL( after it (its DO forward) is
    // where an approve-only step-up gate must live; requireStepUp( and the `.action === "approve"` guard
    // must both appear textually inside that span.
    const matcherGatesApproveOnly = (matcherName: string): boolean => {
      const callIdx = routerSrc.indexOf(`${matcherName}(req.method, sub)`);
      if (callIdx === -1) return false;
      const forwardIdx = routerSrc.indexOf("scheduler.fetch(doURL(", callIdx);
      if (forwardIdx === -1) return false;
      const block = routerSrc.slice(callIdx, forwardIdx);
      return block.includes('.action === "approve"') && /requireStepUp\(/.test(block);
    };
    ok("structural: matchConfigChangeAction's approve leg calls requireStepUp before the DO forward", matcherGatesApproveOnly("matchConfigChangeAction"));
    ok("structural: matchOwnerActionAction's approve leg calls requireStepUp before the DO forward", matcherGatesApproveOnly("matchOwnerActionAction"));
  }

  // ============================================================================================
  // 4e. AUTH-37: requireStepUp FAILS CLOSED when the DO /stepup/check is UNAVAILABLE. The end-to-end step-up
  //     tests above all run against a healthy DO; this drives requireStepUp DIRECTLY with a scheduler stub
  //     whose fetch THROWS and asserts the sensitive action is DENIED (401 stepUpRequired), never admitted on
  //     a DO outage (router-core.ts:248-263: the scheduler.fetch is wrapped in try/catch and falls through to
  //     the 401). Contrast: a SATISFIED DO returns null (proceed), and the bare-token / Access methods are
  //     EXEMPT even with a throwing DO (they never reach the cookie path), so the 401 is the outage, not a
  //     blanket deny.
  // ============================================================================================
  {
    const req = (): Request => new Request("https://engine.example/admin/posture/accept", { method: "POST", headers: { cookie: `${SESSION_COOKIE_NAME}=some-session-token`, origin: ORIGIN } });
    const throwingScheduler = { fetch: (): Promise<Response> => { throw new Error("DO unavailable"); } } as unknown as DurableObjectStub;
    const denied = await requireStepUp(req(), throwingScheduler, "passkey");
    ok("AUTH-37: requireStepUp FAILS CLOSED (returns a 401) when the DO /stepup/check throws", denied !== null && denied.status === 401);
    const deniedBody = denied !== null ? ((await denied.json()) as { stepUpRequired?: boolean; error?: string }) : {};
    ok("AUTH-37: the fail-closed response carries stepUpRequired:true", deniedBody.stepUpRequired === true);
    // A native oidc/saml session method is gated the SAME way (still 401 on a DO outage).
    const deniedOidc = await requireStepUp(req(), throwingScheduler, "oidc");
    ok("AUTH-37: an oidc cookie session also fails closed (401) on a DO outage", deniedOidc !== null && deniedOidc.status === 401);
    // The bare-token break-glass and Access are EXEMPT even when the DO would throw (early-return, no DO read).
    ok("AUTH-37: a token caller is exempt from step-up even when the DO would throw", (await requireStepUp(req(), throwingScheduler, "token")) === null);
    ok("AUTH-37: an access caller is exempt from step-up even when the DO would throw", (await requireStepUp(req(), throwingScheduler, "access")) === null);
    // A SATISFIED DO check lets the cookie action PROCEED (null), proving the 401s above are the outage path.
    const okScheduler = { fetch: async (): Promise<Response> => new Response(JSON.stringify({ satisfied: true }), { status: 200, headers: { "content-type": "application/json" } }) } as unknown as DurableObjectStub;
    ok("AUTH-37: a SATISFIED DO check lets the passkey action proceed (null)", (await requireStepUp(req(), okScheduler, "passkey")) === null);
    // RESIDUAL: this proves the catch->401 fail-closed branch faithfully, but a real network partition / DO
    // eviction race under load is not reproducible offline; that is exercised in the live chaos tier.
  }

  // ============================================================================================
  // 4f. AUTH-64: the break-glass-retired predicate is `breakGlassRetired && (await breakGlassRetired())`
  //     (auth.ts:219). When the resolver is OMITTED the && SHORT-CIRCUITS, so the token-fallback predicate
  //     collapses to the env flag (ADMIN_TOKEN_DISABLED) ALONE - a token the DO has RETIRED would still
  //     authenticate via any call site that forgets to wire the resolver. The router always wires it; this
  //     locks the invariant (every call site MUST pass breakGlassRetired, or the param should be made
  //     required): authorise() with NO resolver authorises a valid bearer regardless of any DO-side latch,
  //     and WIRING a retired-resolver is what closes the gap.
  // ============================================================================================
  {
    const env = { ADMIN_TOKEN: "bg-auth64-token" } as unknown as Env;
    const bearerReq = (): Request => new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer bg-auth64-token" } });
    // No verifier, NO resolver (the 4th arg omitted): the && short-circuits to the env-flag-only path, so a
    // valid bearer authorises even though a (notional) DO latch is retired - the downgrade this locks.
    const noResolver = await authorise(bearerReq(), env);
    ok("AUTH-64: with NO breakGlassRetired resolver, a valid bearer AUTHORISES (the && short-circuit / env-flag-only path)", noResolver.ok === true && noResolver.method === "token");
    // WIRING a resolver that reports RETIRED denies the same bearer (the right side of the && is now reached).
    const retiredResolver = async (): Promise<boolean> => true;
    ok("AUTH-64: WIRING a retired-resolver DENIES the same bearer (the resolver is the control)", (await authorise(bearerReq(), env, undefined, retiredResolver)).ok === false);
    // A resolver that reports NOT retired allows it (the resolver IS consulted when wired; the false path).
    const liveResolver = async (): Promise<boolean> => false;
    ok("AUTH-64: a not-retired resolver ALLOWS the bearer (the resolver is consulted, false path of the &&)", (await authorise(bearerReq(), env, undefined, liveResolver)).ok === true);
  }

  // ============================================================================================
  // 5. UNAUTHENTICATED LOGOUT clears the cookie, after which the (now-cleared) request is unauthorised.
  //    (Rejection of a presented pre-logout token after an authenticated logout is proven in section 3c.)
  // ============================================================================================
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator();
    await register(env, auth, "owner@example.com");
    await login(env, auth, "owner@example.com");

    const out = await postAuth(env, "/admin/auth/logout", {});
    ok("logout returns ok", out.status === 200 && out.json.ok === true);
    ok("logout sets a clearing cookie (Max-Age=0)", out.setCookie !== null && /Max-Age=0/.test(out.setCookie));
    // This section drives logout on the UNAUTHENTICATED path: postAuth presents no session cookie, so the
    // handler has no token to read and therefore performs no epoch bump here; it only returns the clearing
    // cookie. The authenticated, server-side revocation (the epoch bump that immediately invalidates any
    // exfiltrated copy of the pre-logout token) is proven in section 3c above. So this section asserts only
    // the cleared-cookie shape and that the empty cookie the browser is left holding is unauthorised.
    const empty = await getAdmin(env, "/admin/whoami", { cookie: `${SESSION_COOKIE_NAME}=` });
    ok("an empty (post-logout) session cookie is unauthorised", empty.status === 401);
  }

  // ============================================================================================
  // 6. CSRF: a MUTATING passkey-authenticated POST is refused cross-origin / Origin-less, and admitted
  //    with the exact CONSOLE_ORIGIN.
  // ============================================================================================
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator();
    await register(env, auth, "owner@example.com");
    const lgn = await login(env, auth, "owner@example.com");
    const cookie = cookiePair(lgn.setCookie)!;

    // A mutating POST (a downpipe upsert) with NO Origin header -> 403 CSRF (fails closed).
    const noOrigin = await postAdmin(env, "/admin/downpipes", { id: "dp1", name: "dp1", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } }, { cookie });
    ok("a mutating passkey POST with no Origin is refused (CSRF 403)", noOrigin.status === 403 && noOrigin.json.error === "csrf origin check failed");

    // Same POST with a FOREIGN Origin -> 403.
    const foreign = await postAdmin(env, "/admin/downpipes", { id: "dp1", name: "dp1", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } }, { cookie, origin: "https://evil.example" });
    ok("a mutating passkey POST from a foreign Origin is refused (CSRF 403)", foreign.status === 403);

    // Same POST WITH the exact CONSOLE_ORIGIN -> passes the CSRF guard (200 upsert).
    const good = await postAdmin(env, "/admin/downpipes", { id: "dp1", name: "dp1", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } }, { cookie, origin: ORIGIN });
    ok("a mutating passkey POST with the exact CONSOLE_ORIGIN passes the CSRF guard (200)", good.status === 200);

    // A READ (GET) needs no Origin (it is not state-changing): the same cookie reads fine with no Origin.
    const read = await getAdmin(env, "/admin/whoami", { cookie });
    ok("a passkey GET is exempt from the CSRF Origin check", read.status === 200);
  }

  // ============================================================================================
  // 6b. CSRF guard is PASSKEY-ONLY: a token-authenticated mutating POST is NOT subject to the Origin
  //     check (it carries an explicit bearer, not an ambient cookie). This proves the guard targets the
  //     ambient-credential method, not every write.
  // ============================================================================================
  {
    const TOKEN = "break-glass-token-value";
    const { env } = makeScheduler({ ADMIN_TOKEN: TOKEN });
    // A token mutating POST with no Origin succeeds (the token is not a CSRF vector). Owner via token.
    const r = await postAdmin(env, "/admin/downpipes", { id: "dpT", name: "dpT", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dpT", include: [], exclude: [] } }, { bearer: TOKEN });
    ok("a token-authenticated mutating POST is NOT blocked by the passkey CSRF guard", r.status === 200);
  }

  // ============================================================================================
  // 7. PRECEDENCE access > passkey > token, driven through the REAL authorise() with a real Access JWT.
  // ============================================================================================
  {
    const accessSetup = await makeAccessSetup();
    try {
      const { env } = makeScheduler({ ...accessSetup.env, ADMIN_TOKEN: "break-glass-token-value" });
      const auth = await makeAuthenticator();
      await register(env, auth, "owner@example.com");
      const lgn = await login(env, auth, "owner@example.com");
      const sessionToken = cookiePair(lgn.setCookie)!.split("=").slice(1).join("=");

      // A request with a VALID Access JWT AND a valid session cookie: Access WINS (method access). We drive
      // authorise() directly with a stub passkey verifier that RECORDS whether it was consulted, to prove
      // the Access branch returns before the passkey branch is even reached.
      let passkeyConsulted = false;
      const reqBoth = new Request("https://engine.example/admin/whoami", {
        method: "GET",
        headers: { "cf-access-jwt-assertion": await accessSetup.makeToken("idp-user@example.com"), cookie: `${SESSION_COOKIE_NAME}=${sessionToken}` },
      });
      const vBoth = await authorise(reqBoth, env, async () => { passkeyConsulted = true; return { email: "owner@example.com", subject: "passkey|owner@example.com", method: "passkey", connId: null, groups: [] }; });
      ok("Access JWT WINS over a present session cookie (method access)", vBoth.ok === true && vBoth.method === "access" && vBoth.email === "idp-user@example.com");
      ok("the passkey verifier is NOT consulted when Access wins", passkeyConsulted === false);

      // A request with a session cookie and NO Access assertion, with the token also configured: passkey
      // WINS over the token (method passkey, not token). Real verifier via the DO this time (full router).
      const cookieOnly = await getAdmin(env, "/admin/whoami", { cookie: `${SESSION_COOKIE_NAME}=${sessionToken}` });
      ok("a session cookie WINS over the configured token (method passkey)", cookieOnly.status === 200 && cookieOnly.json.method === "passkey");

      // A request with ONLY the bearer (no cookie, no Access): token path.
      const tokenOnly = await getAdmin(env, "/admin/whoami", { bearer: "break-glass-token-value" });
      ok("with no Access and no cookie, the token path is used (method token)", tokenOnly.status === 200 && tokenOnly.json.method === "token");

      // An INVALID Access assertion (tampered) does NOT fall through to the passkey cookie: it fails closed.
      const badAccess = await accessSetup.makeToken("idp-user@example.com");
      // Tamper a character INSIDE the signature (the segment after the last '.'), not the final
      // character: flipping the last char can produce a non-canonical trailing-bits base64url that the
      // strict decoder rejects BEFORE the signature is checked (an intermittent ~1-in-1024 flake, since a
      // 256-byte RS256 signature's last base64url char carries only 2 bits, so a "B" there is invalid).
      // Flipping the signature's FIRST char keeps the encoding canonical but makes the signature no longer
      // verify, which is exactly the "a tampered Access assertion fails closed" this asserts.
      const sigDot = badAccess.lastIndexOf(".");
      const sigHead = badAccess[sigDot + 1] === "A" ? "B" : "A";
      const tamperedAccess = badAccess.slice(0, sigDot + 1) + sigHead + badAccess.slice(sigDot + 2);
      let passkeyConsulted2 = false;
      const reqBadAccess = new Request("https://engine.example/admin/whoami", {
        method: "GET",
        headers: { "cf-access-jwt-assertion": tamperedAccess, cookie: `${SESSION_COOKIE_NAME}=${sessionToken}` },
      });
      const vBad = await authorise(reqBadAccess, env, async () => { passkeyConsulted2 = true; return { email: "owner@example.com", subject: "passkey|owner@example.com", method: "passkey", connId: null, groups: [] }; });
      ok("an INVALID Access assertion fails closed and does NOT try the passkey cookie", vBad.ok === false && passkeyConsulted2 === false);
    } finally {
      accessSetup.restoreFetch();
    }
  }

  // ============================================================================================
  // 8. INVITE -> REGISTER: a role granted to an email that has not registered applies once they register
  //    + log in; and registering NEVER self-escalates (a fresh second registrant with no grant is viewer).
  // ============================================================================================
  {
    const { env } = makeScheduler();
    const ownerAuth = await makeAuthenticator();
    await register(env, ownerAuth, "owner@example.com"); // first registrant bootstraps to Owner
    const ownerLogin = await login(env, ownerAuth, "owner@example.com");
    const ownerCookie = cookiePair(ownerLogin.setCookie)!;

    // The Owner INVITES a not-yet-registered email by granting it the operator role (a mutating POST, so it
    // needs the CONSOLE_ORIGIN for the CSRF guard). The DO mints a single-use registration invite (the
    // email had no credential yet) and returns the token on the 200 body.
    const invitee = "invitee@example.com";
    const grant = await postAdmin(env, "/admin/roles", { email: invitee, role: "operator" }, { cookie: ownerCookie, origin: ORIGIN });
    ok("Owner grants operator to a not-yet-registered email", grant.status === 200);
    const inviteTokenRaw = grant.json.inviteToken as string | undefined;
    ok("the grant to a not-yet-enrolled email minted a registration invite", typeof inviteTokenRaw === "string" && inviteTokenRaw.length > 0);
    // Narrow to string for the invited registration below (register's inviteToken is optional and does not
    // accept an explicit undefined); a missing token is a real failure the assertion above already surfaces.
    if (inviteTokenRaw === undefined) throw new Error("expected an invite token from the grant");
    const inviteToken: string = inviteTokenRaw;

    // The invitee now registers a passkey WITH the invite + logs in. Registration grants NO role of its own
    // (the table is non-empty, so no bootstrap); the role comes from the existing GRANT, and the bound email
    // comes from the invite.
    const inviteeAuth = await makeAuthenticator();
    const inviteeReg = await register(env, inviteeAuth, invitee, { inviteToken });
    ok("the invitee registers WITH the invite without a bootstrap", inviteeReg.status === 200 && inviteeReg.json.ok === true && inviteeReg.json.bootstrapped === false);
    const inviteeLogin = await login(env, inviteeAuth, invitee);
    const inviteeCookie = cookiePair(inviteeLogin.setCookie)!;
    const inviteeWho = await getAdmin(env, "/admin/whoami", { cookie: inviteeCookie });
    ok("the invitee's session resolves the GRANTED operator role", inviteeWho.status === 200 && inviteeWho.json.method === "passkey" && inviteeWho.json.role === "operator");

    // NO self-registration without authorisation: a DIFFERENT fresh email with NO grant, NO invite and NO
    // session is now REFUSED at registration entirely (the takeover fix), proving registration cannot
    // self-grant authority OR even self-enrol an unauthorised identity.
    const strangerAuth = await makeAuthenticator();
    const strangerReg = await register(env, strangerAuth, "stranger@example.com", { bearer: "" });
    ok("an unauthorised fresh registrant is REFUSED (forbidden), not enrolled", strangerReg.json.ok === false && strangerReg.json.reason === "forbidden");

    // And the invitee (operator) is correctly DENIED an owner-only capability via their session, proving
    // the role gate is enforced for the passkey method exactly as for the others (a people write needs
    // roles.write, which operator lacks).
    const denied = await postAdmin(env, "/admin/roles", { email: "x@example.com", role: "viewer" }, { cookie: inviteeCookie, origin: ORIGIN });
    ok("the operator session is denied a roles.write (403 forbidden, not 401/200)", denied.status === 403 && denied.json.error === "forbidden");
  }

  // ============================================================================================
  // 9. ADMIN_TOKEN_DISABLED still blocks the token path, while a passkey session still authorises
  //    (the fully self-hosted posture: passkeys, no Access, no shared token).
  // ============================================================================================
  {
    // The operator bootstraps the FIRST Owner with the token ENABLED (the real-world order: enrol the
    // first passkey, THEN harden the token away). enabledEnv and env share the same DO stub/storage, so the
    // Owner enrolled via enabledEnv is the same account the disabled env then authenticates against.
    const { env, stub } = makeScheduler({ ADMIN_TOKEN: "break-glass-token-value", ADMIN_TOKEN_DISABLED: "1" });
    const enabledEnv = { ...env, ADMIN_TOKEN_DISABLED: undefined } as unknown as Env;
    void stub;
    const auth = await makeAuthenticator();
    await register(enabledEnv, auth, "owner@example.com", { bearer: "break-glass-token-value" });
    const lgn = await login(env, auth, "owner@example.com");
    const cookie = cookiePair(lgn.setCookie)!;

    // The bearer is refused even though ADMIN_TOKEN is set (the fallback is disabled).
    const tok = await getAdmin(env, "/admin/whoami", { bearer: "break-glass-token-value" });
    ok("ADMIN_TOKEN_DISABLED blocks the bearer path (401)", tok.status === 401);

    // The passkey session still authorises (self-hosted auth needs no token).
    const sess = await getAdmin(env, "/admin/whoami", { cookie });
    ok("a passkey session still authorises under ADMIN_TOKEN_DISABLED", sess.status === 200 && sess.json.method === "passkey" && sess.json.role === "owner");

    // And a junk cookie under ADMIN_TOKEN_DISABLED is 401 (no token to fall back to anyway), never a 500.
    const junk = await getAdmin(env, "/admin/whoami", { cookie: `${SESSION_COOKIE_NAME}=junk`, bearer: "break-glass-token-value" });
    ok("a junk cookie under ADMIN_TOKEN_DISABLED is 401 (fail closed)", junk.status === 401);
  }

  console.log(failures === 0 ? "\nvalidate-session: ALL PASS" : `\nvalidate-session: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
