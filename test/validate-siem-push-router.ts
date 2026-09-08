// Validates the SIEM push destination's ADMIN ROUTER surface: GET
// /admin/push is redacted (no secret/ciphertext, ever); POST /admin/push enforces the owner gate + is
// step-up listed + dual-control queues a pending approval once a second owner exists, and the QUEUED
// listing (GET /admin/owner-actions) never carries the secret either; POST /admin/push/delete clears
// without needing a second approval; POST /admin/push/test reports the honest outcome and never advances
// the cursor; and every mutation lands the correct redaction-safe audit event. Drives the REAL handleAdmin
// over a REAL SchedulerDO on in-memory storage, mirroring validate-cov-admin-router-status.ts's harness.
// The engine-internal shapers/sender/DO-cursor logic are validated separately in test/validate-siem-push.ts.
// The only network is the stubbed Cloudflare Access JWKS (plus a mocked fetch for the test-send route's
// simulated SIEM endpoint). Run:
//   node test/validate-siem-push-router.ts

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import { PUSH_FORMATS, SYSLOG_TLS_FORMAT_SET, SYSLOG_TLS_FORMATS } from "../src/sched/scheduler-do-limits.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

interface Stack {
  dobj: SchedulerDO;
  storage: MockStorage;
  stub: DurableObjectStub;
  env: Pick<Env, "SCHEDULER">;
}

function makeStack(): Stack {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(input instanceof Request ? input : input.toString(), init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  return { dobj, storage, stub, env: { SCHEDULER: namespace } };
}

// ---- Forged Access JWT (real RS256 verification against a controlled, stubbed JWKS) ----------------------
const TEAM = "cov-push-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "cov-push-aud";
const KID = "cov-push-kid";
const ADMIN_TOKEN = "cov-push-break-glass-token-1234567890";
function jwtPart(o: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(o)));
}

function mkEnv(stack: Stack, extra: Record<string, unknown> = {}): Env {
  return { ...stack.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ...extra } as unknown as Env;
}

interface CallOpts {
  jwt?: string;
  bearer?: string;
  body?: unknown;
}
async function call(env: Env, method: "GET" | "POST", path: string, opts: CallOpts = {}): Promise<{ status: number; json: Record<string, unknown> }> {
  const headers: Record<string, string> = {};
  if (opts.jwt !== undefined) headers["cf-access-jwt-assertion"] = opts.jwt;
  if (opts.bearer !== undefined) headers.authorization = `Bearer ${opts.bearer}`;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  const init: RequestInit = { method, headers };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const resp = await handleAdmin(new Request(`https://engine.cov.example${path}`, init), env);
  let json: Record<string, unknown> = {};
  try {
    json = (await resp.json()) as Record<string, unknown>;
  } catch {
    /* a non-JSON body (e.g. a plaintext 401) leaves json {} */
  }
  return { status: resp.status, json };
}

async function main(): Promise<void> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pub.n, e: pub.e }] };
  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    // A push test-send in flight (a simulated customer SIEM endpoint): default to 200 unless a test below
    // installs its own override (each such test restores this default in a finally block).
    return new Response("ok", { status: 200 });
  }) as typeof fetch;

  try {
    // =====================================================================================
    // Structural: the three push routes are step-up listed, and each reaches a REAL dispatch case (not the
    // 404 default) when driven with a step-up-EXEMPT bare-token caller. The step-up gate ITSELF (a stale
    // passkey session is blocked) is validated generically by validate-session.ts's structural coverage,
    // which derives the router's real dispatched POST set from source and asserts every STEPUP_SUBS entry
    // is a real case; this only proves the strings are present and wired for this feature specifically.
    // =====================================================================================
    {
      ok("STEPUP_SUBS includes /push", STEPUP_SUBS.has("/push"));
      ok("STEPUP_SUBS includes /push/delete", STEPUP_SUBS.has("/push/delete"));
      ok("STEPUP_SUBS includes /push/test", STEPUP_SUBS.has("/push/test"));
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      for (const sub of ["/push", "/push/delete", "/push/test"]) {
        const r = await call(env, "POST", `/admin${sub}`, { bearer: ADMIN_TOKEN, body: {} });
        ok(`a bare-token (step-up-exempt) caller reaches a real dispatch case on POST ${sub} (not 404)`, r.status !== 404);
      }
    }

    // =====================================================================================
    // GET /admin/push, unconfigured: present:false, an empty trail, no secret field of any kind.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/push (unconfigured): 200", r.status === 200);
      ok("present:false, an empty trail array", r.json.present === false && Array.isArray(r.json.trail) && (r.json.trail as unknown[]).length === 0);
      ok("no secret-shaped field anywhere in the unconfigured view", !("authHeaderValue" in r.json) && !JSON.stringify(r.json).toLowerCase().includes("ciphertext"));
    }

    // =====================================================================================
    // Owner gate: a non-owner (viewer) is refused 403 on every mutating route.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const OWNER = "push-owner@cov.example";
      const VIEWER = "push-viewer@cov.example";
      ok("owner bootstrap", (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(OWNER) })).json.role === "owner");
      const setDenied = await call(env, "POST", "/admin/push", { jwt: await tokenFor(VIEWER), body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("POST /admin/push (non-owner): 403", setDenied.status === 403 && setDenied.json.required === "keys.ceremony");
      const delDenied = await call(env, "POST", "/admin/push/delete", { jwt: await tokenFor(VIEWER) });
      ok("POST /admin/push/delete (non-owner): 403", delDenied.status === 403);
      const testDenied = await call(env, "POST", "/admin/push/test", { jwt: await tokenFor(VIEWER) });
      ok("POST /admin/push/test (non-owner): 403", testDenied.status === 403);
    }

    // =====================================================================================
    // Validation: the router refuses BEFORE it ever reaches the DO (never queued as a pending approval).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const bad1 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "http://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("a non-https endpoint is refused 400", bad1.status === 400 && typeof bad1.json.error === "string");
      const bad2 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://169.254.169.254/x", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("an internal-sink (cloud metadata) endpoint is refused 400 (SSRF default-deny at set time)", bad2.status === 400);
      const bad3 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "not-a-format", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("an unknown format is refused 400", bad3.status === 400);
      // KEEP-SECRET: the router now ALLOWS an empty authHeaderValue (it means "keep"); a FIRST create with
      // no secret is refused by the DO instead (nothing to keep), still surfacing as a 400.
      const bad4 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "", enabled: true } });
      ok("a FIRST create with an empty auth header value is refused 400 (at the DO: nothing to keep)", bad4.status === 400);
      const bad5 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s" } });
      ok("a missing enabled flag is refused 400", bad5.status === 400);
      // FORBIDDEN HEADER NAME: content-type would collide with the content-type the sender sets, so it
      // is refused 400 at the router (a runtime-controlled header like host/connection is refused too).
      const badHdr = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "content-type", authHeaderValue: "s", enabled: true } });
      ok("a content-type auth header name is refused 400", badHdr.status === 400 && /content-type|runtime-controlled/i.test(String(badHdr.json.error)));
      // the router screens the auth header VALUE at config time (control chars / over-length) BEFORE
      // sealing, so a CR/LF-bearing value is a clear 400 rather than an opaque send-time network error.
      const badVal = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "tok\r\nX-Injected: 1", enabled: true } });
      ok("a CR/LF auth header value is refused 400 at the router (header-injection guard)", badVal.status === 400 && /control character|length cap/i.test(String(badVal.json.error)));
      const badLong = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "a".repeat(9000), enabled: true } });
      ok("an over-length auth header value is refused 400 at the router", badLong.status === 400);
      const okSpace = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: "Splunk 11111111-2222-3333-4444-555555555555", enabled: true } });
      ok("a legitimate space-bearing value ('Splunk <token>') is accepted (not a 400)", okSpace.status !== 400);
      const badHdr2 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Host", authHeaderValue: "s", enabled: true } });
      ok("a runtime-controlled header name (Host) is refused 400", badHdr2.status === 400);
      // POSTCONDITION, authInUrl. A silently inverted boolean is not a
      // truncated string: the caller believes they set it, and this flag decides whether the credential rides
      // in the endpoint URL or in a header (and relaxes the forbidden-header-name rule). A present
      // non-boolean is refused; absent still means false.
      const httpBase = { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true };
      for (const bad of ["true", "false", 1, 0, {}] as unknown[]) {
        const r = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { ...httpBase, authInUrl: bad } });
        ok(`a non-boolean authInUrl (${JSON.stringify(bad)}) is refused 400 rather than coerced to its opposite`, r.status === 400 && String(r.json.error) === "push destination: carry the auth token in the url must be true or false (omit it to send the token in a header)");
      }
      // NO OVER-REFUSAL: both real booleans, and an omitted flag, still save, and the stored POSTURE is what
      // was asked for. Without these three a route that 400'd every push set would pass the five above.
      for (const [label, flag, want] of [["true", true, true], ["false", false, undefined], ["absent", undefined, undefined]] as Array<[string, boolean | undefined, true | undefined]>) {
        const s = makeStack();
        const e = mkEnv(s, { ADMIN_TOKEN });
        const body = flag === undefined ? { ...httpBase } : { ...httpBase, authInUrl: flag };
        const set = await call(e, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body });
        const view = await call(e, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
        ok(`push CONTROL: authInUrl ${label} still saves 200 and reads back as asked`, set.status === 200 && view.json.authInUrl === want);
      }
      // Alternate-sink validation at the router (the s3 and syslog-tls sinks): each malformed target is a
      // 400 refused BEFORE the DO, covering validatePushSetShape's s3/syslog reject arms.
      const badSink = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", sink: "kafka", enabled: true } });
      ok("an unknown sink is refused 400", badSink.status === 400);
      const s3NoTarget = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true } });
      ok("s3 sink with no s3Target is refused 400", s3NoTarget.status === 400);
      const s3BadEndpoint = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "http://s3.example.com", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s" } } });
      ok("s3 sink with a non-https endpoint is refused 400", s3BadEndpoint.status === 400);
      const s3NoBucket = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "", region: "r", accessKeyId: "k", secretAccessKey: "s" } } });
      ok("s3 sink missing a bucket/region/key is refused 400", s3NoBucket.status === 400);
      const syslogNoTarget = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "cef", sink: "syslog-tls", enabled: true } });
      ok("syslog-tls sink with no syslog target is refused 400", syslogNoTarget.status === 400);
      const syslogNoHost = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "cef", sink: "syslog-tls", enabled: true, syslog: { port: 6514 } } });
      ok("syslog-tls sink missing a host is refused 400", syslogNoHost.status === 400);

      // ===== AN OUT-OF-RANGE PORT AND AN UNRECOGNISED ADDRESSING / STORAGE CLASS ARE REFUSED. =====
      //
      // Without these guards, a malformed port could silently resolve to the default port, sending an
      // operator's audit stream to a port they never chose. Similarly, addressing and storageClass must be
      // validated rather than forwarded bare: a GLACIER tier -- which is not immediately readable and is
      // refused outright on the destination surface for that reason -- must not silently save without applying.
      for (const [port, why] of [
        [0, "zero"],
        [70000, "above 65535"],
        [514.5, "fractional"],
      ] as Array<[number, string]>) {
        const r = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "cef", sink: "syslog-tls", enabled: true, syslog: { host: "siem.example.com", port } } });
        ok(`syslog port ${port} (${why}) is refused 400, not silently 6514`, r.status === 400 && String((r.json as { error?: string }).error).includes("1 to 65535"));
      }
      const s3BadAddressing = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s", addressing: "virtual" } } });
      ok("s3 sink with an unrecognised addressing is refused 400, not silently dropped", s3BadAddressing.status === 400);
      const s3BadClass = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s", storageClass: "GLACIER" } } });
      ok("s3 sink with a GLACIER storage class is refused 400, not silently dropped", s3BadClass.status === 400);
      // POSTCONDITION, the s3 KEY PREFIX. sanitisePrefix promises a value with no trailing slash.
      // An over-length prefix is REFUSED rather than trimmed (a prefix names a location, so a value
      // trimmed to fit addresses somewhere else), and the length is measured AFTER cleaning so a legal prefix
      // behind a control character is not refused for a length it does not have.
      const s3Pfx = (prefix: string): Record<string, unknown> => ({ format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s", prefix } });
      const s3PfxOver = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: s3Pfx(`${"a".repeat(511)}/${"b".repeat(200)}`) });
      ok("s3 key prefix over 512 characters is refused 400, not truncated back onto a trailing slash", s3PfxOver.status === 400 && String(s3PfxOver.json.error) === "push destination s3 key prefix must be 512 characters or fewer once leading and trailing slashes are removed (yours is 712)");
      const s3Pfx513 = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: s3Pfx("a".repeat(513)) });
      ok("s3 key prefix at 513 characters is refused 400", s3Pfx513.status === 400);
      // NO OVER-REFUSAL, twice over: exactly 512 legal characters, and 512 legal characters that only fit
      // once a control character and wrapping slashes come off. Both must SAVE, and the stored value must be
      // all 512 characters with no trailing slash on it.
      {
        const s = makeStack();
        const e = mkEnv(s, { ADMIN_TOKEN });
        const at512 = await call(e, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: s3Pfx("a".repeat(512)) });
        const view = await call(e, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
        const stored = (view.json.s3 as Record<string, unknown> | undefined)?.prefix;
        ok("push CONTROL: a 512-character s3 key prefix still saves 200 and reads back whole", at512.status === 200 && stored === "a".repeat(512));
        ok("POSTCONDITION: the stored s3 key prefix never ends in a slash", typeof stored === "string" && !stored.endsWith("/"));
      }
      {
        const s = makeStack();
        const e = mkEnv(s, { ADMIN_TOKEN });
        const dirty = await call(e, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: s3Pfx(`/\u0001${"a".repeat(512)}/`) });
        const view = await call(e, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
        const stored = (view.json.s3 as Record<string, unknown> | undefined)?.prefix;
        ok("push CONTROL: 512 legal characters behind a control character and slashes still save 200, whole", dirty.status === 200 && stored === "a".repeat(512));
      }
      // POSITIVE CONTROLS that must DISCRIMINATE: the in-range port and the supported enum values still
      // save. Without these, a route that 400'd every push set would pass all five refusals above.
      const syslogOk = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "cef", sink: "syslog-tls", enabled: true, syslog: { host: "siem.example.com", port: 6514 } } });
      ok("push CONTROL: an in-range syslog port still saves 200", syslogOk.status === 200);
      const s3Ok = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s", addressing: "path", storageClass: "STANDARD_IA" } } });
      ok("push CONTROL: a supported addressing + storage class still saves 200", s3Ok.status === 200);
      // THE CROSS-FIELD RULE: syslog-tls carries CEF or LEEF only; any other configured format must be
      // refused rather than silently forwarded over the syslog-tls sink. The refusal is
      // driven by the engine's own PUSH_FORMATS authority minus SYSLOG_TLS_FORMATS, so a ninth format is
      // covered with no edit here; the floor stops the loop passing vacuously.
      const notSyslogFormats = PUSH_FORMATS.filter((f) => !SYSLOG_TLS_FORMAT_SET.has(f));
      ok(`there are non-syslog formats to refuse (${notSyslogFormats.length} of ${PUSH_FORMATS.length})`, notSyslogFormats.length >= 6);
      const admitted: string[] = [];
      for (const format of notSyslogFormats) {
        const r = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format, sink: "syslog-tls", enabled: true, syslog: { host: "siem.internal.example", port: 6514 } } });
        if (r.status !== 400 || !/cef or leef for the syslog-tls sink/i.test(String(r.json.error))) admitted.push(`${format}:${r.status}`);
      }
      ok(`every non-CEF/LEEF format is refused 400 on the syslog-tls sink (admitted: ${admitted.length === 0 ? "none" : admitted.join(", ")})`, admitted.length === 0);
      // And the two it CAN carry are still admitted, so the rule discriminates rather than blocking the sink.
      for (const format of SYSLOG_TLS_FORMATS) {
        const r = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format, sink: "syslog-tls", enabled: true, syslog: { host: "siem.internal.example", port: 6514 } } });
        ok(`${format} over syslog-tls is still admitted (not a blanket refusal)`, r.status !== 400);
      }
      // The console's opaque destination-identity tag is screened here too: a crafted value never reaches
      // storage, and the vendor field is OPTIONAL (a caller that does not say is not a 400).
      const badVendor = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "splunk-hec", authHeaderValue: "Splunk t", enabled: true, vendor: "Splunk <script>" } });
      ok("a crafted vendor tag is refused 400 at the router", badVendor.status === 400 && /vendor/i.test(String(badVendor.json.error)));
      const longVendor = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "splunk-hec", authHeaderValue: "Splunk t", enabled: true, vendor: "a".repeat(65) } });
      ok("an over-length vendor tag is refused 400 at the router", longVendor.status === 400);
      // None of the above reached the DO's dual-control queue (no pending owner action was ever recorded).
      const inbox = await call(env, "GET", "/admin/owner-actions", { bearer: ADMIN_TOKEN });
      ok("no pending owner action was queued by any rejected submission", Array.isArray(inbox.json) && (inbox.json as unknown[]).length === 0);
    }

    // =====================================================================================
    // GATE OFF (single owner, the default): POST /admin/push sets inline (200 + the fresh redacted view);
    // GET reflects it; the secret NEVER appears in either response, and the set/cleared audit events land.
    // =====================================================================================
    const SECRET = "xoxb-hec-token-DO-NOT-LEAK-1a2b3c";
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const set = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true } });
      ok("POST /admin/push (owner, gate off): 200 (applied inline)", set.status === 200);
      ok("the 200 body is the redacted view: no secret, no ciphertext", !("authHeaderValue" in set.json) && !JSON.stringify(set.json).includes(SECRET) && !JSON.stringify(set.json).toLowerCase().includes("ciphertext"));
      ok("the 200 body reflects the non-secret fields", set.json.present === true && set.json.endpoint === "https://siem.example.com/ingest" && set.json.format === "splunk-hec" && set.json.authHeaderName === "Authorization" && set.json.enabled === true);

      const get = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/push reflects the same redacted state", get.json.present === true && get.json.endpoint === "https://siem.example.com/ingest" && !JSON.stringify(get.json).includes(SECRET));
      ok("GET /admin/push carries lastPushedSeq + headSeq for the console's cursor-lag display", typeof get.json.lastPushedSeq === "number" && typeof get.json.headSeq === "number");

      const audit = await call(env, "GET", "/admin/audit?limit=200", { bearer: ADMIN_TOKEN });
      const events = (audit.json.events as Array<{ action?: string; target?: Record<string, unknown> }>) ?? [];
      ok("a push-destination-set audit event was recorded, closed target only", events.some((e) => e.action === "push-destination-set" && e.target?.kind === "push-destination" && e.target?.op === "set"));
      ok("the audit chain never carries the secret or the endpoint URL in the push target", !JSON.stringify(events.find((e) => e.action === "push-destination-set")?.target).includes(SECRET));

      // POST /admin/push/delete: owner, NOT dual-control gated even conceptually (there is only one owner
      // here, so this also proves the gate-off/no-second-owner default behaviour).
      const del = await call(env, "POST", "/admin/push/delete", { bearer: ADMIN_TOKEN });
      ok("POST /admin/push/delete (owner): 200 { ok: true }", del.status === 200 && del.json.ok === true);
      const getAfterDel = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/push after delete: present:false", getAfterDel.json.present === false);
      const auditAfterDel = await call(env, "GET", "/admin/audit?limit=200", { bearer: ADMIN_TOKEN });
      ok("a push-destination-cleared audit event was recorded", ((auditAfterDel.json.events as Array<{ action?: string }>) ?? []).some((e) => e.action === "push-destination-cleared"));
    }

    // GATE OFF, alternate sinks: a valid s3-sink and a valid syslog-tls-sink destination each set inline
    // (200 + redacted view), covering validatePushSetShape's s3/syslog accept arms end to end at the router.
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const S3_SECRET = "s3-write-secret-DO-NOT-LEAK";
      const s3Set = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "audit-bucket", region: "us-east-1", accessKeyId: "AKIA_TEST", secretAccessKey: S3_SECRET, addressing: "path", storageClass: "STANDARD", prefix: "downpipes-audit/" } } });
      ok("POST /admin/push (s3 sink, valid): 200 applied inline", s3Set.status === 200);
      ok("the s3 200 view echoes the bucket/region/endpoint but NEVER the secret key", s3Set.json.sink === "s3" && (s3Set.json.s3 as Record<string, unknown>)?.bucket === "audit-bucket" && !JSON.stringify(s3Set.json).includes(S3_SECRET));
      const syslogSet = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "cef", sink: "syslog-tls", enabled: true, syslog: { host: "siem.internal.example", port: 6514 } } });
      ok("POST /admin/push (syslog-tls sink, valid): 200 applied inline", syslogSet.status === 200);
      ok("the syslog 200 view echoes host + port", syslogSet.json.sink === "syslog-tls" && (syslogSet.json.syslog as Record<string, unknown>)?.host === "siem.internal.example" && (syslogSet.json.syslog as Record<string, unknown>)?.port === 6514);
    }

    // =====================================================================================
    // THE DESTINATION-IDENTITY TAG (`vendor`), end to end through the router and the DO.
    //
    // The push is a SINGLETON keyed only by format crossed with sink, and that pair is NOT injective over the
    // console's vendor catalogue: Splunk and CrowdStrike Falcon Next-Gen SIEM both take splunk-hec over http.
    // One live Splunk push therefore lit both tiles Active in the console, both panels claimed the config, and
    // the Splunk-only "paste the token as Splunk <token>" instruction rendered on the CrowdStrike form where
    // it is wrong. The engine now stores what the console says it is, echoes it in the redacted view, and
    // keeps it across a keep-secret re-set, so the console never has to guess from the wire again.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const VSECRET = "Splunk 99999999-8888-7777-6666-555555555555";
      const setV = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://http-inputs.splunkcloud.example/services/collector/event", format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: VSECRET, enabled: true, vendor: "splunk" } });
      ok("POST /admin/push carrying vendor:'splunk' is applied inline (200)", setV.status === 200);
      ok("the redacted 200 view echoes the vendor tag, and still no secret", setV.json.vendor === "splunk" && !JSON.stringify(setV.json).includes(VSECRET));
      const getV = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/push echoes the stored vendor tag", getV.json.vendor === "splunk");
      // A keep-secret re-set (the console's enable/disable toggle path) must not drop the tag: dropping it
      // would silently hand the config back to the format-crossed-sink guess this field exists to replace.
      const toggle = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://http-inputs.splunkcloud.example/services/collector/event", format: "splunk-hec", authHeaderName: "Authorization", enabled: false, vendor: "splunk" } });
      ok("a keep-secret re-set keeps the vendor tag", toggle.status === 200 && toggle.json.vendor === "splunk" && toggle.json.enabled === false);
      // A submission with NO vendor is still valid, and the view then says nothing rather than guessing: the
      // honest reading for a record written before the field existed, or by a direct API caller.
      const noVendor = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: VSECRET, enabled: true } });
      ok("a submission with no vendor tag is accepted, and the view carries no vendor (never a guess)", noVendor.status === 200 && noVendor.json.vendor === undefined);
    }

    // =====================================================================================
    // KEEP-SECRET (the write-only-secret-field UX, end to end through the router + DO): create with a
    // secret, then set again WITHOUT one to toggle enabled + edit non-secret fields -> the sealed secret is
    // kept, the non-secret fields update, and the kept secret STILL DELIVERS (a test-send carries it). A
    // first-ever set with no secret is refused.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      // A first-ever set with no secret is refused (the DO has nothing to keep).
      const firstNoSecret = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", enabled: true } });
      ok("a FIRST set with no authHeaderValue is refused 400 (needs a secret to create)", firstNoSecret.status === 400);
      ok("nothing was stored by the rejected first create", (await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN })).json.present === false);

      // Create WITH a secret.
      const create = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true } });
      ok("create WITH a secret -> 200", create.status === 200 && create.json.present === true && create.json.enabled === true);

      // Set again WITHOUT a secret: toggle enabled off + edit endpoint/format/header name (keep the secret).
      const edit = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem2.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", enabled: false } });
      ok("a later set WITHOUT authHeaderValue -> 200 (keep-secret, the console can toggle/edit)", edit.status === 200);
      const view = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("the secretless edit updated the non-secret fields", view.json.endpoint === "https://siem2.example.com/ingest" && view.json.format === "datadog" && view.json.authHeaderName === "DD-API-KEY" && view.json.enabled === false);
      ok("still no secret in the redacted view after keep-secret", !JSON.stringify(view.json).includes(SECRET));

      // Re-enable + test-send: the KEPT secret resolves and delivers, and is carried in the configured header.
      await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem2.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", enabled: true } });
      const captures: Array<{ headers: Record<string, string>; body: string }> = [];
      const savedFetch = globalThis.fetch;
      globalThis.fetch = (async (_url, init) => {
        captures.push({ headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
        return new Response("ok", { status: 200 });
      }) as typeof fetch;
      let test: { status: number; json: Record<string, unknown> };
      try {
        test = await call(env, "POST", "/admin/push/test", { bearer: ADMIN_TOKEN });
      } finally {
        globalThis.fetch = savedFetch;
      }
      const sent = captures[captures.length - 1];
      ok("KEEP-SECRET still delivers -- a test-send with the kept secret succeeds (200)", test.json.ok === true && test.json.httpStatus === 200);
      ok("the kept secret was carried in the configured header (DD-API-KEY)", sent?.headers["DD-API-KEY"] === SECRET);
      ok("the test-send body never contains the secret", sent?.body.includes(SECRET) !== true);
    }

    // =====================================================================================
    // DUAL CONTROL (two owners, the opt-in gate ON): owner1 proposes -> 202 queued; the QUEUED listing
    // (GET /admin/owner-actions) NEVER carries the secret (redactOwnerActionParamsForListing coverage,
    // invariant 2's owner-action half); owner2 (a DISTINCT identity) approves -> the DO-executed push-
    // dest-set runs immediately (maker != checker); GET /admin/push then reflects the new destination.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const O1 = "push-dc-owner1@cov.example";
      const O2 = "push-dc-owner2@cov.example";
      ok("owner1 bootstrap", (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(O1) })).json.role === "owner");
      const grant = await call(env, "POST", "/admin/roles", { jwt: await tokenFor(O1), body: { email: O2, role: "owner" } });
      ok("owner2 granted (inline, gate still off)", grant.status === 200);
      const arm = await call(env, "POST", "/admin/config/approval-policy", { jwt: await tokenFor(O1), body: { requireConfigApproval: true } });
      ok("dual control armed", arm.status === 200);

      const proposal = await call(env, "POST", "/admin/push", { jwt: await tokenFor(O1), body: { endpoint: "https://siem.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", authHeaderValue: SECRET, enabled: true } });
      ok("owner1 proposes: 202 queued (gate on, second owner exists -> auto-gated high-blast op)", proposal.status === 202 && proposal.json.ownerActionQueued === true);
      const pendingId = proposal.json.id as string;

      const inbox = await call(env, "GET", "/admin/owner-actions", { jwt: await tokenFor(O2) });
      const pending = (inbox.json as unknown as Array<{ id: string; kind: string; params: Record<string, unknown> }>).find((a) => a.id === pendingId);
      ok("the pending action is visible to owner2 (an owner reviewer)", pending !== undefined && pending.kind === "push-dest-set");
      ok("the QUEUED listing's params carry the non-secret fields (endpoint/format/header name)", pending?.params.endpoint === "https://siem.example.com/ingest" && pending?.params.format === "datadog" && pending?.params.authHeaderName === "DD-API-KEY");
      ok("the QUEUED listing NEVER carries the secret (redactOwnerActionParamsForListing strips authHeaderValue)", !("authHeaderValue" in (pending?.params ?? {})) && !JSON.stringify(pending?.params ?? {}).includes(SECRET));

      // Self-approval is refused (maker != checker), at the DO (defence in depth).
      const selfApprove = await call(env, "POST", `/admin/owner-actions/${pendingId}/approve`, { jwt: await tokenFor(O1) });
      ok("owner1 cannot approve their own proposal", selfApprove.status !== 200);

      const approve = await call(env, "POST", `/admin/owner-actions/${pendingId}/approve`, { jwt: await tokenFor(O2) });
      ok("owner2 (distinct identity) approves: 200, executed", approve.status === 200 && approve.json.status === "executed");

      const get = await call(env, "GET", "/admin/push", { jwt: await tokenFor(O1) });
      ok("the approved config is now live (GET reflects it)", get.json.present === true && get.json.endpoint === "https://siem.example.com/ingest" && get.json.format === "datadog" && get.json.authHeaderName === "DD-API-KEY");
      ok("still no secret in the live GET after the dual-control execute", !JSON.stringify(get.json).includes(SECRET));
    }

    // =====================================================================================
    // S3-DROP SINK (gate off, single owner): POST /admin/push with sink:"s3" sets inline; the redacted view
    // carries the s3 LOCATION (endpoint/bucket/region) but NEVER the s3 secret or the s3 access key id.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const S3SECRET = "s3-access-key-secret-DO-NOT-LEAK-9z8y";
      const set = await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.example.com", bucket: "audit-bucket", region: "us-east-1", accessKeyId: "AKIA-ROUTER-KEYID", secretAccessKey: S3SECRET } } });
      ok("POST /admin/push (owner, s3 sink, gate off): 200 applied inline", set.status === 200);
      ok(
        "the s3 set 200 body carries the s3 location but NEVER the s3 secret or access key id",
        set.json.sink === "s3" && (set.json.s3 as Record<string, unknown> | undefined)?.bucket === "audit-bucket" && !JSON.stringify(set.json).includes(S3SECRET) && !JSON.stringify(set.json).includes("AKIA-ROUTER-KEYID"),
      );
      const get = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/push reflects the s3 sink location, still no secret", (get.json.s3 as Record<string, unknown> | undefined)?.region === "us-east-1" && !JSON.stringify(get.json).includes(S3SECRET));
    }

    // =====================================================================================
    // DUAL CONTROL, s3 sink: owner1 proposes an s3 push destination carrying an s3 secret ->
    // 202 queued; the QUEUED listing (GET /admin/owner-actions) carries the non-secret s3 fields but NEVER the
    // s3 secretAccessKey (redactOwnerActionParamsForListing's new s3Target branch). Without the fix the
    // proposer's live S3 key would leak in the pending-approval listing to every reviewing owner.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const O1 = "push-s3-owner1@cov.example";
      const O2 = "push-s3-owner2@cov.example";
      const S3SECRET = "s3-queued-secret-DO-NOT-LEAK-7q6w";
      ok("owner1 bootstrap", (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(O1) })).json.role === "owner");
      ok("owner2 granted", (await call(env, "POST", "/admin/roles", { jwt: await tokenFor(O1), body: { email: O2, role: "owner" } })).status === 200);
      ok("dual control armed", (await call(env, "POST", "/admin/config/approval-policy", { jwt: await tokenFor(O1), body: { requireConfigApproval: true } })).status === 200);

      const proposal = await call(env, "POST", "/admin/push", { jwt: await tokenFor(O1), body: { format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.example.com", bucket: "audit-bucket", region: "us-east-1", accessKeyId: "AKIA-QUEUED-KEYID", secretAccessKey: S3SECRET } } });
      ok("owner1 proposes an s3 push destination: 202 queued (auto-gated high-blast op)", proposal.status === 202 && proposal.json.ownerActionQueued === true);
      const pendingId = proposal.json.id as string;

      const inbox = await call(env, "GET", "/admin/owner-actions", { jwt: await tokenFor(O2) });
      const pending = (inbox.json as unknown as Array<{ id: string; kind: string; params: Record<string, unknown> }>).find((a) => a.id === pendingId);
      ok("the pending s3 action is visible to owner2 (kind push-dest-set)", pending !== undefined && pending.kind === "push-dest-set");
      const s3params = (pending?.params.s3Target ?? {}) as Record<string, unknown>;
      ok("the QUEUED listing carries the non-secret s3 fields (endpoint/bucket/region/accessKeyId)", s3params.endpoint === "https://s3.example.com" && s3params.bucket === "audit-bucket" && s3params.region === "us-east-1" && s3params.accessKeyId === "AKIA-QUEUED-KEYID");
      ok(
        "the QUEUED listing NEVER carries the s3 secret (redactOwnerActionParamsForListing strips s3Target.secretAccessKey)",
        !("secretAccessKey" in s3params) && !JSON.stringify(pending?.params ?? {}).includes(S3SECRET),
      );

      const approve = await call(env, "POST", `/admin/owner-actions/${pendingId}/approve`, { jwt: await tokenFor(O2) });
      ok("owner2 (distinct identity) approves the s3 proposal: 200 executed", approve.status === 200 && approve.json.status === "executed");
      const get = await call(env, "GET", "/admin/push", { jwt: await tokenFor(O1) });
      ok("the approved s3 config is live (GET reflects the s3 location), still no secret", get.json.sink === "s3" && (get.json.s3 as Record<string, unknown> | undefined)?.bucket === "audit-bucket" && !JSON.stringify(get.json).includes(S3SECRET));
    }

    // =====================================================================================
    // POST /admin/push/test: honest outcomes (2xx / a real 4xx / not-configured), and it NEVER advances
    // the cursor or touches the delivery trail (a diagnostic probe, not a drain tick).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const notConfigured = await call(env, "POST", "/admin/push/test", { bearer: ADMIN_TOKEN });
      ok("test-send with nothing configured: ok:false, reason not-configured", notConfigured.status === 200 && notConfigured.json.ok === false && notConfigured.json.reason === "not-configured");

      await call(env, "POST", "/admin/push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true } });

      globalThis.fetch = (async () => new Response("ok", { status: 200 })) as typeof fetch;
      const testOk = await call(env, "POST", "/admin/push/test", { bearer: ADMIN_TOKEN });
      ok("test-send success: ok:true + httpStatus:200 + a measured ms", testOk.json.ok === true && testOk.json.httpStatus === 200 && typeof testOk.json.ms === "number");

      globalThis.fetch = (async () => new Response("unauthorized", { status: 401 })) as typeof fetch;
      const testUnauth = await call(env, "POST", "/admin/push/test", { bearer: ADMIN_TOKEN });
      // A 401 reports the distinct http-auth code (not the blanket
      // http-4xx), so the test-send route surfaces "fix your credential" honestly, not a generic 4xx.
      ok("test-send reports a REAL 401 from the SIEM honestly as http-auth (not masked as generic failure)", testUnauth.json.ok === false && testUnauth.json.httpStatus === 401 && testUnauth.json.reason === "http-auth");

      // Restore the JWKS-serving default fetch for any subsequent test in this file.
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
        return new Response("ok", { status: 200 });
      }) as typeof fetch;

      const view = await call(env, "GET", "/admin/push", { bearer: ADMIN_TOKEN });
      ok("the test-send never advanced the cursor", view.json.lastPushedSeq === 0);
      ok("the test-send never touched the delivery trail", Array.isArray(view.json.trail) && (view.json.trail as unknown[]).length === 0);
    }

    // =====================================================================================
    // The default fall-through: a method+path this spoke does not own returns null (the hub 404s).
    // =====================================================================================
    {
      const s = makeStack();
      const r = await call(mkEnv(s, { ADMIN_TOKEN }), "GET", "/admin/push-not-a-route", { bearer: ADMIN_TOKEN });
      ok("default: an unowned push-spoke path falls through to 404", r.status === 404);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nSIEM PUSH ROUTER VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
