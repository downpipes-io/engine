// validate-cov-admin-router-destinations: branch-coverage proof for src/admin/router-destinations.ts,
// the archive-destination admin spoke (GET/POST /destination, the /destinations collection,
// /destination/verify, the consolidated GET /setup-state read and POST /email/test). It drives the
// PRODUCTION handleAdmin over an in-memory SchedulerDO, with a single combined fetch stub that serves
// the Access JWKS, the live S3 destination write-probe and an STS AssumeRole response, so every write
// path runs its REAL validate-then-probe core. Each assertion checks an actual outcome: an HTTP status,
// a returned body field, or a stored-and-read-back effect. The only network is the harness stub.
//
// Run: node test/validate-cov-admin-router-destinations.ts

import { handleAdmin } from "../src/admin/router.ts";
import { fetchSchedDiag, fetchAdminCounters } from "../src/admin/support-sections-diag.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { DISCOVERY_KEY, DEMO_FRESH_FIRST_RUN_KEY } from "../src/sched/scheduler-do-records.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

// makeScheduler wires a SchedulerDO over MockStorage. failPaths is a MUTABLE allow-list of pathname
// prefixes the stub rejects (a rejected promise, not a sync throw, so the route's allSettled / try-catch
// fallbacks fire), used only by the defensive-branch group; it is empty for every other call.
function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; failPaths: string[] } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const failPaths: string[] = [];
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const path = new URL(url).pathname;
      for (const f of failPaths) if (path === f || path.startsWith(f)) throw new Error(`injected DO failure for ${f}`);
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, failPaths };
}

// ---- Forged-but-correctly-signed Access JWT + the combined fetch stub ------------------------------
const TEAM = "dest-cov-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "dest-cov-aud";
const KID = "dest-cov-kid-1";
const CERTS_URL = `${ISS}/cdn-cgi/access/certs`;
const S3_HOST = "acct.r2.cloudflarestorage.com";
// GCS_HOST is Google Cloud Storage's S3-interop endpoint. It is served by the stub below so a GCS
// destination can be driven END TO END here, rather than reaching the harness's loud throw and reading as
// a refusal by the product. That distinction is the same one the vhost comment below records.
const GCS_HOST = "storage.googleapis.com";
// Azure Blob became a supported destination, so this stub must answer as one: a HEAD on a
// missing blob is 404, a PUT is 201 and a DELETE is 202. Those are Azure's own codes, not S3's.
const AZURE_HOST = "acct.blob.core.windows.net";
const GOOD_ENDPOINT = `https://${S3_HOST}`;
// A well-formed STS AssumeRole response so the assumeRole path mints temp creds and the probe proceeds.
const STS_XML =
  "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP</AccessKeyId>" +
  "<SecretAccessKey>tempsecret</SecretAccessKey><SessionToken>tok</SessionToken>" +
  "<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>";
const LOCK_XML = "<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>";
// (R4): the object-lock probe's OWN answer, which is the discriminator the verify row was discarding. A
// least-privilege key that may PutObject/GetObject and NOT DeleteObject is, by the same allow-list, usually not
// allowed GetBucketObjectLockConfiguration either -- so the lock probe 403s ("denied": a one-line IAM fix). A
// store with no Object-Lock API at all answers 501 ("not-implemented": the refused delete is the customer's own
// delete policy, and there is nothing to fix). Those two produced a byte-identical row.
const LOCK_ON_XML = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
type LockMode = "disabled" | "enabled" | "denied" | "not-implemented";
let lockMode: LockMode = "disabled";
function lockResponse(): Response {
  if (lockMode === "denied") return new Response("AccessDenied", { status: 403 });
  if (lockMode === "not-implemented") return new Response("NotImplemented", { status: 501 });
  return new Response(lockMode === "enabled" ? LOCK_ON_XML : LOCK_XML, { status: 200 });
}

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// azureVlwMode controls what the Azure stub's Get Container Properties says about VERSION-LEVEL
// IMMUTABILITY, which is what decides whether an Azure destination may carry an immutability policy. A
// container with it enabled answers the header "true"; one without it omits the header entirely, which is
// the definite not-enabled reading (see versionLevelImmutabilityStatus for why an absent header is not an
// "unknown" here). "disabled" is the default because it is the ordinary container.
let azureVlwMode: "enabled" | "disabled" = "disabled";
let probeMode: "ok" | "deny" = "ok"; // controls the live write-probe outcome (PUT 200 vs 403)
// controls the CLEANUP DELETE the probe issues after its write. A bucket that accepts the write and
// REFUSES the delete is a destination whose retention silently does not work: backups land for ever and nothing
// can expire them. probeDestination reports ok:TRUE for it (correctly: backups work), which is exactly why the
// state was invisible.
// and the TRANSIENT half of that input space, which the stub never drove. del() throws on ANY unusable
// status and on a transport fault, and the probe used to call every one of them "denied" -- a PERMISSION fact a
// 503 SlowDown, a 500, a 429 throttle and a dropped socket do not establish.
let deleteMode: "ok" | "deny" | "slowdown" | "server-error" | "throttled" | "reset" | "conflict" = "ok";
function deleteResponse(): Response {
  if (deleteMode === "deny") return new Response("AccessDenied", { status: 403 });
  if (deleteMode === "slowdown") return new Response("SlowDown", { status: 503 });
  if (deleteMode === "server-error") return new Response("InternalError", { status: 500 });
  if (deleteMode === "throttled") return new Response("TooManyRequests", { status: 429 });
  if (deleteMode === "conflict") return new Response("OperationAborted", { status: 409 });
  return new Response(null, { status: 204 });
}

async function main(): Promise<void> {
  const kp = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pub.n, e: pub.e }] };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === CERTS_URL) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    let host = "";
    try {
      host = new URL(url).host;
    } catch {
      /* fall through to the loud throw */
    }
    if (host.startsWith("sts.")) return new Response(STS_XML, { status: 200, headers: { "content-type": "text/xml" } });
    // vhost addressing signs and sends against <bucket>.<host>, not <host>. This stub answered only the bare
    // host, so the LEGAL value "vhost" could not be driven here at all: its probe reached the loud throw
    // below and read as a refusal by the product rather than by the harness. Serving the virtual-hosted form
    // as well is what lets the no-over-refusal check tell those two apart.
    // The GCS arm answers what a REAL GCS bucket answered when this was driven live, not
    // what would be convenient: 404 ObjectLockConfigurationNotFound on the Object-Lock probe (GCS has no
    // S3 Object Lock), and an ordinary 200 on the write and delete. Copying the measurement rather than
    // the R2 arm's mock is what makes the "a clean GCS destination stores" assertion mean anything.
    if (host === AZURE_HOST) {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "HEAD") return new Response(null, { status: 404 });
      if (method === "PUT") return new Response(null, { status: 201, headers: { etag: '"0x1"' } });
      if (method === "DELETE") return new Response(null, { status: 202 });
      // The WORM capability probe: Get Container Properties, answering the version-level immutability
      // header. Two modes, because the whole point of the reversal is that the two containers
      // get DIFFERENT answers. Before it, every Azure endpoint was refused an immutability policy by a
      // hardcoded rule, so the enabled container could not be told from the disabled one.
      if (method === "GET" && url.includes("restype=container") && !url.includes("comp=list")) {
        return new Response(null, { status: 200, headers: azureVlwMode === "enabled" ? { "x-ms-immutable-storage-with-versioning-enabled": "true" } : {} });
      }
      return new Response("", { status: 200, headers: { etag: '"0x1"' } });
    }
    if (host === GCS_HOST) {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "HEAD") return new Response(null, { status: 404 });
      if (method === "PUT") return new Response(null, { status: 200, headers: { etag: '"p"' } });
      if (method === "DELETE") return new Response(null, { status: 204 });
      if (method === "GET" && url.includes("object-lock")) {
        return new Response("<?xml version='1.0' encoding='UTF-8'?><Error><Code>ObjectLockConfigurationNotFound</Code></Error>", { status: 404 });
      }
      if (method === "GET") return new Response("", { status: 200, headers: { etag: '"x"' } });
      return new Response(null, { status: 200 });
    }
    if (host === S3_HOST || host.endsWith(`.${S3_HOST}`)) {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "HEAD") return new Response(null, { status: 404 });
      if (method === "PUT") return probeMode === "deny" ? new Response("AccessDenied", { status: 403 }) : new Response(null, { status: 200, headers: { etag: '"p"' } });
      if (method === "DELETE") {
        if (deleteMode === "reset") throw new TypeError("network connection lost"); // the transport fault: no status was ever seen
        return deleteResponse();
      }
      if (method === "GET") return url.includes("object-lock") ? lockResponse() : new Response("", { status: 200, headers: { etag: '"x"' } });
      return new Response(null, { status: 200 });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  // Memoise the minted JWT per email: a token is valid for an hour, so reusing it across the many
  // rate-limit-trip calls avoids re-signing an RSA assertion each time (faster, and it keeps the whole
  // run well inside the limiter's 60s window so the trip stays deterministic).
  const tokenCache = new Map<string, string>();
  async function tokenFor(email: string): Promise<string> {
    const cached = tokenCache.get(email);
    if (cached !== undefined) return cached;
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    const tok = `${header}.${body}.${b64urlEncode(sig)}`;
    tokenCache.set(email, tok);
    return tok;
  }

  const s = makeScheduler();
  const baseEnv = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-token-dest-cov" };
  const DEST_ENV = { DEST_ENDPOINT: GOOD_ENDPOINT, DEST_BUCKET: "env-bucket", DEST_REGION: "auto", DEST_ACCESS_KEY_ID: "ENVAK", DEST_SECRET_ACCESS_KEY: "ENVSK" };

  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown, extra?: Record<string, unknown>): Promise<Response> => {
    const env = { ...baseEnv, ...(extra ?? {}) } as unknown as Env;
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), env);
  };
  const callTok = async (method: "GET" | "POST", path: string, body?: unknown, extra?: Record<string, unknown>): Promise<Response> => {
    const env = { ...baseEnv, ...(extra ?? {}) } as unknown as Env;
    const init: RequestInit = {
      method,
      headers: { authorization: "Bearer bg-token-dest-cov", ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), env);
  };
  const j = async (r: Response): Promise<Record<string, unknown>> => (await r.json()) as Record<string, unknown>;
  const cfg = (bucket: string, region: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
    endpoint: GOOD_ENDPOINT,
    bucket,
    region,
    accessKeyId: "AKID",
    secretAccessKey: "SKEY",
    ...extra,
  });

  const OWNER = "owner-dest@acme.example";
  const VIEWER = "viewer-dest@acme.example";
  const KEYS = { SIGNER_PRIVATE: "x", BREAK_GLASS_PUBLIC: "x" };

  // ===== Phase 0: bootstrap the first Access caller as Owner (must be the first authenticated call). =====
  const who = (await (await call(OWNER, "GET", "/admin/whoami")).json()) as { role: string };
  ok("0: the first Access caller bootstraps as Owner", who.role === "owner");
  // An admin path this spoke does not own falls through its switch default (return null) to the hub 404.
  ok("0: an unmatched admin path falls through the destinations spoke to 404", (await call(OWNER, "GET", "/admin/not-a-destinations-route")).status === 404);

  // ===== Phase 1: GET /setup-state variants (NO console destination yet). =====
  {
    const base = await j(await call(OWNER, "GET", "/admin/setup-state"));
    const dest = base.destination as { configured?: boolean; source?: unknown; verified?: boolean };
    ok("1a: setup-state base -> destination not configured, source null (no console, no env)", dest.configured === false && dest.source === null && dest.verified === false);
    ok("1a: setup-state base -> keysReady false, no downpipes, anyRunCompleted false", base.keysReady === false && base.downpipeCount === 0 && base.anyRunCompleted === false);
    ok("1a: setup-state base -> discoveryTokenPresent/accountsSelected/emailConfigured all false", base.discoveryTokenPresent === false && base.accountsSelected === false && base.emailConfigured === false);
  }
  // Seed a downpipe with a completed run so anyRunCompleted flips true on the next read.
  await s.storage.put("dp:withrun", { config: { id: "withrun", name: "WithRun", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] } }, nextRunAt: 0, lastRunId: "run-9", inFlight: false });
  {
    const b1 = await j(await call(OWNER, "GET", "/admin/setup-state", undefined, { ...KEYS, ...DEST_ENV, EMAIL: { send: async () => {} }, EMAIL_FROM: "ops@acme.example" }));
    const dest = b1.destination as { configured?: boolean; source?: unknown };
    ok("1b: setup-state with keys+env-dest -> keysReady true, emailConfigured true", b1.keysReady === true && b1.emailConfigured === true);
    ok("1b: setup-state with env dest, no console -> destination.source 'deploy'", dest.configured === true && dest.source === "deploy");
    ok("1b: setup-state sees the seeded downpipe (count 1, anyRunCompleted true)", b1.downpipeCount === 1 && b1.anyRunCompleted === true);
  }
  {
    const b1c = await j(await call(OWNER, "GET", "/admin/setup-state", undefined, { SIGNER_PRIVATE: "x" }));
    ok("1c: signer set but break-glass absent -> keysReady false", b1c.keysReady === false && b1c.signerConfigured === true && b1c.breakGlassConfigured === false);
  }
  {
    const b1d = await j(await call(OWNER, "GET", "/admin/setup-state", undefined, { DISCOVERY_API_TOKEN: "cfat_env_discovery_token_value_123456" }));
    ok("1d: an env discovery token satisfies discoveryTokenPresent/accountsSelected", b1d.discoveryTokenPresent === true && b1d.accountsSelected === true);
  }
  // Seed a console discovery config so the DO-side presence/selection answers (not via the env token).
  await s.storage.put(DISCOVERY_KEY, { token: "cfat_seeded_discovery_token_value_123456", setAt: 1, setBy: OWNER, accountsSeen: [{ id: "acct-1", name: "Acct One" }], selected: ["acct-1"], engineAccountId: "acct-1" });
  {
    const b1e = await j(await call(OWNER, "GET", "/admin/setup-state"));
    ok("1e: a seeded discovery config (DO-side) satisfies discoveryTokenPresent/accountsSelected", b1e.discoveryTokenPresent === true && b1e.accountsSelected === true);
  }
  // 1g: DEMO_MODE with NO fresh-first-run marker -> forceFirstRun false -> keysReady stays true with keys.
  {
    const b1g = await j(await call(OWNER, "GET", "/admin/setup-state", undefined, { ...KEYS, DEMO_MODE: "true" }));
    ok("1g: DEMO_MODE without a fresh marker -> keysReady true (forceFirstRun false)", b1g.keysReady === true);
  }
  // 1f: seed the fresh-first-run marker -> DEMO_MODE forces a fresh run -> keysReady false despite keys.
  await s.storage.put(DEMO_FRESH_FIRST_RUN_KEY, true);
  {
    const b1f = await j(await call(OWNER, "GET", "/admin/setup-state", undefined, { ...KEYS, DEMO_MODE: "true" }));
    ok("1f: DEMO_MODE + fresh marker -> forceFirstRun masks keysReady to false", b1f.keysReady === false);
  }
  await s.storage.delete(DEMO_FRESH_FIRST_RUN_KEY);

  // ===== Phase 2: GET /destination WITHOUT a console destination (null + deploy sources). =====
  {
    const d2a = await j(await call(OWNER, "GET", "/admin/destination"));
    ok("2a: GET /destination with nothing configured -> source null", d2a.present === false && d2a.source === null && d2a.envConfigured === false);
    const d2b = await j(await call(OWNER, "GET", "/admin/destination", undefined, DEST_ENV));
    ok("2b: GET /destination with an env dest, no console -> source 'deploy'", d2b.present === false && d2b.source === "deploy" && d2b.envConfigured === true);
  }

  // ===== Phase 3: POST /destination/verify WITHOUT a console destination. =====
  {
    const v3a = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    ok("3a: verify with no console + no env dest -> probe fails (ok:false)", v3a.ok === false && typeof v3a.reason === "string");
    const v3b = await j(await call(OWNER, "POST", "/admin/destination/verify?id=ghost", {}, DEST_ENV));
    ok("3b: verify ?id=ghost falls back to the env dest -> ok:true, source 'deploy'", v3b.ok === true && v3b.source === "deploy");
  }

  // ===== Phase 4: validation rejections + the owner-gate denials (no state is stored). =====
  {
    const clear = await call(OWNER, "POST", "/admin/destination", { config: null });
    ok("4a: POST /destination {config:null} clears (no-op, 200, present:false)", clear.status === 200 && (await j(clear)).present === false);

    const bad = async (body: unknown, frag: string, extra?: Record<string, unknown>): Promise<void> => {
      const r = await call(OWNER, "POST", "/admin/destination", body, extra);
      const b = await j(r);
      ok(`4: ${frag}`, r.status === 400 && typeof b.error === "string" && (b.error as string).length > 0);
    };
    await bad({ config: { ...cfg("b", "us-east-1"), endpoint: "http://insecure.example" } }, "a non-https endpoint is rejected (400)");
    await bad({ config: { ...cfg("b", "us-east-1"), endpoint: "https://[" } }, "an https URL that fails to parse is rejected (400)");
    await bad({ config: { ...cfg("b", "us-east-1"), endpoint: "https://169.254.169.254" } }, "an internal/metadata endpoint host is rejected (400)");
    await bad({ config: cfg("", "us-east-1") }, "a missing bucket is rejected (400)");
    await bad({ config: { ...cfg("b", "us-east-1"), storageClass: "GLACIER" } }, "an unsupported storage class is rejected (400)");
    await bad({ config: { ...cfg("b", "auto"), assumeRole: { roleArn: "arn:aws:iam::123456789012:role/r" } } }, "AssumeRole with a non-AWS region is rejected (400)");

    // A MICROSOFT ENTRA SERVICE PRINCIPAL is refused on two grounds, both before the live probe, because
    // both faults are in the submitted config and a round trip could add nothing to either.
    {
      const GOOD_SP = { tenantId: "98d21390-5d4f-488d-8fef-cb5b4defe180", clientId: "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57" };
      // Ground one: a malformed principal. Refused rather than dropped, the same reasoning as the
      // assumeRole and addressing refusals above: a dropped principal stores a destination that answers
      // 200, reports itself verified, and then tries to spend the client secret as a storage account key.
      await bad({ config: { ...cfg("b", "us-east-1"), azureEntra: { tenantId: "common", clientId: GOOD_SP.clientId } } }, "an Entra principal naming the multi-tenant alias is rejected (400)");
      await bad({ config: { ...cfg("b", "us-east-1"), azureEntra: { tenantId: GOOD_SP.tenantId, clientId: "not-a-guid" } } }, "an Entra principal with a non-GUID application id is rejected (400)");
      const aliasE = (await j(await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b", "us-east-1"), azureEntra: { tenantId: "common", clientId: GOOD_SP.clientId } } }))).error as string;
      ok("4: the Entra alias refusal says a destination has to name ONE directory", /ONE directory/.test(aliasE), aliasE);

      // Ground two: a WELL-FORMED principal on an endpoint that is not Azure Blob. Nothing reads it there,
      // so storing it would leave a destination showing a service principal in the console and signing
      // with an S3 key pair on the wire. This is the mirror of AZURE_REFUSED_FIELDS refusing an AWS
      // assumeRole on an Azure endpoint, and the two together mean neither cloud's credential can be
      // stored against the other's store.
      await bad({ config: { ...cfg("b", "us-east-1"), azureEntra: GOOD_SP } }, "a well-formed Entra principal on a NON-Azure endpoint is rejected (400)");
      const wrongStoreE = (await j(await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b", "us-east-1"), azureEntra: GOOD_SP } }))).error as string;
      ok("4: that refusal names Azure Blob Storage as the only store a service principal authenticates against", /Azure Blob Storage/.test(wrongStoreE), wrongStoreE);

      // NO OVER-REFUSAL. The identical S3 destination WITHOUT a principal still stores, so the two
      // refusals above are pinned to the azureEntra field rather than to "a bad request".
      const control = await call(OWNER, "POST", "/admin/destination", { config: cfg("b-entra-control", "us-east-1") });
      ok("4: NO OVER-REFUSAL: the same S3 destination with no service principal still stores (200)", control.status === 200, String(control.status));
    }

    // An addressing style outside auto/path/vhost is REFUSED rather than dropped.
    // It used to be dropped: the destination stored, answered 200,
    // reported itself verified, and addressed every object the AUTO way while the operator had chosen path
    // or vhost. It was the last of the four submitted destination fields still doing that; assumeRole and
    // worm carry rejection twins and storageClass is refused just above.
    await bad({ config: { ...cfg("b", "us-east-1"), addressing: "virtual" } }, "an out-of-enum addressing style is rejected (400)");
    {
      const r = await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b", "us-east-1"), addressing: "virtual" } });
      const e = (await j(r)).error as string;
      ok("4: the addressing refusal names the field and the three legal values", /addressing style must be/.test(e) && /"auto", "path" or "vhost"/.test(e));
      // PINNING CONTROL. The identical body with a LEGAL addressing and a bad storage class must answer
      // about the STORAGE CLASS, so the refusal above is pinned to addressing rather than to "a bad request".
      const other = await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b", "us-east-1"), addressing: "path", storageClass: "GLACIER" } });
      const otherE = (await j(other)).error as string;
      ok("4: PINNING CONTROL: a legal addressing with a bad storage class answers about the storage class, not addressing", other.status === 400 && /storage class/.test(otherE) && otherE !== e);
      // NO OVER-REFUSAL. Every legal value is still accepted and STORED AS CHOSEN, and an absent or blank
      // value still means the auto default rather than a refusal.
      for (const legal of ["auto", "path", "vhost"] as const) {
        const okR = await call(OWNER, "POST", "/admin/destination", { config: cfg("b-addr", "us-east-1", { addressing: legal }) });
        ok(`4: NO OVER-REFUSAL: addressing "${legal}" is accepted and stored as "${legal}"`, okR.status === 200 && (await j(okR)).addressing === legal);
      }
      const blank = await call(OWNER, "POST", "/admin/destination", { config: cfg("b-addr", "us-east-1", { addressing: "" }) });
      ok("4: NO OVER-REFUSAL: a blank addressing is accepted (the auto default), not refused", blank.status === 200);
      const absent = await call(OWNER, "POST", "/admin/destination", { config: cfg("b-addr", "us-east-1") });
      ok("4: NO OVER-REFUSAL: an absent addressing is accepted (the auto default), not refused", absent.status === 200);
    }

    probeMode = "deny";
    const denyR = await call(OWNER, "POST", "/admin/destination", { config: cfg("b", "us-east-1") });
    ok("4h: a destination that fails the live write probe is refused (400)", denyR.status === 400 && /verification failed/i.test((await j(denyR)).error as string));
    probeMode = "ok";

    // ---- Provider-aware refusals, driven through the REAL POST /destination ------------------------
    //
    // These four arms exist because the constants alone prove nothing: a refusal set that is never
    // consulted is the same defect as no refusal set. Each asserts the STATUS and the SENTENCE, because
    // the sentence is the whole change (every one of these was already refused, just wrongly explained).

    // An Azure Blob endpoint is now a SUPPORTED destination, so the arm that used to prove it was refused
    // by name proves the opposite: it is accepted and stored. The pair below is the same shape as the GCS
    // pair, because the two providers share the refusal MECHANISM and differ only in the field set.
    // accessKeyId carries the storage ACCOUNT for an Azure destination, and it must be the account in the
    // endpoint host: a Shared Key signature is scoped to one account. Written out here rather than reusing
    // cfg()'s "AKID" because the mismatch guard refuses that, correctly, and it is proven below.
    const azureCfg = { ...cfg("b-azure", "auto"), endpoint: "https://acct.blob.core.windows.net", accessKeyId: "acct", secretAccessKey: "ZmFrZS1henVyZS1hY2NvdW50LWtleS12YWx1ZQ==" };
    const azureOk = await call(OWNER, "POST", "/admin/destination", { config: azureCfg });
    ok("4p: an Azure Blob destination is accepted and stored", azureOk.status === 200 && (await j(azureOk)).bucket === "b-azure");

    // The mismatch guard, proven rather than assumed. Without it the request is signed for one account and
    // sent to another, and Azure answers 403 with an error naming neither.
    const azureMismatch = await call(OWNER, "POST", "/admin/destination", { config: { ...azureCfg, accessKeyId: "someotheraccount" } });
    const mismatchBody = (await j(azureMismatch)).error as string;
    ok("4p2: an account that is not the one in the endpoint host is refused", azureMismatch.status === 400 && /is not the account in the endpoint host/.test(mismatchBody), mismatchBody);
    // The message has to SURVIVE the surface that carries it. classifyProbeError clips a probe reason to
    // 200 characters and appends its own generic tail, and the first draft of this refusal was 234, so an
    // operator saw it end mid-word and was then told to check a credential that was never wrong. Asserting
    // the closing words is what makes that a test rather than a comment.
    // What decides whether the operator sees a whole sentence is what sits IMMEDIATELY BEFORE the generic
    // tail this path appends, so the assertion is anchored there.
    ok("4p3: ...and the refusal reaches the operator WHOLE, not clipped mid-word by the 200-char cap", /so these must match\.\. Check the bucket name/.test(mismatchBody), mismatchBody);

    // AN AZURE DESTINATION'S IMMUTABILITY POLICY IS DECIDED BY THE LIVE PROBE, NOT BY A HARDCODED RULE, and
    // this pair is the assertion that the reversal is real rather than the same refusal wearing a
    // different sentence. Azure's unlocked/locked policy plus legal hold maps onto one mode plus one window, so the two
    // containers below must get OPPOSITE answers.
    const azureWormCfg = { ...azureCfg, bucket: "b-azure-worm", worm: { mode: "compliance", retentionDays: 30 } };

    // A container WITHOUT version-level immutability. A lock-bearing write to it would be refused by Azure,
    // so the save is refused here, at the one moment the operator can still act on it.
    azureVlwMode = "disabled";
    const azureWorm = await call(OWNER, "POST", "/admin/destination", { config: azureWormCfg });
    const azureWormBody = (await j(azureWorm)).error as string;
    ok("4q: an Azure container that does NOT have version-level immutability refuses the policy (400)", azureWorm.status === 400, `${azureWorm.status} ${azureWormBody}`);
    ok("4q2: ...and the refusal is the store's own not-enforced verdict, not a rule about Azure as a provider", /cannot enforce an immutability policy/.test(azureWormBody) && !/Azure does have immutability/.test(azureWormBody), azureWormBody);
    // THE REMEDY IS AZURE'S OWN. Amazon's sentence, "re-create the bucket with Object-Lock enabled", does not apply here: there is no
    // Object-Lock setting on an Azure container to enable:
    // the mechanism is version-level immutability, which is also the one setting that would actually change
    // this verdict. The negative arm is the half that moves: an operator sent looking for an Object-Lock
    // checkbox in the Azure portal never finds one, so the refusal reads as a downpipes defect.
    ok("4q2b: ...and the remedy names AZURE's mechanism (version-level immutability), not Amazon's Object-Lock", /VERSION-LEVEL IMMUTABILITY/.test(azureWormBody) && !/Object-Lock ENABLED/.test(azureWormBody), azureWormBody);
    // The store noun follows the store: Azure has containers, and an operator told to re-create a "bucket"
    // is being described a thing their own portal does not have.
    ok("4q2c: ...and it calls the thing a container, which is what Azure calls it", /^this container cannot enforce/.test(azureWormBody), azureWormBody);

    // THE CONTROL, and it is the half that matters: the same policy on a container that IS enabled must be
    // ACCEPTED. Without this arm, "refused" above would pass just as happily under the old blanket refusal.
    azureVlwMode = "enabled";
    const azureWormOk = await call(OWNER, "POST", "/admin/destination", { config: azureWormCfg });
    ok("4q3: ...while a container WITH version-level immutability enabled accepts the same policy", azureWormOk.status === 200, `${azureWormOk.status} ${JSON.stringify(await j(azureWormOk))}`);
    azureVlwMode = "disabled";

    // A GCS endpoint carrying an Amazon-only storage class. GCS answers 400 InvalidStorageClass on the
    // wire, so this was already refused as a failed probe; the operator now learns which field and why.
    const gcsSc = await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b", "us-east-1", { storageClass: "STANDARD_IA" }), endpoint: "https://storage.googleapis.com" } });
    const gcsScBody = (await j(gcsSc)).error as string;
    ok("4r: a GCS endpoint with an Amazon storage class is refused (400)", gcsSc.status === 400);
    ok("4s: ...and the refusal names the GCS remedy, not a failed probe", /Google Cloud Storage/.test(gcsScBody) && !/verification failed/i.test(gcsScBody));

    // A GCS endpoint carrying an immutability policy. GCS answers 404 on the Object-Lock probe, so
    // wormCannotBeEnforced already refused this; the OLD message told the operator to create a bucket
    // with Object Lock enabled, which is impossible on Google Cloud.
    // A GCS endpoint with an immutability policy is decided by the LIVE PROBE, not by a hardcoded rule.
    // The stub's GCS arm answers the Object-Lock probe 404, which is what a bucket created WITHOUT
    // per-object retention really answers, so wormCannotBeEnforced refuses the save. A bucket created WITH retention answers 200/Enabled and is accepted.
    const gcsWorm = await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b", "us-east-1", { worm: { mode: "compliance", retentionDays: 30 } }), endpoint: "https://storage.googleapis.com" } });
    const gcsWormBody = (await j(gcsWorm)).error as string;
    ok("4t: a GCS bucket that cannot enforce Object Lock is refused an immutability policy (400)", gcsWorm.status === 400);
    ok("4u: ...by the live probe's own verdict, not by a rule that names the provider", /cannot enforce an immutability policy/.test(gcsWormBody) && !/downpipes does not translate/.test(gcsWormBody));
    // THE REMEDY IS GOOGLE CLOUD'S OWN. Google Cloud DOES have the capability, under its own name and only
    // at bucket-create time, so the remedy names PER-OBJECT RETENTION rather than sending the operator to
    // hunt for an "Object Lock" control that Google Cloud's console does not have.
    ok("4u2: ...and the remedy names Google Cloud's own setting, per-object retention", /per-object retention/.test(gcsWormBody), gcsWormBody);

    // The control that stops all of the above being a blanket GCS refusal: a clean GCS destination must
    // still get through to the probe and store, because GCS is a SUPPORTED destination and this whole
    // change would be worthless if naming it also blocked it.
    const gcsOkR = await call(OWNER, "POST", "/admin/destination", { config: { ...cfg("b-gcs", "auto"), endpoint: "https://storage.googleapis.com" } });
    const gcsOkBody = await j(gcsOkR);
    ok("4v: a GCS destination with no Amazon-only field is accepted and stored", gcsOkR.status === 200 && gcsOkBody.bucket === "b-gcs");

    const noCfg = await call(OWNER, "POST", "/admin/destinations", {});
    ok("4i: POST /destinations with no config body is a clean 400 (nullish config)", noCfg.status === 400);

    // Owner-gate denials: a viewer is refused at each owner-exclusive route (the DO never runs).
    ok("4k: viewer POST /destination -> 403", (await call(VIEWER, "POST", "/admin/destination", { config: cfg("b", "us-east-1") })).status === 403);
    ok("4l: viewer POST /destination/verify -> 403", (await call(VIEWER, "POST", "/admin/destination/verify")).status === 403);
    ok("4m: viewer POST /destinations -> 403", (await call(VIEWER, "POST", "/admin/destinations", { config: cfg("b", "us-east-1") })).status === 403);
    ok("4n: viewer POST /destinations/remove -> 403", (await call(VIEWER, "POST", "/admin/destinations/remove", { id: "x" })).status === 403);
    ok("4o: viewer POST /destinations/default -> 403", (await call(VIEWER, "POST", "/admin/destinations/default", { id: "x" })).status === 403);
  }

  // ===== Phase 5: success POSTs that verify-then-store (probe ok). =====
  {
    // 5e: a plain default, NO WORM (covers the worm-absent spread on POST /destination); 5a overwrites it.
    const plainR = await call(OWNER, "POST", "/admin/destination", { config: cfg("b0", "us-east-1") });
    const plain = await j(plainR);
    ok("5e: POST /destination stores a default with no WORM policy (worm omitted)", plainR.status === 200 && plain.present === true && plain.bucket === "b0" && plain.worm === undefined);

    // 5a/5f DRIVE A LOCK-ENABLED BUCKET, and they used to drive the default "disabled" one. THAT WAS THE
    // DEFECT, ASSERTED (WORM-ON-A-NON-LOCKED-BUCKET-STORES-AS-VERIFIED): both asked for an
    // immutability policy on a bucket the probe had just read as NOT Object-Lock enabled, both asserted a
    // 200, and every write to the destination they stored would have been refused by the store. The
    // ACCEPTED case is a WORM policy on a bucket that can enforce it, which is what these now drive; the
    // refused case is 5h below.
    lockMode = "enabled";
    const setR = await call(OWNER, "POST", "/admin/destination", { config: cfg("b1", "us-east-1", { addressing: "path", storageClass: "STANDARD_IA", worm: { mode: "governance", retentionDays: 30 } }) });
    const set = await j(setR);
    ok("5a: POST /destination stores the verified default (present, bucket, region)", setR.status === 200 && set.present === true && set.bucket === "b1" && set.region === "us-east-1");
    ok("5a: the stored default carries the validated WORM + storage-class + addressing", (set.worm as { mode?: string })?.mode === "governance" && set.storageClass === "STANDARD_IA" && set.addressing === "path");

    // 5f: an added destination WITH a WORM policy (covers the worm-present spread on POST /destinations).
    const wormR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b4-worm", "us-east-1", { worm: { mode: "compliance", retentionDays: 7 } }), label: "Locked" });
    const worm = await j(wormR);
    ok("5f: POST /destinations stores an added destination carrying a WORM policy", wormR.status === 200 && (worm.destinations as Array<{ bucket?: string; worm?: { mode?: string } }>).some((d) => d.bucket === "b4-worm" && d.worm?.mode === "compliance"));
    lockMode = "disabled";

    // ===== 5g: A SUBMITTED-BUT-MALFORMED WORM POLICY IS REFUSED, NOT SILENTLY DROPPED. =====
    //
    // (, and it REPLACES the contract this suite used to pin.)
    // A valid mode with an invalid retentionDays of 0 used to store the destination 200 with the policy
    // dropped, on the reasoning that dropping beats storing a partial policy. That reasoning is right for a
    // value already IN STORAGE and wrong at the submit boundary: the operator asked for compliance-mode
    // immutability, was told "verified and saved", and had a bucket with no lock on it. A compliance control
    // that is silently absent is the worst shape a compliance control can take, and only an admin counter
    // recorded it -- nothing the operator would ever see. It is now a 400 that names both halves of the rule.
    //
    // The counter still fires, because "somebody tried to set an immutability policy and could not" is a
    // support question with a real answer. Read across the POST (delta) so a prior/other bump cannot mask it.
    // Uses the /destinations collection add so it does not overwrite the single console default 6a/7a assert.
    // bucketsNow0 reads the stored destination buckets, so a REFUSAL can be checked against what is in the
    // store and not only against the status line: a 400 that stored the row anyway is the failure that matters.
    const bucketsNow0 = async (): Promise<string[]> =>
      (((await j(await call(OWNER, "GET", "/admin/destinations"))).destinations as Array<{ bucket?: string }> | undefined) ?? []).map((d) => d.bucket ?? "");
    const wormDropReader = async (): Promise<number> =>
      (await fetchAdminCounters(s.env.SCHEDULER.get(s.env.SCHEDULER.idFromName("scheduler"))))["dest-config-worm-policy-submitted-dropped"]?.count ?? 0;
    const wormDropBefore = await wormDropReader();
    const droppedR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b5-wormbad", "us-east-1", { worm: { mode: "governance", retentionDays: 0 } }), label: "Bad WORM" });
    const droppedBody = await j(droppedR);
    ok("5g: a malformed WORM policy is REFUSED 400, never stored without immutability", droppedR.status === 400);
    ok("5g: the refusal names BOTH halves of the rule (a mode AND a positive whole number of days)", typeof droppedBody.error === "string" && (droppedBody.error as string).includes("governance or compliance") && (droppedBody.error as string).includes("greater than zero"));
    ok("5g: NOTHING was stored for the refused destination", !(await bucketsNow0()).includes("b5-wormbad"));
    ok("5g: the dest-config-worm-policy-submitted-dropped breadcrumb still fires on the refusal", (await wormDropReader()) === wormDropBefore + 1);
    // POSITIVE CONTROL, and it must DISCRIMINATE: the identical body with a VALID retentionDays stores 200 on
    // a lock-enabled bucket. Without this the refusal above would also pass if the route had simply broken.
    lockMode = "enabled";
    const wormOkR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b5-wormgood", "us-east-1", { worm: { mode: "governance", retentionDays: 1 } }), label: "Good WORM" });
    ok("5g CONTROL: the same body with retentionDays 1 stores 200 with the policy on the record", wormOkR.status === 200 && ((await j(wormOkR)).destinations as Array<{ bucket?: string; worm?: { retentionDays?: number } }>).some((d) => d.bucket === "b5-wormgood" && d.worm?.retentionDays === 1));
    lockMode = "disabled";

    // ===== 5g-sts: A SUBMITTED-BUT-UNUSABLE AssumeRole POLICY IS REFUSED, NOT SILENTLY DROPPED. =====
    //
    // Same shape as the WORM one and found in the same sweep. A durationSeconds outside AWS's own 900..43200
    // window was not copied onto the policy, so the destination stored with no duration and every AssumeRole
    // ran at the 3600-second default; a malformed roleArn dropped the WHOLE policy, so the destination stored
    // using the principal keys DIRECTLY instead of the role the operator named. Both answered 200.
    const stsBadDurR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b5-stsdur", "us-east-1", { assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Backup", durationSeconds: 60 } }), label: "Bad STS duration" });
    ok("5g-sts: a durationSeconds below the AWS minimum is REFUSED 400, not dropped", stsBadDurR.status === 400);
    const stsBadDurBody = await j(stsBadDurR);
    ok("5g-sts: the refusal names the window (900 to 43200), so the operator can fix it without reading AWS docs", typeof stsBadDurBody.error === "string" && (stsBadDurBody.error as string).includes("900") && (stsBadDurBody.error as string).includes("43200"));
    ok("5g-sts: nothing was stored for it", !(await bucketsNow0()).includes("b5-stsdur"));
    const stsBadArnR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b5-stsarn", "us-east-1", { assumeRole: { roleArn: "myrole" } }), label: "Bad STS arn" });
    ok("5g-sts: a malformed roleArn is REFUSED 400, not dropped into a keys-direct destination", stsBadArnR.status === 400);
    ok("5g-sts: nothing was stored for that one either", !(await bucketsNow0()).includes("b5-stsarn"));
    // POSITIVE CONTROL that DISCRIMINATES: a duration INSIDE the window stores, and the stored record carries it.
    const stsOkR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b5-stsok", "us-east-1", { assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Backup", durationSeconds: 900 } }), label: "Good STS" });
    // Read AT REST, not off the response: the /destinations projection reports authMode and never the policy
    // itself, so a response-shaped assertion here would be checking the projection and not the stored value.
    type StoredDest = { bucket?: string; assumeRole?: { durationSeconds?: number; roleArn?: string } };
    const storedDests = (await s.storage.get<{ list?: StoredDest[] }>("destinations")) ?? {};
    const stsOkStored = (storedDests.list ?? []).find((d) => d.bucket === "b5-stsok");
    ok("5g-sts CONTROL: durationSeconds 900 stores 200 and the duration is ON the stored policy at rest", stsOkR.status === 200 && stsOkStored?.assumeRole?.durationSeconds === 900 && stsOkStored.assumeRole.roleArn === "arn:aws:iam::123456789012:role/Backup");

    // ===== 5h: A WORM POLICY ON A BUCKET THAT CANNOT ENFORCE IT IS REFUSED AT ADD TIME. =====
    //
    // (WORM-ON-A-NON-LOCKED-BUCKET-STORES-AS-VERIFIED.) `worm` is the ONE stored field the
    // add-time probe never runs under: the probe writes no lock headers, so it passes, and every write
    // afterwards carries them and the store refuses all of them. The product stored the destination, marked
    // it verified and showed it working, and nothing could ever be archived there.
    //
    // The verdict the refusal needs was ALREADY IN HAND at that moment -- probeDestination reads the
    // bucket's Object-Lock configuration in the same function, before the same store call -- so this costs
    // no extra request. Probing WITH the policy armed was refused as the fix: a WORM-armed scratch object is
    // undeletable for the retention window just typed, so it would leave a locked object in the customer's
    // bucket that neither party can remove.
    const bucketsNow = async (): Promise<string[]> =>
      ((await j(await call(OWNER, "GET", "/admin/destinations"))).destinations as Array<{ bucket?: string }> | undefined ?? []).map((d) => d.bucket ?? "");
    const beforeRefusal = await bucketsNow();

    // CHECKED AND FAILED, arm 1: the store answered, and the bucket has no Object-Lock configuration.
    const refusedR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b6-unlocked", "us-east-1", { worm: { mode: "governance", retentionDays: 30 } }), label: "Unlocked+WORM" });
    const refused = await j(refusedR);
    ok("5h: a WORM policy on a NOT-ENFORCED bucket is REFUSED (400), not stored as verified", refusedR.status === 400);
    // THE REMEDY MUST BE THE STORE'S OWN, and this fixture's endpoint is an R2 one (S3_HOST above is
    // acct.r2.cloudflarestorage.com), which is the one provider with NO remedy. R2's S3 endpoint answers a PUT carrying x-amz-object-lock-mode with 501 NotImplemented, so an R2 bucket
    // can never carry Object Lock and the customer must be told that directly rather than sent to Amazon's remedy.
    ok("5h: an R2 customer is told the truth, that no R2 bucket enforces this by any route", typeof refused.error === "string" && /501 NotImplemented/.test(refused.error as string) && !/Object-Lock ENABLED/.test(refused.error as string), refused.error as string);
    ok("5h: ...and it names the only thing that changes the answer, a store that does enforce it", typeof refused.error === "string" && /Point this destination at a store that does enforce it/.test(refused.error as string), refused.error as string);
    ok("5h: NOTHING was stored for the refused destination", !(await bucketsNow()).includes("b6-unlocked"));

    // CHECKED AND FAILED, arm 2: the store answered 501 -- it has no Object-Lock API AT ALL, so no bucket it
    // holds can enforce anything. This is the arm R2 reaches. It is a store FACT, not a gap in our reading.
    lockMode = "not-implemented";
    const noApiR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b7-nolockapi", "us-east-1", { worm: { mode: "compliance", retentionDays: 7 } }), label: "No lock API" });
    ok("5h: a WORM policy on a store with NO Object-Lock API is REFUSED (400)", noApiR.status === 400);
    ok("5h: nothing was stored for that one either", !(await bucketsNow()).includes("b7-nolockapi"));

    // COULD NOT CHECK: the probe was DENIED the lock-configuration read (a least-privilege credential that
    // may write but not read it). This is the whole point of the split. Refusing here would turn a
    // diagnostic gap into a customer-facing rejection of a destination that may be perfectly configured.
    lockMode = "denied";
    const unknownR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b8-cannotconfirm", "us-east-1", { worm: { mode: "governance", retentionDays: 14 } }), label: "Cannot confirm" });
    ok("5h: a WORM policy is ACCEPTED when the lock verdict is could-not-check, never refused on unknown", unknownR.status === 200 && (await bucketsNow()).includes("b8-cannotconfirm"));
    lockMode = "disabled";

    // ATTRIBUTION CONTROL: the SAME not-enforced bucket with NO policy is still accepted. The refusal is the
    // POLICY, not the bucket and not the credential (5e asserts the same on the single-destination route).
    const noPolicyR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b9-unlocked-nopolicy", "us-east-1"), label: "Unlocked, no policy" });
    ok("5h CONTROL: the SAME not-enforced bucket with NO immutability policy is still accepted", noPolicyR.status === 200 && (await bucketsNow()).includes("b9-unlocked-nopolicy"));
    const afterRefusal = await bucketsNow();
    ok("5h: the refusals disturbed nothing that was already stored", beforeRefusal.every((b) => afterRefusal.includes(b)));

    const addR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b2", "auto"), label: "Second" });
    const add = await j(addR);
    const dests = (add.destinations as Array<{ id: string; bucket?: string; label?: string }>) ?? [];
    const id2 = dests.find((d) => d.id !== "default")?.id ?? "";
    ok("5b: POST /destinations adds a second destination (region defaults to auto)", addR.status === 200 && id2 !== "" && dests.some((d) => d.bucket === "b2"));

    const editR = await call(OWNER, "POST", "/admin/destinations", { id: id2, config: cfg("b2-edited", "auto") });
    const edit = await j(editR);
    ok("5c: POST /destinations with an id edits in place (label defaults to bucket)", editR.status === 200 && (edit.destinations as Array<{ id: string; bucket?: string }>).some((d) => d.id === id2 && d.bucket === "b2-edited"));

    const stsR = await call(OWNER, "POST", "/admin/destinations", { config: cfg("b3-sts", "us-east-1", { accessKeyId: "PRINCIPALAK", secretAccessKey: "PRINCIPALSK", assumeRole: { roleArn: "arn:aws:iam::123456789012:role/downpipes-backup" } }) });
    ok("5d: POST /destinations with an AssumeRole policy probes via STS then stores", stsR.status === 200);
    const listed = await j(await call(OWNER, "GET", "/admin/destinations"));
    ok("5d: GET /destinations shows the STS destination (authMode 'sts')", (listed.destinations as Array<{ authMode?: string }>).some((d) => d.authMode === "sts"));

    // capture id2 for the later default/remove group
    (globalThis as Record<string, unknown>).__id2 = id2;
  }

  // ===== Phase 6/7/8: reads + verify WITH the console destination set. =====
  {
    const d6 = await j(await call(OWNER, "GET", "/admin/destination"));
    ok("6a: GET /destination now reports the console-set default -> source 'console'", d6.present === true && d6.source === "console" && d6.bucket === "b1");

    const b7 = await j(await call(OWNER, "GET", "/admin/setup-state"));
    const dest7 = b7.destination as { configured?: boolean; verified?: boolean; source?: unknown; bucket?: unknown; endpointHost?: unknown };
    ok("7a: setup-state with a console dest -> configured+verified, source 'console', bucket+host echoed", dest7.configured === true && dest7.verified === true && dest7.source === "console" && dest7.bucket === "b1" && typeof dest7.endpointHost === "string");

    const v8 = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    ok("8a: verify the console-set default -> ok:true, source 'console'", v8.ok === true && v8.source === "console");
  }

  // ===== THE DELETE-DENIED DESTINATION, driven through the REAL POST /destination/verify. =====
  //
  // A destination that accepts every write and refuses every delete PASSES the probe, correctly, because
  // backups genuinely work. But its retention silently does not: nothing can ever expire an archive, so storage
  // grows for ever. This drives the PRODUCTION route and reads the rows out of the REAL pack projector.
  {
    const surfaceRows = async (): Promise<Array<Record<string, unknown>>> => {
      const diag = await fetchSchedDiag(s.env.SCHEDULER.get(s.env.SCHEDULER.idFromName("scheduler")));
      const t = (diag.testOutcomes ?? {}) as Record<string, Array<Record<string, unknown>>>;
      return t["dest-verify"] ?? [];
    };
    const before = (await surfaceRows()).length;

    // STATE A: healthy -- writes and prunes.
    deleteMode = "ok";
    const healthy = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    // STATE B: the DELETE is refused. objectLock is "not-enforced" (the stub's LOCK_XML says Disabled), so
    // NOBODY chose this: it is not a WORM bucket, the credential simply cannot delete.
    deleteMode = "deny";
    const denied = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    deleteMode = "ok";

    ok("a DELETE-DENIED destination still verifies ok:true (backups work; this is not a failed test)", denied.ok === true && denied.deleteProbe === "denied");
    ok("...and a healthy one reports deleteProbe 'ok'", healthy.ok === true && healthy.deleteProbe === "ok");

    const rows = (await surfaceRows()).slice(before);
    const healthyRow = rows[0];
    const deniedRow = rows[1];
    ok("both verifies reached the pack's dest-verify ring through the REAL route", rows.length === 2);
    // THE DISCRIMINATION BAR: hold ONLY the pack, and tell the two apart.
    ok("the healthy row and the delete-denied row are NOT byte-identical (they used to be)", JSON.stringify(healthyRow) !== JSON.stringify(deniedRow));
    ok("the healthy row carries ok:true + deleteProbe 'ok'", healthyRow?.ok === true && healthyRow?.deleteProbe === "ok");
    ok("the delete-denied row carries ok:true + deleteProbe 'denied' -- a working destination whose retention CANNOT be managed", deniedRow?.ok === true && deniedRow?.deleteProbe === "denied");
    // ...and it does not cry wolf on a deliberately immutable bucket: objectLock separates the customer's own
    // WORM hardening from a credential that simply cannot delete.
    ok("the row carries the OBJECT-LOCK verdict, so a deliberate WORM bucket is not confused with this", deniedRow?.objectLock === "not-enforced");
    // NO-CUSTODY: closed enums only. No bucket, endpoint, credential or provider text.
    const rowText = JSON.stringify(rows);
    ok("NO-CUSTODY -- no bucket, endpoint, key or provider prose in the ring", !rowText.includes("b1") && !rowText.includes(S3_HOST) && !rowText.includes("AccessDenied") && !rowText.includes("AK"));

    // ===== THE TWO INTENTS THAT WERE STILL ONE ROW. =====
    //
    // A refused DELETE with an UNKNOWN object-lock verdict is two states with opposite remedies. The commonest
    // real shape of the silent one: a least-privilege key allowed s3:PutObject and s3:GetObject and not
    // s3:DeleteObject is, by the same allow-list, not allowed s3:GetBucketObjectLockConfiguration either -- so
    // the lock probe 403s and objectLock reads "unknown". The other: a store with NO Object-Lock API at all
    // (501), where the refused delete is the customer's own deny-delete policy, and there is nothing to fix.
    const beforeR4 = (await surfaceRows()).length;

    deleteMode = "deny";
    lockMode = "denied"; // the lock-config read is ALSO denied -- the key's allow-list is short two actions
    const iamShort = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    lockMode = "not-implemented"; // the store has no Object-Lock API; the delete refusal is a policy
    const noLockApi = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    deleteMode = "ok";
    lockMode = "enabled"; // a locked bucket with the lock merely switched ON and no default retention rule
    const lockedNoRule = await j(await call(OWNER, "POST", "/admin/destination/verify"));
    lockMode = "disabled";

    ok("both R4 states still verify ok:true (backups work; neither is a failed test)", iamShort.ok === true && noLockApi.ok === true);
    const r4 = (await surfaceRows()).slice(beforeR4);
    const iamRow = r4[0];
    const noApiRow = r4[1];
    const lockedRow = r4[2];
    ok("all three R4 verifies reached the pack ring through the REAL route", r4.length === 3);
    // THE BAR: hold ONLY the pack and tell the two apart. They were BYTE-IDENTICAL.
    ok("the short IAM allow-list and the lock-less store are NO LONGER the same row", JSON.stringify(iamRow) !== JSON.stringify(noApiRow));
    ok("the short IAM allow-list names its remedy -- the lock-config read was DENIED", iamRow?.deleteProbe === "denied" && iamRow?.objectLock === "unknown" && iamRow?.objectLockUnknownReason === "denied");
    ok("the lock-less store names ITS fact -- the store has no Object-Lock API", noApiRow?.deleteProbe === "denied" && noApiRow?.objectLock === "unknown" && noApiRow?.objectLockUnknownReason === "not-implemented");
    // "enforced" no longer stands in for "locked": Object-Lock ENABLED with no default rule retains nothing.
    ok("a locked bucket with the lock merely switched ON reports defaultRetention:false", lockedRow?.objectLock === "enforced" && lockedRow?.defaultRetention === false);
    // NOISE: the healthy row above gained nothing. The two new fields ride only where they mean something.
    ok("the healthy row carries NEITHER new field (they ride only where they describe something)", healthyRow?.objectLockUnknownReason === undefined && healthyRow?.defaultRetention === undefined);
    const r4Text = JSON.stringify(r4);
    ok("NO-CUSTODY -- the new fields are closed members and a boolean, no bucket/endpoint/body", !r4Text.includes("b1") && !r4Text.includes(S3_HOST) && !r4Text.includes("AccessDenied") && !r4Text.includes("NotImplemented"));

    // ===== "DENIED" IS A PERMISSION FACT, NOT INFERRED FROM ANY THROW. =====
    //
    // del() throws on any unusable status as well as on a transport fault, so a 503 SlowDown, a 500, a 429
    // throttle and a dropped socket must NOT all land as "denied": that would be byte-identical to a real
    // least-privilege denial, sending support to an IAM allow-list that is already correct.
    lockMode = "disabled";
    const drive = async (mode: typeof deleteMode): Promise<Record<string, unknown>> => {
      deleteMode = mode;
      const r = await j(await call(OWNER, "POST", "/admin/destination/verify"));
      deleteMode = "ok";
      return r;
    };
    const iamDenied = await drive("deny");
    const slowDown = await drive("slowdown");
    const serverErr = await drive("server-error");
    const throttled = await drive("throttled");
    const socketLost = await drive("reset");
    const conflict = await drive("conflict");

    ok("a real 403 is still the DENIAL, and it names the status class", iamDenied.deleteProbe === "denied" && iamDenied.deleteStatusClass === "403");
    ok("a 503 SlowDown is TRANSIENT -- the store was busy, the credential is fine, nothing is broken for ever", slowDown.deleteProbe === "transient" && slowDown.deleteStatusClass === "5xx");
    ok("a 500 store error is TRANSIENT too", serverErr.deleteProbe === "transient" && serverErr.deleteStatusClass === "5xx");
    ok("a 429 throttle is TRANSIENT, and separable from the store erroring", throttled.deleteProbe === "transient" && throttled.deleteStatusClass === "429");
    ok("a dropped socket is TRANSIENT with NO status class -- the absence IS the transport fact", socketLost.deleteProbe === "transient" && socketLost.deleteStatusClass === undefined);
    ok("a 409 is the honest residual, never guessed at", conflict.deleteProbe === "other" && conflict.deleteStatusClass === "4xx");
    ok("every one of these still verifies ok:true (the destination writes; the probe never failed)", [iamDenied, slowDown, serverErr, throttled, socketLost, conflict].every((r) => r.ok === true));

    // The ring is bounded at TEST_OUTCOMES_PER_SURFACE, so the six newest rows ARE these six, in order.
    const r5 = (await surfaceRows()).slice(-6);
    ok("all six verifies reached the pack ring through the REAL route", r5.length === 6 && r5.every((r) => r.ok === true));
    // THE BAR: hold ONLY the pack, and tell the denial apart from the blip. They were BYTE-IDENTICAL.
    ok("DISCRIMINATION -- the least-privilege denial and the busy store are no longer the same row", JSON.stringify(r5[0]) !== JSON.stringify(r5[1]));
    ok("...and the throttle, the store fault and the dropped socket are three rows, not one", new Set(r5.slice(1, 5).map((r) => JSON.stringify({ p: r.deleteProbe, s: r.deleteStatusClass }))).size === 3);
    ok("the pack's DENIED row now means what its vocabulary says: the credential cannot delete", r5[0]?.deleteProbe === "denied" && r5[0]?.deleteStatusClass === "403");
    ok("NOISE -- a healthy delete carries NO status class (there is nothing to explain)", healthyRow?.deleteProbe === "ok" && healthyRow?.deleteStatusClass === undefined);
    const r5Text = JSON.stringify(r5);
    ok("NO-CUSTODY -- closed members and status classes only, no bucket, endpoint or store body", !r5Text.includes("b1") && !r5Text.includes(S3_HOST) && !r5Text.includes("SlowDown") && !r5Text.includes("InternalError") && !r5Text.includes("network connection lost"));
  }

  // ===== Phase 9: default + remove (id present and absent). =====
  {
    const id2 = (globalThis as Record<string, unknown>).__id2 as string;
    const defR = await call(OWNER, "POST", "/admin/destinations/default", { id: id2 });
    ok("9a: POST /destinations/default with a known id makes it the default", defR.status === 200 && (await j(defR)).defaultId === id2);
    const defBad = await call(OWNER, "POST", "/admin/destinations/default", {});
    ok("9b: POST /destinations/default with no id is refused by the DO (not 200)", defBad.status !== 200);

    const rmR = await call(OWNER, "POST", "/admin/destinations/remove", { id: id2, force: true });
    ok("9c: POST /destinations/remove (force) removes the destination", rmR.status === 200 && !(((await j(rmR)).destinations as Array<{ id: string }>) ?? []).some((d) => d.id === id2));
    const rmBad = await call(OWNER, "POST", "/admin/destinations/remove", {});
    ok("9d: POST /destinations/remove with no id is refused by the DO (not 200)", rmBad.status !== 200);
  }

  // ===== Phase 10: POST /email/test (no identity vs identity, EMAIL_FROM set vs unset). =====
  {
    const tokR = await j(await callTok("POST", "/admin/email/test"));
    ok("10a: bare-token email test has no identity -> email-test-needs-identity", tokR.ok === false && tokR.reason === "email-test-needs-identity");
    const unconf = await j(await call(OWNER, "POST", "/admin/email/test"));
    ok("10b: email test with an identity but no EMAIL binding -> email-not-configured", unconf.ok === false && unconf.reason === "email-not-configured");
    const sent = await j(await call(OWNER, "POST", "/admin/email/test", undefined, { EMAIL: { send: async () => {} }, EMAIL_FROM: "ops@acme.example" }));
    ok("10c: email test with a bound EMAIL service + sender -> ok:true", sent.ok === true);

    // ===== THE EMAIL SERVICE'S OWN CODE MUST REACH THE PACK =====
    //
    // An un-onboarded sending domain, an unverified sender and a platform throttle are three failures with
    // three different remedies, so each must land in the pack as its own row rather than one generic failure.
    const emailRows = async (): Promise<Array<Record<string, unknown>>> => {
      const diag = await fetchSchedDiag(s.env.SCHEDULER.get(s.env.SCHEDULER.idFromName("scheduler")));
      const t = (diag.testOutcomes ?? {}) as Record<string, Array<Record<string, unknown>>>;
      return t["email"] ?? [];
    };
    const emailFails = async (code: string | undefined): Promise<Record<string, unknown>> => {
      const err = Object.assign(new Error("send failed for cfo@acme.example"), code !== undefined ? { code } : {});
      await call(OWNER, "POST", "/admin/email/test", undefined, {
        EMAIL: {
          send: async () => {
            throw err;
          },
        },
        EMAIL_FROM: "ops@acme.example",
      });
      // Wait for the outcome row this call produces, rather than reading once and hoping. The route
      // records the email outcome into the scheduler DO after the response returns, so a single read
      // straight after the POST can land before the write.
      const before = (await emailRows()).length;
      for (let i = 0; i < 200; i++) {
        const rows = await emailRows();
        if (rows.length > before) return rows.at(-1) ?? {};
        await new Promise<void>((r) => setTimeout(r, 5));
      }
      return (await emailRows()).at(-1) ?? {};
    };
    const notOnboarded = await emailFails("E_SENDER_DOMAIN_NOT_AVAILABLE");
    const notVerified = await emailFails("E_SENDER_NOT_VERIFIED");
    const throttled = await emailFails("E_RATE_LIMITED");
    const nonConforming = await emailFails("something the platform made up");
    ok("an un-onboarded sending domain now carries the platform's own code into the pack", notOnboarded.ok === false && notOnboarded.platformCode === "E_SENDER_DOMAIN_NOT_AVAILABLE");
    ok("an unverified sender is a DIFFERENT row (it used to be byte-identical)", notVerified.platformCode === "E_SENDER_NOT_VERIFIED" && notVerified.platformCode !== notOnboarded.platformCode);
    ok("a platform throttle is a third row", throttled.platformCode === "E_RATE_LIMITED");
    ok("a NON-CONFORMING code records the FACT without the text (E_OTHER, never the message)", nonConforming.platformCode === "E_OTHER");
    ok("no recipient, sender or platform message rides in any email row", !/acme\.example|send failed|made up/.test(JSON.stringify(await emailRows())));
    const okRow = (await emailRows()).find((r) => r.ok === true);
    ok("a DELIVERED test carries no platform code (a field must not ride on a row it cannot describe)", okRow !== undefined && !("platformCode" in okRow));
    const destRows = async (): Promise<Array<Record<string, unknown>>> => {
      const diag = await fetchSchedDiag(s.env.SCHEDULER.get(s.env.SCHEDULER.idFromName("scheduler")));
      const t = (diag.testOutcomes ?? {}) as Record<string, Array<Record<string, unknown>>>;
      return t["dest-verify"] ?? [];
    };
    ok("and no other surface can carry one (the recorder admits it on the email ring alone)", (await destRows()).every((r) => !("platformCode" in r)));
  }

  // ===== Phase 11: defensive fallbacks via injected DO failures. =====
  {
    s.failPaths.length = 0;
    s.failPaths.push("/dest-status");
    const d11a = await call(OWNER, "GET", "/admin/destination");
    ok("11a: GET /destination tolerates a failed /dest-status read (present:false, 200)", d11a.status === 200 && (await j(d11a)).present === false);
    s.failPaths.length = 0;

    s.failPaths.push("/downpipes", "/sources/discovery-status", "/policy/break-glass-disposal", "/dest-status", "/demo/first-run", "/demo/mark");
    const b11b = await call(OWNER, "GET", "/admin/setup-state", undefined, { DEMO_MODE: "true" });
    const body11b = await j(b11b);
    const dest11b = body11b.destination as { configured?: boolean; source?: unknown };
    ok("11b: setup-state stays 200 when every DO read rejects (presence-safe)", b11b.status === 200);
    ok("11b: the rejected reads leave their facts honestly absent", !("downpipeCount" in body11b) && !("ownerExists" in body11b) && dest11b.source === null);
    s.failPaths.length = 0;
  }

  // ===== Phase 12: verify-catch (an incomplete stored config makes fetchDestConfig throw). =====
  {
    await s.storage.put("destinations", { list: [{ id: "default", endpoint: GOOD_ENDPOINT, bucket: "partial", accessKeyId: "AK" }], defaultId: "default" });
    const vcat = await call(OWNER, "POST", "/admin/destination/verify");
    const b = await j(vcat);
    ok("12: verify reports an unreadable stored config as ok:false (caught, 200)", vcat.status === 200 && b.ok === false && /incomplete/i.test(b.reason as string));
  }

  // ===== Phase 13: trip the per-caller rate limit, then prove each mutating route returns 429. =====
  {
    let tripped = false;
    for (let i = 0; i < 300 && !tripped; i++) {
      const r = await call(OWNER, "POST", "/admin/destinations/default", {});
      if (r.status === 429) tripped = true;
    }
    ok("13: the per-caller rate limit trips after the window cap", tripped);
    if (tripped) {
      ok("13: POST /destination is rate-limited (429)", (await call(OWNER, "POST", "/admin/destination", { config: cfg("b", "us-east-1") })).status === 429);
      ok("13: POST /destination/verify is rate-limited (429)", (await call(OWNER, "POST", "/admin/destination/verify")).status === 429);
      ok("13: POST /destinations is rate-limited (429)", (await call(OWNER, "POST", "/admin/destinations", { config: cfg("b", "us-east-1") })).status === 429);
      ok("13: POST /destinations/remove is rate-limited (429)", (await call(OWNER, "POST", "/admin/destinations/remove", { id: "x" })).status === 429);
      ok("13: POST /destinations/default is rate-limited (429)", (await call(OWNER, "POST", "/admin/destinations/default", { id: "x" })).status === 429);
      ok("13: POST /email/test is rate-limited (429)", (await call(OWNER, "POST", "/admin/email/test")).status === 429);
    }
  }

  globalThis.fetch = realFetch;
  console.log(failures === 0 ? "\nVALIDATE-COV-ADMIN-ROUTER-DESTINATIONS VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
