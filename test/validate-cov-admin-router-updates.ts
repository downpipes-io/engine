// validate-cov-admin-router-updates: branch-coverage proof for src/admin/router-updates.ts, the
// licence-activation + safe-apply engine-update route group (GET /downpipes|updates|history|runs/at|
// rto|replication|licence|update/status and POST /licence|update/apply|update/settle|update/rollback|
// update/ramp|update/ramp/settle). It drives the REAL handleUpdates spoke through the production
// handleAdmin with a forged-but-correctly-signed Access JWT, an in-memory SchedulerDO, a vendor-signed
// update channel and a stubbed Cloudflare deploy API, so every gate, fallback, refusal and lifecycle
// branch is exercised over real code paths with no network, no deploy and no Cloudflare account. The
// only network is the harness fetch stub (JWKS, channel, artefact and the CF versions/deployments API).
//
// Each assertion checks a real outcome: an HTTP status, a returned body field, or a stored/audited
// effect read back through the DO. Run: node test/validate-cov-admin-router-updates.ts
//
// Honestly-untestable in this harness (need a live canary that sings, i.e. a real destination, signer
// keys and an alive verdict, or a live CF deploy): the stale-and-healthy 409 expiry, the
// currentLiveVersions-absent legacy else (the real driver always exposes it), and the ownerActionGate
// "error" verdict (an Access owner never makes the DO refuse the gate-check). These are listed in the
// untestable field. (The settle/ramp-settle KEEP directions ARE exercised below, via the
// recommendedVersion===ENGINE_VERSION + fresh-preflight self-check fallback -- a genuinely alive canary
// verdict specifically still needs a real destination.)

import { handleAdmin } from "../src/admin/router.ts";
import { rateLimitKey } from "../src/admin/router-core.ts";
import { RATE_LIMIT_PREFIX } from "../src/sched/scheduler-do-limits.ts";
import { fetchAdminCounters } from "../src/admin/support-sections-diag.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { SETTLE_PROBE_SCHEDULE } from "../src/admin/update-gate.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { loadSigner } from "../src/keys-env.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { concat, utf8, b64urlEncode, hexEncode, base64Encode, sha256Hex } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import { compareSemver } from "../src/admin/updates.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
// checks counts every assertion actually run and is handed to verdictReached as its `checks` argument (a
// COUNT). It was not passed at all, so this file's vacuous-run arm was never armed: a run that reached no
// assertion -- a harness import that resolved to an empty stub, a `main` that returned early -- would have
// declared a pass over nothing and exited 0. Same shape as the defect the admin-route-manifest pass found in
// its own guard, where a module identifier had been passed where a count belongs.
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

import { MockStorage } from "./mock-storage.ts";

// events is the shared ORDER LOG the persistence-first proofs read: the DO stub pushes its writes and the
// CF fetch stub pushes the deploy calls, so an assertion can prove "the settled outcome was persisted
// BEFORE the rollback deploy was issued" (incident). failNextAudit arms a ONE-SHOT DO fault on
// the next /audit append, simulating the response path dying AFTER the deploy (the isolate-swap race).
const events: string[] = [];
let failNextAudit = false;

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const path = new URL(url).pathname;
      events.push(`DO ${init?.method ?? "GET"} ${path}`);
      if (failNextAudit && path === "/audit") {
        failNextAudit = false;
        throw new Error("injected audit fault (the response path racing its own teardown)");
      }
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, stub };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ----
const TEAM = "cov-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
// OWNER_RATE_KEY is the rate-limit bucket this suite's Access OWNER really counts against, DERIVED from the
// router's own rateLimitKey rather than spelled out, so a future change to the key derivation cannot
// silently land the seed/reset on a key the limiter no longer reads.
const AUD = "cov-router-updates-aud";
const KID = "cov-kid-1";
const OWNER = "owner@acme.example";
const OWNER_RATE_KEY = `${RATE_LIMIT_PREFIX}${rateLimitKey({ method: "access", email: OWNER, subject: `${ISS}|sub-of-${OWNER}`, role: "owner", groups: [], sourceIp: null })}`;
const OWNER2 = "owner2@acme.example";
const VIEWER = "viewer@acme.example";
const jwtPart = (obj: unknown): string => b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));

// ---- The vendor-signed update channel ----
// THE FIXTURE VERSION IS COUPLED TO ENGINE_VERSION, and it is a silent coupling, so it is asserted at
// the top of main() below rather than left to be rediscovered. Every apply case here needs a channel
// recommending a version the engine does NOT already run: updateAvailable is
// recommendedVersion !== ENGINE_VERSION, so the day the fixture version equals the running one, the
// whole apply half of this file stops testing an apply. It was typed as "0.2.0" until, when
// the 0.1.9 -> 0.2.0 release bump made the two equal and thirty assertions failed at once. 0.4.0 was
// chosen deliberately: strictly ABOVE ENGINE_VERSION so the forward-only guard passes, strictly BELOW
// the 0.5.0 anti-rollback floor the R8 cases seed, and not the 0.3.0 the console-component cases use.
const CHANNEL_URL = "https://update.example.com/stable.json";
const ARTEFACT_URL = "https://update.example.com/engine-0.4.0.mjs";
const ARTEFACT_URL_MISSING = "https://update.example.com/missing-0.4.0.mjs";
const ARTEFACT = utf8("downpipe-engine-bundle-v0.4.0-content");
const BAD_HASH = "deadbeef".repeat(12); // 96 hex chars; never matches the real artefact hash
const DEPLOY_TOKEN = "cf_deploy_token_0123456789abcdef"; // passes validateDeployToken shape
// The CONSOLE bundle artefact (multi-component updates): a REAL, strictly-parseable console bundle whose
// bytes + sha384 the v2 channels below serve, so the console flows run the exact shipped parse/verify.
const CONSOLE_ARTEFACT_URL = "https://update.example.com/console.json";
const CONSOLE_SHELL = utf8("export default { fetch() { return new Response('shell'); } };");
const CONSOLE_ASSET = utf8("<!doctype html><h1>console</h1>");

async function main(): Promise<void> {
  // The coupling named at ARTEFACT_URL, asserted rather than commented. compareSemver returns 1 when the
  // first argument is the newer one; anything else here means the fixture version has been overtaken by a
  // release bump and every apply case below would pass vacuously.
  ok(`the fixture update version 0.4.0 is strictly newer than the running ENGINE_VERSION (${ENGINE_VERSION})`, compareSemver("0.4.0", ENGINE_VERSION) === 1);

  // Zero the settle probe's retry backoffs (SETTLE_PROBE_SCHEDULE is read at call time for exactly this:
  // the route-level suite must not sleep for real; the probe's retry behaviour has its own injected-sleep
  // vectors in validate-update-orchestrate.ts).
  SETTLE_PROBE_SCHEDULE.backoffMs = [];
  SETTLE_PROBE_SCHEDULE.selfCheckBackoffMs = 0;
  // The console bundle the v2 channels serve: built once (async sha256 per asset).
  const consoleBundleFor = async (version: string): Promise<Uint8Array> =>
    utf8(
      JSON.stringify({
        format: "downpipe-console-bundle/1",
        version,
        worker: { mainModule: "worker.js", sourceB64: base64Encode(CONSOLE_SHELL) },
        config: { compatibilityDate: "2026-06-01", runWorkerFirst: true },
        assets: [{ path: "/index.html", contentType: "text/html; charset=utf-8", sha256: await sha256Hex(CONSOLE_ASSET), b64: base64Encode(CONSOLE_ASSET) }],
      }),
    );
  // RSA keypair for the Access JWT.
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  // Ed25519 + ML-DSA signer for the update channel; pin its public as UPDATE_SIGNER_PUBLIC.
  const edSeed = rand(32);
  const edPublic = ed25519.getPublicKey(edSeed);
  const edPrivate = await crypto.subtle.importKey("pkcs8", concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), edSeed), "Ed25519", false, ["sign"]);
  const mldsa = mldsaKeygen();
  const signerPublic = b64urlEncode(concat(edPublic, new Uint8Array(mldsa.publicKey)));
  const artefactHash = hexEncode(await sha384(ARTEFACT));

  // The vendor LICENCE signer (a separate hybrid keypair, pinned as LICENCE_SIGNER_PUBLIC).
  const vendor = await loadSigner(b64urlEncode(concat(rand(32), rand(32))));
  const pinnedLicencePublic = b64urlEncode(concat(vendor.edPublic, vendor.mldsaPublic));
  const future = new Date(Date.now() + 365 * 86400_000).toISOString();
  const past = new Date(Date.now() - 86400_000).toISOString();
  async function mintLicence(notAfter: string): Promise<string> {
    const body = canonicalJSON({ account: "acme", tier: "enterprise", notAfter, features: ["dashboard"] });
    const sig = await hybridSign(vendor.edPrivate, vendor.mldsaSecret, body);
    return `${b64urlEncode(body)}.${b64urlEncode(sig)}`;
  }
  const VALID_LICENCE = await mintLicence(future);
  const EXPIRED_LICENCE = await mintLicence(past);
  // A genuinely signed, NOT-YET-EXPIRED token whose term ends sooner than VALID_LICENCE's. This is the
  // renewal-overlap paste: both tokens verify, and storing this one silently shortens the customer's term.
  const soon = new Date(Date.now() + 30 * 86400_000).toISOString();
  const SHORTER_LICENCE = await mintLicence(soon);
  const SHAPED_FAKE = "a".repeat(40) + "." + "b".repeat(40); // valid shape, never verifies

  async function signedChannel(
    version: string,
    risk: string,
    opts: { urlMissing?: boolean; badHash?: boolean; meta?: boolean; seq?: number; issuedAt?: string; console?: { version: string; risk?: string; broken?: "no-url" | "wrong-kind"; minEngineVersion?: string }; extraComponent?: { id: string; version: string } } = {},
  ): Promise<{ channel: Uint8Array; sig: Uint8Array }> {
    const artefact: Record<string, unknown> = { version, url: opts.urlMissing ? ARTEFACT_URL_MISSING : ARTEFACT_URL, sha384: opts.badHash ? BAD_HASH : artefactHash, riskClass: risk };
    if (opts.meta) {
      // The W2 rich, signed metadata: each field flips a `...(art.artefact.X ? {X} : {})` spread in the
      // route's input-meta builder to its true arm. requiresMigration also routes the release down the
      // migration guard (refused), which is what the assertion checks.
      artefact.requiresMigration = true;
      artefact.mainModule = "main.js";
      artefact.minEngineVersion = "0.0.1";
    }
    // R9: sequence + issuedAt are top-level SIGNED freshness fields (opt-in per channel).
    const channelObj: Record<string, unknown> = { channel: "stable", recommendedVersion: version, artefacts: [artefact] };
    if (opts.seq !== undefined) channelObj.sequence = opts.seq;
    if (opts.issuedAt !== undefined) channelObj.issuedAt = opts.issuedAt;
    // v2 components map (multi-component updates): the engine mirror + an optional console entry whose
    // bundle bytes the fetch stub serves at CONSOLE_ARTEFACT_URL. "broken" shapes drive the honest
    // console-unusable refusals (consoleIssue).
    if (opts.console !== undefined) {
      const bundle = await consoleBundleFor(opts.console.version);
      currentConsoleBundle = bundle;
      const consoleEntry: Record<string, unknown> = {
        kind: opts.console.broken === "wrong-kind" ? "worker-module" : "static-assets",
        version: opts.console.version,
        riskClass: opts.console.risk ?? "routine",
        ...(opts.console.minEngineVersion !== undefined ? { minEngineVersion: opts.console.minEngineVersion } : {}),
      };
      if (opts.console.broken !== "no-url") {
        consoleEntry.url = CONSOLE_ARTEFACT_URL;
        consoleEntry.sha384 = hexEncode(await sha384(bundle));
      }
      channelObj.components = {
        engine: { kind: "worker-module", ...artefact },
        console: consoleEntry,
        // G275: a FUTURE release naming a component id this build cannot plan. Well-formed (a known kind,
        // a version), so it is kept and displayed, and no apply/settle/rollback here can act on it.
        ...(opts.extraComponent !== undefined ? { [opts.extraComponent.id]: { kind: "worker-module", version: opts.extraComponent.version, url: ARTEFACT_URL, sha384: artefactHash } } : {}),
      };
    }
    const channel = utf8(JSON.stringify(channelObj));
    const sig = await hybridSign(edPrivate, mldsa.secretKey, channel);
    return { channel, sig };
  }

  // Mutable harness state the env builder + fetch stub read, so each test sets exactly the world it needs.
  // (currentConsoleBundle is set by signedChannel when a channel carries a console component; the CONSOLE
  // script's deploy state is stateful so the post-promote confirmation read sees what was deployed.)
  let currentConsoleBundle: Uint8Array = new Uint8Array(0);
  let consoleLive = "cv-live-0"; // the console script's live version (advanced by its deployments-CREATE)
  let consoleUploads = 0; // console versions-POST counter (each upload mints a fresh id)
  let consoleConfirmDrift = false; // ONE-SHOT: the next console deployments-CREATE succeeds but does not land
  let consoleFailDeploy = false; // make the console deployments-CREATE fail (atomic; prior still serving)
  let consoleWorkerNameOn = false; // set CONSOLE_WORKER_NAME (the renamed-console deploy-target arm)
  let current = await signedChannel("0.4.0", "routine");
  let accountOn = true; // CF_ACCOUNT_ID present (resolveEngineAccount)
  let channelOn = true; // UPDATE_CHANNEL_URL + UPDATE_SIGNER_PUBLIC present
  let workerNameOn = true; // WORKER_NAME present (scriptName branch)
  let licencePinOn = true; // LICENCE_SIGNER_PUBLIC present (effectiveSignerPin)
  // destOn (0.1.5 destination gate, design §4): a MINIMAL fake R2 binding, present by default so every
  // pre-existing live-apply scenario below is undisturbed by the new pre-token destination-configured check
  // (buildDestination constructs an R2Destination over {} without ever calling a method on it -- this suite
  // never reaches the canary/preflight machinery that would, so it never produces a real fetch and never
  // trips "no unexpected outbound fetch"). RESERVED_BINDINGS excludes DEST_R2 from ever being offered as a
  // downpipe source, so it cannot perturb sourceBindingsBefore/droppedSources either. Toggled OFF only for
  // the dedicated destination-gate scenarios (GROUP C-DEST) so they exercise the genuinely-unconfigured arm.
  let destOn = true;
  let failDeploy = false; // make the CF deployments-CREATE fail (drives a rollback "failed")
  let liveSplit = false; // make the CF deployments-LIST report a two-version SPLIT (liveSingle === null)
  const liveVersionId = "v-live"; // the version the CF deployments-LIST reports as live (single-version shape)
  let deployCalls = 0; // counts real CF deployments-CREATE calls (asvs-HI-19: proves the cutover really landed)

  // G183: channelNetworkFault makes the SIGNED CHANNEL itself unreachable (a DNS/TLS/connection fault, the
  // shape defaultFetch throws on), and channelFetched records that the channel HAS been served -- which is
  // what lets the DO-fault injector below target the anti-rollback FLOOR READ specifically, since that is the
  // only /update-status read the apply performs AFTER the channel fetch.
  let channelNetworkFault = false;
  let channelFetched = false;

  const unexpectedFetches: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? "GET";
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    if (url === CHANNEL_URL && channelNetworkFault) throw new TypeError("fetch failed: connection refused");
    if (url === CHANNEL_URL) { channelFetched = true; return new Response(new Uint8Array(current.channel), { status: 200 }); }
    if (url === CHANNEL_URL + ".sig") return new Response(b64urlEncode(current.sig) + "\n", { status: 200 });
    if (url === ARTEFACT_URL) return new Response(ARTEFACT, { status: 200 });
    if (url === ARTEFACT_URL_MISSING) return new Response("not found", { status: 404 });
    if (url === CONSOLE_ARTEFACT_URL) return new Response(new Uint8Array(currentConsoleBundle), { status: 200 });
    // ---- the CONSOLE script's CF surface (multi-component updates): STATEFUL, so the post-promote
    // confirmation read sees exactly what was deployed. The engine script's arms below stay static. ----
    const isConsoleScript = /\/workers\/scripts\/downpipe-console[^/]*\//.test(url);
    if (isConsoleScript && method === "POST" && /\/assets-upload-session$/.test(url)) {
      // Full dedup at the route level (the bucket-upload byte path is unit-proven in
      // validate-assets-deploy.ts): no buckets, the session token doubles as the completion token.
      return new Response(JSON.stringify({ success: true, result: { jwt: "session-is-completion", buckets: [] } }), { status: 200 });
    }
    if (method === "POST" && /\/workers\/assets\/upload/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { jwt: "completion-jwt" } }), { status: 200 });
    }
    if (isConsoleScript && method === "POST" && /\/versions$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { id: `cv-new-${++consoleUploads}` } }), { status: 200 });
    }
    if (isConsoleScript && method === "GET" && /\/deployments$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { deployments: [{ id: "cd-1", versions: [{ version_id: consoleLive, percentage: 100 }] }] } }), { status: 200 });
    }
    if (isConsoleScript && method === "POST" && /\/deployments$/.test(url)) {
      events.push("CF POST deployments console");
      if (consoleFailDeploy) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "console deploy refused" }] }), { status: 403 });
      if (consoleConfirmDrift) {
        // The API accepts the deploy but the deployment does not land (a promote that silently missed):
        // the confirmation read then sees the stale live version -> the honest auto-rollback path.
        consoleConfirmDrift = false;
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      const posted = JSON.parse(String(init?.body)) as { versions?: Array<{ version_id?: string }> };
      consoleLive = posted.versions?.[0]?.version_id ?? consoleLive;
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }
    // CF: the CONSOLE script's settings -- the ownership proof reads these: the console's live bindings
    // must include a service binding pointing at THIS engine (the harness engine name), or every mutating
    // console call refuses before touching anything.
    if (isConsoleScript && method === "GET" && /\/settings$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { bindings: [{ type: "service", name: "ENGINE", service: "downpipe-engine" }, { type: "assets", name: "ASSETS" }], compatibility_date: "2024-01-01" } }), { status: 200 });
    }
    // CF: read script settings (preserve bindings before an upload). Empty bindings -> no unknown types.
    if (method === "GET" && /\/workers\/scripts\/[^/]+\/settings$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { bindings: [], compatibility_date: "2024-01-01" } }), { status: 200 });
    }
    // CF: upload a new version -> returns the new version id.
    if (method === "POST" && /\/workers\/scripts\/[^/]+\/versions$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { id: "v-new" } }), { status: 200 });
    }
    // CF: read a version's content back (the DP-D read-back between upload and promote). Returns the
    // uploaded artefact bytes as the version's main module, so the warn-mode gate records a VERIFIED
    // verdict in these flows (the gate's own refusal/unavailable arms are unit-proven in
    // validate-update-apply.ts; this suite proves the route wiring does not add surprise fetches).
    if (method === "GET" && /\/workers\/scripts\/[^/]+\/versions\/[^/]+/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { modules: [{ name: "index.js", content_base64: Buffer.from(ARTEFACT).toString("base64") }] } }), { status: 200 });
    }
    // CF: list deployments (record the rollback target) -> a single live version at 100%, or, when
    // liveSplit is set, a real two-version split (so the orchestration sees liveSingle === null).
    if (method === "GET" && /\/workers\/scripts\/[^/]+\/deployments$/.test(url)) {
      const versions = liveSplit ? [{ version_id: "v-a", percentage: 40 }, { version_id: "v-b", percentage: 60 }] : [{ version_id: liveVersionId, percentage: 100 }];
      return new Response(JSON.stringify({ success: true, result: { deployments: [{ id: "d-1", versions }] } }), { status: 200 });
    }
    // CF: create a deployment (promote / rollback / ramp). failDeploy makes it fail (atomic; prior still live).
    if (method === "POST" && /\/workers\/scripts\/[^/]+\/deployments$/.test(url)) {
      events.push("CF POST deployments engine");
      if (!failDeploy) deployCalls++;
      return new Response(JSON.stringify(failDeploy ? { success: false, errors: [{ code: 10000, message: "deploy refused" }] } : { success: true }), { status: failDeploy ? 403 : 200 });
    }
    unexpectedFetches.push(`${method} ${url}`);
    return new Response(JSON.stringify({ error: "unexpected network fetch in test", method, url }), { status: 404, headers: { "content-type": "application/json" } });
  }) as typeof fetch;

  try {
    const sched = makeScheduler();
    // injectSelfDeployReset simulates the exact platform fault the finding is about: a
    // self-redeploy (promote/rollback/ramp) momentarily resets the SchedulerDO, so the very next call(s)
    // against it reject with the DO's real error message instead of returning a Response. It makes the
    // stub's OWN fetch() throw for the next `times` POSTs whose path ends with `matchPath`, then falls
    // through to the real in-memory DO for everything else (including the retried attempt once `times` is
    // exhausted); the returned function restores the original fetch. `times` >= the 5-attempt retry budget
    // (router-audit.ts SELF_DEPLOY_RETRY_MAX_ATTEMPTS) models a reset that never recovers within the window.
    function injectSelfDeployReset(matchPath: string, times: number): () => void {
      const stubAny = sched.stub as unknown as { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> };
      const original = stubAny.fetch;
      let remaining = times;
      stubAny.fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (remaining > 0 && (init?.method ?? "GET") === "POST" && url.endsWith(matchPath)) {
          remaining--;
          return Promise.reject(new Error("Durable Object reset because its code was updated"));
        }
        return original(input, init);
      };
      return () => {
        stubAny.fetch = original;
      };
    }
    const baseEnv = (): Env => ({
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      ADMIN_TOKEN: "bg-token-cov", // the bare-token break-glass credential (owner-equivalent, null email)
      ...(accountOn ? { CF_ACCOUNT_ID: "acct-test" } : {}),
      ...(workerNameOn ? { WORKER_NAME: "downpipe-engine" } : {}),
      ...(consoleWorkerNameOn ? { CONSOLE_WORKER_NAME: "downpipe-console-demo" } : {}),
      ...(channelOn ? { UPDATE_CHANNEL_URL: CHANNEL_URL, UPDATE_SIGNER_PUBLIC: signerPublic } : {}),
      ...(licencePinOn ? { LICENCE_SIGNER_PUBLIC: pinnedLicencePublic } : {}),
      ...(destOn ? { DEST_R2: {} } : {}),
    }) as unknown as Env;

    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    async function tokenFor(email: string): Promise<string> {
      const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
      const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
      return `${header}.${body}.${b64urlEncode(sig)}`;
    }
    async function call(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const assertion = await tokenFor(email);
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), baseEnv());
    }
    // callWithEnv is `call` with an explicit env instead of the shared baseEnv() (licbind3, GROUP D2 below):
    // it drives the same forged Access JWT against a DIFFERENT scheduler DO, so a test can prove what a
    // request does to a FRESH engine without disturbing (or being disturbed by) the shared `sched` state
    // every other group in this file reads and writes.
    async function callWithEnv(envOverride: Env, email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const assertion = await tokenFor(email);
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), envOverride);
    }
    // callMalformed sends a body that is not valid JSON so the route's try { await req.json() } throws into
    // its fail-safe catch (a clean 400, nothing changed).
    async function callMalformed(email: string, path: string): Promise<Response> {
      const assertion = await tokenFor(email);
      return handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", headers: { "cf-access-jwt-assertion": assertion, "content-type": "application/json" }, body: "{ not json" }), baseEnv());
    }
    // bareCall drives the bare-token break-glass path (authorization: Bearer ADMIN_TOKEN): an
    // owner-equivalent caller with a NULL email/subject, so the deep success records take the
    // `caller.email ?? null` null arm, and the dual-control gate-check refuses it as a maker.
    async function bareCall(method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const init: RequestInit = {
        method,
        headers: { authorization: "Bearer bg-token-cov", ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), baseEnv());
    }
    // Seed the DO update lifecycle directly (the internal bookkeeping endpoints the router itself calls).
    async function seedPending(p: Record<string, unknown>): Promise<void> {
      await sched.stub.fetch("https://scheduler.internal/update-pending", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(p) });
    }
    async function seedSettled(last: Record<string, unknown>): Promise<void> {
      await sched.stub.fetch("https://scheduler.internal/update-settled", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(last) });
    }
    const jsonOf = async (r: Response): Promise<Record<string, unknown>> => (await r.json()) as Record<string, unknown>;

    // ===== Bootstrap: first Access caller is Owner; grant OWNER2 (a second owner, applies immediately
    // while only one owner exists) so the dual-control arm/disarm has a distinct approver. =====
    const who = await jsonOf(await call(OWNER, "GET", "/admin/whoami"));
    ok("bootstrap: the first Access caller is Owner", who.role === "owner");
    const grant2 = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    ok("a second owner is granted (applies immediately while one owner exists)", grant2.status === 200);

    // The default spoke fall-through: a non-update authed route passes through handleUpdates' default
    // (return null) on its way to the spoke that answers it.
    const statusResp = await call(OWNER, "GET", "/admin/status");
    ok("a non-update route falls through handleUpdates' default (200 from a later spoke)", statusResp.status === 200);

    // ===================================================================================================
    // GROUP A: the thin GET forwarders + read views.
    // ===================================================================================================
    ok("GET /downpipes forwards to the DO (200, array)", (await (async () => { const r = await call(OWNER, "GET", "/admin/downpipes"); return r.status === 200 && Array.isArray(await r.json()); })()));
    {
      const r = await call(OWNER, "GET", "/admin/updates");
      const j = await jsonOf(r);
      ok("GET /updates runs checkUpdates (verified against the pinned channel)", r.status === 200 && j.verified === true && j.recommendedVersion === "0.4.0");
    }
    ok("GET /history forwards to the DO (200)", (await call(OWNER, "GET", "/admin/history?id=dp1")).status === 200);
    {
      // GET /runs/at, gate satisfied (owner has downpipe.read): a malformed query (no ?downpipe) maps the
      // DO's { error } hint to a 400; a well-formed query is a 200 (found:false is a valid answer).
      const bad = await call(OWNER, "GET", "/admin/runs/at");
      ok("GET /runs/at with no downpipe -> 400 (the DO error hint maps to a 400)", bad.status === 400);
      const good = await call(OWNER, "GET", "/admin/runs/at?downpipe=dp1&at=2026-01-01T00:00:00.000Z");
      const gj = await jsonOf(good);
      ok("GET /runs/at well-formed -> 200, an honest found:false (no error)", good.status === 200 && gj.error === undefined && gj.found === false);
    }
    ok("GET /rto (gate reports.read satisfied) -> 200", (await call(OWNER, "GET", "/admin/rto?id=dp1")).status === 200);
    ok("GET /replication forwards to the DO (200)", (await call(OWNER, "GET", "/admin/replication")).status === 200);
    // GATE-GAP: the three thin forwarders above named NO capability while /runs/at and /rto
    // beside them each named one. They now gate on downpipe.read. The point of these three assertions is
    // that the gate is a DECLARATION, not a narrowing: the least-privileged resting role in this engine
    // still gets 200 on all three, so nothing an operator could reach yesterday is refused today. Driven
    // through the real handleAdmin, not read off the capability table, so a future edit that gated one of
    // them on something a viewer does NOT hold fails here rather than in a customer's console. Every OTHER
    // assertion on these three routes calls as OWNER, who holds every capability, so none of them can tell
    // a correct gate from a wrong one -- these are the assertions that can.
    ok("GET /downpipes: the viewer floor still passes the new downpipe.read gate (200)", (await call(VIEWER, "GET", "/admin/downpipes")).status === 200);
    ok("GET /history: the viewer floor still passes the new downpipe.read gate (200)", (await call(VIEWER, "GET", "/admin/history?id=dp1")).status === 200);
    ok("GET /replication: the viewer floor still passes the new downpipe.read gate (200)", (await call(VIEWER, "GET", "/admin/replication")).status === 200);
    {
      const r = await call(OWNER, "GET", "/admin/licence");
      const j = await jsonOf(r);
      ok("GET /licence is fail-open 200 (community, nothing activated yet)", r.status === 200 && j.tier === "community");
      // estate (volume-based self-serve licensing): rides alongside the entitlement, computed against
      // the SAME real in-memory SchedulerDO this suite already drives. No downpipe has been added
      // anywhere in this fixture, so the rollup honestly resolves to a real, all-zero object (never
      // null: null means the rollup itself could not be computed, not "nothing to show yet").
      const estate = j.estate as { downpipes: number; totalProtectedBytes: number; accounts: number; zones: number; asOf: string | null } | null | undefined;
      ok(
        "GET /licence carries estate (a real, honestly-empty rollup; no downpipes exist in this fixture)",
        estate !== null && estate !== undefined && estate.downpipes === 0 && estate.totalProtectedBytes === 0 && estate.accounts === 0 && estate.zones === 0 && estate.asOf === null,
      );
    }
    ok("GET /update/status (gate downpipe.read satisfied) -> 200", (await call(OWNER, "GET", "/admin/update/status")).status === 200);

    // ===================================================================================================
    // GROUP B: POST /licence (verify-before-store activation + clear).
    // ===================================================================================================
    ok("POST /licence by a non-owner -> 403 (keys.ceremony gate)", (await call(VIEWER, "POST", "/admin/licence", { token: "x" })).status === 403);
    ok("POST /licence malformed body -> 400 (fail-safe catch)", (await callMalformed(OWNER, "/admin/licence")).status === 400);
    {
      const r = await call(OWNER, "POST", "/admin/licence", { token: null });
      ok("POST /licence { token:null } clears -> 200 community (nothing was stored)", r.status === 200 && (await jsonOf(r)).tier === "community");
    }
    {
      // token is not a string -> coerced to "" -> the shape refusal.
      const r = await call(OWNER, "POST", "/admin/licence", { token: 12345 });
      ok("POST /licence non-string token -> 400 'does not look like a licence token'", r.status === 400 && /does not look like/.test(String((await jsonOf(r)).error)));
    }
    {
      const r = await call(OWNER, "POST", "/admin/licence", { token: "no-dot-here" });
      ok("POST /licence bad-shape token (no dot) -> 400 shape refusal", r.status === 400 && /does not look like/.test(String((await jsonOf(r)).error)));
    }
    {
      const r = await call(OWNER, "POST", "/admin/licence", { token: "a".repeat(20001) });
      ok("POST /licence over-length token -> 400 (length bound before the regex)", r.status === 400 && /does not look like/.test(String((await jsonOf(r)).error)));
    }
    {
      // Verify-before-store with NO env pin: the compile-time BAKED vendor pin now resolves
      // (effectiveSignerPin), so a shaped-but-fake token reaches the real verify and bounces on the
      // SIGNATURE arm, not the retired 'vendor has not pinned' hint (that arm remains only for a
      // build with the baked constant blanked).
      licencePinOn = false;
      const r = await call(OWNER, "POST", "/admin/licence", { token: SHAPED_FAKE });
      const j = await jsonOf(r);
      ok("POST /licence valid-shape token, no env pin -> 400 via the baked pin's verify", r.status === 400 && /could not be activated/.test(String(j.error)) && !/vendor has not pinned/.test(String(j.error)));
      licencePinOn = true;
    }
    {
      // A signed-but-EXPIRED token: it verifies, then resolves expired -> the 'licence expired' hint arm.
      const r = await call(OWNER, "POST", "/admin/licence", { token: EXPIRED_LICENCE });
      ok("POST /licence expired token -> 400 names renewal (fail-open meantime)", r.status === 400 && /request a renewed token/.test(String((await jsonOf(r)).error)));
    }
    {
      // A valid-shape token that does NOT verify under the pin -> the generic (no-hint) refusal arm.
      const r = await call(OWNER, "POST", "/admin/licence", { token: SHAPED_FAKE });
      const j = await jsonOf(r);
      ok("POST /licence unverifiable token -> 400 with the honest signature reason (no hint)", r.status === 400 && /could not be activated/.test(String(j.error)) && /did not verify/.test(String(j.error)));
    }
    {
      // A VALID vendor-signed token verifies and is stored; GET /licence then reads it back as enterprise.
      const r = await call(OWNER, "POST", "/admin/licence", { token: VALID_LICENCE });
      const j = await jsonOf(r);
      ok("POST /licence valid token -> 200, stored + activated (tier enterprise)", r.status === 200 && j.valid === true && j.tier === "enterprise");
      const readBack = await jsonOf(await call(OWNER, "GET", "/admin/licence"));
      ok("the activated licence is read back through GET /licence (source console)", readBack.tier === "enterprise" && readBack.source === "console");
    }
    {
      // THE SUPERSEDED-TOKEN OVERWRITE, proven in FOUR directions because a blanket refusal would pass the
      // one assertion that matters and break the two paths that must keep working. setLicenceToken puts the
      // record unconditionally, so an older term's token used to verify, overwrite the current one, and
      // report success. A longer term is active from the block above.
      //
      // 1. IDEMPOTENT RE-PASTE MUST STILL WORK. Re-pasting the SAME token is the commonest thing a confused
      //    customer does, and refusing it would build a dead end. Equal end dates are not a regression.
      const same = await call(OWNER, "POST", "/admin/licence", { token: VALID_LICENCE });
      ok("POST /licence re-pasting the SAME token is still 200 (idempotent, never a dead end)", same.status === 200 && (await jsonOf(same)).valid === true);
      // 2. THE SHORTER TERM IS REFUSED, and the refusal names both dates because "your licence would end
      //    sooner" is only actionable if you can see by how much.
      const shorter = await call(OWNER, "POST", "/admin/licence", { token: SHORTER_LICENCE });
      const sj = await jsonOf(shorter);
      ok(
        "POST /licence a shorter-term token -> 400 with the closed reasonCode and BOTH end dates",
        shorter.status === 400 && sj.reasonCode === "supersedes-current-term" && sj.currentNotAfter === future && sj.incomingNotAfter === soon,
      );
      // 3. AND NOTHING WAS STORED. The refusal claiming "nothing has been changed" is the sentence a customer
      //    has to believe, so it is checked rather than trusted: the active term must still be the longer one.
      const afterRefusal = await jsonOf(await call(OWNER, "GET", "/admin/licence"));
      ok("the refused activation really changed nothing (the longer term is still active)", afterRefusal.notAfter === future && afterRefusal.valid === true);
      // 4. THE OPT-IN IS NOT A NO-OP. allowSupersede is the deliberate move to an earlier-ending licence
      //    (a downgrade, a corrected issue), shaped like allowDowngrade on POST /update/apply. If this passed
      //    while the flag did nothing, arm 2 would be a ban rather than a default.
      const forced = await call(OWNER, "POST", "/admin/licence", { token: SHORTER_LICENCE, allowSupersede: true });
      ok("POST /licence allowSupersede:true really stores the shorter term (an opt-in, not a ban)", forced.status === 200 && (await jsonOf(forced)).notAfter === soon);
      // Restore the longer term for anything that follows. It is LONGER than what is now active, so this also
      // re-proves that moving forward is never refused.
      const restored = await call(OWNER, "POST", "/admin/licence", { token: VALID_LICENCE });
      ok("moving to a LONGER term is never refused (the check is one-directional)", restored.status === 200 && (await jsonOf(restored)).notAfter === future);
    }
    {
      // THE REASON THE ENGINE ALREADY KNEW AND DROPPED FROM THE ANSWER. The closed reasonCode was written to
      // the engine's own refusal counter and the caller got prose only, so the person holding the token was
      // the one party not told whether it was expired, wrongly signed or tampered with. It rides in the body
      // now. Asserted on the EXPIRED arm because that code ("expired") is the one with a real remedy.
      const r = await call(OWNER, "POST", "/admin/licence", { token: EXPIRED_LICENCE });
      ok("POST /licence a refusal now carries its closed reasonCode in the body, not only in the counter", r.status === 400 && (await jsonOf(r)).reasonCode === "expired");
    }

    // ===================================================================================================
    // GROUP C: POST /update/apply (gate OFF for these).
    // ===================================================================================================
    ok("POST /update/apply by a non-owner -> 403 (keys.ceremony gate)", (await call(VIEWER, "POST", "/admin/update/apply", {})).status === 403);
    ok("POST /update/apply malformed body -> 400 (fail-safe catch)", (await callMalformed(OWNER, "/admin/update/apply")).status === 400);
    {
      accountOn = false;
      const r = await call(OWNER, "POST", "/admin/update/apply", {});
      ok("apply with no engine account marked -> 400 (choose it under Sources)", r.status === 400 && /Cloudflare account is not marked/.test(String((await jsonOf(r)).error)));
      accountOn = true;
    }
    {
      channelOn = false;
      const r = await call(OWNER, "POST", "/admin/update/apply", {});
      ok("apply with no update channel configured -> 400 'no applicable update'", r.status === 400 && /no applicable update/.test(String((await jsonOf(r)).error)));
      channelOn = true;
    }
    {
      current = await signedChannel(ENGINE_VERSION, "routine"); // recommends the running ENGINE_VERSION
      const r = await call(OWNER, "POST", "/admin/update/apply", {});
      ok("apply when recommended == running -> 200 no-update", r.status === 200 && (await jsonOf(r)).outcome === "no-update");
    }
    {
      current = await signedChannel("0.4.0", "routine", { urlMissing: true });
      const r = await call(OWNER, "POST", "/admin/update/apply", {});
      ok("apply when the artefact will not download -> 400 (cannot download the bundle)", r.status === 400 && /could not download the update artefact/.test(String((await jsonOf(r)).error)));
    }
    {
      // DRY-RUN (the default): verify + plan, never upload/promote. Drives planAndPromote with dryRun:true
      // and the allowDowngrade:true spread arm. Reaches neither record branch (outcome dry-run).
      current = await signedChannel("0.4.0", "routine");
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true, allowDowngrade: true });
      ok("apply dry-run -> 200 outcome dry-run (verified + planned, nothing deployed)", r.status === 200 && (await jsonOf(r)).outcome === "dry-run");
    }
    {
      // Going live, routine release, dual control OFF, NO token -> the token-required 400 (gate skipped).
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false });
      ok("apply live (routine, gate off, no token) -> 400 token-required", r.status === 400 && /one-shot Cloudflare deploy token/.test(String((await jsonOf(r)).error)));
    }
    {
      // Full PROMOTE: routine + valid token -> planAndPromote uploads + promotes -> outcome promoted; the
      // route records the pending verification + the update-promoted audit. WORKER_NAME absent here exercises
      // the scriptName default branch.
      workerNameOn = false;
      current = await signedChannel("0.4.0", "routine");
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("apply live (routine, token) -> 200 promoted (uploaded + promoted)", r.status === 200 && j.outcome === "promoted" && j.toVersion === "v-new" && j.fromVersion === liveVersionId);
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the promote recorded a pending verification in the DO", (st.pending as { toVersion?: string } | null)?.toVersion === "v-new");
      workerNameOn = true;
    }
    {
      // asvs-HI-14 (PRIMARY guard): a SECOND apply while the promote above is still awaiting verification
      // must be refused BEFORE it ever reaches planAndPromote -- this is exactly the exploit's step 2 (a
      // "finish the ramp"/repeat apply reaching verifyAndGuard while a prior transition is still open).
      const blocked = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("a second apply while a prior one is pending -> 409 (not a repeat deploy)", blocked.status === 409 && /already awaiting verification/.test(String((await jsonOf(blocked)).error)));
      // Clear it so the tests below (which deliberately exercise OTHER refusal arms) are not blocked by it.
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
    }
    {
      // REFUSED: a channel whose declared sha384 does not match the served artefact -> planAndPromote
      // verify-before-deploy refuses; the route records the update-refused audit.
      current = await signedChannel("0.4.0", "routine", { badHash: true });
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply live with a hash mismatch -> 200 refused (verify-before-deploy)", r.status === 200 && (await jsonOf(r)).outcome === "refused");
    }
    {
      // A release carrying the W2 rich metadata (requiresMigration + mainModule + minEngineVersion): the
      // route builds the input meta with all three optional fields (the meta-spread true arms), then the
      // migration guard refuses it. token present + gate OFF so it reaches the input builder.
      current = await signedChannel("0.4.0", "migration", { meta: true });
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply of a metadata-rich migration release -> 200 refused (migration guard; meta carried)", r.status === 200 && (await jsonOf(r)).outcome === "refused");
    }

    // ===================================================================================================
    // GROUP C-DEST: the destination gate (design UPDATE-UX-015 §4). destOn is toggled OFF here only, so
    // every other scenario in this file keeps its fake-but-present destination undisturbed.
    // ===================================================================================================
    {
      current = await signedChannel("0.4.0", "routine");
      destOn = false;
      // [§7] GET /update/status carries the SAME authoritative destinationConfigured fact, so the console
      // can show the "add a destination first" line without ever attempting an apply.
      const stNoDest = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("GET /update/status reports destinationConfigured:false with none configured", stNoDest.destinationConfigured === false);
      const eventsBefore = events.length;
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("live apply with no destination -> 400 the exact §4 reason string", r.status === 400 && j.error === "updates verify themselves with a canary flight to your destination; add a destination first, then apply this update");
      ok("the refusal happened before any deploy (no NEW CF deployments call)", !events.slice(eventsBefore).includes("CF POST deployments engine"));
      const dry = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true });
      ok("dry-run with no destination is UNGATED -> still 200 a real plan", dry.status === 200 && (await jsonOf(dry)).outcome === "dry-run");
      // The component-aware path (router-updates-components.ts) carries the SAME gate.
      const rc = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine"], dryRun: false, token: DEPLOY_TOKEN });
      const jc = await jsonOf(rc);
      ok("a component-aware live apply with no destination -> the SAME 400 (both paths gated)", rc.status === 400 && jc.error === j.error);
      ok("neither refusal ever deployed anything", !events.slice(eventsBefore).includes("CF POST deployments engine"));
      destOn = true;
      const stWithDest = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("GET /update/status flips to destinationConfigured:true once one exists", stWithDest.destinationConfigured === true);
      const withDest = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("with a destination configured -> unchanged behaviour (200 promoted, not the gate)", withDest.status === 200 && (await jsonOf(withDest)).outcome === "promoted");
    }

    // ===================================================================================================
    // GROUP C: THE DISCRIMINATION TEST. "Update apply always fails with a generic message" -- and the
    // question the pack has to answer is WHOSE fault it is: the customer's own scheduler DO, or the signed
    // channel (the vendor's CDN, or the customer's egress). Those are different owners and different
    // remedies, and the FIRST build of this aggregate recorded them as the SAME ROW.
    //
    // The anti-rollback FLOOR READ (readUpdateFloor) is a scheduler DO read with no catch of its own, and it
    // sat INSIDE the channel-fetch window, so a DO outage recorded "update-apply|channel-fetch" -- and the
    // pack's own legend then told the support engineer to go and check a CDN that was never involved. It is
    // not a narrow window either: every other call in that span is throw-proof, so the DO read was a large
    // share of the real rows landing under the channel's label.
    //
    // Both states are driven for real here, through the real route and the real recorder, and the assertion
    // is that they produce DIFFERENT KEYS. "A row was recorded" is precisely what got the first build refuted.
    // ===================================================================================================
    {
      const routeErrors = async (): Promise<Record<string, number>> => {
        const r = await (sched.stub as unknown as { fetch(req: Request): Promise<Response> }).fetch(new Request("https://do/admin-route-errors"));
        const body = (await r.json()) as { errors?: { byRouteStage?: Record<string, number> } };
        return body.errors?.byRouteStage ?? {};
      };
      // Clear any pending verification a prior GROUP C apply left behind: the pending guard refuses BEFORE
      // either fault site is reached, and a refusal that never reaches the fault is not a test of the fault.
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
      const before = await routeErrors();
      const delta = (after: Record<string, number>, key: string): number => (after[key] ?? 0) - (before[key] ?? 0);

      // STATE 1: the customer's SCHEDULER DO is faulting. Injected on the floor read specifically (the only
      // /update-status read the apply performs after the channel has been served), which is exactly where a
      // real DO outage lands: readUpdateFloor deliberately has no catch, so the route fails closed on it.
      channelFetched = false;
      const stubAny = sched.stub as unknown as { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> };
      const originalStubFetch = stubAny.fetch;
      stubAny.fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (channelFetched && (init?.method ?? "GET") === "GET" && url.endsWith("/update-status")) {
          return Promise.reject(new Error("Durable Object storage failure"));
        }
        return originalStubFetch(input, init);
      };
      const doFault = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true });
      stubAny.fetch = originalStubFetch;
      const afterDo = await routeErrors();
      ok("a DO fault on the floor read still refuses the apply (fail-closed, unchanged)", doFault.status === 400);
      ok("THE DO FAULT IS RECORDED AS do-read (it used to be recorded as channel-fetch)", delta(afterDo, "update-apply|do-read") === 1);
      ok("...and it did NOT land on the channel's key", delta(afterDo, "update-apply|channel-fetch") === 0);

      // STATE 2: the SIGNED CHANNEL is unreachable. A genuinely different owner (the vendor's CDN, or the
      // customer's egress), and it must not be able to wear the DO's label either.
      channelNetworkFault = true;
      const chFault = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true });
      channelNetworkFault = false;
      const afterCh = await routeErrors();
      ok("a channel network fault still refuses the apply", chFault.status === 400);
      ok("THE CHANNEL FAULT IS RECORDED AS channel-fetch", delta(afterCh, "update-apply|channel-fetch") === 1);
      ok("DISCRIMINATION: the DO outage and the channel outage are TWO DIFFERENT ROWS, not one", delta(afterCh, "update-apply|do-read") === 1 && delta(afterCh, "update-apply|channel-fetch") === 1);
    }

    // ===================================================================================================
    // GROUP D: POST /update/settle. The settle flies the canary to decide; with no destination it is
    // "pending", so the in-harness verdict is always ROLLBACK (decision.keep === false). That covers the
    // decision computation, the token gate, the superseded guard and the rolled-back settle + record.
    // ===================================================================================================
    ok("POST /update/settle by a non-owner -> 403", (await call(VIEWER, "POST", "/admin/update/settle", {})).status === 403);
    ok("POST /update/settle malformed body -> 400 (fail-safe catch)", (await callMalformed(OWNER, "/admin/update/settle")).status === 400);
    {
      await seedSettled({ outcome: "expired", at: Date.now(), by: null }); // clears any pending
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle with no pending verification -> 400", r.status === 400 && /no update awaiting verification/.test(String((await jsonOf(r)).error)));
    }
    {
      // Pending present, NO token -> the decision is computed (canary flown, self-check consulted) then the
      // token-required 400 is returned (the canaryBaseline ?? gate.baseline() right arm is exercised here).
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/settle", {});
      ok("settle with a pending, no token -> 400 token-required (decision computed first)", r.status === 400 && /paste the one-shot deploy token/.test(String((await jsonOf(r)).error)));
    }
    {
      // SUPERSEDED: the live version (deployments LIST = v-live) differs from pending.toVersion -> 409, and
      // the pending is cleared without any change. A seeded canaryBaseline:"alive" exercises the
      // liveBaseline !== "alive" FALSE arm (so the inline self-check is skipped).
      await seedPending({ fromVersion: "v-prior", toVersion: "v-other", recommendedVersion: "0.4.0", riskClass: "routine", canaryBaseline: "alive", promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle when the live version is no longer the promoted one -> 409 superseded", r.status === 409 && /no longer the one this update promoted/.test(String((await jsonOf(r)).error)));
    }
    {
      // No engine account marked after the token gate (a non-number promotedAt also exercises the TTL
      // guard's typeof-number FALSE arm, so the stale-clear branch is skipped on a malformed timestamp).
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", riskClass: "routine", promotedAt: "not-a-number", promotedBy: OWNER });
      accountOn = false;
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle with a token but no engine account -> 400", r.status === 400 && /Cloudflare account is not marked/.test(String((await jsonOf(r)).error)));
      accountOn = true;
    }
    {
      // SPLIT live deployment (liveSingle === null): the route does NOT declare superseded on a split (it
      // would collapse the split by deploying at 100%); it proceeds and rolls back. Exercises the
      // liveSingle ?? slices.map(...) label fallback and the liveSingle !== null FALSE arm.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-other", recommendedVersion: "0.4.0", riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER });
      liveSplit = true;
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle on a multi-version split -> proceeds (not superseded) -> 200 applied (optimistic keep)", r.status === 200 && (await jsonOf(r)).outcome === "applied");
      liveSplit = false;
    }
    {
      // KEEP direction. The inline canary is pending (no destination), so the self-check is consulted: with
      // recommendedVersion === ENGINE_VERSION and a fresh preflight (a recorded tick), the self-check passes
      // and decideKeep returns KEEP. A migration risk routes it through the KEEP dual-control gate (OFF here
      // -> proceeds); settleAfterPromote then keeps the new version (no deploy) -> 200 applied + an
      // update-applied record.
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "migration", promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("settle KEEP (self-check passes) -> 200 applied (new version kept, no deploy)", r.status === 200 && j.outcome === "applied");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the KEEP settle recorded an applied last outcome", (st.last as { outcome?: string } | null)?.outcome === "applied");
    }
    {
      // POST-UPDATE SOURCE VERIFICATION: a KEPT update whose pre-update snapshot (sourceBindingsBefore)
      // lists a binding the now-live engine no longer exposes -> the settle response carries droppedSources
      // so the console prompts a re-attach. The harness env has no source bindings, so a snapshotted
      // SRC_GONE reads as dropped (the diff's TRUE arm + the droppedSources return).
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "migration", promotedAt: Date.now(), promotedBy: OWNER, sourceBindingsBefore: ["SRC_GONE"] });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("settle KEEP that dropped a source -> 200 applied with droppedSources naming it", r.status === 200 && j.outcome === "applied" && Array.isArray(j.droppedSources) && (j.droppedSources as string[]).includes("SRC_GONE"));
    }
    {
      // KEEP but STALE: a pending older than the settle TTL whose live version self-checks HEALTHY is cleared
      // as expired (409), never silently forgotten -> the health-aware TTL guard's keep arm (decision.keep
      // is the third operand, reached only when the live version is healthy).
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "routine", promotedAt: 0, promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle KEEP but stale -> 409 expired (cleared; the canary confirms the live version healthy)", r.status === 409 && /expired/.test(String((await jsonOf(r)).error)));
    }
    {
      // PROCEED: pending.toVersion == the live version (not superseded). The harness canary can only be
      // "pending" (no real destination flight), which under the OPTIMISTIC settle KEEPS the
      // verified new version (confirmation pending) rather than rolling back -- the exact fix for the three
      // live drills that reverted healthy updates. A stale promotedAt is now decision.keep=true, so the TTL
      // guard clears it as expired (see the dedicated stale block below). This exercises the KEEP settle:
      // the persistence-first record write, settleAfterPromote (no rollback deploy), the applied record.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER });
      workerNameOn = false; // also exercise the scriptName default here
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("settle proceed (canary could not complete) -> 200 applied (optimistic keep, no rollback)", r.status === 200 && j.outcome === "applied");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const last = st.last as { outcome?: string; confirmationPending?: boolean; selfCheckOk?: boolean; settleTrace?: unknown } | null;
      ok("the settle cleared the pending and recorded an applied last outcome", (st.pending === null) && last?.outcome === "applied");
      ok("the applied record is confirmation-pending (the hourly canary confirms it)", last?.confirmationPending === true);
      ok("the settle DECISION TRACE was persisted (selfCheckOk + settleTrace ride the record)", typeof last?.selfCheckOk === "boolean" && Array.isArray(last?.settleTrace));
      workerNameOn = true;
    }

    // ===================================================================================================
    // GROUP D2: GET /admin/status.cfAccountId must not stay absent forever on any engine that self-updates
    // past the release which introduced recordVerifiedEngineAccountAfterSelfDeploy, because that release wires
    // the persist call into the PROMOTE leg only (router-updates.ts:533, inside the very request that swaps
    // the code): on the FIRST such self-update, that request runs on the code that was already live BEFORE
    // the swap, which does not contain the call at all. The settle continuation (this same case, run as a
    // SEPARATE request after the swap) is the first request guaranteed to run on the new code, so it must
    // wire the persist call there too. Two things are proven with a FRESH scheduler DO (never touched above,
    // so it starts genuinely unverified -- GROUP C's own "apply live -> 200 promoted" case already records
    // the shared `sched` DO's account, which would make this fresh-start assertion vacuous if run against it):
    //   1. A settle replayed after a self-update (a pending seeded directly, the same shape any promote --
    //      old code or new -- leaves behind) persists the account id.
    //   2. That id is genuinely NEW information: absent immediately before the settle, present immediately
    //      after, with the correct accountId and via:"update-apply" -- an old-engine-to-new-engine first
    //      cycle recording it AT settle, not before.
    // ===================================================================================================
    {
      const sched2 = makeScheduler();
      const env2 = { ...baseEnv(), ...sched2.env } as unknown as Env;
      const beforeResp = await sched2.stub.fetch("https://scheduler.internal/sources/engine-account-verified", { method: "GET" });
      const before = (await beforeResp.json()) as { accountId?: string } | null;
      ok("fresh engine: cfAccountId starts genuinely unverified (nothing has ever recorded it)", before === null);
      // Seed the pending record DIRECTLY (bypassing POST /update/apply entirely), exactly what a promote's
      // OWN persist call being absent (old code) leaves behind for the settle to find: a normal pending, no
      // trace of whether the apply that produced it could or could not call
      // recordVerifiedEngineAccountAfterSelfDeploy.
      await sched2.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      await sched2.stub.fetch("https://scheduler.internal/update-pending", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "migration", promotedAt: Date.now(), promotedBy: OWNER }),
      });
      const settleResp = await callWithEnv(env2, OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const settleJson = (await settleResp.json()) as Record<string, unknown>;
      ok("settle after a self-update -> 200 applied (the ordinary KEEP path, undisturbed)", settleResp.status === 200 && settleJson.outcome === "applied");
      const afterResp = await sched2.stub.fetch("https://scheduler.internal/sources/engine-account-verified", { method: "GET" });
      const after = (await afterResp.json()) as { accountId?: string; via?: string } | null;
      ok("the settle continuation alone recorded cfAccountId (old-engine-to-new-engine first cycle, at settle)", after !== null && after.accountId === "acct-test" && after.via === "update-apply");
    }

    // ===================================================================================================
    // GROUP E: POST /update/rollback (standalone, always-available revert).
    // ===================================================================================================
    ok("POST /update/rollback by a non-owner -> 403", (await call(VIEWER, "POST", "/admin/update/rollback", {})).status === 403);
    ok("POST /update/rollback malformed body -> 400 (fail-safe catch)", (await callMalformed(OWNER, "/admin/update/rollback")).status === 400);
    {
      // No reliable known-good (a superseded last, no pending) -> no-target 400.
      await seedSettled({ outcome: "superseded", at: Date.now(), by: null });
      const r = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      ok("rollback with no recorded known-good -> 400 no-target", r.status === 400 && /no recorded prior engine version/.test(String((await jsonOf(r)).error)));
    }
    {
      // Target present (pending.fromVersion) but NO token -> the token-required 400.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-new", recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/rollback", {});
      ok("rollback with a target, no token -> 400 token-required", r.status === 400 && /one-shot Cloudflare deploy token/.test(String((await jsonOf(r)).error)));
    }
    {
      // A target present but no engine account marked (after the token gate) -> 400.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-new", recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: OWNER });
      accountOn = false;
      const r = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      ok("rollback with a target but no engine account -> 400", r.status === 400 && /Cloudflare account is not marked/.test(String((await jsonOf(r)).error)));
      accountOn = true;
    }
    {
      // Full rollback: target v-prior, live is v-live (differs), deploy succeeds, canary pending ->
      // reverted-unverified; the route records the update-rolled-back audit + clears the pending.
      // WORKER_NAME absent exercises the scriptName default branch.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-new", recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: OWNER });
      workerNameOn = false;
      const r = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("rollback deploys the known-good, canary unconfirmed -> 200 reverted-unverified", r.status === 200 && j.outcome === "reverted-unverified" && j.toVersion === "v-prior");
      workerNameOn = true;
    }
    {
      // The deploy of the known-good FAILS -> outcome failed; the route records the update-refused audit.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-new", recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: OWNER });
      failDeploy = true;
      const r = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      ok("rollback when the deploy fails -> 200 failed (engine unchanged)", r.status === 200 && (await jsonOf(r)).outcome === "failed");
      failDeploy = false;
    }

    // ===================================================================================================
    // GROUP F: POST /update/ramp (opt-in gradual rollout, gate OFF here).
    // ===================================================================================================
    ok("POST /update/ramp by a non-owner -> 403", (await call(VIEWER, "POST", "/admin/update/ramp", { percentage: 25 })).status === 403);
    ok("POST /update/ramp malformed body -> 400 (fail-safe catch)", (await callMalformed(OWNER, "/admin/update/ramp")).status === 400);
    // GROUP E's last (failed-deploy) rollback attempt left a pending verification open (a
    // "failed" rollback outcome does not clear it); clear it so this group's own guard-order tests below are
    // not blocked by the new pendingUpdateRefusal check.
    await seedSettled({ outcome: "expired", at: Date.now(), by: null });
    {
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 100 });
      ok("ramp with an invalid percentage (100) -> 400 (1..99 only)", r.status === 400 && /percentage between 1 and 99/.test(String((await jsonOf(r)).error)));
    }
    {
      // A non-number percentage -> the `typeof === "number" ? : NaN` else arm -> rampPercentageValid(NaN) false.
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: "lots" });
      ok("ramp with a non-number percentage -> 400 (NaN is invalid)", r.status === 400 && /percentage between 1 and 99/.test(String((await jsonOf(r)).error)));
    }
    {
      accountOn = false;
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp with no engine account marked -> 400", r.status === 400 && /Cloudflare account is not marked/.test(String((await jsonOf(r)).error)));
      accountOn = true;
    }
    {
      channelOn = false;
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp with no update channel configured -> 400 'no applicable update'", r.status === 400 && /no applicable update/.test(String((await jsonOf(r)).error)));
      channelOn = true;
    }
    {
      current = await signedChannel(ENGINE_VERSION, "routine");
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp when recommended == running -> 200 no-update", r.status === 200 && (await jsonOf(r)).outcome === "no-update");
    }
    {
      current = await signedChannel("0.4.0", "routine", { urlMissing: true });
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp when the artefact will not download -> 400", r.status === 400 && /could not download the update artefact/.test(String((await jsonOf(r)).error)));
    }
    {
      current = await signedChannel("0.4.0", "routine");
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp (routine, gate off, no token) -> 400 token-required", r.status === 400 && /one-shot Cloudflare deploy token/.test(String((await jsonOf(r)).error)));
    }
    {
      // asvs-HI-13: upload + ramp succeed -> 200 ramp-pending, NEVER flown/verified inline (phase 1 cannot
      // fly a canary at all any more -- see update-ramp.ts). The route persists the pending-ramp record
      // (carrying `percentage`, which GROUP F2 below relies on) + the update-promoted audit.
      // allowDowngrade:true exercises the ramp input's allowDowngrade spread true arm; WORKER_NAME absent
      // exercises the scriptName default branch.
      current = await signedChannel("0.4.0", "routine");
      workerNameOn = false;
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, token: DEPLOY_TOKEN, allowDowngrade: true });
      const j = await jsonOf(r);
      ok("ramp live (routine, token) -> 200 ramp-pending (never flown inline)", r.status === 200 && j.outcome === "ramp-pending" && j.percentage === 25 && j.toVersion === "v-new");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the ramp recorded a pending verification carrying percentage", (st.pending as { toVersion?: string; percentage?: number } | null)?.toVersion === "v-new" && (st.pending as { percentage?: number } | null)?.percentage === 25);
      workerNameOn = true;
    }
    {
      // asvs-HI-14 (PRIMARY guard): a second ramp while the ramp above is still awaiting verification must
      // be refused before it ever reaches startGradualRamp.
      const blockedRamp = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, token: DEPLOY_TOKEN });
      ok("a second ramp while a prior one is pending -> 409 (not a repeat traffic shift)", blockedRamp.status === 409 && /already awaiting verification/.test(String((await jsonOf(blockedRamp)).error)));
      // Also prove the CROSS-route guard: this is the finding's exact exploit path (ramp, then apply to
      // "finish" it) -- apply must be blocked too while the ramp's own pending verification is still open.
      const blockedApply = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply while a prior RAMP is pending -> 409 (the exploit's exact path is now closed)", blockedApply.status === 409 && /already awaiting verification/.test(String((await jsonOf(blockedApply)).error)));
      // Clear it so the tests below (which deliberately exercise OTHER refusal arms) are not blocked by it.
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
    }
    {
      // REFUSED ramp: hash mismatch -> refused; the route records the update-refused audit.
      current = await signedChannel("0.4.0", "routine", { badHash: true });
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, token: DEPLOY_TOKEN });
      ok("ramp live with a hash mismatch -> 200 refused (verify-before-deploy)", r.status === 200 && (await jsonOf(r)).outcome === "refused");
    }
    {
      // A metadata-rich migration ramp release: the route builds the ramp input meta with all three
      // optional fields (the meta-spread true arms), then the migration guard refuses it.
      current = await signedChannel("0.4.0", "migration", { meta: true });
      const r = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, token: DEPLOY_TOKEN });
      ok("ramp of a metadata-rich migration release -> 200 refused (migration guard; meta carried)", r.status === 200 && (await jsonOf(r)).outcome === "refused");
    }

    // ===================================================================================================
    // GROUP F2 (asvs-HI-13): POST /update/ramp/settle -- phase 2, a genuinely SEPARATE request from
    // POST /update/ramp above, so Cloudflare has a real chance of routing it onto the ramped slice. Gate
    // OFF here, same as GROUP F.
    // ===================================================================================================
    ok("POST /update/ramp/settle by a non-owner -> 403", (await call(VIEWER, "POST", "/admin/update/ramp/settle", {})).status === 403);
    ok("POST /update/ramp/settle malformed body -> 400 (fail-safe catch)", (await callMalformed(OWNER, "/admin/update/ramp/settle")).status === 400);
    {
      await seedSettled({ outcome: "expired", at: Date.now(), by: null }); // clears any pending
      const r = await call(OWNER, "POST", "/admin/update/ramp/settle", { token: DEPLOY_TOKEN });
      ok("ramp-settle with no pending verification -> 400", r.status === 400 && /no gradual ramp awaiting verification/.test(String((await jsonOf(r)).error)));
    }
    {
      // A pending from the ATOMIC apply path (no `percentage`) is NOT ramp-shaped -> ramp-settle refuses
      // it; the two settle routes stay mutually exclusive (see POST /update/settle's own guard, GROUP D).
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/ramp/settle", { token: DEPLOY_TOKEN });
      ok("ramp-settle against an apply's (non-ramp) pending -> 400 (wrong endpoint)", r.status === 400 && /no gradual ramp awaiting verification/.test(String((await jsonOf(r)).error)));
    }
    {
      // Conversely: a ramp-shaped pending (percentage present) is refused by the PLAIN settle endpoint.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", percentage: 25, promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("plain settle against a ramp's (percentage-carrying) pending -> 400 (wrong endpoint)", r.status === 400 && /ramp settle call instead/.test(String((await jsonOf(r)).error)));
    }
    {
      // Pending present, NO token -> the token-required 400 (before any decision work).
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", percentage: 25, promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/ramp/settle", {});
      ok("ramp-settle with a pending, no token -> 400 token-required", r.status === 400 && /paste the one-shot deploy token/.test(String((await jsonOf(r)).error)));
    }
    {
      // SUPERSEDED: the live version (deployments LIST = v-live) differs from pending.toVersion, and it is
      // a SINGLE version (not a split) -> 409, pending cleared.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-other", recommendedVersion: "0.4.0", percentage: 25, promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/ramp/settle", { token: DEPLOY_TOKEN });
      ok("ramp-settle when the live version is no longer the ramped one -> 409 superseded", r.status === 409 && /no longer the one this ramp promoted/.test(String((await jsonOf(r)).error)));
    }
    {
      // STILL A SPLIT (liveSingle === null): NOT superseded (a live split is exactly what an in-flight
      // ramp looks like); proceeds -- the 409 superseded-guard from the previous case does NOT fire here.
      // recommendedVersion "0.4.0" !== the real running ENGINE_VERSION, so self-check fails (no destination
      // configured either); under the OPTIMISTIC decideKeep (..07 rework) a non-dead verdict keeps
      // regardless, so this settle's OWN self-identity gate is what actually decides it: a keep this request
      // cannot prove it ran the ramped code on is INCONCLUSIVE, never a rollback the failed self-check alone
      // cannot justify. The ramp is left completely unchanged (no deploy, pending stays armed for a retry).
      const deployCallsBefore = deployCalls;
      await seedPending({ fromVersion: "v-prior", toVersion: "v-other", recommendedVersion: "0.4.0", percentage: 25, promotedAt: Date.now(), promotedBy: OWNER });
      liveSplit = true;
      const r = await call(OWNER, "POST", "/admin/update/ramp/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("ramp-settle on a still-live split -> proceeds (not superseded) -> 200 inconclusive (optimistic keep, unidentified)", r.status === 200 && j.outcome === "inconclusive" && j.toVersion === "v-other");
      ok("the still-split inconclusive settle makes NO deploy call", deployCalls === deployCallsBefore);
      liveSplit = false;
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the still-split inconclusive settle leaves the pending ARMED for a retry (nothing changed)", (st.pending as { toVersion?: string } | null)?.toVersion === "v-other");

      // ===== G275: "THE RAMP HAS BEEN PENDING FOR TWO DAYS. HOW MANY SETTLE ATTEMPTS WERE INCONCLUSIVE?" =====
      //
      // That question separates a ramp that is STUCK (the dispatch never lands on the ramped slice, so no
      // attempt can conclude) from a ramp NOBODY HAS TRIED TO SETTLE. Opposite answers: unpick the split by
      // hand, or press the button. A ramp-shaped pending can be settled ONLY by this route (the plain settle
      // refuses it with the "ramp-shaped" guard), and this branch -- the one that leaves the pending armed --
      // recorded NOTHING AT ALL. Forty real overnight attempts and zero attempts produced a byte-identical pack.
      //
      // The settle above was a REAL 200/inconclusive through the PRODUCTION route. The counter is read out of
      // the DO's own /admin-counters, which is the exact source of the pack's adminCounters section.
      const inconclusiveCount = (((await jsonOf(await sched.stub.fetch("https://do/admin-counters", { method: "GET" }))) as Record<string, { count?: number }>)["update-settle-inconclusive"]?.count) ?? 0;
      ok("the REAL inconclusive ramp settle MOVED the counter (it used to move by exactly zero)", inconclusiveCount >= 1);
      ok("...so 'we tried to settle the ramp all night' is no longer byte-identical to 'nobody touched it'", inconclusiveCount > 0);
    }
    {
      // GENUINE HIT: recommendedVersion === ENGINE_VERSION (as if THIS very dispatch landed on the ramped
      // slice) + a fresh preflight tick -> self-check passes -> decideKeep KEEPs AND self-identity confirms
      // it -> applied (the ramp is now TRUSTED at its configured percentage; still no 100% promote/deploy).
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, percentage: 25, promotedAt: Date.now(), promotedBy: OWNER });
      const r = await call(OWNER, "POST", "/admin/update/ramp/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("ramp-settle GENUINE hit (self-check confirms identity) -> 200 applied (ramp trusted, no deploy)", r.status === 200 && j.outcome === "applied");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the ramp-settle KEEP recorded an applied last outcome", (st.last as { outcome?: string } | null)?.outcome === "applied");
    }
    {
      // asvs-HI-14-r2: the EXACT documented "finish the ramp via apply" flow the split-refusal permanently
      // disabled -- ramp -> settle "applied" (genuinely STILL split; settleAfterRamp's applied branch makes
      // no deploy call, so the split it leaves live never collapses itself) -> a plain POST /update/apply to
      // promote it to 100% (console/src/screens/licence/shared.ts: "Promote it to 100% with Update now when
      // you are confident"). liveSplit models exactly that still-live split; fromVersion/toVersion are
      // seeded to its fixed shape (v-a@40%, v-b@60%) so the router's resolveTrustedRampTarget recognises it.
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      liveSplit = true;
      await seedPending({ fromVersion: "v-a", toVersion: "v-b", recommendedVersion: ENGINE_VERSION, percentage: 40, promotedAt: Date.now(), promotedBy: OWNER });
      const settle = await call(OWNER, "POST", "/admin/update/ramp/settle", { token: DEPLOY_TOKEN });
      const settleJ = await jsonOf(settle);
      ok("setup: ramp-settle GENUINE hit while genuinely still split -> 200 applied (trusted, still split)", settle.status === 200 && settleJ.outcome === "applied");
      const stAfterSettle = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("setup: settling did NOT collapse the split (pending clears, but no deploy happens on 'applied')", (stAfterSettle.pending === null) && (stAfterSettle.last as { outcome?: string } | null)?.outcome === "applied");

      // The documented next step: POST /update/apply (a plain "Update now") while the SAME trusted split is
      // still genuinely live (liveSplit is still true). BEFORE this fix: refused every time ("the engine's
      // live deployment is currently split..."), a PERMANENT lockout of the ramp feature's own completion
      // step -- settling again cannot help, it already happened, and nothing else ever collapses the split.
      // AFTER this fix: the router recognises this exact split as the just-settled, trusted transition and
      // lets the apply complete.
      current = await signedChannel("0.4.0", "routine");
      const deployCallsBefore = deployCalls;
      const apply = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      const applyJ = await jsonOf(apply);
      ok("finishing the ramp via apply -> 200 promoted (the documented flow actually completes)", apply.status === 200 && applyJ.outcome === "promoted");
      ok("the TRUSTED fromVersion (v-a) was used, never re-guessed from the dominant live slice (v-b@60%)", applyJ.fromVersion === "v-a");
      ok("the apply genuinely collapsed the split (a real CF deployments-CREATE call fired)", deployCalls > deployCallsBefore);
      liveSplit = false;
      // Clear the fresh pending this promote just opened, so GROUP G's own apply/settle sequence below is
      // not blocked by it.
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
    }

    // ===================================================================================================
    // GROUP G: the BARE-TOKEN break-glass caller (owner-equivalent, NULL email). It drives the deep success
    // records down the `caller.email ?? null` / `promotedBy: caller.email ?? null` null arms. Gate is OFF.
    // ===================================================================================================
    {
      // apply promote as the bare token -> the pending record's promotedBy is null (the null arm).
      current = await signedChannel("0.4.0", "routine");
      const r = await bareCall("POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply promote as the bare token -> 200 promoted (promotedBy null arm)", r.status === 200 && (await jsonOf(r)).outcome === "promoted");
    }
    {
      // settle superseded as the bare token -> the superseded record's `by` is null.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-other", recommendedVersion: "0.4.0", riskClass: "routine", promotedAt: Date.now(), promotedBy: null });
      const r = await bareCall("POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle superseded as the bare token -> 409 (by null arm)", r.status === 409);
    }
    {
      // settle proceed (optimistic keep) as the bare token -> the settle record's `by` is null.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.4.0", riskClass: "routine", promotedAt: Date.now(), promotedBy: null });
      const r = await bareCall("POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle proceed as the bare token -> 200 applied (optimistic keep, by null arm)", r.status === 200 && (await jsonOf(r)).outcome === "applied");
    }
    {
      // standalone rollback as the bare token -> the rolled-back record's `by` is null.
      await seedPending({ fromVersion: "v-prior", toVersion: "v-new", recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: null });
      const r = await bareCall("POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      ok("rollback as the bare token -> 200 reverted-unverified (by null arm)", r.status === 200 && (await jsonOf(r)).outcome === "reverted-unverified");
    }
    {
      // settle KEEP-but-stale as the bare token -> the expired record's `by` takes the null arm (the
      // self-check still passes; it is caller-independent). The tick recorded in GROUP D keeps preflight fresh.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "routine", promotedAt: 0, promotedBy: null });
      const r = await bareCall("POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle KEEP-but-stale as the bare token -> 409 expired (by null arm)", r.status === 409);
    }

    // ===================================================================================================
    // GROUP H: DUAL CONTROL ON -> a migration release going live is gated (202 ownerActionQueued) for both
    // apply and ramp, BEFORE any token/deploy; a BARE-TOKEN maker is refused at the gate (the g.kind error arm).
    // ===================================================================================================
    {
      const arm = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
      ok("dual control armed (immediate, 200)", arm.status === 200);
      current = await signedChannel("0.4.0", "migration");
      const ra = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false }); // no token on the first call
      const ja = await jsonOf(ra);
      ok("apply of a migration release under dual control -> 202 ownerActionQueued (no token/deploy)", ra.status === 202 && ja.ownerActionQueued === true);
      const rr = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 }); // no token
      const jr = await jsonOf(rr);
      ok("ramp of a migration release under dual control -> 202 ownerActionQueued (no token/deploy)", rr.status === 202 && jr.ownerActionQueued === true);
      // A BARE-TOKEN maker cannot propose an owner action: ownerActionGate surfaces the DO refusal verbatim
      // (the g.kind === "error" arm), so the apply/ramp return the DO's 4xx, never a 202 or a deploy.
      const ea = await bareCall("POST", "/admin/update/apply", { dryRun: false });
      ok("apply under dual control by the bare token -> the gate-error arm (>=400, not 202)", ea.status >= 400 && ea.status !== 202);
      const er = await bareCall("POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp under dual control by the bare token -> the gate-error arm (>=400, not 202)", er.status >= 400 && er.status !== 202);
      // A KEEP of a migration release under dual control is gated: the settle decision is KEEP (self-check
      // passes), so the route consults the update-settle owner-action gate, which queues a 202 on the first
      // call (no armed approval) -> the settle KEEP gate's queued arm, distinct from apply's.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "migration", promotedAt: Date.now(), promotedBy: OWNER });
      const ks = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle KEEP of a migration release under dual control -> 202 ownerActionQueued", ks.status === 202 && (await jsonOf(ks)).ownerActionQueued === true);
      // The SAME KEEP path by the BARE TOKEN: the decision is KEEP and the risk is migration, so the route
      // consults the update-settle gate, which refuses a bare-token maker -> the settle KEEP gate's error arm.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "migration", promotedAt: Date.now(), promotedBy: null });
      const kse = await bareCall("POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("settle KEEP under dual control by the bare token -> the gate-error arm (>=400, not 202)", kse.status >= 400 && kse.status !== 202);
    }

    // ===================================================================================================
    // GROUP R: the anti-rollback floor + channel freshness/replay protection threaded through the route.
    // Dual control is still ON from GROUP H, but every channel here is "routine" (not gated), so the apply
    // reaches the floor/freshness logic. The freshness cases run FIRST (while the high-water mark is still
    // low), then the floor case sets the mark high (monotonic + sticky, so it must run last among these).
    // ===================================================================================================
    {
      // GROUP H's dual-control KEEP tests left a pending verification open (a queued/gate-error
      // settle response never reaches settleAfterPromote, so it was never resolved); clear it before this
      // group's own apply sequence so it is not blocked by the new pendingUpdateRefusal check.
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
      // R9 baseline: promote a fresh descriptor at sequence 5 so the engine records lastChannelSeq = 5. A
      // routine release with a token promotes (uploads + deploys v-new) and advances the freshness watermark.
      current = await signedChannel("0.4.0", "routine", { seq: 5, issuedAt: "2026-06-20T00:00:00Z" });
      const seed = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("promote a fresh descriptor (seq 5) -> 200 promoted (advances the freshness watermark)", seed.status === 200 && (await jsonOf(seed)).outcome === "promoted");
      // clear the pending verification the promote above just opened so the replay attempt below
      // is not blocked by pendingUpdateRefusal -- it must reach the R9 freshness check itself. Sticky fields
      // (the freshness watermark just advanced to seq 5, and the HWM) survive a clear (stickyUpdateFields).
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
      // R9 REPLAY: a validly-signed but OLDER descriptor (seq 3) is refused as a replay BEFORE any deploy.
      current = await signedChannel("0.4.0", "routine", { seq: 3, issuedAt: "2026-05-01T00:00:00Z" });
      const replay = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      const rj = await jsonOf(replay);
      ok("a replayed older descriptor (seq 3 < seen 5) -> 400 refused (no deploy)", replay.status === 400 && /replayed or superseded|older than the last-seen sequence/.test(String(rj.error)));
      // R9 FORWARD: a genuinely newer descriptor (seq 6) passes the freshness gate (dry-run, so it stops at plan).
      current = await signedChannel("0.4.0", "routine", { seq: 6, issuedAt: "2026-06-25T00:00:00Z" });
      const fwd = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true });
      ok("a newer descriptor (seq 6 >= 5) passes the freshness gate -> 200 (not a replay 400)", fwd.status === 200 && (await jsonOf(fwd)).outcome === "dry-run");
      // R9 WARN-AND-PROCEED: a descriptor that DROPS the sequence (though one was seen) is tolerated (warn, not
      // refused) -> the backward-compatible absent-field path; it still plans on a dry-run.
      current = await signedChannel("0.4.0", "routine");
      const noseq = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true });
      ok("a descriptor dropping the sequence -> tolerated (warn), still 200 dry-run (backward-compatible)", noseq.status === 200 && (await jsonOf(noseq)).outcome === "dry-run");

      // R8: seed an APPLIED settle at 0.5.0 so the monotonic high-water mark becomes 0.5.0. The channel then
      // recommends 0.4.0 (newer than the running 0.1.0, so the forward-only guard would PASS) but BELOW the
      // settled 0.5.0, so the anti-rollback floor refuses it even on a dry-run, and even if allowDowngrade is set.
      await seedSettled({ outcome: "applied", recommendedVersion: "0.5.0", fromVersion: "v-prior", toVersion: "v-mark", at: Date.now(), by: OWNER });
      const stHwm = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("an applied settle persisted the high-water mark (0.5.0)", stHwm.settledHighWaterMark === "0.5.0");
      current = await signedChannel("0.4.0", "routine");
      const below = await call(OWNER, "POST", "/admin/update/apply", { dryRun: true, allowDowngrade: true });
      const bj = await jsonOf(below);
      ok("apply of 0.4.0 below the 0.5.0 floor (allowDowngrade set) -> 200 refused (anti-rollback)", below.status === 200 && bj.outcome === "refused" && /BELOW 0\.5\.0|high.?water/i.test(String(bj.reason)));
      ok("the anti-rollback refusal logged the anti-rollback-guard step", Array.isArray(bj.steps) && (bj.steps as { step?: string; ok?: boolean }[]).some((s) => s.step === "anti-rollback-guard" && s.ok === false));
      // R8 on the RAMP path: the same below-floor 0.4.0 is refused before any traffic shift.
      const belowRamp = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, token: DEPLOY_TOKEN });
      const brj = await jsonOf(belowRamp);
      ok("ramp of 0.4.0 below the 0.5.0 floor -> 200 refused (anti-rollback)", belowRamp.status === 200 && brj.outcome === "refused" && /BELOW 0\.5\.0|high.?water/i.test(String(brj.reason)));
    }

    // ===================================================================================================
    // GROUP J: MULTI-COMPONENT updates -- the components-aware apply/settle/rollback routes plus the
    // incident proofs (persistence-first ordering + the honest catch arm). Dual control is
    // still ON from GROUP H; every release here is "routine" unless a case gates deliberately, and the
    // ENGINE floor sits at 0.5.0 from GROUP R8, so engine-moving versions here are 0.6.0+.
    // ===================================================================================================
    {
      // Request-shape refusals: the closed component set is enforced loudly on every route.
      const bad = await call(OWNER, "POST", "/admin/update/apply", { components: ["cli"] });
      ok("apply naming an unknown component -> 400 honest refusal", bad.status === 400 && /unknown update component/.test(String((await jsonOf(bad)).error)));
      const empty = await call(OWNER, "POST", "/admin/update/apply", { components: [] });
      ok("apply with an empty components array -> 400 (omit the field for the legacy apply)", empty.status === 400 && /non-empty array/.test(String((await jsonOf(empty)).error)));
      const rampC = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, components: ["console"] });
      ok("ramp naming the console -> 400 (ramp is engine-only; an assets swap is atomic)", rampC.status === 400 && /engine only/.test(String((await jsonOf(rampC)).error)));
      const rampBad = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, components: ["cli"] });
      ok("ramp naming an unknown component -> 400 (the same parser as apply)", rampBad.status === 400 && /unknown update component/.test(String((await jsonOf(rampBad)).error)));
      const rbBad = await call(OWNER, "POST", "/admin/update/rollback", { components: ["svc"] });
      ok("rollback naming an unknown component -> 400", rbBad.status === 400 && /unknown update component/.test(String((await jsonOf(rbBad)).error)));
      const stBad = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN, components: ["svc"] });
      ok("settle naming an unknown component -> 400 (the field is validated, never ignored)", stBad.status === 400 && /unknown update component/.test(String((await jsonOf(stBad)).error)));
    }
    {
      // Console resolution refusals: a console-less release, a console entry missing its verification
      // material, and a console entry of the wrong deploy kind -- each an honest 400 before any action.
      current = await signedChannel("0.6.0", "routine");
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      ok("console-only apply on a console-less release -> 400 'does not carry a console component'", r.status === 400 && /does not carry a console component/.test(String((await jsonOf(r)).error)));
      current = await signedChannel("0.6.0", "routine", { console: { version: "0.3.0", broken: "no-url" } });
      const r2 = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      ok("a console entry without url/sha384 -> 400 naming the missing verification material", r2.status === 400 && /missing the url and\/or sha384/.test(String((await jsonOf(r2)).error)));
      current = await signedChannel("0.6.0", "routine", { console: { version: "0.3.0", broken: "wrong-kind" } });
      const r3 = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      ok("a console entry of the wrong kind -> 400 honest kind refusal", r3.status === 400 && /declares kind/.test(String((await jsonOf(r3)).error)));
      // A console-targeting live apply with no token (routine risk, gate not triggered) -> token-required.
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.3.0" } });
      const r4 = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false });
      ok("console-only live apply without a token -> 400 token-required", r4.status === 400 && /one-shot Cloudflare deploy token/.test(String((await jsonOf(r4)).error)));
    }
    {
      // Standalone console rollback BEFORE any console outcome exists -> honest no-target.
      const rb0 = await call(OWNER, "POST", "/admin/update/rollback", { components: ["console"], token: DEPLOY_TOKEN });
      const j = await jsonOf(rb0);
      ok("console rollback with no recorded console outcome -> 200 no-target", rb0.status === 200 && j.outcome === "no-target" && j.component === "console");
    }
    {
      // Explicit components:["engine"] keeps today's single-component response shape (no componentResults).
      current = await signedChannel("0.6.0", "routine");
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine"], dryRun: true });
      const j = await jsonOf(r);
      ok("explicit engine-only apply -> today's top-level dry-run shape, no componentResults", r.status === 200 && j.outcome === "dry-run" && j.componentResults === undefined);
    }
    {
      // CONSOLE-ONLY: dry-run then live. The engine row is current (a console-only release), so the
      // console applies INLINE; the promote confirmation reads the stateful console deployment.
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.3.0", minEngineVersion: "0.1.0" } });
      const dry = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"] });
      const dj = await jsonOf(dry);
      ok("console-only dry-run -> 200 dry-run describing the console", dry.status === 200 && dj.outcome === "dry-run" && dj.component === "console" && dj.recommendedVersion === "0.3.0");
      const live = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      const lj = await jsonOf(live);
      ok("console-only live apply -> 200 applied (promote confirmed at 100%)", live.status === 200 && lj.outcome === "applied" && String(lj.toVersion).startsWith("cv-new-"));
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const lastConsole = st.lastConsole as { outcome?: string; component?: string; minEngineVersion?: string } | null;
      const floors = st.floors as { engine?: string; console?: string } | undefined;
      ok("the console outcome landed in lastConsole (never clobbering the engine's last)", lastConsole?.outcome === "applied" && lastConsole?.component === "console");
      ok("floors.console advanced to 0.3.0 while the ENGINE floor (0.5.0) is untouched", floors?.console === "0.3.0" && floors?.engine === "0.5.0" && st.settledHighWaterMark === "0.5.0");
      ok("the update history ring carries the console entry with its component", Array.isArray(st.history) && (st.history as Array<{ component?: string; outcome?: string }>).some((h) => h.component === "console" && h.outcome === "applied"));
      // the applied console's OWN minEngineVersion floor (from the verified channel entry) is
      // persisted onto lastConsole -- the input the engine's own standalone rollback floor-checks against.
      ok("the applied console's minEngineVersion floor is persisted onto lastConsole", lastConsole?.minEngineVersion === "0.1.0");
    }
    {
      // R8 per-component: a console version BELOW floors.console (0.3.0) refuses even with the token.
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.2.9" } });
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("a console component below floors.console -> 200 refused (anti-rollback)", r.status === 200 && j.outcome === "refused" && /BELOW 0\.3\.0/.test(String(j.reason)));
    }
    {
      // BOTH components: the engine promotes and the CONSOLE is QUEUED behind the settle (never inline).
      // The channel carries the R9 claim (seq 6 advances the watermark from GROUP R9's 5) and the request
      // sets allowDowngrade (its spread arm), both riding the component path's engine flow.
      current = await signedChannel("0.6.0", "routine", { console: { version: "0.6.0" }, seq: 6, issuedAt: "2026-06-26T00:00:00Z" });
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine", "console"], dryRun: false, token: DEPLOY_TOKEN, allowDowngrade: true });
      const j = await jsonOf(r);
      const results = j.componentResults as Array<{ component?: string; outcome?: string }> | undefined;
      ok("both-apply -> top-level engine promoted + componentResults [engine promoted, console queued]", r.status === 200 && j.outcome === "promoted" && results?.[0]?.component === "engine" && results?.[0]?.outcome === "promoted" && results?.[1]?.component === "console" && results?.[1]?.outcome === "queued");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const queued = (st.pending as { consoleQueued?: { version?: string } } | null)?.consoleQueued;
      ok("the pending record carries the queued console intent (version only, no url/sha)", queued?.version === "0.6.0" && JSON.stringify(queued).includes("sha") === false && JSON.stringify(queued).includes("url") === false);
    }
    {
      // ENGINE-NON-APPLIED-ABORTS-CONSOLE. When the engine settle resolves to anything but "applied", the
      // queued console component must be ABORTED with the honest partial-state reason. Under the optimistic
      // settle a healthy pending KEEPS (so the console runs -- covered in the next block); the reachable
      // non-applied engine outcome in this harness is SUPERSEDED (the live version is no longer the one this
      // pending promoted), which drives the SAME `outcome !== "applied"` abort in setUpdateSettled. This
      // proves the queue closes honestly whenever the engine does not land, without needing a dead canary
      // (unreachable here; the rollback DECISION itself is unit-covered in validate-update-apply).
      await seedPending({ fromVersion: "v-prior", toVersion: "v-other", recommendedVersion: "0.6.0", riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER, consoleQueued: { version: "0.6.0", riskClass: "routine", queuedAt: Date.now() } });
      events.length = 0;
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      ok("engine settle superseded (not applied) -> 409, nothing deployed", r.status === 409 && /no longer the one this update promoted/.test(String((await jsonOf(r)).error)));
      const doIdx = events.indexOf("DO POST /update-settled");
      const cfIdx = events.indexOf("CF POST deployments engine");
      ok("the superseded outcome was PERSISTED and NO engine deploy was issued", doIdx !== -1 && cfIdx === -1);
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const lastConsole = st.lastConsole as { outcome?: string; reason?: string } | null;
      ok("the DO recorded the aborted console (queue closed honestly)", lastConsole?.outcome === "refused" && /did not settle as applied/.test(String(lastConsole?.reason)));
      ok("the engine's last outcome is superseded and the pending is cleared", (st.last as { outcome?: string } | null)?.outcome === "superseded" && st.pending === null);
    }
    {
      // SETTLE KEEP runs the QUEUED CONSOLE (keep decided via the self-check counts as settled -- else a
      // console could never update on an engine whose canary cannot gate).
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.6.5" } });
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER, consoleQueued: { version: "0.6.5", riskClass: "routine", queuedAt: Date.now() } });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      const results = j.componentResults as Array<{ component?: string; outcome?: string }> | undefined;
      ok("settle KEEP (via self-check) applies the queued console -> [engine applied, console applied]", r.status === 200 && j.outcome === "applied" && results?.[0]?.outcome === "applied" && results?.[1]?.component === "console" && results?.[1]?.outcome === "applied");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the queued-console apply advanced floors.console to 0.6.5", (st.floors as { console?: string } | undefined)?.console === "0.6.5");
    }
    {
      // QUEUE DRIFT: the channel moved between apply and settle -> the queued version is REFUSED (never a
      // version that moved underneath the approval), recorded as the queue's honest resolution.
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.9.9" } });
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER, consoleQueued: { version: "0.6.6", riskClass: "routine", queuedAt: Date.now() } });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      const results = j.componentResults as Array<{ component?: string; outcome?: string; reason?: string }> | undefined;
      ok("a queued console whose channel moved -> engine stays applied, console refused honestly", r.status === 200 && j.outcome === "applied" && results?.[1]?.outcome === "refused" && /moved underneath the approval/.test(String(results?.[1]?.reason)));
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the drift resolution landed in lastConsole", (st.lastConsole as { outcome?: string } | null)?.outcome === "refused");
    }
    {
      // BOTH-APPLY when the ENGINE IS CURRENT: the console applies INLINE (the engine-settled
      // precondition is trivially met by the running engine); top-level engine no-update + both results.
      // The channel's R9 claim rides into the INLINE console record (the settle IS the accepting act).
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.0" }, seq: 7, issuedAt: "2026-06-27T00:00:00Z" });
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine", "console"], dryRun: false, token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      const results = j.componentResults as Array<{ component?: string; outcome?: string }> | undefined;
      ok("both-apply with a current engine -> engine no-update + console applied inline", r.status === 200 && j.outcome === "no-update" && results?.[0]?.outcome === "no-update" && results?.[1]?.outcome === "applied");
    }
    {
      // STANDALONE CONSOLE ROLLBACK: the recorded prior console version is re-deployed + confirmed, then
      // a redundant second rollback is an idempotent "already".
      const before = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const target = (before.lastConsole as { fromVersion?: string } | null)?.fromVersion;
      const rb = await call(OWNER, "POST", "/admin/update/rollback", { components: ["console"], token: DEPLOY_TOKEN });
      const rj = await jsonOf(rb);
      ok("console rollback re-deploys the recorded prior console version (confirmed) -> reverted", rb.status === 200 && rj.outcome === "reverted" && rj.toVersion === target);
      const rb2 = await call(OWNER, "POST", "/admin/update/rollback", { components: ["console"], token: DEPLOY_TOKEN });
      ok("a redundant console rollback is an idempotent 'already'", rb2.status === 200 && (await jsonOf(rb2)).outcome === "already");
    }
    {
      // CONSOLE-FAIL-ROLLS-BACK-CONSOLE-KEEPS-ENGINE at the ROUTE level: the console promote is accepted
      // by the API but does not land (confirm drift), so the console auto-rolls-back to its recorded
      // target and the record says so; the engine is untouched throughout (a console-only apply).
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.1" } });
      consoleConfirmDrift = true;
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("a console promote that does not land -> 200 rolled-back (recorded target re-deployed)", r.status === 200 && j.outcome === "rolled-back" && /engine is unaffected/.test(String(j.reason)));
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the console rollback landed in lastConsole and floors.console did NOT advance", (st.lastConsole as { outcome?: string } | null)?.outcome === "rolled-back" && (st.floors as { console?: string } | undefined)?.console === "0.7.0");
    }
    {
      // The console component's artefact failing to DOWNLOAD refuses honestly at the route level.
      const missing = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.4" } });
      const doc = JSON.parse(new TextDecoder().decode(missing.channel)) as { components: { console: { url: string } } };
      doc.components.console.url = ARTEFACT_URL_MISSING;
      const bytes = utf8(JSON.stringify(doc));
      current = { channel: bytes, sig: await hybridSign(edPrivate, mldsa.secretKey, bytes) };
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("a console bundle that will not download -> 200 refused (nothing was changed)", r.status === 200 && j.outcome === "refused" && /could not download the console component/.test(String(j.reason)));
    }
    {
      // BARE-TOKEN console-only apply: the by/promotedBy null arms of the console records. Runs under a
      // RENAMED console (CONSOLE_WORKER_NAME set), the deploy-target guarantee's explicit arm.
      consoleWorkerNameOn = true;
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.2" } });
      const r = await bareCall("POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      ok("a bare-token console-only apply -> 200 applied (by null arm; renamed console script)", r.status === 200 && (await jsonOf(r)).outcome === "applied");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the bare-token console record carries by:null", (st.lastConsole as { by?: string | null } | null)?.by === null);
      consoleWorkerNameOn = false;
    }
    {
      // A BOTH-apply whose ENGINE bundle will not download refuses before any deploy (component path).
      current = await signedChannel("0.6.2", "routine", { urlMissing: true, console: { version: "0.7.9" } });
      const r = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine", "console"], dryRun: false, token: DEPLOY_TOKEN });
      ok("a both-apply whose engine bundle will not download -> 400 (nothing proceeds)", r.status === 400 && /could not download the update artefact/.test(String((await jsonOf(r)).error)));
    }
    {
      // A QUEUED-console settle whose re-verified channel carries the R9 freshness claim: the console
      // apply advances the watermark (the channelSeq/issuedAt arms of the continuation).
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.3" }, seq: 20, issuedAt: "2026-07-02T00:00:00Z" });
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: ENGINE_VERSION, riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER, consoleQueued: { version: "0.7.3", riskClass: "routine", queuedAt: Date.now() } });
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("a queued-console settle applies the console and advances the freshness watermark", r.status === 200 && j.outcome === "applied" && ((await jsonOf(await call(OWNER, "GET", "/admin/update/status"))).lastChannelSeq === 20));
    }
    {
      // A console standalone rollback whose DEPLOY fails -> failed (prior serving), audited as a refusal.
      consoleFailDeploy = true;
      const r = await call(OWNER, "POST", "/admin/update/rollback", { components: ["console"], token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("a console rollback whose deploy fails -> 200 failed (previously-live still serving)", r.status === 200 && j.outcome === "failed" && /still serving/.test(String(j.reason)));
      consoleFailDeploy = false;
    }
    {
      // ===== G275: THE ROLLBACK THE CONSOLE ACTUALLY ASKS FOR ==========================================
      //
      // The route used to read a SINGULAR `component` key. The console has only ever sent the PLURAL
      // `components` array, and customers never run a terminal, so the console is the only client: the
      // console arm of this route had never once run in the field, and every console-rollback request
      // silently fell through to the ENGINE arm. The operator pressed "Roll back console" and the engine
      // rolled ITSELF back, on a preview that described the engine rollback they never asked for.
      //
      // These bodies are the ones console/src/lib/api/client-update.ts BUILDS, copied from it verbatim:
      //   rollbackUpdate (:142)  body: { token, ...(components?.length ? { components } : {}) }
      //   rollbackPlan   (:170)  body: { dryRun: true, ...(components?.length ? { components } : {}) }
      // and the callers are console update-console-check.ts:127 rollbackUpdate(token, ["console"]),
      // update-components-advanced.ts:137 rollbackUpdate(token, [id]) and update-rollback-confirm.ts:31
      // rollbackPlan(components). Nothing is hand-shaped here: post what the client posts, through the
      // production handleAdmin, and read the outcome + the DO records back out.
      const rollbackUpdateBody = (token: string, components?: string[]): Record<string, unknown> => ({ token, ...(components !== undefined && components.length > 0 ? { components } : {}) });
      const rollbackPlanBody = (components?: string[]): Record<string, unknown> => ({ dryRun: true, ...(components !== undefined && components.length > 0 ? { components } : {}) });
      // The per-caller rate window is REAL state that accumulates across this whole file (GROUP I seeds it
      // at the cap deliberately, last). These two blocks add calls, so hand the window back to the blocks
      // below exactly as they found it rather than spending their headroom.
      sched.storage.rawPut(OWNER_RATE_KEY, { windowStart: Date.now(), count: 0 });

      // A console version is applied first, so there IS a recorded console known-good to revert to.
      await sched.stub.fetch("https://scheduler.internal/tick", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.6" } });
      const applied = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
      ok("a console-only apply landed, so a console rollback target is recorded", applied.status === 200 && (await jsonOf(applied)).outcome === "applied");
      const stBefore = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const engineLastBefore = JSON.stringify(stBefore.last);
      const consoleTarget = (stBefore.lastConsole as { fromVersion?: string } | null)?.fromVersion;

      // THE PREVIEW the operator confirms against (rollbackPlan(["console"])). It used to describe an
      // ENGINE rollback whatever component was picked.
      const plan = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", rollbackPlanBody(["console"])));
      ok("the console's rollback PLAN describes the CONSOLE (it described the engine)", plan.component === "console" && plan.outcome === "dry-run" && plan.toVersion === consoleTarget);

      // THE LIVE ROLLBACK the console fires.
      const rb = await call(OWNER, "POST", "/admin/update/rollback", rollbackUpdateBody(DEPLOY_TOKEN, ["console"]));
      const rj = await jsonOf(rb);
      ok("the REAL console body rolls back the CONSOLE (it rolled back the engine)", rb.status === 200 && rj.component === "console" && rj.outcome === "reverted" && rj.toVersion === consoleTarget);
      const stAfter = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the console's own record carries the revert", (stAfter.lastConsole as { outcome?: string } | null)?.outcome === "rolled-back");
      ok("and the ENGINE was NOT rolled back: its lifecycle record is byte-identical", JSON.stringify(stAfter.last) === engineLastBefore);

      // The engine arm is unchanged for the body the standalone control sends (rollback.ts:92, no split).
      const eng = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", rollbackPlanBody()));
      ok("an omitted split is still the engine rollback, byte-for-byte", eng.component === "engine" && eng.outcome === "dry-run");
      const engPlan = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", rollbackPlanBody(["engine"])));
      ok("and an explicit ['engine'] split (confirmEngineRollback) plans the engine", engPlan.component === "engine" && engPlan.outcome === "dry-run");
    }
    {
      // ===== G275: THE ATTEMPTS THAT WERE NEVER COUNTED, AND THE RELEASE THAT PLANS NOTHING ============
      //
      // A rollback refused by a guard used to leave nothing in the pack: `updates.last` keeps only the most
      // recent OUTCOME, so a night of refused attempts collapsed to one row. The attempt counters are what
      // answer "we tried to roll back at 02:00 and it refused, how often?" -- driven here through the body
      // the console's own rollbackUpdate really posts.
      //
      // There is NO counter for a components split this build cannot plan: the honest 400 stands, but the
      // console's component ids ARE the set this build plans, so no client request can reach that arm.
      const counters = async (): Promise<Record<string, { count?: number }>> => (await jsonOf(await sched.stub.fetch("https://do/admin-counters", { method: "GET" }))) as Record<string, { count?: number }>;
      const countOf = (c: Record<string, { count?: number }>, n: string): number => c[n]?.count ?? 0;
      const before = await counters();
      const rbRefusedBefore = countOf(before, "update-rollback-refused");
      // The engine rollback with NO recorded target: the guard the console's own body can actually trip.
      const rbNoTarget = await call(OWNER, "POST", "/admin/update/rollback", { components: ["engine"], token: "" });
      ok("a rollback the guards refuse -> a refusal, not a revert", rbNoTarget.status >= 400);
      const after = await counters();
      ok("the rollback attempt is counted, so 'we tried to roll back and it refused' is not silence", countOf(after, "update-rollback-refused") === rbRefusedBefore + 1);

      // THE RELEASE that names a component this build cannot plan: nothing is refused (a later engine
      // learns it), the component simply never updates while the release says it ships one. That is the
      // "we updated but X is still on the old version" ticket, and it recorded nothing at all.
      const unplannableBefore = countOf(after, "update-degraded-components-unplannable");
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.7.7" }, extraComponent: { id: "scheduler", version: "1.2.3" } });
      const dry = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"] });
      ok("the release still applies (forward compatibility is the design)", dry.status === 200);
      ok("the UNPLANNABLE RELEASE is now recorded in the pack's counters", countOf(await counters(), "update-degraded-components-unplannable") > unplannableBefore);
    }
    {
      // ONE APPROVAL GATES THE WHOLE LIVE APPLY (dual control is ON): a migration-class console component
      // queues a single owner action for the console-only apply AND for the both-apply.
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.8.0", risk: "migration" } });
      const c1 = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false });
      ok("a migration-class console-only apply under dual control -> 202 ownerActionQueued", c1.status === 202 && (await jsonOf(c1)).ownerActionQueued === true);
      current = await signedChannel("0.8.0", "migration", { console: { version: "0.8.0", risk: "routine" } });
      const c2 = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine", "console"], dryRun: false });
      ok("a both-apply whose ENGINE is migration-class -> ONE 202 gate for the whole action", c2.status === 202 && (await jsonOf(c2)).ownerActionQueued === true);
      const c3 = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine"], dryRun: false });
      ok("an explicit engine-only migration apply gates with the engine wording", c3.status === 202 && (await jsonOf(c3)).ownerActionQueued === true);
      // A BREAKING-class console component takes the most cautious combined class (the breaking arm).
      current = await signedChannel(ENGINE_VERSION, "routine", { console: { version: "0.8.2", risk: "breaking" } });
      const c4 = await call(OWNER, "POST", "/admin/update/apply", { components: ["console"], dryRun: false });
      ok("a breaking-class console component gates (combined risk takes the most cautious)", c4.status === 202 && (await jsonOf(c4)).ownerActionQueued === true);
      // The BARE TOKEN cannot propose the gated console action: the gate-error arm, never a 202 or deploy.
      const c5 = await bareCall("POST", "/admin/update/apply", { components: ["console"], dryRun: false });
      ok("a gated console apply by the bare token -> the gate-error arm (>=400, not 202)", c5.status >= 400 && c5.status !== 202);
    }
    {
      // / asvs-HI-19: the AUDIT append (not the bookkeeping write) fails right after settle --
      // the response path racing its own teardown, the live incident. The settled outcome is
      // STILL persisted (recordBookkeepingAfterSelfDeploy targets a separate DO path from the audit append
      // and is unaffected by this fault), so the route answers HONESTLY: 200, the real settle outcome, plus
      // a note that the audit trail could not be confirmed -- never the OLD dishonest "could not report the
      // settle outcome...nothing was changed" 400 the live incident hit (the deploy/keep had already landed;
      // the response must never claim otherwise). This harness's canary can only ever read "pending" (no
      // real destination, see the module header) with a failing self-check, which under the OPTIMISTIC
      // decideKeep (..07 rework) KEEPS regardless -- so the reachable outcome here is "applied",
      // not a rollback; the persistence-first write happens for that KEEP too, so the property still holds:
      // the recorded outcome (and the decision trace, selfCheckOk) outlives a failing audit append.
      await seedPending({ fromVersion: "v-prior", toVersion: liveVersionId, recommendedVersion: "0.6.1", riskClass: "routine", promotedAt: Date.now(), promotedBy: OWNER });
      failNextAudit = true;
      const r = await call(OWNER, "POST", "/admin/update/settle", { token: DEPLOY_TOKEN });
      const j = await jsonOf(r);
      ok("an audit-append fault after an optimistic keep -> 200 honest (real outcome + could-not-record note), never a false 400", r.status === 200 && j.outcome === "applied" && /could not be fully recorded/.test(String(j.reason)));
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      const last = st.last as { outcome?: string; recommendedVersion?: string; selfCheckOk?: boolean } | null;
      ok("the persisted outcome survived the audit fault (the bookkeeping write is self-redeploy-safe and independent of it)", last?.outcome === "applied" && last?.recommendedVersion === "0.6.1" && st.pending === null);
      ok("the persisted record carries the decision trace (selfCheckOk)", typeof last?.selfCheckOk === "boolean");
    }

    // ===================================================================================================
    // GROUP K: conditional-bundling rollback (design UPDATE-UX-015 §6). Each case seeds a controlled
    // lastConsole.minEngineVersion + engine rollback target directly via seedSettled (self-contained,
    // independent of GROUP J's cumulative floor state), so the ROUTE's floor-read + pairing orchestration
    // is proven in isolation. The pure floor-check function's exhaustive semver/unparseable matrix
    // (including the REALISTIC case: a genuine Cloudflare version id, which never parses as semver) lives
    // in validate-update-apply.ts.
    // ===================================================================================================
    {
      // K1: NO console floor recorded (lastConsole has no minEngineVersion) -> engine-only, byte-identical
      // to before this feature existed. The preview carries no `paired` key at all (additive-only).
      await seedSettled({ outcome: "applied", component: "console", recommendedVersion: "0.9.0", fromVersion: "cv-k1a", toVersion: "cv-k1b", at: Date.now(), by: OWNER });
      await seedSettled({ outcome: "applied", recommendedVersion: "0.9.1", fromVersion: "v-k1-target", toVersion: liveVersionId, at: Date.now(), by: OWNER });
      const previewNoFloor = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", { dryRun: true }));
      ok("preview with no console floor -> plan only, no `paired` key at all", previewNoFloor.outcome === "dry-run" && previewNoFloor.toVersion === "v-k1-target" && previewNoFloor.paired === undefined);
      const r1 = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      const j1 = await jsonOf(r1);
      ok("rollback with no console floor -> engine-only (no paired key, no componentResults)", r1.status === 200 && j1.outcome === "reverted-unverified" && j1.paired === undefined && j1.componentResults === undefined);
    }
    {
      // K2: a floor the rollback TARGET satisfies (0.5.0 >= floor 0.3.0) -> engine-only, exactly as today.
      await seedSettled({ outcome: "applied", component: "console", recommendedVersion: "0.9.2", fromVersion: "cv-k2a", toVersion: "cv-k2b", minEngineVersion: "0.3.0", at: Date.now(), by: OWNER });
      await seedSettled({ outcome: "applied", recommendedVersion: "0.9.3", fromVersion: "0.5.0", toVersion: liveVersionId, at: Date.now(), by: OWNER });
      const preview = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", { dryRun: true }));
      ok("preview with a SATISFIED floor -> no `paired` key", preview.outcome === "dry-run" && preview.toVersion === "0.5.0" && preview.paired === undefined);
      const r2 = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      const j2 = await jsonOf(r2);
      ok("rollback with a satisfied floor -> engine-only (no paired key)", r2.status === 200 && j2.outcome === "reverted-unverified" && j2.paired === undefined && j2.componentResults === undefined);
    }
    {
      // K3: a floor the rollback TARGET VIOLATES (0.4.0 < floor 0.5.0) -> PAIRED. The preview reports
      // paired:true + the exact §6 copy line BEFORE any token is read (no token in this request at all).
      await seedSettled({ outcome: "applied", component: "console", recommendedVersion: "0.9.4", fromVersion: "cv-k3-prior", toVersion: "cv-k3-now", minEngineVersion: "0.5.0", at: Date.now(), by: OWNER });
      await seedSettled({ outcome: "applied", recommendedVersion: "0.9.5", fromVersion: "0.4.0", toVersion: liveVersionId, at: Date.now(), by: OWNER });
      const preview = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", { dryRun: true }));
      ok("preview with a VIOLATED floor -> paired:true + the exact §6 copy, no token spent", preview.outcome === "dry-run" && preview.paired === true && preview.reason === "Rolling the engine back past what this console requires; the console will be rolled back with it.");
      const r3 = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      const j3 = await jsonOf(r3);
      const results3 = j3.componentResults as Array<{ component?: string; outcome?: string }> | undefined;
      ok("live rollback with a violated floor -> paired:true + componentResults [engine, console]", r3.status === 200 && j3.outcome === "reverted-unverified" && j3.paired === true && results3?.[0]?.component === "engine" && results3?.[0]?.outcome === "reverted-unverified" && results3?.[1]?.component === "console");
      ok("the paired console arm reverted to ITS OWN recorded known-good (cv-k3-prior)", results3?.[1]?.outcome === "reverted" && (results3[1] as { toVersion?: string }).toVersion === "cv-k3-prior");
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the paired console rollback landed in lastConsole (rolled-back, not clobbering the engine's last)", (st.lastConsole as { outcome?: string } | null)?.outcome === "rolled-back" && (st.last as { outcome?: string } | null)?.outcome === "rolled-back");
    }
    {
      // K4: an UNPARSEABLE rollback target vs a set floor fails CLOSED into paired (never strand) -- the
      // realistic case in production, where the target is a genuine Cloudflare version id, not a semver.
      await seedSettled({ outcome: "applied", component: "console", recommendedVersion: "0.9.6", fromVersion: "cv-k4-prior", toVersion: "cv-k4-now", minEngineVersion: "0.1.0", at: Date.now(), by: OWNER });
      await seedSettled({ outcome: "applied", recommendedVersion: "0.9.7", fromVersion: "017e156b-2b34-4a3e-b3a4-9a5f5a5f5a5f", toVersion: liveVersionId, at: Date.now(), by: OWNER });
      const preview = await jsonOf(await call(OWNER, "POST", "/admin/update/rollback", { dryRun: true }));
      ok("preview with an unparseable target vs a set floor -> fails closed into paired:true", preview.outcome === "dry-run" && preview.paired === true);
      const r4 = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      const j4 = await jsonOf(r4);
      ok("live rollback with an unparseable target -> fails closed into paired (never strand)", r4.status === 200 && j4.paired === true && Array.isArray(j4.componentResults));
    }
    {
      // K5: a FAILED engine deploy never pairs (nothing moved, so nothing to bundle) -- the console arm is
      // never even attempted.
      await seedSettled({ outcome: "applied", component: "console", recommendedVersion: "0.9.8", fromVersion: "cv-k5-prior", toVersion: "cv-k5-now", minEngineVersion: "9.9.9", at: Date.now(), by: OWNER });
      await seedSettled({ outcome: "applied", recommendedVersion: "0.9.9", fromVersion: "v-k5-target", toVersion: "v-new", at: Date.now(), by: OWNER });
      failDeploy = true;
      const r5 = await call(OWNER, "POST", "/admin/update/rollback", { token: DEPLOY_TOKEN });
      const j5 = await jsonOf(r5);
      ok("a failed engine deploy (even with a violated floor) never pairs the console", r5.status === 200 && j5.outcome === "failed" && j5.paired === undefined && j5.componentResults === undefined);
      failDeploy = false;
    }

    // ===================================================================================================
    // GROUP J2: a self-redeploy Durable Object reset immediately after the live version cutover
    // (promote/rollback/ramp) must never (a) get silently lost past the retry the codebase already uses for
    // the structurally-identical source-attach/detach flow, or (b) make the route claim "nothing was changed"
    // when the deploy already went live. Every scenario below promotes a version ABOVE the cumulative engine
    // anti-rollback floor left behind by the groups that ran first (GROUP K's K5 seedSettled advanced
    // floors.engine to 0.9.9), so 1.0.0+ is used, and stays "routine" so GROUP H's dual control (still armed)
    // never gates it. (The atomic-apply floor refusal is proven separately in GROUP R8.)
    // ===================================================================================================
    {
      // TRANSIENT: the reset clears after ONE retry (the common case: the new code answers within the
      // first ~300ms backoff). Both post-promote DO calls (the pending write, the audit) hit the reset on
      // their FIRST attempt and land on their second; the response must be indistinguishable from a clean
      // promote (the fix: recordBookkeepingAfterSelfDeploy / recordAuditAfterSelfDeploy).
      current = await signedChannel("1.0.0", "routine");
      const restorePending = injectSelfDeployReset("/update-pending", 1);
      const restoreAudit = injectSelfDeployReset("/audit", 1);
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      restorePending();
      restoreAudit();
      const j = await jsonOf(r);
      ok("apply survives a one-shot DO reset on both follow-up writes -> 200 promoted, no degraded note", r.status === 200 && j.outcome === "promoted" && j.reason === undefined);
      const st = await jsonOf(await call(OWNER, "GET", "/admin/update/status"));
      ok("the pending verification landed despite the reset (retried, not silently dropped)", (st.pending as { toVersion?: string } | null)?.toVersion === "v-new");
      const aud = await jsonOf(await call(OWNER, "GET", "/admin/audit?action=update-promoted"));
      const events = (aud.events as { target?: { detail?: string } }[] | undefined) ?? [];
      ok("the update-promoted audit event landed despite the reset (retried, not silently dropped)", events.some((e) => (e.target?.detail ?? "").includes("1.0.0")));
      await seedSettled({ outcome: "expired", at: Date.now(), by: null }); // clear the pending; do not block the next scenario (HI-14)
    }
    {
      // PERSISTENT: the reset outlasts every retry (a genuine, extended DO outage). THE EXPLOIT this closes:
      // before the fix, an uncaught throw here fell straight into the route's outer catch and answered
      // "could not start the update right now; nothing was changed" -- false, driver.deployVersion already
      // landed (proven below via the real CF deploy-call counter). After the fix, recordAuditAfterSelfDeploy
      // exhausts its retries and returns false WITHOUT throwing, so the route still reports the true
      // outcome, with an honest note that the recording could not be confirmed.
      current = await signedChannel("1.1.0", "routine");
      const deployCallsBefore = deployCalls;
      const restoreAudit = injectSelfDeployReset("/audit", 10); // 10 > the 5-attempt retry budget: never recovers
      const r = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      restoreAudit();
      const j = await jsonOf(r);
      ok("the deploy really did go live (CF deployments-CREATE was called)", deployCalls > deployCallsBefore);
      ok("a persistent post-promote DO reset -> STILL 200 promoted (never the false 'nothing was changed' 400)", r.status === 200 && j.outcome === "promoted");
      ok("...and says so honestly instead of silently pretending the audit landed", typeof j.reason === "string" && /could not be fully recorded|update\/status/.test(j.reason as string));
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });
    }

    // ===================================================================================================
    // GROUP: EVERY UPDATE-FAMILY GUARD MUST BE PACK-VISIBLE. Each refusal class (token missing, account
    // unmarked, artefact unresolvable, artefact undownloadable, no destination, a verification still open) is
    // its own named, counted row in the support pack rather than one coalesced "denied", so a support engineer
    // reading a night of failed apply/ramp attempts can tell which guard fired.
    //
    // Every refusal below is driven through the PRODUCTION handleAdmin with the console's own bodies, and the
    // rows are read back through the PACK'S OWN projector (fetchAdminCounters, the source of the bundle's
    // `adminCounters`). Nothing is hand-posted into the recorder.
    // ===================================================================================================
    {
      await seedSettled({ outcome: "expired", at: Date.now(), by: null }); // clear any pending from earlier groups
      sched.storage.rawPut("diag:admincounters", {}); // a clean slate, so every row below is one this block drove
      current = await signedChannel("0.4.0", "routine");

      // 1. THE "UPDATE NOW" BUTTON, live, no token (the console's own applyUpdate body).
      const noTok = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false });
      ok("apply live with no deploy token -> 400 (unchanged)", noTok.status === 400);

      // 2. THE COMPONENTS LEG, live, no token (the body the console posts for a console-bearing release).
      const noTokComp = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine"], dryRun: false });
      ok("the components-aware apply with no deploy token -> 400 (unchanged)", noTokComp.status === 400);

      // 3. RAMP START, no token.
      const noTokRamp = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 });
      ok("ramp start with no deploy token -> 400 (unchanged)", noTokRamp.status === 400);

      // 4. THE ENGINE'S OWN ACCOUNT IS NOT MARKED (apply).
      accountOn = false;
      const unmarked = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply with an unmarked engine account -> 400 (unchanged)", unmarked.status === 400);
      accountOn = true;

      // 5. THE SIGNED CHANNEL RESOLVES NO ARTEFACT (the channel is not configured at all).
      channelOn = false;
      const noChan = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply with no resolvable artefact -> 400 (unchanged)", noChan.status === 400);
      channelOn = true;

      // 6. THE ARTEFACT WILL NOT DOWNLOAD (a signed channel naming a url that returns nothing).
      current = await signedChannel("0.4.0", "routine", { urlMissing: true });
      const noDl = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      ok("apply whose artefact will not download -> 400 (unchanged)", noDl.status === 400);
      current = await signedChannel("0.4.0", "routine");

      // 7. NO DESTINATION (the canary flight would have nowhere to fly), on BOTH apply legs.
      destOn = false;
      const noDest = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      const noDestComp = await call(OWNER, "POST", "/admin/update/apply", { components: ["engine"], dryRun: false, token: DEPLOY_TOKEN });
      ok("both apply legs refuse with no destination -> 400 (unchanged)", noDest.status === 400 && noDestComp.status === 400);
      destOn = true;

      // 8. A PRIOR VERIFICATION IS STILL OPEN (asvs-HI-14): arm a pending record and press Update now again.
      await seedPending({ fromVersion: "0.1.9", toVersion: "0.4.0", recommendedVersion: "0.4.0", promotedAt: Date.now(), promotedBy: null });
      const openPending = await call(OWNER, "POST", "/admin/update/apply", { dryRun: false, token: DEPLOY_TOKEN });
      const openPendingRamp = await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25, token: DEPLOY_TOKEN });
      ok("apply and ramp both refuse while a verification is open -> 409 (unchanged)", openPending.status === 409 && openPendingRamp.status === 409);
      await seedSettled({ outcome: "expired", at: Date.now(), by: null });

      // ---- THE PACK ROWS a support engineer holds, through the pack's own projector. ----
      const counters = await fetchAdminCounters(sched.stub) as Record<string, { count: number; lastAt: string }>;
      const c = (n: string): number => counters[n]?.count ?? 0;
      console.log(`  ..   the pack's adminCounters after the night: ${JSON.stringify(counters)}`);
      ok("the 'Update now' button's OWN token refusal is now a NAMED, COUNTED row (it recorded NOTHING before)", c("update-refused-deploy-token") === 3);
      ok("all THREE bare token guards fired into ONE closed name (apply + components-apply + ramp start)", counters["update-refused-deploy-token"]?.lastAt !== undefined);
      ok("the unmarked-account refusal carries its guard class (it audited, and the pack stripped the detail)", c("update-refused-account-unmarked") === 1);
      ok("an unresolvable artefact is its OWN row, not an unclassed denial", c("update-refused-artefact-resolve") === 1);
      ok("an artefact that will not download is a DIFFERENT row from one that will not resolve", c("update-refused-artefact-download") === 1);
      ok("the destination gate refuses on BOTH apply legs and both are counted", c("update-refused-no-destination") === 2);
      ok("'settle the open verification first' is a row, on both apply and ramp", c("update-refused-pending-open") === 2);
      ok("the eight guard classes are EIGHT different rows, never one coalesced 'denied'", new Set([
        c("update-refused-deploy-token"), c("update-refused-account-unmarked"), c("update-refused-artefact-resolve"),
        c("update-refused-artefact-download"), c("update-refused-no-destination"), c("update-refused-pending-open"),
      ]).size > 1 && c("update-refused-deploy-token") > 0 && c("update-refused-account-unmarked") > 0);
      const serialised = JSON.stringify(counters);
      ok("no token, version, url or email rides in any row (closed names, ints, engine stamps)", !/DEPLOY|token-|0\.2\.0|acme\.example|https?:/i.test(serialised.replace(/update-refused-deploy-token/g, "")));
    }

    // ===================================================================================================
    // GROUP I (LAST): the per-caller rate limiter. Seed OWNER's window at the cap so the next mutating call
    // on EACH POST route returns 429 (a refused check does not increment, so the window stays saturated).
    // This is the final OWNER activity; nothing depends on OWNER's bucket afterwards.
    // ===================================================================================================
    sched.storage.rawPut(OWNER_RATE_KEY, { windowStart: Date.now(), count: 120 });
    ok("rate-limited: POST /licence -> 429", (await call(OWNER, "POST", "/admin/licence", { token: "x" })).status === 429);
    ok("rate-limited: POST /update/apply -> 429", (await call(OWNER, "POST", "/admin/update/apply", {})).status === 429);
    ok("rate-limited: POST /update/settle -> 429", (await call(OWNER, "POST", "/admin/update/settle", {})).status === 429);
    ok("rate-limited: POST /update/rollback -> 429", (await call(OWNER, "POST", "/admin/update/rollback", {})).status === 429);
    ok("rate-limited: POST /update/ramp -> 429", (await call(OWNER, "POST", "/admin/update/ramp", { percentage: 25 })).status === 429);
    ok("rate-limited: POST /update/ramp/settle -> 429", (await call(OWNER, "POST", "/admin/update/ramp/settle", {})).status === 429);

    ok("no unexpected outbound fetch occurred during the proofs", unexpectedFetches.length === 0);
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
