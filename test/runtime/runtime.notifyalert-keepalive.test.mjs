// runtime.notifyalert-keepalive.test.mjs -- do the OTHER routeXxxAlert records survive the request?
//
// Run: node test/runtime/runtime.notifyalert-keepalive.test.mjs [--n 3] [--calibrate] [--holds] [--probe]
//                                                                  [--only <id>] [--json <path>]
//
// WHY THIS EXISTS. The four destination-change alerts were driven and found to LOSE every record, which led
// to a repair of the shared helper: routeEmission fired BOTH its writes -- noteEmissionFailure's counter
// and the /notify/record post that IS the notify-history row -- with a bare `void` and returned, so the
// promise every call site held resolved BEFORE the only durable record existed. Its keep-alive covered the
// channel resolve and the delivery and stopped exactly short of the record. Every OTHER routeXxxAlert
// wrapper goes through the same helper, so the same loss was live for all of them, and none of them had yet
// been measured.
//
// "THEY SHARE THE FIXED HELPER" IS THE REASONING THAT FAILED THIS MORNING. The four sites repaired on
// resemblance to their neighbours read 0 of 3. Elsewhere in this engine one shared helper LOSES under one
// caller and KEEPS under another on the identical line, because one caller returns immediately and the other
// then does awaited work. So the helper being fixed settles nothing about a CALLER SHAPE, and the whole point
// of this drive is to find a caller the fix does not reach.
//
// THE CALLER SHAPES, read off source rather than assumed (engine 7935cff6):
//   waitUntil     fireInBackground(runtime, routeXxxAlert(...))  -- the repaired shape the four dest sites carry
//   awaited       await routeDualControlDisarmAlert(...)         -- inside the request's own turn
//   BARE VOID     void routePostureRegressions(...).catch(...)   -- router-posture.ts:340, NO keep-alive at all
// The third is the one that cannot be fixed by a helper that returns its writes, because the caller throws the
// returned promise away. It is driven here over the product's own route.
//
// CALIBRATION (--calibrate). The floating-promise pair MUST separate (0/N bare against N/N kept) or nothing
// below can be trusted. The in-flight-subrequest pair is printed BESIDE it because it reads N/N on BOTH holds:
// an outstanding subrequest keeps the context alive by itself, so a harness reading only that arm is
// STRUCTURALLY BLIND to this defect class, learned the hard way on the destination-change drive and carried
// here rather than re-solved.
//
// A ZERO ON BOTH ARMS IS NOT A MISSED DRIVE HERE. For these records the write is issued AFTER the outer
// response by a subrequest that does not exist yet when the caller's turn ends, so nothing holds either arm
// open and the native-dispatch reachability arm cannot see the difference. The destination-change drive
// replaced it with EMISSION-RAN evidence: the wired twin's posts to the stub webhook sink, made from inside
// routeEmission.
//
// THAT ARM IS ITSELF TOO LATE FOR ONE OF THESE SITES, and this drive had to move it. The webhook post happens
// AFTER routeEmission awaits the channel resolve. A caller that drops the promise entirely abandons the
// emission AT THAT FIRST AWAIT: the resolve subrequest is issued, the outer response returns, the context is
// torn down, and the delivery never happens -- so the sink sees nothing and the site reads as a drive that
// never occurred. Measured, not supposed: the posture-regression site issues /notify/resolve on both arms and
// then issues NOTHING further, delivery included.
//
// So reachability here is the RESOLVE-ISSUED arm: routeEmission's first statement is the /notify/resolve
// fetch, and a fetch is issued synchronously when the function is entered, so one counted resolve per drive
// proves the alert line executed BEFORE anything downstream could be dropped. The webhook count rides
// alongside it, and the two DISAGREEING is itself the finding rather than a fault in the instrument.
//
// THE ASSERTION IS ON THE EXACT RECORD, never existence and never a count. Wired: a notify-history row whose
// event is the one THIS alert emits AND whose detail is the one THIS call site composes. A mutant that files
// one route's alert under another route's name leaves the event, the class, the counts and the row count
// identical and is caught only by the detail. Unwired: the composed counter `alert-emit-<class>-no-channel`,
// which is CLASS-grained rather than site-grained (four IdP sites share idp-change, two offboards share
// offboard, two credential revokes share credential-change), and that is stated rather than glossed: the
// unwired arm proves the record survived, the wired arm proves it was the RIGHT record.
//
// THE KNOWN POSITIVE IS OF THE RIGHT KIND: dest-change-set (router-destinations.ts:272), a site the
// destination-change drive measured as KEEPS at this exact sha, on the SAME routeEmission helper, in the same
// runtime, with the same deferred dispatch. It runs first and must read KEEPS in every run, including any
// run where a site under test reads zero. noteTestOutcome (router-destinations.ts:495) rides alongside as
// the READER's own known positive.
//
// Exit: 0 every case matched its expectation; 1 a case disagreed; 4 could-not-check.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "admin-refusal-keepalive-worker.ts");
const OUT = join(here, ".bundle", "notifyalert-keepalive-worker.js");
const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : d;
};
const N = Number(argOf("--n", "3"));
const JSON_OUT = argOf("--json", null);
const ONLY = argOf("--only", null);
const CALIBRATE = args.includes("--calibrate");
const HOLDS = args.includes("--holds");
const PROBE = args.includes("--probe");
const TOKEN = "signal-keepalive-test-token";
const SCIM_TOKEN = "notifyalert-scim-token";
const IP = "203.0.113.7";
const REGRESSION_TITLE = "notify-alert probe check";

const say = (s) => console.log(s);
let couldNotCheck = false;

const DEST_CONFIG = {
  endpoint: "https://s3.destchange-sink.test",
  bucket: "destchange-bucket",
  region: "auto",
  accessKeyId: "DESTCHANGETESTKEYID000000",
  secretAccessKey: "destchange-test-secret",
};

// ---- a minimal DER X.509 cert, lifted from test/validate-idp-rollover-lockout.ts. It exists so the CERT
//      ROLLOVER case can drive a rollover the DO ACCEPTS. See the idp-cert case for why it has to. -----------
const derLen = (n) => {
  if (n < 0x80) return [n];
  const b = [];
  let x = n;
  while (x > 0) {
    b.unshift(x & 0xff);
    x = Math.floor(x / 256);
  }
  return [0x80 | b.length, ...b];
};
const tlv = (tag, content) => [tag, ...derLen(content.length), ...content];
const asciiBytes = (s) => Array.from(s).map((c) => c.charCodeAt(0));
const toPem = (b64) => `-----BEGIN CERTIFICATE-----\n${b64.replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;
const buildCert = (notAfterUtc, serial) => {
  const tbs = tlv(0x30, [
    ...tlv(0x02, [serial & 0xff]),
    ...tlv(0x30, []),
    ...tlv(0x30, []),
    ...tlv(0x30, [...tlv(0x17, asciiBytes("200101000000Z")), ...tlv(0x17, asciiBytes(notAfterUtc))]),
  ]);
  return toPem(Buffer.from(tlv(0x30, tbs)).toString("base64"));
};
const CERT_A = buildCert("300101000000Z", 21);
const CERT_B = buildCert("350101000000Z", 22);

// A SAML proposal the validators ACCEPT, so a cert rollover has a SAML connection to roll over.
const samlProposal = (id) => ({
  id,
  kind: "saml",
  label: `notify-alert saml ${id}`,
  presetId: "generic-saml",
  enabled: false,
  idpEntityId: "https://idp.notifyalert-sink.test/entity",
  idpSsoUrl: "https://idp.notifyalert-sink.test/sso",
  idpSigningCerts: [CERT_A],
  spEntityId: "https://sp.downpipes.io",
  nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  wantAssertionsSigned: true,
  allowIdpInitiated: false,
  clockSkewSec: 120,
  emailVerifiedPolicy: "trust-idp",
  emailAttr: "email",
  groupsAttr: "groups",
});

// An OIDC proposal the DO's pure pre-write validators ACCEPT, so the connection really lands and the delete /
// enable / cert routes act on a real record rather than an absent one.
const idpProposal = (id) => ({
  id,
  kind: "oidc",
  label: `notify-alert ${id}`,
  presetId: "generic-oidc",
  issuer: "https://idp.notifyalert-sink.test",
  clientId: "notifyalert-client",
  scopes: ["openid"],
  idTokenSigAlgs: ["RS256"],
  pkce: "required",
  clientAuth: "pkce_public",
  requireNonce: true,
  enabled: false,
});

// ---------------------------------------------------------------------------------------------------------
// THE CASES. Each names ONE call site, the request that reaches it, the state it needs first, and the EXACT
// record it must leave. `expect` is what the helper repair at 7935cff6 claims for it.
//
// `event`/`detail` are the wired assertion (the notify-history row this call site composes). `cls` is the
// unwired assertion (the composed alert-emit-<cls>-no-channel counter).
// ---------------------------------------------------------------------------------------------------------
const CASES = [
  // THE KNOWN POSITIVE OF THE RIGHT KIND, first on purpose: same helper, same runtime, same deferred dispatch,
  // MEASURED KEEPS at this sha by the pass that repaired the helper. If it reads anything else here, this
  // instrument is measuring itself and every zero below is worthless.
  {
    id: "control-dest-change-set",
    expect: "keep",
    knownPositive: true,
    site: "router-destinations.ts:272 POST /destination -- KNOWN POSITIVE, measured KEEPS at 7935cff6",
    shape: "waitUntil",
    path: "/destination",
    method: "POST",
    body: { config: DEST_CONFIG },
    status: 200,
    event: "dest-change",
    detail: "A backup destination was set/repointed.",
    cls: "dest-change",
  },
  {
    id: "idp-add",
    expect: "keep",
    site: "router-identity.ts:876 POST /idp/connections (IdP connection add)",
    shape: "waitUntil",
    path: "/idp/connections",
    method: "POST",
    bodyFor: (i) => ({ proposal: idpProposal(`notifyalert-add-${i}`) }),
    status: 200,
    event: "auth-credential-change",
    detail: "An IdP connection add was requested (changes who can sign in).",
    cls: "idp-change",
  },
  {
    id: "idp-delete",
    expect: "keep",
    site: "router-identity.ts:890 POST /idp/connections/delete (IdP connection removal)",
    shape: "waitUntil",
    path: "/idp/connections/delete",
    method: "POST",
    seed: "idp-per-drive",
    bodyFor: (i) => ({ connId: `notifyalert-seed-${i}` }),
    status: 200,
    event: "auth-credential-change",
    detail: "An IdP connection removal was requested (changes who can sign in).",
    cls: "idp-change",
  },
  {
    id: "idp-enabled",
    expect: "keep",
    site: "router-identity.ts:906 POST /idp/connections/enabled (IdP enable/disable)",
    shape: "waitUntil",
    path: "/idp/connections/enabled",
    method: "POST",
    seed: "idp-once",
    body: { connId: "notifyalert-seed-0", enabled: true },
    status: 200,
    event: "auth-credential-change",
    detail: "An IdP connection enable/disable was requested (changes who can sign in).",
    cls: "idp-change",
  },
  // THIS CASE USED TO DRIVE A REFUSAL AND SCORE IT GREEN, and that is worth stating rather than quietly
  // rewriting. It posted { certs: [] } at `notifyalert-seed-0`, which is an OIDC connection, so
  // idpConnSamlCertUpdate refused it twice over ("cert rollover applies only to a SAML connection", and an
  // empty cert array) and wrote nothing. The route fired the alert anyway, because it was guarded on the
  // transport-level `certResp.ok` and a DO refusal comes back as a plain 200 -- so a rollover that never
  // happened, over a connection that is not even SAML, raised "A SAML signing-certificate rollover was
  // requested (an IdP trust-root change)" and this suite measured it as a keep. The guard was then repaired
  // (router-identity.ts idpChangeRefused), which correctly makes that drive fire NOTHING and turned this case
  // red. The case is now what its own title always claimed: a SAML connection is seeded and its pinned cert
  // set is really REPLACED, so the alert fires because a trust root really moved. The keep-alive question this
  // case exists to answer is untouched; only the state it drives from is now the state the alert is about.
  {
    id: "idp-cert",
    expect: "keep",
    site: "router-identity.ts:923 POST /idp/connections/cert (SAML signing-cert rollover)",
    shape: "waitUntil",
    path: "/idp/connections/cert",
    method: "POST",
    seed: "saml-once",
    body: { connId: "notifyalert-saml-0", certs: [CERT_B] },
    status: 200,
    event: "auth-credential-change",
    detail: "A SAML signing-certificate rollover was requested (an IdP trust-root change).",
    cls: "idp-change",
  },
  {
    id: "role-change",
    expect: "keep",
    site: "router-rbac.ts:113 POST /roles (role grant/change)",
    shape: "waitUntil",
    path: "/roles",
    method: "POST",
    bodyFor: (i) => ({ email: `notifyalert-grant-${i}@example.test`, role: "viewer" }),
    status: 200,
    event: "role-change",
    detailFor: (i) => `Role changed for notifyalert-grant-${i}@example.test to viewer.`,
    cls: "owner-role-grant",
  },
  {
    id: "offboard-console",
    expect: "keep",
    site: "router-rbac.ts:144 POST /roles/delete (offboarding, console path)",
    shape: "waitUntil",
    path: "/roles/delete",
    method: "POST",
    seed: "role-per-drive",
    bodyFor: (i) => ({ email: `notifyalert-seed-${i}@example.test` }),
    status: 200,
    event: "role-change",
    detailFor: (i) => `Member removed (offboarded): notifyalert-seed-${i}@example.test.`,
    cls: "offboard",
  },
  // RECOVERY-REGENERATE IS PER-USER, so the bearer break-glass caller cannot reach it: the route answers 403
  // "recovery codes are per-user" for a token caller with no email. It is driven as a COOKIE-BORNE caller, with
  // the session token minted by the DO's own POST /passkey/session/issue (the same mint the passkey login uses)
  // and presented in the same __Host- cookie a real login sets. That is the product's own session, not a
  // harness bypass: authorise() verifies it against the in-DO signing key like any other request.
  {
    id: "recovery-regenerate",
    expect: "keep",
    site: "router-auth-flow.ts:185 POST /auth/recovery-codes/regenerate",
    shape: "waitUntil",
    path: "/auth/recovery-codes/regenerate",
    method: "POST",
    seed: "session",
    sessionEmail: "notifyalert-owner@example.test",
    body: {},
    status: 200,
    event: "auth-credential-change",
    detail: "Recovery codes were regenerated for notifyalert-owner@example.test.",
    cls: "recovery-regenerate",
  },
  {
    id: "factors-revoke",
    expect: "keep",
    site: "router-account-session.ts:152 POST /signin-factors/revoke",
    shape: "waitUntil",
    path: "/signin-factors/revoke",
    method: "POST",
    seed: "role-per-drive",
    bodyFor: (i) => ({ email: `notifyalert-seed-${i}@example.test` }),
    status: 200,
    event: "auth-credential-change",
    detail: "Every sign-in factor was revoked for a member.",
    cls: "credential-change",
  },
  {
    id: "dual-control-disarm",
    expect: "keep",
    site: "router-config-version.ts:160 POST /config/approval-policy (immediate disarm)",
    shape: "awaited",
    path: "/config/approval-policy",
    method: "POST",
    seed: "arm-dual-control",
    body: { requireConfigApproval: false },
    status: 200,
    event: "dual-control-disabled",
    detail: "Dual control was turned OFF (the break-glass admin token); high-blast-radius config and owner operations no longer require a second owner's approval until it is turned back on.",
    cls: "dual-control-disarm",
  },
  // THE SUSPECT. router-posture.ts:340 is `void routePostureRegressions(...).catch(...)`: the caller drops the
  // returned promise on the floor, so the helper repair -- which put both writes BACK into that promise -- has
  // nothing to hand them to. Driven over the product's own route (GET /admin/posture), with the DO answering
  // with a regression present, which is the only state in which this call site executes at all.
  {
    id: "posture-regression",
    expect: "keep",
    site: "router-posture.ts:340 GET /posture (posture regression) -- was a BARE VOID with no keep-alive at the caller",
    shape: "keepAlive (was bare void)",
    path: "/posture",
    method: "GET",
    injectRegression: true,
    status: 200,
    event: "posture-regression",
    detail: `Posture regression: ${REGRESSION_TITLE} now failing`,
    cls: "posture-regression",
  },
  {
    id: "scim-leaver",
    expect: "keep",
    site: "admin/scim.ts:268 DELETE /scim/v2/Users/{id} (SCIM leaver offboard)",
    shape: "ctx.waitUntil (index.ts:206)",
    scim: true,
    seed: "role-per-drive",
    status: 204,
    event: "role-change",
    detailFor: (i) => `Member removed (offboarded) via SCIM: notifyalert-seed-${i}@example.test.`,
    cls: "offboard",
  },
];

// THE LEAF CASES. These call sites fire only from a completed SAML/OIDC/passkey ceremony or a verified
// recovery-code round trip, none of which this harness can mint (the session signing key never leaves the DO).
// They are driven at the LEAF with the SITE'S OWN HOLD, and reported as leaf drives rather than as product
// drives, because that is what they are.
const LEAF_CASES = [
  {
    id: "sign-in-context",
    sites: "router-idp-web.ts:259 (SAML ACS), router-idp-web.ts:409 (OIDC callback), router-auth-flow.ts:491->602 (passkey login/finish)",
    shape: "waitUntil",
    which: "sign-in-context",
    hold: "waituntil",
    cls: "sign-in-context",
    event: "sign-in-new-context",
    detail: "A successful sign-in came from a network not seen recently for that operator. If this was not you, sign out other sessions under Access and security and review passkeys and IdP access.",
    expect: "keep",
  },
  {
    id: "recovery-code-used",
    sites: "router-auth-flow.ts:94 (successful break-glass sign-in)",
    shape: "waitUntil",
    which: "recovery-used",
    hold: "waituntil",
    cls: "recovery-code-used",
    event: "recovery-code-used",
    email: "notifyalert-bg@example.test",
    detail: "Recovery code used for admin sign-in by notifyalert-bg@example.test; prompt a fresh passkey enrolment.",
    expect: "keep",
  },
  {
    id: "recovery-code-abuse",
    sites: "router-auth-flow.ts:73 (repeated / rate-limited recovery attempts)",
    shape: "waitUntil",
    which: "recovery-abuse",
    hold: "waituntil",
    cls: "recovery-code-abuse",
    event: "recovery-code-abuse",
    detail: "Repeated or rate-limited recovery-code attempts detected; a high-value admin credential may be under attack.",
    expect: "keep",
  },
  // A passkey CREDENTIAL cannot be authored by this harness: registering one needs a real WebAuthn
  // attestation over a challenge the DO minted, and the route's alert fires only on {deleted:true}, which a
  // delete of an absent credential never returns (measured: {"deleted":false}, so the alert line is never
  // executed). Driven at the leaf with the site's own hold instead, and reported as a leaf drive.
  {
    id: "passkey-revoke",
    sites: "router-account-session.ts:116 (a passkey credential revoked), router-account-session.ts:152 was driven over its product route",
    shape: "waitUntil",
    which: "auth-change",
    hold: "waituntil",
    cls: "credential-change",
    event: "auth-credential-change",
    detail: "A passkey credential was revoked.",
    expect: "keep",
  },
  {
    id: "dual-control-disarm-approve",
    sites: "router.ts:664 (an approved second-owner disarm, via the owner-action approve route)",
    shape: "awaited",
    which: "dual-control-disarm",
    hold: "await",
    cls: "dual-control-disarm",
    event: "dual-control-disabled",
    via: "an approved second-owner disarm",
    detail: "Dual control was turned OFF (an approved second-owner disarm); high-blast-radius config and owner operations no longer require a second owner's approval until it is turned back on.",
    expect: "keep",
  },
];

async function bundle() {
  mkdirSync(dirname(OUT), { recursive: true });
  const r = await build({
    entryPoints: [ENTRY],
    outfile: OUT,
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    conditions: ["workerd", "browser"],
    external: ["cloudflare:sockets", "cloudflare:workers", "cloudflare:email"],
    keepNames: true,
    legalComments: "none",
    write: true,
    logLevel: "silent",
  });
  if (r.errors.length) throw new Error(r.errors.map((e) => e.text).join("\n"));
  return OUT;
}

// THE SINK. Everything the drive sends off-worker lands here and nowhere else: the SigV4 destination probe and
// the webhook alert sink. No packet leaves the machine; every host is a .test name.
const sinkHits = { head: 0, put: 0, delete: 0, objectLock: 0, webhook: 0, other: [] };
const outbound = async (request) => {
  const u = new URL(request.url);
  if (u.hostname === "hook.destchange-sink.test") {
    sinkHits.webhook++;
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  }
  if (u.hostname === "s3.destchange-sink.test") {
    if (u.searchParams.has("object-lock")) {
      sinkHits.objectLock++;
      return new Response("", { status: 404 });
    }
    if (request.method === "HEAD") {
      sinkHits.head++;
      return new Response(null, { status: 404 });
    }
    if (request.method === "PUT") {
      sinkHits.put++;
      return new Response("", { status: 200, headers: { etag: '"notifyalert"' } });
    }
    if (request.method === "DELETE") {
      sinkHits.delete++;
      return new Response("", { status: 204 });
    }
  }
  sinkHits.other.push(`${request.method} ${u.host}${u.pathname}`);
  return new Response("notifyalert sink: unrouted", { status: 502 });
};

function countOf(agg, key) {
  if (agg === null || typeof agg !== "object") return 0;
  const v = agg[key];
  if (v === undefined || v === null) return 0;
  if (typeof v === "number") return v;
  if (Array.isArray(v)) return v.length;
  if (typeof v === "object" && typeof v.count === "number") return v.count;
  return 0;
}

// historyMatches counts the notify-history rows for EXACTLY this call site: the event this alert emits AND the
// detail this one route composes. A row for another route, or another event, does not count. The stored detail
// may carry an actor suffix the harness's token caller does not produce, so the match is a PREFIX on the
// composed detail -- which still separates every site from every other, because no two of these details share
// a prefix.
function historyMatches(history, event, detail) {
  if (!Array.isArray(history)) return 0;
  return history.filter((h) => h !== null && typeof h === "object" && h.event === event && typeof h.detail === "string" && h.detail.startsWith(detail.replace(/\.$/, ""))).length;
}

async function main() {
  const bundlePath = await bundle();
  const script = readFileSync(bundlePath, "utf8");

  const mkInstance = async () => {
    const mf = new Miniflare({
      modules: true,
      script,
      scriptPath: bundlePath,
      compatibilityDate: "2026-06-01",
      durableObjects: { SCHEDULER: { className: "SchedulerDO", useSQLite: true }, REFUSAL_SLOW: { className: "RefusalSlowDO", useSQLite: true } },
      bindings: { ADMIN_TOKEN: TOKEN, CONSOLE_ORIGIN: "https://console.test", SCIM_BEARER_TOKEN: SCIM_TOKEN },
      outboundService: outbound,
      log: new Log(LogLevel.WARN),
    });
    await mf.ready;
    const hit = async (p, init) => {
      const r = await mf.dispatchFetch(`https://engine.test${p}`, init);
      return { status: r.status, text: await r.text() };
    };
    return { mf, hit };
  };

  const auth = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };

  // ---- CALIBRATION: prove this instrument can see the difference on a KNOWN pair --------------------------
  if (CALIBRATE) {
    const { mf, hit } = await mkInstance();
    await hit("/refusal/awaited");
    const kpRaw = await hit("/refusal/read");
    const kpOk = kpRaw.status === 200 && (JSON.parse(kpRaw.text)["update-apply:validation"]?.count ?? 0) === 1;
    for (let i = 0; i < N; i++) await hit("/refusal/bare-delay?d=250");
    for (let i = 0; i < N; i++) await hit("/refusal/kept-delay?d=250");
    for (let i = 0; i < N; i++) await hit("/refusal/bare-slowdo?d=250");
    for (let i = 0; i < N; i++) await hit("/refusal/kept-slowdo?d=250");
    await new Promise((r) => setTimeout(r, 2500));
    const refRaw = await hit("/refusal/read");
    const slowRaw = await hit("/refusal/slowread");
    await mf.dispose();
    if (refRaw.status !== 200 || slowRaw.status !== 200 || !kpOk) {
      say("   THE READER DID NOT ANSWER, OR ITS AWAITED KNOWN POSITIVE WAS ABSENT -> COULD-NOT-CHECK");
      return 4;
    }
    const ref = JSON.parse(refRaw.text);
    const slow = JSON.parse(slowRaw.text);
    const bare = ref["restore-apply:validation"]?.count ?? 0;
    const kept = ref["drill:validation"]?.count ?? 0;
    say(`== CALIBRATION, ${N} each, identical work, only the hold differs ==`);
    say(`   floating promise      bare ${bare}/${N}   kept ${kept}/${N}`);
    say(`   in-flight subrequest  bare ${slow.bare}/${N}   kept ${slow.kept}/${N}   (the loopback's blind arm)`);
    if (kept !== N || bare !== 0) {
      say("   THIS HARNESS CANNOT SEE THE DEFECT CLASS (it needs kept=N and bare=0) -> COULD-NOT-CHECK");
      return 4;
    }
    say("   the instrument separates the two holds, so a zero below is a lost record and not a blind reader");
    return 0;
  }

  // setupFor performs one case's preconditions on a fresh isolate. Everything goes STRAIGHT TO THE DO, never
  // through the admin router, because several of the router's own routes ARE the call sites under test and
  // seeding through them would put the setup into the aggregate the measurement then reads.
  const setupFor = async (hit, c, wired) => {
    const setup = [];
    if (wired) {
      const w = await hit("/signal/wire-alert-channel");
      setup.push({ stage: "wire", status: w.status, body: w.text.slice(0, 200) });
      if (w.status !== 200) return { setup, ok: false };
    }
    if (c.seed === "role-per-drive" || c.seed === "role-once") {
      const n = c.seed === "role-once" ? 1 : N;
      for (let i = 0; i < n; i++) {
        const s = await hit(`/notifyalert/seed-role?email=notifyalert-seed-${i}@example.test`);
        setup.push({ stage: `seed-role-${i}`, status: s.status, body: s.text.slice(0, 200) });
        if (s.status !== 200) return { setup, ok: false };
      }
    }
    if (c.seed === "idp-per-drive" || c.seed === "idp-once") {
      const n = c.seed === "idp-once" ? 1 : N;
      for (let i = 0; i < n; i++) {
        const s = await hit(`/notifyalert/seed-idp-conn?id=notifyalert-seed-${i}`);
        setup.push({ stage: `seed-idp-${i}`, status: s.status, body: s.text.slice(0, 200) });
        if (s.status !== 200) return { setup, ok: false };
      }
    }
    if (c.seed === "saml-once") {
      // Straight on the DO, like every other seed here, because POST /admin/idp/connections is itself one of
      // the call sites under test and seeding through it would put its own alert into the aggregate this
      // measurement then reads.
      const s = await hit("/notifyalert/do?p=/idp/conn/create&m=POST", { method: "POST", body: JSON.stringify({ proposal: samlProposal("notifyalert-saml-0") }) });
      setup.push({ stage: "seed-saml", status: s.status, body: s.text.slice(0, 200) });
      if (s.status !== 200) return { setup, ok: false };
    }
    if (c.seed === "arm-dual-control") {
      // Arm dual control STRAIGHT ON THE DO so the disarm the drive performs is a real true->false transition.
      // It is re-armed BEFORE EVERY DRIVE (see perDrive below), because a second disarm of an already-disarmed
      // engine answers { disarmed:false } and never executes the alert line -- which read as 1 of 3 and would
      // have been scored as a partial loss rather than as two drives that never reached the site.
      const s = await hit("/notifyalert/do?p=/config/approval-policy&m=POST", { method: "POST", body: JSON.stringify({ requireConfigApproval: true }) });
      setup.push({ stage: "arm-dual-control", status: s.status, body: s.text.slice(0, 200) });
      if (s.status !== 200) return { setup, ok: false };
    }
    if (c.seed === "session") {
      // Grant the email a role STRAIGHT ON THE DO (never through POST /admin/roles, which is itself a call site
      // under test), then mint the session with the DO's OWN issue route -- the same mint a passkey login uses.
      const g = await hit(`/notifyalert/seed-role?email=${encodeURIComponent(c.sessionEmail)}`);
      setup.push({ stage: "seed-session-role", status: g.status, body: g.text.slice(0, 160) });
      if (g.status !== 200) return { setup, ok: false };
      // The token is minted FRESH IMMEDIATELY BEFORE EACH DRIVE (see mintSession below), not N times up front.
      // A regenerate bumps the caller's SESSION EPOCH, which invalidates every token issued before it, so a
      // batch minted in advance is refused 401 from the second drive on -- which read as 1 of 3 and would have
      // been mis-scored as a partial loss rather than as two drives the route never admitted.
      return { setup, ok: true, mintSession: c.sessionEmail };
    }
    if (c.injectRegression === true) {
      // A posture regression needs a PRIOR snapshot. One product read lays it down; the drive's reads then
      // carry the injected regression. The prior read goes through the SAME product route so the DO's stored
      // snapshot is the real one.
      const s = await hit("/notifyalert-defer/admin/posture", { method: "GET", headers: { ...auth, "CF-Connecting-IP": IP } });
      setup.push({ stage: "prior-posture", status: s.status, body: s.text.slice(0, 120) });
    }
    return { setup, ok: true };
  };

  // ---- THE HOLD TABLE: the LEAF drive, only the hold different -----------------------------------------
  if (HOLDS) {
    const which = argOf("--which", "posture-regression");
    const detail = which === "posture-regression" ? `Posture regression: ${REGRESSION_TITLE} now failing` : "notify-alert leaf detail.";
    const cls = which === "posture-regression" ? "posture-regression" : "credential-change";
    const event = which === "posture-regression" ? "posture-regression" : "auth-credential-change";
    say(`== HOLD TABLE (LEAF drive of ${which}; same alert, same DO, same reader, only the hold differs) ==`);
    for (const wired of [false, true]) {
      for (const hold of ["bare", "waituntil", "await", "settle"]) {
        for (const defer of [true, false]) {
          const { mf, hit } = await mkInstance();
          try {
            if (wired) {
              const w = await hit("/signal/wire-alert-channel");
              if (w.status !== 200) {
                say(`  wired=${wired} hold=${hold} defer=${defer} WIRING FAILED ${w.status} -> COULD-NOT-CHECK`);
                couldNotCheck = true;
                continue;
              }
            }
            await hit("/signal/awaited");
            const kp = JSON.parse((await hit("/signal/read")).text);
            const kpOk = countOf(kp.adminCounters, "degraded-read-providers-list") >= 1;
            const before = wired ? historyMatches(kp.notifyHistory, event, detail) : countOf(kp.adminCounters, `alert-emit-${cls}-no-channel`);
            for (let i = 0; i < N; i++) await hit(`/notifyalert-hold-probe?which=${which}&hold=${hold}&defer=${defer ? "1" : "0"}&detail=${encodeURIComponent(detail)}&cls=${cls}`);
            await new Promise((r) => setTimeout(r, 1500));
            const after = JSON.parse((await hit("/signal/read")).text);
            const seen = (wired ? historyMatches(after.notifyHistory, event, detail) : countOf(after.adminCounters, `alert-emit-${cls}-no-channel`)) - before;
            say(`  ${(wired ? "wired  " : "unwired").padEnd(8)} hold=${hold.padEnd(10)} defer=${defer ? "yes" : "no "}  kp=${kpOk ? "OK" : "DEAD"}  seen=${seen}/${N}`);
            if (!kpOk) couldNotCheck = true;
          } finally {
            await mf.dispose();
          }
        }
      }
    }
    say(`   sink: webhook=${sinkHits.webhook} unrouted=${sinkHits.other.length}`);
    return couldNotCheck ? 4 : 0;
  }

  // ---- THE LEAF DRIVES: the sites no bearer, cookie or SCIM caller can reach ----------------------------
  //
  // Each runs the SITE'S OWN HOLD, flanked by two controls on the same alert, the same DO and the same reader:
  // `bare` is the NEGATIVE control (the shape that is known to lose, so a run where it does not lose is an
  // instrument that cannot see the defect) and `settle` is the POSITIVE control (the caller waits and then
  // keeps working, so a row landing there and not at the site's own hold is a hold problem and not a dead
  // reader). The assertion is the exact record: the composed alert-emit-<class>-no-channel counter unwired,
  // and a notify-history row whose event AND detail are the ones THAT wrapper composes, wired.
  if (args.includes("--leaf")) {
    let leafFailures = 0;
    say("== LEAF DRIVES (NOT a drive over the product's own route; the site's own hold, flanked by controls) ==");
    for (const c of LEAF_CASES) {
      say(`  ${c.id}  [${c.shape}]  ${c.sites}`);
      for (const wired of [false, true]) {
        for (const hold of ["bare", c.hold, "settle"]) {
          const { mf, hit } = await mkInstance();
          try {
            if (wired) {
              const w = await hit("/signal/wire-alert-channel");
              if (w.status !== 200) {
                say(`     wired hold=${hold} WIRING FAILED ${w.status} -> COULD-NOT-CHECK`);
                couldNotCheck = true;
                continue;
              }
            }
            await hit("/signal/awaited");
            const kp = JSON.parse((await hit("/signal/read")).text);
            const kpOk = countOf(kp.adminCounters, "degraded-read-providers-list") >= 1;
            const before = wired ? historyMatches(kp.notifyHistory, c.event, c.detail) : countOf(kp.adminCounters, `alert-emit-${c.cls}-no-channel`);
            await hit("/notifyalert/resolve-count?reset=1");
            const q = new URLSearchParams({ which: c.which, hold, defer: "1", cls: c.cls, detail: c.detail, event: c.event });
            if (c.email !== undefined) q.set("email", c.email);
            if (c.via !== undefined) q.set("via", c.via);
            for (let i = 0; i < N; i++) await hit(`/notifyalert-hold-probe?${q.toString()}`);
            await new Promise((r) => setTimeout(r, 1500));
            const resolves = JSON.parse((await hit("/notifyalert/resolve-count")).text).resolves ?? 0;
            const after = JSON.parse((await hit("/signal/read")).text);
            const seen = (wired ? historyMatches(after.notifyHistory, c.event, c.detail) : countOf(after.adminCounters, `alert-emit-${c.cls}-no-channel`)) - before;
            const role = hold === "bare" ? "negative control" : hold === "settle" ? "positive control" : "THE SITE'S OWN HOLD";
            say(`     ${(wired ? "wired  " : "unwired").padEnd(8)} hold=${String(hold).padEnd(10)} kp=${kpOk ? "OK" : "DEAD"} resolves=${resolves}/${N} seen=${seen}/${N}   ${role}`);
            if (!kpOk) couldNotCheck = true;
            if (resolves < N) {
              say("        THE ALERT LINE DID NOT EXECUTE ONCE PER DRIVE -> COULD-NOT-CHECK");
              couldNotCheck = true;
            }
            const want = hold === "bare" ? 0 : N;
            if (hold === "bare" ? seen !== 0 : seen < N) {
              leafFailures++;
              say(`        FAIL expected ${want}/${N}, measured ${seen}/${N}`);
            }
          } finally {
            await mf.dispose();
          }
        }
      }
    }
    say(`   sink: webhook=${sinkHits.webhook} unrouted=${sinkHits.other.length}`);
    if (couldNotCheck) {
      say("VERDICT: COULD-NOT-CHECK (exit 4). This is NOT a pass.");
      return 4;
    }
    say(leafFailures === 0 ? "LEAF DRIVES PASS" : `LEAF DRIVES FAIL (${leafFailures} arm(s))`);
    return leafFailures === 0 ? 0 : 1;
  }

  // --only takes a COMMA-SEPARATED list, and the KNOWN POSITIVE always rides along whatever is asked for.
  // A scored run without it is a run whose zeros cannot be told apart from a dead instrument, which is exactly
  // the state a mutation score must never be computed in.
  const wanted = ONLY === null ? null : new Set(ONLY.split(","));
  const cases = wanted === null ? CASES : CASES.filter((c) => c.knownPositive === true || wanted.has(c.id));
  if (cases.length === 0 || (wanted !== null && cases.length === 1)) {
    say(`no case matched --only ${ONLY} -> COULD-NOT-CHECK`);
    return 4;
  }

  // ---- PROBE: just show what each case's request answers, so an unreachable site is named, not guessed ----
  if (PROBE) {
    for (const c of cases) {
      const { mf, hit } = await mkInstance();
      try {
        const s = await setupFor(hit, c, false);
        if (!s.ok) {
          say(`  ${c.id.padEnd(24)} SETUP FAILED ${JSON.stringify(s.setup)}`);
          continue;
        }
        const headers = { ...auth, "CF-Connecting-IP": IP };
        if (c.injectRegression === true) headers["x-notifyalert-inject-regression"] = "1";
        if (s.mintSession !== undefined) {
          const m = await hit("/notifyalert/do?p=/passkey/session/issue&m=POST", { method: "POST", body: JSON.stringify({ email: s.mintSession }) });
          const tok = m.status === 200 ? (JSON.parse(m.text).token ?? null) : null;
          headers.cookie = `__Host-downpipes_session=${tok}`;
          headers.origin = "https://console.test";
          delete headers.authorization;
        }
        let r;
        if (c.scim === true) {
          r = await hit(`/notifyalert-scim/Users/${encodeURIComponent("notifyalert-seed-0@example.test")}`, { method: "DELETE", headers: { authorization: `Bearer ${SCIM_TOKEN}` } });
        } else {
          const body = c.bodyFor ? c.bodyFor(0) : (c.body ?? {});
          r = await hit(`/notifyalert-defer/admin${c.path}`, { method: c.method, headers, ...(c.method === "GET" ? {} : { body: JSON.stringify(body) }) });
        }
        say(`  ${c.id.padEnd(24)} want=${c.status} got=${r.status}  ${r.text.slice(0, 220).replace(/\n/g, " ")}`);
        say(`       setup: ${JSON.stringify(s.setup.map((x) => `${x.stage}=${x.status}`))}`);
      } finally {
        await mf.dispose();
      }
    }
    return 0;
  }

  const rows = [];
  const emissionRan = new Map();

  // driveOnce runs ONE arm of ONE case in its OWN isolate.
  const driveOnce = async (c, wired, defer) => {
    const { mf, hit } = await mkInstance();
    const webhookBefore = sinkHits.webhook;
    try {
      const s = await setupFor(hit, c, wired);
      if (!s.ok) return { setup: s.setup, setupOk: false, webhookDelta: 0 };

      // Control 0: the reader's own known positive, AWAITED, taken AFTER the setup and before any drive, so
      // the `before` baseline already contains anything the setup left behind.
      await hit("/signal/awaited");
      const kpRaw = await hit("/signal/read");
      const kp = kpRaw.status === 200 ? JSON.parse(kpRaw.text) : null;
      const kpOk = kp !== null && countOf(kp.authSignals, "recovery-ratelimited") >= 1 && countOf(kp.adminCounters, "degraded-read-providers-list") >= 1 && countOf(kp.testOutcomes, "idp") >= 1;
      const detailAt = (i) => (c.detailFor ? c.detailFor(i) : c.detail);
      const measure = (snap) => {
        if (snap === null) return 0;
        if (wired) {
          let n = 0;
          for (let i = 0; i < N; i++) n += Math.min(1, historyMatches(snap.notifyHistory, c.event, detailAt(i)));
          return c.detailFor ? n : historyMatches(snap.notifyHistory, c.event, c.detail);
        }
        return countOf(snap.adminCounters, `alert-emit-${c.cls}-no-channel`);
      };
      const before = measure(kp);

      const headers = { ...auth, "CF-Connecting-IP": IP };
      if (defer === false) headers["x-notifyalert-defer"] = "0";
      if (c.injectRegression === true) headers["x-notifyalert-inject-regression"] = "1";

      const statuses = [];
      const bodies = [];
      // Zero the RESOLVE-ISSUED arm here, AFTER every setup step, so it counts only this arm's own drives.
      await hit("/notifyalert/resolve-count?reset=1");
      for (let i = 0; i < N; i++) {
        // PER-DRIVE state. A dual-control disarm is a true->false transition and is not repeatable without a
        // re-arm; a cookie-borne regenerate bumps its own session epoch and needs a fresh token each time.
        // Both go straight to the DO, never through a route under test.
        if (c.seed === "arm-dual-control" && i > 0) await hit("/notifyalert/do?p=/config/approval-policy&m=POST", { method: "POST", body: JSON.stringify({ requireConfigApproval: true }) });
        if (s.mintSession !== undefined) {
          const m = await hit("/notifyalert/do?p=/passkey/session/issue&m=POST", { method: "POST", body: JSON.stringify({ email: s.mintSession }) });
          const tok = m.status === 200 ? (JSON.parse(m.text).token ?? null) : null;
          if (typeof tok !== "string" || tok.length === 0) break;
          headers.cookie = `__Host-downpipes_session=${tok}`;
          headers.origin = "https://console.test";
          delete headers.authorization;
        }
        let r;
        if (c.scim === true) {
          const h = { authorization: `Bearer ${SCIM_TOKEN}` };
          if (defer === false) h["x-notifyalert-defer"] = "0";
          r = await hit(`/notifyalert-scim/Users/${encodeURIComponent(`notifyalert-seed-${i}@example.test`)}`, { method: "DELETE", headers: h });
        } else {
          const body = c.bodyFor ? c.bodyFor(i) : (c.body ?? {});
          r = await hit(`/notifyalert-defer/admin${c.path}`, { method: c.method, headers, ...(c.method === "GET" ? {} : { body: JSON.stringify(body) }) });
        }
        statuses.push(r.status);
        if (r.status !== c.status) bodies.push(r.text.slice(0, 240));
      }
      await new Promise((r) => setTimeout(r, 1500));
      const resolves = JSON.parse((await hit("/notifyalert/resolve-count")).text).resolves ?? 0;
      const afterRaw = await hit("/signal/read");
      if (afterRaw.status !== 200) return { setup: s.setup, setupOk: true, statuses, bodies, kpOk, readerReached: false, seen: 0, resolves, webhookDelta: sinkHits.webhook - webhookBefore };
      const after = JSON.parse(afterRaw.text);
      const seen = measure(after) - before;
      const aggKeys = wired
        ? (Array.isArray(after.notifyHistory) ? after.notifyHistory.map((h) => `${h?.event}|${String(h?.detail).slice(0, 46)}`) : []).slice(0, 8)
        : Object.keys(after.adminCounters ?? {}).filter((k) => k.startsWith("alert-emit-")).slice(0, 24);
      return { setup: s.setup, setupOk: true, statuses, bodies, kpOk, readerReached: true, seen, aggKeys, resolves, webhookDelta: sinkHits.webhook - webhookBefore };
    } finally {
      await mf.dispose();
    }
  };

  for (const c of cases) {
    for (const wired of [false, true]) {
      const deferred = await driveOnce(c, wired, true);
      const live = await driveOnce(c, wired, false);
      rows.push({ id: c.id, site: c.site, shape: c.shape, expect: c.expect, knownPositive: c.knownPositive === true, event: c.event, cls: c.cls, status: c.status, wired, ...deferred, live });
      // THE EMISSION-RAN EVIDENCE. The wired arm posts to the stub webhook sink once per drive, from INSIDE
      // routeEmission, after the channel resolve and before the record write. N posts prove the alert line
      // executed N times whatever the record then did. Carried onto the unwired rows because both wiring modes
      // drive the identical route.
      if (wired) emissionRan.set(c.id, { deferred: deferred.webhookDelta ?? 0, live: live.webhookDelta ?? 0, rDeferred: deferred.resolves ?? 0, rLive: live.resolves ?? 0 });
    }
  }

  // ---- the controls, read off the rows ---------------------------------------------------------------
  let failures = 0;
  say(`== TEN-ALERT KEEP-ALIVE, ${N} drives per case, ONE FRESH ISOLATE PER ARM ==`);
  say(`   the record asserted: unwired = adminCounters["alert-emit-<class>-no-channel"], wired = a notifyHistory row whose event AND detail are the ones THIS call site composes`);
  let knownPositiveKept = null;
  for (const r of rows) {
    const label = `${r.id}/${r.wired ? "wired" : "unwired"}`;
    if (r.setupOk === false) {
      say(`  ${label.padEnd(34)} SETUP FAILED -> COULD-NOT-CHECK`);
      for (const st of r.setup) say(`       setup ${st.stage} status=${st.status} ${st.body}`);
      couldNotCheck = true;
      continue;
    }
    const kept = r.seen >= N;
    const zero = r.seen === 0;
    const ran = emissionRan.get(r.id);
    // REACHABILITY IS THE RESOLVE-ISSUED ARM, on this row's OWN arms, because it is the only signal issued
    // before the first await. The webhook count is printed beside it and is NOT the gate: for a caller that
    // abandons the emission at that await the delivery never happens, so a webhook zero is a fact about the
    // defect and not about the drive.
    const reached = (r.resolves ?? 0) >= N && (r.live.resolves ?? 0) >= N;
    const verdict = !reached ? "NOT-REACHED" : kept ? "KEEPS" : zero ? "LOSES" : "PARTIAL";
    if (r.knownPositive) knownPositiveKept = knownPositiveKept === false ? false : kept;
    say(`  ${label.padEnd(34)} kp=${r.kpOk && r.live.kpOk ? "OK" : "DEAD"} st=${JSON.stringify(r.statuses)} ${verdict.padEnd(11)} seen=${r.seen}|${r.live.seen ?? 0}/${N}  resolves=${r.resolves ?? 0}|${r.live.resolves ?? 0}/${N}${ran ? `  delivered=${ran.deferred}|${ran.live}/${N}` : ""}   [${r.shape}]`);
    if (r.bodies.length > 0) say(`       an off-status body: ${r.bodies[0]}`);
    if (!r.readerReached || !r.live.readerReached) {
      say("       THE READER DID NOT REACH ITS ENDPOINT -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!r.kpOk || !r.live.kpOk) {
      say("       THE AWAITED KNOWN POSITIVE WAS NOT READ BACK IN THIS ISOLATE: the reader is dead and this zero means nothing -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!r.statuses.every((s) => s === r.status)) {
      say(`       THE DRIVE DID NOT ANSWER ${r.status} ON EVERY ATTEMPT, so it did not reach the call site -> COULD-NOT-CHECK`);
      couldNotCheck = true;
    }
    if (r.status !== 429 && r.statuses.some((s) => s === 429)) {
      say("       AN UNASKED-FOR 429 APPEARED: the shared limiter refused before the call site, so this zero means nothing -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!reached) {
      say("       REACHABILITY NOT ESTABLISHED: routeEmission did not issue its channel resolve once per drive, so the");
      say("       alert line did not demonstrably execute and this zero is a drive that missed -> COULD-NOT-CHECK");
      say(`       the arm held ${JSON.stringify((r.live.aggKeys ?? []).slice(0, 8))}`);
      couldNotCheck = true;
    }
    // The two reachability signals DISAGREEING is a fact worth printing rather than smoothing: the alert line
    // ran and the delivery did not, which means the emission was abandoned between the two.
    if (reached && r.wired && ran !== undefined && (ran.deferred < N || ran.live < N)) {
      say(`       THE EMISSION RAN AND THE DELIVERY DID NOT: resolve ${r.resolves}|${r.live.resolves} of ${N} against webhook ${ran.deferred}|${ran.live} of ${N}.`);
      say("       The alert was abandoned at its first await, so no human was told either -- not merely a lost record.");
    }
    if (r.expect !== undefined) {
      const want = r.expect === "keep";
      if (want !== kept) {
        failures++;
        say(`       FAIL expected ${r.expect}, measured ${verdict}`);
        say(`       the deferred arm held ${JSON.stringify((r.aggKeys ?? []).slice(0, 8))}`);
      }
    }
  }
  // THE KNOWN POSITIVE'S OWN GATE. It must read KEEPS in every run, including a run where a site under test
  // reads zero. If it does not, the instrument is measuring itself and no zero below it means anything.
  if (knownPositiveKept !== true) {
    say("   THE KNOWN POSITIVE (dest-change-set, measured KEEPS at 7935cff6 on this same helper) DID NOT READ KEEPS.");
    say("   Every reading in this run is worthless -> COULD-NOT-CHECK");
    couldNotCheck = true;
  }
  say(`   sink: head=${sinkHits.head} put=${sinkHits.put} delete=${sinkHits.delete} objectLock=${sinkHits.objectLock} webhook=${sinkHits.webhook} unrouted=${sinkHits.other.length}`);
  if (sinkHits.other.length > 0) say(`   UNROUTED OUTBOUND (the stub did not answer these): ${JSON.stringify([...new Set(sinkHits.other)].slice(0, 6))}`);

  const out = { n: N, rows, failures, couldNotCheck, sinkHits };
  if (JSON_OUT) writeFileSync(JSON_OUT, `${JSON.stringify(out, null, 1)}\n`);
  if (couldNotCheck) {
    say("VERDICT: COULD-NOT-CHECK (exit 4). This is NOT a pass.");
    return 4;
  }
  say(failures === 0 ? "TEN-ALERT KEEP-ALIVE PASS" : `TEN-ALERT KEEP-ALIVE FAIL (${failures} arm(s))`);
  return failures === 0 ? 0 : 1;
}

main().then(
  (c) => process.exit(c),
  (e) => {
    console.error("TEN-ALERT DRIVE FAILED:", e);
    process.exit(1);
  },
);

export { LEAF_CASES };
