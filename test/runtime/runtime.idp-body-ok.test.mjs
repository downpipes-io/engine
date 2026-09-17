// runtime.idp-body-ok.test.mjs -- does an IdP change the DURABLE OBJECT REFUSED still raise an alert
// saying it was requested?
//
// Run: node test/runtime/runtime.idp-body-ok.test.mjs [--n 3] [--calibrate] [--probe] [--only <id>]
//                                                            [--json <path>] [--before]
//
// The IdP routes fire their alert on the TRANSPORT-level `resp.ok` rather than on the response BODY's own
// `ok` field.
//
// THE SET IS FOUR. router-identity.ts:876 (add), :890 (delete), :906 (enable/disable) and :923
// (SAML signing-cert rollover) all read `<resp>.ok`.
//
// WHY THE TRANSPORT RESULT IS NOT THE BODY'S RESULT HERE, read off source. Every one of the four DO methods
// (scheduler-do-idp.ts idpConnCreate / idpConnDelete / idpConnSetEnabled / idpConnSamlCertUpdate) returns
// `{ ok:false, reason }` on a refusal, and scheduler-do.ts:773 ownerActionJson wraps that in `this.json(...)`,
// which is a plain HTTP 200. So a refused change is a 200 and `resp.ok` is TRUE. The router even KNOWS this:
// eleven lines above the add alert it clones the response and branches on `peek.ok === false` to classify the
// refusal. It then fires the alert on the transport result anyway.
//
// AND THE TRANSPORT RESULT IS NOT SIMPLY WRONG EITHER, which is the reason a naive repair is a regression.
// ownerActionJson ALSO returns a 202 `{ ownerActionQueued:true, id, actionHash, status }` when dual control is
// armed: the change did not run, it is waiting for a second owner. That body has NO `ok` field at all, so
// gating the alert on `body.ok === true` would DELETE the queued alert -- and router.ts:664 fires an alert on
// the approve path for `dual-control-disable` AND NOTHING ELSE, so the propose-time alert is the ONLY alert an
// IdP change under dual control ever gets. The word the four sites use is "was requested", which is exactly
// right for a queued change and wrong only for a refused one.
//
// SO THE FOUR OUTCOMES THIS FILE SEPARATES, and it separates them by MEASUREMENT rather than by reading:
//   applied  200 { ok:true, deleted:true }  -> the alert MUST fire (unchanged)
//   queued   202 { ownerActionQueued }      -> the alert MUST fire (unchanged; "requested" is the true word)
//   refused  200 { ok:false, reason }       -> the alert MUST NOT fire; nothing changed and nothing was queued
//   no-op    200 { ok:true, deleted:false } -> the alert MUST NOT fire; the delete found nothing to delete
//
// THE FOURTH OUTCOME. A delete of a VALID-SHAPED BUT ABSENT connection is NOT a
// refusal, so doRefusedTheChange is blind to it by construction: it passes every gate and every validator and
// rightly answers ok:true. It also removed nothing and wrote NO AUDIT ROW, because idpConnDelete guards the
// append on the same `existed` it now reports. The mechanism is the MIRROR of the refusal defect rather than
// the same one -- there the router ignored a verdict the DO gave, here the DO gave no verdict for the router
// to read -- so the repair is a FIELD on the DO's response (`deleted`), spelled exactly as the sibling that
// solved it first (router-rbac.ts:144), and a second helper, doDeletedNothing, that reads it. What gets
// AUDITED is unchanged: the skip was always right, it was the silence about the skip that was not.
//
// AND THE NO-OP TEST IS NO MORE A SUCCESS TEST THAN THE REFUSAL TEST IS. Only an explicit `deleted:false`
// suppresses. The 202 body carries no `deleted` field at all, so `deleted === true` would have deleted the
// queued alert exactly as `ok === true` would have -- which is why idp-delete-queued is driven in every
// scored run here and must read N/N before and after.
//
// THE HOUSE ALREADY STATES THE RULE, eleven lines from a sibling site. router-rbac.ts:144 reads the BODY:
// "notify on an ACTUAL offboarding ... The DO returns { deleted:true } only when a member was really removed;
// a no-op delete of an absent member returns { deleted:false } and is not a change worth alerting on." And
// routeAuthChangeAlert's own contract (router-notify.ts:217) opens "The change itself is already committed +
// AUDITED in the DO". A refusal commits nothing and audits nothing.
//
// THE ASSERTION IS THE EXACT RECORD, never existence and never a count. Wired: a notify-history row whose
// event is the one this alert emits AND whose detail is the one THIS call site composes. All four IdP sites
// share the event `auth-credential-change` AND the class `idp-change`, so a mutant that files the ADD alert
// under the REMOVAL route's name leaves the event, the class, the counter name, the counts and the row count
// all identical and is caught ONLY by the detail. Unwired: the composed `alert-emit-idp-change-no-channel`
// counter, which is CLASS-grained and therefore cannot tell the four apart -- stated, not glossed: the
// unwired arm proves a record survived, the wired arm proves it was the RIGHT record.
//
// THE ZERO IS THE WHOLE POINT HERE, so it carries controls a zero cannot borrow:
//  * EVERY REFUSED CASE IS DRIVEN BESIDE ITS OWN APPLIED TWIN, same site, same isolate shape, same reader,
//    same run. A refused case reading 0 next to an applied twin reading N/N is the body doing the work. A
//    refused case reading 0 next to an applied twin ALSO reading 0 is a dead site, and is reported as
//    could-not-check rather than as a pass.
//  * THE ROUTE'S OWN ANSWER IS ASSERTED, status AND body class. A refused drive must come back 200 with a
//    body carrying `ok:false`; if it comes back 400, 403 or 429 the site was never reached and the arm is
//    could-not-check. An unasked-for 429 from the shared per-caller limiter is never read as a clean zero.
//  * THE RESOLVE-ISSUED ARM: routeEmission's first
//    statement is the /notify/resolve fetch, issued synchronously on entry, so a counted resolve proves the
//    ALERT LINE ran.
//    For a must-fire case it must read N; for a must-not-fire case it must read 0, and the two together are
//    a much sharper reading than the history row alone -- a suppressed alert issues no resolve at all.
//  * THE KNOWN POSITIVE OF THE RIGHT KIND rides in EVERY scored run, --only included: control-dest-change-set
//    (router-destinations.ts:272), a site whose alert holds steady on the same
//    routeEmission helper, in the same runtime, with the same deferred dispatch. It is a site whose alert this
//    change does not touch, so it must read N/N in every run INCLUDING one where a site under test reads zero.
//  * THE READER'S OWN known positive, AWAITED, taken after setup and before any drive.
//  * CALIBRATION (--calibrate) on the shared worker's floating-promise pair, which MUST separate (0/N bare
//    against N/N kept) before anything below is trusted. The in-flight-subrequest pair is printed beside it
//    because it reads N/N on BOTH and is the arm that produced a false could-not-check over a real defect.
//
// --before scores the PRE-REPAIR expectations (every refused case FIRES, and every no-op case with it), so
// the same instrument reads the defect and the repair without being edited between the two runs. A case whose
// response SHAPE moved under the repair also carries verdictBefore, so --before asserts the DO answer an
// UNREPAIRED engine really gives rather than the one this one does.
//
// AND --before COVERS A MIXED VINTAGE, which is stated rather than glossed because it will otherwise read as
// a bug. The refusal guard and the no-op field are two separate repairs, so firesBefore describes the engine
// before EACH repair, not one single unrepaired engine. Read --before as "what did the engine do before the
// repair this case is about".
//
// Nothing leaves the machine: every host is a .test name answered in-process by the Miniflare outboundService.
//
// Exit: 0 every case matched its expectation; 1 a case disagreed; 4 could-not-check.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "admin-refusal-keepalive-worker.ts");
const OUT = join(here, ".bundle", "idp-body-ok-worker.js");
const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : d;
};
const N = Number(argOf("--n", "3"));
const JSON_OUT = argOf("--json", null);
const ONLY = argOf("--only", null);
const CALIBRATE = args.includes("--calibrate");
const PROBE = args.includes("--probe");
const BEFORE = args.includes("--before");
const TOKEN = "signal-keepalive-test-token";
const IP = "203.0.113.7";

const say = (s) => console.log(s);
let couldNotCheck = false;

const DEST_CONFIG = {
  endpoint: "https://s3.destchange-sink.test",
  bucket: "destchange-bucket",
  region: "auto",
  accessKeyId: "DESTCHANGETESTKEYID000000",
  secretAccessKey: "destchange-test-secret",
};

// ---- a minimal DER X.509 cert, lifted from test/validate-idp-rollover-lockout.ts so a rollover that must be
//      APPLIED has a certificate validateSamlCerts accepts and certNotAfter can parse. -----------------------
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
const ascii = (s) => Array.from(s).map((c) => c.charCodeAt(0));
const toPem = (b64) => `-----BEGIN CERTIFICATE-----\n${b64.replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;
const buildCert = (notAfterUtc, serial) => {
  const tbs = tlv(0x30, [
    ...tlv(0x02, [serial & 0xff]),
    ...tlv(0x30, []),
    ...tlv(0x30, []),
    ...tlv(0x30, [...tlv(0x17, ascii("200101000000Z")), ...tlv(0x17, ascii(notAfterUtc))]),
  ]);
  return toPem(Buffer.from(tlv(0x30, tbs)).toString("base64"));
};
const CERT_A = buildCert("300101000000Z", 11);
const CERT_B = buildCert("350101000000Z", 12);

// An OIDC proposal the DO's pure pre-write validators ACCEPT, and its REFUSED twin: the same proposal with a
// plain-http issuer, which is the first refusal the add route refuses on ("the issuer is not https"). Only
// that one field differs, so the two drives
// differ in the DO's verdict and in nothing else.
const okProposal = (id) => ({
  id,
  kind: "oidc",
  label: `idp-body-ok ${id}`,
  presetId: "generic-oidc",
  issuer: "https://idp.bodyok-sink.test",
  clientId: "bodyok-client",
  scopes: ["openid"],
  idTokenSigAlgs: ["RS256"],
  pkce: "required",
  clientAuth: "pkce_public",
  requireNonce: true,
  enabled: false,
});
const refusedProposal = (id) => ({ ...okProposal(id), issuer: "http://idp.bodyok-sink.test" });

const samlProposal = (id) => ({
  id,
  kind: "saml",
  label: `idp-body-ok saml ${id}`,
  presetId: "generic-saml",
  enabled: false,
  idpEntityId: "https://idp.bodyok-sink.test/entity",
  idpSsoUrl: "https://idp.bodyok-sink.test/sso",
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

const IDP_EVENT = "auth-credential-change";
const IDP_CLS = "idp-change";
const D_ADD = "An IdP connection add was requested (changes who can sign in)";
const D_DEL = "An IdP connection removal was requested (changes who can sign in)";
const D_ENA = "An IdP connection enable/disable was requested (changes who can sign in)";
const D_CERT = "A SAML signing-certificate rollover was requested (an IdP trust-root change)";

// ---------------------------------------------------------------------------------------------------------
// THE CASES. `verdict` is what the DO must answer for the drive to have reached the site at all, and it is
// ASSERTED, not assumed. `fires` is the alert expectation AFTER the repair; `firesBefore` is what the
// unrepaired engine does, so --before scores the defect with the same instrument.
// ---------------------------------------------------------------------------------------------------------
const CASES = [
  // THE KNOWN POSITIVE OF THE RIGHT KIND, first on purpose and forced into every --only run. Its alert is not
  // touched by this change, so it must read N/N in every scored run including one where a site under test
  // reads zero. If it reads anything else the instrument is measuring itself.
  {
    id: "control-dest-change-set",
    knownPositive: true,
    site: "router-destinations.ts:272 POST /destination -- KNOWN POSITIVE, fires reliably",
    path: "/destination",
    method: "POST",
    body: { config: DEST_CONFIG },
    status: 200,
    // POST /destination answers with the stored destination RECORD, which carries no `ok` field at all. That
    // is asserted as its own verdict rather than glossed: this site is untouched by the change under test and
    // its answer shape is part of what must stay identical.
    verdict: "no-ok-field",
    event: "dest-change",
    detail: "A backup destination was set/repointed.",
    cls: "dest-change",
    fires: true,
    firesBefore: true,
  },

  // ---- ADD (router-identity.ts:876) ----------------------------------------------------------------------
  {
    id: "idp-add-applied",
    twin: "idp-add-refused",
    site: "router-identity.ts:876 POST /idp/connections -- the DO ACCEPTS the proposal and the connection lands",
    path: "/idp/connections",
    method: "POST",
    bodyFor: (i) => ({ proposal: okProposal(`bodyok-add-${i}`) }),
    status: 200,
    verdict: "ok-true",
    event: IDP_EVENT,
    detail: `${D_ADD}.`,
    cls: IDP_CLS,
    fires: true,
    firesBefore: true,
  },
  {
    id: "idp-add-refused",
    site: "router-identity.ts:876 POST /idp/connections -- the DO REFUSES (issuer is not https) and writes NOTHING",
    path: "/idp/connections",
    method: "POST",
    bodyFor: (i) => ({ proposal: refusedProposal(`bodyok-badadd-${i}`) }),
    status: 200,
    verdict: "ok-false",
    event: IDP_EVENT,
    detail: `${D_ADD}.`,
    cls: IDP_CLS,
    fires: false,
    firesBefore: true,
  },

  // ---- DELETE (router-identity.ts:890) -------------------------------------------------------------------
  {
    id: "idp-delete-applied",
    // TWO must-not-fire cases hang off this one applied twin, and they are different defects: the REFUSAL the
    // DO rejected outright, and the NO-OP it accepted and did nothing for. Both of their zeros are readings
    // only if this case fires in the same run, so both are checked against it.
    twin: ["idp-delete-refused", "idp-delete-absent"],
    site: "router-identity.ts:890 POST /idp/connections/delete -- a real connection is removed",
    path: "/idp/connections/delete",
    method: "POST",
    seed: "idp-per-drive",
    bodyFor: (i) => ({ connId: `bodyok-seed-${i}` }),
    status: 200,
    verdict: "ok-true-deleted",
    verdictBefore: "ok-true",
    event: IDP_EVENT,
    detail: `${D_DEL}.`,
    cls: IDP_CLS,
    fires: true,
    firesBefore: true,
  },
  {
    id: "idp-delete-refused",
    site: "router-identity.ts:890 POST /idp/connections/delete -- the DO REFUSES (invalid connId) and removes NOTHING",
    path: "/idp/connections/delete",
    method: "POST",
    body: { connId: "bodyok NOT a conn id!" },
    status: 200,
    verdict: "ok-false",
    event: IDP_EVENT,
    detail: `${D_DEL}.`,
    cls: IDP_CLS,
    fires: false,
    firesBefore: true,
  },

  // THE NO-OP, MEASURED AND HANDED OVER EARLIER AND REPAIRED BY THIS RUN. It is a THIRD outcome, not a
  // second refusal, and the distinction is the whole subject: a delete of a connection that is VALID-SHAPED
  // BUT ABSENT passes every gate and every validator, so idpConnDelete answers `ok:true` and
  // doRefusedTheChange is blind to it by construction. It removed nothing, and it wrote NO AUDIT ROW -- the
  // append is guarded on the same `existed` -- so the alert was announcing a change the durable object had
  // not even recorded as one. The mechanism is the mirror of the refusal defect rather than the same one:
  // there, the router ignored a verdict the DO gave; here, the DO gave no verdict for the router to read.
  //
  // ITS TWIN IS idp-delete-applied AND THE TWIN IS THE POINT: same route, same isolate shape, same reader,
  // same run, and the ONLY difference between them is whether the connection was there. The applied twin must
  // read 3/3 with `deleted:true` in the same run this reads 0/3 with `deleted:false`, or the zero is a dead
  // site and not a suppressed alert. Both verdicts are asserted off the response BEFORE either alert count is
  // read, and an engine that has not been repaired answers a bare `ok-true` here, which fails the verdict
  // assertion and is reported as COULD-NOT-CHECK rather than borrowed as a pass.
  {
    id: "idp-delete-absent",
    site: "router-identity.ts:890 POST /idp/connections/delete -- valid connId, NO such connection: the DO removes nothing and says so",
    path: "/idp/connections/delete",
    method: "POST",
    body: { connId: "bodyok-never-existed" },
    status: 200,
    verdict: "ok-true-deleted-nothing",
    verdictBefore: "ok-true",
    event: IDP_EVENT,
    detail: `${D_DEL}.`,
    cls: IDP_CLS,
    fires: false,
    firesBefore: true,
  },

  // ---- ENABLE/DISABLE (router-identity.ts:906) -----------------------------------------------------------
  {
    id: "idp-enabled-applied",
    twin: "idp-enabled-refused",
    site: "router-identity.ts:906 POST /idp/connections/enabled -- a real connection is enabled",
    path: "/idp/connections/enabled",
    method: "POST",
    seed: "idp-per-drive",
    bodyFor: (i) => ({ connId: `bodyok-seed-${i}`, enabled: true }),
    status: 200,
    verdict: "ok-true",
    event: IDP_EVENT,
    detail: `${D_ENA}.`,
    cls: IDP_CLS,
    fires: true,
    firesBefore: true,
  },
  {
    id: "idp-enabled-refused",
    site: "router-identity.ts:906 POST /idp/connections/enabled -- the DO REFUSES (connection not found), no flag flips",
    path: "/idp/connections/enabled",
    method: "POST",
    body: { connId: "bodyok-absent-conn", enabled: true },
    status: 200,
    verdict: "ok-false",
    event: IDP_EVENT,
    detail: `${D_ENA}.`,
    cls: IDP_CLS,
    fires: false,
    firesBefore: true,
  },

  // ---- SAML CERT ROLLOVER (router-identity.ts:923) -------------------------------------------------------
  // The refused twin here is the SHARPEST of the four: posting { certs: [] } at an OIDC seed connection, which
  // idpConnSamlCertUpdate refuses with "cert rollover applies only to a SAML connection". A refused rollover
  // over a connection that is not even SAML has been raising "a SAML signing-certificate rollover was
  // requested" in-tree, measured, and scored green.
  {
    id: "idp-cert-applied",
    twin: "idp-cert-refused",
    site: "router-identity.ts:923 POST /idp/connections/cert -- a real SAML connection's pinned certs are replaced",
    path: "/idp/connections/cert",
    method: "POST",
    seed: "saml-per-drive",
    bodyFor: (i) => ({ connId: `bodyok-saml-${i}`, certs: [CERT_B] }),
    status: 200,
    verdict: "ok-true",
    event: IDP_EVENT,
    detail: `${D_CERT}.`,
    cls: IDP_CLS,
    fires: true,
    firesBefore: true,
  },
  {
    id: "idp-cert-refused",
    site: "router-identity.ts:923 POST /idp/connections/cert -- the DO REFUSES (the connection is OIDC, not SAML)",
    path: "/idp/connections/cert",
    method: "POST",
    seed: "idp-once",
    body: { connId: "bodyok-seed-0", certs: [] },
    status: 200,
    verdict: "ok-false",
    event: IDP_EVENT,
    detail: `${D_CERT}.`,
    cls: IDP_CLS,
    fires: false,
    firesBefore: true,
  },

  // ---- THE QUEUED CASE: the regression guard on the repair -----------------------------------------------
  // Dual control armed + an ATTRIBUTABLE (cookie-borne, owner) caller, because recordOwnerAction refuses a
  // bare-token proposer outright. The DO answers 202 { ownerActionQueued } and the change has NOT run. The
  // alert MUST still fire, before and after, and "was requested" is the true word for it: router.ts:664 fires
  // an alert on approve for dual-control-disable and for nothing else, so this is the only alert this change
  // will ever produce. A repair that gates on `body.ok === true` silently deletes it.
  {
    id: "idp-add-queued",
    site: "router-identity.ts:876 POST /idp/connections -- dual control ARMED, the DO QUEUES for a second owner",
    path: "/idp/connections",
    method: "POST",
    seed: "queued-owner",
    sessionEmail: "bodyok-owner@example.test",
    bodyFor: (i) => ({ proposal: okProposal(`bodyok-queued-${i}`) }),
    status: 202,
    verdict: "queued",
    event: IDP_EVENT,
    detail: `${D_ADD}`,
    cls: IDP_CLS,
    fires: true,
    firesBefore: true,
  },
  // A SECOND QUEUED CASE, ON A SECOND ROUTE, GUARDS AGAINST A MUTANT THAT WOULD OTHERWISE SURVIVE. If only
  // the add route drove a queued body, a mutant that turns the shared helper's refusal test into a success
  // test (`.ok !== true`) would suppress every refusal exactly as the real repair does, and the only body it
  // wrongly suppresses -- the queued one -- would be reached only through the one route the first case does
  // not serve. Driving a queued change through a second route as well closes that gap: all four sites call
  // the one helper, and a mutation of it is caught on both routes.
  {
    id: "idp-delete-queued",
    site: "router-identity.ts:890 POST /idp/connections/delete -- dual control ARMED, queued THROUGH doRefusedTheChange",
    path: "/idp/connections/delete",
    method: "POST",
    seed: "queued-owner-idp",
    sessionEmail: "bodyok-owner@example.test",
    body: { connId: "bodyok-seed-0" },
    status: 202,
    verdict: "queued",
    event: IDP_EVENT,
    detail: `${D_DEL}`,
    cls: IDP_CLS,
    fires: true,
    firesBefore: true,
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
      return new Response("", { status: 200, headers: { etag: '"bodyok"' } });
    }
    if (request.method === "DELETE") {
      sinkHits.delete++;
      return new Response("", { status: 204 });
    }
  }
  sinkHits.other.push(`${request.method} ${u.host}${u.pathname}`);
  return new Response("bodyok sink: unrouted", { status: 502 });
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
// may carry an actor suffix the harness's caller does not always produce, so the match is a PREFIX on the
// composed detail -- which still separates every site from every other, because no two of these details share
// a prefix. All four IdP details begin differently ("An IdP connection add", "An IdP connection removal",
// "An IdP connection enable/disable", "A SAML signing-certificate rollover"), which is the whole reason the
// detail and not the event is the assertion.
function historyMatches(history, event, detail) {
  if (!Array.isArray(history)) return 0;
  const want = detail.replace(/\.$/, "");
  return history.filter((h) => h !== null && typeof h === "object" && h.event === event && typeof h.detail === "string" && h.detail.startsWith(want)).length;
}

// classifyVerdict reads the DO's OWN answer out of the route's response, which is the evidence that the drive
// reached the site at all. This is the control a "must not fire" case cannot do without: a zero alert count
// beside a 403 or a 429 is a drive that never happened, not a suppressed alert.
function classifyVerdict(status, text) {
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    return status === 200 || status === 202 ? "non-json" : `http-${status}`;
  }
  if (body !== null && typeof body === "object" && body.ownerActionQueued === true) return "queued";
  if (body !== null && typeof body === "object" && body.ok === false) return "ok-false";
  // THE DELETE'S THIRD OUTCOME IS READ HERE AND NOWHERE ELSE. `ok:true` alone is two states, not one: a real
  // removal and a no-op over an absent connection. The DO now separates them with `deleted`, and this reads it
  // BEFORE any alert count is read, so an absent case that scores zero has already proved the durable object
  // said "I removed nothing" -- rather than the drive having quietly 400ed, 403ed or 429ed short of the site.
  // A body still carrying a bare `ok:true` with no `deleted` at all classifies as ok-true and therefore FAILS
  // the absent case's verdict assertion, which is what makes an unrepaired engine could-not-check here instead
  // of a clean zero.
  if (body !== null && typeof body === "object" && body.ok === true && body.deleted === true) return "ok-true-deleted";
  if (body !== null && typeof body === "object" && body.ok === true && body.deleted === false) return "ok-true-deleted-nothing";
  if (body !== null && typeof body === "object" && body.ok === true) return "ok-true";
  if (status === 429) return "http-429";
  if (status !== 200 && status !== 202) return `http-${status}`;
  return "no-ok-field";
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
      bindings: { ADMIN_TOKEN: TOKEN, CONSOLE_ORIGIN: "https://console.test" },
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
  const doPost = (hit, p, body) => hit(`/notifyalert/do?p=${encodeURIComponent(p)}&m=POST`, { method: "POST", body: JSON.stringify(body) });

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
    say("   the instrument separates the two holds, so a zero below is a real reading and not a blind reader");
    return 0;
  }

  // setupFor performs one case's preconditions on a fresh isolate. Everything goes STRAIGHT TO THE DO, never
  // through the admin router, because the router's own IdP routes ARE the call sites under test and seeding
  // through them would put the setup's own alerts into the aggregate the measurement then reads.
  const setupFor = async (hit, c, wired) => {
    const setup = [];
    if (wired) {
      const w = await hit("/signal/wire-alert-channel");
      setup.push({ stage: "wire", status: w.status });
      if (w.status !== 200) return { setup, ok: false };
    }
    if (c.seed === "idp-per-drive" || c.seed === "idp-once") {
      const n = c.seed === "idp-once" ? 1 : N;
      for (let i = 0; i < n; i++) {
        const s = await hit(`/notifyalert/seed-idp-conn?id=bodyok-seed-${i}`);
        setup.push({ stage: `seed-idp-${i}`, status: s.status, body: s.text.slice(0, 160) });
        if (s.status !== 200) return { setup, ok: false };
      }
    }
    if (c.seed === "saml-per-drive") {
      for (let i = 0; i < N; i++) {
        const s = await doPost(hit, "/idp/conn/create", { proposal: samlProposal(`bodyok-saml-${i}`) });
        setup.push({ stage: `seed-saml-${i}`, status: s.status, body: s.text.slice(0, 160) });
        if (s.status !== 200 || classifyVerdict(s.status, s.text) !== "ok-true") return { setup, ok: false };
      }
    }
    if (c.seed === "queued-owner-idp") {
      // The connection is seeded BEFORE dual control is armed, on purpose: once the gate is on, the DO's own
      // /idp/conn/create refuses a bare-token proposer outright, so a seed taken afterwards would 500 the setup
      // rather than lay down the connection the drive then acts on.
      const s = await hit("/notifyalert/seed-idp-conn?id=bodyok-seed-0");
      setup.push({ stage: "seed-idp-0", status: s.status, body: s.text.slice(0, 160) });
      if (s.status !== 200) return { setup, ok: false };
    }
    if (c.seed === "queued-owner" || c.seed === "queued-owner-idp") {
      // An ATTRIBUTABLE owner, granted straight on the DO (never through POST /admin/roles), then dual control
      // ARMED, also straight on the DO. Both are preconditions, not drives.
      const g = await doPost(hit, "/roles", { email: c.sessionEmail, role: "owner" });
      setup.push({ stage: "seed-owner", status: g.status, body: g.text.slice(0, 160) });
      if (g.status !== 200) return { setup, ok: false };
      const a = await doPost(hit, "/config/approval-policy", { requireConfigApproval: true });
      setup.push({ stage: "arm-dual-control", status: a.status, body: a.text.slice(0, 160) });
      if (a.status !== 200) return { setup, ok: false };
      return { setup, ok: true, mintSession: c.sessionEmail };
    }
    return { setup, ok: true };
  };

  // headersFor builds the caller for one drive. The queued case is COOKIE-BORNE with a session the DO's own
  // mint issued (the same mint a passkey login uses), because a bare-token proposer cannot queue an owner
  // action at all. The token is minted FRESH per drive rather than once up front.
  const headersFor = async (hit, s) => {
    const h = { ...auth, "CF-Connecting-IP": IP };
    if (s.mintSession === undefined) return h;
    const m = await doPost(hit, "/passkey/session/issue", { email: s.mintSession });
    const tok = m.status === 200 ? (JSON.parse(m.text).token ?? null) : null;
    if (typeof tok !== "string" || tok.length === 0) return null;
    delete h.authorization;
    h.cookie = `__Host-downpipes_session=${tok}`;
    h.origin = "https://console.test";
    return h;
  };

  // --only takes a COMMA-SEPARATED list, and the KNOWN POSITIVE always rides along whatever is asked for. A
  // scored run without it is a run whose zeros cannot be told apart from a dead instrument.
  const wanted = ONLY === null ? null : new Set(ONLY.split(","));
  const cases = wanted === null ? CASES : CASES.filter((c) => c.knownPositive === true || wanted.has(c.id));
  if (cases.length === 0 || (wanted !== null && cases.length === 1)) {
    say(`no case matched --only ${ONLY} -> COULD-NOT-CHECK`);
    return 4;
  }

  // ---- PROBE: show what each case's request actually answers, so an unreachable site is NAMED, not guessed -
  if (PROBE) {
    for (const c of cases) {
      const { mf, hit } = await mkInstance();
      try {
        const s = await setupFor(hit, c, false);
        if (!s.ok) {
          say(`  ${c.id.padEnd(24)} SETUP FAILED ${JSON.stringify(s.setup)}`);
          continue;
        }
        const headers = await headersFor(hit, s);
        if (headers === null) {
          say(`  ${c.id.padEnd(24)} SESSION MINT FAILED`);
          continue;
        }
        const body = c.bodyFor ? c.bodyFor(0) : (c.body ?? {});
        const r = await hit(`/notifyalert-defer/admin${c.path}`, { method: c.method, headers, body: JSON.stringify(body) });
        say(`  ${c.id.padEnd(24)} want=${c.status}/${c.verdict} got=${r.status}/${classifyVerdict(r.status, r.text)}  ${r.text.slice(0, 200).replace(/\n/g, " ")}`);
        say(`       setup: ${JSON.stringify(s.setup.map((x) => `${x.stage}=${x.status}`))}`);
      } finally {
        await mf.dispose();
      }
    }
    return 0;
  }

  const rows = [];

  // driveOnce runs ONE arm (wired or unwired) of ONE case in its OWN fresh isolate.
  const driveOnce = async (c, wired) => {
    const { mf, hit } = await mkInstance();
    try {
      const s = await setupFor(hit, c, wired);
      if (!s.ok) return { setupOk: false, setup: s.setup };

      // Control 0: the reader's own known positive, AWAITED, taken AFTER the setup and before any drive, so
      // the `before` baseline already contains anything the setup left behind.
      await hit("/signal/awaited");
      const kpRaw = await hit("/signal/read");
      const kp = kpRaw.status === 200 ? JSON.parse(kpRaw.text) : null;
      const kpOk = kp !== null && countOf(kp.authSignals, "recovery-ratelimited") >= 1 && countOf(kp.adminCounters, "degraded-read-providers-list") >= 1 && countOf(kp.testOutcomes, "idp") >= 1;
      const measure = (snap) => {
        if (snap === null) return 0;
        return wired ? historyMatches(snap.notifyHistory, c.event, c.detail) : countOf(snap.adminCounters, `alert-emit-${c.cls}-no-channel`);
      };
      const before = measure(kp);

      const verdicts = [];
      const statuses = [];
      // Zero the RESOLVE-ISSUED arm here, AFTER every setup step, so it counts only this arm's own drives.
      await hit("/notifyalert/resolve-count?reset=1");
      for (let i = 0; i < N; i++) {
        const headers = await headersFor(hit, s);
        if (headers === null) break;
        const body = c.bodyFor ? c.bodyFor(i) : (c.body ?? {});
        const r = await hit(`/notifyalert-defer/admin${c.path}`, { method: c.method, headers, body: JSON.stringify(body) });
        statuses.push(r.status);
        verdicts.push(classifyVerdict(r.status, r.text));
      }
      await new Promise((r) => setTimeout(r, 1500));
      const resolves = JSON.parse((await hit("/notifyalert/resolve-count")).text).resolves ?? 0;
      const afterRaw = await hit("/signal/read");
      const after = afterRaw.status === 200 ? JSON.parse(afterRaw.text) : null;
      const seen = measure(after) - before;
      return { setupOk: true, kpOk, seen, resolves, statuses, verdicts, drives: verdicts.length };
    } finally {
      await mf.dispose();
    }
  };

  say(`== ${BEFORE ? "BEFORE (the unrepaired engine: every refused change alerts)" : "AFTER (the repair: a refused change alerts NOT AT ALL)"} ==`);
  say(`   N=${N} per arm, a fresh isolate per arm, the DO subrequest dispatched a tick after the caller's turn`);
  say("");

  let failures = 0;
  const seenById = new Map();

  for (const c of cases) {
    const want = BEFORE ? c.firesBefore : c.fires;
    say(`  ${c.id}`);
    say(`     ${c.site}`);
    for (const wired of [false, true]) {
      const r = await driveOnce(c, wired);
      const arm = wired ? "wired  " : "unwired";
      if (r.setupOk !== true) {
        say(`     ${arm}  SETUP FAILED ${JSON.stringify(r.setup)} -> COULD-NOT-CHECK`);
        couldNotCheck = true;
        continue;
      }
      // The verdict a case must answer is the one THIS engine gives. A repaired delete answers
      // ok-true-deleted / ok-true-deleted-nothing where an unrepaired one answers a bare ok-true, so a case
      // whose response SHAPE moved carries verdictBefore and --before asserts that instead. The two runs stay
      // the same instrument reading two engines, rather than an instrument edited between them.
      const wantVerdict = BEFORE && c.verdictBefore !== undefined ? c.verdictBefore : c.verdict;
      const verdictOk = r.drives === N && r.verdicts.every((v) => v === wantVerdict);
      const statusOk = r.statuses.every((st) => st === c.status);
      say(
        `     ${arm}  kp=${r.kpOk ? "OK" : "DEAD"}  status=${[...new Set(r.statuses)].join(",")}  DO verdict=${[...new Set(r.verdicts)].join(",")}  resolves=${r.resolves}/${N}  alert rows=${r.seen}/${N}  want ${want ? `${N}/${N}` : `0/${N}`}`,
      );
      rows.push({ id: c.id, wired, want, seen: r.seen, resolves: r.resolves, verdict: [...new Set(r.verdicts)].join(","), statuses: [...new Set(r.statuses)].join(",") });
      if (wired) seenById.set(c.id, r.seen);

      if (!r.kpOk) {
        say("        THE READER'S OWN KNOWN POSITIVE WAS ABSENT -> COULD-NOT-CHECK");
        couldNotCheck = true;
      }
      // THE ROUTE MUST HAVE ANSWERED WHAT THE CASE SAYS IT ANSWERS. This is the control that stops a zero
      // alert count being read as a suppressed alert when it is really a drive that never reached the site.
      if (!statusOk || !verdictOk) {
        say(`        THE ROUTE DID NOT ANSWER ${c.status}/${wantVerdict} ON EVERY DRIVE -> COULD-NOT-CHECK, not a clean zero`);
        couldNotCheck = true;
        continue;
      }
      // THE RESOLVE-ISSUED ARM. routeEmission's first statement is the /notify/resolve fetch, issued
      // synchronously on entry, so this counts EXECUTIONS OF THE ALERT LINE and not deliveries.
      const wantResolves = want ? N : 0;
      if (r.resolves !== wantResolves) {
        failures++;
        say(`        FAIL the alert line executed ${r.resolves} time(s), expected ${wantResolves}`);
      }
      if (want ? r.seen < N : r.seen !== 0) {
        failures++;
        say(`        FAIL expected ${want ? `${N}/${N}` : `0/${N}`} alert rows, measured ${r.seen}/${N}`);
      }
    }
    say("");
  }

  // ---- THE TWIN CONTROL: a refused case's zero is only a zero if its APPLIED twin fired in the same run ---
  // Both twins ran in this process, against the same bundle, the same reader and the same helper. If the
  // applied twin is ALSO zero the site is dead and the refused zero says nothing at all.
  if (!BEFORE) {
    say("== TWIN CONTROL (wired arm): a refusal's zero is a reading only when its applied twin fired ==");
    for (const c of cases) {
      if (c.twin === undefined) continue;
      // `twin` is one id or several. The delete site has TWO must-not-fire twins hanging off one applied case
      // (a refusal and a no-op), and each one's zero has to be checked against that same applied reading.
      for (const twinId of Array.isArray(c.twin) ? c.twin : [c.twin]) {
      const applied = seenById.get(c.id);
      const refused = seenById.get(twinId);
      if (applied === undefined || refused === undefined) continue;
      const good = applied >= N && refused === 0;
      say(`   ${c.id.padEnd(22)} ${applied}/${N}   ${twinId.padEnd(22)} ${refused}/${N}   ${good ? "SEPARATED" : "NOT SEPARATED"}`);
      if (!good) {
        if (applied < N) {
          // The applied twin coming up short has ALREADY failed its own assertion above, so the run is a FAIL
          // and stays one. It must not be softened to could-not-check here: a mutation run scores exit 4 as
          // UNSCORED, so downgrading a detected mutation to "could not check" hides a kill the suite made.
          // A mutant that files the cert alert under the add route's name must be caught as a FAIL, not
          // reported as could-not-check.
          say("        the applied twin did not fire; its own arm already FAILED above, so this run stays a FAIL");
        } else {
          failures++;
        }
      }
      }
    }
    say("");
  }

  const kpSeen = seenById.get("control-dest-change-set");
  say(`   KNOWN POSITIVE control-dest-change-set (wired): ${kpSeen}/${N} -- it must be ${N}/${N} in every scored run`);
  say(`   sink: webhook=${sinkHits.webhook} unrouted=${sinkHits.other.length}${sinkHits.other.length > 0 ? ` ${JSON.stringify(sinkHits.other.slice(0, 5))}` : ""}`);
  if (kpSeen === undefined || kpSeen < N) {
    say("   THE KNOWN POSITIVE DID NOT FIRE -> every zero above is worthless, COULD-NOT-CHECK");
    couldNotCheck = true;
  }

  if (JSON_OUT !== null) writeFileSync(JSON_OUT, `${JSON.stringify({ n: N, before: BEFORE, rows, failures, couldNotCheck }, null, 2)}\n`);

  if (couldNotCheck) {
    say("VERDICT: COULD-NOT-CHECK (exit 4). This is NOT a pass.");
    return 4;
  }
  say(failures === 0 ? "VERDICT: PASS" : `VERDICT: FAIL (${failures} arm(s) disagreed)`);
  return failures === 0 ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e);
    process.exit(4);
  },
);
