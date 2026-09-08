// SCHEDULER-DO FAULT LEDGER validator.
//
// These seven gaps share one shape: the scheduler DO ABSORBS a fault (a coarse ceremony reason, a fail-open
// limiter, a `?? []` coercion, a fixed "unreachable" string, an early return) and the WHY existed only in a
// Workers Logs line that remote support structurally cannot read (the no-custody floor). Each block below
// proves the SAME two things the audit demands of every new recording:
//
//   (a) RECORDED ON THE FAULT PATH: the evidence is written when the fault happens (not on a happy path), and
//       it is READABLE BACK through the DO's support-pack read (GET /sched-diag).
//   (b) REDACTION-SAFE (binding, NO-CUSTODY): a customer value, a secret and a RAW ERROR planted at every one
//       of those sites NEVER appears in the recorded evidence, and every enum member it carries is drawn from
//       the closed vocabularies declared in src/sched/sched-fault-ledger.ts.
//
// What each area covers:
//   "sign-in failed (err:ab12cd)" / "internal error, errorId 7f3a..." -> the OPAQUE id the customer quotes
//        can finally be DEREFERENCED from the pack (stage + coarse class + a recurrence count), including the
//        stored-COSE-key corruption, which the caller only ever sees as their own bad_request.
//   "users randomly cannot sign in during busy periods" (a challenge EVICTED by a begin flood, not
//        expired), "the invite link fails for my colleague", "the console keeps refusing my sensitive action".
//   "every recovery code we try is rejected" -> which limiter tripped (per-email bucket, per-IP bucket, or
//        the limiter's own store failing CLOSED), and "I never got recovery codes at enrolment".
//   "the map said Fresh for weeks while my backups had stopped" -> the staleness rule NEVER ARMED.
//   "the pack shows zero failures during an outage the customer swears was full of them" -> the recorders'
//        OWN dropped writes are counted, and the shared rate limiter's silent fail-open is finally visible.
//   "our secondary destination has shown down for a week" -> WHY (expired credential / WORM refusal /
//        timeout), and a single-destination tenant gets a down indicator at all.
//   After a partial deploy: a route 404ing on every load, an enum-drifted counter that silently stops
//        incrementing, a `[]` coercion that CLEARS the detached-source marker, a real completion discarded.
//
// Run: node test/validate-sched-fault-ledger.ts

import { applyDroppedWrites } from "../src/admin/diag-records.ts";
import { RateLimitDO } from "../src/sched/ratelimit-do.ts";
import { PASSKEY_CHALLENGE_PREFIX, PASSKEY_CRED_PREFIX, PASSKEY_LOGIN_CHALLENGE_CAP } from "../src/sched/scheduler-do-base.ts";
import {
  CEREMONY_FAULT_KINDS,
  CONTRACT_FAULT_KINDS,
  CONTRACT_ROUTE_CLASSES,
  DROPPED_WRITES_KEY,
  DROPPED_WRITE_KINDS,
  ERROR_REASON_CLASSES,
  ERROR_STAGES,
  FRESHNESS_FAULT_CAUSES,
  REPLICATION_REASONS,
  appendRecentError,
  classifyReplicationReason,
  errorReasonClass,
  flushDroppedWrites,
  freshnessFaultCause,
  readSchedDiag,
  recordCeremonyFault,
  recordFreshnessFault,
  type LedgerStorage,
  type SchedDiagBundle,
} from "../src/sched/sched-fault-ledger.ts";
import { MockStorage, getFailures, makeConfig, makeScheduler, ok, stubFetch } from "./validate-scheduler-shared.ts";

declare const process: { exit(code?: number): never };

// The POISON values planted at every fault site. Each is something the ledger must NEVER carry: a raw
// destination error naming a live key, a customer bucket, a secret, an operator email, a source IP and a
// credential id. A substring scan over the serialised evidence is therefore conclusive.
const POISON_ERROR = "destination rejected the write: AccessDenied for AKIAPOISONKEY on bucket acme-crown-jewels";
const POISON_BUCKET = "acme-crown-jewels";
const POISON_SECRET = "s3cr3t-live-value-DO-NOT-LEAK";
const POISON_EMAIL = "cfo@acme-customer.example";
const POISON_IP = "203.0.113.77";
const POISON_CRED = "cred-POISON-abcdefghijklmnop";
const POISON_ALL = [POISON_ERROR, POISON_BUCKET, POISON_SECRET, POISON_EMAIL, POISON_IP, POISON_CRED, "AKIAPOISONKEY"];

function scanClean(label: string, subject: unknown): void {
  const json = JSON.stringify(subject ?? null);
  const leaked = POISON_ALL.filter((p) => json.includes(p));
  ok(`${label} (redaction: no raw error / secret / customer value in the record)`, leaked.length === 0);
}

async function diag(stub: Parameters<typeof stubFetch>[0]): Promise<SchedDiagBundle> {
  const res = await stubFetch(stub, "GET", "/sched-diag");
  return (await res.json()) as SchedDiagBundle;
}

// ---- per-destination failure ATTRIBUTION + the env-default destination's heartbeat ---------
async function testDestinationAttribution(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // The fan-out destination ids ride on the COMPLETION (the driver reports which destinations it proved down);
  // the config needs no console-set destination for that, so this drives the exact production body shape.
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-fanout"));
  const trig = (await (await stubFetch(stub, "POST", "/trigger", { id: "dp-fanout" })).json()) as { index: number };

  // A FAILED run whose coarse class carries the store's sanitised rejection code (an EXPIRED CREDENTIAL). The
  // old code booked every down destination as the literal "unreachable", so support could not tell this from a
  // WORM refusal or a timeout - three faults with three different owners and three different fixes.
  await stubFetch(stub, "POST", "/complete", {
    id: "dp-fanout",
    runId: "",
    index: trig.index,
    status: "failed",
    error: POISON_ERROR,
    downDestinationIds: ["dest-secondary"],
  });
  const repl = storage.rawGet<Record<string, { lastOk: boolean; reason?: string }>>("repl:dp-fanout");
  ok("the down destination's replication state is recorded", repl?.["dest-secondary"] !== undefined);
  ok("its reason is the CLOSED class `auth` (an expired/denied credential), not the fixed 'unreachable'", repl?.["dest-secondary"]?.reason === "auth");
  ok("the reason is a member of the closed vocabulary", (REPLICATION_REASONS as readonly string[]).includes(String(repl?.["dest-secondary"]?.reason)));
  scanClean("replication state", repl);

  // The classifier is the redaction boundary: it READS the coarse error only to SELECT an enum member, and
  // RETURNS that enum type. Every branch is exercised, and every output is in the closed set.
  const cases: Array<[string, string]> = [
    ["destination rejected the write (AccessDenied)", "auth"],
    ["destination rejected the write (InvalidObjectLockRetention)", "worm-refused"],
    ["destination rejected the write (SlowDown)", "throttled"],
    ["s3 PUT timed out after 30000ms", "timeout"],
    ["TLS handshake failed", "tls"],
    ["fetch failed: ECONNRESET", "network"],
    ["destination access error", "unreachable"],
    ["source read error", "other"],
  ];
  for (const [raw, want] of cases) {
    ok(`classifyReplicationReason(${JSON.stringify(raw.slice(0, 34))}) -> ${want}`, classifyReplicationReason(raw) === want);
  }
  ok("an absent/garbled coarse error falls to the historical `unreachable`, never to free text", classifyReplicationReason(undefined) === "unreachable" && classifyReplicationReason({ e: POISON_ERROR }) === "unreachable");
  ok("every classifier output is a member of the closed vocabulary", cases.every(([raw]) => (REPLICATION_REASONS as readonly string[]).includes(classifyReplicationReason(raw))));

  // The ENV-DEFAULT destination (no console destination id): recordReplicationState requires an id, so such a
  // tenant used to get NO per-destination down indicator ANYWHERE and triage started on the source side.
  const { stub: stub2 } = makeScheduler();
  await stubFetch(stub2, "POST", "/downpipes", makeConfig("dp-default"));
  const t2 = (await (await stubFetch(stub2, "POST", "/trigger", { id: "dp-default" })).json()) as { index: number };
  await stubFetch(stub2, "POST", "/complete", { id: "dp-default", runId: "", index: t2.index, status: "failed", error: `destination access error [${POISON_BUCKET}]` });
  let d = await diag(stub2);
  ok("a single-destination tenant NOW gets a down indicator (defaultDestination)", d.defaultDestination?.ok === false);
  ok("with a closed reason class and a first-down stamp ('down for a week' is a fact, not an inference)", d.defaultDestination?.reason === "unreachable" && typeof d.defaultDestination?.downSince === "string");
  scanClean("defaultDestination", d.defaultDestination);

  // A SOURCE-side failure must NOT be booked as a destination fault (that would send triage the wrong way).
  const { stub: stub3 } = makeScheduler();
  await stubFetch(stub3, "POST", "/downpipes", makeConfig("dp-src"));
  const t3 = (await (await stubFetch(stub3, "POST", "/trigger", { id: "dp-src" })).json()) as { index: number };
  await stubFetch(stub3, "POST", "/complete", { id: "dp-src", runId: "", index: t3.index, status: "failed", error: "source read error" });
  const d3 = await diag(stub3);
  ok("a SOURCE-side failure records NO destination-down verdict", d3.defaultDestination === null);

  // A later successful run SELF-HEALS the indicator.
  const t4 = (await (await stubFetch(stub2, "POST", "/trigger", { id: "dp-default" })).json()) as { index: number; runId: string };
  await stubFetch(stub2, "POST", "/complete", { id: "dp-default", runId: t4.runId, index: t4.index, status: "ok" });
  d = await diag(stub2);
  ok("a successful run clears the default-destination down indicator (it self-heals)", d.defaultDestination?.ok === true && d.defaultDestination.reason === null);
}

// ---- the staleness rule that never arms ----------------------------------------------------
async function testFreshnessUncomputable(): Promise<void> {
  // The pure predicate first (the same rule both the map and the overview share).
  ok("a non-positive cadence is `cadence-malformed`", freshnessFaultCause(0, "2026-07-10T00:00:00.000Z") === "cadence-malformed");
  ok("a non-finite cadence is `cadence-malformed`", freshnessFaultCause(Number.NaN, undefined) === "cadence-malformed");
  ok("an unparseable newest-run timestamp is `timestamp-malformed`", freshnessFaultCause(3600, "not-a-date") === "timestamp-malformed");
  ok("a well-formed downpipe records NOTHING (this is a fault path, not a happy path)", freshnessFaultCause(3600, "2026-07-10T00:00:00.000Z") === null);
  ok("every cause is a member of the closed vocabulary", (FRESHNESS_FAULT_CAUSES as readonly string[]).includes(String(freshnessFaultCause(0, ""))));

  const { stub, storage } = makeScheduler();
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-stale", { name: POISON_BUCKET }));
  // validateConfig REFUSES a cadence below 60 at the write boundary, so a malformed cadence can only reach the
  // store from an older/looser engine or a corrupt write. Plant one exactly as such a record would look.
  const ds = storage.rawGet<{ config: { cadenceSeconds: number } }>("dp:dp-stale")!;
  ds.config.cadenceSeconds = 0;
  await storage.put("dp:dp-stale", ds);

  const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "dp-stale" })).json()) as { index: number; runId: string };
  await stubFetch(stub, "POST", "/complete", { id: "dp-stale", runId: t.runId, index: t.index, status: "ok" });
  let d = await diag(stub);
  ok("the downpipe whose staleness rule can NEVER arm is marked", d.freshnessFaults["dp-stale"]?.cause === "cadence-malformed");
  scanClean("freshnessFaults", d.freshnessFaults);

  // Repairing the cadence CLEARS the marker (a healed downpipe must stop reporting a fault it no longer has).
  const fixed = storage.rawGet<{ config: { cadenceSeconds: number } }>("dp:dp-stale")!;
  fixed.config.cadenceSeconds = 3600;
  await storage.put("dp:dp-stale", fixed);
  const t2 = (await (await stubFetch(stub, "POST", "/trigger", { id: "dp-stale" })).json()) as { index: number; runId: string };
  await stubFetch(stub, "POST", "/complete", { id: "dp-stale", runId: t2.runId, index: t2.index, status: "ok" });
  d = await diag(stub);
  ok("a repaired downpipe's marker is CLEARED", d.freshnessFaults["dp-stale"] === undefined);

  // A healthy fleet leaves the record empty.
  const { stub: clean } = makeScheduler();
  await stubFetch(clean, "POST", "/downpipes", makeConfig("dp-ok"));
  const t3 = (await (await stubFetch(clean, "POST", "/trigger", { id: "dp-ok" })).json()) as { index: number; runId: string };
  await stubFetch(clean, "POST", "/complete", { id: "dp-ok", runId: t3.runId, index: t3.index, status: "ok" });
  ok("a healthy downpipe records no freshness fault", Object.keys((await diag(clean)).freshnessFaults).length === 0);
}

// ---- G013 / the DO-side ceremony fault classes + the errorId ring ---------------------------
async function testCeremonyFaults(): Promise<void> {
  const { stub, storage } = makeScheduler();

  // (1) rp.id absent: the SERVER's deploy config (an unset CONSOLE_ORIGIN after a host change) reported to
  // every user as their own bad_request. The wire response is unchanged; the cause is now counted.
  const begin = await stubFetch(stub, "POST", "/passkey/login/begin", { email: POISON_EMAIL });
  ok("the client response is UNCHANGED (still the coarse bad_request; no oracle is created)", ((await begin.json()) as { reason?: string }).reason === "bad_request");

  // (2) a STORED credential whose COSE key no longer decodes: the engine's OWN record is corrupt, but the user
  // is told bad_request and blames their browser. This is the single most misdiagnosed passkey ticket.
  await storage.put(`${PASSKEY_CRED_PREFIX}${POISON_CRED}`, {
    credentialId: POISON_CRED,
    email: POISON_EMAIL,
    cosePublicKey: "!!!not-valid-base64url!!!",
    alg: -7,
    signCount: 1,
    transports: [],
    aaguid: "AAAA",
    createdAt: "2026-07-01T00:00:00.000Z",
  });
  await storage.put(`${PASSKEY_CHALLENGE_PREFIX}login:cid1`, { challenge: "Y2hhbA", scope: "login:cid1", createdAt: Date.now(), expiresAt: Date.now() + 60_000 });
  const fin = await stubFetch(stub, "POST", "/passkey/login/finish", {
    challengeId: "cid1",
    rpId: "console.example",
    origin: "https://console.example",
    credential: { id: POISON_CRED, response: { clientDataJSON: "eyJ4IjoxfQ", authenticatorData: "AAAA", signature: "AAAA" } },
  });
  const finBody = (await fin.json()) as { ok: boolean; reason?: string; errorId?: string };
  ok("the corrupt STORED key still answers the caller coarsely (behaviour unchanged)", finBody.ok === false);

  // (3) a step-up demanded of a caller with no enrolled passkey: they can never satisfy it and the console just
  // keeps refusing the action.
  await stubFetch(stub, "POST", "/stepup/begin", { rpId: "console.example" });

  // (4) an invite token that is unknown/expired/consumed ("the link you sent me does not work").
  await stubFetch(stub, "POST", "/passkey/register/begin", { email: POISON_EMAIL, rpId: "console.example", inviteToken: `${POISON_SECRET}-token` });

  const d = await diag(stub);
  const kinds = Object.keys(d.ceremonyFaults);
  ok("an absent rp.id/origin is recorded as a SERVER-side cause (passkey-rpid-absent)", d.ceremonyFaults["passkey-rpid-absent"] !== undefined);
  ok("the corrupt stored COSE key is recorded as passkey-stored-key-corrupt (NOT as the user's bad_request)", d.ceremonyFaults["passkey-stored-key-corrupt"]?.count === 1);
  ok("a step-up with no enrolled passkey is recorded (stepup-no-passkey)", d.ceremonyFaults["stepup-no-passkey"]?.count === 1);
  ok("a registration refused by every authorisation path is recorded (passkey-register-forbidden)", d.ceremonyFaults["passkey-register-forbidden"] !== undefined);
  ok("every recorded kind is a member of the CLOSED ceremony vocabulary", kinds.every((k) => (CEREMONY_FAULT_KINDS as readonly string[]).includes(k)));
  ok("each entry is a {count,lastAt} pair (an int + a timestamp, never a message)", kinds.every((k) => typeof d.ceremonyFaults[k]!.count === "number" && typeof d.ceremonyFaults[k]!.lastAt === "string"));
  scanClean("G013/ceremonyFaults (the email, the credential id and the invite token were all planted)", d.ceremonyFaults);

  // (5) the errorId RING: the id the customer quotes from the toast is dereferenceable from the pack alone.
  ok("the ceremony's errorId is filed in the ring", d.recentErrors.length >= 1);
  ok("every ring entry carries a CLOSED stage + reason class + a count", d.recentErrors.every((r) => (ERROR_STAGES as readonly string[]).includes(r.stage) && (ERROR_REASON_CLASSES as readonly string[]).includes(r.reasonClass) && typeof r.count === "number"));
  ok("the ring carries NO message field at all", d.recentErrors.every((r) => Object.keys(r).sort().join(",") === "at,count,errorId,reasonClass,stage"));
  scanClean("recentErrors", d.recentErrors);
  const quoted = d.recentErrors[d.recentErrors.length - 1]!.errorId;
  ok("the quoted id can be looked up in the pack (support can finally answer 'err:...')", d.recentErrors.some((r) => r.errorId === quoted && r.stage === "login/finish"));

  // A caller-authored / non-engine id can NEVER enter the ring (the id is the one field a caller might hope to
  // influence, so the pattern guard is the redaction boundary).
  const ring = appendRecentError([], { errorId: "ab12cd", stage: "login/finish", reasonClass: "internal", count: 1, at: "t0" });
  const repeated = appendRecentError(ring, { errorId: "ab12cd", stage: "login/finish", reasonClass: "internal", count: 1, at: "t1" });
  ok("a RECURRING id bumps its count in place (one row + a count, not 64 identical rows)", repeated.length === 1 && repeated[0]!.count === 2);
  const bounded = Array.from({ length: 200 }).reduce<ReturnType<typeof appendRecentError>>((acc, _v, i) => appendRecentError(acc, { errorId: `${i.toString(16)}f`, stage: "do-route", reasonClass: "internal", count: 1, at: "t" }), []);
  ok("the ring is BOUNDED (a fault storm can never grow DO storage without limit)", bounded.length === 64);

  // The reason CLASS is derived from the closed PasskeyReason, never from a message.
  ok("a NON-PasskeyError (an engine fault the user is told is their own bad request) classes as `internal`", errorReasonClass(null) === "internal" && errorReasonClass(POISON_ERROR) === "internal");
  ok("a verification failure classes as `verify-failed`", errorReasonClass("signature") === "verify-failed" && errorReasonClass("origin") === "verify-failed");
}

// ---- a LIVE challenge evicted by a begin flood (not expired) --------------------------------
async function testChallengeEviction(): Promise<void> {
  const { stub, storage } = makeScheduler();
  const now = Date.now();
  // Fill the login-challenge family past its cap with LIVE (unexpired) challenges: exactly what an
  // unauthenticated begin flood does. The next begin sweeps and EVICTS the oldest survivors, so an innocent
  // user's in-flight sign-in dies with the same generic "challenge" reason a TTL expiry gives.
  for (let i = 0; i <= PASSKEY_LOGIN_CHALLENGE_CAP; i++) {
    await storage.put(`${PASSKEY_CHALLENGE_PREFIX}login:flood-${String(i).padStart(4, "0")}`, { challenge: "Y2hhbA", scope: `login:flood-${i}`, createdAt: now - (PASSKEY_LOGIN_CHALLENGE_CAP - i) * 10, expiresAt: now + 60_000 });
  }
  await stubFetch(stub, "POST", "/passkey/login/begin", { rpId: "console.example" });
  const d = await diag(stub);
  ok("the EVICTION (the begin-flood tell) is recorded, distinct from a TTL expiry", d.ceremonyFaults["passkey-challenge-evicted"] !== undefined);
  scanClean("challenge eviction", d.ceremonyFaults);

  // No flood, no eviction: the counter is written by the fault path only.
  const { stub: quiet } = makeScheduler();
  await stubFetch(quiet, "POST", "/passkey/login/begin", { rpId: "console.example" });
  ok("an ordinary begin records NO eviction (fault path only)", (await diag(quiet)).ceremonyFaults["passkey-challenge-evicted"] === undefined);
}

// ---- WHICH recovery limiter tripped, and the silent generation/regenerate failures ----------
async function testRecoveryCauses(): Promise<void> {
  const { stub, storage } = makeScheduler();

  // The per-EMAIL bucket: six attempts from one account (the cap is 5). Every one answers the SAME generic
  // failure to the caller (the no-oracle property, unchanged) - the pack now says WHICH bucket denied.
  for (let i = 0; i < 6; i++) {
    await stubFetch(stub, "POST", "/recovery/recover", { email: POISON_EMAIL, code: `${POISON_SECRET}-${i}`, ip: POISON_IP });
  }
  let d = await diag(stub);
  ok("the per-EMAIL bucket denial is named (this one account is being sprayed)", d.ceremonyFaults["recovery-denied-email-bucket"] !== undefined);
  scanClean("recovery bucket faults (the email, the IP and the codes were all planted)", d.ceremonyFaults);

  // The limiter's own STORE failing: the attempt is denied FAIL-CLOSED, so a legitimate operator with GOOD
  // codes is refused - "every recovery code we try is rejected" while nothing is wrong with the codes.
  const { stub: stub2, storage: st2 } = makeScheduler();
  const realGet = st2.get.bind(st2);
  st2.get = (async (key: string) => {
    if (typeof key === "string" && key.startsWith("recovery-rate:")) throw new Error(`DO storage unavailable: ${POISON_ERROR}`);
    return realGet(key);
  }) as typeof st2.get;
  const denied = await stubFetch(stub2, "POST", "/recovery/recover", { email: POISON_EMAIL, code: "AAAA-BBBB", ip: POISON_IP });
  st2.get = realGet;
  ok("a limiter-store outage still FAILS CLOSED (the attempt is denied; behaviour unchanged)", ((await denied.json()) as { ok: boolean }).ok === false);
  d = await diag(stub2);
  ok("and the fail-closed LIMITER OUTAGE is named, distinct from a genuine throttle", d.ceremonyFaults["recovery-limiter-unavailable"]?.count === 1);
  ok("it is NOT mis-booked as a bucket denial", d.ceremonyFaults["recovery-denied-email-bucket"] === undefined);
  scanClean("recovery-limiter-unavailable (the raw storage error was planted)", d.ceremonyFaults);

  // Regenerate refused before it began ("the console nags me to regenerate and I never can").
  const { stub: stub3 } = makeScheduler();
  const regen = await stubFetch(stub3, "POST", "/recovery/regenerate", { email: "   " });
  ok("the refused regenerate still answers ok:false (behaviour unchanged)", ((await regen.json()) as { ok: boolean }).ok === false);
  ok("and the refusal is recorded (recovery-regenerate-refused)", (await diag(stub3)).ceremonyFaults["recovery-regenerate-refused"]?.count === 1);

  // The REJECTED-code path reuses the EXISTING closed auth-signal vocabulary rather than a parallel one.
  const signals = (await (await stubFetch(stub, "GET", "/auth-signals")).json()) as Record<string, { count: number }>;
  ok("a rejected code bumps the EXISTING recovery-code-invalid auth-signal (vocabulary reused, not forked)", (signals["recovery-code-invalid"]?.count ?? 0) >= 1);
  ok("a throttled attempt still bumps the EXISTING recovery-ratelimited signal", (signals["recovery-ratelimited"]?.count ?? 0) >= 1);
  scanClean("authSignals", signals);
  void storage;
}

// ---- the Worker<->DO contract faults that used to be coerced in silence ---------------------
async function testContractFaults(): Promise<void> {
  const { stub } = makeScheduler();

  // An out-of-vocabulary auth-signal name (an edge/DO version skew): recordAuthSignal DROPS it (the redaction
  // boundary, unchanged) while the edge is told ok - so the counter silently STOPS INCREMENTING.
  await stubFetch(stub, "POST", "/auth-signal", { name: `not-a-real-signal-${POISON_SECRET}` });
  // A notify-health field the DO does not know: the Worker's fire-and-forget bump ignores the 400.
  await stubFetch(stub, "POST", "/notify/health-bump", { field: POISON_BUCKET });
  // A malformed source-drift body: the `?? []` coercion CLEARS the detached-source marker, so a REAL, ongoing
  // source detachment reads as healed in the pack.
  await stubFetch(stub, "POST", "/source-drift/reconcile", { missing: POISON_BUCKET });
  await stubFetch(stub, "POST", "/volume-regression/reconcile", {});
  // A route this build does not have (a partial deploy: a console screen 404ing on every load).
  await stubFetch(stub, "GET", "/a-route-this-build-does-not-have");

  const d = await diag(stub);
  const keys = Object.keys(d.contractFaults);
  ok("the rejected auth-signal name is COUNTED (skew, not silence)", d.contractFaults["auth-signal|enum-drift"]?.count === 1);
  ok("the rejected notify-health field is counted", d.contractFaults["notify-health|enum-drift"]?.count === 1);
  ok("the malformed drift body is counted as a bad body (it would have CLEARED the detached-source marker)", d.contractFaults["drift-reconcile|bad-body"]?.count === 1);
  ok("an absent volume-regression list is counted as a coerced default", d.contractFaults["volume-reconcile|coerced-default"]?.count === 1);
  ok("the unmatched route is counted", d.contractFaults["unmatched-route|unknown-route"]?.count === 1);
  ok("every key is CLOSED route|kind (no path, method, body or rejected string ever rides)", keys.every((k) => {
    const [route, kind] = k.split("|");
    return (CONTRACT_ROUTE_CLASSES as readonly string[]).includes(String(route)) && (CONTRACT_FAULT_KINDS as readonly string[]).includes(String(kind));
  }));
  scanClean("contractFaults", d.contractFaults);

  // A run completion discarded as UNOWNED: usually a benign duplicate, but it is also how a REAL completion is
  // lost (the run then keeps reading "abandoned" in the pack while it actually finished).
  const { stub: s2 } = makeScheduler();
  await stubFetch(s2, "POST", "/downpipes", makeConfig("dp-u"));
  await stubFetch(s2, "POST", "/complete", { id: "dp-u", runId: "run-that-never-triggered", index: 9999, status: "ok" });
  ok("the unowned/discarded completion is counted", (await diag(s2)).contractFaults["run-completion-unowned|unowned-drop"]?.count === 1);

  // A HEALTHY, in-vocabulary call records nothing (fault path only).
  const { stub: s3 } = makeScheduler();
  await stubFetch(s3, "POST", "/auth-signal", { name: "auth-ratelimited" });
  await stubFetch(s3, "POST", "/notify/health-bump", { field: "passSkips" });
  ok("in-vocabulary calls record NO contract fault (fault path only)", Object.keys((await diag(s3)).contractFaults).length === 0);
}

// ---- the recorders' OWN dropped writes, and the limiter's silent fail-open ------------------
async function testDroppedWritesAndLimiter(): Promise<void> {
  // A fake store whose put THROWS: the recorder cannot persist its own fault, which is exactly the case that
  // makes the pack UNDER-COUNT during the very outage it should explain. The drop is held in memory and FOLDED
  // into the durable aggregate by the next write that succeeds.
  const map = new Map<string, unknown>();
  let failWrites = true;
  const store: LedgerStorage = {
    async get<T>(key: string): Promise<T | undefined> {
      return map.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      if (failWrites) throw new Error(`DO storage unavailable while writing ${POISON_BUCKET}: ${POISON_ERROR}`);
      map.set(key, value);
    },
  };
  await recordCeremonyFault(store, "passkey-stored-key-corrupt");
  await recordFreshnessFault(store, "dp-a", "cadence-malformed");
  ok("a recorder whose write FAILS never throws (observing a fault must not break the path it observed)", true);
  ok("and nothing was silently persisted", map.size === 0);

  failWrites = false;
  await recordCeremonyFault(store, "passkey-internal-fault"); // the store is back: this write also FOLDS the drops
  const dropped = map.get(DROPPED_WRITES_KEY) as Record<string, { count: number; lastAt: string }> | undefined;
  ok("the DROPPED writes are folded into the durable aggregate on the next successful write", dropped?.["ceremony-fault"]?.count === 1 && dropped?.["freshness-fault"]?.count === 1);
  ok("every dropped-write kind is a member of the closed vocabulary", Object.keys(dropped ?? {}).every((k) => (DROPPED_WRITE_KINDS as readonly string[]).includes(k)));
  scanClean("droppedWrites (the raw storage error was planted in the throwing put)", dropped);
  await flushDroppedWrites(store);
  ok("a second flush does not double-count", (map.get(DROPPED_WRITES_KEY) as Record<string, { count: number }>)["ceremony-fault"]!.count === 1);
  const bundle = await readSchedDiag(store);
  ok("the pack's read carries the under-count caveat (droppedWrites is non-zero)", Object.keys(bundle.droppedWrites).length === 2);
  scanClean("the whole sched-diag bundle", bundle);

  // CO-OWNERSHIP of the ONE droppedWrites record: the Worker-EDGE recorders (admin/diag-records.ts) write the
  // SAME diag:droppedwrites key with the same shape and a DISJOINT vocabulary. One aggregate answering "how
  // much of this pack is missing?" is the right shape, but only if each writer PRESERVES the other's kinds.
  // Pin that here, in both directions, so a future vocabulary change cannot silently erase the other half.
  const folded = applyDroppedWrites(map.get(DROPPED_WRITES_KEY) as Record<string, { count: number; lastAt: string }>, { "auth-signal": 2 }, "2026-07-11T00:00:00.000Z");
  ok("the EDGE writer preserves the SCHED kinds in the shared droppedWrites record", folded["ceremony-fault"]?.count === 1 && folded["auth-signal"]?.count === 2);
  map.set(DROPPED_WRITES_KEY, folded);
  await recordCeremonyFault(store, "passkey-internal-fault");
  await flushDroppedWrites(store);
  const both = map.get(DROPPED_WRITES_KEY) as Record<string, { count: number }>;
  ok("and the SCHED writer preserves the EDGE kinds (the two vocabularies are disjoint and additive)", both["auth-signal"]?.count === 2 && both["ceremony-fault"]?.count === 1);

  // The shared RATE LIMITER's fail-open: "Cloudflare is 429-ing our crawls" while the limiter has been degraded
  // to no-throttle for weeks. The pack carried a PRESENCE bit only.
  const rlMap = new Map<string, unknown>();
  let bucketReadFails = true;
  const rlStorage = {
    async get<T>(key: string): Promise<T | undefined> {
      if (bucketReadFails && key === "cf-api-bucket") throw new Error(`DO storage unavailable: ${POISON_ERROR}`);
      return rlMap.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      rlMap.set(key, value);
    },
  };
  const rl = new RateLimitDO({ storage: rlStorage } as unknown as DurableObjectState, { CF_API_RATE_PER_SEC: "10/s" });
  const grant = (await (await rl.fetch(new Request("https://rl.internal/take", { method: "POST" }))).json()) as { granted: boolean; waitMs: number };
  ok("the limiter still FAILS OPEN on a storage fault (a broken limiter never stops backups)", grant.granted === true && grant.waitMs === 0);
  bucketReadFails = false;
  const health = (await (await rl.fetch(new Request("https://rl.internal/health"))).json()) as { failOpenCount: number; lastFailOpenAt: number; knobInvalid: boolean };
  ok("and the fail-open is now COUNTED (the pack can say the limiter was degraded to no-throttle)", health.failOpenCount === 1 && health.lastFailOpenAt > 0);
  ok("an unparseable CF_API_RATE_PER_SEC (silently falling back to the default) is flagged", health.knobInvalid === true);
  scanClean("rateLimitDoHealth (the raw storage error was planted)", health);
  const rlOk = new RateLimitDO({ storage: { async get() { return undefined; }, async put() {} } } as unknown as DurableObjectState, { CF_API_RATE_PER_SEC: "25" });
  const okHealth = (await (await rlOk.fetch(new Request("https://rl.internal/health"))).json()) as { failOpenCount: number; knobInvalid: boolean };
  ok("a healthy limiter with a VALID knob reports a clean bill (fault path only)", okHealth.failOpenCount === 0 && okHealth.knobInvalid === false);
}

// ---- the DO-route errorId the console shows the customer -------------------------------------
async function testDoRouteErrorId(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // An unexpected RUNTIME fault inside a route: the caller gets an opaque errorId in a console toast and quotes
  // it to support, who (holding only the pack) had nothing to dereference it against.
  const realList = storage.list.bind(storage);
  storage.list = (async () => {
    throw new TypeError(`cannot read properties of undefined (reading '${POISON_BUCKET}') ${POISON_ERROR}`);
  }) as unknown as MockStorage["list"];
  const res = await stubFetch(stub, "GET", "/downpipes");
  storage.list = realList;
  const body = (await res.json()) as { error: string; errorId?: string };
  ok("the DO still answers an opaque 500 (no internal name leaks to the caller)", res.status === 500 && body.error === "internal error" && typeof body.errorId === "string");

  const d = await diag(stub);
  const hit = d.recentErrors.find((r) => r.errorId === body.errorId);
  ok("the id the customer quotes is filed in the pack's ring", hit !== undefined);
  ok("with the DO-route stage and the internal class (the message stays in Workers Logs)", hit?.stage === "do-route" && hit?.reasonClass === "internal");
  scanClean("the DO-route ring entry (the raw TypeError message was planted)", d.recentErrors);
}

async function main(): Promise<void> {
  console.log("scheduler-DO fault ledger");
  await testDestinationAttribution();
  await testFreshnessUncomputable();
  await testCeremonyFaults();
  await testChallengeEviction();
  await testRecoveryCauses();
  await testContractFaults();
  await testDroppedWritesAndLimiter();
  await testDoRouteErrorId();
  const failures = getFailures();
  console.log(failures === 0 ? "\nsched-fault-ledger: all checks passed" : `\nsched-fault-ledger: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

await main();
