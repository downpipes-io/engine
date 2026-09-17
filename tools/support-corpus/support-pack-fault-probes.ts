// support-pack-fault-probes.ts -- ONE PROBE PER ROW OF THE DEFECT TABLE, in table order.
//
// Each probe induces the defect's OWN state in the world the support pack is built from, and then asks the
// GENERATED PACK whether it can say what is wrong. The verdict is taken from the pack's bytes; see
// support-pack-fault-oracle.ts for the four verdicts and for the two controls that bound the measurement.
//
// A CONSOLE-SIDE OR PUBLISHED-ARTEFACT DEFECT INDUCES NOTHING IN THIS WORLD, ON PURPOSE. The engine's state
// does not move when a tablist loses focus or a website page names a retired format, so the pack the customer
// sends is the healthy pack. `NOOP` is that fact written down, not a probe that was skipped: a probe with
// NOOP and no `notApplicable` reason scores SILENT, which is the correct and the worst answer.

import { DEST_PROBE_FAULTS_KEY, INTEGRITY_FAULTS_KEY } from "../../src/admin/diag-records.ts";
import { readSchedDiag, recordFreshnessFault, type LedgerStorage } from "../../src/sched/sched-fault-ledger.ts";
import { SchedulerDO } from "../../src/sched/scheduler-do.ts";
import { MockStorage } from "../../test/mock-storage.ts";
import type { World } from "./harness.ts";
import { NOOP, packSays, rows, sec, type Probe } from "./support-pack-fault-oracle.ts";

type Dict = Record<string, unknown>;
const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = 1_786_000_000_000;
const iso = (t: number): string => new Date(t).toISOString();

// ---------------------------------------------------------------------------------------------------------
// The three cap-truncation ledgers, driven through the REAL recorders (an earlier pass's fixtures, re-driven
// here so this pass's score for defects 8/9/10 rests on its own generated packs rather than on that pass's report).

function memStorage(): LedgerStorage {
  const map = new Map<string, unknown>();
  return {
    async get<T>(k: string): Promise<T | undefined> {
      return map.get(k) as T | undefined;
    },
    async put<T>(k: string, v: T): Promise<void> {
      map.set(k, v);
    },
  };
}
interface DiagDO {
  recordIntegrityFaults(b: { id?: unknown; snapshot?: unknown }): Promise<{ ok: true }>;
  recordDestProbeFaults(b: { rows?: unknown; refusedUpstream?: unknown }): Promise<{ ok: true }>;
}
function makeDO(): { dobj: DiagDO; storage: MockStorage } {
  const storage = new MockStorage();
  return { dobj: new SchedulerDO({ storage } as never) as unknown as DiagDO, storage };
}

const FLEET = 60;
const FAULTING = 55;
const dpId = (i: number): string => `dp-${String(i).padStart(4, "0")}`;
const INTEGRITY_REFUSED = "acme-payroll-nightly";
const DEST_REFUSED = "acme-crown-jewels-offsite";
const SNAP = { cryptoFaults: [{ cls: "recipient-no-capsule-match", role: "operational", heldFingerprint: "0123456789ab", wantFingerprint: "ba9876543210" }], defaultedEmptyRecords: 1 };

const freshnessDiag = await (async (): Promise<Dict> => {
  const s = memStorage();
  for (let i = 0; i < FAULTING; i++) await recordFreshnessFault(s, dpId(i), "cadence-malformed");
  return (await readSchedDiag(s)) as unknown as Dict;
})();

const { integrityDiag, integrityRecord } = await (async (): Promise<{ integrityDiag: Dict; integrityRecord: Dict }> => {
  const { dobj, storage } = makeDO();
  for (let i = 0; i < 100; i++) await dobj.recordIntegrityFaults({ id: dpId(i), snapshot: SNAP });
  await dobj.recordIntegrityFaults({ id: INTEGRITY_REFUSED, snapshot: SNAP });
  return { integrityDiag: (await readSchedDiag(storage as unknown as LedgerStorage)) as unknown as Dict, integrityRecord: (await storage.get<Dict>(INTEGRITY_FAULTS_KEY)) ?? {} };
})();

const { destProbeDiag, destProbeRecord } = await (async (): Promise<{ destProbeDiag: Dict; destProbeRecord: Dict }> => {
  const { dobj, storage } = makeDO();
  const r = [...Array.from({ length: 69 }, (_, i) => ({ id: `dest-${String(i).padStart(4, "0")}`, reason: "auth" })), { id: DEST_REFUSED, reason: "auth" }];
  await dobj.recordDestProbeFaults({ rows: r, refusedUpstream: 7 });
  return { destProbeDiag: (await readSchedDiag(storage as unknown as LedgerStorage)) as unknown as Dict, destProbeRecord: (await storage.get<Dict>(DEST_PROBE_FAULTS_KEY)) ?? {} };
})();

function fleetRoster(): Dict[] {
  return Array.from({ length: FLEET }, (_, i) => ({
    config: { id: dpId(i), name: `pipe ${i}`, enabled: true, cadenceSeconds: 3600, source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "ns-uploads", include: ["uploads/*"], exclude: [] } },
    lastRunId: "01RUNOK",
    inFlight: false,
    nextRunAt: NOW + 30 * MIN,
    cronResolve: { class: "ok", at: NOW + 30 * MIN },
    lastRestoreTestAt: NOW - 6 * HOUR,
    lastRestoreTestOk: true,
  }));
}

function subjects(b: Dict, surface: string): { ids: string[]; incomplete: boolean } {
  const cts = sec(b, "schedDiag").capTruncationSubjects;
  const e = (typeof cts === "object" && cts !== null ? (cts as Dict)[surface] : undefined) as { ids?: unknown; incomplete?: unknown } | undefined;
  return { ids: Array.isArray(e?.ids) ? (e.ids as unknown[]).filter((v): v is string => typeof v === "string") : [], incomplete: e?.incomplete === true };
}

const ok = (): string[] => [];

// ---------------------------------------------------------------------------------------------------------

export const PROBES: Probe[] = [
  // 1 ------------------------------------------------------------------------------------------------------
  {
    n: 1,
    what: "registration ceiling: a browser refusal reported as an unreachable engine, draining the recovery bank",
    where: "console",
    mutate: (w: World): void => {
      // The engine ANSWERED every one of those calls, and the recovery bank is draining. Both facts are its own.
      w.routes["/webauthn-faults"] = {};
      w.routes["/auth-posture"] = { sessionSigningKey: { present: true, ageMs: 3 * DAY, adequateLength: true }, doPlaintextSecretsMissing: 0, adminCredentialPaths: { passkeyCredentials: 25, enabledIdpConnections: 1 } };
    },
    clientDiag: (): unknown => ({ records: [{ kind: "engine-call", screen: "access", httpClass: "network", faultClass: "transport", count: 6, firstMs: 20, lastMs: 4000 }] }),
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "engine-call")) f.push("the console's own claim that the engine was unreachable does not ride, so the false diagnosis leaves no trace");
      // The refusal itself: the webauthn fault ring is a CLOSED phase:class cross product and every one of its
      // 15 classes is a CBOR/COSE/authData PARSE fault. An authenticator at its resident-key ceiling parses
      // perfectly and is refused for a reason the ring has no member for.
      f.push("no engine record names an authenticator at its registration ceiling: WEBAUTHN_FAULT_CLASSES is 15 members and every one of them is a parse fault");
      return f;
    },
    note: "The pack shows a CONTRADICTION -- the browser claims the engine was unreachable and the engine answered -- which is worth something, and it never names the ceiling.",
  },
  // 2 ------------------------------------------------------------------------------------------------------
  {
    n: 2,
    what: "assertion ceiling: step-up gates the only route that lowers a credential count",
    where: "console",
    mutate: (w: World): void => {
      w.routes["/auth-posture"] = { sessionSigningKey: { present: true, ageMs: 3 * DAY, adequateLength: true }, doPlaintextSecretsMissing: 0, adminCredentialPaths: { passkeyCredentials: 20, enabledIdpConnections: 1 } };
      w.routes["/auth-signals"] = { "stepup-check-unavailable": { count: 12, lastAt: iso(NOW - 2 * MIN) } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "stepup-check-unavailable")) f.push("no auth signal says step-up itself is refusing");
      const ap = sec(b, "authPosture");
      const paths = (typeof ap.adminCredentialPaths === "object" && ap.adminCredentialPaths !== null ? ap.adminCredentialPaths : {}) as Dict;
      if (paths.passkeyCredentials !== 20) f.push("the pack does not carry the credential count that is at its ceiling");
      return f;
    },
  },
  // 3 ------------------------------------------------------------------------------------------------------
  {
    n: 3,
    what: "SAML rollover cap: the refusal borrows the empty-array sentence at IdP cut-over",
    where: "engine",
    mutate: (w: World): void => {
      // The connection is AT the cap with its certificates about to expire, which is the cut-over state.
      w.routes["/idp-cert-health"] = { health: { certCount: 4, parseableCount: 4, windowReadableCount: 4, expiryObserved: true, nearestNotAfter: 1_786_200_000, curves: { "p-256": 4 } } };
    },
    names: (b: Dict): string[] => {
      const h = sec(b, "idpCertHealth");
      const f: string[] = [];
      if (h.certCount !== 4) f.push("the pack does not carry the certificate count that is at its cap");
      f.push("nothing says a ROLLOVER WAS REFUSED: idpCertHealth reports how many certificates parse and when the nearest expires, and there is no counter, refusal ledger or audit action for a cut-over the cap turned away");
      return f;
    },
    note: "The pack can show an operator is AT the cap. It cannot show they tried to roll over and were refused.",
  },
  // 4 ------------------------------------------------------------------------------------------------------
  {
    n: 4,
    what: "offline retention prune: the cap is a permanent refusal on break-glass estates",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/retention-state"] = { record: { at: iso(NOW - 10 * MIN), enforce: true, downpipes: [{ id: "dp1", outcome: "deferred", deferralClass: "prune-cap-reached", deleted: 0 }] } };
    },
    names: (b: Dict): string[] => (packSays(b, "prune-cap-reached") || packSays(b, "deferred") ? ok() : ["the retention record does not say the pass abstained, nor why"]),
  },
  // 5 ------------------------------------------------------------------------------------------------------
  {
    n: 5,
    what: "destination migration walks past the only-proven-copy guard, writing a zero into the audit",
    where: "engine",
    mutate: (w: World): void => {
      // The migration completed and the audit records the deed. Nothing anywhere records that the guard was
      // walked past: the record the pack reads is a successful destination change.
      w.routes["/audit/export"] = (url: URL): unknown => {
        const events = [
          { seq: 11, ts: iso(NOW - 2 * DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
          { seq: 12, ts: iso(NOW - DAY), action: "destination-set", outcome: "ok", prevHash: "sha384:h11", hash: "sha384:h12" },
        ];
        return url.searchParams.get("action") !== null
          ? { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) }
          : { events, headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) };
      };
      w.routes["/replication"] = { byDownpipe: { dp1: { "d-new": { holdsRunId: null, holdsIndex: 0, lastOk: false, lastAttemptAt: NOW - 60 * MIN } } } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "onlyProvenCopy") && !packSays(b, "provenCopy")) f.push("nothing in the pack names the only-proven-copy guard, so the pack cannot say the guard was walked past");
      const r0 = rows(b)[0];
      const repBlock = (typeof r0?.replication === "object" && r0.replication !== null ? r0.replication : {}) as Dict;
      const rep = Array.isArray(repBlock.destinations) ? (repBlock.destinations as Dict[]) : [];
      if (rep.length === 0) f.push("population: the induced replication heartbeat did not reach the downpipe row");
      else if (!rep.some((x) => x.ok === false)) f.push("population: the new destination does not read as unproven");
      return f;
    },
  },
  // 6 ------------------------------------------------------------------------------------------------------
  {
    n: 6,
    what: "dual-control deadlock: the escape is disposable and the product prescribes disposing of it",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/policy/break-glass-disposal"] = { bootstrapConsumed: true, breakGlassTokenRetired: true };
      w.routes["/owner-actions/queue-stats"] = { pendingCount: 3, approvalsOutstanding: 3, expiredUndecidedCount: 1, oldestProposedAt: iso(NOW - 9 * DAY) };
      w.routes["/auth-posture"] = { sessionSigningKey: { present: true, ageMs: 3 * DAY, adequateLength: true }, doPlaintextSecretsMissing: 0, adminCredentialPaths: { passkeyCredentials: 1, enabledIdpConnections: 0 } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const st = sec(b, "status");
      if (st.breakGlassTokenRetired !== true) f.push("the pack does not say the break-glass escape has been retired");
      const q = sec(b, "ownerActionQueue");
      if (JSON.stringify(q) === "{}") f.push("the pack carries no owner-action queue, so it cannot say approvals are stuck");
      return f;
    },
    note: "Two independent facts ride; the DEADLOCK itself (nobody can approve) is a join a reader must make.",
  },
  // 7 ------------------------------------------------------------------------------------------------------
  {
    n: 7,
    what: "audit near-cap warning had never fired on any engine and could not",
    where: "engine",
    mutate: (w: World): void => {
      // The state the defect produces: the ring IS near its cap and the warning flag stays false.
      w.routes["/audit/verify"] = { intact: true, checkedThrough: 9800, earliestSeq: 1, rolledOver: false, rolledOverCount: 0, auditCount: 9800, auditNearCap: false, verify: { at: iso(NOW - MIN), entriesChecked: 9800, durationMs: 40, complete: true } };
    },
    names: (b: Dict): string[] => {
      const a = sec(b, "audit");
      return typeof a.auditCount === "number" && a.auditCount === 9800 ? ok() : ["the pack does not carry the raw audit entry count, so a reader cannot see the ring is near its cap while the flag says otherwise"];
    },
    note: "The pack carries the COUNT beside the flag, so the two can be read against each other.",
  },
  // 8 ------------------------------------------------------------------------------------------------------
  {
    n: 8,
    what: "freshness-fault cap: the pack asserted the 51st downpipe was healthy",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/downpipes"] = fleetRoster();
      w.routes["/sched-diag"] = freshnessDiag;
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const r = rows(b);
      if (r.length !== FLEET) f.push(`population: expected ${FLEET} rows, got ${r.length}`);
      const unknown = r.filter((x) => x.freshnessComputableUnknown === true);
      const neither = r.filter((x) => x.freshnessComputable === undefined && x.freshnessComputableUnknown === undefined);
      if (neither.length !== FLEET - FAULTING) f.push(`population: expected ${FLEET - FAULTING} rows carrying NEITHER field, got ${neither.length}`);
      if (unknown.length !== FAULTING - 50) f.push(`the downpipes past the cap still read as downpipes with a working staleness rule (${unknown.length} marked unknown)`);
      if (!subjects(b, "freshness-faults").ids.includes(dpId(FAULTING - 1))) f.push("capTruncationSubjects does not name the dropped downpipe");
      return f;
    },
  },
  // 9 ------------------------------------------------------------------------------------------------------
  {
    n: 9,
    what: "integrity faults per downpipe: a void writer returns at the 101st",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/sched-diag"] = integrityDiag;
      w.routes["/integrity-faults"] = integrityRecord;
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const rec = sec(b, "integrityFaults");
      if (Object.keys(rec).length !== 100) f.push(`population: expected 100 integrityFaults rows, got ${Object.keys(rec).length}`);
      if (!subjects(b, "integrity-faults-downpipe").ids.includes(INTEGRITY_REFUSED)) f.push("the pack does not name the downpipe whose verification evidence it could not hold");
      return f;
    },
  },
  // 10 -----------------------------------------------------------------------------------------------------
  {
    n: 10,
    what: "destination-probe faults: THREE undeclared cuts rather than one",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/sched-diag"] = destProbeDiag;
      w.routes["/dest-probe-faults"] = destProbeRecord;
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const s = subjects(b, "dest-probe-faults");
      if (!s.ids.includes(DEST_REFUSED)) f.push("the pack does not name the refused destination");
      if (!s.incomplete) f.push("the unnameable upstream cut is not declared, so the named list reads as the whole truth");
      return f;
    },
  },
  // 11 -----------------------------------------------------------------------------------------------------
  {
    n: 11,
    what: "sign-in baseline lapse: the unrecognised sign-in reads as first-ever and is adopted",
    where: "engine",
    mutate: (w: World): void => {
      // Every baseline row has aged out. The engine's own record of that is... the absence of rows.
      w.routes["/auth-signals"] = {};
      w.routes["/sso-failures"] = {};
    },
    names: (b: Dict): string[] => (packSays(b, "signinBaseline") || packSays(b, "baselineEmpty") || packSays(b, "unusual-location") ? ok() : ["nothing in the pack carries the unusual-location baseline, so an EMPTY baseline and a baseline that has simply never seen a strange sign-in are the same evidence"]),
  },
  // 12 -----------------------------------------------------------------------------------------------------
  {
    n: 12,
    what: "audit rollover count lost: a rollover record whose count has been LOST reports a rollover of zero",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/audit/verify"] = { intact: true, checkedThrough: 60, earliestSeq: 41, rolledOver: true, rolledOverCount: 0, auditCount: 20, auditNearCap: false, verify: { at: iso(NOW - MIN), entriesChecked: 20, durationMs: 5, complete: true } };
      // FIDELITY: verifyAudit BOOKS the anomaly on the same pass, so a real faulted engine carries it too.
      w.routes["/sched-diag"] = { storageAnomalies: { "rollover-record-lost": { count: 1, lastAt: iso(NOW - MIN) } } };
    },
    names: (b: Dict): string[] => {
      const a = sec(b, "audit");
      const f: string[] = [];
      if (a.rolledOver !== true) f.push("the pack does not say a rollover happened");
      if (a.rolledOverCount !== 0) f.push("the induced state did not reach the pack");
      // The engine books `rollover-record-lost` on the line above; the pack reads admin counters.
      if (!packSays(b, "rollover-record-lost")) f.push("the pack carries `rolledOver:true, rolledOverCount:0` and NOTHING that says the count was lost rather than genuinely zero");
      return f;
    },
  },
  // 13 -----------------------------------------------------------------------------------------------------
  {
    n: 13,
    what: "canary in-flight lease: the console reclaim path counts nothing",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/canary/transitions"] = { enabled: true, status: "alive", deadDestinations: 0, transitionCount: 0, transitions: [], lostFlights: 0 };
    },
    names: (b: Dict): string[] => (packSays(b, "reclaim") || packSays(b, "lost-flight") ? ok() : ["the canary block carries no reclaim evidence at all, so an operator-reclaimed flight and a flight that never stalled are the same pack"]),
  },
  // 14 -----------------------------------------------------------------------------------------------------
  {
    n: 14,
    what: "change-control and config-snapshot markers coerced to zero make the block VANISH",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/config-snapshot-health"] = { count: 0, coerced: true };
      w.routes["/change-control/refusals"] = { count: 0, coerced: true };
    },
    names: (b: Dict): string[] => {
      const ci = sec(b, "configIntegrity");
      const up = Array.isArray(ci.unavailableProbes) ? (ci.unavailableProbes as string[]) : [];
      const f: string[] = [];
      if (!up.includes("config-snapshot")) f.push("a coerced config-snapshot marker is not declared unavailable");
      if (!up.includes("change-control-refusals")) f.push("a coerced change-control marker is not declared unavailable");
      return f;
    },
  },
  // 15 -----------------------------------------------------------------------------------------------------
  {
    n: 15,
    what: "the /support pull refusal class, decided and discarded",
    where: "engine",
    mutate: (w: World): void => {
      // The FIVE-WAY classification the gate already computes, booked to the admin counters it now writes.
      w.routes["/admin-counters"] = {
        "ingest-pull-refused-credential-expired": { count: 9, lastAt: iso(NOW - 3 * MIN) },
        "ingest-pull-refused-no-grant": { count: 2, lastAt: iso(NOW - 40 * MIN) },
        "ingest-pull-refused-secret-mismatch": { count: 1, lastAt: iso(NOW - 90 * MIN) },
      };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      for (const k of ["ingest-pull-refused-credential-expired", "ingest-pull-refused-no-grant", "ingest-pull-refused-secret-mismatch"]) {
        if (!packSays(b, k)) f.push(`the pack does not carry the refusal class ${k}`);
      }
      return f;
    },
  },
  // 16 -----------------------------------------------------------------------------------------------------
  {
    n: 16,
    what: "the ingest-credential expiry that could never expire",
    where: "engine",
    mutate: (w: World): void => {
      const grant = { grantedAt: iso(NOW - 30 * DAY), expiresAt: "not-a-date", pulls: [{ at: iso(NOW - HOUR) }] };
      w.routes["/ingest-credential"] = (url: URL): unknown => (url.searchParams.get("scope") === null ? { grant: null } : { grant });
      // The DO route table keys on pathname alone, so both scopes land here.
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const af = sec(b, "auditFeed");
      const mf = sec(b, "metricsFeed");
      if (af.expiryUnreadable !== true) f.push("auditFeed does not say the stored expiry is unreadable");
      if (mf.expiryUnreadable !== true) f.push("metricsFeed does not say the stored expiry is unreadable");
      if (af.expired !== true) f.push("auditFeed still answers expired:false for a grant whose expiry does not parse");
      return f;
    },
  },
  // 17 -----------------------------------------------------------------------------------------------------
  {
    n: 17,
    what: "a submit-time field refusal painted and then erased within one task",
    where: "console",
    mutate: NOOP,
    clientDiag: (): unknown => ({ records: [{ kind: "form-rejected", screen: "destinations", formField: "dest-endpoint", rejectOutcome: "rejected", count: 1, firstMs: 10, lastMs: 20 }] }),
    names: (b: Dict): string[] => (packSays(b, "form-rejected") ? ok() : ["no clientDiagnostics row survived, so the console's own refusal is invisible"]),
    note: "THE PACK'S EVIDENCE SURVIVES THE ERASURE THE SCREEN DID NOT. `refuse()` at console/src/components/field.ts:433 -- the exact call the form's own submit rule makes, and the one whose message the deferred blur revalidation wipes -- calls `recordFormRefused` BEFORE `setError`, so the row is pushed to the ring a task before the reason is erased from the screen.",
  },
  // 18 -----------------------------------------------------------------------------------------------------
  {
    n: 18,
    what: "keyboard focus destroyed by a tab activation",
    where: "console",
    mutate: NOOP,
    // The browser is the ONLY witness to this one, exactly as it is for a blocked canvas or a refused
    // download: no request is made, the engine's world does not move, and the row below is the whole
    // evidence. It is the row the console's shell now pushes at its post-navigation focus move, with the
    // healthy landing beside it so the pack can say the mechanism WAS working on the other screen.
    clientDiag: (): unknown => ({
      records: [
        { kind: "focus-landing", screen: "keys", focusOutcome: "dropped-detached", count: 4, firstMs: 120, lastMs: 980 },
        { kind: "focus-landing", screen: "notifications", focusOutcome: "honoured", count: 2, firstMs: 30, lastMs: 60 },
      ],
    }),
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "focus-landing")) f.push("no focus-landing row survived, so a keyboard user trapped on the first tab is invisible");
      if (!packSays(b, "dropped-detached")) f.push("the pack does not carry the outcome, so it says a navigation moved focus and refuses to say what became of it");
      if (!packSays(b, "honoured")) f.push("the HEALTHY landing is missing, so a broken tablist and a tablist the customer never touched are the same absence");
      return f;
    },
    note: "CLOSED BY ANOTHER PASS (G346). The zero two passes measured was re-verified over the 1,173 member strings of the 126 closed unions, with three known positives firing, before anything was built. The producer is not a new capture: nav.ts's takePostNavigationFocus ALREADY computed the discrimination and collapsed it, returning one null for both `no screen declared an intent` (the ordinary route change) and `a screen declared one and the element was not mounted` (the defect).",
  },
  // 19 -----------------------------------------------------------------------------------------------------
  {
    n: 19,
    what: "an unauthenticated caller chose the name the audit chain recorded as the ACTOR",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/audit/export"] = (url: URL): unknown => {
        const events = [
          { seq: 11, ts: iso(NOW - 2 * DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
          { seq: 12, ts: iso(NOW - HOUR), action: "recovery-code-used", outcome: "failed", actorEmail: "attacker@example.invalid", prevHash: "sha384:h11", hash: "sha384:h12" },
        ];
        return url.searchParams.get("action") !== null ? { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) } : { events, headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) };
      };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const ev = Array.isArray(b.configEvents) ? (b.configEvents as Dict[]) : [];
      const row = ev.find((e) => e.action === "recovery-code-used");
      if (row === undefined) f.push("the refused break-glass row does not reach the pack at all");
      else if (row.attributed !== true) f.push("the pack's configEvents row does not say the refused row carries an actor at all");
      return f;
    },
    note: "`attributed` is the pack's boolean for whether an event named an actor; the ADDRESS itself is deliberately dropped.",
  },
  // 20 -----------------------------------------------------------------------------------------------------
  {
    n: 20,
    what: "the multi-component apply told the operator nothing changed while the engine was live on the new version",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/update-status"] = { settledHighWaterMark: "0.1.0", pending: null, last: { outcome: "applied-unconfirmed", fromVersion: "0.1.0", toVersion: "0.2.0", at: iso(NOW - 20 * MIN), confirmationPending: true }, lastConsole: { outcome: "failed", reason: "reset threw", at: iso(NOW - 20 * MIN), component: "console" } };
      w.routes["/update-faults"] = { "component-apply:followup-threw": { count: 1, lastAt: iso(NOW - 20 * MIN) } };
    },
    names: (b: Dict): string[] => {
      const u = sec(b, "updates");
      const last = (typeof u.last === "object" && u.last !== null ? u.last : {}) as Dict;
      return last.outcome === "applied-unconfirmed" || packSays(b, "applied-unconfirmed") ? ok() : ["the pack does not carry the applied-unconfirmed outcome, so an apply whose confirming read failed reads as an apply that never happened"];
    },
  },
  // 21 -----------------------------------------------------------------------------------------------------
  {
    n: 21,
    what: "a served product surface named the archive wire format the 2026-07-12 cutover retired",
    where: "console",
    mutate: NOOP,
    notApplicable: "A STATIC ASSET SERVED BY THE CONSOLE WORKER. Widening the pack to fetch a sibling repo's published file is the wrong repair, and the right home is the build-time gate two other passes landed. Recorded as NOT counting against the pack by a further pass; that adjudication stands and both halves are now closed.",
    names: ok,
  },
  // 22 -----------------------------------------------------------------------------------------------------
  {
    n: 22,
    what: "the guided tour framed its own chrome instead of the subject at every width but the widest",
    where: "console",
    mutate: NOOP,
    notApplicable: "THE GUIDED TOUR CANNOT REACH ANY ENGINE, so no pack from any estate can carry a fact about it, and a vocabulary member for it would be an ANTI-DETECTOR: a word that makes the pack look as though it covers a surface nothing can ever populate. Three independent facts, each checked rather than assumed. (1) console/wrangler.public-demo.toml, the tour's only deploy, OMITS the ENGINE service binding entirely and says so in its own words, so the worker serves the SPA and answers /engine-topology.json with proxied:false; the backend is a fetch shim in the browser and every /admin/* call is answered in-page and never leaves the origin. (2) console/src/lib/demo/tour-mode.ts turns the tour on BY HOSTNAME (tour.downpipes.io) and scopes the ?tour= flag to loopback hosts, so console.downpipes.io is false by construction and cannot be coaxed into it by a crafted URL. (3) The tour subtree is behind a dynamic import gated on that guard, so esbuild's code-splitting keeps it out of the bundle a real console ships. This is defect 21's adjudication, not defect 18's: a surface met OUTSIDE any customer's engine, whose standing home is a measurement another pass landed. Recorded by a second pass after re-verifying the vocabulary zero it shares with 18, and DELIBERATELY NOT closed with a member.",
    names: ok,
    note: "Its SIBLING in the same class, defect 18, WAS a missing vocabulary and is now closed (G346). This one is not: the difference is that 18 happens in the real console, which posts a client-diagnostics ring with the pack, and 22 happens on a static public surface with no engine behind it at all.",
  },
  // 23 -----------------------------------------------------------------------------------------------------
  {
    n: 23,
    what: "the control-plane recovery banner offers an established account no exit that can work",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/control-plane/recovery-status"] = {
        recoveryRequired: true,
        configEmpty: false,
        resumeApplied: false,
        deploy: { engineVersion: "0.1.0", cfVersionId: "cfv-current-001", cfVersionIdAbsent: false, baselineEstablished: true, changesObserved: 0, firstSeenAt: iso(NOW - 30 * DAY), lastSeenAt: iso(NOW - 5 * MIN) },
        exportHealth: { at: iso(NOW - 20 * MIN), wroteAny: true, configVersion: 7, perDest: [{ id: "d-primary", ok: true }] },
      };
      w.routes["/recovery-refusals"] = { refusals: { total: 4, bySurfaceClass: { "apply-staged|staged-malformed": 4 } } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const r = sec(b, "recovery");
      if (r.recoveryRequired !== true) f.push("the latch does not reach the pack");
      if (r.configEmpty !== false) f.push("the pack cannot say the account is established rather than empty");
      if (!packSays(b, "apply-staged")) f.push("the refusals the operator actually hit are not carried");
      return f;
    },
    note: "recoveryRequired:true beside configEmpty:false IS the unreachable state, stated in two adjacent fields, and the apply-staged refusals say what the operator tried. THE BOUND: `acknowledge` is a RECOVERY_REFUSAL_SURFACES member and the console never calls it, so the pack can show every route that WAS tried and can never show the one that would have worked.",
  },
  // 24 -----------------------------------------------------------------------------------------------------
  {
    n: 24,
    what: "the integrations grid told the owner they were not the owner, on all 40 tiles at once",
    where: "console",
    mutate: NOOP,
    clientDiag: (): unknown => ({ records: [{ kind: "identity-stale-gate", screen: "integrations", count: 3, firstMs: 12, lastMs: 900 }] }),
    names: (b: Dict): string[] => (packSays(b, "identity-stale-gate") ? ok() : ["the identity-stale-gate row did not survive into the pack"]),
    note: "The vocabulary member exists and its own comment names this exact symptom.",
  },
  // 25 -----------------------------------------------------------------------------------------------------
  {
    n: 25,
    what: "a Splunk HEC refusal carried inside a 200 advanced the audit cursor past the events it refused",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/push"] = {
        present: true,
        format: "splunk-hec",
        sink: "https",
        enabled: true,
        lastPushedSeq: 900,
        headSeq: 900,
        trail: [{ at: iso(NOW - 5 * MIN), ok: false, httpStatus: 200, reason: "hec-declined-index", count: 40, fromSeq: 861, toSeq: 900 }],
      };
    },
    names: (b: Dict): string[] => (packSays(b, "hec-declined-index") ? ok() : ["the push trail cannot say a 200 carried a refusal, so a lost batch reads as a clean delivery"]),
  },
  // 26 -----------------------------------------------------------------------------------------------------
  {
    n: 26,
    what: "the published path from the website to a running backup did not reach a running backup",
    where: "website",
    mutate: NOOP,
    notApplicable: "A JOURNEY ACROSS PUBLISHED MARKETING PAGES, met BEFORE any engine exists. There is no engine to generate a pack from, so a pack cannot be the instrument. Its standing check is `website/scripts/deploy-path-parity.mjs`.",
    names: ok,
  },
  // 27 -----------------------------------------------------------------------------------------------------
  {
    n: 27,
    what: "the docs MCP serves a stale index",
    where: "docs",
    mutate: NOOP,
    notApplicable: "A VENDOR-SIDE PUBLISHING DEFECT on docs.downpipes.io, in no customer's account. A customer's pack is built from their own engine and can hold no fact about our documentation index. Its standing checks are the two gates another pass landed.",
    names: ok,
  },
  // 28 -----------------------------------------------------------------------------------------------------
  {
    n: 28,
    what: "the config-history cap destroys signed versions and every surface answers as though they never existed",
    where: "engine",
    mutate: (w: World): void => {
      // 2,098 versions written against a 2,000 cap: the rollover has destroyed 98 and the record says nothing.
      w.routes["/config-history-health"] = { count: 2000, headId: 2098, verify: { intact: true, checkedThrough: 2098, earliestId: 99 } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const ci = sec(b, "configIntegrity");
      const h = (typeof ci.history === "object" && ci.history !== null ? ci.history : {}) as Dict;
      if (h.rolledOver !== true) f.push("nothing anywhere says the config chain rolled over: the block is omitted entirely because the pruned chain still verifies");
      if (h.rolledOverAtLeast !== 98) f.push("the pack cannot say how many signed versions the cap destroyed");
      if (h.earliestId !== 99) f.push("the pack does not carry the earliest surviving version id, so a customer asking for a destroyed version cannot be told it once existed");
      return f;
    },
    note: "THE ROLLOVER IS DERIVED THE WAY THE AUDIT CHAIN ALREADY DERIVES ITS OWN, from earliestId > 1. The block used to be OMITTED ENTIRELY on a pruned chain, because the prune is correct and the chain still verifies -- so a rollover that destroyed 98 signed versions left a pack that was 96,039 bytes before and after.",
  },
  // 29 -----------------------------------------------------------------------------------------------------
  {
    n: 29,
    what: "a failed rollback left the console reading Up to date, and the engine advertised an update its own apply path refuses",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/update-status"] = { settledHighWaterMark: "0.1.10", pending: null, last: { outcome: "rollback-failed", fromVersion: "0.1.10", toVersion: "0.2.0", canaryVerdict: "rejected", at: iso(NOW - 30 * MIN) } };
    },
    names: (b: Dict): string[] => {
      const u = sec(b, "updates");
      const last = (typeof u.last === "object" && u.last !== null ? u.last : {}) as Dict;
      return last.outcome === "rollback-failed" ? ok() : ["the pack does not carry rollback-failed, so an engine still serving a REJECTED build reads as settled"];
    },
  },
  // 30 -----------------------------------------------------------------------------------------------------
  {
    n: 30,
    what: "an audit head record whose count was zeroed reports zero entries over eight retained ones",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/audit/verify"] = { intact: true, checkedThrough: 8, earliestSeq: 1, rolledOver: false, rolledOverCount: 0, auditCount: 8, auditCountRecovered: true, auditNearCap: false, headAnchorUnreadable: true, verify: { at: iso(NOW - MIN), entriesChecked: 8, durationMs: 3, complete: true } };
      // FIDELITY: the same pass BOOKS both anomalies (scheduler-do-audit.ts:246 and :380).
      w.routes["/sched-diag"] = { storageAnomalies: { "audit-head-count-lost": { count: 1, lastAt: iso(NOW - MIN) }, "audit-head-anchor-unreadable": { count: 1, lastAt: iso(NOW - MIN) } } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "audit-head-count-lost")) f.push("no storage anomaly says the head count was lost");
      const a = sec(b, "audit");
      if (a.auditCountRecovered !== true) f.push("the AUDIT BLOCK ITSELF still states `auditCount` with no caveat beside it: `verifyAudit` answers `auditCountRecovered` and the pack's own projection drops it");
      if (a.headAnchorUnreadable !== true) f.push("the AUDIT BLOCK ITSELF still states `intact:true` with no caveat beside it: `verifyAudit` answers `headAnchorUnreadable` and the pack's own projection drops it");
      return f;
    },
    note: "THE CAVEAT IS IN A DIFFERENT SECTION FROM THE ASSERTION -- the R1 shape this campaign exists to remove.",
  },
  // 31 -----------------------------------------------------------------------------------------------------
  {
    n: 31,
    what: "the lockout surface is byte-identical whether the only Owner grant is intact or corrupt",
    where: "engine",
    mutate: (w: World): void => {
      // The repair added `rosterUnreadable` to GET /policy/lockout-preflight. This world puts the account in
      // exactly that state: one Owner grant, stored corrupt, so the roster reads empty.
      w.routes["/policy/lockout-preflight"] = { passkeyOwnerEnrolled: false, passkeyOwnerEvidence: "no-credential", passkeyWitnessSince: null, recoveryReady: false, recoveryReadyReason: "no-recovery-record", secondOwner: false, rosterUnreadable: 1 };
      w.routes["/roster-hygiene"] = { scanned: 1, ghostCount: 0, neverRanCount: 0 };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const lp = sec(b, "lockoutPosture");
      if (lp.rosterUnreadable !== 1) f.push("the pack does not carry `rosterUnreadable`, the field another pass's repair added, so a corrupt only-Owner grant is still byte-identical to a healthy roster");
      if (lp.secondOwner !== false) f.push("the pack cannot say there is no second Owner to fall back on");
      return f;
    },
  },
  // 32 -----------------------------------------------------------------------------------------------------
  {
    n: 32,
    what: "five of seven damage classes make the expiry warning count read zero",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/expiry/warnings"] = { expiryWarnings: 0, cleanupPending: 0, expiryUnreadable: 1 };
      w.routes["/expiry"] = [{ id: "prod-origin-cert", kind: "certificate", lifecycleClass: "functional", state: "ok", tokenRef: "tok-1" }];
      w.routes["/admin-counters"] = { "stored-expiry-unparseable-timestamp": { count: 1, lastAt: iso(NOW - 12 * MIN) } };
      w.routes["/sched-diag"] = { storageAnomalies: { "expiry-row-unreadable-surfaced": { count: 1, lastAt: iso(NOW - 12 * MIN) } } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "stored-expiry-unparseable-timestamp")) f.push("no admin counter names the unreadable expiry row");
      if (!packSays(b, "expiryUnreadable")) f.push("status.expiryWarnings still reads 0 with nothing beside it saying a row could not be read");
      return f;
    },
    note: "The evidence is reachable ONLY at /admin-counters, which no console screen drives and which reaches an operator solely inside a pack.",
  },
  // 33 -----------------------------------------------------------------------------------------------------
  {
    n: 33,
    what: "a stranger who deploys by terminal is told to generate a second key set",
    where: "docs",
    mutate: NOOP,
    notApplicable: "A CONTRADICTION BETWEEN TWO PUBLISHED PAGES, met before and around the product rather than inside it. The trial's own finding was that the PRODUCT WAS ALREADY RIGHT and the documentation was the defect, so there is no engine state to carry.",
    names: ok,
  },
  // 34 -----------------------------------------------------------------------------------------------------
  {
    n: 34,
    what: "the exit page's five kept artefacts omit signer.pub",
    where: "docs",
    mutate: NOOP,
    notApplicable: "A DOCUMENTATION OMISSION on the exit page, read by somebody who no longer has a console. A pack is generated FROM a running engine and the customer in this defect has deliberately torn theirs down.",
    names: ok,
  },
  // 35 -----------------------------------------------------------------------------------------------------
  {
    n: 35,
    what: "pausing every downpipe does not stop the engine writing to and deleting from the destination",
    where: "engine",
    mutate: (w: World): void => {
      const paused = (w.routes["/downpipes"] as Dict[]).map((s) => ({ ...s, config: { ...(s.config as Dict), enabled: false } }));
      w.routes["/downpipes"] = paused;
      // The canary keeps flying and the retention pass keeps enforcing, which is the defect.
      w.routes["/canary/transitions"] = { enabled: true, status: "alive", deadDestinations: 0, transitionCount: 0, transitions: [] };
      w.routes["/retention-state"] = { record: { at: iso(NOW - 10 * MIN), enforce: true, downpipes: [{ id: "dp1", outcome: "applied", deleted: 8 }] } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const r = rows(b);
      if (!r.every((x) => x.enabled === false)) f.push("the pack does not show the fleet paused");
      const c = sec(b, "canary");
      if (c.enabled !== true) f.push("the pack does not show the canary still enabled over a paused fleet");
      const ret = sec(b, "retention");
      if (!packSays(b, "applied")) f.push("the pack does not show the retention pass still deleting");
      if (JSON.stringify(ret) === "{}") f.push("no retention evidence at all");
      return f;
    },
    note: "Three adjacent facts: every downpipe paused, the canary enabled, the retention pass applied and deleting.",
  },
  // 36 -----------------------------------------------------------------------------------------------------
  {
    n: 36,
    what: "the proof-of-deletion exit asks for an audit export from an engine route the previous step deleted",
    where: "docs",
    mutate: NOOP,
    notApplicable: "AN ORDERING FAULT IN A PUBLISHED PROCEDURE whose sixth step DELETES THE WORKER THAT SERVES THE PACK. The pack cannot be the instrument for a defect whose precondition is that the pack can no longer be generated.",
    names: ok,
  },
  // 37 -----------------------------------------------------------------------------------------------------
  {
    n: 37,
    what: "both exit pages said there is no vendor system to be removed from, and there is one",
    where: "docs",
    mutate: NOOP,
    notApplicable: "A FACT ABOUT THE VENDOR'S OWN CONTROL PLANE (the customer-of-record registry), which lives in Maelstrom's account and not in the customer's. No engine holds it, so no pack can carry it.",
    names: ok,
  },
  // 38 -----------------------------------------------------------------------------------------------------
  {
    n: 38,
    what: "the Overview Updates tile answered an unreadable version pair with the same green Up to date",
    where: "console",
    mutate: (w: World): void => {
      // The ENGINE's half is present and correct: it says the versions cannot be compared.
      w.routes["/update-status"] = { settledHighWaterMark: "0.1.10", pending: null, last: null };
    },
    clientDiag: (): unknown => ({ records: [{ kind: "contract-skew", screen: "overview", driftClass: "unknown-enum", count: 1, firstMs: 5, lastMs: 5 }] }),
    names: (b: Dict): string[] => (packSays(b, "contract-skew") ? ok() : ["no console-asserted row names the skew the tile rendered through"]),
    note: "The engine's versionSkew rides in the pack; what the CONSOLE painted from it does not, unless the console emits a contract-skew row, which it does not for this site.",
  },
  // 39 -----------------------------------------------------------------------------------------------------
  {
    n: 39,
    what: "the triage list said Nothing needs your attention over a console that had read nothing",
    where: "console",
    mutate: NOOP,
    clientDiag: (): unknown => ({ records: [{ kind: "read-degraded", screen: "overview", callClass: "status", count: 5, firstMs: 5, lastMs: 400 }] }),
    names: (b: Dict): string[] => (packSays(b, "read-degraded") ? ok() : ["no console-asserted row says the reads behind the all-clear failed"]),
  },
  // 40 -----------------------------------------------------------------------------------------------------
  {
    n: 40,
    what: "an unreadable recovery-code count wore the ok green a healthy eight wears",
    where: "console",
    mutate: NOOP,
    clientDiag: (): unknown => ({ records: [{ kind: "wire-anomaly", screen: "security", fieldClass: "count", anomaly: "non-finite", count: 1, firstMs: 7, lastMs: 7 }] }),
    names: (b: Dict): string[] => (packSays(b, "wire-anomaly") && packSays(b, "non-finite") ? ok() : ["no console-asserted row says a count arrived in a shape the console could not read"]),
  },
  // 41 -----------------------------------------------------------------------------------------------------
  {
    n: 41,
    what: "the Configuration tile said Missing: . and named nothing",
    where: "console",
    mutate: NOOP,
    names: (): string[] => ["there is no vocabulary member for a REFUSAL THAT PROMISES TO NAME SOMETHING AND NAMES NOTHING: it is not a wire anomaly (every field arrived), not a contract skew (every value parsed) and not an unhandled fault (nothing threw)"],
    note: "Its own row records that no byte-identity test could see it either; a third grading axis had to be invented for it.",
  },
  // 42 -----------------------------------------------------------------------------------------------------
  {
    n: 42,
    what: "two operators editing one downpipe at once both get 200 and one edit is discarded",
    where: "engine",
    mutate: (w: World): void => {
      // The world AFTER the lost update: the downpipe carries B's cadence, and A's is gone. Both writes were
      // audited as successes, because both succeeded.
      const dp0 = (w.routes["/downpipes"] as Dict[])[0] ?? {};
      w.routes["/downpipes"] = [{ ...dp0, config: { ...(dp0.config as Dict), cadenceSeconds: 86400 } }];
      w.routes["/audit/export"] = (url: URL): unknown => {
        const events = [
          { seq: 11, ts: iso(NOW - 2 * MIN), action: "downpipe-create", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
          { seq: 12, ts: iso(NOW - 2 * MIN), action: "downpipe-create", outcome: "ok", prevHash: "sha384:h11", hash: "sha384:h12" },
        ];
        return url.searchParams.get("action") !== null ? { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) } : { events, headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) };
      };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "baseMoved") && !packSays(b, "superseded") && !packSays(b, "lostUpdate")) {
        f.push("nothing in the pack says a write overwrote a base it had not read: the two successful upserts are indistinguishable from two deliberate sequential edits");
      }
      return f;
    },
  },
  // 43 -----------------------------------------------------------------------------------------------------
  {
    n: 43,
    what: "clicking a downpipe's enable switch writes back every other field as the page last saw it",
    where: "console",
    mutate: (w: World): void => {
      const dp0 = (w.routes["/downpipes"] as Dict[])[0] ?? {};
      w.routes["/downpipes"] = [{ ...dp0, config: { ...(dp0.config as Dict), cadenceSeconds: 86400, enabled: false } }];
    },
    names: (b: Dict): string[] => (packSays(b, "staleWriteback") || packSays(b, "baseMoved") ? [] : ["the reverted configuration is simply the current configuration: nothing distinguishes a field an operator deliberately set from one a toggle wrote back stale"]),
  },
  // 44 -----------------------------------------------------------------------------------------------------
  {
    n: 44,
    what: "a delete answers deleted:true while the downpipe is still there",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/audit/export"] = (url: URL): unknown => {
        const events = [
          { seq: 11, ts: iso(NOW - 3 * MIN), action: "downpipe-delete", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
          { seq: 12, ts: iso(NOW - 3 * MIN), action: "downpipe-create", outcome: "ok", prevHash: "sha384:h11", hash: "sha384:h12" },
        ];
        return url.searchParams.get("action") !== null ? { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) } : { events, headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW - MIN) };
      };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const ev = Array.isArray(b.configEvents) ? (b.configEvents as Dict[]) : [];
      const del = ev.find((e) => e.action === "downpipe-delete");
      if (del === undefined) f.push("the delete does not reach the pack at all");
      if (rows(b).length !== 1) f.push("population: the deleted downpipe should still be present");
      // The pack carries a delete event AND the live downpipe. Nothing joins them.
      if (!packSays(b, "deleteContested") && !packSays(b, "deleteRaced")) {
        f.push("the pack carries a successful delete event and a live downpipe with the same id and says nothing about the contradiction");
      }
      return f;
    },
  },
  // 45 -----------------------------------------------------------------------------------------------------
  {
    n: 45,
    what: "a brand-new Owner passkey dated before the record-keeping opened for it",
    where: "engine",
    mutate: (w: World): void => {
      w.routes["/policy/lockout-preflight"] = { passkeyOwnerEnrolled: true, passkeyOwnerEvidence: "unknown", passkeyWitnessSince: iso(NOW - 10 * DAY), recoveryReady: true, recoveryReadyReason: "ok", secondOwner: false, rosterUnreadable: 0 };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const lp = sec(b, "lockoutPosture");
      if (lp.passkeyOwnerEvidence !== "unknown") f.push("the pack does not carry `passkeyOwnerEvidence`, the enum this defect corrupts, so `unknown` and the true `never-asserted` are the same pack");
      if (lp.passkeyWitnessSince === undefined) f.push("the pack carries no witness-since stamp, so the ORDERING that produced the wrong member cannot be read");
      return f;
    },
  },
  // 46 -----------------------------------------------------------------------------------------------------
  {
    n: 46,
    what: "a PAUSED downpipe's archives were still being deleted",
    where: "engine",
    mutate: (w: World): void => {
      const dp0 = (w.routes["/downpipes"] as Dict[])[0] ?? {};
      w.routes["/downpipes"] = [{ ...dp0, config: { ...(dp0.config as Dict), enabled: false } }];
      w.routes["/retention-state"] = { record: { at: iso(NOW - 10 * MIN), enforce: true, downpipesPaused: 1, downpipes: [{ id: "dp1", outcome: "paused", deleted: 0 }] } };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "\"paused\"")) f.push("the retention record cannot say the pass STOOD DOWN because the downpipe is paused");
      if (!packSays(b, "downpipesPaused")) f.push("the pass record carries no count of downpipes it stood down for");
      return f;
    },
    note: "The fix made the stand-down a FIRST-CLASS OUTCOME rather than an absent row, precisely so the pack could tell it from a downpipe that was never selected.",
  },
  // 47 -----------------------------------------------------------------------------------------------------
  {
    n: 47,
    what: "six console screens said the engine could not be reached while the engine was answering 200",
    where: "console",
    mutate: NOOP,
    // THE REPAIRED CONSOLE'S OWN ROW. `console-fault` maps to faultClass `other` in the console's classifier
    // (console/src/lib/client-diag/classify.ts:239), and `recordNetworkBlock` -- which banked the FALSE
    // `origin-rejected` -- now fires only for a genuine `network` kind.
    clientDiag: (): unknown => ({ records: [{ kind: "engine-call", screen: "access", faultClass: "other", count: 6, firstMs: 30, lastMs: 900 }] }),
    names: (b: Dict): string[] => {
      const f: string[] = [];
      // THE HARM WAS NOT SILENCE, IT WAS A FALSE CLAIM: the pack banked "set CONSOLE_ORIGIN" for an account
      // whose CONSOLE_ORIGIN was correct. That must be gone, and this asserts it rather than assuming it.
      if (packSays(b, "origin-rejected")) f.push("the pack STILL banks origin-rejected for an engine that answered, which is a wrong remedy rather than a missing one");
      if (!packSays(b, "engine-call")) f.push("no console-asserted row survives at all");
      // And what remains says very little: `other` is the closed vocabulary's catch-all.
      f.push("faultClass `other` is the bucket that says nothing: the pack can show the console threw on a screen and cannot say the throw came from the console's own render code after a successful 200");
      return f;
    },
    note: "THE DECISIVE MOVEMENT IS THE REMOVAL OF A FALSE CLAIM RATHER THAN THE ADDITION OF A TRUE ONE. A pack that misdirects is worse than a partial one, and this was the only defect in the table whose harm was a wrong sentence IN THE PACK.",
  },
  // 48 -----------------------------------------------------------------------------------------------------
  {
    n: 48,
    what: "ONE malformed downpipe row blanked the WHOLE Overview and left the skeleton up for ever",
    where: "console",
    mutate: (w: World): void => {
      // The ENGINE's own roster hygiene names the malformed class, and the pack reads it.
      w.routes["/roster-hygiene"] = { scanned: 4, ghostCount: 1, ghosts: [{ key: "dp:acme-payroll", embeddedId: null, kind: "malformed" }], neverRanCount: 0 };
    },
    clientDiag: (): unknown => ({ records: [{ kind: "unhandled", screen: "overview", errorClass: "TypeError", faultSource: "unhandled-rejection", count: 1, firstMs: 400, lastMs: 400 }] }),
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const ri = sec(b, "rosterIntegrity");
      if (ri.ghostCount !== 1) f.push("the engine's own roster hygiene does not name the malformed row");
      if (!packSays(b, "malformed")) f.push("the malformed CLASS is not carried, so a reader cannot tell an undeletable ghost from a row the console could not read");
      if (!packSays(b, "unhandled-rejection")) f.push("the browser's own evidence that a render died is absent, so the pack cannot say the operator saw a skeleton rather than a screen");
      return f;
    },
    note: "BOTH HALVES RIDE AND THEY JOIN: the engine names the malformed row, and the browser says a render rejected on the overview. Neither alone reaches the fault.",
  },
  // 49 -----------------------------------------------------------------------------------------------------
  {
    n: 49,
    what: "one absent status field still cost the operator four of nine stat tiles",
    where: "console",
    mutate: (w: World): void => {
      // The engine answers 200 with no `operationalConfigured` object at all. The pack carries status verbatim.
      w.routes["/status-baseline"] = { version: "0.1.0", cfVersionId: "cfv-current-001", at: NOW - 7 * DAY };
      w.env.RUNSEAL = undefined;
    },
    clientDiag: (): unknown => ({ records: [{ kind: "wire-anomaly", screen: "overview", fieldClass: "status-enum", anomaly: "missing", count: 1, firstMs: 60, lastMs: 60 }] }),
    names: (b: Dict): string[] => {
      const f: string[] = [];
      if (!packSays(b, "wire-anomaly")) f.push("no console-asserted row says a field the screen needed was absent");
      if (!packSays(b, "\"missing\"")) f.push("the ANOMALY is not carried, so an absent field and an unparseable one are the same row");
      return f;
    },
    note: "The pack's own `status` block is built by the engine and always carries operationalConfigured, so the ABSENCE this defect needs is a wire state only the browser can witness. The `wire-anomaly` kind is the member for it and it exists.",
  },
  // 50 -----------------------------------------------------------------------------------------------------
  {
    n: 50,
    what: "an estate that LOST its run history and one that never had any were the SAME response",
    where: "engine",
    mutate: (w: World): void => {
      // Every downpipe deleted: the rings are gone and the account-global counter is untouched, which is the
      // whole of the discriminating fact.
      w.routes["/history"] = { byDownpipe: {} };
      w.routes["/downpipes"] = [];
      w.routes["/scheduler-signals"] = {
        ticks: [],
        dueIndex: { at: NOW - 3 * MIN, indexEntriesBeforeRebuild: 0, indexEntriesRequired: 0, dpTotal: 0, matched: true },
        runlog: { counter: 812, maxHistoryIndex: 0 },
        storageFaults: { total: 0, valueTooLarge: 0, putFailed: 0 },
      };
    },
    names: (b: Dict): string[] => {
      const f: string[] = [];
      const sch = sec(b, "scheduler");
      const rl = (typeof sch.runlog === "object" && sch.runlog !== null ? sch.runlog : {}) as Dict;
      if (rl.counter !== 812) f.push("the pack does not carry the account-global run counter, so an estate that lost its history and one that never had any are the same pack");
      if (rows(b).length !== 0) f.push("population: the fleet should be empty");
      return f;
    },
    note: "THE PACK ALREADY HAD THE FACT THE CONSOLE DID NOT. `runlogCounter` has ridden on GET /scheduler-signals for the pack all along and was simply not on GET /history, the read the console makes -- so the pack could always tell these two apart and the screen could not.",
  },
];
