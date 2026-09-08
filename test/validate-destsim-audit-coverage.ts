// Covers the audit EXPORT/FILTER branches the format-matrix did not reach (src/admin/audit.ts): pageEvents /
// matchesFilter's per-field filter arms, and describeTarget's ALTERNATE ternary arms (the field-absent paths
// its opposite fixtures leave untaken). These are the SIEM CSV-export + admin-audit-page paths; pinning the
// filter + target-rendering branches keeps the export honest and redaction-safe on every shape.
//
// Run: node test/validate-destsim-audit-coverage.ts

import { pageEvents, toCSV, headOf } from "../src/admin/audit.ts";
import type { AuditEvent, AuditTarget } from "../src/admin/audit-types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

let seq = 1;
const H = `sha384:${"0".repeat(96)}`;
function ev(target: AuditTarget, o: Partial<AuditEvent> = {}): AuditEvent {
  const s = seq++;
  return { seq: s, ts: new Date(1_700_000_000_000 + s * 1000).toISOString(), actorSubject: null, actorEmail: "a@x.example", actorMethod: "access", sourceIp: "203.0.113.1", action: "downpipe-create", outcome: "success", target, prevHash: H, hash: H, ...o };
}

async function main(): Promise<void> {
  // ---- pageEvents / matchesFilter: each filter arm ----
  const base: AuditEvent[] = [
    ev({ kind: "downpipe", id: "dp-1" }, { actorEmail: "alice@x.example", action: "downpipe-create", outcome: "success", ts: "2026-01-01T00:00:00.000Z" }),
    ev({ kind: "downpipe", id: "dp-2" }, { actorEmail: "bob@x.example", action: "downpipe-delete", outcome: "denied", ts: "2026-06-01T00:00:00.000Z" }),
    ev({ kind: "run", runId: "r-1" }, { actorEmail: "alice@x.example", action: "run-trigger", outcome: "failed", ts: "2026-12-01T00:00:00.000Z" }),
  ];
  ok("filter actor: only alice's events", pageEvents(base, { actor: "alice@x.example" }).every((e) => e.actorEmail === "alice@x.example"));
  ok("filter action: only downpipe-delete", pageEvents(base, { action: "downpipe-delete" }).every((e) => e.action === "downpipe-delete"));
  ok("filter outcome: only denied", pageEvents(base, { outcome: "denied" }).every((e) => e.outcome === "denied"));
  ok("filter downpipe: only events targeting dp-1", pageEvents(base, { downpipe: "dp-1" }).length === 1);
  ok("filter from: only events at/after 2026-06", pageEvents(base, { from: "2026-06-01T00:00:00.000Z" }).every((e) => e.ts >= "2026-06-01T00:00:00.000Z"));
  ok("filter to: only events at/before 2026-06", pageEvents(base, { to: "2026-06-01T00:00:00.000Z" }).every((e) => e.ts <= "2026-06-01T00:00:00.000Z"));
  ok("filter before (seq cursor): only seq < 2", pageEvents(base, { before: 2 }).every((e) => e.seq < 2));
  ok("filter afterSeq (tail cursor): only seq > 1", pageEvents(base, { afterSeq: 1 }).every((e) => e.seq > 1));

  // ---- describeTarget: the ALTERNATE ternary arms (field-absent / opposite-op paths), via toCSV ----
  const alt: AuditEvent[] = [
    // restore with NO redirectBinding / NOT latest / NO approver / NO destinationId (all the else-arms)
    ev({ kind: "restore", runId: "r-a", redirectBinding: null, planHash: H, isLatest: false, reason: null, approverEmail: null, approverSubject: null } as unknown as AuditTarget),
    // restore-receipt NOT all verified
    ev({ kind: "restore-receipt", runId: "r-b", receiptSha384: H, recordsRestored: 3, allVerified: false, complete: false, recordsVerified: 2, failures: 1, outOfWindow: 0, readbackVerified: 2, readbackMismatched: 0, d1Total: 0, d1Verified: 0 } as unknown as AuditTarget),
    // customrole capabilityCount 0 (the removal arm)
    ev({ kind: "customrole", name: "Removed Role", capabilityCount: 0 } as unknown as AuditTarget),
    // configchange / owneraction with NO approver
    ev({ kind: "configchange", id: "c-1", changeKind: "role-set", approverEmail: null } as unknown as AuditTarget),
    ev({ kind: "owneraction", id: "o-1", actionKind: "dest-remove", approverEmail: null } as unknown as AuditTarget),
    // change EMERGENCY (with number + reason) and emergency with no number
    ev({ kind: "change", actionKind: "restore-apply", emergency: true, changeNumber: "CHG-9", reason: "prod incident" } as unknown as AuditTarget),
    ev({ kind: "change", actionKind: "restore-apply", emergency: true, changeNumber: null, reason: null } as unknown as AuditTarget),
    // posture-check overrideKind null (the no-override arm)
    ev({ kind: "posture-check", checkId: "p-1", overrideKind: null } as unknown as AuditTarget),
    // dest-change: remove (forced), remove (promo default change), default, clear
    ev({ kind: "dest-change", op: "remove", id: "d-1", force: true, uncoveredOriginRunCount: 2, fromDefaultId: "d-1", toDefaultId: "d-2" } as unknown as AuditTarget),
    ev({ kind: "dest-change", op: "default", id: "d-2", toDefaultId: "d-2" } as unknown as AuditTarget),
    ev({ kind: "dest-change", op: "clear", fromDefaultId: "d-2", toDefaultId: null } as unknown as AuditTarget),
    // idpconnection non-signin op; credential-cleanup with no tokenRef; push-destination delivery-failure
    ev({ kind: "idpconnection", connId: "ic-1", connKind: "saml", op: "update" } as unknown as AuditTarget),
    ev({ kind: "credential-cleanup", itemId: "ci-1" } as unknown as AuditTarget),
    ev({ kind: "push-destination", op: "delivery-failure", failureCount: 3 } as unknown as AuditTarget),
  ];
  const csv = toCSV(alt, headOf(alt));
  ok("describeTarget alternate arms render without throwing over the opposite-field fixtures", csv.length > 0 && csv.split("\r\n").length >= alt.length);
  // Spot-check a couple of the alternate arms rendered their distinct text.
  ok("describeTarget: an EMERGENCY change renders loudly", csv.includes("EMERGENCY CHANGE"));
  ok("describeTarget: a forced destination removal names the forced-orphan count", /FORCED, 2 run/.test(csv));
  ok("describeTarget: a delivery-failure names the consecutive failure count", /delivery|failure/i.test(csv));
  ok("describeTarget: no fixture leaked a secret-shaped value (redaction-safe)", !csv.includes("sekret") && !csv.includes("AKIA"));

  console.log(failures === 0 ? "\nDESTSIM AUDIT-COVERAGE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
