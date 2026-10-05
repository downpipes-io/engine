import type { AuditEvent } from "./audit.ts";

// mirrorAuditEvent emits one structured JSON line per committed audit event, which is
// what makes the product's audit trail land in a SIEM with ZERO inbound surface: the
// line flows into Workers Logs, and a customer-configured Logpush job ships it to
// Splunk (native HEC destination), an HTTP collector (Microsoft Sentinel ingestion,
// Exabeam, Rapid7 InsightIDR, CrowdStrike NG-SIEM, Wazuh), or R2/S3 for batch pickup.
// The complementary PULL path (a platform-issued client/secret reading
// GET /support/audit-feed) serves collectors that prefer polling; both carry the same
// events. See docs/SCALE-AND-ENTERPRISE.md section 3 (where the logs are, and how they reach a SIEM).
//
// The line is REDACTION-SAFE BY CONSTRUCTION: an AuditEvent already carries only the
// closed-union action/outcome, the coarse target labels, the actor's verified email and
// the chain fields; never a key, a token or a value (audit.ts owns that contract). The
// chain fields (seq, prevHash, hash) ride along deliberately so a SIEM can both
// checkpoint by seq AND alert on a gap or a hash discontinuity, which extends the
// tamper-evidence of the in-account chain into the customer's detection stack.
//
// `source` is the stable selector for Logpush filtering and SIEM parsing; `v` versions
// the line shape for collectors.
// mirrorAuditEvent RETURNS whether the line was emitted. The swallow is still absolute (a mirror failure must
// never affect the audit commit -- the in-account chain is the authority and the SIEM line is observability),
// but swallowing it SILENTLY would mean "our SIEM stopped receiving Downpipes audit events" had no engine-side
// record at all: a dead mirror and a healthy one would look identical from the pack. The caller (appendAudit)
// counts the false into the auditEgress ledger. No content and no reason ride: the boolean is the whole signal.
export function mirrorAuditEvent(event: AuditEvent): boolean {
  try {
    // GUARDRAILS section 6 deviation (accepted): this console.log IS the intentional Workers-Logs/Logpush
    // egress for the audit SIEM channel, not a debug trace. The audit-trail design depends on it.
    console.log(JSON.stringify({ source: "downpipe-audit", v: 1, ...event }));
    return true;
  } catch {
    // A mirror failure must never affect the audit commit; the in-account chain is the
    // authority and the SIEM line is observability.
    return false;
  }
}

// DRY_RUN_MIRROR_HOLD holds the Durable Object instances whose audit mirror is suspended for a dry run.
// dryRunConfigMutation (scheduler-do-change-control.ts) runs the real mutation and then rolls storage back.
// The rollback removes the audit row the mutation wrote, but it cannot recall a line already sent to
// Workers Logs. Without this hold, a SIEM saw a "success" line for a change that never committed, and the
// propose row that followed carried the same seq. appendAudit skips the mirror while its instance is held,
// so the stream carries only the rows that stay on the chain. A WeakSet keyed by the instance keeps the hold
// per DO and never outlives it.
const DRY_RUN_MIRROR_HOLD = new WeakSet<object>();

export function holdAuditMirror(owner: object): void {
  DRY_RUN_MIRROR_HOLD.add(owner);
}

export function releaseAuditMirror(owner: object): void {
  DRY_RUN_MIRROR_HOLD.delete(owner);
}

export function auditMirrorHeld(owner: object): boolean {
  return DRY_RUN_MIRROR_HOLD.has(owner);
}
