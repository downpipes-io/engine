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
// It RETURNS whether the line was emitted. The swallow is still absolute (a mirror failure must never
// affect the audit commit -- the in-account chain is the authority and the SIEM line is observability), but
// swallowing it SILENTLY meant "our SIEM stopped receiving Downpipes audit events" had no engine-side record
// at all: a dead mirror and a healthy one looked identical from the pack. The caller (appendAudit) counts the
// false into the auditEgress ledger. No content and no reason ride: the boolean is the whole signal.
export function mirrorAuditEvent(event: AuditEvent): boolean {
  try {
    // This console.log IS the intentional Workers-Logs/Logpush
    // egress for the audit SIEM channel, not a debug trace. The audit-trail design depends on it.
    console.log(JSON.stringify({ source: "downpipe-audit", v: 1, ...event }));
    return true;
  } catch {
    // A mirror failure must never affect the audit commit; the in-account chain is the
    // authority and the SIEM line is observability.
    return false;
  }
}
