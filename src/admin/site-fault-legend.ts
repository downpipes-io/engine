// The site-fault legend: one entry per catch that calls noteSiteFault (admin/site-faults.ts).
//
// The key is the site id the catch passes. It is a constant written at the call site, so it survives a move,
// a rename or a reorder of the code around it. SiteFaultId is derived from this table, so a call with an id
// that has no entry here does not type-check.
//
// Each entry is what the support pack shows beside the id: the subsystem, what failed (one sentence, no
// customer value), and the fix class from the closed list below. The pack carries the entry text for the
// sites that fired and nothing for the others. A row for a site whose class undermines also carries the evidence
// it undermines.

export const SITE_FAULT_FIX_CLASSES = [
  // A platform fault that clears on its own. Wait, then check that the next run or read succeeds.
  "transient-platform",
  // Durable Object storage failed a read or a write. Check the Cloudflare status page; repeated rows mean
  // the engine is running on degraded storage and support should look at the whole pack.
  "storage-health",
  // A cursor, token or body the engine made was refused by the platform. The work continues on a slower path.
  "slow-path-fallback",
  // The engine's own code or data failed a check it should always pass. Send the pack to support.
  "engine-defect",
] as const;
export type SiteFaultFixClass = (typeof SITE_FAULT_FIX_CLASSES)[number];

export interface SiteFaultLegendEntry {
  readonly subsystem: string;
  readonly what: string;
  readonly fixClass: SiteFaultFixClass;
  // Present on every storage-health and engine-defect entry, and on no other. It names the pack evidence that
  // fault may leave wrong, as pack paths. An empty list means the entry names no pack section, so the whole
  // pack needs review.
  readonly undermines?: readonly string[];
}

export const SITE_FAULT_LEGEND = {
  "sched.replica-floor-write": {
    subsystem: "replication",
    what: "A replica copy was recorded as good, but the write that raises that replica's anti-rollback floor failed. The floor stays at its old value, so a later restore from that replica does not refuse an older RUNLOG.",
    fixClass: "storage-health",
    undermines: ["downpipes[].replication"],
  },
  "ratelimit.health-read": {
    subsystem: "rate-limit",
    what: "The account rate limiter could not read its own health record. The pack's rateLimitDoHealth then shows zero fail-open counts, which may be false.",
    fixClass: "storage-health",
    undermines: ["rateLimitDoHealth"],
  },
  "source.kv-resume-cursor": {
    subsystem: "sources",
    what: "KV refused a saved list cursor when a sliced backup resumed. The listing restarted from the last key seen, so the slice read more list pages than it needed to.",
    fixClass: "slow-path-fallback",
  },
  "diag.site-fault-drain-storage": {
    subsystem: "support-pack",
    what: "The scheduler could not write its site-fault record to its own storage. The rows were kept in memory for the next request, so their counts may arrive late or, if the isolate ended, not at all.",
    fixClass: "storage-health",
    undermines: ["siteFaults"],
  },
  "diag.site-fault-drain-post": {
    subsystem: "support-pack",
    what: "A Worker or Durable Object could not send its site-fault rows to the scheduler. The rows were kept in memory for the next attempt, so their counts may arrive late or, if the isolate ended, not at all.",
    fixClass: "transient-platform",
  },
  "admin.inbound-body-cancel": {
    subsystem: "admin-edge",
    what: "A sign-in request body over its byte cap was refused with 413, but cancelling the rest of the body failed. The refusal stood; the platform closes the stream when the request ends.",
    fixClass: "transient-platform",
  },
  "admin.disarm-alert-body": {
    subsystem: "admin-edge",
    what: "An approval-policy change answered 200 with a body that is not JSON, so the Worker could not read whether a policy was turned off and sent no disarm alert. The body was returned to the caller unchanged.",
    fixClass: "engine-defect",
    undermines: ["notify"],
  },
  "admin.member-invite-body": {
    subsystem: "admin-edge",
    what: "A role change answered 200 with a body that is not JSON, so the Worker could not check it for a member-only invite link. The body was returned to the caller unchanged.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "notify.retention-armed-alone-alert": {
    subsystem: "notify",
    what: "A downpipe edit armed or widened the scheduled retention prune with no second approver, and the retention-armed-alone alert could not be routed. The edit stayed applied and its audit row was written.",
    fixClass: "transient-platform",
  },
  "notify.otlp-body-cancel": {
    subsystem: "notify",
    what: "An OTLP collector answered with a response body over the read cap, and cancelling the rest of the body failed. The push still counted as delivered, and its partial-success body was recorded as oversized.",
    fixClass: "transient-platform",
  },
  "restore.plan-hash": {
    subsystem: "restore",
    what: "A restore request carried a plan that the engine could not hash. The request was refused as a plan mismatch, so the operator runs the dry run again and requests from the plan it returns.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "change-control.prune-widen-check": {
    subsystem: "change-control",
    what: "The check that decides whether a downpipe edit widens the retention prune failed. The edit was treated as widening, so it queued for a second approver where one exists.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "rekey.runlog-precheck-read": {
    subsystem: "re-key",
    what: "Before a signer re-key, reading a destination's RUNLOG or its signature failed. The re-key stopped before any key changed and named the destination as unreadable.",
    fixClass: "transient-platform",
  },
  "rekey.runlog-precheck-parse": {
    subsystem: "re-key",
    what: "Before a signer re-key, a destination's RUNLOG verified under the current signer but did not parse. The re-key stopped before any key changed and named the destination as unparsable.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "rekey.runlog-handover-read": {
    subsystem: "re-key",
    what: "After a signer re-key, reading a destination's RUNLOG to hand it over to the new signer failed. That destination stays pending under the held old public key.",
    fixClass: "transient-platform",
  },
  "rekey.handover-target-open": {
    subsystem: "re-key",
    what: "A signer re-key could not open one destination to check its RUNLOG. The re-key stopped before any key changed and named the destination as unreadable.",
    fixClass: "transient-platform",
  },
  "rekey.handover-resign": {
    subsystem: "re-key",
    what: "After a signer re-key, signing a destination's RUNLOG under the new signer failed part way. That destination stays pending under the held old public key.",
    fixClass: "transient-platform",
  },
  "rekey.handover-settle": {
    subsystem: "re-key",
    what: "A key install failed during a signer re-key, and settling the RUNLOG hand-over after it also failed. The held old public key stays, so the attended re-sign can finish the hand-over.",
    fixClass: "transient-platform",
  },
  "rekey.install-response-body": {
    subsystem: "re-key",
    what: "The key install response was not JSON when the RUNLOG hand-over outcome was added to it. The response carried the hand-over outcome only.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "rekey.verifier-decode": {
    subsystem: "re-key",
    what: "The held old public key of a signer re-key did not decode. The engine treated it as no held key, so no RUNLOG was handed over under it.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "sched.runlog-route-body": {
    subsystem: "runlog",
    what: "The scheduler received a RUNLOG floor or re-key hand-over request whose body was not JSON. It read the request as empty.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "runlog.attended-dest-open": {
    subsystem: "runlog",
    what: "The attended RUNLOG routes could not open a destination. The Owner was refused with 409 and the reason.",
    fixClass: "transient-platform",
  },
  "runlog.relink-parse": {
    subsystem: "runlog",
    what: "An attended relink found a RUNLOG that verified under the current signer but did not parse. Nothing was written, and the relink was refused.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "runlog.floor-read": {
    subsystem: "runlog",
    what: "A RUNLOG writer could not read the destination's anti-rollback floor from the scheduler. The write went ahead without the floor check, as a fresh destination would.",
    fixClass: "transient-platform",
  },
  "runlog.index-held-report": {
    subsystem: "runlog",
    what: "A RUNLOG append refused an index its destination already holds, and the report to the scheduler failed. The run was refused as usual, but allocation was not held and the counter was not moved until a later refusal reports it.",
    fixClass: "transient-platform",
  },
  "runlog.advance-failed": {
    subsystem: "runlog",
    what: "The cron pass that moves the run counter past the highest RUNLOG index failed. The scheduler keeps the report and holds new runs, and the next pass tries again.",
    fixClass: "transient-platform",
  },
  "runlog.advance-archive-list": {
    subsystem: "runlog",
    what: "The cron pass could not list the configured destinations while it moved the run counter. Only the default destination was read for this pass.",
    fixClass: "transient-platform",
  },
  "runlog.advance-archive-read": {
    subsystem: "runlog",
    what: "A destination's RUNLOG could not be read while the cron pass moved the run counter. The counter moved past the indices the other destinations hold, and a repeated index at this one is refused again.",
    fixClass: "transient-platform",
  },
  "runlog.advance-signer": {
    subsystem: "runlog",
    what: "The engine's signer could not be loaded to verify a RUNLOG while the cron pass moved the run counter. The counter moved past the refused index only.",
    fixClass: "engine-defect",
    undermines: [],
  },
  "repl.runlog-read": {
    subsystem: "replication",
    what: "The replication pass could not read a destination's RUNLOG. That destination was skipped as unreadable for this pass and is tried again next pass.",
    fixClass: "transient-platform",
  },
  "repl.source-runlog-verify": {
    subsystem: "replication",
    what: "A read or write failed while the replication pass verified a source RUNLOG. The RUNLOG was not used as a source this pass.",
    fixClass: "transient-platform",
  },
  "repl.root-parse": {
    subsystem: "replication",
    what: "A run's root manifest verified on a replica but did not parse. The replica copy was refused as an integrity failure and is retried next pass.",
    fixClass: "engine-defect",
    undermines: ["downpipes[].replication"],
  },
  "diag.site-fault-post-body": {
    subsystem: "support-pack",
    what: "The scheduler received a site-fault batch it could not parse. The batch was dropped.",
    fixClass: "engine-defect",
    undermines: ["siteFaults"],
  },
} as const satisfies Record<string, SiteFaultLegendEntry>;

export type SiteFaultId = keyof typeof SITE_FAULT_LEGEND;

export function isSiteFaultId(v: unknown): v is SiteFaultId {
  return typeof v === "string" && Object.hasOwn(SITE_FAULT_LEGEND, v);
}
