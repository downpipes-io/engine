// The restore-applied notification's content, as a pure function.
//
// It lives in its own engine-only module rather than in restore-types.ts, which is the WIRE contract and is
// copied verbatim into the console's api.ts: the console has no use for this and copying a function into a
// types file would make that hand-copy noisier for no gain.
//
// It is pure so that what a customer is told about an irreversible operation can be tested directly. Inline
// in the router handler, neither of the two decisions below was reachable from a test.

// restoreAppliedEmission derives the severity and detail from an applied restore's own counts. A restore that fell short is not info-severity news:
// severityOf gives the event's baseline (info, success-class, digestible), and a shortfall escalates it to
// warning so it LEAVES the digest and reaches someone promptly, which is the only reason a shortfall alert
// is worth sending at all. The detail states the shortfall rather than only the total, for the same reason
// the receipt and the console outcome do: "restored 98 of 100" with no cause reads as success, and a
// notification is the surface an operator is least likely to go back and interrogate.
export function restoreAppliedEmission(input: {
  runId: string;
  recordsVerified: number;
  recordsRestored: number;
  failures: number;
  recordsSkipped?: number;
}): { severity: "info" | "warning"; detail: string; shortfall: boolean } {
  const parts: string[] = [];
  if (input.failures > 0) parts.push(`${input.failures} failed to write`);
  if (input.recordsSkipped) parts.push(`${input.recordsSkipped} deliberately not written and still outstanding`);
  const detail = `run ${input.runId}: restored ${input.recordsRestored} of ${input.recordsVerified} verified record(s)${parts.length > 0 ? `, ${parts.join(", ")}` : ""}`;
  return {
    severity: parts.length > 0 ? "warning" : "info",
    // Clamped here rather than at the call site: the cap is part of what the emission IS, and a caller that
    // forgot it would push an over-long detail into a channel adapter.
    detail: detail.slice(0, 200),
    shortfall: parts.length > 0,
  };
}
