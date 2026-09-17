// Dependency-free home for the recovery-code threshold so the three readers (recovery.ts, the pure
// posture-checks module, and scheduler-do.ts) all bind to ONE literal. posture-checks.ts is deliberately free
// of business-logic imports; this module carries no logic, only the constant, so it can be imported there
// without dragging in recovery.ts's crypto dependency.

// RECOVERY_CODES_LOW_THRESHOLD is the count at or below which the console/posture prompts a regenerate (the
// caller's spec: warn at <= 2 remaining, which includes 0). A user who is down to their last couple of codes
// should mint a fresh set before they are locked out.
export const RECOVERY_CODES_LOW_THRESHOLD = 2;
