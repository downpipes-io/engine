// bytesEqual is a plain length-then-byte comparison shared by the non-security byte compares (the
// RUNLOG sig-still-current check in seal/pipeline.ts and the config-history de-dupe in
// scheduler-helpers.ts). It is NOT a security comparison: no secret is compared and no timing channel
// matters here (both inputs are the account's own non-secret serialised bytes), so a short-circuiting
// compare is correct and cheap. A single shared definition keeps the two call sites in lockstep (a
// future length-guard or fix lands once, not twice). For a constant-time compare of secrets use
// constantTimeEqual in crypto/bytes.ts instead.
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
