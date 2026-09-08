// Change management (OWNER OPT-IN "Require Change Number", default OFF). This leaf module holds the
// CHANGE REFERENCE the operator attaches to a CAB-worthy change when the policy is on, the pure validator
// that decides whether a reference satisfies the policy, and the safe parse of an untrusted reference off
// the wire. It is a process / compliance control, NOT a security control and NOT an authority input: no
// gate reads a ChangeRef. It rides on the caller exactly like sourceIp (request-scoped, non-authoritative
// provenance), and a change number / emergency reason is operator-attested free text, the same redaction
// class as the restore `reason` (bounded, control-chars stripped, never trusted as a secret).
//
// It is a LEAF (imports nothing from the admin layer) so the router, the scheduler DO, identity.ts (the
// caller codec) and reports.ts can all import it without a cycle. The "which owner actions are
// change-controlled" predicate lives in owner-action.ts (which owns the OwnerActionKind set); this module
// owns only the reference shape + its validation + parsing.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries a value.

// ChangeRef is what the operator attaches to a change-controlled action when requireChangeNumber is ON:
// EITHER a change number (a normal CAB change) OR an Emergency Change (a deliberate bypass of the number
// requirement, recorded loudly) carrying a justification. number is null only for an emergency raised
// without one; reason is the emergency justification (null for a normal change). All fields are
// redaction-safe operator text (bounded, control-chars stripped); none is a secret or an authority input.
export interface ChangeRef {
  number: string | null;
  emergency: boolean;
  reason: string | null;
}

// CHANGE_HEADER is the request header the console sets to carry the change reference to the engine:
// base64url(JSON(ChangeRef)). The router reads it ONCE onto caller.change (mirroring how it reads the edge
// CF-Connecting-IP onto caller.sourceIp); it is non-authority metadata, so reading it from the inbound
// client request (rather than an internal header) is safe: it confers nothing, it is only the operator's
// attestation of which change this request belongs to.
export const CHANGE_HEADER = "x-downpipes-change";

// CHANGE_NUMBER_MAX / CHANGE_REASON_MAX bound the operator free text so a reference cannot carry an
// unbounded blob into the audit target (the same discipline the caller groups + the restore reason use).
export const CHANGE_NUMBER_MAX = 64;
export const CHANGE_REASON_MAX = 500;

// CHANGE_NUMBER_TOO_LONG is the refusal the operator sees when the change number they attached is longer
// than the cap. It is customer-facing prose the console surfaces verbatim, so it names the bound AND the
// remedy: the operator is looking at the field, and the only useful thing to tell them is what to type
// instead. It is exported so the router and any reader use the same words.
export const CHANGE_NUMBER_TOO_LONG = `a change number must be ${CHANGE_NUMBER_MAX} characters or fewer (shorten it to the reference your change record uses)`;

// stripChangeControlChars drops the ASCII control characters and trims, WITHOUT bounding the length. It is
// the measuring half of normaliseChangeText: "how long is the reference the operator actually supplied",
// asked of the same cleaned text the store would hold. Kept separate rather than folded into
// normaliseChangeText because that function caps FIRST and trims after, so its output can never answer a
// question about a value longer than the cap.
function stripChangeControlChars(v: string): string {
  let out = "";
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) continue; // drop control chars
    out += v[i];
  }
  return out.trim();
}

// changeNumberExceedsMax answers whether a supplied change number is longer than the cap, measured on the
// CLEANED text (control characters dropped, trimmed) rather than on the raw bytes. That is deliberate and it
// is the no-over-refusal property: a legal reference padded with whitespace, or carrying a stray CR from a
// paste, is still a legal reference and must be accepted. A non-string is not an over-length number (it
// carries no reference at all, which parseChangeRef already reads as "none").
export function changeNumberExceedsMax(v: unknown): boolean {
  return typeof v === "string" && stripChangeControlChars(v).length > CHANGE_NUMBER_MAX;
}

// normaliseChangeText trims, drops ASCII control characters (0x00-0x1F / 0x7F, matching the caller-group
// normaliser so the two agree), and bounds the length, returning "" for a non-string / empty / all-control
// value. It is the single normaliser both the parse (off the wire) and the validation use, so a stored or
// audited reference is always the same clean shape.
//
// IT TRUNCATES, AND FOR THE NUMBER THAT IS NOT ENOUGH ON ITS OWN. A justification is prose: losing its tail
// costs detail, and the cut is visible to whoever later reads the record. A change number is a REFERENCE to
// a record in the customer's own change-management system, and its only job is to match. A truncated one
// still looks like a change number, is stored without complaint, and matches nothing. So the number is
// refused BEFORE it reaches here, at the wire (decodeChangeHeaderWithFault below, answered by the router),
// while the justification keeps degrading gracefully.
//
// IT NOW CLEANS BEFORE IT CAPS, AND THAT ORDER IS THE POINT. It used to take the first `max` non-control
// characters and trim afterwards, so whitespace the operator never meant to send ate into the budget: a
// change number of exactly 64 characters pasted with three leading spaces was ACCEPTED as legal (its cleaned
// length is 64) and then stored as 61 characters. That is the same silent-alteration defect the refusal
// above exists to close, in a narrower case, and the refusal alone would not have caught it. Cleaning first
// makes the contract exact: whatever is accepted is stored equal to its own cleaned form. Nothing else moves,
// because for text with no leading or trailing whitespace the two orders agree.
function normaliseChangeText(v: unknown, max: number): string {
  if (typeof v !== "string") return "";
  return stripChangeControlChars(v).slice(0, max).trim();
}

// parseChangeRef safely reconstructs a ChangeRef from an untrusted decoded object (a header value, or the
// caller payload), returning null when there is nothing to carry (no emergency flag and no number and no
// reason). It NEVER throws and NEVER enforces the policy (number-required is a policy decision made at
// enforcement time by evaluateChangeControl); it only produces a clean, bounded shape or null. A
// non-object yields null (the absent reference).
export function parseChangeRef(v: unknown): ChangeRef | null {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
  const rec = v as Record<string, unknown>;
  const emergency = rec.emergency === true;
  const number = normaliseChangeText(rec.number, CHANGE_NUMBER_MAX);
  const reason = normaliseChangeText(rec.reason, CHANGE_REASON_MAX);
  // Nothing to carry: not an emergency, no number, no reason -> the absent reference (treated as "none").
  if (!emergency && number === "" && reason === "") return null;
  return { number: number === "" ? null : number, emergency, reason: reason === "" ? null : reason };
}

// decodeChangeHeader parses the console-set X-Downpipes-Change request header: base64url(JSON(ChangeRef)).
// It returns null on any malformed value (the absent reference), so a garbled header never throws and
// simply reads as "no reference supplied" (which the policy then refuses if one was required). The
// base64url + JSON decode is inlined (not shared with decodeCaller) so this module stays a dependency-free
// leaf; it is a small, faithful transport decode, not a security boundary.
export function decodeChangeHeader(header: string | null): ChangeRef | null {
  return decodeChangeHeaderWithFault(header).ref;
}

// ChangeHeaderFault is the closed classification of a change header that was SENT and produced NO reference
// Null means "nothing to report": either no header at all (the overwhelmingly common
// case, and a completely legitimate one -- the policy is off by default and most requests carry no CR), or a
// header that decoded into a usable reference.
//
// The two faults are the ones behind "the console demands a change number I already entered":
//
//   garbled    a header WAS present and did not decode at all (bad base64url, bad JSON, a proxy that mangled
//              it). The engine never saw the number, so the policy correctly refuses -- and the operator, who
//              typed one, is told to enter the number they just entered. The console is the only thing that
//              writes this header, so a garbled one is always a defect, never a legitimate state.
//   truncated  a header decoded and carried operator TEXT that NORMALISED TO NOTHING (all ASCII control
//              characters, or whitespace only). parseChangeRef then returns null, so downstream this is
//              byte-identical to "no reference was supplied" -- and the operator did supply one.
//   over-length  a header decoded and carried a change NUMBER longer than CHANGE_NUMBER_MAX. This one does
//              not become a null reference: the router REFUSES the request outright and names the bound, so
//              the operator corrects it while they are looking at the field. See the note on
//              normaliseChangeText for why the number is refused and the justification is not.
//
// All three are detectable ONLY at the edge: by the time the reference reaches the DO's policy gate it has
// already been normalised, and a normalised reference cannot say what it used to be.
export type ChangeHeaderFault = "garbled" | "truncated" | "over-length" | null;

/**
 * decodeChangeHeaderWithFault is decodeChangeHeader plus the classification of a header that produced nothing.
 * It NEVER throws. NOISE DISCIPLINE: an ABSENT header reports no fault at all, because an absent header is the
 * normal, correct state on every request made while the policy is off (which is the default).
 *
 * @param header - the raw X-Downpipes-Change value, or null when the request carried none.
 * @returns the parsed reference (null when there is none) and the closed fault class (null when there is none).
 */
export function decodeChangeHeaderWithFault(header: string | null): { ref: ChangeRef | null; fault: ChangeHeaderFault } {
  if (!header) return { ref: null, fault: null }; // no header: the legitimate, overwhelmingly common case
  let obj: unknown;
  try {
    const b64 = header.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    obj = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    return { ref: null, fault: "garbled" }; // the header was sent and the engine could not read it
  }
  // OVER-LENGTH NUMBER, checked BEFORE the parse, because the parse is what destroys the evidence: it caps
  // the number to CHANGE_NUMBER_MAX and returns a reference that is indistinguishable from one the operator
  // typed at exactly the cap. The router answers this fault with a 400 naming the bound; a reference that
  // cannot be carried faithfully is not carried at all.
  const numberField = (obj !== null && typeof obj === "object" && !Array.isArray(obj) ? (obj as Record<string, unknown>).number : undefined) as unknown;
  if (changeNumberExceedsMax(numberField)) return { ref: null, fault: "over-length" };
  const ref = parseChangeRef(obj);
  if (ref !== null) return { ref, fault: null };
  // The header decoded and yielded NO reference. Distinguish "the operator typed text that normalised away"
  // (truncated: they DID enter a change number, and it was all control characters or whitespace) from a body
  // that carried nothing at all (garbled: the console never sends one of these).
  const rec = (obj !== null && typeof obj === "object" && !Array.isArray(obj) ? obj : {}) as Record<string, unknown>;
  const sentText = (typeof rec.number === "string" && rec.number.length > 0) || (typeof rec.reason === "string" && rec.reason.length > 0);
  return { ref: null, fault: sentText ? "truncated" : "garbled" };
}

// ChangeControlVerdict is the result of validating a (possibly absent) reference against the policy. On a
// pass, `change` is the normalised reference to record (or null when the policy is OFF, the dormant
// default). On a fail, `reason` is the actionable message the console surfaces verbatim ("a change number
// is required ..." / "an emergency change requires a justification").
export type ChangeControlVerdict = { ok: true; change: ChangeRef | null } | { ok: false; reason: string };

// evaluateChangeControl is the PURE policy decision (no I/O), the single place the number-required and
// emergency-needs-justification rules live so the engine and any reader agree:
//   - policy OFF (required=false): always ok, change=null (the feature is dormant; a supplied reference is
//     ignored, so a tenant that never enabled it behaves byte-identically to before).
//   - policy ON, EMERGENCY (emergency=true): the justification (reason) is REQUIRED; the number is OPTIONAL
//     (kept when supplied, e.g. a retrospectively-raised CR). An emergency with no reason is refused.
//   - policy ON, NORMAL (emergency=false): the number is REQUIRED; an empty number is refused (the operator
//     must supply a CR or raise it as an Emergency Change). reason is dropped (not an emergency).
export function evaluateChangeControl(required: boolean, raw: ChangeRef | null | undefined): ChangeControlVerdict {
  if (!required) return { ok: true, change: null };
  const emergency = raw?.emergency === true;
  const number = normaliseChangeText(raw?.number, CHANGE_NUMBER_MAX);
  if (emergency) {
    const reason = normaliseChangeText(raw?.reason, CHANGE_REASON_MAX);
    if (reason === "") return { ok: false, reason: "an emergency change requires a justification" };
    return { ok: true, change: { number: number === "" ? null : number, emergency: true, reason } };
  }
  if (number === "") {
    return { ok: false, reason: "a change number is required for this change (or raise it as an Emergency Change)" };
  }
  return { ok: true, change: { number, emergency: false, reason: null } };
}
