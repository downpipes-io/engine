// The shared error type + opaque error id for the WebAuthn / passkey core, split out of passkey.ts so each
// module stays a coherent unit under 500 lines. This is the leaf the CBOR/COSE parser (passkey-cose.ts), the
// authenticator-data parser (passkey-authdata.ts) and the ceremony core (passkey.ts) all depend on, so it
// imports nothing from the rest of the passkey core (no import cycle). Behaviour is byte-identical to the
// original passkey.ts: this code was MOVED verbatim, not changed.
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no Node built-ins, no enums,
// explicit field declarations.

// ---- Opaque error id (matches the engine's errId pattern, restore.ts) --------------------------
// errId produces a short, stable, opaque identifier for an exception so console.error carries a
// correlatable code rather than raw internal text. 8-hex-digit FNV-1a 32-bit over "ClassName:message",
// deterministic across restarts and revealing nothing about the exception body. This is the SAME
// construction as src/admin/restore.ts so the operational log format is uniform across the engine.
export function errId(e: unknown): string {
  const name = e instanceof Error ? e.constructor.name : "unknown";
  const msg = e instanceof Error ? e.message : String(e);
  let h = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(`${name}:${msg}`)) {
    h = Math.imul(h ^ byte, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

// PasskeyError is the typed rejection every parse/verify step throws. The message is the PRECISE
// internal reason (logged to console.error with an opaque id by the DO/router, never returned to the
// client); the `reason` is the COARSE client-facing category the caller maps into the response body, so
// a client learns "registration could not be verified" without learning which byte was malformed.
export type PasskeyReason =
  | "bad_request" // a malformed or missing client field (a 400-shaped fault)
  | "challenge" // challenge missing, expired, or did not match
  | "origin" // clientDataJSON origin did not match CONSOLE_ORIGIN
  | "rpid" // authenticatorData rpIdHash did not match SHA-256(rp.id)
  | "user_present" // the user-present flag was not set
  | "user_verified" // the user-verified (UV) flag was not set (the admin front door requires it)
  | "signature" // the assertion signature did not verify
  | "clone" // signCount went backwards or did not advance (possible cloned authenticator)
  | "unknown_credential" // the asserted credential id is not registered
  | "already_registered"; // (registration) the credential id is already registered

export class PasskeyError extends Error {
  reason: PasskeyReason;
  constructor(reason: PasskeyReason, detail: string) {
    super(detail);
    this.name = "PasskeyError";
    this.reason = reason;
  }
}

// StoredKeyCorruptError is a PasskeyError whose WIRE REASON is `bad_request` -- byte-identical to what the
// caller has always been told -- and which additionally says, INSIDE the engine, that the fault was OURS: the
// stored credential's COSE public key no longer decodes. That distinction is the single most misdiagnosed
// passkey ticket ("my browser stopped working"), and the recentErrors ring could not carry it, because the ring
// classes an errorId from the thrown reason and the reason is, correctly, the coarse client-facing one.
//
// The reason is NOT changed to a new member: a PasskeyReason IS the wire contract (coarsePasskeyError maps it
// straight into the response), and inventing a reason to carry a diagnosis would oracle the engine's internal
// state back to an unauthenticated caller. A SUBCLASS carries the fact where only the engine can read it: every
// `instanceof PasskeyError` test, every response and every existing message stays exactly as it was.
export class StoredKeyCorruptError extends PasskeyError {
  constructor(detail: string) {
    super("bad_request", detail);
    this.name = "StoredKeyCorruptError";
  }
}

// ---- Support-pack signal mapping -------------------------------------------------
// WHY: after a custom-domain or CONSOLE_ORIGIN change, EVERY passkey enrolment / sign-in / step-up fails, and
// until now every one of those failures funnelled into an errId'd console.error in Workers Logs - which remote
// support structurally cannot read (the no-custody floor). So a total lockout and a quiet weekend looked
// IDENTICAL in the pack. passkeySignalName maps a ceremony outcome to a CLOSED auth-signal name so the failure
// CLASS (not the user, credential or origin) is counted in the bounded aggregate the pack already carries.
//
// REDACTION / ANTI-ORACLE, both directions:
//  - The `reason` handed in comes off the DO's ceremony response. It is ALLOWLISTED against the closed
//    PasskeyReason set below: a value that is not a member can never become a signal name (it falls to the
//    residual per-ceremony bucket). So even if a future DO returned free text, no free text, email, credential
//    id or origin value could ever be interpolated into a stored key.
//  - The CLIENT-facing response is untouched: these names are recorded pack-side only, so a caller still cannot
//    tell "wrong challenge" from "unknown credential" (the anti-enumeration property of the coarse response).
const PASSKEY_REASON_SIGNAL: Record<PasskeyReason, string> = {
  bad_request: "passkey-bad-request",
  challenge: "passkey-challenge-failed", // the CHALLENGE_TTL ceiling, or a challenge evicted under a begin flood
  origin: "passkey-origin-mismatch", // the classic CONSOLE_ORIGIN / custom-domain-change lockout
  rpid: "passkey-rpid-mismatch", // PASSKEY_RP_ID no longer a registrable suffix of the console origin
  user_present: "passkey-up-unmet",
  user_verified: "passkey-uv-unmet", // a UV-incapable authenticator against a front door that requires UV
  signature: "passkey-signature-failed",
  clone: "passkey-clone-detected", // signCount went backwards: a possible cloned authenticator (a posture signal)
  unknown_credential: "passkey-unknown-credential", // an unregistered credential id was asserted (probing, or a wiped store)
  already_registered: "passkey-already-registered",
};

// PASSKEY_CEREMONIES is the closed set of ceremonies whose failures we count, and supplies the residual bucket
// name for a rejection whose reason is not a PasskeyReason member (a forbidden register, a spent invite, an
// internal DO fault). Keyed so the caller cannot pass an arbitrary ceremony string into a storage key either.
const PASSKEY_CEREMONY_RESIDUAL = {
  login: "passkey-login-rejected",
  register: "passkey-register-rejected",
  stepup: "stepup-failed",
} as const;
export type PasskeyCeremony = keyof typeof PASSKEY_CEREMONY_RESIDUAL;

export function passkeySignalName(ceremony: PasskeyCeremony, reason: unknown): string {
  // A step-up failure is diagnosed as ONE class (the console "keeps refusing my sensitive action" ticket): the
  // finer WebAuthn reason is already counted by the login ceremony that shares the same verify path.
  if (ceremony === "stepup") return PASSKEY_CEREMONY_RESIDUAL.stepup;
  if (typeof reason === "string" && Object.hasOwn(PASSKEY_REASON_SIGNAL, reason)) {
    return PASSKEY_REASON_SIGNAL[reason as PasskeyReason];
  }
  return PASSKEY_CEREMONY_RESIDUAL[ceremony];
}
