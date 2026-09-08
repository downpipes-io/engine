// Advisory authentication-context signal (ASVS V6.8.4). The native OIDC/SAML relying party can READ the
// IdP's assertion-of-strength claims -- OIDC `acr` (authentication context class), `amr` (methods, e.g.
// ["pwd","otp","mfa"]) and `auth_time`; the SAML equivalents AuthnContextClassRef + AuthnInstant -- and
// carry them forward as an ADVISORY, STRICTLY NON-GATING signal on the sign-in record.
//
// NON-GATING is the whole point (and the reason this is a leaf with no authority): authorization must NEVER
// depend on any of these values. An IdP may omit them, or assert a value the engine cannot independently
// verify (acr/amr are self-asserted strings the IdP chooses), so treating them as a gate would either lock
// out a legitimate sign-in or trust an unverifiable claim. The engine's real strength control is step-up
// re-auth (which does not rely on a spoofable/absent claim). This signal exists only so an operator can SEE,
// on the sign-in audit event, "the IdP said this session was MFA / password / at this auth_time" -- useful
// context for a review, never an input to a decision.
//
// REDACTION / bounding: every field is bounded before it is stored so a hostile or misconfigured IdP cannot
// use a claim as an unbounded free-text or amplification channel into the (authenticated, but no-custody)
// audit surface: acr is a length-capped single string; amr is a count-capped list of length-capped strings;
// authTime is a finite non-negative epoch-seconds number or nothing. Nothing here is a secret (it names how
// someone signed in, not a credential), and it carries no email/subject.

import { type ClaimBoundary, type ClaimDropTally, claimDropCounter } from "./posture-counters.ts";

// Bounding limits. Generous enough for every real IdP value (acr URNs, the small amr vocabulary) while
// refusing an abusive payload. A value over the limit is DROPPED, never truncated-and-stored, so a partial
// value can never be mistaken for the real one.
export const ACR_MAX_LEN = 256; // an acr is a short token or URN; 256 covers every real value
export const AMR_MAX_COUNT = 16; // amr is a small set of method identifiers; cap the list length
export const AMR_ENTRY_MAX_LEN = 64; // each amr entry is a short token (pwd, otp, mfa, hwk, ...)

// AdvisoryAuthContext is the bounded, redaction-safe advisory signal. Every field is OPTIONAL: an IdP that
// asserts none of them yields `undefined` (see buildAuthContext), so the sign-in record simply omits it.
export interface AdvisoryAuthContext {
  acr?: string; // authentication context class reference (OIDC acr / SAML AuthnContextClassRef)
  amr?: string[]; // authentication methods references (OIDC amr); absent for SAML (no direct analogue)
  authTime?: number; // epoch SECONDS of the original authentication (OIDC auth_time / SAML AuthnInstant)
}

// boundAcr returns a bounded acr string, or undefined when the value is not a usable acr (not a string, empty
// after trim, or over the length cap). It is deliberately strict: an over-cap value is dropped, not truncated.
export function boundAcr(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  if (t.length === 0 || t.length > ACR_MAX_LEN) return undefined;
  return t;
}

// boundAmr returns a bounded amr list, or undefined when the value is not a usable amr. It accepts only an
// array, keeps only non-empty string entries within the per-entry length cap, and caps the LIST length. An
// entry over the cap is dropped (not truncated). An empty result (no usable entries) is undefined, not [].
export function boundAmr(v: unknown): string[] | undefined {
  return boundAmrTallied(v).amr;
}

/**
 * boundAmrTallied is boundAmr plus the fact boundAmr structurally cannot report: whether the list OVERFLOWED.
 *
 * THE AMR LIST CAP WAS AN UNTALLIED DROP, AND THE COUNTER'S OWN COMMENT CLAIMED OTHERWISE. boundAmr
 * `break`s at AMR_MAX_COUNT and returns the first 16 entries, so `amr` is DEFINED -- and buildAuthContext's
 * drop test was `amr === undefined && input.amr !== undefined`, which therefore never fired. An amr of 20
 * entries with "mfa" at index 18 was dropped and recorded NOTHING, producing the same row as a fully usable
 * amr, while claim-drop-oidc-token-amr was documented as covering an entry "over-long, OR PAST THE LIST CAP".
 * It did not cover the list cap. That is the exact groups-list-capped failure mode, unrecorded, on the exact
 * question the counter exists to answer: "prove this session was MFA'd".
 *
 * @param v - the raw amr claim.
 * @returns the bounded list (undefined when nothing was usable) and whether usable entries were dropped at the cap.
 */
export function boundAmrTallied(v: unknown): { amr: string[] | undefined; listCapped: boolean } {
  if (!Array.isArray(v)) return { amr: undefined, listCapped: false };
  const out: string[] = [];
  let listCapped = false;
  for (const e of v) {
    if (typeof e !== "string") continue;
    const t = e.trim();
    if (t.length === 0 || t.length > AMR_ENTRY_MAX_LEN) continue;
    // A USABLE entry arriving after the cap is a real loss: the entry passed every other check and is being
    // dropped only because the list is full. Counted once, whatever the overflow's size; the value never rides.
    if (out.length >= AMR_MAX_COUNT) {
      listCapped = true;
      continue;
    }
    out.push(t);
  }
  return { amr: out.length > 0 ? out : undefined, listCapped };
}

// boundAuthTime returns a finite, non-negative epoch-SECONDS number, or undefined. It accepts a JSON number
// (OIDC auth_time is a NumericDate in seconds) and rejects NaN/Infinity/negative/non-number. A caller that
// has epoch MILLISECONDS (e.g. SAML AuthnInstant parsed to ms) must convert to seconds before calling.
export function boundAuthTime(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0) return undefined;
  return Math.floor(v);
}

// buildAuthContext assembles an AdvisoryAuthContext from already-bounded-or-raw inputs, bounding each field
// and returning undefined when NONE of them is usable (so the caller can omit the whole optional field with
// an exactOptionalPropertyTypes-safe spread). This is the single constructor both the OIDC and SAML paths use.
//
// `drops` is the bounded out-parameter naming the advisory claims that were ASSERTED and DROPPED. The
// distinction that matters is PRESENT-BUT-UNUSABLE versus ABSENT: an IdP that asserts nothing is the ordinary
// state of a basic connection and is NOT recorded (recording it would be pure noise on every sign-in). An acr
// over the length cap, an amr whose entries are all unusable or whose list overflowed, or an auth_time that is
// not a usable NumericDate IS recorded: "prove this session was MFA'd" then has an honest answer ("the IdP
// asserted an amr we could not use") instead of silence. The VALUE never rides, only the closed kind.
// `boundary` says WHICH front door this context came through, and it must be passed rather than assumed: this
// constructor is shared by the OIDC and SAML paths. The SAML caller passes "saml"; the OIDC caller passes "oidc-token".
export function buildAuthContext(input: { acr?: unknown; amr?: unknown; authTime?: unknown }, drops?: ClaimDropTally, boundary: ClaimBoundary = "oidc-token"): AdvisoryAuthContext | undefined {
  const acr = boundAcr(input.acr);
  const { amr, listCapped } = boundAmrTallied(input.amr);
  const authTime = boundAuthTime(input.authTime);
  if (drops !== undefined) {
    if (acr === undefined && input.acr !== undefined && input.acr !== null) drops.add(claimDropCounter(boundary, "acr"));
    // The amr is dropped when NOTHING was usable, and ALSO when usable entries were lost at the list cap: the
    // second case leaves a defined amr, so testing `amr === undefined` alone missed it entirely (see
    // boundAmrTallied). SAML has no amr analogue, so this can only fire on the OIDC boundary.
    if (((amr === undefined && input.amr !== undefined && input.amr !== null) || listCapped) && boundary !== "saml") drops.add(claimDropCounter(boundary, "amr"));
    if (authTime === undefined && input.authTime !== undefined && input.authTime !== null) drops.add(claimDropCounter(boundary, "auth-time"));
  }
  if (acr === undefined && amr === undefined && authTime === undefined) return undefined;
  return {
    ...(acr !== undefined ? { acr } : {}),
    ...(amr !== undefined ? { amr } : {}),
    ...(authTime !== undefined ? { authTime } : {}),
  };
}

// extractOidcAuthContext reads the advisory signal from a VERIFIED OIDC id_token's claims (the full signed
// payload oidc-verify.ts returns on success). It reads acr/amr/auth_time ONLY; it never reads or trusts any
// claim for authorization. Returns undefined when the IdP asserted none of them (the common case for a basic
// IdP), which the caller omits from the principal.
export function extractOidcAuthContext(claims: Record<string, unknown>, drops?: ClaimDropTally): AdvisoryAuthContext | undefined {
  return buildAuthContext({ acr: claims.acr, amr: claims.amr, authTime: claims.auth_time }, drops);
}
