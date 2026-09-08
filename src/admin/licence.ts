import { b64urlDecode } from "../crypto/bytes.ts";
import { parseVerifier } from "../crypto/keys.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import { hybridVerify } from "../crypto/sign.ts";
import type { Env } from "../env.d.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import { DEFAULT_LICENCE_SIGNER_PUBLIC } from "../licence-pins.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import { doURL } from "../do-url.ts";

// The licence check: a customer carries an out-of-band vendor-signed grant (a LICENCE_TOKEN) and the
// engine decides which ASSURANCE features are active (audit assistance, compliance evidence, priority
// support). It is FAIL-OPEN by design: a missing, malformed, unverifiable or expired licence degrades
// to tier 'community' and is never an error or a block. Per CONTROL-PLANE.md the licence can NEVER gate
// anything on the data or recovery path: backups run regardless, and restore/drill are gated only by the
// in-account OPERATIONAL key, never by the licence.
//
// ACTIVATION (no customer CLI): a customer activates their token FROM THE CONSOLE (POST /admin/licence;
// the router verifies it live against the pinned signer and the scheduler DO stores it). The DO-stored
// token WINS over the deploy-time env.LICENCE_TOKEN, exactly as the console-set destination and discovery
// token win over their env fallbacks. A renewal is a re-paste of the new token; a clear removes it.
//
// The verifier is ALWAYS the pinned env key (LICENCE_SIGNER_PUBLIC), NEVER a key asserted by the token
// and NEVER customer-settable. The token has no header/kid/alg field by design, exactly like updates.ts
// verifying against env.UPDATE_SIGNER_PUBLIC and openRun verifying against the operator-pinned signer
// rather than the artefact's self-asserted key.

// TIER_VALUES is the single source of truth for the closed set of tiers a licence can carry:
// LicenceTier (the compile-time type) and KNOWN_TIERS (the runtime membership check isTier uses) both
// DERIVE from this one array, so a future tier added here updates both automatically -- there is no
// second list to remember to keep in step. community is the fail-open default (never minted; a
// customer with no token, or an unverifiable one, simply IS community). business-1/-3/-10/-25 are the
// estate-banded self-serve tiers (see docs/CONTROL-PLANE.md); the band and any per-tier service grant ride
// as feature strings (estates:<n>, procurement-pack, plus the per-tier service strings), never as a new
// schema field -- LicenceClaims below is unchanged. msp is per-client-estate (metadata rides the same way,
// open-set feature strings). enterprise keeps its own pre-existing 7 features, unchanged. Pricing restart
// : starter, growth and the old flat business tier are
// DELETED, not aliased -- zero customers, zero minted tokens, no legacy compat.
const TIER_VALUES = ["community", "business-1", "business-3", "business-10", "business-25", "msp", "enterprise"] as const;
export type LicenceTier = (typeof TIER_VALUES)[number];

// KNOWN_TIERS is the runtime membership set isTier checks an arbitrary decoded string against, derived
// from TIER_VALUES above (never a second hand-typed list). A tier outside this set is a FUTURE tier
// this engine does not yet understand (see the future-tier reasonCode below), never a new grant.
const KNOWN_TIERS: ReadonlySet<string> = new Set(TIER_VALUES);

// LicenceSource records WHERE the active token came from, so the console can show activation provenance
// and choose the right affordance (Activate when none, Replace/Remove when console-activated). It is
// omitted entirely when there is no token at all (the plain Community default).
export type LicenceSource = "console" | "deploy";

// LicenceReasonCode is the CLOSED machine sub-classification of a non-valid licence outcome, projected
// ALONGSIDE the human `reason` (kept byte-identical for the console/existing callers). It splits the coarse
// "licence malformed" into its distinct causes so the support pack can tell a tamper from a stale client
// from a not-yet-supported tier: no-token/no-pin/pin-invalid are the pre-verify gates; segments/decode/
// signature/body-malformed/not-canonical are the token faults; unparseable-expiry vs expired distinguish a
// bad notAfter from a lapsed one; future-tier is a well-formed, correctly-signed body carrying a tier this
// engine does not yet understand (fail closed, but distinctly attributable = "engine too old for this
// licence"). A closed enum only; it never carries a value.
export type LicenceReasonCode =
  | "no-token"
  | "no-pin"
  | "pin-invalid"
  | "segments"
  | "decode"
  | "signature"
  | "body-malformed"
  | "not-canonical"
  | "unparseable-expiry"
  | "future-tier"
  | "expired"
  // G081: the BACKSTOP catches. Every unexpected throw inside the licence path used to fail open to
  // community with reasonCode "body-malformed" -- the code for a CORRUPT TOKEN. So an ENGINE regression
  // (a crypto import that started throwing, a DO read that returned a shape the parser chokes on) made
  // every VALID licence in the fleet read as a corrupt token, and support chased token corruption for days
  // while the customer re-pasted a token that was never the problem. internal-error says plainly "this is
  // OUR fault, not your token": it is never returned for any token defect, only from a catch.
  | "internal-error";

export interface LicenceStatus {
  tier: LicenceTier;
  valid: boolean;
  notAfter?: string;
  reason?: string;
  // reasonCode is the closed sub-classification of `reason` (see LicenceReasonCode). Additive/optional; it
  // is present on every non-valid outcome and absent on the valid path. Redaction-safe (a closed enum).
  reasonCode?: LicenceReasonCode;
  features?: string[];
  // Activation provenance (all additive/optional; redaction-safe, never the token bytes or claims
  // account). source is set whenever a token was present (valid or not); setAt/setBy are carried only
  // for a console-activated token (who pinned it and when), from the DO record.
  source?: LicenceSource;
  setAt?: number;
  setBy?: string | null;
  // envTokenPresent is set by readLicence (the route-facing, DO-resolving entry) ONLY: whether a deploy-time
  // env LICENCE_TOKEN is ALSO configured. Combined with source==="console" it reveals a STALE console token
  // masking a newer env token (the operator re-pasted the token in env but the DO-stored one still wins).
  // Presence-only boolean; never the token bytes.
  envTokenPresent?: boolean;
  // doReadFellBack is set by readLicence when the DO licence read THREW and the resolution silently fell back
  // to the env token: an intermittent DO hiccup can otherwise flip the effective source console->deploy with
  // no trace. A boolean flag only; honestly absent on the normal (DO read succeeded, or no scheduler) path.
  doReadFellBack?: boolean;
  // accountClaimMatchesEngine reports whether the engine's OWN Cloudflare account (env.CF_ACCOUNT_ID) is
  // one this licence is bound to: true when it is, false when it is not. LICENCE-BINDING-ON-CLAIM
  // computes this from `claims.boundAccounts` (membership) when that list is present and
  // non-empty; a token minted before this field existed (or an operator-mint that still predates it)
  // falls back to the ORIGINAL v1 check, `claims.account === engineAccountTag`. Computed ONLY when the
  // engine's own account tag is known and the claim verified; the claim's account/boundAccounts VALUES
  // are NEVER surfaced (no-custody): only this boolean verdict, so a licence bound to a different
  // account is visible without leaking any id. v1 echoes (does not enforce) the account claim, so this
  // is a diagnostic signal, not a block.
  accountClaimMatchesEngine?: boolean;
}

// LicenceClaims is the signed-over body: an opaque billing-account id (echoed, not enforced in v1: for a
// self-serve tier this is the Stripe customer id, never a Cloudflare account), the granted tier, an
// RFC-3339 UTC-millis expiry, and the enabled feature list.
interface LicenceClaims {
  account: string;
  tier: LicenceTier;
  notAfter: string;
  features: string[];
  // boundAccounts (LICENCE-BINDING-ON-CLAIM,, optional/additive): the Cloudflare account
  // id(s) this licence is bound to, populated by the control plane at claim time for a self-serve tier
  // (control-plane's licence/claim.ts bindClaimAccount) or at mint time for an operator mint (always
  // `[account]`, licence/admin.ts). Absent, or an empty array, means "not yet bound to any account" (a
  // self-serve token between checkout and first claim), see checkExpiry, which then falls back to the
  // legacy single-account comparison rather than treating an empty list as "matches everything" or
  // "matches nothing".
  boundAccounts?: string[];
}

// community returns the fail-open status for an abnormal path. Every non-valid outcome flows through
// here so the closed reason set is the only thing that ever leaves the engine; the underlying detail
// stays in the logs. source is carried through when a token was actually present (so the console can say
// "your activated token expired"); it is omitted for the no-token-at-all path.
function community(reason: string, reasonCode: LicenceReasonCode, notAfter?: string, source?: LicenceSource): LicenceStatus {
  return { tier: "community", valid: false, reason, reasonCode, ...(notAfter ? { notAfter } : {}), ...(source ? { source } : {}) };
}

// isTier is exported for the band-manifest emitter and its verifiers (support.ts buildBandManifest,
// the vendor opener, the corpus harness): the manifest carries a tier ONLY when it is a member of
// this closed vocabulary, and every checker derives from this one predicate, never a second list.
export function isTier(v: unknown): v is LicenceTier {
  return typeof v === "string" && KNOWN_TIERS.has(v);
}

// validClaims narrowly checks the decoded body shape before any value is trusted, so a well-signed but
// malformed token still fails closed to 'community'.
function validClaims(v: unknown): v is LicenceClaims {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  if (typeof c.account !== "string") return false;
  if (!isTier(c.tier)) return false;
  if (typeof c.notAfter !== "string") return false;
  if (!Array.isArray(c.features) || !c.features.every((f) => typeof f === "string")) return false;
  // boundAccounts is OPTIONAL (a token minted before LICENCE-BINDING-ON-CLAIM,, carries no
  // such key at all): absent is valid. When present it must be a string array, same shape discipline as
  // `features`; a present-but-malformed value fails the whole body closed (body-malformed), never a
  // silently-ignored field.
  if (c.boundAccounts !== undefined && (!Array.isArray(c.boundAccounts) || !c.boundAccounts.every((a) => typeof a === "string"))) return false;
  return true;
}

// verifyLicenceToken runs the full verification of an EXPLICIT token against an EXPLICIT pinned signer
// public and returns the effective status. It is the one verification path, shared by the env wrapper
// (verifyLicence), the DO-resolution (readLicence) and the console activation route's verify-before-store
// (POST /admin/licence). It catches its own failures so it can never throw. The signed-over bytes are
// EXACTLY b64urlDecode(body_b64url) (the canonical-JSON body bytes, not the base64url text), and both the
// Ed25519 and the ML-DSA-87 halves must verify (hybridVerify returns false unless both pass and neither
// can be stripped). source is echoed onto the result (when a token was present) for the console.
// parseVerifiedClaims verifies the token's hybrid signature under the verifier, then parses, validates and
// re-canonicalises the body. It returns the verified claims on success or a community status carrying the
// precise reason. The signed-over bytes are EXACTLY b64urlDecode(body_b64url); both signature halves must
// verify; and the body must canonicalise back to the signed-over bytes (a malleability defence).
async function parseVerifiedClaims(token: string, verifier: HybridVerifier, source?: LicenceSource): Promise<{ ok: true; claims: LicenceClaims } | { ok: false; status: LicenceStatus }> {
  // Each failure returns the SAME human "licence malformed" reason (unchanged for existing callers/tests)
  // but a DISTINCT reasonCode so the pack can tell the causes apart.
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { ok: false, status: community("licence malformed", "segments", undefined, source) };
  }

  let message: Uint8Array;
  let sig: Uint8Array;
  try {
    message = b64urlDecode(parts[0]);
    sig = b64urlDecode(parts[1]);
  } catch {
    return { ok: false, status: community("licence malformed", "decode", undefined, source) };
  }

  if (!(await hybridVerify(verifier, message, sig))) {
    return { ok: false, status: community("licence signature did not verify under the pinned vendor key", "signature", undefined, source) };
  }

  let claims: unknown;
  try {
    claims = JSON.parse(new TextDecoder().decode(message));
  } catch {
    return { ok: false, status: community("licence malformed", "body-malformed", undefined, source) };
  }
  if (!validClaims(claims)) {
    // A well-formed, correctly-signed body whose `tier` is a STRING but not a currently-known tier is a
    // FUTURE tier this engine does not yet understand: still fail closed (never grant an unknown tier), but
    // classify it distinctly from a shape-malformed body so the pack can read "engine too old for this
    // licence" rather than "the token is corrupt". The tier VALUE is never surfaced (only the reasonCode).
    const t = typeof claims === "object" && claims !== null ? (claims as Record<string, unknown>).tier : undefined;
    const futureTier = typeof t === "string" && !isTier(t);
    return { ok: false, status: community("licence malformed", futureTier ? "future-tier" : "body-malformed", undefined, source) };
  }

  // The signed body must canonicalise back to the exact signed-over bytes; otherwise the body was
  // re-serialised in a non-canonical form (a malleability attempt) and is treated as malformed even
  // though the raw signature checked.
  let recanon: Uint8Array;
  try {
    recanon = canonicalJSON(claims);
  } catch {
    return { ok: false, status: community("licence malformed", "not-canonical", undefined, source) };
  }
  if (recanon.length !== message.length || !recanon.every((b, i) => b === message[i])) {
    return { ok: false, status: community("licence malformed", "not-canonical", undefined, source) };
  }
  return { ok: true, claims };
}

// checkExpiry resolves the verified claims to the effective status. A signed but unparseable notAfter is
// malformed (fail closed, not a perpetual grant). An expired licence still echoes its notAfter (so the
// operator sees when it lapsed) but resolves to community.
function checkExpiry(claims: LicenceClaims, source?: LicenceSource, engineAccountTag?: string): LicenceStatus {
  const expiry = Date.parse(claims.notAfter);
  if (!Number.isFinite(expiry)) {
    // (NaN comparisons are always false, which would otherwise never expire.) Distinct reasonCode: an
    // unparseable expiry is a different fault from a shape-malformed body, though both fail closed.
    return community("licence malformed", "unparseable-expiry", undefined, source);
  }
  if (expiry <= Date.now()) {
    return community("licence expired", "expired", claims.notAfter, source);
  }
  // Compare the signed account claim against the engine's own account tag WITHOUT surfacing the claim: a
  // boolean verdict only, present only when the engine tag is known. A false means the engine's account
  // is not one this licence is bound to (v1 echoes, does not enforce, so this is a diagnostic signal,
  // never a block).
  //
  // LICENCE-BINDING-ON-CLAIM: a NON-EMPTY boundAccounts list is the authoritative check
  // (membership, since a self-serve licence can bind up to its band's estate count, not just one
  // account); an ABSENT or EMPTY list falls back to the original v1 single-account comparison, so a
  // token minted before this field existed (or an Enterprise/operator-mint token, which always carries
  // an explicit `[account]` list and so never falls back at all) verifies exactly as it always has.
  const hasBoundAccounts = Array.isArray(claims.boundAccounts) && claims.boundAccounts.length > 0;
  const accountClaimMatchesEngine =
    typeof engineAccountTag === "string" && engineAccountTag !== ""
      ? hasBoundAccounts
        ? (claims.boundAccounts as string[]).includes(engineAccountTag)
        : claims.account === engineAccountTag
      : undefined;
  return {
    tier: claims.tier,
    valid: true,
    notAfter: claims.notAfter,
    features: claims.features,
    ...(source ? { source } : {}),
    ...(accountClaimMatchesEngine !== undefined ? { accountClaimMatchesEngine } : {}),
  };
}

// engineAccountTag (env.CF_ACCOUNT_ID, the operator's OWN Cloudflare account id) is threaded in so the
// account-claim-vs-engine verdict can be computed without ever surfacing the claim's account value. It is
// optional: absent leaves accountClaimMatchesEngine unset (honestly unknown), never a fabricated verdict.
export async function verifyLicenceToken(token: string | null | undefined, pinnedSignerPublic: string | undefined, source?: LicenceSource, engineAccountTag?: string): Promise<LicenceStatus> {
  try {
    if (!token) return community("no licence configured", "no-token");
    if (!pinnedSignerPublic) return community("pinned vendor key not configured", "no-pin", undefined, source);
    let verifier: HybridVerifier;
    try {
      verifier = parseVerifier(b64urlDecode(pinnedSignerPublic));
    } catch {
      return community("pinned vendor key invalid", "pin-invalid", undefined, source);
    }
    const parsed = await parseVerifiedClaims(token, verifier, source);
    if (!parsed.ok) return parsed.status; // a community status carrying the failure reason + reasonCode
    return checkExpiry(parsed.claims, source, engineAccountTag);
  } catch {
    // Any unexpected error fails open to community, never out of the handler. G081: this is an ENGINE fault,
    // not a token fault, so it is classed internal-error and NEVER "body-malformed" (which would send support
    // hunting a corrupt token the customer does not have). The human `reason` is deliberately unchanged.
    return community("licence malformed", "internal-error", undefined, source);
  }
}

// effectiveSignerPin resolves the pinned vendor public key the licence signature is verified against.
// Resolution order: a NON-EMPTY env.LICENCE_SIGNER_PUBLIC override (a self-host pinning their own, or the
// demo, which sets it) WINS; otherwise the compile-time baked vendor pin DEFAULT_LICENCE_SIGNER_PUBLIC
// (src/licence-pins.ts) is used so a stock engine verifies a licence without the customer ever pinning
// it; otherwise undefined. An empty-string env value is treated as absent (whitespace trimmed) so a
// blank binding does not shadow the baked default. When BOTH are empty the result is undefined, exactly
// as before this baked-default existed, verifyLicenceToken then returns the unchanged "pinned vendor key
// not configured" community fail-open (no regression; the bake is inert until the constant is filled).
export function effectiveSignerPin(env: Env): string | undefined {
  const override = typeof env.LICENCE_SIGNER_PUBLIC === "string" ? env.LICENCE_SIGNER_PUBLIC.trim() : "";
  if (override) return override;
  const baked = DEFAULT_LICENCE_SIGNER_PUBLIC.trim();
  if (baked) return baked;
  return undefined;
}

// verifyLicence is the DEPLOY-TIME (env-only) entry, kept for callers without a scheduler stub. It reads
// the token from env and the pinned key from effectiveSignerPin (env override, else the baked vendor
// pin) and tags the source as 'deploy'.
export async function verifyLicence(env: Env): Promise<LicenceStatus> {
  return verifyLicenceToken(env.LICENCE_TOKEN, effectiveSignerPin(env), "deploy", env.CF_ACCOUNT_ID);
}

// The DO record shape for the console-activated token (internal-only; GET /licence-token returns it).
interface LicenceTokenRecord {
  token?: string | null;
  setAt?: number;
  setBy?: string | null;
}

// readLicence is the route-facing entry: a final try/catch backstop so a licence problem can NEVER throw
// out of GET /admin/licence (fail-open is absolute). With a scheduler stub it resolves the DO-stored
// (console-activated) token FIRST and, when present, that token is authoritative, it is verified and its
// status returned even if it no longer verifies (expired, key unpinned), exactly as the console-set
// destination wins over the env destination. Only when no console token is stored does it fall back to
// the deploy-time env token. A DO read hiccup degrades to the env path (still fail-open). The handler
// returns HTTP 200 with this status on every path, including expiry, tamper and absence.
export async function readLicence(env: Env, scheduler?: DurableObjectStub): Promise<LicenceStatus> {
  try {
    // Whether a deploy-time env token is ALSO configured. Combined with source==="console" this reveals a
    // stale console token masking a newer env token. Presence-only; computed once and attached below.
    //
    // This read is INSIDE the backstop, so the one statement in
    // readLicence that could throw was the one line the "fail-open is absolute" contract did not cover.
    const envTokenPresent = typeof env.LICENCE_TOKEN === "string" && env.LICENCE_TOKEN !== "";
    if (scheduler) {
      let rec: LicenceTokenRecord | null = null;
      let doReadFellBack = false;
      try {
        const resp = await scheduler.fetch(doURL("/licence-token"), { method: "GET" });
        // A RESOLVED NON-2XX bypassed this catch entirely, so the DO answering 500 during a storage
        // incident silently flipped a console-activated Enterprise licence to whatever the deploy token holds
        // (or to community) with doReadFellBack UNSET -- the pack then showed a tier drop with no cause at
        // all. A non-2xx is the same loss of the console token as a throw, and is now recorded as such.
        if (!resp.ok) throw new Error("licence-token read: non-2xx");
        rec = (await resp.json()) as LicenceTokenRecord;
      } catch {
        // A DO read failure must not break the fail-open read: fall through to the env token below, but
        // RECORD the fallback so an intermittent DO hiccup flipping the effective source is not silent.
        rec = null;
        doReadFellBack = true;
      }
      if (rec && typeof rec.token === "string" && rec.token !== "") {
        const status = await verifyLicenceToken(rec.token, effectiveSignerPin(env), "console", env.CF_ACCOUNT_ID);
        // Attach the redaction-safe activation provenance (who + when) from the DO record. Never the token.
        return {
          ...status,
          ...(typeof rec.setAt === "number" ? { setAt: rec.setAt } : {}),
          ...(rec.setBy !== undefined ? { setBy: rec.setBy } : {}),
          envTokenPresent,
        };
      }
      // No console token stored -> env fallback. Carry envTokenPresent + (when it happened) doReadFellBack so
      // a fell-back read that flipped console->deploy is attributable.
      //
      // G081: doReadFellBack is a LIVE-READ boolean -- it says the CURRENT read fell back, and the next
      // healthy read erases it. So an INTERMITTENT DO fault (the case that actually generates the ticket:
      // "our Enterprise tier keeps dropping to community for a few minutes at a time") left no trace by the
      // time anyone generated a pack. The counter is the durable rate: any non-zero licence-source-flip means
      // the effective licence source has been flipping under the customer, however healthy it looks now.
      // Best-effort and never awaited into the response (the licence read is fail-open and must stay fast).
      if (doReadFellBack) void bumpAdminCounter(scheduler, "licence-source-flip");
      return { ...(await verifyLicence(env)), envTokenPresent, ...(doReadFellBack ? { doReadFellBack } : {}) };
    }
    return { ...(await verifyLicence(env)), envTokenPresent };
  } catch {
    // G081: the route-facing backstop. An ENGINE fault, never a token fault (see the LicenceReasonCode note).
    if (scheduler) void bumpAdminCounter(scheduler, "licence-internal-error");
    return community("licence malformed", "internal-error");
  }
}
