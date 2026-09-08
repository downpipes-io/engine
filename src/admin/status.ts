import type { Env } from "../env.d.ts";
import { type DestProvider, providerForEndpoint } from "../dest/provider.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { AUDIT_CAP, AUDIT_NEAR_CAP_FRACTION } from "./audit.ts";
import { envFlagEnabled } from "./auth.ts";
import { effectiveSignerPin } from "./licence.ts";
import { inviteSenderConfigured } from "./router-sources.ts";

// The onboarding readiness probe. It reports the PRESENCE of configuration as booleans so
// the in-account console can poll, during onboarding, whether the operator has finished
// wiring the engine out of band (the console cannot itself write the engine's secrets; that
// is the no-custody contract, so it observes presence and unlocks the next step).
//
// PRESENCE is not VALIDITY, and the distinction is deliberate. A field is "configured" when
// the env var is set or the binding is bound, never when its value parses or verifies. So a
// malformed SIGNER_PRIVATE still reads signerConfigured:true here, and the dedicated route
// (GET /admin/licence for the licence verdict, GET /admin/updates for the signed channel)
// reports why a configured thing does not actually work. Keeping this a pure truthiness check
// has two payoffs: it cannot leak a parse-derived detail of a secret, and it is cheap enough
// to poll. This route therefore never calls readLicence/checkUpdates/loadSigner/parseVerifier.
//
// What it NEVER returns: any secret bytes or fingerprint (signer/break-glass/operational
// halves), any destination endpoint/bucket/region/credential, the update channel URL or its
// pinned signer, the licence token or its pinned signer, the licence tier or validity, or any
// downpipe name/id. Only the booleans, the selected destination KIND enum, the engine
// version, and the integer downpipe count cross the wire. The provenance descriptors below
// (artefactSha384, releaseSignerPin) are PUBLIC build identifiers, not secrets: a public artefact
// digest and a release-signer pin, never a private key half.

export interface StatusReport {
  service: string;
  engineVersion: string;
  signerConfigured: boolean;
  breakGlassConfigured: boolean;
  // inviteSenderConfigured (G340): can this engine EMAIL a new member their set-up link at all? "The new
  // members never received a set-up link" has two completely different answers, and the pack could not tell
  // them apart: a deployment that deliberately configures no invite sender (the Owner hands the link over by
  // hand, which is a legitimate posture) and one whose sender is MISCONFIGURED (the send is attempted and
  // refused). This boolean is the first half of telling them apart; the role-grant-invite-undeliverable counter
  // and the invite-email auth signals are the second. Presence only: the sender address never rides.
  inviteSenderConfigured: boolean;
  operationalConfigured: { public: boolean; private: boolean };
  destConfigured: boolean;
  destKind: DestProvider | null;
  // statusSource (gap-B6) tells a bundle consumer whether this report's DESTINATION facts reflect the LIVE
  // console-set destination (a successful DO /dest-status read: "live") or fell back to the ENV mirror alone
  // ("env-fallback") because the caller did not, or could not, read the DO. It is derived PURELY from whether
  // the caller supplied the DO-read consoleDestSet (present => "live"; absent => "env-fallback"), so it never
  // 500s and carries no secret. The support bundle reads the DO dest-status and passes consoleDestSet, so a
  // silent DO blip (the bundle degrading to env-only dest resolution) is VISIBLE as "env-fallback" rather
  // than being indistinguishable from a genuinely env-configured engine (the diagnosis bot's
  // status-preflight-conflict signal reasons over exactly this: an "env-fallback" status beside a preflight
  // that reached the DO is the tell of a degraded read, not a real config).
  statusSource: "live" | "env-fallback";
  // destResolved is destKind with the not-resolved case named explicitly ("unknown" for null), so a consumer
  // (the same status-preflight-conflict signal) can branch on the resolved archive kind without special-
  // casing null. r2 / s3 / unknown only, never an endpoint / bucket / region / credential.
  destResolved: DestProvider | "unknown";
  // G277: destAmbiguous names the ONE unconfigured-looking state that is not unconfigured at all. The customer
  // set BOTH an R2 binding AND S3 credentials without a DEST_KIND to choose between them; dest/factory.ts
  // REFUSES the ambiguity (correctly -- silently picking one would split the archive), and status coarsened the
  // refusal into destKind:null / destConfigured:false. So the console and the pack both say "destination not
  // configured", and support tells the customer to add the credentials they have already added -- twice over.
  // The remedy is one line ("set DEST_KIND"), and it was unreachable because the pack could not distinguish
  // "nothing is configured" from "TWO things are configured and I will not guess". A boolean, never a value.
  destAmbiguous: boolean;
  updateChannelConfigured: boolean;
  licenceConfigured: boolean;
  // signerPinConfigured reflects whether the engine has a pinned vendor licence-signer key to verify a
  // LICENCE_TOKEN against, presence-only like the rest of this report (never the key bytes). It is true
  // when effectiveSignerPin resolves a value (a non-empty env.LICENCE_SIGNER_PUBLIC override, or the
  // compile-time baked DEFAULT_LICENCE_SIGNER_PUBLIC); false when neither is set. A stock build ships
  // with the baked pin empty, so this reads false until the vendor bakes the key at release or a
  // self-host sets the env override. It is NOT a validity check: the value is not parsed or verified here.
  signerPinConfigured: boolean;
  // licenceSignerWarning is set ONLY when a LICENCE_TOKEN is present but no signer pin is configured,
  // the silent-downgrade case: the engine cannot verify the token and runs as community with no operator
  // signal. It carries an operator-facing explanation and the two ways to pin the key. It is honestly
  // OMITTED on every other path (no token, or a pin is configured), never a fabricated empty string. The
  // licence is fail-open by design, so this is a reporting signal, not a block, and the data and recovery
  // paths are never gated.
  licenceSignerWarning?: string;
  downpipeCount: number;
  // sourcesDetachedCount is how many configured source bindings are currently NOT present on the engine
  // (a deploy dropped them, or the resource was removed), so their downpipes' next runs fail. Presence-
  // safe like the rest of this report: a COUNT only, never a binding name or downpipe id. Optional /
  // DO-derived (the GET /admin/status handler computes it from the live env bindings vs the roster), so
  // it is honestly absent when the caller does not supply it (a plain env-only status read), never a
  // fabricated 0. The console reads it to surface a proactive "N sources need re-attaching" banner rather
  // than waiting for the next run to fail. Zero is a meaningful value (all attached) and IS reported when
  // the handler supplies it.
  sourcesDetachedCount?: number;
  ready: boolean;
  // tokenFallbackDisabled (P9) reflects ADMIN_TOKEN_DISABLED: true when the shared-token fallback is
  // hardened away and only Cloudflare Access is accepted, so the console can show the hardened
  // posture. It is env-derived (presence-only, like the rest of this report), never a secret.
  tokenFallbackDisabled: boolean;
  // adminTokenConfigured reflects the PRESENCE of the ADMIN_TOKEN env var (presence-only, never the value),
  // so the console can tell whether a break-glass token is set at all (needed to render the dispose-bootstrap-
  // token finding + the retire control). Like the rest of this report it is a pure truthiness check; an
  // empty/absent var reads false.
  adminTokenConfigured: boolean;
  // demoMode reflects the DEMO_MODE env flag (presence-only): true ONLY on a throwaway demo engine, where
  // the console may show the "Reset demo to fresh" affordance. A production engine never sets it, so this
  // reads false there AND the reset route does not exist (it 404s). Never a secret.
  demoMode: boolean;
  // bootstrapConsumed (break-glass disposal) is true once the FIRST Owner has been claimed, so the console
  // can decide whether disposing of the break-glass token is now SAFE (the bootstrap is complete) and render
  // the dispose-bootstrap-token prompt. It lives in the scheduler DO (not env), so it is OPTIONAL: present
  // only when the caller supplies it (exactOptionalPropertyTypes: honestly absent, never a fabricated false).
  // It carries no secret (a single boolean latch).
  bootstrapConsumed?: boolean;
  // breakGlassTokenRetired (break-glass disposal) is true once the Owner has retired the ADMIN_TOKEN bearer
  // in-app, so the console can show the token as already disposed and the finding as cleared. Like
  // bootstrapConsumed it lives in the DO, so it is OPTIONAL (honestly absent when the caller does not supply
  // it, never a fabricated false). No secret (a single boolean latch).
  breakGlassTokenRetired?: boolean;
  // recoveryCodesRemaining (recovery-code break-glass) is the count of UNCONSUMED recovery codes for the
  // CALLER'S OWN email, so the console can show "N recovery codes left" and prompt a regenerate when low. It
  // is per the verified caller (the DO scopes it to the caller's email; another user's count is never
  // exposed), and it lives in the DO (the per-email record), so it is OPTIONAL: present only when the caller
  // supplies it (the GET /admin/status DO round-trip for an email-bearing caller), honestly absent for the
  // bare-token break-glass (which has no per-email codes). It is a count, never a code or a hash.
  recoveryCodesRemaining?: number;
  // auditNearCap (P4 / DEF-03 / C8-02) is true when the retained audit-log count is at or above
  // AUDIT_NEAR_CAP_FRACTION of AUDIT_CAP, so the console can prompt an export before the rollover
  // begins. It depends on DO state (the audit count), which buildStatus does not itself hold, so it
  // is OPTIONAL: present only when the caller supplies the count (exactOptionalPropertyTypes:
  // honestly absent, never a fabricated false). The count itself never crosses the wire here; only
  // the boolean warning does.
  auditNearCap?: boolean;
  // auditRolledOverCount is how many audit entries the retention rollover has ALREADY destroyed, and it is
  // here because auditNearCap ALONE CANNOT SAY. The retained count is pinned at exactly AUDIT_CAP from the
  // first rollover onwards, so the boolean reads true both at the moment nothing has been lost and for ever
  // afterwards: on the screen, an operator who can still export everything and one who lost a year of
  // entries months ago were shown the same warning and the same sentence. Zero on an estate that has never
  // rolled, which is every estate until the cap is crossed. Like auditNearCap it is DO-owned, so it is
  // present only when the caller supplied it and honestly absent otherwise, never a fabricated 0.
  auditRolledOverCount?: number;
  // expiryWarnings (contract section 4) is the count of tracked credential/key expiry items that are
  // approaching or already expired, so the console can badge the credentials surface during onboarding
  // and at a glance. Like auditNearCap it depends on DO state (the expiry items live in the scheduler
  // DO, not in env), so it is OPTIONAL: present only when the caller supplies the count
  // (exactOptionalPropertyTypes: honestly absent, never a fabricated 0). The items themselves never
  // cross the wire here; only the integer count does, and an item carries no secret regardless.
  expiryWarnings?: number;
  // cleanupPending (credential lifecycle) is the count of EPHEMERAL spent tokens still awaiting the
  // operator's deletion confirmation in Cloudflare; presence-safe like expiryWarnings (the items live in
  // the scheduler DO, so it is OPTIONAL, honestly absent, never a fabricated 0).
  cleanupPending?: number;
  // DEF-04 release provenance for the console's provenance card: a public artefact digest and a
  // release-signer pin, honestly OMITTED when unset (optional, never fabricated). These are
  // documentation the operator cross-checks against the published release; they are not verified here
  // and carry no key material.
  //
  // artefactSha384 (W1) is the engine's SELF-REPORTED build-stamped digest of its own deployable
  // bundle (src/format/build-id.ts, written at build by scripts/stamp-build-id.mjs), the real hash,
  // not a manual-only env echo. A manual env.ARTEFACT_SHA384 OVERRIDES it when set (a deliberate
  // out-of-band pin); when neither is present the field is honestly absent. This is what closes the
  // "artefact hash not yet reported by this engine version" gap.
  artefactSha384?: string;
  releaseSignerPin?: string;
  // cfVersionId / cfVersionTag (W1) are the deployed Cloudflare Worker version's immutable identity
  // from the version_metadata binding (env.CF_VERSION_METADATA), so the console can show exactly which
  // deployed version is running and the safe-apply self-check can confirm the live id. They are
  // presence-safe: the binding is absent in local/dry-run/test (no deployed version), so these are
  // honestly OMITTED then, never fabricated. Public build identifiers, never a secret.
  cfVersionId?: string;
  cfVersionTag?: string;
  // restorabilityProven (restorability assurance) is the count of configured downpipes that have an
  // "offline restorability last proven" record (a passed BLIND restore test or KEYLESS attestation), so
  // the console can badge, at a glance, how many downpipes have an affirmative recoverability proof. Like
  // auditNearCap/expiryWarnings it depends on DO state (the records live on each downpipe state, not in
  // env), so it is OPTIONAL: present only when the caller supplies the count (honestly absent, never a
  // fabricated 0). The per-downpipe record itself (who+when+method) is read from GET /downpipes; only the
  // integer count crosses here, and the record carries no secret regardless.
  restorabilityProven?: number;
  // cfAccountId is the engine's own
  // Cloudflare account id, so the console can send it with a self-serve licence claim (POST
  // /control-plane/licence/claim) and the control plane can bind the licence to it. This is the
  // CUSTOMER'S OWN account id, not a vendor secret and not backup data, so surfacing it here (unlike
  // everything else this route deliberately withholds, see the module header) costs nothing: the browser
  // reading this response is already inside that same Cloudflare account's console.
  //
  // TWO SOURCES, in order: env.CF_ACCOUNT_ID when an operator has set it by hand (opt-in; no deploy path
  // writes it), OTHERWISE the value GET /admin/status's caller supplies as verifiedCfAccountId below --
  // the engine's OWN proof, persisted in the scheduler DO the first time an attach or an update-apply
  // succeeds (both read /accounts/{a}/workers/scripts/{name} for this engine's own script name before
  // writing to it, so a success already proves the account). No customer deployment writes
  // CF_ACCOUNT_ID by itself (not wrangler.toml, not the deploy script), so this proof path is how a
  // self-serve customer's status ever carries an account id with a claim.
  //
  // Still HONESTLY OMITTED on a genuinely fresh engine: one that has never had CF_ACCOUNT_ID set and has
  // never completed an attach or an update-apply. That engine has not yet proven its account to anyone,
  // including itself, and buildStatus never fabricates the field to fill the gap; the console reads the
  // absence as "unknown until the first attach or update" (see console lib/billing.ts) rather than as a
  // mismatch. The licence then binds on the customer's next claim once either source has landed.
  cfAccountId?: string;
}

// buildStatus is pure: env presence in, booleans out. The destination selection MIRRORS
// dest/factory.ts EXACTLY so status agrees with what a run would actually do, but it never
// calls buildDestination because that THROWS on the ambiguous/misconfigured case and status
// must never 500. The ambiguous case (an R2 binding AND S3 credentials with no DEST_KIND) is
// the one the factory refuses, so status reports it not-ready (destConfigured:false,
// destKind:null) rather than silently picking one. destKind reports only the selected kind;
// it never echoes DEST_ENDPOINT/DEST_BUCKET/DEST_REGION or any access key.
//
// auditCount is OPTIONAL: the audit-log size lives in the scheduler DO, not in env, so a caller that
// has it (the DO's own status path, or a router that has round-tripped GET /audit) passes it here to
// light up auditNearCap; a caller that does not omits it and auditNearCap is honestly absent rather
// than a fabricated false. Keeping it a parameter (not a second env read) preserves buildStatus's
// purity and its "never calls into the DO" property.
// expiryWarnings is OPTIONAL for the same reason auditCount is: the tracked expiry items live in the
// scheduler DO, not in env, so a caller that has the count (the router after a GET /expiry/warnings
// round-trip) passes it here to light up status.expiryWarnings; a caller that does not omits it and
// the field is honestly absent rather than a fabricated 0. Keeping it a parameter preserves
// buildStatus's purity and its "never calls into the DO" property.
// restorabilityProven is OPTIONAL for the same reason auditCount/expiryWarnings are: the per-downpipe
// "last proven" records live on the scheduler DO state, not in env, so a caller that has the count (the
// router, which already holds the fetched DownpipeState[] for GET /status) passes it here to light up
// status.restorabilityProven; a caller that does not omits it and the field is honestly absent rather than
// a fabricated 0. Keeping it a parameter preserves buildStatus's purity and its "never calls into the DO".
// consoleDestSet is OPTIONAL for the same reason the DO-owned facts are: the console-set
// destination record lives in the scheduler DO, not in env, so a caller that has read its
// presence (the router after a GET /dest-status round-trip) passes it here and the destination
// facts reflect the EFFECTIVE choice (the console-set record wins over env, the same precedence
// the factory applies at run time, so status never disagrees with what a run would do). A caller
// that does not omits it and the env mirror answers alone, exactly as before.
// consoleDestHost is the console-set destination's endpoint host (from the same /dest-status
// round-trip): it lets the status distinguish an R2 bucket reached via its S3-compatible endpoint
// (<account>.r2.cloudflarestorage.com) from a genuine third-party S3, so a console-set R2 is
// labelled in-account R2 rather than "out of account" S3.
//
// The host-to-provider derivation MOVED to dest/provider.ts, which recognises Google Cloud Storage's
// S3-interop endpoint and Azure Blob Storage's as well as R2, and answers "s3" for every store it does
// not know by name. It is shared with the destination-refusal path so the label an operator READS and
// the fields the engine REFUSES cannot be derived from two patterns that drift.

// selfReportedArtefactSha384 is OPTIONAL for the same reason the DO-owned facts are: the build-stamped
// digest is read via reportedArtefactSha384() (an async dynamic import of the generated build-stamp
// module), which buildStatus must not itself await (it is pure + synchronous). The GET /admin/status
// route resolves it once and passes it here; a caller that does not (the support bundle, dest-status
// echoes) omits it and the env override / honest absence answers alone, exactly as before. A null means
// "resolved, none stamped"; undefined means "not resolved by this caller", both fall back to the env
// override, then to honest absence.
// BuildStatusOptions groups the OPTIONAL, DO-owned facts buildStatus accepts beyond (env, downpipeCount).
// Each is honestly absent when the caller does not supply it (the field below stays omitted, never a
// fabricated 0/false), preserving buildStatus's "never calls into the DO" purity: the router that has
// round-tripped the DO passes what it read, every other caller passes none and the env mirror answers
// alone. A single options object replaces the former 10-positional tail (GUARDRAILS §6 max-4-params).
export interface BuildStatusOptions {
  // Each field accepts undefined explicitly (not just optional-absent) so a caller can pass a
  // `T | undefined` local directly; buildStatus treats undefined identically to absent (the report
  // spreads the field only when it is not undefined), so an undefined value is honestly omitted.
  auditCount?: number | undefined;
  // auditRolledOverCount travels with auditCount and is meaningless without it: it is the cumulative number
  // of entries the retention rollover has already destroyed, and it is what separates a log that is about
  // to start losing entries from one that has been losing them for months.
  auditRolledOverCount?: number | undefined;
  expiryWarnings?: number | undefined;
  restorabilityProven?: number | undefined;
  bootstrapConsumed?: boolean | undefined;
  breakGlassTokenRetired?: boolean | undefined;
  recoveryCodesRemaining?: number | undefined;
  consoleDestSet?: boolean | undefined;
  consoleDestHost?: string | undefined;
  cleanupPending?: number | undefined;
  selfReportedArtefactSha384?: string | null | undefined;
  // The count of configured source bindings currently missing from the engine (computed by the GET
  // /admin/status handler from enumerateBoundSources(env) vs the roster). A count only, never a name.
  sourcesDetachedCount?: number | undefined;
  // demoFreshFirstRun (DEMO ONLY) masks the key-presence booleans (signer/break-glass/operational and
  // thus ready) to false. A demo reset wipes this engine's Durable Object and sets a fresh-first-run
  // marker, but it CANNOT delete the engine's Worker Secrets (the engine holds no standing CF token to
  // remove its own secrets), so env.SIGNER_PRIVATE / BREAK_GLASS_PUBLIC physically persist and would make
  // status report keys-present on a "fresh" engine, pinning the onboarding wizard at "keys already set".
  // The GET /admin/status handler reads the marker (only when DEMO_MODE) and passes it here so the wizard
  // sees a genuinely fresh engine; re-installing the keys (which overwrites the secrets) clears the marker
  // and presence reads honestly again. The marker exists ONLY on a demo engine, so production is untouched.
  demoFreshFirstRun?: boolean | undefined;
  // verifiedCfAccountId: the engine's own proof of its
  // Cloudflare account id, read by the GET /admin/status handler from the scheduler DO (a presence-only,
  // no-network round trip; see scheduler-do-account-config.ts's recordVerifiedEngineAccount) and passed
  // here so StatusReport.cfAccountId can report it. env.CF_ACCOUNT_ID always wins when set (see
  // StatusReport.cfAccountId's own doc comment); this is the fallback for the deployment that has never
  // had that var set but has completed at least one attach or update-apply. Honestly absent otherwise,
  // never fabricated: a DO hiccup or a genuinely fresh engine both degrade to cfAccountId staying absent.
  verifiedCfAccountId?: string | undefined;
}

// resolveDestKind MIRRORS dest/factory.ts's selection EXACTLY so status agrees with what a run would do,
// without ever calling buildDestination (which THROWS on the ambiguous case; status must never 500). The
// ambiguous case (an R2 binding AND S3 credentials with no DEST_KIND) reports not-ready rather than
// silently choosing. A console-set destination is stored S3-shaped, but an R2 bucket reached through its
// S3-compatible endpoint is reported as in-account R2 (not a foreign "out of account" S3).
/**
 * Mirrors dest/factory.ts's destination selection so status, and the posture's WORM slice, agree with
 * what a run would actually do, without ever calling buildDestination (which THROWS on the ambiguous
 * case). EXPORTED for gatherWormSlice (router-posture.ts), which has to name the store behind the
 * default destination to offer a remedy an operator of THAT store can follow: the four providers have
 * four different immutability mechanisms, and re-deriving the selection there would be the second
 * pattern that drifts from this one.
 *
 * @param env - the Worker environment carrying DEST_KIND, the DEST_* vars and the DEST_R2 binding.
 * @param consoleDestSet - whether a console-set destination record exists (it wins over every env fact).
 * @param consoleDestHost - that record's endpoint host, from which its provider is derived.
 * @returns the selected provider (null when none or ambiguous), whether one is configured at all, and
 *   whether the selection was refused as ambiguous.
 */
export function resolveDestKind(env: Env, consoleDestSet: boolean | undefined, consoleDestHost: string | undefined): { destKind: DestProvider | null; destConfigured: boolean; destAmbiguous: boolean } {
  const r2 = env.DEST_R2 !== undefined;
  const kind = env.DEST_KIND?.trim();
  const s3 = Boolean(
    env.DEST_ENDPOINT || env.DEST_BUCKET || env.DEST_REGION || env.DEST_ACCESS_KEY_ID || env.DEST_SECRET_ACCESS_KEY,
  );
  if (consoleDestSet === true) return { destKind: providerForEndpoint(consoleDestHost), destConfigured: true, destAmbiguous: false };
  if (kind === "r2") return { destKind: "r2", destConfigured: r2, destAmbiguous: false };
  // DEST_KIND stays the two-member WIRE selector (an R2 binding, or the HTTP client the factory picks
  // from the endpoint) and gains neither a "gcs" nor an "azure" member: GCS is reached with the S3
  // client, and an Azure endpoint is dispatched to the Azure client by providerForEndpoint inside the
  // factory, so a third or fourth value here would select nothing the endpoint does not already select.
  // The REPORTED kind is derived from the endpoint instead, so an env-configured GCS or Azure Blob
  // destination is labelled as itself rather than as a generic S3, exactly as a console-set one is.
  if (kind === "s3") return { destKind: providerForEndpoint(env.DEST_ENDPOINT), destConfigured: s3, destAmbiguous: false };
  // The factory rejects the ambiguous (r2 && s3) case, so status reports not-ready, not a guess.
  // G277: and it now SAYS SO. destConfigured stays false (the engine genuinely cannot pick a destination and no
  // backup can run), so every existing consumer is byte-identical; destAmbiguous carries the CAUSE, which turns
  // "configure a destination" into "set DEST_KIND".
  if (r2 && s3) return { destKind: null, destConfigured: false, destAmbiguous: true };
  if (r2) return { destKind: "r2", destConfigured: true, destAmbiguous: false };
  if (s3) return { destKind: providerForEndpoint(env.DEST_ENDPOINT), destConfigured: true, destAmbiguous: false };
  return { destKind: null, destConfigured: false, destAmbiguous: false };
}

// resolveProvenance returns the public build-provenance descriptors (honestly OMITTED when unset, never
// fabricated). The artefact digest PREFERS a manual env.ARTEFACT_SHA384 override (a deliberate out-of-band
// pin), then the engine's SELF-REPORTED build-stamped digest the caller resolved, then honest absence.
// The Cloudflare version identity comes from the version_metadata binding (absent in local/dry-run/test).
function resolveProvenance(env: Env, selfReportedArtefactSha384: string | null | undefined): { artefactSha384?: string; releaseSignerPin?: string; cfVersionId?: string; cfVersionTag?: string } {
  const envArtefact = env.ARTEFACT_SHA384?.trim();
  const stamped = typeof selfReportedArtefactSha384 === "string" ? selfReportedArtefactSha384.trim().toLowerCase() : "";
  const artefactSha384 = (envArtefact && envArtefact !== "") ? envArtefact : (stamped !== "" ? stamped : undefined);
  const releaseSignerPin = env.RELEASE_SIGNER_PIN?.trim();
  const vm = env.CF_VERSION_METADATA;
  const cfVersionId = vm && typeof vm.id === "string" && vm.id !== "" ? vm.id : undefined;
  const cfVersionTag = vm && typeof vm.tag === "string" && vm.tag !== "" ? vm.tag : undefined;
  return {
    ...(artefactSha384 ? { artefactSha384 } : {}),
    ...(releaseSignerPin ? { releaseSignerPin } : {}),
    ...(cfVersionId ? { cfVersionId } : {}),
    ...(cfVersionTag ? { cfVersionTag } : {}),
  };
}

// auditNearCapAt is the ONE place the near-cap threshold is evaluated on the router side, so buildStatus
// and withAuditCapacity below cannot drift from each other. It mirrors the DO's auditCountAndNearCap.
export function auditNearCapAt(auditCount: number): boolean {
  return auditCount >= Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION);
}

// withAuditCapacity folds the DO-owned audit capacity facts into an already-built report.
//
// WHY IT EXISTS RATHER THAN BEING ANOTHER buildStatus OPTION. The audit count lives in the scheduler DO and
// the ONLY place GET /admin/status learns it is the response to the status observation it posts, which it
// can only post AFTER the report is built (the observation carries the report's own presence booleans). So
// the count arrives strictly after buildStatus has run, and this function folds it in afterwards.
//
// A non-finite or negative count is treated as absent, so a malformed DO answer degrades to the honest
// unknown the console already handles rather than to a fabricated all-clear.
export function withAuditCapacity(report: StatusReport, auditCount: unknown, auditRolledOverCount: unknown): StatusReport {
  if (typeof auditCount !== "number" || !Number.isFinite(auditCount) || auditCount < 0) return report;
  const rolled = typeof auditRolledOverCount === "number" && Number.isFinite(auditRolledOverCount) && auditRolledOverCount > 0 ? Math.floor(auditRolledOverCount) : 0;
  return { ...report, auditNearCap: auditNearCapAt(Math.floor(auditCount)), auditRolledOverCount: rolled };
}

export function buildStatus(env: Env, downpipeCount: number, opts: BuildStatusOptions = {}): StatusReport {
  const { auditCount, auditRolledOverCount, expiryWarnings, restorabilityProven, bootstrapConsumed, breakGlassTokenRetired, recoveryCodesRemaining, consoleDestSet, consoleDestHost, cleanupPending, selfReportedArtefactSha384, demoFreshFirstRun, sourcesDetachedCount, verifiedCfAccountId } = opts;
  const { destKind, destConfigured, destAmbiguous } = resolveDestKind(env, consoleDestSet, consoleDestHost);

  // cfAccountId's two sources, in order (see the field's own doc comment): env.CF_ACCOUNT_ID when an
  // operator has set it by hand, else the engine's own DO-persisted proof (verifiedCfAccountId, from the
  // first attach or update-apply to succeed). Both trimmed and treated as absent when blank/whitespace,
  // matching effectiveSignerPin's own trim-then-check pattern for an env override.
  const envCfAccountId = typeof env.CF_ACCOUNT_ID === "string" && env.CF_ACCOUNT_ID.trim() !== "" ? env.CF_ACCOUNT_ID.trim() : undefined;
  const resolvedCfAccountId = envCfAccountId ?? (typeof verifiedCfAccountId === "string" && verifiedCfAccountId.trim() !== "" ? verifiedCfAccountId.trim() : undefined);

  // While a demo fresh-first-run marker is set, MASK the key-presence booleans (see BuildStatusOptions
  // .demoFreshFirstRun): the reset cannot delete the engine's Worker Secrets, so without this the onboarding
  // wizard would read the stale keys as present and skip the ceremony. Demo-scoped: the option is only ever
  // passed when DEMO_MODE is set, so a production status read is byte-identical to before.
  const freshFirstRun = demoFreshFirstRun === true;
  const signerConfigured = !freshFirstRun && Boolean(env.SIGNER_PRIVATE);
  // The invite path is ON only when the email binding is bound AND a dedicated invite sender is set. This is
  // the SAME condition sendRoleInvite gates on (router-sources.ts), read here as presence so the pack can
  // state the posture without a send being attempted. A malformed sender address still reads as configured
  // here (as with signerConfigured above); the send-time refusal is what names that, and the two together are
  // what separate "no invite path exists" from "the invite path is broken".
  const inviteSenderConfiguredNow = inviteSenderConfigured(env);
  const breakGlassConfigured = !freshFirstRun && Boolean(env.BREAK_GLASS_PUBLIC);
  // The pinned vendor licence-signer key the licence signature would be verified against (env override,
  // else the compile-time baked default, else undefined). Presence-only: the value is never surfaced.
  const signerPinConfigured = effectiveSignerPin(env) !== undefined;
  // A LICENCE_TOKEN present with NO pin to verify it is the silent-downgrade case: the token would degrade
  // to community with no operator signal. Surface a warning that names the cause and the fix. On every
  // other path the warning is honestly absent (no token, or a pin is configured). This is a reporting
  // signal only; the licence is fail-open and gates nothing on the data or recovery path.
  const licenceSignerWarning =
    env.LICENCE_TOKEN && !signerPinConfigured
      ? "A licence token is set but no vendor signer key is pinned, so the engine cannot verify it and runs as community. Bake DEFAULT_LICENCE_SIGNER_PUBLIC into the build at release, or set the LICENCE_SIGNER_PUBLIC env var to the vendor licence-signer public key."
      : undefined;
  // auditNearCap is included ONLY when the caller supplied a count (exactOptionalPropertyTypes: an
  // omitted count means we cannot honestly assert near-cap, so the field is absent, not false). The
  // threshold mirrors the DO's auditCountAndNearCap so status and the DO agree on the boundary.
  const auditNearCap = auditCount !== undefined ? auditNearCapAt(auditCount) : undefined;
  // The provenance descriptors (artefact digest, release-signer pin, Cloudflare version identity) are the
  // public build identifiers, honestly omitted when unset; resolveProvenance computes them and the spread
  // below keeps the absent ones out of the report (exactOptionalPropertyTypes).
  const provenance = resolveProvenance(env, selfReportedArtefactSha384);
  return {
    service: "downpipe-engine",
    engineVersion: ENGINE_VERSION,
    signerConfigured,
    breakGlassConfigured,
    inviteSenderConfigured: inviteSenderConfiguredNow,
    operationalConfigured: {
      public: !freshFirstRun && Boolean(env.OPERATIONAL_PUBLIC),
      // The operational private read-back half being present means in-account drill/restore
      // are possible; its absence is a deliberate higher-assurance posture, not a fault.
      private: !freshFirstRun && Boolean(env.OPERATIONAL_PRIVATE),
    },
    destConfigured,
    destKind,
    // gap-B6: whether the destination facts came from a LIVE DO read (the caller supplied consoleDestSet)
    // or the env mirror alone. Derived purely from the presence of the DO-read opt, so it never calls the
    // DO itself and never 500s; a caller that skipped or failed the DO dest read reads "env-fallback".
    statusSource: consoleDestSet !== undefined ? "live" : "env-fallback",
    // The resolved archive kind with the null case named "unknown" (never an endpoint/bucket/credential).
    destResolved: destKind === null ? "unknown" : destKind,
    destAmbiguous,
    // Each of these needs BOTH halves to be useful, so report the AND, still presence-only.
    updateChannelConfigured: Boolean(env.UPDATE_CHANNEL_URL && env.UPDATE_SIGNER_PUBLIC),
    licenceConfigured: Boolean(env.LICENCE_TOKEN && env.LICENCE_SIGNER_PUBLIC),
    // signerPinConfigured includes the baked vendor pin, so it reads true where licenceConfigured (which
    // only checks the env override) reads false but a baked default is present.
    signerPinConfigured,
    downpipeCount,
    // ready is the minimum to run: a signer to sign, a break-glass recipient to wrap to, and a
    // resolvable destination to write to. The licence and updates channel are not required.
    ready: signerConfigured && breakGlassConfigured && destConfigured,
    // P9: reflect the token-fallback hardening so the console can show "Access only".
    tokenFallbackDisabled: envFlagEnabled(env.ADMIN_TOKEN_DISABLED),
    // Break-glass disposal: the PRESENCE of the ADMIN_TOKEN env var (presence-only, never the value), so
    // the console can render the dispose-bootstrap-token finding + the retire control.
    adminTokenConfigured: Boolean(env.ADMIN_TOKEN),
    // demoMode: true only on a demo engine (DEMO_MODE set), so the console can show the demo reset button.
    demoMode: envFlagEnabled(env.DEMO_MODE),
    // Conditional spreads keep the optional fields ABSENT (not present-as-undefined) under
    // exactOptionalPropertyTypes when there is nothing honest to report.
    ...(licenceSignerWarning ? { licenceSignerWarning } : {}),
    ...(auditNearCap !== undefined ? { auditNearCap } : {}),
    // Only ever present alongside the boolean: a rolled-over count with no capacity reading behind it would
    // be a number the console could not place.
    ...(auditNearCap !== undefined && auditRolledOverCount !== undefined ? { auditRolledOverCount: Math.max(0, Math.floor(auditRolledOverCount)) } : {}),
    // The two DO-owned break-glass-disposal flags are present only when the caller supplied them (the DO
    // round-trip in the GET /admin/status handler), honestly absent otherwise (never a fabricated false).
    ...(bootstrapConsumed !== undefined ? { bootstrapConsumed } : {}),
    ...(breakGlassTokenRetired !== undefined ? { breakGlassTokenRetired } : {}),
    // The caller's own unconsumed recovery-code count, present only when the caller supplied it (the DO
    // round-trip in the GET /admin/status handler for an email-bearing caller), honestly absent otherwise.
    ...(recoveryCodesRemaining !== undefined ? { recoveryCodesRemaining } : {}),
    ...(expiryWarnings !== undefined ? { expiryWarnings } : {}),
    // The detached-source count, present only when the GET /admin/status handler computed it (env vs roster);
    // honestly absent on a plain env-only status read. Zero IS reported (all attached), only undefined omits.
    ...(sourcesDetachedCount !== undefined ? { sourcesDetachedCount } : {}),
    ...(cleanupPending !== undefined ? { cleanupPending } : {}),
    ...(restorabilityProven !== undefined ? { restorabilityProven } : {}),
    // cfAccountId: honestly omitted only when NEITHER source resolved (see the field's own doc comment
    // and resolvedCfAccountId above).
    ...(resolvedCfAccountId !== undefined ? { cfAccountId: resolvedCfAccountId } : {}),
    ...provenance,
  };
}
