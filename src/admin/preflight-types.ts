// Preflight result shapes, shared by the orchestrator (preflight.ts) and the individual
// probes (preflight-probes.ts) so the probe module and the orchestrator do not depend on
// each other in a cycle.

export type PreflightStatus = "verified" | "configured" | "unconfigured" | "failed";

// ---------------------------------------------------------------------------------------------------------
// The STRUCTURED preflight discriminators.
//
// THE GAP. Preflight rides verbatim in the support bundle, and it was the pack's ONLY evidence for a whole
// family of setup faults. But every discriminating detail was carried in ONE free-text `evidence` line that
// is TRUNCATED to 60-80 characters, and the two list-bearing probes capped their detail at SIX names. So the
// pack said "recipient keys are set but do not parse (...)" without saying WHICH of the two env vars; "6 of 30
// source binding(s) are missing: A, B, C, D, E, F (+24 more)" after a bad deploy dropped thirty of them; "the
// destination probe failed (...)" with the sanitised evidence cut off BEFORE the S3 error code that names the
// cause; and "no read-only discovery token is resolvable" whether the token was genuinely unset or the DO read
// that resolves it simply FAULTED. The tail that was cut is exactly the tail that discriminates.
//
// THE FIX. The free-text evidence STAYS (it is what an operator reads on the onboarding screen), and the
// discriminating detail moves ALONGSIDE it into closed enums, capped operator-label lists and clamped counts,
// which survive the projection intact.
//
// NO-CUSTODY. Every field below is a CLOSED ENUM, a COUNT, a BOOLEAN or a BINDING NAME. Binding names are the
// established operator-label class the pack already ships in sourcesDetached (capped 64, sorted, deduped);
// they are not archive contents, not values and not keys. No endpoint, bucket, namespace id, database id,
// store id, token or Cloudflare message can reach any of these fields: the classifier reads a throw ONLY to
// SELECT an enum member and returns the member (the classifyCoarseError idiom).
// ---------------------------------------------------------------------------------------------------------

// PREFLIGHT_ERROR_CLASSES is the closed cause vocabulary for a probe that did not verify. It is deliberately
// finer than failureClass (auth/transient/other): failureClass answers "whose fault, and does it self-heal";
// this answers "what actually happened", which is what the truncated evidence string used to carry.
export const PREFLIGHT_ERROR_CLASSES = [
  "do-unreachable", // a scheduler / RUNSEAL Durable Object round trip threw: the DO could not be reached at all
  "binding-absent", // the binding the probe needs is not on the engine (a migration or a deploy did not carry it)
  "key-absent", // the key material env var is not set
  "key-unparseable", // the key material env var IS set and does not parse (the paste is wrong, or half a rotation landed)
  "auth", // 401/403: the credential is wrong or lacks the permission
  "not-found", // 404: the named resource does not exist
  "rate-limited", // 429: throttled
  "unavailable", // 5xx: the platform's own fault
  "http-other", // any other non-2xx (the status was seen; it is none of the above)
  "transport", // the call threw before a status was seen (DNS, TLS, abort, a network reset)
  "timeout", // the call did not answer in time (distinct from transport: the path is up, the peer is slow)
  "parse", // the response was read and is not the shape the probe expected (a body that would not decode)
  "shape", // the response decoded and does not satisfy the probe's contract (e.g. a JWKS with no keys)
  "unconfigured", // the probe found nothing to check because the feature is genuinely not set up (NOT a fault)
  "other", // classified as none of the above (the honest floor; never a message)
] as const;
export type PreflightErrorClass = (typeof PREFLIGHT_ERROR_CLASSES)[number];

// PREFLIGHT_RECIPIENT_SLOTS names WHICH recipient public key slot failed to parse. loadRecipients takes both
// env vars and throws ONE error, so "recipient keys do not parse" could never say which var to re-paste --
// and the two have completely different remedies (a bad BREAK_GLASS_PUBLIC is a broken key ceremony; a bad
// OPERATIONAL_PUBLIC leaves break-glass working and silently disables the in-account read-back drill).
export const PREFLIGHT_RECIPIENT_SLOTS = ["break-glass", "operational"] as const;
export type PreflightRecipientSlot = (typeof PREFLIGHT_RECIPIENT_SLOTS)[number];

// PREFLIGHT_TOKEN_RESOLVE splits the discovery token's null. resolveDiscoveryToken returns null BOTH when no
// token is configured anywhere AND when the DO read that holds the console-set one FAULTED and the env
// fallback is absent. Those are opposite tickets ("set a token" vs "your scheduler is down"), and they
// produced a byte-identical preflight item.
export const PREFLIGHT_TOKEN_RESOLVE = ["resolved", "unset", "do-fault"] as const;
export type PreflightTokenResolve = (typeof PREFLIGHT_TOKEN_RESOLVE)[number];

// PREFLIGHT_BINDING_CAP bounds every operator-label list below. 64 matches sourcesDetached, the established
// precedent for exactly this class of name in exactly this pack; six (the old evidence-line cap) is what threw
// away the 24 bindings a bad deploy actually dropped.
export const PREFLIGHT_BINDING_CAP = 64;

// PreflightBindingFault is ONE binding that is missing from the engine, and why it is unusable: `reserved`
// means the configured name COLLIDES with an engine-reserved binding, so the run path refuses it even if it
// were present (a different fix from re-attaching it).
export interface PreflightBindingFault {
  binding: string;
  reserved: boolean;
}

// PreflightResourceFault is ONE binding that IS present and whose named Cloudflare resource did not answer a
// liveness probe. `kind` is the source-liveness verdict (deleted / unavailable / misconfigured), which is the
// difference between "re-create the resource" and "retry, it is transient".
export interface PreflightResourceFault {
  binding: string;
  kind: string;
}

export interface PreflightItem {
  id: string;
  name: string;
  // The Cloudflare product/plan or onboarding step this item depends on.
  requires: string;
  // Required for core backup/restore, or an optional feature.
  required: boolean;
  status: PreflightStatus;
  evidence: string; // the observed fact, redaction-safe (never a value, never a key)
  remediation?: string;
  // For a FAILED probe whose cause has a fault class: "auth" (401/403, a credential/permission
  // fault), "transient" (429/503/5xx/network, throttled or unreachable, self-heals), or "other"
  // (a permanent 4xx the store rejects identically on retry). Lets a diagnosis distinguish "check
  // your credentials" (auth) from "the destination was throttled/down" (transient), never conflate
  // a 503 with a 403. Absent on non-failed items and on probes with no class to report.
  failureClass?: "auth" | "transient" | "other";
  // ---- The structured discriminators the truncated evidence string used to cut off ----
  // The closed cause of a non-verified probe (see PREFLIGHT_ERROR_CLASSES). Absent on a verified item.
  probeErrorClass?: PreflightErrorClass;
  // WHICH recipient key slot failed to parse (the recipients probe only).
  whichRecipient?: PreflightRecipientSlot;
  // The discovery token's resolution outcome (the api-source-discovery-token probe only): a DO fault and a
  // genuinely-unset token both used to render as the same "no token is resolvable".
  tokenResolve?: PreflightTokenResolve;
  // The source-bindings probe: EVERY missing binding (capped 64, sorted), the true total, and whether the
  // list was cut. Six names plus "+24 more" is not a diagnosis of a deploy that dropped thirty bindings.
  missingBindings?: PreflightBindingFault[];
  missingBindingsTotal?: number;
  missingBindingsTruncated?: boolean;
  // The source-liveness probe: the bindings whose RESOURCE is gone or unreachable (capped 64, with the
  // per-binding kind), and the bindings that are present but could not be PROVEN. `unproven` used to be a
  // bare count, so "one of many sources is unprovable" could not name which one.
  missingResources?: PreflightResourceFault[];
  missingResourcesTotal?: number;
  unprovenBindings?: string[];
  unprovenBindingsTotal?: number;
}

export interface PreflightReport {
  generatedAt: string;
  engineVersion: string;
  summary: { required: number; requiredVerified: number; failed: number };
  items: PreflightItem[];
}
