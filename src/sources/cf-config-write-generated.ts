// Table-driven write-back for the list surfaces whose create and update endpoints Cloudflare's OpenAPI
// declares. Generated from the schema, then hand-reviewed.
//
// READ THIS BEFORE TRUSTING ANY WRITER IN HERE
// --------------------------------------------
// Cloudflare's schema tells us two things reliably: the PATH and the METHOD. It tells us nothing about
// the two things that decide whether a writer corrupts data.
//
//   1. The NATURAL KEY. `writeList` matches a snapshot item to its live counterpart by server id and by
//      a natural key. Too coarse and it UPDATES the wrong object. Too narrow and a restore DUPLICATES
//      everything it touches. The schema does not say which field names an object.
//   2. The BODY. Server-computed fields must be stripped or the update is refused. `stripStamped`
//      handles the common ones, but not the per-surface ones. Evidence, from the single hand-written
//      list writer added the same day: `account-rule-lists` needed `num_items` and
//      `num_referencing_filters` removed, and neither is in the shared strip list.
//
// So these writers are NOT equivalent to the hand-written, round-trip-proven ones. They are marked
// `proven: false` and the distinction is load-bearing, not decorative. `PROVEN_WRITE_SURFACES` in this
// module is what `resolveCfConfigSurfaces` uses to decide the DEFAULT restore scope, so an unproven
// writer never runs unless an operator names it explicitly and an approver signs a plan hash that
// includes it. That is the mechanism that lets the catalogue be complete without the product
// over-claiming.
//
// A writer graduates by passing the live round trip in test/live-cf-roundtrip.ts: create a real object,
// capture, delete it, restore, and re-run to prove exactly one copy survives. Move its id into
// PROVEN_WRITE_SURFACES when it does, and not before.

import type { Meter } from "../meter.ts";
import { type CfApi, type CfConfigSurface, type ConfigWriteResult, type Ids, listWithSub } from "./cf-config-core.ts";
import { naturalKey } from "./cf-config-shared.ts";
import { normaliseItem, writeListSpec } from "./cf-config-write.ts";

// PROVEN_WRITE_SURFACES are the surfaces whose write() has survived the live round trip. Everything
// else with a write() is available but off by default. This list only ever grows by someone running the
// round trip and watching it pass, which is the whole point of it existing as data rather than a
// comment.
// `dex-tests` has no writer. Its READ unwraps the DEX envelope: DEX answers `{dex_tests: [...]}`, and a
// plain list reader would archive the ENVELOPE as the single item, so the surface would capture one object
// whose only key is `dex_tests` and a restore would have nothing to rebuild from. Unwrapping it makes the
// read shape-changing, and the offline structural gate demands that a generated writer for such a surface
// supply its own matching reader, which this one cannot: the existing `subCollection` mechanism wires
// listWithSub, not listEnvelope.
//
// The writer is left out rather than patched because there is nothing to patch it against. It is unproven,
// its create is refused with `dex.api.parameter.invalid` on both accounts, and DEX is not entitled on the
// free one, so no round trip can exercise it. A writer that can only ever skip is a promise the product
// cannot keep. The surface still captures, which is what a customer actually loses without it.
//
// `rate-limits` has no writer. Its READ works and the surface stays in the registry, but the write can
// never succeed for anyone: POST returns 403 code 10037, "ratelimit.api.maintenance_mode. This API is in
// maintenance mode and no longer accepts modifications." The GET carries its own deprecation notice
// (code 10035) while still returning data, so backup is right to keep it and a writer is not. Cloudflare
// directs modifications to the Rulesets API, which we already write.

// UNPROVEN_WRITE_CAUSES records WHY each surface with a writer has not passed the live round trip.
//
// The reasons used to live in two places that cannot gate: prose comments in this file, and a markdown
// ledger under the workspace's design corpus. The ledger is the fuller account and stays, but it sits in
// a directory that is NOT under version control, so the recorded cause for an unproven writer could be
// lost without a trace and nothing could check it was ever written. Causes are data here for the same
// reason PROVEN_WRITE_SURFACES is data rather than a comment: so a gate can read them.
//
// The rule the gate enforces is that every surface carrying a write() is either PROVEN or has a cause
// here, and never both. An unproven writer with no recorded cause is the state this is written against:
// it looks identical to one that was tested and passed, and it is how four surfaces sat in the available
// set with no evidence either way until they were cross-checked against the ledger by hand.
//
// A cause is a statement about EVIDENCE, not a verdict on the writer. Cloudflare's own words are quoted
// where it gave any, because an entitlement verdict recorded in our own paraphrase has twice turned out
// to be our malformed request wearing a plan limit.
export const UNPROVEN_WRITE_CAUSES: ReadonlyMap<string, string> = new Map([
  // Plan or product entitlement. No engineering moves these on a Free account.
  ["waiting-rooms", "zone plan does not include Waiting Rooms"],
  ["spectrum-apps", "Forbidden: Spectrum is not available on a Free zone"],
  ["gateway-proxy-endpoints", "2009: IP based proxy endpoints are limited to enterprise accounts"],
  ["web3-hostnames", "account not entitled"],
  ["regional-hostnames", "1002 forbidden: Regional Services is a paid add-on"],
  ["leaked-credential-detections", "11001: product has not been enabled"],
  ["content-scanning-settings", "not entitled to use the phase http_request_firewall_scan_file [entitlement]"],
  // NOT an entitlement, despite what this said. The live sweep reports a PROBER LIMIT: the harness found
  // no two-valued field it was willing to change, and the one it tried produced "invalid
  // ValidationDefaultMitigationAction", which is our value being wrong rather than the account refusing.
  // Recorded as owed work, because an entitlement verdict is never retried and this one should be.
  ["schema-validation-settings", "Unentitled mitigation action: Zone is not entitled to use log actions [entitlement]. Established by writing the schema-declared enum member rather than by the prober failing to find a field"],
  ["zone-setting-origin-h2-max-streams", "1135: this zone setting is not available for your plan type"],
  ["zone-setting-aegis", "PRECONDITION: the pool_id can not be empty, so an Aegis pool must exist first. Not attempted"],
  ["zone-setting-csam-scanner", "PRECONDITION, not a silent no-op. The writer does issue the write, on path csam_scanner_third_party, and Cloudflare refuses it with csam-config-service.api.unknown_error. The account reads email_state unverified and cybertip.verified false, so CSAM scanning is not set up here. Satisfiable in principle, and it is account state rather than plan"],
  ["tiered-caching", "the account reports this setting as not editable"],
  // DLP is a paid Zero Trust product. Recorded as Forbidden rather than as a body defect, after the
  // dlp-email-rules correction showed that one of this family was creatable all along and our malformed
  // request stood in front of the real answer.
  ["dlp-profiles-custom", "3314 Forbidden: DLP is not enabled on this account"],
  ["dlp-sensitivity-groups", "3314 Forbidden: DLP is not enabled on this account"],
  ["dlp-custom-prompt-topics", "3314 Forbidden: DLP is not enabled on this account"],
  // Quota of zero is an entitlement wearing a number, per the refusal classifier.
  ["page-shield-policies", "exceeded the maximum number of rules in the phase http_response_page_shield: 1 out of 0"],
  // Our own request is still in front of the answer for these two. Recorded as OURS, not as a plan
  // limit, so they read as work owed rather than as settled.
  // Recorded as OUR BODY on the strength of a 3312 "UUID parsing failed", which the vector body no longer
  // produces: it carries all four required fields with syntactically valid UUIDs and the account answers
  // 3314 Forbidden, the same entitlement as every other DLP surface. Re-probed directly rather than
  // inferred.
  ["dlp-data-classes", "3314 Forbidden: DLP is not enabled on this account"],
  ["account-endpoint-healthchecks", "1002 Invalid request, naming no field, to a body that matches Cloudflare's published schema. Also tried with a ROUTABLE endpoint (1.1.1.1) as well as the TEST-NET-3 address in the vector, in case an ICMP check refused an unroutable target: both refused identically, so the endpoint value is not the variable. The schema is magic-transit_endpoint_health_check and this account has no Magic Transit. Recorded as unknown rather than entitlement, because Cloudflare has not said so"],
  // A silent-discard misdiagnosis has two compounding causes, and both run in the most expensive
  // direction: they blame Cloudflare for silently discarding when Cloudflare refused loudly and said
  // exactly why.
  //
  //   Reading only whether a write applied misses the writer's own report. writeSingleObject CATCHES an
  //   API error and RETURNS it as a skip, so nothing throws; a check that stops at a read-back after
  //   seeing no change can misread that as a silent discard rather than reading `skipped` as well.
  //
  //   A whole-object PATCH hides the reason underneath. Sending every field means Cloudflare validates
  //   every field, so the refusal that comes back can be about a plan-gated neighbour rather than the
  //   field under test. A diff-only body makes the endpoint name the real blocker.
  //
  // Two of these are PRECONDITIONS rather than entitlements, which the classifier treats as satisfiable:
  // an object has to exist before it can be modified. They are candidates for the `prereq` mechanism.
  // A PRECONDITION CAN BE AN ENTITLEMENT IN DISGUISE, and the only way to tell is to try to satisfy it.
  // Both read as "the object does not exist yet", which the classifier calls satisfiable; creating the
  // object was attempted for both, and both were refused outright, so no amount of prereq work reaches
  // either surface on this plan.
  ["zone-hold", "Zone holds are only available on Enterprise zones (1005). Creating one was attempted and refused"],
  ["custom-nameserver-usage", "custom nameserver sets are not enabled for this account (1002). Creating one was attempted and refused"],
  ["dlp-settings", "Forbidden: DLP is not enabled on this account"],
  // Unprovable HERE rather than untried: its changed field sits inside `zone_defaults`, so the top-level
  // diff sends that whole nested object and carries the plan-gated `flatten_all_cnames` with it. Cloudflare
  // MERGES a partial nested PATCH on this endpoint (measured: nine sibling keys survived), so recursing one
  // level would prove it. That is deliberately not done on one endpoint's evidence: PATCH semantics for
  // nested objects are not guaranteed across Cloudflare, and an endpoint that REPLACES instead would
  // silently delete the siblings left out.
  // Unprovable BY THIS HARNESS rather than by the account. Both of its fields are two-member enums (type:
  // cloudflare/rfc3986, scope: incoming/both), and the prober only knows booleans and Cloudflare's on/off
  // spellings, so its only move is to invent a value and the endpoint answers "erroneous scope". Teaching
  // the prober to read two-member enums from the vendored schema does not reach this surface either:
  // Cloudflare declares no request body for that PUT at all, so the enum is not there to read. The write
  // path is untested, not suspected.
  // All five keep their writers and stay off by default: none is shown to be BROKEN, which is the bar for
  // removing one.
  ["waiting-room-settings", "Zone not entitled to this functionality [entitlement]"],
  ["acm-total-tls", "Access to configure this resource has not been granted for this zone: Total TLS needs Advanced Certificate Manager"],

  ["fraud-detection-settings", "PROBER LIMIT: user_profiles is stripped (the endpoint refuses it) and username_expressions is a list, so nothing two-valued remains to flip"],
  ["api-shield-schema-validation-settings", "Unentitled mitigation action: Zone is not entitled to use log actions [entitlement]. Same refusal as its schema_validation twin, from the same hand-written value"],
]);

// NO_LIVE_ROUTE_HERE names the PROVEN surfaces that no live harness re-exercises on the throwaway proving
// account, and why.
//
// A proof is a claim about the past. What keeps it true is a harness that re-runs it, so a proven surface
// nothing re-exercises can regress in silence: the count stays put and every harness stays green. That is
// not hypothetical: dns-settings stopped being re-proved the moment the refusal classifier learnt one more
// phrase, and nothing noticed until the coverage question was asked directly.
//
// It is DATA rather than a prose comment, for the same reason UNPROVEN_WRITE_CAUSES is: the live suite
// reads it, unions what each harness reports proving, and fails when a surface that is supposed to have a
// live route was not exercised. An entry here is a deliberate exemption from that check, so it carries the
// reason at the point of exemption.
//
// AN ENTRY HERE CLAIMS NOBODY ANYWHERE RE-EXERCISES THE SURFACE. If a prover outside this repo does, it
// belongs in LIVE_ROUTE_ELSEWHERE below, which carries a clock. The note there names two entries that were
// wrong on exactly that point.
export const NO_LIVE_ROUTE_HERE: ReadonlyMap<string, string> = new Map([
  ["page-rules", "the account refuses the READ, so no harness can drive it here"],
  ["account-custom-page-assets", "quota of zero: the create is refused before anything downstream runs"],
  ["zone-custom-page-assets", "quota of zero: the create is refused before anything downstream runs"],
  ["account-rulesets", "hand-written writer; its additive-contract proof is not reproduced by a standing harness, and the console loop that reaches the ZONE rulesets surface does not reach this one: the proving token carries no account-level edit scope"],
  ["zone-setting-origin-max-http-version", "PROBER LIMIT on an already-proven surface: the value is 1 or 2 and the prober will not guess an enum"],
  ["zone-setting-origin-tls-compliance", "PROBER LIMIT on an already-proven surface: no two-valued field it is willing to change"],
  ["zone-setting-ssl-automatic-mode", "PROBER LIMIT on an already-proven surface: the endpoint answers 400 to the prober's flip"],
]);

// LIVE_ROUTE_ELSEWHERE is the OTHER kind of exemption from the live suite's coverage check, kept separate
// from NO_LIVE_ROUTE_HERE deliberately.
//
// `rulesets` and `zone-settings` belong here rather than in NO_LIVE_ROUTE_HERE, because a standing harness
// DOES reproduce them: it arms them on a throwaway zone, damages them outside the product, restores
// through the console, and reads Cloudflare back to prove the value returned. `zone-settings` sits here
// precisely BECAUSE it is the only surface served by the inline hand-written keyed-member writer, and
// `rulesets` because it is the only one whose restore mints fresh server ids.
//
// AN EXEMPTION MUST BE ABLE TO EXPIRE, so each entry carries the same shape as the refusal ledger in the
// harness: an entry names the prover, the ledger KIND that prover banks, and the date the route was
// established. A gate reads it and refuses the exemption when no counting row of that kind exists and
// `since` has fallen out of the expiry window. The claim "it is
// proved elsewhere" is itself checked against evidence, on a clock, without anyone remembering to look.
//
// The suite exempts these from its own gap check, because the route genuinely is not in this repo and
// failing a live engine run over it would be a false accusation. It says so distinctly rather than
// reporting them as unreachable.
export interface LiveRouteElsewhere {
  /** The prover, by repo-relative path, in the repo named by `repo`. */
  prover: string;
  repo: string;
  /** The ledger row kind that prover banks. A row of any other kind does not satisfy this exemption. */
  banks: string;
  /** The date the route was established, ISO. Read as a claim with a clock on it, not as a fact. */
  since: string;
  why: string;
}
export const LIVE_ROUTE_ELSEWHERE: ReadonlyMap<string, LiveRouteElsewhere> = new Map([
  [
    "rulesets",
    {
      prover: "spec/journeys/cf-config-roundtrip.spec.ts",
      repo: "harness",
      banks: "console-product",
      since: "2026-07-31",
      why: "hand-written writer, and no engine harness drives it. The console round trip arms a WAF custom-phase rule, damages it, restores through the console and matches on description because the restore mints fresh server ids",
    },
  ],
  [
    "zone-settings",
    {
      prover: "spec/journeys/cf-config-roundtrip.spec.ts",
      repo: "harness",
      banks: "console-product",
      since: "2026-07-31",
      why: "the inline hand-written keyed-member writer, PATCHing only changed members at their own endpoints. No engine harness reaches it; the console round trip overwrites a member and reads it back",
    },
  ],
]);
export const PROVEN_WRITE_SURFACES: ReadonlySet<string> = new Set([
  // Proven by flipping zone_defaults.multi_provider. It was unprovable until the writer learnt
  // to diff INTO nested objects: the whole-object PATCH carries the `soa` block on every write, and a Free
  // account refuses it with "Custom SOA records are not available to this account or zone", so the surface
  // read as unwritable over a field nobody was changing. The partial nested body is accepted, and Cloudflare
  // deep-merges it, which was verified against the live API before the writer was allowed to rely on it.
  "account-dns-settings",
  // Proven through the full singleton round trip, both by a value read out of Cloudflare's
  // published OpenAPI rather than guessed (see test/cf-hand-damage.ts). Neither was reachable by the
  // prober's own two-valued flip, and both were recorded as a PROBER LIMIT, which describes the harness
  // rather than the writer.
  //
  // url-normalization's recorded cause also claimed Cloudflare declares no request body for the PUT. The
  // schema declares one, with `type` as a two-member enum, so that claim was wrong as well as incomplete.
  "url-normalization",
  // Its one configurable field is a rotation interval, a number with a declared range of 21 to 365, which
  // is exactly the shape a two-valued flip cannot reach.
  "access-key-configuration",
  // Proven through the full singleton round trip (flipped multi_provider, confirmed the change
  // took, restored, confirmed the original came back). It was unprovable until writeSingleObject stopped
  // PATCHing the whole object: Cloudflare validates the whole body, so the plan-gated `flatten_all_cnames`
  // on a Free zone refused the entire write and the surface read as unwritable.
  "dns-settings",
  // Proven by the same loop (flipped is_ui_read_only). The Zero Trust organisation settings: seat
  // controls, session duration, the login page. Chosen because Access is a family customers configure by
  // hand and then cannot reconstruct from memory.
  "access-organizations",
  // Proven (flipped value). Web Analytics / RUM on a zone. It PROVED A DEFECT on the way:
  // enabling RUM mints a server-assigned `site_tag`, the restore's diff carried it back, Cloudflare
  // answered 10004 malformedParams to the whole request, and the write failed entirely, including the
  // harness's own attempt to undo its damage. Adding site_tag to SERVER_STAMPED fixed the surface.
  "zone-rum",
  // Proven (flipped enable_js). Bot management: JS detection, fight mode, the AI-crawler
  // controls. It was unprovable until the writer stopped sending `using_latest_model`, a server-computed
  // status the endpoint reports and then refuses; dropping that one field makes the same PUT succeed.
  "bot-management",
  // Proven through the same loop. Both reached only once writeSingleObject accepted POST: their
  // endpoints expose GET and POST alone, and Cloudflare documents POST as the SETTER ("Set Leaked
  // Credential Checks Status", "Set Global WARP override state"), not a create. The path addresses one
  // object, so a POST cannot make a second.
  "leaked-credential-checks",
  "device-resilience-disconnect",
  // Proven, both found by sweeping every writerless idempotent surface against the verb
  // Cloudflare's schema declares for the path it READS, rather than proposing writers by eye.
  "device-policy-default",
  "zone-zero-trust-organization",
  // Proven by test/live-cf-email-routing-prove.ts, which exists because this surface's shape
  // (settings PLUS a rule list behind one id) fits neither the collection prover nor the singleton one.
  // Full loop including the UPDATE path and a convergence pass. Its rules had been backed up and verified
  // recoverable while being impossible to re-apply, because the surface had no writer at all.
  "email-routing",
  // Hand-written and shipped before this sweep.
  "dns",
  "zone-settings",
  "rulesets",
  "account-rulesets",
  "page-rules",
  "firewall-access-rules",
  "account-firewall-access-rules",
  // Proven live: capture, damage, dry run, restore, re-read, converge.
  "zone-setting-speed-brain",
  "zone-setting-ssl-automatic-mode",
  "zone-setting-origin-max-http-version",
  "zone-setting-fonts",
  // Proven live by the LIST loop: created, captured, DELETED, restored, re-run with exactly
  // one copy surviving.
  "account-rule-lists",
  // Proven live by the auto-prove sweep, using a create body synthesised from Cloudflare's
  // own OpenAPI schema rather than hand-written.
  "kv-namespaces-config",
  // Proven live with hand-written create bodies, after the schema-synthesised ones were
  // refused. zone-lockdowns and ua-rules were nearly removed as broken: the harness was matching the
  // restored object by its OLD id, which a restore never reproduces, so a working writer read as failed.
  "teamnet-virtual-networks",
  "zone-lockdowns",
  "ua-rules",
  // Proven live after the write path was taught to adapt its page size. Its writer could
  // never have worked before that: writeListSpec listed live state at the registry default and
  // Cloudflare refuses anything above 100 here, so the apply failed before it reached the diff. The
  // create body was correct the whole time.
  "ai-search-namespaces",
  // Proven live. The ledger had recorded this as blocked because "Magic Transit is an
  // enterprise product". That was wrong: the create needed a CIDR in `targets` and the synthesised body
  // put a plain string there. Nothing about the account was the obstacle.
  "magic-bgp-filter-profiles",
  // Proven live after two separate fixes, neither of them about the create body the ledger had
  // blamed. Its `id` is customer-chosen, so stripStamped removed it and only the CREATE path failed; and
  // `modified_at` was missing from SERVER_STAMPED, so the diff never converged even once the create worked.
  "ai-gateway-gateways",
  // Proven live once writeSingleSetting stopped assuming every zone setting carries its value
  // under `value`. This one carries it under `enabled` and its PATCH refuses {value: ...} outright, so the
  // surface had skipped on every restore, including when nothing had changed. Found by the idempotence
  // sweep, not by the round trip: a writer that refuses its own snapshot never gets as far as a round trip.
  "zone-setting-auto-origin-tls-kex",
  // Proven live after three fixes, in the order they had to happen: the READ had to sub-read
  // each list's items (they were never captured), the WRITER had to read live the same way (its own read
  // saw no items at all, so every list looked changed forever), and the nested guard had to refuse an
  // update that would replace the collection. Round trip: created, captured, deleted, restored, converged;
  // and an entry added live that the snapshot lacks is named and refused rather than dropped.
  "gateway-lists",
  // Proven live. The ledger had recorded this as needing "a reachable TLS endpoint with a
  // matching certificate hash". It needed neither: the harness addressed the item by `name` when the only
  // key that works is `network_id`, so its cleanup deleted at a path Cloudflare refuses, the orphan
  // survived, and every later run failed with "a managed network with name ... already exists". Three
  // entitlement verdicts in this ledger have now turned out to be defects on our side of the call.
  "device-managed-networks",
  // Proven live. Recorded as plan-gated with the 1135 family; it is not gated at all. Two of my
  // own probes had to be corrected to find that out: the settings endpoint ECHOES a different id
  // (origin_tls_cmpl) from the one it is requested under (origin_tls_compliance_modes), and probing the
  // echoed id returns "Undefined zone setting", which reads exactly like a missing feature. Cloudflare then
  // named the valid values in its own validation message: a list of `fips` and/or `pqh`.
  "zone-setting-origin-tls-compliance",
  // Proven live by writeSingleObject, a new writer shape for a surface whose whole body IS the
  // configuration rather than one wrapped in {value} or {enabled}. These three were among 131 idempotent
  // surfaces carrying no writer at all: captured and previewed, never re-applied, and each one something a
  // customer configures by hand and would otherwise re-enter from the snapshot by eye.
  "page-shield-settings",
  "gateway-logging",
  "email-routing-catch-all",
  // Proven live by the same writeSingleObject shape, found by sweeping the 131 idempotent
  // surfaces that carried no writer rather than by re-probing the ones already blocked. Each was captured
  // and previewed but never re-applied, and each is configuration a customer sets by hand.
  "universal-ssl-settings",
  "workers-account-settings",
  "zt-device-settings",
  "zt-connectivity-settings",
  "email-dmarc-reports",
  "ct-alerting",
  "zaraz-config",
  "magic-bgp-settings",
  "origin-tls-client-auth-settings",
  // Proven live once the damage step reached where the change had to go. The generic prober
  // flipped the first boolean at the top level or one level down; managed-headers keeps its booleans inside
  // an ARRAY, and gateway-configuration two levels down under settings. Both are proven, and neither was
  // ever blocked: "cannot damage it" was a limit of the probe, which is a different fact from "cannot
  // restore it" and was worth separating rather than recording as a blocker.
  "managed-headers",
  "gateway-configuration",
  // Proven live after re-testing two removal verdicts that were wrong on their face.
  "observability-saved-queries",
  "secondary-dns-acls",
  // Proven live, and it was never blocked. The ledger said it "requires an existing subnet_id,
  // so a WARP subnet must exist first", and I then spent a round confirming a WARP Connector id is accepted
  // and hitting a 2042 internal error behind it. The account already had SIX subnets all along, at
  // /accounts/{id}/zerotrust/subnets, which is a surface this registry already reads. Supplying one of
  // those creates cleanly and the loop closes with no internal error at all.
  "device-ip-profiles",
  // Proven live after enabling Zero Trust on the proving account. access-tags is the first
  // ID-LESS collection proven: it has no id field at all, the NAME is the key, and the harness had been
  // treating a successful create as a refusal because it looked for an id that never exists.
  "access-tags",
  // Proven live by test/live-cf-singleton-prove.ts, the first COMMITTED prober for one-object
  // surfaces. The fourteen singletons proven before it were done by a script written inline and never kept,
  // so none of those claims could be re-checked and a new singleton writer had nothing to run against.
  //
  // Both were carried as unproven for a reason that was an artefact of the probe: their value is
  // the string "on"/"off" rather than a boolean, and a boolean-only prober reports "nothing safe to change"
  // on the whole zone-settings family. "on"/"off" is Cloudflare's own two-valued vocabulary for those
  // endpoints, so flipping it is not the enum guessing that produced two misattributed 500s earlier.
  //
  // tiered-caching stayed unproven and its reason improved: the account answers `editable: false`, which the
  // writer already honours by skipping. That is the plan speaking, not a defect.
  "smart-shield",
  "smart-tiered-cache",
  // Proven live. Its value is one of a named set rather than a boolean, so the singleton prober
  // had recorded it against "no two-valued field", which blamed the harness for what was really a missing
  // vocabulary. The values came from CLOUDFLARE, not from a guess: sending a deliberately invalid value
  // makes the endpoint answer "The value must either be `off`, `supported`", and that probe is now part of
  // the harness so the next surface of this shape answers the same way instead of sitting unproven.
  //
  // Its setting id is a THIRD instance of the echo trap: the surface answers `origin_pqe` while the
  // validation message names `origin_post_quantum_encryption`, and neither is the path it is served at. A
  // hand probe against the echoed id returns "Unrecognized zone setting" and reads exactly like a missing
  // feature; going through the surface's own writer is what got the real answer.
  "cache-origin-pq-encryption",
  // Proven live, full loop including the update leg. It had been carried as blocked on
  // "rule can not be added without initial account configuration", which is not an entitlement and not a
  // defect: it is a fact about account STATE, and states can be changed. The refusal classifier calls that
  // a PRECONDITION for exactly this reason, and this is the first time that class paid for itself.
  //
  // The harness can now declare a `prereq` per surface: something that must exist before the surface's own
  // create is legal. Here it is the Magic Network Monitoring config. It is stood up before the loop and
  // torn down in a `finally`, on every path including the ones that throw, because setup without matching
  // teardown is how this account ended up with a Zero Trust organisation and a default Gateway location
  // that cannot now be removed.
  "mnm-rules",
  // Proven live on the owner's paid account, full loop including the update leg. Two defects had
  // to be fixed first and NEITHER was about these surfaces:
  //
  //   1. HTTP 204 was read as a failure, so the round trip's own DELETE looked like a create refusal.
  //   2. The items carry NO id at all ({name, description, url, last_updated, size_bytes}); the name is the
  //      path segment. resolveServerId returned "", so the writer could create and could never update,
  //      skipping every changed item with "no id to update in place".
  //
  // Both were invisible on the proving account, which allows ZERO custom page assets: the create was
  // refused, so nothing downstream of it ever ran. A quota of zero hid two real bugs.
  "account-custom-page-assets",
  "zone-custom-page-assets",
  // Proven live on the paid account. It had been recorded as BAD-BODY, that is OUR fault, and
  // that was the wrong reason twice over: `action` is an internally tagged enum, {"action": "Block"}, not
  // the bare string the synthesised body carried, AND unlike every other DLP surface here this one is NOT
  // Forbidden on a paid account. The malformed body was masking a surface that was creatable all along.
  //
  // Its update path is NOT exercised: the endpoint accepts a change and does not apply it, so live never
  // differs from the snapshot and there is nothing for the harness to observe. Recorded rather than left
  // to look like coverage.
  "dlp-email-rules",
]);

// resolveServerId finds the field that ADDRESSES an item, which is not always `id`.
//
// Cloudflare is inconsistent: most collections use `id`, device-managed-networks uses `network_id`, and
// Turnstile widgets use `sitekey`. writeListSpec needs this to build the update path, and returning ""
// makes it skip a changed item rather than update it. The same rule exists in test/cf-item-key.ts for the
// harnesses; it is duplicated rather than shared because src must not import from test.
// Exported so the live idempotence sweep can ask the SAME question the writer asks, rather than carrying a
// second copy of the rule. A copy is how the in-band split drifted across three repos.
export function resolveServerIdField(it: Record<string, unknown>): string {
  if (typeof it.id === "string" && it.id !== "") return "id";
  for (const k of Object.keys(it)) {
    if (/_id$/.test(k) && typeof it[k] === "string" && it[k] !== "") return k;
  }
  for (const k of ["sitekey", "site_tag"]) {
    if (typeof it[k] === "string" && it[k] !== "") return k;
  }
  return "";
}

function resolveServerId(it: Record<string, unknown>): string {
  const f = resolveServerIdField(it);
  return f === "" ? "" : (it[f] as string);
}

// preferredKey picks the field that NAMES an object, in the order Cloudflare's own payloads tend to use
// it. The final fallback is the whole writable body, which is deliberate and is the safe direction: an
// item whose content changed will not match, so it is CREATED rather than used to overwrite something
// else. That can duplicate, which is visible and recoverable, rather than silently updating the wrong
// object, which is neither. The leftover is made visible in the diff.
function preferredKey(it: Record<string, unknown>): string {
  for (const f of ["name", "title", "hostname", "expression", "pattern", "url", "host", "domain", "identifier"]) {
    const v = it[f];
    if (typeof v === "string" && v !== "") return `${f}=${v}`;
  }
  return naturalKey(it);
}

interface GeneratedSpec {
  id: string;
  listPath(i: Ids): string;
  itemPath(i: Ids, id: string): string;
  createMethod: "POST" | "PUT";
  updateMethod: "PUT" | "PATCH";
  // idNamesTheItem marks a collection whose `id` is CHOSEN BY THE CUSTOMER rather than allocated by
  // Cloudflare. AI Gateway is one: you POST `{"id":"my-gateway",...}` and that string is both the
  // gateway's name and its path segment forever.
  //
  // It matters because stripStamped removes `id` on the assumption that a server allocated it, which is
  // right for almost every collection and wrong for these. The update path still worked, so the writer
  // looked fine until a restore had to CREATE, at which point Cloudflare refused with "Required" and the
  // surface read as a body-synthesis problem. Set this and `id` stays in the create body and becomes the
  // natural key, which is also the sharpest key available: it is unique by construction, unlike a `name`
  // field that two items may share.
  idNamesTheItem?: boolean;
  // keyField names the field that ADDRESSES an item at itemPath, for collections that carry no id at all.
  // Custom page assets are the case: the item is {name, description, url, last_updated, size_bytes} and the
  // name is the path segment. resolveServerId returns "" for those, so the writer could create and could
  // never update, skipping every changed item with "no id to update in place".
  //
  // Declared per surface rather than inferred. Falling back to `name` for any id-less collection would
  // guess, and a wrong guess here does not fail loudly: it addresses SOME OTHER object at itemPath and
  // overwrites it. That is the exact failure this engine is built to refuse rather than risk.
  keyField?: string;
  // nestedCollections is passed straight through to ListWriteSpec: fields on an item that are collections
  // of their own, so an update replaces them wholesale unless the guard refuses.
  nestedCollections?: readonly string[];
  // subCollection makes the WRITER read live the same way the SURFACE does, for a surface whose read
  // sub-reads a nested collection. Without it the writer's live view lacks the nested field entirely and
  // the item looks changed on every run.
  subCollection?: { field: string; path(i: Ids, id: string): string; perPage?: number };
}

// GENERATED_LIST_WRITERS is the table. Paths and methods come from Cloudflare's published schema; the
// natural key is `preferredKey` for every one of them, which is exactly why none is proven.
// `gateway-lists` carries a writer once both reasons against one were fixed. Its read now sub-reads each
// list's items (listWithSub), so the snapshot carries the entries rather than just a count, and
// `nestedCollections: ["items"]` makes an update refuse rather than replace the collection when live holds
// entries the snapshot lacks. Without the second, the writer would reintroduce the earlier destructive
// shape one level down.
//
// NO WRITER, each for a demonstrated reason rather than caution: device-posture-rules, healthchecks,
// smart-shield-healthchecks, gateway-locations, gateway-pac-files, access-custom-pages,
// logs-explorer-datasets, account-logs-explorer-datasets, images-variants, dex-rules, firewall-rules and
// turnstile. Their names are not unique within the collection, or the surface cannot round-trip at all, so
// `preferredKey` cannot identify an item. The engine REFUSES an ambiguous match rather than guessing, so
// giving them a writer anyway would be safe but dishonest: a writer that can only ever skip is a promise
// the product cannot keep.
const GENERATED_LIST_WRITERS: GeneratedSpec[] = [
  // filters has NO writer. Its create endpoint takes an ARRAY of filters and writeList sends one object
  // per item, so the create is refused with filters.api.malformed_request_body. This is a shape writeList
  // cannot express, which is the stated bar for not having a writer at all rather than special-casing the
  // shared engine for one surface.
  //
  // THREE MORE EXCLUDED FOR A RELATED REASON, checked against Cloudflare's published schema
  // after a sweep for idempotent surfaces whose collection is EMPTY here but which can be POSTed to. All
  // three can be created and deleted and NOT updated, so a writer could restore a missing item and could
  // never reconcile a changed one:
  //
  //   account-email-sending-suppressions   item path exposes DELETE and GET only
  //   notification-silences                item path exposes DELETE and GET only. Its COLLECTION offers a
  //                                        PUT, which is a wholesale replace, and the contract this engine
  //                                        is built on forbids that outright
  //   workers-observability-metricsexport  no item path at all; DELETE/GET/POST on the collection
  //
  // "Creates but never updates" is precisely the shape this engine refuses to give a writer, and it fails
  // silently in the worse direction: a restore after a DELETE creates and looks correct,
  // while a restore over live data does nothing at all. A surface with no writer is honest; a surface with
  // a writer that cannot reconcile is a liability.
  { id: "zone-lockdowns", listPath: (i) => `/zones/${i.zoneId}/firewall/lockdowns`, itemPath: (i, id) => `/zones/${i.zoneId}/firewall/lockdowns/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "ua-rules", listPath: (i) => `/zones/${i.zoneId}/firewall/ua_rules`, itemPath: (i, id) => `/zones/${i.zoneId}/firewall/ua_rules/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "page-shield-policies", listPath: (i) => `/zones/${i.zoneId}/page_shield/policies`, itemPath: (i, id) => `/zones/${i.zoneId}/page_shield/policies/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "waiting-rooms", listPath: (i) => `/zones/${i.zoneId}/waiting_rooms`, itemPath: (i, id) => `/zones/${i.zoneId}/waiting_rooms/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "spectrum-apps", listPath: (i) => `/zones/${i.zoneId}/spectrum/apps`, itemPath: (i, id) => `/zones/${i.zoneId}/spectrum/apps/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "web3-hostnames", listPath: (i) => `/zones/${i.zoneId}/web3/hostnames`, itemPath: (i, id) => `/zones/${i.zoneId}/web3/hostnames/${id}`, createMethod: "POST", updateMethod: "PATCH" },
  { id: "regional-hostnames", listPath: (i) => `/zones/${i.zoneId}/addressing/regional_hostnames`, itemPath: (i, id) => `/zones/${i.zoneId}/addressing/regional_hostnames/${id}`, createMethod: "POST", updateMethod: "PATCH" },
  { id: "leaked-credential-detections", listPath: (i) => `/zones/${i.zoneId}/leaked-credential-checks/detections`, itemPath: (i, id) => `/zones/${i.zoneId}/leaked-credential-checks/detections/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "zone-custom-page-assets", listPath: (i) => `/zones/${i.zoneId}/custom_pages/assets`, itemPath: (i, id) => `/zones/${i.zoneId}/custom_pages/assets/${id}`, createMethod: "POST", updateMethod: "PUT" , keyField: "name"},
  { id: "gateway-lists", listPath: (i) => `/accounts/${i.accountId}/gateway/lists`, itemPath: (i, id) => `/accounts/${i.accountId}/gateway/lists/${id}`, createMethod: "POST", updateMethod: "PUT", nestedCollections: ["items"], subCollection: { field: "items", path: (i, id) => `/accounts/${i.accountId}/gateway/lists/${id}/items`, perPage: 100 } },
  // Both list outputs plainly carry id AND name, so a natural key built from the read output works for
  // both: observability-saved-queries round-trips immediately, and secondary-dns-acls converges once
  // created_time / modified_time join SERVER_STAMPED (without them the two fields survive the strip and
  // differ on every read, so the writer re-applies an identical ACL forever: the same defect modified_at
  // caused, one spelling along, producing the "duplicates on re-run" symptom).
  //
  // observability-saved-queries updates with PATCH, not PUT, and the DRIFT GUARD is what caught that: PUT
  // /{id} is a 404 there and is absent from Cloudflare's schema. The round trip could not have caught it,
  // because a restore after a delete only ever CREATES, so the update method is never exercised. A writer
  // that creates correctly and can never update is exactly the shape a proof-by-round-trip misses.
  { id: "observability-saved-queries", listPath: (i) => `/accounts/${i.accountId}/workers/observability/queries`, itemPath: (i, id) => `/accounts/${i.accountId}/workers/observability/queries/${id}`, createMethod: "POST", updateMethod: "PATCH" },
  { id: "secondary-dns-acls", listPath: (i) => `/accounts/${i.accountId}/secondary_dns/acls`, itemPath: (i, id) => `/accounts/${i.accountId}/secondary_dns/acls/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "access-tags", listPath: (i) => `/accounts/${i.accountId}/access/tags`, itemPath: (i, id) => `/accounts/${i.accountId}/access/tags/${id}`, createMethod: "POST", updateMethod: "PUT" , keyField: "name"},
  { id: "gateway-proxy-endpoints", listPath: (i) => `/accounts/${i.accountId}/gateway/proxy_endpoints`, itemPath: (i, id) => `/accounts/${i.accountId}/gateway/proxy_endpoints/${id}`, createMethod: "POST", updateMethod: "PATCH" },
  { id: "device-managed-networks", listPath: (i) => `/accounts/${i.accountId}/devices/networks`, itemPath: (i, id) => `/accounts/${i.accountId}/devices/networks/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "device-ip-profiles", listPath: (i) => `/accounts/${i.accountId}/devices/ip-profiles`, itemPath: (i, id) => `/accounts/${i.accountId}/devices/ip-profiles/${id}`, createMethod: "POST", updateMethod: "PATCH" },
    { id: "dlp-profiles-custom", listPath: (i) => `/accounts/${i.accountId}/dlp/profiles/custom`, itemPath: (i, id) => `/accounts/${i.accountId}/dlp/profiles/custom/${id}`, createMethod: "POST", updateMethod: "PUT" },
  // dlp-entries has NO writer, and the reason is worth keeping. On a live account it returns 152 items
  // with DUPLICATE server ids and DUPLICATE names: the same predefined entry appears once per profile it
  // belongs to, distinguished only by profile_id. Both the id index and any name-based natural key
  // therefore collide, so a snapshot item would match a different profile's copy of itself. The writer
  // sweep caught this by feeding the surface its own live data and finding it would rewrite 12 items.
  // This is not a key that needs widening; the collection is not a flat set of independently addressable
  // items, so writeList is the wrong shape for it entirely.
  { id: "dlp-data-classes", listPath: (i) => `/accounts/${i.accountId}/dlp/data_classes`, itemPath: (i, id) => `/accounts/${i.accountId}/dlp/data_classes/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "dlp-sensitivity-groups", listPath: (i) => `/accounts/${i.accountId}/dlp/sensitivity_groups`, itemPath: (i, id) => `/accounts/${i.accountId}/dlp/sensitivity_groups/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "dlp-custom-prompt-topics", listPath: (i) => `/accounts/${i.accountId}/dlp/custom_prompt_topics`, itemPath: (i, id) => `/accounts/${i.accountId}/dlp/custom_prompt_topics/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "dlp-email-rules", listPath: (i) => `/accounts/${i.accountId}/dlp/email/rules`, itemPath: (i, id) => `/accounts/${i.accountId}/dlp/email/rules/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "teamnet-virtual-networks", listPath: (i) => `/accounts/${i.accountId}/teamnet/virtual_networks`, itemPath: (i, id) => `/accounts/${i.accountId}/teamnet/virtual_networks/${id}`, createMethod: "POST", updateMethod: "PATCH" },
  { id: "mnm-rules", listPath: (i) => `/accounts/${i.accountId}/mnm/rules`, itemPath: (i, id) => `/accounts/${i.accountId}/mnm/rules/${id}`, createMethod: "POST", updateMethod: "PATCH" },
  { id: "ai-gateway-gateways", listPath: (i) => `/accounts/${i.accountId}/ai-gateway/gateways`, itemPath: (i, id) => `/accounts/${i.accountId}/ai-gateway/gateways/${id}`, createMethod: "POST", updateMethod: "PUT", idNamesTheItem: true },
  { id: "ai-search-namespaces", listPath: (i) => `/accounts/${i.accountId}/ai-search/namespaces`, itemPath: (i, id) => `/accounts/${i.accountId}/ai-search/namespaces/${id}`, createMethod: "POST", updateMethod: "PUT" , keyField: "name"},
  { id: "kv-namespaces-config", listPath: (i) => `/accounts/${i.accountId}/storage/kv/namespaces`, itemPath: (i, id) => `/accounts/${i.accountId}/storage/kv/namespaces/${id}`, createMethod: "POST", updateMethod: "PUT" },
  { id: "magic-bgp-filter-profiles", listPath: (i) => `/accounts/${i.accountId}/magic/bgp/filter_profiles`, itemPath: (i, id) => `/accounts/${i.accountId}/magic/bgp/filter_profiles/${id}`, createMethod: "POST", updateMethod: "PUT" },
  // secondary-dns-acls has NO writer. The round trip created an ACL, deleted it, restored it, and the
  // SECOND restore applied again: the surface's read output does not carry the field the natural key is
  // built from, so a restored ACL never matches its own snapshot and every restore adds a copy.
  { id: "account-endpoint-healthchecks", listPath: (i) => `/accounts/${i.accountId}/diagnostics/endpoint-healthchecks`, itemPath: (i, id) => `/accounts/${i.accountId}/diagnostics/endpoint-healthchecks/${id}`, createMethod: "POST", updateMethod: "PUT" },
  // observability-saved-queries has NO writer. The auto-prove run created a query, deleted it, restored
  // it, and then found the SECOND restore applied again: the surface's read output does not carry the
  // field the natural key is built from, so a restored item never matches its own snapshot and every
  // re-run adds another copy. Caught by running the restore twice, which is the only way this is visible.
  { id: "account-custom-page-assets", listPath: (i) => `/accounts/${i.accountId}/custom_pages/assets`, itemPath: (i, id) => `/accounts/${i.accountId}/custom_pages/assets/${id}`, createMethod: "POST", updateMethod: "PUT" , keyField: "name"},
];

// GENERATED_KEY_FIELDS names the surfaces that declare their own address field, for collections carrying no
// id at all. Exported for the same reason as resolveServerIdField: so the addressability check in the live
// sweep reads the real declarations instead of a hand-maintained list that can fall behind them.
export const GENERATED_KEY_FIELDS: ReadonlyMap<string, string> = new Map(
  GENERATED_LIST_WRITERS.filter((w) => w.keyField !== undefined).map((w) => [w.id, w.keyField as string]),
);

// generatedWriter builds the write() for one table row. Every one goes through the shared, safety-
// contracted `writeList`: never a wholesale collection PUT, additive with no pruning, idempotent on
// re-run, fail-open per item, and a live-only leftover is reported rather than hidden.
function generatedWriter(spec: GeneratedSpec): NonNullable<CfConfigSurface["write"]> {
  // Bound once, so the closure below does not have to re-narrow the optional on every call.
  const sub = spec.subCollection;
  // The UPDATE body for one live item, and the id it would be addressed by. Extracted so the writer can
  // publish them: the echo harness needs to ask an endpoint whether it accepts one of its OWN items back,
  // and rebuilding this in a harness would test a body the writer never sends, which is a mistake that
  // has now been made twice with the one-object writers.
  const bodyFor = (it: Record<string, unknown>): Record<string, unknown> => {
    const b = normaliseItem({ nestedCollections: spec.nestedCollections, serverId: resolveServerId } as never, it);
    if (spec.idNamesTheItem === true && typeof it.id === "string" && it.id !== "") b.id = it.id;
    return b;
  };
  const serverIdFor = (it: Record<string, unknown>): string => {
    if (spec.keyField !== undefined) {
      const v = it[spec.keyField];
      return typeof v === "string" ? v : "";
    }
    return resolveServerId(it);
  };
  const fn = (api: CfApi, ids: Ids, data: unknown, opts: { dryRun: boolean }, meter?: Meter): Promise<ConfigWriteResult> =>
    writeListSpec({
      listPath: spec.listPath,
      itemPath: spec.itemPath,
      identity: (it) => resolveServerId(it) || preferredKey(it),
      // resolveServerId, not `it.id`. A collection that keys on network_id (device-managed-networks) or
      // sitekey has no `id`, so this returned "" and writeListSpec skipped every changed item with "the
      // live item has no id to update in place": the writer could CREATE but never UPDATE, and the round
      // trip could not see it because a restore after a delete only ever creates. Found by the update leg.
      serverId: serverIdFor,
      // When the id NAMES the item it is the natural key, and a sharper one than preferredKey can build:
      // unique by construction rather than by hope.
      natural: (it) =>
        spec.idNamesTheItem === true && typeof it.id === "string" && it.id !== ""
          ? `${spec.id}:id=${it.id}`
          : `${spec.id}:${preferredKey(it)}`,
      createMethod: spec.createMethod,
      updateMethod: spec.updateMethod,
      ...(spec.nestedCollections !== undefined ? { nestedCollections: spec.nestedCollections } : {}),
      ...(sub !== undefined
        ? { readLive: async (a: CfApi, i: Ids, m?: Meter) => (await listWithSub(spec.listPath, sub.path, sub.field, sub.perPage)(a, i, m)) as unknown[] }
        : {}),
      // normaliseItem, not stripStamped: a nested collection's entries carry their own server-stamped
      // fields, and sending a Gateway list entry's created_at back is at best noise in the request. The
      // customer-chosen id is put back by bodyFor, because stripStamped takes it out as a server field,
      // which is what made the create fail while the update kept working.
      body: bodyFor,
      label: spec.id,
    }, api, ids, data, opts, meter);
  return Object.assign(fn, {
    cfWriteKind: "list" as const,
    cfListItemPath: spec.itemPath,
    cfListUpdateMethod: spec.updateMethod,
    cfListBody: bodyFor,
    cfListServerId: serverIdFor,
    // The WHOLE spec, as data. The four tags above are what the echo harness needs to send one update; this
    // is what a reader needs to know whether a banked restore proof is still a proof of this writer. The
    // natural key is the case that matters: `keyField` is the difference between an update in place and a
    // write over some other object, it is declared per surface precisely because a guess here fails
    // silently, and none of the four tags above carries it.
    cfWriteSpec: spec,
  });
}

// GENERATED_WRITERS maps surface id to its write(), for the registry to attach.
export const GENERATED_WRITERS: ReadonlyMap<string, NonNullable<CfConfigSurface["write"]>> = new Map(
  GENERATED_LIST_WRITERS.map((s) => [s.id, generatedWriter(s)]),
);
