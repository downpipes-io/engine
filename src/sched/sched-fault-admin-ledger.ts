// The ADMIN-EDGE refusal ledgers: the families that record an ANSWER THE EDGE RETURNED to a caller, rather
// than a fault the scheduler hit on its own path. That is the whole reason they are one module.
//
//   adminRefusals    (G146 + G126) the engine-computed refusal the browser showed once and forgot
//   configRejections (G139 + G141) the 400 that reached only the browser
//   authzRefusals    (G187 + G249) the 403 that is audited only when it SUCCEEDS
//   configCoercions  (G297)        the write that was ACCEPTED, then quietly narrowed
//
// Moved verbatim out of./sched-fault-ledger.ts, each family WHOLE: its closed vocabulary, the
// private Set built from that vocabulary, its pure classifier and the recorder that gates on the Set all live
// here. The module boundary is the FAMILY boundary rather than a layer boundary, so a member added without its
// gate is still a compile error, and each gating Set is now unreachable from any other module, which is a
// stronger guarantee than the single file gave. The redaction rule these records are written under is stated
// once, in ./sched-fault-ledger.ts, and binds this file.

// The capability names are the closed PRODUCT vocabulary the authz-refusal gate axis is built from (G187 /
// G249), imported rather than re-listed so a capability added to the product cannot silently fall out of the
// aggregate. identity-rbac.ts is a pure leaf (types + closed sets), so this adds no cycle.
import { ALL_CAPABILITIES } from "../admin/identity-rbac.ts";
import { type FaultCountAgg, type LedgerStorage, bumpCount, writeLedger } from "./sched-fault-core.ts";

// ---- adminRefusals (G146 + G126): the engine-computed refusal the browser showed once and forgot -----
//
// The engine computes a PRECISE refusal (a live-probe verdict, a validator, a guardrail, the only-proven-copy
// orphan guard) and returns it to a toast. Support then cannot see WHICH check fired, HOW OFTEN, or on which
// surface -- including the onboarding-critical ones ("I cannot get past Verify and save", "I cannot remove
// this destination"). This is the generalised bounded ring: a closed ROUTE CLASS x a closed REASON CODE,
// counted. It is deliberately a COUNT map rather than a per-event ring: the customer's question is "which
// check keeps refusing me", which is a rate, and a count map cannot be grown by a retry storm.
export const ADMIN_REFUSAL_ROUTES = [
  // REMOVED: `dest-verify`. THIS LEDGER IS THE DO'S, and the live Verify-and-save PROBE is a network
  // call (probeDestination): the DO does no network I/O, by design, so it never sees a probe verdict and no
  // site in this file can classify one. The refusal is not unrecorded -- it is recorded on the OTHER side of
  // the pair, by the Worker edge that actually ran the probe, as {dest-add, validation} / {dest-add,
  // not-configured}, and a validator refusal at set time lands here already as {dest-set, <closed reason>}. A
  // route class the recording side structurally cannot reach is dead vocabulary, however true the ticket is.
  "dest-set", // a destination create/update was refused by a validator or the probe
  "dest-default", // a set-default was refused
  "dest-remove-guard", // a destination removal was refused (in use, or the only-proven-copy orphan guard)
  "canary-config", // a canary configuration change was refused (a pinned id that names no destination)
  "canary-run", // a "fly now" was refused (the bird is disabled)
  "notify-channel", // a notify channel create/delete was refused
  "drill-evidence", // a drill-evidence append was refused (G097's validation half)
  "rbac-guardrail", // an RBAC mutation was refused by a guardrail (last owner, reserved capability, unknown role)
  "licence", // a licence activation was refused
] as const;
export type AdminRefusalRoute = (typeof ADMIN_REFUSAL_ROUTES)[number];
const ADMIN_REFUSAL_ROUTE_SET: ReadonlySet<string> = new Set(ADMIN_REFUSAL_ROUTES);

// The closed refusal-reason vocabulary, shared across routes (a route only ever uses the members that can
// apply to it). Deliberately CAUSE-shaped, not message-shaped: each member is a distinct operator REMEDY.
export const ADMIN_REFUSAL_REASONS = [
  "unreachable", // the destination endpoint could not be reached at all (DNS/egress/refused)
  "auth-refused", // the destination reached us and rejected the credential (the rotated-key case)
  "write-probe-failed", // the credential authenticated and the write probe was refused (a read-only key, a bucket policy)
  "object-lock-mismatch", // the bucket's Object-Lock/WORM posture does not match what was asked for
  "tls", // a TLS/certificate failure reaching the destination
  "endpoint-not-https", // the submitted endpoint is not an https URL (the pre-probe shape guard)
  "missing-fields", // a required field was absent
  "invalid-config", // the submitted configuration failed a validator for any other reason
  "in-use", // the object cannot be removed because something still references it
  "orphan-guard", // THE DATA-LOSS GUARD: the destination holds the only proven copy of backed-up runs
  "not-found", // the named object does not exist
  "disabled", // the subsystem is switched off (a "fly now" against a disabled canary)
  "guardrail", // a policy guardrail refused (last owner, reserved capability, a lockout-prevention check)
  "shape-rejected", // the submitted body failed its shape validator
  "transport", // the engine could not complete the round trip (a DO/binding availability fault, not a customer fault)
  // --- G235/G251: the notify-channel URL validator's own closed reject codes (additive, disjoint from the
  // destination reasons above; "non-https" maps onto the existing endpoint-not-https, which says exactly that).
  // "I can't save my SIEM/webhook channel" is a common ticket where the customer is stuck in a validation loop
  // the pack was blind to: every rejection was a 400 to the browser and nothing else.
  "userinfo-in-url", // the url carried user:pass@ credentials: a CREDENTIAL in a stored config, refused
  "workers-dev-sink", // the sink is a workers.dev host: refused as a sink (it is almost always a copy-paste of the engine's own URL)
  "internal-sink-no-optin", // the sink resolves to a private/internal address and the per-channel SSRF override was not ticked
  "url-too-long", // the submitted url exceeded the 2048-char bound
  "url-unparseable", // the submitted url could not be parsed at all
] as const;
export type AdminRefusalReason = (typeof ADMIN_REFUSAL_REASONS)[number];
const ADMIN_REFUSAL_REASON_SET: ReadonlySet<string> = new Set(ADMIN_REFUSAL_REASONS);

export function adminRefusalKey(route: AdminRefusalRoute, reason: AdminRefusalReason): string {
  return `${route}|${reason}`;
}

// THE KEY (and a deliberate non-collision). A concurrently-built Worker-edge recorder writes its own
// admin-refusal aggregate under `diag:adminrefusals` with a DIFFERENT composite key format (route:reason).
// The value SHAPE is the same bounded {name -> {count,lastAt}}, so co-writing one record would not corrupt
// either side -- but the two key FORMATS would then mix in one aggregate, and a reader that gates on ONE
// closed vocabulary (as the validate suite does, and must) would be surfacing keys it cannot vouch for.
// So this ledger keeps its OWN key. The two are complementary (the edge records what the ROUTER refused; this
// records what the DO refused) and the pack can carry both; converging them is a plumb-pass decision, not one
// to make by silently sharing a key.
export const ADMIN_REFUSALS_KEY = "diag:schedadminrefusals";
// The key ceiling: routes x reasons is already bounded by the two closed sets, so this is defence in depth.
export const ADMIN_REFUSALS_CAP = 64;

// classifyDestProbeRefusal reduces a destination VERIFY/SAVE refusal to a closed reason. It reads the engine's
// own refusal prose (and the store's sanitised error CODE, which buildDestRecord / the probe already coarsened)
// ONLY to select a member, and RETURNS that member: the endpoint, bucket, credential and the platform's
// verbatim body never leave this function. Ordering is load-bearing: the SPECIFIC probe verdicts are tested
// before the generic invalid-config residual, so "your key is read-only" never coarsens to "invalid config".
export function classifyDestProbeRefusal(e: unknown): AdminRefusalReason {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (/https URL/i.test(m)) return "endpoint-not-https";
  if (/bucket, a region|required|missing/i.test(m)) return "missing-fields";
  if (/AccessDenied|InvalidAccessKey|SignatureDoesNotMatch|ExpiredToken|Unauthorized|Forbidden|403|401/i.test(m)) return "auth-refused";
  if (/ObjectLock|Object Lock|WORM|Retention|LegalHold|Compliance/i.test(m)) return "object-lock-mismatch";
  if (/\bTLS\b|\bSSL\b|certificate|handshake/i.test(m)) return "tls";
  if (/write probe|could not write|PutObject|read-only/i.test(m)) return "write-probe-failed";
  if (/unreachable|fetch failed|ENOTFOUND|ECONNREFUSED|ECONNRESET|DNS|network|timeout|timed out/i.test(m)) return "unreachable";
  if (/only proven copy/i.test(m)) return "orphan-guard";
  if (/in use|still referenced/i.test(m)) return "in-use";
  return "invalid-config";
}

// recordAdminRefusal counts ONE engine-computed refusal by {route, reason}. Both halves are closed-set
// validated at the boundary, so the operator's submitted value, endpoint, URL, key material and the engine's
// free-text reason structurally cannot enter the record.
// webhookRejectReason maps the notify validator's CLOSED webhook-reject code onto the CLOSED admin-refusal
// reason vocabulary (G235/G251). Both halves are closed sets, so the mapping is total and can never widen what
// is recorded: the operator-facing SENTENCE -- which quotes the submitted URL's shape and is free text -- is
// never passed in and can never be stored. PURE, so the validator and the recorder are pinned by one test.
export function webhookRejectReason(code: string): AdminRefusalReason {
  switch (code) {
    case "non-https":
      return "endpoint-not-https";
    case "userinfo":
      return "userinfo-in-url";
    case "workers-dev":
      return "workers-dev-sink";
    case "internal-no-optin":
      return "internal-sink-no-optin";
    case "too-long":
      return "url-too-long";
    case "unparseable":
      return "url-unparseable";
    default:
      // A code outside the closed set (a drifted validator) coarsens to the shape-reject residual rather than
      // riding verbatim: an unknown token must never become a storage key.
      return "shape-rejected";
  }
}

export async function recordAdminRefusal(storage: LedgerStorage, route: AdminRefusalRoute, reason: AdminRefusalReason): Promise<void> {
  if (!ADMIN_REFUSAL_ROUTE_SET.has(route) || !ADMIN_REFUSAL_REASON_SET.has(reason)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, ADMIN_REFUSALS_KEY, "admin-refusal", (prior) => {
    const agg = { ...(prior ?? {}) };
    const key = adminRefusalKey(route, reason);
    if (agg[key] === undefined && Object.keys(agg).length >= ADMIN_REFUSALS_CAP) return agg; // capped: the fleet-wide fact is already made
    return bumpCount(agg, key, at);
  });
}

// ---- configRejections (G139 + G141): the 400 that reached only the browser -----------------------
//
// EVERY rejected configuration write in this DO -- a downpipe upsert, a cron/blackout/retention edit, a
// source binding, a role grant, a group mapping, a custom role, a notify channel/rule, an IdP connection or
// cert rollover, an expiry item, an OTLP/SIEM destination, a coverage inventory, a cf-config mode, a change
// proposal, and the DR-critical break-glass control-plane reconcile/import -- throws a plain Error that
// SchedulerDO.fetch() turns into a 400 { error: <message> }. The message reaches the browser, the operator
// reads it once, and NOTHING is persisted. So "my save will not stick", "12 of my 40 bulk downpipes failed"
// and "the estate import keeps failing during our migration" all have zero remote evidence.
//
// This is the aggregate for that, recorded at the ONE funnel every one of those throws passes through
// (scheduler-do.ts fetch()'s 400 branch), so no site can be missed and no site has to remember to call it.
// The SURFACE comes from the DO's own STATIC route key (`${method} ${pathname}` -- the DO's routes carry no
// path ids; every id rides in the body or query), which is engine-owned vocabulary, never customer data. The
// REASON is selected by a classifier that READS the validator's message and RETURNS a closed member: the
// message itself -- which quotes the submitted cron string, bucket name, URL, email or account id -- is
// discarded at that boundary and can never be stored.
//
// `reserved-binding` is deliberately its own reason (G139): a source binding naming SIGNER_PRIVATE (or any
// other engine-reserved binding) is a CONFUSED-DEPUTY attempt, and it must never be indistinguishable from a
// typo in the aggregate support reads.
export const CONFIG_SURFACES = [
  // --- downpipe + schedule (G139) ---
  "downpipe-config", // POST /downpipes: the upsert (id/name/cadence/enabled/source/destination shapes)
  "bulk-downpipe", // POST /downpipes/bulk: the N-at-once create ("12 of my 40 failed and I cannot see why")
  "downpipe-delete", // POST /delete
  "cf-config-mode", // POST /cf-config/mode: the capture-mode enum
  // --- account-wide source config (G139) ---
  "discovery-token", // POST /sources/discovery-token
  "discovery-accounts", // POST /sources/discovery-accounts
  "discovery-sources", // POST /sources/enable
  // --- destinations (G139) ---
  "destination-set", // POST /destinations / POST /dest-config
  "destination-remove", // POST /destinations/remove (incl. the only-proven-copy orphan guard)
  "destination-default", // POST /destinations/default
  "canary-config", // POST /canary/config
  // --- alerting + observability (G139/G141) ---
  "notify-channel", // POST /notify/channel
  "notify-rule", // POST /notify/rules
  "otlp-destination", // POST /otlp-push
  "siem-destination", // POST /push
  // --- identity (G139/G140/G141) ---
  "idp-connection", // POST /idp/conn/create | /idp/conn/enabled | /idp/conn/delete
  "idp-cert-rollover", // POST /idp/conn/cert: THE ONE THAT EXPIRES TOMORROW
  "role-write", // POST /roles
  "group-mapping", // POST /group-roles
  "custom-role", // POST /custom-roles
  "session", // the session/step-up write routes
  // --- governance (G139/G141) ---
  "expiry-item", // POST /expiry
  "change-propose", // POST /config/changes/* + the change-control gate
  "restore-approval", // POST /restore/*
  "posture-override", // POST /posture/accept | /posture/unaccept
  "coverage-inventory", // POST /coverage/inventory
  "fleet-drill", // POST /fleet-drill/start
  "licence", // POST /licence
  // --- the DR-critical break-glass path (G141): a failed reconcile/import wrote NOTHING at all ---
  "cp-reconcile", // POST /control-plane/reconcile
  "cp-import", // POST /control-plane/import
  "cp-stage-apply", // POST /control-plane/stage | /control-plane/apply-staged | /control-plane/resume-apply
  // The residual. A 400 on a route this vocabulary does not name is COUNTED, never dropped: a silent drop
  // here would rebuild the very blind spot this ledger exists to remove.
  "other",
] as const;
export type ConfigSurface = (typeof CONFIG_SURFACES)[number];
const CONFIG_SURFACE_SET: ReadonlySet<string> = new Set(CONFIG_SURFACES);

// The closed reject-reason vocabulary. Deliberately CAUSE-shaped (each member is a distinct operator remedy),
// and shared across surfaces (a surface only ever uses the members that can apply to it).
export const CONFIG_REJECT_REASONS = [
  "reserved-binding", // SECURITY-SIGNIFICANT (G139): a source binding named an engine-reserved binding (SIGNER_PRIVATE, a destination credential). Never a typo; never coarsened into one.
  "id-shape", // the id failed its charset/length bound
  "name-shape", // the name failed its length bound
  "cadence-bounds", // cadenceSeconds below the floor / not an integer
  "restore-cadence-bounds", // restoreTestCadenceSeconds below the floor ("restore tests were never actually configured")
  "cron-invalid", // schedule.cron did not parse (the field-named cron reason)
  "timezone-invalid", // schedule.timeZone is not a known IANA zone
  "blackout-window-invalid", // a blackout window's shape/bounds
  "retention-bounds", // retention.keepRuns / keepDays out of bounds, or an empty policy
  "destination-shape", // a destinationId / destinationIds shape failure
  "destination-unknown", // a pinned destination id names no live destination
  "destination-cap", // the fan-out list exceeds the per-downpipe cap
  "source-type-unknown", // source.type is not one of the nine
  "source-binding-invalid", // a binding failed its charset bound (NOT reserved: that is reserved-binding)
  "source-list-empty", // a secrets source with no secrets
  "source-cap", // a source list exceeded its cap
  "discovery-scope", // the cross-account confused-deputy guard: the accountId is not discovery-selected
  "token-shape", // a submitted token did not look like a Cloudflare API token
  "endpoint-not-https", // the submitted endpoint is not https
  "url-invalid", // a submitted URL failed the webhook/channel validator
  "unknown-role", // the named built-in role does not exist
  "unknown-custom-role", // the named custom role does not exist
  "unknown-check-id", // the posture check id is not a real check
  "email-shape", // the submitted email is not a valid lowercased address
  "missing-field", // a required field was absent
  "not-found", // the named object does not exist
  "in-use", // the object cannot be removed because something references it
  "orphan-guard", // THE DATA-LOSS GUARD: the destination holds the only proven copy
  "already-active", // the operation is already running
  "over-cap", // the request exceeds an engine cap
  "duplicate", // the object already exists
  "precondition", // a state precondition failed (no discovery token set, no destination, gate not armed)
  "shape-rejected", // the body failed a shape validator with no more specific class
  "body-unparseable", // the body was not parseable JSON (a SyntaxError through the same 400 funnel)
  "other", // the residual: counted, never dropped
] as const;
export type ConfigRejectReason = (typeof CONFIG_REJECT_REASONS)[number];
const CONFIG_REJECT_REASON_SET: ReadonlySet<string> = new Set(CONFIG_REJECT_REASONS);

export const CONFIG_REJECTIONS_KEY = "diag:configrejections";
// surfaces x reasons is bounded by the two closed sets; the cap is defence in depth.
export const CONFIG_REJECTIONS_CAP = 160;

export function configRejectionKey(surface: ConfigSurface, reason: ConfigRejectReason): string {
  return `${surface}|${reason}`;
}

// classifyConfigSurface maps the DO's OWN static route key onto a closed surface. PURE. The DO's routes are
// literal switch cases (`POST /downpipes`, `POST /idp/conn/cert`, ...) with no path parameters, so the
// pathname is engine-owned vocabulary; an unrecognised path returns "other" and is still counted. Nothing
// derived from the caller's body, query or headers is ever read here.
export function classifyConfigSurface(method: string, pathname: string): ConfigSurface {
  const p = pathname;
  if (p === "/downpipes/bulk") return "bulk-downpipe";
  if (p === "/downpipes") return "downpipe-config";
  if (p === "/delete") return "downpipe-delete";
  if (p === "/cf-config/mode") return "cf-config-mode";
  if (p === "/sources/discovery-token") return "discovery-token";
  if (p === "/sources/discovery-accounts") return "discovery-accounts";
  if (p === "/sources/enable") return "discovery-sources";
  if (p === "/destinations/remove") return "destination-remove";
  if (p === "/destinations/default") return "destination-default";
  if (p === "/destinations" || p === "/dest-config") return "destination-set";
  if (p.startsWith("/canary")) return "canary-config";
  if (p.startsWith("/notify/rule")) return "notify-rule";
  if (p.startsWith("/notify/")) return "notify-channel";
  if (p.startsWith("/otlp-push")) return "otlp-destination";
  if (p === "/push" || p.startsWith("/push/") || p === "/push-config") return "siem-destination";
  if (p === "/idp/conn/cert") return "idp-cert-rollover";
  if (p.startsWith("/idp/conn/")) return "idp-connection";
  if (p === "/roles" || p === "/roles/delete") return "role-write";
  if (p === "/group-roles" || p === "/group-roles/delete") return "group-mapping";
  if (p.startsWith("/custom-roles")) return "custom-role";
  if (p.startsWith("/passkey/session") || p.startsWith("/stepup/") || p === "/signin-context") return "session";
  if (p.startsWith("/expiry")) return "expiry-item";
  if (p.startsWith("/config/changes") || p.startsWith("/change-control") || p === "/config/approval-policy" || p === "/config/change-number-policy") return "change-propose";
  if (p.startsWith("/restore/")) return "restore-approval";
  if (p.startsWith("/posture")) return "posture-override";
  if (p.startsWith("/coverage")) return "coverage-inventory";
  if (p.startsWith("/fleet-drill")) return "fleet-drill";
  if (p === "/licence" || p.startsWith("/licence")) return "licence";
  if (p === "/control-plane/reconcile") return "cp-reconcile";
  if (p === "/control-plane/import") return "cp-import";
  if (p.startsWith("/control-plane/")) return "cp-stage-apply";
  void method; // the surface is path-determined; the method is not needed to select it (kept for future splits)
  return "other";
}

// classifyConfigReject READS the validator's own message ONLY to SELECT a closed reason, and RETURNS that
// reason. The message is the ONE place a submitted value can appear (it quotes the cron string, the bucket,
// the account id, the URL, the role name), so it is consumed here and DISCARDED: nothing derived from it is
// returned or stored. Ordering is load-bearing -- the SECURITY-significant reserved-binding test runs FIRST
// so it can never coarsen into source-binding-invalid, and the specific validator classes are tested before
// the generic shape residual.
export function classifyConfigReject(e: unknown): ConfigRejectReason {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (m === "") return "other";
  // 1. The confused-deputy attempt, always first.
  if (/reserved binding|RESERVED_BINDINGS|SIGNER_PRIVATE|reserved engine binding/i.test(m)) return "reserved-binding";
  // 2. A JSON body that never parsed (a SyntaxError riding the same 400 funnel).
  if (e instanceof SyntaxError || /Unexpected token|JSON at position|is not valid JSON/i.test(m)) return "body-unparseable";
  // 3. The named validators, specific first.
  if (/discovery-selected|not one of the discovery/i.test(m)) return "discovery-scope";
  if (/only proven copy/i.test(m)) return "orphan-guard";
  if (/Cloudflare API token/i.test(m)) return "token-shape";
  if (/cron/i.test(m)) return "cron-invalid";
  if (/timeZone|time zone|IANA/i.test(m)) return "timezone-invalid";
  if (/blackout/i.test(m)) return "blackout-window-invalid";
  if (/retention\./i.test(m) || /retention requires|retention must/i.test(m)) return "retention-bounds";
  if (/restoreTestCadenceSeconds/i.test(m)) return "restore-cadence-bounds";
  if (/cadenceSeconds/i.test(m)) return "cadence-bounds";
  if (/destinationIds must not exceed|must not exceed .* entries/i.test(m)) return "destination-cap";
  if (/destination.*(not found|does not exist|unknown|no longer exists|names no)/i.test(m)) return "destination-unknown";
  if (/destinationIds?|archive destination/i.test(m)) return "destination-shape";
  if (/source\.type/i.test(m)) return "source-type-unknown";
  if (/non-empty secrets list|needs a non-empty/i.test(m)) return "source-list-empty";
  if (/must not exceed .* secrets|exceed .* (entries|items|sources)/i.test(m)) return "source-cap";
  if (/binding/i.test(m)) return "source-binding-invalid";
  if (/https URL|must be https/i.test(m)) return "endpoint-not-https";
  if (/\burl\b/i.test(m)) return "url-invalid";
  if (/valid lowercased address|must be a valid.*email/i.test(m)) return "email-shape";
  if (/unknown custom role|customRole must name/i.test(m)) return "unknown-custom-role";
  if (/role must be viewer|must be a built-in role/i.test(m)) return "unknown-role";
  if (/known posture check id|checkId must/i.test(m)) return "unknown-check-id";
  if (/downpipe id must|id must be 1 to/i.test(m)) return "id-shape";
  if (/name must be/i.test(m)) return "name-shape";
  if (/already (exists|active|running|in flight)/i.test(m)) return "duplicate";
  if (/already|in progress/i.test(m)) return "already-active";
  if (/in use|still referenced/i.test(m)) return "in-use";
  if (/not found|does not exist|unknown /i.test(m)) return "not-found";
  if (/exceed|too many|cap\b|limit/i.test(m)) return "over-cap";
  if (/no discovery token is set|connect your account first|first\b.*then|not configured|requires/i.test(m)) return "precondition";
  if (/required|must be|needs a|choose at least|cannot list any/i.test(m)) return "missing-field";
  return "shape-rejected";
}

// recordConfigRejection counts ONE refused configuration write by {surface, reason}. Both halves are
// closed-set validated at the boundary, so no caller-derived string can become a storage key and the
// submitted value structurally cannot enter the record.
export async function recordConfigRejection(storage: LedgerStorage, surface: ConfigSurface, reason: ConfigRejectReason): Promise<void> {
  if (!CONFIG_SURFACE_SET.has(surface) || !CONFIG_REJECT_REASON_SET.has(reason)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, CONFIG_REJECTIONS_KEY, "config-rejection", (prior) => {
    const agg = { ...(prior ?? {}) };
    const key = configRejectionKey(surface, reason);
    if (agg[key] === undefined && Object.keys(agg).length >= CONFIG_REJECTIONS_CAP) return agg; // capped: the fleet-wide fact is already made
    return bumpCount(agg, key, at);
  });
}

// ---- authzRefusals (G187 + G249): the 403 that is audited only when it SUCCEEDS ------------------
//
// The audit chain records COMMITTED mutations. A refusal commits nothing, so it is audited nowhere, and the
// DO's single AuthError funnel returns a deliberately bare "forbidden" (anti-enumeration) while the gate name
// goes to Workers Logs the vendor structurally cannot pull. Result: "everything I click says forbidden since
// the role change" is unanswerable from the pack, and so is its forensic twin -- "did our access-admin try to
// self-elevate, terminate the Owner's sessions or wipe production?".
//
// The gate vocabulary is the CAPABILITY names (a closed PRODUCT vocabulary, never operator data) plus the
// named guards. Counts + lastAt only: no caller email, no subject, no IP, no per-refusal rows -- so the
// anti-enumeration posture of the HTTP response is preserved exactly (the record is readable only by the
// account's own owner, in their own pack).
export const AUTHZ_GUARD_GATES = [
  "owner-only", // a role !== owner refusal on an owner-exclusive route
  "last-owner-guard", // the guard that stops the last Owner being removed/demoted
  "owner-escalation-guard", // only an Owner may grant or remove the owner role
  "grant-over-authority", // the no-escalation guard: cannot grant a capability you do not hold
  "group-to-owner", // a group may never be mapped to owner
  "break-glass-required", // the route requires the break-glass token and the caller was not it (control-plane reconcile)
  "break-glass-forbidden", // the route REFUSES the break-glass token and requires an authenticated Owner (estate import)
  "dual-control-owner", // an owner-action approve/execute/reject refused for a non-Owner
  "support-credential-owner-only", // minting/clearing a support ingest credential is Owner-only
  // REMOVED: `posture-riskaccept-refused`. The gate it named is real and its refusals ARE counted --
  // as the capability `posture.riskaccept`. requirePostureRiskAccept throws the standard capability AuthError
  // ("forbidden: posture.riskaccept capability required"), and classifyAuthzGate's capability arm (which runs
  // over ALL_CAPABILITIES, before every named-guard arm) matches it first and always. So this member was an
  // ALIAS for a gate that already has a live producer, and the only way to write the alias would have been to
  // break the capability arm that correctly claims it. Two names for one refusal split its count in half.
  //
  // Some guards throw a PLAIN Error and answer 400 rather than raising an AuthError, so they never reach this
  // ledger through the funnel below. `last-owner-guard` and the two guards after it are recorded directly at
  // their own call site instead, where WHICH GUARD FIRED is known as a fact rather than inferred from a status.
  // The HTTP answer is unchanged (still a 400 carrying the guard's own sentence to the operator): only the
  // closed counter is new, and no email, subject, credential id or role name has a field to travel in.
  "last-passkey-guard", // refusing to revoke the LAST passkey of the SOLE Owner (a lock-out guard, not a shape refusal)
  "first-party-session-required", // terminate-others on a caller who HOLDS a cookie session and the engine still found none
  "unclassified", // the residual: an AuthError whose message matched no gate. COUNTED, never dropped.
] as const;
// The full closed gate vocabulary = every capability name + every named guard. Built from ALL_CAPABILITIES so
// a capability added to the product cannot silently fall out of this aggregate.
export const AUTHZ_GATES: readonly string[] = [...ALL_CAPABILITIES, ...AUTHZ_GUARD_GATES];
const AUTHZ_GATE_SET: ReadonlySet<string> = new Set(AUTHZ_GATES);

export const AUTHZ_REFUSALS_KEY = "diag:authzrefusals";
export const AUTHZ_REFUSALS_CAP = 64;

// classifyAuthzGate READS an AuthError's internal detail ONLY to SELECT a closed gate, and RETURNS that gate.
// The detail is the ONE place a role/capability name is spelled out; it is consumed here and discarded, and
// the caller's identity was never in it to begin with. A message matching no gate counts as "unclassified"
// rather than riding verbatim: an unknown token must never become a storage key.
export function classifyAuthzGate(e: unknown): string {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (m === "") return "unclassified";
  // The capability gates: `forbidden: <cap> capability required` and the grant-over-authority variant, which
  // also NAMES a capability but is a DIFFERENT guard (it must not read as a plain capability refusal).
  if (/cannot grant a role conferring/i.test(m)) return "grant-over-authority";
  for (const cap of ALL_CAPABILITIES) {
    if (m.includes(`${cap} capability`)) return cap;
  }
  if (/group cannot be mapped to owner/i.test(m)) return "group-to-owner";
  if (/grant or remove the owner role/i.test(m)) return "owner-escalation-guard";
  // The last-passkey guard is tested BEFORE the last-Owner one: its sentence names the sole Owner too ("cannot
  // revoke the last passkey of the sole Owner"), so the broader last-owner pattern would swallow it and file a
  // lock-out guard as a role-removal guard. Ordering is the discrimination here. Both guards ALSO record
  // directly at their own site (they throw plain Errors and never reach this funnel); this arm is defence in
  // depth for the day one of them is converted to an AuthError.
  if (/last passkey/i.test(m)) return "last-passkey-guard";
  if (/last owner|final owner|sole owner|only remaining owner/i.test(m)) return "last-owner-guard";
  if (/requires the break-glass token/i.test(m)) return "break-glass-required";
  if (/not the break-glass token|requires an authenticated Owner/i.test(m)) return "break-glass-forbidden";
  if (/support credentials require the owner/i.test(m)) return "support-credential-owner-only";
  if (/owner action|owner-action|high-blast-radius/i.test(m)) return "dual-control-owner";
  if (/only an Owner|owner role|role !== owner/i.test(m)) return "owner-only";
  return "unclassified";
}

// recordAuthzRefusal counts ONE authorisation refusal by its closed gate. Out-of-vocabulary gates are
// DROPPED (defence in depth: no caller-derived string can ever add a key).
export async function recordAuthzRefusal(storage: LedgerStorage, gate: string): Promise<void> {
  if (!AUTHZ_GATE_SET.has(gate)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, AUTHZ_REFUSALS_KEY, "authz-refusal", (prior) => {
    const agg = { ...(prior ?? {}) };
    if (agg[gate] === undefined && Object.keys(agg).length >= AUTHZ_REFUSALS_CAP) return agg;
    return bumpCount(agg, gate, at);
  });
}

// ---- configCoercions (G297): the write that was ACCEPTED, then quietly narrowed ------------------
//
// The worst class of config bug: the write returns 200, the audit records success, and part of what the
// operator submitted was silently DROPPED. "I selected three accounts and only two show up" (an id filtered
// out), "account X is in my org but Downpipes refuses it" (the 101st account past the truncation cap), "we
// configured WORM and it shows nothing" (a malformed optional field dropped fail-safe), "we rotated the
// Datadog key but the engine kept pushing with the old one" (the keep-secret path silently retained the
// prior sealed secret). None of it was recorded, because the write SUCCEEDED.
//
// Counts of DROPPED ITEMS + a closed drop class. Never the dropped account id, source-type token or value.
export const CONFIG_COERCION_SURFACES = [
  "discovery-accounts-seen", // setDiscoveryToken: accountsSeen truncated at 100 / entries without a usable id
  "discovery-selected", // setDiscoveryAccounts: a selected id that is not in accountsSeen, and the engineAccountId coerced to null
  // REMOVED: "discovery-sources" is retired. setEnabledSources now REFUSES an unknown source type rather
  // than silently dropping it, so nothing can write this member any more; reintroducing it would restore the
  // silent-drop behaviour this ledger exists to prevent.
  "destination", // buildDestRecord: a malformed optional (worm / objectLock / assumeRole / addressing / storageClass) dropped, or a pricing rate coerced to 0
  "otlp-destination", // setOtlpPushDestination: an absent/unusable auth header value KEPT THE PRIOR SECRET
] as const;
export type ConfigCoercionSurface = (typeof CONFIG_COERCION_SURFACES)[number];
const CONFIG_COERCION_SURFACE_SET: ReadonlySet<string> = new Set(CONFIG_COERCION_SURFACES);

export const CONFIG_DROP_CLASSES = [
  "truncated-over-cap", // the submitted list was longer than the cap and the tail was cut
  "unknown-id", // an id the engine could not resolve was filtered out
  // REMOVED (dead-vocab gate): "unknown-source-type" was paired only with the now-removed
  // "discovery-sources" surface above; see that comment for why the pairing can never fire any more.
  "invalid-optional-field", // a malformed optional field was dropped fail-safe (no false protection)
  "malformed-secret-kept-prior", // a secret was not usable, so the PRIOR sealed secret stayed live
  "coerced-zero", // a non-finite/negative numeric rate was coerced to 0
] as const;
export type ConfigDropClass = (typeof CONFIG_DROP_CLASSES)[number];
const CONFIG_DROP_CLASS_SET: ReadonlySet<string> = new Set(CONFIG_DROP_CLASSES);

export const CONFIG_COERCIONS_KEY = "diag:configcoercions";

export function configCoercionKey(surface: ConfigCoercionSurface, cls: ConfigDropClass): string {
  return `${surface}|${cls}`;
}

// recordConfigCoercion adds `dropped` (the NUMBER of items narrowed away, clamped) to the {surface, class}
// tally. A zero/negative count is a no-op, so the happy path (nothing dropped) never writes.
export async function recordConfigCoercion(storage: LedgerStorage, surface: ConfigCoercionSurface, cls: ConfigDropClass, dropped = 1): Promise<void> {
  if (!CONFIG_COERCION_SURFACE_SET.has(surface) || !CONFIG_DROP_CLASS_SET.has(cls)) return;
  const n = Number.isFinite(dropped) ? Math.floor(dropped) : 0;
  if (n <= 0) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, CONFIG_COERCIONS_KEY, "config-coercion", (prior) => bumpCount(prior ?? {}, configCoercionKey(surface, cls), at, n));
}

// destCoercionClasses is the PURE detector for what buildDestRecord will silently narrow away in a
// destination submission: each malformed OPTIONAL field it drops fail-safe, and each pricing rate
// validateDestPricing coerces to 0. It reads the submitted object's SHAPE only and returns closed classes;
// the endpoint, bucket, credential and every submitted value stay inside the caller. Pure, so the drop
// detection and the validators it mirrors are pinned by one test.
export function destCoercionClasses(config: unknown): ConfigDropClass[] {
  const out: ConfigDropClass[] = [];
  if (typeof config !== "object" || config === null) return out;
  const c = config as Record<string, unknown>;
  // A PRESENT-but-unusable optional is dropped by buildDestRecord (validateWormPolicyValue /
  // validateAssumeRolePolicy / validateAddressing / validateStorageClass all return null/undefined on a
  // malformed value, and objectLock is accepted only as one of three literals). Presence + non-object /
  // out-of-enum is the observable; the VALUE never leaves this function.
  const objectish = (v: unknown) => typeof v === "object" && v !== null && !Array.isArray(v);
  if (c.worm !== undefined && !objectish(c.worm)) out.push("invalid-optional-field");
  if (c.assumeRole !== undefined && !objectish(c.assumeRole)) out.push("invalid-optional-field");
  if (c.objectLock !== undefined && c.objectLock !== "enforced" && c.objectLock !== "not-enforced" && c.objectLock !== "unknown") out.push("invalid-optional-field");
  if (c.addressing !== undefined && c.addressing !== "path" && c.addressing !== "virtual") out.push("invalid-optional-field");
  if (c.storageClass !== undefined && typeof c.storageClass !== "string") out.push("invalid-optional-field");
  // validateDestPricing coerces a negative / NaN / non-numeric rate to 0, which silently understates a cost
  // estimate rather than refusing the save ("our cost projection is nonsense").
  if (objectish(c.pricing)) {
    const p = c.pricing as Record<string, unknown>;
    for (const k of ["storagePerGBMonth", "classAPerMillion", "classBPerMillion", "egressPerGB"]) {
      const v = p[k];
      if (v !== undefined && !(typeof v === "number" && Number.isFinite(v) && v >= 0)) {
        out.push("coerced-zero");
        break;
      }
    }
  }
  return out;
}

