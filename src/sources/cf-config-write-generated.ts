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
// includes it (F10). That is the mechanism that lets the catalogue be complete without the product
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
// REMOVED: `dex-tests`. Its READ was fixed the same day and stays: DEX answers
// `{dex_tests: [...]}` and the plain list reader was archiving the ENVELOPE as the single item, so the
// surface captured one object whose only key was `dex_tests` and a restore had nothing to rebuild from.
// Unwrapping it made the read shape-changing, and the offline structural gate immediately demanded that a
// generated writer for such a surface supply its own matching reader, which this one cannot: the existing
// `subCollection` mechanism wires listWithSub, not listEnvelope.
//
// The writer is removed rather than patched because there is nothing to patch it against. It is unproven,
// its create is refused with `dex.api.parameter.invalid` on both accounts, and DEX is not entitled on the
// free one, so no round trip can exercise it. A writer that can only ever skip is a promise the product
// cannot keep. The surface still captures, which is what a customer actually loses without it.
//
// REMOVED: `rate-limits`. Its READ works and the surface stays in the registry, but the write
// can never succeed for anyone: POST returns 403 code 10037, "ratelimit.api.maintenance_mode. This API is
// in maintenance mode and no longer accepts modifications." The GET carries its own deprecation notice
// (code 10035) while still returning data, so backup is right to keep it and a writer is not. Cloudflare
// directs modifications to the Rulesets API, which we already write. The ledger had recorded this as a
// Free-plan limit, which was wrong in the same way waf-overrides was.

export const PROVEN_WRITE_SURFACES: ReadonlySet<string> = new Set([
  // Proven by flipping zone_defaults.multi_provider. It was unprovable until the writer learnt
  // to diff INTO nested objects: the whole-object PATCH carries the `soa` block on every write, and a Free
  // account refuses it with "Custom SOA records are not available to this account or zone", so the surface
  // read as unwritable over a field nobody was changing. The partial nested body is accepted, and Cloudflare
  // deep-merges it, verified against the live API before the writer was allowed to rely on it.
  "account-dns-settings",
  // Proven through the full singleton round trip, both by a value read out of Cloudflare's
  // published OpenAPI rather than guessed (see test/cf-hand-damage.ts).
  //
  // url-normalization's schema declares a request body for the PUT, with `type` as a two-member enum.
  "url-normalization",
  // Its one configurable field is a rotation interval, a number with a declared range of 21 to 365.
  "access-key-configuration",
  // Proven through the full singleton round trip (flipped multi_provider, confirmed the change
  // took, restored, confirmed the original came back). It was unprovable until writeSingleObject stopped
  // PATCHing the whole object: Cloudflare validates the whole body, so the plan-gated `flatten_all_cnames`
  // on a Free zone refused the entire write and the surface read as unwritable.
  "dns-settings",
  // Proven, same loop (flipped is_ui_read_only). The Zero Trust organisation settings: seat
  // controls, session duration, the login page. Chosen because Access is a family customers configure by
  // hand and then cannot reconstruct from memory.
  "access-organizations",
  // Proven (flipped value). Web Analytics / RUM on a zone. Enabling RUM mints a server-assigned
  // `site_tag`; without excluding it, a restore's diff would carry it back and Cloudflare would answer
  // 10004 malformedParams to the whole request. Adding site_tag to SERVER_STAMPED fixed the surface.
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
  // Proven by matching each writerless idempotent surface against the verb Cloudflare's schema declares
  // for the path it READS, rather than proposing writers by eye.
  "device-policy-default",
  "zone-zero-trust-organization",
  // Proven by test/live-cf-email-routing-prove.ts, which exists because this surface's shape
  // (settings PLUS a rule list behind one id) fits neither the collection prover nor the singleton one.
  // Full loop including the UPDATE path and a convergence pass.
  "email-routing",
  // Hand-written.
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
  // Proven live using a create body synthesised from Cloudflare's own OpenAPI schema rather than
  // hand-written.
  "kv-namespaces-config",
  // Proven live with hand-written create bodies, after the schema-synthesised ones were refused.
  "teamnet-virtual-networks",
  "zone-lockdowns",
  "ua-rules",
  // Proven live after the write path was taught to adapt its page size: writeListSpec listed live state
  // at the registry default and Cloudflare refuses anything above 100 here, so the apply failed before it
  // reached the diff. The create body was correct the whole time.
  "ai-search-namespaces",
  // Proven live. The create needed a CIDR in `targets`; a synthesised body that put a plain string there
  // was the obstacle, not the account's entitlement.
  "magic-bgp-filter-profiles",
  // Proven live after two fixes: its `id` is customer-chosen, so stripStamped removed it and only the
  // CREATE path failed; and `modified_at` was missing from SERVER_STAMPED, so the diff never converged
  // even once the create worked.
  "ai-gateway-gateways",
  // Proven live once writeSingleSetting stopped assuming every zone setting carries its value under
  // `value`. This one carries it under `enabled` and its PATCH refuses {value: ...} outright, so the
  // surface had skipped on every restore, including when nothing had changed.
  "zone-setting-auto-origin-tls-kex",
  // Proven live after three fixes, in the order they had to happen: the READ had to sub-read
  // each list's items (they were never captured), the WRITER had to read live the same way (its own read
  // saw no items at all, so every list looked changed forever), and the nested guard had to refuse an
  // update that would replace the collection. Round trip: created, captured, deleted, restored, converged;
  // and an entry added live that the snapshot lacks is named and refused rather than dropped.
  "gateway-lists",
  // Proven live. It needs no reachable TLS endpoint or matching certificate hash: the item is addressed
  // by `network_id`, not `name`.
  "device-managed-networks",
  // Proven live; not plan-gated. The settings endpoint ECHOES a different id (origin_tls_cmpl) from the
  // one it is requested under (origin_tls_compliance_modes), and probing the echoed id returns "Undefined
  // zone setting", which reads exactly like a missing feature. Cloudflare names the valid values in its
  // own validation message: a list of `fips` and/or `pqh`.
  "zone-setting-origin-tls-compliance",
  // Proven live by writeSingleObject, a writer shape for a surface whose whole body IS the
  // configuration rather than one wrapped in {value} or {enabled}. Each is something a customer configures
  // by hand and would otherwise re-enter from the snapshot by eye.
  "page-shield-settings",
  "gateway-logging",
  "email-routing-catch-all",
  // Proven live by the same writeSingleObject shape. Each is configuration a customer sets by hand.
  "universal-ssl-settings",
  "workers-account-settings",
  "zt-device-settings",
  "zt-connectivity-settings",
  "email-dmarc-reports",
  "ct-alerting",
  "zaraz-config",
  "magic-bgp-settings",
  "origin-tls-client-auth-settings",
  // Proven live. managed-headers keeps its booleans inside an ARRAY, and gateway-configuration two levels
  // down under settings; both are proven.
  "managed-headers",
  "gateway-configuration",
  // Proven live.
  "observability-saved-queries",
  "secondary-dns-acls",
  // Proven live. A WARP Connector id is accepted where a subnet_id was thought required; the account's
  // existing subnets (at /accounts/{id}/zerotrust/subnets, a surface this registry already reads) satisfy
  // it and the loop closes with no internal error.
  "device-ip-profiles",
  // Proven live with Zero Trust enabled on the account. access-tags is the first ID-LESS collection
  // proven: it has no id field at all, and the NAME is the key.
  "access-tags",
  // Proven live by test/live-cf-singleton-prove.ts.
  //
  // Both carry a value that is the string "on"/"off" rather than a boolean, which is Cloudflare's own
  // two-valued vocabulary for those endpoints.
  //
  // tiered-caching's account answers `editable: false`, which the writer already honours by skipping.
  // That is the plan speaking, not a defect.
  "smart-shield",
  "smart-tiered-cache",
  // Proven live. Its value is one of a named set rather than a boolean; the values came from CLOUDFLARE,
  // not from a guess: sending a deliberately invalid value makes the endpoint answer "The value must
  // either be `off`, `supported`".
  //
  // Its setting id echoes `origin_pqe` while the validation message names
  // `origin_post_quantum_encryption`, and neither is the path it is served at; going through the surface's
  // own writer is what gets the real answer.
  "cache-origin-pq-encryption",
  // Proven live, full loop including the update leg. It requires the Magic Network Monitoring config to
  // exist first ("rule can not be added without initial account configuration" is a fact about account
  // STATE, not an entitlement), which is stood up before the loop and torn down after.
  "mnm-rules",
  // Proven live on a paid account, full loop including the update leg. Two fixes were needed: HTTP 204
  // must read as success, not a failure; and the items carry NO id at all
  // ({name, description, url, last_updated, size_bytes}), the name is the path segment, so resolveServerId
  // must resolve it rather than returning "" (which would skip every changed item with "no id to update in
  // place"). Both were invisible on a free-tier account, which allows ZERO custom page assets, so the
  // create was refused before either bug could run.
  "account-custom-page-assets",
  "zone-custom-page-assets",
  // Proven live on a paid account. `action` is an internally tagged enum, {"action": "Block"}, not the
  // bare string a naively synthesised body would carry, and this surface is not Forbidden on a paid
  // account like its DLP siblings.
  //
  // Its update path is NOT exercised: the endpoint accepts a change and does not apply it, so live never
  // differs from the snapshot. Recorded rather than left to look like coverage.
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
// object, which is neither. F9 makes the leftover visible in the diff.
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
  // overwrites it. That is the exact failure the adversarial review removed twelve writers for.
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
// RESTORED: `gateway-lists`, after both reasons it was removed were fixed. Its read now
// sub-reads each list's items (listWithSub), so the snapshot carries the entries rather than just a count,
// and `nestedCollections: ["items"]` makes an update refuse rather than replace the collection when live
// holds entries the snapshot lacks. Without the second, restoring the writer would have reintroduced B3's
// destructive shape one level down.
//
// REMOVED by the adversarial review of this branch, each for a demonstrated reason rather than caution:
// device-posture-rules, healthchecks, smart-shield-healthchecks, gateway-locations, gateway-pac-files,
// access-custom-pages, logs-explorer-datasets, account-logs-explorer-datasets, images-variants,
// dex-rules, firewall-rules and turnstile. Their names are not unique within the collection, or the
// surface cannot round-trip at all, so `preferredKey` cannot identify an item. The engine now REFUSES an
// ambiguous match rather than guessing, so leaving them would have been safe but dishonest: a writer
// that can only ever skip is a promise the product cannot keep.
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
  // "Creates but never updates" is precisely the shape the adversarial review removed twelve writers for,
  // and it fails silently in the worse direction: a restore after a DELETE creates and looks correct,
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
  // Re-added and PROVEN. Both had been removed with "its read output does not carry the field
  // the natural key is built from", and both list outputs plainly carry id AND name, so the stated reason
  // was wrong on its face. observability-saved-queries round-tripped immediately. secondary-dns-acls did
  // not converge until created_time / modified_time joined SERVER_STAMPED: they survived the strip and
  // differed on every read, so the writer re-applied an identical ACL forever. That is what the "duplicates
  // on re-run" symptom actually was, and it is the same defect modified_at caused, one spelling along.
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
// re-run, fail-open per item, and (since F9) a live-only leftover is reported rather than hidden.
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
