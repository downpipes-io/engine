// Part 3 of the Cloudflare configuration surface registry: the OPENAPI-GAP surfaces (the
// coverage sweep). cf-config-registry.ts concatenates core + expanded + this list to form
// CF_CONFIG_SURFACES. See cf-config-registry.ts for the full restoreTier / fail-open contract.
//
// WHY THIS MODULE EXISTS
// ----------------------
// The registry's first 214 surfaces were built against Cloudflare's own tooling surface, so the coverage
// inherited that tooling's boundary rather than the API's. Diffing the registry's 241 endpoints against
// Cloudflare's published OpenAPI (2,017 paths, 3,233 operations, 1,594 GETs across 187 product areas)
// found 71 areas the registry did not touch at all. The existing drift guard could not have caught this:
// it checks that the endpoints we HAVE still exist upstream, and has no opinion about the ones we lack.
//
// Not all 71 are configuration, and this module deliberately does not chase the count. `radar` alone is
// 274 GETs of public internet intelligence, and analytics, findings, scan results, billing and platform
// catalogues are all out of scope by the same boundary that excludes customer content. What is in scope
// is configuration, policy, access rules, routing and grants.
//
// EVERY SURFACE BELOW WAS PROBED LIVE before it was added, against a real Cloudflare account. The probe
// recorded the status, the payload shape and the item count for each endpoint, so
// the ones marked as read-verified returned a real 200 rather than a plausible-looking guess from the
// schema. Six surfaces are included that returned 403 on that account: they are entitlement or
// permission gates, not absent endpoints, and the adapter's fail-open contract turns each into a marker
// on an account that lacks the product while capturing it properly on one that has it. Each is noted.
//
// Endpoints the probe REFUSED and that are therefore deliberately absent: dlp/limits (403 Forbidden),
// dlp/payload_log and dlp/email/account_mapping (404 not found), dlp/data_tag_category_templates (404 no
// route), artifacts/namespaces (403 "Access denied by feature gate"), mnm/config/full (404), images/v1/keys
// (403 not authorised for the service), and the tags collection reads, which require resource_type and
// resource_id query parameters and so are lookups rather than surfaces. Recording the refusals matters as
// much as recording the additions: it stops the same ground being re-researched.

import { writeSingleObject } from "./cf-config-write-settings.ts";
import { type CfConfigSurface, list, listCapped, one } from "./cf-config-core.ts";

export const CF_CONFIG_SURFACES_GAPS: CfConfigSurface[] = [
  // ---- account: Zero Trust DLP. The largest single hole in the old registry, 35 GET ops untouched. ----
  // DLP profiles and entries are hand-authored detection content: losing a custom profile loses the
  // pattern library a security team wrote, and there is no version history behind it.
  { id: "dlp-profiles", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/profiles`) },
  { id: "dlp-profiles-custom", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/profiles/custom`) },
  { id: "dlp-entries", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/entries`) },
  { id: "dlp-data-classes", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/data_classes`) },
  { id: "dlp-datasets", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/dlp/datasets`) }, /* datasets carry uploaded column data; re-create then re-upload */
  { id: "dlp-data-tag-categories", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/data_tag_categories`) },
  { id: "dlp-sensitivity-groups", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/sensitivity_groups`) },
  { id: "dlp-document-fingerprints", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/dlp/document_fingerprints`) }, /* fingerprints are derived from uploaded documents the API never returns */
  { id: "dlp-custom-prompt-topics", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/custom_prompt_topics`) },
  { id: "dlp-email-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dlp/email/rules`) },
  { id: "dlp-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/dlp/settings`), write: writeSingleObject((i) => `/accounts/${i.accountId}/dlp/settings`, "PATCH", "dlp-settings") },

  // ---- account: Zero Trust risk scoring. 403 on a Free account (entitlement), captured on an entitled one. ----
  { id: "zt-risk-scoring-behaviors", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/zt_risk_scoring/behaviors`) },
  { id: "zt-risk-scoring-integrations", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/zt_risk_scoring/integrations`) },

  // ---- account: Cloudflare Tunnel routing and WARP. teamnet is the tunnel route table, which decides
  // which private CIDRs resolve through which tunnel. Losing it silently strips private connectivity. ----
  { id: "teamnet-routes", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/teamnet/routes`) }, /* routes reference tunnel ids, so they restore after the tunnel exists */
  { id: "teamnet-virtual-networks", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/teamnet/virtual_networks`) },
  { id: "warp-connector", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/warp_connector`) }, /* each connector carries a write-only token */

  // ---- account: Cloudflare One and data security ----
  { id: "cloudflare-one-applications", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/one/applications`) },
  { id: "cloudflare-one-integrations", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/one/integrations`) },
  { id: "data-security-posture-webhooks", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/data-security/posture/webhooks`) }, /* webhook targets carry a secret */

  // ---- account: Magic Network Monitoring. Returns a null result until the account is onboarded, which
  // the fail-open contract already handles; on an onboarded account this is the rule set. ----
  { id: "mnm-config", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/mnm/config`) },
  { id: "mnm-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/mnm/rules`) },

  // ---- account: AI Gateway and AI Search. Gateway objects are configuration; billing, usage history and
  // the evaluation-type catalogue are not, and are deliberately excluded. ----
  { id: "ai-gateway-gateways", scope: "account", restoreTier: "idempotent", read: listCapped((i) => `/accounts/${i.accountId}/ai-gateway/gateways`, 100) },
  { id: "ai-gateway-custom-providers", scope: "account", restoreTier: "reprovision", read: listCapped((i) => `/accounts/${i.accountId}/ai-gateway/custom-providers`, 100) }, /* provider credentials are write-only */
  { id: "ai-search-instances", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/ai-search/instances`, 100) },
  { id: "ai-search-namespaces", scope: "account", restoreTier: "idempotent", read: listCapped((i) => `/accounts/${i.accountId}/ai-search/namespaces`, 100) },
  { id: "ai-search-tokens", scope: "account", restoreTier: "reprovision", read: listCapped((i) => `/accounts/${i.accountId}/ai-search/tokens`, 100) }, /* token metadata only; the value is never returned */

  // ---- account: feature flags. A deleted flag cannot be restored and flags gate payment paths. ----
  { id: "flagship-apps", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/flagship/apps`) },

  // ---- account: registrar control layer. Domain lapse or hijack is existential and nobody archives it. ----
  { id: "registrar-domains", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/registrar/domains`) }, /* one(), not list(): the registrar API errors "Page bigger than the number of pages" on page 1 of an EMPTY collection, so paginating it fails precisely on the accounts that have no domains */ /* transfer locks and auth codes are registry state, never replayable by API */
  { id: "registrar-registrations", scope: "account", restoreTier: "reprovision", read: listCapped((i) => `/accounts/${i.accountId}/registrar/registrations`, 50) },

  // ---- account: store and namespace inventories. These are the CONFIGURATION of stores whose CONTENTS
  // the engine already backs up through its own source types, so they complete the picture rather than
  // duplicating it: a namespace's existence, title and binding are not carried by a data-store backup. ----
  { id: "kv-namespaces-config", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/storage/kv/namespaces`) },
  { id: "d1-databases-config", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/d1/database`) },
  { id: "secrets-store-stores", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/secrets_store/stores`, 100) },
  { id: "account-tag-keys", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/tags/keys`) },

  // ---- account: Stream configuration. 403 on this account (the token lacks the Stream permission), and
  // it is configuration rather than media: signing keys, live inputs, watermark profiles and the webhook
  // are all account settings the existing `stream` source type does not carry. ----
  { id: "stream-live-inputs", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/stream/live_inputs`) },
  { id: "stream-watermarks", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/stream/watermarks`) },
  { id: "stream-signing-keys", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/stream/keys`) }, /* signing keys are write-only secrets */
  { id: "stream-webhook", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/stream/webhook`) },

  // ---- account: Images variants. Variant definitions are the resize/format contract a site depends on. ----
  { id: "images-variants", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/images/v1/variants`) },

  // ---- zone: API Shield schema validation. Distinct from the api-shield-* surfaces already registered,
  // which sit under the zone's api_gateway path; these are the uploaded schemas and their settings. ----
  { id: "schema-validation-schemas", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/schema_validation/schemas`) },
  { id: "schema-validation-hosts", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/schema_validation/schemas/hosts`) },
  { id: "schema-validation-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/schema_validation/settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/schema_validation/settings`, "PATCH", "schema-validation-settings") },
  { id: "schema-validation-operations", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/schema_validation/settings/operations`) },
];
