// Part 4 of the Cloudflare configuration surface registry: the OPENAPI-GAP DEPTH sweep.
// Part 3 (cf-config-registry-gaps.ts) closed product areas the registry did not touch AT ALL. This module
// closes the second, less visible gap: areas the registry DID touch, but only shallowly. Having one
// endpoint in an area made the coverage look complete when it was not. Magic Transit had 64 GET
// operations against our 11, Access 53 against 13, Workers 45 against 8, Gateway 26 against 7.
//
// Same discipline as part 3: every surface here was PROBED LIVE against a real Cloudflare account
// before being registered, and endpoints the probe refused are recorded rather than silently
// dropped. Catalogues are excluded by the same scope boundary as before, and there are a lot of them in
// this sweep: gateway/app_types (1,575 entries), tokens/permission_groups (379),
// iam/permission_groups (100), gateway/categories (34), alerting available_alerts (27),
// resource-library (25), data-security finding_types (50) and every */regions endpoint are Cloudflare's
// own reference data, identical for every customer, and backing them up would inflate the surface count
// while protecting nothing.
//
// THE FINDING THAT JUSTIFIES HALF THIS MODULE
// -------------------------------------------
// The shipped `zone-settings` surface reads the AGGREGATE /zones/{id}/settings endpoint, which returned
// 56 settings when probed. Ten settings that exist as their own endpoints are NOT in that
// aggregate, verified by listing the aggregate's ids and checking each: aegis, auto_origin_tls_kex,
// csam_scanner_third_party, fonts, origin_h2_max_streams, origin_max_http_version,
// origin_tls_compliance_modes, speed_brain, ssl_automatic_mode and zaraz. Cloudflare adds newer settings
// at their own paths without backfilling the aggregate, so a customer who has configured any of them has
// been silently unprotected. Each is registered individually below.
//
// Refused by the probe and therefore absent, with Cloudflare's own reason: 50 endpoints returned 403 as
// an entitlement or permission gate on a Free account, and 53 returned 4xx for a missing required query
// parameter or because the product is not enabled. The ones that are genuinely configuration and merely
// gated are included anyway, because the adapter's fail-open contract renders them as markers rather
// than errors on an account without the product.

import { expandIds, list, listCapped, one, type CfConfigSurface } from "./cf-config-core.ts";
// Write-back for the single-setting shape. `zaraz/default` is GET-only in Cloudflare's schema and so
// keeps NO writer: a surface with no writer is honest, a surface with a wrong writer is a liability.
import { writeSingleObject, writeSingleSetting } from "./cf-config-write-settings.ts";

export const CF_CONFIG_SURFACES_GAPS2: CfConfigSurface[] = [
  // ---- zone settings that the aggregate endpoint does not return. See the header. ----
  { id: "zone-setting-aegis", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/aegis`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/aegis`, "aegis") },
  { id: "zone-setting-auto-origin-tls-kex", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/auto_origin_tls_kex`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/auto_origin_tls_kex`, "auto_origin_tls_kex") },
  { id: "zone-setting-csam-scanner", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/csam_scanner_third_party`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/csam_scanner_third_party`, "csam_scanner_third_party") },
  { id: "zone-setting-fonts", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/fonts`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/fonts`, "fonts") },
  { id: "zone-setting-origin-h2-max-streams", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/origin_h2_max_streams`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/origin_h2_max_streams`, "origin_h2_max_streams") },
  { id: "zone-setting-origin-max-http-version", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/origin_max_http_version`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/origin_max_http_version`, "origin_max_http_version") },
  { id: "zone-setting-origin-tls-compliance", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/origin_tls_compliance_modes`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/origin_tls_compliance_modes`, "origin_tls_compliance_modes") },
  { id: "zone-setting-speed-brain", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/speed_brain`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/speed_brain`, "speed_brain") },
  { id: "zone-setting-ssl-automatic-mode", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/ssl_automatic_mode`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/ssl_automatic_mode`, "ssl_automatic_mode") },
  { id: "zone-setting-zaraz-default", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/zaraz/default`) },

  // ---- account: Magic Transit and Magic WAN. 64 provider GET ops against 11 registered surfaces. This
  // is enterprise network fabric: tunnels, routes, interconnects and BGP policy. ----
  { id: "magic-gre-tunnels", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/magic/gre_tunnels`) }, /* tunnel health-check secrets are write-only */
  { id: "magic-ipsec-tunnels", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/magic/ipsec_tunnels`) }, /* pre-shared keys are write-only */
  { id: "magic-static-routes", scope: "account", restoreTier: "ordered", read: one((i) => `/accounts/${i.accountId}/magic/routes`) },
  { id: "magic-cf-interconnects", scope: "account", restoreTier: "ordered", read: one((i) => `/accounts/${i.accountId}/magic/cf_interconnects`) },
  { id: "magic-cf1-sites", scope: "account", restoreTier: "ordered", read: one((i) => `/accounts/${i.accountId}/magic/cf1_sites`) },
  { id: "magic-bgp-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/magic/bgp/settings`), write: writeSingleObject((i) => `/accounts/${i.accountId}/magic/bgp/settings`, "PUT", "magic-bgp-settings") },
  { id: "magic-bgp-filter-profiles", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/bgp/filter_profiles`) },

  // ---- account: WARP device policy. The split-tunnel and fallback-domain lists decide what traffic
  // leaves the tunnel at all. A wrong restore here is a routing outage, hence the ordered tier. ----
  { id: "device-policy-default", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/devices/policy`), write: writeSingleObject((i) => `/accounts/${i.accountId}/devices/policy`, "PATCH", "device-policy-default", {
    // Cloudflare refuses each of these in turn if it is echoed back on write: policy_id/default/
    // gateway_unique_id are server-assigned, the DEFAULT policy is always enabled so `enabled` cannot be
    // set on it, and fallback_domains is a separate sub-resource with its own surface and its own endpoint.
    alsoStrip: ["policy_id", "default", "gateway_unique_id", "enabled", "fallback_domains"],
  }) },
  { id: "device-policy-split-tunnel-exclude", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/devices/policy/exclude`) },
  { id: "device-policy-split-tunnel-include", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/devices/policy/include`) },
  { id: "device-policy-fallback-domains", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/devices/policy/fallback_domains`) },

  // ---- account: Gateway depth. 26 provider GET ops against 7 registered. ----
  { id: "gateway-audit-ssh-settings", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/gateway/audit_ssh_settings`) }, /* carries an SSH CA key pair */
  { id: "gateway-certificates", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/gateway/certificates`) },
  { id: "gateway-custom-certificate", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/gateway/configuration/custom_certificate`) },
  { id: "gateway-egress-cidr-pairs", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/gateway/egress_cidr_pairs`) },

  // ---- account: Zero Trust private network routing ----
  { id: "zerotrust-subnets", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/zerotrust/subnets`) },
  { id: "zerotrust-hostname-routes", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/zerotrust/routes/hostname`) },

  // ---- account: threat-intel content the CUSTOMER authors (feeds and IP lists), as opposed to
  // Cloudflare's own intelligence, which is excluded. ----
  { id: "intel-indicator-feeds", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/intel/indicator-feeds`) },
  { id: "intel-ip-lists", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/intel/ip-lists`) },

  // ---- account: addressing (BYOIP) ----
  { id: "addressing-leases", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/addressing/leases`) },
  { id: "addressing-services", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/addressing/services`) },

  // ---- account: email routing and sending ----
  { id: "account-email-routing-rules", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/email/routing/rules`) },
  { id: "account-email-sending-suppressions", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email/sending/suppressions`) },

  // ---- account: Workers observability and remaining account objects ----
  { id: "workers-observability-destinations", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/workers/observability/destinations`) }, /* destination credentials are write-only */
  { id: "workers-observability-metricsexport", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/workers/observability/metricsexport`) },
  { id: "account-load-balancers", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/load_balancers`) },
  { id: "account-waiting-rooms", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/waiting_rooms`) },
  { id: "account-custom-page-assets", scope: "account", restoreTier: "idempotent", read: listCapped((i) => `/accounts/${i.accountId}/custom_pages/assets`, 200) },
  { id: "browser-extension-config", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/browser-extension/config`) },
  { id: "vectorize-indexes-config", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/vectorize/indexes`) },
  { id: "vuln-scanner-credential-sets", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/vuln_scanner/credential_sets`) }, /* scanner credentials are write-only */
  { id: "rum-site-info", scope: "account", restoreTier: "idempotent", read: expandIds((i) => `/accounts/${i.accountId}/rum/site_info/site_tag/list`, (i, tag) => `/accounts/${i.accountId}/rum/site_info/${tag}`) },

  // ---- zone: API Shield depth. 16 provider GET ops against a thin registration. ----
  { id: "api-gateway-labels", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/api_gateway/labels`) },
  { id: "api-gateway-schemas", scope: "zone", restoreTier: "ordered", read: one((i) => `/zones/${i.zoneId}/api_gateway/schemas`) },
  { id: "api-gateway-user-schema-hosts", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/api_gateway/user_schemas/hosts`) },
  { id: "api-gateway-discovery-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/api_gateway/discovery`) },

  // ---- zone: TLS and origin authentication ----
  { id: "origin-tls-client-auth-hostnames", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/origin_tls_client_auth/hostnames`) },
  { id: "origin-tls-client-auth-certificates", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/origin_tls_client_auth/hostnames/certificates`) },
  { id: "origin-tls-client-auth-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/origin_tls_client_auth/settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/origin_tls_client_auth/settings`, "PUT", "origin-tls-client-auth-settings") },
  { id: "acm-total-tls", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/acm/total_tls`), write: writeSingleObject((i) => `/zones/${i.zoneId}/acm/total_tls`, "POST", "acm-total-tls") },
  { id: "dcv-delegation", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/dcv_delegation/uuid`) },
  { id: "dnssec-zsk", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/dnssec/zsk`) }, /* signing key material */
  { id: "cache-origin-pq-encryption", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/cache/origin_post_quantum_encryption`), write: writeSingleObject((i) => `/zones/${i.zoneId}/cache/origin_post_quantum_encryption`, "PUT", "cache-origin-pq-encryption") },

  // ---- zone: remaining zone objects ----
  { id: "zone-custom-page-assets", scope: "zone", restoreTier: "idempotent", read: listCapped((i) => `/zones/${i.zoneId}/custom_pages/assets`, 200) },
  { id: "zone-logpush-edge-jobs", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/logpush/edge/jobs`) },
  { id: "waf-legacy-packages", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/firewall/waf/packages`) },
  { id: "smart-shield-healthchecks", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/smart_shield/healthchecks`) },
  { id: "speed-monitored-pages", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/speed_api/pages`) },
];
