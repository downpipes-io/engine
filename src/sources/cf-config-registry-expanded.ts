// Part 2 of the Cloudflare configuration surface registry: the SOURCE-EXPANSION surfaces (the
// coverage sweep and the phase-1 follow-up). This was split out of cf-config-registry.ts purely to keep
// each module a readable size; the surfaces and their EXACT order are unchanged. cf-config-registry.ts
// concatenates the core list with this one to form CF_CONFIG_SURFACES. See cf-config-registry.ts for the
// full restoreTier / fail-open contract.

import { writeSingleObject, writeSingleSetting } from "./cf-config-write-settings.ts";
import { list, listCapped, listEnvelope, one, oneTolerating, paginate, type CfConfigSurface } from "./cf-config-core.ts";
// Support-pack fault evidence (gaps G042/G068/G110). These surfaces are the registry's only NESTED reads:
// a per-item expand (one queue's consumers, one waiting room's rules) and a per-SUB-PART read (one bucket's
// lifecycle/lock/CORS). Both classes of failure were invisible remotely: a sub-part that failed archived as
// `null`, byte-identical to "not configured" (so a LOST object-lock/WORM posture was unprovable), and a
// per-item throw voided the whole surface with only the bare surface id in the pack. Each site below now
// records a COARSE, redaction-safe fact (closed reason class + a bounded attribution id whose customer-owned
// item name is reduced to a one-way handle) before it degrades. The CF error text never leaves the site.
import { classifySourceFaultReason, faultItemId, recordIncompleteFault, recordShapeAnomaly } from "./source-fault-ledger.ts";

// subPartFault records ONE failed sub-resource read inside a surface (G042). The surface still archives (the
// part degrades to null), so there is no record and no marker for the seal to count: this ledger entry is the
// ONLY evidence that the part's absence is a READ FAILURE and not a genuine "not configured".
async function subPartFault(surfaceAndPart: string, item: string, e: unknown): Promise<void> {
  recordIncompleteFault("_unavailable", classifySourceFaultReason(e), { id: await faultItemId(surfaceAndPart, item) });
}

// itemFault records ONE failed nested per-item read that is about to VOID the whole surface (G068), so the
// pack can attribute the surface's "_unavailable" marker to the single item that sank it.
async function itemFault(surfaceAndPart: string, item: string, e: unknown): Promise<void> {
  recordIncompleteFault("_unavailable", classifySourceFaultReason(e), { id: await faultItemId(surfaceAndPart, item) });
}

export const CF_CONFIG_SURFACES_EXPANDED: CfConfigSurface[] = [
  // ===== source-expansion: +158 surfaces ( coverage sweep) =====
  { id: "access-reusable-policies", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/access/policies`) },
  { id: "access-mtls-certificates", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/access/certificates`) }, /* value-free: carries secrets */
  { id: "access-key-configuration", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/access/keys`), write: writeSingleObject((i) => `/accounts/${i.accountId}/access/keys`, "PUT", "access-key-configuration") },
  { id: "zone-access-apps", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/access/apps`) },
  { id: "zone-access-groups", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/access/groups`) },
  { id: "zone-access-identity-providers", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/access/identity_providers`) }, /* value-free: carries secrets */
  { id: "zone-access-service-tokens", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/access/service_tokens`) }, /* value-free: carries secrets */
  { id: "zone-zero-trust-organization", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/access/organizations`), write: writeSingleObject((i) => `/zones/${i.zoneId}/access/organizations`, "PUT", "zone-zero-trust-organization") },
  { id: "iam-user-groups", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/iam/user_groups`) },
  { id: "iam-resource-groups", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/iam/resource_groups`) },
  { id: "resource-shares", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/shares`, 100) },
  { id: "api-shield-user-schemas", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/api_gateway/user_schemas`) },
  { id: "api-shield-operations", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/api_gateway/operations`) },
  { id: "api-shield-schema-validation-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/api_gateway/settings/schema_validation`), write: writeSingleObject((i) => `/zones/${i.zoneId}/api_gateway/settings/schema_validation`, "PATCH", "api-shield-schema-validation-settings") },
  { id: "api-shield-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/api_gateway/configuration`) },
  { id: "api-shield-token-validation-config", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/token_validation/config`) }, /* value-free: carries secrets */
  { id: "api-shield-token-validation-rules", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/token_validation/rules`) },
  { id: "api-shield-client-certificates", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/client_certificates`) }, /* value-free: carries secrets */
  { id: "api-shield-cert-hostname-associations", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/certificate_authorities/hostname_associations`) },
  { id: "keyless-certificates", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/keyless_certificates`) }, /* value-free: carries secrets */
  { id: "custom-trust-store", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/acm/custom_trust_store`) },
  { id: "universal-ssl-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/ssl/universal/settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/ssl/universal/settings`, "PATCH", "universal-ssl-settings") },
  { id: "custom-csrs", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/custom_csrs`) }, /* value-free: carries secrets */
  { id: "custom-csrs-account", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/custom_csrs`) }, /* value-free: carries secrets */
  { id: "workers-account-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/workers/account-settings`), write: writeSingleObject((i) => `/accounts/${i.accountId}/workers/account-settings`, "PUT", "workers-account-settings") },
  { id: "workers-subdomain", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/workers/subdomain`) },
  { id: "access-organizations", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/access/organizations`), write: writeSingleObject((i) => `/accounts/${i.accountId}/access/organizations`, "PUT", "access-organizations") },
  { id: "zt-device-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/devices/settings`), write: writeSingleObject((i) => `/accounts/${i.accountId}/devices/settings`, "PATCH", "zt-device-settings") },
  { id: "zt-connectivity-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/zerotrust/connectivity_settings`), write: writeSingleObject((i) => `/accounts/${i.accountId}/zerotrust/connectivity_settings`, "PATCH", "zt-connectivity-settings") },
  { id: "gateway-logging", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/gateway/logging`), write: writeSingleObject((i) => `/accounts/${i.accountId}/gateway/logging`, "PUT", "gateway-logging") },
  { id: "email-routing-addresses", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/email/routing/addresses`) },
  { id: "email-sending-subdomains", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/email/sending/subdomains`) },
  { id: "email-dmarc-reports", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/email/auth/dmarc-reports`), write: writeSingleObject((i) => `/zones/${i.zoneId}/email/auth/dmarc-reports`, "PATCH", "email-dmarc-reports") },
  { id: "email-routing-catch-all", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/email/routing/rules/catch_all`), write: writeSingleObject((i) => `/zones/${i.zoneId}/email/routing/rules/catch_all`, "PUT", "email-routing-catch-all") },
  { id: "lb-monitor-groups", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/load_balancers/monitor_groups`) },
  { id: "email-security-allow-policies", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email-security/settings/allow_policies`) },
  { id: "email-security-block-senders", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email-security/settings/block_senders`) },
  { id: "email-security-domains", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/email-security/settings/domains`) },
  { id: "email-security-impersonation-registry", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email-security/settings/impersonation_registry`) },
  { id: "email-security-sending-domain-restrictions", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email-security/settings/sending_domain_restrictions`) },
  { id: "email-security-trusted-domains", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email-security/settings/trusted_domains`) },
  { id: "email-security-url-ignore-patterns", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/email-security/settings/url_ignore_patterns`) },
  { id: "device-posture-integrations", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/devices/posture/integration`) }, /* value-free: carries secrets */
  { id: "device-managed-networks", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/devices/networks`) },
  { id: "device-resilience-disconnect", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/devices/resilience/disconnect`), write: writeSingleObject((i) => `/accounts/${i.accountId}/devices/resilience/disconnect`, "POST", "device-resilience-disconnect") },
  { id: "zone-device-policy-certificates", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/devices/policy/certificates`) },
  { id: "advanced-dns-protection-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/advanced_dns_protection/configs/dns_protection/rules`) },
  { id: "advanced-tcp-protection-allowlist", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/allowlist`) },
  { id: "advanced-tcp-protection-prefixes", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/prefixes`) },
  { id: "advanced-tcp-protection-syn-filters", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/syn_protection/filters`) },
  { id: "advanced-tcp-protection-syn-rules", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/syn_protection/rules`) },
  { id: "advanced-tcp-protection-tcp-flow-filters", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/tcp_flow_protection/filters`) },
  { id: "advanced-tcp-protection-tcp-flow-rules", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/tcp_flow_protection/rules`) },
  { id: "advanced-tcp-protection-status", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/magic/advanced_tcp_protection/configs/tcp_protection_status`) },
  { id: "device-ip-profiles", scope: "account", restoreTier: "idempotent", read: listCapped((i) => `/accounts/${i.accountId}/devices/ip-profiles`, 100) },
  { id: "dls-prefix-bindings", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/dls/regional_services/prefix_bindings`) },
  { id: "calls-apps", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/calls/apps`) }, /* value-free: carries secrets */
  { id: "calls-turn-keys", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/calls/turn_keys`) }, /* value-free: carries secrets */
  { id: "moq-relays", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/moq/relays`) }, /* value-free: carries secrets */
  { id: "realtimekit-apps", scope: "account", restoreTier: "reprovision", read: listEnvelope((i) => `/accounts/${i.accountId}/realtime/kit/apps`, "data", { totalKey: "paging.total_count" }) }, /* value-free: carries secrets */
  { id: "logs-explorer-datasets", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/logs/explorer/datasets`) },
  { id: "account-logs-explorer-datasets", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/logs/explorer/datasets`) },
  { id: "observability-saved-queries", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/workers/observability/queries`) },
  { id: "logcontrol-cmb-config", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/logs/control/cmb/config`) },
  { id: "log-retention-flag", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/logs/control/retention/flag`) },
  { id: "cni-cnis", scope: "account", restoreTier: "idempotent", read: listEnvelope((i) => `/accounts/${i.accountId}/cni/cnis`, "items", { moreKey: "next" }) },
  { id: "connectivity-services", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/connectivity/directory/services`) },
  { id: "magic-cloud-onramps", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/magic/cloud/onramps`) },
  { id: "magic-cloud-providers", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/magic/cloud/providers`) }, /* value-free: carries secrets */
  { id: "gateway-locations", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/gateway/locations`) },
  { id: "gateway-proxy-endpoints", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/gateway/proxy_endpoints`) },
  { id: "gateway-pac-files", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/gateway/pacfiles`) },
  { id: "gateway-ssh-ca", scope: "account", restoreTier: "reprovision", read: oneTolerating((i) => `/accounts/${i.accountId}/access/gateway_ca`, [12112]) }, /* value-free: carries secrets */
  { id: "zone-entity", scope: "zone", restoreTier: "reprovision", read: one((i) => `/zones/${i.zoneId}`) },
  { id: "zone-hold", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/hold`), write: writeSingleObject((i) => `/zones/${i.zoneId}/hold`, "PATCH", "zone-hold") },
  { id: "zone-environments", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/environments`) },
  { id: "image-registries", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/containers/registries`) },
  { id: "deployment-groups", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/devices/deployment-groups`) },
  { id: "vuln-scanner-target-environments", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/vuln_scanner/target_environments`) },
  { id: "build-tokens", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/builds/tokens`) }, /* value-free: carries secrets */
  { id: "notification-silences", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/alerting/v3/silences`) },
  { id: "ct-alerting", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/ct/alerting`), write: writeSingleObject((i) => `/zones/${i.zoneId}/ct/alerting`, "PATCH", "ct-alerting") },
  { id: "notification-pagerduty-destinations", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/alerting/v3/destinations/pagerduty`) }, /* value-free: carries secrets */
  { id: "intel-sinkholes", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/intel/sinkholes`) },
  { id: "botnet-feed-asn-configs", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/botnet_feed/configs/asn`) },
  { id: "fraud-detection-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/fraud_detection/settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/fraud_detection/settings`, "PUT", "fraud-detection-settings", { alsoStrip: ["user_profiles"] }) },
  { id: "account-api-tokens", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/tokens`) }, /* value-free: carries secrets */
  { id: "rate-limits", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/rate_limits`) },
  { id: "zone-lockdowns", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/firewall/lockdowns`) },
  { id: "ua-rules", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/firewall/ua_rules`) },
  { id: "dex-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/dex/rules`) },
  // listCapped at 50, not the registry default of 1000: DEX refuses per_page=1000 outright with
  // `dex.api.parameter.invalid`, and per_page=50 is accepted. Same shape as the rulesets ceiling, and the
  // same consequence if missed, which is that the surface cannot capture at all.
  //
  // On an account where DEX is not entitled, the read fails earlier with an entitlement error before the
  // parameter is ever rejected, so an account's own entitlement gate can mask this ceiling entirely.
  // listEnvelope, not listCapped: DEX answers `{dex_tests: [...]}` and the plain list reader archived the
  // ENVELOPE as the single item. So the surface captured one object whose only key was `dex_tests`, and a
  // restore had nothing to rebuild from. Same shape as the gateway-lists defect, where a count was archived
  // and the values were not.
  //
  // The pagination ceiling still applies underneath: DEX refuses per_page=1000 with
  // `dex.api.parameter.invalid`. Both faults were on the same surface and each hid behind the other, since
  // the entitlement error on the free account meant neither was ever reached.
  { id: "dex-tests", scope: "account", restoreTier: "idempotent", read: listEnvelope((i) => `/accounts/${i.accountId}/dex/devices/dex_tests?per_page=50`, "dex_tests") },
  { id: "sso-connectors", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/sso_connectors`) }, /* value-free: carries secrets */
  { id: "oauth-clients", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/oauth_clients`) }, /* value-free: carries secrets */
  { id: "scim-users", scope: "account", restoreTier: "ordered", read: listEnvelope((i) => `/accounts/${i.accountId}/scim/v2/Users`, "Resources", { totalKey: "totalResults" }) },
  { id: "scim-groups", scope: "account", restoreTier: "ordered", read: listEnvelope((i) => `/accounts/${i.accountId}/scim/v2/Groups`, "Resources", { totalKey: "totalResults" }) },
  { id: "secondary-dns-acls", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/secondary_dns/acls`) },
  { id: "secondary-dns-tsigs", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/secondary_dns/tsigs`) }, /* value-free: carries secrets */
  { id: "secondary-dns-peers", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/secondary_dns/peers`) },
  { id: "secondary-dns-incoming", scope: "zone", restoreTier: "ordered", read: one((i) => `/zones/${i.zoneId}/secondary_dns/incoming`) },
  { id: "secondary-dns-outgoing", scope: "zone", restoreTier: "ordered", read: one((i) => `/zones/${i.zoneId}/secondary_dns/outgoing`) },
  { id: "queue-event-subscriptions", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/event_subscriptions/subscriptions`, 100) },
  { id: "account-dns-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/dns_settings`), write: writeSingleObject((i) => `/accounts/${i.accountId}/dns_settings`, "PATCH", "account-dns-settings", { nestedDiff: true }) },
  { id: "dnssec", scope: "zone", restoreTier: "ordered", read: one((i) => `/zones/${i.zoneId}/dnssec`) },
  { id: "waiting-room-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/waiting_rooms/settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/waiting_rooms/settings`, "PATCH", "waiting-room-settings") },
  // writeSingleSetting, NOT writeSingleObject. The RUM endpoint accepts `{value}` and refuses any body
  // carrying a second field, INCLUDING fields it reports itself: {value, host}, {value, lite} and
  // {value, site_tag} are all 10004 malformedParams. writeSingleObject sends the whole diff, so it worked
  // only while `value` happened to be the only field that differed, and would have failed a restore where
  // anything else had moved. writeSingleSetting sends exactly one field by construction.
  { id: "zone-rum", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/rum`), write: writeSingleSetting((i) => `/zones/${i.zoneId}/settings/rum`, "zone-rum") },
  { id: "cloudforce-one-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/cloudforce-one/rules`) },
  { id: "healthchecks", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/healthchecks`) },
  { id: "account-endpoint-healthchecks", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/diagnostics/endpoint-healthchecks`) },
  { id: "pages-projects", scope: "account", restoreTier: "reprovision", read: listCapped((i) => `/accounts/${i.accountId}/pages/projects`, 10) }, /* value-free: carries secrets */
  { id: "pipelines-streams", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/pipelines/v1/streams`) },
  { id: "pipelines-sinks", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/pipelines/v1/sinks`) }, /* value-free: carries secrets */
  { id: "pipelines", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/pipelines/v1/pipelines`) },
  { id: "workers-custom-domains", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/workers/domains`) },
  { id: "r2-catalog", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/r2-catalog`) },
  { id: "r2-catalog-syncs", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/magic/cloud/catalog-syncs`) }, /* value-free: carries secrets */
  { id: "workflows", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/workflows`, 100) },
  { id: "tiered-caching", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/argo/tiered_caching`), write: writeSingleObject((i) => `/zones/${i.zoneId}/argo/tiered_caching`, "PATCH", "tiered-caching") },
  { id: "cache-reserve", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/cache/cache_reserve`) },
  { id: "regional-tiered-cache", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/cache/regional_tiered_cache`) },
  { id: "smart-tiered-cache", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/cache/tiered_cache_smart_topology_enable`), write: writeSingleObject((i) => `/zones/${i.zoneId}/cache/tiered_cache_smart_topology_enable`, "PATCH", "smart-tiered-cache") },
  { id: "cache-variants", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/cache/variants`) },
  { id: "origin-cloud-regions", scope: "zone", restoreTier: "idempotent", read: listCapped((i) => `/zones/${i.zoneId}/origin/cloud_regions`, 100) },
  { id: "page-shield-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/page_shield`), write: writeSingleObject((i) => `/zones/${i.zoneId}/page_shield`, "PUT", "page-shield-settings") },
  { id: "smart-shield", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/smart_shield`), write: writeSingleObject((i) => `/zones/${i.zoneId}/smart_shield`, "PATCH", "smart-shield") },
  { id: "web3-hostnames", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/web3/hostnames`) },
  { id: "access-mcp-servers", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/access/ai-controls/mcp/servers`, 100) },
  { id: "access-mcp-portals", scope: "account", restoreTier: "ordered", read: listCapped((i) => `/accounts/${i.accountId}/access/ai-controls/mcp/portals`, 100) },
  { id: "pay-per-crawl-config", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/pay-per-crawl/configuration`) },
  { id: "pay-per-crawl-crawler-stripe", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/pay-per-crawl/crawler/stripe`) }, /* value-free: carries secrets */
  { id: "pay-per-crawl-publisher-stripe", scope: "account", restoreTier: "reprovision", read: one((i) => `/accounts/${i.accountId}/pay-per-crawl/publisher/stripe`) }, /* value-free: carries secrets */
  { id: "custom-hostname-fallback-origin", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/custom_hostnames/fallback_origin`) },
  { id: "zaraz-config", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/zaraz/config`), write: writeSingleObject((i) => `/zones/${i.zoneId}/settings/zaraz/config`, "PUT", "zaraz-config") },
  { id: "zaraz-workflow", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/zaraz/workflow`) },
  { id: "regional-hostnames", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/addressing/regional_hostnames`) },
  { id: "account-custom-nameservers", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/custom_ns`) },
  { id: "custom-nameserver-usage", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/custom_ns`), write: writeSingleObject((i) => `/zones/${i.zoneId}/custom_ns`, "PUT", "custom-nameserver-usage") },
  { id: "infrastructure-targets", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/infrastructure/targets`) },
  { id: "snippet-rules", scope: "zone", restoreTier: "ordered", read: oneTolerating((i) => `/zones/${i.zoneId}/snippets/snippet_rules`, [10003]) },
  { id: "container-applications", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/containers/applications`) }, /* value-free: carries secrets */
  { id: "content-scanning-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/content-upload-scan/settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/content-upload-scan/settings`, "PUT", "content-scanning-settings") },
  { id: "content-scanning-expressions", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/content-upload-scan/payloads`) },
  { id: "leaked-credential-checks", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/leaked-credential-checks`), write: writeSingleObject((i) => `/zones/${i.zoneId}/leaked-credential-checks`, "POST", "leaked-credential-checks") },
  { id: "leaked-credential-detections", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/leaked-credential-checks/detections`) },
  { id: "dns-internal-views", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/dns_settings/views`) },
  { id: "argo-smart-routing", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/argo/smart_routing`) },
  { id: "security-txt", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/security-center/securitytxt`) },
  { id: "bot-management", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/bot_management`), write: writeSingleObject((i) => `/zones/${i.zoneId}/bot_management`, "PUT", "bot-management", { alsoStrip: ["using_latest_model"] }) },
  { id: "cloud-connector-rules", scope: "zone", restoreTier: "idempotent", read: oneTolerating((i) => `/zones/${i.zoneId}/cloud_connector/rules`, [10003]) },
  { id: "google-tag-gateway", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/settings/google-tag-gateway/config`) },
  // ---- NEW: custom per-item-expand surfaces (cf. expandRulesets); no write() => capture-only/out-of-band restore ----
  {
    id: "queues", scope: "account", restoreTier: "ordered",
    read: async (api, ids, meter) => {
      const queues = (await paginate(api, `/accounts/${ids.accountId}/queues`, meter)) as Array<{ queue_id?: string; id?: string }>;
      const out: unknown[] = [];
      for (const q of queues) {
        const qid = q?.queue_id ?? q?.id;
        if (typeof qid !== "string") { recordShapeAnomaly("cf-config/queues:list-item"); out.push(q); continue; } // G110: an unrecognised list item is dropped through un-expanded
        meter?.spend(1);
        try {
          out.push({ ...q, consumers: await api.get(`/accounts/${ids.accountId}/queues/${qid}/consumers`) });
        } catch (e) {
          // G068: one queue's consumers read failing voids the WHOLE queues surface. Attribute the item first.
          await itemFault("cf-config/queues:consumers", qid, e);
          throw e;
        }
      }
      return out;
    },
  },
  {
    // Workers for Platforms: the dispatch NAMESPACES and, per namespace, the user-Worker script inventory
    // with each script's settings (bindings, compatibility date/flags). Value-free: per-script secrets and
    // code content are NOT captured here (secrets are value-bearing; code is a heavier, known follow-up
    // like the workers source, not yet built).
    // restoreTier reprovision: the platform re-creates namespaces + re-deploys scripts.
    id: "workers-for-platforms", scope: "account", restoreTier: "reprovision",
    read: async (api, ids, meter) => {
      const namespaces = (await paginate(api, `/accounts/${ids.accountId}/workers/dispatch/namespaces`, meter)) as Array<{ namespace_name?: string; name?: string; namespace_id?: string; id?: string }>;
      const out: unknown[] = [];
      for (const ns of namespaces) {
        const nsName = ns?.namespace_name ?? ns?.name ?? ns?.namespace_id ?? ns?.id;
        if (typeof nsName !== "string") { recordShapeAnomaly("cf-config/workers-for-platforms:namespace"); out.push(ns); continue; } // G110: an unrecognised namespace is never expanded
        try {
          meter?.spend(1);
          const list = await api.get(`/accounts/${ids.accountId}/workers/dispatch/namespaces/${encodeURIComponent(nsName)}/scripts`);
          // G110: a script inventory that is neither an array nor {scripts:[...]} coerces to an EMPTY list here,
          // so a whole dispatch namespace archives as "no scripts" on an API-shape change while the run reports ok.
          if (!Array.isArray(list) && !Array.isArray((list as { scripts?: unknown[] } | null)?.scripts)) recordShapeAnomaly("cf-config/workers-for-platforms:script-list");
          const arr = Array.isArray(list) ? list : ((list as { scripts?: unknown[] } | null)?.scripts ?? []);
          const scripts: unknown[] = [];
          for (const s of arr as Array<{ script_name?: string; name?: string; id?: string }>) {
            const sn = s?.script_name ?? s?.name ?? s?.id;
            if (typeof sn !== "string") { recordShapeAnomaly("cf-config/workers-for-platforms:script-item"); scripts.push(s); continue; }
            meter?.spend(1);
            // settings carries the bindings + compatibility config (value-free); fail-open per script.
            // G042: a FAILED settings read archives as `settings: null`, byte-identical to a script with no
            // settings, so a restore silently loses the script's bindings/compatibility config with nothing in
            // the pack to prove the read was failing. Record the sub-part fault (handle, never the script name).
            const settings = await api
              .get(`/accounts/${ids.accountId}/workers/dispatch/namespaces/${encodeURIComponent(nsName)}/scripts/${encodeURIComponent(sn)}/settings`)
              .catch(async (e: unknown) => {
                await subPartFault("cf-config/workers-for-platforms:settings", sn, e);
                return null;
              });
            scripts.push({ ...s, settings });
          }
          out.push({ namespace: ns, scripts });
        } catch (e) {
          // G068: this namespace's whole script inventory is lost; the surface still archives, so nothing else
          // records WHICH namespace was short. Attribute it (handle) with the closed reason class.
          await itemFault("cf-config/workers-for-platforms:scripts", nsName, e);
          out.push({ namespace: ns, scripts: { _unavailable: "script inventory could not be read" } });
        }
      }
      return out;
    },
  },
  {
    id: "waiting-room-rules", scope: "zone", restoreTier: "ordered",
    read: async (api, ids, meter) => {
      const rooms = (await paginate(api, `/zones/${ids.zoneId}/waiting_rooms`, meter)) as Array<{ id?: string }>;
      const out: unknown[] = [];
      for (const r of rooms) {
        if (typeof r?.id !== "string") { recordShapeAnomaly("cf-config/waiting-room-rules:room"); continue; } // G110: an id-less room is DROPPED entirely (not even pushed through)
        meter?.spend(1);
        try {
          out.push({ waitingRoomId: r.id, rules: await api.get(`/zones/${ids.zoneId}/waiting_rooms/${r.id}/rules`) });
        } catch (e) {
          await itemFault("cf-config/waiting-room-rules:rules", r.id, e); // G068: one room's rules read voids the surface
          throw e;
        }
      }
      return out;
    },
  },
  {
    id: "waiting-room-events", scope: "zone", restoreTier: "ordered",
    read: async (api, ids, meter) => {
      const rooms = (await paginate(api, `/zones/${ids.zoneId}/waiting_rooms`, meter)) as Array<{ id?: string }>;
      const out: unknown[] = [];
      for (const r of rooms) {
        if (typeof r?.id !== "string") { recordShapeAnomaly("cf-config/waiting-room-events:room"); continue; } // G110
        meter?.spend(1);
        try {
          out.push({ waitingRoomId: r.id, events: await api.get(`/zones/${ids.zoneId}/waiting_rooms/${r.id}/events`) });
        } catch (e) {
          await itemFault("cf-config/waiting-room-events:events", r.id, e); // G068
          throw e;
        }
      }
      return out;
    },
  },
  {
    id: "web-analytics-sites", scope: "account", restoreTier: "ordered",
    read: async (api, ids, meter) => {
      const sites = (await paginate(api, `/accounts/${ids.accountId}/rum/site_info/list`, meter)) as Array<{ ruleset?: { id?: string }; ruleset_id?: string; id?: string }>;
      const out: unknown[] = [];
      for (const s of sites) {
        const rsid = s?.ruleset?.id ?? s?.ruleset_id ?? s?.id;
        if (typeof rsid !== "string") { recordShapeAnomaly("cf-config/web-analytics-sites:site"); out.push(s); continue; } // G110
        meter?.spend(1);
        try {
          out.push({ ...s, rules: await api.get(`/accounts/${ids.accountId}/rum/v2/${rsid}/rules`) });
        } catch (e) {
          await itemFault("cf-config/web-analytics-sites:rules", rsid, e); // G068
          throw e;
        }
      }
      return out;
    },
  },
  {
    id: "account-rule-list-items", scope: "account", restoreTier: "idempotent",
    read: async (api, ids, meter) => {
      const lists = (await paginate(api, `/accounts/${ids.accountId}/rules/lists`, meter)) as Array<{ id?: string; name?: string }>;
      const out: unknown[] = [];
      for (const l of lists) {
        if (typeof l?.id !== "string") { recordShapeAnomaly("cf-config/account-rule-list-items:list"); continue; } // G110: an id-less list is dropped, items and all
        try {
          out.push({ listId: l.id, name: l.name, items: await paginate(api, `/accounts/${ids.accountId}/rules/lists/${l.id}/items`, meter) });
        } catch (e) {
          await itemFault("cf-config/account-rule-list-items:items", l.id, e); // G068
          throw e;
        }
      }
      return out;
    },
  },
  {
    id: "snippets", scope: "zone", restoreTier: "idempotent",
    read: async (api, ids, meter) => {
      const snips = (await paginate(api, `/zones/${ids.zoneId}/snippets`, meter)) as Array<{ snippet_name?: string; id?: string }>;
      const out: unknown[] = [];
      for (const s of snips) {
        const name = s?.snippet_name ?? s?.id;
        if (typeof name !== "string") { recordShapeAnomaly("cf-config/snippets:list-item"); out.push(s); continue; } // G110
        meter?.spend(1);
        let content: unknown = null;
        // G042: a failed content read archives as `content: null`, byte-identical to a snippet that genuinely has
        // no content, so "the restored snippet has null content" was unprovable at capture time. Record the fault.
        try { content = await api.get(`/zones/${ids.zoneId}/snippets/${name}/content`); } catch (e) { await subPartFault("cf-config/snippets:content", name, e); content = null; }
        out.push({ ...s, content });
      }
      return out;
    },
  },
  {
    id: "ai-security", scope: "zone", restoreTier: "idempotent",
    read: async (api, ids, meter) => {
      meter?.spend(1);
      const settings = await api.get(`/zones/${ids.zoneId}/ai-security/settings`);
      meter?.spend(1);
      const customTopics = await api.get(`/zones/${ids.zoneId}/ai-security/custom-topics`);
      return { settings, customTopics };
    },
  },
  // ===== source-expansion phase 1: remaining config/metadata surfaces =====
  // NOTE: a "hyperdrive" surface was removed here as a duplicate of "hyperdrive-configs" above (engine-src-048-01):
  // both read /accounts/{}/hyperdrive/configs with the same scope and restore tier, so they captured the identical
  // record. The richer-labelled "hyperdrive-configs" is kept; its catalogue label/category are carried below.
  { id: "durable-objects-namespaces", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/workers/durable_objects/namespaces`) }, // inventory only; per-object SQLite/KV STORAGE has no CF export API (documented platform limit)
  {
    id: "vectorize",
    scope: "account",
    restoreTier: "reprovision",
    // Vectorize INDEX CONFIG (name, dimensions, metric, metadata schema) + per-index info. The vectors
    // themselves are NOT exportable (Vectorize has no list-all-vectors API; reads are id-driven), so this
    // captures the index DEFINITIONS for reprovision, not the vector data (see the coverage matrix note).
    read: async (api, ids, meter) => {
      const indexes = (await paginate(api, `/accounts/${ids.accountId}/vectorize/v2/indexes`, meter)) as Array<{ name?: string; id?: string }>;
      const out: unknown[] = [];
      for (const ix of indexes) {
        const name = ix?.name ?? ix?.id;
        if (typeof name !== "string") {
          recordShapeAnomaly("cf-config/vectorize:list-item"); // G110
          out.push(ix);
          continue;
        }
        meter?.spend(1);
        let info: unknown = null;
        try {
          info = await api.get(`/accounts/${ids.accountId}/vectorize/v2/indexes/${name}/info`);
        } catch (e) {
          await subPartFault("cf-config/vectorize:info", name, e); // G042: a failed info read is indistinguishable from an index with no info
          info = null;
        }
        out.push({ ...ix, info });
      }
      return out;
    },
  },
  {
    id: "r2-bucket-config",
    scope: "account",
    restoreTier: "idempotent",
    // R2 BUCKET-LEVEL config (NOT the objects, which the r2 data adapter captures): lifecycle, bucket
    // lock / WORM retention posture, CORS, custom domains, Sippy, and event-notification rules, per bucket.
    // Per-sub-call fail-open so one bucket's missing setting never voids the whole surface.
    read: async (api, ids, meter) => {
      const buckets = (await paginate(api, `/accounts/${ids.accountId}/r2/buckets`, meter)) as Array<{ name?: string; id?: string }>;
      const out: unknown[] = [];
      for (const b of buckets) {
        const name = b?.name ?? b?.id;
        if (typeof name !== "string") {
          recordShapeAnomaly("cf-config/r2-bucket-config:bucket"); // G110
          out.push(b);
          continue;
        }
        const cfg: Record<string, unknown> = { bucket: name };
        // G042 (the retention-posture case): every one of these per-part reads fails to `null`, which is
        // BYTE-IDENTICAL to "this bucket has no lifecycle / no object-lock / no CORS". For a backup product
        // that is the worst possible ambiguity: "why did the restored bucket lose its object-lock (WORM)
        // config?" cannot be answered, at capture time or afterwards, because the archive proves nothing. Each
        // catch now records the failing "<surface>:<part>" with the bucket reduced to a one-way handle, so the
        // pack shows a recurring per-part read failure with attribution instead of a clean, empty posture.
        for (const part of ["lifecycle", "lock", "cors", "sippy"] as const) {
          meter?.spend(1);
          try {
            cfg[part] = await api.get(`/accounts/${ids.accountId}/r2/buckets/${name}/${part}`);
          } catch (e) {
            await subPartFault(`cf-config/r2-bucket-config:${part}`, name, e);
            cfg[part] = null;
          }
        }
        meter?.spend(1);
        try {
          cfg.customDomains = await api.get(`/accounts/${ids.accountId}/r2/buckets/${name}/domains/custom`);
        } catch (e) {
          await subPartFault("cf-config/r2-bucket-config:customDomains", name, e);
          cfg.customDomains = null;
        }
        meter?.spend(1);
        try {
          cfg.eventNotifications = await api.get(`/accounts/${ids.accountId}/event_notifications/r2/${name}/configuration`);
        } catch (e) {
          await subPartFault("cf-config/r2-bucket-config:eventNotifications", name, e);
          cfg.eventNotifications = null;
        }
        out.push(cfg);
      }
      return out;
    },
  },
];
