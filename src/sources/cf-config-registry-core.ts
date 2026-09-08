// Part 1 of the Cloudflare configuration surface registry: the ORIGINAL surfaces (zone DNS/rules/WAF/
// traffic/TLS/email/logs and the first wave of account settings/access/data-service config). This was
// split out of cf-config-registry.ts purely to keep each module a readable size; the surfaces and their
// EXACT order are unchanged. cf-config-registry.ts concatenates this with the source-expansion list to
// form CF_CONFIG_SURFACES. See cf-config-registry.ts for the full restoreTier / fail-open contract.

import { writeSingleObject } from "./cf-config-write-settings.ts";
import { expandRulesets, list, listCapped, listWithSub, one, paginate, type CfConfigSurface, type ConfigWriteResult } from "./cf-config-core.ts";
import { classifyCfWriteSkip } from "./cf-config-fault.ts";
import type { ConfigChange } from "./cf-config-shared.ts";
import { writeAccountRuleLists, writeDns, writeFirewallAccessRules, writePageRules, writeRulesets } from "./cf-config-write.ts";
import { writeEmailRouting } from "./cf-config-write-email-routing.ts";

export const CF_CONFIG_SURFACES_CORE: CfConfigSurface[] = [
  // ---- zone: DNS & core ----
  { id: "dns", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/dns_records`), write: writeDns },
  // NO nestedDiff here, deliberately, and the reason is worth keeping. This is the zone twin of
  // account-dns-settings, which needed nestedDiff because its whole-object body carries an `soa` block a
  // Free account refuses. This endpoint behaves differently: it ACCEPTS `soa` echoed back unchanged and
  // refuses only a CHANGED one ("Custom SOA records are not available to this account or zone"), so the
  // whole-object body works today and there is no defect to fix.
  //
  // It is not flagged because the flag may only be set where deep-merge semantics have been PROVEN live,
  // and on this account they cannot be: `soa` is the only nested object here with more than one field, and
  // it is exactly the one entitlement blocks, so there is no partial nested body to test with. An account
  // entitled to custom SOA could settle it in one probe. Guessing would risk a partial body being REPLACED
  // rather than merged, which drops the omitted fields and turns a restore into data loss.
  { id: "dns-settings", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/dns_settings`), write: writeSingleObject((i) => `/zones/${i.zoneId}/dns_settings`, "PATCH", "dns-settings") },
  {
    id: "zone-settings",
    scope: "zone",
    restoreTier: "idempotent",
    read: one((i) => `/zones/${i.zoneId}/settings`),
    write: async (api, ids, data, opts, meter) => {
      // Read CURRENT settings, diff against the snapshot: only EDITABLE settings whose value
      // actually changed are touched. Apply each individually (PATCH /settings/{id}) so one
      // un-settable field (ACM-gated ciphers, log_to_cloudflare, ...) skips itself, not the rest.
      meter?.spend(1, "cfApiRead");
      const current = (await api.get(`/zones/${ids.zoneId}/settings`)) as Array<{ id?: unknown; value?: unknown }>;
      const curById = new Map<string, string>();
      for (const c of current) if (typeof c?.id === "string") curById.set(c.id, JSON.stringify(c.value ?? null));
      const changes: ConfigChange[] = [];
      const toApply: Array<{ id: string; value: unknown }> = [];
      for (const s of Array.isArray(data) ? data : []) {
        const setting = s as { id?: unknown; value?: unknown; editable?: unknown };
        if (typeof setting?.id !== "string" || setting.editable === false || setting.value === undefined) continue;
        const to = JSON.stringify(setting.value);
        const from = curById.get(setting.id);
        if (from === to) continue; // unchanged: never touched
        changes.push({ path: setting.id, action: from === undefined ? "add" : "change", from: from ?? "", to });
        toApply.push({ id: setting.id, value: setting.value });
      }
      const skipped: ConfigWriteResult["skipped"] = [];
      let applied = 0;
      if (!opts.dryRun) {
        for (const it of toApply) {
          try {
            meter?.spend(1);
            await api.send("PATCH", `/zones/${ids.zoneId}/settings/${it.id}`, { value: it.value });
            applied++;
          } catch (e) {
            // G191: an un-settable zone setting (an ACM-gated cipher, a plan-gated feature) skips itself.
            // The class says WHICH, so "WAF restore silently applied 0 rulesets on a downgraded plan" reads
            // as `entitlement` rather than as an anonymous integer.
            skipped.push({ path: it.id, reason: (e as Error).message.replace(/^Cloudflare API [A-Z]+ [^:]+:\s*/, "").slice(0, 120), cls: classifyCfWriteSkip(e) });
          }
        }
      }
      return { changes, applied, skipped };
    },
  },
  { id: "managed-headers", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/managed_headers`), write: writeSingleObject((i) => `/zones/${i.zoneId}/managed_headers`, "PATCH", "managed-headers") },
  { id: "url-normalization", scope: "zone", restoreTier: "idempotent", read: one((i) => `/zones/${i.zoneId}/url_normalization`), write: writeSingleObject((i) => `/zones/${i.zoneId}/url_normalization`, "PUT", "url-normalization", { keep: ["scope"] }) },
  // ---- zone: rules & WAF ----
  { id: "rulesets", scope: "zone", restoreTier: "idempotent", read: expandRulesets("zone"), write: writeRulesets("zone") },
  { id: "page-rules", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/pagerules`), write: writePageRules },
  { id: "firewall-access-rules", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/firewall/access_rules/rules`), write: writeFirewallAccessRules("zone") },
  { id: "filters", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/filters`) },
  { id: "firewall-rules", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/firewall/rules`) },
  { id: "page-shield-policies", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/page_shield/policies`) },
  // ---- zone: traffic & delivery ----
  { id: "workers-routes", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/workers/routes`) },
  { id: "load-balancers", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/load_balancers`) },
  { id: "waiting-rooms", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/waiting_rooms`) },
  { id: "spectrum-apps", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/spectrum/apps`) },
  { id: "custom-hostnames", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/custom_hostnames`) },
  { id: "custom-pages", scope: "zone", restoreTier: "idempotent", read: list((i) => `/zones/${i.zoneId}/custom_pages`) },
  // ---- zone: TLS (cert PRIVATE keys are write-only -> reprovision) ----
  { id: "certificate-packs", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/ssl/certificate_packs`) },
  { id: "custom-certificates", scope: "zone", restoreTier: "reprovision", read: list((i) => `/zones/${i.zoneId}/custom_certificates`) },
  { id: "origin-tls-client-auth", scope: "zone", restoreTier: "reprovision", read: one((i) => `/zones/${i.zoneId}/origin_tls_client_auth`) },
  // ---- zone: email & logs ----
  {
    id: "email-routing",
    scope: "zone",
    restoreTier: "idempotent",
    read: async (api, ids, meter) => {
      meter?.spend(1);
      const settings = await api.get(`/zones/${ids.zoneId}/email/routing`);
      const rules = await paginate(api, `/zones/${ids.zoneId}/email/routing/rules`, meter); // rules are a list -> paginate
      return { settings, rules };
    },
    write: writeEmailRouting(),
  },
  { id: "logpush", scope: "zone", restoreTier: "ordered", read: list((i) => `/zones/${i.zoneId}/logpush/jobs`) },
  { id: "account-logpush", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/logpush/jobs`) },

  // ---- account: settings & rules ----
  // NO WRITER, DELIBERATELY, and not because we cannot. Cloudflare documents PUT /accounts/{id} and the
  // account accepts it; the reason is what a restore would then send. `stripStamped` leaves `name`, `type`,
  // `settings` and `legacy_flags`, so re-applying this surface RENAMES the customer's Cloudflare account
  // to whatever it was called at backup time, and changes its type.
  //
  // That is a defensible reading of "restore the configuration" and it is also the most visible thing a
  // restore could do, arriving as a side effect of restoring something else in the same run. Whether the
  // product should do it is a call about customer expectations rather than a technical question, so the
  // writer is not added on an engineer's judgement. If it is ever added, `name` and `type` want their own
  // decision, not the default whole-object body.
  { id: "account-settings", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}`) },
  { id: "account-rulesets", scope: "account", restoreTier: "idempotent", read: expandRulesets("account"), write: writeRulesets("account") },
  { id: "account-rule-lists", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/rules/lists`), write: writeAccountRuleLists },
  { id: "account-custom-pages", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/custom_pages`) },
  { id: "account-firewall-access-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/firewall/access_rules/rules`), write: writeFirewallAccessRules("account") },
  // ---- account: access governance (membership & role inventory, restore is reprovision: a checklist, never an auto-grant) ----
  { id: "account-members", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/members`) },
  { id: "account-roles", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/roles`) },
  // ---- account: DNS / network ----
  { id: "dns-firewall", scope: "account", restoreTier: "idempotent", read: listCapped((i) => `/accounts/${i.accountId}/dns_firewall`, 100) },
  { id: "lb-pools", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/load_balancers/pools`) },
  { id: "lb-monitors", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/load_balancers/monitors`) },
  { id: "address-maps", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/addressing/address_maps`) },
  { id: "ip-prefixes", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/addressing/prefixes`) },
  { id: "mtls-certificates", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/mtls_certificates`) },
  // ---- account: alerting & turnstile ----
  { id: "notification-policies", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/alerting/v3/policies`) },
  { id: "notification-webhooks", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/alerting/v3/destinations/webhooks`) },
  { id: "turnstile", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/challenges/widgets`) },
  // ---- account: Zero Trust / Cloudflare One ----
  { id: "access-apps", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/access/apps`) },
  { id: "access-groups", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/access/groups`) },
  { id: "access-identity-providers", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/access/identity_providers`) },
  { id: "access-service-tokens", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/access/service_tokens`) },
  { id: "access-custom-pages", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/access/custom_pages`) },
  { id: "access-tags", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/access/tags`) },
  { id: "gateway-rules", scope: "account", restoreTier: "ordered", read: list((i) => `/accounts/${i.accountId}/gateway/rules`) },
  // listWithSub, because the list endpoint returns {id, name, type, count} and NOT the values: they live at
  // /gateway/lists/{id}/items. Capturing the count alone lost the entire security-relevant content of a
  // Zero Trust allowlist or blocklist while the surface read cleanly and reported no shortfall.
  { id: "gateway-lists", scope: "account", restoreTier: "idempotent", read: listWithSub((i) => `/accounts/${i.accountId}/gateway/lists`, (i, id) => `/accounts/${i.accountId}/gateway/lists/${id}/items`, "items", 100) },
  // nestedDiff: Gateway keeps its whole configuration under one `settings` object, so without it a change
  // to any single setting sends every other one back too, including `certificate` and the null-valued
  // product blocks a Free account does not have. Deep-merge was PROVEN against the live API before this was
  // set: a partial {settings: {tls_decrypt: {enabled: true}}} moved tls_decrypt alone, left antivirus,
  // activity_log, block_page, fips and certificate untouched, and restored byte-identical.
  { id: "gateway-configuration", scope: "account", restoreTier: "idempotent", read: one((i) => `/accounts/${i.accountId}/gateway/configuration`), write: writeSingleObject((i) => `/accounts/${i.accountId}/gateway/configuration`, "PATCH", "gateway-configuration", { nestedDiff: true }) },
  { id: "tunnels-cloudflared", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/cfd_tunnel`) },
  { id: "device-posture-rules", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/devices/posture`) },
  { id: "device-settings-policies", scope: "account", restoreTier: "idempotent", read: list((i) => `/accounts/${i.accountId}/devices/policies`) },
  // ---- account: data-service config (declarative wiring; the data itself is captured by the kv/r2/d1
  //      sources or is ephemeral). restoreTier reprovision: each carries a WRITE-ONLY secret the API never
  //      returns (Hyperdrive the origin DB password; a Queue consumer's bindings), so the snapshot documents
  //      what to re-create rather than blind-applying an incomplete config. (cov-hyperdrive-config-missing,
  //      cov-queues-config-missing.)
  { id: "hyperdrive-configs", scope: "account", restoreTier: "reprovision", read: list((i) => `/accounts/${i.accountId}/hyperdrive/configs`) },
  // NOTE: a "vectorize-indexes" surface was removed here as a duplicate of the richer "vectorize" surface below
  // (engine-src-048-02): both read /accounts/{}/vectorize/v2/indexes, but "vectorize" additionally captures each
  // index's /info, so "vectorize-indexes" was a strict subset. The "vectorize" surface is kept.
];
