// The Cloudflare configuration surface registry FACADE: the single import point the cf-config
// source backup adapter (cloudflare-config.ts), the restore sink and the discovery scan all consume.
//
// Each surface backs up as ONE archived record: name = surface id, value = the surface's
// config as canonical JSON. The selector applies by surface id (prefix), not within a surface.
// The adapter is FAIL-OPEN per surface: a surface the token cannot read (a missing scope, a
// product not on the plan, a deprecated endpoint) becomes an "_unavailable" marker, never a
// fatal error, so the registry can be GENEROUS (cover everything config-shaped) and an account
// simply gets markers for the products it does not use.
//
// SCOPE of the registry: CONFIGURATION ("settings"), not data and not runtime/analytics. KV / R2 /
// D1 / Secrets Store are their own data source types; logs, analytics, Radar, Stream/Images
// CONTENT, compute deployments and billing are deliberately excluded.
//
// REGISTRAR IS CAPTURED: registrar-domains and registrar-registrations are in the registry with ordinary
// read() builders on the discovery token, which does not need the Global API Key. The console catalogue
// labels them and the generated surface table in the docs lists them as captured. What IS out of reach is
// narrower and is recorded beside the surface itself: the registry-side transfer locks and authorisation
// codes, which are registrar state rather than Cloudflare configuration and are not replayable by any API.
//
// restoreTier classifies how a surface restores (the honesty contract, surfaced in the restore
// plan): "idempotent" replays cleanly (settings PATCH, ruleset PUT, list create); "ordered" needs
// dependency-ordered create + id remapping (Access apps -> groups/IdPs, load balancers -> pools);
// "reprovision" carries write-only values (certificate private keys, service-token secrets, IdP
// client secrets, tunnel secrets) so restore can only emit a re-provision checklist, never replay.
//
// This file is now a thin FACADE that re-exports every symbol its callers import so they keep
// importing them by name from cf-config-surfaces.ts. The core types + API client + paginator + read-
// builders live in ./cf-config-core.ts; the registry array + counts + surfaceById in ./cf-config-
// registry.ts; the console catalogue (labels/categories + cfConfigCatalogue/surfaceLabel) in
// ./cf-config-catalogue.ts; the diff-driven restore WRITE specs in ./cf-config-write.ts; the shared
// JSON helpers in ./cf-config-shared.ts; and the restore diff PREVIEW in ./cf-config-diff.ts. Those
// were MOVED VERBATIM out of this module to keep it a readable size; the behaviour is unchanged.


// Re-export the console catalogue (per-surface selection metadata) + the label helper. They live in
// ./cf-config-catalogue.ts.
export { type CfConfigSurfaceMeta, cfConfigCatalogue, surfaceLabel } from "./cf-config-catalogue.ts";
// Re-export the core types + client + paginator + read-builders so existing callers keep importing them
// by name from cf-config-surfaces.ts. They live in ./cf-config-core.ts.
export {
  CF_PAGINATION_MAX_PAGES,
  CF_PAGINATION_PER_PAGE,
  type CfApi,
  CfApiError,
  type CfConfigSurface,
  type CfPage,
  CfPaginationTruncated,
  type CfResultInfo,
  type CfScope,
  type ConfigWriteResult,
  isCfPlanEntitlementError,
  makeCfApi,
  paginate,
  type RestoreTier,
} from "./cf-config-core.ts";
export { type ConfigDiff, diffConfig } from "./cf-config-diff.ts";

// Re-export the registry array, the derived counts and surfaceById. They live in ./cf-config-registry.ts.
export {
  CF_CONFIG_INBAND_COUNT,
  CF_CONFIG_SCOPE_COUNTS,
  CF_CONFIG_SURFACE_COUNT,
  CF_CONFIG_SURFACES,
  CF_CONFIG_TIER_COUNTS,
  surfaceById,
} from "./cf-config-registry.ts";
// Re-export the shared ConfigChange shape and the restore diff PREVIEW so existing callers keep importing
// them by name from cf-config-surfaces.ts.
export type { ConfigChange } from "./cf-config-shared.ts";

// CF_CONFIG_IDENTITY_ID is the reserved record name of the self-identifying record every cf-config crawl
// emits FIRST: its value records WHICH account/zone this backup is for ({ v, accountId, zoneId?, zoneName? }),
// so an archive identifies its own zone without relying on the downpipe name (which lives only in config, not
// the backup). It is deliberately NOT a real surface (no read/write, absent from CF_CONFIG_SURFACES /
// surfaceById), so the restore path recognises it as metadata and never treats it as a restorable surface.
// The leading underscore matches the _unavailable/_truncated marker convention: a reserved, non-surface name.
export const CF_CONFIG_IDENTITY_ID = "_cf-config-identity";

// surfaceSelected applies a downpipe's selector to a surface id by EXACT id (not the prefix match
// KV keys use): an empty include means all surfaces; otherwise the surface must be listed by id and
// not excluded. This is what makes the per-surface tick-boxes select exactly what was ticked.
export function surfaceSelected(id: string, include: string[], exclude: string[]): boolean {
  if (exclude.includes(id)) return false;
  return include.length === 0 || include.includes(id);
}
