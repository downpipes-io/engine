// The Cloudflare configuration surface registry: the canonical list of zone/account config
// surfaces the cf-config source backs up, the derived surface counts, and surfaceById. This was
// MOVED VERBATIM out of cf-config-surfaces.ts to keep that module a readable size; the behaviour is
// unchanged. cf-config-surfaces.ts re-exports CF_CONFIG_SURFACES, the count constants and
// surfaceById so existing callers keep importing them by name from there.
//
// Each surface backs up as ONE archived record: name = surface id, value = the surface's
// config as canonical JSON. The selector applies by surface id (prefix), not within a surface.
// The adapter is FAIL-OPEN per surface: a surface the token cannot read (a missing scope, a
// product not on the plan, a deprecated endpoint) becomes an "_unavailable" marker, never a
// fatal error, so the registry can be GENEROUS (cover everything config-shaped) and an account
// simply gets markers for the products it does not use.
//
// restoreTier classifies how a surface restores (the honesty contract, surfaced in the restore
// plan): "idempotent" replays cleanly (settings PATCH, ruleset PUT, list create); "ordered" needs
// dependency-ordered create + id remapping (Access apps -> groups/IdPs, load balancers -> pools);
// "reprovision" carries write-only values (certificate private keys, service-token secrets, IdP
// client secrets, tunnel secrets) so restore can only emit a re-provision checklist, never replay.

import type { CfConfigSurface, CfScope, RestoreTier } from "./cf-config-core.ts";
import { CF_CONFIG_SURFACES_CORE } from "./cf-config-registry-core.ts";
import { CF_CONFIG_SURFACES_EXPANDED } from "./cf-config-registry-expanded.ts";
import { CF_CONFIG_SURFACES_GAPS } from "./cf-config-registry-gaps.ts";
import { CF_CONFIG_SURFACES_GAPS2 } from "./cf-config-registry-gaps2.ts";
// Table-driven writers generated from Cloudflare's schema. Attached below to surfaces that do not
// already carry a hand-written one, so a hand-tuned writer always wins over a generated guess.
import { GENERATED_WRITERS } from "./cf-config-write-generated.ts";

// CF_CONFIG_SURFACES is the registry. It is data, so adding a surface is a one-line append; the
// adapter and the restore sink pick it up automatically, and fail-open turns an unusable surface
// into a marker. LIST-shaped surfaces use list(), which PAGINATES to exhaustion (SRC-4) so a large
// DNS/firewall/custom-hostname set is captured in full, never truncated at one page, while
// single-object surfaces (settings objects, the account root) use one() (a single GET).
//
// The surface list is split across two sibling data modules purely to keep each file a readable
// size: cf-config-registry-core.ts holds the original surfaces and cf-config-registry-expanded.ts
// holds the source-expansion sweep. They are concatenated here in the EXACT order they had when this
// was a single array, so the derived counts and surfaceById are unchanged.
// attachGenerated bolts a generated write() onto a surface that has none. A hand-written writer ALWAYS
// wins: the generated table is a floor, never an override, because the hand-written ones encode
// per-surface knowledge (rule order, which server-computed fields to strip) that the schema does not
// carry. Generated writers are additionally off by DEFAULT at restore time, see PROVEN_WRITE_SURFACES.
function attachGenerated(surfaces: CfConfigSurface[]): CfConfigSurface[] {
  return surfaces.map((s) => {
    if (typeof s.write === "function" || s.restoreTier !== "idempotent") return s;
    const gen = GENERATED_WRITERS.get(s.id);
    return gen === undefined ? s : { ...s, write: gen };
  });
}

export const CF_CONFIG_SURFACES: CfConfigSurface[] = attachGenerated([
  ...CF_CONFIG_SURFACES_CORE,
  ...CF_CONFIG_SURFACES_EXPANDED,
  // The OpenAPI-gap sweep. Appended LAST so every pre-existing surface keeps its index and
  // the core/expanded ordering is untouched; only the totals move.
  ...CF_CONFIG_SURFACES_GAPS,
  // The DEPTH half of the same sweep: areas the registry touched only shallowly.
  ...CF_CONFIG_SURFACES_GAPS2,
]);

// The canonical cf-config surface counts are DERIVED from the registry above, not hand-written, so
// prose (docs, website, console) and the drift guard share one source of truth. validate-cf-config-
// surface-count.ts pins these against the registry and prints them to stdout; if a surface is added
// the numbers move and any out-of-date prose must be regenerated from the printed line.
export const CF_CONFIG_SURFACE_COUNT: number = CF_CONFIG_SURFACES.length;
export const CF_CONFIG_INBAND_COUNT: number = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function").length;
export const CF_CONFIG_TIER_COUNTS: Record<RestoreTier, number> = CF_CONFIG_SURFACES.reduce(
  (acc, s) => {
    acc[s.restoreTier] += 1;
    return acc;
  },
  { idempotent: 0, ordered: 0, reprovision: 0 } as Record<RestoreTier, number>,
);
export const CF_CONFIG_SCOPE_COUNTS: Record<CfScope, number> = CF_CONFIG_SURFACES.reduce(
  (acc, s) => {
    acc[s.scope] += 1;
    return acc;
  },
  { zone: 0, account: 0 } as Record<CfScope, number>,
);

// _surfaceById is the module-level lookup index so surfaceById is O(1) per call rather than a linear
// scan of the registry on every restore dispatch. Surface ids are unique, so a later duplicate would
// overwrite an earlier one; the registry is the single source of those ids.
const _surfaceById = new Map<string, CfConfigSurface>(CF_CONFIG_SURFACES.map((s) => [s.id, s]));

// surfaceById is the restore-side lookup: given an archived record name, the surface (and so its
// restore tier and scope) it came from, or undefined for an unknown/forward-compatible name.
export function surfaceById(id: string): CfConfigSurface | undefined {
  return _surfaceById.get(id);
}
