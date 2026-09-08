// Cloudflare config-surface DRIFT GUARD for the cf-config registry.
//
// WHY THIS EXISTS
// ---------------
// engine/src/sources/cf-config-surfaces.ts hand-maintains the Cloudflare configuration
// surfaces the cf-config backup reads and restores: 214 surfaces with around 241 api.cloudflare.com
// endpoint templates plus, per surface, a restoreTier (the idempotent/ordered/reprovision "honesty
// contract"). The exact counts are enforced by validate-cf-config-surface-count.ts, so this prose
// need not be updated by hand. The restoreTier is surfaced in the restore plan.
// cf's single TypeScript schema now machine-generates
// the endpoint half of this for the whole platform, which makes two kinds of drift the thing to
// guard against:
//   (1) OUR drift -- someone edits the registry: adds/removes a surface, renames an endpoint, or
//       flips a restoreTier (a reprovision surface quietly becoming "idempotent" would be a real
//       restore-safety regression). That must be a CONSCIOUS, reviewed change, never silent.
//   (2) CLOUDFLARE drift -- Cloudflare renames/moves/removes an endpoint upstream, so a template
//       we hand-maintain silently 404s. The adapter is fail-open, so that surface degrades to an
//       "_unavailable" marker and the backup quietly stops covering it.
//
// WHAT THIS PROVES (read the run output; do not infer more):
//
//   [1] SELF-DRIFT -- ALWAYS runs, no network. The endpoint templates AND the {id,scope,
//       restoreTier} of every surface are extracted from the LIVE registry by driving each
//       surface's read()/write() through a recording stub CfApi (no network, no Cloudflare), then
//       compared to a committed baseline (test/vectors/cf-config/endpoint-baseline.json). Any
//       added/removed endpoint, added/removed surface, or changed restoreTier FAILS the guard
//       until the baseline is regenerated and committed -- so the change is a reviewed diff.
//
//   [2] CLOUDFLARE CROSS-CHECK -- runs only if Cloudflare's published OpenAPI is vendored at
//       test/vectors/cf-openapi/openapi.json (run `node scripts/fetch-cf-openapi.mjs`). Every
//       registry endpoint (METHOD + normalised path) is looked up in Cloudflare's schema;
//       endpoints with no match are reported as CANDIDATE DRIFT, minus a committed allow-list of
//       known-undocumented endpoints (test/vectors/cf-config/endpoint-cf-allowlist.json). When the
//       OpenAPI is not vendored, this section SKIPS honestly and the guard still enforces [1].
//
// HONEST LIMITS: this does NOT call Cloudflare and does NOT prove the registry is COMPLETE -- it
// guards what is there against change and against Cloudflare's published schema. Write-METHOD
// coverage is best-effort: writes are driven with synthetic data, so a surface whose write needs a
// specific payload shape may contribute only its read paths (its write path is then simply not in
// the baseline, deterministically). Path parameters on both sides are normalised to "{}", so the
// match is structural (a registry "PUT /zones/{}/dns_records/{}" matches Cloudflare's
// "/zones/{zone_id}/dns_records/{dns_record_id}" put).
//
// Regenerate the baseline after an INTENTIONAL registry change, then commit it:
//   node test/validate-cf-config-drift.ts --write-baseline
//
// Run with: node test/validate-cf-config-drift.ts

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";

const here = dirname(fileURLToPath(import.meta.url));
const baselineDir = join(here, "vectors", "cf-config");
const baselinePath = join(baselineDir, "endpoint-baseline.json");
const allowlistPath = join(baselineDir, "endpoint-cf-allowlist.json");
const openapiPath = join(here, "vectors", "cf-openapi", "openapi.json");

const WRITE_BASELINE = process.argv.includes("--write-baseline");
// REQUIRE_CF_OPENAPI turns the Section-2 Cloudflare cross-check from optional-skip into a HARD requirement:
// when set (CI sets it after fetching the schema), a missing openapi.json FAILS instead of skipping, so CI
// genuinely catches a Cloudflare-side rename/removal of a registry endpoint (cf-drift-section2-never-runs-
// in-ci). Locally it stays optional (absent => skip), so an offline dev run is not blocked.
const REQUIRE_CF_OPENAPI = process.env.REQUIRE_CF_OPENAPI === "1" || process.argv.includes("--require-openapi");

// Sentinel ids. CONVENTION: any path segment containing "__" is a parameter and is collapsed to
// "{}" in normalisation. (No real Cloudflare path segment in the registry contains a double
// underscore -- they use single underscores, e.g. dns_records.)
const IDS = { accountId: "__ACCT__", zoneId: "__ZONE__" };

// One synthetic LIVE item, rich enough that: (a) list() pages exactly once and yields one item so
// per-item read paths fire; (b) a write's UPDATE path fires (the item is matched by id); and
// (c) the rulesets write fetches the full ruleset by id and PUTs it.
const LIVE_ITEM = {
  id: "__ID__", phase: "__PHASE__", type: "__V__", name: "__V__", content: "__V__",
  value: "__V__", editable: true, targets: ["__V__"],
  configuration: { target: "__V__", value: "__V__" }, expression: "__V__", mode: "__V__",
};

// Synthetic snapshot for write(): item 1 matches the live id (forces an UPDATE -> itemPath) and
// carries a rules array (forces the rulesets PUT); item 2 has no id (forces a CREATE -> listPath).
// The SINGLETON counterpart to WRITE_DATA: an object whose value differs from LIVE_ITEM's, so a
// singleton writer sees a change and issues its PATCH/PUT rather than converging silently. It carries both
// spellings a setting can use (`value` and `enabled`) plus a distinctive field, so writeSingleSetting and
// writeSingleObject each find something to write.
const WRITE_SINGLETON_DATA = { id: "__ID__", value: "__CHANGED__", enabled: true, editable: true, _probe_singleton_: 1 };

// `name` matches LIVE_ITEM's as well as `id`, so a NAME-KEYED collection can match this item too. Not every
// collection is addressed by an id: a custom page asset is {name, description, url, ...} with no id at all,
// and the name is the path segment. Carrying only an id meant such a writer could never match the synthetic
// live item, so it skipped without issuing anything and its PUT was invisible to this guard. The guard was
// blind to the write path of every name-keyed surface, in the same way it was blind to every singleton
// before WRITE_SINGLETON_DATA was added below.
const WRITE_DATA = [
  { id: "__ID__", name: "__V__", value: "__CHANGED__", editable: true, phase: "__PHASE__", rules: [{ _probe_: 1 }] },
  { id: "__ID2__", value: "__NEW__", editable: true, _probe_create_: 1 },
];

// A COMPOSITE snapshot: an object holding both settings and a nested collection. `email-routing` reads
// `{ settings, rules }` and its writer refuses both shapes above, so it contributed no write endpoint and
// the guard was blind to its PATCH and its rule create exactly as it had been blind to every hand-written
// singleton before WRITE_SINGLETON_DATA was added. That earlier gap is described a few lines below in the
// comment that drives these shapes; this is the same gap one surface-shape along, and it is fixed the
// same way rather than by special-casing the surface.
const WRITE_COMPOSITE_DATA = {
  settings: { skip_wizard: true, support_subaddress: true, _probe_composite_: 1 },
  rules: [{ id: "__ID__", name: "__V__", matchers: [{ type: "literal", field: "to", value: "__V__" }], actions: [{ type: "drop" }] }],
};

interface Call {
  method: string;
  path: string;
}

function recorder(): { api: CfApi; calls: Call[] } {
  const calls: Call[] = [];
  // structuredClone: surfaces may mutate the returned object, so isolate each call from the shared LIVE_ITEM.
  const api: CfApi = {
    get: async (path) => {
      calls.push({ method: "GET", path });
      return [structuredClone(LIVE_ITEM)];
    },
    getPage: async (path): Promise<CfPage> => {
      calls.push({ method: "GET", path });
      return { result: [structuredClone(LIVE_ITEM)], result_info: { page: 1, total_pages: 1 } };
    },
    send: async (method, path) => {
      calls.push({ method, path });
      return null;
    },
  };
  return { api, calls };
}

function normalize(path: string): string {
  const noQuery = path.split("?")[0] ?? path;
  return noQuery
    .split("/")
    .map((seg) => (seg.includes("__") ? "{}" : seg))
    .join("/");
}

interface Surface {
  id: string;
  scope: string;
  restoreTier: string;
}
interface Extracted {
  endpoints: string[]; // "METHOD /normalised/path", sorted unique
  surfaces: Surface[]; // sorted by id
}

async function extract(): Promise<Extracted> {
  const all: Call[] = [];
  for (const s of CF_CONFIG_SURFACES) {
    const { api, calls } = recorder();
    // Fail-open per surface, exactly like the adapter: a surface whose read/write throws on the
    // synthetic client still contributes whatever paths it recorded before throwing.
    try {
      await s.read(api, IDS, undefined);
    } catch {
      /* keep recorded paths */
    }
    if (s.write) {
      // Drive the write with BOTH shapes, because one synthetic snapshot cannot exercise every writer.
      //
      // WRITE_DATA is an ARRAY, shaped for a list writer. A SINGLETON writer (writeSingleSetting for a
      // zone setting, writeSingleObject for a config object) refuses an array outright and returns a skip
      // without issuing a request, so its write endpoint was never recorded and never entered the
      // baseline. That is why GET /zones/{}/settings/speed_brain is in there and the PATCH that goes with
      // it is not, even though speed_brain is a PROVEN writer: the guard was blind to the write path of
      // every hand-written singleton, which now includes Page Shield, Gateway logging and the Email
      // Routing catch-all. Both shapes are attempted and whichever the surface accepts is what gets
      // recorded; a writer that refuses both simply contributes nothing, as before.
      for (const shape of [WRITE_DATA, WRITE_SINGLETON_DATA, WRITE_COMPOSITE_DATA]) {
        try {
          await s.write(api, IDS, shape, { dryRun: false }, undefined);
        } catch {
          /* best-effort write-path capture */
        }
      }
    }
    for (const c of calls) all.push(c);
  }
  const endpoints = Array.from(new Set(all.map((c) => `${c.method} ${normalize(c.path)}`))).sort();
  const surfaces = CF_CONFIG_SURFACES.map((s) => ({ id: s.id, scope: s.scope as string, restoreTier: s.restoreTier as string })).sort(
    (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  return { endpoints, surfaces };
}

let failures = 0;
function ok(msg: string): void {
  console.log(`  ok   ${msg}`);
}
function fail(msg: string): void {
  console.log(`  FAIL ${msg}`);
  failures++;
}

function diffSets(label: string, baseArr: string[], curArr: string[]): boolean {
  const base = new Set(baseArr);
  const cur = new Set(curArr);
  const added = curArr.filter((x) => !base.has(x));
  const removed = baseArr.filter((x) => !cur.has(x));
  if (added.length === 0 && removed.length === 0) {
    ok(`${label}: unchanged (${curArr.length})`);
    return true;
  }
  for (const a of added) fail(`${label}: NEW, not in baseline -> ${a}`);
  for (const r of removed) fail(`${label}: MISSING vs baseline -> ${r}`);
  return false;
}

function surfaceLines(surfaces: Surface[]): string[] {
  return surfaces.map((s) => `${s.id} | ${s.scope} | ${s.restoreTier}`);
}

function loadCfMethodPaths(path: string): Set<string> {
  const out = new Set<string>();
  let doc: { paths?: Record<string, Record<string, unknown>> };
  try {
    doc = JSON.parse(readFileSync(path, "utf8")) as { paths?: Record<string, Record<string, unknown>> };
  } catch {
    return out;
  }
  const paths = doc.paths ?? {};
  const methods = ["get", "post", "put", "patch", "delete"];
  for (const p of Object.keys(paths)) {
    const np = p
      .split("/")
      .map((seg) => (/^\{.+\}$/.test(seg) ? "{}" : seg))
      .join("/");
    const item = paths[p] ?? {};
    for (const m of methods) if (item[m]) out.add(`${m.toUpperCase()} ${np}`);
  }
  return out;
}

interface Baseline {
  surfaces: Surface[];
  endpoints: string[];
}

async function main(): Promise<void> {
  console.log("=== cf-config surface drift guard ===\n");
  const current = await extract();
  console.log(`Extracted ${current.surfaces.length} surfaces and ${current.endpoints.length} endpoint templates from the live registry.\n`);

  // [1] SELF-DRIFT vs committed baseline (always on, no network).
  console.log("Section 1 -- SELF-DRIFT vs committed baseline (always runs, no network):");
  if (WRITE_BASELINE || !existsSync(baselinePath)) {
    mkdirSync(baselineDir, { recursive: true });
    const payload = {
      _comment:
        "Drift-guard baseline for engine/src/sources/cf-config-surfaces.ts (test/validate-cf-config-drift.ts). " +
        "Regenerate after an INTENTIONAL change: node test/validate-cf-config-drift.ts --write-baseline",
      surfaceCount: current.surfaces.length,
      endpointCount: current.endpoints.length,
      surfaces: current.surfaces,
      endpoints: current.endpoints,
    };
    writeFileSync(baselinePath, JSON.stringify(payload, null, 2) + "\n");
    console.log(`  ${WRITE_BASELINE ? "REWROTE" : "bootstrapped"} baseline at ${baselinePath}`);
    console.log(`  -> ${current.surfaces.length} surfaces, ${current.endpoints.length} endpoint templates`);
    console.log("  Commit this file. Re-run WITHOUT --write-baseline to enforce it.\n");
  } else {
    const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as Baseline;
    const surfOk = diffSets("surface/tier", surfaceLines(baseline.surfaces), surfaceLines(current.surfaces));
    const epOk = diffSets("endpoint", baseline.endpoints, current.endpoints);
    if (!surfOk || !epOk) {
      console.log("\n  Registry drift detected. If this change is INTENTIONAL, regenerate the baseline:");
      console.log("    node test/validate-cf-config-drift.ts --write-baseline");
      console.log("    (then commit test/vectors/cf-config/endpoint-baseline.json)");
    }
    console.log("");
  }

  // [2] Cloudflare OpenAPI cross-check (optional, when vendored).
  console.log("Section 2 -- CLOUDFLARE OpenAPI cross-check (optional, runs when vendored):");
  if (!existsSync(openapiPath)) {
    if (REQUIRE_CF_OPENAPI) {
      // CI mode: the cross-check is mandatory. A missing schema means CI cannot detect an upstream rename,
      // which is the whole point, so FAIL loudly rather than skip. CI must run `node
      // scripts/fetch-cf-openapi.mjs` before this with REQUIRE_CF_OPENAPI=1.
      fail(`Cloudflare OpenAPI cross-check REQUIRED (REQUIRE_CF_OPENAPI) but no schema at ${openapiPath}; run \`node scripts/fetch-cf-openapi.mjs\` first`);
    } else {
      console.log(`  SKIPPED -- no Cloudflare OpenAPI vendored at ${openapiPath}.`);
      console.log("  To enable: node scripts/fetch-cf-openapi.mjs   (downloads if online; prints guidance offline)");
    }
    console.log("");
  } else {
    const cf = loadCfMethodPaths(openapiPath);
    const allow: Set<string> = existsSync(allowlistPath)
      ? new Set(((JSON.parse(readFileSync(allowlistPath, "utf8")) as { endpoints?: string[] }).endpoints ?? []))
      : new Set();
    if (cf.size === 0) {
      fail(`Cloudflare OpenAPI at ${openapiPath} yielded 0 documented paths (check the file)`);
    } else {
      const unmatched = current.endpoints.filter((e) => !cf.has(e));
      const newUnmatched = unmatched.filter((e) => !allow.has(e));
      if (newUnmatched.length === 0) {
        ok(
          `all ${current.endpoints.length} registry endpoints matched Cloudflare's OpenAPI ` +
            `(${cf.size} documented operations)` +
            (unmatched.length ? `, ${unmatched.length} on the allow-list` : ""),
        );
      } else {
        for (const e of newUnmatched) fail(`endpoint not in Cloudflare's OpenAPI (candidate drift) -> ${e}`);
        console.log("\n  Each line is a registry endpoint Cloudflare's schema does not document. Triage:");
        console.log("   - genuine drift (renamed/removed/moved upstream): fix the path in src/sources/cf-config-surfaces.ts;");
        console.log("   - intentionally undocumented/beta: add it to test/vectors/cf-config/endpoint-cf-allowlist.json.");
      }
    }
    console.log("");

    // Section 3 -- COVERAGE REPORT (the blind spot Section 2 structurally cannot see).
    //
    // Section 2 asks "do the endpoints we HAVE still exist upstream". It has no opinion about the ones
    // we LACK, and that asymmetry is exactly how the registry sat at 214 surfaces while 71 Cloudflare
    // product areas went untouched: every check was green the whole time. This section asks the other
    // question. It does not fail the build, because Cloudflare ships new products continuously and a
    // guard that goes red on their release schedule would be turned off within a month. It PRINTS, so
    // the gap is visible in CI output and in a support pack rather than needing a research project to
    // rediscover.
    //
    // Areas are compared, not endpoints: an endpoint-level diff would drown in per-item and analytics
    // paths. NOT_CONFIG is the scope boundary already written into the strategy (configuration, policy,
    // access rules, routing and grants; not analytics, intelligence feeds, or customer content).
    const NOT_CONFIG = /^\/(radar|memberships|user|organizations|tenants|graphql)\b/;
    const areaOf = (p: string): string => {
      const seg = p.replace(/\{[^}]*\}/g, "{}").replace(/^\//, "").split("/");
      return seg.length >= 3 && (seg[0] === "zones" || seg[0] === "accounts") ? `${seg[0]}/${seg[2]}` : "";
    };
    const ourAreas = new Set(current.endpoints.map((e) => areaOf(e.split(" ")[1] ?? "")).filter(Boolean));
    const theirAreas = new Map<string, number>();
    for (const e of cf) {
      const path = e.split(" ")[1] ?? "";
      if (!e.startsWith("GET ") || NOT_CONFIG.test(path)) continue;
      const a = areaOf(path);
      if (a) theirAreas.set(a, (theirAreas.get(a) ?? 0) + 1);
    }
    const untouched = [...theirAreas.entries()].filter(([a]) => !ourAreas.has(a)).sort((x, y) => y[1] - x[1]);
    const untouchedOps = untouched.reduce((n, [, c]) => n + c, 0);
    console.log("Section 3 -- COVERAGE against Cloudflare's OpenAPI (report only, never fails the build):");
    console.log(`  registry covers ${ourAreas.size} of ${theirAreas.size} config-shaped product areas`);
    console.log(`  ${untouched.length} areas untouched, ${untouchedOps} GET operations`);
    for (const [a, n] of untouched.slice(0, 15)) console.log(`     ${String(n).padStart(4)}  ${a}`);
    if (untouched.length > 15) console.log(`     ... and ${untouched.length - 15} more`);
    console.log("");
  }

  console.log(failures === 0 ? "DRIFT GUARD PASS" : `\n${failures} DRIFT FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
