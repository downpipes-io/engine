// Every npm package the SHIPPED Worker code imports must be a DIRECT, exactly-pinned dependency of this
// repo, and the lockfile must hold the version that pin names.
//
// THE CLASS IT CLOSES, measured on this repo. src/crypto/streamseal.ts, src/seal/record.ts,
// src/format/reader.ts, src/admin/restore-sinks.ts and src/admin/cf-assets-deploy.ts all import
// "@noble/hashes/*" -- the incremental SHA-384 and HMAC behind every content address in the archive, and
// blake3 for the assets deploy -- while package.json's dependencies block held exactly two entries,
// @noble/curves and @noble/post-quantum. @noble/hashes resolved only because those two hoist it. The
// version the product's streaming hash runs on was therefore whatever their transitive resolution
// happened to place at node_modules/@noble/hashes, and it could move under the product on any lockfile
// refresh without anybody deciding to move it. The engine's own cryptographic bill of materials had
// already published the resulting version (2.2.0) as a provenance note rather than as a pin.
//
// A transitive resolution is not a supply-chain decision. It is also invisible to the two gates that do
// the deciding: scripts/dependency-advisory-gate.mjs and scripts/deps-installed-gate.mjs both read the
// DECLARED set, so an undeclared direct import is outside advisory scanning by construction.
//
// THREE ASSERTIONS, and each has a distinct failure it catches:
//   1. every package src/ imports appears in "dependencies" (the defect above);
//   2. every runtime dependency is pinned to an EXACT version, no ^ or ~ (a caret on a crypto library is
//      the same drift wearing a declaration, and docs/security/sbom.md already records that concern);
//   3. the installed lockfile version equals the declared pin (so the pin is the version that ships, and
//      the number the bill of materials publishes is the number the reader can verify).
//
// SCOPE IS src/ ONLY, deliberately. test/ and scripts/ are entitled to devDependencies; the Worker
// bundle is not. Imports are read with the TypeScript compiler's own preProcessFile rather than a regex,
// because this repo is comment-dense and a regex over `from "..."` matches the prose (a bare grep for it
// across src/ returns ~100 lines of English before it returns an import).
//
// Run: node test/validate-direct-deps.ts

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC_DIR = join(ENGINE_DIR, "src");

interface PackageJson {
  dependencies?: Record<string, string>;
}
interface LockJson {
  packages?: Record<string, { version?: string }>;
}

const pkg = JSON.parse(readFileSync(join(ENGINE_DIR, "package.json"), "utf8")) as PackageJson;
const lock = JSON.parse(readFileSync(join(ENGINE_DIR, "package-lock.json"), "utf8")) as LockJson;
const deps = pkg.dependencies ?? {};

// walk lists every .ts file under dir. src/ holds no generated or vendored subtree, so there is nothing
// to exclude; a .d.ts carries type-only imports which are still resolution edges, so they count too.
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

// packageOf reduces an import specifier to the npm package that must be declared for it: "@scope/name/sub"
// -> "@scope/name", "name/sub" -> "name". A relative specifier and the two runtime-provided schemes
// (node:, cloudflare:) resolve to no package at all and return null.
function packageOf(spec: string): string | null {
  if (spec.startsWith(".") || spec.startsWith("/")) return null;
  if (spec.startsWith("node:") || spec.startsWith("cloudflare:")) return null;
  const parts = spec.split("/");
  if (spec.startsWith("@")) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : spec;
  return parts[0] ?? spec;
}

async function main(): Promise<void> {
  const files = walk(SRC_DIR);
  console.log(`-- direct dependencies of the shipped Worker code (${files.length} files under src/) --`);
  ok("src/ holds source to scan (a zero here would make every assertion below vacuous)", files.length > 50);

  // importers maps a package name to the src/ files that import it, so a failure names where to look.
  const importers = new Map<string, string[]>();
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    // preProcessFile is the compiler's own scanner: it reads real import/export/require edges and is not
    // fooled by the word "from" inside a comment or a string, which a regex over this repo is.
    const pre = ts.preProcessFile(text, /* readImportFiles */ true, /* detectJavaScriptImports */ true);
    for (const ref of pre.importedFiles) {
      const name = packageOf(ref.fileName);
      if (name === null) continue;
      const seen = importers.get(name) ?? [];
      seen.push(file.slice(ENGINE_DIR.length + 1));
      importers.set(name, seen);
    }
  }

  const imported = [...importers.keys()].sort();
  ok(`src/ imports at least one npm package (found ${imported.length}: ${imported.join(", ") || "none"})`, imported.length > 0);

  for (const name of imported) {
    const where = importers.get(name) ?? [];
    ok(
      `${name} is a DIRECT dependency (imported by ${where.length} src file${where.length === 1 ? "" : "s"}, e.g. ${where[0]})`,
      Object.hasOwn(deps, name),
    );
  }

  console.log("\n-- the declared pins --");
  for (const [name, range] of Object.entries(deps).sort()) {
    ok(`${name} is pinned to an exact version, not a range (declared "${range}")`, /^\d+\.\d+\.\d+([-+].*)?$/.test(range));
    const locked = lock.packages?.[`node_modules/${name}`]?.version;
    ok(`${name}: the lockfile holds the declared pin (declared "${range}", lockfile "${locked ?? "absent"}")`, locked === range);
  }

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nDIRECT-DEPS VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
