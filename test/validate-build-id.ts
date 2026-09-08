// W1 provenance / self-hash. Proves the engine self-reports a build-stamped artefact SHA-384 and that
// GET /admin/status surfaces the REAL hash (build-stamp over the env echo), honestly omits it when none
// is stamped, lets a manual env var override, and surfaces the version_metadata id/tag presence-safely.
// Driven in-memory (no network, no deploy): the build-stamp side-car is written/restored around the
// reporting assertions, and buildStatus is exercised with hand-built envs. Run:
//   node test/validate-build-id.ts

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reportedArtefactSha384, ARTEFACT_SHA384_PLACEHOLDER } from "../src/format/build-id.ts";
import { buildStatus } from "../src/admin/status.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode, utf8 } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const STAMP_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "format", "build-stamp.ts");

// writeStamp overwrites the build-stamp side-car with a given exported value (a real digest, the
// placeholder, or garbage), so the reporting branch can be exercised without an actual build. A cache-
// busting query in the dynamic import is NOT available for a .ts strip-types import. The test uses a
// two-pass strategy: most variants pass a value to buildStatus's selfReported argument directly, while
// freshImportReport() spawns a child process for the one case where Node's per-specifier module cache
// would otherwise return a stale reportedArtefactSha384. So this test writes ONCE (a real stamped digest)
// for the live read, and uses buildStatus's selfReported argument directly for the absence/override/garbage cases.
function writeStamp(value: string): void {
  writeFileSync(STAMP_PATH, `export const ARTEFACT_SHA384 = ${JSON.stringify(value)}\n`);
}

async function main(): Promise<void> {
  const original = readFileSync(STAMP_PATH, "utf8");

  // The committed placeholder is NOT a real hash, so a fresh checkout honestly reports null.
  ok("placeholder is not a 96-hex SHA-384 (cannot be mistaken for a real digest)", !/^[0-9a-f]{96}$/.test(ARTEFACT_SHA384_PLACEHOLDER.toLowerCase()));

  try {
    // ---- 1. A real stamped digest is read + reported ----
    const digest = hexEncode(await sha384(utf8("a-fake-deployable-bundle")));
    writeStamp(digest);
    const reported = await reportedArtefactSha384();
    ok("reportedArtefactSha384 returns the stamped digest when a real one is present", reported === digest);
    ok("the reported digest is a 96-hex SHA-384", typeof reported === "string" && /^[0-9a-f]{96}$/.test(reported));

    // ---- 2. status reports the SELF-STAMPED hash (no manual env echo) ----
    const envNoArtefact = {} as Env;
    const statusStamped = buildStatus(envNoArtefact, 0, { selfReportedArtefactSha384: digest });
    ok("status.artefactSha384 is the self-stamped digest when no env override is set", statusStamped.artefactSha384 === digest);

    // ---- 3. a manual env.ARTEFACT_SHA384 OVERRIDES the self-stamped value ----
    const override = "sha384:operator-pinned-override-value";
    const envOverride = { ARTEFACT_SHA384: override } as Env;
    const statusOverride = buildStatus(envOverride, 0, { selfReportedArtefactSha384: digest });
    ok("env.ARTEFACT_SHA384 overrides the self-stamped digest (deliberate out-of-band pin)", statusOverride.artefactSha384 === override);

    // ---- 4. honest ABSENCE: no stamp + no env => the field is omitted, never fabricated ----
    const statusAbsent = buildStatus(envNoArtefact, 0, { selfReportedArtefactSha384: null });
    ok("no stamp + no env => artefactSha384 honestly absent (not fabricated)", statusAbsent.artefactSha384 === undefined);
    // not resolved by this caller (undefined) + no env => still absent.
    const statusUnresolved = buildStatus(envNoArtefact, 0);
    ok("caller did not resolve a stamp + no env => artefactSha384 absent", statusUnresolved.artefactSha384 === undefined);

    // ---- 5. version_metadata id/tag surface presence-safely ----
    const envWithVm = { CF_VERSION_METADATA: { id: "v-abc123", tag: "tag-1", timestamp: "2026-06-17T00:00:00Z" } } as unknown as Env;
    const statusVm = buildStatus(envWithVm, 0);
    ok("status surfaces the Cloudflare version id when version_metadata is bound", statusVm.cfVersionId === "v-abc123");
    ok("status surfaces the Cloudflare version tag when version_metadata is bound", statusVm.cfVersionTag === "tag-1");
    ok("status never surfaces the version_metadata timestamp (only id/tag are public build ids)", !("timestamp" in statusVm) && JSON.stringify(statusVm).indexOf("2026-06-17") === -1);
    // absent binding => honestly omitted.
    ok("no version_metadata binding => cfVersionId/cfVersionTag honestly absent", statusUnresolved.cfVersionId === undefined && statusUnresolved.cfVersionTag === undefined);

    // ---- 6. a garbage/placeholder stamp is rejected (honest absence), not reported ----
    writeStamp("unstamped-build");
    ok("the placeholder value is rejected -> reportedArtefactSha384 returns null", (await freshImportReport()) === null);
  } finally {
    // Restore the committed placeholder side-car so the working tree is left clean.
    writeFileSync(STAMP_PATH, original);
  }

  console.log(failures === 0 ? "\nALL BUILD-ID / PROVENANCE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// freshImportReport re-reads the stamp through a child process so the module cache does not return the
// first-imported value (Node caches a .ts specifier after the first dynamic import). This lets the test
// assert a DIFFERENT stamp value (the placeholder) is correctly rejected even after a real one was read.
async function freshImportReport(): Promise<string | null> {
  const { execFileSync } = await import("node:child_process");
  const out = execFileSync(process.execPath, ["-e", `import("${pathToFileUrl(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "format", "build-id.ts"))}").then(m=>m.reportedArtefactSha384()).then(v=>process.stdout.write(JSON.stringify(v)))`], { encoding: "utf8" });
  return JSON.parse(out) as string | null;
}

function pathToFileUrl(p: string): string {
  return "file://" + p.replace(/\\/g, "/");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
