// validate-rpc-binding-tripwire.ts -- a TRIPWIRE for a latent risk identified and deliberately left
// inert.
//
// THE RISK. enumerateBoundSources (src/admin/router-sources.ts) tells a Secrets Store binding apart from
// every other Cloudflare binding kind by duck-typing: a value that answers "yes" to three or more of five
// mutually exclusive method-name groups (R2/KV/D1/DO/email), plus .get, is routed to `secrets`. That is
// correct for every binding kind this engine deploys today, because each one is a native object exposing
// a small, FIXED, documented method set -- it can only ever answer "yes" to the one group it actually is.
//
// A Workers RPC stub is not that shape. Cloudflare's own docs describe the client-side stub for a service
// binding targeting a WorkerEntrypoint/RpcTarget, or for a dispatch-namespace binding, as literally
// `new Proxy(...)` with a wildcard trap -- "appears to have an infinite number of methods of every
// possible name" (developers.cloudflare.com/workers/runtime-apis/rpc/; entrypoint/RPC support for
// `[[services]]` and `[[dispatch_namespaces]]` confirmed at developers.cloudflare.com/workers/wrangler/
// configuration/, both read). Attach one as a source and its runtime value would plausibly
// answer "yes" to three-plus groups and .get for the exact structural reason the Secrets Store binding
// did, and get misclassified as a backup source. INERT today: this scan (below) finds zero `[[services]]`
// or `[[dispatch_namespaces]]` declarations anywhere in this repo's wrangler*.toml files.
//
// WHAT THIS DOES NOT DO. It does not ban a `[[services]]` or `[[dispatch_namespaces]]` binding -- the
// engine may have a legitimate reason to declare one someday. It forces a human decision at the moment of
// introduction: the binding's name must be listed in REVERIFIED_PROXY_BINDINGS
// (src/admin/rpc-proxy-bindings-reverified.ts), which is only honest to do after
// test/validate-rpc-stub-classification.ts exists, builds its double from a REAL `new Proxy(...)`
// wildcard trap (not a hand-built object naming methods, the shape an earlier related fix's own unit
// test used and which is insufficient evidence for THIS risk), and passes.
//
// WHAT THIS DOES NOT COVER, and why. kv_namespaces / r2_buckets / d1_databases / durable_objects /
// secrets_store_secrets / send_email / queues / vectorize / hyperdrive / ai / browser /
// analytics_engine_datasets / mtls_certificates are all native JS wrapper objects exposing a small fixed
// method set per Cloudflare's own binding docs, not a generic Proxy trap, so they cannot exhibit the
// "answers yes to everything" signature this tripwire exists to catch. A Durable Object STUB returned at
// runtime from a namespace binding's own `.get(id)` call can carry arbitrary RPC methods too, but that
// stub is created dynamically per request and is never itself a static env binding enumerateBoundSources
// walks -- out of scope for a wrangler.toml-time check, and the namespace binding itself is already
// excluded from the classification ladder by name (`idFromName`) regardless of what a runtime `.get()`
// call later returns.
//
// Run: node test/validate-rpc-binding-tripwire.ts

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REVERIFIED_PROXY_BINDINGS } from "../src/admin/rpc-proxy-bindings-reverified.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const REVERIFICATION_TEST_REL = "test/validate-rpc-stub-classification.ts";

// The two wrangler.toml table kinds whose runtime binding value Cloudflare documents as RPC-capable and
// therefore Proxy-stub-shaped. Judged on the evidence cited above, not guessed: every other binding table
// kind wraps a native, fixed-method object.
const RISKY_TABLES = new Set(["services", "dispatch_namespaces"]);

interface RiskyDeclaration {
  file: string;
  table: string;
  binding: string | null;
}

// findRiskyDeclarations is a small state machine over TOML lines: track the current `[[table]]` (or
// `[section]`, which resets it -- a bracket header that is not itself an array-of-tables binding block),
// and for a risky table, capture its `binding = "NAME"` line the same way bindings-sync.ts's own
// existingBindingNames parses wrangler.toml elsewhere in this repo. A block with no binding line still
// reports (binding: null) rather than being silently skipped -- a malformed declaration is not a clean
// bill of health.
export function findRiskyDeclarations(toml: string, fileName: string): RiskyDeclaration[] {
  const found: RiskyDeclaration[] = [];
  let currentTable: string | null = null;
  let pendingBinding: string | null = null;
  const flush = (): void => {
    if (currentTable !== null && RISKY_TABLES.has(currentTable)) {
      found.push({ file: fileName, table: currentTable, binding: pendingBinding });
    }
  };
  for (const raw of toml.split("\n")) {
    const line = raw.trim();
    const arrayHeader = /^\[\[\s*([a-zA-Z0-9_.]+)\s*\]\]$/.exec(line);
    if (arrayHeader) {
      flush();
      currentTable = arrayHeader[1] ?? null;
      pendingBinding = null;
      continue;
    }
    const sectionHeader = /^\[\s*([a-zA-Z0-9_.]+)\s*\]$/.exec(line);
    if (sectionHeader) {
      flush();
      currentTable = null;
      pendingBinding = null;
      continue;
    }
    if (currentTable !== null && RISKY_TABLES.has(currentTable)) {
      const bindingLine = /^binding[ \t]*=[ \t]*["']([^"']+)["']/.exec(line);
      if (bindingLine) pendingBinding = bindingLine[1] ?? null;
    }
  }
  flush();
  return found;
}

function teachingMessage(decl: RiskyDeclaration): string {
  return (
    `\n  ${decl.file} declares a [[${decl.table}]] binding ("${decl.binding ?? "<no binding name found>"}"),` +
    ` and enumerateBoundSources (src/admin/router-sources.ts) has not been re-verified against that shape.\n` +
    `\n  A Workers RPC stub -- what a [[services]] binding targeting a WorkerEntrypoint/RpcTarget, or a\n` +
    `  [[dispatch_namespaces]] binding, hands back -- is a JavaScript Proxy with a wildcard trap: it\n` +
    `  answers "yes, I have a method with that name" for ANY name you probe. enumerateBoundSources tells\n` +
    `  binding kinds apart by duck-typing a handful of method names, and duck-typing cannot tell "this\n` +
    `  object genuinely has these methods" from "this object says yes to every name I ask it" -- the exact\n` +
    `  signature that got a Secrets Store binding misclassified as a backup source.\n` +
    `\n  Re-verification means building a test double from the REAL shape -- a genuine\n` +
    `  \`new Proxy(target, { get: () => () => {} })\` wildcard trap, the mechanism Workers RPC actually\n` +
    `  uses -- not a hand-built object naming methods one by one, which cannot exercise this risk because\n` +
    `  it only ever answers "yes" to the names it was told to list.\n` +
    `\n  To clear this check: add ${REVERIFICATION_TEST_REL}, build its double from a real Proxy, confirm\n` +
    `  enumerateBoundSources classifies it the way you intend, then list "${decl.binding ?? "<binding name>"}"` +
    ` in src/admin/rpc-proxy-bindings-reverified.ts's REVERIFIED_PROXY_BINDINGS.\n`
  );
}

function reverificationTestIsGenuine(): boolean {
  const abs = path.join(REPO_ROOT, REVERIFICATION_TEST_REL);
  if (!existsSync(abs)) return false;
  const src = readFileSync(abs, "utf8");
  if (!/new\s+Proxy\s*\(/.test(src)) return false;
  try {
    execFileSync(process.execPath, [abs], { cwd: REPO_ROOT, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function main(): void {
  // ---- parser self-test: prove the state machine actually has teeth before trusting it on real files ----
  const noRiskySample = 'name = "x"\n[[durable_objects.bindings]]\nname = "SCHEDULER"\nclass_name = "SchedulerDO"\n';
  ok("parser self-test: a toml with no risky table reports nothing", findRiskyDeclarations(noRiskySample, "sample.toml").length === 0);

  const riskySample = 'name = "x"\n[[services]]\nbinding = "RPC_TEST"\nservice = "other-worker"\nentrypoint = "SomeEntrypoint"\n';
  const riskyFound = findRiskyDeclarations(riskySample, "sample.toml");
  ok("parser self-test: a [[services]] block with a binding is detected", riskyFound.length === 1 && riskyFound[0]?.binding === "RPC_TEST");

  const dispatchSample = 'name = "x"\n[[dispatch_namespaces]]\nbinding = "DISPATCHER"\nnamespace = "platform"\n';
  const dispatchFound = findRiskyDeclarations(dispatchSample, "sample.toml");
  ok("parser self-test: a [[dispatch_namespaces]] block with a binding is detected", dispatchFound.length === 1 && dispatchFound[0]?.binding === "DISPATCHER");

  const safeSample = 'name = "x"\n[[kv_namespaces]]\nbinding = "SRC_KV"\nid = "n"\n[vars]\nCONSOLE_ORIGIN = "https://x"\n';
  ok("parser self-test: a [section] header resets the current table (does not leak into the next block)", findRiskyDeclarations(safeSample, "sample.toml").length === 0);

  const noBindingSample = "name = \"x\"\n[[services]]\nservice = \"other-worker\"\n";
  const noBindingFound = findRiskyDeclarations(noBindingSample, "sample.toml");
  ok("parser self-test: a risky table with no binding line still reports (binding: null), not silently clean", noBindingFound.length === 1 && noBindingFound[0]?.binding === null);

  // ---- the real gate: scan every committed wrangler*.toml -------------------------------------------
  const wranglerFiles = readdirSync(REPO_ROOT).filter((f) => /^wrangler.*\.toml$/.test(f));
  ok(`found at least one wrangler*.toml to scan (harness sanity check)`, wranglerFiles.length > 0);

  const allDeclarations: RiskyDeclaration[] = [];
  for (const file of wranglerFiles) {
    const toml = readFileSync(path.join(REPO_ROOT, file), "utf8");
    allDeclarations.push(...findRiskyDeclarations(toml, file));
  }

  if (allDeclarations.length === 0) {
    ok("no [[services]] or [[dispatch_namespaces]] binding is declared in any committed wrangler*.toml -- nothing to re-verify", true);
  }

  for (const decl of allDeclarations) {
    const named = decl.binding !== null && REVERIFIED_PROXY_BINDINGS.has(decl.binding);
    const genuine = reverificationTestIsGenuine();
    const cleared = named && genuine;
    if (!cleared) console.error(teachingMessage(decl));
    ok(
      `${decl.file} [[${decl.table}]] "${decl.binding ?? "?"}" is re-verified (listed in REVERIFIED_PROXY_BINDINGS AND ${REVERIFICATION_TEST_REL} exists, builds a real Proxy double, and passes)`,
      cleared,
    );
  }

  console.log(failures === 0 ? "\nALL RPC-BINDING-TRIPWIRE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
