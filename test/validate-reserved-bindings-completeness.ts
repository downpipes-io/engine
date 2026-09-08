// Regression guard for RESERVED_BINDINGS completeness (ASVS V13). RESERVED_BINDINGS
// (sched/config-validate.ts) is the ENGINE'S SOLE defence against a downpipe "secrets" source naming
// one of the engine's own bindings and sealing it into a customer backup (config-validate.ts:13-14); it
// is a hand-maintained Set, so a new secret added to env.d.ts without a matching entry silently reopens
// the exact hole CONFIG_WRAP_KEY/SCIM_BEARER_TOKEN/BEACON_INGEST_KEY had. env.d.ts is imported only via
// `import type` everywhere (it declares no runtime values), so it cannot host a runtime manifest the way
// a normal module could; instead this test reads it as TEXT, regex-extracts every string-typed Env
// property whose name LOOKS secret-shaped, and asserts each one (minus a short, explicit, commented
// exceptions list) is present in RESERVED_BINDINGS. Run:
//   node test/validate-reserved-bindings-completeness.ts

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RESERVED_BINDINGS } from "../src/sched/config-validate.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// SECRET_NAME_PATTERN is deliberately broad (a completeness scan, not a precise one): any Env property
// whose name contains one of these substrings is secret-SHAPED and must either be reserved or be on the
// EXCEPTIONS list below with a reason on file.
const SECRET_NAME_PATTERN = /KEY|TOKEN|SECRET|PRIVATE|BEARER|CREDENTIAL/i;

// EXCEPTIONS are the only Env properties that match SECRET_NAME_PATTERN but are not secrets, each with
// its reason inline. This list must stay short (a manual audit trail, not a bypass); a name added here
// without a real justification defeats the whole point of the scan.
const EXCEPTIONS: Record<string, string> = {
  ADMIN_TOKEN_DISABLED: "a boolean feature flag, not a secret value",
  PASSKEY_RP_ID: "a public WebAuthn relying-party id (matches on the KEY substring in PASSKEY), not a secret",
};

// extractEnvStringProperties isolates the `export interface Env { ... }` block (never the sibling
// CfEmailSend interface below it) and returns the name of every property declared `NAME?: string;` or
// `NAME?: string | undefined;`. Comment-only lines are skipped first so prose mentioning a binding name
// in passing (e.g. the BEACON_URL/BEACON_INGEST_KEY comment above the fields themselves) is never
// mistaken for a declaration.
function extractEnvStringProperties(envDtsSource: string): string[] {
  const block = /export interface Env \{([\s\S]*?)\n\}/.exec(envDtsSource);
  if (!block) throw new Error("could not locate 'export interface Env { ... }' in env.d.ts");
  // block[1] is the regex's own (non-optional) capture group -- always a string once the outer match
  // succeeds -- but noUncheckedIndexedAccess types every indexed read off a RegExpExecArray as possibly
  // undefined, so the body is guarded explicitly rather than asserted away.
  const body = block[1];
  if (body === undefined) throw new Error("could not read the captured 'export interface Env { ... }' body");
  const propertyLine = /^([A-Z][A-Z0-9_]*)\??:\s*string(?:\s*\|\s*undefined)?\s*;/;
  const names: string[] = [];
  for (const raw of body.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("//") || line.startsWith("/*") || line.startsWith("*")) continue;
    const m = propertyLine.exec(line);
    // Same noUncheckedIndexedAccess note: m[1] is the pattern's own required capture group, always present
    // once `m` itself is non-null (a name that failed the exec would not enter this branch at all).
    if (m && m[1] !== undefined) names.push(m[1]);
  }
  return names;
}

function main(): void {
  const envDtsPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "env.d.ts");
  const stringProps = extractEnvStringProperties(readFileSync(envDtsPath, "utf8"));

  // Harness self-check: prove the extraction actually finds real, long-stable properties, so a future
  // reformat of env.d.ts breaking the regex fails LOUD (an empty extraction) rather than passing vacuously.
  ok("extraction finds SIGNER_PRIVATE (harness sanity check)", stringProps.includes("SIGNER_PRIVATE"));
  ok("extraction finds DEST_SECRET_ACCESS_KEY (harness sanity check)", stringProps.includes("DEST_SECRET_ACCESS_KEY"));
  ok("extraction finds a plausible number of string properties (harness sanity check)", stringProps.length >= 40);

  const secretShaped = stringProps.filter((name) => SECRET_NAME_PATTERN.test(name));
  ok("at least one secret-shaped property was found to check", secretShaped.length > 0);

  // Prove the exceptions list is narrow: each entry would otherwise be flagged by the pattern, so listing
  // it is a deliberate exclusion, not an accidentally-wide one.
  for (const name of Object.keys(EXCEPTIONS)) {
    ok(`exception ${name} matches the secret-shaped pattern (else it would not need excepting)`, SECRET_NAME_PATTERN.test(name));
  }

  // The actual completeness assertion: every secret-shaped property not on the exceptions list must be
  // in RESERVED_BINDINGS. Asserted per-name (not just "some gap exists") so a future regression's failure
  // output names the exact binding that reopened the hole.
  for (const name of secretShaped) {
    if (name in EXCEPTIONS) continue;
    ok(`env.d.ts secret-shaped binding ${name} is present in RESERVED_BINDINGS`, RESERVED_BINDINGS.has(name));
  }

  console.log(failures === 0 ? "\nALL RESERVED-BINDINGS COMPLETENESS VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
