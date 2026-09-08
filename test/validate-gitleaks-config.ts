// Regex-logic sanity check for the "downpipe-break-glass-private-key" gitleaks rule in
// .gitleaks.toml (positive detection for the product's own downpipe-identity-v1 /
// downpipe-signer-private-v1 key format -- see src/crypto/keys.ts LABEL_IDENTITY /
// LABEL_SIGNER_PRIVATE). Added after a real identity.key/signer.pub pair was briefly committed with no
// rule in place to have caught it.
//
// Also models gitleaks' ALLOWLIST PRECEDENCE (see the allowlist-precedence section below): the regex alone
// isn't the whole control. The first cut of this rule was silently nullified for most of the
// tree by the pre-existing top-level [allowlist]'s untargeted `test/.*` paths entry -- a global
// allowlist takes precedence over every rule regardless of scope, so it doesn't matter how
// tightly this rule's OWN [rules.allowlist] is drawn. That class of bug lives in allowlist
// RESOLUTION, not the regex, so a regex-only test reports green while the real control has a
// directory-wide blind spot.
//
// This is dependency-free (no gitleaks binary required, so it runs on any machine and in the
// plain `validate` chain): it parses the rule's own `regex = '''...'''` and the allowlist blocks
// straight out of the real .gitleaks.toml (never a hand-duplicated copy, so they can't drift
// silently) and exercises them with Node's RegExp against representative lines/paths. It does NOT
// invoke gitleaks itself -- end-to-end enforcement is the blocking CI job
// (.github/workflows/ci.yml secret-scan, gitleaks-action) and the local pre-commit hook
// (.pre-commit-config.yaml), both of which read .gitleaks.toml directly.
//
// Run with: node test/validate-gitleaks-config.ts

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TOML_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", ".gitleaks.toml");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// Pulls the live regex source out of the named [[rules]] block so this test tracks the real file
// instead of a copy that could go stale. Scoped to the slice between the rule's `id` line and the
// following [rules.allowlist] table so a later rule appended after this one can't be mismatched.
function extractRuleRegex(toml: string, ruleId: string): string {
  const idMarker = `id = "${ruleId}"`;
  const idIdx = toml.indexOf(idMarker);
  if (idIdx === -1) {
    throw new Error(`rule id ${JSON.stringify(ruleId)} not found in ${TOML_PATH}`);
  }
  const allowlistIdx = toml.indexOf("[rules.allowlist]", idIdx);
  const slice = toml.slice(idIdx, allowlistIdx === -1 ? undefined : allowlistIdx);
  const m = /regex\s*=\s*'''(.*?)'''/s.exec(slice);
  if (!m || !m[1]) {
    throw new Error(`no regex = '''...''' found for rule ${JSON.stringify(ruleId)} in ${TOML_PATH}`);
  }
  return m[1];
}

// ---- allowlist-precedence model ----------------------------------------------------
// gitleaks resolves a finding against TWO kinds of allowlist: the file's global one(s)
// (`[allowlist]` / `[[allowlists]]`) and each rule's own (`[rules.allowlist]` / `[[rules.allowlists]]`).
// A global allowlist applies to EVERY rule -- default and custom alike -- UNLESS it declares
// `targetRules`, in which case it applies only to the listed rule ids. Critically, a global
// allowlist's precedence is independent of any rule-scoped allowlist: a tightly-scoped
// [rules.allowlist] cannot claw back ground an untargeted global allowlist already gave away.
// (Confirmed against the real pinned gitleaks v8.30.1 binary across `detect --no-git`,
// `detect` over full history, and `protect --staged`.)

// Pulls a TOML array-of-strings literal (e.g. `paths = ['''a''', "b"]`) into a plain string array.
// Triple-quoted entries are taken verbatim (the whole point of ''' in TOML); double/single-quoted
// entries get a light backslash-unescape. Returns null if the field is absent from `source`.
function extractTomlArray(source: string, field: string): string[] | null {
  const fieldMatch = new RegExp(`${field}\\s*=\\s*\\[([\\s\\S]*?)\\]`).exec(source);
  // fieldMatch[1] is the pattern's own required capture group -- always a string once the exec matched --
  // but noUncheckedIndexedAccess types an indexed read off RegExpExecArray as possibly undefined, so it is
  // guarded explicitly rather than asserted away.
  const inner = fieldMatch?.[1];
  if (inner === undefined) return null;
  const out: string[] = [];
  const itemRe = /'''([\s\S]*?)'''|"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
  let item: RegExpExecArray | null;
  while ((item = itemRe.exec(inner)) !== null) {
    out.push(item[1] !== undefined ? item[1] : item[2] !== undefined ? item[2].replace(/\\(.)/g, "$1") : (item[3] ?? ""));
  }
  return out;
}

// Slices out the file's top-level (global) allowlist block: from its own `[allowlist]` (legacy
// singular, what this file uses) or `[[allowlists]]` (modern array) header up to the first
// `[[rules]]` declaration, so a rule-scoped allowlist appearing later can't be mismatched.
function extractGlobalAllowlistBlock(toml: string): string {
  const firstRuleIdx = toml.search(/\n\[\[rules\]\]/);
  const head = firstRuleIdx === -1 ? toml : toml.slice(0, firstRuleIdx);
  const hdr = /\[\[?allowlists?\]\]?/.exec(head);
  if (!hdr) {
    throw new Error(`no top-level [allowlist] / [[allowlists]] block found in ${TOML_PATH}`);
  }
  return head.slice(hdr.index);
}

// True if the config's global allowlist would suppress a `ruleId` finding at `filePath`: its
// `paths` matches AND (targetRules is absent/empty [untargeted => applies to ALL rules] OR
// `ruleId` is explicitly listed).
function globalAllowlistSuppresses(toml: string, filePath: string, ruleId: string): boolean {
  const block = extractGlobalAllowlistBlock(toml);
  const targetRules = extractTomlArray(block, "targetRules");
  if (targetRules && targetRules.length > 0 && !targetRules.includes(ruleId)) return false;
  const paths = extractTomlArray(block, "paths") ?? [];
  return paths.some((p) => new RegExp(p).test(filePath));
}

// True if the named rule's OWN [rules.allowlist] suppresses `filePath` (independent of the
// global allowlist above -- this is the narrower, rule-local exemption).
function ruleAllowlistSuppresses(toml: string, filePath: string, ruleId: string): boolean {
  const idIdx = toml.indexOf(`id = "${ruleId}"`);
  if (idIdx === -1) throw new Error(`rule id ${JSON.stringify(ruleId)} not found in ${TOML_PATH}`);
  const allowIdx = toml.indexOf("[rules.allowlist", idIdx);
  if (allowIdx === -1) return false;
  const after = toml.slice(allowIdx + 1);
  const nextIdx = after.search(/\n\[\[?(rules|allowlists?)\]?\]/);
  const block = nextIdx === -1 ? toml.slice(allowIdx) : toml.slice(allowIdx, allowIdx + 1 + nextIdx);
  const paths = extractTomlArray(block, "paths") ?? [];
  return paths.some((p) => new RegExp(p).test(filePath));
}

// End-to-end: per gitleaks' documented precedence, is `filePath` actually flagged for `ruleId`?
// (Suppressed by EITHER allowlist => not flagged.)
function isFlagged(toml: string, filePath: string, ruleId: string): boolean {
  return !globalAllowlistSuppresses(toml, filePath, ruleId) && !ruleAllowlistSuppresses(toml, filePath, ruleId);
}

// A syntactically-plausible base64url run of a given length (alphabet A-Za-z0-9_-, matching
// bytes.ts's b64urlDecode alphabet), long enough to clear the rule's {80,} floor unless noted.
function blob(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[(i * 37 + 11) % alphabet.length];
  return out;
}

function main(): void {
  const toml = readFileSync(TOML_PATH, "utf8");
  const source = extractRuleRegex(toml, "downpipe-break-glass-private-key");
  const re = new RegExp(source);

  console.log("gitleaks downpipe-break-glass-private-key rule:");

  // ---- positive: real-shaped private-key lines must be caught ----
  ok("matches a downpipe-identity-v1 line with a 128-char payload", re.test(`downpipe-identity-v1 ${blob(128)}`));
  ok("matches a downpipe-signer-private-v1 line with a 128-char payload", re.test(`downpipe-signer-private-v1 ${blob(128)}`));
  ok("matches a real ~3499-char signer-private payload (recovery-kit scale)", re.test(`downpipe-signer-private-v1 ${blob(3499)}`));
  ok("matches with a tab separator (not just a space)", re.test(`downpipe-identity-v1\t${blob(96)}`));
  ok("matches at the exact 80-char floor (inclusive)", re.test(`downpipe-identity-v1 ${blob(80)}`));
  ok("matches embedded mid-line (rule is not line-anchored)", re.test(`prefix noise downpipe-identity-v1 ${blob(90)} trailing noise`));

  // ---- negative: must NOT fire on the public/shareable labels (deliberately out of scope) ----
  ok("does NOT match downpipe-signer-public-v1 (public key, not a secret)", !re.test(`downpipe-signer-public-v1 ${blob(128)}`));
  ok("does NOT match downpipe-recipient-v1 (public key, not a secret)", !re.test(`downpipe-recipient-v1 ${blob(128)}`));

  // ---- negative: must NOT fire below the length floor or with no payload ----
  ok("does NOT match one char under the 80-char floor", !re.test(`downpipe-identity-v1 ${blob(79)}`));
  ok("does NOT match a bare label with no payload (e.g. docs prose mentioning the format)", !re.test("downpipe-identity-v1"));
  ok("does NOT match the label glued to short unrelated text", !re.test("downpipe-identity-v1 short"));

  // ---- negative: unrelated strings and the pre-existing allowlisted placeholders stay inert ----
  ok("does NOT match an unrelated sentence", !re.test("hello world, nothing to see here"));
  ok("does NOT match the pre-existing AKIAEXAMPLE placeholder", !re.test("AKIAEXAMPLE"));
  ok("does NOT match the pre-existing super-secret-key placeholder", !re.test("super-secret-key"));

  // ---- allowlist precedence (the regex checks above can't catch this class of bug) ----
  console.log("\ngitleaks allowlist precedence (downpipe-break-glass-private-key vs the global allowlist):");
  const RULE_ID = "downpipe-break-glass-private-key";
  ok(
    "a real key at the repo root is flagged (the shape of a real key committed at the repo root)",
    isFlagged(toml, "identity.key", RULE_ID),
  );
  ok(
    "a real key under test/incident-notes/ (an ordinary test/ path outside test/vectors/) is flagged, not silently allowlisted",
    isFlagged(toml, "test/incident-notes/drill-log.md", RULE_ID),
  );
  ok(
    "a real key under test/debug/ (an ordinary test/ path outside test/vectors/) is flagged",
    isFlagged(toml, "test/debug/identity.key", RULE_ID),
  );
  ok(
    "the allowlisted test/vectors/ fixture path stays exempt (intended exemption, not a blind spot)",
    !isFlagged(toml, "test/vectors/identity.key", RULE_ID),
  );
  ok(
    "the global allowlist is NOT untargeted (it must declare targetRules, or it silently blinds this rule too)",
    (extractTomlArray(extractGlobalAllowlistBlock(toml), "targetRules") ?? []).length > 0,
  );
  ok(
    "the pre-existing generic-api-key false-positive suppression under test/ is preserved",
    !isFlagged(toml, "test/validate-expiry.ts", "generic-api-key"),
  );

  console.log(failures === 0 ? "\nGITLEAKS CONFIG VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
