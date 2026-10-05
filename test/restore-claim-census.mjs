// The RESTORE-CLAIM CENSUS: a DERIVED denominator for what a restore promises a customer, per source type.
//
// WHY THIS EXISTS. Capture is measured (surface counts, completeness reports, per-source adapters). RESTORE
// is a DIFFERENT promise per source type, and until this file there was no denominator for it at all, so no
// percentage could ever fall on it. The docs make specific, differing claims about each type (KV carries back
// metadata and expiration; secrets are never written in band; Workers are reprovision, not redeploy; a video
// gets a new uid). Each of those is a falsifiable statement about what a customer gets back, and a wrong one
// costs most during a recovery.
//
// WHAT THE DENOMINATOR IS. A RESTORE DISPOSITION is one terminal outcome the engine's restore path can hand a
// record: an out-of-band guidance string, a per-record failure reason, a receipt `via`, a failure `cls`, a
// sink refusal, or a media fault class. Every disposition is a promise ("this is what happened to your
// record"). The set is DERIVED from the engine's own source by extracting those literals, never hand-listed,
// so a restore path that gains a branch raises the denominator on the next run and a path that loses one
// lowers it. cf-config dispositions are counted separately and EXCLUDED from the fraction: they are measured
// by their own pass.
//
// WHAT THE NUMERATOR IS, AND WHY IT IS NOT A GREP. A literal appearing in a test file proves nothing; it can
// be a fixture string nothing asserts. So the numerator is MUTATION-EARNED: for each disposition, the literal
// is mutated IN THE ENGINE SOURCE to a sentinel, the candidate validators are re-run, and the disposition
// counts as PROVEN only if at least one of them turns red. A disposition whose mutation leaves every
// validator green is UNPROVEN, whatever any comment or doc says about it.
//
// Run:
//   node test/restore-claim-census.mjs                # derive only, print the denominator
//   node test/restore-claim-census.mjs --prove        # derive + mutation-prove (slow, minutes)
//   node test/restore-claim-census.mjs --prove --only <substring>
//
// It mutates files under src/ and ALWAYS restores them (git checkout on the touched file) in a finally block.
// Run it in a worktree you own. It never touches an account, a destination or a network.
// FS-WRITES: src/** (mutated then reverted via git checkout), test/restore-claim-census.out.json

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// The restore path's modules. Every disposition a record can terminate in is emitted from one of these.
const SOURCES = [
  "src/admin/restore-plan.ts",
  "src/admin/restore-apply.ts",
  "src/admin/restore-sinks.ts",
  "src/admin/restore-verify.ts",
  "src/dest/restore-sink.ts",
  "src/admin/media-restore.ts",
];

// A disposition is cf-config's when its text names Cloudflare config. Counted, then excluded from the
// fraction: the cf-config restore path has its own denominator and its own pass.
function isCfConfig(text) {
  return /Cloudflare config|cf-config/.test(text);
}

// SOURCE_TYPE_HINTS maps a disposition to the source types that can reach it, from the literal's own wording
// and the enclosing branch. It is a REPORTING aid only: nothing in the fraction depends on it, so a wrong
// hint cannot inflate a number.
function typesFor(id, text) {
  if (/secret/i.test(text)) return ["secrets"];
  if (/Workers script/i.test(text)) return ["workers"];
  if (/Artifact Registry/i.test(text)) return ["artifacts"];
  if (/\bvideo\b|Stream|uid/i.test(text) && /media|upload|Video/i.test(text)) return ["stream"];
  if (/\bimage\b|Image/i.test(text)) return ["images"];
  if (/media|caption/i.test(text)) return ["stream", "images"];
  if (/D1|d1/.test(text) || /^d1\./.test(id)) return ["d1"];
  if (/R2|bucket|object/i.test(text)) return ["r2"];
  if (/KV|expiration/i.test(text)) return ["kv"];
  return ["kv", "r2", "d1", "secrets", "workers", "stream", "images"];
}

// literalCore reduces a template literal to its longest fixed run, which is the substring that must survive
// into the string a customer actually sees. A pure literal is its own core.
function literalCore(raw) {
  const parts = raw.split(/\$\{[^}]*\}/g).map((s) => s.trim());
  return parts.reduce((a, b) => (b.length > a.length ? b : a), "");
}

// derive extracts the disposition set from the engine source. The patterns are deliberately narrow: they
// match the SITE (a reason property, a receipt via, a failure class, a thrown sink refusal, a media fault
// class), not any string that happens to look like prose, so a comment can never become a disposition.
function derive() {
  const out = [];
  const seen = new Set();
  const add = (file, line, kind, raw) => {
    const core = literalCore(raw);
    if (core.length < 12) return; // too short to be a distinguishing promise
    if (seen.has(core)) return;
    seen.add(core);
    out.push({ id: `${kind}:${core.slice(0, 44)}`, kind, file, line, core, cfConfig: isCfConfig(core) });
  };
  // GUIDANCE_FNS are the functions whose whole job is to RETURN the operator-facing sentence. Every string
  // literal inside one of them is a disposition by construction, including the arms of a ternary, which the
  // property-level patterns below cannot see.
  const GUIDANCE_FNS = /^(export )?(function|const) (workersRestoreGuidance|mediaRestoreGuidance|windowSkippedReason|inAccountTooLargeReason|cfUnrestoredReason|coarseCfReason)\b/;
  for (const rel of SOURCES) {
    const text = readFileSync(join(ROOT, rel), "utf8");
    const lines = text.split("\n");
    let inGuidance = 0;
    lines.forEach((l, i) => {
      const n = i + 1;
      if (GUIDANCE_FNS.test(l)) inGuidance = 1;
      else if (inGuidance > 0 && /^\}/.test(l)) inGuidance = 0;
      if (/^\s*(\/\/|\*|\/\*)/.test(l)) return; // a comment is never a disposition
      if (inGuidance > 0) {
        for (const m of l.matchAll(/(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)/g)) add(rel, n, "guidance", m[1] ?? m[2]);
      }
      // A `reason:` written as a ternary carries a promise in EACH arm; take every literal on such a line.
      if (/\breason:/.test(l) && /\?/.test(l)) {
        for (const m of l.matchAll(/(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)/g)) add(rel, n, "reason", m[1] ?? m[2]);
      }
      for (const m of l.matchAll(/\breason:\s*(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)/g)) add(rel, n, "reason", m[1] ?? m[2]);
      for (const m of l.matchAll(/\breturn\s+(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)/g)) add(rel, n, "guidance", m[1] ?? m[2]);
      for (const m of l.matchAll(/\?\s*"((?:[^"\\]|\\.)*)"\s*$/g)) add(rel, n, "guidance", m[1]);
      for (const m of l.matchAll(/^\s*:\s*"((?:[^"\\]|\\.)*)"/g)) add(rel, n, "guidance", m[1]);
      for (const m of l.matchAll(/\bvia:\s*"([a-z-]+)"/g)) add(rel, n, "via", m[1]);
      for (const m of l.matchAll(/\bcls:\s*"([a-z-]+)"/g)) add(rel, n, "cls", m[1]);
      for (const m of l.matchAll(/throw new (?:Error|D1RestoreError|MediaFault|ReadbackNotSupportedError)\(\s*(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)/g)) add(rel, n, "refusal", m[1] ?? m[2]);
      for (const m of l.matchAll(/^\s*"([a-z-]{6,})",\s*\/\//g)) add(rel, n, "fault-class", m[1]);
    });
  }
  for (const d of out) d.types = typesFor(d.id, d.core);
  return out;
}

// candidateProvers lists the test files whose text carries the disposition's own promise. A validator rarely
// quotes a long sentence in full (it asserts on a prefix or a distinctive clause), so the probe is the whole
// core OR its first PROBE_LEN characters. They are CANDIDATES, not proof: the mutation below is what decides.
// A validator may quote ANY clause of a long sentence, not its opening, so the probe set is every 24-character
// window of the core at an 8-character stride. Matching only the first N characters scored seven Workers and
// media promises as "no validator carries this literal" when a validator in this very directory asserts a
// clause from the middle of each: that was the instrument, not the product.
const PROBE_LEN = 24;
const PROBE_STRIDE = 8;
function probesOf(core) {
  if (core.length <= PROBE_LEN) return [core];
  const out = [];
  for (let i = 0; i + PROBE_LEN <= core.length; i += PROBE_STRIDE) out.push(core.slice(i, i + PROBE_LEN));
  return out;
}
function candidateProvers(core) {
  const dir = join(ROOT, "test");
  const probes = probesOf(core);
  const hits = [];
  for (const f of readdirSync(dir)) {
    if (!f.startsWith("validate-") || !/\.ts$/.test(f)) continue;
    let t;
    try {
      t = readFileSync(join(dir, f), "utf8");
    } catch {
      continue;
    }
    if (t.includes(core) || probes.some((p) => t.includes(p))) hits.push(f);
  }
  return hits;
}

function runTest(file) {
  try {
    execFileSync(process.execPath, [join("test", file)], { cwd: ROOT, stdio: "pipe", timeout: 300_000 });
    return true; // green
  } catch {
    return false; // red
  }
}

// prove mutates one disposition's literal in the engine source, re-runs its candidate validators, and
// reports whether any of them noticed. The source file is ALWAYS restored.
function prove(d) {
  if (d.provers.length === 0) return { proven: false, killedBy: [], why: "no validator carries this literal at all" };
  const abs = join(ROOT, d.file);
  const original = readFileSync(abs, "utf8");
  // The whole promise is replaced, not its tail: a validator that asserts on a PREFIX of the sentence must
  // notice too, and a tail-only mutation would let it pass and be scored as unproven when it is not.
  const mutated = original.split(d.core).join("ZQXJ-MUTATED-RESTORE-PROMISE");
  if (mutated === original) return { proven: false, killedBy: [], why: "the literal could not be mutated (not found verbatim)" };
  const killedBy = [];
  try {
    writeFileSync(abs, mutated);
    for (const p of d.provers) {
      if (!runTest(p)) killedBy.push(p);
    }
  } finally {
    writeFileSync(abs, original);
  }
  return { proven: killedBy.length > 0, killedBy, why: killedBy.length > 0 ? "" : "every candidate validator stayed green with the promise mutated" };
}

const argv = process.argv.slice(2);
const doProve = argv.includes("--prove");
const onlyAt = argv.indexOf("--only");
const only = onlyAt >= 0 ? argv[onlyAt + 1] : null;

const all = derive();
for (const d of all) d.provers = candidateProvers(d.core);
const scope = all.filter((d) => !d.cfConfig);

// BASELINE. A validator that is ALREADY RED cannot prove anything: it would turn red under every mutation and
// score every disposition it touches as proven. Run each candidate once, unmutated, and drop the red ones from
// the prover sets before a single mutation runs. This is the difference between measuring the product and
// measuring the instrument.
const alreadyRed = new Set();
if (doProve) {
  const candidates = [...new Set(scope.flatMap((d) => d.provers))].sort();
  for (const c of candidates) {
    if (!runTest(c)) alreadyRed.add(c);
  }
  if (alreadyRed.size > 0) console.log(`BASELINE: ${alreadyRed.size} candidate validator(s) are ALREADY RED and cannot prove anything: ${[...alreadyRed].join(", ")}`);
  for (const d of scope) d.provers = d.provers.filter((p) => !alreadyRed.has(p));
}

console.log(`DERIVED DISPOSITIONS: ${all.length} total, ${all.length - scope.length} cf-config (excluded, measured by its own pass), ${scope.length} in scope`);
const byKind = {};
for (const d of scope) byKind[d.kind] = (byKind[d.kind] ?? 0) + 1;
console.log(`  by kind: ${Object.entries(byKind).map(([k, n]) => `${k}=${n}`).join(" ")}`);
console.log(`  with NO candidate validator at all: ${scope.filter((d) => d.provers.length === 0).length}`);

if (!doProve) {
  for (const d of scope) console.log(`  ${d.provers.length === 0 ? "NO-PROVER" : String(d.provers.length).padStart(9)} ${d.file}:${d.line} [${d.types.join("/")}] ${d.core.slice(0, 100)}`);
  process.exit(0);
}

const results = [];
let n = 0;
for (const d of scope) {
  if (only !== null && !d.core.includes(only)) continue;
  n++;
  const r = prove(d);
  results.push({ ...d, ...r });
  console.log(`${r.proven ? "PROVEN  " : "UNPROVEN"} [${n}/${scope.length}] ${d.file}:${d.line} ${d.core.slice(0, 84)}${r.proven ? `  (killed ${r.killedBy.join(",")})` : `  (${r.why})`}`);
}
const proven = results.filter((r) => r.proven).length;
console.log(`\nRESTORE-DISPOSITION COVERAGE: ${proven} of ${results.length} mutation-proven (${((proven / Math.max(1, results.length)) * 100).toFixed(1)}%)`);
writeFileSync(join(ROOT, "test/restore-claim-census.out.json"), `${JSON.stringify({ derivedAt: new Date().toISOString(), total: all.length, cfConfigExcluded: all.length - scope.length, inScope: scope.length, proven, results }, null, 2)}\n`);
console.log("wrote test/restore-claim-census.out.json");
