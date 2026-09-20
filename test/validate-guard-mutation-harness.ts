// Self-test for scripts/guard-mutation-harness.mjs, the shared tool four passes have now rebuilt.
//
// WHY A SELF-TEST AND NOT JUST A TOOL. Every mechanism in that harness exists because a pass lost something
// without it, and each one is exactly the sort of thing that silently stops working: a mutation that becomes
// a no-op reads as a SURVIVING site, which is a finding in the campaign's own direction. A harness whose
// mutations quietly stop mutating manufactures the result it is looking for. So the mutation kinds are
// driven here against fixtures with KNOWN answers, both ways.
//
// THE CASE THAT JUSTIFIES THE WHOLE FILE is the paren-balanced discard. The first draft of that kind matched
// the call with a non-greedy `\([^;]*?\)`, which stops at the FIRST closing paren -- the NESTED call's paren
// whenever an argument is itself a call. On two real sites it produced
//   hybridVerify(verifier, serialise(sealed), true), b64urlDecode(sig))
// which PARSES CLEAN, passes `true` as a fourth argument, and discards nothing at all. Both arms would have
// run against an unmutated guard and been recorded as held by nothing.
//
// Run: node test/validate-guard-mutation-harness.ts

import { applyKind, armMovedStableOutput, balancedCallAt, classify, countAtOffset, discoverSites, normaliseLog, offsetOfCallOnLine, resolveIdx, sitesOfSpec, stableLines, uniqueAnchor } from "../scripts/guard-mutation-harness.mjs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function throws(label: string, fn: () => unknown): void {
  checks++;
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  console.log(threw ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!threw) failures++;
}

console.log("\n-- the balanced matcher, which is why this file exists --\n");

{
  const line = `    return await hybridVerify(verifier, serialise(sealed), decode(sig));`;
  const at = line.indexOf("hybridVerify");
  const span = balancedCallAt(line, at);
  ok("a call whose arguments are themselves calls matches to its OWN closing paren", span !== null && line.slice(span[0], span[1] + 1) === "hybridVerify(verifier, serialise(sealed), decode(sig))");
  const naive = line.match(/hybridVerify\([^;]*?\)/);
  ok("and the non-greedy form this replaced would have stopped short", naive !== null && naive[0] !== "hybridVerify(verifier, serialise(sealed), decode(sig))");
}

console.log("\n-- the mutation kinds, driven both ways --\n");

{
  // discard: the verdict must actually be thrown away, on nested and flat forms alike
  const flat = `  if (!(await hybridVerify(v, m, s))) throw x;`;
  const outFlat = applyKind(flat, { id: "t", kind: "discard", name: "hybridVerify" });
  ok("discard wraps a flat call in a comma expression", outFlat.includes("(await hybridVerify(v, m, s), true)"));

  const nested = `    return await hybridVerify(verifier, serialise(sealed), decode(sig));`;
  const outNested = applyKind(nested, { id: "t", kind: "discard", name: "hybridVerify" });
  ok("discard keeps the WHOLE nested call inside the comma expression", outNested.includes("(await hybridVerify(verifier, serialise(sealed), decode(sig)), true)"));
  ok("and it does not leave the call with an extra argument", /hybridVerify\(verifier, serialise\(sealed\), decode\(sig\), true\)/.test(outNested) === false);
  ok("the mutated line is balanced", (outNested.match(/\(/g) ?? []).length === (outNested.match(/\)/g) ?? []).length);

  // swap
  const swapped = applyKind(`  const x = await wrapSecret(k, p, AAD);`, { id: "t", kind: "swap", from: "wrapSecret", to: "wrapSecretTwin" });
  ok("swap changes the identifier and nothing else", swapped === `  const x = await wrapSecretTwin(k, p, AAD);`);
  throws("swap REFUSES when the target is not on the line", () => applyKind(`  const x = 1;`, { id: "t", kind: "swap", from: "wrapSecret", to: "wrapSecretTwin" }));
  throws("swap REFUSES two calls on one line, which would mutate two sites at once", () =>
    applyKind(`  const x = wrapSecret(a) + wrapSecret(b);`, { id: "t", kind: "swap", from: "wrapSecret", to: "wrapSecretTwin" }),
  );
  ok("swap does not fire on a PROPERTY of the same name", applyKind(`  const x = o.wrapSecret(a) + wrapSecret(b);`, { id: "t", kind: "swap", from: "wrapSecret", to: "T" }) === `  const x = o.wrapSecret(a) + T(b);`);

  // dropArg
  ok("dropArg removes exactly the named argument", applyKind(`  await w(k, p, PUSH_SECRET_AAD);`, { id: "t", kind: "dropArg", arg: ", PUSH_SECRET_AAD" }) === `  await w(k, p);`);
  throws("dropArg REFUSES when the argument is absent", () => applyKind(`  await w(k, p);`, { id: "t", kind: "dropArg", arg: ", PUSH_SECRET_AAD" }));

  // deleteStmt
  ok("deleteStmt replaces the guard with a no-op", applyKind(`      assertNoPlaintext(x);`, { id: "t", kind: "deleteStmt", stmt: "assertNoPlaintext(x);" }) === `      void 0;`);
  throws("deleteStmt REFUSES when the statement is absent", () => applyKind(`      other(x);`, { id: "t", kind: "deleteStmt", stmt: "assertNoPlaintext(x);" }));
}

console.log("\n-- a refusal is not a pass, and not a failure --\n");

ok("exit 0 is a pass", classify({ code: 0, log: "" }) === "pass");
ok("exit 4 is a REFUSAL", classify({ code: 4, log: "" }) === "refused");
// The one that cost a pass a site: a member exiting non-zero whose LOG says it could not check.
ok("a non-zero exit whose log reads NOT-REACHED is a REFUSAL, not a finding", classify({ code: 1, log: "discovery-token-set-refused ... NOT-REACHED ..." }) === "refused");
ok("an ordinary failing member is a finding", classify({ code: 1, log: "  FAIL something\n1 FAILURE(S)" }) === "found");
// THE CASE THAT COST FORTY KILLS. The first draft matched the bare word REFUSED anywhere in the log, so a
// validator that KILLED an arm and declared `VERDICT: FAIL` read as a could-not-check, because among its own
// assertion labels were sentences like "an envelope with NO wrap key bound is REFUSED, not returned". A
// DECLARED VERDICT MUST WIN OVER ANY PROSE.
ok(
  "a declared FAIL is a finding even when the prose says REFUSED",
  classify({ code: 1, log: '  ok   an envelope with NO wrap key bound is REFUSED, not returned\n1 FAILURE(S) of 187 checks\nVERDICT: FAIL failures=1 checks=187' }) === "found",
);
ok(
  "and a genuine runner refusal is still a refusal",
  classify({ code: 2, log: "VERDICT SKIPPED: test/validate-x.ts: REFUSED, exit 2: the docs checkout is behind its own origin/main" }) === "refused",
);
ok("a bare mention of the word refused in passing prose does not make a refusal", classify({ code: 1, log: "  FAIL the write was refused\n1 FAILURE(S)" }) === "found");

console.log("\n-- discovery walks the tree rather than a hand-kept list --\n");

{
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const sites = discoverSites(root, "src", "maybeWrapConfigSecret");
  // The count is asserted against the census in validate-secret-and-signature-guard-completeness.ts, which
  // reaches the same number by a different reader. Two readers, one answer.
  // 7 across 6 files since 2026-09-10, when the IdP client secret's write ingress joined them (POST
  // /idp/connections seals it under IDP_SECRET_AAD). Both numbers are asserted, because a site added in a
  // file already counted would leave the file total unchanged.
  ok("it finds the seven maybeWrapConfigSecret call sites", sites.length === 7);
  ok("across six files, so it is not reading one file and stopping", new Set(sites.map((s) => s.file)).size === 6);
  ok("and it excludes the declaration itself", sites.every((s) => s.file !== "admin/config-secret.ts"));
  const verify = discoverSites(root, "src", "hybridVerify");
  // Eleven since b236b6e4 (2026-08-11) added a second site to format/freshness.ts. Both readers are moved
  // together on purpose: the point of "two readers, one answer" is that a wrong number has to be written
  // twice to survive, and updating only the census would have left this one red and the pair silent.
  ok("it finds the eleven hybridVerify call sites", verify.length === 11);
  ok("and it does not confuse hybridVerify with hybridVerifyDetailed", verify.every((s) => !/hybridVerifyDetailed\s*\(/.test(s.text) || /(?<![.\w$])hybridVerify\s*\(/.test(s.text)));
}

console.log("\n-- precondition 6: an arm that changed nothing is a could-not-check, never a survivor --\n");

// The case that justifies this section, measured rather than imagined: another pass planted
// `if (!key.startsWith("seg/"))` on the run-tree copy loop in src/seal/replicate.ts, where every key is
// `run/<id>/...`, watched five validators stay green, and was one paragraph from reporting the replica's
// segment copying as held by nothing. The arm was a no-op. Under the old rule that is SURVIVED.
{
  // 1. The nondeterminism calibration. Two runs of the SAME tree disagree on clocks and random ids, and
  //    anything they disagree on cannot be evidence that an arm did something.
  const runA = "start\nrecords verified: 12\nrun 01J8ZZ0000000000000000000A took 41 ms\ndone";
  const runB = "start\nrecords verified: 12\nrun 01J8ZZ0000000000000000000B took 77 ms\ndone";
  const stable = stableLines(runA, runB);
  ok("the clock and the run id are normalised away, so two pristine runs agree on every line", stable.length === 4);
  ok("and the load-bearing line survives normalisation rather than being blurred out", stable.some((l) => l.includes("records verified: 12")));

  // 2. THE INERT ARM. Output identical to baseline: the arm changed nothing this member can see.
  ok("an arm whose output matches the pristine baseline is reported as NOT having moved anything", armMovedStableOutput(stable, runA) === false);
  ok("and it is still NOT moved when only the nondeterministic parts differ (a fresh run id and timing)", armMovedStableOutput(stable, "start\nrecords verified: 12\nrun 01J8ZZ000000000000000000ZZ took 5 ms\ndone") === false);

  // 3. THE LIVE ARM, which is the known-positive control. Without this the check could return false for
  //    everything and both cells above would pass while measuring nothing.
  ok("CONTROL: an arm that changes a stable line IS reported as moved", armMovedStableOutput(stable, "start\nrecords verified: 0\nrun 01J8ZZ0000000000000000000C took 9 ms\ndone") === true);
  ok("CONTROL: an arm that DROPS a stable line entirely is reported as moved", armMovedStableOutput(stable, "start\nrun 01J8ZZ0000000000000000000C took 9 ms\ndone") === true);

  // 4. The failure DIRECTION is the safety property: normalisation that is too blunt can only make a live
  //    arm look inert (withholding a finding), never make an inert arm look live (manufacturing one). A
  //    log of nothing but nondeterminism therefore yields an empty baseline, and an empty baseline can
  //    never report "moved", so such an arm is INERT-OR-UNOBSERVED rather than a site held by nothing.
  // A short id (below the 20-character threshold) is NOT normalised, so the two runs agree on nothing and
  // the baseline is empty. An empty baseline can never report "moved", so the arm is INERT-OR-UNOBSERVED:
  // the harness withholds a finding it cannot substantiate rather than inventing one.
  const allNoise = stableLines("run 01J8A took 3 ms", "run 01J8B took 9 ms");
  ok("a member whose whole output is nondeterministic yields an EMPTY baseline", allNoise.length === 0);
  ok("and an empty baseline cannot manufacture a finding (never reports moved)", armMovedStableOutput(allNoise, "run 01J8C took 4 ms") === false);

  // 5. normaliseLog trims trailing whitespace only, so an arm that changes real content is never hidden by it.
  ok("normalisation does not collapse two genuinely different content lines into one", normaliseLog("wrote 3 objects\nwrote 4 objects")[0] !== normaliseLog("wrote 3 objects\nwrote 4 objects")[1]);
}

{
  console.log("\n-- precondition 7a: a line number is not an address, and a drifted arm is not an inert one --");

  // the fourth attempt's corpus was pinned by line number and THREE of its 43 arms had moved within one day, because
  // two unrelated commits landed above them. An arm that never reaches its site and an arm that reaches it
  // and changes nothing BOTH end in "no member went red", and only one of them is a harness fault.
  const rows = ["import { a } from './a.ts';", "const x = wrapSecret(v, AAD);", "// filler", "const y = wrapSecret(w, AAD2);"];
  ok("an arm whose recorded line still carries its anchor is not moved", resolveIdx({ id: "A", line: 2, file: "f.ts", anchor: "const x = wrapSecret(v, AAD);" }, rows, 0).idx === 1);
  ok("and an arm with NO anchor is taken at its line, which is the old behaviour unchanged", resolveIdx({ id: "A", line: 2, file: "f.ts" }, rows, 0).idx === 1);
  // The drifted case: the arm was recorded at line 4 and its content now sits at line 2.
  const drifted = resolveIdx({ id: "A", line: 4, file: "f.ts", anchor: "const x = wrapSecret(v, AAD);" }, rows, 0);
  ok("a drifted arm is RELOCATED to the line that carries its anchor", drifted.idx === 1);
  ok("and the drift is REPORTED rather than silently absorbed", drifted.drift?.recorded === 4 && drifted.drift?.found === 2);
  // THE TWO REFUSALS, which are the point. A family here has up to ten sites and four files hold more than
  // one, so relocating to the wrong one would mutate a guard nobody asked about and file the answer under
  // this arm's name.
  throws("a site whose anchor is GONE is a REFUSAL, never the nearest similar line", () => resolveIdx({ id: "A", line: 2, file: "f.ts", anchor: "const x = wrapSecret(v, DELETED);" }, rows, 0));
  throws("an anchor matching TWO windows is a REFUSAL, because it cannot tell the sites apart", () => resolveIdx({ id: "A", line: 9, file: "f.ts", anchor: "// filler" }, ["// filler", "x", "// filler"], 0));
  ok("the import scaffolding shift is still applied to an un-anchored arm", resolveIdx({ id: "A", line: 1, file: "f.ts" }, rows, 1).idx === 1);

  // A SINGLE LINE IS NOT ENOUGH ON THIS VERY CORPUS: it is ambiguous for EIGHT of the fourth attempt's 43 arms,
  // including format/reader.ts:397 and :566, the character-identical pair its headline was built on. So an
  // anchor is a WINDOW ending at the site.
  const twin = ["function a() {", "  if (!(await verify(v, b, s))) {", "}", "function z() {", "  if (!(await verify(v, b, s))) {", "}"];
  // The hazard is not the ambiguity by itself, it is ambiguity ONCE THE LINE HAS MOVED: while the recorded
  // line still carries the anchor nothing is searched for. This cell was written the other way round at
  // first and the self-test refuted it, which is the whole reason the cells are driven rather than reasoned.
  ok("an ambiguous anchor is harmless while the recorded line still carries it", resolveIdx({ id: "C10", line: 5, file: "reader.ts", anchor: "if (!(await verify(v, b, s))) {" }, twin, 0).idx === 4);
  throws("but once the line has DRIFTED, a one-line anchor matching the twin REFUSES rather than picking the first", () => resolveIdx({ id: "C10", line: 3, file: "reader.ts", anchor: "if (!(await verify(v, b, s))) {" }, twin, 0));
  ok("uniqueAnchor widens the window until it occurs exactly once", uniqueAnchor(twin, 5) === "function z() {\nif (!(await verify(v, b, s))) {");
  ok("and the widened anchor resolves to the SECOND of the two identical sites, not the first", resolveIdx({ id: "C10", line: 5, file: "reader.ts", anchor: uniqueAnchor(twin, 5) as string }, twin, 0).idx === 4);
  ok("CONTROL: the same widening on the FIRST site resolves to the first", resolveIdx({ id: "C9", line: 2, file: "reader.ts", anchor: uniqueAnchor(twin, 2) as string }, twin, 0).idx === 1);
  ok("a drifted multi-line anchor is still relocated by content", resolveIdx({ id: "C10", line: 2, file: "reader.ts", anchor: uniqueAnchor(twin, 5) as string }, twin, 0).drift?.found === 5);
  ok("uniqueAnchor returns null when nothing in the window can disambiguate", uniqueAnchor(["x", "x"], 2, 1) === null);

  console.log("\n-- precondition 7b: a site no member executes cannot be judged by mutating it --");

  const src = "const a = 1;\nif (cond) wrapSecret(v, AAD);\nconst b = 2;\n";
  // The probe is the CALL, not the line: a line can execute its head and never reach the call.
  ok("the probe offset lands on the call, not on the start of the line", src.slice(offsetOfCallOnLine(src, 2, "wrapSecret")).startsWith("wrapSecret("));
  ok("and with no name it falls back to the first non-space byte of the line", src.slice(offsetOfCallOnLine(src, 2, null)).startsWith("if (cond)"));
  const off = offsetOfCallOnLine(src, 2, "wrapSecret");
  const url = "file:///x/f.ts";
  // V8 nests ranges and an inner range OVERRIDES its parent. Taking the outer one would report a whole
  // function's entry count for a branch that never ran, which is the direction that reports a site as
  // driven when it is not.
  const cov = { result: [{ url, functions: [{ ranges: [{ startOffset: 0, endOffset: src.length, count: 7 }, { startOffset: off - 10, endOffset: off + 25, count: 0 }] }] }] };
  ok("CONTROL: the INNERMOST range wins, so an unexecuted branch inside an executed function reads 0", countAtOffset(cov, url, off) === 0);
  const cov2 = { result: [{ url, functions: [{ ranges: [{ startOffset: 0, endOffset: src.length, count: 7 }, { startOffset: off - 10, endOffset: off + 25, count: 3 }] }] }] };
  ok("CONTROL: an executed branch reads its own count, not the enclosing function's", countAtOffset(cov2, url, off) === 3);
  ok("a script this process never loaded is null, which is not the same as loaded-and-not-reached", countAtOffset(cov, "file:///x/other.ts", off) === null);

  // Arms that share a call share a SITE. A5 and AAD4 are one call on admin/router-push.ts:262, and counting
  // that site twice would double its reachability.
  const sites = sitesOfSpec({ arms: [{ id: "A5", file: "r.ts", line: 262, from: "wrapSecret" }, { id: "AAD4", file: "r.ts", line: 262, kind: "dropArg", arg: ", AAD" }, { id: "A6", file: "r.ts", line: 265, from: "wrapSecret" }] });
  ok("two arms on one call collapse to ONE site", sites.length === 2);
  ok("and the site carries both arm ids", sites[0].arms.join(",") === "A5,AAD4");
  ok("and it takes the callee name from whichever arm names it", sites[0].name === "wrapSecret");
}

console.log(failures === 0 ? `\nGUARD MUTATION HARNESS PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
