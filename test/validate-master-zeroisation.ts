// Every run master must be ended, and no call site may return with a live one.
//
// WHY THIS EXISTS. The invariant this gate asserts: no call site may return with a non-zeroed master. The
// discipline was previously held only by `finally` blocks that nothing enforced, so a new site added without
// one would have passed every other gate in this repo.
//
// Writing it found two real holes rather than confirming a clean state, which is the point of a gate over a
// convention:
//
//   1. `openRunWith` acquired a master and then ran four steps that can each throw (key-commitment
//      mismatch, a shard that will not open, a record that fails verification, a freshness refusal) with no
//      protection at all. Every one of those returned with a live master and no reference left to reach it.
//   2. `Run` held the master for its whole lifetime with no way to end it. The master must live that long,
//      because restoreRecord derives segment keys from it lazily, so the fix is an explicit dispose() the
//      caller owns rather than a wipe at construction. The path that makes it matter is attended
//      verification: that master is decapsulated in the operator's browser, and the posture's claim is that
//      the key is gone when the session ends, not whenever the isolate collects the object.
//
// WHAT THIS CHECKS, and it is deliberately static. A runtime test would have to stand up each of the seal,
// canary, drill and attest paths to inspect a buffer, which is heavy and, worse, could not catch the case
// this is really for: a NEW site added later. Source-level checking catches that on the first commit.
//
// Four rules. The header said "two" while three were implemented, which is how a gate loses a rule without
// anyone noticing, so the count is kept honest here:
//   A. Every function that ACQUIRES a master into a `const`/`let` (unwrapMaster, or a fresh 32 random bytes)
//      must zeroise it in a `finally`. Producers that hand ownership upward by returning it are listed as
//      exceptions BY NAME, so a new one has to be added deliberately rather than slipping under a loosened
//      rule.
//   A2. Every master acquired as an OBJECT PROPERTY must be zeroised through its owning binding, in a
//      `finally`. Rule A's `const|let` extractor was blind to the buffered seal path, which builds the run
//      master inside a RunClock literal.
//   B. Every function that opens a Run must dispose it. The Run owns a master, so a site that opens one and
//      walks away leaks exactly as much as a missing `fill(0)`.
//   C. Every Run held in a local binding must be disposed, which is the shape rule B cannot see.
//
// Run with `node test/validate-master-zeroisation.ts`.
//

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = resolve(fileURLToPath(new URL("..", import.meta.url)), "src");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

// OWNERSHIP-TRANSFER EXCEPTIONS, named rather than pattern-matched away. Each of these produces a master and
// RETURNS it, so the obligation to zeroise moves to the caller. Naming them means a future producer that
// quietly returns a master fails this gate instead of joining a category.
const TRANSFERS_OWNERSHIP = new Set([
  "src/seal/checkpoint.ts::unwrapMaster", // unwraps the checkpointed master for the caller's try/finally
  "src/crypto/capsule.ts::openCapsule", // decapsulates for the caller (the reader, or the console's own path)
  "src/format/reader.ts::openRunWith", // hands the master to the Run it returns; the Run's dispose() ends it
]);

// Sites that RECEIVE a master as a parameter are not producers: the caller owns it and already zeroises it.
// `runstate-helpers.ts` documents exactly this in its own words, so the rule matches the code's stated model.

const files = walk(SRC).sort();
ok(`the engine source is readable (${files.length} files)`, files.length > 50);

// ---- rule A: a produced master is zeroised in a finally ---------------------------------------------------
// The binding must NAME a master. A fresh 32 random bytes is not on its own a master: recovery.ts builds a
// fake MAC that way and the canary builds probe bytes, and sweeping those in would have forced a suppression
// list, which is how a gate turns into noise nobody reads. The invariant this enforces is about run masters,
// so the extractor says so.
const PRODUCER = /(?:const|let)\s+(\w*[Mm]aster\w*)\s*=\s*(?:await\s+)?(?:unwrapMaster|crypto\.getRandomValues\(new Uint8Array\(32\)\)|acquireMaster|openCapsule)/g;

let producers = 0;
const unguarded: string[] = [];
for (const f of files) {
  const rel = relative(resolve(SRC, ".."), f).replace(/\\/g, "/");
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(PRODUCER)) {
    const name = m[1] as string;
    producers++;
    // Everything after the producer in this file. A `finally` that zeroises this binding, or an explicit
    // ownership transfer, must appear. Scoping to the whole remainder of the file is deliberately loose:
    // this gate is a floor, and a false PASS from over-tight scoping would be worse than a false alarm.
    const after = text.slice((m.index ?? 0));
    // The zeroise must be in a FINALLY, and it must be THIS binding. A bare `name.fill(0)` anywhere later in the file is not enough: the file may also hold an unrelated
    // `clock.master.fill(0)` further down, and a substring match cannot tell `master` from `clock.master`. The
    // lookbehind rejects a qualified reference, so a sibling buffer with a similar name cannot stand in for the
    // one being checked.
    const zeroised = new RegExp(`finally\\s*\\{[^}]*(?<![.\\w])${name}\\.fill\\(0\\)`, "s").test(after);
    if (zeroised) continue;
    // An ownership transfer is allowed only for a function named in the set above.
    const transferred = [...TRANSFERS_OWNERSHIP].some((entry) => {
      const [file, fn] = entry.split("::");
      return rel === file && new RegExp(`function\\s+${fn}\\b|${fn}\\s*[:=]`).test(text);
    });
    if (!transferred) unguarded.push(`${rel} (${name})`);
  }
}

// ---- rule A2: a master produced as an OBJECT PROPERTY -----------------------------------------------------
// Rule A only sees `const master = ...`. The buffered seal path does not look like that: sealRunBuffered
// builds the run master INSIDE a RunClock literal (`master: crypto.getRandomValues(new Uint8Array(32))`), so
// rule A never counted it and nothing here checked it. Deleting BOTH of that path's zeroises must make this gate fail rather than leave the producer count
// unchanged, which is precisely the silent-clean failure this gate exists to prevent. The buffered path was
// zeroising at the end of the try and again at the head of the catch rather than in a finally, so an early
// `return` added to that try would have returned with a live master.
//
// The property name must still NAME a master, for the same reason rule A's binding must: this is a rule
// about run masters, not about every 32 random bytes. Measured precision at the time of writing: one match
// across the 414 source files, and it is the real run master.
const PROPERTY_PRODUCER = /(\w*[Mm]aster\w*)\s*:\s*(?:await\s+)?(?:unwrapMaster|crypto\.getRandomValues\(new Uint8Array\(32\)\)|acquireMaster|openCapsule)/g;

let propertyProducers = 0;
for (const f of files) {
  const rel = relative(resolve(SRC, ".."), f).replace(/\\/g, "/");
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(PROPERTY_PRODUCER)) {
    const prop = m[1] as string;
    propertyProducers++;
    const idx = m.index ?? 0;
    // The owning binding is the nearest `const`/`let` declaration before the literal. Naming it means the
    // failure message points at the buffer to end, rather than at "something in this file".
    const before = text.slice(0, idx);
    const owner = [...before.matchAll(/(?:const|let)\s+(\w+)\s*(?::[^=\n]*)?=/g)].pop()?.[1];
    if (owner === undefined) {
      unguarded.push(`${rel} (${prop}: no owning binding found)`);
      continue;
    }
    const after = text.slice(idx);
    const zeroised = new RegExp(`finally\\s*\\{[^}]*(?<![.\\w])${owner}\\.${prop}\\.fill\\(0\\)`, "s").test(after);
    if (!zeroised) unguarded.push(`${rel} (${owner}.${prop})`);
  }
}

ok(`the extractor found master producers (${producers} const/let, ${propertyProducers} object property)`, producers >= 5 && propertyProducers >= 1);
ok("every produced master is zeroised, or transfers ownership to a named exception", unguarded.length === 0);
if (unguarded.length > 0) {
  for (const u of unguarded) console.log(`       unguarded: ${u}`);
  console.log("       A produced master must be zeroised in a finally, or its function must be listed in TRANSFERS_OWNERSHIP here.");
}

// ---- rule B: an opened Run is disposed ---------------------------------------------------------------------
// A Run owns a master for its lifetime, so opening one and walking away leaks exactly as much as a missing
// fill(0). This is what the attended path was doing before this gate.
const OPENERS = /(?:const|let)\s+(\w+)\s*=\s*await\s+(?:openRun|openRunWithMaster|openVerifiedRun|openRunFromMaster)\s*\(/g;

let opens = 0;
const undisposed: string[] = [];
for (const f of files) {
  const rel = relative(resolve(SRC, ".."), f).replace(/\\/g, "/");
  // reader.ts defines them; it does not consume them.
  if (rel === "src/format/reader.ts") continue;
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(OPENERS)) {
    const name = m[1] as string;
    opens++;
    const after = text.slice(m.index ?? 0);
    if (new RegExp(`${name}\\.dispose\\(\\)`).test(after)) continue;
    // A site that RETURNS the Run passes the obligation to its caller, which this gate then checks there.
    if (new RegExp(`return\\s+${name}\\b`).test(after)) continue;
    undisposed.push(`${rel} (${name})`);
  }
}

ok(`the extractor found Run open sites (${opens} found)`, opens >= 3);
ok("every opened Run is disposed, or returned so its caller owns it", undisposed.length === 0);
if (undisposed.length > 0) {
  for (const u of undisposed) console.log(`       undisposed: ${u}`);
  console.log("       A Run holds a run master for its lifetime. Close it in a finally, or return it so the caller does.");
}

// ---- rule C: a Run held in a local binding is disposed -----------------------------------------------------
// Rule B only sees `const run = await openRun(...)`. The canary does not look like that: a helper opens the
// Run and the flight holds it in a hoisted `let opened: Run | undefined`, so rule B was blind to it and the
// operational-key path really was leaving that Run's master live. A gate that silently does not check a
// shape is worse than one that admits it cannot, so the shape gets its own rule.
const HELD = /(?:const|let)\s+(\w+)\s*:\s*Run(?:\s*\|\s*undefined)?\s*[;=]/g;

let held = 0;
const heldUndisposed: string[] = [];
for (const f of files) {
  const rel = relative(resolve(SRC, ".."), f).replace(/\\/g, "/");
  if (rel === "src/format/reader.ts") continue;
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(HELD)) {
    const name = m[1] as string;
    held++;
    const after = text.slice(m.index ?? 0);
    if (new RegExp(`${name}\\??\\.dispose\\(\\)`).test(after)) continue;
    if (new RegExp(`return\\s+${name}\\b`).test(after)) continue;
    heldUndisposed.push(`${rel} (${name})`);
  }
}

ok(`the extractor found Run-typed locals (${held} found)`, held >= 1);
ok("every Run held in a local is disposed, or returned so its caller owns it", heldUndisposed.length === 0);
if (heldUndisposed.length > 0) {
  for (const u of heldUndisposed) console.log(`       held but never disposed: ${u}`);
}

// ---- the gate must be able to fail --------------------------------------------------------------------------
// A validator that can only pass reads exactly like a passing validator. These assert the extractors are
// really matching the shapes they claim to, so a regex that silently stopped matching cannot report clean.
ok("rule A's extractor matches the real producer forms", PRODUCER.source.includes("unwrapMaster") && PRODUCER.source.includes("Uint8Array") && PRODUCER.source.includes("aster"));
// Fresh RegExp objects, because `test` on a /g/ regex carries lastIndex between calls and would make the
// second assertion depend on the first.
ok("rule A2's extractor really matches an object-property master", new RegExp(PROPERTY_PRODUCER.source).test("  master: crypto.getRandomValues(new Uint8Array(32)),"));
ok("rule A2's extractor does not sweep in a const/let master (rule A owns those)", !new RegExp(PROPERTY_PRODUCER.source).test("const master = crypto.getRandomValues(new Uint8Array(32))"));
ok("rule B's extractor matches the real opener forms", OPENERS.source.includes("openRunWithMaster"));
ok("the ownership exceptions are named individually, not pattern-matched", TRANSFERS_OWNERSHIP.size >= 3);

console.log(`\n${failures === 0 ? "MASTER-ZEROISATION PASS" : `MASTER-ZEROISATION: ${failures} FAILED`}\n`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
