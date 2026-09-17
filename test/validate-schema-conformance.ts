// JSON-Schema conformance gate: the positive conformance vectors carry real downpipe/0.1.0
// cleartext format objects, and docs/format/schema.json is the normative JSON shape for those
// objects. This validator compiles schema.json with ajv (draft 2020-12) and validates every
// plain-JSON format object in the POSITIVE vector corpus against it, failing CI on any violation.
//
// What this gates that the writer->reader interop demo (ci.yml e2e-writer-reader) does NOT: that
// the bytes the writer emits still match the PUBLISHED JSON shape, field for field, with the schema
// as the contract. The interop demo proves the two implementations agree on bytes; this proves the
// bytes agree with the documented schema, so a schema/emitter drift is caught even if both sides
// drift together.
//
// Scope and why only the positive corpus:
//   - The schema-constrained plain-JSON objects present in a vector archive are the RootManifest
//     (run/<id>/root.manifest.json) and the RunlogEntry lines (_RECOVERY/RUNLOG). The shard
//     manifests (ShardPreamble + ShardRecord) live inside the encrypted .dpe stream and are not
//     plain JSON on disk, so they are covered by the interop demo (which decrypts and recomputes),
//     not here. The RestoreReceipt is emitted by the reader at restore time, not stored in a vector.
//   - NEGATIVE vectors deliberately corrupt format objects. Some corruptions violate the schema
//     (for example unknown-major sets formatVersion to downpipe/9.0, which the const rejects) and
//     some do not (in-range-count-as-string sets a count to a string, which the countField oneOf
//     still accepts because JSON Schema cannot express the 2^53 threshold). Validating negatives
//     against the schema would be meaningless either way, so the negative corpus is out of scope:
//     it is covered by the interop demo's reject-path and the bespoke validators.
//
// Schema source and drift:
//   - Prefers $DOWNPIPE_REPO/docs/format/schema.json (the SAME live schema the e2e job checks out),
//     so this validator cross-checks against the canonical source when it is available.
//   - Falls back to the vendored copy at test/vectors/schema.json (needed because the required
//     `validate` CI job does not check out the downpipe repo; only the e2e job does).
//   - The vendored copy is pinned by its SHA-384 in test/vectors/SCHEMA_SHA384; a silent edit to the
//     vendored copy fails here. When both the DOWNPIPE_REPO schema and the vendored copy are present
//     they MUST be byte-identical, so a divergence between the engine's pinned copy and the live
//     schema is caught (this is the real anti-drift guard; the schema legitimately evolves after any
//     given test/vectors/VECTORS_COMMIT, so the schema is not pinned to that commit).
//
// Run: node test/validate-schema-conformance.ts
//      DOWNPIPE_REPO=/path/to/downpipe node test/validate-schema-conformance.ts   (cross-check live)

import { readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(HERE, "vectors");
const VENDORED_SCHEMA = join(VECTORS_DIR, "schema.json");
const VENDORED_SHA_FILE = join(VECTORS_DIR, "SCHEMA_SHA384");

let pass = 0;
let fail = 0;
function ok(msg: string): void {
  pass++;
  console.log(`  ok   ${msg}`);
}
function bad(msg: string): void {
  fail++;
  console.error(`  FAIL ${msg}`);
}

function sha384(b: Buffer): string {
  return createHash("sha384").update(b).digest("hex");
}

// ---- resolve and verify the schema source -------------------------------------------------------

const vendoredBytes = readFileSync(VENDORED_SCHEMA);
const expectedSha = readFileSync(VENDORED_SHA_FILE, "utf8").trim();
const vendoredSha = sha384(vendoredBytes);
if (vendoredSha === expectedSha) {
  ok(`vendored test/vectors/schema.json matches its pinned SHA-384 (${expectedSha.slice(0, 16)}...)`);
} else {
  bad(
    `vendored schema SHA-384 drift: pinned ${expectedSha} but file is ${vendoredSha}. ` +
      `If the schema changed deliberately, re-vendor it and update test/vectors/SCHEMA_SHA384.`,
  );
}

const downpipeRepo = process.env.DOWNPIPE_REPO;
// Annotate as Buffer so the live-schema reassignment below (a Buffer<ArrayBufferLike> from readFileSync) is
// assignable: inferring the type from vendoredBytes pins the narrower NonSharedBuffer flavour.
let schemaBytes: Buffer = vendoredBytes;
let schemaSource = "vendored test/vectors/schema.json";
if (downpipeRepo) {
  const live = join(downpipeRepo, "docs", "format", "schema.json");
  let liveBytes: Buffer | null = null;
  try {
    liveBytes = readFileSync(live);
  } catch {
    liveBytes = null;
  }
  if (liveBytes) {
    // WHICH DOWNPIPE TREE, and REFUSE when it is not the sibling's main. Only this arm is guarded: without
    // DOWNPIPE_REPO the gate grades the vendored copy against its own pinned SHA-384 and reads no sibling at
    // all, so a freshness refusal there would be a refusal about nothing.
    //
    // The whole claim of this arm is "byte-identical to the LIVE canonical schema". A downpipe checkout that
    // is behind makes that sentence false in both directions and says neither out loud: an ok() line asserts
    // no drift against a canonical schema that has since moved, and a bad() line orders a re-vendor from a
    // tree whose format/schema.json main has already changed again. The gate is a hash comparison and costs
    // milliseconds to re-run, so refusing costs almost nothing and a wrong re-vendor costs a pinned SHA.
    reportSiblings([{ name: "downpipe", path: downpipeRepo }], { gate: "schema-conformance (live cross-check)" });
    requireFreshSiblings([{ name: "downpipe", path: downpipeRepo }], {
      gate: "schema-conformance (live cross-check)",
      consequence: "the no-drift claim would be about an older canonical schema than the published one",
      exit: (code: number) => {
        verdictSkipped(`REFUSED, exit ${code}: the downpipe checkout at DOWNPIPE_REPO is behind its own origin/main, so nothing was concluded`);
        process.exit(code);
      },
    });
    schemaBytes = liveBytes;
    schemaSource = live;
    if (sha384(liveBytes) === vendoredSha) {
      ok("DOWNPIPE_REPO schema.json is byte-identical to the vendored engine copy (no drift)");
    } else {
      bad(
        `DOWNPIPE_REPO schema.json (${live}) differs from the vendored engine copy. ` +
          `Re-vendor test/vectors/schema.json from the downpipe repo and update SCHEMA_SHA384.`,
      );
    }
  } else {
    console.log(`  note DOWNPIPE_REPO set but ${live} not found; using the vendored copy`);
  }
}

const schema = JSON.parse(schemaBytes.toString("utf8"));
// strict:false because schema.json is the canonical published schema, authored for general
// JSON-Schema validators and the Go reader; it uses conditional `then.required` shapes that ajv's
// strict authoring mode flags even though they are valid draft 2020-12. We validate the data against
// the schema as published, we do not re-author it.
const ajv = new Ajv2020({ allErrors: true, strict: false });
ajv.addSchema(schema, "downpipe-1.0");

const validateRootManifest = ajv.getSchema("downpipe-1.0#/$defs/RootManifest");
const validateRunlogEntry = ajv.getSchema("downpipe-1.0#/$defs/RunlogEntry");
if (!validateRootManifest) {
  bad("schema has no $defs/RootManifest (cannot gate the run manifest)");
}
if (!validateRunlogEntry) {
  bad("schema has no $defs/RunlogEntry (cannot gate the runlog)");
}

console.log(`  note schema source: ${schemaSource}`);

// ---- adversary check: the schema must actually CONSTRAIN the objects it is gating ----------------
// Guard against a vacuous pass: confirm the run-manifest and runlog objects carry required +
// additionalProperties so a corrupted/extra field is genuinely rejected. If the schema ever loosens
// these, the gate would silently stop gating, so fail loudly.
const rm = schema?.$defs?.RootManifest;
if (rm && Array.isArray(rm.required) && rm.required.length > 0 && rm.additionalProperties === false) {
  ok(`RootManifest is constrained (required: ${rm.required.length} fields, additionalProperties:false)`);
} else {
  bad("RootManifest is not meaningfully constrained (missing required[] or additionalProperties:false)");
}
const re = schema?.$defs?.RunlogEntry;
if (re && Array.isArray(re.required) && re.required.length > 0 && re.additionalProperties === false) {
  ok(`RunlogEntry is constrained (required: ${re.required.length} fields, additionalProperties:false)`);
} else {
  bad("RunlogEntry is not meaningfully constrained (missing required[] or additionalProperties:false)");
}

// ---- walk the positive corpus -------------------------------------------------------------------

function readExpect(vectorDir: string): { mode?: string } | null {
  const p = join(vectorDir, "expect.json");
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function findFiles(root: string, name: string): string[] {
  const out: string[] = [];
  function walk(dir: string): void {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (entry === name) out.push(full);
    }
  }
  try {
    walk(root);
  } catch {
    /* archive may be absent for crypto-only vectors */
  }
  return out;
}

function ajvErrors(v: ReturnType<typeof ajv.getSchema>): string {
  return (v?.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ");
}

let manifestsChecked = 0;
let runlogEntriesChecked = 0;
let positiveVectors = 0;

if (validateRootManifest && validateRunlogEntry) {
  for (const name of readdirSync(VECTORS_DIR).sort()) {
    const vectorDir = join(VECTORS_DIR, name);
    let st;
    try {
      st = statSync(vectorDir);
    } catch {
      continue;
    }
    if (!st.isDirectory()) continue;
    const expect = readExpect(vectorDir);
    // Only the positive archives carry well-formed format objects; skip negatives and any
    // vector without an expect.json (the crypto KAT corpora are not archives).
    if (!expect || expect.mode !== "positive") continue;
    positiveVectors++;

    const archive = join(vectorDir, "archive");
    for (const mf of findFiles(archive, "root.manifest.json")) {
      const data = JSON.parse(readFileSync(mf, "utf8"));
      manifestsChecked++;
      if (validateRootManifest(data)) {
        ok(`RootManifest conforms: ${mf.slice(VECTORS_DIR.length + 1)}`);
      } else {
        bad(`RootManifest violates schema: ${mf.slice(VECTORS_DIR.length + 1)} -- ${ajvErrors(validateRootManifest)}`);
      }
    }

    for (const rl of findFiles(archive, "RUNLOG")) {
      const lines = readFileSync(rl, "utf8").split("\n").filter((l) => l.trim().length > 0);
      for (const [i, line] of lines.entries()) {
        const data = JSON.parse(line);
        runlogEntriesChecked++;
        if (validateRunlogEntry(data)) {
          ok(`RunlogEntry conforms: ${rl.slice(VECTORS_DIR.length + 1)} line ${i + 1}`);
        } else {
          bad(
            `RunlogEntry violates schema: ${rl.slice(VECTORS_DIR.length + 1)} line ${i + 1} -- ${ajvErrors(validateRunlogEntry)}`,
          );
        }
      }
    }
  }
}

// The corpus must not be empty, or the gate would pass vacuously.
if (positiveVectors === 0 || manifestsChecked === 0 || runlogEntriesChecked === 0) {
  bad(
    `empty corpus: positiveVectors=${positiveVectors} manifests=${manifestsChecked} runlogEntries=${runlogEntriesChecked}` +
      " (expected to validate format objects from several positive vectors)",
  );
} else {
  ok(
    `validated ${manifestsChecked} RootManifest + ${runlogEntriesChecked} RunlogEntry across ${positiveVectors} positive vectors`,
  );
}

console.log("");
verdictReached(fail);
if (fail > 0) {
  console.error(`SCHEMA CONFORMANCE FAILED: ${fail} failure(s), ${pass} ok`);
  process.exit(1);
}
console.log(`SCHEMA CONFORMANCE PASS (${pass} checks)`);
