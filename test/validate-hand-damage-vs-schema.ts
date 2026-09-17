// Every hand-written damage value must still be a value Cloudflare declares.
//
// WHY THIS EXISTS
// ---------------
// cf-hand-damage.ts exists because the singleton prover's flipOf only knows two-valued vocabularies, so a
// three-member enum leaves the surface unproven. The table lets a human supply the value instead, and the
// single rule that makes that safe is that the value is QUOTED FROM THE VENDOR'S SCHEMA rather than
// guessed. Two Cloudflare 500s earlier in this work were misattributed as vendor bugs when both were
// guessed values of mine.
//
// A rule that lives only in a comment is a rule until someone is in a hurry. This checks it.
//
// It is also the guard against the table going stale. Cloudflare removes enum members; when
// validation_default_mitigation_action stops accepting "log", the honest outcome is this gate failing,
// not a live harness sending a value the API no longer takes and the surface quietly falling out of the
// proven set with a confusing reason recorded against it.
//
// WHAT IT CHECKS, per entry
// -------------------------
//   1. the surface exists, has a writer, and the writer declares its method and path
//   2. that method and path resolve to a real operation in the published schema
//   3. the damaged field is a property of that operation's request body
//   4. every candidate value is legal there: a member of the declared enum, or inside the declared
//      minimum/maximum, or of the declared type when the schema constrains neither
//
// Point 4 is the one worth having. The rest can be got right by accident.
//
// The schema is gitignored and ~22MB. Absent, this SKIPS, unless REQUIRE_CF_OPENAPI=1, matching
// validate-autoprove-bodies-vs-schema.ts. A gate that opts out when it cannot check reads as a pass, so
// CI sets that variable.
//
// IT DID NOT UNTIL, and the line above said it did for as long as it was untrue. This file runs
// inside `npm run validate`, and the only step that fetches the schema sits AFTER that in the workflow, so
// on a runner the schema has never been on disk by the time this looks. It printed "SCHEMA CHECK SKIPPED"
// and exited 0 on every CI run it has ever had, which is the exact failure the paragraph above describes,
// stated as a fact about a variable nobody had checked was set. Section 2 of the drift guard had already
// been through this and been fixed (cf-drift-section2-never-runs-in-ci); the same fix did not reach here or
// its sibling. The workflow now runs both after the fetch, in the requiring form.
//
//   node test/validate-hand-damage-vs-schema.ts
//   REQUIRE_CF_OPENAPI=1 node test/validate-hand-damage-vs-schema.ts

import { existsSync, readFileSync } from "node:fs";
import { HAND_DAMAGE } from "./cf-hand-damage.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const SCHEMA = new URL("./vectors/cf-openapi/openapi.json", import.meta.url);

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

if (!existsSync(SCHEMA)) {
  if (process.env.REQUIRE_CF_OPENAPI === "1") {
    console.error("FAIL no vendored Cloudflare OpenAPI schema and REQUIRE_CF_OPENAPI=1.");
    console.error("     Run: node scripts/fetch-cf-openapi.mjs");
    process.exit(1);
  }
  console.log("HAND DAMAGE SCHEMA CHECK SKIPPED: no vendored OpenAPI schema (set REQUIRE_CF_OPENAPI=1 to require it)");
  verdictSkipped("HAND DAMAGE SCHEMA CHECK SKIPPED: no vendored OpenAPI schema (set REQUIRE_CF_OPENAPI=1 to require it)");
  process.exit(0);
}

interface SchemaNode {
  $ref?: string;
  type?: string;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  properties?: Record<string, SchemaNode>;
  allOf?: SchemaNode[];
  oneOf?: SchemaNode[];
  anyOf?: SchemaNode[];
  requestBody?: SchemaNode;
  content?: Record<string, { schema?: SchemaNode }>;
}

const doc = JSON.parse(readFileSync(SCHEMA, "utf8")) as {
  paths?: Record<string, Record<string, SchemaNode>>;
};

// $ref chasing, depth-capped rather than cycle-tracked: the depth a real Cloudflare body reaches is small,
// and an unbounded chase on a self-referential schema hangs the gate instead of failing it.
function deref(node: SchemaNode | undefined, depth = 0): SchemaNode | undefined {
  if (node === undefined || depth > 12) return node;
  if (typeof node.$ref !== "string") return node;
  let target: unknown = doc;
  for (const part of node.$ref.replace(/^#\//, "").split("/")) {
    target = (target as Record<string, unknown> | undefined)?.[part];
  }
  return deref(target as SchemaNode | undefined, depth + 1);
}

// Cloudflare wraps many bodies in allOf/oneOf. MERGE every branch that carries properties rather than
// taking the first.
//
// Taking the first was wrong and hid a field. Reading the account dns_settings PATCH body that way reported
// zone_defaults as declaring exactly one property, `nameservers`, because that is all the first branch
// holds. Merged, it declares nine, including the multi_provider the table below now damages. A gate that
// silently sees one field where the vendor declares nine will refuse a legitimate entry and send whoever
// added it looking for a fault in their own path.
function objectSchema(node: SchemaNode | undefined, depth = 0): SchemaNode | undefined {
  const cur = deref(node);
  if (cur === undefined || depth > 6) return cur;
  if (cur.properties !== undefined) return cur;
  const branches = cur.allOf ?? cur.oneOf ?? cur.anyOf;
  if (branches === undefined || branches.length === 0) return cur;
  const merged: Record<string, SchemaNode> = {};
  for (const branch of branches) {
    const resolved = objectSchema(branch, depth + 1);
    if (resolved?.properties !== undefined) Object.assign(merged, resolved.properties);
  }
  return Object.keys(merged).length > 0 ? { properties: merged } : cur;
}

// resolveField walks a damage path through the request body and returns the schema of the field it names.
//
// This exists because the table needs NESTED entries. account-dns-settings returns one object from its GET,
// zone_defaults, so every damageable field on it is nested by construction, and a gate that could only
// check top-level fields had to refuse the entry outright. Refusing was the right interim behaviour (a
// check that silently stops checking is the failure this campaign keeps finding) but it is not a place to
// stay.
//
// Returns the field's schema, or a string saying which segment failed, so the caller can report WHERE the
// path left the schema rather than a bare "not found".
function resolveField(body: SchemaNode, path: ReadonlyArray<string | number>): SchemaNode | string {
  let node: SchemaNode = body;
  for (let i = 0; i < path.length - 1; i++) {
    const seg = String(path[i]);
    const child = objectSchema(node.properties?.[seg]);
    if (child?.properties === undefined) return `${seg} is not an object with properties in the schema`;
    node = child;
  }
  const last = String(path[path.length - 1]);
  const field = deref(node.properties?.[last]);
  return field ?? `${last} is not a property of ${path.length > 1 ? String(path[path.length - 2]) : "the request body"}`;
}

// The writer's own declared path, with the placeholders the schema uses. The writer builds a concrete path
// from real ids, so the ids are substituted back out rather than the path being written down twice. Writing
// it twice is what this whole campaign keeps finding: a second copy that drifts.
const SENTINEL = { accountId: "__ACCT__", zoneId: "__ZONE__" };

console.log(`-- ${HAND_DAMAGE.size} hand-written damage entr(ies) --\n`);

for (const [id, entries] of HAND_DAMAGE) {
  const surface = CF_CONFIG_SURFACES.find((s) => s.id === id);
  if (surface === undefined) {
    ok(`${id}: names a surface that exists`, false);
    continue;
  }
  const writer = surface.write as unknown as
    | { cfWriteMethod?: string; cfWritePath?: (ids: { accountId: string; zoneId: string }) => string }
    | undefined;
  if (typeof surface.write !== "function" || writer?.cfWriteMethod === undefined || writer.cfWritePath === undefined) {
    ok(`${id}: has a writer that declares its method and path`, false);
    continue;
  }

  const concrete = writer.cfWritePath(SENTINEL);
  const templated = concrete
    .replace("__ACCT__", "{account_id}")
    .replace("__ZONE__", "{zone_id}");
  const verb = writer.cfWriteMethod.toLowerCase();
  const op = doc.paths?.[templated]?.[verb];
  if (op === undefined) {
    ok(`${id}: ${verb.toUpperCase()} ${templated} is an operation in the published schema`, false);
    continue;
  }

  const body = objectSchema(deref(op.requestBody)?.content?.["application/json"]?.schema);
  if (body?.properties === undefined) {
    ok(`${id}: ${verb.toUpperCase()} ${templated} declares a request body with properties`, false);
    continue;
  }

  for (const entry of entries) {
    const field = entry.path.join(".");
    const resolved = resolveField(body, entry.path);
    if (typeof resolved === "string") {
      ok(`${id}.${field}: resolves in the ${verb.toUpperCase()} body (${resolved})`, false);
      continue;
    }
    const prop = resolved;

    for (const value of entry.values) {
      let legal: boolean;
      let how: string;
      if (Array.isArray(prop.enum)) {
        legal = prop.enum.some((m) => m === value);
        how = `a member of the declared enum ${JSON.stringify(prop.enum)}`;
      } else if (prop.minimum !== undefined || prop.maximum !== undefined) {
        legal =
          typeof value === "number" &&
          (prop.minimum === undefined || value >= prop.minimum) &&
          (prop.maximum === undefined || value <= prop.maximum);
        how = `inside the declared range ${prop.minimum ?? "-inf"}..${prop.maximum ?? "inf"}`;
      } else if (typeof prop.type === "string") {
        // No enum and no range, so the schema constrains only the type. Weaker, and said plainly rather
        // than dressed up as a check of the value: this is the case where the vendor has told us least.
        legal = prop.type === "boolean" ? typeof value === "boolean" : prop.type === "number" || prop.type === "integer" ? typeof value === "number" : typeof value === prop.type;
        how = `of the declared type ${prop.type} (the schema constrains no enum or range here)`;
      } else {
        legal = false;
        how = "checkable at all: the schema declares no enum, no range, and no type for this field";
      }
      ok(`${id}.${field} = ${JSON.stringify(value)} is ${how}`, legal);
    }
  }
}

// NON-VACUITY. A gate over a table can pass by finding the table empty, and this one would then report a
// clean run while the prover leans on values nothing has checked. The console's twin of this idea reported
// a pass having scanned nothing at all, because of a path bug, which is the reason this floor is asserted
// rather than assumed.
console.log("");
ok(`the table has entries to check (${HAND_DAMAGE.size})`, HAND_DAMAGE.size > 0);
const values = [...HAND_DAMAGE.values()].reduce((n, es) => n + es.reduce((m, e) => m + e.values.length, 0), 0);
ok(`those entries carry candidate values (${values})`, values > 0);

console.log(failures === 0 ? "\nHAND DAMAGE SCHEMA CHECK PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
