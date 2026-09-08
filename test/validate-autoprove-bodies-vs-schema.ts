// A create body for an UNPROVEN surface must only send fields Cloudflare's own schema declares.
//
// WHY THIS EXISTS
// ---------------
// A create body that names a field the endpoint has never heard of cannot succeed, and the endpoint is
// under no obligation to say which field is wrong. Cloudflare mostly answers "Invalid request".
//
// account-endpoint-healthchecks is the worked example. Its body sent `target` and `type`. The endpoint
// declares `check_type` and `endpoint`. Neither field sent exists, so every attempt was refused with a
// bare 1002 naming nothing, and the answer was sitting in a file the drift guard already downloads.
//
// dlp-profiles-custom is the same shape: the body wrapped the profile in a `profiles` array when the
// schema says the request body IS the profile. Its recorded refusal was 3314 Forbidden, a plausible
// entitlement for a paid Zero Trust product, reached with a body that would have failed validation
// regardless: a wrong body stands in front of the real answer, and the real answer is what gets written down.
//
// SCOPE, AND WHY IT IS NARROW
// ---------------------------
// Only surfaces that HAVE a writer and are NOT proven. Both exclusions are deliberate:
//
//   A PROVEN surface's body is validated by reality, and reality outranks the schema. mnm-rules omits two
//   fields the schema marks required and completes the whole round trip, so enforcing the schema against
//   it would fail a body demonstrated to work.
//
//   A surface with no writer cannot be proven at all, so its body is inert. rate-limits keeps a body and
//   sends two fields the schema does not declare; its writer was removed because Cloudflare retired the
//   endpoint (HTTP 410), and correcting a body for a dead endpoint is busywork.
//
// It checks fields SENT against fields DECLARED, and deliberately not required-fields-omitted. A vector
// may fill a field at run time through `resolve` (device-ip-profiles gets its subnet_id that way), so an
// omission here is not evidence of anything, while an undeclared field always is.
//
// The schema is gitignored and ~22MB. Absent, this SKIPS. REQUIRE_CF_OPENAPI=1 turns that into a failure,
// the same flag and the same reasoning as the drift guard's Section 2.
//
// And like Section 2 before it was fixed, nothing set that flag. This file runs inside `npm run validate`,
// which the workflow runs BEFORE the step that fetches the schema, so it has skipped and passed on every CI
// run since it was written. The workflow now runs it again after the fetch with REQUIRE_CF_OPENAPI=1, which
// is where the check on the bodies this engine sends Cloudflare actually happens.
//
//   node test/validate-autoprove-bodies-vs-schema.ts

import { existsSync, readFileSync } from "node:fs";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";

const SCHEMA = new URL("./vectors/cf-openapi/openapi.json", import.meta.url);
const VECTOR = new URL("./vectors/cf-config/autoprove-bodies.json", import.meta.url);

if (!existsSync(SCHEMA)) {
  if (process.env.REQUIRE_CF_OPENAPI === "1") {
    console.error("FAIL no vendored Cloudflare OpenAPI schema and REQUIRE_CF_OPENAPI=1.");
    console.error("     Run: node scripts/fetch-cf-openapi.mjs");
    process.exit(1);
  }
  console.log("AUTOPROVE BODY SCHEMA CHECK SKIPPED: no vendored OpenAPI schema (set REQUIRE_CF_OPENAPI=1 to require it)");
  /* skipped: advisory */
  process.exit(0);
}

interface Schema {
  $ref?: string;
  type?: string;
  properties?: Record<string, unknown>;
  required?: string[];
  allOf?: Schema[];
  oneOf?: Schema[];
  anyOf?: Schema[];
  discriminator?: { propertyName?: string; mapping?: Record<string, string> };
}

const spec = JSON.parse(readFileSync(SCHEMA, "utf8")) as {
  paths?: Record<string, { post?: { requestBody?: { content?: Record<string, { schema?: Schema }> } } }>;
  components?: { schemas?: Record<string, Schema> };
};
const vector = JSON.parse(readFileSync(VECTOR, "utf8")) as Record<string, unknown>;
const bodies = ((vector.bodies ?? vector) as Record<string, { body?: unknown; path?: string }>) ?? {};

// Resolves a schema to the set of property names a body may legally carry.
//
// The union branches (allOf / oneOf / anyOf / discriminator.mapping) are all merged rather than picked
// between. That is deliberate and it is the SAFE direction for this check: merging can only ever widen
// the declared set, so the check stays conservative and reports a field only when NO variant declares it.
// Picking one variant would invent failures. gateway-proxy-endpoints is exactly that case: its top-level
// schema declares only `kind`, and a discriminator maps kind:"ip" to a variant declaring `ips` and `name`.
// Without following the mapping this gate reported a correct body as wrong on its first run.
function deref(node: Schema | undefined, depth = 0, seen = new Set<string>()): Schema | undefined {
  if (node === undefined || depth > 10) return undefined;
  if (node.$ref !== undefined) {
    if (seen.has(node.$ref)) return undefined;
    seen.add(node.$ref);
    return deref(spec.components?.schemas?.[node.$ref.replace("#/components/schemas/", "")], depth + 1, seen);
  }
  const branches = [...(node.allOf ?? []), ...(node.oneOf ?? []), ...(node.anyOf ?? [])];
  for (const target of Object.values(node.discriminator?.mapping ?? {})) branches.push({ $ref: target });
  if (branches.length === 0) return node;
  const merged: Schema = { type: "object", properties: { ...(node.properties ?? {}) }, required: [...(node.required ?? [])] };
  for (const part of branches) {
    const d = deref(part, depth + 1, seen);
    Object.assign(merged.properties as object, d?.properties ?? {});
    merged.required!.push(...(d?.required ?? []));
  }
  return merged;
}

// Our vector paths spell every id as `{}`. The schema names them, and which name goes where depends on
// the surface, so try the orderings rather than assuming one.
function schemaPaths(p: string): string[] {
  const parts = p.split("{}");
  const fills = [
    ["{account_id}", "{zone_id}"],
    ["{zone_id}", "{account_id}"],
    ["{account_id}", "{account_id}"],
    ["{zone_id}", "{zone_id}"],
  ];
  const out = new Set<string>();
  for (const f of fills) {
    let s = parts[0] ?? "";
    for (let i = 1; i < parts.length; i++) s += `${f[i - 1] ?? "{id}"}${parts[i]}`;
    out.add(s);
  }
  return [...out];
}

const withWriter = new Set(CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function").map((s) => s.id));

let failures = 0;
let checked = 0;
let unresolvable = 0;
const offenders: string[] = [];

for (const [id, entry] of Object.entries(bodies)) {
  if (!withWriter.has(id) || PROVEN_WRITE_SURFACES.has(id)) continue;
  const body = entry.body;
  if (entry.path === undefined || body === null || typeof body !== "object" || Array.isArray(body)) continue;
  let post: { requestBody?: { content?: Record<string, { schema?: Schema }> } } | undefined;
  for (const c of schemaPaths(entry.path)) {
    const p = spec.paths?.[c]?.post;
    if (p !== undefined) { post = p; break; }
  }
  const sch = deref(post?.requestBody?.content?.["application/json"]?.schema);
  if (sch?.properties === undefined) { unresolvable++; continue; }
  checked++;
  // A field the schema marks REQUIRED is one the endpoint accepts, whatever `properties` says. Cloudflare's
  // own schema needs this: zero-trust-gateway_proxy-endpoint-ip-create lists `ips` in `required` and does
  // not declare it as a property, so a properties-only reading calls a body wrong for sending a field the
  // same schema insists on. Reported as a false positive on this gate's first run against a correct body.
  const declared = new Set([...Object.keys(sch.properties), ...(sch.required ?? [])]);
  const undeclared = Object.keys(body as Record<string, unknown>).filter((k) => !declared.has(k));
  if (undeclared.length > 0) {
    failures++;
    offenders.push(`  FAIL ${id}: sends ${undeclared.join(", ")}, which the schema does not declare. It declares: ${[...declared].slice(0, 10).join(", ")}`);
  }
}

console.log(`-- ${checked} unproven writers with a resolvable POST schema (${unresolvable} without one) --`);
for (const line of offenders) console.log(line);
console.log(
  failures === 0
    ? `\nAUTOPROVE BODY SCHEMA CHECK PASS: every checked body sends only declared fields`
    : `\n${failures} body/bodies send fields Cloudflare does not declare`,
);
// Pass the count, because this validator reports one summary line rather than a line per body, so the guard
// has no assertion lines to corroborate a pass with. `checked` is the right number: it counts bodies actually
// compared against a resolvable POST schema, and it deliberately excludes the `unresolvable` ones, which were
// never checked against anything. That makes the nothing-to-check case FAIL rather than pass quietly: a run
// where no writer had a resolvable schema proves nothing about any body, and used to report PASS regardless.
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
