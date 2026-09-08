// Validates that the ONE event the customer-facing Test send button emits is well formed, by driving the
// REAL synthetic event (src/cron/siem-push-shape.ts buildSyntheticPushEvent, the exact object POST
// /admin/push/test sends) through destsim's STRICT parsers.
//
// The synthetic event's two hash placeholders and destsim's accepting regex both derive their width from
// ONE constant (SHA384_HEX_LEN in src/admin/audit-types.ts): the producer's placeholder is
// GENESIS_PREV_HASH, built from it, and destsim's accepting regex is built from it too.
//
// The suite is deliberately two-sided. It proves the real event is ACCEPTED, and it proves a wrong width is
// REJECTED by the same parsers, so a green result cannot mean "the check does nothing".
//
// No network, no Durable Object. Run: node test/validate-siem-testsend-parity.ts

import { readFileSync } from "node:fs";
import { SHA384_HEX_LEN } from "../src/admin/audit-types.ts";
import { GENESIS_PREV_HASH } from "../src/admin/audit.ts";
import { buildSyntheticPushEvent, shapeCef, shapeDatadog, shapeGelf, shapeJsonArray, shapeLeef, shapeNdjson, shapeRawJson, shapeSplunkHec, type PushCursorMeta } from "../src/cron/siem-push-shape.ts";
import { DestsimParseError, parseCef, parseDatadog, parseGelf, parseJsonArray, parseLeef, parseNdjson, parseRawJson, parseSplunkHec } from "./destsim/parsers.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
function rejects(label: string, fn: () => unknown): void {
  try {
    fn();
    ok(label, false);
  } catch (e) {
    ok(label, e instanceof DestsimParseError);
  }
}

const META: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 0, headSeq: 0, headHash: "" };

// Every shaper that carries the audit event's prevHash/hash on the wire, paired with the strict parser that
// reads it back. cef/leef/gelf carry the two hashes in their flattened projection; the five JSON-shaped
// formats carry the whole event. All eight went out malformed.
const ROUND_TRIPS: Array<{ format: string; shape: (e: ReturnType<typeof buildSyntheticPushEvent>[]) => { body: string }; parse: (raw: string) => unknown }> = [];
function roundTrip(format: string, shape: (evs: Array<ReturnType<typeof buildSyntheticPushEvent>>) => { body: string }, parse: (raw: string) => unknown): void {
  ROUND_TRIPS.push({ format, shape: shape as never, parse });
}
roundTrip("splunk-hec", (evs) => shapeSplunkHec(evs, META), (raw) => parseSplunkHec(raw));
roundTrip("raw-json", (evs) => shapeRawJson(evs, META), (raw) => parseRawJson(raw));
roundTrip("ndjson", (evs) => shapeNdjson(evs, META), (raw) => parseNdjson(raw));
roundTrip("json-array", (evs) => shapeJsonArray(evs, META), (raw) => parseJsonArray(raw));
roundTrip("datadog", (evs) => shapeDatadog(evs, META), (raw) => parseDatadog(raw));
roundTrip("cef", (evs) => shapeCef(evs, META), (raw) => parseCef(raw));
roundTrip("leef", (evs) => shapeLeef(evs, META), (raw) => parseLeef(raw));
roundTrip("gelf", (evs) => shapeGelf(evs, META), (raw) => parseGelf(raw));

console.log("1. the ONE constant both sides derive from");
ok(`SHA384_HEX_LEN is 96 (a SHA-384 digest is 48 bytes, so 96 hex characters)`, SHA384_HEX_LEN === 96);
ok(`GENESIS_PREV_HASH's hex body is exactly SHA384_HEX_LEN wide (${GENESIS_PREV_HASH.length - "sha384:".length})`, GENESIS_PREV_HASH.slice("sha384:".length).length === SHA384_HEX_LEN);
ok("GENESIS_PREV_HASH's hex body is all zeros", /^0+$/.test(GENESIS_PREV_HASH.slice("sha384:".length)));

console.log("2. the REAL synthetic test-send event is well formed");
const synthetic = buildSyntheticPushEvent();
ok(`the synthetic event's prevHash is SHA384_HEX_LEN wide (${SHA384_HEX_LEN})`, synthetic.prevHash.slice("sha384:".length).length === SHA384_HEX_LEN);
ok(`the synthetic event's hash is SHA384_HEX_LEN wide (${SHA384_HEX_LEN})`, synthetic.hash.slice("sha384:".length).length === SHA384_HEX_LEN);
ok("both placeholders ARE the audit chain's own genesis placeholder, not a second hand-typed literal", synthetic.prevHash === GENESIS_PREV_HASH && synthetic.hash === GENESIS_PREV_HASH);
ok("the synthetic event is still unambiguously labelled as a test in its detail field", typeof synthetic.target === "object" && synthetic.target !== null && "detail" in synthetic.target && String((synthetic.target as { detail?: unknown }).detail).includes("synthetic test event"));

// THE FLOOR. Sections 3 and 4 iterate ROUND_TRIPS, so an empty or shortened list would run no assertions and
// still print PASS: a gate with nothing to check reads exactly like a gate that checked and was satisfied.
// Every shaper that puts the audit event's hash on the wire must be in this list, and there are eight.
ok(`the round-trip list covers all eight hash-carrying formats (got ${ROUND_TRIPS.length})`, ROUND_TRIPS.length === 8);
ok("no format is listed twice, which would inflate the count and hide a missing one", new Set(ROUND_TRIPS.map((r) => r.format)).size === ROUND_TRIPS.length);

console.log("3. the emulator and the product now AGREE: every format round-trips the real payload");
for (const rt of ROUND_TRIPS) {
  const body = rt.shape([synthetic]).body;
  let accepted = false;
  let why = "";
  try {
    rt.parse(body);
    accepted = true;
  } catch (e) {
    why = e instanceof Error ? e.message : String(e);
  }
  ok(`${rt.format}: destsim's strict parser ACCEPTS the real test-send payload${accepted ? "" : ` -- rejected: ${why}`}`, accepted);
}

console.log("4. a WRONG width still fails, so the acceptance above is not vacuous");
// Mutate the event's hashes to the old, wrong width and to two neighbouring widths. Every parser that reads
// the hash must refuse all three, or its acceptance in section 3 proves nothing about the width at all.
for (const wrongLen of [SHA384_HEX_LEN - 2, SHA384_HEX_LEN - 1, SHA384_HEX_LEN + 1]) {
  const wrong = { ...synthetic, prevHash: `sha384:${"0".repeat(wrongLen)}`, hash: `sha384:${"0".repeat(wrongLen)}` };
  for (const rt of ROUND_TRIPS) {
    const body = rt.shape([wrong]).body;
    rejects(`${rt.format}: a ${wrongLen}-character hash is REJECTED`, () => rt.parse(body));
  }
}

console.log("5. the width cannot be re-typed into the producer");
// A source-text guard: the defect was a hand-typed run of zeros, so the producer must not contain one. Read
// the real file (a missing file throws, so this cannot pass by failing to run).
const shapeSrc = readFileSync(new URL("../src/cron/siem-push-shape.ts", import.meta.url), "utf8");
ok("src/cron/siem-push-shape.ts is readable and non-trivial", shapeSrc.length > 1000);
const zeroRuns = shapeSrc.match(/0{16,}/g) ?? [];
ok(`src/cron/siem-push-shape.ts contains no hand-typed run of 16 or more zeros (found ${zeroRuns.length})`, zeroRuns.length === 0);
const auditTypesSrc = readFileSync(new URL("../src/admin/audit-types.ts", import.meta.url), "utf8");
ok("SHA384_HEX_LEN is declared exactly once, in the leaf both sides import", (auditTypesSrc.match(/export const SHA384_HEX_LEN\b/g) ?? []).length === 1);
const parsersSrc = readFileSync(new URL("./destsim/parsers.ts", import.meta.url), "utf8");
// The placeholder below is the SUBJECT of the assertion: it checks that parsers.ts CONTAINS that text,
// proving parsers.ts derives the hash width from the constant rather than typing 96. Making it a real
// template literal would interpolate the width, and the assertion would then pass against a hard-coded
// regex, which is the thing it exists to refuse. The suppression must be the LAST line before the code,
// or biome reports it as having no effect and the diagnostic count goes UP rather than down.
// biome-ignore lint/suspicious/noTemplateCurlyInString: explained directly above.
ok("destsim's hash regex derives its width from SHA384_HEX_LEN rather than typing it", parsersSrc.includes("${SHA384_HEX_LEN}") && !/\[0-9a-f\]\{96\}/.test(parsersSrc));

console.log(failures === 0 ? "\nSIEM TEST-SEND PARITY PASS" : `\nSIEM TEST-SEND PARITY FAIL (${failures})`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
