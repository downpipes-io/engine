// ASVS V13.2.1 doc-to-bindings gate: docs/security/cryptography-and-keys.md carries a table naming, for
// each outbound service credential the engine holds, whether it is individually scoped and whether it is
// short-term on the wire. That table cites real bindings, functions and constants at real file:line
// locations, and states two numeric facts (the discovery-token term limit, the STS session-duration
// window) that live in the code, not in the prose.
//
// WHY THIS EXISTS. The sibling validate-posture-and-docs-parity.ts closed the same class of drift for the
// auditor-facing posture page: a table can be right the day it is written and silently wrong the day a
// binding is renamed or a constant changes, because nothing re-reads the prose against the code it
// describes. This is that same gate, scoped to the V13.2.1 section, and it needs no sibling checkout: the
// doc lives inside this repo.
//
// WHAT IT ASSERTS:
//   - every citation the section makes (`path:line` or `path:startLine-endLine`) resolves in the current
//     tree, and the cited line(s) still carry the identifier the prose names there;
//   - the two numeric claims in the prose (90 days; 900 seconds to 12 hours) match the actual exported
//     constants (DISCOVERY_TOKEN_MAX_DAYS; STS_DURATION_MIN/MAX), so the doc cannot drift from the code it
//     is a plain-English restatement of;
//   - the two "not applicable" rows (DoH, the update channel) stay true: neither call site sends an
//     Authorization header, which is the whole basis for calling them credential-free.
//
// Run with `node test/validate-v13-2-1-outbound-credentials.ts`.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DISCOVERY_TOKEN_MAX_DAYS } from "../src/admin/discovery-health.ts";
import { STS_DURATION_MIN, STS_DURATION_MAX } from "../src/dest/factory-validators.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DOC_PATH = "docs/security/cryptography-and-keys.md";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function lines(path: string): string[] {
  return readFileSync(resolve(ROOT, path), "utf8").split("\n");
}

/** citationHolds checks that file:startLine..endLine exists and that its joined text contains `expect`. */
function citationHolds(file: string, start: number, end: number, expect: string): boolean {
  const full = resolve(ROOT, file);
  if (!existsSync(full)) return false;
  const all = lines(file);
  if (end > all.length) return false;
  const slice = all.slice(start - 1, end).join("\n");
  return slice.includes(expect);
}

async function main(): Promise<void> {
  const doc = readFileSync(resolve(ROOT, DOC_PATH), "utf8");
  const sectionStart = doc.indexOf("#### ASVS V13.2.1");
  const sectionEnd = doc.indexOf("### 3.5 Destruction and clearing");
  ok("the V13.2.1 section exists in the doc", sectionStart !== -1 && sectionEnd > sectionStart);
  const section = sectionStart !== -1 && sectionEnd > sectionStart ? doc.slice(sectionStart, sectionEnd) : "";

  console.log("\n-- every citation in the section resolves and still carries the named identifier --\n");
  const citations: Array<{ file: string; start: number; end: number; expect: string; label: string }> = [
    { file: "src/env.d.ts", start: 515, end: 515, expect: "DISCOVERY_API_TOKEN", label: "the discovery token binding" },
    { file: "src/admin/cf-api.ts", start: 263, end: 263, expect: "discoveryTokenExpiryVerdict", label: "the discovery term-limit function" },
    { file: "src/admin/router-discovery.ts", start: 384, end: 384, expect: "discoveryTokenExpiryVerdict", label: "the discovery term limit enforced on the console-set path" },
    { file: "src/admin/preflight-probes.ts", start: 672, end: 672, expect: "discoveryTokenExpiryVerdict", label: "the discovery term limit enforced on the IaC fallback" },
    { file: "src/lib/outbound.ts", start: 20, end: 20, expect: "DOH_ENDPOINT", label: "the DoH endpoint constant" },
    { file: "src/notify/types.ts", start: 762, end: 762, expect: "DOH_ENDPOINT", label: "the DoH call site" },
    { file: "src/lib/outbound.ts", start: 21, end: 21, expect: "UPDATE_CHANNEL_HOST", label: "the update-channel host constant" },
    { file: "src/env.d.ts", start: 439, end: 439, expect: "UPDATE_SIGNER_PUBLIC", label: "the update-channel verify key binding" },
    { file: "src/dest/sts.ts", start: 28, end: 33, expect: "AssumeRoleParams", label: "the AssumeRole params type" },
    { file: "src/dest/sts.ts", start: 123, end: 188, expect: "export async function assumeRole", label: "the assumeRole function" },
    { file: "src/dest/factory.ts", start: 76, end: 101, expect: "export async function resolveRuntimeDest", label: "the fail-closed STS resolution" },
    { file: "src/dest/azure-entra.ts", start: 47, end: 51, expect: "AzureEntraCreds", label: "the Entra credential type" },
    { file: "src/dest/azure-entra.ts", start: 221, end: 234, expect: "async bearer(", label: "the cached-bearer-token method" },
    { file: "src/env.d.ts", start: 321, end: 322, expect: "DEST_ACCESS_KEY_ID", label: "the destination access key id binding" },
    { file: "src/env.d.ts", start: 321, end: 322, expect: "DEST_SECRET_ACCESS_KEY", label: "the destination secret access key binding" },
  ];
  for (const c of citations) {
    const inDoc = section.includes(`${c.file}:${c.start}${c.end !== c.start ? `-${c.end}` : ""}`);
    ok(`the doc cites ${c.file}:${c.start}${c.end !== c.start ? `-${c.end}` : ""} (${c.label})`, inDoc);
    ok(`${c.file}:${c.start}${c.end !== c.start ? `-${c.end}` : ""} still names ${JSON.stringify(c.expect)}`, citationHolds(c.file, c.start, c.end, c.expect));
  }

  console.log("\n-- the two numeric claims match the code they restate --\n");
  ok("DISCOVERY_TOKEN_MAX_DAYS is still 90 (the doc says \"90 days\")", DISCOVERY_TOKEN_MAX_DAYS === 90);
  ok('the doc states "90 days" for the discovery-token term limit', section.includes("90 days"));
  ok("STS_DURATION_MIN is still 900 and STS_DURATION_MAX is still 43200 (12h)", STS_DURATION_MIN === 900 && STS_DURATION_MAX === 43_200);
  ok('the doc states "900 seconds to 12 hours" for the STS session window', section.includes("900 seconds to 12 hours"));

  console.log("\n-- the two \"not applicable\" rows stay true: neither call sends a bearer credential --\n");
  const updatesSrc = readFileSync(resolve(ROOT, "src/admin/updates.ts"), "utf8");
  ok("the update-channel consult never sets an Authorization header", !/authorization/i.test(updatesSrc));
  const notifySrc = readFileSync(resolve(ROOT, "src/notify/types.ts"), "utf8");
  // 762 is the fetchImpl(...) line itself; the call's own arguments run a few lines further (redirect,
  // headers, signal), so the whole call is inspected rather than just its first line.
  const dohCallBlock = lines("src/notify/types.ts").slice(761, 767).join("\n"); // lines 762-767, 0-indexed
  ok("the DoH call carries no authorization header", !/authorization/i.test(dohCallBlock));
  ok("(sanity) src/notify/types.ts does define a DoH resolver at all", notifySrc.includes("DOH_ENDPOINT"));

  console.log(failures === 0 ? "\nV13.2.1-OUTBOUND-CREDENTIALS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
