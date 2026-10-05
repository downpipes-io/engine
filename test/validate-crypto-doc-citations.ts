// The cryptography document's line citations into src/crypto/pq.ts and src/env.d.ts must land on the code
// they describe.
//
// WHY THIS EXISTS. docs/security/cryptography-and-keys.md is the key-custody reference an assessor reads. It
// pins the post-quantum imports, the ML-DSA verify function, the engine's caveat about the post-quantum
// library, and the key bindings by file and line. A comment change grew the pq.ts header by
// six lines, and every pq.ts citation in the document then pointed at the wrong code. No gate was red. A
// comment-only change to env.d.ts does the same to the binding citations.
//
// WHAT IT ASSERTS.
//   1. POPULATION. Every citation of pq.ts or env.d.ts in the document (with or without the engine/ and src/
//      prefixes) has an entry in ANCHORS below, and every entry in ANCHORS is still cited. A new citation must
//      say what it points at, and an entry the document no longer uses cannot hide as a pass.
//   2. ANCHOR. Each anchor text is on a line inside the cited range. A binding anchor is the declaration
//      (`NAME?:`), so a comment that only names the binding does not satisfy it. For a range that cites a
//      comment block, `first` and `last` must be on the first and last cited lines, so the range cannot
//      grow past the block or lose part of it without a red.
//
// When a pq.ts or env.d.ts edit moves lines, re-pin the document and the matching key below in the same
// change. Run with `node test/validate-crypto-doc-citations.ts`.
//
//

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const DOC = "docs/security/cryptography-and-keys.md";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail) console.log(`       ${detail}`);
  }
}

interface Anchor {
  within: string[];
  first?: string;
  last?: string;
}

// Keyed by the normalised citation `src/<file>:<start>[-<end>]`.
const ANCHORS: Record<string, Anchor> = {
  "src/crypto/pq.ts:26": { within: ['import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js"'] },
  "src/crypto/pq.ts:27": { within: ['import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js"'] },
  "src/crypto/pq.ts:98-100": { within: ["export function mldsaVerify(", "ml_dsa87.verify("] },
  "src/crypto/pq.ts:10-12": {
    within: ["OPERATIONAL_PRIVATE and decapsulates with it routinely", "retention prune"],
    first: "In the two-recipient posture",
    last: "retention prune all do",
  },
  "src/crypto/pq.ts:7-24": {
    within: ["NOT constant-time-guaranteed", "Rust/WASM escalation"],
    first: "The library is NOT constant-time-guaranteed",
    last: "constant-time implementation is required.",
  },
  "src/env.d.ts:321-322": { within: ["DEST_ACCESS_KEY_ID?:", "DEST_SECRET_ACCESS_KEY?:"] },
  "src/env.d.ts:408": { within: ["SIGNER_PRIVATE?:"] },
  "src/env.d.ts:409": { within: ["BREAK_GLASS_PUBLIC?:"] },
  "src/env.d.ts:410": { within: ["OPERATIONAL_PUBLIC?:"] },
  "src/env.d.ts:411": { within: ["OPERATIONAL_PRIVATE?:"] },
  "src/env.d.ts:429-432": { within: ["UPDATE_SIGNER_PUBLIC?:"] },
  "src/env.d.ts:432": { within: ["UPDATE_SIGNER_PUBLIC?:"] },
  "src/env.d.ts:444-458": { within: ["LICENCE_SIGNER_PUBLIC?:"] },
  "src/env.d.ts:508": { within: ["DISCOVERY_API_TOKEN?:"] },
};

const doc = readFileSync(resolve(HERE, DOC), "utf8");
const CITE = /(?<![\w/.-])(?:engine\/)?(?:src\/)?(crypto\/pq\.ts|env\.d\.ts):(\d+)(?:-(\d+))?/g;

const cited = new Map<string, number[]>();
doc.split("\n").forEach((line, i) => {
  for (const m of line.matchAll(CITE)) {
    const key = `src/${m[1]}:${m[2]}${m[3] ? `-${m[3]}` : ""}`;
    const at = cited.get(key) ?? [];
    at.push(i + 1);
    cited.set(key, at);
  }
});

// CONTROL: the scan reaches both files and both prefix forms the document uses.
ok(`the scan found pq.ts and env.d.ts citations in ${DOC} (${cited.size} distinct)`, cited.size > 0);
ok("CONTROL: the scan reaches a pq.ts citation", [...cited.keys()].some((k) => k.startsWith("src/crypto/pq.ts:")));
ok("CONTROL: the scan reaches a bare `env.d.ts:` citation", /`env\.d\.ts:\d/.test(doc) && cited.has("src/env.d.ts:408"));

const sources = new Map<string, string[]>();
function sourceLines(file: string): string[] {
  let lines = sources.get(file);
  if (!lines) {
    lines = readFileSync(resolve(HERE, file), "utf8").split("\n");
    sources.set(file, lines);
  }
  return lines;
}

for (const [key, docLines] of cited) {
  const anchor = ANCHORS[key];
  ok(`${key} (doc line ${docLines.join(", ")}) has an anchor entry`, anchor !== undefined, "add it to ANCHORS with the text the citation points at");
  if (!anchor) continue;
  const m = /^(.+):(\d+)(?:-(\d+))?$/.exec(key) as RegExpExecArray;
  const file = m[1] as string;
  const start = Number(m[2]);
  const end = m[3] ? Number(m[3]) : start;
  const lines = sourceLines(file);
  ok(`${key} is inside ${file} (${lines.length} lines)`, start >= 1 && end >= start && end <= lines.length);
  const range = lines.slice(start - 1, end);
  const text = range.join("\n");
  for (const w of anchor.within) {
    ok(`${key} contains ${JSON.stringify(w)}`, text.includes(w), `cited lines read: ${JSON.stringify(range.map((l) => l.trim()).join(" | ").slice(0, 300))}`);
  }
  if (anchor.first !== undefined) {
    ok(`${key} starts on ${JSON.stringify(anchor.first)}`, (range[0] ?? "").includes(anchor.first), `line ${start} reads: ${JSON.stringify(range[0] ?? "")}`);
  }
  if (anchor.last !== undefined) {
    ok(`${key} ends on ${JSON.stringify(anchor.last)}`, (range[range.length - 1] ?? "").includes(anchor.last), `line ${end} reads: ${JSON.stringify(range[range.length - 1] ?? "")}`);
  }
}

for (const key of Object.keys(ANCHORS)) {
  ok(`anchor entry ${key} is still cited by the document`, cited.has(key), "remove the entry or restore the citation");
}

console.log(failures === 0 ? "\nCRYPTO-DOC-CITATIONS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
