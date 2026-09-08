// Unit test for the pure selector logic (SPEC 12.2), runnable with node alone.

import { inScope } from "../src/sources/selector.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

ok("empty include matches all", inScope("anything", { include: [], exclude: [] }));
ok("include prefix matches", inScope("uploads/a", { include: ["uploads/"], exclude: [] }));
ok("non-matching include excluded", !inScope("media/a", { include: ["uploads/"], exclude: [] }));
ok("exclude wins over include", !inScope("uploads/tmp/x", { include: ["uploads/"], exclude: ["uploads/tmp/"] }));
ok("multi-include any match", inScope("media/a", { include: ["uploads/", "media/"], exclude: [] }));
ok("exact prefix boundary", inScope("user:1", { include: ["user:"], exclude: [] }));

// Empty-include (match-all) combined with a non-empty exclude is a common config ("back up
// everything except tmp/"). These guard against exclude being accidentally gated on a non-empty
// include, and against the empty-string and exact-prefix edge cases.
ok("empty include + exclude: excluded key is excluded", !inScope("tmp/foo", { include: [], exclude: ["tmp/"] }));
ok("empty include + exclude: non-excluded key passes", inScope("data/foo", { include: [], exclude: ["tmp/"] }));
ok("key exactly equal to a prefix is included", inScope("tmp/", { include: ["tmp/"], exclude: [] }));
ok("empty key with empty include/exclude", inScope("", { include: [], exclude: [] }));

// ---- vectors that DISCRIMINATE the predicate, rather than agreeing with several -------------------
// Every vector above is lowercase, anchored at a top-level prefix and slash-consistent, so a whole family
// of one-token rewrites of inScope agrees with all ten of them. The vectors below are needed because four
// mutations of inScope change the answer for none of the calls elsewhere in the test suite.
//
//   include `startsWith` -> `includes`          over-selects
//   exclude `startsWith` -> `includes`          under-selects, a SILENT GAP
//   a `toLowerCase()` normalisation on both     under-selects, a SILENT GAP
//   stripping a trailing slash from the prefix  under-selects, a SILENT GAP
//
// Three of the four are the dangerous direction: a record the customer asked to be backed up is skipped
// and the run reports success. Nothing in the repo could tell any of them from the real predicate, not
// because the call sites are unexercised but because every vector set in the repo was too tame to
// discriminate. A fifth, exclude's `.some` becoming `.every`, is caught above only because `[].every()`
// is vacuously true; restore the empty-list case and the real confusion needs a two-element exclude,
// which no vector had.
//
// Cloudflare KV and R2 keys are case-sensitive and may contain any UTF-8, so none of these shapes is
// contrived: `TMP/` and `tmp/` are different keys, and `logs-archive-2026` is a sibling of `logs/`,
// not a child.

// The include prefix EMBEDDED mid-path is not a match. `startsWith` anchors; `includes` does not.
ok("include: a prefix appearing mid-key does NOT select it", !inScope("archive/uploads/customer-pii", { include: ["uploads/"], exclude: [] }));

// The exclude prefix EMBEDDED mid-path is not a match either, so the record stays IN scope. This is the
// one that loses data: under `includes`, every key with "archive/" anywhere in it silently stops being
// backed up.
ok("exclude: a prefix appearing mid-key does NOT exclude it", inScope("2026/archive/ledger", { include: [], exclude: ["archive/"] }));

// CASE SENSITIVITY, both sides. A case-folding "tidy-up" makes `TMP/` match `tmp/`.
ok("exclude: matching is case-SENSITIVE, so TMP/ is not excluded by tmp/", inScope("TMP/quarterly-report", { include: [], exclude: ["tmp/"] }));
ok("include: matching is case-SENSITIVE, so UPLOADS/ is not selected by uploads/", !inScope("UPLOADS/a", { include: ["uploads/"], exclude: [] }));

// THE TRAILING SLASH IS PART OF THE PREFIX. `logs-archive-2026` is a sibling of `logs/`, not a child of
// it, so stripping the slash from the prefix eats keys the customer never excluded.
ok("exclude: a sibling key sharing the stem is NOT excluded by a slash-terminated prefix", inScope("logs-archive-2026", { include: [], exclude: ["logs/"] }));
ok("include: a sibling key sharing the stem is NOT selected by a slash-terminated prefix", !inScope("logs-archive-2026", { include: ["logs/"], exclude: [] }));

// A MULTI-ELEMENT EXCLUDE. Any one match excludes; it is not a conjunction. With a single-element list
// `.some` and `.every` agree, which is why the confusion needs two prefixes to show up at all.
ok("exclude: ANY of several prefixes excludes (not all of them together)", !inScope("tmp/scratch", { include: [], exclude: ["tmp/", "logs/"] }));
ok("exclude: a key matching the OTHER prefix is excluded too", !inScope("logs/app", { include: [], exclude: ["tmp/", "logs/"] }));
ok("exclude: a key matching NEITHER of several prefixes passes", inScope("data/app", { include: [], exclude: ["tmp/", "logs/"] }));

console.log(failures === 0 ? "\nSELECTOR TESTS PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
