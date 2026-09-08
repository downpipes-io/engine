// A compliance capability may not assert unattended restore proof without naming the posture that provides it.
//
// WHY THIS EXISTS. `src/admin/frameworks.ts` maps regulatory controls to what this product does, and that
// mapping is rendered into the SIGNED evidence pack a customer hands an auditor. six of those
// capability strings offered "scheduled restore drills with a dated evidence log" as the thing satisfying a
// recovery-testing obligation: CPS 234, Essential Eight ML1, DORA Art. 11, NIST CP-4, GDPR Art. 32 and SOC 2
// A1.3.
//
// Scheduled drills do not run in the strict break-glass-only posture, which became the DEFAULT the same day.
// So on a default estate those six lines described evidence the customer was not generating, in a document
// whose whole purpose is to be relied upon. That is the worst place in the product for a stale claim.
//
// The capability is real in both postures, which is why the fix was wording rather than scope: drills run
// scheduled and unattended where an operational key is installed, and attended with the break-glass key
// where it is not, and either way the dated evidence log exists. This gate keeps that qualification
// attached.
//
// Run with `node test/validate-framework-posture-claims.ts`.
//

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL("..", import.meta.url));

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

console.log("\n-- no framework capability asserts unattended restore proof without naming the posture --\n");

const text = readFileSync(resolve(HERE, "src/admin/frameworks.ts"), "utf8");

// Every control-to-capability mapping in the file.
const entries = [...text.matchAll(/\{ control: "([^"]+)",[^}]*?capability: "([^"]+)"/gs)].map((m) => ({
  control: m[1] as string,
  capability: m[2] as string,
}));

// A gate that matched nothing would report clean for ever, and this file is edited by hand.
ok(`the extractor found control-to-capability mappings (${entries.length} found)`, entries.length >= 20);

// The claim shape: an unattended qualifier attached to a restore PROOF. "Scheduled per-source BACKUPS" is
// deliberately not caught, because backups are scheduled in either posture; it is the PROOF that depends on
// the operational key.
const ASSERTS_UNATTENDED = /(?:scheduled|in-account|automated)[^.]{0,40}(?:drill|restore test)|(?:drill|restore test)[^.]{0,25}(?:scheduled|in-account|automated)/i;
// The qualification that makes it honest: it must say which posture, either by naming the operational key
// or by naming the attended alternative.
const NAMES_POSTURE = /attended|operational key/i;

const bare = entries.filter((e) => ASSERTS_UNATTENDED.test(e.capability) && !NAMES_POSTURE.test(e.capability));
ok("every capability asserting unattended restore proof names the posture that provides it", bare.length === 0);
if (bare.length > 0) {
  for (const b of bare) console.log(`       ${b.control}: ${b.capability.slice(0, 120)}`);
  console.log("       Scheduled drills do not run in the DEFAULT strict break-glass-only posture. Say which posture provides");
  console.log("       the proof, as the corrected entries do: scheduled where an operational key is installed, attended where not.");
}

// The six that prompted this, pinned by control id. The rule above would catch a regression in any of them,
// but naming them records WHICH claims were wrong, so a later reader can tell whether this still matters.
//
// FILTER, not find. A control id is NOT unique here: `Art. 32(1)(d)` appears in both the GDPR and the UK
// GDPR blocks, with different capability text, and the first of the two is "Repeatable drills that verify
// the integrity chain", which asserts nothing unattended and correctly needs no posture qualifier. The pin is therefore
// the main rule scoped to these ids: every entry under them is either posture-neutral or qualified.
const PROMPTED = ["CPS 234 para 27-28", "ML1 test restoration", "Art. 11(4),(6)", "CP-4", "Art. 32(1)(d)", "A1.3"];
for (const id of PROMPTED) {
  const matches = entries.filter((x) => x.control === id);
  const clean = matches.every((e) => !ASSERTS_UNATTENDED.test(e.capability) || NAMES_POSTURE.test(e.capability));
  ok(`${id} is present (${matches.length}) and every entry is posture-neutral or qualified`, matches.length > 0 && clean);
}

// The extractor must really be reading capability text, not matching an empty set.
ok(
  "the extractor reads capability prose (a known phrase is present)",
  entries.some((e) => /evidence log/i.test(e.capability)),
);

// ---------------------------------------------------------------------------------------------------
// SECOND RULE: a capability may not pair R2 with S3 Object Lock as one mechanism.
//
// R2 DOES NOT ENFORCE S3 OBJECT-LOCK ON ANY BUCKET, by any route. The lock-configuration GET answers 404
// ObjectLockConfigurationNotFoundError, and a PUT carrying x-amz-object-lock-mode: COMPLIANCE answers 501
// NotImplemented, naming the header. R2's own bucket-lock retention feature is a SEPARATE mechanism.
//
// Two of these capability strings read "R2/S3 Object Lock", which asserts to an auditor, in a signed
// evidence pack, that R2 has the Amazon mechanism. A third in the same file already had it right ("R2
// bucket locks or S3 Object Lock"), so the file contradicted itself, and nothing here graded any of them.
//
// THE RULE IS STRUCTURAL, not a banned phrase: a capability that names both R2 and Object Lock must also
// name R2's OWN mechanism, bucket locks, so the two are stated as two things. That passes every correct
// spelling and fails every conflation, without pinning anybody's wording.
console.log("\n-- no framework capability pairs R2 with S3 Object Lock as one mechanism --\n");
const NAMES_R2 = /\bR2\b/;
const NAMES_OBJECT_LOCK = /Object[ -]Lock/i;
const NAMES_R2_OWN_MECHANISM = /bucket lock/i;
function conflatesR2WithObjectLock(capability: string): boolean {
  return NAMES_R2.test(capability) && NAMES_OBJECT_LOCK.test(capability) && !NAMES_R2_OWN_MECHANISM.test(capability);
}
const conflations = entries.filter((e) => conflatesR2WithObjectLock(e.capability));
ok(`no capability claims R2 has S3 Object Lock (${conflations.length} offender(s): ${conflations.map((e) => e.control).join(", ") || "none"})`, conflations.length === 0);

// KNOWN POSITIVE. A scanner that matches nothing passes a file full of the defect just as happily as a
// clean one, so the rule is run against the exact string that shipped and must call it out.
ok("control: the rule REJECTS the string that shipped (\"paired with R2/S3 Object Lock\")", conflatesR2WithObjectLock("Append-only archives paired with R2/S3 Object Lock; the signed run log detects rollback."));
// KNOWN NEGATIVES, both directions. The correct spelling passes, and a capability that names neither is
// not swept up by a rule that is about the pairing rather than about either word.
ok("control: the rule ACCEPTS the correct spelling (\"R2 bucket locks or S3 Object Lock\")", !conflatesR2WithObjectLock("Destination retention locks (R2 bucket locks or S3 Object Lock) over content-addressed, append-only archives."));
ok("control: the rule ignores a capability that names neither", !conflatesR2WithObjectLock("Per-source cadence and retention."));
// And the population is real: at least one capability in the live file does name both, so the rule above
// is grading something rather than reporting zero over an empty set.
ok("the live file has capabilities that name R2 and Object Lock at all (so the zero above is measured)", entries.some((e) => NAMES_R2.test(e.capability) && NAMES_OBJECT_LOCK.test(e.capability)));

console.log(`\n${failures === 0 ? "FRAMEWORK-POSTURE-CLAIMS PASS" : `FRAMEWORK-POSTURE-CLAIMS: ${failures} FAILED`}\n`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
