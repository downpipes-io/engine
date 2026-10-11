// A compliance capability may not assert unattended restore proof without naming the posture that provides it.
//
// WHY THIS EXISTS. `src/admin/frameworks.ts` maps regulatory controls to what this product does, and that
// mapping is rendered into the SIGNED evidence pack a customer hands an auditor. Six of those
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
// SIBLING RULE, and the reason this is a separate gate rather than a line in the console's
// posture-claims-gate.mjs: that gate bans two claims which UNDERSTATE the strict posture, and it scans
// console/src. This is the opposite direction, claims that OVERSTATE what runs by default, and it lives
// where the artefact is generated.
//
// Run with `node test/validate-framework-posture-claims.ts`.
//

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FRAMEWORKS } from "../src/admin/frameworks.ts";
import type { PostureReport } from "../src/admin/posture.ts";
import { buildEvidencePackReport } from "../src/admin/reports.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

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
// the integrity chain", which asserts nothing unattended and correctly needs no posture qualifier. The
// first draft used find(), picked that one, and failed against perfectly good code. The pin is therefore
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
// R2 DOES NOT ENFORCE S3 OBJECT-LOCK ON ANY BUCKET, by any route. Measured that day against a real R2
// bucket over its S3 endpoint with this repo's own signer: the lock-configuration GET answers 404
// ObjectLockConfigurationNotFoundError, and a PUT carrying x-amz-object-lock-mode: COMPLIANCE answers 501
// NotImplemented, naming the header. R2's own bucket-lock retention feature is a SEPARATE mechanism.
//
// Two of these capability strings read "R2/S3 Object Lock", which asserts to an auditor, in a signed
// evidence pack, that R2 has the Amazon mechanism. A third in the same file already had it right ("R2
// bucket locks or S3 Object Lock"), so the file contradicted itself, and nothing here graded any of them.
//
// CORRECTED. The rule as first written accepted "R2 bucket locks or S3 Object Lock" as the
// correct spelling, and so it certified the next defect: three capabilities (Essential Eight ML3 admin
// immutability, SEC 17a-4(f)(2)(i)(B) and ISM-1708) offered "R2 bucket locks" first among the locks that
// satisfy the control. downpipes can neither arm nor read an R2 bucket lock, and the `immutability` check
// these rows cite reads unknown on R2 by construction, so the signed pack evidenced a mechanism nothing in
// it can see. The rule is now: a capability that names R2 beside Object Lock must say R2 enforces NO lock,
// and no capability may offer an R2 bucket lock as a retention mechanism at all.
console.log("\n-- no framework capability offers R2 as a retention lock --\n");
const NAMES_R2 = /\bR2\b/;
const NAMES_OBJECT_LOCK = /Object[ -]Lock/i;
// Widened: "R2 enforces no lock" reads as a claim about the platform, and R2 has its own bucket
// lock. The rows now say R2 cannot enforce S3 Object Lock, which is the fact this rule exists for.
const SAYS_R2_ENFORCES_NONE = /R2 enforces no(?:ne| lock)|R2 cannot enforce (?:S3 )?Object Lock/i;
const OFFERS_R2_BUCKET_LOCK = /R2 bucket lock/i;
function offersR2AsLock(capability: string): boolean {
  if (OFFERS_R2_BUCKET_LOCK.test(capability)) return true;
  return NAMES_R2.test(capability) && NAMES_OBJECT_LOCK.test(capability) && !SAYS_R2_ENFORCES_NONE.test(capability);
}
const r2Offers = entries.filter((e) => offersR2AsLock(e.capability));
ok(`no capability offers R2 as a retention lock (${r2Offers.length} offender(s): ${r2Offers.map((e) => e.control).join(", ") || "none"})`, r2Offers.length === 0);

// KNOWN POSITIVES: the string that shipped and the three that shipped after it.
ok("control: the rule REJECTS \"paired with R2/S3 Object Lock\"", offersR2AsLock("Append-only archives paired with R2/S3 Object Lock; the signed run log detects rollback."));
ok("control: the rule REJECTS \"(R2 bucket locks, S3 Object Lock, ...)\"", offersR2AsLock("Destination retention locks (R2 bucket locks, S3 Object Lock, Google Cloud per-object retention or Azure version-level immutability) over content-addressed, append-only archives."));
ok("control: the rule REJECTS \"R2 bucket locks or S3 Object Lock\", which it used to accept", offersR2AsLock("Destination retention locks (R2 bucket locks or S3 Object Lock) over content-addressed, append-only archives."));
// KNOWN NEGATIVES.
ok("control: the rule ACCEPTS a capability that says R2 enforces no lock", !offersR2AsLock("A retention lock set in compliance mode (S3 Object Lock or a locked Azure policy); Cloudflare R2 enforces no lock."));
ok("control: the rule ignores an R2 destination with no lock claim", !offersR2AsLock("You choose the destination: an in-account R2 bucket, or an S3-compatible store in an Australian region."));
ok("the live file has capabilities that name R2 and Object Lock at all (so the zero above is measured)", entries.some((e) => NAMES_R2.test(e.capability) && NAMES_OBJECT_LOCK.test(e.capability)));

// ---------------------------------------------------------------------------------------------------
// THIRD RULE: a capability answering an obligation that binds ADMINISTRATORS, or that
// demands a non-erasable format, must name compliance mode. Under governance mode (an unlocked Azure
// policy) a principal holding the bypass permission can shorten or remove the window, and that principal
// is usually the backup administrator the obligation is about. dest/s3-worm.ts states the difference.
console.log("\n-- every capability for an administrator-proof or non-erasable obligation names compliance mode --\n");
const withObligation = [...text.matchAll(/\{ control: "([^"]+)", obligation: "([^"]+)", capability: "([^"]+)"/gs)].map((m) => ({
  control: m[1] as string,
  obligation: m[2] as string,
  capability: m[3] as string,
}));
const BINDS_ADMINS = /backup administrators? (?:are )?prevented|non-erasable/i;
const NAMES_COMPLIANCE_MODE = /compliance mode/i;
const adminRows = withObligation.filter((e) => BINDS_ADMINS.test(e.obligation));
const modeless = adminRows.filter((e) => !NAMES_COMPLIANCE_MODE.test(e.capability));
ok(`the obligation extractor found the administrator-proof rows (${adminRows.length} found)`, adminRows.length >= 3);
ok(`every one names compliance mode (${modeless.length} offender(s): ${modeless.map((e) => e.control).join(", ") || "none"})`, modeless.length === 0);
ok(
  "control: the rule REJECTS the ISM-1708 capability that shipped",
  !NAMES_COMPLIANCE_MODE.test("Append-only archives paired with the destination's own retention lock (R2 bucket locks, S3 Object Lock, Google Cloud per-object retention or Azure version-level immutability); the signed run log detects rollback."),
);

// ---------------------------------------------------------------------------------------------------
// FOURTH RULE SET: six shapes of overclaim a read of every row against the engine found.
//
// Each rule names a claim the engine does not make good on its default settings, and the qualifier that
// makes the sentence true. The sources are next to each rule. Each one is proved against the retired
// wording it was built for (it must fire) and the corrected wording (it must not).
console.log("\n-- the conditional claims carry their condition --\n");
interface ClaimRule {
  name: string;
  claim: RegExp;
  qualifier: RegExp;
  why: string;
  retired: string[];
  fixed: string[];
}
const CLAIM_RULES: ClaimRule[] = [
  {
    // admin/router-retention-prune.ts:40-41 and admin/prune-approvals.ts:4-7: only a prune applied from the
    // console always needs a second approver. Arming the scheduled prune is dual-controlled only when
    // requireConfigApproval is on (off by default), and a second restore approver is optional and off by
    // default (sched/scheduler-do-restore-approval.ts:494-505).
    name: "dual control names its default or its scope",
    claim: /dual[- ]control|second approver|two-person|approver-confirmed/i,
    qualifier: /off by default|optional|applied from the console|attended prune/i,
    why: "dual control is always on only for a prune applied from the console; restore and scheduled-prune approval are off by default",
    retired: [
      "Dual-control approvals and role-based access control enforce two-person authorisation before backup data can be deleted or pruned.",
      "Four-role RBAC and dual-control approvals over who can restore and who can prune.",
      "Restores are dry-run and approver-confirmed; the integrity chain is verified before anything is trusted.",
      "In-account restore with dual-control gates and offline restore via the open reader; recovery instructions travel in the bucket.",
    ],
    fixed: [
      "Six-role RBAC. A prune applied from the console always needs a second approver; a second approver for a restore, or for a change to the scheduled prune policy, is optional and off by default.",
      "An attended prune applies only after a second authorised identity approves the exact plan.",
    ],
  },
  {
    // engine wrangler.toml: a bound DEST_R2 (an R2 bucket in this account) is the default destination.
    name: "off-account is conditional on the destination you choose",
    claim: /off-account|outside the source account|off the source account/i,
    qualifier: /unless it is an in-account|when you choose|choose an off-account|in-account R2|including one outside|mirrored off-account/i,
    why: "an in-account R2 bucket is a supported destination, so an off-account copy exists only when you choose one",
    retired: [
      "Immutable, encrypted, off-account backups implement the control directly.",
      "Copies land outside the source account, and 3-2-1 failover keeps a redundant set.",
      "The signed, append-only run log, stored off-account, protects the backup audit record; a freshness high-water mark exposes a rollback.",
      "Scheduled off-account backups with per-dataset cadence and retention.",
    ],
    fixed: [
      "Copies land at a destination you choose, off-account unless it is an in-account R2 bucket, and 3-2-1 failover keeps a redundant set.",
      "Tested, tamper-evident, customer-keyed backups implement the control, held off-account when you choose an off-account destination.",
    ],
  },
  {
    // docs backing-up/data-safety-model.mdx: a wholesale tail rollback to an older, validly signed RUNLOG is
    // caught only by an out-of-band minimum-index pin, and the offline reader's pin defaults off.
    name: "rollback detection names the minimum-index pin",
    claim: /rollback|rolled[- ]back/i,
    qualifier: /pin|min-runlog-index/i,
    why: "the signed run log alone does not catch a rollback to an older, validly signed log",
    retired: [
      "The signed run log makes rollback detectable.",
      "A signed, append-only run log with a freshness high-water mark detects a silent rollback or a forked history.",
    ],
    fixed: ["The signed run log makes a rewrite within the log detectable; a wholesale rollback to an older, validly signed log is caught by the minimum-index pin from your recovery sheet."],
  },
  {
    // env.d.ts: WORM is opt-in and off by default, and R2 enforces no Object Lock at all.
    name: "immutability is conditional on a lock you set",
    claim: /\bimmutable\b/i,
    qualifier: /where you set|when you set|compliance mode/i,
    why: "WORM is opt-in and off by default; without a lock an archive is tamper-evident, not immutable",
    retired: [
      "Verified restore drills with a dated evidence log, immutable off-account copies in a region you choose, and an offline recovery path.",
      "Encryption and customer-held keys, plus the immutable, signed archive.",
    ],
    fixed: ["copies at a destination you choose, write-once where you set a destination retention lock."],
  },
  {
    // sched/scheduler-do-rbac.ts: an admitted identity with no grant resolves to Viewer (source "default").
    name: "an explicit-role claim names the Viewer default",
    claim: /explicit (?:downpipes )?role|explicitly granted|explicit grant/i,
    qualifier: /resolves to Viewer|with no grant/i,
    why: "an authenticated identity with no grant resolves to Viewer, so access does not require an explicit role",
    retired: [
      "Access requires an explicit role keyed to a stable IdP subject; Viewer/Operator tiers cannot read archive contents.",
      "Explicit downpipes role behind SSO/passkeys; no self-service archive access.",
    ],
    fixed: ["An authenticated identity with no grant resolves to Viewer, which cannot read any record value; every higher role is an explicit grant."],
  },
  {
    // sched/scheduler-do-recovery.ts and admin/identity.ts: a passkey caller's subject is passkeySubject(email),
    // so for a passkey sign-in the stable key comes from the email the passkey is bound to. "A stable IdP
    // subject" reads as a claim no email is involved, which holds for an IdP sign-in only.
    name: "a subject-keyed grant claim names the passkey case",
    claim: /stable (?:IdP )?subject|subject claim/i,
    qualifier: /passkey[^.]{0,80}(?:bound email|email the passkey is bound to)/i,
    why: "a passkey sign-in's subject comes from the email the passkey is bound to, not from an IdP",
    retired: [
      "An authenticated identity with no grant resolves to Viewer, which cannot read any record value; every higher role is an explicit grant keyed to a stable IdP subject, once the break-glass admin token is retired. Viewer and Operator cannot read record values.",
      "An authenticated identity with no grant resolves to Viewer, which cannot read any record value; every higher role is an explicit grant behind SSO/passkeys, keyed to a stable IdP subject, once the break-glass admin token is retired.",
      "Every higher role is an explicit grant keyed to the IdP's subject claim, not a reassignable email.",
    ],
    fixed: [
      "Every higher role is an explicit grant keyed to the stable subject of the sign-in or to an IdP group you map. A passkey sign-in has a subject that comes from the email the passkey is bound to.",
      "every higher role is an explicit grant behind SSO and passkeys, keyed to the stable subject of the sign-in (for a passkey, a subject that comes from its bound email) or to an IdP group you map.",
    ],
  },
  {
    // admin/identity-rbac.ts: six roles, and Approver and Restore operator (both below Owner) can apply a restore.
    name: "the role count is six and sub-Owner roles are not said to be blind",
    claim: /\b(?!six-)[a-z]+-role RBAC|sub-Owner roles cannot/i,
    qualifier: /(?!)/,
    why: "there are six built-in roles, and two roles below Owner can apply a restore",
    retired: ["Four-role RBAC and dual-control approvals over who can restore and who can prune.", "Credentials bind to the engine; sub-Owner roles cannot read archive contents."],
    fixed: ["Six-role RBAC.", "The Viewer, Operator and Access admin roles carry no capability that reads a record value."],
  },
];
const convicts = (r: ClaimRule, s: string): boolean => r.claim.test(s) && !r.qualifier.test(s);
for (const r of CLAIM_RULES) {
  const off = entries.filter((e) => convicts(r, e.capability));
  const seen = entries.filter((e) => r.claim.test(e.capability)).length;
  ok(`${r.name} (${seen} claim(s) read, ${off.length} offender(s): ${off.map((e) => e.control).join(", ") || "none"})`, off.length === 0);
  if (off.length > 0) console.log(`       ${r.why}.`);
  ok(`  control: the rule fires on all ${r.retired.length} retired wording(s)`, r.retired.every((s) => convicts(r, s)));
  ok(`  control: and accepts the corrected wording`, r.fixed.every((s) => !convicts(r, s)));
}

// ---------------------------------------------------------------------------------------------------
// FIFTH RULE: a check bound to a control must be able to fail for it.
//
// The signed pack prints each bound check's live status under the control, and counts a pass as
// evidence. Before this rule, GDPR and UK Art. 5(1)(e) and APP 11.2 (storage limitation) were evidenced
// only by credential-expiry, which grades expiring destination credentials. ISO A.8.10 and OAIC 11.39
// (deletion) and NIST AU-9 were evidenced only by audit-export-available, which always passes. NIST
// CP-9(7) (dual authorisation for deletion) was evidenced by two-owners, which counts Owners. So a
// customer with no retention policy and pruning in dry run received a signed pass under each.
console.log("\n-- no control is evidenced by a check that cannot fail for it --\n");
const bound = [...text.matchAll(/\{ control: "([^"]+)", obligation: "([^"]+)", capability: "[^"]+", checkIds: \[([^\]]*)\] \}/gs)].map((m) => ({
  control: m[1] as string,
  obligation: m[2] as string,
  checkIds: [...(m[3] as string).matchAll(/"([^"]+)"/g)].map((x) => x[1] as string),
}));
ok(`the binding extractor read every control (${bound.length} of ${entries.length})`, bound.length === entries.length && bound.length >= 20);
const DOES_NOT_BEAR: { check: string; obligation: RegExp; why: string }[] = [
  { check: "credential-expiry", obligation: /storage limitation|delet|destr|dispos|no longer/i, why: "grades expiring credentials, not retention" },
  { check: "audit-export-available", obligation: /storage limitation|delet|destr|dispos|no longer|protection of audit information/i, why: "always passes" },
  { check: "two-owners", obligation: /dual authori[sz]ation/i, why: "counts Owners, not deletion approvals" },
];
const wrongBindings = bound.flatMap((b) => DOES_NOT_BEAR.filter((d) => b.checkIds.includes(d.check) && d.obligation.test(b.obligation)).map((d) => `${b.control} <- ${d.check} (${d.why})`));
ok(`no deletion, retention or audit-protection control is evidenced by a check that cannot fail for it (${wrongBindings.length}: ${wrongBindings.join("; ") || "none"})`, wrongBindings.length === 0);
ok("control: the rule would have caught Art. 5(1)(e) <- credential-expiry", DOES_NOT_BEAR[0]?.obligation.test("Storage limitation: keep personal data no longer than necessary.") === true);
ok("control: and CP-9(7) <- two-owners", DOES_NOT_BEAR[2]?.obligation.test("Dual Authorization for the deletion or destruction of backup information.") === true);
const au9 = bound.find((b) => b.control === "AU-9");
ok("AU-9 is evidenced by the check that grades it (off-account-audit-mirror)", au9?.checkIds.includes("off-account-audit-mirror") === true);

// The same, run through the generator the signed pack uses: a posture where credential-expiry and
// audit-export-available both pass must put no passing check under a storage-limitation row.
{
  const posture: PostureReport = {
    score: 90,
    generatedAt: "2026-09-23T00:00:00.000Z",
    checks: ["credential-expiry", "audit-export-available", "two-owners"].map((id) => ({ id, title: id, severity: "low", status: "pass", autoStatus: "pass", control: "", detail: "", remediation: "", how: "" })),
  };
  const packRows = buildEvidencePackReport(FRAMEWORKS, posture, "all").packs.flatMap((p) => p.controls);
  const passingUnder = (control: string): boolean => packRows.filter((c) => c.control === control).some((c) => c.checks.some((k) => k.status === "pass"));
  for (const control of ["Art. 5(1)(e)", "APP 11.2", "A.8.10", "OAIC Guidelines para 11.39", "CP-9(7)"]) {
    ok(`the signed pack shows no passing check under ${control} on a posture with no retention evidence`, packRows.some((c) => c.control === control) && !passingUnder(control));
  }
}

console.log(`\n${failures === 0 ? "FRAMEWORK-POSTURE-CLAIMS PASS" : `FRAMEWORK-POSTURE-CLAIMS: ${failures} FAILED`}\n`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
