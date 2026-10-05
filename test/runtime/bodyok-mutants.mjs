// bodyok-mutants.mjs -- can the idp-body-ok drive actually kill a wrong repair, or does it only agree with itself?
//
// Run: node test/runtime/bodyok-mutants.mjs
//
// STRICTLY SERIAL. One mutant is planted, scored and restored before the next is planted, because the driver
// bundles the engine's source from disk and two mutants live at once would score each other. Nothing that
// imports a mutated file may run beside this.
//
// Each mutant is anchored on a literal ASSERTED to occur EXACTLY ONCE in the file, so a plant cannot silently
// hit a second site or none. The file's sha256 is asserted MOVED after planting (a plant that changed nothing
// would otherwise score as a survivor, which reads as "the test is weak" when it means "the mutation never
// happened") and re-asserted EQUAL after a BYTE-COPY restore from a pristine copy taken before the first
// plant. Never `git checkout`: a checkout would also discard anything else in the working tree.
//
// THE COMMENT-ONLY MUTANT MUST SURVIVE. A suite that kills it is keying on something other than behaviour.
//
// Exit: 0 every mutant scored as expected; 1 one did not; 4 the harness could not check.

import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, "..", "..");
const TARGETS = {
  identity: join(ROOT, "src", "admin", "router-identity.ts"),
  notify: join(ROOT, "src", "admin", "router-notify.ts"),
  idp: join(ROOT, "src", "sched", "scheduler-do-idp.ts"),
};
const PRISTINE = {
  identity: join(here, ".bundle", "bodyok-router-identity.pristine.ts"),
  notify: join(here, ".bundle", "bodyok-router-notify.pristine.ts"),
  idp: join(here, ".bundle", "bodyok-scheduler-do-idp.pristine.ts"),
};
const DRIVER = join(here, "runtime.idp-body-ok.test.mjs");

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const say = (s) => console.log(s);

// Each mutant names the FILE it edits (`in`), a `from` literal ASSERTED to occur exactly once in that file,
// the case id whose arm must go RED (`kills`), and the case list the driver is given (`only`; the known
// positive is forced in by the driver itself).
const MUTANTS = [
  {
    id: "M1-add-reverts-to-transport-ok",
    in: "identity",
    why: "the add site goes back to firing on resp.ok, which is the defect this pass repaired",
    from: "if (created.ok && !(await doRefusedTheChange(created))) fireInBackground",
    to: "if (created.ok) fireInBackground",
    only: "idp-add-applied,idp-add-refused,idp-add-queued",
    kills: "idp-add-refused",
    expect: "killed",
  },
  {
    id: "M2-delete-reverts-to-transport-ok",
    in: "identity",
    why: "the delete site goes back to firing on resp.ok",
    from: "if (deleted.ok && !(await doRefusedTheChange(deleted)) && !(await doDeletedNothing(deleted))) fireInBackground",
    to: "if (deleted.ok) fireInBackground",
    only: "idp-delete-applied,idp-delete-refused",
    kills: "idp-delete-refused",
    expect: "killed",
  },
  {
    id: "M3-refusal-test-becomes-a-success-test",
    in: "notify",
    why:
      "THE SHARP ONE. `.ok === false` becomes `.ok !== true`, which is the naive repair: it suppresses every " +
      "refusal exactly as the real one does, so all four refused cases stay green. It ALSO suppresses the 202 " +
      "{ ownerActionQueued } body, which has no ok field -- deleting the only alert an IdP change under dual " +
      "control ever gets. IT SURVIVED THE FIRST MUTATION RUN, and that survival is the finding: the add site " +
      "then carried its own inline copy of the test rather than calling the helper, and idp-add-queued was " +
      "the only queued case in the suite, so the mutant was never in the path that case drove. Two things " +
      "changed after it: idp-delete-queued reaches the helper with a 202 body, and all four sites now call " +
      "the one helper, so the queued cases on BOTH routes kill it.",
    from: "return ((await resp.clone().json()) as { ok?: unknown }).ok === false;",
    to: "return ((await resp.clone().json()) as { ok?: unknown }).ok !== true;",
    only: "idp-add-applied,idp-add-refused,idp-delete-refused,idp-enabled-refused,idp-cert-refused,idp-add-queued,idp-delete-queued",
    kills: "idp-delete-queued",
    expect: "killed",
  },
  {
    id: "M4-cert-alert-filed-under-the-add-route-name",
    in: "identity",
    why:
      "the cert rollover fires the ADD route's detail. The event, the alert class, the counter name, the " +
      "counts and the notify-history ROW COUNT are all unchanged; only the exact composed detail separates them.",
    from: "`A SAML signing-certificate rollover was requested (an IdP trust-root change)${caller.email",
    to: "`An IdP connection add was requested (changes who can sign in)${caller.email",
    only: "idp-cert-applied,idp-cert-refused",
    kills: "idp-cert-applied",
    expect: "killed",
  },
  // ---- the no-op delete guard's four mutants. Every one leaves the DO's own answer untouched, so each is
  //      scored as a KILL by an arm and never as a could-not-check. ---------------------------------------
  {
    id: "M6-nooop-test-becomes-a-success-test",
    in: "notify",
    why:
      "THE SHARP ONE FOR THIS REPAIR, and it is M3's shape again on the second field. `.deleted === false` " +
      "becomes `.deleted !== true`, which is the naive way to write it: every no-op is suppressed exactly " +
      "as the real guard suppresses it, so idp-delete-absent stays green and the repair looks done. It ALSO " +
      "suppresses the 202 { ownerActionQueued } body, which carries no `deleted` field at all -- deleting " +
      "the propose-time alert that is the ONLY alert a queued IdP removal ever gets, because router.ts:664 " +
      "fires on approve for dual-control-disable and nothing else. idp-delete-queued is the arm that catches " +
      "it, and it drives a 202 THROUGH the delete site rather than around it.",
    from: "return ((await resp.clone().json()) as { deleted?: unknown }).deleted === false;",
    to: "return ((await resp.clone().json()) as { deleted?: unknown }).deleted !== true;",
    only: "idp-delete-applied,idp-delete-absent,idp-delete-queued",
    kills: "idp-delete-queued",
    expect: "killed",
  },
  {
    id: "M7-noop-guard-dropped-at-the-delete-site",
    in: "identity",
    why: "the delete site reverts to b790adfa exactly: the refusal guard stays, the no-op guard goes, and an absent delete alerts again.",
    from: "if (deleted.ok && !(await doRefusedTheChange(deleted)) && !(await doDeletedNothing(deleted))) fireInBackground",
    to: "if (deleted.ok && !(await doRefusedTheChange(deleted))) fireInBackground",
    only: "idp-delete-applied,idp-delete-refused,idp-delete-absent",
    kills: "idp-delete-absent",
    expect: "killed",
  },
  {
    id: "M8-guard-reads-the-OLD-field",
    in: "notify",
    why:
      "doDeletedNothing reads `ok` instead of `deleted`, making it a duplicate of doRefusedTheChange. Every " +
      "refusal case stays green because the refusal guard beside it already catches those, so this is caught " +
      "ONLY by the no-op arm -- which is the point: it proves the assertion is keyed on the NEW field and " +
      "not merely on there being two guards.",
    from: "return ((await resp.clone().json()) as { deleted?: unknown }).deleted === false;",
    to: "return ((await resp.clone().json()) as { ok?: unknown }).ok === false;",
    only: "idp-delete-applied,idp-delete-refused,idp-delete-absent",
    kills: "idp-delete-absent",
    expect: "killed",
  },
  {
    id: "M9-suppresses-on-PRESENCE-not-on-VALUE",
    in: "notify",
    why:
      "the guard fires on the field being THERE rather than on it being false, which is the careless version " +
      "of the same idea. Every no-op stays suppressed, so idp-delete-absent still reads 0/N and looks right; " +
      "what breaks is the REAL removal, which now loses its alert silently. Caught by idp-delete-applied, " +
      "and it is the arm that proves this guard was written on the value and not on the shape.",
    from: "return ((await resp.clone().json()) as { deleted?: unknown }).deleted === false;",
    to: "return ((await resp.clone().json()) as { deleted?: unknown }).deleted !== undefined;",
    only: "idp-delete-applied,idp-delete-refused,idp-delete-absent",
    kills: "idp-delete-applied",
    expect: "killed",
  },
  // ---- the DO-side mutant, and it is scored differently ON PURPOSE ---------------------------------------
  {
    id: "M10-DO-always-claims-it-deleted-something",
    in: "idp",
    why:
      "`deleted: existed` becomes `deleted: true`, so the durable object lies about the no-op and the router " +
      "correctly believes it. THIS IS NOT SCORED AS A KILL AND MUST NOT BE, because the driver catches it " +
      "UPSTREAM of any alert count: every case asserts the DO's own verdict off the response first, so an " +
      "absent delete answering ok-true-deleted trips 'THE ROUTE DID NOT ANSWER 200/ok-true-deleted-nothing' " +
      "and the arm is could-not-check rather than a clean zero. That is the detector working, and naming it " +
      "here is honest where scoring it as a kill would be a lie about which assertion fired. The same reading " +
      "was taken WITHOUT a mutant, against a pristine b790adfa control -- an engine whose DO genuinely does " +
      "not report the field -- and it exits 4 with the same line.",
    from: "return { ok: true, deleted: existed };",
    to: "return { ok: true, deleted: true };",
    only: "idp-delete-applied,idp-delete-absent",
    kills: "THE ROUTE DID NOT ANSWER 200/ok-true-deleted-nothing",
    expect: "caught-as-verdict",
  },
  {
    id: "M5-comment-only-CONTROL",
    in: "notify",
    why: "a behaviour-neutral edit inside a comment. It MUST survive; a suite that kills it is keying on text.",
    from: "// FAIL-OPEN: an unreadable or non-JSON body keeps the alert rather than losing it.",
    to: "// FAIL-OPEN (control): an unreadable or non-JSON body keeps the alert rather than losing it.",
    only: "idp-add-applied,idp-add-refused,idp-add-queued",
    kills: null,
    expect: "survived",
  },
];

// A pristine byte copy of EVERY file any mutant touches, taken before the first plant. Restores come from
// these and never from `git checkout`, which would also discard anything else in the working tree.
const BASE = {};
for (const k of Object.keys(TARGETS)) {
  copyFileSync(TARGETS[k], PRISTINE[k]);
  BASE[k] = sha(PRISTINE[k]);
  say(`pristine ${TARGETS[k]}`);
  say(`  sha256 ${BASE[k]}`);
}
say("");

let bad = 0;
for (const m of MUTANTS) {
  say(`== ${m.id} ==`);
  say(`   ${m.why}`);

  const target = TARGETS[m.in];
  const pristine = PRISTINE[m.in];
  const base = BASE[m.in];
  const before = readFileSync(target, "utf8");
  const hits = before.split(m.from).length - 1;
  if (hits !== 1) {
    say(`   ANCHOR OCCURS ${hits} TIME(S), NOT EXACTLY ONCE -> COULD-NOT-CHECK`);
    process.exit(4);
  }
  writeFileSync(target, before.replace(m.from, m.to));
  const planted = sha(target);
  if (planted === base) {
    say("   THE SHA DID NOT MOVE, SO NOTHING WAS PLANTED -> COULD-NOT-CHECK");
    copyFileSync(pristine, target);
    process.exit(4);
  }
  say(`   planted in ${m.in}, sha256 MOVED to ${planted.slice(0, 16)}...`);

  const r = spawnSync(process.execPath, [DRIVER, "--only", m.only], { cwd: ROOT, encoding: "utf8" });
  const code = r.status;
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;

  // BYTE-COPY RESTORE, then re-assert EQUAL. Never `git checkout`.
  copyFileSync(pristine, target);
  const restored = sha(target);
  if (restored !== base) {
    say(`   RESTORE DID NOT RETURN THE ORIGINAL BYTES (${restored}) -> COULD-NOT-CHECK`);
    process.exit(4);
  }
  say(`   restored by byte copy, sha256 EQUAL to pristine`);

  // The named case's own arm must be the one that went red, so a mutant is never credited to a neighbour.
  const killedHere = code === 1 && (m.kills === null || out.includes(m.kills));
  const verdict = code === 0 ? "survived" : code === 1 ? "killed" : `could-not-check (exit ${code})`;
  say(`   driver exit ${code} -> ${verdict}${m.kills !== null ? `, expected the red arm at ${m.kills}` : ""}`);
  // A mutant that corrupts the DURABLE OBJECT'S OWN ANSWER is caught by the verdict assertion, which runs
  // BEFORE any alert count is read, so the driver exits 4 and naming that as a kill would misreport which
  // assertion fired. Such a mutant declares expect:"caught-as-verdict" and must produce exit 4 AND the exact
  // diagnostic line, so "could not check" here is a NAMED detection and never a shrug. Note the asymmetry
  // with the twin control below, and it is deliberate: a kill the suite MADE is never softened to exit 4,
  // and a detection the suite made THIS way is never inflated to a kill.
  if (m.expect === "caught-as-verdict") {
    const caught = code === 4 && out.includes(m.kills);
    say(`   expected CAUGHT BY THE VERDICT ASSERTION (exit 4 + the named line): ${caught ? "yes" : "NO"}`);
    if (!caught) {
      say("   FAIL the DO-side mutant was not caught by the verdict assertion");
      bad++;
    }
    say("");
    continue;
  }
  if (code === 4) {
    say("   THE DRIVER COULD NOT CHECK, so this mutant is unscored");
    bad++;
  } else if (m.expect === "killed" && !killedHere) {
    say("   FAIL this mutant was NOT killed by the case that must catch it");
    bad++;
  } else if (m.expect === "survived" && code !== 0) {
    say("   FAIL the comment-only control was killed, so the suite is keying on text and not behaviour");
    bad++;
  } else {
    // Print the one line that carries the reading, so the kill is legible rather than asserted.
    for (const line of out.split("\n")) {
      if (m.kills !== null && line.includes("FAIL ") ) say(`      ${line.trim()}`);
    }
  }
  say("");
}

say(bad === 0 ? "MUTANTS: every one scored as expected" : `MUTANTS: ${bad} scored wrong`);
process.exit(bad === 0 ? 0 : 1);
