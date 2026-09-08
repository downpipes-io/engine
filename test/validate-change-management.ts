// Validator for CHANGE MANAGEMENT (OWNER OPT-IN "Require Change Number", default OFF). Part A proves the
// PURE logic (the policy validation, the safe parse, the report + posture projections, the change-controlled
// set). Part B drives the PRODUCTION handleAdmin + the scheduler DO to prove the enforcement chokepoint
// refuses a change-controlled action without a reference, records the change-recorded CR ledger, flags an
// Emergency Change loudly + bumps the compliance marker, never blocks the break-glass token, and surfaces the
// emergency-change posture finding + the change-requests report. It reuses the owner-action dual-control
// harness (makeScheduler / buildContext / the forged-Access-JWT call()) so the proof runs the real wiring.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments } from "./lib/blank-comments.mjs";
import { ok, failureCount, buildContext } from "./validate-owner-action-dualcontrol-harness.ts";
import { evaluateChangeControl, parseChangeRef, decodeChangeHeader, decodeChangeHeaderWithFault, changeNumberExceedsMax, CHANGE_NUMBER_MAX, CHANGE_NUMBER_TOO_LONG, CHANGE_REASON_MAX } from "../src/admin/change-ref.ts";
import { isChangeControlledOwnerAction, isOwnerActionKind } from "../src/admin/owner-action.ts";
import { buildChangeRequestsReport } from "../src/admin/reports.ts";
import { buildEmergencyChangeReview } from "../src/admin/posture-checks.ts";
import type { PostureInput } from "../src/admin/posture.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";

// A minimal PostureInput carrying only the change-management slice the emergency-change builder reads (it
// touches nothing else), cast through unknown like the other validators cast their DO state shims.
function withChangeManagement(cm: PostureInput["changeManagement"]): PostureInput {
  return { changeManagement: cm } as unknown as PostureInput;
}

// A change-recorded AuditEvent for the report-builder test (the chain fields are placeholders the builder drops).
function changeEvent(ts: string, actorEmail: string | null, actionKind: string, emergency: boolean, changeNumber: string | null, reason: string | null): AuditEvent {
  return { seq: 1, ts, actorEmail, actorMethod: "access", sourceIp: null, action: "change-recorded", outcome: "success", target: { kind: "change", actionKind, emergency, changeNumber, reason }, prevHash: "sha384:x", hash: "sha384:y" };
}

// SRC_ROOT is the engine source tree the vocabulary scan below reads. The scan runs over the SOURCE rather
// than over any exported list, because the thing being checked is whether a NEW enforcement site can appear
// without anyone declaring what it enforces, and an exported list cannot see a site that never joined it.
const SRC_ROOT = fileURLToPath(new URL("../src/", import.meta.url));

// tsFilesUnder walks the source tree and returns every .ts file, so a new subsystem's directory is covered
// the day it is added rather than the day someone remembers to list it here.
function tsFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFilesUnder(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

// scanLiteralChangeKinds derives, FROM SOURCE, the change-controlled action kinds that are NOT owner actions.
//
// WHY THIS IS THE RIGHT QUESTION TO ASK OF THE SOURCE. enforceChangeControl is the SOLE writer of the CR
// ledger (recordChange has exactly one caller, and it is inside enforceChangeControl), so "what does the
// customer's change-number policy actually cover" is answerable from its call sites and from nowhere else.
// Most of those sites pass a kind VARIABLE: gatedOwnerAction and checkOwnerActionGate forward whichever
// OwnerActionKind they were handed, and isChangeControlledOwnerAction (asserted above) already decides that
// half. What is left is the LITERAL kinds, and a literal kind is exactly an action that is change-controlled
// WITHOUT being an owner action -- the shape that went missing: POST /push/delete and POST /otlp-push/delete
// prompted the operator for a change number through the console and recorded nothing, because they are
// owner-exclusive but are not owner actions, so gatedOwnerAction was never on their path.
//
// Two call shapes reach the chokepoint with a literal, and both are scanned:
//   - a DO route calling this.enforceChangeControl("kind", caller) directly (the two push clears);
//   - the ROUTER asking the DO through its internal POST /change-control/enforce route (the restore apply),
//     which carries the kind in the request body.
// Comments are blanked first (scripts/lib/blank-comments.mjs), because this repo has already shipped a
// scanner that read a commented-out line as live code; string CONTENT is left intact, which is the point.
// The enforce-route scan REFUSES a call site whose body it cannot read rather than passing over it: a kind
// the scan cannot see is a kind nobody declared, which is the failure this whole check exists to catch.
function scanLiteralChangeKinds(): { kinds: string[]; unreadableEnforceCalls: string[] } {
  const kinds = new Set<string>();
  const unreadable: string[] = [];
  for (const file of tsFilesUnder(SRC_ROOT)) {
    const src = blankComments(readFileSync(file, "utf8"));
    for (const m of src.matchAll(/enforceChangeControl\(\s*"([^"]+)"/g)) kinds.add(m[1] ?? "");
    for (const m of src.matchAll(/"\/change-control\/enforce"/g)) {
      const window = src.slice(m.index ?? 0, (m.index ?? 0) + 400);
      const kind = /actionKind:\s*"([^"]+)"/.exec(window);
      if (kind === null) unreadable.push(`${file}:${src.slice(0, m.index ?? 0).split("\n").length}`);
      else kinds.add(kind[1] ?? "");
    }
  }
  return { kinds: [...kinds].sort(), unreadableEnforceCalls: unreadable };
}

function partA(): void {
  // ---- evaluateChangeControl (the policy decision) -------------------------------------------------
  const off = evaluateChangeControl(false, null);
  ok("A: policy OFF => ok with no reference (dormant)", off.ok === true && off.change === null);
  const offIgnore = evaluateChangeControl(false, { number: "x", emergency: false, reason: null });
  ok("A: policy OFF ignores a supplied reference", offIgnore.ok === true && offIgnore.change === null);

  const normalOk = evaluateChangeControl(true, { number: "CHG0001", emergency: false, reason: null });
  ok("A: ON + a change number => ok, normal change", normalOk.ok === true && normalOk.change?.number === "CHG0001" && normalOk.change?.emergency === false);
  const normalMissing = evaluateChangeControl(true, { number: "", emergency: false, reason: null });
  ok("A: ON + empty change number => refused", normalMissing.ok === false);
  const normalAbsent = evaluateChangeControl(true, null);
  ok("A: ON + no reference at all => refused", normalAbsent.ok === false);

  const emOk = evaluateChangeControl(true, { number: null, emergency: true, reason: "prod outage" });
  ok("A: ON + emergency + justification => ok, emergency", emOk.ok === true && emOk.change?.emergency === true && emOk.change?.reason === "prod outage" && emOk.change?.number === null);
  const emNoReason = evaluateChangeControl(true, { number: null, emergency: true, reason: "" });
  ok("A: ON + emergency without justification => refused", emNoReason.ok === false);
  const emWithNumber = evaluateChangeControl(true, { number: "CHG9", emergency: true, reason: "ECAB pending" });
  ok("A: ON + emergency keeps a supplied number", emWithNumber.ok === true && emWithNumber.change?.number === "CHG9" && emWithNumber.change?.emergency === true);

  // ---- parseChangeRef / decodeChangeHeader (safe parse off the wire) -------------------------------
  ok("A: parseChangeRef(null) => null", parseChangeRef(null) === null);
  ok("A: parseChangeRef({}) => null (nothing to carry)", parseChangeRef({}) === null);
  const trimmed = parseChangeRef({ number: "  CHG-1  ", emergency: false, reason: null });
  ok("A: parseChangeRef trims the number", trimmed !== null && trimmed.number === "CHG-1");
  const ctrl = parseChangeRef({ number: "CHG", emergency: false });
  ok("A: parseChangeRef strips control chars", ctrl !== null && ctrl.number === "CHG");
  const bounded = parseChangeRef({ number: "C".repeat(CHANGE_NUMBER_MAX + 50), emergency: false });
  ok("A: parseChangeRef bounds the number length", bounded !== null && (bounded.number ?? "").length === CHANGE_NUMBER_MAX);

  // ---- The change NUMBER is REFUSED over the cap, not trimmed to it -------------------------------
  //
  // A change number is a reference to a record in the CUSTOMER'S change-management system, and its only job
  // is to match. Trimming it produced a value that still looked like a change number, went into the
  // immutable CR ledger without complaint, and matched nothing. The JUSTIFICATION is deliberately left
  // truncating: it is prose, the tail costs detail rather than identity, and the cut is visible to whoever
  // reads the record. changeNumberExceedsMax is the measuring half and it measures the CLEANED text, so a
  // legal reference padded with whitespace or carrying a stray CR from a paste is NOT refused.
  ok("A: exactly CHANGE_NUMBER_MAX is not over length", changeNumberExceedsMax("A".repeat(CHANGE_NUMBER_MAX)) === false);
  ok("A: one character over CHANGE_NUMBER_MAX is over length", changeNumberExceedsMax("A".repeat(CHANGE_NUMBER_MAX + 1)) === true);
  ok("A: a padded legal number is NOT over length (measured on the cleaned text)", changeNumberExceedsMax(`   ${"A".repeat(CHANGE_NUMBER_MAX)}   `) === false);
  ok("A: a legal number carrying a stray CR/LF is NOT over length", changeNumberExceedsMax(`${"A".repeat(CHANGE_NUMBER_MAX)}\r\n`) === false);
  ok("A: a non-string is not an over-length number (it carries no reference at all)", changeNumberExceedsMax(null) === false && changeNumberExceedsMax(undefined) === false && changeNumberExceedsMax(12345) === false);

  // The refusal is customer-facing prose, so it is asserted on its CONTENT rather than only against itself:
  // a wire assertion that compares the message to the same constant it came from moves with any edit to it
  // and cannot notice the bound going missing. It has to name the bound and tell the operator what to do.
  ok("A: the over-length refusal names the bound", CHANGE_NUMBER_TOO_LONG.includes(String(CHANGE_NUMBER_MAX)) && /characters or fewer/.test(CHANGE_NUMBER_TOO_LONG));
  ok("A: the over-length refusal names the remedy", /shorten it/i.test(CHANGE_NUMBER_TOO_LONG));

  // WHAT IS ACCEPTED IS STORED WHOLE. Capping BEFORE trimming would let leading whitespace eat into the
  // budget, so a padded reference at the cap would be accepted as legal and then stored shorter: a silent
  // alteration the length rule alone does not catch.
  const paddedRef = parseChangeRef({ number: `   ${"A".repeat(CHANGE_NUMBER_MAX)}   `, emergency: false });
  ok("A: a padded number at exactly the cap is stored WHOLE, not shortened by its own padding", paddedRef !== null && paddedRef.number === "A".repeat(CHANGE_NUMBER_MAX));

  const overHeader = b64urlEncode(new TextEncoder().encode(JSON.stringify({ number: "C".repeat(200), emergency: false, reason: null })));
  const overFault = decodeChangeHeaderWithFault(overHeader);
  ok("A: an over-length number in the header is classified over-length, and carries NO reference", overFault.fault === "over-length" && overFault.ref === null);
  const atCapHeader = b64urlEncode(new TextEncoder().encode(JSON.stringify({ number: "A".repeat(CHANGE_NUMBER_MAX), emergency: false, reason: null })));
  ok("A: a number at exactly the cap is NOT classified over-length", decodeChangeHeaderWithFault(atCapHeader).fault === null);
  const longReasonHeader = b64urlEncode(new TextEncoder().encode(JSON.stringify({ number: null, emergency: true, reason: "R".repeat(2000) })));
  const longReasonFault = decodeChangeHeaderWithFault(longReasonHeader);
  ok("A: an over-length JUSTIFICATION is NOT a fault: it still truncates, by decision", longReasonFault.fault === null && (longReasonFault.ref?.reason ?? "").length === CHANGE_REASON_MAX);
  const header = b64urlEncode(new TextEncoder().encode(JSON.stringify({ number: "CHG-77", emergency: false, reason: null })));
  const dec = decodeChangeHeader(header);
  ok("A: decodeChangeHeader round-trips a reference", dec !== null && dec.number === "CHG-77");
  ok("A: decodeChangeHeader(garbage) => null", decodeChangeHeader("not base64 %%%") === null);
  ok("A: decodeChangeHeader(null) => null", decodeChangeHeader(null) === null);

  // ---- isChangeControlledOwnerAction (the CAB set) ------------------------------------------------
  ok("A: dest-remove is change-controlled", isChangeControlledOwnerAction("dest-remove") === true);
  ok("A: idp-conn-create is change-controlled", isChangeControlledOwnerAction("idp-conn-create") === true);
  ok("A: dual-control-disable is NOT change-controlled (the OFF switch)", isChangeControlledOwnerAction("dual-control-disable") === false);
  ok("A: sources-attach is NOT change-controlled (additive / low-blast)", isChangeControlledOwnerAction("sources-attach") === false);

  // ---- The change-controlled kinds that are NOT owner actions (scanned from source) ---------------
  // This is the whole of the other half of the policy's coverage, and until this check it was written down
  // nowhere: the owner-action half has a predicate anyone can read, and the rest was three call sites in
  // three files. DECLARE the members here, beside the assertions that prove enforcement, so a fourth cannot
  // arrive without a reader deciding it belongs -- and so a member cannot QUIETLY LEAVE either, which is the
  // direction that actually bit (the two clears prompted the operator and recorded nothing for as long as
  // nothing named them).
  //   restore-apply  a restore writes customer data back over live records (router-restore.ts asks the DO to
  //                  enforce before applying). Data plane, so it was never an owner action.
  //   push-clear     clearing the SIEM push destination stops the customer's SIEM receiving the audit trail.
  //   otlp-clear     clearing the OTLP destination stops their collector receiving backup-health telemetry.
  // The two clears are owner-EXCLUSIVE but deliberately not dual-control gated (closing an egress is the safe
  // direction), and OwnerActionKind IS the dual-control set, so they enforce at their own DO route instead.
  const EXPECTED_NON_OWNER_ACTION_CHANGE_KINDS = ["otlp-clear", "push-clear", "restore-apply"];
  const scanned = scanLiteralChangeKinds();
  ok(
    `A: every enforce call site the scan cannot read is a kind nobody declared (found ${scanned.unreadableEnforceCalls.length}: ${scanned.unreadableEnforceCalls.join(", ") || "none"})`,
    scanned.unreadableEnforceCalls.length === 0,
  );
  ok(
    `A: the non-owner-action change-controlled kinds in src are exactly the declared three (found ${scanned.kinds.join(", ") || "none"})`,
    JSON.stringify(scanned.kinds) === JSON.stringify(EXPECTED_NON_OWNER_ACTION_CHANGE_KINDS),
  );
  // None of them may be an OwnerActionKind. A literal kind that IS one would mean a second, hand-rolled path
  // to the chokepoint for an action gatedOwnerAction already routes -- two enforcement paths for one action,
  // which is how a double CR (or a bypass of the dual-control queue that follows it) arrives.
  ok("A: no non-owner-action change kind collides with an OwnerActionKind", scanned.kinds.every((k) => !isOwnerActionKind(k)));

  // ---- buildEmergencyChangeReview (the compliance flag) -------------------------------------------
  ok("A: emergency check is not applicable when the policy is off", buildEmergencyChangeReview(withChangeManagement({ required: false, emergencyCount: 3 })) === null);
  ok("A: emergency check is absent when the slice is absent", buildEmergencyChangeReview(withChangeManagement(undefined)) === null);
  const passCheck = buildEmergencyChangeReview(withChangeManagement({ required: true, emergencyCount: 0 }));
  ok("A: emergency check passes with 0 emergencies", passCheck !== null && passCheck.auto === "pass" && passCheck.id === "emergency-change-review");
  const failCheck = buildEmergencyChangeReview(withChangeManagement({ required: true, emergencyCount: 2, emergencyLastAt: "2026-06-28T00:00:00.000Z" }));
  ok("A: emergency check FAILS with >=1 emergency + names the count + date", failCheck !== null && failCheck.auto === "fail" && /2 emergency changes/.test(failCheck.detail) && /2026-06-28/.test(failCheck.detail));

  // ---- buildChangeRequestsReport (the CR ledger projection) ---------------------------------------
  const events = [
    changeEvent("2026-06-01T00:00:00.000Z", "a@x", "dest-remove", false, "CHG-1", null),
    changeEvent("2026-06-10T00:00:00.000Z", "b@x", "idp-conn-create", true, null, "outage"),
    changeEvent("2026-06-20T00:00:00.000Z", "c@x", "restore-apply", false, "CHG-3", null),
  ];
  const all = buildChangeRequestsReport(events, null);
  ok("A: report tallies all CR entries + the emergency total", all.total === 3 && all.emergencyTotal === 1);
  ok("A: report is newest-first", all.entries[0]?.actionKind === "restore-apply" && all.entries[2]?.actionKind === "dest-remove");
  const from = Math.floor(Date.parse("2026-06-05T00:00:00Z") / 1000);
  const to = Math.floor(Date.parse("2026-06-15T00:00:00Z") / 1000);
  const windowed = buildChangeRequestsReport(events, { fromSeconds: from, toSeconds: to });
  ok("A: report period-filters to the window", windowed.total === 1 && windowed.entries[0]?.actionKind === "idp-conn-create");
}

async function partB(): Promise<void> {
  const ctx = await buildContext();
  const { OWNER, OWNER2, call, doFetch, ownerCaller, readLog, setGate, listDestinations, destConfig, ownerActionKeyCount } = ctx;
  const changeRecorded = async (): Promise<Array<Extract<AuditEvent["target"], { kind: "change" }> & { actorEmail: string | null }>> => {
    const log = await readLog();
    return log.events.filter((e) => e.action === "change-recorded" && e.target.kind === "change").map((e) => ({ ...(e.target as Extract<AuditEvent["target"], { kind: "change" }>), actorEmail: e.actorEmail }));
  };
  try {
    // (1) Policy OFF (default): the enforce chokepoint is a no-op, records nothing.
    const offResp = await doFetch("/change-control/enforce", ownerCaller(OWNER), { actionKind: "dest-remove" });
    ok("B: enforce is a no-op when the policy is OFF (200)", offResp.status === 200);
    ok("B: no change-recorded event while the policy is OFF", (await changeRecorded()).length === 0);

    // (2) The owner turns Require Change Number ON; the view reflects it.
    const setResp = await call(OWNER, "POST", "/admin/config/change-number-policy", { requireChangeNumber: true });
    ok("B: the owner turns Require Change Number ON (200)", setResp.status === 200);
    const view = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval?: boolean; requireChangeNumber?: boolean };
    ok("B: the policy view reports requireChangeNumber=true (alongside the dual-control flag)", view.requireChangeNumber === true && view.requireConfigApproval === false);

    // (3) Enforce: refused without a reference.
    const noRef = await doFetch("/change-control/enforce", ownerCaller(OWNER), { actionKind: "dest-remove" });
    ok("B: a change-controlled action without a reference is refused (400)", noRef.status === 400);
    ok("B: the refusal names the change-number requirement", /change number/i.test(((await noRef.json()) as { error?: string }).error ?? ""));
    ok("B: a refused action records NO change-recorded entry", (await changeRecorded()).length === 0);

    // (4) Enforce: a change number records a normal CR.
    const withNum = await doFetch("/change-control/enforce", { ...ownerCaller(OWNER), change: { number: "CHG-100", emergency: false, reason: null } }, { actionKind: "dest-remove" });
    ok("B: a valid change number passes (200)", withNum.status === 200);
    const afterNum = await changeRecorded();
    const crNum = afterNum.find((t) => t.changeNumber === "CHG-100");
    ok("B: a change-recorded CR entry was written, normal, with the number + actor", crNum !== undefined && crNum.emergency === false && crNum.actionKind === "dest-remove" && crNum.actorEmail === OWNER);

    // (5) Enforce: an Emergency Change records loudly + carries the justification.
    const em = await doFetch("/change-control/enforce", { ...ownerCaller(OWNER), change: { number: null, emergency: true, reason: "prod outage, repointing now" } }, { actionKind: "dest-remove" });
    ok("B: an Emergency Change passes (200)", em.status === 200);
    const crEm = (await changeRecorded()).find((t) => t.emergency === true && t.reason === "prod outage, repointing now");
    ok("B: the emergency CR entry is flagged emergency + carries the reason + a null number", crEm !== undefined && crEm.changeNumber === null);

    // (6) The break-glass token (no attributable caller) is NEVER blocked: recorded as an automatic emergency.
    const tok = await doFetch("/change-control/enforce", null, { actionKind: "dest-remove" });
    ok("B: a break-glass token action is never blocked (200)", tok.status === 200);
    const crTok = (await changeRecorded()).find((t) => t.reason === "performed via the break-glass admin token");
    ok("B: the break-glass action is recorded as an automatic emergency", crTok !== undefined && crTok.emergency === true && crTok.changeNumber === null);

    // (7) The COMPLIANCE FLAG: the emergency-change-review posture check is now failing (2 emergencies on record).
    // Read BEFORE any destination is configured so the posture WORM probe has nothing to fetch (the harness shim
    // rejects unexpected network calls).
    const posture = (await (await call(OWNER, "GET", "/admin/reports/posture")).json()) as { data?: { checks?: Array<{ id: string; status: string; severity: string }> } };
    const ecCheck = posture.data?.checks?.find((c) => c.id === "emergency-change-review");
    ok("B: the emergency-change-review posture check is present, medium, and FAILING", ecCheck !== undefined && ecCheck.status === "fail" && ecCheck.severity === "medium");

    // (8) The REAL owner-action chokepoint (gatedOwnerAction): a dest-put is refused without a reference, and
    // proceeds with one. dest-put runs inline here (one owner, dual control off), so enforceChangeControl is the
    // gate that blocks it.
    const destNoRef = await doFetch("/destinations", ownerCaller(OWNER), { label: "cm-test", config: destConfig("cm-bucket") });
    ok("B: a real owner action (dest-put) is refused without a change reference (400)", destNoRef.status === 400);
    ok("B: the refused dest-put did NOT add the destination", !(await listDestinations()).destinations.some((d) => d.label === "cm-test"));
    const destWith = await doFetch("/destinations", { ...ownerCaller(OWNER), change: { number: "CHG-200", emergency: false, reason: null } }, { label: "cm-test", config: destConfig("cm-bucket") });
    ok("B: dest-put proceeds with a change reference (200)", destWith.status === 200);
    ok("B: the dest-put added the destination", (await listDestinations()).destinations.some((d) => d.label === "cm-test"));
    const crDest = (await changeRecorded()).find((t) => t.changeNumber === "CHG-200");
    ok("B: the dest-put recorded a change-recorded CR for dest-put", crDest !== undefined && crDest.actionKind === "dest-put");

    // (8b) checkOwnerActionGate (the ROUTER-EXECUTED gate) must honour the SAME isChangeControlledOwnerAction
    // exemption gatedOwnerAction (scheduler-do-dual-control.ts:34) already applies -- sources-attach,
    // update-apply and update-settle are ROUTER-EXECUTED, so gatedOwnerAction is never their path;
    // checkOwnerActionGate is, at BOTH its enforceChangeControl call sites (the gate-OFF inline branch and the
    // gate-ON first-call/pending branch). Drive the DO route directly (the gate sits ahead of the router's
    // manifest/probe plumbing either way, so this proves the chokepoint without a real signed release).
    await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    const exemptRouterExecuted: readonly string[] = ["sources-attach", "update-apply", "update-settle"];
    for (const kind of exemptRouterExecuted) {
      const r = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind, params: {}, summary: "cm-test" });
      ok(`B: exempt ${kind} is not refused at the gate-OFF site without a change reference (200, gate off)`, r.status === 200 && ((await r.json()) as { gate?: string }).gate === "off");
    }
    ok("B: none of the exempt gate-OFF calls above recorded a change-recorded CR", !(await changeRecorded()).some((t) => exemptRouterExecuted.includes(t.actionKind)));
    // Negative control: support-credential-mint is ROUTER-EXECUTED but NOT exempt, so the SAME site must still
    // refuse it -- proving the fix targets the exemption, not a blanket bypass of the gate.
    const mintNoRef = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "support-credential-mint", params: {}, summary: "cm-test" });
    ok("B: the non-exempt support-credential-mint is still refused at the gate-OFF site (400)", mintNoRef.status === 400);

    // Arm dual control (immediate; arming never needs a second owner) to reach the OTHER call site: the
    // gate-ON first-call/pending branch.
    await setGate(OWNER, true);
    const pendingIds: string[] = [];
    for (const kind of exemptRouterExecuted) {
      const r = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind, params: {}, summary: "cm-test" });
      const body = (await r.json()) as { gate?: string; id?: string };
      ok(`B: exempt ${kind} is not refused at the gate-ON first-call site without a change reference (200, recorded pending)`, r.status === 200 && body.gate === "pending" && typeof body.id === "string" && body.id.length > 0);
      if (typeof body.id === "string") pendingIds.push(body.id);
    }
    // Clean up: withdraw the 3 pending actions (the proposer may reject their own) and disarm dual control via
    // the second owner, leaving the gate state this test found (OFF) for anything that runs after it.
    for (const id of pendingIds) await doFetch("/owner-actions/reject", ownerCaller(OWNER), { id });
    await setGate(OWNER, false);

    // (8c) BOTH GATES ON TOGETHER: requireConfigApproval and requireChangeNumber are
    // independent toggles with independent call sites, and gatedOwnerAction is the ONE place a
    // change-controlled, non-exempt owner action passes through both: enforceChangeControl runs FIRST
    // (scheduler-do-dual-control.ts:35), then the dual-control queue check runs SECOND
    // (scheduler-do-dual-control.ts:40-48). Nothing before this proof had armed both at once against a
    // kind gated by both (the KNOT test in governance-cross-area-recovery-p1.spec.ts arms both but only
    // drives ConfigChangeKind routes, which proposeConfigMutation never threads through
    // enforceChangeControl at all -- requireChangeNumber has NO effect there; the emergency-branch cell
    // in governance-config-approval-lifecycle-p1.spec.ts:459 explicitly holds requireConfigApproval OFF
    // for the isolate). This proves both directions on the ONE action class where the two genuinely
    // compose: (a) a missing reference is refused BEFORE dual control ever sees the action -- no pending
    // owner-action record is created at all; (b) a valid reference passes change-number, is recorded,
    // THEN queues for dual control instead of applying, and only a SECOND owner's approval makes it take
    // effect -- both requirements satisfied, in the right order, before anything changed.
    const armBoth = await setGate(OWNER, true);
    ok("B(8c): arming requireConfigApproval with a second owner present succeeds (2xx)", armBoth.status >= 200 && armBoth.status < 300);
    const bothPolicy = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval?: boolean; requireChangeNumber?: boolean };
    ok("B(8c): both gates read ON simultaneously", bothPolicy.requireConfigApproval === true && bothPolicy.requireChangeNumber === true);

    const oaCountBeforeBoth = ownerActionKeyCount();
    const crCountBeforeBoth = (await changeRecorded()).length;

    // (a) BLOCKED: both ON, no change reference. Refused by change-number; dual control never gets a look.
    const bothNoRef = await doFetch("/destinations", ownerCaller(OWNER), { label: "cm-both-noref", config: destConfig("cm-both-bucket-1") });
    ok("B(8c): both ON + no reference -> refused (400)", bothNoRef.status === 400);
    ok("B(8c): the refusal names the change-number requirement", /change number/i.test(((await bothNoRef.json()) as { error?: string }).error ?? ""));
    ok("B(8c): the block happens BEFORE dual control -- no pending owner-action record was created", ownerActionKeyCount() === oaCountBeforeBoth);
    ok("B(8c): no change-recorded CR entry for the blocked attempt", (await changeRecorded()).length === crCountBeforeBoth);
    ok("B(8c): the blocked destination was NOT added", !(await listDestinations()).destinations.some((d) => d.label === "cm-both-noref"));

    // (b) PROCEEDS: both ON, a valid reference. Passes change-number (recorded), then queues for dual
    // control (not applied) instead of the change-number-only case (8) where it applied inline.
    const bothWithRef = await doFetch("/destinations", { ...ownerCaller(OWNER), change: { number: "CHG-BOTH-1", emergency: false, reason: null } }, { label: "cm-both-ok", config: destConfig("cm-both-bucket-2") });
    ok("B(8c): both ON + a valid reference -> queued (202), NOT applied inline", bothWithRef.status === 202);
    const bothBody = (await bothWithRef.json()) as { ownerActionQueued?: boolean; id?: string };
    ok("B(8c): the response is the owner-action-queued shape", bothBody.ownerActionQueued === true && typeof bothBody.id === "string" && bothBody.id.length > 0);
    ok("B(8c): the CR was recorded even though the action only queued", (await changeRecorded()).some((t) => t.changeNumber === "CHG-BOTH-1" && t.actionKind === "dest-put"));
    ok("B(8c): the queued destination is NOT yet added (dual control still pending)", !(await listDestinations()).destinations.some((d) => d.label === "cm-both-ok"));
    ok("B(8c): a pending owner-action record now exists", ownerActionKeyCount() === oaCountBeforeBoth + 1);

    // The SECOND owner (maker != checker) approves; only now does the doubly-gated action apply.
    const bothId = typeof bothBody.id === "string" ? bothBody.id : "";
    const approveBoth = await call(OWNER2, "POST", `/admin/owner-actions/${encodeURIComponent(bothId)}/approve`);
    ok("B(8c): a distinct second owner's approval succeeds (2xx)", approveBoth.status >= 200 && approveBoth.status < 300);
    ok("B(8c): the destination now exists -- both gates satisfied, in order, before anything applied", (await listDestinations()).destinations.some((d) => d.label === "cm-both-ok"));

    // Leave the state this block found (requireConfigApproval OFF, requireChangeNumber ON) for (9) below.
    await setGate(OWNER, false);

    // (9) The change-requests report lists the CR ledger (the user-facing deliverable).
    const report = (await (await call(OWNER, "GET", "/admin/reports/change-requests")).json()) as { kind?: string; data?: { total: number; emergencyTotal: number; entries: Array<{ actionKind: string; emergency: boolean; changeNumber: string | null }> } };
    ok("B: the change-requests report is the right kind", report.kind === "change-requests");
    ok("B: the report lists every CR entry incl. both emergencies", (report.data?.total ?? 0) >= 4 && (report.data?.emergencyTotal ?? 0) >= 2);
    ok("B: the report carries the change number an auditor reads", (report.data?.entries ?? []).some((e) => e.changeNumber === "CHG-100"));

    // (10) STRUCTURAL WIRING (the remaining kinds): dest-put proved the ORDERING at the ONE
    // shared chokepoint (gatedOwnerAction). That logic is not per-kind -- it is one `if` in one function -- so
    // re-running the full propose/queue/approve journey for every other change-controlled kind would re-prove
    // ordering the chokepoint already guarantees by construction. What the chokepoint does NOT guarantee is
    // that a given kind's own call site (scattered across scheduler-do-routing*.ts) actually reaches it with
    // ITS OWN literal kind string rather than a sibling's -- a copy-paste/typo defect that is easy to introduce
    // at one call site while missing a sibling. That is a WIRING question, not a
    // BEHAVIOURAL one, so it gets a wiring-grade proof: drive each kind's real route directly (empty params;
    // every route here parses its body loosely and never throws before reaching gatedOwnerAction, so the
    // proof needs no business-valid setup) and check (a) it is refused without a reference by ITS OWN
    // enforceChangeControl call, and (b) with a reference carrying a kind-UNIQUE change number, the
    // change-recorded CR this exact call produces names ITS OWN kind, not a neighbour's. (b) is the one that
    // actually catches a kind-string swap: enforceChangeControl commits the CR before execute() ever runs, so
    // it holds regardless of whether the minimal params satisfy the op's own business validation, and a
    // mis-wired call site would record the WRONG kind under this call's unique change number. requireChangeNumber
    // is already ON here (left that way after (8c)); dest-put itself is proved above and not repeated.
    const doExecutedRemaining: ReadonlyArray<{ kind: string; path: string }> = [
      { kind: "dest-set", path: "/dest-config" },
      { kind: "dest-remove", path: "/destinations/remove" },
      { kind: "dest-default", path: "/destinations/default" },
      { kind: "push-dest-set", path: "/push" },
      { kind: "otlp-push-dest-set", path: "/otlp-push" },
      { kind: "idp-conn-create", path: "/idp/conn/create" },
      { kind: "idp-conn-delete", path: "/idp/conn/delete" },
      { kind: "idp-conn-enabled", path: "/idp/conn/enabled" },
      { kind: "idp-conn-cert", path: "/idp/conn/cert" },
      { kind: "break-glass-retire", path: "/policy/break-glass-retired" },
      { kind: "discovery-token-set", path: "/sources/discovery-token" },
      { kind: "discovery-accounts-set", path: "/sources/discovery-accounts" },
    ];
    for (const { kind, path } of doExecutedRemaining) {
      const noRef = await doFetch(path, ownerCaller(OWNER), {});
      ok(`B(10) [${kind}]: refused without a change reference at its own call site (400)`, noRef.status === 400);
      const noRefBody = (await noRef.json()) as { error?: string };
      ok(`B(10) [${kind}]: the refusal names the change-number requirement`, /change number/i.test(noRefBody.error ?? ""));

      const uniqueNumber = `CHG-WIRE-${kind}`;
      await doFetch(path, { ...ownerCaller(OWNER), change: { number: uniqueNumber, emergency: false, reason: null } }, {});
      const recorded = (await changeRecorded()).find((t) => t.changeNumber === uniqueNumber);
      ok(`B(10) [${kind}]: its own call site recorded the CR under ITS OWN kind, not a sibling's`, recorded !== undefined && recorded.actionKind === kind);
    }

    // (11) support-credential-mint, BOTH GATES ON: the one change-controlled kind that is
    // ROUTER-EXECUTED, so it never passes through gatedOwnerAction at all -- its chokepoint is
    // checkOwnerActionGate (scheduler-do-dual-control.ts ~537-590), a DIFFERENT function with its OWN two
    // enforceChangeControl call sites (the gate-off inline branch and the gate-on first-call/pending branch),
    // and its propose/approve/RE-SUBMIT/consume shape is genuinely different from every DO-executed kind
    // above (the mint itself runs in the router, on the re-submit, once an armed approval is consumed). (8b)
    // proved the gate-off site refuses it without a reference as a negative control; that full propose ->
    // approve -> re-submit -> consume journey has never been driven with requireChangeNumber ALSO on, so this
    // is genuine behavioural coverage, not a repeat of the structural loop above.
    await setGate(OWNER, true);
    const mintNoRefBoth = await call(OWNER, "POST", "/admin/support/credentials", { scope: "diagnostics" });
    ok("B(11) [support-credential-mint]: both gates ON, no reference -> refused before dual control ever sees it (400)", mintNoRefBoth.status === 400);
    ok("B(11) [support-credential-mint]: the refusal names the change-number requirement", /change number/i.test(((await mintNoRefBoth.json()) as { error?: string }).error ?? ""));
    const oaCountBeforeMint = ownerActionKeyCount();
    ok("B(11) [support-credential-mint]: the blocked propose recorded no pending owner action", ownerActionKeyCount() === oaCountBeforeMint);

    const mintRef: { number: string; emergency: boolean; reason: null } = { number: "CHG-MINT-1", emergency: false, reason: null };
    const mintProposal = await call(OWNER, "POST", "/admin/support/credentials", { scope: "diagnostics", ttlSeconds: 3600 }, mintRef);
    ok("B(11) [support-credential-mint]: both gates ON, a valid reference -> queued (202), not minted", mintProposal.status === 202);
    const mintPb = (await mintProposal.json()) as { ownerActionQueued?: boolean; id?: string; status?: string };
    ok("B(11) [support-credential-mint]: the response is the owner-action-queued shape", mintPb.ownerActionQueued === true && typeof mintPb.id === "string" && mintPb.id.length > 0);
    const mintCr = (await changeRecorded()).find((t) => t.changeNumber === "CHG-MINT-1");
    ok("B(11) [support-credential-mint]: the CR was recorded (under its own kind) even though the action only queued", mintCr !== undefined && mintCr.actionKind === "support-credential-mint");
    ok("B(11) [support-credential-mint]: a pending owner-action record now exists", ownerActionKeyCount() === oaCountBeforeMint + 1);

    const mintId = typeof mintPb.id === "string" ? mintPb.id : "";
    const mintApprove = await call(OWNER2, "POST", `/admin/owner-actions/${encodeURIComponent(mintId)}/approve`);
    ok("B(11) [support-credential-mint]: a distinct second owner's approval arms it (2xx)", mintApprove.status >= 200 && mintApprove.status < 300);

    // Re-submit: the ARMED branch of checkOwnerActionGate never calls enforceChangeControl again (a re-submit
    // need not carry a reference -- the CR was already raised at initiation), so this succeeds with NO change
    // header even though requireChangeNumber is still ON, and the mint runs exactly once.
    const mintResubmit = await call(OWNER, "POST", "/admin/support/credentials", { scope: "diagnostics", ttlSeconds: 3600 });
    ok("B(11) [support-credential-mint]: re-submit (armed -> consume), no reference needed -> mints (200)", mintResubmit.status === 200);
    const mintBody = (await mintResubmit.json()) as { scope?: string; secret?: string; clientId?: string };
    ok("B(11) [support-credential-mint]: the secret is minted once, on the approved execution", mintBody.scope === "diagnostics" && (mintBody.secret ?? "").startsWith("dps_") && (mintBody.clientId ?? "").startsWith("dpc_"));
    ok("B(11) [support-credential-mint]: no second CR was recorded for the re-submit", (await changeRecorded()).filter((t) => t.actionKind === "support-credential-mint").length === 1);

    // Leave the state this block found (requireConfigApproval OFF) for anything after.
    await setGate(OWNER, false);

    // (12) THE TWO PUSH CLEARS, which are change-controlled WITHOUT being owner actions. POST /push/delete and
    // POST /otlp-push/delete are owner-exclusive but deliberately NOT dual-control gated (closing an egress is
    // the safe direction), so they are not OwnerActionKinds and gatedOwnerAction -- the only caller of
    // enforceChangeControl for the config surface -- was never on their path. The console has always prompted
    // the operator for a change reference before both, so the reference was collected and discarded: the
    // operator supplied a change number and NOTHING was recorded anywhere, which is worse than never asking.
    // Their DO routes now call the SAME chokepoint directly, so the proof is the full pair on each: refused
    // without a reference WITH THE DESTINATION STILL STANDING (the refusal has to stop the clear, not merely
    // fail to record it), and recorded under its OWN kind with one. requireChangeNumber is still ON here and
    // requireConfigApproval is OFF, but both push kinds are HIGH_BLAST_ALWAYS_GATED and a second owner exists
    // by now, so the SEEDING set auto-queues and needs OWNER2's approval to land; that is the seed, not the
    // proof.
    const seedRef = { number: "CHG-CLEAR-SEED", emergency: false, reason: null };
    const seedOwnerOp = async (path: string, body: unknown): Promise<void> => {
      const r = await doFetch(path, { ...ownerCaller(OWNER), change: seedRef }, body);
      if (r.status === 202) await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: ((await r.json()) as { id?: string }).id ?? "" });
    };
    const pushPresent = async (path: string): Promise<boolean> => ((await (await doFetch(path, ownerCaller(OWNER), undefined, "GET")).json()) as { present?: boolean }).present === true;

    const clearCases: ReadonlyArray<{ kind: string; view: string; clear: string; seed: unknown; label: string }> = [
      {
        kind: "push-clear",
        view: "/push",
        clear: "/push/delete",
        label: "SIEM push",
        seed: { format: "ndjson", sink: "http", enabled: true, endpoint: "https://siem.example.com/ingest", authHeaderName: "Authorization", authHeaderValue: "seed-secret-value" },
      },
      {
        kind: "otlp-clear",
        view: "/otlp-push",
        clear: "/otlp-push/delete",
        label: "OTLP metrics push",
        seed: { enabled: true, endpoint: "https://collector.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "seed-secret-value" },
      },
    ];
    for (const c of clearCases) {
      await seedOwnerOp(c.view, c.seed);
      ok(`B(12) [${c.kind}]: the ${c.label} destination is configured (the state a clear must actually destroy)`, await pushPresent(c.view));

      const noRefClear = await doFetch(c.clear, ownerCaller(OWNER), {});
      ok(`B(12) [${c.kind}]: refused without a change reference (400)`, noRefClear.status === 400);
      ok(`B(12) [${c.kind}]: the refusal names the change-number requirement`, /change number/i.test(((await noRefClear.json()) as { error?: string }).error ?? ""));
      ok(`B(12) [${c.kind}]: the refusal STOPPED the clear -- the destination still stands`, await pushPresent(c.view));
      ok(`B(12) [${c.kind}]: a refused clear records no CR`, !(await changeRecorded()).some((t) => t.actionKind === c.kind));

      const uniqueNumber = `CHG-CLEAR-${c.kind}`;
      const withRefClear = await doFetch(c.clear, { ...ownerCaller(OWNER), change: { number: uniqueNumber, emergency: false, reason: null } }, {});
      ok(`B(12) [${c.kind}]: proceeds with a change reference (200)`, withRefClear.status === 200);
      ok(`B(12) [${c.kind}]: the destination is gone -- the clear really ran`, !(await pushPresent(c.view)));
      const clearCr = (await changeRecorded()).find((t) => t.changeNumber === uniqueNumber);
      ok(`B(12) [${c.kind}]: the CR is recorded under ITS OWN kind, not a sibling's`, clearCr !== undefined && clearCr.actionKind === c.kind && clearCr.emergency === false);
    }

    // (13) AN OVER-LENGTH CHANGE NUMBER IS REFUSED AT THE WIRE, driven through the router's own
    // X-Downpipes-Change header rather than through the DO shortcut, because the header is where the raw
    // operator value exists and where the refusal has to live: by the time a reference reaches the policy
    // gate it has already been normalised and cannot say what it used to be.
    //
    // A change number that is merely trimmed to the cap would still look like a change number, would be
    // stored without complaint, and would match nothing in the customer's change-management system, which is
    // the one job the field has. The JUSTIFICATION is deliberately still truncated and asserted so below:
    // prose degrades gracefully and its cut is visible to the reader, an identifier's is not.
    const crsBeforeLen = (await changeRecorded()).length;
    const overNumber = "C".repeat(200);
    const overResp = await call(OWNER, "POST", "/admin/otlp-push/delete", undefined, { number: overNumber, emergency: false, reason: null });
    ok("B(13): an over-length change number is REFUSED at the wire (400)", overResp.status === 400);
    ok("B(13): the refusal names the bound and the remedy, verbatim", ((await overResp.json()) as { error?: string }).error === CHANGE_NUMBER_TOO_LONG);
    ok("B(13): the refused request recorded NO CR", (await changeRecorded()).length === crsBeforeLen);
    ok("B(13): no 64-character truncation of the refused value reached the ledger", !(await changeRecorded()).some((t) => t.changeNumber === "C".repeat(CHANGE_NUMBER_MAX)));

    // NO OVER-REFUSAL. Every legal value must still be accepted, including one at exactly the cap and one
    // whose padding would make its RAW length exceed it. Without these the refusal above is unfalsifiable:
    // a rule that refuses everything passes the refusal check and breaks every customer.
    const legalCases: ReadonlyArray<{ sent: string; stored: string; why: string }> = [
      { sent: "A".repeat(CHANGE_NUMBER_MAX), stored: "A".repeat(CHANGE_NUMBER_MAX), why: "exactly the cap" },
      { sent: `   ${"D".repeat(CHANGE_NUMBER_MAX)}   `, stored: "D".repeat(CHANGE_NUMBER_MAX), why: "at the cap, padded with whitespace" },
      { sent: `${"E".repeat(CHANGE_NUMBER_MAX)}\r\n`, stored: "E".repeat(CHANGE_NUMBER_MAX), why: "at the cap, carrying a stray CR/LF from a paste" },
    ];
    for (const lc of legalCases) {
      const r = await call(OWNER, "POST", "/admin/otlp-push/delete", undefined, { number: lc.sent, emergency: false, reason: null });
      ok(`B(13): a legal number ${lc.why} is ACCEPTED (200)`, r.status === 200);
      ok(`B(13): a legal number ${lc.why} is stored WHOLE, not shortened`, (await changeRecorded()).some((t) => t.changeNumber === lc.stored));
    }

    // The justification is UNCHANGED, and that is a decision rather than an omission.
    const longJustification = "R".repeat(2000);
    const emLong = await call(OWNER, "POST", "/admin/otlp-push/delete", undefined, { number: null, emergency: true, reason: longJustification });
    ok("B(13): an over-length JUSTIFICATION is still accepted (200): prose degrades gracefully", emLong.status === 200);
    const storedJustification = (await changeRecorded()).find((t) => t.emergency === true && typeof t.reason === "string" && (t.reason as string).startsWith("RR"))?.reason ?? null;
    ok(`B(13): the justification still truncates to ${CHANGE_REASON_MAX}`, storedJustification !== null && storedJustification.length === CHANGE_REASON_MAX);
  } finally {
    // Restore the global fetch the harness replaced, so a later validator in the same process is unaffected.
    globalThis.fetch = ctx.realFetch;
  }
}

async function main(): Promise<void> {
  console.log("CHANGE MANAGEMENT (Require Change Number) VECTORS");
  partA();
  await partB();
  const failures = failureCount();
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`\nFAIL: ${failures} change-management assertion(s) failed`);
    process.exit(1);
  }
  console.log("\nCHANGE MANAGEMENT VECTORS PASS");
}

await main();
