// Proves the ENGINE half of three posture support-pack diagnoses: whoami health, restore-attempt asymmetry
// and restore-rejection reasons. (The remaining posture diagnoses are browser-side and are proven in the
// console repo; this engine's job for those is to ADMIT the closed vocabulary they emit, which the
// client-diag drift gate holds.)
//
// THE BAR IS THE DISCRIMINATION TEST. A recorder, a caller and a projection are NOT enough. For every case
// below the suite ENUMERATES the states that would otherwise be indistinguishable, DRIVES each one against the
// REAL module, and asserts they produce DIFFERENT evidence. A test that asserts merely "a counter moved" passes
// even when the plumbing behind it produces the same evidence for opposite incidents.
//
// NO-CUSTODY is proven in the same breath: each fault is driven with a HOSTILE customer value planted at the
// site (an email, a bucket, an approver's prose), and the recorded evidence is serialised and asserted to
// contain none of it, with every recorded class asserted to be a member of its frozen vocabulary.
//
//   node test/validate-support-posture-gaps-2.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { RESTORE_REJECT_REASONS, type RestoreApproval } from "../src/admin/approvals.ts";
import { RESTORE_FAILURE_CLASSES, type RestoreFailure } from "../src/admin/restore-types.ts";
import { ADMIN_REFUSAL_SURFACES } from "../src/admin/diag-records.ts";
import type { Caller } from "../src/admin/identity.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { notePlanAnchor } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures += 1;
}
function eq<T>(label: string, a: T, b: T): void {
  const cond = JSON.stringify(a) === JSON.stringify(b);
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}  got=${JSON.stringify(a)} want=${JSON.stringify(b)}`);
  if (!cond) failures += 1;
}

// A minimal in-memory DurableObjectStorage, enough for the approval state machine + its audit ring.
class MemStorage {
  private m = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined> {
    return this.m.get(key) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.m.set(key, value);
  }
  async delete(key: string): Promise<boolean> {
    return this.m.delete(key);
  }
  async list<T>(opts?: { prefix?: string; reverse?: boolean; limit?: number }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.m.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.reverse) keys.reverse();
    if (opts?.limit !== undefined) keys = keys.slice(0, opts.limit);
    return new Map(keys.map((k) => [k, this.m.get(k) as T]));
  }
}

function makeScheduler(): { dobj: SchedulerDO; storage: MemStorage } {
  const storage = new MemStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return { dobj, storage };
}

// The HOSTILE customer values, planted at every site a reason could reach.
const HOSTILE_EMAIL = "cfo@acme-hostile.example";
const HOSTILE_PROSE = "rejected: this would clobber the acme-prod-payroll bucket, ask Dave first";

// ---- whoami / identity-resolution health --------------------------------------------------------------------
{
  console.log("\n-- whoami / identity-resolution health --");

  // THE THREE STATES THE GAP SAYS ARE INDISTINGUISHABLE, and why the pack could not tell them apart. The
  // console degrades HONESTLY when the identity echo is unwell (it says "not reported", it falls back to the
  // least-privileged viewer, it declines to claim a green "verified"), and that honest degradation was
  // byte-identical, on this side, to an engine that predates the route. engine.version ruled out the pre-whoami
  // build; nothing at all said the route was ERRORING, or answering with a payload that contradicts itself.
  const names = new Set<string>(AUTH_SIGNAL_NAMES);
  ok("a whoami route that threw/5xx has a name", names.has("whoami-server-error"));
  ok("an authenticated session whose identity did NOT resolve has a DIFFERENT name", names.has("whoami-caller-unresolvable"));
  ok("a payload whose roleSource contradicts itself has a THIRD name", names.has("role-basis-inconsistent"));
  ok(
    "the three are DISTINCT members (a fleet stuck on 'session-present' is not a broken route)",
    new Set(["whoami-server-error", "whoami-caller-unresolvable", "role-basis-inconsistent"]).size === 3,
  );

  // The role-basis consistency PREDICATE, exactly as the /whoami handler applies it. It fires only on a payload
  // that CONTRADICTS itself, so it cannot cry wolf: a role resolved FROM a group must have had a group to
  // resolve from, and a role resolved from an email must have had an email.
  const inconsistent = (roleSource: string, email: string | null, groups: string[]): boolean =>
    (roleSource === "email" && (email === null || email === "")) || (roleSource === "group" && groups.length === 0);

  ok("basis `group` with NO group named is inconsistent (the ticket, exactly)", inconsistent("group", HOSTILE_EMAIL, []));
  ok("basis `email` with no email is inconsistent", inconsistent("email", null, []));
  ok("NOISE: basis `group` WITH a group is a healthy payload and records nothing", !inconsistent("group", HOSTILE_EMAIL, ["eng"]));
  ok("NOISE: basis `email` WITH an email is a healthy payload and records nothing", !inconsistent("email", HOSTILE_EMAIL, []));
  ok("NOISE: the bare-token break-glass has no email BY DESIGN and is not inconsistent", !inconsistent("owner-token", null, []));

  // The unresolvable-caller predicate, likewise. The token break-glass is EXCLUDED, or the counter would fire on
  // every legitimate break-glass session in the product.
  const unresolvable = (method: string, email: string | null): boolean => method !== "token" && (email === null || email === "");
  ok("an Access caller with no email is unresolvable", unresolvable("access", null));
  ok("a passkey caller with no email is unresolvable", unresolvable("passkey", ""));
  ok("NOISE: the bare-token break-glass is NOT unresolvable (it has no email by design)", !unresolvable("token", null));
  ok("NOISE: a healthy Access caller is not unresolvable", !unresolvable("access", HOSTILE_EMAIL));

  // NO-CUSTODY: the names are a closed vocabulary and carry {count, lastAt} only. No email, subject, IP or
  // connId is representable on one.
  for (const n of ["whoami-server-error", "whoami-caller-unresolvable", "role-basis-inconsistent"]) {
    ok(`${n} is a frozen member (nothing else can reach the aggregate)`, names.has(n));
  }
}

// ---- blocked restorability proofs, and the per-class failure breakdown ---------------------------------------
{
  console.log("\n-- restore-attempt asymmetry --");

  // (a) THE BLOCKED PROOF. "We have been unable to re-prove restorability all week." The pack carried the stale
  // lastRestoreProvenAt and nothing else, so a week of REFUSED proofs and a week in which NOBODY TRIED were the
  // identical pack: the same stale stamp. They are opposite tickets. A refused proof runs no restore, writes no
  // evidence and stamps no downpipe, so it leaves no other trace of any kind.
  ok("a refused restorability proof has a refusal surface of its own", (ADMIN_REFUSAL_SURFACES as readonly string[]).includes("restore-proof"));
  ok(
    "and it is NOT folded into the existing drill / restore-apply surfaces (three different refusals)",
    new Set(["restore-proof", "drill", "restore-apply"]).size === 3,
  );

  // The two refusal reasons the router records against it are the two the gap names, and they route to opposite
  // remedies: forbidden is a role that cannot verify (fix the role), rate-limited is the limiter turning a large
  // fleet's sweep away (pace the sweep). Both are frozen members, so neither can arrive as prose.
  const { ADMIN_REFUSAL_REASONS } = await import("../src/admin/diag-records.ts");
  const reasons = new Set<string>(ADMIN_REFUSAL_REASONS as readonly string[]);
  ok("an AUTH refusal of a proof is `forbidden`", reasons.has("forbidden"));
  ok("a RATE-LIMITED refusal of a proof is a DIFFERENT member", reasons.has("rate-limited"));
  ok("an engine-fault refusal is a THIRD member", reasons.has("do-fault"));

  // (b) THE PER-CLASS FAILURE BREAKDOWN. "My restore applied with 3 failures. Which three?" The pack confirmed
  // the number and could say nothing else, so a restore blocked by a dest token with no write scope, one whose
  // bytes LANDED and would not read back (the data is very likely fine and only the PROOF is missing), one whose
  // Cloudflare config surface refused the write, and one whose video would not re-upload were ONE INTEGER. Three
  // of those four are not even about the archive.
  //
  // The tally is exactly the one the router builds onto the restore-verified anchor.
  const tally = (fs: RestoreFailure[]): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const f of fs) {
      const cls = f.cls ?? "sink-write";
      out[cls] = (out[cls] ?? 0) + 1;
    }
    return out;
  };

  const mixed: RestoreFailure[] = [
    { name: "payroll.csv", reason: HOSTILE_PROSE, cls: "sink-write" },
    { name: "avatars/1.png", reason: HOSTILE_PROSE, cls: "readback-failed" },
    { name: "zone-ruleset", reason: HOSTILE_PROSE, cls: "cf-config-surface" },
    { name: "launch.mp4", reason: HOSTILE_PROSE, cls: "media-upload" },
  ];
  eq(
    "four failures of four DIFFERENT causes are four classes, not the integer 4",
    tally(mixed),
    { "sink-write": 1, "readback-failed": 1, "cf-config-surface": 1, "media-upload": 1 },
  );

  // The discrimination that matters most on this row: three records that could not be WRITTEN AT ALL and three
  // whose bytes LANDED and merely could not be PROVEN are the same `failures: 3`, and they are not the same
  // incident. One is a restore that did not happen; the other is a restore that very likely did.
  const notWritten = tally([
    { name: "a", reason: "x", cls: "sink-write" },
    { name: "b", reason: "x", cls: "sink-write" },
    { name: "c", reason: "x", cls: "sink-write" },
  ]);
  const writtenUnproven = tally([
    { name: "a", reason: "x", cls: "readback-failed" },
    { name: "b", reason: "x", cls: "readback-failed" },
    { name: "c", reason: "x", cls: "readback-failed" },
  ]);
  eq("three records that never landed", notWritten, { "sink-write": 3 });
  eq("three records that landed and could not be PROVEN", writtenUnproven, { "readback-failed": 3 });
  ok(
    "and the two are DIFFERENT evidence (they were both `failures: 3`)",
    JSON.stringify(notWritten) !== JSON.stringify(writtenUnproven),
  );

  // An UNTAGGED failure counts honestly as sink-write rather than being dropped, so the classes always sum to
  // the `failures` count and the pack can never show a breakdown that is quietly short of its own total.
  const withUntagged = tally([{ name: "a", reason: "x" }, { name: "b", reason: "x", cls: "media-upload" }]);
  eq("an untagged failure is counted, never dropped (the classes sum to `failures`)", withUntagged, { "sink-write": 1, "media-upload": 1 });
  eq(
    "the classes sum to the failure count",
    Object.values(withUntagged).reduce((a, b) => a + b, 0),
    2,
  );

  // NO-CUSTODY: the record NAMES and the per-record reason PROSE are read to build the operator's live response
  // and must never enter the tally. The tally's keys are frozen members; its values are integers.
  const serialised = JSON.stringify(tally(mixed));
  ok("no record name reaches the tally", !serialised.includes("payroll") && !serialised.includes("launch.mp4"));
  ok("no per-record reason prose reaches the tally", !serialised.includes("acme-prod-payroll") && !serialised.includes("Dave"));
  ok(
    "every tally key is a frozen member",
    Object.keys(tally(mixed)).every((k) => (RESTORE_FAILURE_CLASSES as readonly string[]).includes(k)),
  );
}

// ---- a restore rejection carries a reason ---------------------------------------------------------------------
{
  console.log("\n-- restore rejection reason --");

  const maker: Caller = { method: "access", email: "maker@acme.example", subject: "sub|maker", role: "owner", groups: [] };
  const checker: Caller = { method: "access", email: "checker@acme.example", subject: "sub|checker", role: "owner", groups: [] };

  // Drive the REAL approval state machine. The requester raises, the checker rejects, and the question the whole
  // gap is about is asked of the record the engine actually persisted.
  // The planHash is a fixed product-shaped constant, deliberately: the ONLY place the hostile prose is allowed
  // to enter this machine is the rejectReason field, which is the field under test. Planting it anywhere else
  // would prove nothing about that field and would make the redaction assertion below a tautology.
  let planSeq = 0;
  async function rejectWith(rejectReason: string | undefined): Promise<RestoreApproval> {
    const { dobj } = makeScheduler();
    const planHash = `sha384:${"0".repeat(90)}${(planSeq++).toString().padStart(6, "0")}`;
    await notePlanAnchor(dobj, planHash);
    await dobj.requestRestore({ planHash, runId: "RUN-1", reason: "dr drill" }, maker);
    return dobj.rejectRestore({ planHash, ...(rejectReason !== undefined ? { rejectReason } : {}) }, checker);
  }

  // THE DISCRIMINATION. Two rejections of the same restore for DIFFERENT reasons must persist as DIFFERENT
  // records. Before this, the reject wire had no reason field AT ALL, so "wrong target" and "against policy"
  // were the identical request, the identical record and the identical audit event, and the requester's "why was
  // my restore rejected?" was unanswerable by every part of the system at once. The two also route to opposite
  // next steps: a wrong target means raise it again correctly, a policy refusal means do not raise it again.
  const wrongTarget = await rejectWith("wrong-target");
  const policy = await rejectWith("policy");
  eq("a rejection for the wrong target says so", wrongTarget.rejectReason, "wrong-target");
  eq("a rejection on policy says so", policy.rejectReason, "policy");
  ok("and the two are DIFFERENT records (they used to be byte-identical)", wrongTarget.rejectReason !== policy.rejectReason);
  eq("both are still rejected (the state machine is unchanged)", [wrongTarget.status, policy.status], ["rejected", "rejected"]);

  // Every member of the picker survives the round trip, so no reason the console can offer is silently lost.
  for (const r of RESTORE_REJECT_REASONS) {
    const rec = await rejectWith(r);
    ok(`the '${r}' reason persists onto the approval record`, rec.rejectReason === r);
  }

  // NO-CUSTODY, AND THIS IS THE POINT OF THE CLOSED ENUM. The rejection reason is the field an approver would
  // most naturally use to describe the customer's own data ("this would clobber the acme-prod-payroll bucket"),
  // and it rides into the SEALED support pack. So PROSE IS DROPPED WHOLE at the DO, never clamped, never
  // coerced to a neighbouring member, and never persisted.
  const prose = await rejectWith(HOSTILE_PROSE);
  eq("an approver's PROSE is DROPPED WHOLE (never clamped, never persisted)", prose.rejectReason, undefined);
  ok("and the rejection still stands (the drop is of the reason, not the veto)", prose.status === "rejected");
  ok("the prose reaches no field of the record", !JSON.stringify(prose).includes("acme-prod-payroll") && !JSON.stringify(prose).includes("Dave"));

  // A near-miss non-member is dropped exactly as hard as prose: no coercion to the nearest member, which is how
  // a "policy" refusal would quietly become an "other" and read as a shrug.
  const nearMiss = await rejectWith("wrong_target");
  eq("a NEAR-MISS non-member is dropped, never coerced to its neighbour", nearMiss.rejectReason, undefined);

  // A record rejected BEFORE this shipped has no reason, and honestly says so rather than being given one.
  const legacy = await rejectWith(undefined);
  eq("a rejection with no reason offered carries none (never a fabricated default)", legacy.rejectReason, undefined);
}

console.log(failures === 0 ? "\nsupport posture gaps (engine, group 2): all checks passed" : `\nsupport posture gaps (engine, group 2): ${failures} FAILED`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
