// PROOF 3 / 4 / 5 for the D4 audit validator (split out of validate-audit.ts, finding
// engine-test-001-01): the restore-apply event records the maker and binds the plan hash; maker and
// checker are both recorded (maker != checker) including the subject axis and backward-compatible
// hashing across the subject-keying upgrade; the intent markers (the only console audit WRITE).

import { auditHash, type AuditEvent, type AuditDraft } from "../src/admin/audit.ts";
import type { Ctx } from "./validate-audit-harness.ts";
import { OWNER, OPERATOR, APPROVER } from "./validate-audit-harness.ts";

export async function runRecords(ctx: Ctx): Promise<void> {
  const { ok, call, readLog, sched } = ctx;

  // ---- PROOF 3: the restore-apply event records the maker (and carries the plan hash) ------
  {
    // An Approver applies (reaches runRestore; the test engine is not configured, so it answers
    // 200 ok:false in-flow -> a restore-apply 'failed' event with the maker = the approver email
    // and a redaction-safe plan hash). This proves the apply route records, attributes the maker,
    // and binds the plan hash.
    await call(APPROVER, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", target: { binding: "KV_dest" }, confirm: true });
    const log = await readLog();
    const apply = log.events.find((e) => e.action === "restore-apply" && e.actorEmail === APPROVER);
    ok("restore-apply records the maker (the requesting/applying identity)", apply !== undefined && apply.actorEmail === APPROVER);
    ok("restore-apply target is the redaction-safe restore shape", apply?.target.kind === "restore");
    const rt = apply?.target as { kind: "restore"; planHash: string; redirectBinding: string | null; runId: string };
    ok("restore-apply carries a sha384 plan hash", typeof rt?.planHash === "string" && rt.planHash.startsWith("sha384:"));
    ok("restore-apply records the redirect binding NAME only", rt?.redirectBinding === "KV_dest");
  }

  // ---- PROOF 4: MAKER and CHECKER are both recorded (maker != checker) --------------------
  {
    // Dual control (D2) supplies the checker as target.approverEmail. The router does not yet
    // populate it (D2 is a separate workstream), so prove the AUDIT LOG faithfully RECORDS BOTH
    // distinct identities by appending an apply draft with the maker as the actor and a DIFFERENT
    // approver on the target, straight to the DO append path (the chain authority). This proves
    // the record shape and the storage carry both, and that maker != checker is preserved through
    // the hash chain, which is what the audit requirement asks of the log itself.
    const maker = "maker@acme.example";
    const checker = "checker@acme.example";
    const makerSubject = "https://team.example|sub-maker";
    const checkerSubject = "https://team.example|sub-checker";
    const draft: AuditDraft = {
      actorSubject: makerSubject,
      actorEmail: maker,
      actorMethod: "access",
      sourceIp: "203.0.113.7",
      action: "restore-apply",
      outcome: "success",
      target: { kind: "restore", runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", redirectBinding: null, planHash: "sha384:abc", isLatest: true, reason: "quarterly DR rehearsal", approverEmail: checker, approverSubject: checkerSubject },
    };
    const appended = (await (await sched.stub.fetch("https://scheduler.internal/audit", { method: "POST", body: JSON.stringify(draft), headers: { "content-type": "application/json" } })).json()) as AuditEvent;
    ok("dual-control apply records the maker as the actor (email)", appended.actorEmail === maker);
    ok("dual-control apply records the maker SUBJECT (actorSubject, the authority axis)", appended.actorSubject === makerSubject);
    const t = appended.target as { kind: "restore"; approverEmail?: string; approverSubject?: string; reason?: string };
    ok("dual-control apply records the checker (approverEmail)", t.approverEmail === checker);
    ok("dual-control apply records the checker SUBJECT (target.approverSubject)", t.approverSubject === checkerSubject);
    ok("maker and checker are distinct (maker != checker, email)", appended.actorEmail !== t.approverEmail);
    ok("maker and checker SUBJECTS are distinct (maker != checker, subject)", appended.actorSubject !== t.approverSubject);
    ok("the free-text reason is recorded (not a secret)", t.reason === "quarterly DR rehearsal");
    ok("the source IP is recorded", appended.sourceIp === "203.0.113.7");
    // The recorded subject is folded into the entry HASH (tamper-evidence covers it): recomputing the hash
    // reproduces the stored value, and flipping the actorSubject breaks recomputation.
    ok("the entry hash commits to actorSubject (recompute matches)", (await auditHash(appended)) === appended.hash);
    ok("tampering actorSubject breaks the entry hash", (await auditHash({ ...appended, actorSubject: "https://team.example|sub-evil" })) !== appended.hash);

    // BACKWARD-COMPATIBLE HASH: a LEGACY entry recorded before subject-keying has NO actorSubject key, and
    // a new entry with no caller subject carries actorSubject:null. auditHash folds the field in ONLY when
    // it is a STRING, so BOTH the legacy (absent) and the null shapes hash IDENTICALLY to the pre-upgrade
    // digest. This is what keeps the chain verifiable across the upgrade: an old entry's stored hash still
    // recomputes, and a new null-subject entry links to it cleanly.
    const legacyShaped = { seq: 9, ts: "2026-06-07T00:00:00.000Z", actorEmail: "x@acme.example", actorMethod: "access" as const, sourceIp: null, action: "role-change" as const, outcome: "success" as const, target: { kind: "role" as const, email: "x@acme.example", role: "viewer" as const }, prevHash: "sha384:" + "0".repeat(96), hash: "" };
    const hashNoKey = await auditHash(legacyShaped as unknown as AuditEvent); // actorSubject absent
    const hashNull = await auditHash({ ...legacyShaped, actorSubject: null } as unknown as AuditEvent); // actorSubject null
    ok("a legacy entry (no actorSubject) and a null-subject entry hash IDENTICALLY (chain survives upgrade)", hashNoKey === hashNull);
    const hashWithSubject = await auditHash({ ...legacyShaped, actorSubject: "https://team.example|sub-x" } as unknown as AuditEvent);
    ok("adding a string actorSubject DOES change the hash (the field is committed when present)", hashWithSubject !== hashNoKey);

    // BACKWARD-COMPATIBLE ADVISORY (V6.8.4): auditHash folds the OPTIONAL acr/amr/auth_time signal in ONLY
    // when present, exactly like actorSubject. An event without it (every non-sign-in entry, every pre-upgrade
    // entry) hashes byte-for-byte as before; an idp-sign-in that carries it commits to it (tamper-evident).
    const hashAdvisoryUndef = await auditHash({ ...legacyShaped, advisory: undefined } as unknown as AuditEvent);
    ok("advisory:undefined hashes IDENTICALLY to advisory-absent (folded only when present, chain survives upgrade)", hashAdvisoryUndef === hashNoKey);
    const withAdvisory = { ...legacyShaped, advisory: { acr: "urn:x:mfa", amr: ["pwd", "otp"], authTime: 1_700_000_000 } };
    const hashWithAdvisory = await auditHash(withAdvisory as unknown as AuditEvent);
    ok("adding an advisory DOES change the hash (committed when present)", hashWithAdvisory !== hashNoKey);
    ok("the advisory-bearing hash recomputes (tamper-evident)", (await auditHash(withAdvisory as unknown as AuditEvent)) === hashWithAdvisory);
    ok("tampering the advisory acr breaks recomputation", (await auditHash({ ...withAdvisory, advisory: { ...withAdvisory.advisory, acr: "urn:x:weak" } } as unknown as AuditEvent)) !== hashWithAdvisory);
  }

  // ---- PROOF 5: the intent markers (the only console audit WRITE) -------------------------
  {
    const keyIntent = (await (await call(OWNER, "POST", "/admin/audit/intent", { action: "key-ceremony-intent" })).json()) as AuditEvent;
    const policyIntent = (await (await call(OWNER, "POST", "/admin/audit/intent", { action: "access-policy-change-intent" })).json()) as AuditEvent;
    ok("key-ceremony-intent recorded as an intent event", keyIntent.action === "key-ceremony-intent" && keyIntent.target.kind === "key-ceremony");
    ok("access-policy-change-intent recorded as an intent event", policyIntent.action === "access-policy-change-intent" && policyIntent.target.kind === "access-policy");
    // A non-Owner cannot write an intent marker (Owner-gated); an unknown action is refused 400.
    ok("intent marker is Owner-gated (Operator 403)", (await call(OPERATOR, "POST", "/admin/audit/intent", { action: "key-ceremony-intent" })).status === 403);
    ok("intent marker refuses an unknown action (400)", (await call(OWNER, "POST", "/admin/audit/intent", { action: "totally-made-up" })).status === 400);
  }
}
