// PROOF 1 / 1b / 2 / 2b for the D4 audit validator (split out of validate-audit.ts, finding
// engine-test-001-01): first-class events recorded from the routes that perform them; the source IP
// threaded onto commit-point successes; denied attempts recorded; the support ingest credential
// lifecycle audited and DO-re-checked. Drives the shared live DO via the orchestrator's context.

import type { Ctx } from "./validate-audit-harness.ts";
import { OWNER, OPERATOR, VIEWER, CALLER_HEADER, encodeCaller, type Caller } from "./validate-audit-harness.ts";

export async function runEvents(ctx: Ctx): Promise<void> {
  const { ok, call, readLog, sched, subjectOf } = ctx;

  // ---- PROOF 1: first-class events are recorded from the routes that perform them ---------
  {
    // A successful downpipe create (Operator) and delete record success events with the safe
    // downpipe id/name target. A create against the DO validator succeeds (valid config).
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp1", name: "Uploads KV", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } });
    await call(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dp1" });
    const log = await readLog();
    const create = log.events.find((e) => e.action === "downpipe-create" && e.outcome === "success");
    const del = log.events.find((e) => e.action === "downpipe-delete" && e.outcome === "success");
    ok("downpipe-create success recorded", create !== undefined);
    ok("downpipe-create target carries the safe id + name", create?.target.kind === "downpipe" && (create.target as { id: string; name?: string }).id === "dp1" && (create.target as { id: string; name?: string }).name === "Uploads KV");
    ok("downpipe-create attributes the verified actor", create?.actorEmail === OPERATOR && create?.actorMethod === "access");
    // A REAL router-driven write records the actor's STABLE subject (the authority axis) alongside the
    // display email, end to end through handleAdmin -> recordAudit -> the DO append.
    ok("downpipe-create records the actor SUBJECT (iss|sub) end to end", create?.actorSubject === subjectOf(OPERATOR));
    ok("downpipe-delete success recorded", del !== undefined);
    // The role grants above each recorded a role-change success (recorded in the DO at commit).
    const roleChanges = log.events.filter((e) => e.action === "role-change" && e.outcome === "success");
    ok("role-change success events recorded for the grants", roleChanges.length >= 3);
    ok("role-change target carries the member email + role, no secret", roleChanges.every((e) => e.target.kind === "role"));
  }

  // ---- PROOF 1c: a manual run-now (POST /trigger) is recorded with the actor + runId (audit completeness) ----
  {
    // A run-now is a gated, state-mutating privileged action; like create/delete it must leave an audit row
    // naming WHO initiated the off-schedule run. Create a fresh downpipe, trigger it, and prove the
    // run-trigger success event carries the runId (run kind) and the verified actor. A viewer is refused.
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_trig", name: "Trig KV", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } });
    const body = (await (await call(OPERATOR, "POST", "/admin/trigger", { id: "dp_trig" })).json()) as { runId?: string; skipped?: string };
    const log = await readLog();
    const trig = log.events.find((e) => e.action === "run-trigger" && e.outcome === "success");
    ok("run-trigger success recorded for a manual run-now", trig !== undefined);
    ok("run-trigger target carries the runId (run kind), no config or value", trig?.target.kind === "run" && (trig.target as { runId?: string }).runId === body.runId && typeof body.runId === "string");
    ok("run-trigger attributes the verified actor (email + stable subject)", trig?.actorEmail === OPERATOR && trig?.actorSubject === subjectOf(OPERATOR) && trig?.actorMethod === "access");
    const denied = await call(VIEWER, "POST", "/admin/trigger", { id: "dp_trig" });
    ok("a viewer without run.trigger is denied the manual trigger", denied.status >= 400);
  }

  // ---- PROOF 1b: the SOURCE IP is threaded onto a commit-point SUCCESS (not just denials) -----
  {
    // The audit-IP fix: a human-initiated SUCCESS is recorded in the DO at the commit point via the
    // FORWARDED caller (x-downpipe-caller header), which now carries the source IP the router read from
    // the edge CF-Connecting-IP header. Before the fix that draft hardcoded sourceIp:null, so a denied
    // role-change carried an IP but the MATCHING successful role-change did not. Drive a real role grant
    // (a DO-commit success) AND a denied role write (a router-recorded denial) through the production
    // handleAdmin -> caller -> DO path with a mocked CF-Connecting-IP, and prove BOTH carry that exact IP.
    const SUCCESS_IP = "198.51.100.23";
    const DENIED_IP = "198.51.100.99";
    // A successful Owner-driven role grant: recorded at the DO commit point from the forwarded caller.
    await call(OWNER, "POST", "/admin/roles", { email: "ipproof@acme.example", role: "viewer" }, { "CF-Connecting-IP": SUCCESS_IP });
    // A DENIED role write (a non-Owner Operator): recorded at the router gate with the same IP plumbing.
    await call(OPERATOR, "POST", "/admin/roles", { email: VIEWER, role: "owner" }, { "CF-Connecting-IP": DENIED_IP });
    const log = await readLog();
    const grantSuccess = log.events.find(
      (e) => e.action === "role-change" && e.outcome === "success" && e.target.kind === "role" && (e.target as { email: string }).email === "ipproof@acme.example",
    );
    ok("a router-driven role grant records a SUCCESS at the DO commit point", grantSuccess !== undefined);
    // THE FIX: the commit-point success carries the NON-NULL source IP the router read, end to end through
    // resolveCaller -> caller.sourceIp -> encodeCaller -> the DO's decodeCaller -> appendAudit (was null).
    ok("the commit-point SUCCESS carries the NON-NULL source IP (the fix)", grantSuccess?.sourceIp === SUCCESS_IP);
    const deniedWithIp = log.events.find(
      (e) => e.action === "role-change" && e.outcome === "denied" && e.actorEmail === OPERATOR && e.sourceIp === DENIED_IP,
    );
    ok("a denied role-change still carries its source IP (router path unchanged)", deniedWithIp !== undefined);
    // Negative control: the IP is the edge header's value, not some constant; the success and denial carry
    // their OWN distinct IPs, proving the value is genuinely threaded per request rather than hardcoded.
    ok("the success and denial carry their OWN distinct IPs (genuinely per-request)", grantSuccess?.sourceIp !== deniedWithIp?.sourceIp);
    // SECURITY: a CLIENT-SUPPLIED x-downpipe-caller carrying a forged sourceIp must NOT reach the trail.
    // the router overwrites the header from the verified verdict and the edge IP it read. Send a request
    // with both a forged caller header (claiming a bogus IP) and a real edge IP; the recorded IP must be
    // the EDGE one, never the forged caller-header value (the inbound-overwrite property).
    // Typed as string (not literals) so `sourceIp === EDGE_IP && sourceIp !== FORGED_IP` stays a genuine
    // runtime check: with literal types TypeScript narrows sourceIp and flags the !== as statically-known (TS2367).
    const FORGED_IP: string = "10.10.10.10";
    const EDGE_IP: string = "198.51.100.77";
    const forgedCaller: Caller = { method: "access", email: OWNER, subject: subjectOf(OWNER), role: "owner", groups: [], sourceIp: FORGED_IP };
    await call(
      OWNER,
      "POST",
      "/admin/roles",
      { email: "ipforge@acme.example", role: "viewer" },
      { "CF-Connecting-IP": EDGE_IP, [CALLER_HEADER]: encodeCaller(forgedCaller) },
    );
    const forgeLog = await readLog();
    const forgeEvent = forgeLog.events.find(
      (e) => e.action === "role-change" && e.outcome === "success" && e.target.kind === "role" && (e.target as { email: string }).email === "ipforge@acme.example",
    );
    ok("a forged caller-header source IP does NOT reach the trail (inbound-overwrite holds)", forgeEvent !== undefined && forgeEvent.sourceIp === EDGE_IP && forgeEvent.sourceIp !== FORGED_IP);
  }

  // ---- PROOF 2: denied attempts are recorded ---------------------------------------------
  {
    // A Viewer is refused a downpipe create (403) -> a denied downpipe-create event. An Operator
    // is refused a restore apply (403, the F1 rule) -> a denied restore-apply event. A non-Owner
    // is refused a role write (403) -> a denied role-change event.
    await call(VIEWER, "POST", "/admin/downpipes", { id: "dpX", name: "x", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] } });
    await call(OPERATOR, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    await call(OPERATOR, "POST", "/admin/roles", { email: VIEWER, role: "owner" });
    const log = await readLog();
    ok("denied downpipe-create recorded (Viewer)", log.events.some((e) => e.action === "downpipe-create" && e.outcome === "denied" && e.actorEmail === VIEWER));
    ok("denied restore-apply recorded (Operator, the F1 rule)", log.events.some((e) => e.action === "restore-apply" && e.outcome === "denied" && e.actorEmail === OPERATOR));
    ok("denied role-change recorded (non-Owner)", log.events.some((e) => e.action === "role-change" && e.outcome === "denied" && e.actorEmail === OPERATOR));
  }

  // ---- PROOF 2b: the support ingest credential lifecycle is audited and DO-re-checked ------
  // ENG-SUP-AUDIT-1 / NC-3: minting/revoking a vendor-readable pull credential is an owner-class
  // custody action and must be first-class in the trail (success at the DO commit point, denied
  // at the router gate), with the secret unrepresentable in the closed target.
  {
    const deniedMint = await call(OPERATOR, "POST", "/admin/support/credentials", { scope: "diagnostics" });
    ok("a non-Owner credential mint is refused (403)", deniedMint.status === 403);
    const mintResp = await call(OWNER, "POST", "/admin/support/credentials", { scope: "diagnostics" });
    ok("an Owner credential mint succeeds", mintResp.status === 200);
    const minted = (await mintResp.json()) as { clientId: string; secret: string; expiresAt: string };
    const revokeResp = await call(OWNER, "POST", "/admin/support/credentials/delete", { scope: "diagnostics" });
    ok("an Owner credential revoke succeeds", revokeResp.status === 200);
    // A second revoke of the now-absent credential is a no-op and must record nothing (the
    // role-delete idempotent-offboarding discipline).
    await call(OWNER, "POST", "/admin/support/credentials/delete", { scope: "diagnostics" });
    const log = await readLog();
    const grantDenied = log.events.find((e) => e.action === "support-credential-grant" && e.outcome === "denied");
    const grantOk = log.events.find((e) => e.action === "support-credential-grant" && e.outcome === "success");
    const revokes = log.events.filter((e) => e.action === "support-credential-revoke" && e.outcome === "success");
    ok("denied support-credential-grant recorded (non-Owner attempt)", grantDenied !== undefined && grantDenied.actorEmail === OPERATOR && grantDenied.target.kind === "supportcredential");
    ok("support-credential-grant success recorded at the DO commit point, attributed to the Owner", grantOk !== undefined && grantOk.actorEmail === OWNER && grantOk.actorSubject === subjectOf(OWNER));
    const grantTarget = grantOk?.target as { kind: string; scope?: string; clientId?: string; expiresAt?: string } | undefined;
    ok("the grant target carries scope + PUBLIC clientId + expiry, nothing else", grantTarget?.kind === "supportcredential" && grantTarget.scope === "diagnostics" && grantTarget.clientId === minted.clientId && grantTarget.expiresAt === minted.expiresAt);
    ok("exactly one revoke recorded (the no-op second revoke records nothing)", revokes.length === 1 && (revokes[0]!.target as { clientId?: string }).clientId === minted.clientId);
    ok("the credential SECRET never reaches the audit log", !JSON.stringify(log.events).includes(minted.secret));

    // ENG-SUP-DO-1: the DO re-checks owner at the commit point from the FORWARDED caller (defence
    // in depth behind the router gate). A direct /ingest-credential/set whose caller RESOLVES to
    // viewer (re-resolved from the DO's own tables, never the asserted role) is an authorisation
    // refusal -> 403 (037-03) and stores nothing, even though the asserted role claims owner.
    const forgedViewer: Caller = { method: "access", email: VIEWER, subject: subjectOf(VIEWER), role: "owner", groups: [] };
    const evilSet = await sched.stub.fetch("https://do/ingest-credential/set", {
      method: "POST",
      body: JSON.stringify({ scope: "audit-feed", grant: { clientId: "dpc_forged", secretSha384: "x", scope: "audit-feed", grantedAt: "2026-06-10T00:00:00.000Z", expiresAt: "2027-06-10T00:00:00.000Z", grantedBy: null, pulls: [] } }),
      headers: { [CALLER_HEADER]: encodeCaller(forgedViewer) },
    });
    ok("the DO refuses a set whose caller resolves below owner (asserted role ignored)", evilSet.status === 403);
    const afterEvil = (await (await sched.stub.fetch("https://do/ingest-credential?scope=audit-feed")).json()) as { grant: unknown };
    ok("the refused set stored nothing", afterEvil.grant === null);
    const evilClear = await sched.stub.fetch("https://do/ingest-credential/clear", {
      method: "POST",
      body: JSON.stringify({ scope: "diagnostics" }),
      headers: { [CALLER_HEADER]: encodeCaller(forgedViewer) },
    });
    ok("the DO refuses a clear whose caller resolves below owner", evilClear.status === 403);
  }
}
