// router-restore.ts -- the restore dry-run / apply path and the dual-control request -> approve/reject ->
// apply machinery plus the BLIND restore test and KEYLESS attestation. The F1 role gate, the maker !=
// checker dual-control gate and every status code run inline per route.

import { b64urlDecode } from "../crypto/bytes.ts";
import type { RunCapsule } from "../format/reader.ts";
import { isValidRunId } from "../format/ulid.ts";
import { log } from "../log.ts";
import { routeEngineNotification } from "../notify.ts";
import { classifyRestoreFailure } from "../restore-reasons.ts";
import type { SourceSpec } from "../sched/types.ts";
import { selectorPrefixFault } from "../sources/selector.ts";
import { RESTORE_APPLY_LEASE_MS, RESTORE_REJECT_REASON_SET, type RestoreApproval, restorePlanHash } from "./approvals.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { recordAdminRefusal } from "./diag-admin.ts";
import { bumpAdminCounter, noteInvalidRunId } from "./diag-counters.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { callerCan } from "./identity.ts";
import { readRestoreCapsule, runBlindRestoreTest, runKeylessAttest, runRestore } from "./restore.ts";
import { restoreAppliedEmission } from "./restore-alert.ts";
import { recordRestoreFaultRow, recordRestoreOutcome } from "./restore-faults.ts";
import { bufferedRestoreMaxBytesInvalid, errId } from "./restore-sinks.ts";
import type { BlindRestoreTest, CapsuleResult, KeylessAttestationResult, RestorePlan, RestoreRequest, RestoreResult } from "./restore-types.ts";
import { callerHeaders, gate, jsonResponse, rateLimited, recordAudit, requireStepUp, stampRestoreProven, stampRestoreTested } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { withRunDestFallback } from "./router-sources.ts";

// fireInBackground: see router-identity.ts's identical helper.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// notePlanSeen records THE PLAN ANCHOR for a dry run the operator has just been shown: the instant an
// approval for this plan hash must start its TTL from, so that the applyDeadline the plan published is the
// deadline the apply actually obeys. See the DO's notePlanSeen for why the anchor is put-if-absent and
// swept, and restore-plan.ts for what the deadline is used to warn about.
//
// Swallows every failure, and the CONSEQUENCE of that is stated here rather than glossed. It is called from
// the read-only dry-run path, so a DO hiccup must not turn a preview into an error. But an unrecorded anchor
// is NOT harmless: requestRestore refuses a request whose plan has no recorded dry run, so a preview whose
// anchor did not land cannot be requested against and the operator has to run the dry run again. That is the
// deliberate direction. The comment this replaces said the DO "falls back to the request instant, which is a
// plan computed at that moment"; that was false in the part that mattered, because the request route's
// re-plan computes fidelityWarnings and DISCARDS them (only isLatest/plannedWrites/bytes are forwarded), so
// the fresh disclosure reached nobody and the operator approved a card the engine had stopped standing
// behind. A refusal an operator can clear with one read-only call is the honest failure.
async function notePlanSeen(scheduler: DurableObjectStub, planHash: string, plannedAt: string | undefined): Promise<void> {
  try {
    // The plan's OWN instant, not this call's. They differ by however long the preview took to serialise,
    // and the plan computed its deadline from plannedAt, so anchoring to the later instant would put the
    // last permitted write a few milliseconds past the deadline the plan warned on. The DO clamps it to its
    // own now, so the value can only ever shorten the approval.
    const plannedAtMs = Date.parse(plannedAt ?? "");
    await scheduler.fetch(doURL("/restore/plan-seen"), {
      method: "POST",
      body: JSON.stringify({ planHash, ...(Number.isFinite(plannedAtMs) ? { plannedAt: plannedAtMs } : {}) }),
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    log("error", `restore plan anchor not recorded (the approval will anchor to its request instead): ${(e as Error).message}`);
  }
}

// buildSourceBindingMap resolves a backed-up resource's identity -> the Worker binding its source was
// attached under, read from the live downpipe configs (one DO round trip). The attach binding name is
// operator-chosen (e.g. SRC_KV_uploads) and need NOT match the KV_<namespaceId>/R2_<bucket>/D1_<dbName>
// restore convention, so WITHOUT this map a "restore to original bindings" looks for a convention binding
// that does not exist and every record skips with "target binding not present". Keys are
// `kv:<namespaceId>` / `r2:<bucketName>` / `d1:<dbName>` (a D1 database's dbName is its binding name on the
// read path). Presence-safe: an unreadable list yields an empty map and resolveSink falls back to the
// convention exactly as before (it never fails the restore).
export async function buildSourceBindingMap(scheduler: DurableObjectStub): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  try {
    const resp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
    // THE SOURCE IS ON `config`, AND READING IT OFF THE TOP LEVEL MADE THIS MAP ALWAYS EMPTY.
    //
    // GET /downpipes returns the DO's listDownpipes(), an array of DownpipeState, and sched/types.ts:197
    // declares `config: DownpipeConfig` with the source inside it. This function cast the response to
    // `Array<{ source?: SourceSpec }>` and read `dp.source`, which is undefined on every row, so the loop
    // `continue`d on all of them and returned an EMPTY map every time, for kv, r2 and d1 alike. Every
    // "restore to original bindings" therefore fell back to the KV_<id>/R2_<bucket>/D1_<name> convention,
    // which is exactly the failure this map exists to prevent.
    //
    // The cast is what hid it: it asserted a shape the DO has never returned, so the compiler could not
    // object and the code read a plausible field that was never there: GET /admin/downpipes actually returns
    // {"config":{"source":{"type":"kv","binding":"SRC_KV",...}},...} and the map came back empty.
    //
    // Typed against the real shape now rather than cast at it, and `source` is still accepted at the top
    // level so a caller or fixture using the flat shape keeps working.
    const downpipes = (await resp.json()) as Array<{ config?: { source?: SourceSpec }; source?: SourceSpec }>;
    for (const dp of downpipes) {
      const s = dp?.config?.source ?? dp?.source;
      if (!s || typeof s.binding !== "string" || s.binding === "") continue;
      if (s.type === "kv") {
        if (typeof s.namespaceId === "string" && s.namespaceId !== "") map.set(`kv:${s.namespaceId}`, s.binding);
        // BINDING FALLBACK, for a kv source stored WITHOUT a namespaceId. sched/types.ts declares that field
        // optional "for back-compat", so a downpipe saved before it existed, or created over an already-bound
        // namespace, carries only a binding name. Without this the map gains no kv: entry at all, resolveSink
        // misses and falls back to the KV_<namespace> convention, and every record skips with "target binding
        // not present": a restore that completes and writes nothing.
        //
        // The key is the BINDING because that is what the archive record actually carries in these cases.
        // seal/adapters.ts:192 constructs the source with `s.namespaceId ?? s.binding`, and the crawl stamps
        // that value as each record's `namespace` (sources/kv.ts:123). So a record captured from a config with
        // no namespaceId is stamped `SRC_KV`, resolveSink looks up `kv:SRC_KV`, and this is the entry that
        // answers it. The D1 branch below already keys on the binding for the same reason: no separate id.
        //
        // Deliberately does NOT overwrite an existing entry. Keying two different things into one namespace
        // makes a collision possible in principle (one downpipe's binding equalling another's namespace id),
        // and if that ever happens the namespaceId mapping is the authoritative one.
        if (!map.has(`kv:${s.binding}`)) map.set(`kv:${s.binding}`, s.binding);
      } else if (s.type === "r2") {
        if (typeof s.bucketName === "string" && s.bucketName !== "") map.set(`r2:${s.bucketName}`, s.binding);
        // BINDING FALLBACK, the exact counterpart of the kv one above, for an r2 source stored WITHOUT a
        // bucketName. This branch used to REQUIRE that field, so a source carrying only a binding produced no
        // r2: entry at all, resolveSink missed and fell back to the R2_<bucket> convention, and every record
        // skipped with "target binding not present": a restore that completes and writes nothing.
        //
        // The key is the BINDING because that is what the archive record actually carries in these cases.
        // seal/adapters.ts:198 constructs the source with `s.bucketName ?? s.binding`, and the crawl stamps
        // that value as each record's `bucket`. So a record captured from a config with no bucketName is
        // stamped `SRC_R2`, resolveSink looks up `r2:SRC_R2`, and this is the entry that answers it. The kv
        // branch above and the d1 branch below already key on the binding for the same reason.
        //
        // This is the same defect the kv branch was repaired for, left standing in the sibling two lines
        // away: a source declaring only a binding (no bucketName) planned zero writes with every record
        // skipping "target binding not present", while an otherwise-identical source declaring bucketName
        // planned correctly.
        //
        // Deliberately does NOT overwrite an existing entry, exactly as the kv fallback does not: one
        // downpipe's binding could equal another's bucket name, and if that ever happens the bucketName
        // mapping is the authoritative one.
        if (!map.has(`r2:${s.binding}`)) map.set(`r2:${s.binding}`, s.binding);
      } else if (s.type === "d1") map.set(`d1:${s.binding}`, s.binding);
    }
  } catch {
    // presence-safe: no overrides -> resolveSink uses the KV_<id>/R2_<bucket>/D1_<name> convention.
  }
  return map;
}

// RESTORE_MASTER_HEADER carries the browser-supplied per-run master for the in-console break-glass restore
// (008), as a base64url(32 bytes) value on a DISTINCT TRANSPORT HEADER. It is NEVER a field on RestoreRequest:
// the console posts JSON.stringify(req) as the body, and restorePlanHash, every recordAudit target, the
// RestorePlan/RestoreResult, the receipt and every Durable Object write are built from that parsed JSON body,
// which never carries the master. So keeping the master on a header (never merged into the hashed body) makes
// its exclusion from all of those STRUCTURAL, not merely a matter of discipline. It rides exactly the way the
// optional X-Downpipes-Change reference already does (change-ref.ts). The engine uses it only to open the run
// (openRunFromMaster) and discards it, the same contract the attend verify path keeps for its per-run masters.
const RESTORE_MASTER_HEADER = "x-downpipes-restore-master";

// decodeRestoreMaster reads the optional per-run master header and decodes it to its 32 raw bytes, returning
// { master } on success, {} when the header is absent (an ordinary operational restore, or the honest
// break-glass refusal when there is also no operational key), or a 400 Response for a malformed / wrong-length
// value (never a 500). A structurally-VALID-but-WRONG master (32 bytes, wrong value, or another run's master)
// is NOT rejected here: it flows to openRunFromMaster, where the signed key-commitment check fails it closed
// with nothing written, so a wrong or cross-run master can never open a run it is not the master for. The
// decoded bytes are never logged.
function decodeRestoreMaster(req: Request): { master?: Uint8Array } | Response {
  const b64 = req.headers.get(RESTORE_MASTER_HEADER);
  if (b64 === null || b64.trim() === "") return {};
  let bytes: Uint8Array;
  try {
    bytes = b64urlDecode(b64.trim());
  } catch {
    return new Response(JSON.stringify({ error: "restore master is not valid base64url" }), { status: 400, headers: { "content-type": "application/json" } });
  }
  // The per-run master is exactly 32 bytes; a value of any other length (notably the 96-byte break-glass
  // private) is a malformed request, refused here rather than allowed to reach the open.
  if (bytes.length !== 32) {
    return new Response(JSON.stringify({ error: "restore master must decode to 32 bytes" }), { status: 400, headers: { "content-type": "application/json" } });
  }
  return { master: bytes };
}

// handleRestore dispatches the restore + dual-control + verify/attest group. Returns the route's Response,
// or null when no case here matched (the hub falls to the next spoke).
export async function handleRestore(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, sourceIp, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- restore: dry-run any role; APPLY requires Approver/Owner (the F1 hard rule) ------
    case "POST /restore": {
      const body = (await req.json()) as RestoreRequest;
      if (!body.runId) return new Response(JSON.stringify({ error: "runId required" }), { status: 400, headers: { "content-type": "application/json" } });
      // HI-09: reject a runId that is not a canonical ULID before it reaches any object-key
      // template. A dot-segment payload (e.g. "../../evil-bucket") would otherwise flow unchecked
      // into `run/${runId}/...` and, for an S3-style destination, collapse the signed request path
      // outside the configured bucket via new URL()'s RFC-3986 normalisation (dest/sigv4.ts).
      // G321: the rejection reaches only the immediate HTTP caller, so a customer's integration script can 400
      // for weeks with support unable to see WHY (truncated, case-mangled or out-of-range ids are three
      // different fixes). noteInvalidRunId counts the closed KIND; the candidate never crosses the wire.
      if (!isValidRunId(body.runId)) {
        fireInBackground(runtime, noteInvalidRunId(scheduler, body.runId));
        return new Response(JSON.stringify({ error: "runId must be a valid ULID" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // EMPTY-PREFIX SELECTOR. inScope is a literal startsWith test and every string starts with "", so a
      // single "" in exclude puts every record out of scope: this restore would plan zero writes and report
      // a SUCCESS. Checked here beside the runId shape check, before any role is consulted, because it is a
      // statement about the request and not about the caller. Refused rather than filtered; see
      // selectorPrefixFault for why silently dropping the entry would be worse.
      {
        const selFault = selectorPrefixFault(body.include ?? [], body.exclude ?? []);
        if (selFault !== null) return new Response(JSON.stringify({ error: selFault }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // 008: the OPTIONAL browser-supplied per-run master rides a distinct transport header (never on the
      // RestoreRequest body). Decode it into a local variable here and thread it ONLY into runRestore's options
      // for the open; it never reaches restorePlanHash (below), any recordAudit target, the RestorePlan/
      // RestoreResult, the receipt or a DO write. A malformed / wrong-length value is a plain 400 (alongside the
      // runId 400 above), never a 500 -- decoded before the role gate so a malformed request is a 400
      // regardless of role. Absent => an operational restore, or runRestore's honest break-glass refusal.
      const md = decodeRestoreMaster(req);
      if (md instanceof Response) return md;
      const master = md.master;
      // Resolve each backed-up resource to its ACTUAL attached source binding (operator-chosen at attach,
      // not the KV_<id>/R2_<bucket>/D1_<name> convention) from the live downpipe configs, so "restore to
      // original bindings" writes back to the real binding instead of skipping with "target binding not
      // present". Built once for both the apply and dry-run branches below; presence-safe (empty on a read
      // hiccup -> convention fallback). It is read-only reconnaissance the caller already has rights to.
      const sourceBindings = await buildSourceBindingMap(scheduler);
      // G315: the restore knob the operator SET and the engine silently DISCARDED. RESTORE_BUFFERED_MAX_BYTES
      // is resolved deep inside the restore core (restore-sinks.ts), which holds no DO stub and must not grow
      // one; this route is where the knob's usability is first answerable WITH a recorder in hand, and it is
      // also the real entry point (\"we set the knob and records still buffer\" is a complaint about a restore).
      // A boolean predicate over env: the unusable value itself never travels. An absent knob is the default,
      // not a fault, so an ordinary deployment records nothing here.
      if (bufferedRestoreMaxBytesInvalid(env)) fireInBackground(runtime, bumpAdminCounter(scheduler, "restore-buffered-max-invalid"));
      // The F1 hard rule, enforced SERVER-SIDE: any apply (confirm:true) requires Approver or
      // Owner; an Operator (or Viewer) gets dry-run + drill only. A dry-run (confirm omitted or
      // false) writes nothing and gates on restore.dryrun (every built-in role holds it from the
      // viewer floor up, the same read-safe floor restore.verify sits on). The request is
      // request-evaluable (confirm is a boolean on the body), so there is no client-side
      // "lower vs higher impact" judgement; a direct-API apply by an Operator is refused here.
      //
      // Rate-limiting applies to BOTH paths (the dry-run plan and an AUTHORISED apply): each is a
      // mutating POST that drives real planning/IO, so both count against the caller's window. But the
      // limiter must NEVER mask a security-relevant denial: for the apply path the F1 ROLE GATE (and
      // its denied-apply audit) runs FIRST, BEFORE the rate-limit check, so an UNAUTHORISED apply that
      // is also over its window still gets the 403 + the denied-apply audit, never a 429 that hides it
      // (a 429 would let a rate-limited Operator's blocked production write go unaudited). Rate-limiting
      // is then applied to the AUTHORISED apply below, and to the dry-run path in its own branch, so an
      // authenticated caller still cannot drive an unbounded burst of either. The runId check above
      // stays first so a malformed/empty request is a plain 400, never a 403/429.
      //
      // A dry-run writes nothing and is NOT a first-class audit event (it is a read-only preview);
      // only an APPLY (confirm:true) is audited, as restore-apply. The apply is the only path that
      // writes customer data back, so it is the high-consequence event the trail must hold.
      if (body.confirm === true) {
        const redirectBinding = body.target?.binding ?? null;
        const planHash = await restorePlanHash(body);
        // 1) The F1 capability gate FIRST (before rate-limiting): an apply (confirm:true) requires
        // restore.apply (restore-operator/approver/owner); an operator/viewer is refused here. This
        // precedes the rate-limit check on purpose, so an unauthorised apply always yields the 403 +
        // the denied-apply audit and a security-relevant denial is never masked by a 429. (For the four
        // existing roles this is identical allow/deny to the prior "approver" rank gate; the maker !=
        // checker dual-control gate below is unchanged and still absolute.)
        const denied = gate(caller, "restore.apply");
        if (denied) {
          // Record the refused apply (a reviewer cares about a blocked production write). isLatest
          // is unknown for a denied apply (no plan was run), so report false; the target carries
          // only names/counts/the plan hash, never a value.
          await recordAudit(scheduler, caller, sourceIp, "restore-apply", "denied", {
            kind: "restore",
            runId: body.runId,
            redirectBinding,
            planHash,
            isLatest: false,
          });
          return denied;
        }
        // 1a) STEP-UP (ASVS V7.5.1 / V7.5.3, STEPUP-SESSION-TERMINATION-GAP): a stale ambient
        // session must not write customer data back without a fresh re-auth. POST /restore is ONE static
        // sub carrying BOTH the read-only dry-run (this branch never reaches; confirm is not true) and the
        // actual apply, so it cannot be a literal STEPUP_SUBS member (a Set keyed on `sub` cannot see the
        // body's `confirm` field) -- this mirrors the HI-04 dynamic-<id>-approve pattern exactly, one static
        // sub gated on its PARSED dangerous action instead of one dynamic id (see router-core.ts's comment
        // on STEPUP_SUBS). Called here, after the role gate and before the dual-control reservation, so an
        // unauthorised OR unfresh apply is refused before any DO state is touched or any byte written; the
        // token/access methods stay exempt inside requireStepUp exactly as everywhere else.
        const stepUp = await requireStepUp(req, scheduler, caller.method, runtime);
        if (stepUp) return stepUp;
        // 1b) Rate-limit the AUTHORISED apply (only now that the role + step-up gates have passed): an
        // Approver/Owner hammering the apply surface still counts against their window. Placed AFTER the
        // role gate so a rate-limited UNAUTHORISED apply is the 403 above, not a 429 here.
        const limitedApply = await rateLimited(scheduler, caller);
        if (limitedApply) return limitedApply;
        // 2) Dual control (D2): the apply additionally requires a SECOND authorised identity's
        // approval, bound to THIS plan hash, with maker != checker. The DO is the authority; ask it to
        // RESERVE a usable approval BEFORE touching live data -- gateRestore atomically checks
        // usability AND flips the record to "applying" in one Durable Object read-modify-write (ASVS
        // 2.1.6: this closes the TOCTOU race a read-only gate left open, where N concurrent identical
        // applies could all observe usable:true and all run before any of them consumed). A
        // self-approval is already refused at approve time, and the reservation re-checks approver !=
        // requester, so a caller cannot approve their own apply. No usable approval -> 403 { error:
        // "restore not approved", planHash } (a capability gate the console routes to "awaiting
        // approval", not a mystery failure), recorded as a denied apply; nothing was reserved, so
        // there is nothing to release.
        const gateResp = await scheduler.fetch(doURL("/restore/gate"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } });
        const gateBody = (await gateResp.json()) as { usable: boolean; approval: RestoreApproval | null; required?: boolean };
        // OWNER-OPT-IN DUAL CONTROL OVER THE APPLY. `required` false means the estate has not armed the
        // policy, so there is no approval record: the reserve and the single-use consume below are skipped
        // because they only mean something against a record. Absent is read as REQUIRED (fail-safe): an
        // older DO that does not yet return the field must not be taken as permission to skip the gate.
        const approvalRequired = gateBody.required !== false;
        if (!gateBody.usable) {
          // G245, THE MARQUEE SPLIT: "our approved restore said not-approved" is one of two OPPOSITE things.
          // Either the approval genuinely is not there (the operator must go and get one), or the GATE COULD
          // NOT BE READ -- a DO fault -- and the apply was refused FAIL-CLOSED while a perfectly valid approval
          // sat in storage. The response is byte-identical in both cases (deliberately: the gate stays
          // fail-closed and must never oracle), and the pack could not tell them apart. Now it can, so the
          // DR-hour question "is my approval missing, or is your engine broken?" finally has an answer.
          fireInBackground(runtime, recordAdminRefusal(scheduler, "restore-apply", gateResp.ok ? "not-approved" : "gate-unavailable"));
          await recordAudit(scheduler, caller, sourceIp, "restore-apply", "denied", {
            kind: "restore",
            runId: body.runId,
            redirectBinding,
            planHash,
            isLatest: false,
          });
          return new Response(JSON.stringify({ error: "restore not approved", planHash }), { status: 403, headers: { "content-type": "application/json" } });
        }
        // G080 (THE CRASHED APPLY): a usable approval that STILL carries an appliedAt is proof that an
        // EARLIER apply reserved this approval, died mid-write (the Worker was killed: no /restore/release,
        // no /restore/consume, no restore-apply audit event -- nothing at all) and had its reservation
        // RECLAIMED by the lease (approvals.ts effectiveStatus). releaseRestore DELETES appliedAt on every
        // clean release and consumeApproval terminates the record, so this state is reachable ONLY through a
        // crash. It was previously a pure read-time projection: this retry is about to overwrite the stale
        // appliedAt, erasing the only trace that a half-written apply ever happened -- exactly the evidence
        // support needs for "my KV namespace is half restored and I have no idea why". Recorded BEFORE the
        // reserve below overwrites it, best-effort (it never gates the retry).
        const staleApply = gateBody.approval?.appliedAt;
        if (staleApply !== undefined) {
          const applied = Date.parse(staleApply);
          const staleMs = Number.isFinite(applied) ? Math.max(0, Date.now() - applied) : RESTORE_APPLY_LEASE_MS;
          await recordRestoreFaultRow(scheduler, { op: "apply", phase: "write", cls: "apply-crashed-lease-reclaimed", count: Math.floor(staleMs / 1000) });
          await bumpAdminCounter(scheduler, "restore-apply-lease-reclaimed");
        }
        const approverEmail = gateBody.approval?.approvedBy;
        const approverSubject = gateBody.approval?.approverSubject;
        const reason = gateBody.approval?.reason;
        // 2a) CHANGE MANAGEMENT (OWNER OPT-IN "Require Change Number"): a restore apply writes customer data
        // back, so it is a CAB-worthy change-controlled action. Ask the DO to enforce the change-number policy
        // and record the change-recorded CR before applying: with the policy ON the operator must have attached
        // a valid change reference (carried on the caller via callerHeaders), else the DO returns 400 and the
        // apply is refused here; with the policy OFF this is a no-op. Placed AFTER the role + approval gates so
        // a CR is raised only for an apply that is otherwise authorised and about to proceed (a refused apply
        // records no change). The enforce route is the SAME chokepoint the owner-action gate uses.
        const ccResp = await scheduler.fetch(doURL("/change-control/enforce"), {
          method: "POST",
          body: JSON.stringify({ actionKind: "restore-apply" }),
          headers: callerHeaders(caller),
        });
        if (!ccResp.ok) return ccResp;
        // 2b) RESERVE (HI-03 / ASVS 2.1.6: the gate above is READ-ONLY, so two concurrent applies for the SAME plan hash
        // both observe usable:true and both would otherwise reach the write below). Immediately adjacent to
        // the write -- nothing else runs in between -- this is the actual atomic single-use transition: the
        // DO flips approved -> applying in one read-modify-write, so of two racing requests only ONE can
        // reserve; the other is refused here with the same 403 shape the unapproved-gate path returns above.
        // A crashed reservation self-heals via the DO's lease (approvals.ts RESTORE_APPLY_LEASE_MS), so this
        // never wedges a genuinely failed apply.
        if (approvalRequired) {
          const reserveResp = await scheduler.fetch(doURL("/restore/reserve"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } });
          const reserveBody = (await reserveResp.json()) as { reserved: boolean };
          if (!reserveBody.reserved) {
            await recordAudit(scheduler, caller, sourceIp, "restore-apply", "denied", {
              kind: "restore",
              runId: body.runId,
              redirectBinding,
              planHash,
              isLatest: false,
            });
            return new Response(JSON.stringify({ error: "restore not approved", planHash }), { status: 403, headers: { "content-type": "application/json" } });
          }
        }
        // 3) Apply. The RESERVATION above (not merely the read-only gate) is what makes this exclusive: a
        // failed apply -- including an exception thrown out of withRunDestFallback/runRestore, which
        // otherwise propagates uncaught -- RELEASES the reservation back to "approved" (a retry needs no
        // fresh round of dual control, the same UX a plain failed apply always had); only a SUCCESSFUL apply
        // CONSUMES it (single use). try/finally covers every exit, thrown or returned, so the reservation is
        // never left dangling.
        let result: RestoreResult | undefined;
        try {
          result = (await withRunDestFallback(scheduler, body.runId, body.destinationId, (cfg, destFallback) => runRestore(env, body, cfg, { sourceBindings, ...(master !== undefined ? { master } : {}), ...(destFallback !== undefined ? { destFallback } : {}) }), loadConfigWrapKey(env.CONFIG_WRAP_KEY))) as RestoreResult;
        } catch (e) {
          // G070 (THE THROWN APPLY): a throw out of the restore core propagates past every line below --
          // the recordAudit at (4), the receipt anchor at (5) -- so an apply that DIED left NO outcome row
          // anywhere: the pack showed a consumed/released approval and nothing else, and support could not
          // even tell whether the engine had started writing. Record BOTH the closed fault row (op apply,
          // phase write, class apply-threw, carrying the 8-hex errId that joins to the Workers-Logs line)
          // and a FAILED restore-apply audit event, which rides the existing keystone projection unchanged.
          // Both are best-effort and neither swallows the throw: the caller still gets its 500, exactly as
          // before, so no behaviour changes -- only the evidence exists now.
          await recordRestoreFaultRow(scheduler, { op: "apply", phase: "write", cls: "apply-threw", errId: errId(e) });
          try {
            await recordAudit(scheduler, caller, sourceIp, "restore-apply", "failed", {
              kind: "restore",
              runId: body.runId,
              redirectBinding,
              planHash,
              isLatest: false,
            });
          } catch {
            /* the audit write is itself best-effort: never mask the original throw with a bookkeeping fault */
          }
          throw e;
        } finally {
          // result is undefined only when the call above THREW (propagating out uncaught, exactly as before
          // this fix); either way the reservation must not be left dangling, so an unset result also releases.
          //
          // G100: CHECKED. This is the DUAL-CONTROL accounting write. A dropped CONSUME means a single-use
          // approval was never terminated (it may authorise a SECOND apply -- the single-use guarantee a
          // dual-control attestation rests on is then not proven); a dropped RELEASE strands the reservation
          // until the lease is reclaimed, so the operator's retry is refused with no cause anywhere. Both used
          // to vanish in silence. The path is unchanged (still best-effort, still never fails the restore);
          // only the loss is now counted, and the DO's own approvalFaults ring records the reclaim from the
          // other side.
          // Only when the estate armed dual control: with the policy off nothing was requested, approved
          // or reserved, so there is no single-use record to terminate and no reservation to release.
          // Calling either would ask the DO to mutate a record that was never created.
          if (approvalRequired) {
            await recordDiagWrite(scheduler, "restore-receipt", () =>
              scheduler.fetch(doURL(result?.ok ? "/restore/consume" : "/restore/release"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } }),
            );
          }
        }
        // 3a) G070: project the finished apply into the bounded restoreFaults ring -- WHICH record failed,
        // in WHICH phase, in WHICH closed failure mode (integrity abort vs a WORM-refused write vs an object
        // written-then-unreadable vs a D1 half-load vs a cf-config surface the CF API refused), plus every
        // marker skip and the windowed remainder. A CLEAN apply records nothing. This is the per-record and
        // per-phase detail the restore-apply keystone's counts coarsen away; it never alters the result.
        await recordRestoreOutcome(scheduler, "apply", result);
        // 4) Record the apply with BOTH identities, on BOTH axes: the maker is the caller (the applier/
        // actor: actorSubject + actorEmail via recordAudit), the checker is the approval's approver
        // (target.approverSubject the stable axis + target.approverEmail the display). success when the
        // engine applied (ok:true), failed for an in-flow ok:false (break-glass-only posture, a
        // verification failure). The reason carried on the approval is recorded too (redaction-safe text).
        await recordAudit(scheduler, caller, sourceIp, "restore-apply", result.ok ? "success" : "failed", {
          kind: "restore",
          runId: body.runId,
          redirectBinding,
          planHash,
          isLatest: result.isLatest,
          ...(reason !== undefined ? { reason } : {}),
          ...(approverSubject !== undefined ? { approverSubject } : {}),
          ...(approverEmail !== undefined ? { approverEmail } : {}),
          // HI-15: name the destination the BYTES were actually read from at apply, so a divergence from
          // the reviewed destinationId (now hash-bound; see restorePlanHash) is visible on the final event too.
          ...(body.destinationId !== undefined ? { destinationId: body.destinationId } : {}),
        });
        // 5) ANCHOR THE RESTORE RECEIPT into the tamper-evident chain (auditable proof-of-correct-restore).
        // Whenever the apply reached the write phase it returns a receipt; append a "restore-verified" entry
        // carrying the receipt's SHA-384 (+ runId, recordsRestored, allVerified) so the receipt is BOUND to
        // the chain even when no signer key was reachable to sign it (the audit anchor is the tamper-
        // evidence in that posture). The target is redaction-safe (hash + counts only). This is best-effort,
        // beside the apply record: a failed anchor must not turn a completed restore into a user-facing
        // error, so it is wrapped and degraded to a coarse log line (the apply already succeeded).
        if (result.receipt) {
          try {
            // WS-P4: enrich the receipt anchor with a REDACTION-SAFE apply SUMMARY so the support pack can see
            // HOW the apply landed, not just that it happened. All fields are booleans / non-negative integer
            // COUNTS (never a record name, value, key, or hash of content): the windowed-restore complete flag
            // (a windowed apply left records unrestored), the verified/restored/failure counts, a READBACK-HASH
            // summary (how many records the post-write readback PROVED vs found mismatched), and the per-DB(D1)
            // apply outcome (D1 records attempted vs proven -- a D1 restore writes over several non-atomic
            // batches, so a partial load is the one to surface). receiptSha384 already anchors the full signed
            // per-record hashes; this is the pack-visible digest of the same. Derived from the already-computed
            // result: NO restore behaviour changes, purely an enriched audit target on the existing anchor.
            const rr = result.receipt.records;
            // G191: the cf-config restore's per-item skip CLASSES, summed across every surface. Each skip site
            // attached a closed class (cf-config-fault.ts); the raw 120-char Cloudflare message still rides to
            // the operator's live response and is never recorded.
            //
            // READ OFF THE RECEIPT, not re-summed from result.configApplied, for the reason recordsSkipped is
            // read off it below: the receipt is the SIGNED artefact, and an audit entry that derived the same
            // number a second way could disagree with the evidence it is anchoring. The apply computes this
            // tally once, on the path that classified the refusals, and both readers take it from there.
            const receiptSkipReasons = result.receipt.summary.configSkipReasonCounts ?? {};
            const configSkipReasons = Object.keys(receiptSkipReasons).length > 0 ? receiptSkipReasons : undefined;
            // G285: the per-CLASS breakdown of the failures. `failures: 3` was an integer with no cause, so a
            // restore blocked by a dest token with no write scope, one whose bytes LANDED and would not read
            // back (the data is very likely fine and only the proof is missing), one whose Cloudflare config
            // surface refused the write, and one whose video would not re-upload were the SAME evidence. Three
            // of those four are not even about the archive. The class is the one the fault site TAGGED; the
            // per-record `reason` prose and the record names never ride. An untagged failure counts honestly as
            // sink-write rather than being dropped, so the classes always sum to `failures`.
            const failTally: Record<string, number> = {};
            for (const f of result.failures) {
              const cls = f.cls ?? "sink-write";
              failTally[cls] = (failTally[cls] ?? 0) + 1;
            }
            const summary = {
              complete: result.complete === true,
              recordsVerified: result.recordsVerified,
              failures: result.failures.length,
              ...(Object.keys(failTally).length > 0 ? { failuresByClass: failTally } : {}),
              outOfWindow: result.outOfWindow ?? 0,
              readbackVerified: rr.filter((r) => r.verified).length,
              readbackMismatched: rr.filter((r) => !r.verified).length,
              d1Total: rr.filter((r) => r.sourceType === "d1").length,
              d1Verified: rr.filter((r) => r.sourceType === "d1" && r.verified).length,
              // G030: the media apply's per-CLASS failure counts and any conflict digest pairs, exactly as the
              // apply classified them at the fault site. Redaction-safe by construction (closed class keys, int
              // counts, SHA-384 hex of the customer's own bytes); honestly ABSENT when no media record failed.
              ...(result.mediaFaults !== undefined ? { mediaFaults: result.mediaFaults } : {}),
              ...(result.mediaConflictDigests !== undefined ? { mediaConflictDigests: result.mediaConflictDigests } : {}),
              // G055: the D1 partial-apply LOCALISATION (closed error class + failed batch index / batch total,
              // or the residual-table count behind a "target not empty" refusal) and the schema objects a
              // table-SUBSET restore filtered out. d1Total/d1Verified above say a D1 record failed; these say
              // WHERE it stopped and WHY, which is the difference between "drop and retry" and "the archive
              // disagrees with your schema". Closed enum + clamped integers, exactly as the apply classified
              // them at the fault site; the SQLite message (table names, column names, row values) never rides.
              ...(result.d1Fault !== undefined ? { d1Fault: result.d1Fault } : {}),
              ...(result.d1SchemaObjectsFiltered !== undefined ? { d1SchemaObjectsFiltered: result.d1SchemaObjectsFiltered } : {}),
              // G348: the restore descriptor fields a sink SHED by design (an unusable KV expiration, an
              // unparseable R2 cacheExpiry). Counts against a closed field vocabulary; never the raw value.
              ...(result.metadataFieldsDropped !== undefined ? { metadataFieldsDropped: result.metadataFieldsDropped } : {}),
            };
            await recordAudit(scheduler, caller, sourceIp, "restore-verified", result.receipt.summary.allVerified ? "success" : "failed", {
              kind: "restore-receipt",
              runId: result.receipt.runId,
              receiptSha384: result.receipt.receiptSha384,
              recordsRestored: result.receipt.summary.recordsRestored,
              allVerified: result.receipt.summary.allVerified,
              // Read off the receipt rather than recomputed from result.skipped, so the audit entry and the
              // signed receipt can never disagree about the same apply.
              ...(result.receipt.summary.recordsSkipped ? { recordsSkipped: result.receipt.summary.recordsSkipped } : {}),
              ...summary,
              // configSkipReasons (G191): fold the per-surface cf-config skip classes the apply already
              // classified at each skip site into ONE closed {class -> count} map, so "a DNS restore applied
              // 180 of 200 records -- why did 20 skip?" is answerable from the pack. Derived from the
              // already-computed result (no restore behaviour changes); OMITTED when nothing skipped.
              ...(configSkipReasons !== undefined ? { configSkipReasons } : {}),
            });
          } catch (e) {
            // G070: the RECEIPT phase. The apply SUCCEEDED and its proof-of-correct-restore did not land: the
            // receipt's SHA-384 was never bound into the tamper-evident chain, so the one artefact an auditor
            // asks for after a restore ("prove what you wrote back, and that it verified") does not exist, and
            // the only trace was this log line in a Workers Logs stream the vendor cannot pull. The restore is
            // NOT failed and nothing about the apply changes; the anchor's loss is now a row. `other` is the
            // honest class (the throw is a DO/audit-write fault, not one of the named restore failure modes)
            // and errId is the existing irreversible join key; the message never rides.
            await recordRestoreFaultRow(scheduler, { op: "apply", phase: "receipt", cls: "other", errId: errId(e) });
            log("error", `restore ${body.runId} receipt audit-anchor skipped (non-critical): ${(e as Error).message}`);
          }

          // The restore-applied notification. The event was in the vocabulary, the severity switch, the
          // digest set and the DO admit-guard, and NOTHING ever emitted it: a customer could select it on a
          // rule and the rule matched nothing, so the one irreversible operation in the product told nobody
          // while a restore TEST passing did.
          //
          // The detail states the shortfall rather than only the total, for the same reason the receipt and
          // the console outcome now do. "Restored 98 of 100" with no cause is the message that reads as
          // success, and a notification is the surface where an operator is least likely to go looking.
          //
          // Fail-open by construction: this runs after the apply has completed and returned its result, and
          // routeEngineNotification never throws, so a channel outage cannot affect a restore.
          const applied = result.receipt.summary;
          const alert = restoreAppliedEmission({
            runId: body.runId,
            recordsVerified: result.recordsVerified,
            recordsRestored: applied.recordsRestored,
            failures: result.failures.length,
            ...(applied.recordsSkipped !== undefined ? { recordsSkipped: applied.recordsSkipped } : {}),
          });
          await routeEngineNotification(
            env,
            scheduler,
            {
              event: "restore-applied",
              severity: alert.severity,
              downpipeId: null,
              downpipeName: null,
              detail: alert.detail,
              at: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
            },
            "restore",
          );
        }
        return new Response(JSON.stringify(result), { headers: { "content-type": "application/json" } });
      }
      // Dry-run path (confirm omitted or false), gated on restore.dryrun. B9: this capability was
      // declared in the contract and shown in the console's roles-builder (a creator could tick or
      // untick it) but no gate()/can() call anywhere ever checked it; the gate below closes that
      // hole, making restore.dryrun a real, live authorisation check rather than a phantom one
      // (proven directly against a hand-built caller lacking it in validate-custom-roles.ts).
      // PRECISE CLAIM: every built-in role holds restore.dryrun from the viewer floor up, and
      // identity-rbac.ts's read floor is additionally folded, unconditionally, into every custom
      // role's resolved capability set (resolveAuthority, scheduler-do-rbac.ts:530-533, "custom roles
      // are additive"), so no custom role composable through the product today can actually be
      // excluded from it -- this gate is correct and future-proofing (it bites the moment a narrower
      // caller becomes constructible), not a live boundary against any caller reachable now. The gate
      // runs BEFORE the rate limit, the same discipline as the apply branch above, so a refused
      // dry-run is never masked by a 429. Rate-limited too once past the gate: a dry-run drives real
      // planning/IO, so it counts against the caller's window like an authorised apply does. It still
      // FAILS OPEN (see rateLimited), so an unavailable limiter never blocks a verified operator's
      // preview.
      const deniedDryRun = gate(caller, "restore.dryrun");
      if (deniedDryRun) return deniedDryRun;
      const limitedDryRun = await rateLimited(scheduler, caller);
      if (limitedDryRun) return limitedDryRun;
      const result = await withRunDestFallback(scheduler, body.runId, body.destinationId, (cfg, destFallback) => runRestore(env, body, cfg, { sourceBindings, ...(master !== undefined ? { master } : {}), ...(destFallback !== undefined ? { destFallback } : {}) }), loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      // G070: a dry-run REFUSAL persisted nowhere at all -- an oversized in-account window, a reserved target
      // binding, a run that could not be opened, every record skipped for a missing binding. So "we cannot
      // even preview a restore" was invisible in the pack while the customer was blocked for a week. A clean
      // dry-run records nothing; the refusal now names its closed class and phase.
      await recordRestoreOutcome(scheduler, "dry-run", result);
      // THE PLAN ANCHOR. This preview is what an operator reads and then asks a second person to approve, and
      // the plan above has just published the applyDeadline its fidelity warnings were computed against.
      // Record the instant so the approval's TTL starts HERE rather than at the request, which is what makes
      // that deadline true: without it the last instant an apply could still be writing was
      // `request + RESTORE_APPLY_DEADLINE_MS`, later than this plan's deadline by however long the operator
      // spent reading it, and a KV expiration lapsing in that gap was dropped by the sink with nothing in
      // the approved plan naming it. Put-if-absent in the DO, so the anchor is the OLDEST preview still in
      // play and every card an operator may be holding is covered.
      //
      // Best-effort and never on the response path: a failed anchor must not turn a read-only preview into
      // an error. A missing anchor is not a silent loss of the property either, but not for the reason this
      // comment used to give: requestRestore does NOT fall back to its own re-plan instant, it REFUSES the
      // request, because the re-plan's fidelity warnings are discarded and so the fallback disclosed nothing
      // to anyone. An anchor that did not land costs the operator one more dry run, loudly.
      //
      // AWAITED, NOT FIRED INTO THE BACKGROUND, and the ordering is the whole reason. The operator can raise
      // the approval request the instant this response reaches them, so the anchor has to be durable BEFORE
      // the plan leaves the engine; a note dispatched into waitUntil and then dropped would leave the
      // approval anchored to the request, which is precisely the gap this closes, and it would be silent.
      // The call swallows its own faults, so an unavailable DO still returns the preview rather than turning
      // a read-only operation into an error.
      await notePlanSeen(scheduler, await restorePlanHash(body), (result as RestorePlan).plannedAt);
      return new Response(JSON.stringify(result), { headers: { "content-type": "application/json" } });
    }

    // ---- serve a chosen run's master capsule so the browser can decap its per-run master (008) -----------
    case "POST /restore/capsule": {
      // The in-console break-glass restore's key handoff. Return the NON-SECRET master-capsule wraps + key
      // commitment for a caller-CHOSEN run so the operator's browser can recover THIS run's per-run master
      // locally (openCapsule), then supply only that 32-byte master back on the restore. Read-safe: gated on
      // restore.verify, the read-safe viewer-floor capability the sibling POST /restore/verify and
      // POST /restore/attest routes also gate on. It discloses nothing new: the capsule already sits encrypted in the
      // customer's own destination bucket and is undecryptable without the break-glass private, which never
      // leaves the browser. readRestoreCapsule SIGNATURE-VERIFIES the run's root manifest before serving, so
      // the route cannot be driven to emit attacker-shaped bytes, and a non-ULID runId is refused at the
      // boundary exactly as the sibling restore routes refuse it.
      const denied = gate(caller, "restore.verify");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { runId?: unknown };
      const runId = typeof body.runId === "string" ? body.runId : "";
      if (runId === "") return new Response(JSON.stringify({ error: "runId required" }), { status: 400, headers: { "content-type": "application/json" } });
      if (!isValidRunId(runId)) {
        fireInBackground(runtime, noteInvalidRunId(scheduler, runId));
        return new Response(JSON.stringify({ error: "runId must be a valid ULID" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Per-run destination resolution + 3-2-1 replica fallback, exactly as the attend capsule route does. The
      // capsule rides in the signed root manifest, so it is identical across replicas; the run's own recorded
      // destination is resolved (no caller-picked override). A read / verify fault is an honest ok:false, never
      // a 500 (classifyRestoreFailure yields the coarse, secret-free reason).
      const res = await withRunDestFallback(
        scheduler,
        runId,
        undefined,
        async (cfg): Promise<{ ok: boolean; capsule?: RunCapsule; reason?: string }> => {
          try {
            return { ok: true, capsule: await readRestoreCapsule(env, runId, cfg) };
          } catch (e) {
            return { ok: false, reason: classifyRestoreFailure(e) };
          }
        },
        loadConfigWrapKey(env.CONFIG_WRAP_KEY),
      );
      if (!res.ok || !res.capsule) {
        const miss: CapsuleResult = { ok: false, runId, reason: res.reason ?? "capsule read failed" };
        return jsonResponse(miss);
      }
      const out: CapsuleResult = { ok: true, runId, masterCapsule: res.capsule.masterCapsule, keyCommitment: res.capsule.keyCommitment, recordCount: res.capsule.declaredRecordCount };
      return jsonResponse(out);
    }

    // ---- dual control (D2): request -> approve (maker != checker) -> apply ----------------
    case "POST /restore/request": {
      // An Operator+ raises a restore request bound to the plan hash, carrying the dry-run plan's
      // blast-radius cues (for the approver) and a required free-text reason (for the trail). The
      // engine recomputes the plan hash from the submitted request server-side, so the binding the
      // approval keys on is the engine's, not a client-supplied value to be trusted. Operator+; the
      // DO re-checks the role and refuses the bare-token fallback (dual control needs an attributable
      // maker). The restore-request audit event is recorded by the DO at the commit point.
      //
      // ENG-H3: the blast-radius cues (isLatest/plannedWrites/bytes) are RECOMPUTED SERVER-SIDE from
      // the runId + selectors below, never forwarded from the client. Previously they were taken
      // verbatim from the request body, so an Operator+ raising a request by direct API could show an
      // approver benign cues (e.g. isLatest:true/plannedWrites:0) while the hash-bound plan restored a
      // large or stale run. The bound hash already binds only the real decision fields and the apply
      // already recomputes from the archive, so this never altered WHAT was restored; but the approver
      // inbox and the restore-request audit event are the maker-checker signal, so they must show the
      // engine's truth, not the requester's claim.
      const reqBody = (await req.json()) as RestoreRequest & { reason?: string; isLatest?: boolean; plannedWrites?: number; bytes?: number };
      if (!reqBody.runId) return new Response(JSON.stringify({ error: "runId required" }), { status: 400, headers: { "content-type": "application/json" } });
      // HI-09: same ULID-shape gate as the other restore routes (see the comment on POST /restore).
      // G321: same closed-kind counter as the sibling routes (see POST /restore).
      if (!isValidRunId(reqBody.runId)) {
        fireInBackground(runtime, noteInvalidRunId(scheduler, reqBody.runId));
        return new Response(JSON.stringify({ error: "runId must be a valid ULID" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // EMPTY-PREFIX SELECTOR. inScope is a literal startsWith test and every string starts with "", so a
      // single "" in exclude puts every record out of scope: this restore would plan zero writes and report
      // a SUCCESS. Checked here beside the runId shape check, before any role is consulted, because it is a
      // statement about the request and not about the caller. Refused rather than filtered; see
      // selectorPrefixFault for why silently dropping the entry would be worse.
      {
        const selFault = selectorPrefixFault(reqBody.include ?? [], reqBody.exclude ?? []);
        if (selFault !== null) return new Response(JSON.stringify({ error: selFault }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // 008: decode the OPTIONAL browser-supplied per-run master from its transport header (never on the
      // RestoreRequest body). The request re-plans the dry-run to recompute the approver's blast-radius cues
      // server-side, and on a break-glass-only estate that re-plan needs the master to open the run, so the
      // master is threaded into the re-plan's runRestore options below. It is NEVER forwarded to the DO, never
      // folded into restorePlanHash (computed from reqBody, which has no master) and never into an audit
      // target. A malformed / wrong-length value is a plain 400, decoded before the role gate like the runId
      // check above.
      const md = decodeRestoreMaster(req);
      if (md instanceof Response) return md;
      const master = md.master;
      // Section 8: raising a restore request gates on restore.request (operator/restore-operator/
      // approver/owner). Same allow/deny as the prior "operator" rank gate for the four existing roles.
      const denied = gate(caller, "restore.request");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "restore-request", "denied", {
          kind: "restore",
          runId: reqBody.runId,
          redirectBinding: reqBody.target?.binding ?? null,
          planHash: await restorePlanHash(reqBody),
          isLatest: false,
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const planHash = await restorePlanHash(reqBody);
      // Recompute the cues by running the SAME dry-run plan an apply for this plan hash would run:
      // the decision fields ONLY (runId, target, selectors, record cap), with confirm forced off so
      // it writes NOTHING. runRestore returns a RestorePlan carrying the engine's own isLatest /
      // plannedWrites / bytes; a posture that cannot be planned (no read-back key, a missing/invalid
      // run) returns the honest ok:false dry-run with isLatest:false / plannedWrites:0 / bytes:0, which
      // is a safe, benign cue (an approver sees "could not be planned", never a forged benign picture).
      // The client-supplied cues are IGNORED for what is stored; they are read only for the
      // cross-check log below. The plan hash is unchanged: restorePlanHash binds the real decision
      // fields and never the cues, so recomputing the cues does not move the binding.
      const dryRunReq: RestoreRequest = {
        runId: reqBody.runId,
        confirm: false,
        ...(reqBody.target !== undefined ? { target: reqBody.target } : {}),
        ...(reqBody.include !== undefined ? { include: reqBody.include } : {}),
        ...(reqBody.exclude !== undefined ? { exclude: reqBody.exclude } : {}),
        ...(reqBody.maxRecords !== undefined ? { maxRecords: reqBody.maxRecords } : {}),
        ...(reqBody.recordName !== undefined ? { recordName: reqBody.recordName } : {}),
        ...(reqBody.cfConfig !== undefined ? { cfConfig: reqBody.cfConfig } : {}),
        // d1Tables NARROWS the scope, so the recomputed blast-radius cues (plannedWrites/bytes) must be
        // planned WITH it, else the approver would see the whole run's cues for a table-subset apply.
        ...(reqBody.d1Tables !== undefined ? { d1Tables: reqBody.d1Tables } : {}),
      };
      // Same source-binding resolution as POST /restore so the recomputed cues (plannedWrites) reflect the
      // records that WILL resolve to a real binding, not a convention-only undercount.
      const sourceBindings = await buildSourceBindingMap(scheduler);
      // HI-15: the cues are computed WITHOUT the caller's destinationId (explicit passed as undefined),
      // never letting a direct-API requester pick which destination's RUNLOG produces isLatest. With no
      // explicit override, withRunDestFallback/resolveRunDestCandidates resolve the run's OWN recorded
      // destination(s) from the DO's history (origin first, falling back to a replica only on a genuine
      // AVAILABILITY fault) -- a server-computed, caller-uncontrolled choice that structurally cannot be
      // behind the account's real freshness picture the way an attacker-picked lagging replica can be.
      // destinationId is still honoured (and now hash-bound, see restorePlanHash) at the ACTUAL apply
      // below and in POST /restore's dry-run/apply branches, which is WHERE the bytes are read from; only
      // the reviewed cues stop being destination-shoppable.
      const plan = (await withRunDestFallback(scheduler, reqBody.runId, undefined, (cfg, destFallback) => runRestore(env, dryRunReq, cfg, { sourceBindings, ...(master !== undefined ? { master } : {}), ...(destFallback !== undefined ? { destFallback } : {}) }), loadConfigWrapKey(env.CONFIG_WRAP_KEY))) as RestorePlan;
      const cues = { isLatest: plan.isLatest === true, plannedWrites: plan.plannedWrites, bytes: plan.bytes };
      // Cross-check ONLY: if the client sent cues that disagree with the engine's recomputed ones, log
      // it coarsely (the engine's values still win). The cue magnitudes are redaction-safe counts (the
      // same class the audit target records), so logging the divergence carries no secret; it is a
      // tamper/misuse signal that a direct-API caller tried to seed a misleading inbox value.
      const claimedLatest = reqBody.isLatest === true;
      const claimedWrites = typeof reqBody.plannedWrites === "number" ? reqBody.plannedWrites : undefined;
      const claimedBytes = typeof reqBody.bytes === "number" ? reqBody.bytes : undefined;
      if (
        (reqBody.isLatest !== undefined && claimedLatest !== cues.isLatest) ||
        (claimedWrites !== undefined && claimedWrites !== cues.plannedWrites) ||
        (claimedBytes !== undefined && claimedBytes !== cues.bytes)
      ) {
        log(
          "error",
          `restore-request ${reqBody.runId} client cues ignored (server-recomputed wins): claimed isLatest=${claimedLatest}/writes=${claimedWrites ?? "-"}/bytes=${claimedBytes ?? "-"} server isLatest=${cues.isLatest}/writes=${cues.plannedWrites}/bytes=${cues.bytes}`,
        );
      }
      // Forward the engine-computed plan hash + the SERVER-RECOMPUTED cues + the reason to the DO. The
      // DO validates the reason is non-empty and stores the requested record (a 400 { error } on a bad
      // reason / missing runId / an existing usable approval). The caller is forwarded so the DO
      // records requestedBy = the verified maker.
      return scheduler.fetch(doURL("/restore/request"), {
        method: "POST",
        body: JSON.stringify({
          planHash,
          runId: reqBody.runId,
          isLatest: cues.isLatest,
          plannedWrites: cues.plannedWrites,
          bytes: cues.bytes,
          redirectBinding: reqBody.target?.binding ?? null,
          ...(reqBody.reason !== undefined ? { reason: reqBody.reason } : {}),
          // HI-15: record WHICH destination the requester named (display/audit only; the cues above are
          // deliberately NOT computed from it -- see the withRunDestFallback comment above).
          ...(reqBody.destinationId !== undefined ? { destinationId: reqBody.destinationId } : {}),
        }),
        headers: callerHeaders(caller),
      });
    }
    case "POST /restore/approve": {
      // A DIFFERENT authorised identity approves a pending request for a plan hash. The DO enforces
      // maker != checker (a self-approval is refused 400 "cannot approve your own request") and the
      // state rule, and records a restore-approve event with both identities. Section 8: gates on
      // restore.approve (restore-operator/approver/owner); the DO re-checks and refuses the bare-token
      // fallback. Same allow/deny as the prior "approver" rank gate for the four existing roles.
      const denied = gate(caller, "restore.approve");
      if (denied) {
        const ab = (await req.json()) as { planHash?: string };
        await recordAudit(scheduler, caller, sourceIp, "restore-approve", "denied", {
          kind: "restore",
          runId: "",
          redirectBinding: null,
          planHash: String(ab.planHash ?? ""),
          isLatest: false,
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/restore/approve"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /restore/reject": {
      // Rejecting a pending request is the approver-side counterpart of approving, so it gates on the
      // same restore.approve capability (restore-operator/approver/owner). The DO records a
      // restore-reject event. Read the body BEFORE the gate check so planHash is available for the
      // denied audit entry (mirroring the approve path; a denied first-class action must be audited).
      const body = (await req.json()) as { planHash?: string; rejectReason?: string };
      const denied = gate(caller, "restore.approve");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "restore-reject", "denied", {
          kind: "restore",
          runId: "",
          redirectBinding: null,
          planHash: String(body.planHash ?? ""),
          isLatest: false,
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // G288: the checker's CLOSED rejection reason, gated at the edge as well as in the DO. A value outside the
      // set is DROPPED here rather than forwarded, so the console cannot put prose on this wire even by mistake:
      // the field the requester most wants filled in is the field an approver would most naturally describe the
      // customer's data in, and it rides into the sealed support pack.
      const rejectReason = typeof body.rejectReason === "string" && RESTORE_REJECT_REASON_SET.has(body.rejectReason) ? body.rejectReason : undefined;
      return scheduler.fetch(doURL("/restore/reject"), {
        method: "POST",
        body: JSON.stringify({ planHash: body.planHash, ...(rejectReason !== undefined ? { rejectReason } : {}) }),
        headers: callerHeaders(caller),
      });
    }
    case "GET /restore/approvals": {
      // The pending-approval inbox. A caller who can approve (restore.approve: approver/owner, plus the
      // new restore-operator) sees every request; anyone else who raised a request still sees their own.
      // Any authenticated role may read it (so a requester can track their own); the DO filters by the
      // forwarded caller and the approver flag. For the four existing roles this is identical to the
      // prior roleAtLeast(approver) check (only approver/owner saw all).
      const isApprover = callerCan(caller, "restore.approve");
      return scheduler.fetch(doURL(`/restore/approvals${isApprover ? "?approver=1" : ""}`), { method: "GET", headers: callerHeaders(caller) });
    }

    // ---- restorability assurance: BLIND restore test + KEYLESS attestation (restore.verify) ----------
    // Both prove a sealed archive can be recovered WITHOUT writing a byte back and WITHOUT surfacing any
    // plaintext, so both gate on the read-safe restore.verify (viewer and up) rather than restore.apply.
    // On a PASS the engine stamps the per-downpipe "offline restorability last proven" record (who+when+
    // method) so the console can show "offline restorability last proven on <date> by <who>". The stamp is
    // best-effort (fire within a guard): a DO hiccup recording the stamp must never turn a genuine proof
    // into a failure, and the proof result is the immediate signal regardless. These are mutating POSTs
    // (they drive real decryption/IO), so each is rate-limited per caller like the dry-run path.
    case "POST /restore/verify": {
      // The BLIND restore test: decrypt EVERY in-scope record to a discard sink, verify each record's
      // plaintext hash, return counts + a restoreDigest, NEVER any plaintext. restore.verify gated.
      // G285: a restorability PROOF that was refused BEFORE it ever ran. The pack carries the stale
      // lastRestoreProvenAt and nothing else, so "we have been unable to re-prove restorability all week" is
      // byte-identical to "nobody tried all week", and they are opposite tickets: one is a fleet whose operators
      // have been locked out of their own proof, the other is a fleet nobody is drilling. The reason class is
      // what separates them again: forbidden (a role/capability that cannot verify) from rate-limited (the
      // limiter turning a large fleet's sweep away). Neither leaves any other trace: a refused proof runs no
      // restore, writes no evidence, and stamps no downpipe.
      const denied = gate(caller, "restore.verify");
      if (denied) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "restore-proof", "forbidden"));
        return denied;
      }
      const body = (await req.json()) as RestoreRequest;
      if (!body.runId) return new Response(JSON.stringify({ error: "runId required" }), { status: 400, headers: { "content-type": "application/json" } });
      // HI-09: reject a runId that is not a canonical ULID before it reaches any object-key
      // template. A dot-segment payload (e.g. "../../evil-bucket") would otherwise flow unchecked
      // into `run/${runId}/...` and, for an S3-style destination, collapse the signed request path
      // outside the configured bucket via new URL()'s RFC-3986 normalisation (dest/sigv4.ts).
      // G321: the rejection reaches only the immediate HTTP caller, so a customer's integration script can 400
      // for weeks with support unable to see WHY (truncated, case-mangled or out-of-range ids are three
      // different fixes). noteInvalidRunId counts the closed KIND; the candidate never crosses the wire.
      if (!isValidRunId(body.runId)) {
        fireInBackground(runtime, noteInvalidRunId(scheduler, body.runId));
        return new Response(JSON.stringify({ error: "runId must be a valid ULID" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // EMPTY-PREFIX SELECTOR, the same rule as POST /restore. A "" in exclude puts every record out of
      // scope, so the blind restore test would verify nothing and report a PASS, which is the worst answer a
      // restorability proof can give. Refused rather than filtered; see selectorPrefixFault.
      {
        const selFault = selectorPrefixFault(body.include ?? [], body.exclude ?? []);
        if (selFault !== null) return new Response(JSON.stringify({ error: selFault }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "restore-proof", "rate-limited"));
        return limited;
      }
      // HI-05: pass the live scheduler so runBlindRestoreTest can pin minRunlogIndex to its account-global
      // runlogCounter, closing the identical whole-document RUNLOG replay its sibling /restore/attest below
      // already closes -- this endpoint persists the SAME stampRestoreProven compliance stamp on a pass, so
      // it is an equally-reachable, equally-valuable sink to close (same restore.verify capability, same
      // audit-stamp consequence).
      const result: BlindRestoreTest = await withRunDestFallback(scheduler, body.runId, body.destinationId, (cfg) => runBlindRestoreTest(env, body, cfg, scheduler), loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      // G070: a FAILED restorability proof is the highest-value diagnostic in the product ("can I actually
      // get my data back?") and it persisted only as a coarse restore-test reason code on the downpipe. The
      // ring now names the phase and the per-record class (WHICH record failed to decrypt, and whether the
      // fault was integrity or availability). A PASS records nothing.
      await recordRestoreOutcome(scheduler, "blind-test", result);
      // Stamp the "last proven" record ONLY on a clean pass with a known downpipe (a failure or a
      // break-glass-only posture records nothing). Best-effort, behind a guard, so a stamp hiccup never
      // demotes a real proof to a failure.
      if (result.ok && result.downpipeId) {
        await stampRestoreProven(scheduler, caller, result.downpipeId, "blind-test", result.runId);
      }
      // Stamp the "Last restore test" RECENCY whenever the test actually ran (the run was opened, so
      // downpipeId is present), with its outcome + measured cost, so a manual verify updates the field like
      // the scheduled test (a break-glass-only posture has no downpipeId and records no test).
      if (result.downpipeId) {
        await stampRestoreTested(scheduler, caller, result.downpipeId, result.ok, { recordsVerified: result.recordsVerified, bytesVerified: result.bytesVerified });
      }
      return jsonResponse(result);
    }
    case "POST /restore/attest": {
      // The Tier 0 KEYLESS integrity attestation: signature + completeness + anti-rollback, NO decryption
      // key and NO data, so it runs even in the break-glass-only posture. restore.verify gated.
      // G285: a restorability PROOF that was refused BEFORE it ever ran. The pack carries the stale
      // lastRestoreProvenAt and nothing else, so "we have been unable to re-prove restorability all week" is
      // byte-identical to "nobody tried all week", and they are opposite tickets: one is a fleet whose operators
      // have been locked out of their own proof, the other is a fleet nobody is drilling. The reason class is
      // what separates them again: forbidden (a role/capability that cannot verify) from rate-limited (the
      // limiter turning a large fleet's sweep away). Neither leaves any other trace: a refused proof runs no
      // restore, writes no evidence, and stamps no downpipe.
      const denied = gate(caller, "restore.verify");
      if (denied) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "restore-proof", "forbidden"));
        return denied;
      }
      const body = (await req.json()) as RestoreRequest;
      if (!body.runId) return new Response(JSON.stringify({ error: "runId required" }), { status: 400, headers: { "content-type": "application/json" } });
      // HI-09: reject a runId that is not a canonical ULID before it reaches any object-key
      // template. A dot-segment payload (e.g. "../../evil-bucket") would otherwise flow unchecked
      // into `run/${runId}/...` and, for an S3-style destination, collapse the signed request path
      // outside the configured bucket via new URL()'s RFC-3986 normalisation (dest/sigv4.ts).
      // G321: the rejection reaches only the immediate HTTP caller, so a customer's integration script can 400
      // for weeks with support unable to see WHY (truncated, case-mangled or out-of-range ids are three
      // different fixes). noteInvalidRunId counts the closed KIND; the candidate never crosses the wire.
      if (!isValidRunId(body.runId)) {
        fireInBackground(runtime, noteInvalidRunId(scheduler, body.runId));
        return new Response(JSON.stringify({ error: "runId must be a valid ULID" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "restore-proof", "rate-limited"));
        return limited;
      }
      // HI-05: pass the live scheduler so runKeylessAttest can pin minRunlogIndex to its account-global
      // runlogCounter, closing a whole-document RUNLOG replay (this is the endpoint stampRestoreProven
      // below persists a compliance stamp from, so a false-clean attestation here is the highest-value
      // sink to close).
      const result: KeylessAttestationResult = await withRunDestFallback(scheduler, body.runId, body.destinationId, (cfg) => runKeylessAttest(env, body, cfg, scheduler), loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      // G070: the keyless attestation runs even in the break-glass-only posture, so a FAILED one is often the
      // only recovery signal an engine can produce at all. Its reason now lands in the ring as a closed class.
      await recordRestoreOutcome(scheduler, "attest", result);
      if (result.ok && result.downpipeId) {
        await stampRestoreProven(scheduler, caller, result.downpipeId, "keyless-attest", result.runId);
      }
      // The keyless attestation is also a restore test; stamp its recency whenever it ran (no bytes are
      // decrypted, so it carries no RTO measurement).
      if (result.downpipeId) {
        await stampRestoreTested(scheduler, caller, result.downpipeId, result.ok);
      }
      return jsonResponse(result);
    }
    default:
      return null;
  }
}
