// validate-availability-evidence: drives eight availability support-pack scenarios as real faults,
// through the real recorder, the real Durable Object, and into a real built support bundle.
//
//   PREFLIGHT'S EVIDENCE. Preflight rides verbatim in the pack and carries every discriminating
//         detail rather than one free-text line truncated to 60-80 chars, with the two list-bearing probes capped
//         at SIX names. So "recipient keys do not parse" says WHICH env var; a bad deploy that drops thirty
//         source bindings names all thirty (with a short "+24 more" summary kept for the operator's screen); the
//         sanitised destination evidence carries the S3 code; and a DO fault and a genuinely-unset discovery
//         token are distinguishable failed items.
//   THE ATTACH / RE-ATTACH FAILURE. reattach-missing is the heal for the owner's #1 fear (a deploy wiping
//         the source bindings), and its failures are recorded rather than only returned as an HTTP response. The
//         plan itself reports its own gaps: a CONFLICTING claim is blocked out of the heal, and a MALFORMED
//         source is named in its own list.
//   THE GOVERNANCE REFUSAL'S REASON. governanceFaults carries a distinct member for every refusal cause rather
//         than one ("guard-refused"), because a refusal is never just "a guard said no" -- it is expired vs
//         self-approval vs a concurrent apply holding the lease vs a garbled change header. Four causes, four
//         distinguishable rows.
//   THE ADMIN-ROUTE OUTER CATCH. The update / rollback / ramp / licence routes record the exception behind a
//         "nothing was changed" response, because that sentence can be FALSE: the promote redeploys the engine
//         and the throw can land AFTER the new version is live.
//   THE AUTH-PLANE OUTAGE. Fail-open and fail-closed outage branches are told apart from genuine auth verdicts:
//         the diagnostic signal fires on every outage shape -- not only THROWN paths, but also the garbled-shape
//         and silent-downgrade branches. The pack stays informative during the lockout it explains.
//   THE RECOVERY-PATH REFUSAL. On the path where the pack may be the ONLY surviving artefact, a THROWN crypto
//         fault (a damaged kit) and a genuine signature MISMATCH (tamper) are told apart.
//   THE AUTO-HEAL SUB-CAUSE. refusedCode "signature" covers a truncated .sig, a rotated signer, a MIXED
//         rotation and a tamper, and the sub-cause names which. conflictingAtLatestGen says when two artefacts
//         claim the latest generation. A hand-renamed artefact is counted rather than silently ignored, and the
//         DO route carries the code through rather than dropping it.
//   THE OUTCOME ENUM MATCHES REALITY. A failed rollback records "rollback-failed", never "rolled-back", while
//         the customer is still serving the dead build; an unconfirmed promote records "applied-unconfirmed",
//         never "applied".
//
// THE BAR: a scenario is proven only once its evidence is in the BUNDLE, AND THE EVIDENCE ANSWERS THE QUESTION
// ASKED. So no hop is taken on trust, and every case ends on a DISCRIMINATION assertion: two states that could
// otherwise produce the same row must produce different ones. A recorder with no caller, a DO route no gatherer
// fetches, and a generic fault recorded where a discriminator is needed all fail here.
//
// NO-CUSTODY: every case plants customer SENTINELS at the fault site (a bucket, an account, an operator e-mail,
// a token, a Cloudflare message, a change number) and asserts that not one appears in ANY byte of the stored
// record, the projected section, or the whole bundle.
//
// Run: node test/validate-availability-evidence.ts

import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { makeScheduler, type MockStorage } from "./validate-scheduler-shared.ts";
import { handleDiscovery } from "../src/admin/router-discovery.ts";
import { runPreflight } from "../src/admin/preflight.ts";
import { classifyProbeError } from "../src/admin/preflight-probes.ts";
import { PREFLIGHT_BINDING_CAP, PREFLIGHT_ERROR_CLASSES, type PreflightItem } from "../src/admin/preflight-types.ts";
import { planRosterReattach } from "../src/admin/roster-reattach.ts";
import { applyAttachHealth, classifyAttachError, ATTACH_FAULT_CLASSES } from "../src/admin/discovery-health.ts";
import { applyAdminRouteError, applyRecoveryRefusal, ADMIN_ROUTE_STAGES } from "../src/admin/diag-records.ts";
import { canApprove, canReject, approvalKey, type RestoreApproval } from "../src/admin/approvals.ts";
import { seedBoundRole } from "./testutil.ts";
import { canApproveChange } from "../src/admin/change-control.ts";
import { canApproveOwnerAction } from "../src/admin/owner-action.ts";
import { decodeChangeHeaderWithFault } from "../src/admin/change-ref.ts";
import { GOVERNANCE_REFUSAL_REASONS, recordGovernanceRefusal, GOVERNANCE_REFUSALS_KEY } from "../src/sched/sched-fault-ledger.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { scanControlPlaneCandidates } from "../src/admin/control-plane.ts";
import { hybridVerifyDetailed, hybridSign } from "../src/crypto/sign.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { RECOVERY_REFUSAL_CLASSES } from "../src/admin/diag-records.ts";
import { CALLER_HEADER } from "../src/admin/identity.ts";
import { authRateLimited, requireStepUp } from "../src/admin/router-core.ts";
import { breakGlassRetiredViaDO, adminTokenRateLimitedViaDO, verifyPasskeySessionViaDO } from "../src/admin/router-session.ts";
import { settleAfterPromote } from "../src/admin/update-apply.ts";
import { settleAfterRamp } from "../src/admin/update-ramp.ts";
import { resolveRollbackTarget } from "../src/admin/router-core.ts";
import { fetchDiscoveryHealth, fetchSourcesDetached } from "../src/admin/support-sections-config.ts";
import { fetchAdminRouteErrors } from "../src/admin/support-sections-faults.ts";
import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";
import { fetchUpdateStatus } from "../src/admin/support-sections-runs.ts";
import { buildSupportBundle, SUPPORT_SECTION_NAMES } from "../src/admin/support.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

// makeRecipientPublic mints a recipient public key in the exact form loadRecipientPublic parses:
// b64url( x25519(32) || ML-KEM-1024 ek(1568) ) = 1600 bytes. The KEY MATERIAL is irrelevant here; what
// matters is that this slot PARSES, so the probe's failure can only be the OPERATIONAL one beside it.
function makeRecipientPublic(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(1600)));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- the CUSTOMER SENTINELS ------------------------------------------------------------------------------
// Each is planted at a real fault site below. None may appear in any recorded byte.
const SENTINEL_BUCKET = "acme-prod-customer-invoices";
const SENTINEL_ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const SENTINEL_EMAIL = "cfo@acme.example";
const SENTINEL_TOKEN = "cf-token-Ax9-SECRET-Vv1";
const SENTINEL_MESSAGE = "Authentication error (10000): token lacks com.cloudflare.edge.worker.write";
const SENTINEL_ENDPOINT = "https://s3.acme-internal.example/backups";
const SENTINEL_CHANGE = "CHG-0042-acme-payroll-migration";
const SENTINELS = [SENTINEL_BUCKET, SENTINEL_ACCOUNT_ID, SENTINEL_EMAIL, SENTINEL_TOKEN, SENTINEL_MESSAGE, SENTINEL_ENDPOINT, SENTINEL_CHANGE];

function scanForSentinels(v: unknown): string[] {
  const hay = JSON.stringify(v) ?? "";
  return SENTINELS.filter((s) => hay.includes(s));
}

// ---- the harness ------------------------------------------------------------------------------------------
// A REAL SchedulerDO over MockStorage: every recorder writes through the production route, the production
// applier and production storage, and every pack gatherer reads it back through the production route.
// The wrapper normalises the (string | Request) first argument production code passes into the Request the raw
// SchedulerDO expects, exactly as the DurableObjectStub does at runtime -- without it the DO sees a string and
// every route 500s on an "Invalid URL", which would silently turn every assertion below into a false pass.
type Sched = { storage: MockStorage; stub: DurableObjectStub };
function realScheduler(): Sched {
  const { storage, stub } = makeScheduler();
  const real = stub as unknown as { fetch(req: Request): Promise<Response> };
  const wrapped = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return real.fetch(input instanceof Request ? input : new Request(String(input), init));
    },
  } as unknown as DurableObjectStub;
  return { storage, stub: wrapped };
}

const OWNER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Caller;

function routerCtx(sched: Sched, env: Env, method: string, sub: string, body?: unknown): RouterCtx {
  const url = new URL(`https://engine.example/admin${sub}`);
  return {
    req: new Request(url.toString(), { method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }),
    env,
    url,
    scheduler: sched.stub,
    caller: OWNER,
    sub,
    sourceIp: null,
    runtime: undefined,
    verdict: { ok: true } as never,
  } as unknown as RouterCtx;
}

const item = (r: { items: PreflightItem[] }, id: string): PreflightItem | undefined => r.items.find((i) => i.id === id);

// ---------------------------------------------------------------------------------------------------------
// preflight carries its discriminators past the 60-80-char clamp and the 6-name cap.
// ---------------------------------------------------------------------------------------------------------
async function g130(): Promise<void> {
  console.log("\npreflight carries the discriminators, not a truncated sentence:");

  // A THIRTY-binding deploy drop. The roster names thirty source bindings and
  // the engine holds NONE of them (a bare `wrangler deploy` reset the worker's bindings).
  const thirty = Array.from({ length: 30 }, (_, i) => ({
    config: { id: `dp-${i}`, name: `pipe-${i}`, source: { type: "kv", binding: `KV_${String(i).padStart(2, "0")}`, namespaceId: `ns-${i}` } },
  }));
  const sched = realScheduler();
  await sched.stub.fetch(new Request("https://do/downpipes", { method: "GET" })); // warm the real DO
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      const p = new URL(req.url).pathname;
      if (p === "/downpipes") return new Response(JSON.stringify(thirty));
      if (p === "/tick-info") return new Response(JSON.stringify({ lastTickAt: Date.now() }));
      if (p === "/sources/discovery-config") throw new Error(`durable object unreachable while reading ${SENTINEL_ACCOUNT_ID}`);
      return sched.stub.fetch(req);
    },
  } as unknown as DurableObjectStub;

  // The env: the recipient keys are BOTH set and the OPERATIONAL one is garbage (so the report must say WHICH
  // env var is broken); the destination is misconfigured with a sentinel endpoint; and the
  // discovery config read FAULTS above while DISCOVERY_API_TOKEN is absent (a DO fault must not read as the same thing as a genuinely unset token).
  // A REAL, parseable break-glass recipient public: the whole point of the assertion is that the OPERATIONAL
  // slot is the broken one, which cannot be shown with a break-glass key that is itself unparseable.
  const goodRecipient = makeRecipientPublic();
  const env = {
    SIGNER_PRIVATE: "not-a-key",
    BREAK_GLASS_PUBLIC: goodRecipient,
    OPERATIONAL_PUBLIC: "totally-corrupt-paste",
    DEST_ENDPOINT: SENTINEL_ENDPOINT,
    DEST_BUCKET: SENTINEL_BUCKET,
  } as unknown as Env;

  const report = await runPreflight(env, stub);

  // ---- WHICH recipient key? ----
  const recipients = item(report, "recipients");
  ok("the recipients probe FAILS (as it always did)", recipients?.status === "failed");
  ok("DISCRIMINATOR: it names WHICH env var -- whichRecipient=operational, not a truncated parse message", recipients?.whichRecipient === "operational");
  ok("and its closed class says the key is SET and does not PARSE (not merely absent)", recipients?.probeErrorClass === "key-unparseable");

  // The break-glass slot is the OTHER state, and it must not collide with it. Same probe, opposite slot.
  const bgBroken = await runPreflight({ ...env, BREAK_GLASS_PUBLIC: "corrupt", OPERATIONAL_PUBLIC: undefined } as unknown as Env, stub);
  ok("DISCRIMINATION: a broken BREAK_GLASS key reports whichRecipient=break-glass -- a DIFFERENT row from the one above", item(bgBroken, "recipients")?.whichRecipient === "break-glass");

  // ---- the thirty dropped bindings ----
  const bindings = item(report, "source-bindings");
  ok("the source-bindings probe FAILS on a deploy that dropped every binding", bindings?.status === "failed");
  ok("DISCRIMINATOR: ALL THIRTY are named (the evidence line still says six; the structured list does not)", bindings?.missingBindingsTotal === 30 && (bindings?.missingBindings ?? []).length === 30);
  ok("the six-name evidence line is UNCHANGED (the operator's screen keeps its short summary)", (bindings?.evidence ?? "").includes("+24 more"));
  ok("the cap is the sourcesDetached precedent (64), so 30 rides whole and is not marked truncated", PREFLIGHT_BINDING_CAP === 64 && bindings?.missingBindingsTruncated === undefined);

  // ---- the destination's S3 code ----
  const dest = item(report, "destination");
  ok("the destination probe reports a class ALONGSIDE the truncated, sanitised prose", dest?.probeErrorClass !== undefined);
  ok("REDACTION: the sanitised evidence still carries no endpoint and no bucket", scanForSentinels(dest).length === 0);

  // ---- the token: DO-fault vs genuinely unset ----
  // With an API-based source configured, the token probe runs. The DO read THREW above and no env fallback is
  // set, so the resolver returns null -- exactly as it does when nobody ever pasted a token.
  const apiStub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      const p = new URL(req.url).pathname;
      if (p === "/downpipes") return new Response(JSON.stringify([{ config: { id: "dp-cf", name: "cf", source: { type: "cf-config" } } }]));
      if (p === "/tick-info") return new Response(JSON.stringify({ lastTickAt: Date.now() }));
      if (p === "/sources/discovery-config") throw new Error(`durable object unreachable while reading ${SENTINEL_ACCOUNT_ID}`);
      return sched.stub.fetch(req);
    },
  } as unknown as DurableObjectStub;
  const faulted = await runPreflight(env, apiStub);
  const tokFault = item(faulted, "api-source-discovery-token");
  ok("the token probe FAILS when no token resolves (unchanged)", tokFault?.status === "failed");
  ok("DISCRIMINATOR: tokenResolve=do-fault -- the scheduler could not be READ, the token may be perfectly fine", tokFault?.tokenResolve === "do-fault");

  const unsetStub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      const p = new URL(req.url).pathname;
      if (p === "/downpipes") return new Response(JSON.stringify([{ config: { id: "dp-cf", name: "cf", source: { type: "cf-config" } } }]));
      if (p === "/tick-info") return new Response(JSON.stringify({ lastTickAt: Date.now() }));
      if (p === "/sources/discovery-config") return new Response(JSON.stringify({ config: null }));
      return sched.stub.fetch(req);
    },
  } as unknown as DurableObjectStub;
  const unset = await runPreflight(env, unsetStub);
  const tokUnset = item(unset, "api-source-discovery-token");
  ok("DISCRIMINATION: a genuinely UNSET token reports tokenResolve=unset -- a DIFFERENT row from the DO fault", tokUnset?.tokenResolve === "unset");
  ok("and the two carry DIFFERENT closed classes (do-unreachable vs unconfigured), so they can never coalesce", tokFault?.probeErrorClass === "do-unreachable" && tokUnset?.probeErrorClass === "unconfigured");

  // ---- the classifier reads text ONLY to select an enum ----
  ok("CLASSIFIER: an ECONNREFUSED is TRANSPORT, never auth (the unanchored-/refus/ trap)", classifyProbeError(new Error("connect ECONNREFUSED 10.0.0.1:443")) === "transport");
  ok("CLASSIFIER: a 403 is auth; a 503 is unavailable; they can never be the same row", classifyProbeError(new Error("status 403")) === "auth" && classifyProbeError(new Error("HTTP 503")) === "unavailable");
  ok("REDACTION: the classifier RETURNS a closed member; the Cloudflare message it read never escapes", PREFLIGHT_ERROR_CLASSES.includes(classifyProbeError(new Error(SENTINEL_MESSAGE))) && !ATTACH_FAULT_CLASSES.includes(SENTINEL_MESSAGE as never));

  // ---- THE BUNDLE ----
  const bundle = await buildSupportBundle(env, stub);
  const pf = bundle.preflight as { items?: PreflightItem[] } | undefined;
  const packBindings = pf?.items?.find((i) => i.id === "source-bindings");
  ok("THE BUNDLE carries preflight with the STRUCTURED fields (it rides verbatim; nothing clamps them away)", (packBindings?.missingBindings ?? []).length === 30);
  ok("THE BUNDLE names which recipient key is broken", pf?.items?.find((i) => i.id === "recipients")?.whichRecipient === "operational");
  ok("REDACTION: the WHOLE BUNDLE carries no endpoint, bucket, account id or Cloudflare message", scanForSentinels(bundle).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the attach / re-attach failure, and what the heal plan reports about itself.
// ---------------------------------------------------------------------------------------------------------
async function g131(): Promise<void> {
  console.log("\nthe attach / re-attach failure and the plan's omissions reach the bundle:");
  const sched = realScheduler();

  // The ROSTER: one healthy binding, one CONFLICTING claim (two downpipes, same binding name, DIFFERENT
  // native ids), and one MALFORMED source (binding-backed, no binding name at all).
  const roster = [
    { id: "dp-ok", source: { type: "kv" as const, binding: "KV_OK", namespaceId: "ns-1" } },
    { id: "dp-a", source: { type: "r2" as const, binding: "R2_SHARED", bucketName: SENTINEL_BUCKET } },
    { id: "dp-b", source: { type: "r2" as const, binding: "R2_SHARED", bucketName: "someone-elses-bucket" } },
    { id: "dp-malformed", source: { type: "d1" as const, binding: "", databaseId: "db-9" } },
  ];
  const plan = planRosterReattach(roster as never, new Set<string>());
  ok("the CONFLICTING binding is blocked out of toAttach (unchanged safety)", plan.toAttach.every((a) => a.binding !== "R2_SHARED"));
  ok("DISCRIMINATOR: the MALFORMED source is REPORTED, not absent from all four of the plan's lists", plan.malformed.length === 1 && plan.malformed[0]?.downpipe === "dp-malformed");
  ok("REDACTION: the malformed row carries an engine-minted downpipe id and a closed type, never a bucket", scanForSentinels(plan.malformed).length === 0);

  // The pack's sourcesDetached projection, computed the SAME way the console's one-click heal computes it.
  const detachStub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      if (new URL(req.url).pathname === "/downpipes") return new Response(JSON.stringify(roster.map((r) => ({ config: r }))));
      return sched.stub.fetch(req);
    },
  } as unknown as DurableObjectStub;
  const detached = await fetchSourcesDetached({} as unknown as Env, detachStub);
  ok("THE PACK carries conflictingClaims (a binding the heal will NEVER fix, while reporting success)", detached.conflictingClaims === 1);
  ok("THE PACK carries malformedSources (the downpipe silently omitted from the heal plan)", detached.malformedSources === 1);
  ok("REDACTION: sourcesDetached carries binding LABELS and engine ids, never a bucket name", scanForSentinels(detached).length === 0);

  // The RE-ATTACH itself, driven through the real route: a token the engine will refuse as not token-shaped.
  const env = { WORKER_NAME: "downpipe-engine", CF_ACCOUNT_ID: SENTINEL_ACCOUNT_ID } as unknown as Env;
  const ctx = routerCtx(sched, env, "POST", "/sources/reattach-missing", { token: "not-a-token" });
  (ctx as { scheduler: DurableObjectStub }).scheduler = detachStub;
  const resp = await handleDiscovery({ ...ctx, scheduler: detachStub } as RouterCtx);
  ok("the re-attach route still REFUSES the bad token (this records; it does not gate)", resp?.status === 400);

  const stored = (await (await sched.stub.fetch(new Request("https://do/attach-health"))).json()) as { health?: Record<string, unknown> };
  const h = stored.health ?? {};
  const faults = (h.faults ?? {}) as Record<string, Record<string, number>>;
  ok("the fault site RECORDED (there was no recorder here at all: the refusal was an HTTP response and nothing else)", faults.reattach?.["token-invalid"] === 1);
  ok("DISCRIMINATOR: the plan SHAPE rides with it -- the heal knows it can never fix the conflicting claim", (h.lastPlan as Record<string, number>)?.conflictingClaims === 1);
  ok("and that the malformed source is not even in the plan", (h.lastPlan as Record<string, number>)?.malformedSources === 1);
  ok("REDACTION: the STORED attach record carries no token, account id, script name or binding name", scanForSentinels(h).length === 0);

  // DISCRIMINATION: the four causes of a failed re-attach must NOT coalesce.
  ok("CLASSIFIER: a 403 from Cloudflare is auth", classifyAttachError(new Error(`HTTP 403: ${SENTINEL_MESSAGE}`)) === "auth");
  ok("CLASSIFIER: a 5xx is unavailable -- never the same row as a bad token", classifyAttachError(new Error("HTTP 503")) === "unavailable");
  ok("CLASSIFIER: a TAGGED post-write alarm OUTRANKS the message: the write LANDED and the verify disagrees", classifyAttachError(new Error("HTTP 403"), true) === "binding-alarm");
  ok("CLASSIFIER: an ECONNREFUSED is transport, never auth", classifyAttachError(new Error("connect ECONNREFUSED")) === "transport");

  // The pure applier is the redaction chokepoint: an out-of-vocabulary op or class is DROPPED.
  const hostile = applyAttachHealth(undefined, { op: "reattach", fault: SENTINEL_MESSAGE, plan: { conflictingClaims: SENTINEL_BUCKET } }, 1000);
  // The VALUE is dropped, but the FAILURE is not: an out-of-vocabulary class never falls through to the success
  // branch, so a failed heal is never counted as a heal that worked.
  ok("CHOKEPOINT: an out-of-vocabulary fault class does not enter, and the attempt is still recorded as a FAILURE", hostile.faults.reattach?.unclassified === 1 && hostile.attempts.reattach === 1 && hostile.successes.reattach === undefined);
  ok("CHOKEPOINT: a non-numeric plan count is clamped to 0, never stored as a string", hostile.lastPlan?.conflictingClaims === 0);
  ok("CHOKEPOINT: an out-of-vocabulary OP records nothing at all", applyAttachHealth(undefined, { op: SENTINEL_BUCKET }, 1000).attempts.attach === undefined);

  const projected = await fetchDiscoveryHealth(sched.stub);
  const attach = projected.attach as Record<string, unknown> | undefined;
  ok("the pack projector reads the attach record back (it rides inside discoveryHealth)", (attach?.faults as Record<string, Record<string, number>>)?.reattach?.["token-invalid"] === 1);

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const dh = bundle.discoveryHealth as Record<string, unknown> | undefined;
  ok("THE BUNDLE CARRIES the attach / re-attach evidence", (dh?.attach as Record<string, unknown>) !== undefined);
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel", scanForSentinels(bundle).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the governance refusal's REASON, distinct from the generic "guard-refused".
// ---------------------------------------------------------------------------------------------------------
async function g182(): Promise<void> {
  console.log("\nthe governance refusal carries its closed reason:");

  const now = 1_000_000;
  const approval = (over: Record<string, unknown>) => ({ requesterSubject: "sub-maker", approverSubject: null, expiresAt: new Date(now + 60_000).toISOString(), status: "requested", ...over }) as never;

  // The FOUR states the ticket "my approved restore refuses to apply" actually covers. Each must be its own row.
  const expired = canApprove(approval({ expiresAt: new Date(now - 1).toISOString() }), null, "sub-checker", now);
  const selfApproval = canApprove(approval({}), null, "sub-maker", now);
  const applying = canApprove(approval({ status: "applying", appliedAt: new Date(now).toISOString() }), null, "sub-checker", now);
  const consumed = canApprove(approval({ status: "consumed" }), null, "sub-checker", now);
  ok("expired carries reasonCode=expired", !expired.ok && expired.reasonCode === "expired");
  ok("a SELF-approval carries reasonCode=self-approval", !selfApproval.ok && selfApproval.reasonCode === "self-approval");
  ok("a CONCURRENT apply holding the lease carries reasonCode=applying-lease", !applying.ok && applying.reasonCode === "applying-lease");
  ok("a spent approval carries reasonCode=consumed", !consumed.ok && consumed.reasonCode === "consumed");
  ok("DISCRIMINATION: all four are DIFFERENT codes, distinct rows rather than one 'guard-refused' row", new Set([expired, selfApproval, applying, consumed].map((v) => (v.ok ? "ok" : v.reasonCode))).size === 4);

  // the EMAIL floor is a self-approval too, even when the subjects genuinely differ -- the exact
  // case a single human holding two IdP-bound identities sharing one email exploited.
  const emailFloor = canApprove(approval({ requestedBy: "shared@x.example" }), "shared@x.example", "sub-second-identity", now);
  ok("same email, DIFFERENT subject is ALSO reasonCode=self-approval", !emailFloor.ok && emailFloor.reasonCode === "self-approval");
  const genuinelyDistinct = canApprove(approval({ requestedBy: "maker@x.example" }), "checker@x.example", "sub-checker", now);
  ok("a genuinely distinct email AND subject is NOT refused as a self-approval", genuinelyDistinct.ok);
  const rejected = canReject(approval({ status: "applying", appliedAt: new Date(now).toISOString() }), now);
  ok("a refused VETO during an in-flight apply is applying-lease too (the highest-signal event this machine makes)", !rejected.ok && rejected.reasonCode === "applying-lease");

  // The bare token can never be a checker, and a superseded change is a base-moved: two more collapsed rows.
  const bare = canApproveChange({ status: "pending", proposedBy: SENTINEL_EMAIL, proposedBySubject: "sub-maker", kind: "dest-set" } as never, null, null, true, now);
  ok("the bare break-glass token carries reasonCode=bare-token (it has no attributable identity)", !bare.ok && bare.reasonCode === "bare-token");
  const superseded = canApproveChange({ status: "superseded", proposedBy: SENTINEL_EMAIL, proposedBySubject: "sub-maker", kind: "dest-set" } as never, "checker@x", "sub-checker", true, now);
  ok("a superseded change carries reasonCode=base-moved (the config moved under the approver)", !superseded.ok && superseded.reasonCode === "base-moved");
  const notOwner = canApproveOwnerAction({ status: "pending", proposedBy: SENTINEL_EMAIL, proposedBySubject: "sub-maker", expiresAt: new Date(now + 60_000).toISOString() } as never, "checker@x", "sub-checker", false, now);
  ok("a non-owner approving an owner action carries reasonCode=not-owner", !notOwner.ok && notOwner.reasonCode === "not-owner");
  ok("REDACTION: the reasonCode is an enum; the prose (which interpolates the proposer's e-mail) is never it", ![expired, bare].some((v) => !v.ok && GOVERNANCE_REFUSAL_REASONS.includes(v.reasonCode) === false) && scanForSentinels([expired, bare].map((v) => (v.ok ? null : v.reasonCode))).length === 0);

  // THE CHANGE HEADER: "the console demands a change number I already entered".
  const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
  const good = decodeChangeHeaderWithFault(b64({ number: SENTINEL_CHANGE }));
  const garbled = decodeChangeHeaderWithFault("!!!not-base64url!!!");
  const truncated = decodeChangeHeaderWithFault(b64({ number: "" })); // the operator typed control chars
  const absent = decodeChangeHeaderWithFault(null);
  ok("a GOOD header yields the reference and no fault", good.ref?.number === SENTINEL_CHANGE && good.fault === null);
  ok("DISCRIMINATOR: a GARBLED header is reported as garbled -- the engine never saw the number they typed", garbled.ref === null && garbled.fault === "garbled");
  ok("DISCRIMINATOR: a header whose text NORMALISED AWAY is truncated, not missing", truncated.ref === null && truncated.fault === "truncated");
  ok("NOISE DISCIPLINE: an ABSENT header reports NO fault (the policy is off by default; most requests carry none)", absent.ref === null && absent.fault === null);

  // =========================================================================================================
  // THE DISCRIMINATION TEST: THE APPLY GATE.
  //
  // "Our approved restore refuses to apply" is a ticket the apply's FIRST approval check must classify. That
  // check is the read-only gateRestore, and a flat adminRefusal "restore-apply|not-approved" cannot tell an
  // approval that EXPIRED between approve and apply, from one already CONSUMED by an apply that actually
  // worked, from one whose apply is IN FLIGHT right now (the concurrent-apply loser, which reads to the
  // operator as a flat no), from one that was never approved at all. Four causes need four remedies, so
  // governanceRefusals must classify all four rather than staying empty while the pack's own legend advertises
  // restore-apply|expired and restore-apply|applying-lease as discriminators nothing writes.
  //
  // The one site that DOES classify (reserveRestore) is reached only AFTER the gate says usable, so it fires
  // only in the millisecond TOCTOU window between the two, never on the ticket.
  //
  // Every state below is driven through the REAL DO route (POST /restore/gate), the REAL classifier and the
  // REAL recorder. The assertion is that they produce DIFFERENT KEYS: a row must be recorded, and a distinct
  // row per cause.
  // =========================================================================================================
  // The restore-approval gate is OWNER-OPT-IN and OFF by default (an unconditional gate would lock
  // one-identity estates out of restore entirely). This section grades the gate's REFUSAL classification,
  // so it arms the policy: with it off there is no approval to refuse and no refusal to classify.
  const sched = realScheduler();
  await sched.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
  const iso = (ms: number): string => new Date(ms).toISOString();
  // `clear` names the approver fields a seed must REMOVE from the approved baseline. A record that was never
  // approved carries no approver at all, and absence is the state the gate reads; passing undefined would store
  // the keys holding undefined, which is a shape no real request path produces.
  // The maker and the checker hold their grants in the DO's OWN role table. The seeded records below are
  // hand-built rather than raised through the routes, so without this the SPEND-TIME identity binding
  // (approvals.ts approvalIdentitiesStillAuthorised) would correctly refuse every one of them as an authority
  // lapse -- including the HEALTHY control -- and this block would be measuring the wrong refusal.
  await seedBoundRole(sched.storage, "sub-maker", SENTINEL_EMAIL, "operator");
  await seedBoundRole(sched.storage, "sub-checker", "checker@acme.example", "approver");
  const seed = async (planHash: string, over: Partial<RestoreApproval>, clear: readonly ("approverSubject" | "approvedBy" | "approvedAt")[] = []): Promise<void> => {
    const record: RestoreApproval = {
      planHash,
      runId: "run-1",
      isLatest: true,
      plannedWrites: 3,
      bytes: 1024,
      redirectBinding: null,
      requesterSubject: "sub-maker",
      requestedBy: SENTINEL_EMAIL, // the requester's e-mail: a customer value, planted to prove it never rides
      requesterGroups: [],
      requestedAt: iso(Date.now() - 1000),
      reason: `restore ${SENTINEL_BUCKET} after the migration`, // free-text justification: also must never ride
      status: "approved",
      approverSubject: "sub-checker",
      approvedBy: SENTINEL_EMAIL,
      approvedAt: iso(Date.now() - 500),
      expiresAt: iso(Date.now() + 60_000),
      ...over,
    };
    for (const k of clear) delete record[k];
    await sched.storage.put(approvalKey(planHash), record);
  };
  const gate = async (planHash: string): Promise<boolean> => {
    const r = await sched.stub.fetch(
      new Request("https://do/restore/gate", { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } }),
    );
    return ((await r.json()) as { usable: boolean }).usable;
  };

  // The SIX apply-time worlds an operator can actually be in, each a real stored record, each driven through
  // the real gate. A HEALTHY approval is driven too, because a gate that records a fault on a legitimate
  // apply is a noise failure the recorder must refuse to produce.
  await seed("sha384:HEALTHY", {});
  await seed("sha384:EXPIRED", { expiresAt: iso(Date.now() - 1) });
  await seed("sha384:CONSUMED", { status: "consumed" });
  await seed("sha384:APPLYING", { status: "applying", appliedAt: iso(Date.now()) });
  await seed("sha384:PENDING", { status: "requested" }, ["approverSubject", "approvedBy", "approvedAt"]);
  await seed("sha384:SELF", { approverSubject: "sub-maker" }); // maker == checker
  const healthy = await gate("sha384:HEALTHY");
  const usable = [await gate("sha384:EXPIRED"), await gate("sha384:CONSUMED"), await gate("sha384:APPLYING"), await gate("sha384:PENDING"), await gate("sha384:SELF"), await gate("sha384:NEVER-RAISED")];

  ok("the HEALTHY approval still applies (the gate's verdict is unchanged: this is evidence, not a new guard)", healthy === true);
  ok("...and every one of the six refusals still refuses (fail-closed, unchanged)", usable.every((u) => u === false));

  const agg = (await sched.storage.get(GOVERNANCE_REFUSALS_KEY)) as Record<string, { count: number }>;
  ok("THE APPLY GATE NOW CLASSIFIES: an EXPIRED approval is its own row (raise a fresh request)", agg["restore-apply|expired"]?.count === 1);
  ok("a CONSUMED approval is its own row (an earlier apply ALREADY WORKED: the retry is the mistake)", agg["restore-apply|consumed"]?.count === 1);
  ok("a CONCURRENT apply holding the lease is its own row (wait; do not raise anything)", agg["restore-apply|applying-lease"]?.count === 1);
  ok("one that was never approved is its own row (the console badge is stale: get a second person)", agg["restore-apply|pending"]?.count === 1);
  ok("a SELF-approval is its own row", agg["restore-apply|self-approval"]?.count === 1);
  ok("a plan nobody ever raised is its own row (distinct from a record that exists and is unapproved)", agg["restore-apply|no-such-request"]?.count === 1);
  ok(
    "DISCRIMINATION: the six states produce SIX DIFFERENT ROWS rather than one (restore-apply|not-approved), so governanceRefusals is never empty",
    new Set(Object.keys(agg).filter((k) => k.startsWith("restore-apply|"))).size === 6,
  );
  ok("NOISE DISCIPLINE: the HEALTHY apply recorded NOTHING (a signal that cries wolf devalues every true one)", (agg["restore-apply|terminal-state"]?.count ?? 0) === 0 && Object.keys(agg).length === 6);
  ok("REDACTION: the requester e-mail and the free-text justification on the stored record NEVER ride", scanForSentinels(agg).length === 0);

  // THE SECONDARY COALESCENCE TO AVOID: a refused VETO recorded under "restore-approve" would put "the approval
  // was refused" and "our reject of a live restore kept failing while the apply went through" -- the
  // highest-signal event this machine produces -- on the SAME key.
  await sched.stub.fetch(
    new Request("https://do/restore/reject", {
      method: "POST",
      body: JSON.stringify({ planHash: "sha384:APPLYING" }),
      headers: { "content-type": "application/json", [CALLER_HEADER]: Buffer.from(JSON.stringify({ method: "access", email: SENTINEL_EMAIL, subject: "sub-checker", role: "owner" })).toString("base64url") },
    }),
  );
  const agg2 = (await sched.storage.get(GOVERNANCE_REFUSALS_KEY)) as Record<string, { count: number }>;
  ok("a refused VETO of an in-flight restore records under its OWN stage (restore-reject)", agg2["restore-reject|applying-lease"]?.count === 1);
  ok("DISCRIMINATION: it can no longer coalesce with a refused APPROVAL (restore-approve|applying-lease)", agg2["restore-approve|applying-lease"] === undefined);

  // The CHOKEPOINT, on the pure recorder: nothing out of vocabulary can widen the key space.
  const storage = sched.storage as unknown as Parameters<typeof recordGovernanceRefusal>[0];
  await recordGovernanceRefusal(storage, "change-ref", "change-ref-garbled");
  await recordGovernanceRefusal(storage, "role-escalation", "escalation-refused");
  const keysBefore = Object.keys((await sched.storage.get(GOVERNANCE_REFUSALS_KEY)) as object).length;
  await recordGovernanceRefusal(storage, SENTINEL_BUCKET as never, "expired"); // hostile: out of vocabulary
  await recordGovernanceRefusal(storage, "restore-apply", SENTINEL_MESSAGE as never); // hostile: out of vocabulary
  const agg3 = (await sched.storage.get(GOVERNANCE_REFUSALS_KEY)) as Record<string, { count: number }>;
  ok("the change-header fault and the ESCALATION attempt are their own rows", agg3["change-ref|change-ref-garbled"]?.count === 1 && agg3["role-escalation|escalation-refused"]?.count === 1);
  ok("CHOKEPOINT: an out-of-vocabulary stage or reason records NOTHING (the key space cannot be widened)", Object.keys(agg3).length === keysBefore);

  type CountRow = { count: number; lastAt?: string };
  const diag = await fetchSchedDiag(sched.stub);
  const projected = (diag as { governanceRefusals?: Record<string, CountRow> }).governanceRefusals;
  ok("the pack projector reads governanceRefusals back", projected?.["restore-apply|expired"]?.count === 1);
  ok(
    "DISCRIMINATION IN THE PACK: expired / consumed / applying-lease / pending survive the projection as FOUR rows",
    projected?.["restore-apply|expired"]?.count === 1 && projected?.["restore-apply|consumed"]?.count === 1 && projected?.["restore-apply|applying-lease"]?.count === 1 && projected?.["restore-apply|pending"]?.count === 1,
  );
  ok("CHOKEPOINT (pack): the hostile stage/reason never reach the projection either", Object.keys(projected ?? {}).length === keysBefore);

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const sd = bundle.schedDiag as { governanceRefusals?: Record<string, CountRow> } | undefined;
  ok("THE BUNDLE CARRIES governanceRefusals", sd?.governanceRefusals?.["role-escalation|escalation-refused"]?.count === 1);
  ok("THE BUNDLE separates the refused VETO from the refused APPROVAL", sd?.governanceRefusals?.["restore-reject|applying-lease"]?.count === 1);
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel", scanForSentinels(bundle).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the admin-route outer catch, and the "nothing was changed" claim it cannot support unaided.
// ---------------------------------------------------------------------------------------------------------
async function g183(): Promise<void> {
  console.log("\nthe admin-route outer catch records its locus and how far it got:");
  const sched = realScheduler();

  // The REAL recorder, through the REAL route, into the REAL applier.
  const post = async (route: string, stage: string): Promise<void> => {
    await sched.stub.fetch(new Request("https://do/diag/admin-route-error", { method: "POST", body: JSON.stringify({ route, stage }), headers: { "content-type": "application/json" } }));
  };
  await post("update-apply", "channel-fetch");
  await post("update-apply", "channel-fetch");
  await post("update-apply", "deploy-driver"); // the one where "nothing was changed" may be a LIE
  await post("licence-activate", "do-read");
  await post(SENTINEL_BUCKET, "do-read"); // hostile: out of vocabulary
  await post("update-apply", SENTINEL_MESSAGE); // hostile: out of vocabulary

  const stored = (await (await sched.stub.fetch(new Request("https://do/admin-route-errors"))).json()) as { errors?: Record<string, unknown> };
  const e = stored.errors ?? {};
  const by = (e.byRouteStage ?? {}) as Record<string, number>;
  ok("the fault site RECORDED (these catches otherwise write nothing, anywhere)", by["update-apply|channel-fetch"] === 2);
  ok("DISCRIMINATOR: the LOCUS -- a channel-fetch fault is the signed channel, not Cloudflare's deploy API", by["update-apply|deploy-driver"] === 1 && by["licence-activate|do-read"] === 1);
  ok("DISCRIMINATOR: mutatingFaults counts the faults where 'nothing was changed' is NOT safe to believe", e.mutatingFaults === 1);
  ok("...and it counts ONLY those: the two channel-fetch faults genuinely changed nothing", e.total === 4);
  ok("CHOKEPOINT: an out-of-vocabulary route or stage records NOTHING", Object.keys(by).length === 3);
  ok("REDACTION: the STORED record is two enums and integers; the exception text never persists", scanForSentinels(e).length === 0);

  // The pure applier's own contract.
  const clean = applyAdminRouteError(undefined, { route: "ramp-start", stage: "persist" }, 5000);
  ok("APPLIER: a persist-stage fault is MUTATING (the split is live and the record of it did not land)", clean.mutatingFaults === 1 && clean.lastStage === "persist");
  ok("APPLIER: the closed stage vocabulary is ordered by how much may have changed", ADMIN_ROUTE_STAGES.indexOf("do-read") < ADMIN_ROUTE_STAGES.indexOf("deploy-driver"));

  const projected = await fetchAdminRouteErrors(sched.stub);
  ok("the pack projector reads it back", (projected.byRouteStage as Record<string, number>)?.["update-apply|deploy-driver"] === 1);

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const are = bundle.adminRouteErrors as Record<string, unknown> | undefined;
  ok("THE BUNDLE CARRIES adminRouteErrors", are !== undefined && are.mutatingFaults === 1);
  ok("adminRouteErrors is on the closed roster, so it cannot slip past the sections health vector", SUPPORT_SECTION_NAMES.includes("adminRouteErrors" as never));
  ok("the sections vector reports it gathered (ok), not error", (bundle.sections as Record<string, string>).adminRouteErrors === "ok");
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel", scanForSentinels(bundle).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the auth-plane outage branches, told apart from genuine verdicts.
// ---------------------------------------------------------------------------------------------------------
async function g201(): Promise<void> {
  console.log("\nthe auth-plane outage is told apart from the auth verdict:");

  // The vocabulary must ADMIT each state. A name the engine fires and the aggregate does not know is a counter
  // that silently stops incrementing during the lockout it exists to explain.
  for (const n of ["session-verify-unavailable", "session-verify-verdict-malformed", "session-shape-invalid", "stepup-check-unavailable", "stepup-check-verdict-malformed", "limiter-verdict-malformed", "caller-verdict-degraded", "admin-token-ratelimited-overcap", "admin-token-ratelimited-unavailable"]) {
    ok(`the closed vocabulary admits ${n}`, AUTH_SIGNAL_NAMES.includes(n as never));
  }
  ok("DISCRIMINATION: the break-glass OVER-CAP and the limiter OUTAGE are two names, not one", AUTH_SIGNAL_NAMES.includes("admin-token-ratelimited-overcap" as never) && AUTH_SIGNAL_NAMES.includes("admin-token-ratelimited-unavailable" as never));

  // =========================================================================================================
  // THE DISCRIMINATION TEST, and THE MECHANISM AN OUTER-CATCH-ONLY WIRING MISSES.
  //
  // scheduler.fetch() does NOT throw on an HTTP error status. The SchedulerDO's own outer catch answers a JSON
  // 500 {"error":"internal error"}. So an UP-BUT-BROKEN limiter DO (a storage fault, a TypeError, deploy/route
  // drift) is an ANSWERED OUTAGE: resp.json() parses, the verdict field is simply absent, NO catch runs -- and
  // the fail-closed gates then substitute a denial that is byte-identical to the genuine verdict. Wiring only
  // the CATCH arms leaves the three tickets below unanswerable, and can file one of them
  // as the OPPOSITE of the truth. The gates below classify the answered-but-broken shape explicitly, so none of
  // that happens.
  //
  // Each gate is driven for real, against three DOs: one that ANSWERS RUBBISH (the outage), one that THROWS
  // (the unreachable DO) and one that gives the GENUINE verdict. Three states, three different rows.
  // =========================================================================================================
  const stubThat = (mode: "answers-rubbish" | "throws" | "genuine", genuine: Record<string, unknown>): { stub: DurableObjectStub; fired: string[] } => {
    const fired: string[] = [];
    const stub = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        // The auth-signal POST is the recorder under test: capture what the gate actually fired.
        if (url.endsWith("/auth-signal")) {
          const body = init?.body ?? (input instanceof Request ? await input.text() : "{}");
          fired.push((JSON.parse(String(body)) as { name: string }).name);
          return new Response("{}", { headers: { "content-type": "application/json" } });
        }
        if (mode === "throws") throw new TypeError("Network connection lost"); // the DO is UNREACHABLE
        // The DO is UP AND BROKEN: its outer catch answers a JSON 500 that carries no verdict at all. This is
        // the shape that never reached a catch, and therefore never recorded anything.
        if (mode === "answers-rubbish") return new Response(JSON.stringify({ error: "internal error", errorId: "e-1" }), { status: 500, headers: { "content-type": "application/json" } });
        return new Response(JSON.stringify(genuine), { headers: { "content-type": "application/json" } });
      },
    } as unknown as DurableObjectStub;
    return { stub, fired };
  };
  const req = new Request("https://engine/admin/x", { headers: { "cf-connecting-ip": "203.0.113.7" } });

  // ---- SITE 1: authRateLimited, the "ALL SIGN-INS 429" ticket -------------------------------------------
  // The sign-in limiter fails CLOSED, so every non-admit answer returns the same 429. A genuine over-cap
  // records auth-ratelimited (the DO's own auto-signal on `ip:` keys); an ANSWERED-but-broken limiter DO
  // recorded NOTHING AT ALL, so the pack during "nobody in the company can sign in" was byte-identical to a
  // healthy quiet day.
  const s1Broken = stubThat("answers-rubbish", {});
  const s1Down = stubThat("throws", {});
  const s1Overcap = stubThat("genuine", { allowed: false, retryAfterMs: 30_000 });
  const s1Healthy = stubThat("genuine", { allowed: true });
  const r1Broken = await authRateLimited(s1Broken.stub, req);
  const r1Down = await authRateLimited(s1Down.stub, req);
  const r1Overcap = await authRateLimited(s1Overcap.stub, req);
  const r1Healthy = await authRateLimited(s1Healthy.stub, req);
  ok("the sign-in limiter still fails CLOSED on a broken DO (the 429 is unchanged)", r1Broken?.status === 429 && r1Down?.status === 429 && r1Overcap?.status === 429);
  ok("SITE 1 an ANSWERED-BUT-BROKEN limiter fires auth-limiter-verdict-malformed (it fired NOTHING before)", s1Broken.fired.includes("auth-limiter-verdict-malformed"));
  ok("SITE 1 an UNREACHABLE limiter fires auth-limiter-unavailable -- a DIFFERENT row", s1Down.fired.includes("auth-limiter-unavailable") && !s1Down.fired.includes("auth-limiter-verdict-malformed"));
  ok("SITE 1 DISCRIMINATION: the answered outage and the unreachable DO are two different names", s1Broken.fired.join() !== s1Down.fired.join());
  ok("SITE 1 NOISE: a GENUINE over-cap fires no fault here (the limiter is WORKING; the DO counts it)", s1Overcap.fired.length === 0);
  ok("SITE 1 NOISE: a healthy admit fires nothing and admits the request", r1Healthy === null && s1Healthy.fired.length === 0);

  // ---- SITE 2: breakGlassRetiredViaDO, the "MY BREAK-GLASS TOKEN STOPPED WORKING" ticket -----------------
  // Three ways the token is denied, each needing its own trace. An INTENTIONAL retire records
  // nothing (correct: the Owner asked for exactly this), so an answered-but-rotten retire check must stay
  // distinguishable in the pack from a retire the customer never performed.
  const s2Broken = stubThat("answers-rubbish", {});
  const s2Down = stubThat("throws", {});
  const s2Retired = stubThat("genuine", { breakGlassTokenRetired: true });
  const s2Live = stubThat("genuine", { breakGlassTokenRetired: false });
  const denyBroken = await breakGlassRetiredViaDO(s2Broken.stub);
  const denyDown = await breakGlassRetiredViaDO(s2Down.stub);
  const denyRetired = await breakGlassRetiredViaDO(s2Retired.stub);
  const denyLive = await breakGlassRetiredViaDO(s2Live.stub);
  ok("the retire check still fails CLOSED on a broken DO (the token is denied, unchanged)", denyBroken === true && denyDown === true && denyRetired === true && denyLive === false);
  ok("SITE 2 an ANSWERED-BUT-BROKEN retire check fires break-glass-check-shape-invalid (it fired NOTHING before)", s2Broken.fired.includes("break-glass-check-shape-invalid"));
  ok("SITE 2 an UNREACHABLE DO fires break-glass-check-unavailable -- a DIFFERENT row", s2Down.fired.includes("break-glass-check-unavailable") && !s2Down.fired.includes("break-glass-check-shape-invalid"));
  ok("SITE 2 DISCRIMINATION: a broken check is no longer identical to an INTENTIONAL retire, which fires nothing", s2Broken.fired.length > 0 && s2Retired.fired.length === 0);
  ok("SITE 2 NOISE: a live, un-retired token fires nothing", s2Live.fired.length === 0);

  // ---- SITE 3: adminTokenRateLimitedViaDO, THE ANTI-GOAL TO AVOID -----------------------------------
  // Firing -overcap on ANY non-admit answer would file an up-but-broken limiter DO as "the
  // limiter is WORKING and someone is guessing your break-glass token" and send the ticket hunting an attacker
  // who does not exist. -overcap is gated STRICTLY on an explicit allowed === false.
  const s3Broken = stubThat("answers-rubbish", {});
  const s3Down = stubThat("throws", {});
  const s3Overcap = stubThat("genuine", { allowed: false });
  const s3Healthy = stubThat("genuine", { allowed: true });
  const limBroken = await adminTokenRateLimitedViaDO(s3Broken.stub, req);
  const limDown = await adminTokenRateLimitedViaDO(s3Down.stub, req);
  const limOvercap = await adminTokenRateLimitedViaDO(s3Overcap.stub, req);
  const limHealthy = await adminTokenRateLimitedViaDO(s3Healthy.stub, req);
  ok("the break-glass limiter still fails CLOSED (the denial is unchanged)", limBroken === true && limDown === true && limOvercap === true && limHealthy === false);
  ok("SITE 3 a GENUINE over-cap is the ONLY state filed as throttling", s3Overcap.fired.includes("admin-token-ratelimited-overcap"));
  ok("SITE 3 THE ANTI-GOAL IS GONE: an ANSWERED-BUT-BROKEN limiter is NOT filed as an attack", !s3Broken.fired.includes("admin-token-ratelimited-overcap") && s3Broken.fired.includes("admin-token-ratelimited-malformed"));
  ok("SITE 3 an UNREACHABLE limiter is its own row again", s3Down.fired.includes("admin-token-ratelimited-unavailable") && !s3Down.fired.includes("admin-token-ratelimited-overcap"));
  ok(
    "SITE 3 DISCRIMINATION: over-cap / answered-broken / unreachable are THREE different names -- an outage can no longer wear a throttle's clothes",
    new Set([s3Overcap.fired.filter((f) => f !== "admin-token-ratelimited").join(), s3Broken.fired.filter((f) => f !== "admin-token-ratelimited").join(), s3Down.fired.join()]).size === 3,
  );
  ok("SITE 3 NOISE: a healthy admit fires nothing at all", s3Healthy.fired.length === 0);

  // ---- SITE 4: verifyPasskeySessionViaDO, the "WHOLE TEAM GOT LOGGED OUT FOR AN HOUR" ticket ------------
  // THE GUARD MUST NOT INVERT ITS TWO FAULT STATES.
  //
  // passkeySessionVerify answers { email: null } on all SIX of its ordinary rejection paths (no token, a bad
  // MAC, an expired token, an email-epoch revoke, a subject-epoch revoke, a connection-epoch revoke). A guard
  // asking `res.email !== undefined` would treat those the same as an up-but-broken DO, because `null !==
  // undefined` is TRUE, so:
  //   - a LEGITIMATE EXPIRED COOKIE would fire session-shape-invalid. On the hottest path in the product, on every
  //     stale page load, and on every session on the estate after a terminate-all or an epoch bump -- as an
  //     EXACT-COUNT signal, so a storage write per rejected request. A fault that fires on a legitimate state
  //     devalues every true one.
  //   - the ACTUAL up-but-broken DO -- the state that signs the whole company out -- would record NOTHING, and
  //     its pack would be byte-identical to a healthy quiet day.
  // The DO returns an explicit closed `verdict` and the guard keys on THAT, which is the contract rather
  // than a guess about the payload.
  const sessionOf = (email: string): Record<string, unknown> => ({ verdict: "verified", email, subject: `passkey:${email}`, method: "passkey", connId: null, groups: [] });
  const s4Broken = stubThat("answers-rubbish", {});
  const s4Down = stubThat("throws", {});
  const s4Expired = stubThat("genuine", { verdict: "rejected", email: null }); // THE LEGITIMATE STATE: an expired / revoked / absent cookie
  const s4Rotten = stubThat("genuine", { verdict: "verified", email: null, subject: null, method: "passkey" }); // answered VERIFIED and broke its own contract
  const s4Healthy = stubThat("genuine", sessionOf("owner@example.test"));
  const v4Broken = await verifyPasskeySessionViaDO(s4Broken.stub, "cookie");
  const v4Down = await verifyPasskeySessionViaDO(s4Down.stub, "cookie");
  const v4Expired = await verifyPasskeySessionViaDO(s4Expired.stub, "cookie");
  const v4Rotten = await verifyPasskeySessionViaDO(s4Rotten.stub, "cookie");
  const v4Healthy = await verifyPasskeySessionViaDO(s4Healthy.stub, "cookie");
  ok("SITE 4 the session verify still fails CLOSED on every non-verified answer (the denial is unchanged)", v4Broken === null && v4Down === null && v4Expired === null && v4Rotten === null);
  ok("SITE 4 a healthy cookie still verifies (the hot path is untouched)", v4Healthy?.email === "owner@example.test");
  ok("SITE 4 THE NOISE DEFECT IS DEAD: a LEGITIMATE expired / revoked cookie fires NOTHING AT ALL", s4Expired.fired.length === 0);
  ok("SITE 4 THE OUTAGE IS LOUD: an ANSWERED-BUT-BROKEN session DO fires session-verify-verdict-malformed (it fired NOTHING before)", s4Broken.fired.includes("session-verify-verdict-malformed"));
  ok("SITE 4 an UNREACHABLE session DO fires session-verify-unavailable -- a DIFFERENT row", s4Down.fired.includes("session-verify-unavailable") && !s4Down.fired.includes("session-verify-verdict-malformed"));
  ok("SITE 4 a DO that answers 'verified' and breaks its own contract fires session-shape-invalid -- a THIRD row", s4Rotten.fired.join() === "session-shape-invalid");
  ok(
    "SITE 4 DISCRIMINATION: expired cookie / answered-broken DO / unreachable DO / rotten accept / healthy are FIVE DIFFERENT rows, and the two legitimate states are the two silent ones",
    new Set([s4Expired.fired.join(), s4Broken.fired.join(), s4Down.fired.join(), s4Rotten.fired.join(), s4Healthy.fired.join()]).size === 4 && s4Expired.fired.length === 0 && s4Healthy.fired.length === 0,
  );

  // ---- SITE 5: requireStepUp, the "IT KEEPS DEMANDING A PASSKEY AND NEVER ACCEPTS IT" ticket ------------
  // Wiring only the CATCH arm would let an answered-but-broken step-up DO fall through to a bare 401 with no
  // classification -- the SAME 401 the ceremony legitimately OPENS with, collapsing the outage and the healthy
  // prompt into one state. stepUpCheck's contract is total ({ satisfied: boolean } on every path), so a
  // non-boolean marks a DO that never ran it, and an explicit `false` is the ceremony working exactly as designed.
  const stepReq = new Request("https://engine/admin/x", { method: "POST", headers: { cookie: "dp_session=cookie" } });
  const s5Broken = stubThat("answers-rubbish", {});
  const s5Down = stubThat("throws", {});
  const s5NotYet = stubThat("genuine", { satisfied: false }); // THE LEGITIMATE STATE: the ceremony's opening move
  const s5Satisfied = stubThat("genuine", { satisfied: true });
  const u5Broken = await requireStepUp(stepReq, s5Broken.stub, "passkey");
  const u5Down = await requireStepUp(stepReq, s5Down.stub, "passkey");
  const u5NotYet = await requireStepUp(stepReq, s5NotYet.stub, "passkey");
  const u5Satisfied = await requireStepUp(stepReq, s5Satisfied.stub, "passkey");
  ok("SITE 5 step-up still fails CLOSED on a broken or unreachable DO (the 401 is unchanged)", u5Broken?.status === 401 && u5Down?.status === 401 && u5NotYet?.status === 401);
  ok("SITE 5 a satisfied step-up still proceeds (the sensitive action is not blocked)", u5Satisfied === null);
  ok("SITE 5 NOISE: the ceremony's own opening 401 (satisfied:false) fires NOTHING -- recording it would put a phantom fault on every successful step-up", s5NotYet.fired.length === 0 && s5Satisfied.fired.length === 0);
  ok("SITE 5 THE OUTAGE IS LOUD: an ANSWERED-BUT-BROKEN step-up DO fires stepup-check-verdict-malformed (it fired NOTHING before)", s5Broken.fired.join() === "stepup-check-verdict-malformed");
  ok("SITE 5 an UNREACHABLE step-up DO fires stepup-check-unavailable -- a DIFFERENT row", s5Down.fired.join() === "stepup-check-unavailable");
  ok(
    "SITE 5 DISCRIMINATION: not-yet-stepped-up / answered-broken / unreachable are THREE rows, and the legitimate one is the silent one",
    new Set([s5NotYet.fired.join(), s5Broken.fired.join(), s5Down.fired.join()]).size === 3 && s5NotYet.fired.length === 0,
  );

  // ---- THE AGGREGATE + THE BUNDLE, through the REAL DO route and the REAL pack gatherer ------------------
  const sched = realScheduler();
  const fire = async (name: string): Promise<void> => {
    await sched.stub.fetch(new Request("https://do/auth-signal", { method: "POST", body: JSON.stringify({ name }), headers: { "content-type": "application/json" } }));
  };
  // Every name below is one a REAL caller fired above, not a string handed to the recorder: that is the whole
  // difference between proving the plumbing and proving the discrimination. caller-verdict-degraded is the one
  // exception (its caller is the role resolver, driven elsewhere).
  for (const n of [...s1Broken.fired, ...s2Broken.fired, ...s3Broken.fired, ...s3Overcap.fired, ...s4Broken.fired, ...s4Down.fired, ...s4Rotten.fired, ...s5Broken.fired, ...s5Down.fired, "caller-verdict-degraded"]) await fire(n);
  await fire(SENTINEL_EMAIL); // hostile: an out-of-vocabulary name

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const signals = bundle.authSignals as Record<string, { count: number }> | undefined;
  ok("THE BUNDLE CARRIES the step-up OUTAGE ('it keeps demanding a passkey and never accepts it')", signals?.["stepup-check-unavailable"]?.count === 1 && signals?.["stepup-check-verdict-malformed"]?.count === 1);
  ok("THE BUNDLE CARRIES the session-verify OUTAGE ('the whole team got logged out for an hour')", signals?.["session-verify-verdict-malformed"]?.count === 1 && signals?.["session-verify-unavailable"]?.count === 1 && signals?.["session-shape-invalid"]?.count === 1);
  ok("THE BUNDLE CARRIES the silent viewer DOWNGRADE ('I am an owner but I am treated as a viewer')", signals?.["caller-verdict-degraded"]?.count === 1);
  ok("THE BUNDLE separates the break-glass THROTTLE from the ANSWERED limiter OUTAGE", signals?.["admin-token-ratelimited-overcap"]?.count === 1 && signals?.["admin-token-ratelimited-malformed"]?.count === 1);
  ok("THE BUNDLE carries the answered sign-in-limiter outage ('all sign-ins 429', third form)", signals?.["auth-limiter-verdict-malformed"]?.count === 1);
  ok("THE BUNDLE carries the answered break-glass retire-check fault", signals?.["break-glass-check-shape-invalid"]?.count === 1);
  ok("CHOKEPOINT: an out-of-vocabulary signal name never enters the aggregate", signals?.[SENTINEL_EMAIL] === undefined);
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel (counts and closed names only)", scanForSentinels(bundle).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the recovery path, where the pack may be the only artefact that survives.
// ---------------------------------------------------------------------------------------------------------
async function g202g218(): Promise<void> {
  console.log("\nthe recovery refusal names its cause:");
  const sched = realScheduler();

  // ---- the damaged KIT and the tampered EXPORT must not be the same refusal ----
  const refuse = async (surface: string, cls: string): Promise<void> => {
    await sched.stub.fetch(new Request("https://do/diag/recovery-refusal", { method: "POST", body: JSON.stringify({ surface, cls }), headers: { "content-type": "application/json" } }));
  };
  // ===========================================================================================================
  // THE CRYPTO VERDICT THE THREE RECOVERY ROUTES MAP FROM.
  //
  // A LENGTH CHECK ON THE SIGNATURE STRING (`signatureDecodes`) is a pure function of the signature and CANNOT
  // SEE THE KEY AT ALL, so it must not stand in for this verdict. A recovery-kit signer.pub that
  // is the correct 2624 bytes and CORRUPT -- bit rot, a partially restored file, the wrong same-size key --
  // would sail through a length check, fail inside the total verify, and record as `signature`:
  // BYTE-IDENTICAL to a genuinely ALTERED export. That would tell the support engineer "your recovery artefact
  // was tampered with" when the truth is "your kit file is damaged, take another copy". On the disaster-
  // recovery path, where the pack may be the only artefact that survives, that is the worst possible inversion.
  //
  // hybridVerifyDetailed computes the honest verdict. Four worlds, four verdicts, four remedies.
  // ===========================================================================================================
  const signer = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
  const verifier = verifierFrom(signer);
  const message = new TextEncoder().encode(`the estate export for ${SENTINEL_BUCKET}`);
  const goodSig = await hybridSign(signer.edPrivate, signer.mldsaSecret, message);
  ok("an intact export under the right kit key VERIFIES (the healthy path is untouched)", (await hybridVerifyDetailed(verifier, message, goodSig)) === "ok");

  // WORLD 1: the .sig FILE is truncated / half-written. Nothing was ever checked. Re-copy the signature.
  const vSigFile = await hybridVerifyDetailed(verifier, message, goodSig.slice(0, 40));
  // WORLD 2: the EXPORT was ALTERED, under the correct key. This is the ONLY world that is tamper.
  const vTamper = await hybridVerifyDetailed(verifier, new TextEncoder().encode(`the estate export for ${SENTINEL_BUCKET} PLUS ONE EXTRA DOWNPIPE`), goodSig);
  // WORLD 3: THE KIT KEY'S ML-DSA HALF HAS ROTTED. Right length, so parseVerifier admits it; the classical half
  // still verifies, so the export is provably INTACT. A length-only check would call this state TAMPER.
  const rotted = Uint8Array.from(verifier.mldsa);
  rotted[7] = rotted[7]! ^ 0xff;
  const vRottedKey = await hybridVerifyDetailed({ ed: verifier.ed, mldsa: rotted }, message, goodSig);
  // WORLD 4: the kit key will not IMPORT at all (a mangled kit file). Re-copy the key.
  const vUnimportable = await hybridVerifyDetailed({ ed: new Uint8Array(3), mldsa: verifier.mldsa }, message, goodSig);

  ok("WORLD 1 a TRUNCATED .sig is sig-decode: the signature FILE is damaged, and nothing was ever checked", vSigFile === "sig-decode");
  ok("WORLD 2 an ALTERED export is ed25519-mismatch: TAMPER LIVES HERE, and only here", vTamper === "ed25519-mismatch");
  ok("WORLD 3 a CORRUPT (right-length) kit key is mldsa-mismatch -- NOT the tamper verdict. This is the inversion the gap exists to stop", vRottedKey === "mldsa-mismatch" && vRottedKey !== vTamper);
  ok("WORLD 4 an UNIMPORTABLE kit key is verifier-invalid: the KEY is corrupt, the export is innocent", vUnimportable === "verifier-invalid");

  // ===========================================================================================================
  // WORLDS 5-7: THE DAMAGE IN THE *CLASSICAL* HALF OF THE KEY -- and why the verify must not short-circuit.
  //
  // Checking the classical half FIRST and RETURNING THE INSTANT IT FAILS would throw the
  // second half away. Both halves sign the SAME message bytes, so the second half is a free discriminator, and
  // discarding it would collapse a corrupt kit file, a partially-restored key and a half-written key into the SAME
  // row as a real tamper. The customer whose signer.pub had rotted would be told their disaster-recovery artefact
  // had been ATTACKED -- the worst possible inversion on the one path where the artefact
  // in front of them may be the only one left.
  //
  // If the ML-DSA half VERIFIES, it verified THESE EXACT EXPORT BYTES under this kit's own key. The export is
  // therefore PROVABLY INTACT and the damage is in the Ed25519 half of the KEY. It is never tamper: altering
  // the export breaks BOTH halves.
  // ===========================================================================================================
  // WORLD 5: BIT ROT in the Ed25519 half of the kit key. Right length, so parseVerifier admits it.
  const edRot = Uint8Array.from(verifier.ed);
  edRot[3] = edRot[3]! ^ 0xff;
  const vEdRot = await hybridVerifyDetailed({ ed: edRot, mldsa: verifier.mldsa }, message, goodSig);
  // WORLD 6: a HALF-WRITTEN key file: the Ed25519 head is ZEROED, the ML-DSA tail landed.
  const vHalfWritten = await hybridVerifyDetailed({ ed: new Uint8Array(32), mldsa: verifier.mldsa }, message, goodSig);
  // WORLD 7: a PARTIALLY-RESTORED key: a STALE Ed25519 half (a different signer's) beside the right ML-DSA half.
  const other = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
  const otherVerifier = verifierFrom(other);
  const vPartial = await hybridVerifyDetailed({ ed: otherVerifier.ed, mldsa: verifier.mldsa }, message, goodSig);
  // WORLD 8: the WRONG KIT KEY ENTIRELY. Both halves fail, which is exactly what an altered export does, and
  // the honest verdict is the same for both: this does not verify under the key you hold. Tamper lives here.
  const vWrongKit = await hybridVerifyDetailed(otherVerifier, message, goodSig);

  ok("WORLD 5 BIT ROT in the kit key's Ed25519 half is ed25519-only-mismatch: the PQ half verified these exact bytes, so the EXPORT IS INTACT", vEdRot === "ed25519-only-mismatch");
  ok("WORLD 6 a HALF-WRITTEN key (zeroed Ed25519 head) is ed25519-only-mismatch, NOT tamper", vHalfWritten === "ed25519-only-mismatch");
  ok("WORLD 7 a PARTIALLY-RESTORED key (stale Ed25519 half) is ed25519-only-mismatch, NOT tamper", vPartial === "ed25519-only-mismatch");
  ok("THE INVERSION IS DEAD: not one of the three damaged-key worlds can reach the tamper verdict any more", [vEdRot, vHalfWritten, vPartial].every((v) => v !== vTamper));
  ok("WORLD 8 the WRONG KIT KEY (both halves fail) is ed25519-mismatch, which is honest: nothing here proves the export intact", vWrongKit === "ed25519-mismatch");
  ok("DISCRIMINATION: damaged .sig / tamper / rotted PQ half / unimportable key / damaged Ed25519 half are FIVE DIFFERENT VERDICTS", new Set([vSigFile, vTamper, vRottedKey, vUnimportable, vEdRot]).size === 5);
  ok("NOISE: an intact export under the right key is still 'ok' -- no verdict is invented for a healthy verify", (await hybridVerifyDetailed(verifier, message, goodSig)) === "ok");
  ok("REDACTION: the verdict is a closed 6-member union; no signature material or export byte can ride it", [vSigFile, vTamper, vRottedKey, vUnimportable, vEdRot].every((v) => typeof v === "string" && v.length < 24));

  // The refusal CLASSES the routes record, one per verdict, so the worlds stay separate rows in the pack.
  for (const c of ["signature", "signature-pq", "classical-half-damaged", "verify-threw", "verifier-invalid"]) {
    ok(`the closed refusal vocabulary admits ${c}`, RECOVERY_REFUSAL_CLASSES.includes(c as never));
  }

  await refuse("estate-import", "verify-threw"); // a damaged .sig FILE
  await refuse("estate-import", "signature"); // an ALTERED export: tamper
  await refuse("estate-import", "signature-pq"); // a rotted PQ key half / a partial signer rotation
  await refuse("estate-import", "verifier-invalid"); // an unimportable kit key
  await refuse("estate-import", "classical-half-damaged"); // a corrupt / partially-restored / half-written Ed25519 half of the KEY or the .sig
  await refuse("export-download", "build-failed");
  await refuse("apply-staged", "staged-malformed");
  await refuse(SENTINEL_BUCKET, "signature"); // hostile
  await refuse("estate-import", SENTINEL_MESSAGE); // hostile

  const stored = (await (await sched.stub.fetch(new Request("https://do/recovery-refusals"))).json()) as { refusals?: Record<string, unknown> };
  const r = stored.refusals ?? {};
  const by = (r.bySurfaceClass ?? {}) as Record<string, number>;
  ok("the recovery refusals RECORDED (they lived only in the operator's browser)", by["estate-import|verify-threw"] === 1);
  ok(
    "DISCRIMINATION IN THE RING: the damaged .sig, the unimportable KEY, the rotted PQ half, the DAMAGED Ed25519 KEY HALF and the ALTERED export are FIVE rows on the tuple key",
    by["estate-import|verify-threw"] === 1 && by["estate-import|verifier-invalid"] === 1 && by["estate-import|signature-pq"] === 1 && by["estate-import|classical-half-damaged"] === 1 && by["estate-import|signature"] === 1,
  );
  ok("the recovery-kit DOWNLOAD fault is its own row ('the recovery-kit download 502s')", by["export-download|build-failed"] === 1);
  ok("stagedMalformed LATCHES: the confirm 409s forever until it is re-staged, and no retry will change that", r.stagedMalformed === true);
  ok("CHOKEPOINT: an out-of-vocabulary surface or class records NOTHING", Object.keys(by).length === 7);
  ok("REDACTION: no signature material, export bytes, bucket key or refusal sentence", scanForSentinels(r).length === 0);

  const pure = applyRecoveryRefusal(undefined, { surface: "reconcile", cls: SENTINEL_MESSAGE }, 1000);
  ok("CHOKEPOINT (pure): a hostile class drops the refusal whole rather than storing a half-classified row", pure.total === 0);

  // ---- the auto-heal sub-cause + the candidate-scan census ----
  const scan = scanControlPlaneCandidates([
    "_RECOVERY/CONTROL-PLANE/000000000007-2026-07-12T00:00:00.000Z.json",
    "_RECOVERY/CONTROL-PLANE/000000000007-2026-07-12T00:00:00.000Z.json.sig",
    "_RECOVERY/CONTROL-PLANE/000000000007-2026-07-12T01:00:00.000Z.json", // a SECOND artefact at the SAME latest generation
    "_RECOVERY/CONTROL-PLANE/000000000007-2026-07-12T01:00:00.000Z.json.sig",
    `_RECOVERY/CONTROL-PLANE/backup-of-${SENTINEL_BUCKET}.json`, // a HAND-RENAMED artefact: parses as no generation
  ]);
  ok("DISCRIMINATOR: conflictingAtLatestGen SAYS two artefacts claim the latest generation ('ambiguous' could not)", scan.conflictingAtLatestGen === 2);
  ok("DISCRIMINATOR: a HAND-RENAMED artefact is COUNTED, not silently ignored", scan.malformedNames === 1 && scan.artefactsSeen === 3);
  ok("REDACTION: the scan returns four counts; the bucket key it read never leaves the function", scanForSentinels(scan).length === 0);

  const empty = scanControlPlaneCandidates([]);
  ok("DISCRIMINATION: an EMPTY bucket (artefactsSeen 0) is a DIFFERENT row from a bucket full of unparseable ones", empty.artefactsSeen === 0 && empty.malformedNames === 0);

  // NOISE DISCIPLINE: a plaintext generation sitting beside its sealed successor is the NORMAL state during the
  // sealing transition, and must never be reported as a conflict.
  const transitioning = scanControlPlaneCandidates([
    "_RECOVERY/CONTROL-PLANE/000000000009-2026-07-12T00:00:00.000Z.json",
    "_RECOVERY/CONTROL-PLANE/000000000009-2026-07-12T00:00:00.000Z.json.sig",
    "_RECOVERY/CONTROL-PLANE/000000000009-2026-07-12T00:00:00.000Z.sealed.json",
    "_RECOVERY/CONTROL-PLANE/000000000009-2026-07-12T00:00:00.000Z.sealed.json.sig",
  ]);
  ok("NOISE DISCIPLINE: a healthy sealing transition is NOT a conflict (a signal that cries wolf devalues the true ones)", transitioning.conflictingAtLatestGen === 0);

  // The auto-heal refusal, through the REAL DO route, which carries the code through rather than dropping it.
  await sched.stub.fetch(new Request("https://do/control-plane/recovery-refused", {
    method: "POST",
    body: JSON.stringify({ reason: `the export failed the shape check at .destinations[0].secret (${SENTINEL_TOKEN})`, code: "signature", subCause: "mldsa-mismatch", scan }),
    headers: { "content-type": "application/json" },
  }));
  const status = (await (await sched.stub.fetch(new Request("https://do/control-plane/recovery-status"))).json()) as Record<string, unknown>;
  ok("THE WIRE CARRIES THE CODE (the route reads `reason` AND `code` rather than dropping `code`; refusedCode is never null)", status.refusedCode === "signature");
  ok("DISCRIMINATOR: the sub-cause splits a MIXED signer rotation from a tamper and from a truncated .sig", status.refusedSubCause === "mldsa-mismatch");
  ok("the candidate scan rides with the refusal", (status.refusedScan as Record<string, number>)?.conflictingAtLatestGen === 2);

  const projected = await fetchRecoveryStatus(sched.stub);
  ok("the pack projector forwards the code", projected.refusedCode === "signature");
  ok("the pack projector forwards the SUB-CAUSE", projected.refusedSubCause === "mldsa-mismatch");
  ok("the pack projector forwards the scan", (projected.refusedScan as Record<string, number>)?.malformedNames === 1);
  ok("the pack projector folds in the MANUAL-path refusals", (projected.recoveryRefusals as Record<string, unknown>)?.stagedMalformed === true);
  ok("REDACTION: the free-text reason (which embeds a JSON path AND a token) is NOT forwarded", scanForSentinels(projected).length === 0);

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const rec = bundle.recovery as Record<string, unknown> | undefined;
  ok("THE BUNDLE CARRIES the refusal's sub-cause", rec?.refusedSubCause === "mldsa-mismatch");
  ok("THE BUNDLE CARRIES the manual-path refusals, with verify-threw split from signature", ((rec?.recoveryRefusals as Record<string, Record<string, number>>)?.bySurfaceClass ?? {})["estate-import|verify-threw"] === 1);
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel", scanForSentinels(bundle).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the outcome enum states reality accurately.
// ---------------------------------------------------------------------------------------------------------
async function g219(): Promise<void> {
  console.log("\nthe update outcome tells the truth:");

  // A driver whose ROLLBACK DEPLOY FAILS. The canary says the new version is dead; the engine tries to revert;
  // the revert throws. The engine is now SERVING THE DEAD BUILD.
  const deadCanaryGate = {
    baseline: async (): Promise<"alive"> => "alive",
    flyNow: async (): Promise<"dead"> => "dead", // POSITIVE evidence the new build is bad: decideKeep always rolls back
    selfCheck: async (): Promise<boolean> => false,
  } as never;
  const rollbackBreaks = {
    currentLiveVersionId: async (): Promise<string> => "v-new",
    uploadVersion: async (): Promise<string> => "v-new",
    deployVersion: async (): Promise<void> => { throw new Error(`Cloudflare refused the deploy: ${SENTINEL_MESSAGE}`); },
  } as never;

  const settled = await settleAfterPromote(rollbackBreaks, deadCanaryGate, { fromVersion: "v-old", toVersion: "v-new", recommendedVersion: "1.2.3", canaryBaseline: "alive" });
  ok("THE LIE IS GONE: a FAILED rollback is 'rollback-failed', not 'rolled-back'", settled.outcome === "rollback-failed");
  ok("DISCRIMINATION: it is a DIFFERENT enum member from a rollback that actually worked", settled.outcome !== "rolled-back");

  const rollbackWorks = { ...(rollbackBreaks as object), deployVersion: async (): Promise<void> => {} } as never;
  const reverted = await settleAfterPromote(rollbackWorks, deadCanaryGate, { fromVersion: "v-old", toVersion: "v-new", recommendedVersion: "1.2.3", canaryBaseline: "alive" });
  ok("...and a rollback that DID land still reads 'rolled-back' (the healthy case is unchanged)", reverted.outcome === "rolled-back");

  // The RAMP: a failed rollback leaves a LIVE TRAFFIC SPLIT still routing to the suspect version.
  const ramp = await settleAfterRamp(rollbackBreaks, deadCanaryGate, { fromVersion: "v-old", toVersion: "v-new", recommendedVersion: "1.2.3" });
  ok("THE LIE IS GONE (ramp): a failed rollback is 'rollback-failed-still-split', not 'rolled-back'", ramp.outcome === "rollback-failed-still-split");

  // THE CONSEQUENCE THE WIDENING MUST NOT BREAK: a rollback-failed record must still yield a rollback TARGET.
  // Excluding it would refuse the operator a manual rollback in precisely the state that needs one.
  ok("resolveRollbackTarget still resolves a target from a rollback-failed record (the remedy is to RETRY it)", resolveRollbackTarget({ pending: null, last: { outcome: "rollback-failed", fromVersion: "v-old" } }) === "v-old");
  ok("...and from a rollback-failed-still-split record", resolveRollbackTarget({ pending: null, last: { outcome: "rollback-failed-still-split", fromVersion: "v-old" } }) === "v-old");
  ok("...and from an applied-unconfirmed one", resolveRollbackTarget({ pending: null, last: { outcome: "applied-unconfirmed", fromVersion: "v-old" } }) === "v-old");
  ok("a genuinely unknown outcome still yields NO target (fail-safe: never deploy a stale version)", resolveRollbackTarget({ pending: null, last: { outcome: "superseded", fromVersion: "v-old" } }) === "");

  // THE BUNDLE: the record, and the two version-skew-proof booleans every downstream consumer can read.
  const sched = realScheduler();
  await sched.stub.fetch(new Request("https://do/update-settled", {
    method: "POST",
    body: JSON.stringify({ outcome: settled.outcome, recommendedVersion: "1.2.3", fromVersion: "v-old", toVersion: "v-new", at: Date.now(), by: SENTINEL_EMAIL, reason: settled.reason }),
    headers: { "content-type": "application/json" },
  }));

  const projected = await fetchUpdateStatus({} as unknown as Env, sched.stub);
  const last = projected.last as Record<string, unknown> | undefined;
  ok("the pack projector carries the honest outcome", last?.outcome === "rollback-failed");
  ok("DISCRIMINATOR: stillServingBadVersion is the unambiguous fact -- readable by a consumer that never learned the new enum", last?.stillServingBadVersion === true);

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const upd = (bundle.updates as { last?: Record<string, unknown> } | undefined)?.last;
  ok("THE BUNDLE says the customer is still serving the build they tried to escape", upd?.outcome === "rollback-failed" && upd?.stillServingBadVersion === true);

  // REDACTION. The operator's e-mail (`by` on the settled record) must not be projected, and is not.
  ok("REDACTION: the operator e-mail on the settled record is NOT projected into the pack", upd?.by === undefined && !JSON.stringify(upd).includes(SENTINEL_EMAIL));

  // The free-text `reason` must never ride into the pack as an accepted leak on the grounds that the settle
  // path interpolates the platform's message into its operator-facing prose regardless.
  //
  // A clamp is not a redaction: it bounds the LENGTH of a leak, not its content. The prose carries the raw
  // Cloudflare deploy-driver error, which can embed a URL, an account id or a script name, and must not ride
  // into the SEALED bundle that a customer sends to the vendor. In a no-custody product that is the one thing
  // that must never happen, regardless of which code path produced the text.
  //
  // The prose is absent from the pack and replaced by the closed reasonClass. The operator still sees the full
  // sentence in their OWN console. See test/validate-update-reason-redaction.ts.
  ok("the free-text reason is GONE from the pack (it carried the raw platform message)", upd?.reason === undefined);
  ok("the platform's message does not appear ANYWHERE in the update record", !JSON.stringify(upd ?? {}).includes(SENTINEL_MESSAGE));
  ok("the DIAGNOSIS survives as a closed class (redacting the evidence into uselessness is its own failure)", typeof upd?.reasonClass === "string");
  ok("REDACTION: every field of the update record is sentinel-free, with no prose exception", scanForSentinels((upd ?? {}) as Record<string, unknown>).length === 0);
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel, with no carve-out", scanForSentinels(bundle).length === 0);
}

async function main(): Promise<void> {
  await g130();
  await g131();
  await g182();
  await g183();
  await g201();
  await g202g218();
  await g219();
  console.log(failures === 0 ? "\navailability evidence: OK" : `\navailability evidence: ${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
