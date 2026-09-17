// Prove the fault evidence reaches the BUNDLE, and reaches it redaction-safe.
//
// Evidence is not usable until it is IN THE PACK: a recorder that fires correctly on the fault path and
// writes a durable DO record is worthless if nothing reads it back, since the pack a customer generates
// during the outage then carries none of it. Recording into a void is indistinguishable from not recording
// at all. So every assertion below is END TO END: a DO record goes in, buildSupportBundle runs, and the
// FIELD is asserted in the built bundle body.
//
// The second half is the no-custody proof. Every DO record here is served HOSTILE: each carries planted
// customer sentinels (an operator e-mail, a bucket, an object key, an access-key id, a live-looking secret, an
// endpoint URL and a raw provider error message), out-of-vocabulary enum VALUES, and out-of-vocabulary map
// KEYS -- the last being the classic closed-vocabulary bypass, where a caller-derived string becomes a map key
// and rides into the pack as a key rather than a value. The suite then serialises the whole bundle and asserts
// that not one byte of any sentinel survives, KEYS AND VALUES ALIKE, and that every hostile enum was dropped.
//
// Run: node test/validate-support-round4.ts

import { buildSupportBundle } from "../src/admin/support.ts";
import { SUPPORT_SECTION_NAMES } from "../src/admin/support-roster.ts";
import { renderReportPDF, drainReportRenderFaults } from "../src/pdf.ts";
import { webhookRejectReason } from "../src/sched/sched-fault-ledger.ts";
import { WEBHOOK_REJECT_CODES } from "../src/notify/types.ts";
import { drainSizingOutcomes, estimateSourceSize } from "../src/cost/sizing-probe.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The customer sentinels. Each is planted INSIDE a DO record that the pack reads, in the field a drifted,
// older or malicious writer would most plausibly have put it in. None may appear in any byte of the bundle.
// Left un-annotated on purpose: a `Record<string, string>` annotation would widen every read to
// `string | undefined` under noUncheckedIndexedAccess, and a possibly-undefined string cannot be a computed
// property name -- which is exactly how the hostile map KEYS below are planted.
const SENTINELS = {
  email: "cfo@acme-payroll.example",
  bucket: "acme-prod-payroll-backups",
  objectKey: "kv/tenants/acme/salaries-2026.json",
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secret: "sk_live/51H8xQ2eZ+vKYlo2C0abcdefghij=",
  endpoint: "https://acme.r2.cloudflarestorage.com/payroll",
  providerMessage: "AccessDenied: user arn:aws:iam::9911:user/backup is not authorized to PutObject",
};

// The scheduler double. Every route answers with a record that is deliberately CONTAMINATED: real,
// in-vocabulary evidence sits alongside sentinels, hostile enum values and hostile map keys. A gatherer that
// merely passes its record through, or that gates values but not keys, fails here.
function schedulerDouble(opts: { faultRoutes?: Set<string> } = {}): DurableObjectStub {
  const json = (v: unknown): Response => new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
  return {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const p = url.pathname;
      // A route in faultRoutes THROWS: the section must read "error", never a clean "empty". An unreadable
      // ledger reported as an honest absence is a lie the diagnosis would act on.
      if (opts.faultRoutes?.has(p)) throw new Error(`DO unreachable: ${SENTINELS.endpoint}`);
      switch (p) {
        // ---- key-unwrap faults ---------------------------------------------------------------------
        case "/unwrap-faults":
          return json({
            "aead-tag": { count: 3, firstAt: 1752191000000, lastAt: 1752277400000 },
            // A hostile KEY: a raw provider message used as the map key. It must not become a bundle key.
            [SENTINELS.providerMessage]: { count: 9, firstAt: 1, lastAt: 2 },
          });
        // ---- binding alarms ------------------------------------------------------------------------
        case "/binding-alarms":
          return json({
            alarms: [
              // PATIENTS_KV is binding-SHAPED and must survive; the secret and the object key are not, and
              // must be dropped OUTRIGHT by the shape gate (not merely clamped).
              { at: 1752277400000, kind: "lost-update-race", bindingNames: ["PATIENTS_KV", SENTINELS.secret, SENTINELS.objectKey] },
              { at: 1752277400001, kind: "not-a-real-kind", bindingNames: ["X"] }, // hostile enum: whole row dropped
            ],
          });
        // ---- update faults -------------------------------------------------------------------------
        case "/update-faults":
          return json({
            faults: [
              {
                at: 1752277400000,
                component: "engine",
                step: "binding-guard",
                cause: "sources-dropped",
                httpStatus: 500,
                cfCodes: [10021],
                rollbackFailed: true,
                droppedSources: ["PATIENTS_KV", "LEDGER_D1", SENTINELS.secret],
                readbackShape: { topLevelKeys: 3, hasSuccess: true, hasResult: false, hasErrors: true },
                recordPhase: "settled",
                observedSha384: SENTINELS.objectKey, // not 96-hex: must be dropped
              },
              { at: 2, component: "engine", step: "promote", cause: "not-a-real-cause" }, // hostile enum: dropped
            ],
          });
        // ---- admin refusals ------------------------------------------------------------------------
        case "/admin-refusals":
          return json({
            "restore-apply:gate-unavailable": { count: 2, lastAt: "2026-07-11T00:00:00.000Z" },
            [`${SENTINELS.email}:gate-unavailable`]: { count: 7, lastAt: "2026-07-11T00:00:00.000Z" }, // hostile key
          });
        // ---- integrity faults ----------------------------------------------------------------------
        case "/integrity-faults":
          return json({
            dp1: {
              fetchFaults: { "runlog|cold-storage|4xx": 2, [`runlog|${SENTINELS.bucket}|4xx`]: 5 },
              failStages: { "freshness-signature": 1, [SENTINELS.objectKey]: 3 },
              classifiedBy: { "keyword-fallback": 1 },
              locators: [
                { kind: "chunk-range", shardOrdinal: 401, declaredCount: 500, recoveredCount: 499, digest: "ab12cd34ef56" },
                { kind: "chunk-range", digest: SENTINELS.objectKey }, // a raw key in a digest field: dropped
              ],
              cryptoFaults: [{ cls: "recipient-no-capsule-match", role: "recipient", heldFingerprint: "dpr1:" + "a".repeat(96), wantFingerprint: SENTINELS.secret }],
              streamFaults: [{ leg: "decrypt-open", cls: "gcm-auth-fail", chunkIndex: 4000, expectedBytes: 4001 }],
              defaultedEmptyRecords: 7,
              formatVersionSeen: "downpipe/2.x",
              at: 1752277400000,
            },
          });
        // ---- dispatch faults -----------------------------------------------------------------------
        case "/dispatch-faults":
          return json({
            faults: [
              { at: 1752277400000, surface: "fetch", routeFamily: "support", errId: "ab12cd34", httpStatus: 500 },
              { at: 2, surface: SENTINELS.email, errId: "ff00ff00" }, // hostile surface: row dropped
            ],
          });
        // ---- cron health ---------------------------------------------------------------------------
        case "/cron-health":
          return json({
            passes: {
              "restore-tests": { consecutiveFailures: 4, failCount: 12, lastErrorClass: "do-fetch", lastErrorAt: "2026-07-11T00:00:00.000Z" },
              [SENTINELS.objectKey]: { consecutiveFailures: 9, failCount: 9 }, // hostile pass name: dropped
            },
            tick: { lastAt: "2026-07-11T00:00:00.000Z", intervalMs: 300000, gapDetected: true, missedApprox: 12, recordFailures: 3 },
            discovery: { skips: { "out-of-scope": 5, [SENTINELS.bucket]: 4 }, consecutiveSkips: 5 },
            beacon: { envPresent: { url: true, ingestKey: false, accountId: true }, lastFailClass: "url-invalid", failCounts: { "url-invalid": 6 }, stateWriteFailures: 1 },
            autoHeal: { lastAttemptAt: "2026-07-11T00:00:00.000Z", lastDeferral: "budget-reserve", deferrals: { "budget-reserve": 30 }, resumeApplyLastReasonCode: "not-staged", amnesiaProbeWriteFailures: 2 },
            siem: { "cursor-reset": { count: 1, lastAt: "2026-07-11T00:00:00.000Z" }, "batch-cap-truncated": { count: 4, lastAt: "2026-07-11T00:00:00.000Z" } },
            danglingDestinationRefs: 2,
          });
        // ---- destination probe faults --------------------------------------------------------------
        case "/dest-probe-faults":
          return json({
            "dest-primary": { reason: "auth", count: 9, at: 1752277400000 },
            "dest-hostile": { reason: SENTINELS.providerMessage, count: 3, at: 1 }, // hostile reason: dropped
          });
        // ---- destination build health ---------------------------------------------------------------
        case "/dest-build-health":
          return json({
            health: {
              lastAt: 1752277400000,
              lastOutcome: "failed",
              failingSinceAt: 1752101400000,
              lastCause: "sts-assume-role-failed",
              lastVarName: "DEST_ENDPOINT",
              lastStsFailureClass: "access-denied",
              lastDoStatus: 500,
              consecutiveFailures: 42,
              causes: { "sts-assume-role-failed": 42, [SENTINELS.endpoint]: 3 },
              stsClasses: { "access-denied": 42 },
            },
          });
        // ---- cost sizing ---------------------------------------------------------------------------
        case "/cost-sizing":
          return json({
            kv: { sized: 3, unavailable: 1, measuredZero: 5, lastClass: "analytics-schema-drift", lastAt: "2026-07-11T00:00:00.000Z" },
            [SENTINELS.bucket]: { sized: 1, unavailable: 0, measuredZero: 0, lastClass: "ok", lastAt: "2026-07-11T00:00:00.000Z" }, // hostile type key
          });
        // ---- the eight blocks inside the existing /sched-diag read --------------------------------
        case "/sched-diag":
          return json({
            destResolveFallbacks: {
              counts: { "dangling-default-healed": { count: 11, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.bucket]: { count: 4, lastAt: "x" } },
              recent: [{ cls: "canary-pin-dangling", downpipeId: "dp1", at: "2026-07-11T00:00:00.000Z" }],
            },
            canaryLosses: { counts: { "lost-flight": { count: 2, lastAt: "2026-07-11T00:00:00.000Z" } }, uncoveredDestIds: ["dest-cold"] },
            drillDrops: { "member-requeued": { count: 17, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.email]: { count: 3, lastAt: "x" } },
            notifyDrops: {
              counts: { "parse-reject": { count: 4, lastAt: "2026-07-11T00:00:00.000Z" } },
              recent: [{ at: "2026-07-11T00:00:00.000Z", dropKind: "parse-reject", event: "backup-failure", severity: "critical", downpipeId: "dp1" }],
            },
            governanceFaults: { "owner-action-execute|replay-detected": { count: 1, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.providerMessage]: { count: 2, lastAt: "x" } },
            refusalRings: { "licence-activation": [{ at: "2026-07-11T00:00:00.000Z", code: "expired" }], [SENTINELS.email]: [{ at: "x", code: "y" }] },
            adminRefusals: { "dest-remove-guard|orphan-guard": { count: 3, lastAt: "2026-07-11T00:00:00.000Z" } },
            clientDiagnostics: {
              consoleBuildId: "1.4.2",
              crashes: { "chunk-load": { count: 6, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.objectKey]: { count: 2, lastAt: "x" } },
              faults: { "worker-asset-miss": { count: 4, lastAt: "2026-07-11T00:00:00.000Z" } },
              skew: { "restore|route-missing": { count: 3, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.endpoint]: { count: 1, lastAt: "x" } },
              bulkOutcomes: [{ at: "2026-07-11T00:00:00.000Z", op: "bulk-protect", attempted: 1000, succeeded: 300, failed: 700, halted: true, timedOut: false, pollFailures: 2, failedByClass: { "halted-401": { count: 700, lastAt: "2026-07-11T00:00:00.000Z" } } }],
              settleJourneys: [{ at: "2026-07-11T00:00:00.000Z", terminalState: "stalled", settleAttempts: 3, statusReadFailures: 1, pollAttempts: 30, pollCeilingHit: true, unexpectedOutcome: false }],
              at: "2026-07-11T00:00:00.000Z",
            },
          });
        // ---- the drill's discriminating detail on the existing restore-fault ring -------------------
        case "/restore-faults":
          return json({
            faults: [
              { at: 1752277400000, op: "drill", phase: "verify", cls: "posture-unexercisable", count: 3, index: 401, binding: "signer-private" },
              { at: 1752277400001, op: "drill", phase: "verify", cls: "integrity", count: 1, index: -5, binding: SENTINELS.secret }, // hostile binding + negative index
            ],
          });
        // The roster: one downpipe with a SECRETS source (a derived restorability posture) and a cf-config
        // discovery carrying the closed unavailability-class map + truncation list.
        case "/downpipes":
          return json([
            {
              config: { id: "dp1", name: "payroll", enabled: true, cadenceSeconds: 3600, source: { type: "secrets", secrets: ["a", "b", "c"] } },
              lastRunId: "01RUN",
              inFlight: false,
              cfConfigDiscovery: { at: 1752277400000, present: ["dns"], empty: [], gated: [], unavailable: ["waf"], unavailableByClass: { "403": 12, [SENTINELS.bucket]: 3 }, truncated: ["dns"] },
            },
          ]);
        default:
          return json({});
      }
    },
  } as unknown as DurableObjectStub;
}

function envDouble(): Env {
  return { SCHEDULER: {} as DurableObjectNamespace, CF_ACCOUNT_ID: "acct-xyz" } as unknown as Env;
}

async function main(): Promise<void> {
  const bundle = await buildSupportBundle(envDouble(), schedulerDouble());
  const text = JSON.stringify(bundle);
  const sections = bundle.sections as Record<string, string>;

  console.log("the fault evidence reaches the BUNDLE (a gap is not closed until it is in the pack):");
  {
    // The fact the probe-time wrapKeyHealth verdict structurally cannot recover -- since when.
    const uf = bundle.unwrapFaults as Record<string, { count: number; firstAt: number }>;
    ok("unwrapFaults rides, with the never-overwritten firstAt", uf?.["aead-tag"]?.count === 3 && uf["aead-tag"].firstAt === 1752191000000);
    // The owner's #1 fear, with the binding to re-attach named.
    const ba = bundle.bindingAlarms as Array<{ kind: string; bindingNames?: string[] }>;
    ok("bindingAlarms rides with the operator's binding label", ba?.[0]?.kind === "lost-update-race" && ba[0].bindingNames?.[0] === "PATIENTS_KV");
    // The failing step, the closed cause, the rollback latch and WHICH bindings the update dropped.
    const uff = bundle.updateFaults as Array<Record<string, unknown>>;
    // The surviving row is pulled out once: it is read across two assertions, and an absent row must FAIL
    // both rather than throw out of the block.
    const uf0 = uff?.[0];
    ok("updateFaults rides (step + cause + rollbackFailed + droppedSources)", uf0?.step === "binding-guard" && uf0.cause === "sources-dropped" && uf0.rollbackFailed === true && (uf0.droppedSources as string[])[1] === "LEDGER_D1");
    ok("the bookkeeping recordPhase and the bounded CF readback descriptor ride", uf0?.recordPhase === "settled" && (uf0.readbackShape as { topLevelKeys: number }).topLevelKeys === 3);
    // The DR-hour split -- an engine fault, not a missing approval.
    ok("adminRefusals rides the gate-unavailable split", (bundle.adminRefusals as Record<string, { count: number }>)?.["restore-apply:gate-unavailable"]?.count === 2);
    // The integrity locus.
    const ifs = (bundle.integrityFaults as Record<string, Record<string, unknown>>)?.dp1;
    ok("the fetch fault behind an 'absent' RUNLOG rides (cold-storage, not a credential fault)", (ifs?.fetchFaults as Record<string, number>)?.["runlog|cold-storage|4xx"] === 2);
    ok("the verify failStage + the keyword-fallback confidence caveat ride", (ifs?.failStages as Record<string, number>)?.["freshness-signature"] === 1 && (ifs?.classifiedBy as Record<string, number>)?.["keyword-fallback"] === 1);
    ok("the locator rides its ordinal and one-way digest", (ifs?.locators as Array<{ kind: string; shardOrdinal?: number }>)?.[0]?.shardOrdinal === 401);
    ok("defaultedEmptyRecords rides (the SILENT zero-byte seal behind a green run)", ifs?.defaultedEmptyRecords === 7);
    ok("the streaming CHUNK INDEX rides (chunk 4000 of 4001 = a truncated tail)", (ifs?.streamFaults as Array<{ chunkIndex?: number }>)?.[0]?.chunkIndex === 4000);
    // The self-referential surface.
    ok("dispatchFaults rides the support surface + the 8-hex log join key", (bundle.dispatchFaults as Array<{ surface: string; errId?: string }>)?.[0]?.errId === "ab12cd34");
    // The cron plane.
    const ch = bundle.cronHealth as Record<string, Record<string, unknown>>;
    ok("the failing cron PASS is named with its closed error class", (ch?.passes?.["restore-tests"] as { consecutiveFailures: number; lastErrorClass: string })?.consecutiveFailures === 4);
    ok("the tick ring's HOLES ride (gapDetected + missedApprox)", ch?.tick?.gapDetected === true && ch.tick.missedApprox === 12);
    ok("the auto-heal STALL rides (budget-reserve, so the heal literally never runs)", (ch?.autoHeal?.deferrals as Record<string, number>)?.["budget-reserve"] === 30);
    ok("the discovery skip rides (out-of-scope can NEVER refresh again)", (ch?.discovery?.skips as Record<string, number>)?.["out-of-scope"] === 5);
    // Both presence booleans come off the SAME projected object, so it is read once; a missing beacon block
    // then fails the assertion instead of throwing.
    const envPresent = ch?.beacon?.envPresent as { url?: boolean; ingestKey?: boolean } | undefined;
    ok("the beacon's PARTIAL configuration rides as presence booleans", envPresent?.url === true && envPresent?.ingestKey === false);
    const siem = ch?.siem as Record<string, { count: number }> | undefined;
    ok("the SIEM cursor-reset (duplicate delivery) and batch-cap truncation (audit LOSS) ride", siem?.["cursor-reset"]?.count === 1 && siem?.["batch-cap-truncated"]?.count === 4);
    ok("destProbeFaults names a CAUSE per destination", (bundle.destProbeFaults as Record<string, { reason: string }>)?.["dest-primary"]?.reason === "auth");
    const dbh = bundle.destBuildHealth as Record<string, unknown>;
    ok("destBuildHealth rides failingSinceAt ('unbuildable since Tuesday')", dbh?.failingSinceAt === 1752101400000 && dbh.consecutiveFailures === 42);
    ok("the STS failure class rides (a trust-policy denial, not a rotated key)", dbh?.lastStsFailureClass === "access-denied" && dbh.lastVarName === "DEST_ENDPOINT");
    ok("costSizing rides measuredZero (a 0 presented as a MEASURED size)", (bundle.costSizing as Record<string, { measuredZero: number }>)?.kv?.measuredZero === 5);
    // The eight blocks inside schedDiag.
    const sd = bundle.schedDiag as Record<string, Record<string, unknown>>;
    ok("destResolveFallbacks rides (writes are landing where the customer did not choose)", (sd?.destResolveFallbacks?.counts as Record<string, { count: number }>)?.["dangling-default-healed"]?.count === 11);
    ok("canaryLosses rides, and NAMES the destinations the cap never flies", (sd?.canaryLosses?.uncoveredDestIds as string[])?.[0] === "dest-cold");
    ok("drillDrops rides member-requeued (the 'stuck at 3 remaining for two days' loop)", (sd?.drillDrops as Record<string, { count: number }>)?.["member-requeued"]?.count === 17);
    ok("notifyDrops NAMES the dead alert (event + severity + downpipe)", (sd?.notifyDrops?.recent as Array<{ event?: string }>)?.[0]?.event === "backup-failure");
    ok("governanceFaults rides replay-detected (one approval, two applies)", (sd?.governanceFaults as Record<string, { count: number }>)?.["owner-action-execute|replay-detected"]?.count === 1);
    ok("the refusal RING rides the sequence, not just the last code", (sd?.refusalRings?.["licence-activation"] as Array<{ code: string }>)?.[0]?.code === "expired");
    ok("schedAdminRefusals rides the dest-remove guard split (in-use vs orphan-guard)", (sd?.schedAdminRefusals as Record<string, { count: number }>)?.["dest-remove-guard|orphan-guard"]?.count === 3);
    ok("the console's bulk casualties ride (300 of 1000, halted mid-bulk)", (sd?.clientDiagnostics?.bulkOutcomes as Array<{ succeeded: number; halted: boolean }>)?.[0]?.succeeded === 300);
    ok("the settle journey rides its silently-hit poll ceiling", (sd?.clientDiagnostics?.settleJourneys as Array<{ pollCeilingHit: boolean }>)?.[0]?.pollCeilingHit === true);
    ok("the SKEW PAIR is assemblable (consoleBuildId beside engine.version)", sd?.clientDiagnostics?.consoleBuildId === "1.4.2" && typeof (bundle.engine as { version: string }).version === "string");
    ok("the console worker's asset-miss (the blank page after a deploy) rides", (sd?.clientDiagnostics?.faults as Record<string, { count: number }>)?.["worker-asset-miss"]?.count === 4);
    // The existing restore-fault ring.
    const rf = bundle.restoreFaults as Array<Record<string, unknown>>;
    ok("the drill's failing INDEX and absent BINDING ride, with the honest posture-unexercisable class", rf?.[0]?.cls === "posture-unexercisable" && rf[0].index === 401 && rf[0].binding === "signer-private");
    // The roster.
    const dp = (bundle.downpipes as Array<Record<string, unknown>>)[0];
    const disc = dp?.cfConfigDiscovery as Record<string, unknown>;
    ok("the cf-config unavailability CLASS rides (a 403 scope gap, not a Cloudflare blip)", (disc?.unavailableByClass as Record<string, number>)?.["403"] === 12 && (disc!.truncated as string[])[0] === "dns");
    ok("secretsRestorability rides: 3 bound secrets, none restorable in-account", (bundle.secretsRestorability as { bound: number; unwired: number })?.bound === 3 && (bundle.secretsRestorability as { unwired: number }).unwired === 3);
  }

  console.log("the section roster and the health vector stay honest:");
  {
    for (const name of ["unwrapFaults", "bindingAlarms", "updateFaults", "adminRefusals", "integrityFaults", "dispatchFaults", "cronHealth", "destProbeFaults", "destBuildHealth", "costSizing"]) {
      ok(`${name} is in the roster and gathered "ok"`, (SUPPORT_SECTION_NAMES as readonly string[]).includes(name) && sections[name] === "ok");
    }
    // A faulted read must read "error", never a clean "empty": an unreadable ledger reported as an honest
    // absence is a lie a diagnosis would act on ("nothing was wrong" vs "I could not look").
    const degraded = await buildSupportBundle(envDouble(), schedulerDouble({ faultRoutes: new Set(["/cron-health", "/integrity-faults"]) }));
    const ds = degraded.sections as Record<string, string>;
    ok("a faulted ledger read propagates to section() as \"error\", never \"empty\"", ds.cronHealth === "error" && ds.integrityFaults === "error");
    ok("one faulted section does not crash the build (the rest still gather)", ds.unwrapFaults === "ok" && ds.destBuildHealth === "ok");
  }

  console.log("REDACTION (no-custody): no customer sentinel reaches the pack, as a value OR as a key:");
  {
    for (const [what, s] of Object.entries(SENTINELS)) {
      ok(`the planted ${what} appears in NO byte of the bundle`, !text.includes(s));
    }
    // The hostile map KEYS are the classic closed-vocabulary bypass: a caller-derived string becoming a
    // storage/bundle key rides as a KEY, not a value, so a value-only gate misses it entirely.
    ok("a hostile MAP KEY is dropped at every composite aggregate (unwrap/refusal/skew/governance)", !text.includes(SENTINELS.providerMessage) && !text.includes(SENTINELS.endpoint));
    // The hostile ENUM VALUES must be dropped, not carried and not coerced into a neighbouring member.
    ok("an out-of-vocabulary alarm kind drops the whole row", (bundle.bindingAlarms as unknown[]).length === 1);
    ok("an out-of-vocabulary update cause drops the whole row", (bundle.updateFaults as unknown[]).length === 1);
    ok("an out-of-vocabulary dispatch surface drops the whole row", (bundle.dispatchFaults as unknown[]).length === 1);
    ok("an out-of-vocabulary dest-probe reason drops the destination", Object.keys(bundle.destProbeFaults as object).length === 1);
    ok("an out-of-vocabulary cost-sizing source type cannot become a bundle key", Object.keys(bundle.costSizing as object).length === 1);
    ok("a hostile restore-fault binding is dropped and a NEGATIVE index cannot ride", (bundle.restoreFaults as Array<Record<string, unknown>>)[1]?.binding === undefined && ((bundle.restoreFaults as Array<Record<string, unknown>>)[1]?.index as number) >= 0);
    ok("a non-96-hex observedSha384 is dropped (no message can ride a digest field)", (bundle.updateFaults as Array<Record<string, unknown>>)[0]?.observedSha384 === undefined);
    ok("a raw object key in a digest field is dropped", !JSON.stringify(bundle.integrityFaults).includes(SENTINELS.objectKey));
    ok("a secret in a public-key fingerprint field is dropped", !JSON.stringify(bundle.integrityFaults).includes(SENTINELS.secret));
    // THE DOCUMENTED RESIDUAL on the binding-name fields (bindingAlarms.bindingNames, updateFaults
    // .droppedSources). They carry the operator's OWN Workers binding labels, and a binding label and an
    // identifier-shaped token are structurally the SAME string -- no shape gate can separate them, and
    // pretending otherwise would be a false guarantee. What the gate DOES foreclose is everything that is not
    // identifier-shaped (a secret with punctuation, an e-mail, an endpoint, an object key), and the real
    // guarantee lives at the WRITE site: these names are read out of the Cloudflare binding DIFF, never out of
    // a value or a message. Pinned here so the property is asserted rather than assumed.
    const alarmNames = (bundle.bindingAlarms as Array<{ bindingNames?: string[] }>)[0]?.bindingNames ?? [];
    ok("a binding-name field drops an e-mail, an endpoint, an object key and a punctuated secret outright", alarmNames.length === 1 && alarmNames[0] === "PATIENTS_KV");
    // No raw exception text, stack frame, S3 error document or bearer may ride anywhere.
    ok("no raw exception text, stack frame, S3 error code or bearer rides", !text.includes("Error:") && !text.includes("    at ") && !text.includes("</Code>") && !text.includes("Bearer "));
  }

  console.log("the compliance report a customer could not download:");
  {
    // A non-numeric lastRestoreTestAt must not throw a RangeError out of `new Date(Number(...)).toISOString()`
    // deep inside PDF assembly: that would 500 the whole download, and the auditor's report would be
    // unproducible for a reason nothing recorded.
    drainReportRenderFaults();
    const report = {
      kind: "restore-tests",
      generatedAt: "2026-07-11T00:00:00.000Z",
      period: { fromSeconds: 1752000000, toSeconds: 1752277400 },
      data: { recency: [{ name: "payroll", lastRestoreTestAt: "not-a-timestamp", lastRestoreTestOk: false }], evidence: [] },
    } as unknown as Parameters<typeof renderReportPDF>[0];
    let threw = false;
    // Annotated: renderReportPDF returns a plain `Uint8Array` (buffer type ArrayBufferLike), which the
    // narrower type inferred from `new Uint8Array(0)` would not accept.
    let bytes: Uint8Array = new Uint8Array(0);
    try {
      bytes = renderReportPDF(report);
    } catch {
      threw = true;
    }
    ok("a non-numeric lastRestoreTestAt no longer throws a RangeError out of the PDF renderer", !threw && bytes.length > 0);
    ok("the coerced cell is COUNTED, so a degraded cell is not a new silent fallback", drainReportRenderFaults().unparseableTimestamps >= 1);
    // A second render after the drain must start from zero: the tally is per-render, so one report's fault
    // can never be attributed to the next.
    renderReportPDF({ ...report, data: { recency: [{ name: "payroll", lastRestoreTestAt: 1752277400000, lastRestoreTestOk: true }], evidence: [] } } as unknown as Parameters<typeof renderReportPDF>[0]);
    ok("the render tally is drained per render (one report's fault never rides into the next)", drainReportRenderFaults().unparseableTimestamps === 0);
  }

  console.log("the sizing probe WRITES to its own sink:");
  {
    // The cost-sizing aggregate has a DO record, a POST route, a redaction chokepoint and a writer: a ledger
    // nothing writes to is indistinguishable from a ledger that does not exist, and the pack would otherwise
    // carry a permanently empty section.
    const probed: Array<{ sourceType: string; cls: string }> = [];
    // measured-zero is the load-bearing class: analytics ANSWERED, and it answered zero, which the console
    // then shows the customer as a MEASURED "this source is empty".
    const zeroAnalytics = { kvNamespaceSize: async () => ({ bytes: 0, count: 0 }), r2BucketSize: async () => ({ bytes: 0, count: 0 }) };
    const driftAnalytics = { kvNamespaceSize: async () => "schema-drift" as const, r2BucketSize: async () => "schema-drift" as const };
    await estimateSourceSize({ type: "kv", namespaceId: "ns1" }, { analytics: zeroAnalytics, accountId: "a" });
    probed.push(...drainSizingOutcomes());
    ok("an ANSWERED zero is classified measured-zero, not silently rendered as an empty source", probed[0]?.cls === "measured-zero" && probed[0]?.sourceType === "kv");
    await estimateSourceSize({ type: "r2", bucketName: "b1" }, { analytics: driftAnalytics, accountId: "a" });
    const drift = drainSizingOutcomes();
    ok("a Cloudflare schema drift is classified as such (no customer action can fix it)", drift[0]?.cls === "analytics-schema-drift");
    await estimateSourceSize({ type: "kv" }, { analytics: zeroAnalytics, accountId: "a" });
    await estimateSourceSize({ type: "d1" }, { analytics: zeroAnalytics, accountId: "a" });
    const rest = drainSizingOutcomes();
    ok("a missing identifier and an unsupported type are their own classes", rest[0]?.cls === "missing-identifier" && rest[1]?.cls === "unsupported-source-type");
    ok("the probe tally is drained per probe (one estate's outcomes never ride into the next)", drainSizingOutcomes().length === 0);
  }

  console.log("the webhook-reject code is TOTAL over its closed set:");
  {
    // Both halves are closed sets, so the mapping is total and can never widen what is recorded: the
    // operator-facing SENTENCE (which quotes the submitted URL) is never passed in and can never be stored.
    const mapped = WEBHOOK_REJECT_CODES.map((c) => webhookRejectReason(c));
    ok("every webhook reject code maps to a closed admin-refusal reason", mapped.length === WEBHOOK_REJECT_CODES.length && mapped.every((m) => typeof m === "string" && m.length > 0));
    ok("non-https maps onto the reason that says exactly that", webhookRejectReason("non-https") === "endpoint-not-https");
    ok("a private sink with no opt-in is distinguishable from a bad URL", webhookRejectReason("internal-no-optin") === "internal-sink-no-optin" && webhookRejectReason("unparseable") === "url-unparseable");
    ok("a DRIFTED code coarsens to the residual and never rides verbatim", webhookRejectReason(SENTINELS.email) === "shape-rejected");
  }

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
