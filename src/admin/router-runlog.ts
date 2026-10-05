// The ATTENDED RUNLOG re-sign: the one way past a destination RUNLOG whose signature does not verify under
// the current signer, and never automatic.
//
// The engine refuses to modify a RUNLOG it cannot verify under its own key, because re-signing an unverified
// RUNLOG is how a change made in the bucket would be laundered. Legitimate states also leave a RUNLOG that does
// not verify: a deleted or expired .sig, a crash that also lost the pending signature, a re-key over a signer
// that would not load, or a late old-version seal after a re-key hand-over. An Owner decides those here:
//
//   GET  /runlog/signature?destinationId=<id>  what does not verify: the object, the key it was checked under,
//        the digest of the stored bytes, the highest index in them, and the last good index (the destination's
//        confirmed floor). keys.ceremony (Owner).
//   POST /runlog/resign {destinationId, digest}  sign, under the current signer, the exact bytes whose SHA-384
//        the Owner confirmed. keys.ceremony (Owner) + step-up (STEPUP_SUBS). When a re-key hand-over holds the
//        old public key and the bytes verify under it, this finishes that hand-over instead. It refuses a
//        RUNLOG that does not parse, has a chain anomaly or sits below the last good index: a signature cannot
//        repair those, and the engine would still refuse the RUNLOG. Each re-sign writes a runlog-resigned
//        audit row and raises the runlog-resigned alert (warning) to every channel.
//   GET  /runlog/floor?destinationId=<id>  the destination's anti-rollback floor against the RUNLOG it holds now:
//        the floor, the bucket the destination points at, the highest index of its RUNLOG, and why the writers
//        refuse it (absent-above-floor or below-floor). keys.ceremony (Owner).
//   POST /runlog/floor/reset {destinationId, expectFloor, digest}  the way out of an env destination repointed
//        by redeploy (sched/runlog-floor.ts residual): move the floor down to the highest index of the RUNLOG the
//        Owner was shown (0 when absent). Only when the writers refuse on the floor alone, and only over a RUNLOG
//        that verifies under the current signer; it signs nothing. keys.ceremony (Owner) + step-up. Writes a
//        runlog-floor-reset audit row and raises the runlog-floor-reset alert (warning).
//   GET  /runlog/chain?destinationId=<id>&downpipeId=<dp>  one downpipe's chain in a destination RUNLOG: whether
//        the RUNLOG verifies, the chain anomaly (kind, the disagreeing indices, the reason), and whether relinking
//        that one chain clears it. keys.ceremony (Owner).
//   POST /runlog/relink {destinationId, downpipeId, digest, anomalyKind}  relink that ONE chain, once, in a RUNLOG
//        whose .sig verifies under the current signer (seal/runlog-handover.ts relinkRunlogAttended), for the stuck
//        case where the append refuses to relink an anomalous chain itself. Refused when the RUNLOG does not
//        verify, is below its floor, the chain has no anomaly or a relink would not clear it (a duplicate index).
//        keys.ceremony (Owner) + step-up. Writes a runlog-relinked audit row recording what was acknowledged, and
//        raises the runlog-relinked alert (warning).

import { buildDestination, type RuntimeDestConfig, resolveDestination } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import { signerFingerprint } from "../format/writer-root.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { decodeVerifier } from "../sched/rekey-handover.ts";
import { diagnoseChain, type RunlogSignatureDiagnosis, diagnoseRunlogSignature, handOverRunlog, relinkRunlogAttended, resignRunlogAttended } from "../seal/runlog-handover.ts";
import { resolveRunlogSignature } from "../seal/pipeline.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { fetchRunlogFloor } from "./restore-open.ts";
import { gate, jsonError, jsonResponse, parseJsonBody, rateLimited, recordAudit } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { routeAuthChangeAlert } from "./router-notify.ts";
import { noteSiteFault } from "./site-faults.ts";

const DIGEST_RE = /^[0-9a-f]{96}$/;

interface Context {
  dest: Destination;
  bucket: string; // where this destination points now: endpoint host and bucket, or the R2 binding
  current: HybridVerifier;
  heldOld: HybridVerifier | null;
  pending: string[];
  floor: number | undefined;
}

// openContext resolves the destination, the current signer's verifier, any held re-key public key and the
// destination's confirmed floor. A Response is a refusal.
export async function openContext(ctx: RouterCtx, destinationId: string): Promise<Context | Response> {
  const { env, scheduler } = ctx;
  let current: HybridVerifier;
  try {
    const s = await loadSigner(env.SIGNER_PRIVATE ?? "");
    current = verifierFrom(s);
    s.mldsaSecret.fill(0);
  } catch {
    // site-fault-waiver: src/admin/router-runlog.ts:openContext:catch:1 -- an engine with no signer that loads is a setup state, and this 409 tells the Owner so
    return jsonError("the engine signer is not installed or does not load, so no RUNLOG can be checked or signed", 409);
  }
  let dest: Destination;
  let bucket: string;
  try {
    const res = await resolveDestination(env, scheduler, destinationId || undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
    if (!res.ok) return jsonError(`destination ${destinationId || "(default)"} is not configured (${res.reason})`, 404);
    bucket = bucketOf(env, res.config);
    dest = await buildDestination(env, undefined, res.config, destinationId || undefined);
  } catch (e) {
    noteSiteFault("runlog.attended-dest-open", e);
    return jsonError(`destination ${destinationId || "(default)"} could not be opened: ${(e as Error).message.slice(0, 160)}`, 409);
  }
  const h = (await (await scheduler.fetch(doURL("/rekey-handover"), { method: "GET" })).json()) as { open?: boolean; oldVerifier?: unknown; pending?: unknown };
  const heldOld = h.open === true ? decodeVerifier(h.oldVerifier) : null;
  const pending = Array.isArray(h.pending) ? h.pending.filter((p): p is string => typeof p === "string") : [];
  return { dest, bucket, current, heldOld, pending, floor: await fetchRunlogFloor(scheduler, destinationId || undefined) };
}

// refusalOf says why a re-sign cannot help, or null when it can.
function refusalOf(d: RunlogSignatureDiagnosis, floor: number | undefined): string | null {
  if (!d.present) return "there is no RUNLOG at this destination";
  if (d.state === "verified") return "the RUNLOG already verifies under the current signer";
  if (!d.parses) return "the RUNLOG does not parse, so a signature cannot make it readable";
  if (d.chainAnomaly) return `the RUNLOG chain has an anomaly (${d.chainAnomaly}), which a signature does not repair`;
  if (floor !== undefined && (d.maxIndex ?? 0) < floor) return `the RUNLOG's highest index (${d.maxIndex ?? 0}) is below the last good index (${floor}): it is a rollback, and a signature does not repair it`;
  return null;
}

async function view(ctx: Context, destinationId: string): Promise<Record<string, unknown>> {
  const d = await diagnoseRunlogSignature(ctx.dest, ctx.current, ctx.heldOld);
  const refusal = refusalOf(d, ctx.floor);
  return {
    destinationId,
    object: "_RECOVERY/RUNLOG",
    signatureObject: d.sigPresent ? "_RECOVERY/RUNLOG.sig" : "_RECOVERY/RUNLOG.sig (absent)",
    ...d,
    currentSigner: await signerFingerprint(ctx.current),
    ...(ctx.heldOld ? { heldOldSigner: await signerFingerprint(ctx.heldOld), handoverPending: ctx.pending.includes(destinationId) } : {}),
    lastGoodIndex: ctx.floor ?? null,
    canResign: refusalOf(d, ctx.floor) === null && d.state !== "pending-verifies",
    ...(refusal !== null ? { refusal } : {}),
  };
}

// bucketOf names where a destination points now, with no credential: a console destination's endpoint host and
// bucket, or the env-backed one (the R2 binding, or the DEST_* endpoint host and bucket).
function bucketOf(env: RouterCtx["env"], config: RuntimeDestConfig | null): string {
  // The endpoint is operator input, so one that does not parse is shown, not caught.
  const host = (u: string | undefined): string => (!u ? "(no endpoint)" : URL.canParse(u) ? new URL(u).host : "(unparsable endpoint)");
  if (config) return `${host(config.endpoint)}/${config.bucket}`;
  if (env.DEST_R2 !== undefined && env.DEST_R2 !== null) return "the R2 binding DEST_R2 (deploy-time destination)";
  return `${host(env.DEST_ENDPOINT)}/${env.DEST_BUCKET ?? "(no bucket)"} (deploy-time destination)`;
}

// floorRefusal says why the RUNLOG writers refuse this destination on the FLOOR alone, or null when they do not
// (no floor, the RUNLOG is at or above it, or the RUNLOG fails for another reason a floor reset cannot fix).
function floorRefusal(d: RunlogSignatureDiagnosis, floor: number | undefined): "absent-above-floor" | "below-floor" | null {
  if (floor === undefined) return null;
  if (!d.present) return "absent-above-floor";
  if (d.state !== "verified" && d.state !== "pending-verifies") return null;
  if (!d.parses) return null;
  return (d.maxIndex ?? 0) < floor ? "below-floor" : null;
}

// relinkRefusal says why an attended relink cannot help this chain, or null when it can.
function relinkRefusal(d: Awaited<ReturnType<typeof diagnoseChain>>, floor: number | undefined): string | null {
  if (!d.present) return "there is no RUNLOG at this destination";
  if (!d.verifies) return "the RUNLOG does not verify under the current signer; a relink never re-signs bytes that do not verify (see GET /admin/runlog/signature)";
  if (d.maxIndex === undefined) return "the RUNLOG does not parse";
  if (floor !== undefined && d.maxIndex < floor) return `the RUNLOG's highest index (${d.maxIndex}) is below the last good index (${floor}) (see GET /admin/runlog/floor)`;
  if (!d.anomaly) return "this downpipe's chain has no anomaly";
  if (!d.relinkClears) return `a relink does not clear this anomaly (${d.anomaly.kind}): two entries hold one index, and relinking does not change an index. Attach this downpipe to a fresh destination to keep backing up`;
  return null;
}

async function floorView(ctx: Context, destinationId: string): Promise<Record<string, unknown>> {
  const d = await diagnoseRunlogSignature(ctx.dest, ctx.current, null);
  const refusal = floorRefusal(d, ctx.floor);
  const blocked = ctx.floor !== undefined && d.present && d.state !== "verified" && d.state !== "pending-verifies";
  return {
    destinationId,
    bucket: ctx.bucket,
    floor: ctx.floor ?? null,
    runlogPresent: d.present,
    runlogState: d.state,
    ...(d.digest !== undefined ? { digest: d.digest } : {}),
    ...(d.maxIndex !== undefined ? { maxIndex: d.maxIndex } : {}),
    refusal: refusal === "absent-above-floor"
      ? `the RUNLOG is absent while index ${ctx.floor} was confirmed at this destination, so the writers will not start a fresh one`
      : refusal === "below-floor"
        ? `the RUNLOG's highest index (${d.maxIndex ?? 0}) is below the ${ctx.floor} confirmed at this destination, so the writers read it as a rollback`
        : null,
    canReset: refusal !== null,
    ...(refusal !== null ? { resetTo: d.present ? (d.maxIndex ?? 0) : 0 } : {}),
    ...(blocked ? { note: "the RUNLOG does not verify under the current signer; a floor reset does not help, see GET /admin/runlog/signature" } : {}),
  };
}

export async function handleRunlog(ctx: RouterCtx): Promise<Response | null> {
  const { req, url, scheduler, caller, sub, sourceIp, env } = ctx;
  switch (`${req.method} ${sub}`) {
    case "GET /runlog/signature": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const id = url.searchParams.get("destinationId") ?? "";
      const c = await openContext(ctx, id);
      if (c instanceof Response) return c;
      return jsonResponse(await view(c, id));
    }
    case "POST /runlog/resign": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const parsed = await parseJsonBody<{ destinationId?: unknown; digest?: unknown }>(req);
      const body = parsed.ok ? parsed.body : {};
      const id = typeof body.destinationId === "string" ? body.destinationId : "";
      const digest = typeof body.digest === "string" ? body.digest.toLowerCase() : "";
      if (!DIGEST_RE.test(digest)) return jsonError("digest must be the 96-hex SHA-384 of the RUNLOG bytes, as GET /admin/runlog/signature shows it", 400);
      const c = await openContext(ctx, id);
      if (c instanceof Response) return c;
      const d = await diagnoseRunlogSignature(c.dest, c.current, c.heldOld);
      if (d.digest !== digest) return jsonError("the RUNLOG changed since it was shown; read it again before deciding", 409);
      if (d.state === "pending-verifies") {
        // The engine's own interrupted write: resume it from the pending signature. No Owner decision is needed.
        await resolveRunlogSignature(c.dest, (await c.dest.get("_RECOVERY/RUNLOG"))?.body ?? new Uint8Array(), c.current);
        return jsonResponse({ ok: true, outcome: "resumed", destinationId: id });
      }
      const refusal = refusalOf(d, c.floor);
      if (refusal !== null) return jsonError(`not re-signed: ${refusal}`, 409);
      let outcome: string;
      let state: string = d.state;
      const signer = await loadSigner(env.SIGNER_PRIVATE ?? "");
      try {
        if (d.verifiesUnderHeldOld && c.heldOld) {
          // The pending re-key hand-over, finished under the held old public key: only bytes that key verifies.
          state = "held-old";
          outcome = await handOverRunlog(c.dest, c.heldOld, signer);
          if (outcome === "re-signed" || outcome === "already-current") {
            const settled = (await (await scheduler.fetch(doURL("/rekey-handover/settle"), { method: "POST", body: JSON.stringify({ pending: c.pending.filter((p) => p !== id) }), headers: { "content-type": "application/json" } })).json()) as { discarded?: unknown };
            if (settled.discarded === true) await recordAudit(scheduler, caller, sourceIp, "runlog-handover", "success", { kind: "runlog-signature", op: "held-key-discarded" });
          }
        } else {
          outcome = await resignRunlogAttended(c.dest, signer, digest);
        }
      } finally {
        signer.mldsaSecret.fill(0);
      }
      if (outcome !== "re-signed" && outcome !== "already-current") return jsonError(`not re-signed: ${outcome === "changed-since-read" ? "the RUNLOG changed since it was shown; read it again before deciding" : outcome}`, 409);
      await recordAudit(scheduler, caller, sourceIp, "runlog-resigned", "success", { kind: "runlog-signature", op: "resign", destinationIds: [id], state, digest: digest.slice(0, 24), ...(d.maxIndex !== undefined ? { maxIndex: d.maxIndex } : {}), ...(c.floor !== undefined ? { lastGoodIndex: c.floor } : {}) });
      const who = caller.email ? ` by ${caller.email}` : "";
      await routeAuthChangeAlert(env, scheduler, "runlog-resigned", "dest-change", `The backup RUNLOG of destination ${id || "(default)"} did not verify (${state}) and was re-signed${who}. Highest index ${d.maxIndex ?? 0}, last good index ${c.floor ?? "none"}. Check this was expected.`);
      log("warn", `runlog-resigned: destination ${id || "(default)"} (${state}) re-signed by an Owner after step-up`);
      return jsonResponse({ ok: true, outcome: "re-signed", destinationId: id, state, maxIndex: d.maxIndex ?? 0, lastGoodIndex: c.floor ?? null });
    }
    case "GET /runlog/floor": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const id = url.searchParams.get("destinationId") ?? "";
      const c = await openContext(ctx, id);
      if (c instanceof Response) return c;
      return jsonResponse(await floorView(c, id));
    }
    case "POST /runlog/floor/reset": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const parsed = await parseJsonBody<{ destinationId?: unknown; expectFloor?: unknown; digest?: unknown }>(req);
      const body = parsed.ok ? parsed.body : {};
      const id = typeof body.destinationId === "string" ? body.destinationId : "";
      const c = await openContext(ctx, id);
      if (c instanceof Response) return c;
      const d = await diagnoseRunlogSignature(c.dest, c.current, null);
      const refusal = floorRefusal(d, c.floor);
      if (refusal === null) return jsonError("not reset: the RUNLOG writers do not refuse this destination on its floor (see GET /admin/runlog/floor)", 409);
      if (body.expectFloor !== c.floor || (d.present ? body.digest !== d.digest : body.digest !== "absent")) return jsonError("the floor or the RUNLOG changed since it was shown; read it again before deciding", 409);
      const to = d.present ? (d.maxIndex ?? 0) : 0;
      const r = (await (await scheduler.fetch(doURL("/runlog-floor/reset"), { method: "POST", body: JSON.stringify({ id, expect: c.floor, to }), headers: { "content-type": "application/json" } })).json()) as { outcome?: unknown };
      if (r.outcome !== "reset") return jsonError("the floor changed since it was shown; read it again before deciding", 409);
      await recordAudit(scheduler, caller, sourceIp, "runlog-floor-reset", "success", { kind: "runlog-signature", op: "floor-reset", destinationIds: [id], state: refusal, ...(d.digest !== undefined ? { digest: d.digest.slice(0, 24) } : {}), maxIndex: to, ...(c.floor !== undefined ? { lastGoodIndex: c.floor } : {}) });
      const who = caller.email ? ` by ${caller.email}` : "";
      await routeAuthChangeAlert(env, scheduler, "runlog-floor-reset", "dest-change", `The anti-rollback floor of destination ${id || "(default)"} (${c.bucket}) was reset from ${c.floor} to ${to}${who} (${refusal}). Check this was expected: a reset accepts the RUNLOG this bucket holds now.`);
      log("warn", `runlog-floor-reset: destination ${id || "(default)"} floor ${c.floor} -> ${to} (${refusal}) by an Owner after step-up`);
      return jsonResponse({ ok: true, outcome: "reset", destinationId: id, oldFloor: c.floor, newFloor: to, reason: refusal });
    }
    case "GET /runlog/chain": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const id = url.searchParams.get("destinationId") ?? "";
      const downpipeId = url.searchParams.get("downpipeId") ?? "";
      if (downpipeId === "") return jsonError("downpipeId is required", 400);
      const c = await openContext(ctx, id);
      if (c instanceof Response) return c;
      const d = await diagnoseChain(c.dest, c.current, downpipeId);
      const refusal = relinkRefusal(d, c.floor);
      return jsonResponse({ destinationId: id, downpipeId, bucket: c.bucket, ...d, lastGoodIndex: c.floor ?? null, canRelink: refusal === null, ...(refusal !== null ? { refusal } : {}) });
    }
    case "POST /runlog/relink": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const parsed = await parseJsonBody<{ destinationId?: unknown; downpipeId?: unknown; digest?: unknown; anomalyKind?: unknown }>(req);
      const body = parsed.ok ? parsed.body : {};
      const id = typeof body.destinationId === "string" ? body.destinationId : "";
      const downpipeId = typeof body.downpipeId === "string" ? body.downpipeId : "";
      const digest = typeof body.digest === "string" ? body.digest.toLowerCase() : "";
      if (downpipeId === "" || !DIGEST_RE.test(digest)) return jsonError("downpipeId and the 96-hex digest GET /admin/runlog/chain shows are required", 400);
      const c = await openContext(ctx, id);
      if (c instanceof Response) return c;
      const d = await diagnoseChain(c.dest, c.current, downpipeId);
      if (d.digest !== digest || d.anomaly?.kind !== body.anomalyKind) return jsonError("the RUNLOG or its chain changed since it was shown; read it again before deciding", 409);
      const refusal = relinkRefusal(d, c.floor);
      if (refusal !== null) return jsonError(`not relinked: ${refusal}`, 409);
      const signer = await loadSigner(env.SIGNER_PRIVATE ?? "");
      let outcome: string;
      try {
        outcome = await relinkRunlogAttended(c.dest, signer, downpipeId, digest);
      } finally {
        signer.mldsaSecret.fill(0);
      }
      if (outcome !== "relinked") return jsonError(`not relinked: ${outcome}`, 409);
      const a = d.anomaly!;
      await recordAudit(scheduler, caller, sourceIp, "runlog-relinked", "success", { kind: "runlog-signature", op: "relink", destinationIds: [id], downpipeId, state: a.kind, ...(a.indexA !== undefined ? { indexA: a.indexA } : {}), ...(a.indexB !== undefined ? { indexB: a.indexB } : {}), ...(d.chainEntries !== undefined ? { chainEntries: d.chainEntries } : {}), digest: digest.slice(0, 24) });
      const who = caller.email ? ` by ${caller.email}` : "";
      await routeAuthChangeAlert(env, scheduler, "runlog-relinked", "dest-change", `The backup RUNLOG chain of downpipe ${downpipeId} at destination ${id || "(default)"} had an anomaly (${a.kind}) and was relinked${who}. Check this was expected: a relink accepts that chain's history as it stands.`);
      log("warn", `runlog-relinked: destination ${id || "(default)"} downpipe ${downpipeId} (${a.kind}) relinked by an Owner after step-up`);
      return jsonResponse({ ok: true, outcome: "relinked", destinationId: id, downpipeId, acknowledged: a.kind });
    }
    default:
      return null;
  }
}
