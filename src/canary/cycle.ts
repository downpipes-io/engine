import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { destDownReason } from "../dest/classify.ts";
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import type { Run } from "../format/reader.ts";
import { openRun, openRunWithMaster } from "../format/reader.ts";
import type { Signer } from "../format/writer.ts";
import { loadIdentity, loadRecipients, loadSigner, verifierFrom } from "../keys-env.ts";
import { type RunClock, type RunConfig, runBackup } from "../seal/pipeline.ts";
import { CANARY_CORPUS, type CanaryRecord, CanarySource } from "./corpus.ts";
import { byteDelta, bytesEqual, classifyReadFailure, cleanup, finalise, nowIso, reqEnv } from "./cycle-helpers.ts";
import { PrefixedDestination, prefixedStore } from "./prefixed-dest.ts";
import { CANARY_DOWNPIPE_ID, CANARY_NAMESPACE_PREFIX, type CanaryAspectResult, type CanaryCheckResult, type CanaryRunDescriptor } from "./types.ts";

// runCanaryCycle flies one canary: it writes the known corpus to an isolated cell inside the
// configured destination, validates the read-back signatures and freshness, decrypts every
// record and compares it to the known bytes, restores over the cell, and tests the restored
// bytes against the known corpus. Every byte returning exactly means the bird sings (alive);
// any byte straying means it is dead (evacuate). A fault that stops the check completing (the
// destination unreachable) is ailing, not a death, and is quiet.
//
// It NEVER throws: it always returns a redaction-safe CanaryCheckResult the DO folds into the
// history. It touches only the _CANARY/ namespace and never a customer archive or a real
// binding, so a canary flight can never affect a real backup (fail-open).

// A step either finishes the flight early (done) or hands the next step the data it produced (ok).
type Step<T> = { done: CanaryCheckResult } | { ok: T };

// CycleCtx threads the accumulated aspects, the add() recorder and the run identity through the
// named steps so each step reads as one phase of the flight.
interface CycleCtx {
  env: Env;
  run: CanaryRunDescriptor;
  startMs: number;
  aspects: CanaryAspectResult[];
  add: (key: CanaryAspectResult["key"], outcome: CanaryAspectResult["outcome"], detail: string) => void;
}

// resolveDestination resolves the destination the operator pointed the canary at (null = the
// account default). A configured-but-unreadable destination is a fault, not a death: report
// pending so the bird sits quiet until a destination exists, rather than crying wolf every hour
// before setup.
async function resolveDestination(ctx: CycleCtx, scheduler: DurableObjectStub): Promise<Step<{ baseDest: Destination; dest: PrefixedDestination; prefix: string }>> {
  let baseDest: Destination;
  try {
    const destCfg = await fetchDestConfig(scheduler, ctx.run.destinationId, loadConfigWrapKey(ctx.env.CONFIG_WRAP_KEY));
    baseDest = await buildDestination(ctx.env, undefined, destCfg);
  } catch {
    ctx.add("write-probe", "skip", "no destination is configured for the canary yet");
    return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, { status: "pending", reason: "no destination configured" }) };
  }
  const prefix = `${CANARY_NAMESPACE_PREFIX}${ctx.run.runId}/`;
  const dest = new PrefixedDestination(baseDest, prefix);
  return { ok: { baseDest, dest, prefix } };
}

// runProbes runs ASPECT 1 + 2: write-probe (can PUT) and delete-probe (can DELETE / immutability
// observation). A probe object is written, read back byte-exact, then deleted. A write failure
// halts the flight (ailing: the path is unreachable, not proven drifted). A delete failure is a
// NOTE, never a death: an immutable bucket legitimately refuses it (the archive can write, the
// prune cannot), which is worth surfacing but is not a dead canary. NOTE: this is a COARSE
// observation (a refused delete merely SUGGESTS immutability); the AUTHORITATIVE WORM/Object-Lock
// signal is the posture "immutability" check, fed by the real capability probe
// (Destination.objectLockStatus / GetObjectLockConfiguration), see src/admin/posture.ts. The
// posture does NOT infer immutability from this delete behaviour.
async function runProbes(ctx: CycleCtx, dest: PrefixedDestination): Promise<Step<void>> {
  const probeBytes = crypto.getRandomValues(new Uint8Array(32));
  try {
    await dest.put("_probe", probeBytes);
    const got = await dest.get("_probe");
    if (!got || !bytesEqual(got.body, probeBytes)) {
      ctx.add("write-probe", "fail", "the destination did not return the probe bytes it was given");
      return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, { status: "ailing", reason: "write probe mismatch", ailingCause: "probe-mismatch" }) };
    }
    ctx.add("write-probe", "pass", "the destination accepted and returned a probe object");
  } catch (e) {
    ctx.add("write-probe", "fail", "the destination refused the write probe");
    // The throw is CLASSIFIED rather than assumed: a refused write is an expired credential, a WORM
    // retention refusal, a throttling store or a dead endpoint, and each needs a different operator action.
    return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, { status: "ailing", reason: "write probe failed", ailingCause: destDownReason(e) }) };
  }
  try {
    await dest.delete("_probe");
    ctx.add("delete-probe", "pass", "the destination allowed the probe object to be deleted");
  } catch {
    ctx.add("delete-probe", "note", "the destination refused the delete (an immutable bucket keeps the prune out)");
  }
  return { ok: undefined };
}

// runSeal runs ASPECT 3: build a real archive of the known corpus, signed and encrypted to the
// same recipients a real backup uses, written through the identical seal pipeline (only
// namespaced). It returns the loaded signer so later steps can verify and then zero it; on
// failure it zeroes the signer, notes the failure, cleans up and ends the flight ailing. The
// per-run master is OWNED BY runCanaryCycle and passed in, because openAndVerify needs it after
// this returns; this function must not zero it.
async function runSeal(ctx: CycleCtx, dest: PrefixedDestination, baseDest: Destination, master: Uint8Array): Promise<Step<Signer>> {
  let signer: Signer | undefined;
  try {
    signer = await loadSigner(reqEnv(ctx.env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
    // Hereafter (past this try) signer is always assigned: every path out of the seal block that
    // skips the assignment goes through the catch, which returns.
    const recipients = loadRecipients(reqEnv(ctx.env.BREAK_GLASS_PUBLIC, "BREAK_GLASS_PUBLIC"), ctx.env.OPERATIONAL_PUBLIC);
    const cfg: RunConfig = {
      downpipeId: CANARY_DOWNPIPE_ID,
      downpipeName: "Canary",
      cadence: "3600s",
      selector: { include: [], exclude: [] },
      recipients,
    };
    // A self-contained RUNLOG per flight (index 1, no prior chain): the cell is the only run in
    // its namespace, so freshness reads it as the latest. The flight uses a fresh per-run master
    // and zeroes it when the flight ends, exactly like a real run.
    const clock: RunClock = {
      runId: ctx.run.runId,
      runlogIndex: 1,
      prevRunId: null,
      now: nowIso(),
      randomNonce: () => crypto.getRandomValues(new Uint8Array(16)),
      randomSalt: () => crypto.getRandomValues(new Uint8Array(16)),
      // The master is OWNED BY runCanaryCycle, not allocated here, so its single finally zeroises it on
      // every exit including the early ailing returns below. openAndVerify needs it after this function
      // returns (it is how a break-glass-only engine reads its own canary cell back), so zeroising it
      // here -- as this function used to -- would defeat the whole read-back.
      master,
    };
    const summary = await runBackup([new CanarySource()], cfg, signer, dest, clock);
    ctx.add("seal", "pass", `sealed ${summary.records} records (${summary.bytes} bytes) to the canary cell`);
  } catch {
    if (signer) signer.mldsaSecret.fill(0);
    ctx.add("seal", "fail", "the archive could not be sealed to the destination");
    cleanup(baseDest, ctx.run.cleanupRunId).catch(() => {});
    return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, { status: "ailing", reason: "seal failed", ailingCause: "other" }) };
  }
  return { ok: signer };
}

// openAndVerify runs ASPECT 4 + 5: open and verify the run (root + shard signatures, the RUNLOG
// chain and freshness). It opens with the in-account read-back key (the OPERATIONAL identity)
// when there is one, and otherwise with this flight's own per-run master, so the read-back runs
// in every posture. Either path zeroes the signer.
async function openAndVerify(ctx: CycleCtx, prefix: string, baseDest: Destination, signer: Signer, master: Uint8Array): Promise<Step<Run>> {
  // A break-glass-only engine holds no in-account read-back key. It still holds this flight's own
  // per-run master (the canary seals its OWN synthetic corpus), which opens this cell and nothing
  // else, so the read-back runs in every posture rather than skipping for a break-glass-only engine.
  //
  // PRECEDENCE IS DELIBERATE, and it mirrors verify-at-seal. With the operational key present the cell is
  // opened through the CAPSULE, so the recipient-wrap decapsulation stays exercised hourly; preferring
  // the master would have deleted the last recurring proof that a wrap actually opens. Neither path
  // exercises the BREAK-GLASS wrap: the engine has never held that private and cannot, so no RUNNING engine,
  // in either posture, proves the offline key opens what was sealed to it. Attended verification is the only
  // thing that proves it in production, and the aspect detail below says so rather than implying otherwise.
  //
  // Worded carefully, because the earlier phrasing read as "nothing proves this anywhere" and sent a reader
  // hunting a gap that is covered. The PROPERTY is proven, just not by anything running here:
  // test/validate-restore-from-master.ts decapsulates a sealed run's capsule with the break-glass private,
  // asserts the recovered master is the one the run was sealed under, and opens the run from it in an
  // environment holding no operational key. What is missing live is a check, not a proof.
  const haveOperationalKey = typeof ctx.env.OPERATIONAL_PRIVATE === "string" && ctx.env.OPERATIONAL_PRIVATE.length > 0;

  let opened: Run;
  try {
    const verifier = verifierFrom(signer);
    const store = prefixedStore(baseDest, prefix);
    const opts = { verifyFreshness: true, allowStale: false };
    opened = haveOperationalKey
      ? await openRun(store, ctx.run.runId, loadIdentity(ctx.env.OPERATIONAL_PRIVATE as string), verifier, opts)
      : await openRunWithMaster(store, ctx.run.runId, master, verifier, opts);
    ctx.add("read-signature", "pass", haveOperationalKey ? "the root and shard manifest signatures verified, and the operational recipient wrap opened" : "the root and shard manifest signatures verified, opened with this flight's own run key");
    ctx.add("runlog-freshness", "pass", "the RUNLOG entry verified fresh and chained");
  } catch (e) {
    signer.mldsaSecret.fill(0);
    const c = classifyReadFailure(e);
    ctx.add(c.aspect, c.dead ? "fail" : "skip", c.detail);
    cleanup(baseDest, ctx.run.cleanupRunId).catch(() => {});
    return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, c.dead ? undefined : { status: "ailing", reason: c.detail, ailingCause: destDownReason(e) }) };
  }
  signer.mldsaSecret.fill(0);
  return { ok: opened };
}

// decryptAndCompare runs ASPECT 6: decrypt every record and compare it to the KNOWN corpus,
// byte-for-byte. The match is by exact bytes (record names are stored only as
// privacy-preserving hashes), so it is order-independent and collision-safe. restoreRecord also
// re-verifies each record's own plaintext hash; the corpus comparison is the stronger "exact
// known data" check on top. It returns the restored pairs for the restore step.
async function decryptAndCompare(ctx: CycleCtx, opened: Run, baseDest: Destination): Promise<Step<{ plaintext: Uint8Array; corpus: CanaryRecord }[]>> {
  const remaining: CanaryRecord[] = CANARY_CORPUS.map((r) => ({ name: r.name, value: r.value }));
  const restored: { plaintext: Uint8Array; corpus: CanaryRecord }[] = [];
  let strayBytes = 0;
  let strayRecords = 0;
  try {
    for (const rec of opened.records) {
      const plaintext = await opened.restoreRecord(rec);
      const idx = remaining.findIndex((c) => bytesEqual(c.value, plaintext));
      if (idx >= 0) {
        const corpus = remaining.splice(idx, 1)[0]!;
        restored.push({ plaintext, corpus });
      } else {
        strayRecords++;
        // Best-effort delta against a same-length known record, else the whole record strayed.
        const sameLen = remaining.find((c) => c.value.length === plaintext.length);
        strayBytes += sameLen ? byteDelta(plaintext, sameLen.value) : plaintext.length;
      }
    }
  } catch (e) {
    // A throw here is EITHER a genuine integrity failure (a record did not decrypt, or its plaintext
    // hash did not match) OR a TRANSPORT fault: restoreRecord issues a store.get per segment, so a
    // transient destination 500 or a timeout lands in this same catch. Failing blanket would call a
    // transient destination 500 or a timeout lands in this same catch. Failing blanket would call a
    // destination blip a data-integrity DEATH and fire the evacuation alert on a break-glass-only estate
    // just as readily as any other, so the classifier below is what keeps that path honest.
    // Reuse the classifier openAndVerify already uses: transport degrades to ailing, a real integrity
    // fault is still a death, and an unrecognised message still FAILS CLOSED to a death.
    const c = classifyReadFailure(e);
    ctx.add("decrypt-integrity", c.dead ? "fail" : "skip", c.dead ? "a record failed to decrypt or failed its plaintext hash" : c.detail);
    cleanup(baseDest, ctx.run.cleanupRunId).catch(() => {});
    if (!c.dead) return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, { status: "ailing", reason: c.detail, ailingCause: destDownReason(e) }) };
    return { done: { status: "dead", durationMs: Date.now() - ctx.startMs, destinationId: ctx.run.destinationId, aspects: ctx.aspects, byteDelta: null, deadReason: "decrypt-integrity: a record failed to decrypt" } };
  }
  // A missing known record (remaining non-empty) or an unexpected stray is a drift.
  for (const missing of remaining) strayBytes += missing.value.length;
  const recordsOk = remaining.length === 0 && strayRecords === 0;
  if (!recordsOk) {
    ctx.add("decrypt-integrity", "fail", `${remaining.length + strayRecords} records diverged; ${strayBytes} bytes strayed from the known corpus`);
    cleanup(baseDest, ctx.run.cleanupRunId).catch(() => {});
    return { done: { status: "dead", durationMs: Date.now() - ctx.startMs, destinationId: ctx.run.destinationId, aspects: ctx.aspects, byteDelta: strayBytes, deadReason: `decrypt-integrity: ${strayBytes} bytes strayed from the known data` } };
  }
  ctx.add("decrypt-integrity", "pass", `${restored.length} records decrypted and matched the known corpus byte-for-byte`);
  return { ok: restored };
}

// restoreAndVerify runs ASPECT 7 + 8: restore over the canary cell and test the restored bytes
// against the known corpus. Each restored value is written back into the cell (the real
// restore-write path, proving restore-side permission) and read back, then byte-compared to the
// known data.
async function restoreAndVerify(ctx: CycleCtx, dest: PrefixedDestination, baseDest: Destination, restored: { plaintext: Uint8Array; corpus: CanaryRecord }[]): Promise<Step<void>> {
  let restoreStray = 0;
  try {
    for (let i = 0; i < restored.length; i++) {
      const pair = restored[i]!;
      await dest.put(`restored/${i}`, pair.plaintext);
      const got = await dest.get(`restored/${i}`);
      if (!got || !bytesEqual(got.body, pair.corpus.value)) {
        restoreStray += got ? byteDelta(got.body, pair.corpus.value) : pair.corpus.value.length;
      }
    }
  } catch (e) {
    // Same split as the decrypt step. This loop is a put + a get per record, so a destination that
    // starts refusing writes mid-restore throws here; that is the destination being unreachable, not
    // the customer's data having drifted. Only an unrecognised or integrity-shaped failure is a death.
    const c = classifyReadFailure(e);
    ctx.add("restore", c.dead ? "fail" : "skip", c.dead ? "the restore could not write the recovered data back to the cell" : c.detail);
    cleanup(baseDest, ctx.run.cleanupRunId).catch(() => {});
    if (!c.dead) return { done: finalise(ctx.aspects, ctx.run.destinationId, ctx.startMs, { status: "ailing", reason: c.detail, ailingCause: destDownReason(e) }) };
    return { done: { status: "dead", durationMs: Date.now() - ctx.startMs, destinationId: ctx.run.destinationId, aspects: ctx.aspects, byteDelta: null, deadReason: "restore: the restore-write failed" } };
  }
  ctx.add("restore", "pass", `${restored.length} records restored over the isolated canary cell`);
  if (restoreStray > 0) {
    ctx.add("restore-verify", "fail", `the restored data strayed ${restoreStray} bytes from the known corpus`);
    cleanup(baseDest, ctx.run.cleanupRunId).catch(() => {});
    return { done: { status: "dead", durationMs: Date.now() - ctx.startMs, destinationId: ctx.run.destinationId, aspects: ctx.aspects, byteDelta: restoreStray, deadReason: `restore-verify: ${restoreStray} bytes strayed after restore` } };
  }
  ctx.add("restore-verify", "pass", "every restored byte matched the known corpus exactly");
  return { ok: undefined };
}

export async function runCanaryCycle(env: Env, scheduler: DurableObjectStub, run: CanaryRunDescriptor): Promise<CanaryCheckResult> {
  const startMs = Date.now();
  const aspects: CanaryAspectResult[] = [];
  const add = (key: CanaryAspectResult["key"], outcome: CanaryAspectResult["outcome"], detail: string): void => {
    aspects.push({ key, outcome, detail });
  };
  const ctx: CycleCtx = { env, run, startMs, aspects, add };

  // The flight's per-run master is allocated HERE, not inside runSeal, for one reason: openAndVerify
  // needs it after the seal (it is how a break-glass-only engine reads its own cell back), and the
  // cycle has roughly ten early `{done}` returns. Owning it at this level means ONE finally zeroises it
  // on every one of those exits, including the throwing ones, instead of each step having to remember.
  const master = crypto.getRandomValues(new Uint8Array(32));
  // The Run opened below owns a master too, and it is NOT always this one. With an operational key present,
  // openRun decapsulates a separate master from the run's capsule and holds it inside the Run, so zeroising
  // the buffer above would leave that one live. Hoisted here for the same reason the master is: one finally
  // ends it on every exit, including the throwing ones.
  let opened: Run | undefined;
  try {
    const resolved = await resolveDestination(ctx, scheduler);
    if ("done" in resolved) return resolved.done;
    const { baseDest, dest, prefix } = resolved.ok;

    const probed = await runProbes(ctx, dest);
    if ("done" in probed) return probed.done;

    const sealed = await runSeal(ctx, dest, baseDest, master);
    if ("done" in sealed) return sealed.done;
    const signer = sealed.ok;

    const verified = await openAndVerify(ctx, prefix, baseDest, signer, master);
    if ("done" in verified) return verified.done;
    opened = verified.ok;

    const compared = await decryptAndCompare(ctx, opened, baseDest);
    if ("done" in compared) return compared.done;
    const restored = compared.ok;

    const restoreVerified = await restoreAndVerify(ctx, dest, baseDest, restored);
    if ("done" in restoreVerified) return restoreVerified.done;

    // Housekeeping: delete the PRIOR flight's cell, so only the latest cell lingers (a tiny
    // residue). This is best-effort and doubles as a real deletion of real objects; an immutable
    // bucket simply keeps them, which the delete-probe has already noted.
    cleanup(baseDest, run.cleanupRunId).catch(() => {});

    return finalise(aspects, run.destinationId, startMs);
  } finally {
    master.fill(0);
    opened?.dispose();
  }
}
