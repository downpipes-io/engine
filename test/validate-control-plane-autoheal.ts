// Prove the AUTO-RECONCILE-ON-DETECT (the SAFE auto-heal) end to end, server-side, with in-memory
// doubles only. No network, no deploy, no cost. Run:
//   node test/validate-control-plane-autoheal.ts
//
// The auto-heal restores backups WITHOUT silently restoring authority. What this proves:
//
//  - SELECTION (the cron's refuse-on-ambiguity logic): selectLatestControlPlaneExport picks the single
//    signed latest-generation export, REFUSES when two artefacts claim the same latest generation
//    (ambiguous), REFUSES when the latest has no detached signature (unsigned), and returns "none" for an
//    empty namespace. parseControlPlaneArtefactVersion parses the padded version (and rejects .sig/foreign).
//  - BUCKET-SCAN + VERIFY (the cron's read path against a real artefact layout): writing the signed export
//    + its .sig to a MemoryDestination the way the export pass does, the scan selects it, reads it back, and
//    it VERIFIES; a tampered body fails verification; a second artefact at the same top version is ambiguous.
//  - RESUME SLICE = NO AUTHORITY (the headline invariant): applying the resume slice from a verified export
//    on a wiped DO restores the downpipes + destinations so BACKUPS RESUME, but DOES NOT restore RBAC, DOES
//    NOT clear the silence-killer latch, and DOES NOT re-arm the first-Owner bootstrap. An Access caller
//    STILL resolves to recovery-required viewer — the auto-heal can NEVER silently re-bootstrap Owner to
//    whoever calls first. A no-latch resume is refused. Idempotent. A control-plane-resumed audit is written.
//  - BREAK-GLASS CONFIRM = the only path to authority: applyControlPlaneAuthoritySlice restores RBAC, clears
//    the latch, re-arms bootstrap and writes the bridge ONLY for the bare-token break-glass; a non-token
//    caller is refused; it refuses to clobber a non-empty role table; the restored Owner then resolves to
//    Owner with no re-bootstrap; the staged record is consumed.

import { makeScheduler, makeConfig, stubFetch } from "./validate-scheduler-shared.ts";
import { MemoryDestination } from "./memdest.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { wrapConfigSecret } from "../src/admin/config-secret.ts";
import {
  type ControlPlaneExport,
  type StagedControlPlane,
  assertNoPlaintextSecretInExport,
  candidateVersionMatchesExport,
  controlPlaneArtefactKey,
  isControlPlaneExport,
  parseControlPlaneArtefactVersion,
  selectLatestControlPlaneExport,
  selectLatestSealedControlPlaneExport,
  plaintextGenerationKeysToPurge,
  serialiseControlPlaneExport,
  signControlPlaneExport,
  verifyControlPlaneSignature,
} from "../src/admin/control-plane.ts";
import type { DestinationCollection, StoredDestination } from "../src/sched/scheduler-do-base.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function seedStoredDest(id: string, secretAccessKey: StoredDestination["secretAccessKey"]): StoredDestination {
  return {
    id,
    label: `dest ${id}`,
    endpoint: "https://s3.example.com",
    bucket: `bucket-${id}`,
    region: "auto",
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey,
    setAt: 1_700_000_000_000,
    setBy: "owner@example.com",
    verifiedAt: 1_700_000_000_000,
    deleteProbe: "ok",
  };
}

// stage builds the parked StagedControlPlane the cron auto-heal would store (the export + its detached sig).
function stagedFrom(exp: ControlPlaneExport, signature: string, version: number): StagedControlPlane {
  return { export: exp, signature, sourceKey: controlPlaneArtefactKey(version, exp.exportedAt), version, stagedAt: new Date().toISOString(), resumeApplied: false };
}

async function main(): Promise<void> {
  const seed = crypto.getRandomValues(new Uint8Array(64));
  const signer = await loadSigner(b64urlEncode(seed));
  const verifier = verifierFrom(signer);
  const wrapKey = crypto.getRandomValues(new Uint8Array(32));

  // ---- Seed a real export from DO-A (a downpipe, a wrapped destination, a bootstrapped Owner) ----------
  const A = makeScheduler();
  await A.stub.addDownpipe(makeConfig("dp-amnesia"));
  const wrapped = await wrapConfigSecret(wrapKey, "super-secret-s3-key");
  const coll: DestinationCollection = { list: [seedStoredDest("d1", wrapped)], defaultId: "d1" };
  await A.stub.saveDestinations(coll);
  const bootA = await A.stub.whoami("owner@example.com", "subj-owner", "access", null);
  ok("seed: first Access caller bootstraps Owner", bootA.role === "owner");
  const exp = await A.stub.buildControlPlaneExport();
  const sig = await signControlPlaneExport(signer, exp);

  // ---- (1) PURE SELECTION: parse + refuse-on-ambiguity/unsigned --------------------------------------
  ok("parse: a well-formed .json artefact key yields its version", parseControlPlaneArtefactVersion("_RECOVERY/CONTROL-PLANE/000000000009-2026-06-28T10-30-00.123Z.json") === 9);
  ok("parse: a .sig sibling is not a candidate (null)", parseControlPlaneArtefactVersion("_RECOVERY/CONTROL-PLANE/000000000009-2026-06-28T10-30-00.123Z.json.sig") === null);
  ok("parse: a foreign key is not a candidate (null)", parseControlPlaneArtefactVersion("run/abc/root.json") === null);
  // A SEALED generation (S5) ends with .json too, but is NOT a plaintext candidate: the plaintext auto-heal
  // scanner must skip it (the sealed auto-heal handles it separately), so a mixed transition never misparses one.
  ok("parse: a .sealed.json generation is NOT a plaintext candidate (null)", parseControlPlaneArtefactVersion("_RECOVERY/CONTROL-PLANE/000000000009-2026-06-28T10-30-00.123Z.sealed.json") === null);

  const k5 = "_RECOVERY/CONTROL-PLANE/000000000005-2026-06-28T09-00-00.000Z.json";
  const k9 = "_RECOVERY/CONTROL-PLANE/000000000009-2026-06-28T10-00-00.000Z.json";
  const k9b = "_RECOVERY/CONTROL-PLANE/000000000009-2026-06-28T11-00-00.000Z.json";
  ok("select: empty namespace => none", selectLatestControlPlaneExport([]).kind === "none");
  ok("select: only .sig (no .json) => none", selectLatestControlPlaneExport([`${k9}.sig`]).kind === "none");
  const single = selectLatestControlPlaneExport([k9, `${k9}.sig`]);
  ok("select: a single signed artefact => ok", single.kind === "ok" && single.jsonKey === k9 && single.sigKey === `${k9}.sig`);
  const twoGen = selectLatestControlPlaneExport([k5, `${k5}.sig`, k9, `${k9}.sig`]);
  ok("select: two generations => picks the LATEST (v9), ignores the older v5", twoGen.kind === "ok" && twoGen.version === 9 && twoGen.jsonKey === k9);
  const ambiguous = selectLatestControlPlaneExport([k9, `${k9}.sig`, k9b, `${k9b}.sig`]);
  ok("select: TWO artefacts at the same latest generation => AMBIGUOUS (refuse)", ambiguous.kind === "ambiguous" && ambiguous.version === 9);
  const unsigned = selectLatestControlPlaneExport([k5, `${k5}.sig`, k9]); // v9 has no .sig
  ok("select: the latest artefact has no signature => UNSIGNED (refuse, no older fallback)", unsigned.kind === "unsigned" && unsigned.version === 9);

  // ---- (1a-sealed) SELECTION of SEALED generations (S5), and plaintext/sealed isolation ---------------
  const s5 = "_RECOVERY/CONTROL-PLANE/000000000005-2026-06-28T09-00-00.000Z.sealed.json";
  const s9 = "_RECOVERY/CONTROL-PLANE/000000000009-2026-06-28T10-00-00.000Z.sealed.json";
  ok("sealed-select: empty => none", selectLatestSealedControlPlaneExport([]).kind === "none");
  const sSingle = selectLatestSealedControlPlaneExport([s9, `${s9}.sig`]);
  ok("sealed-select: a single signed sealed artefact => ok", sSingle.kind === "ok" && sSingle.jsonKey === s9 && sSingle.sigKey === `${s9}.sig`);
  const sTwo = selectLatestSealedControlPlaneExport([s5, `${s5}.sig`, s9, `${s9}.sig`]);
  ok("sealed-select: two sealed generations => picks the latest (v9)", sTwo.kind === "ok" && sTwo.version === 9);
  ok("sealed-select: an unsigned latest sealed => unsigned (refuse)", selectLatestSealedControlPlaneExport([s9]).kind === "unsigned");
  // ISOLATION: the plaintext scanner ignores sealed keys, and the sealed scanner ignores plaintext keys, so a
  // mixed bucket never confuses one for the other (each finds only its own regime).
  ok("isolation: the PLAINTEXT scanner ignores a sealed generation (=> none on sealed-only)", selectLatestControlPlaneExport([s9, `${s9}.sig`]).kind === "none");
  ok("isolation: the SEALED scanner ignores a plaintext generation (=> none on plaintext-only)", selectLatestSealedControlPlaneExport([k9, `${k9}.sig`]).kind === "none");
  const mixed = [k5, `${k5}.sig`, s9, `${s9}.sig`];
  ok("isolation: in a mixed bucket the plaintext scanner picks the plaintext v5", selectLatestControlPlaneExport(mixed).kind === "ok" && (selectLatestControlPlaneExport(mixed) as { version: number }).version === 5);
  ok("isolation: in a mixed bucket the sealed scanner picks the sealed v9", selectLatestSealedControlPlaneExport(mixed).kind === "ok" && (selectLatestSealedControlPlaneExport(mixed) as { version: number }).version === 9);

  // ---- (1a-purge) plaintextGenerationKeysToPurge (S5.3: on enabling sealing, remove readable plaintext) ---
  // A mixed bucket: two plaintext generations (each with a sig) + a sealed generation (with its sig). The
  // purge set is EXACTLY the plaintext bodies + their sigs; the sealed generation is NEVER purged.
  {
    const purge = plaintextGenerationKeysToPurge([k5, `${k5}.sig`, k9, `${k9}.sig`, s9, `${s9}.sig`]);
    const set = new Set(purge);
    ok("purge: includes both plaintext bodies + their sigs", set.has(k5) && set.has(`${k5}.sig`) && set.has(k9) && set.has(`${k9}.sig`));
    ok("purge: NEVER includes a sealed generation or its sig", !set.has(s9) && !set.has(`${s9}.sig`));
    ok("purge: exactly the 4 plaintext keys (2 bodies + 2 sigs)", purge.length === 4);
    ok("purge: a plaintext body with NO sig sibling still purges the body", plaintextGenerationKeysToPurge([k5]).length === 1 && plaintextGenerationKeysToPurge([k5])[0] === k5);
    ok("purge: a sealed-only bucket has nothing to purge", plaintextGenerationKeysToPurge([s9, `${s9}.sig`]).length === 0);
    ok("purge: an empty bucket => empty", plaintextGenerationKeysToPurge([]).length === 0);
  }

  // ---- (1b) VERSION-CONSISTENCY GATE: filename version vs signed configVersion ---------------
  // Reproduce the exploit precisely: copy exp's REAL, untouched signed bytes to a NEW key with a
  // FABRICATED higher version -- no forgery needed. Selection alone picks it as the unambiguous "latest"
  // and the real signature still verifies (both PASS, proving the vulnerability precondition); only the
  // configVersion cross-check can tell this apart from a genuine newer generation.
  const fabricatedVersion = exp.configVersion + 999_999;
  const fabricatedKey = controlPlaneArtefactKey(fabricatedVersion, exp.exportedAt);
  const replayBucket = new MemoryDestination();
  await replayBucket.put(fabricatedKey, serialiseControlPlaneExport(exp)); // same real body, relabelled key
  await replayBucket.put(`${fabricatedKey}.sig`, utf8(sig)); // same real signature
  const replayCandidate = selectLatestControlPlaneExport(await replayBucket.list("_RECOVERY/CONTROL-PLANE/"));
  ok(
    "replay: the relabelled artefact is picked as the unambiguous \"latest\" (the vulnerability precondition)",
    replayCandidate.kind === "ok" && replayCandidate.version === fabricatedVersion,
  );
  if (replayCandidate.kind === "ok") {
    const replayJson = await replayBucket.get(replayCandidate.jsonKey);
    const replayParsed = JSON.parse(new TextDecoder().decode(replayJson!.body)) as ControlPlaneExport;
    ok("replay: the real signature still verifies over the real, unmodified body", await verifyControlPlaneSignature(replayParsed, sig, verifier));
    ok(
      "replay: candidateVersionMatchesExport CATCHES the relabelled-filename replay (the fix)",
      !candidateVersionMatchesExport({ version: replayCandidate.version }, replayParsed),
    );
  }
  ok("consistency: a genuinely-labelled candidate matches its own signed configVersion", candidateVersionMatchesExport({ version: exp.configVersion }, exp));

  // ---- (2) NO-CUSTODY + SIGN/VERIFY gate the cron applies before staging -----------------------------
  let noCustodyOk = true;
  try {
    assertNoPlaintextSecretInExport(exp);
  } catch {
    noCustodyOk = false;
  }
  ok("verify-gate: the export passes the no-custody assertion", noCustodyOk);
  ok("verify-gate: a correctly-signed export verifies", await verifyControlPlaneSignature(exp, sig, verifier));
  const tampered = JSON.parse(JSON.stringify(exp)) as ControlPlaneExport;
  tampered.downpipes.push(makeConfig("dp-injected"));
  ok("verify-gate: a TAMPERED export fails verification (the cron would refuse)", !(await verifyControlPlaneSignature(tampered, sig, verifier)));

  // ---- (3) BUCKET-SCAN + VERIFY against a real artefact layout (the cron read path) ------------------
  const bucket = new MemoryDestination();
  const key = controlPlaneArtefactKey(exp.configVersion, exp.exportedAt);
  await bucket.put(key, serialiseControlPlaneExport(exp));
  await bucket.put(`${key}.sig`, utf8(sig));
  const scanned = selectLatestControlPlaneExport(await bucket.list("_RECOVERY/CONTROL-PLANE/"));
  ok("scan: the written export is selected as the latest signed candidate", scanned.kind === "ok");
  if (scanned.kind === "ok") {
    const jsonObj = await bucket.get(scanned.jsonKey);
    const sigObj = await bucket.get(scanned.sigKey);
    const parsed = JSON.parse(new TextDecoder().decode(jsonObj!.body)) as unknown;
    ok("scan: the read-back body is a control-plane export artefact", isControlPlaneExport(parsed));
    const readSig = new TextDecoder().decode(sigObj!.body).trim();
    ok("scan: the read-back export VERIFIES against the signer", isControlPlaneExport(parsed) && (await verifyControlPlaneSignature(parsed, readSig, verifier)));
  }
  // A tampered stored body no longer verifies (the cron would refuse rather than stage).
  const tamperedBucket = new MemoryDestination();
  const badBody = JSON.parse(new TextDecoder().decode(serialiseControlPlaneExport(exp))) as ControlPlaneExport;
  badBody.downpipes.push(makeConfig("dp-smuggled"));
  await tamperedBucket.put(key, serialiseControlPlaneExport(badBody));
  await tamperedBucket.put(`${key}.sig`, utf8(sig));
  const tScan = selectLatestControlPlaneExport(await tamperedBucket.list("_RECOVERY/CONTROL-PLANE/"));
  ok("scan: a tampered stored body fails verification", tScan.kind === "ok" && !(await verifyControlPlaneSignature(JSON.parse(new TextDecoder().decode((await tamperedBucket.get((tScan as { jsonKey: string }).jsonKey))!.body)) as ControlPlaneExport, sig, verifier)));

  // ---- (4) RESUME SLICE = NO AUTHORITY (the headline invariant) --------------------------------------
  const B = makeScheduler();
  // Guard: a resume with NO recovery latch set is refused (resume only runs during a detected amnesia).
  const noLatch = await B.stub.applyControlPlaneResumeSlice();
  ok("resume: refused when no recovery is in effect (latch not set)", noLatch.ok === false);

  // Simulate detection: latch recovery-required, then stage the Worker-verified export (as the cron would).
  await B.stub.setControlPlaneRecoveryRequired("config empty but bucket has runs");
  await B.stub.stageControlPlaneRecovery(stagedFrom(exp, sig, exp.configVersion));
  const resumed = await B.stub.applyControlPlaneResumeSlice();
  ok("resume: applies the no-authority slice (ok)", resumed.ok === true && (resumed as { downpipes: number }).downpipes === 1);
  const dps = await B.stub.listDownpipes();
  ok("resume: the downpipe REAPPEARS => backups resume", dps.some((s) => s.config.id === "dp-amnesia"));
  const restoredDest = await B.stub.getDestConfigById("d1");
  ok("resume: the destination is restored (wrapped secret as an envelope)", restoredDest !== null && typeof restoredDest.secretAccessKey === "object" && (restoredDest.secretAccessKey as { v?: number }).v === 1);
  // THE SECURITY INVARIANTS: no authority was granted.
  ok("resume INVARIANT: the role table is STILL EMPTY (no RBAC silently restored)", await B.stub.roleTableIsEmpty());
  ok("resume INVARIANT: the silence-killer latch is STILL SET", (await B.stub.getControlPlaneRecoveryRequired()).required === true);
  ok("resume INVARIANT: bootstrapConsumed is STILL false (first-Owner not re-armed)", (await B.stub.getBootstrapConsumed()) === false);
  const blocked = await B.stub.whoami("attacker@example.com", "subj-attacker", "access", null);
  ok("resume INVARIANT: an Access caller STILL resolves to recovery-required viewer (NO silent re-bootstrap)", blocked.role === "viewer" && blocked.recoveryRequired === true);
  const bAudit = await B.stub.listAuditEntries();
  ok("resume: a control-plane-resumed audit event is recorded", bAudit.some((e) => e.action === "control-plane-resumed" && e.outcome === "success"));
  // Idempotent: a second resume does not change the security posture (still latched, still no RBAC).
  const resumed2 = await B.stub.applyControlPlaneResumeSlice();
  ok("resume: idempotent (a re-run still ok, still no authority)", resumed2.ok === true && (await B.stub.roleTableIsEmpty()) && (await B.stub.getControlPlaneRecoveryRequired()).required === true);
  // The recovery-status route surfaces the staged state (resumeApplied true) for the console banner.
  const statusResp = (await (await stubFetch(B.stub, "GET", "/control-plane/recovery-status")).json()) as { recoveryRequired: boolean; resumeApplied: boolean; staged: { downpipes: number } | null };
  ok("resume: recovery-status surfaces resumeApplied + the staged summary", statusResp.recoveryRequired === true && statusResp.resumeApplied === true && statusResp.staged?.downpipes === 1);

  // ---- (5) BREAK-GLASS CONFIRM = the only path to authority ------------------------------------------
  // A non-token caller is refused (only the bare-token break-glass may restore authority).
  let nonTokenRefused = false;
  try {
    await B.stub.applyControlPlaneAuthoritySlice({ method: "access", email: "x@y.com", subject: "s", groups: [] });
  } catch {
    nonTokenRefused = true;
  }
  ok("confirm: a non-break-glass caller is refused authority restore", nonTokenRefused);
  // The break-glass token caller restores authority.
  const tokenCaller = { method: "token" as const, email: null, subject: null, groups: [] };
  const authority = await B.stub.applyControlPlaneAuthoritySlice(tokenCaller);
  ok("confirm: the break-glass restores RBAC (roles >= 1)", authority.ok === true && authority.roles >= 1);
  ok("confirm: the latch is now CLEARED", (await B.stub.getControlPlaneRecoveryRequired()).required === false);
  ok("confirm: bootstrapConsumed is re-armed", (await B.stub.getBootstrapConsumed()) === true);
  const who = await B.stub.whoami("owner@example.com", "subj-owner", "access", null);
  ok("confirm: the restored Owner resolves to Owner (no re-bootstrap)", who.role === "owner");
  ok("confirm: bridges from the export's prior audit head", authority.bridgedFrom.headHash === exp.priorAuditHead.headHash);
  const cAudit = await B.stub.listAuditEntries();
  ok("confirm: a control-plane-reconciled BRIDGE event is recorded", cAudit.some((e) => e.action === "control-plane-reconciled" && e.outcome === "success"));
  const afterStatus = (await (await stubFetch(B.stub, "GET", "/control-plane/recovery-status")).json()) as { staged: unknown };
  ok("confirm: the staged record is consumed (cleared)", afterStatus.staged === null);
  // With nothing staged, a further authority confirm is refused.
  let noStagedRefused = false;
  try {
    await B.stub.applyControlPlaneAuthoritySlice(tokenCaller);
  } catch {
    noStagedRefused = true;
  }
  ok("confirm: refused when nothing is staged", noStagedRefused);

  // ---- (6) CLOBBER GUARD: authority restore never overwrites existing authority ----------------------
  const C = makeScheduler();
  // A pre-existing Owner (bootstrapped), THEN a latch + staged export. The authority slice must refuse to
  // overwrite the live role table (so a stale/rolled-back export can never clobber real authority).
  await C.stub.whoami("real-owner@example.com", "subj-real", "access", null);
  await C.stub.setControlPlaneRecoveryRequired("amnesia-like state with a non-empty table");
  await C.stub.stageControlPlaneRecovery(stagedFrom(exp, sig, exp.configVersion));
  let clobberRefused = false;
  try {
    await C.stub.applyControlPlaneAuthoritySlice(tokenCaller);
  } catch {
    clobberRefused = true;
  }
  ok("clobber-guard: authority restore is refused when the role table is non-empty", clobberRefused);

  // ---- (7) DEFENCE IN DEPTH: the DO itself refuses a staged version/body mismatch --------------------
  // Simulates a staged record whose filename-derived `version` disagrees with its own export's signed
  // `configVersion` reaching the DO directly (a future caller other than the hardened cron auto-heal, or
  // -- pre-fix -- exactly what a fabricated-filename replay produces once staged). Both apply paths must
  // refuse rather than silently resume/restore from it.
  const D = makeScheduler();
  await D.stub.setControlPlaneRecoveryRequired("config empty but bucket has runs");
  await D.stub.stageControlPlaneRecovery(stagedFrom(exp, sig, exp.configVersion + 999_999));
  const mismatchedResume = await D.stub.applyControlPlaneResumeSlice();
  ok(
    "defence-in-depth: resume REFUSES a staged version/body mismatch",
    mismatchedResume.ok === false && (mismatchedResume as { reason: string }).reason.includes("version"),
  );
  const dDps = await D.stub.listDownpipes();
  ok("defence-in-depth: nothing was applied (the downpipe never reappears)", !dDps.some((s) => s.config.id === "dp-amnesia"));
  let mismatchedAuthorityReason = "";
  try {
    await D.stub.applyControlPlaneAuthoritySlice(tokenCaller);
  } catch (e) {
    mismatchedAuthorityReason = (e as Error).message;
  }
  ok("defence-in-depth: the break-glass confirm ALSO refuses a staged version/body mismatch", mismatchedAuthorityReason.includes("version"));
  ok("defence-in-depth: no authority was granted from the mismatched generation (role table still empty)", await D.stub.roleTableIsEmpty());

  console.log(failures === 0 ? "\nCONTROL-PLANE AUTO-HEAL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
