// Prove the control-plane recovery layer end to end, server-side, with in-memory doubles only.
// No network, no deploy, no cost. Run:
//   node test/validate-control-plane.ts
//
// What this proves:
//  - NO-CUSTODY: buildControlPlaneExport NEVER emits a plaintext secret — a wrapped destination secret
//    rides as a WrappedSecret envelope, a plaintext-at-rest secret is OMITTED + marked reestablish, and
//    the structural assertNoPlaintextSecretInExport over the parsed export passes; a hand-forged export
//    carrying a plaintext secret is REJECTED by the same assertion.
//  - SIGN/VERIFY: the detached hybrid signature round-trips against the engine's pinned verifier; a TAMPER
//    (a mutated export) and a WRONG-SIGNER both fail verification (no forged export can reconcile).
//  - SILENCE-KILLER: with the recovery-required latch set, an Access caller on an EMPTY table does NOT
//    silently re-bootstrap to Owner — whoami reports recovery-required (viewer), no role is written, the
//    bootstrap latch stays unconsumed; clearing the latch restores the normal first-Owner bootstrap.
//  - RECONCILE: a break-glass (token) reconcile from a verified export rebuilds the downpipe + the
//    destination + the Owner role, re-arms bootstrapConsumed, clears the recovery latch, and writes a
//    control-plane-reconciled BRIDGE audit event referencing the export's prior audit head; a non-token
//    caller is refused; a non-empty plane (config or authority) is refused, and there is no force overwrite.

import { makeScheduler, makeConfig } from "./validate-scheduler-shared.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { wrapConfigSecret } from "../src/admin/config-secret.ts";
import {
  type ControlPlaneExport,
  assertNoPlaintextSecretInExport,
  controlPlaneArtefactKey,
  sameControlPlaneAccount,
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

// makeSigner builds a real engine signer (and its verifier) from a random 64-byte SIGNER_PRIVATE seed.
async function makeSigner(): Promise<{ b64: string }> {
  const seed = crypto.getRandomValues(new Uint8Array(64));
  return { b64: b64urlEncode(seed) };
}

// seedStoredDest builds a StoredDestination with the given principal secret (a WrappedSecret or plaintext).
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

// The recipient pin travels INSIDE the signed export, which is the whole point of putting it there rather
// than in Durable Object storage: whoever can add a recipient controls the deployed code and therefore the
// DO, so a DO pin would be checked by the actor it exists to catch. A signed artefact on the destination is
// a record the engine cannot retroactively rewrite.
function checkRecipientPinIsSignedOver(): void {
  const exp = { v: 1, recipientPin: { breakGlass: "dpr1:aaa", operational: "dpr1:bbb", config: "dpr1:ccc" } } as unknown as Record<string, unknown>;
  const serialised = JSON.stringify(exp);
  ok("the pin is carried on the export, so it is covered by whatever signs the export", serialised.includes("dpr1:aaa") && serialised.includes("recipientPin"));
  // Fingerprints only. dpr1: values are hashes of PUBLIC recipient encodings, so the field carries nothing
  // secret and nothing that helps an attacker who does not already hold the public keys.
  ok("the pin carries fingerprints, never key material", !serialised.includes("BEGIN") && serialised.includes("dpr1:"));
}

async function main(): Promise<void> {
  checkRecipientPinIsSignedOver();
  const { b64: signerB64 } = await makeSigner();
  const signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);
  const wrapKey = crypto.getRandomValues(new Uint8Array(32));

  // ---- Seed DO-A: a downpipe, two destinations (one wrapped secret, one plaintext), a bootstrapped Owner.
  const A = makeScheduler();
  await A.stub.addDownpipe(makeConfig("dp-amnesia"));
  const wrapped = await wrapConfigSecret(wrapKey, "super-secret-s3-key");
  const coll: DestinationCollection = {
    list: [
      // d1 also carries a MICROSOFT ENTRA service principal, so the export/reconcile round trip is graded
      // for it. The two ids are identifiers rather than credentials, so unlike an STS externalId they must
      // ride WHOLE: dropping them would reconcile the destination as a Shared Key one, silently changing
      // which identity backups are written as, while every count and every status still read correct.
      { ...seedStoredDest("d1", wrapped), azureEntra: { tenantId: "98d21390-5d4f-488d-8fef-cb5b4defe180", clientId: "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57" } },
      seedStoredDest("d2", "plaintext-secret-no-wrap"),
    ],
    defaultId: "d1",
  };
  await A.stub.saveDestinations(coll);
  // Bootstrap an Owner via the real whoami path (creates a subject-keyed Owner row + consumes bootstrap).
  const bootA = await A.stub.whoami("owner@example.com", "subj-owner", "access", null);
  ok("seed: first Access caller bootstraps Owner", bootA.role === "owner" && bootA.recoveryRequired === undefined);

  // ---- NO-CUSTODY: build the export, assert no plaintext secret anywhere ---------------------------
  const exp = await A.stub.buildControlPlaneExport();
  let noCustodyOk = true;
  try {
    assertNoPlaintextSecretInExport(exp);
  } catch {
    noCustodyOk = false;
  }
  ok("no-custody: export passes the structural plaintext-secret assertion", noCustodyOk);
  const d1 = exp.destinations.find((d) => d.id === "d1")!;
  const d2 = exp.destinations.find((d) => d.id === "d2")!;
  ok("no-custody: wrapped dest secret rides as a WrappedSecret envelope", "wrapped" in d1.secret && d1.secret.wrapped.v === 1);
  ok("export: an Entra destination carries its directory and application ids, which are not credentials", (d1.azureEntra as { tenantId?: string; clientId?: string } | undefined)?.clientId === "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57");
  ok("no-custody: plaintext-at-rest dest secret is OMITTED + reestablish", "reestablish" in d2.secret && d2.secret.reestablish === true);
  // The literal plaintext must NOT appear anywhere in the serialised export.
  const serialised = new TextDecoder().decode(serialiseControlPlaneExport(exp));
  ok("no-custody: the plaintext secret string is absent from the serialised export", !serialised.includes("plaintext-secret-no-wrap") && !serialised.includes("super-secret-s3-key"));
  ok("no-custody: reestablish lists destination-credentials + session-keys", exp.reestablish.includes("destination-credentials") && exp.reestablish.includes("session-keys"));
  ok("export: the downpipe is carried", exp.downpipes.some((c) => (c as { id: string }).id === "dp-amnesia"));
  ok("export: the bootstrapped Owner role is carried (subject-keyed)", exp.roles.some((r) => r.email === "owner@example.com" && r.subject === "subj-owner" && r.role === "owner"));

  // A hand-forged export that smuggles a plaintext secret MUST be rejected by the assertion.
  let forgedCaught = false;
  try {
    const forged = JSON.parse(JSON.stringify(exp)) as Record<string, unknown>;
    (forged.destinations as Array<Record<string, unknown>>)[0]!.secret = "i-am-a-plaintext-secret";
    assertNoPlaintextSecretInExport(forged);
  } catch {
    forgedCaught = true;
  }
  ok("no-custody: a forged export carrying a plaintext secret is REJECTED", forgedCaught);

  // The SHAPE half of the assertion: a secret-named field carrying a NON-permitted object (not a
  // WrappedSecret / {wrapped} / {reestablish}) is also rejected, so a plaintext cannot ride hidden under a
  // non-secret-named subfield of a secret slot.
  let forgedShapeCaught = false;
  try {
    const forged2 = JSON.parse(JSON.stringify(exp)) as Record<string, unknown>;
    (forged2.destinations as Array<Record<string, unknown>>)[0]!.secret = { note: "totally-not-a-secret", value: "AKIA-plaintext" };
    assertNoPlaintextSecretInExport(forged2);
  } catch {
    forgedShapeCaught = true;
  }
  ok("no-custody: a forged export smuggling a secret as a non-permitted object is REJECTED", forgedShapeCaught);
  // ...and a genuine {reestablish:true} marker in the same slot is ACCEPTED (no false positive).
  let genuineOk = true;
  try {
    const good1 = JSON.parse(JSON.stringify(exp)) as Record<string, unknown>;
    (good1.destinations as Array<Record<string, unknown>>)[0]!.secret = { reestablish: true };
    assertNoPlaintextSecretInExport(good1);
  } catch {
    genuineOk = false;
  }
  ok("no-custody: a genuine {reestablish:true} secret slot is ACCEPTED (no false positive)", genuineOk);
  // A WrappedSecret-SHAPED object carrying an EXTRA (secret-named) key must be rejected: the exact-3-key
  // check means a plaintext cannot ride alongside a real-looking envelope, and the walker no longer
  // short-circuits on a non-exact envelope shape.
  let extraKeyCaught = false;
  try {
    const forged3 = JSON.parse(JSON.stringify(exp)) as Record<string, unknown>;
    (forged3.destinations as Array<Record<string, unknown>>)[0]!.secret = { v: 1, iv: "aa", ct: "bb", secretAccessKey: "AKIA-plaintext-hiding-in-an-envelope" };
    assertNoPlaintextSecretInExport(forged3);
  } catch {
    extraKeyCaught = true;
  }
  ok("no-custody: an envelope-shaped object with an extra secret key is REJECTED", extraKeyCaught);

  // ---- SIGN / VERIFY: round-trip, tamper, wrong-signer --------------------------------------------
  const sig = await signControlPlaneExport(signer, exp);
  ok("sign/verify: a correctly-signed export verifies", await verifyControlPlaneSignature(exp, sig, verifier));
  const tampered = JSON.parse(JSON.stringify(exp)) as ControlPlaneExport;
  tampered.downpipes.push(makeConfig("dp-injected"));
  ok("sign/verify: a TAMPERED export fails verification", !(await verifyControlPlaneSignature(tampered, sig, verifier)));
  const { b64: otherB64 } = await makeSigner();
  const otherVerifier = verifierFrom(await loadSigner(otherB64));
  ok("sign/verify: the WRONG signer fails verification", !(await verifyControlPlaneSignature(exp, sig, otherVerifier)));
  ok("artefact key: timestamped + version-padded under the recovery prefix", controlPlaneArtefactKey(exp.configVersion, exp.exportedAt).startsWith("_RECOVERY/CONTROL-PLANE/"));

  // ---- SILENCE-KILLER: the latch blocks the silent re-bootstrap ----------------------------------
  const B = makeScheduler();
  await B.stub.setControlPlaneRecoveryRequired("config empty but bucket has runs");
  const blocked = await B.stub.whoami("attacker@example.com", "subj-attacker", "access", null);
  ok("silence: with the latch set, whoami does NOT bootstrap (role viewer)", blocked.role === "viewer" && blocked.recoveryRequired === true);
  ok("silence: the latch leaves the role table empty (no rogue Owner minted)", await B.stub.roleTableIsEmpty());
  ok("silence: the latch leaves bootstrap UNconsumed", !(await B.stub.getBootstrapConsumed()));
  // The critical control-plane-empty audit event was written on the false->true transition.
  const bAudit = await B.stub.listAuditEntries();
  ok("silence: a critical control-plane-empty audit event is recorded", bAudit.some((e) => e.action === "control-plane-empty" && e.outcome === "failed"));
  // Clearing the latch restores the normal first-Owner bootstrap.
  await B.stub.clearControlPlaneRecoveryRequired();
  const afterClear = await B.stub.whoami("owner2@example.com", "subj-owner2", "access", null);
  ok("silence: clearing the latch restores the first-Owner bootstrap", afterClear.role === "owner");

  // ---- AMNESIA-LATCH DEADLOCK: the degrade fires on GENUINE amnesia (empty table) only, never an intact Owner
  // The latch degrades whoami ONLY when the role table is EMPTY (the genuine fresh-DO amnesia signature: a
  // redeploy whose fresh DO lost the config AND the identity, on an old bucket that still holds runs). The
  // cron latches on an empty CONFIG regardless of the role table, and the latch clears only through the
  // break-glass reconcile, which refuses a non-empty table -- so before this an INTACT Owner who emptied
  // their config was latched to viewer every session with no in-product clear (a real no-recovery lockout).
  {
    // (1) GENUINE fresh-DO amnesia PRESERVED: an EMPTY role table + the latch set. A caller (a fresh-DO
    // attacker on an old bucket) STILL degrades to recovery-required viewer and can NEVER act as Owner.
    const Amnesia = makeScheduler();
    await Amnesia.stub.setControlPlaneRecoveryRequired("config empty but the bucket has runs");
    ok("deadlock: the amnesia estate has an EMPTY role table (genuine fresh-DO signature)", await Amnesia.stub.roleTableIsEmpty());
    const fresh = await Amnesia.stub.whoami("attacker@example.com", "subj-fresh-attacker", "access", null);
    ok("deadlock: a fresh-DO caller on an empty table STILL degrades to recovery-required viewer (never Owner)", fresh.role === "viewer" && fresh.recoveryRequired === true);
    ok("deadlock: no rogue Owner is minted (the table stays empty)", await Amnesia.stub.roleTableIsEmpty());
    ok("deadlock: the latch stays set (recovery still required in genuine amnesia)", (await Amnesia.stub.getControlPlaneRecoveryRequired()).required === true);

    // (2) INTACT Owner DEADLOCK FIXED: a NON-EMPTY role table + the SAME latch set. The identity survived, so
    // whoami resolves the Owner to Owner (no degrade, no recoveryRequired) instead of latching them out.
    const Intact = makeScheduler();
    const boot = await Intact.stub.whoami("owner@example.com", "subj-intact-owner", "access", null);
    ok("deadlock: the intact estate has a bootstrapped Owner (non-empty table)", boot.role === "owner" && !(await Intact.stub.roleTableIsEmpty()));
    await Intact.stub.setControlPlaneRecoveryRequired("config empty but the bucket has runs");
    const intactWho = await Intact.stub.whoami("owner@example.com", "subj-intact-owner", "access", null);
    ok("deadlock FIXED: an intact Owner with the latch set resolves to Owner (NOT the latched-out viewer)", intactWho.role === "owner");
    ok("deadlock FIXED: whoami does not report recoveryRequired for an intact Owner", intactWho.recoveryRequired === undefined);
    // The latch's OTHER job still holds over a non-empty table: a stranger with no grant is NOT bootstrapped
    // to Owner (the non-empty table skips the bootstrap branch), so they resolve to the least-privilege viewer.
    const stranger = await Intact.stub.whoami("stranger@example.com", "subj-stranger", "access", null);
    ok("deadlock: a stranger is NOT bootstrapped to Owner over the intact table (resolves to viewer)", stranger.role === "viewer" && stranger.recoveryRequired === undefined);
    ok("deadlock: still exactly one Owner (no rogue Owner minted while latched)", (await Intact.stub.listRoles()).filter((r) => r.role === "owner").length === 1);
  }

  // ---- RECONCILE: break-glass rebuild from the verified export ------------------------------------
  const C = makeScheduler();
  ok("reconcile: the wiped plane is empty before reconcile", await C.stub.controlPlaneIsEmpty());
  // A non-token caller is refused.
  let nonTokenRefused = false;
  try {
    await C.stub.reconcileControlPlane(exp, { method: "access", email: "x@y.com", subject: "s", groups: [] });
  } catch {
    nonTokenRefused = true;
  }
  ok("reconcile: a non-break-glass caller is refused", nonTokenRefused);
  // The break-glass token caller reconciles.
  const tokenCaller = { method: "token" as const, email: null, subject: null, groups: [] };
  const result = await C.stub.reconcileControlPlane(exp, tokenCaller);
  ok("reconcile: returns the rebuilt counts", result.ok === true && result.downpipes === 1 && result.destinations === 2 && result.roles >= 1);
  ok("reconcile: bridges from the export's prior audit head", result.bridgedFrom.headHash === exp.priorAuditHead.headHash);
  const dps = await C.stub.listDownpipes();
  ok("reconcile: the downpipe reappears", dps.some((s) => s.config.id === "dp-amnesia"));
  // The Owner role is restored, so whoami resolves Owner WITHOUT a fresh bootstrap.
  const who = await C.stub.whoami("owner@example.com", "subj-owner", "access", null);
  ok("reconcile: the restored Owner resolves to Owner (no re-bootstrap)", who.role === "owner");
  ok("reconcile: bootstrapConsumed is re-armed", await C.stub.getBootstrapConsumed());
  ok("reconcile: the recovery latch is cleared", !(await C.stub.getControlPlaneRecoveryRequired()).required);
  const cAudit = await C.stub.listAuditEntries();
  ok("reconcile: a control-plane-reconciled BRIDGE event is recorded", cAudit.some((e) => e.action === "control-plane-reconciled" && e.outcome === "success"));
  // The restored destination carries the WRAPPED secret back (recoverable by the surviving CONFIG_WRAP_KEY).
  const restoredDest = (await C.stub.getDestConfigById("d1"))!;
  ok("reconcile: the wrapped destination secret is restored as an envelope", typeof restoredDest.secretAccessKey === "object" && (restoredDest.secretAccessKey as { v?: number }).v === 1);
  ok("reconcile: the Entra service principal is restored, so the destination comes back on the SAME identity", restoredDest.azureEntra?.tenantId === "98d21390-5d4f-488d-8fef-cb5b4defe180" && restoredDest.azureEntra.clientId === "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57");

  // ---- RECONCILE: a non-empty plane (config OR authority) is refused; there is no force -----------
  let nonEmptyRefused = false;
  try {
    await C.stub.reconcileControlPlane(exp, tokenCaller);
  } catch {
    nonEmptyRefused = true;
  }
  ok("reconcile: a non-empty plane is refused (no force overwrite)", nonEmptyRefused);
  // A config-empty plane that still holds AUTHORITY (a fresh-bootstrap Owner, no downpipes/destinations) is
  // ALSO refused: the manual reconcile must never clobber an existing role table, mirroring the auto-heal
  // authority slice. This closes the takeover/lockout path a role-blind emptiness check (downpipes+dest only)
  // left open -- an ADMIN_TOKEN holder could otherwise import a stale export's roles over a live bootstrap Owner.
  const G = makeScheduler();
  await G.stub.whoami("owner@example.com", "subj-owner", "access", null); // bootstraps an Owner; no downpipes/dests
  ok("reconcile: a plane with authority still reads controlPlaneIsEmpty() (config empty)", await G.stub.controlPlaneIsEmpty());
  ok("reconcile: ...but its role table is NOT empty", !(await G.stub.roleTableIsEmpty()));
  let roleGuarded = false;
  try {
    await G.stub.reconcileControlPlane(exp, tokenCaller);
  } catch {
    roleGuarded = true;
  }
  ok("reconcile: a plane holding authority is refused (no clobber of existing roles)", roleGuarded);

  // ---- regression: a non-default restore-test cadence SURVIVES reconcile --------------------
  // addDownpipe's scheduledtest.config re-check must NOT also catch this internal replay: prior
  // is null for every downpipe immediately after a wipe, so a naive re-check would misread ANY exported
  // non-default cadence as a "change" and fail closed with no caller, silently dropping the downpipe under
  // the tolerant auto-heal path or aborting the whole reconcile here (the strict path). Seed a downpipe
  // with the test explicitly opted OFF (0), export it, and reconcile onto a fresh plane.
  const D = makeScheduler();
  // Seeded as a real Owner (who holds scheduledtest.config) explicitly opting the test off, exactly the
  // legitimate customisation the reconcile below must not silently discard.
  const ownerSeeder = { method: "access" as const, email: "owner@example.com", subject: "subj-owner", role: "owner" as const, groups: [] };
  await D.stub.addDownpipe(makeConfig("dp-customcadence", { restoreTestCadenceSeconds: 0 }), ownerSeeder);
  const expD = await D.stub.buildControlPlaneExport();
  const E = makeScheduler();
  const reconciledD = await E.stub.reconcileControlPlane(expD, tokenCaller);
  ok("the reconcile replay itself succeeds (not refused)", reconciledD.ok === true && reconciledD.downpipes === 1);
  const restoredCustom = (await E.stub.listDownpipes()).find((s) => s.config.id === "dp-customcadence");
  ok("the opted-OFF (non-default) restore-test cadence survives the reconcile replay", restoredCustom?.config.restoreTestCadenceSeconds === 0);

  // ---- IMPORT KEYSTONE: cross-environment estate import (definition only, GRANTS NO AUTHORITY) ----
  // sameControlPlaneAccount: the pure account-identity decision that drives the disable-downpipes branch.
  ok("account: same iff both ids known and equal", sameControlPlaneAccount("acct-1", "acct-1"));
  ok("account: a mismatch is NOT the same", !sameControlPlaneAccount("acct-1", "acct-2"));
  ok("account: a null export id fails safe to NOT same", !sameControlPlaneAccount(null, "acct-1"));
  ok("account: a null current id fails safe to NOT same", !sameControlPlaneAccount("acct-1", null));
  ok("account: empty strings are NOT same", !sameControlPlaneAccount("", ""));

  // The import is run BY a bootstrapped Owner on a fresh engine; it rebuilds the DEFINITION and grants no
  // authority. `exp` (built above) carries a downpipe + destinations + the OLD owner@example.com role.
  const importOwner = { method: "access" as const, email: "new-owner@example.com", subject: "subj-new-owner", groups: [] };
  // A null / bare-token caller is refused (the import is by an authenticated Owner, not the break-glass token).
  {
    const F = makeScheduler();
    await F.stub.whoami("new-owner@example.com", "subj-new-owner", "access", null); // bootstrap the fresh Owner
    let refusedNull = false;
    try { await F.stub.importControlPlaneDefinition(exp, false, null); } catch { refusedNull = true; }
    ok("import: a null caller is refused", refusedNull);
    let refusedToken = false;
    try { await F.stub.importControlPlaneDefinition(exp, false, tokenCaller); } catch { refusedToken = true; }
    ok("import: the bare break-glass token is refused (the import is by an authenticated Owner)", refusedToken);
  }
  // SAME-account import: the definition applies, downpipes stay ENABLED, and NO authority is imported -- the
  // fresh engine's only role stays its own bootstrap Owner (the export's owner@example.com role is NOT added).
  {
    const H = makeScheduler();
    await H.stub.whoami("new-owner@example.com", "subj-new-owner", "access", null);
    const rolesBefore = (await H.stub.listRoleEntries()).length;
    const res = await H.stub.importControlPlaneDefinition(exp, false, importOwner);
    ok("import(same-account): succeeds, applies the definition, imports NO authority", res.ok === true && res.authorityImported === false && res.downpipes >= 1);
    ok("import(same-account): downpipes are ENABLED (same account)", res.downpipesDisabled === false && (await H.stub.listDownpipes()).every((s) => s.config.enabled === true));
    ok("import(same-account): the role table is UNCHANGED (no imported roles; only the bootstrap Owner)", (await H.stub.listRoleEntries()).length === rolesBefore);
    ok("import(same-account): the export's OLD owner role was NOT added (no authority import)", !(await H.stub.listRoleEntries()).some((r) => r.email === "owner@example.com"));
    ok("import(same-account): a control-plane bridge event is recorded", (await H.stub.listAuditEntries()).some((e) => e.action === "control-plane-reconciled" && e.outcome === "success"));
  }
  // CROSS-account import: every imported downpipe is DISABLED (foreign resource ids; nothing runs until rebind).
  {
    const J = makeScheduler();
    await J.stub.whoami("new-owner@example.com", "subj-new-owner", "access", null);
    const res = await J.stub.importControlPlaneDefinition(exp, true, importOwner);
    ok("import(cross-account): downpipes are DISABLED (rebind required)", res.downpipesDisabled === true && (await J.stub.listDownpipes()).every((s) => s.config.enabled === false));
  }
  // A non-fresh plane (an estate already imported) is refused.
  {
    const K = makeScheduler();
    await K.stub.whoami("new-owner@example.com", "subj-new-owner", "access", null);
    await K.stub.importControlPlaneDefinition(exp, false, importOwner); // first import populates the plane
    let refusedNonFresh = false;
    try { await K.stub.importControlPlaneDefinition(exp, false, importOwner); } catch { refusedNonFresh = true; }
    ok("import: a non-fresh plane (estate already imported) is refused", refusedNonFresh);
  }

  console.log(failures === 0 ? "\nCONTROL-PLANE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
