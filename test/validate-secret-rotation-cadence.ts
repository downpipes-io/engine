// Proves ASVS V13.3.4 for the engine: the seven secrets docs/security/cryptography-and-keys.md commits to
// a rotation cadence are CONFIGURED to expire and rotate, not merely documented as a schedule (that is
// V13.1.4, already met by the table itself).
//
// Coverage:
//  - doc-pin: the cadence table in secret-rotation.ts agrees with the live markdown table, and a hand-
//    edited cadence in the doc is caught (negative control);
//  - seeding: a fresh reconcile (with no prior marker) seeds a tracked expiry row for every in-service
//    cadenced secret, dated cadenceDays out from the seed moment;
//  - the ladder + posture: advancing the clock 61 days crosses ADMIN_TOKEN's 30-day rung (an emission)
//    and fails the credential-expiry posture check, naming it;
//  - POST /admin/secrets/rotated (confirmSecretRotation): an owner confirming ADMIN_TOKEN's rotation
//    clears the posture failure and leaves an audit entry; the identical call as a non-owner is refused
//    (403); a fingerprint-observed (key) secret id is refused (400);
//  - fingerprint-observed reset: replacing SIGNER_PRIVATE's fingerprint resets its tracked row on the
//    NEXT reconcile, with no POST involved;
//  - negative controls: ADMIN_TOKEN_DISABLED means no admin_token row is ever created; every stored
//    rotation marker carries only its closed shape (at/actor/fingerprint), never an extra field.
//
// In-memory doubles only; no network, no deploy, no cost. Run:
//   node test/validate-secret-rotation-cadence.ts

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expiryStatuses, type ExpiryItem } from "../src/admin/expiry.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { buildCredentialExpiry } from "../src/admin/posture-checks.ts";
import type { PostureInput } from "../src/admin/posture-types.ts";
import { checkSecretRotationDocPin, ROTATION_PREFIX, rotationItemId } from "../src/admin/secret-rotation.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

const OWNER_CALLER: Caller = { method: "access", email: "owner@example.au", subject: "subject-owner@example.au", role: "owner", groups: [] };
const OWNER_HEADER = encodeCaller(OWNER_CALLER);
// operator holds expiry.config but NOT keys.ceremony (owner-exclusive), so it proves the DO-side
// defence-in-depth capability re-check refuses a non-owner exactly like the key-ceremony routes do.
const OPERATOR_CALLER: Caller = { method: "access", email: "operator@example.au", subject: "subject-operator@example.au", role: "operator", groups: [] };
const OPERATOR_HEADER = encodeCaller(OPERATOR_CALLER);

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

const DAY = 24 * 60 * 60 * 1000;

async function statusesOf(storage: MockStorage): Promise<ReturnType<typeof expiryStatuses>> {
  const items = [...(await storage.list<ExpiryItem>({ prefix: "expiry:" })).values()];
  return expiryStatuses(items, Date.now());
}

async function main(): Promise<void> {
  // ---- doc-pin: the code table agrees with the live markdown table -----------------------------------
  {
    const ENGINE_ROOT = fileURLToPath(new URL("..", import.meta.url));
    const DOC_PATH = resolve(ENGINE_ROOT, "docs/security/cryptography-and-keys.md");
    const original = readFileSync(DOC_PATH, "utf8");
    const pin = checkSecretRotationDocPin(original);
    ok("doc-pin: every cadence in code matches the live markdown table", pin.ok === true);

    // Negative control: hand-edit ONE cadence in a copy of the text and confirm the check goes red,
    // proving this is a real cross-check and not a vacuous pass.
    const mutated = original.replace(
      "| `SIGNER_PRIVATE` | archive authenticity: it signs every run | 12 months |",
      "| `SIGNER_PRIVATE` | archive authenticity: it signs every run | 24 months |",
    );
    ok("doc-pin negative control: the mutation actually changed the text", mutated !== original);
    const badPin = checkSecretRotationDocPin(mutated);
    ok("doc-pin: a hand-edited cadence in the doc is caught (goes red)", badPin.ok === false && badPin.mismatches.some((m) => m.id === "signer_private" && m.codeDays === 365 && m.docDays === 730));
  }

  // ---- seeding, the ladder, posture, confirm-rotated and the fingerprint-observed reset --------------
  // The clock is fully mocked (both Date.now() and, via rotationNowISO, `new Date()`'s effective reading)
  // for this whole section so every "N days out" assertion is exact, never a few-millisecond flake.
  const realNow = Date.now;
  let clockMs = Date.now();
  Date.now = () => clockMs;
  try {
    const { storage, stub } = makeScheduler();

    // A fresh reconcile with SIGNER_PRIVATE and ADMIN_TOKEN in service and no prior markers: both are
    // seeded, dated exactly cadenceDays out from this seed moment (T0).
    const seedBody = { presentBindings: { SIGNER_PRIVATE: true, ADMIN_TOKEN: true }, fingerprints: { SIGNER_PRIVATE: "edmldsa1:fp-a" }, adminTokenDisabled: false };
    const r1 = (await (await fetchDO(stub, "POST", "/expiry/reconcile", seedBody)).json()) as { emissions: Array<{ id: string }> };
    ok("seed: a fresh reconcile emits nothing (nothing has crossed a rung yet)", r1.emissions.length === 0);

    const afterSeed = await statusesOf(storage);
    const signerRow = afterSeed.find((s) => s.id === "rotation-signer_private");
    const tokenRow = afterSeed.find((s) => s.id === "rotation-admin_token");
    ok("seed: rotation:signer_private is tracked, exactly 365 days out (key cadence)", signerRow?.daysRemaining === 365);
    ok("seed: rotation:admin_token is tracked, exactly 90 days out (credential cadence)", tokenRow?.daysRemaining === 90);
    ok("seed: signer_private is source=observed (engine-observed, not operator-attested)", signerRow?.source === "observed");

    const cleanPosture = buildCredentialExpiry({ expiry: afterSeed } as unknown as PostureInput);
    ok("posture: credential-expiry passes right after seeding (nothing is close to due)", cleanPosture.auto === "pass");

    // Advance the clock 61 days: ADMIN_TOKEN (90-day cadence) now has 29 days left, crossing the 30-day
    // rung; SIGNER_PRIVATE (365-day cadence) has 304 left and stays quiet.
    clockMs += 61 * DAY;
    const r2 = (await (await fetchDO(stub, "POST", "/expiry/reconcile", seedBody)).json()) as { emissions: Array<{ id: string; detail: string }> };
    ok("+61d: reconcile emits the 30-day rung for rotation:admin_token", r2.emissions.some((e) => e.id === "rotation-admin_token"));
    ok("+61d: SIGNER_PRIVATE (365-day cadence) does not emit yet", !r2.emissions.some((e) => e.id === "rotation-signer_private"));

    const afterAge = await statusesOf(storage);
    const agedTokenRow = afterAge.find((s) => s.id === "rotation-admin_token");
    ok("+61d: rotation:admin_token reads approaching (29 days left)", agedTokenRow?.state === "approaching" && agedTokenRow.daysRemaining === 29);
    const failedPosture = buildCredentialExpiry({ expiry: afterAge } as unknown as PostureInput);
    ok("+61d: credential-expiry FAILS, naming the approaching secret", failedPosture.auto === "fail" && failedPosture.detail.includes("Admin bearer token"));

    // A non-owner (operator, which holds expiry.config but not keys.ceremony) is refused.
    const deniedResp = await fetchDO(stub, "POST", "/secret-rotation/confirm", { secret: "admin_token" }, OPERATOR_HEADER);
    ok("confirm-rotated: a non-owner (operator) is refused (403)", deniedResp.status === 403);

    // A fingerprint-observed (key) secret id is refused even for an owner: its rotation is engine-observed.
    const keyRefused = await fetchDO(stub, "POST", "/secret-rotation/confirm", { secret: "signer_private" }, OWNER_HEADER);
    ok("confirm-rotated: an owner cannot manually confirm a fingerprint-observed key (400)", keyRefused.status === 400);

    // An owner confirms ADMIN_TOKEN's rotation: the baseline moves to now (clockMs), posture clears, and
    // an audit entry is recorded.
    const confirmResp = await fetchDO(stub, "POST", "/secret-rotation/confirm", { secret: "admin_token" }, OWNER_HEADER);
    ok("confirm-rotated: an owner confirming ADMIN_TOKEN answers 200", confirmResp.status === 200);
    const confirmed = (await confirmResp.json()) as { ok: true; expiresAt: string };
    ok("confirm-rotated: the new expiresAt is exactly 90 days from the confirming call", Date.parse(confirmed.expiresAt) === clockMs + 90 * DAY);

    const afterConfirm = await statusesOf(storage);
    const clearedTokenRow = afterConfirm.find((s) => s.id === "rotation-admin_token");
    ok("confirm-rotated: rotation:admin_token reads ok again (90 days left)", clearedTokenRow?.state === "ok" && clearedTokenRow.daysRemaining === 90);
    const clearedPosture = buildCredentialExpiry({ expiry: afterConfirm } as unknown as PostureInput);
    ok("confirm-rotated: credential-expiry passes again", clearedPosture.auto === "pass");

    const auditRead = (await (await fetchDO(stub, "GET", "/audit?action=secret-rotation-confirmed")).json()) as { events: Array<{ actorEmail: string | null; outcome: string; target: { kind: string; secretId?: string } }> };
    ok("confirm-rotated: an audit entry exists, attributed to the owner", auditRead.events.length === 1 && auditRead.events[0]?.actorEmail === OWNER_CALLER.email && auditRead.events[0]?.outcome === "success");
    ok("confirm-rotated: the audit target names the secret id only", auditRead.events[0]?.target.kind === "secret-rotation" && auditRead.events[0]?.target.secretId === "admin_token");

    // Replace SIGNER_PRIVATE with a fresh fingerprint: the NEXT reconcile resets its row, no POST involved.
    const rotatedSignerBody = { presentBindings: { SIGNER_PRIVATE: true, ADMIN_TOKEN: true }, fingerprints: { SIGNER_PRIVATE: "edmldsa1:fp-b" }, adminTokenDisabled: false };
    await fetchDO(stub, "POST", "/expiry/reconcile", rotatedSignerBody);
    const afterSignerRotate = await statusesOf(storage);
    const resetSignerRow = afterSignerRotate.find((s) => s.id === "rotation-signer_private");
    ok("fingerprint-observed reset: SIGNER_PRIVATE's row resets to 365 days out, with no POST", resetSignerRow?.daysRemaining === 365 && resetSignerRow.state === "ok");

    // ---- negative control: ADMIN_TOKEN_DISABLED means no admin_token row is ever created --------------
    {
      const { storage: s2, stub: stub2 } = makeScheduler();
      await fetchDO(stub2, "POST", "/expiry/reconcile", { presentBindings: { ADMIN_TOKEN: true }, adminTokenDisabled: true });
      // The tracked row's real storage key is `expiry:${rotationItemId(id)}` (a hyphen, e.g.
      // "expiry:rotation-admin_token": rotationItemId's own hyphen, never the colon expiry.ts's
      // EXPIRY_ID_PATTERN would also accept), so the prefix and the exact key checked here match what
      // seedSecretRotationItems actually writes, not a key shape nothing ever produces.
      const raw = await s2.list<unknown>({ prefix: "expiry:" });
      ok("ADMIN_TOKEN_DISABLED: no rotation:admin_token row is created", !raw.has(`expiry:${rotationItemId("admin_token")}`));
    }

    // ---- negative control: no field outside the enumerated shape (no-custody) -------------------------
    {
      const markers = await storage.list<Record<string, unknown>>({ prefix: ROTATION_PREFIX });
      ok("no-custody: at least one rotation marker exists to check", markers.size > 0);
      let shapeOk = true;
      for (const [key, v] of markers) {
        const keys = Object.keys(v).sort();
        if (!keys.every((k) => k === "at" || k === "actor" || k === "fingerprint")) {
          shapeOk = false;
          console.log(`    unexpected field on ${key}: ${keys.join(",")}`);
        }
      }
      ok("no-custody: every stored rotation marker carries only at/actor/fingerprint, never an extra field", shapeOk);
      const dump = JSON.stringify([...markers.values(), ...afterConfirm]);
      ok("no-custody: no secret-shaped literal (an AWS-style access key id) appears in any stored row", !/AKIA[0-9A-Z]{16}/.test(dump));
    }
  } finally {
    Date.now = realNow;
  }

  console.log(failures === 0 ? "\nSECRET-ROTATION CADENCE (V13.3.4) PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
