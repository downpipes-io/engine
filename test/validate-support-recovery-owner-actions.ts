// Proves the support pack's recovery section states what the Owner must still do after a recovery.
//
// The case: an estate is imported whose destination credential was wrapped under another CONFIG_WRAP_KEY,
// and the bucket's RUNLOG has no signature. Two faults, two owner actions. The pack must say both:
//   recovery.pendingOwnerActions                  a closed list: "resign-runlog", "reenter-destination-keys"
//   recovery.lastImport.destinationsUnreadable    { count, ids } of the imported destinations whose
//                                                 credential cannot be used with the configured key
// The negative cells show nothing is claimed when nothing is pending, and that no secret, key material,
// envelope bytes or URL rides in the section.
//
// Run: node test/validate-support-recovery-owner-actions.ts

import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";
import { wrapConfigSecret } from "../src/admin/config-secret.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { recordRunlogSeed } from "../src/sched/runlog-seed.ts";
import type { DestinationCollection, StoredDestination } from "../src/sched/scheduler-do-base.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { makeScheduler } from "./validate-scheduler-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const PLAINTEXT = "owner-actions-plaintext-secret-9f3a";
const OWNER = { method: "access" as const, email: "new-owner@example.com", subject: "subj-new-owner", groups: [] };

function dest(id: string, secretAccessKey: StoredDestination["secretAccessKey"]): StoredDestination {
  return {
    id, label: `label-${id}`, endpoint: "https://s3.owner-actions.example", bucket: "bkt-owner-actions", region: "auto",
    accessKeyId: "AKIAOWNERACTIONS", secretAccessKey, objectLock: "none", verifiedAt: 1_700_000_000_000, deleteProbe: "ok",
  } as unknown as StoredDestination;
}

// Build an export from a seeded engine whose single destination is wrapped under `wrapKey`, then import it
// into a fresh engine and return that engine.
async function importedEngine(wrapKey: Uint8Array, secretOf: (w: Awaited<ReturnType<typeof wrapConfigSecret>>) => StoredDestination["secretAccessKey"]) {
  const src = makeScheduler();
  const wrapped = await wrapConfigSecret(wrapKey, PLAINTEXT);
  const coll: DestinationCollection = { list: [dest("d1", secretOf(wrapped))], defaultId: "d1" };
  await src.stub.saveDestinations(coll);
  const exp = await src.stub.buildControlPlaneExport();
  const dst = makeScheduler();
  await dst.stub.whoami(OWNER.email, OWNER.subject, "access", null);
  await dst.stub.importControlPlaneDefinition(exp, false, OWNER);
  return dst;
}

// The pack gatherers talk to the DO through a stub whose fetch takes a URL string.
const asStub = (dst: { stub: { fetch(r: Request): Promise<Response> } }): DurableObjectStub =>
  ({ fetch: (input: RequestInfo | URL, init?: RequestInit) => dst.stub.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, init)) }) as unknown as DurableObjectStub;

const section = (r: Record<string, unknown>) => r as { pendingOwnerActions?: unknown; lastImport?: { destinationsUnreadable?: { count?: unknown; ids?: unknown } } };

async function main(): Promise<void> {
  const keyA = crypto.getRandomValues(new Uint8Array(32));
  const keyB = crypto.getRandomValues(new Uint8Array(32));
  const envA = { CONFIG_WRAP_KEY: b64urlEncode(keyA) } as unknown as Env;
  const envB = { CONFIG_WRAP_KEY: b64urlEncode(keyB) } as unknown as Env;

  // ---- Positive: wrapped under key A, engine holds key B, RUNLOG signature absent.
  const bad = await importedEngine(keyA, (w) => w);
  await recordRunlogSeed(bad.storage, { noSeed: "sig-absent" });
  const r = section(await fetchRecoveryStatus(asStub(bad), envB));
  const actions = Array.isArray(r.pendingOwnerActions) ? (r.pendingOwnerActions as string[]) : [];
  ok("pendingOwnerActions lists resign-runlog", actions.includes("resign-runlog"));
  ok("pendingOwnerActions lists reenter-destination-keys", actions.includes("reenter-destination-keys"));
  ok("pendingOwnerActions holds only members of the closed set", actions.length > 0 && actions.every((a) => a === "resign-runlog" || a === "reenter-destination-keys"));
  ok("lastImport.destinationsUnreadable.count is 1", r.lastImport?.destinationsUnreadable?.count === 1);
  ok("lastImport.destinationsUnreadable.ids names the destination", JSON.stringify(r.lastImport?.destinationsUnreadable?.ids) === JSON.stringify(["d1"]));
  const text = JSON.stringify(r);
  ok("no plaintext secret, key material or envelope bytes ride in the section", !text.includes(PLAINTEXT) && !text.includes(envA.CONFIG_WRAP_KEY as string) && !text.includes(envB.CONFIG_WRAP_KEY as string) && !text.includes('"ct"') && !text.includes('"iv"'));
  ok("no URL rides in the section", !/https?:\/\//.test(text) && !text.includes("s3.owner-actions.example"));

  // ---- A destination whose credential was not exported is unreadable too.
  const noSecret = await importedEngine(keyA, () => "");
  const rn = section(await fetchRecoveryStatus(asStub(noSecret), envA));
  ok("an exported-without-credential destination counts as unreadable", rn.lastImport?.destinationsUnreadable?.count === 1);
  ok("it asks for reenter-destination-keys and not resign-runlog", JSON.stringify(rn.pendingOwnerActions) === JSON.stringify(["reenter-destination-keys"]));

  // ---- Negative: right key, RUNLOG seeded. Nothing pending.
  const good = await importedEngine(keyA, (w) => w);
  await recordRunlogSeed(good.storage, { seed: 7 });
  const g = section(await fetchRecoveryStatus(asStub(good), envA));
  ok("right key: destinationsUnreadable count is 0 with no ids", g.lastImport?.destinationsUnreadable?.count === 0 && JSON.stringify(g.lastImport?.destinationsUnreadable?.ids) === "[]");
  ok("right key and a seeded RUNLOG: pendingOwnerActions is absent", g.pendingOwnerActions === undefined);

  // ---- Negative: an estate that was never imported carries neither field.
  const fresh = makeScheduler();
  const f = section(await fetchRecoveryStatus(asStub(fresh), envB));
  ok("no import: pendingOwnerActions is absent", f.pendingOwnerActions === undefined);
  ok("no import: lastImport is absent", f.lastImport === undefined);

  // ---- Only the RUNLOG fault: one action.
  const rl = await importedEngine(keyA, (w) => w);
  await recordRunlogSeed(rl.storage, { noSeed: "sig-absent" });
  const o = section(await fetchRecoveryStatus(asStub(rl), envA));
  ok("only the RUNLOG fault: pendingOwnerActions is exactly [resign-runlog]", JSON.stringify(o.pendingOwnerActions) === JSON.stringify(["resign-runlog"]));

  console.log(failures === 0 ? "\nVALIDATE-SUPPORT-RECOVERY-OWNER-ACTIONS VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
