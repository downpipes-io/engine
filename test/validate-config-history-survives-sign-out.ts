// validate-config-history-survives-sign-out: signing every member out must not break the config history.
//
// The config history signs each version with an HMAC key. That key used to be the session signing key, and
// terminateAllSessions deletes the session key to end every session. After a global sign-out the history
// then failed its signed-digest check at its first version, and GET /config/history reported a break that
// no one had caused. This validator drives the real SchedulerDO and proves:
//  - after terminateAllSessions the retained chain still verifies, and signingKeyRotated is not raised;
//  - a version written after the sign-out joins the same chain and verifies;
//  - an edited stored version still breaks the chain after the sign-out (the check is not vacuous).
//
// Run: node test/validate-config-history-survives-sign-out.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { makeConfig } from "./validate-scheduler-shared.ts";
import type { ConfigVersion } from "../src/admin/config-history.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

interface Driven {
  sessionSigningKey(): Promise<Uint8Array>;
  snapshotConfigNow(author: string | null): Promise<{ created: boolean }>;
  addDownpipe(config: unknown): Promise<unknown>;
  terminateAllSessions(caller: { method: "token"; email: string | null; subject: string | null; groups: string[] }): Promise<{ ok: boolean }>;
  configHistoryList(): Promise<{ verify: { intact: boolean; brokenAt?: number } }>;
  configHistoryHealth(): Promise<{ count: number; verify: { intact: boolean; signingKeyRotated?: boolean } }>;
}

function makeDO(): { dobj: Driven; storage: MockStorage } {
  const storage = new MockStorage();
  return { dobj: new SchedulerDO({ storage } as unknown as DurableObjectState) as unknown as Driven, storage };
}

async function main(): Promise<void> {
  const { dobj, storage } = makeDO();
  await dobj.sessionSigningKey(); // a live account has a session key
  const first = await dobj.snapshotConfigNow("owner@history.example");
  ok("the first version is created", first.created === true);
  const before = await dobj.configHistoryList();
  ok("before the sign-out the chain verifies", before.verify.intact === true);
  await dobj.configHistoryHealth(); // establishes the key fingerprint baseline, as the support pack does

  const out = await dobj.terminateAllSessions({ method: "token", email: "owner@history.example", subject: null, groups: [] });
  ok("terminateAllSessions succeeds", out.ok === true);
  const after = await dobj.configHistoryList();
  console.log(`  after the sign-out: intact=${after.verify.intact} brokenAt=${after.verify.brokenAt ?? "-"}`);
  ok("after the sign-out the retained chain still verifies", after.verify.intact === true);
  const health = await dobj.configHistoryHealth();
  ok("after the sign-out signingKeyRotated is not raised", health.verify.signingKeyRotated !== true);
  ok("after the sign-out the health probe reports the chain intact", health.verify.intact === true);

  // A later change joins the same chain and verifies under the same key.
  const keysBefore = storage.rawKeys("confighist:").length;
  await dobj.addDownpipe(makeConfig("dp-after-signout"));
  await dobj.snapshotConfigNow("owner@history.example");
  const grown = storage.rawKeys("confighist:").length > keysBefore;
  const later = await dobj.configHistoryList();
  ok("a version written after the sign-out is added", grown);
  ok("the chain verifies with a version written after the sign-out", later.verify.intact === true);

  // Not vacuous: an edited stored version still breaks the chain after the sign-out.
  const k = storage.rawKeys("confighist:")[0]!;
  const v = storage.rawGet<ConfigVersion>(k)!;
  storage.rawPut(k, { ...v, summary: `${v.summary} (edited)` });
  const tampered = await dobj.configHistoryList();
  ok("an edited version breaks the chain after the sign-out", tampered.verify.intact === false);

  console.log(failures === 0 ? "\nVALIDATE-CONFIG-HISTORY-SURVIVES-SIGN-OUT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
