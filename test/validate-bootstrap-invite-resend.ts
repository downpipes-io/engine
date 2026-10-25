// validate-bootstrap-invite-resend: pressing the first-Owner "email me the set-up link" button repeatedly
// keeps the one live link and mails it at most once a minute. The send route is reachable without a session,
// so a repeated press must not replace the link already in the owner's mailbox, and must not mail the
// owner again inside the cooldown. Drives the real SchedulerDO on in-memory storage.
//
// NEGATIVE CONTROLS: the first press mints; a press after the cooldown sends the SAME token again; a
// different pinned address still mints its own link. Run: node test/validate-bootstrap-invite-resend.ts

import { AUTH_SIGNALS_KEY } from "../src/admin/auth-signals.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const OWNER = "owner@acme.example";
// The documented minimum gap between two sends of the link, stated here as a literal so the check does not
// follow the source constant.
const BOOTSTRAP_RESEND_COOLDOWN_MS = 60 * 1000;

async function main(): Promise<void> {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const t0 = Date.now();

  const first = await dobj.mintBootstrapInvite(OWNER, t0);
  ok("the first press mints a link", typeof first === "string" && first.length > 0);

  const second = await dobj.mintBootstrapInvite(OWNER, t0 + 1000);
  ok("a second press one second later sends nothing (no second email)", second === null);
  ok("the link from the first press still opens after the second press", (await dobj.peekBootstrapInvite(first as string, t0 + 1500)) === OWNER);

  const flood: Array<string | null> = [];
  for (let i = 2; i < 12; i++) flood.push(await dobj.mintBootstrapInvite(OWNER, t0 + i * 1000));
  ok("ten more presses inside the cooldown all send nothing", flood.every((t) => t === null));
  ok("the first link is still the live one after the flood", (await dobj.peekBootstrapInvite(first as string, t0 + 13000)) === OWNER);

  const later = await dobj.mintBootstrapInvite(OWNER, t0 + BOOTSTRAP_RESEND_COOLDOWN_MS + 1);
  ok("a press after the cooldown sends the SAME link again", later === first);
  const tooSoon = await dobj.mintBootstrapInvite(OWNER, t0 + BOOTSTRAP_RESEND_COOLDOWN_MS + 2000);
  ok("the cooldown restarts from that send", tooSoon === null);

  const sigs = (await storage.get<Record<string, { count?: number }>>(AUTH_SIGNALS_KEY)) ?? {};
  ok("the refused presses are recorded under the closed cooldown signal", (sigs["invite-mint-refused-cooldown"]?.count ?? 0) >= 12);

  const other = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  const a = await other.mintBootstrapInvite(OWNER, t0);
  ok("negative control: a fresh engine mints on its first press", typeof a === "string");
  const b = await other.mintBootstrapInvite("other@acme.example", t0 + 1000);
  ok("negative control: a different pinned address still mints its own link", typeof b === "string" && b !== a);

  console.log(failures === 0 ? "\nBOOTSTRAP INVITE RESEND PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
