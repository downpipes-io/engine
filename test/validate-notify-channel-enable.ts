// Refuter: a notification channel's enable/disable toggle, submitted through the edit
// form, must PERSIST and TAKE EFFECT. Before the fix, addNotifyChannel constructed every edit with
// `enabled: prior ? prior.enabled : true`, so a submitted disable returned a 200, read back enabled=true, and
// the channel kept delivering: the customer was told the toggle worked and it silently did not. This drives
// the DO's OWN addNotifyChannel / listNotifyChannels / resolveNotify (a real SchedulerDO over an in-memory
// storage double, the sibling-validator pattern from validate-servicenow.ts) and asserts the engine's own
// stored AND routed state, so it fails LOUDLY if the discard ever returns. Default-FAIL: reverting the fix
// (writing prior.enabled on an edit) turns the disable + re-enable read-backs red.
//
// It also guards the paths the fix must not break: a fresh create still defaults ON, an edit that OMITS
// enabled keeps the prior state (a caller that never sends the field cannot flip it), and the rule enable
// toggle (which was always correct, the asymmetry the finding named) is unchanged. No network. Run:
//   node test/validate-notify-channel-enable.ts

import type { NotifyChannel } from "../src/notify/types.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeDO(): SchedulerDO {
  return new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
}
const OWNER_CALLER = { method: "token" as const, email: null, subject: null, role: "owner" as const };
const WEBHOOK_URL = "https://ops.example.com/notify-hook";

// readEnabled reads the channel through the DO's OWN list path (what an ADMIN_TOKEN read-back sees on the
// live estate), not the addNotifyChannel return value, so a persist the return value faked but storage
// dropped would still be caught.
async function readEnabled(dobj: SchedulerDO, id: string): Promise<boolean | undefined> {
  const chans = await dobj.listNotifyChannels();
  return chans.find((c) => c.id === id)?.enabled;
}

// routesToChannel reports whether a backup-failure emission RESOLVES to the channel through the engine's own
// resolveNotify. The first channel auto-creates a default global rule selecting backup-failure, so this
// exercises the real routing path: a disabled channel is skipped by resolveDelivery (buildResolvedDelivery
// only pushes enabled channels), which is the toggle TAKING EFFECT, not merely a flipped stored flag.
async function routesToChannel(dobj: SchedulerDO, id: string): Promise<boolean> {
  const emission = { event: "backup-failure", severity: "critical", downpipeId: null, downpipeName: null, detail: "refuter: routing check", at: "2026-07-19T00:00:00.000Z" };
  const res = await dobj.resolveNotify({ emission });
  return res.now.some((c: NotifyChannel) => c.id === id);
}

async function main(): Promise<void> {
  console.log("refuter: a channel enable/disable toggle PERSISTS and TAKES EFFECT (engine read-back + routing)");

  const dobj = makeDO();

  // create: a new channel defaults ON, and the auto-created default rule routes a backup-failure to it.
  const created = await dobj.addNotifyChannel({ kind: "webhook", name: "Ops webhook", url: WEBHOOK_URL, enabled: true }, OWNER_CALLER);
  ok("create: a new channel is enabled", created.enabled === true);
  ok("create: engine read-back agrees it is enabled", (await readEnabled(dobj, created.id)) === true);
  ok("create: the default rule routes a backup-failure to the enabled channel", await routesToChannel(dobj, created.id));

  // THE FIX: an edit submitting enabled:false DISABLES it. Before the fix this read back enabled=true.
  const disabled = await dobj.addNotifyChannel({ id: created.id, kind: "webhook", name: "Ops webhook", url: WEBHOOK_URL, enabled: false }, OWNER_CALLER);
  ok("disable: the returned channel reports enabled=false", disabled.enabled === false);
  ok("disable: engine read-back reports enabled=false (the submitted disable PERSISTS)", (await readEnabled(dobj, created.id)) === false);
  ok("disable: the channel no longer routes a backup-failure (the toggle TOOK EFFECT)", !(await routesToChannel(dobj, created.id)));
  ok("disable: the edit did not create a duplicate channel", (await dobj.listNotifyChannels()).length === 1);

  // re-enable: an edit submitting enabled:true turns it back on, and routing is restored.
  await dobj.addNotifyChannel({ id: created.id, kind: "webhook", name: "Ops webhook", url: WEBHOOK_URL, enabled: true }, OWNER_CALLER);
  ok("re-enable: engine read-back reports enabled=true again", (await readEnabled(dobj, created.id)) === true);
  ok("re-enable: routing to the channel is restored", await routesToChannel(dobj, created.id));

  // NOT BROKEN (keep-current): an edit that OMITS enabled keeps the prior state, so a caller that never sends
  // the field cannot silently flip it. Disable first, then submit a name-only edit with no enabled field.
  await dobj.addNotifyChannel({ id: created.id, kind: "webhook", name: "Ops webhook", url: WEBHOOK_URL, enabled: false }, OWNER_CALLER);
  const nameOnly = await dobj.addNotifyChannel({ id: created.id, kind: "webhook", name: "Ops webhook (renamed)", url: WEBHOOK_URL }, OWNER_CALLER);
  ok("keep-current: an edit that omits enabled keeps the prior (disabled) state", nameOnly.enabled === false);
  ok("keep-current: engine read-back agrees it is still disabled", (await readEnabled(dobj, created.id)) === false);
  ok("keep-current: the name still updated in the same edit", nameOnly.name === "Ops webhook (renamed)");

  // NOT BROKEN (create default): a first channel created WITHOUT an enabled field still defaults ON.
  const dobjDefault = makeDO();
  const defaulted = await dobjDefault.addNotifyChannel({ kind: "webhook", name: "Defaulted", url: WEBHOOK_URL }, OWNER_CALLER);
  ok("create default: a channel created with no enabled field defaults to enabled", defaulted.enabled === true);

  // NOT BROKEN (rule path): the rule enable toggle was already honoured (addNotifyRule spreads the validated
  // enabled) and stays so. This is the sibling path whose asymmetry the finding named.
  const dobjRule = makeDO();
  const rule = await dobjRule.addNotifyRule({ scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: ["some-channel-id"], enabled: true }, OWNER_CALLER);
  ok("rule path: a rule created enabled reads back enabled", rule.enabled === true);
  const ruleOff = await dobjRule.addNotifyRule({ id: rule.id, scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: ["some-channel-id"], enabled: false }, OWNER_CALLER);
  ok("rule path: a rule disable via edit still persists (unchanged by this fix)", ruleOff.enabled === false);
  const ruleBack = (await dobjRule.listNotifyRules()).find((r) => r.id === rule.id);
  ok("rule path: engine read-back shows the rule disabled", ruleBack?.enabled === false);

  console.log(failures === 0 ? "\nCHANNEL ENABLE-TOGGLE REFUTER PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
