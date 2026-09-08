// Prove the support pack derives inert notification rules.
//
// A notify rule that can never deliver -- it names no channel, every channel it names has been deleted, or
// every channel it names is disabled -- fires silently into the void, so "I have an alert rule but I never
// get paged" was undiagnosable from the bundle (the pack carried a dangling-ref COUNT but no per-rule inert
// verdict). fetchNotifyConfig now derives rulesInert {count, byReason} from the channels + rules it already
// fetches. This drives the real gatherer through a DO double and asserts each inert reason is classified and
// a healthy rule (>=1 live enabled channel) is NOT counted, with no rule/channel id echoed.
//
// Run:  node test/validate-support-notify-inert.ts

import { fetchNotifyConfig } from "../src/admin/support-sections-notify.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function notifyScheduler(channels: unknown, rules: unknown): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/notify/channels") return new Response(JSON.stringify(channels));
      if (url.pathname === "/notify/rules") return new Response(JSON.stringify(rules));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("validate-support-notify-inert\n");

  const channels = [
    { id: "ch-live", kind: "webhook", enabled: true },
    { id: "ch-off", kind: "email", enabled: false },
  ];
  const rules = [
    { channelIds: ["ch-live"] }, // healthy: one live enabled channel -> NOT inert
    { channelIds: [] }, // no-channel
    { channelIds: ["ch-deleted"] }, // dangling-channel (id not in the set)
    { channelIds: ["ch-off"] }, // all-channels-disabled
    { channelIds: ["ch-off", "ch-live"] }, // healthy: at least one live enabled -> NOT inert
  ];

  const cfg = (await fetchNotifyConfig(notifyScheduler(channels, rules))) as { rulesInert?: { count: number; byReason: Record<string, number> } };
  const inert = cfg.rulesInert;

  ok("rulesInert.count totals the three inert rules (no-channel + dangling + all-disabled)", inert?.count === 3);
  ok("byReason classifies no-channel", inert?.byReason["no-channel"] === 1);
  ok("byReason classifies dangling-channel", inert?.byReason["dangling-channel"] === 1);
  ok("byReason classifies all-channels-disabled", inert?.byReason["all-channels-disabled"] === 1);
  ok("a rule with at least one live enabled channel is NOT counted inert", inert?.count === 3 && !("healthy" in (inert?.byReason ?? {})));
  ok("rulesInert never echoes a rule or channel id (closed reasons + counts only)", !JSON.stringify(inert).includes("ch-") );

  // Honest absence: every rule deliverable -> rulesInert omitted entirely.
  const allHealthy = (await fetchNotifyConfig(notifyScheduler(channels, [{ channelIds: ["ch-live"] }]))) as { rulesInert?: unknown };
  ok("rulesInert is omitted when every rule can deliver (no false inert block)", allHealthy.rulesInert === undefined);

  console.log(failures === 0 ? "\nALL SUPPORT-NOTIFY-INERT VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
