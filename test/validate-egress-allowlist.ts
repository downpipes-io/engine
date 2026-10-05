// validate-egress-allowlist: the operator-configured outbound egress allowlist (ASVS V13.2.4).
//
// V13.2.4 asks for an allowlist that defines the external resources or systems the application may
// communicate with. The notify-channel surface (webhook/Slack/Teams/JSM/ServiceNow) is screened by two
// layers: the SSRF DENY rules (internal address space, workers.dev) and this operator-configured positive
// allowlist. This suite proves the positive list is enforced at BOTH the config boundary (validateChannel
// / isAllowedWebhookUrl) and the wire boundary (deliverPayload, and JSM's own bespoke sender), and is
// independent of the SSRF internal-sink deny screen.
//
// NEGATIVE CONTROL FIRST, throughout: every refusal assertion is paired with the SAME call succeeding
// (the mock fetch counting exactly one call) when the allowlist is unset, so a check that could not have
// failed is never mistaken for one that passed. Run: node test/validate-egress-allowlist.ts

import { isAllowedWebhookUrl, screenEgressAllowlist, validateEgressAllowlist, normaliseEgressAllowlistEntry, deliverPayload, EGRESS_ALLOWLIST_MAX_ENTRIES } from "../src/notify/types.ts";
import { validateChannel } from "../src/notify-routing.ts";
import { deliver as jsmDeliver } from "../src/notify/channels/jsm.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify/types.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function recipientsValidator(raw: unknown): { ok: true; to: string[] } | { ok: false; reason: string } {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false, reason: "at least one address is required" };
  return { ok: true, to: raw as string[] };
}

const OWNER_CALLER = { method: "token" as const, email: null, subject: null, role: "owner" as const, groups: [] as string[] };
const VIEWER_CALLER = { method: "access" as const, email: "v@example.au", subject: "subject-v@example.au", role: "viewer" as const, groups: [] as string[] };

function makeDO(): SchedulerDO {
  return new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
}

function testEmission(): NotifyEmission {
  return { event: "backup-failure", severity: "critical", downpipeId: null, downpipeName: null, detail: "egress-allowlist test emission", at: "2026-09-13T00:00:00.000Z" };
}

console.log("\nV13.2.4 egress-allowlist: screenEgressAllowlist (the shared match rule)\n");
{
  ok("unset allowlist permits an arbitrary public host", screenEgressAllowlist("evil.example", undefined));
  ok("empty allowlist permits an arbitrary public host", screenEgressAllowlist("evil.example", []));
  ok("a fixed platform host is permitted even with a restrictive list set", screenEgressAllowlist("api.cloudflare.com", ["hooks.slack.com"]));
  ok("a fixed platform host is permitted even with an EMPTY explicit list", screenEgressAllowlist("update.downpipes.io", []));

  // A host under one of isFixedEgressHost's wildcard suffixes (an S3/STS region, an Access team, a Stream
  // customer subdomain) is a customer- or attacker-namespaced value, not one of the engine's own fixed
  // vendor hosts. screenEgressAllowlist screens a customer-typed notify-channel url, so it must NOT treat
  // these suffixes as always-permitted the way the destination-write path does: with a restrictive list
  // set, each is refused like any other non-listed public host. Negative control first: the same host
  // passes when the allowlist is unset, so the refusal below is the list actually taking effect.
  ok("negative control: an *.amazonaws.com host passes with the allowlist unset", screenEgressAllowlist("sts.ap-southeast-2.amazonaws.com", undefined));
  ok(
    "THE PLANT: an *.amazonaws.com host is refused by a restrictive list, not silently exempted as a fixed host",
    !screenEgressAllowlist("sts.ap-southeast-2.amazonaws.com", ["hooks.slack.com"]),
  );
  ok("negative control: an *.cloudflareaccess.com host passes with the allowlist unset", screenEgressAllowlist("maelstrom.cloudflareaccess.com", undefined));
  ok(
    "THE PLANT: an *.cloudflareaccess.com host is refused by a restrictive list, not silently exempted as a fixed host",
    !screenEgressAllowlist("maelstrom.cloudflareaccess.com", ["hooks.slack.com"]),
  );
  ok("negative control: an *.cloudflarestream.com host passes with the allowlist unset", screenEgressAllowlist("customer123.cloudflarestream.com", undefined));
  ok(
    "THE PLANT: an *.cloudflarestream.com host is refused by a restrictive list, not silently exempted as a fixed host",
    !screenEgressAllowlist("customer123.cloudflarestream.com", ["hooks.slack.com"]),
  );

  const list = ["hooks.slack.com", "*.pagerduty.com"];
  ok("exact match permits", screenEgressAllowlist("hooks.slack.com", list));
  ok("exact match is case-insensitive", screenEgressAllowlist("HOOKS.SLACK.COM", list));
  ok("a non-matching public host is refused", !screenEgressAllowlist("evil.example", list));
  ok("wildcard matches its direct subdomain", screenEgressAllowlist("events.pagerduty.com", list));
  ok("wildcard matches a deeper subdomain", screenEgressAllowlist("eu.events.pagerduty.com", list));
  // The two boundary attacks a substring test would pass and a dotted-suffix test must refuse.
  ok("wildcard suffix boundary: a host merely ENDING in the suffix without the dot is refused", !screenEgressAllowlist("notpagerduty.com", list));
  ok("wildcard suffix boundary: the suffix appended as a further label is refused", !screenEgressAllowlist("pagerduty.com.evil", list));
  ok("the wildcard's own bare suffix (no subdomain label) is refused", !screenEgressAllowlist("pagerduty.com", list));
}

console.log("\nV13.2.4 egress-allowlist: validateEgressAllowlist / normaliseEgressAllowlistEntry (config-time shape)\n");
{
  const good = validateEgressAllowlist(["Hooks.Slack.com", "*.pagerduty.com", "hooks.slack.com"]);
  ok("a valid list is accepted", good.ok === true);
  if (good.ok) {
    ok("entries are lowercased", good.hosts.includes("hooks.slack.com"));
    ok("a wildcard entry is kept as written", good.hosts.includes("*.pagerduty.com"));
    ok("a case-only duplicate is de-duplicated", good.hosts.length === 2);
  }
  ok("a non-array is refused", validateEgressAllowlist("hooks.slack.com").ok === false);
  ok("a non-string entry is refused", validateEgressAllowlist([123]).ok === false);
  ok("too many entries is refused", validateEgressAllowlist(Array.from({ length: EGRESS_ALLOWLIST_MAX_ENTRIES + 1 }, (_, i) => `h${i}.example.com`)).ok === false);
  ok("exactly the cap is accepted", validateEgressAllowlist(Array.from({ length: EGRESS_ALLOWLIST_MAX_ENTRIES }, (_, i) => `h${i}.example.com`)).ok === true);
  ok("an empty entry is refused", normaliseEgressAllowlistEntry("").ok === false);
  ok("a scheme is refused", normaliseEgressAllowlistEntry("https://hooks.slack.com").ok === false);
  ok("a port is refused", normaliseEgressAllowlistEntry("hooks.slack.com:443").ok === false);
  ok("userinfo is refused", normaliseEgressAllowlistEntry("user@hooks.slack.com").ok === false);
  ok("a path is refused", normaliseEgressAllowlistEntry("hooks.slack.com/x").ok === false);
  ok("an IPv4 literal is refused", normaliseEgressAllowlistEntry("169.254.169.254").ok === false);
  ok("an IPv6 literal is refused", normaliseEgressAllowlistEntry("[::1]").ok === false);
  ok("a wildcard whose suffix is an IP literal is refused", normaliseEgressAllowlistEntry("*.169.254.169.254").ok === false);
  ok("an over-length entry is refused", normaliseEgressAllowlistEntry(`${"a".repeat(250)}.com`).ok === false);
  ok("a bare wildcard with no suffix is refused", normaliseEgressAllowlistEntry("*.").ok === false);
}

console.log("\nV13.2.4 egress-allowlist: isAllowedWebhookUrl config-time enforcement\n");
{
  const unset = isAllowedWebhookUrl("https://evil.example/hook");
  ok("negative control: with no allowlist option, an arbitrary https host is accepted", unset.ok === true);
  const denied = isAllowedWebhookUrl("https://evil.example/hook", { egressAllowlist: ["hooks.slack.com"] });
  ok("with a configured allowlist, a non-listed host is refused", denied.ok === false);
  if (!denied.ok) ok("the refusal carries the not-allowlisted code", denied.code === "not-allowlisted");
  const allowed = isAllowedWebhookUrl("https://hooks.slack.com/services/x", { egressAllowlist: ["hooks.slack.com"] });
  ok("a listed host is accepted", allowed.ok === true);
  // Ordering: a url that fails an EARLIER screen reports THAT reason, never the allowlist's.
  const nonHttps = isAllowedWebhookUrl("http://hooks.slack.com/x", { egressAllowlist: ["hooks.slack.com"] });
  ok("a non-https url is refused for that reason first, even though the host is listed", !nonHttps.ok && nonHttps.code === "non-https");
}

console.log("\nV13.2.4 egress-allowlist: validateChannel threads the account's list to every url-bearing kind\n");
{
  const allowlist = ["hooks.slack.com"];
  for (const kind of ["webhook", "slack"] as const) {
    const denied = validateChannel({ kind, name: "n", url: "https://evil.example/hook" }, recipientsValidator, allowlist);
    ok(`${kind}: negative control absent (no allowlist arg) accepts an arbitrary host`, validateChannel({ kind, name: "n", url: "https://evil.example/hook" }, recipientsValidator).ok === true);
    ok(`${kind}: a non-listed host is refused once the account has a list`, denied.ok === false);
    const accepted = validateChannel({ kind, name: "n", url: "https://hooks.slack.com/x" }, recipientsValidator, allowlist);
    ok(`${kind}: a listed host is accepted`, accepted.ok === true);
  }
  const teamsDenied = validateChannel({ kind: "teams", name: "n", url: "https://evil.example/hook" }, recipientsValidator, allowlist);
  ok("teams (connector url): a non-listed host is refused", teamsDenied.ok === false);
  const jsmDenied = validateChannel({ kind: "jsm", name: "n", url: "https://evil.example/v2/alerts" }, recipientsValidator, allowlist);
  ok("jsm: a non-listed host is refused", jsmDenied.ok === false);
  const snDenied = validateChannel({ kind: "servicenow", name: "n", url: "https://evil.example/api/now/table/em_event", username: "u" }, recipientsValidator, allowlist);
  ok("servicenow: a non-listed host is refused", snDenied.ok === false);
  // PagerDuty has no customer url at all: the allowlist is meaningless for it and validateChannel never
  // consults it (validatePagerdutyKind takes no allowlist parameter).
  const pd = validateChannel({ kind: "pagerduty", name: "n", routingKey: "r".repeat(20) }, recipientsValidator, allowlist);
  ok("pagerduty: unaffected by the allowlist (no customer host to screen)", pd.ok === true);
}

console.log("\nV13.2.4 egress-allowlist: deliverPayload wire-time enforcement (negative control, then the plant)\n");
{
  // deliverPayload re-screens a hostname-shaped target by RESOLVING it over DoH first (the dns-rebinding
  // screen, unrelated to this control), through the SAME injected fetchImpl -- so a hostname target makes
  // an extra call to cloudflare-dns.com before the real POST. destCalls counts ONLY calls to the target's
  // own host (the thing the allowlist is supposed to stop), which is the fact this suite needs to prove:
  // the mock still answers the DoH lookup (an empty Answer, i.e. resolve-unavailable, fail-open), so the
  // resolve screen's own behaviour is exercised exactly as it is in production, unmodified by this test.
  let destCalls = 0;
  const countingFetch: typeof fetch = (async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (new URL(url).hostname === "cloudflare-dns.com") return new Response(JSON.stringify({ Answer: [] }), { status: 200 });
    destCalls++;
    return new Response("{}", { status: 200 });
  }) as typeof fetch;

  destCalls = 0;
  const unsetResult = await deliverPayload("https://evil.example/hook", { a: 1 }, false, undefined, countingFetch, undefined);
  ok("negative control: with the allowlist unset, deliverPayload reaches the target host exactly once", destCalls === 1);
  ok("negative control: the send succeeds", unsetResult.ok === true);

  destCalls = 0;
  const deniedResult = await deliverPayload("https://evil.example/hook", { a: 1 }, false, undefined, countingFetch, ["hooks.slack.com", "*.pagerduty.com"]);
  ok("THE PLANT: with the account's list configured, a non-listed host makes ZERO calls to the target", destCalls === 0);
  ok("the delivery is refused", deniedResult.ok === false);
  ok("the refusal carries code egress-not-allowlisted", deniedResult.code === "egress-not-allowlisted");
  ok("the refusal carries sinkScreen not-allowlisted", deniedResult.sinkScreen === "not-allowlisted");

  destCalls = 0;
  const wildcardResult = await deliverPayload("https://events.pagerduty.com/v2/enqueue", { a: 1 }, false, undefined, countingFetch, ["hooks.slack.com", "*.pagerduty.com"]);
  ok("a wildcard-matched host still delivers (one call to the target)", destCalls === 1 && wildcardResult.ok === true);

  // Independence from allowInternal: a private host opted into via allowInternalSink is STILL refused by
  // the allowlist (the docs precedent this closure states: an allowlisted private host still needs the
  // internal-sink opt-in too, and the reverse -- opted into internal, but not allowlisted -- is refused here).
  destCalls = 0;
  const internalOptInButNotAllowlisted = await deliverPayload("https://10.0.0.5/hook", { a: 1 }, true, undefined, countingFetch, ["hooks.slack.com"]);
  ok("allowInternal=true does not bypass the allowlist: zero calls to the target", destCalls === 0);
  ok("the refusal is egress-not-allowlisted, not internal-sink-blocked (the allowlist is checked first)", internalOptInButNotAllowlisted.code === "egress-not-allowlisted");

  // Fixed platform hosts are never subject to the operator's list, even when it excludes them entirely.
  destCalls = 0;
  const platformResult = await deliverPayload("https://api.cloudflare.com/client/v4/x", { a: 1 }, false, undefined, countingFetch, ["hooks.slack.com"]);
  ok("a fixed platform host passes with the list set (one call to the target)", destCalls === 1 && platformResult.ok === true);
}

console.log("\nV13.2.4 egress-allowlist: JSM's own bespoke sender (deliver -> deliverJsmRequest / pollJsmRequestStatus)\n");
{
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response(JSON.stringify({ result: "ok", requestId: "req-1" }), { status: 202 });
  }) as typeof fetch;
  try {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "jsm", url: "https://evil.example/v2/alerts", apiKey: "tok", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    calls = 0;
    const unset = await jsmDeliver({} as never, channel, testEmission());
    ok("negative control: JSM with no allowlist reaches the network", calls >= 1);
    ok("negative control: JSM send is accepted (async 202)", unset.ok === true);

    calls = 0;
    const denied = await jsmDeliver({} as never, channel, testEmission(), ["hooks.slack.com"]);
    ok("THE PLANT: JSM with a non-listed host makes zero network calls", calls === 0);
    ok("JSM refusal carries egress-not-allowlisted", denied.ok === false && denied.code === "egress-not-allowlisted");
  } finally {
    globalThis.fetch = realFetch;
  }
}

console.log("\nV13.2.4 egress-allowlist: the DO authority (setEgressAllowlist / getEgressAllowlist / addNotifyChannel)\n");
{
  const dobj = makeDO();
  const initial = await dobj.getEgressAllowlist();
  ok("default: no allowlist configured reads as empty", Array.isArray(initial) && initial.length === 0);

  let threw = false;
  try {
    await dobj.setEgressAllowlist({ egressAllowlist: ["hooks.slack.com"] }, VIEWER_CALLER);
  } catch {
    threw = true;
  }
  ok("a non-owner cannot set the allowlist", threw);

  threw = false;
  try {
    await dobj.setEgressAllowlist({ egressAllowlist: ["169.254.169.254"] }, OWNER_CALLER);
  } catch {
    threw = true;
  }
  ok("an owner submitting an IP literal is refused", threw);

  const set = await dobj.setEgressAllowlist({ egressAllowlist: ["hooks.slack.com", "*.pagerduty.com"] }, OWNER_CALLER);
  ok("an owner can set a valid allowlist", set.egressAllowlist.length === 2);
  ok("the read-back agrees", (await dobj.getEgressAllowlist()).length === 2);

  // Negative control, two config states. With no allowlist configured, any public host can be added (proven
  // above, in the "config-time enforcement" and "validateChannel" groups, with no allowlist argument). With a
  // list configured on a real DO's OrgPolicy, addNotifyChannel refuses a non-listed host and accepts a listed one.
  threw = false;
  try {
    await dobj.addNotifyChannel({ kind: "webhook", name: "evil", url: "https://evil.example/hook", enabled: true }, OWNER_CALLER);
  } catch {
    threw = true;
  }
  ok("addNotifyChannel refuses a webhook host the account did not allowlist", threw);

  const created = await dobj.addNotifyChannel({ kind: "webhook", name: "slack-ish", url: "https://hooks.slack.com/services/x", enabled: true }, OWNER_CALLER);
  ok("addNotifyChannel accepts an exact-listed host", created.url === "https://hooks.slack.com/services/x");

  const createdWildcard = await dobj.addNotifyChannel({ kind: "webhook", name: "pd", url: "https://events.pagerduty.com/v2/enqueue", enabled: true }, OWNER_CALLER);
  ok("addNotifyChannel accepts a wildcard-listed host", createdWildcard.url === "https://events.pagerduty.com/v2/enqueue");

  // Clearing back to an empty list restores unrestricted behaviour (unset === empty, the documented default).
  const cleared = await dobj.setEgressAllowlist({ egressAllowlist: [] }, OWNER_CALLER);
  ok("an owner can clear the allowlist back to empty", cleared.egressAllowlist.length === 0);
  const createdAfterClear = await dobj.addNotifyChannel({ kind: "webhook", name: "anything", url: "https://anything.example/hook", enabled: true }, OWNER_CALLER);
  ok("after clearing, an arbitrary host is accepted again (unset === unrestricted)", createdAfterClear.url === "https://anything.example/hook");
}

console.log(failures === 0 ? "\nEGRESS ALLOWLIST PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
