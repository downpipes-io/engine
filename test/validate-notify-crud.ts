// CRUD, resolve/record and history-ring vectors for the validate-notify suite
// (TC-N-15..TC-N-18b), split out of validate-notify.ts. Covers the
// notify channels/rules DO CRUD + notify.config re-check + default-on rule,
// resolve/record two-phase + history ring, and the ring cap under platform paging.

import { isEntryPoint } from "./lib/entry-point.ts";
import {
  severityOf,
  type NotifyChannel,
  type NotifyRule,
  type NotifyHistoryEntry,
  type NotifyEvent,
  type Severity,
} from "../src/notify.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { ok, getFailures, makeScheduler, stubFetch, callerFetch, isoAt } from "./validate-notify-shared.ts";

// ---- TC-N-15: notify channels/rules DO CRUD + notify.config re-check + default-on rule ----
// Split into focused sub-tests: access control, channel CRUD (create,
// upsert, delete), and rule CRUD (create, upsert, unknown-id, delete). The shared setup (create the
// first channel and read back its id) is the seedFirstChannel helper.

// seedFirstChannel creates the first webhook channel as an operator and returns its id. The first
// channel is what mints the default-on rule, so the rule sub-tests build on this same seed.
async function seedFirstChannel(stub: SchedulerDO): Promise<string> {
  const r = await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" });
  ok("crud: operator POST channel ok", r.status === 200);
  const c = (await r.json()) as NotifyChannel;
  ok("crud: channel has an id", typeof c.id === "string" && c.id.length > 0);
  ok("crud: channel enabled by default", c.enabled === true);
  ok("crud: channel createdAt present", typeof c.createdAt === "string");
  return c.id;
}

async function testNotifyCrudAccessControl(): Promise<void> {
  const { stub } = makeScheduler();
  // A viewer (no notify.config) is refused at the DO re-check (403: an authorisation refusal).
  const channelRefused = await callerFetch(stub, "viewer", "POST", "/notify/channels", { kind: "webhook", name: "x", url: "https://a.example.com/h" });
  ok("crud: viewer POST channel refused (DO re-check)", channelRefused.status === 403);
  // A viewer cannot delete a channel either (seed one as operator first so the id exists).
  const channelId = await seedFirstChannel(stub);
  const deleteRefused = await callerFetch(stub, "viewer", "POST", "/notify/channels/delete", { id: channelId });
  ok("crud: viewer delete channel refused", deleteRefused.status === 403);
}

async function testNotifyCrudChannels(): Promise<void> {
  const { stub } = makeScheduler();
  // An operator can add a channel; the FIRST channel creates the default-on rule.
  const channelId = await seedFirstChannel(stub);
  // The default-on rule exists now: a global rule selecting backup-failure + backup-stale -> the new channel.
  {
    const rules = (await (await stubFetch(stub, "GET", "/notify/rules")).json()) as NotifyRule[];
    ok("crud: default-on rule created on first channel", rules.length === 1);
    const dr = rules[0]!;
    ok("crud: default rule is global", dr.scope.kind === "global");
    ok("crud: default rule selects failure + stale", Array.isArray(dr.events) && dr.events.includes("backup-failure") && dr.events.includes("backup-stale"));
    ok("crud: default rule targets the new channel", dr.channelIds.includes(channelId));
  }
  // Adding a SECOND channel does NOT create another default rule.
  {
    await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "email", name: "ops", toAddresses: ["ops@example.com"] });
    const rules = (await (await stubFetch(stub, "GET", "/notify/rules")).json()) as NotifyRule[];
    ok("crud: no second default rule on second channel", rules.length === 1);
    const channels = (await (await stubFetch(stub, "GET", "/notify/channels")).json()) as NotifyChannel[];
    ok("crud: two channels listed", channels.length === 2);
  }
  // UPSERT BY ID (channel): re-POSTing a channel WITH its id UPDATES it in place; it must not add a
  // duplicate, and createdAt is preserved. (Regression: editing once created a second channel.)
  {
    const before = (await (await stubFetch(stub, "GET", "/notify/channels")).json()) as NotifyChannel[];
    const prior = before.find((c) => c.id === channelId)!;
    const r = await callerFetch(stub, "operator", "POST", "/notify/channels", { id: channelId, kind: "webhook", name: "SIEM (renamed)", url: "https://siem.example.com/h2" });
    ok("crud: upsert channel by id ok", r.status === 200);
    const updated = (await r.json()) as NotifyChannel;
    ok("crud: upsert keeps the same channel id", updated.id === channelId);
    ok("crud: upsert applied the channel change", updated.name === "SIEM (renamed)" && updated.url === "https://siem.example.com/h2");
    ok("crud: upsert preserves channel createdAt", updated.createdAt === prior.createdAt);
    const after = (await (await stubFetch(stub, "GET", "/notify/channels")).json()) as NotifyChannel[];
    ok("crud: upsert channel does NOT create a duplicate", after.length === before.length);
  }
  // Operator deletes the channel; an absent id is an idempotent no-op; an invalid shape is rejected.
  {
    const del = await callerFetch(stub, "operator", "POST", "/notify/channels/delete", { id: channelId });
    ok("crud: operator delete channel ok", del.status === 200 && (await del.json() as { deleted: boolean }).deleted === true);
    ok("crud: delete absent channel -> deleted:false", (await (await callerFetch(stub, "operator", "POST", "/notify/channels/delete", { id: "nope" })).json() as { deleted: boolean }).deleted === false);
    ok("crud: invalid channel -> 400", (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "x", url: "http://insecure.example.com" })).status === 400);
  }
}

async function testNotifyCrudRules(): Promise<void> {
  const { stub } = makeScheduler();
  const channelId = await seedFirstChannel(stub);
  // Add an explicit rule.
  let ruleId = "";
  {
    const r = await callerFetch(stub, "operator", "POST", "/notify/rules", {
      scope: { kind: "downpipe", downpipeId: "pipe-1" },
      minSeverity: "info",
      events: "all",
      channelIds: [channelId],
      digest: "daily",
      enabled: true,
    });
    ok("crud: operator POST rule ok", r.status === 200);
    const rule = (await r.json()) as NotifyRule;
    ruleId = rule.id;
    ok("crud: rule has an id", typeof ruleId === "string" && ruleId.length > 0);
    ok("crud: rule digest persisted", rule.digest === "daily");
  }
  // ===== A RULE MAY NAME A DOWNPIPE THAT DOES NOT EXIST. THAT IS DELIBERATE. =====
  //
  // addNotifyRule's own comment states the policy for the SIBLING reference on
  // the same record: it "does NOT require the referenced channels to exist at write time (an operator may
  // wire a rule before a channel); resolveDelivery skips unknown ids at delivery time". The downpipe scope
  // is the same reference on the same record and follows the same rule: requiring existence would refuse
  // wiring a rule before its downpipe, and would make a configuration restore depend on the order the
  // control plane happens to apply downpipes and rules in.
  //
  // What it leaves open is the AFTERMATH, not the write: deleting a downpipe silently stops the rules scoped
  // to it. That is a visibility gap for the support pack, and it is written down rather than closed here.
  {
    const r = await callerFetch(stub, "operator", "POST", "/notify/rules", {
      scope: { kind: "downpipe", downpipeId: "downpipe-that-does-not-exist" },
      minSeverity: "info",
      events: "all",
      channelIds: [channelId],
      enabled: true,
    });
    ok("crud: a rule naming a downpipe that does not exist is ACCEPTED (DELIBERATE, see the comment)", r.status === 200);
    const stored = (await r.json()) as NotifyRule;
    ok("crud: and it is stored with the id VERBATIM, not silently rewritten to something that resolves", stored.scope.kind === "downpipe" && stored.scope.downpipeId === "downpipe-that-does-not-exist");
    // The refusal it must NOT be confused with: a MALFORMED downpipeId is still a hard failure, so what is
    // pinned above is tolerance of a dangling reference, not the absence of a bound on the field.
    const bad = await callerFetch(stub, "operator", "POST", "/notify/rules", {
      scope: { kind: "downpipe", downpipeId: "has a space and a | pipe" },
      minSeverity: "info",
      events: "all",
      channelIds: [channelId],
      enabled: true,
    });
    ok("crud: a MALFORMED downpipeId is still refused, so the field is bounded even though existence is not checked", bad.status !== 200);
    await callerFetch(stub, "operator", "POST", "/notify/rules/delete", { id: stored.id });
  }
  // UPSERT BY ID (rule): re-POSTing the rule WITH its id UPDATES it in place; it must not add a
  // duplicate. (Regression: editing a rule once created a second rule instead of updating.)
  {
    const before = (await (await stubFetch(stub, "GET", "/notify/rules")).json()) as NotifyRule[];
    const r = await callerFetch(stub, "operator", "POST", "/notify/rules", {
      id: ruleId,
      scope: { kind: "downpipe", downpipeId: "pipe-1" },
      minSeverity: "critical", // changed from info
      events: ["backup-failure"], // changed from "all"
      channelIds: [channelId],
      digest: "weekly", // changed from daily
      enabled: false, // changed from true
    });
    ok("crud: upsert rule by id ok", r.status === 200);
    const updated = (await r.json()) as NotifyRule;
    ok("crud: upsert keeps the same rule id", updated.id === ruleId);
    ok("crud: upsert applied the rule change", updated.minSeverity === "critical" && updated.digest === "weekly" && updated.enabled === false);
    const after = (await (await stubFetch(stub, "GET", "/notify/rules")).json()) as NotifyRule[];
    ok("crud: upsert rule does NOT create a duplicate", after.length === before.length);
    ok("crud: the stored rule reflects the edit", after.find((x) => x.id === ruleId)?.minSeverity === "critical");
  }
  // An UNKNOWN id is treated as a CREATE (the server owns the id space): it mints a new id, never the
  // supplied one, so a client cannot plant a chosen id.
  {
    const before = (await (await stubFetch(stub, "GET", "/notify/rules")).json()) as NotifyRule[];
    const r = await callerFetch(stub, "operator", "POST", "/notify/rules", {
      id: "rule-does-not-exist",
      scope: { kind: "global" },
      minSeverity: "info",
      events: "all",
      channelIds: [channelId],
      enabled: true,
    });
    ok("crud: unknown rule id -> create ok", r.status === 200);
    const created = (await r.json()) as NotifyRule;
    ok("crud: unknown rule id is NOT honoured (server mints a fresh id)", created.id !== "rule-does-not-exist" && created.id.length > 0);
    const after = (await (await stubFetch(stub, "GET", "/notify/rules")).json()) as NotifyRule[];
    ok("crud: unknown-id create adds exactly one rule", after.length === before.length + 1);
    // Clean up the extra rule so the later count assertions are unaffected.
    await callerFetch(stub, "operator", "POST", "/notify/rules/delete", { id: created.id });
  }
  // Operator deletes the rule.
  {
    const r = await callerFetch(stub, "operator", "POST", "/notify/rules/delete", { id: ruleId });
    ok("crud: operator delete rule ok", r.status === 200 && (await r.json() as { deleted: boolean }).deleted === true);
  }
}

// ---- TC-N-17: resolve/record two-phase + history ring (contract section 2.1/2.3) ----------

// seedResolveChannel creates the SIEM channel used by the resolve/record sub-tests and returns its id.
// The first channel's default-on rule selects backup-failure + backup-stale.
async function seedResolveChannel(stub: SchedulerDO): Promise<string> {
  const c = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" })).json()) as NotifyChannel;
  return c.id;
}

const RESOLVE_EMISSION = {
  event: "backup-failure" as NotifyEvent,
  severity: "critical" as Severity,
  downpipeId: "pipe-1",
  downpipeName: "Prod KV",
  detail: "Prod KV last run failed",
  at: "2026-06-09T00:00:00.000Z",
};

// resolve + canonicalisation: a backup-failure emission resolves to the channel; a non-canonical or
// unparseable `at` is normalised; a malformed emission and an admitted update-rollback-needed event
// behave as documented. 
async function testNotifyResolve(): Promise<void> {
  const { stub } = makeScheduler();
  const channelId = await seedResolveChannel(stub);
  const emission = RESOLVE_EMISSION;
  {
    const r = await stubFetch(stub, "POST", "/notify/resolve", { emission });
    ok("resolve: returns 200", r.status === 200);
    const body = (await r.json()) as { now: NotifyChannel[]; digestedCount: number; emission: unknown };
    ok("resolve: channel resolved to now", body.now.length === 1 && body.now[0]?.id === channelId);
    ok("resolve: nothing digested for a failure", body.digestedCount === 0);
    ok("resolve: emission echoed (normalised)", body.emission !== null);
  }
  // parseEmission canonicalisation: an `at` posted in a NON-canonical precision/offset must be
  // normalised by the DO to the producers' RFC-3339 millis-Z form before it is stored/echoed, so a
  // downstream instant comparison never sees a non-canonical string. We post the SAME instant in three
  // shapes (a +10:00 offset, a sub-millisecond fractional, and a no-millis Z) and assert each is echoed
  // canonically. The canonical target reuses isoAt (the same producer normalisation).
  {
    const canon = isoAt(Date.parse("2026-06-09T10:00:00Z"));
    const shapes = [
      "2026-06-09T20:00:00+10:00", // offset form of 10:00:00Z
      "2026-06-09T10:00:00.000123Z", // sub-millisecond precision
      "2026-06-09T10:00:00Z", // no millis at all
    ];
    for (const raw of shapes) {
      const r = await stubFetch(stub, "POST", "/notify/resolve", { emission: { ...emission, at: raw } });
      const body = (await r.json()) as { emission: { at?: string } | null };
      ok(`resolve: non-canonical at (${raw}) -> echoed canonical millis-Z`, body.emission?.at === canon);
    }
    // An UNPARSEABLE `at` must NOT be stored verbatim; it falls back to the DO clock (a real canonical
    // RFC-3339 millis-Z string), never the garbage input.
    const rBad = await stubFetch(stub, "POST", "/notify/resolve", { emission: { ...emission, at: "not-a-real-date" } });
    const bodyBad = (await rBad.json()) as { emission: { at?: string } | null };
    const at = bodyBad.emission?.at ?? "";
    ok("resolve: unparseable at -> NOT echoed verbatim (clock fallback)", at !== "not-a-real-date");
    ok("resolve: unparseable at -> canonical RFC-3339 millis-Z fallback", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(at));
  }
  // A malformed emission -> resolve returns empty (no throw, no 500).
  {
    const r = await stubFetch(stub, "POST", "/notify/resolve", { emission: { event: "nope" } });
    ok("resolve: malformed emission -> 200 empty", r.status === 200);
    const body = (await r.json()) as { now: NotifyChannel[]; emission: unknown };
    ok("resolve: malformed emission -> no channels, null emission", body.now.length === 0 && body.emission === null);
  }
  // FOLD 1: the DO's parseEmission guard must ADMIT update-rollback-needed (a rejected/unknown event echoes a
  // null emission, like the malformed case above). This proves the cron's critical "rollback needed" alert is
  // not silently dropped by the authority-boundary guard. (Routing to a channel depends on a selecting rule;
  // admission is the guarantee under test here.)
  {
    const r = await stubFetch(stub, "POST", "/notify/resolve", { emission: { event: "update-rollback-needed", severity: "critical", downpipeId: null, downpipeName: "Engine update", detail: "rollback needed", at: "2026-06-09T00:00:00.000Z" } });
    const body = (await r.json()) as { emission: unknown };
    ok("resolve admits update-rollback-needed (not silently dropped)", body.emission !== null);
  }
}

// record + history: a delivery record appends one redaction-safe history entry newest-first; malformed
// records are skipped fail-open. 
async function testNotifyRecord(): Promise<void> {
  const { stub } = makeScheduler();
  const channelId = await seedResolveChannel(stub);
  const emission = RESOLVE_EMISSION;
  {
    const r = await stubFetch(stub, "POST", "/notify/record", { emission, records: [{ channelId, channelKind: "webhook", delivered: true }] });
    ok("record: returns 200", r.status === 200);
    ok("record: one entry recorded", (await r.json() as { recorded: number }).recorded === 1);
  }
  {
    const hist = (await (await stubFetch(stub, "GET", "/notify/history")).json()) as NotifyHistoryEntry[];
    ok("history: one entry", hist.length === 1);
    const h = hist[0]!;
    ok("history: event/severity recorded", h.event === "backup-failure" && h.severity === "critical");
    ok("history: channel id/kind recorded", h.channelId === channelId && h.channelKind === "webhook");
    ok("history: delivered recorded", h.delivered === true);
    ok("history: detail is the redaction-safe one-liner", h.detail === "Prod KV last run failed");
    ok("history: downpipeId recorded", h.downpipeId === "pipe-1");
  }
  {
    const r = await stubFetch(stub, "POST", "/notify/record", { emission, records: [{ channelId: "", channelKind: "webhook", delivered: true }, { channelId, channelKind: "bogus", delivered: true }] });
    ok("record: malformed records skipped", (await r.json() as { recorded: number }).recorded === 0);
  }
}

// ---- TC-N-17b: the once-dropped alerts actually route to a channel (notify wiring) ---------
// backup-volume-regression / source-detached / replication-degraded / run-at-risk-eviction are each
// emitted through routeNotification -> POST /notify/resolve -> parseEmission, so a gap in the DO's
// isNotifyEventLocal admit-guard makes resolve return ZERO channels: the backup is protected but the
// operator is NEVER notified (the alert is silently dropped). This drives the real DO end-to-end: (a) a
// broad "all" rule must route each event to a channel (parseEmission admits it -> >=1 channel resolved),
// and (b) a rule must be able to NAME backup-volume-regression + source-detached (the NOTIFY_EVENTS
// vocabulary half). Red before the wiring fix, green after.
async function testDroppedEventsRouteToChannel(): Promise<void> {
  const { stub } = makeScheduler();
  // The first channel mints a default-on rule for backup-failure + backup-stale only; add a broad "all"
  // rule so the once-dropped warnings have a selecting rule, isolating the parseEmission admit gap.
  const c = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" })).json()) as NotifyChannel;
  const broadRule = await callerFetch(stub, "operator", "POST", "/notify/rules", {
    scope: { kind: "global" },
    minSeverity: "warning",
    events: "all",
    channelIds: [c.id],
    enabled: true,
  });
  ok("wiring-route: broad 'all' rule created", broadRule.status === 200);

  const dropped: NotifyEvent[] = ["backup-volume-regression", "source-detached", "replication-degraded", "run-at-risk-eviction"];
  for (const event of dropped) {
    const emission = { event, severity: severityOf(event), downpipeId: "pipe-1", downpipeName: "Prod KV", detail: `${event} detail`, at: "2026-06-09T00:00:00.000Z" };
    const r = await stubFetch(stub, "POST", "/notify/resolve", { emission });
    ok(`wiring-route: /notify/resolve 200 for ${event}`, r.status === 200);
    const body = (await r.json()) as { now: NotifyChannel[]; emission: unknown };
    // A null emission is the silent-drop signature (parseEmission rejected the event at the boundary).
    ok(`wiring-route: ${event} admitted by parseEmission (not silently dropped)`, body.emission !== null);
    // ...and it must resolve to the selecting channel, i.e. the operator is actually notified.
    ok(`wiring-route: ${event} routes to >=1 channel`, body.now.length >= 1 && body.now.some((ch) => ch.id === c.id));
  }

  // The NOTIFY_EVENTS half: a rule must be able to NAME the two events that were missing from the
  // vocabulary (backup-volume-regression + source-detached), else the rule POST 400s "unknown event".
  const namedRule = await callerFetch(stub, "operator", "POST", "/notify/rules", {
    scope: { kind: "global" },
    minSeverity: "warning",
    events: ["backup-volume-regression", "source-detached"],
    channelIds: [c.id],
    enabled: true,
  });
  ok("wiring-route: a rule can NAME backup-volume-regression + source-detached", namedRule.status === 200);
}

// ---- TC-N-18: history ring cap behaviour ---------------------------------------------------
// Directly seed > cap entries via record and assert the ring rolls off to the cap, newest-first.

async function testHistoryRingCap(): Promise<void> {
  const { stub } = makeScheduler();
  const c = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" })).json()) as NotifyChannel;
  const emission = {
    event: "backup-failure" as NotifyEvent,
    severity: "critical" as Severity,
    downpipeId: "pipe-1",
    downpipeName: "Prod KV",
    detail: "Prod KV last run failed",
    at: "2026-06-09T00:00:00.000Z",
  };
  // Append 1005 entries one at a time (each call sends one record; the cap is 1000).
  for (let i = 0; i < 1005; i++) {
    await stubFetch(stub, "POST", "/notify/record", { emission: { ...emission, detail: `entry ${i}` }, records: [{ channelId: c.id, channelKind: "webhook", delivered: true }] });
  }
  const hist = (await (await stubFetch(stub, "GET", "/notify/history")).json()) as NotifyHistoryEntry[];
  ok("ring: capped at 1000", hist.length === 1000);
  // Newest-first: the first entry should be the LAST appended (entry 1004).
  ok("ring: newest-first ordering", hist[0]?.detail === "entry 1004");
  // The oldest retained should be entry 5 (0..4 rolled off).
  ok("ring: oldest entries rolled off", hist[hist.length - 1]?.detail === "entry 5");
}

// ---- TC-N-18b: history ring cap holds under platform paging -------------
// The platform caps a single storage.list() at a page limit; when that page limit is <= the ring
// cap, a bare list({prefix}) used to enforce the cap can NEVER report MORE keys than the cap, so
// rollover would never trigger and history would grow UNBOUNDED. This double caps list() exactly as
// the platform does (limit-bounded pages honouring startAfter), so the OLD bare-list rollover left
// the keyspace growing past the cap; the direct stale-key delete keeps it pruned regardless.
class PagedNotifyStorage {
  private map = new Map<string, unknown>();
  private readonly pageLimit: number;
  constructor(pageLimit: number) {
    this.pageLimit = pageLimit;
  }
  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  // list HONOURS limit + startAfter and caps a page at pageLimit (default to the platform cap when
  // the caller passes no limit), exactly as the real DO storage does. A bare list() therefore returns
  // at MOST pageLimit keys, which is the condition that defeated the old length-compare rollover.
  async list<T>(opts?: { prefix?: string; limit?: number; startAfter?: string }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    const cap = Math.min(opts?.limit ?? this.pageLimit, this.pageLimit);
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > (opts.startAfter as string));
    keys = keys.slice(0, cap);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    return out;
  }
  async setAlarm(_t: number): Promise<void> {}
  // countByPrefix is a test-only probe of the true on-disk key count (not page-bounded), so the
  // assertion can see whether the ring actually pruned rather than what a single page reports.
  countByPrefix(prefix: string): number {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix)).length;
  }
}

async function testHistoryRingCapUnderPaging(): Promise<void> {
  // Page limit EQUAL to the ring cap is the exact failure condition: a bare list() can report at most
  // 1000 keys, so the old `keys.length > 1000` compare was never true and nothing was ever pruned.
  const storage = new PagedNotifyStorage(1000);
  const state = { storage } as unknown as DurableObjectState;
  const stub = new SchedulerDO(state);
  const c = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" })).json()) as NotifyChannel;
  const emission = {
    event: "backup-failure" as NotifyEvent,
    severity: "critical" as Severity,
    downpipeId: "pipe-1",
    downpipeName: "Prod KV",
    detail: "Prod KV last run failed",
    at: "2026-06-09T00:00:00.000Z",
  };
  for (let i = 0; i < 1005; i++) {
    await stubFetch(stub, "POST", "/notify/record", { emission: { ...emission, detail: `entry ${i}` }, records: [{ channelId: c.id, channelKind: "webhook", delivered: true }] });
  }
  // The TRUE on-disk count of history keys must be exactly the cap. The old bare-list rollover left it
  // at 1005 (unbounded growth); the direct stale-key delete holds it at 1000.
  const onDisk = storage.countByPrefix("notify-history:");
  ok("ring-paging: on-disk history pruned to the cap (not unbounded)", onDisk === 1000);
  // The very oldest entries are the ones dropped: seq 1..5 (entries 0..4) are gone, seq 6 (entry 5)
  // is the oldest retained. The history keys are notify-history:<20-padded seq>, seq starting at 1.
  const histKey = (seq: number): string => `notify-history:${String(seq).padStart(20, "0")}`;
  ok("ring-paging: oldest seq (1) deleted", (await storage.get(histKey(1))) === undefined);
  ok("ring-paging: seq 5 (entry 4) deleted", (await storage.get(histKey(5))) === undefined);
  ok("ring-paging: seq 6 (entry 5) retained as oldest", (await storage.get<NotifyHistoryEntry>(histKey(6)))?.detail === "entry 5");
  ok("ring-paging: newest seq (1005) retained", (await storage.get<NotifyHistoryEntry>(histKey(1005)))?.detail === "entry 1004");
}

// ---- TC-N-15d: GET /notify/channels REDACTS a jsm/servicenow sealed apiKey (presence-only) --
// A jsm/servicenow channel carries a sealed bearer/basic credential (apiKey). The operator-facing list read
// must never echo its value (even on the CONFIG_WRAP_KEY-absent plaintext floor this DO test harness uses),
// only THAT one is configured. The single-channel INTERNAL read (GET /notify/channel, the router's test-send
// delivery path) is deliberately NOT redacted: it needs the real credential to authenticate the send.
async function testJsmChannelListRedaction(): Promise<void> {
  const { stub } = makeScheduler();
  const created = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-secret-DO-NOT-ECHO" })).json()) as NotifyChannel;
  ok("redact-route: jsm channel created via the DO route", created.kind === "jsm" && created.id.length > 0);
  const listText = await (await stubFetch(stub, "GET", "/notify/channels")).text();
  ok("redact-route: GET /notify/channels never echoes the apiKey value", !listText.includes("genie-secret-DO-NOT-ECHO"));
  const channels = JSON.parse(listText) as Array<Record<string, unknown>>;
  const jsmInList = channels.find((c) => c.kind === "jsm")!;
  ok("redact-route: the listed jsm channel carries NO apiKey field", !("apiKey" in jsmInList));
  ok("redact-route: it reports apiKeyPresent:true (presence-only)", jsmInList.apiKeyPresent === true);
  ok("redact-route: the non-secret url survives the projection", jsmInList.url === "https://api.opsgenie.com/v2/alerts");
  // The INTERNAL single-channel read keeps the apiKey (the router's test-send delivery needs it).
  const single = (await (await stubFetch(stub, "GET", `/notify/channel?id=${encodeURIComponent(created.id)}`)).json()) as { channel: NotifyChannel | null };
  ok("redact-route: the INTERNAL single-channel read is NOT redacted (delivery needs the credential)", single.channel?.apiKey === "genie-secret-DO-NOT-ECHO");
}

// runCrud runs the CRUD/migration/record/ring groups in their original order.
export async function runCrud(): Promise<void> {
  console.log("notify channels/rules CRUD + notify.config re-check + default-on rule");
  await testNotifyCrudAccessControl();
  await testNotifyCrudChannels();
  await testNotifyCrudRules();

  console.log("GET /notify/channels redacts a jsm/servicenow sealed apiKey (presence-only)");
  await testJsmChannelListRedaction();

  console.log("notify resolve/record two-phase + history");
  await testNotifyResolve();
  await testNotifyRecord();

  console.log("once-dropped alerts route to a channel (notify wiring)");
  await testDroppedEventsRouteToChannel();

  console.log("history ring cap");
  await testHistoryRingCap();

  console.log("history ring cap holds under platform paging");
  await testHistoryRingCapUnderPaging();
}

// This file is BOTH a group imported by validate-notify.ts (which calls runCrud alongside the other
// notify groups and reports one verdict for all of them) AND its own step in the validate chain, as
// `node test/validate-notify-crud.ts` and as the validate:notify-crud script. Until now the standalone
// step only DEFINED runCrud and never called it, so it produced no output, ran none of the TC-N-15..18b
// vectors and exited 0. It was a validate step that could not fail for any reason. Running it here, with
// a verdict of its own, is what makes the step mean what its name says.
if (isEntryPoint(import.meta.url)) {
  await runCrud();
  const failures = getFailures();
  console.log(failures === 0 ? "\nNOTIFY CRUD VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}
