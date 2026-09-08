// Support-pack section gatherers: the notify / alerting domain (delivery history, the
// channel + rule inventory, the notify-pipeline drop counters and pending-digest lifecycle,
// and the per-downpipe alert-cooldown state). Moved verbatim out of support.ts, which
// assembles the bundle from these gatherers; each keeps its original redaction contract
// (see the per-function comments). Behaviour is unchanged.

import { ACK_OUTCOMES, DELIVERY_FAIL_CODES, SINK_SCREEN_VERDICTS, sanitiseEmailPlatformCode } from "../notify.ts";
import { doURL } from "../do-url.ts";
import { clampInt, clampTs } from "./support-shared.ts";

// InertReason is the CLOSED vocabulary for WHY a notification rule can never deliver (G113). Naming it as a
// union (rather than an index signature) keeps the byReason tally statically total.
type InertReason = "no-channel" | "dangling-channel" | "all-channels-disabled";

// NotifyHistoryProjection is what the notify gatherer now returns: the RECENCY window the pack has always
// carried (`entries`), plus the two additions the "alerts stopped reaching PagerDuty three weeks ago" ticket
// needs (G023 + G342), derived from the SAME single fetch of the 1000-entry DO ring:
//   failures : failure-BIASED rows -- the 20 most recent delivered:false rows, PLUS the smart-retained
//              boundary row (the OLDEST undelivered row per channelKind still in the ring, i.e. the ONSET),
//              which a pure recency window structurally cannot reach. By ticket time the recency window is all
//              recent successes and the failing window was unrecoverable remotely.
//   byChannelKind : a rollup over the WHOLE ring per channel kind {failCount, lastFailAt, lastDeliveredAt},
//              so "this kind has not delivered anything since the 3rd" is answerable even when every row of
//              the evidence has rolled out of both windows.
// Same redaction contract as the entries themselves: closed enums, counts and clamped timestamps; a channel's
// URL / address / detail never leaves the DO's redacted view in the first place.
export interface NotifyHistoryProjection {
  entries: unknown[];
  failures: unknown[];
  byChannelKind: Record<string, { failCount: number; lastFailAt?: string; lastDeliveredAt?: string }>;
}

// fetchNotifyHistory shapes the notification delivery outcomes (channel kinds and delivered booleans; a
// channel's URL or key never leaves the DO redacted views in the first place). A failing fetch yields an
// empty list: honest absence beats a fabricated value, and the bundle simply lacks notify history.
export async function fetchNotifyHistory(scheduler: DurableObjectStub): Promise<NotifyHistoryProjection> {
  {
    const nResp = await scheduler.fetch(doURL("/notify/history"), { method: "GET" });
    const raw = (await nResp.json()) as unknown;
    // The DO returns a BARE ARRAY of FLAT NotifyHistoryEntry { seq, ts, event, severity, downpipeId,
    // channelId, channelKind, delivered, detail }, not a wrapped { entries: [{ at, deliveries: [...] }] }.
    // Accept the array (or a legacy { entries } wrapper) and carry the redaction-safe delivery fields the
    // diagnosis needs: the event/severity/channelKind/delivered tell whether an alert actually went out.
    const arr = (Array.isArray(raw)
      ? raw
      : Array.isArray((raw as { entries?: unknown[] } | null)?.entries)
        ? (raw as { entries: unknown[] }).entries
        : []) as Array<{ ts?: string; event?: string; severity?: string; downpipeId?: string | null; channelKind?: string; delivered?: boolean; deliveryCode?: unknown; platformCode?: unknown; recovered?: unknown; sinkScreen?: unknown; unconfirmed?: unknown; ackOutcome?: unknown; recipientIndex?: unknown; test?: unknown }>;
    // Each field is CONDITIONALLY spread (omitted when absent), canonicalJSON rejects an explicit `undefined`
    // value, so a flat notify row missing any optional field (e.g. no severity, or an account-scoped event with
    // no downpipeId) would otherwise throw and fail the WHOLE bundle build. Omit, never emit undefined.
    // deliveryCode is the CLOSED per-channel delivery-failure WHY (validated against the allow-list;
    // anything else dropped), platformCode the SHAPE-GATED email platform code, and recovered marks a
    // PagerDuty resolve emission (its dedup-key correlation with the earlier trigger). sinkScreen is the
    // CLOSED send-time sink-screen verdict (NOTIF: dns-rebinding-gap) -- a `hostname` verdict is the residual
    // rebind-exposed class the literal screen cannot see through. All redaction-safe (closed enums only).
    // The ring is NEWEST-FIRST (scheduler-do-notify.ts listNotifyHistory sorts by descending seq).
    const project = (e: (typeof arr)[number]): Record<string, unknown> => ({
      ...(e.ts !== undefined ? { at: e.ts } : {}),
      ...(e.event !== undefined ? { event: e.event } : {}),
      ...(e.severity !== undefined ? { severity: e.severity } : {}),
      ...(e.downpipeId != null ? { downpipeId: e.downpipeId } : {}),
      ...(e.channelKind !== undefined ? { channelKind: e.channelKind } : {}),
      ...(e.delivered !== undefined ? { delivered: e.delivered } : {}),
      // G246 (R7): a MANUAL TEST press, not a routed engine event. The engine has flagged the row test:true since
      // the test-send was first persisted and the pack dropped the flag -- so a failed Test press read, in the
      // pack, exactly like a real alert that never reached the customer. Now that the test row also carries a
      // deliveryCode (below), saying WHICH rows are tests is what stops "my Slack test keeps failing" being
      // diagnosed as "your production alerting is down". A boolean the engine set; never a customer value.
      ...(e.test === true ? { test: true } : {}),
      ...(typeof e.deliveryCode === "string" && DELIVERY_FAIL_CODES.has(e.deliveryCode) ? { deliveryCode: e.deliveryCode } : {}),
      ...(sanitiseEmailPlatformCode(e.platformCode) !== undefined ? { platformCode: sanitiseEmailPlatformCode(e.platformCode) } : {}),
      ...(e.recovered === true ? { recovered: true } : {}),
      ...(typeof e.sinkScreen === "string" && SINK_SCREEN_VERDICTS.has(e.sinkScreen) ? { sinkScreen: e.sinkScreen } : {}),
      // unconfirmed + ackOutcome (G033: async-create-unconfirmed): a JSM/ServiceNow create is ACCEPTED
      // asynchronously (202), so `delivered:true` means "the sink took it", NOT "the page exists". The engine
      // already recorded `unconfirmed` and the pack silently dropped it. ackOutcome is the CLOSED verdict of the
      // follow-up status poll: `async-create-failed` is a REAL non-delivery the customer was never told about
      // (the sink positively reported the create failed), `confirmation-unavailable` is only a missing
      // confirmation. Gated on the closed vocabulary (an out-of-vocab value is dropped, defence in depth).
      ...(e.unconfirmed === true ? { unconfirmed: true } : {}),
      ...(typeof e.ackOutcome === "string" && ACK_OUTCOMES.has(e.ackOutcome) ? { ackOutcome: e.ackOutcome } : {}),
      // recipientIndex (G020): WHICH entry in the channel's recipient list was rejected. An e-mail channel
      // sends to all its recipients in ONE call, so a single typo'd address kills delivery to EVERY recipient
      // of that channel -- and the pack could not name the bad entry, only report that the channel failed.
      // The INDEX, never the address: the customer holds the list and can read the position off it, and the
      // address itself is no-custody and must never leave. Clamped to a bounded non-negative integer.
      ...(typeof e.recipientIndex === "number" && Number.isFinite(e.recipientIndex) && e.recipientIndex >= 0
        ? { recipientIndex: Math.min(1000, Math.floor(e.recipientIndex)) }
        : {}),
    });
    const entries = arr.slice(0, 20).map(project);
    // FAILURE-BIASED window (G023): the 20 most recent undelivered rows, wherever they are in the ring.
    const failureIdx = new Set<number>();
    for (let i = 0, n = 0; i < arr.length && n < 20; i++) {
      if (arr[i]?.delivered === false) { failureIdx.add(i); n++; }
    }
    // SMART-RETAIN THE BOUNDARY ROW (G342): the OLDEST undelivered row per channelKind (the ring is newest-
    // first, so that is the LAST match), even when it predates the recency window. That row is the ONSET -- the
    // first delivery that failed, and the one whose deliveryCode / sinkScreen / platformCode says what broke.
    const oldestSeen = new Set<string>();
    for (let i = arr.length - 1; i >= 0; i--) {
      const e = arr[i];
      if (e === undefined || e.delivered !== false) continue;
      const kind = typeof e.channelKind === "string" ? e.channelKind : "";
      if (oldestSeen.has(kind)) continue;
      oldestSeen.add(kind);
      failureIdx.add(i);
    }
    const failures = [...failureIdx].sort((a, b) => a - b).map((i) => project(arr[i]!));
    // PER-KIND ROLLUP over the WHOLE ring (G023): failCount + the last failure and last SUCCESS per channel
    // kind. A kind whose lastDeliveredAt is far older than its lastFailAt has been dark since that instant --
    // the answer to "alerts stopped three weeks ago" even after every row of it has rolled out of both windows.
    const byChannelKind: Record<string, { failCount: number; lastFailAt?: string; lastDeliveredAt?: string }> = {};
    for (const e of arr) {
      if (typeof e.channelKind !== "string" || e.channelKind === "") continue;
      byChannelKind[e.channelKind] ??= { failCount: 0 };
      const row = byChannelKind[e.channelKind]!;
      // Newest-first: the FIRST row of each outcome we meet for a kind is its most recent one.
      if (e.delivered === false) {
        row.failCount++;
        if (row.lastFailAt === undefined && typeof e.ts === "string") row.lastFailAt = e.ts.slice(0, 40);
      } else if (e.delivered === true && row.lastDeliveredAt === undefined && typeof e.ts === "string") {
        row.lastDeliveredAt = e.ts.slice(0, 40);
      }
    }
    return { entries, failures, byChannelKind };
  }
}

// fetchNotifyConfig pulls a REDACTION-SAFE inventory of the configured channels + rules so a "an alert
// never reached me" can be diagnosed: WHETHER any channel is configured at all (no channels => no alert can
// be delivered), the channel KINDS (email/webhook/..., never the URL/address/secret), and the routing
// rules (event/severity/scope predicates, what would even fire). Counts + enums + predicates only; a
// failing fetch yields an empty inventory (honest absence).
export async function fetchNotifyConfig(scheduler: DurableObjectStub): Promise<{ channelCount: number; channelKinds: string[]; disabledChannelCount: number; ruleCount: number; danglingChannelRefs: number; rulesInert?: { count: number; byReason: Record<string, number> }; rules: Array<{ events?: unknown; minSeverity?: string; scope?: string }> }> {
  {
    const [chResp, rlResp] = await Promise.all([
      scheduler.fetch(doURL("/notify/channels"), { method: "GET" }),
      scheduler.fetch(doURL("/notify/rules"), { method: "GET" }),
    ]);
    const channels = (await chResp.json().catch(() => [])) as Array<{ id?: string; kind?: string; enabled?: boolean }>;
    const rules = (await rlResp.json().catch(() => [])) as Array<{ events?: unknown; minSeverity?: string; scope?: { kind?: string }; channelIds?: unknown }>;
    const chArr = Array.isArray(channels) ? channels : [];
    const rlArr = Array.isArray(rules) ? rules : [];
    const channelIdSet = new Set(chArr.map((c) => c.id).filter((id): id is string => typeof id === "string"));
    // enabledById: a channel is deliverable only when it EXISTS and is not disabled.
    const enabledById = new Map<string, boolean>(chArr.filter((c): c is { id: string; enabled?: boolean } => typeof c.id === "string").map((c) => [c.id, c.enabled !== false]));
    // danglingChannelRefs (NOTIF: rule-references-missing-or-deleted-channel): count rule->channel references
    // that name a channel id NOT in the channel set (a deleted channel silently drops that rule's delivery).
    // The channel id is a server-minted ULID (not customer data); we count the dangling refs, never echo ids.
    let danglingChannelRefs = 0;
    // rulesInert (G113: inert-notification-rule): a rule that can NEVER deliver -- it has no channel at all,
    // every channel it names is deleted, or every channel it names is disabled. Such a rule silently fires
    // into the void, so "I have an alert rule but never get paged" is otherwise undiagnosable. We derive it
    // from the channels + rules already fetched (no new read) and count by a CLOSED reason (never echo a
    // rule/channel id). The two data-derivable reasons only; severity-unsatisfiable and scope-downpipe-missing
    // need event/downpipe data not fetched here and are a later pass.
    // Keyed on the CLOSED inert-reason vocabulary (an explicit record type, not an index signature, so every
    // read is statically known-present -- an index signature under noUncheckedIndexedAccess types each read as
    // possibly-undefined and the ++ / sum below would not typecheck).
    const byReason: Record<InertReason, number> = { "no-channel": 0, "dangling-channel": 0, "all-channels-disabled": 0 };
    for (const r of rlArr) {
      const ids = (Array.isArray(r.channelIds) ? r.channelIds : []).filter((id): id is string => typeof id === "string");
      for (const id of ids) if (!channelIdSet.has(id)) danglingChannelRefs++;
      if (ids.length === 0) { byReason["no-channel"]++; continue; }
      const live = ids.filter((id) => channelIdSet.has(id));
      if (live.length === 0) { byReason["dangling-channel"]++; continue; }
      if (live.every((id) => enabledById.get(id) === false)) byReason["all-channels-disabled"]++;
    }
    const inertCount = byReason["no-channel"] + byReason["dangling-channel"] + byReason["all-channels-disabled"];
    return {
      channelCount: chArr.length,
      channelKinds: [...new Set(chArr.map((c) => c.kind).filter((k): k is string => typeof k === "string"))],
      disabledChannelCount: chArr.filter((c) => c.enabled === false).length,
      ruleCount: rlArr.length,
      danglingChannelRefs,
      ...(inertCount > 0 ? { rulesInert: { count: inertCount, byReason: Object.fromEntries(Object.entries(byReason).filter(([, v]) => v > 0)) } } : {}),
      // `events` on a rule is NotifyEvent[] | "all", NORMALISE the "all" sentinel to a single-element array so
      // the bundle conforms to its declared array contract (a bare string would make the consumer's allowlist
      // reject the whole bundle). minSeverity + scope.kind are closed enums; a channel URL/address never appears.
      rules: rlArr.slice(0, 20).map((r) => ({ ...(r.events !== undefined ? { events: Array.isArray(r.events) ? r.events : [r.events] } : {}), ...(r.minSeverity ? { minSeverity: r.minSeverity } : {}), ...(r.scope?.kind ? { scope: r.scope.kind } : {}) })),
    };
  }
}

// fetchNotifyHealth pulls the notify-pipeline DROP COUNTERS (NOTIF needs-new-logging: do-fetch-throws-
// pass-skipped + recordnotify-skips-malformed-rows + freetext-detail-overlong-rejected + feedback-fail) so
// "alerts silently stopped" is diagnosable: whole passes the Worker skipped (a DO fetch threw), per-channel
// records dropped as malformed, emissions rejected by the input validator, and delivery-feedback failures.
// Ints + a clamped timestamp only. OMITTED entirely when all counters are zero (nothing to report).
export async function fetchNotifyHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const [hResp, dResp] = await Promise.all([
      scheduler.fetch(doURL("/notify/health"), { method: "GET" }),
      scheduler.fetch(doURL("/notify/digest-pending"), { method: "GET" }),
    ]);
    const j = (await hResp.json()) as { passSkips?: unknown; recordSkips?: unknown; parseRejects?: unknown; feedbackFails?: unknown; lastAt?: unknown };
    const d = (await dResp.json().catch(() => ({}))) as { count?: unknown; oldestAt?: unknown; byPeriod?: Record<string, { count?: unknown; oldestAt?: unknown; dueAt?: unknown }> };
    const out: Record<string, unknown> = {
      passSkips: clampInt(j.passSkips) ?? 0,
      recordSkips: clampInt(j.recordSkips) ?? 0,
      parseRejects: clampInt(j.parseRejects) ?? 0,
      feedbackFails: clampInt(j.feedbackFails) ?? 0,
    };
    const drops = (out.passSkips as number) + (out.recordSkips as number) + (out.parseRejects as number) + (out.feedbackFails as number);
    // pendingDigest (NOTIF: digest-skew-or-bad-at-never-flushes + digest-defers-success-up-to-a-week): the
    // deferred success-stream queue depth + the oldest deferred entry + the PER-CADENCE lifecycle (byPeriod:
    // depth + oldest + the computed dueAt window per daily/weekly), so a digest that never flushes shows as a
    // growing queue with an ever-older oldest AND names WHICH cadence is stuck and WHEN its batch was due.
    // Included only when the queue is non-empty. Counts + clamped timestamps only.
    const pendingCount = clampInt(d.count) ?? 0;
    // Omit the whole block only when there is nothing to report (no drops AND no pending digest).
    if (drops === 0 && pendingCount === 0) return {};
    if (clampTs(j.lastAt) !== undefined) out.lastAt = clampTs(j.lastAt);
    if (pendingCount > 0) {
      // Project the per-period window state, only for the two KNOWN cadences (defence in depth: an unexpected
      // period key is dropped), each carrying its depth + oldest deferred instant + the computed due-at.
      const byPeriod: Record<string, { count: number; oldestAt?: string; dueAt?: string }> = {};
      for (const period of ["daily", "weekly"] as const) {
        const p = d.byPeriod?.[period];
        if (p === undefined || p === null) continue;
        const c = clampInt(p.count) ?? 0;
        if (c <= 0) continue;
        const oldestAt = clampTs(p.oldestAt);
        const dueAt = clampTs(p.dueAt);
        byPeriod[period] = { count: c, ...(oldestAt !== undefined ? { oldestAt } : {}), ...(dueAt !== undefined ? { dueAt } : {}) };
      }
      out.pendingDigest = {
        count: pendingCount,
        ...(clampTs(d.oldestAt) !== undefined ? { oldestAt: clampTs(d.oldestAt) } : {}),
        ...(Object.keys(byPeriod).length > 0 ? { byPeriod } : {}),
      };
    }
    return out;
  }
}

// fetchAlertCooldowns pulls the per-downpipe ALERT-COOLDOWN state (NOTIF: cooldown-suppresses-renudge-1h) into
// the pack: which downpipes are currently within a re-nudge cooldown and SINCE WHEN, for BOTH the staleness/
// failure stream and the 3-2-1 replication stream, so "why didn't I get re-alerted about a still-broken pipe"
// is answerable (it alerted at `at` and is suppressed until at + cooldownMs). It projects ONLY closed values:
// the customer's own downpipe id, a closed state enum, and an epoch ms; never a secret, value, or detail.
// A fetch/parse fault PROPAGATES to section() (recorded "error", not "empty"); OMITTED (empty) only when nothing is in cooldown. Rows bounded (defence in depth against an oversized DO).
const ALERT_STATE_CODES: ReadonlySet<string> = new Set(["failed", "stale"]);
const REPL_ALERT_STATE_CODES: ReadonlySet<string> = new Set(["replication-degraded", "run-at-risk-eviction"]);
export async function fetchAlertCooldowns(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/notify/cooldowns"), { method: "GET" });
    const j = (await r.json()) as { cooldownMs?: unknown; alert?: unknown; replication?: unknown };
    const projectRows = (rows: unknown, codes: ReadonlySet<string>) =>
      (Array.isArray(rows) ? rows : []).slice(0, 200).map((row) => {
        const rr = (typeof row === "object" && row !== null ? row : {}) as { downpipeId?: unknown; state?: unknown; at?: unknown };
        if (typeof rr.downpipeId !== "string" || typeof rr.state !== "string" || !codes.has(rr.state)) return null;
        return { downpipeId: rr.downpipeId.slice(0, 128), state: rr.state, ...(clampInt(rr.at, Number.MAX_SAFE_INTEGER) !== undefined ? { at: clampInt(rr.at, Number.MAX_SAFE_INTEGER) } : {}) };
      }).filter((x): x is NonNullable<typeof x> => x !== null);
    const alert = projectRows(j.alert, ALERT_STATE_CODES);
    const replication = projectRows(j.replication, REPL_ALERT_STATE_CODES);
    if (alert.length === 0 && replication.length === 0) return {};
    return { cooldownMs: clampInt(j.cooldownMs, Number.MAX_SAFE_INTEGER) ?? 0, alert, replication };
  }
}
