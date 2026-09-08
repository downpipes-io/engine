// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the Notifications subsystem (contract
// section 2: channels, rules, history, routing/digest) extracted from the SchedulerDO god module into a
// mixin factory. NotifyMixin layers these methods over a base whose `this` is SchedulerDOSurface, so the
// methods keep calling `this.callerHolds` / `this.state` exactly as before; the dispatch and `this`
// binding are byte-identical to the single class. No storage key, no auth gate, no behaviour changed:
// the requireNotifyConfig re-check still runs on the same writes in the same order. The channels/rules/
// history live in THIS DO under the notify-*: prefixes; the DO does NO network I/O (the Worker delivers).

import { ADMIN_COUNTERS_KEY, type AdminCounters, applyAdminCounters } from "../admin/diag-records.ts";
import type { AuthMethod, Capability, Role } from "../admin/identity.ts";
import { validateRecipients } from "../email.ts";
import { ACK_OUTCOMES, type AckOutcome, type ChannelKind, DELIVERY_FAIL_CODES, type DeliveryFailCode, DIGEST_WINDOW_MS, type DigestBatch, type DigestPeriod, groupDigestDue, NOTIFY_CHANNEL_PREFIX, NOTIFY_HISTORY_CAP, NOTIFY_HISTORY_PREFIX, NOTIFY_RULE_PREFIX, type NotifyChannel, type NotifyEmission, type NotifyHistoryEntry, type NotifyRule, type PendingDigestEntry, resolveDelivery, ruleSelects, SINK_SCREEN_VERDICTS, type SinkScreenVerdict, sanitiseEmailPlatformCode, validateChannel, validateRule } from "../notify.ts";
import { drainNotifyDigestFaults } from "../notify-digest.ts";
import { DOWNPIPE_ID_PATTERN, DOWNPIPE_NAME_MAX_LEN } from "./config-validate.ts";
import { recordAdminRefusal, recordNotifyDrop, recordVocabDrop, webhookRejectReason } from "./sched-fault-ledger.ts";
import { AuthError, NOTIFY_DIGEST_PREFIX, NOTIFY_DIGEST_SEQ_KEY, NOTIFY_HEALTH_KEY, NOTIFY_HISTORY_SEQ_KEY, type NotifyHealth, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { canonMillisISO, isChannelKindLocal, isNotifyEventLocal, isSeverityLocal, newULID, nowMillisISO, padSeqLocal, validateFreeText } from "./scheduler-helpers.ts";

export function NotifyMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Notifications (contract section 2): channels, rules, history, routing ---------------------
    // The channels, rules and history live in THIS DO (the single storage authority) under the
    // notify-channel:/notify-rule:/notify-history: prefixes. Writes are gated by the router on
    // notify.config AND re-checked here from the forwarded caller (requireNotifyConfig, defence in
    // depth, the same pattern as requireCapability). The routing layer (resolveDelivery) is the pure
    // function in notify.ts; the DO supplies the stored rules+channels and records history. The DO
    // does NO network I/O (the same separation as reconcileAlerts and the seal): the Worker delivers
    // (it holds env for the send_email binding and the outbound POST) and posts the outcomes back.

    // requireNotifyConfig is the DO-side authority re-check for a notify write: the forwarded caller
    // must hold the notify.config capability. The token-fallback Owner holds it (owner has every cap),
    // so the break-glass passes. An absent/malformed caller, or a role without the capability, fails
    // closed by THROWING so the DO's fetch() catch maps it to a 400 (the router returns the first-class
    // 403 before forwarding; reaching this throw means the router gate was bypassed). It uses callerHolds
    // (the resolved capability SET when one is supplied, else can(role, cap) over ROLE_CAPABILITIES), the
    // same precedence callerCan uses on the router side, so a CUSTOM-ROLE caller that legitimately holds
    // notify.config (its set is forwarded by the gated propose/replay) is honoured rather than refused on
    // its "viewer" built-in floor; the two cannot disagree.
    requireNotifyConfig(caller: { role: Role; capabilities?: ReadonlySet<Capability> } | null): void {
      if (!this.callerHolds(caller, "notify.config")) throw new AuthError("forbidden: notify.config capability required");
    }

    // listNotifyChannelsRaw reads the whole channel set once (small: configured destinations, not runs).
    async listNotifyChannelsRaw(): Promise<NotifyChannel[]> {
      const map = await this.state.storage.list<NotifyChannel>({ prefix: NOTIFY_CHANNEL_PREFIX });
      return [...map.values()];
    }

    // listNotifyRulesRaw reads the whole rule set once (small).
    async listNotifyRulesRaw(): Promise<NotifyRule[]> {
      const map = await this.state.storage.list<NotifyRule>({ prefix: NOTIFY_RULE_PREFIX });
      return [...map.values()];
    }

    // listNotifyChannels returns every configured channel.
    async listNotifyChannels(): Promise<NotifyChannel[]> {
      return this.listNotifyChannelsRaw();
    }

    // getNotifyChannel returns one channel by id (or null), for the router's test-send.
    async getNotifyChannel(id: string | null): Promise<{ channel: NotifyChannel | null }> {
      if (id === null || id.length === 0) return { channel: null };
      const ch = (await this.state.storage.get<NotifyChannel>(`${NOTIFY_CHANNEL_PREFIX}${id}`)) ?? null;
      return { channel: ch };
    }

    // recordTestSend appends a manual test-send outcome to the history ring (the router's POST
    // /notify/test records its result here), flagged test:true so the console can badge it and no
    // reader mistakes it for a routed engine event, giving a durable trace that the channel was verified.
    // notify.config re-checked (the router gates too; defence in depth). An unknown channel degrades to
    // { ok:false } rather than a throw: the test itself has already reported delivery, and history is
    // best-effort for a manual test.
    async recordTestSend(
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
      body: { channelId?: unknown; delivered?: unknown; detail?: unknown; code?: unknown; platformCode?: unknown },
    ): Promise<{ ok: boolean; reason?: string }> {
      this.requireNotifyConfig(caller);
      const channelId = typeof body.channelId === "string" ? body.channelId : "";
      const { channel } = await this.getNotifyChannel(channelId);
      if (channel === null) return { ok: false, reason: "unknown channel" };
      const detailRaw = typeof body.detail === "string" && body.detail !== "" ? body.detail : "channel test notification";
      const emission: NotifyEmission = {
        event: "backup-success",
        severity: "info",
        downpipeId: null,
        downpipeName: null,
        detail: detailRaw.slice(0, 200),
        at: nowMillisISO(),
      };
      // G246 (R7): the WHY, on the one durable artefact a Test press leaves. The row carried a bare
      // delivered:false, so "my Slack test keeps failing" was, in the pack, a failure with no cause -- while the
      // very same fields (deliveryCode, platformCode) had ridden every REAL failed delivery on this same ring
      // since G236/G248. Re-gated here against the closed sets exactly as recordNotifyDelivery does (the DO is
      // the second redaction boundary), and carried ONLY on a failed test: a delivered test has nothing to
      // explain. recordVocabDrop counts a code this build does not hold, so a version skew is visible rather
      // than silently erasing the reason.
      const delivered = body.delivered === true;
      const code = !delivered && typeof body.code === "string" && DELIVERY_FAIL_CODES.has(body.code) ? (body.code as DeliveryFailCode) : undefined;
      if (!delivered && typeof body.code === "string" && code === undefined) await recordVocabDrop(this.state.storage, "delivery-code");
      const platformCode = !delivered ? sanitiseEmailPlatformCode(body.platformCode) : undefined;
      await this.appendNotifyHistory(emission, channel.id, channel.kind, delivered, {
        test: true,
        ...(code !== undefined ? { code } : {}),
        ...(platformCode !== undefined ? { platformCode } : {}),
      });
      return { ok: true };
    }

    // addNotifyChannel validates and upserts a channel (contract section 2.4). notify.config re-checked.
    // The shape is validated by the shared validateChannel (exactly one transport field per kind,
    // https/no-userinfo/not-workers.dev urls, custom-domain email addresses). UPSERT BY ID: an EDIT
    // carries the existing channel's id; when that id names a channel that already EXISTS we overwrite it
    // in place (preserving its original createdAt; the SUBMITTED enabled is applied so an enable/disable
    // toggle takes effect, while an omitted/non-boolean value keeps the prior enabled state), so an edit
    // UPDATES instead of inserting a duplicate. An absent id, or an id that names no existing channel,
    // mints a fresh ULID
    // (create) - the server still owns the id space, so a client cannot conjure a chosen id. DEFAULT ON
    // FIRST SETUP: when this is the FIRST channel and NO rule exists yet, a global rule selecting
    // backup-failure (critical) and backup-stale (warning) is created so failure and stale alerts are on
    // by default; success stays off (digest). It cannot fire on an edit, since an existing channel means
    // existingChannels is non-empty.
    async addNotifyChannel(
      raw: unknown,
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<NotifyChannel> {
      this.requireNotifyConfig(caller);
      const v = validateChannel(raw, validateRecipients);
      if (!v.ok) {
        // G235/G251: record the CLOSED reject code before re-throwing. The operator's 400 and its sentence are
        // byte-unchanged (nothing is oracled back to the caller); only the engine now keeps a durable count, so
        // a customer stuck in a save-validation loop -- pasting an http:// URL, or a private sink with no
        // internal-sink opt-in -- is finally diagnosable from the pack rather than invisible.
        if (v.code !== undefined) await recordAdminRefusal(this.state.storage, "notify-channel", webhookRejectReason(v.code));
        throw new Error(v.reason);
      }
      const existingChannels = await this.listNotifyChannelsRaw();
      const existingRules = await this.listNotifyRulesRaw();
      const now = Date.now();
      const wantId = typeof (raw as { id?: unknown }).id === "string" ? (raw as { id: string }).id : null;
      const prior = wantId !== null ? existingChannels.find((c) => c.id === wantId) : undefined;
      const id = prior ? prior.id : newULID(now);
      // KEEP-SECRET (jsm/servicenow apiKey) is TIED TO THE CHANNEL IDENTITY. validateChannel allows an
      // absent/empty apiKey through (not a shape error), so an edit that omits it means "keep the existing
      // sealed credential" -- but ONLY when the delivery DESTINATION is unchanged (same kind and same url).
      // If an edit REPOINTS the channel (a new url or kind) with the apiKey omitted, the prior credential is
      // NOT carried over: a fresh apiKey is required. Without this an attacker holding notify.config
      // (operator/approver, not owner-only) could swap the url to a host they control while silently keeping
      // the real sealed token, then a test-send would exfiltrate the live credential to that host. Only the
      // destination gates the keep: a username change alone (servicenow) keeps the password, per the
      // resupply model, because it does not redirect where the secret is sent. The DO never wraps/unwraps --
      // it stores exactly what the router handed it (a plaintext string on the CONFIG_WRAP_KEY-absent floor,
      // or an opaque WrappedSecret envelope), mirroring the SIEM push destination's KEEP-SECRET split. A
      // jsm/servicenow channel that still has no apiKey after the splice (a first-ever create, or a repoint
      // with none supplied) is rejected, never half-stored.
      const identityUnchanged = prior !== undefined && prior.kind === v.channel.kind && prior.url === v.channel.url;
      const keptApiKey = identityUnchanged ? prior?.apiKey : undefined;
      const apiKey = v.channel.apiKey !== undefined ? v.channel.apiKey : keptApiKey;
      if ((v.channel.kind === "jsm" || v.channel.kind === "servicenow") && apiKey === undefined) {
        throw new Error(`${v.channel.kind} channel needs an apiKey (a bearer token/password; provide it when creating or repointing the channel)`);
      }
      // ENABLED is submitted by the caller and honoured here (NF-1 / G-P1-102). validateChannel deliberately
      // does NOT carry enabled (ValidatedChannel omits it: "id/createdAt/enabled defaulted by the caller"), so
      // it is read straight off raw, exactly as wantId is above. A boolean value is applied as sent, so
      // unticking "Enabled" on an edit DISABLES the channel and reticking re-enables it. An absent or
      // non-boolean value keeps the prior state on an edit (a caller that never sends the field cannot flip it)
      // and defaults to on for a create (a new channel starts enabled), matching the rule path (addNotifyRule
      // spreads v.rule) so a submitted disable is honoured rather than silently discarded.
      const wantEnabled = typeof (raw as { enabled?: unknown }).enabled === "boolean" ? (raw as { enabled: boolean }).enabled : undefined;
      const channel: NotifyChannel = {
        id,
        kind: v.channel.kind,
        name: v.channel.name,
        enabled: wantEnabled !== undefined ? wantEnabled : prior ? prior.enabled : true,
        createdAt: prior ? prior.createdAt : nowMillisISO(),
        ...(v.channel.url !== undefined ? { url: v.channel.url } : {}),
        ...(v.channel.routingKey !== undefined ? { routingKey: v.channel.routingKey } : {}),
        ...(v.channel.toAddresses !== undefined ? { toAddresses: v.channel.toAddresses } : {}),
        ...(v.channel.username !== undefined ? { username: v.channel.username } : {}),
        ...(apiKey !== undefined ? { apiKey } : {}),
        // Bugfix while touching this exact construction: allowInternalSink was validated (and returned by
        // validateChannel) but never actually PERSISTED, so a channel configured with the SSRF opt-in
        // would validate fine at config time and then be silently RE-BLOCKED at send time (deliverPayload
        // reads channel.allowInternalSink, which was always undefined post-store). Carries across every
        // kind uniformly, exactOptionalPropertyTypes-safe (omitted when false/absent).
        ...(v.channel.allowInternalSink !== undefined ? { allowInternalSink: v.channel.allowInternalSink } : {}),
      };
      await this.state.storage.put(`${NOTIFY_CHANNEL_PREFIX}${id}`, channel);
      // Default-on rule on first setup: only when this is the very first channel AND there is no rule.
      if (existingChannels.length === 0 && existingRules.length === 0) {
        const ruleId = newULID(now + 1);
        const rule: NotifyRule = {
          id: ruleId,
          scope: { kind: "global" },
          minSeverity: "warning", // failure (critical) + stale (warning) both pass
          events: ["backup-failure", "backup-stale"],
          channelIds: [id],
          enabled: true,
        };
        await this.state.storage.put(`${NOTIFY_RULE_PREFIX}${ruleId}`, rule);
      }
      return channel;
    }

    // deleteNotifyChannel removes a channel by id (notify.config re-checked). It is idempotent
    // (deleting an absent channel returns deleted:false). It does NOT rewrite rules that reference the
    // deleted channel: resolveDelivery already skips an unknown/absent channelId, so a dangling
    // reference is harmless and a later rule edit can clean it; this keeps the delete a single cheap op.
    async deleteNotifyChannel(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      this.requireNotifyConfig(caller);
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id is required");
      const deleted = await this.state.storage.delete(`${NOTIFY_CHANNEL_PREFIX}${req.id}`);
      return { deleted };
    }

    // listNotifyRules returns every configured rule.
    async listNotifyRules(): Promise<NotifyRule[]> {
      return this.listNotifyRulesRaw();
    }

    // addNotifyRule validates and upserts a rule (notify.config re-checked). The shape is validated by
    // the shared validateRule (scope, minSeverity, events, channelIds, optional digest, enabled). UPSERT
    // BY ID: an EDIT carries the existing rule's id (NotifyRuleInput.id); when that id names a rule that
    // already EXISTS we overwrite it in place, so an edit UPDATES instead of inserting a duplicate. An
    // absent id, or an id that names no existing rule, mints a fresh ULID (create) - the server still
    // owns the id space, so a client cannot conjure a chosen id. It does NOT require the referenced
    // channels to exist at write time (an operator may wire a rule before a channel); resolveDelivery
    // skips unknown ids at delivery time.
    //
    // THE SAME POLICY GOVERNS A DOWNPIPE-SCOPED RULE, and it is stated here because it was re-found and
    // re-argued as a defect: a rule whose scope names a
    // downpipe that does not exist is stored verbatim and ruleSelects simply never matches it. That is the
    // channel rule applied to the other reference on the same record, and requiring existence would refuse
    // wiring a rule before its downpipe AND would make a configuration restore depend on the order the
    // control plane happens to apply downpipes and rules in. What it leaves open is not the WRITE but the
    // AFTERMATH: deleting a downpipe silently stops the rules scoped to it, and nothing anywhere says so.
    // That is a visibility gap for the support pack, not a bound this boundary should be enforcing.
    async addNotifyRule(
      raw: unknown,
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<NotifyRule> {
      this.requireNotifyConfig(caller);
      const v = validateRule(raw);
      if (!v.ok) throw new Error(v.reason);
      const wantId = typeof (raw as { id?: unknown }).id === "string" ? (raw as { id: string }).id : null;
      const isUpdate = wantId !== null && (await this.state.storage.get(`${NOTIFY_RULE_PREFIX}${wantId}`)) !== undefined;
      const id = isUpdate ? wantId! : newULID(Date.now());
      const rule: NotifyRule = { id, ...v.rule };
      await this.state.storage.put(`${NOTIFY_RULE_PREFIX}${id}`, rule);
      return rule;
    }

    // deleteNotifyRule removes a rule by id (notify.config re-checked), idempotent.
    async deleteNotifyRule(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      this.requireNotifyConfig(caller);
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id is required");
      const deleted = await this.state.storage.delete(`${NOTIFY_RULE_PREFIX}${req.id}`);
      return { deleted };
    }

    // listNotifyHistory returns the delivery history NEWEST-FIRST (contract section 2.4). The ring is
    // capped at NOTIFY_HISTORY_CAP; storage keys are zero-padded by seq so the list() lexical order is
    // numeric order, and we reverse for newest-first. Each entry is redaction-safe (detail is the
    // downpipe name + state, never a secret).
    async listNotifyHistory(): Promise<NotifyHistoryEntry[]> {
      const map = await this.state.storage.list<NotifyHistoryEntry>({ prefix: NOTIFY_HISTORY_PREFIX });
      const arr = [...map.values()];
      // list() returns lexically-sorted keys; the padded seq makes that ascending numeric, so reverse
      // for newest-first. Sort by seq defensively in case of any key-format drift.
      arr.sort((a, b) => b.seq - a.seq);
      return arr;
    }

    // parseEmission validates and normalises an internal emission posted to /notify/resolve or
    // /notify/record. It is an authority-boundary check (the route is internal, but the DO bounds its
    // own inputs like every other route): event/severity must be valid enums; downpipeId is a bounded
    // id or null; detail is a bounded redaction-safe string (validateFreeText); at is a string;
    // recovered is an optional boolean. Returns null on any malformed value so the caller can 400.
    // dropContextOf salvages the NAMEABLE fields off an emission the parser REJECTED (G060). The whole point of
    // the drop ring is to answer "WHICH alert never arrived", and a parse reject (a bad enum somewhere, an
    // over-long free-text detail) usually leaves the identifying fields perfectly valid. Each field is passed
    // through its OWN closed-set guard here (isNotifyEventLocal / isSeverityLocal) before it is offered to the
    // recorder, and eventKnown:true is the recorder's proof that the closed-vocabulary check has been made.
    // The emission's free-text `detail` -- the field that is most often the reason for the reject -- is never
    // read, never passed and never stored.
    dropContextOf(raw: unknown): { event?: string; eventKnown?: boolean; severity?: unknown; downpipeId?: unknown } {
      if (typeof raw !== "object" || raw === null) return {};
      const e = raw as Record<string, unknown>;
      const eventKnown = typeof e.event === "string" && isNotifyEventLocal(e.event);
      return {
        ...(eventKnown ? { event: e.event as string, eventKnown: true } : {}),
        ...(typeof e.severity === "string" && isSeverityLocal(e.severity) ? { severity: e.severity } : {}),
        ...(typeof e.downpipeId === "string" ? { downpipeId: e.downpipeId } : {}),
      };
    }

    parseEmission(raw: unknown): NotifyEmission | null {
      if (typeof raw !== "object" || raw === null) return null;
      const e = raw as Record<string, unknown>;
      if (!isNotifyEventLocal(e.event)) return null;
      if (!isSeverityLocal(e.severity)) return null;
      let downpipeId: string | null = null;
      if (e.downpipeId !== null && e.downpipeId !== undefined) {
        if (typeof e.downpipeId !== "string" || !DOWNPIPE_ID_PATTERN.test(e.downpipeId)) return null;
        downpipeId = e.downpipeId;
      }
      let downpipeName: string | null = null;
      if (e.downpipeName !== null && e.downpipeName !== undefined) {
        if (typeof e.downpipeName !== "string" || e.downpipeName.length > DOWNPIPE_NAME_MAX_LEN) return null;
        downpipeName = e.downpipeName;
      }
      const detail = e.detail;
      if (typeof detail !== "string" || validateFreeText(detail, "detail", 512) !== null) return null;
      // Canonicalise the accepted `at` to the SAME RFC-3339 millis-Z form the producers emit
      // (nowMillisISO / the cron's at), so a stored emission timestamp is always canonical regardless of
      // the precision/offset the caller sent. A non-string, empty, or UNPARSEABLE `at` falls back to the
      // DO clock; a parseable one is normalised via canonMillisISO (the shared producer normalisation), so
      // downstream instant comparisons (e.g. summariseDigest's window) never see a non-canonical string.
      const at = canonMillisISO(e.at);
      const recovered = e.recovered === true;
      return {
        event: e.event,
        severity: e.severity,
        downpipeId,
        downpipeName,
        detail,
        at,
        ...(recovered ? { recovered: true } : {}),
      };
    }

    // resolveNotify is the FIRST half of the two-phase emit (mirroring reconcileAlerts). Given an
    // emission, it resolves routing against the stored rules+channels (the pure resolveDelivery), and:
    //  - records the DIGEST deferral for any success-class channel a digest rule selected (so a digested
    //    event is "batched, not sent per occurrence" today; the flush is a later wave), and
    //  - returns the immediate `now` channels + the (already-bounded, normalised) emission for the
    //    Worker to deliver out-of-band (the Worker holds env). The DO does no network I/O here.
    async resolveNotify(req: { emission?: unknown }): Promise<{ now: NotifyChannel[]; digestedCount: number; emission: NotifyEmission | null }> {
      const emission = this.parseEmission(req.emission);
      // A rejected emission (bad enum / overlong free-text detail) is counted (NOTIF: freetext-detail-overlong
      // -rejected) so the pack sees an alert was dropped at the input boundary, not silently.
      if (emission === null) {
        await this.bumpNotifyHealth("parseRejects");
        // G060: parseRejects=3 does not answer the customer's question, which is always "MY backup-failure
        // alert never arrived". Name the dead alert by the same closed fields the delivered-history ring
        // already carries (event, severity, downpipeId) and nothing else.
        await recordNotifyDrop(this.state.storage, "parse-reject", this.dropContextOf(req.emission));
        return { now: [], digestedCount: 0, emission: null };
      }
      const rules = await this.listNotifyRulesRaw();
      const channels = await this.listNotifyChannelsRaw();
      const resolved = resolveDelivery({ event: emission.event, severity: emission.severity, downpipeId: emission.downpipeId }, rules, channels);
      // G060: a rule that SELECTED this emission and routes to a channel id that no longer exists is skipped by
      // resolveDelivery, by design (a dangling ref must not break routing). The customer's rule looks armed on
      // the screen and delivers to nothing. notifyConfig.danglingChannelRefs counts the CONFIG defect; this
      // counts it at DELIVERY TIME, which is the only place that proves an actual alert went nowhere because
      // of it. It is a RATE (no ring row): a permanently dangling ref fires on every emission.
      const live = new Set(channels.map((c) => c.id));
      const selected = rules.filter((r) => r.enabled !== false && ruleSelects(r, emission.event, emission.severity, emission.downpipeId));
      const dangling = selected.some((r) => (r.channelIds ?? []).some((id) => !live.has(id)));
      if (dangling) await recordNotifyDrop(this.state.storage, "dangling-channel-skip");
      // Record the digest deferral for each digested channel so the success-class event is batched. The
      // cadence (period) per channel comes from resolveDelivery's digestPeriods (the shortest window any
      // digest rule chose for that channel); it is stamped on the pending entry so the flush knows which
      // window to apply without re-reading the rules. A channel with no recorded period (should not
      // happen for a digested channel) defaults to weekly, the conservative longer window.
      for (const ch of resolved.digested) {
        const period = resolved.digestPeriods[ch.id] ?? "weekly";
        await this.appendDigestEntry(emission, ch, period);
      }
      return { now: resolved.now, digestedCount: resolved.digested.length, emission };
    }

    // appendDigestEntry records one pending digest deferral (a success-class event a digest rule
    // deferred for a channel). It is a redaction-safe PendingDigestEntry under NOTIFY_DIGEST_PREFIX,
    // keyed by an opaque monotonic, ZERO-PADDED sequence so the keys sort in occurrence order (the flush
    // reads them oldest-first to compute the window) and multiple deferrals coexist. There is no
    // cap-driven rollover here (the flush is the natural consumer; the success stream is bounded by the
    // run cadence and a flush window is at most a week). It stores the cadence (period) the deferring
    // rule chose and the safe downpipeName for the roll-up's names list; every field is redaction-safe.
    async appendDigestEntry(emission: NotifyEmission, channel: NotifyChannel, period: DigestPeriod): Promise<void> {
      const seq = ((await this.state.storage.get<number>(NOTIFY_DIGEST_SEQ_KEY)) ?? 0) + 1;
      await this.state.storage.put(NOTIFY_DIGEST_SEQ_KEY, seq);
      const entry: PendingDigestEntry = {
        seq,
        channelId: channel.id,
        channelKind: channel.kind,
        period,
        event: emission.event,
        severity: emission.severity,
        downpipeId: emission.downpipeId,
        downpipeName: emission.downpipeName,
        detail: emission.detail,
        at: emission.at,
      };
      await this.state.storage.put(`${NOTIFY_DIGEST_PREFIX}${padSeqLocal(seq)}`, entry);
    }

    // digestDue is the FIRST half of the digest flush (mirroring resolveNotify / reconcileAlerts). The
    // cron driver PASSES IN the current epoch-millis (nowMs) because the DO has no wall clock; the DO
    // reads every pending digest entry and runs the pure groupDigestDue, which groups by channel and
    // returns ONE batch per channel whose window (measured from that channel's oldest deferred entry to
    // nowMs) has elapsed. It is a near no-op (one prefix list) when nothing is deferred. It does NO
    // network I/O and does NOT clear anything: clearing is the paired digestSent step, so a delivery
    // failure leaves the batch pending to retry. nowMs is bounded to a finite number; a missing/invalid
    // value falls back to the DO clock so a malformed caller cannot wedge the flush. The returned
    // batches carry only the redaction-safe roll-up (counts + downpipe names) and the seqs to clear.
    async digestDue(req: { nowMs?: unknown }): Promise<{ batches: DigestBatch[] }> {
      const map = await this.state.storage.list<PendingDigestEntry>({ prefix: NOTIFY_DIGEST_PREFIX });
      if (map.size === 0) return { batches: [] };
      const entries = [...map.values()];
      const nowMs = typeof req.nowMs === "number" && Number.isFinite(req.nowMs) ? req.nowMs : Date.now();
      const batches = groupDigestDue(entries, nowMs);
      // G223: groupDigestDue's guards suppress CONSERVATIVELY on an unparseable timestamp -- a digest that does
      // not flush, or an entry silently dropped from the window. The pure module tallies isolate-locally; drain
      // it HERE (the only caller) and file the count through the same bounded applyAdminCounters chokepoint the
      // Worker edge posts to. Best-effort: observing the suppression must never break the flush.
      const digestFaults = drainNotifyDigestFaults();
      if (digestFaults.timestampParseFailures > 0) {
        try {
          const prior = await this.state.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY);
          await this.state.storage.put(
            ADMIN_COUNTERS_KEY,
            applyAdminCounters(prior, { "notify-timestamp-parse-failed": digestFaults.timestampParseFailures }, new Date().toISOString()),
          );
        } catch {
          // best-effort: the digest still flushes.
        }
      }
      return { batches };
    }

    // digestSent is the SECOND half of the digest flush: the cron posts back the seqs of the pending
    // entries it delivered (the seqs from each DigestBatch it sent), and the DO deletes EXACTLY those
    // entries. Clearing by the specific seqs the cron consumed (not "everything due now") is what makes
    // it transactional against entries deferred AFTER the due-read: a success that lands between the
    // due-read and this clear keeps its own (later) seq, which is not in the list, so it survives for the
    // next window. It is fail-open and idempotent: a non-array or out-of-range id is skipped, deleting an
    // absent key is a no-op, and it never throws (a malformed payload degrades to "cleared 0"). Returns
    // how many entries were cleared.
    async digestSent(req: { ids?: unknown }): Promise<{ cleared: number }> {
      const ids = Array.isArray(req.ids) ? req.ids : [];
      let cleared = 0;
      let unclearable = 0;
      for (const id of ids) {
        if (typeof id !== "number" || !Number.isFinite(id) || id <= 0) {
          unclearable++;
          continue;
        }
        const deleted = await this.state.storage.delete(`${NOTIFY_DIGEST_PREFIX}${padSeqLocal(id)}`);
        if (deleted) cleared++;
      }
      // G060: a malformed clear-id is skipped, so the entry the cron JUST DELIVERED is NOT cleared and will be
      // delivered AGAIN next window, and the one after that: "we get the same digest email every hour" is a
      // permanent duplicate loop whose only trace was a silent `continue`. Distinct from "not yet due".
      if (unclearable > 0) await recordNotifyDrop(this.state.storage, "digest-clear-failed");
      return { cleared };
    }

    // digestPending reports the PENDING-DIGEST queue depth + the oldest deferred entry's timestamp (NOTIF:
    // digest-skew-or-bad-at-never-flushes), PLUS the per-cadence lifecycle state (digest-defers-success-up-
    // to-a-week / digest-sent-clear-fail-duplicates): for each period the QUEUE DEPTH, the OLDEST deferred
    // instant, and the computed DUE-AT (oldest + that period's window) so a digest that never flushes shows
    // WHICH cadence is stuck and WHEN its batch should have flushed. dueAt is derived from a FIXED window
    // (deterministic; no wall clock needed here). Redaction-safe (counts + clamped timestamps). Near no-op.
    async digestPending(): Promise<{ count: number; oldestAt: string | null; byPeriod: Partial<Record<DigestPeriod, { count: number; oldestAt: string; dueAt: string }>> }> {
      const map = await this.state.storage.list<PendingDigestEntry>({ prefix: NOTIFY_DIGEST_PREFIX });
      const entries = [...map.values()];
      if (entries.length === 0) return { count: 0, oldestAt: null, byPeriod: {} };
      // Fold per-period: depth + the oldest instant (compared by Date.parse so mixed precision cannot pick the
      // wrong end, mirroring summariseDigest). An unparseable `at` cannot win the min. A row's period defaults
      // to weekly (the conservative longer window) when it is not the "daily" sentinel.
      const acc: Partial<Record<DigestPeriod, { count: number; oldestMs: number; oldestAt: string }>> = {};
      let oldestAll = entries[0]!.at;
      let oldestAllMs = Number.POSITIVE_INFINITY;
      for (const e of entries) {
        const period: DigestPeriod = e.period === "daily" ? "daily" : "weekly";
        const t = Date.parse(e.at);
        const ms = Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
        const cur = acc[period];
        if (cur === undefined) acc[period] = { count: 1, oldestMs: ms, oldestAt: e.at };
        else {
          cur.count++;
          if (ms < cur.oldestMs) {
            cur.oldestMs = ms;
            cur.oldestAt = e.at;
          }
        }
        if (Number.isFinite(t) && (oldestAllMs === Number.POSITIVE_INFINITY || t < oldestAllMs)) {
          oldestAllMs = t;
          oldestAll = e.at;
        }
      }
      const byPeriod: Partial<Record<DigestPeriod, { count: number; oldestAt: string; dueAt: string }>> = {};
      for (const period of ["daily", "weekly"] as const) {
        const a = acc[period];
        if (a === undefined) continue;
        const dueAt = Number.isFinite(a.oldestMs) ? new Date(a.oldestMs + DIGEST_WINDOW_MS[period]).toISOString() : a.oldestAt;
        byPeriod[period] = { count: a.count, oldestAt: a.oldestAt, dueAt };
      }
      return { count: entries.length, oldestAt: oldestAll, byPeriod };
    }

    // recordNotify is the SECOND half of the two-phase emit: the Worker posts back the per-channel
    // delivery outcomes (DeliveryRecord[]) and the emission, and the DO appends one redaction-safe
    // NotifyHistoryEntry per outcome to the capped ring (newest at the tail; the head rolls off once
    // NOTIFY_HISTORY_CAP is exceeded). It bounds and validates the records defensively (the route is
    // internal, but the DO bounds its own inputs). It never throws on a malformed record set (it skips
    // bad rows) so a Worker hiccup degrades to "fewer history rows", never a 500. Returns how many
    // entries were appended.
    async recordNotify(req: { emission?: unknown; records?: unknown }): Promise<{ recorded: number; skipped: number }> {
      const emission = this.parseEmission(req.emission);
      // A rejected emission (bad enum / overlong free-text detail) is counted so the pack sees WHY the alert
      // never went out (NOTIF: freetext-detail-overlong-rejected), instead of a silent early return.
      if (emission === null) {
        await this.bumpNotifyHealth("parseRejects");
        // G060: the CRUEL one. A reject HERE discards an ENTIRE emission's per-channel delivery outcomes -- the
        // exact rows the customer is asking about ("did it even try to send it?") -- so the history ring has a
        // hole precisely where the question is. Name the alert whose outcomes were thrown away.
        await recordNotifyDrop(this.state.storage, "parse-reject", this.dropContextOf(req.emission));
        return { recorded: 0, skipped: 0 };
      }
      const records = Array.isArray(req.records) ? req.records : [];
      let recorded = 0;
      let skipped = 0;
      for (const rec of records) {
        if (typeof rec !== "object" || rec === null) {
          skipped++;
          continue;
        }
        const r = rec as Record<string, unknown>;
        const channelId = r.channelId;
        const channelKind = r.channelKind;
        if (typeof channelId !== "string" || channelId.length === 0 || channelId.length > 64) {
          skipped++;
          continue;
        }
        if (!isChannelKindLocal(channelKind)) {
          skipped++;
          continue;
        }
        const delivered = r.delivered === true;
        // The CLOSED delivery-failure code (validated against the allow-list; anything else dropped), the
        // shape-gated email platform code, and the recovered flag ride onto the history entry so the pack
        // can say WHY a delivery failed (NOTIF needs-new-logging). Only carried on a FAILURE / a resolve.
        const code = !delivered && typeof r.code === "string" && DELIVERY_FAIL_CODES.has(r.code) ? (r.code as DeliveryFailCode) : undefined;
        // G092 (version skew): a failure that CARRIED a code we do not hold in the closed set lands with NO
        // deliveryCode at all, so the pack shows an unexplained failed delivery and support cannot tell a
        // missing code from a code this build has never heard of. Count the drop, never the token.
        if (!delivered && typeof r.code === "string" && code === undefined) await recordVocabDrop(this.state.storage, "delivery-code");
        const platformCode = !delivered ? sanitiseEmailPlatformCode(r.platformCode) : undefined;
        const recovered = r.recovered === true;
        // The send-time sink-screen verdict (NOTIF: dns-rebinding-gap) is validated against the CLOSED
        // allow-list (anything else dropped, defence in depth) and carried on SUCCESS and failure alike, so a
        // delivered `hostname` sink (the rebind-exposed class) is observable, not only a blocked internal one.
        const sinkScreen = typeof r.sinkScreen === "string" && SINK_SCREEN_VERDICTS.has(r.sinkScreen) ? (r.sinkScreen as SinkScreenVerdict) : undefined;
        // G092: same skew gate. A verdict this build does not hold silently erases the rebind-exposure
        // evidence for that send. Count the drop (never the verdict token).
        if (typeof r.sinkScreen === "string" && sinkScreen === undefined) await recordVocabDrop(this.state.storage, "sink-screen");
        // unconfirmed (item 10): JSM/Opsgenie's async-accepted (202) outcome. Only meaningful on a
        // delivered:true entry (an accepted-but-unconfirmed send is still "delivered", just honestly caveated).
        const unconfirmed = delivered && r.unconfirmed === true;
        // ackOutcome (G033): the CLOSED verdict of the async-create status poll a JSM/ServiceNow deliver runs
        // after a 202. `async-create-failed` is the cruel one: the sink POSITIVELY reported that the create
        // failed, so delivered:true is true only of the handoff -- the page never existed. Gated on the closed
        // ACK_OUTCOMES vocabulary (an out-of-vocab value is dropped, never stored).
        const ackOutcome = typeof r.ackOutcome === "string" && ACK_OUTCOMES.has(r.ackOutcome) ? (r.ackOutcome as AckOutcome) : undefined;
        await this.appendNotifyHistory(emission, channelId, channelKind, delivered, { ...(code !== undefined ? { code } : {}), ...(platformCode !== undefined ? { platformCode } : {}), ...(recovered ? { recovered: true } : {}), ...(sinkScreen !== undefined ? { sinkScreen } : {}), ...(unconfirmed ? { unconfirmed: true } : {}), ...(ackOutcome !== undefined ? { ackOutcome } : {}) });
        recorded++;
      }
      // Per-channel records dropped as malformed are counted so a Worker/DO shape drift is visible, not silent.
      if (skipped > 0) {
        await this.bumpNotifyHealth("recordSkips", skipped);
        // G060: a skipped outcome row means a channel's delivery result is MISSING from the history the
        // customer is reading -- so a channel that in fact failed reads as one that was never tried.
        await recordNotifyDrop(this.state.storage, "record-skip", { event: emission.event, eventKnown: true, severity: emission.severity, downpipeId: emission.downpipeId });
      }
      return { recorded, skipped };
    }

    // bumpNotifyHealth increments one notify-pipeline drop counter (NOTIF needs-new-logging). It is a small
    // read-modify-write of the single NOTIFY_HEALTH_KEY record so "alerts silently stopped" is diagnosable:
    // whole passes skipped, per-channel records dropped, emissions rejected, and delivery-feedback failures.
    // Fail-open: a counter write must never affect delivery, so a bad `by` is clamped and it never throws.
    async bumpNotifyHealth(field: "passSkips" | "recordSkips" | "parseRejects" | "feedbackFails", by = 1): Promise<void> {
      const cur = (await this.state.storage.get<NotifyHealth>(NOTIFY_HEALTH_KEY)) ?? { passSkips: 0, recordSkips: 0, parseRejects: 0, feedbackFails: 0, lastAt: "" };
      const inc = Number.isFinite(by) && by > 0 ? Math.floor(by) : 1;
      const next: NotifyHealth = { ...cur, [field]: (cur[field] ?? 0) + inc, lastAt: nowMillisISO() };
      await this.state.storage.put(NOTIFY_HEALTH_KEY, next);
    }

    // getNotifyHealth reads the notify-pipeline drop-counter record (null before any drop was recorded).
    async getNotifyHealth(): Promise<NotifyHealth | null> {
      return (await this.state.storage.get<NotifyHealth>(NOTIFY_HEALTH_KEY)) ?? null;
    }

    // appendNotifyHistory appends one entry to the capped history ring inside one read-modify-write of
    // the sequence counter, then rolls off the oldest keys beyond NOTIFY_HISTORY_CAP. The entry is
    // redaction-safe: detail is the emission's one-liner (downpipe name + state), never a secret.
    async appendNotifyHistory(emission: NotifyEmission, channelId: string, channelKind: ChannelKind, delivered: boolean, extra?: { code?: DeliveryFailCode; platformCode?: string; recovered?: boolean; sinkScreen?: SinkScreenVerdict; test?: boolean; unconfirmed?: boolean; ackOutcome?: AckOutcome }): Promise<void> {
      const seq = ((await this.state.storage.get<number>(NOTIFY_HISTORY_SEQ_KEY)) ?? 0) + 1;
      const entry: NotifyHistoryEntry = {
        seq,
        ts: nowMillisISO(),
        event: emission.event,
        severity: emission.severity,
        downpipeId: emission.downpipeId,
        channelId,
        channelKind,
        delivered,
        detail: emission.detail,
        // The closed delivery-failure WHY (+ email platform code) on a failed delivery, and the recovered
        // flag for a PagerDuty resolve, so the pack can diagnose per-channel delivery without the raw response.
        ...(extra?.code !== undefined ? { deliveryCode: extra.code } : {}),
        ...(extra?.platformCode !== undefined ? { platformCode: extra.platformCode } : {}),
        ...(extra?.recovered === true ? { recovered: true } : {}),
        // The send-time sink-screen verdict (NOTIF: dns-rebinding-gap), on url channels only (success + failure).
        ...(extra?.sinkScreen !== undefined ? { sinkScreen: extra.sinkScreen } : {}),
        // A manual test-send (POST /notify/test): flagged so the trace is durable but never read as a
        // routed engine event (rules and digests do not consult history; readers badge it).
        ...(extra?.test === true ? { test: true } : {}),
        // unconfirmed (item 10): JSM/Opsgenie's async-accepted (202) outcome, so "delivered" here is never
        // silently conflated with a positively-confirmed success.
        ...(extra?.unconfirmed === true ? { unconfirmed: true } : {}),
        // ackOutcome (G033): the closed verdict of the follow-up create-status poll, so the pack can separate a
        // genuinely FAILED async create from a merely unconfirmed one.
        ...(extra?.ackOutcome !== undefined ? { ackOutcome: extra.ackOutcome } : {}),
      };
      await this.state.storage.put(NOTIFY_HISTORY_SEQ_KEY, seq);
      await this.state.storage.put(`${NOTIFY_HISTORY_PREFIX}${padSeqLocal(seq)}`, entry);
      // Roll off the single entry that has just fallen out of the cap window. The keys are zero-padded by
      // monotonic seq, so the entry that drops off when seq is written is exactly the one at seq - CAP: once
      // we have written entry N, entries N-CAP and earlier are already gone, so deleting N-CAP keeps the
      // retained set to CAP. This is O(1) per append and does NOT depend on a bare list() (a list() whose
      // page limit equals the cap can never report MORE than the cap, so a list-length compare would NEVER
      // trigger rollover and history would grow unbounded, finding engine-src-040-M1). Deleting a key below
      // 1 (seq <= CAP, before the ring is full) is a harmless no-op against an absent key.
      const staleSeq = seq - NOTIFY_HISTORY_CAP;
      if (staleSeq >= 1) {
        await this.state.storage.delete(`${NOTIFY_HISTORY_PREFIX}${padSeqLocal(staleSeq)}`);
      }
    }

  };
}
