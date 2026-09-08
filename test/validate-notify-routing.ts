// Severity/vocabulary, validation, routing and formatter vectors for the validate-notify suite
// (TC-N-10..TC-N-14), split out of validate-notify.ts. Covers
// severityOf/isSuccessClass/severityAtLeast, the replication vocabulary + pure detectors,
// validateChannel, deliverPayload send-time SSRF re-check, validateRule, ruleSelects/resolveDelivery
// routing resolution and the per-channel formatters.

import {
  isInternalSinkHost,
  deliverPayload,
  severityOf,
  isSuccessClass,
  severityAtLeast,
  isNotifyEvent,
  NOTIFY_EVENT_NAMES,
  classifyReplication,
  isRunEvictionRisk,
  validateChannel,
  validateRule,
  ruleSelects,
  resolveDelivery,
  redactChannelSecretForRead,
  type NotifyChannel,
  type NotifyRule,
  type NotifyEvent,
  type Severity,
  type ChannelKind,
} from "../src/notify.ts";
import { restoreAppliedEmission } from "../src/admin/restore-alert.ts";
import { readdirSync, readFileSync } from "node:fs";
import { join as joinPath, sep } from "node:path";
import { isNotifyEventLocal, isChannelKindLocal } from "../src/sched/scheduler-helpers.ts";
import { format as formatWebhook } from "../src/notify/channels/webhook.ts";
import { format as formatSlack } from "../src/notify/channels/slack.ts";
import { format as formatPagerDuty } from "../src/notify/channels/pagerduty.ts";
import { formatCard as formatTeamsCard } from "../src/notify/channels/teams.ts";
import { format as formatEmail } from "../src/notify/channels/email.ts";
import { validateRecipients } from "../src/email.ts";
import { ok } from "./validate-notify-shared.ts";

// ---- TC-N-10: severity mapping + helpers (contract section 2.1) ---------------------------

function testSeverityMapping(): void {
  ok("severityOf: backup-failure -> critical", severityOf("backup-failure") === "critical");
  ok("severityOf: restore-test-fail -> critical", severityOf("restore-test-fail") === "critical");
  ok("severityOf: backup-stale -> warning", severityOf("backup-stale") === "warning");
  ok("severityOf: source-detached -> warning", severityOf("source-detached") === "warning");
  ok("severityOf: backup-volume-regression -> warning", severityOf("backup-volume-regression") === "warning");
  ok("severityOf: credential-expiry -> warning", severityOf("credential-expiry") === "warning");
  ok("severityOf: posture-regression -> warning (default high)", severityOf("posture-regression") === "warning");
  ok("severityOf: backup-success -> info", severityOf("backup-success") === "info");
  ok("severityOf: restore-applied -> info", severityOf("restore-applied") === "info");
  ok("severityOf: role-change -> info", severityOf("role-change") === "info");

  ok("isSuccessClass: backup-success is success-class", isSuccessClass("backup-success") === true);
  ok("isSuccessClass: role-change is success-class", isSuccessClass("role-change") === true);
  ok("isSuccessClass: backup-failure is NOT success-class", isSuccessClass("backup-failure") === false);
  ok("isSuccessClass: backup-stale is NOT success-class", isSuccessClass("backup-stale") === false);

  ok("severityAtLeast: critical >= warning", severityAtLeast("critical", "warning") === true);
  ok("severityAtLeast: warning >= warning", severityAtLeast("warning", "warning") === true);
  ok("severityAtLeast: info < warning", severityAtLeast("info", "warning") === false);
}

// ---- TC-N-10b: replication-degraded + run-at-risk-eviction vocabulary + pure detectors -----
// This adds two warning-class events (the data-loss redundancy signals) and their pure detectors.
// This proves the vocabulary is recognised (isNotifyEvent), mapped to warning (severityOf), NOT
// success-class (so never digested), and that the leaf detectors return the right verdicts.

function testReplicationVocabularyAndDetectors(): void {
  // isNotifyEvent accepts both new events (so a rule may select them).
  ok("isNotifyEvent: replication-degraded recognised", isNotifyEvent("replication-degraded") === true);
  ok("isNotifyEvent: run-at-risk-eviction recognised", isNotifyEvent("run-at-risk-eviction") === true);
  // The canary and update-rollback events are also recognised (so a rule may select them).
  ok("isNotifyEvent: canary-dead recognised", isNotifyEvent("canary-dead") === true);
  ok("isNotifyEvent: canary-recovered recognised", isNotifyEvent("canary-recovered") === true);
  ok("isNotifyEvent: update-rollback-needed recognised", isNotifyEvent("update-rollback-needed") === true);

  // severityOf maps both to warning (the DO may override eviction-risk to critical at the last copy).
  ok("severityOf: replication-degraded -> warning", severityOf("replication-degraded") === "warning");
  ok("severityOf: run-at-risk-eviction -> warning", severityOf("run-at-risk-eviction") === "warning");

  // Neither is success-class (the redundancy stream is never digested).
  ok("isSuccessClass: replication-degraded is NOT success-class", isSuccessClass("replication-degraded") === false);
  ok("isSuccessClass: run-at-risk-eviction is NOT success-class", isSuccessClass("run-at-risk-eviction") === false);

  // classifyReplication: configured 3 / proven 2 -> degraded.
  ok("classifyReplication: 3 configured, 2 proven -> degraded", classifyReplication({ configuredCopies: 3, provenCopies: 2 }).degraded === true);
  // configured 2 / proven 2 -> healthy.
  ok("classifyReplication: 2 configured, 2 proven -> healthy", classifyReplication({ configuredCopies: 2, provenCopies: 2 }).degraded === false);
  // proven exceeding configured is still healthy (never degraded).
  ok("classifyReplication: 2 configured, 3 proven -> healthy", classifyReplication({ configuredCopies: 2, provenCopies: 3 }).degraded === false);
  // zero proven against a configured target -> degraded.
  ok("classifyReplication: 3 configured, 0 proven -> degraded", classifyReplication({ configuredCopies: 3, provenCopies: 0 }).degraded === true);
  // a non-positive / non-integer configured count never cries wolf.
  ok("classifyReplication: 0 configured -> not degraded (misconfig safe)", classifyReplication({ configuredCopies: 0, provenCopies: 0 }).degraded === false);
  ok("classifyReplication: non-integer configured -> not degraded", classifyReplication({ configuredCopies: 1.5, provenCopies: 0 }).degraded === false);
  // a negative proven count is clamped to zero (still degraded against a real target).
  ok("classifyReplication: negative proven clamps to 0 -> degraded", classifyReplication({ configuredCopies: 2, provenCopies: -4 }).degraded === true);

  // isRunEvictionRisk: ring at cap AND a replica holds an index BELOW the head about to roll off -> at risk.
  ok("isRunEvictionRisk: ring at cap + holdsIndex<headIndex -> at risk", isRunEvictionRisk({ ringAtCap: true, headIndex: 10, holdsIndex: 9 }).atRisk === true);
  // ring at cap but the replica already holds up to the head -> not at risk.
  ok("isRunEvictionRisk: ring at cap + holdsIndex==headIndex -> not at risk", isRunEvictionRisk({ ringAtCap: true, headIndex: 10, holdsIndex: 10 }).atRisk === false);
  ok("isRunEvictionRisk: ring at cap + holdsIndex>headIndex -> not at risk", isRunEvictionRisk({ ringAtCap: true, headIndex: 10, holdsIndex: 11 }).atRisk === false);
  // ring NOT at cap -> nothing is being evicted yet, never at risk regardless of the lag.
  ok("isRunEvictionRisk: ring not at cap -> not at risk", isRunEvictionRisk({ ringAtCap: false, headIndex: 10, holdsIndex: 1 }).atRisk === false);
}

// ---- TC-N-10c: structural wiring guard (every NotifyEvent is fully routed) -----------------
// A NotifyEvent missing from any of the three routing lists is SILENTLY DROPPED. Absent from
// isNotifyEventLocal, the DO's parseEmission returns null so routeNotification resolves ZERO channels
// (the alert never reaches an operator); absent from the NOTIFY_EVENTS rule vocabulary, a rule cannot
// even name it (the rule POST 400s). This guard iterates NOTIFY_EVENT_NAMES (the single source of truth
// the NotifyEvent union is derived from) and asserts EVERY member is wired into isNotifyEventLocal, the
// NOTIFY_EVENTS rule vocabulary (via isNotifyEvent) and severityOf, so a future event that forgets a
// wiring fails CI here rather than shipping a dropped alert (the exact defect that dropped backup-volume-
// regression / source-detached / replication-degraded / run-at-risk-eviction).
function testEventWiringCompleteness(): void {
  const severities = new Set<Severity>(["info", "warning", "critical"]);
  for (const event of NOTIFY_EVENT_NAMES) {
    ok(`wiring: ${event} admitted by isNotifyEventLocal (DO parseEmission)`, isNotifyEventLocal(event) === true);
    ok(`wiring: ${event} in NOTIFY_EVENTS (a rule may name it)`, isNotifyEvent(event) === true);
    ok(`wiring: ${event} has a valid severityOf mapping`, severities.has(severityOf(event)));
  }
  // Guard the guard: the canonical list must still carry the once-dropped events, so an accidental
  // truncation of NOTIFY_EVENT_NAMES cannot make the loop above pass vacuously.
  for (const once of ["backup-volume-regression", "source-detached", "replication-degraded", "run-at-risk-eviction"] as const) {
    ok(`wiring: canonical list still contains the once-dropped ${once}`, (NOTIFY_EVENT_NAMES as readonly string[]).includes(once));
  }
}

// ---- TC-N-10c-2: every event must be PRODUCED, not merely routable --------------------------
// The guard above proves an event can be DELIVERED: admitted by the DO, nameable by a rule, given a
// severity. It never asked whether anything emits it, and restore-applied was fully wired and emitted by
// nothing. A customer could select it on a rule, the rule matched nothing, and the one irreversible
// operation in the product notified no one while a restore TEST passing did.
//
// The engine's dead-vocab gate did not catch it, and the reason is worth stating so this check is not
// mistaken for a duplicate. That gate asks the type checker which vocabulary each occurrence belongs to,
// and every occurrence of restore-applied WAS a NotifyEvent: a case label in the severity switch, a
// member of the digest set, a compared operand in the admit-guard. Those are all real NotifyEvent slots.
// They are classifications OF an event, not productions of one, and no type distinguishes the two.
//
// So this looks at WHERE the literal appears. A member that occurs only in the files that classify and
// route events is a promise nothing can keep.
//
// The bound, stated plainly: this is lexical, so it proves the literal is REACHABLE outside routing, not
// that the occurrence is an emission. It cannot be made exact without the type-aware machinery the
// dead-vocab gate already has, and the two are complements rather than duplicates. It does catch the
// class that bit here, and it is not vacuous: comments are stripped, and a routing LABEL must never be
// spelled the same as its event or it would satisfy this check on its own (which is why the
// restore-applied emission passes "restore" as its log label).
function testEveryEventIsProducedSomewhere(): void {
  // The files that CLASSIFY or ROUTE an event rather than produce one. Kept explicit: adding a file here
  // weakens the check, so it should be a deliberate edit with a reason, not a wildcard that silently grows.
  const classifyOnly = ["src/notify/types.ts", "src/notify-routing.ts", "src/notify-digest.ts", "src/sched/scheduler-helpers.ts"];
  const srcFiles: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = joinPath(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (p.endsWith(".ts")) srcFiles.push(p);
    }
  };
  walk("src");
  const producing = srcFiles.filter((f) => !classifyOnly.includes(f.split(sep).join("/")));
  // Comments are stripped, so an event named only in prose (a TODO, a rationale) cannot satisfy this.
  const haystack = producing
    .map((f) => readFileSync(f, "utf8"))
    .join("\n")
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*");
    })
    .join("\n");
  for (const event of NOTIFY_EVENT_NAMES) {
    ok(
      `production: ${event} appears outside the classification/routing files (something can actually emit it)`,
      haystack.includes(`"${event}"`),
    );
  }
  // Guard the guard: the exclusion list must actually exclude something, or every event would trivially
  // pass by being found in its own declaration file.
  ok("production: the classification files are genuinely excluded from the haystack", producing.length > 0 && producing.length < srcFiles.length);
}

// ---- TC-N-10c-3: what the restore-applied alert actually SAYS ------------------------------
// The production check above proves something emits the event. It cannot prove the emission is worth
// receiving. These two decisions are the whole content of an alert about the product's one irreversible
// operation, and until the logic was pulled out of the router handler neither was reachable from a test.
//
// The severity rule is the load-bearing one. restore-applied is success-class and DIGESTIBLE, so a clean
// apply is batched with the other successes, which is right. A restore that fell short must not be: it
// escalates to warning, and the failure/warning stream is never digested, so it reaches someone promptly.
// Getting that backwards would bury the only alert that matters in a daily summary.
function testRestoreAppliedAlertContent(): void {
  const clean = restoreAppliedEmission({ runId: "01RUN", recordsVerified: 100, recordsRestored: 100, failures: 0 });
  ok("alert: a clean apply stays info (digestible, batched with the other successes)", clean.severity === "info");
  ok("alert: a clean apply is not marked as a shortfall", clean.shortfall === false);
  ok("alert: a clean apply still states the counts", clean.detail.includes("restored 100 of 100 verified record(s)"));
  ok("alert: a clean apply adds no shortfall clause", !clean.detail.includes(","));

  const skipped = restoreAppliedEmission({ runId: "01RUN", recordsVerified: 100, recordsRestored: 98, failures: 0, recordsSkipped: 2 });
  ok("alert: records not written escalate to warning (out of the digest, delivered promptly)", skipped.severity === "warning");
  ok("alert: the shortfall says the records are still outstanding, not merely that fewer landed", skipped.detail.includes("2 deliberately not written and still outstanding"));

  const failed = restoreAppliedEmission({ runId: "01RUN", recordsVerified: 100, recordsRestored: 97, failures: 3 });
  ok("alert: write failures escalate to warning", failed.severity === "warning");
  ok("alert: the failure count is named", failed.detail.includes("3 failed to write"));

  // Both kinds at once: an operator needs both numbers, since they need different remedies.
  const both = restoreAppliedEmission({ runId: "01RUN", recordsVerified: 100, recordsRestored: 95, failures: 3, recordsSkipped: 2 });
  ok("alert: both shortfall kinds are reported, not just the first", both.detail.includes("3 failed to write") && both.detail.includes("2 deliberately not written"));

  // recordsSkipped: 0 must behave exactly like absent, or a caller passing 0 escalates every clean restore
  // to warning and the digest stops meaning anything.
  const zero = restoreAppliedEmission({ runId: "01RUN", recordsVerified: 10, recordsRestored: 10, failures: 0, recordsSkipped: 0 });
  ok("alert: recordsSkipped 0 is not a shortfall (zero is not a distinct state)", zero.severity === "info" && zero.shortfall === false);

  // The detail rides into channel adapters, so the cap is part of the emission rather than the caller's job.
  const long = restoreAppliedEmission({ runId: "0".repeat(400), recordsVerified: 1, recordsRestored: 0, failures: 1 });
  ok("alert: the detail is clamped to 200 chars before it reaches a channel", long.detail.length <= 200);
}

// ---- TC-N-10d: CHANNEL-KIND wiring completeness (the ChannelKind sibling of TC-N-10c) -----
// ChannelKind has no NOTIFY_EVENT_NAMES-style runtime array (it is a bare union), so isChannelKindLocal
// (the DO's authority-boundary guard recordNotify checks a Worker-reported channelKind against before
// storing a NotifyHistoryEntry) can silently fall out of lockstep with it: a kind added to the union but
// forgotten there has every one of its deliveries SILENTLY DROPPED from history (recordNotify's `skipped`
// path), the exact drop class TC-N-10c guards for events. ALL_CHANNEL_KINDS is the runtime list the loop
// below drives off; AssertExactChannelKinds ties it to the ChannelKind union at COMPILE TIME, EXACTLY and
// in BOTH directions -- a kind added to ChannelKind but not listed here, OR a stray/typo'd entry that is
// not a ChannelKind, makes the `const true` assignment below fail `tsc`. This gives ALL_CHANNEL_KINDS the
// same can't-drift guarantee NOTIFY_EVENT_NAMES gets from having its type DERIVED from it, WITHOUT changing
// the ChannelKind declaration (which chaos/coverage-map.mjs parses as a literal `= "a" | "b" | ...` union).
const ALL_CHANNEL_KINDS = ["email", "webhook", "slack", "pagerduty", "teams", "jsm", "servicenow"] as const;
// The `[X] extends [Y]` tuple wrapping stops union distribution, so this is a true set-equality test: it is
// `true` only when ALL_CHANNEL_KINDS[number] and ChannelKind are the SAME set, else it resolves to `never`
// and the `const ... = true` assignment below fails to compile.
type AssertExactChannelKinds<T extends readonly string[]> = [ChannelKind] extends [T[number]]
  ? ([T[number]] extends [ChannelKind] ? true : never)
  : never;
const _channelKindsExactlyMatchUnion: AssertExactChannelKinds<typeof ALL_CHANNEL_KINDS> = true;
void _channelKindsExactlyMatchUnion;

// minimalChannelBodyFor returns a minimal, well-formed channel submission for a given kind, so the
// wiring loop can prove validateChannel actually accepts it (not merely that the kind string exists). Its
// switch is itself compile-time exhaustive on ChannelKind (no default, returns in every case), so a new
// kind that is not handled here also fails `tsc` -- a second structural guard alongside the type assertion.
function minimalChannelBodyFor(kind: ChannelKind): Record<string, unknown> {
  switch (kind) {
    case "webhook":
    case "slack":
      return { kind, name: "w", url: "https://sink.example.com/h" };
    case "teams":
      return { kind, name: "w", url: "https://outlook.office.com/webhook/x" };
    case "pagerduty":
      return { kind, name: "w", routingKey: "R0123456789ABCDEF" };
    case "email":
      return { kind, name: "w", toAddresses: ["ops@example.com"] };
    case "jsm":
      return { kind, name: "w", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-key-abc" };
    case "servicenow":
      return { kind, name: "w", url: "https://instance.service-now.com/api/now/table/em_event", username: "svc", apiKey: "pw" };
  }
}

function testChannelKindWiringCompleteness(): void {
  for (const kind of ALL_CHANNEL_KINDS) {
    ok(`channel-kind wiring: ${kind} admitted by isChannelKindLocal (DO recordNotify guard)`, isChannelKindLocal(kind) === true);
    const r = validateChannel(minimalChannelBodyFor(kind), validateRecipients);
    ok(`channel-kind wiring: ${kind} accepted by validateChannel with a minimal well-formed shape`, r.ok === true);
  }
  // Guard the guard: an UNKNOWN string must never be admitted by isChannelKindLocal (the drop guard must
  // stay closed, not merely "true for anything").
  ok("channel-kind wiring: an unknown kind is NOT admitted by isChannelKindLocal", isChannelKindLocal("sms") === false);
}

// ---- TC-N-11: validateChannel (per-kind transport validation) ----------------------------

function testValidateChannel(): void {
  // webhook: valid https url
  {
    const r = validateChannel({ kind: "webhook", name: "SIEM", url: "https://siem.example.com/ingest" }, validateRecipients);
    ok("validateChannel: webhook with https url ok", r.ok === true);
    if (r.ok) ok("validateChannel: webhook stores url only", r.channel.url === "https://siem.example.com/ingest" && r.channel.routingKey === undefined && r.channel.toAddresses === undefined);
  }
  // webhook: http rejected (reuses isAllowedWebhookUrl)
  ok("validateChannel: webhook http rejected", validateChannel({ kind: "webhook", name: "x", url: "http://siem.example.com" }, validateRecipients).ok === false);
  // webhook: workers.dev rejected
  ok("validateChannel: webhook workers.dev rejected", validateChannel({ kind: "webhook", name: "x", url: "https://a.workers.dev/h" }, validateRecipients).ok === false);
  // slack: valid url
  ok("validateChannel: slack with url ok", validateChannel({ kind: "slack", name: "alerts", url: "https://hooks.slack.com/services/T/B/x" }, validateRecipients).ok === true);
  // pagerduty: routingKey required
  {
    const r = validateChannel({ kind: "pagerduty", name: "PD", routingKey: "R0123456789ABCDEF" }, validateRecipients);
    ok("validateChannel: pagerduty with routingKey ok", r.ok === true);
    if (r.ok) ok("validateChannel: pagerduty stores routingKey only", r.channel.routingKey === "R0123456789ABCDEF" && r.channel.url === undefined);
  }
  ok("validateChannel: pagerduty without routingKey rejected", validateChannel({ kind: "pagerduty", name: "x" }, validateRecipients).ok === false);
  // email: toAddresses required + validated
  {
    const r = validateChannel({ kind: "email", name: "ops", toAddresses: ["ops@example.com"] }, validateRecipients);
    ok("validateChannel: email with toAddresses ok", r.ok === true);
    if (r.ok) ok("validateChannel: email stores toAddresses only", Array.isArray(r.channel.toAddresses) && r.channel.url === undefined);
  }
  ok("validateChannel: email with bad address rejected", validateChannel({ kind: "email", name: "x", toAddresses: ["bad"] }, validateRecipients).ok === false);
  ok("validateChannel: email with workers.dev address rejected", validateChannel({ kind: "email", name: "x", toAddresses: ["a@x.workers.dev"] }, validateRecipients).ok === false);
  // teams: connector url OR email-to-channel
  ok("validateChannel: teams with connector url ok", validateChannel({ kind: "teams", name: "t", url: "https://outlook.office.com/webhook/x" }, validateRecipients).ok === true);
  {
    const r = validateChannel({ kind: "teams", name: "t", toAddresses: ["channel@example.com"] }, validateRecipients);
    ok("validateChannel: teams with email-to-channel ok", r.ok === true);
    if (r.ok) ok("validateChannel: teams email-to-channel stores toAddresses", Array.isArray(r.channel.toAddresses) && r.channel.url === undefined);
  }
  ok("validateChannel: teams with neither url nor toAddresses rejected", validateChannel({ kind: "teams", name: "t" }, validateRecipients).ok === false);

  // jsm (Jira Service Management / Opsgenie): url + apiKey
  {
    const r = validateChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-key-abc123" }, validateRecipients);
    ok("validateChannel: jsm with url + apiKey ok", r.ok === true);
    if (r.ok) ok("validateChannel: jsm stores url + apiKey only", r.channel.url === "https://api.opsgenie.com/v2/alerts" && r.channel.apiKey === "genie-key-abc123" && r.channel.routingKey === undefined && r.channel.toAddresses === undefined && r.channel.username === undefined);
  }
  // jsm: apiKey OMITTED is still accepted at the shape layer (the KEEP-SECRET signal; the DO-level
  // splice in addNotifyChannel is what rejects a genuinely first-ever create with none supplied).
  {
    const r = validateChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts" }, validateRecipients);
    ok("validateChannel: jsm with apiKey omitted is still ok (KEEP-SECRET shape)", r.ok === true);
    if (r.ok) ok("validateChannel: jsm with apiKey omitted stores no apiKey field", !("apiKey" in r.channel));
  }
  // jsm: an empty-string apiKey is treated the same as omitted (KEEP-SECRET), not a validation error.
  ok("validateChannel: jsm with an empty apiKey string is still ok (KEEP-SECRET)", validateChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "" }, validateRecipients).ok === true);
  // A WHITESPACE-ONLY apiKey is the KEEP-SECRET / no-value signal too (never a stored plaintext value) --
  // parseChannelSecret trims before deciding, so "   " stores no apiKey field, exactly like "".
  {
    const r = validateChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "   " }, validateRecipients);
    ok("validateChannel: jsm with a whitespace-only apiKey is KEEP-SECRET, not a stored value", r.ok === true && !("apiKey" in r.channel));
  }
  // jsm: url is mandatory and threads the same isAllowedWebhookUrl discipline (http rejected).
  ok("validateChannel: jsm with http url rejected", validateChannel({ kind: "jsm", name: "Ops", url: "http://api.opsgenie.com/v2/alerts", apiKey: "k" }, validateRecipients).ok === false);
  ok("validateChannel: jsm without a url rejected", validateChannel({ kind: "jsm", name: "Ops", apiKey: "k" }, validateRecipients).ok === false);
  // jsm: a non-string, non-wrapped-secret apiKey (e.g. a number) is rejected at the shape layer.
  ok("validateChannel: jsm with a malformed apiKey (number) rejected", validateChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: 12345 }, validateRecipients).ok === false);
  // jsm: an already-sealed WrappedSecret envelope (what the router forwards once wrapped) is accepted
  // verbatim -- validateChannel never does crypto, only shape-checks.
  {
    const sealed = { v: 1 as const, iv: "aaaa", ct: "bbbb" };
    const r = validateChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: sealed }, validateRecipients);
    ok("validateChannel: jsm accepts an already-sealed WrappedSecret apiKey verbatim", r.ok === true);
    if (r.ok) ok("validateChannel: jsm stores the sealed envelope unchanged (no crypto here)", JSON.stringify(r.channel.apiKey) === JSON.stringify(sealed));
  }

  // servicenow (ServiceNow Event Management): url + username + apiKey
  {
    const r = validateChannel({ kind: "servicenow", name: "SNOW", url: "https://instance.service-now.com/api/now/table/em_event", username: "svc_downpipes", apiKey: "s3cr3t-pw" }, validateRecipients);
    ok("validateChannel: servicenow with url + username + apiKey ok", r.ok === true);
    if (r.ok) {
      ok(
        "validateChannel: servicenow stores url + username + apiKey only",
        r.channel.url === "https://instance.service-now.com/api/now/table/em_event" && r.channel.username === "svc_downpipes" && r.channel.apiKey === "s3cr3t-pw" && r.channel.routingKey === undefined && r.channel.toAddresses === undefined,
      );
    }
  }
  // servicenow: username is ALWAYS required (never KEEP-SECRET; it is not a secret).
  ok("validateChannel: servicenow without a username rejected", validateChannel({ kind: "servicenow", name: "SNOW", url: "https://instance.service-now.com/api/now/table/em_event", apiKey: "pw" }, validateRecipients).ok === false);
  // servicenow: apiKey (the Basic-auth password) OMITTED is still accepted at the shape layer, the same
  // KEEP-SECRET signal as jsm.
  {
    const r = validateChannel({ kind: "servicenow", name: "SNOW", url: "https://instance.service-now.com/api/now/table/em_event", username: "svc" }, validateRecipients);
    ok("validateChannel: servicenow with apiKey omitted is still ok (KEEP-SECRET shape)", r.ok === true);
    if (r.ok) ok("validateChannel: servicenow with apiKey omitted stores no apiKey field", !("apiKey" in r.channel));
  }
  ok("validateChannel: servicenow with http url rejected", validateChannel({ kind: "servicenow", name: "SNOW", url: "http://instance.service-now.com/api/now/table/em_event", username: "svc", apiKey: "pw" }, validateRecipients).ok === false);
  ok("validateChannel: servicenow without a url rejected", validateChannel({ kind: "servicenow", name: "SNOW", username: "svc", apiKey: "pw" }, validateRecipients).ok === false);

  // jsm/servicenow thread the SAME SSRF default-deny + override discipline as webhook/teams.
  ok("validateChannel: jsm -> internal sink rejected by default", validateChannel({ kind: "jsm", name: "x", url: "https://169.254.169.254/v2/alerts", apiKey: "k" }, validateRecipients).ok === false);
  {
    const r = validateChannel({ kind: "jsm", name: "x", url: "https://10.1.2.3/v2/alerts", apiKey: "k", allowInternalSink: true }, validateRecipients);
    ok("validateChannel: jsm -> internal sink allowed WITH override", r.ok === true && r.channel.allowInternalSink === true);
  }
  ok("validateChannel: servicenow -> internal sink rejected by default", validateChannel({ kind: "servicenow", name: "x", url: "https://192.168.0.9/api/now/table/em_event", username: "svc", apiKey: "k" }, validateRecipients).ok === false);
  {
    const r = validateChannel({ kind: "servicenow", name: "x", url: "https://10.1.2.3/api/now/table/em_event", username: "svc", apiKey: "k", allowInternalSink: true }, validateRecipients);
    ok("validateChannel: servicenow -> internal sink allowed WITH override", r.ok === true && r.channel.allowInternalSink === true);
  }

  // bad kind / name
  ok("validateChannel: unknown kind rejected", validateChannel({ kind: "sms", name: "x" }, validateRecipients).ok === false);
  ok("validateChannel: empty name rejected", validateChannel({ kind: "webhook", name: "", url: "https://a.example.com" }, validateRecipients).ok === false);
  ok("validateChannel: non-object rejected", validateChannel("nope", validateRecipients).ok === false);

  // ---- SSRF default-deny threads through validateChannel ----
  // A webhook channel pointed at the cloud-metadata IP is refused at config time by default.
  ok("validateChannel: webhook -> metadata IP rejected by default",
    validateChannel({ kind: "webhook", name: "x", url: "https://169.254.169.254/x" }, validateRecipients).ok === false);
  // A webhook channel pointed at an RFC1918 literal is refused by default.
  ok("validateChannel: webhook -> RFC1918 rejected by default",
    validateChannel({ kind: "webhook", name: "x", url: "https://192.168.0.9/x" }, validateRecipients).ok === false);
  // A webhook channel pointed at a carrier-NAT literal (RFC 6598) is refused at config time by default.
  ok("validateChannel: webhook -> carrier-NAT (CGN) rejected by default",
    validateChannel({ kind: "webhook", name: "x", url: "https://100.100.50.1/x" }, validateRecipients).ok === false);
  // With the explicit per-channel override, the internal sink is accepted and the flag is stored.
  {
    const r = validateChannel({ kind: "webhook", name: "on-prem SIEM", url: "https://10.1.2.3/ingest", allowInternalSink: true }, validateRecipients);
    ok("validateChannel: webhook -> internal sink allowed WITH override", r.ok === true);
    if (r.ok) ok("validateChannel: override flag stored on the channel", r.channel.allowInternalSink === true);
  }
  // The override is stored ONLY when true (default-deny channels carry no flag, exactOptional-safe).
  {
    const r = validateChannel({ kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" }, validateRecipients);
    ok("validateChannel: no override flag stored when absent", r.ok === true && !("allowInternalSink" in r.channel));
  }
  // A non-boolean override is rejected at the boundary.
  ok("validateChannel: non-boolean allowInternalSink rejected",
    validateChannel({ kind: "webhook", name: "x", url: "https://siem.example.com/h", allowInternalSink: "yes" }, validateRecipients).ok === false);
  // teams connector honours the override too.
  ok("validateChannel: teams connector -> internal rejected by default",
    validateChannel({ kind: "teams", name: "t", url: "https://10.0.0.1/webhook" }, validateRecipients).ok === false);
  {
    const r = validateChannel({ kind: "teams", name: "t", url: "https://10.0.0.1/webhook", allowInternalSink: true }, validateRecipients);
    ok("validateChannel: teams connector -> internal allowed WITH override", r.ok === true && r.channel.allowInternalSink === true);
  }
}

// ---- TC-N-11b: deliverPayload SSRF re-check at SEND time (defence-in-depth) ----------
// Even if a channel were persisted by a path that bypassed isAllowedWebhookUrl, deliverPayload
// re-screens the host at send time: an internal target is a fail-open non-delivery unless the
// caller passes allowInternal. This proves the SECOND layer of the E8 fix without any network.

async function testDeliverPayloadSsrf(): Promise<void> {
  // isInternalSinkHost classifier: spot-check the boundaries directly.
  ok("isInternalSinkHost: 169.254.169.254 is internal", isInternalSinkHost("169.254.169.254") === true);
  ok("isInternalSinkHost: 10.0.0.1 is internal", isInternalSinkHost("10.0.0.1") === true);
  ok("isInternalSinkHost: [::1] is internal", isInternalSinkHost("[::1]") === true);
  ok("isInternalSinkHost: example.com is NOT internal", isInternalSinkHost("example.com") === false);
  ok("isInternalSinkHost: 8.8.8.8 (public) is NOT internal", isInternalSinkHost("8.8.8.8") === false);
  // Carrier-grade NAT (RFC 6598 100.64.0.0/10) is internal (some clouds put metadata/internal LBs here).
  ok("isInternalSinkHost: 100.64.0.1 (CGN) is internal", isInternalSinkHost("100.64.0.1") === true);
  ok("isInternalSinkHost: 100.127.255.255 (CGN top) is internal", isInternalSinkHost("100.127.255.255") === true);
  // Boundary: the octets either side of 100.64.0.0/10 are PUBLIC and must NOT be over-blocked.
  ok("isInternalSinkHost: 100.63.255.255 (below CGN) is NOT internal", isInternalSinkHost("100.63.255.255") === false);
  ok("isInternalSinkHost: 100.128.0.1 (above CGN) is NOT internal", isInternalSinkHost("100.128.0.1") === false);

  // Send-time: an internal target with NO override is a non-delivery (ok:false), never a real POST.
  {
    const r = await deliverPayload("https://169.254.169.254/x", { hello: "world" });
    ok("deliverPayload: metadata IP without override -> {ok:false} (blocked, no POST)", r.ok === false && r.status === undefined);
  }
  {
    const r = await deliverPayload("https://10.0.0.5/ingest", { hello: "world" });
    ok("deliverPayload: RFC1918 without override -> {ok:false} (blocked)", r.ok === false);
  }
  {
    // A carrier-NAT literal is screened at SEND time exactly like RFC1918 (blocked, no POST).
    const r = await deliverPayload("https://100.64.12.34/ingest", { hello: "world" });
    ok("deliverPayload: carrier-NAT (CGN) without override -> {ok:false} (blocked, no POST)", r.ok === false && r.status === undefined && r.code === "internal-sink-blocked");
  }
  // With the override the host check is skipped; the POST is attempted (it then fails-open on the
  // network because the host is unreachable, but it was NOT blocked by the screen). We can only
  // assert it does not throw and returns a verdict; the key is the screen did not short-circuit it.
  {
    const r = await deliverPayload("https://203.0.113.10/x", { hello: "world" });
    ok("deliverPayload: a PUBLIC host is not blocked by the screen (attempts the POST, fails-open)", typeof r.ok === "boolean");
  }

  // NO POST IS ISSUED, proven rather than inferred. The assertions above read the RESULT
  // ({ok:false}, no status, the internal-sink-blocked code), and an unreachable host would produce a
  // near-identical result from the network path, so on their own they cannot tell a refusal from a
  // failed attempt. Spy on globalThis.fetch: the screened targets must never reach it, and a public
  // host must. This is the property the removed legacy postWebhook vector (TC-N-05) used to hold, and
  // it belongs on the surviving delivery path.
  {
    const realFetch = globalThis.fetch;
    let fetched = false;
    globalThis.fetch = (async (): Promise<Response> => {
      fetched = true;
      return new Response("{}", { status: 200 });
    }) as typeof globalThis.fetch;
    try {
      const metadata = await deliverPayload("https://169.254.169.254/x", { hello: "world" });
      ok("deliverPayload: metadata IP -> refused with NO fetch attempted", metadata.ok === false && metadata.code === "internal-sink-blocked" && fetched === false);
      fetched = false;
      const cgn = await deliverPayload("https://100.100.10.20/ingest", { hello: "world" });
      ok("deliverPayload: carrier-NAT (CGN) -> refused with NO fetch attempted", cgn.ok === false && cgn.code === "internal-sink-blocked" && fetched === false);
      fetched = false;
      const invalid = await deliverPayload("not-a-url", { hello: "world" });
      ok("deliverPayload: an unparseable url -> refused with NO fetch attempted", invalid.ok === false && invalid.code === "url-invalid" && fetched === false);
      // A PUBLIC host is NOT short-circuited: the screen lets it through to the (stubbed) POST. `fetched`
      // is mutated inside the stub, a closure TS cannot see, so after `fetched = false` it narrows to the
      // literal false; read it through a boolean widening so the runtime value is compared honestly.
      fetched = false;
      const pub = await deliverPayload("https://hooks.example.com/x", { hello: "world" });
      ok("deliverPayload: a public host reaches the POST (the screen does not over-block)", pub.ok === true && (fetched as boolean) === true);
    } finally {
      globalThis.fetch = realFetch;
    }
  }
}

// ---- TC-N-12: validateRule -----------------------------------------------------------------

function testValidateRule(): void {
  // valid global rule
  {
    const r = validateRule({ scope: { kind: "global" }, minSeverity: "warning", events: ["backup-failure", "backup-stale"], channelIds: ["c1"], enabled: true });
    ok("validateRule: valid global rule ok", r.ok === true);
    if (r.ok) ok("validateRule: digest absent when not set", r.rule.digest === undefined);
  }
  // valid downpipe-scoped rule with "all" events and digest
  {
    const r = validateRule({ scope: { kind: "downpipe", downpipeId: "pipe-1" }, minSeverity: "info", events: "all", channelIds: ["c1", "c2"], digest: "daily", enabled: true });
    ok("validateRule: valid downpipe rule with all + digest ok", r.ok === true);
    if (r.ok) ok("validateRule: digest preserved", r.rule.digest === "daily" && r.rule.events === "all");
  }
  // bad scope
  ok("validateRule: bad scope kind rejected", validateRule({ scope: { kind: "team" }, minSeverity: "info", events: "all", channelIds: ["c1"], enabled: true }).ok === false);
  ok("validateRule: downpipe scope without id rejected", validateRule({ scope: { kind: "downpipe" }, minSeverity: "info", events: "all", channelIds: ["c1"], enabled: true }).ok === false);
  // bad minSeverity
  ok("validateRule: bad minSeverity rejected", validateRule({ scope: { kind: "global" }, minSeverity: "urgent", events: "all", channelIds: ["c1"], enabled: true }).ok === false);
  // bad events
  ok("validateRule: unknown event rejected", validateRule({ scope: { kind: "global" }, minSeverity: "info", events: ["nope"], channelIds: ["c1"], enabled: true }).ok === false);
  ok("validateRule: empty events array rejected", validateRule({ scope: { kind: "global" }, minSeverity: "info", events: [], channelIds: ["c1"], enabled: true }).ok === false);
  // bad channelIds
  ok("validateRule: empty channelIds rejected", validateRule({ scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [], enabled: true }).ok === false);
  // bad digest
  ok("validateRule: bad digest rejected", validateRule({ scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: ["c1"], digest: "hourly", enabled: true }).ok === false);
  // bad enabled
  ok("validateRule: non-boolean enabled rejected", validateRule({ scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: ["c1"], enabled: "yes" }).ok === false);
}

// ---- TC-N-13: ruleSelects + resolveDelivery (routing resolution, contract section 2.3) ----

function ch(id: string, over: Partial<NotifyChannel> = {}): NotifyChannel {
  return { id, kind: "webhook", name: id, url: `https://${id}.example.com/h`, enabled: true, createdAt: "2026-01-01T00:00:00.000Z", ...over };
}
function rule(id: string, over: Partial<NotifyRule>): NotifyRule {
  return { id, scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [], enabled: true, ...over } as NotifyRule;
}

// ruleSelects: scope, severity gate and events-list matching.
function testRuleSelects(): void {
  // ruleSelects: disabled rule selects nothing
  ok("ruleSelects: disabled rule -> false", ruleSelects(rule("r", { enabled: false }), "backup-failure", "critical", "p1") === false);
  // ruleSelects: global matches any downpipe
  ok("ruleSelects: global matches downpipe event", ruleSelects(rule("r", { scope: { kind: "global" } }), "backup-failure", "critical", "p1") === true);
  // ruleSelects: downpipe-scoped only matches its downpipe
  ok("ruleSelects: downpipe rule matches its id", ruleSelects(rule("r", { scope: { kind: "downpipe", downpipeId: "p1" } }), "backup-failure", "critical", "p1") === true);
  ok("ruleSelects: downpipe rule does not match other id", ruleSelects(rule("r", { scope: { kind: "downpipe", downpipeId: "p1" } }), "backup-failure", "critical", "p2") === false);
  // ruleSelects: minSeverity gate
  ok("ruleSelects: below minSeverity -> false", ruleSelects(rule("r", { minSeverity: "critical" }), "backup-stale", "warning", "p1") === false);
  ok("ruleSelects: at minSeverity -> true", ruleSelects(rule("r", { minSeverity: "warning" }), "backup-stale", "warning", "p1") === true);
  // ruleSelects: events list
  ok("ruleSelects: event in list -> true", ruleSelects(rule("r", { events: ["backup-failure"] }), "backup-failure", "critical", "p1") === true);
  ok("ruleSelects: event not in list -> false", ruleSelects(rule("r", { events: ["backup-stale"] }), "backup-failure", "critical", "p1") === false);
}

// resolveDelivery: channel resolution, dedupe, per-downpipe override, disabled/unknown skip and the
// success-class digest routing.
function testResolveDelivery(): void {
  // resolveDelivery: global rule selects its channels
  {
    const channels = [ch("c1"), ch("c2")];
    const rules = [rule("g", { channelIds: ["c1"] })];
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: global rule -> c1 now", r.now.length === 1 && r.now[0]?.id === "c1");
    ok("resolveDelivery: no digest for failure", r.digested.length === 0);
  }
  // resolveDelivery: dedupe a channel named by two matching rules
  {
    const channels = [ch("c1")];
    const rules = [rule("g1", { channelIds: ["c1"] }), rule("g2", { channelIds: ["c1"] })];
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: dedupes channel across rules", r.now.length === 1);
  }
  // resolveDelivery: per-downpipe rule OVERRIDES the global default for that event class
  {
    const channels = [ch("global-ch"), ch("dp-ch")];
    const rules = [
      rule("g", { scope: { kind: "global" }, channelIds: ["global-ch"] }),
      rule("d", { scope: { kind: "downpipe", downpipeId: "p1" }, channelIds: ["dp-ch"] }),
    ];
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: per-downpipe override wins (only dp-ch)", r.now.length === 1 && r.now[0]?.id === "dp-ch");
  }
  // resolveDelivery: a downpipe rule for a DIFFERENT event does not override the global for this event
  {
    const channels = [ch("global-ch"), ch("dp-ch")];
    const rules = [
      rule("g", { scope: { kind: "global" }, channelIds: ["global-ch"] }),
      rule("d", { scope: { kind: "downpipe", downpipeId: "p1" }, events: ["backup-stale"], channelIds: ["dp-ch"] }),
    ];
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: global applies when no downpipe rule matches this event", r.now.length === 1 && r.now[0]?.id === "global-ch");
  }
  // resolveDelivery: disabled channel skipped
  {
    const channels = [ch("c1", { enabled: false })];
    const rules = [rule("g", { channelIds: ["c1"] })];
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: disabled channel skipped", r.now.length === 0);
  }
  // resolveDelivery: unknown channelId skipped
  {
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, [rule("g", { channelIds: ["nope"] })], []);
    ok("resolveDelivery: unknown channelId skipped", r.now.length === 0);
  }
  // resolveDelivery: success-class on a digest rule -> digested, not now
  {
    const channels = [ch("c1")];
    const rules = [rule("g", { events: ["backup-success"], minSeverity: "info", digest: "daily", channelIds: ["c1"] })];
    const r = resolveDelivery({ event: "backup-success", severity: "info", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: success on digest rule -> digested", r.digested.length === 1 && r.digested[0]?.id === "c1");
    ok("resolveDelivery: success on digest rule -> nothing now", r.now.length === 0);
  }
  // resolveDelivery: a FAILURE on a digest rule is NOT digested (only success-class is)
  {
    const channels = [ch("c1")];
    const rules = [rule("g", { events: "all", minSeverity: "info", digest: "daily", channelIds: ["c1"] })];
    const r = resolveDelivery({ event: "backup-failure", severity: "critical", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: failure on digest rule still delivered now", r.now.length === 1 && r.digested.length === 0);
  }
  // resolveDelivery: immediate wins over digest for the same channel
  {
    const channels = [ch("c1")];
    const rules = [
      rule("nowRule", { events: ["backup-success"], minSeverity: "info", channelIds: ["c1"] }), // no digest -> now
      rule("digRule", { events: ["backup-success"], minSeverity: "info", digest: "weekly", channelIds: ["c1"] }), // digest
    ];
    const r = resolveDelivery({ event: "backup-success", severity: "info", downpipeId: "p1" }, rules, channels);
    ok("resolveDelivery: immediate wins over digest for same channel", r.now.length === 1 && r.digested.length === 0);
  }
}

// ---- TC-N-14: channel formatters carry only the redaction-safe surface --------------------

function testFormatters(): void {
  const emission = {
    event: "backup-failure" as NotifyEvent,
    severity: "critical" as Severity,
    downpipeId: "pipe-x",
    downpipeName: "Prod KV",
    detail: "Prod KV last run failed",
    at: "2026-06-09T00:00:00.000Z",
  };
  // webhook v1
  {
    const p = formatWebhook(emission);
    ok("formatWebhook: kind is downpipe-event-v1", p.kind === "downpipe-event-v1");
    ok("formatWebhook: carries event/severity/detail", p.event === "backup-failure" && p.severity === "critical" && p.detail === "Prod KV last run failed");
    ok("formatWebhook: downpipe present", p.downpipe?.id === "pipe-x" && p.downpipe?.name === "Prod KV");
    const allowed = new Set(["kind", "at", "event", "severity", "downpipe", "detail"]);
    ok("formatWebhook: no extra keys", Object.keys(p).every((k) => allowed.has(k)));
  }
  // webhook v1 with no downpipe (account-level event)
  {
    const p = formatWebhook({ ...emission, downpipeId: null, downpipeName: null });
    ok("formatWebhook: downpipe omitted for account-level event", !("downpipe" in p));
  }
  // slack
  {
    const p = formatSlack(emission);
    ok("formatSlack: text contains detail", p.text.includes("Prod KV last run failed"));
    ok("formatSlack: has a section block", Array.isArray(p.blocks) && p.blocks.length === 1);
  }
  // pagerduty trigger
  {
    const channel: NotifyChannel = { id: "pd", kind: "pagerduty", name: "PD", routingKey: "R123", enabled: true, createdAt: emission.at };
    const p = formatPagerDuty(channel, emission);
    ok("formatPagerDuty: routing_key from channel", p.routing_key === "R123");
    ok("formatPagerDuty: event_action trigger", p.event_action === "trigger");
    ok("formatPagerDuty: summary is the detail", p.payload.summary === "Prod KV last run failed");
    ok("formatPagerDuty: severity mapped", p.payload.severity === "critical");
    ok("formatPagerDuty: dedup_key stable per downpipe+event", p.dedup_key === "downpipe:pipe-x:backup-failure");
  }
  // pagerduty resolve (recovered)
  {
    const channel: NotifyChannel = { id: "pd", kind: "pagerduty", name: "PD", routingKey: "R123", enabled: true, createdAt: emission.at };
    const p = formatPagerDuty(channel, { ...emission, recovered: true });
    ok("formatPagerDuty: recovered -> resolve action", p.event_action === "resolve");
  }
  // teams card
  {
    const p = formatTeamsCard(emission);
    ok("formatTeamsCard: MessageCard type", p["@type"] === "MessageCard");
    ok("formatTeamsCard: text is the detail", p.text === "Prod KV last run failed");
  }
  // email
  {
    const m = formatEmail(["ops@example.com"], emission);
    ok("formatEmail: to is the addresses", m.to.length === 1 && m.to[0] === "ops@example.com");
    ok("formatEmail: subject names severity + event", m.subject.includes("critical") && m.subject.includes("backup-failure"));
    ok("formatEmail: body contains the detail", m.text.includes("Prod KV last run failed"));
    // no secret: the body is built only from the emission's safe surface
    ok("formatEmail: body does not contain a url/key field", !/https?:|secret|key=/i.test(m.text));
    // the html twin is the same safe surface in the branded card: no link, no secret, no vendor identity
    // (engine mail is sent by the customer's own engine to their own team)
    ok("formatEmail: html is the branded card", typeof m.html === "string" && m.html.includes("<!doctype html>") && m.html.includes(">downpipes</div>"));
    ok("formatEmail: html contains the detail", (m.html ?? "").includes("Prod KV last run failed"));
    ok("formatEmail: html carries no link or key field", !/https?:|secret|key=/i.test(m.html ?? ""));
    ok("formatEmail: html carries no vendor sign-off", !/Maelstrom/.test(m.html ?? ""));
  }
}

// ---- TC-N-14b: redactChannelSecretForRead (the operator-facing list read redacts the sealed apiKey) ----
// The GET /notify/channels list projection must strip a jsm/servicenow apiKey to a presence-only flag, so a
// notify.config holder never reads the credential's value (even on the CONFIG_WRAP_KEY-absent plaintext
// floor). The url/username stay (a sink locator + a non-secret account name); only the sealed apiKey goes.
function testRedactChannelSecretForRead(): void {
  const jsmCh: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-secret-TOKEN", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
  const redacted = redactChannelSecretForRead(jsmCh) as Record<string, unknown>;
  ok("redact: the apiKey value is removed from the read projection", !("apiKey" in redacted));
  ok("redact: apiKeyPresent:true reports a credential IS configured (presence-only)", redacted.apiKeyPresent === true);
  ok("redact: the non-secret fields survive (url/kind/name)", redacted.url === "https://api.opsgenie.com/v2/alerts" && redacted.kind === "jsm" && redacted.name === "Ops");
  ok("redact: the serialised projection never contains the token", !JSON.stringify(redacted).includes("genie-secret-TOKEN"));
  // servicenow: the username (a non-secret account name) survives; the password (apiKey) does not.
  const snowCh: NotifyChannel = { id: "c2", kind: "servicenow", name: "SNOW", url: "https://instance.service-now.com/api/now/table/em_event", username: "svc", apiKey: "s3cr3t-PW", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
  const redactedSnow = redactChannelSecretForRead(snowCh) as Record<string, unknown>;
  ok("redact: servicenow username survives (non-secret), password redacted", redactedSnow.username === "svc" && !("apiKey" in redactedSnow) && redactedSnow.apiKeyPresent === true && !JSON.stringify(redactedSnow).includes("s3cr3t-PW"));
  // A channel with NO apiKey (webhook) carries no apiKeyPresent flag and is otherwise unchanged.
  const webhookCh: NotifyChannel = { id: "c3", kind: "webhook", name: "SIEM", url: "https://siem.example.com/h", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
  const redactedWebhook = redactChannelSecretForRead(webhookCh) as Record<string, unknown>;
  ok("redact: a channel with no apiKey carries no apiKeyPresent flag", !("apiKeyPresent" in redactedWebhook) && redactedWebhook.url === "https://siem.example.com/h");
}

// runRouting runs the routing/validation/formatter groups in their original order.
export async function runRouting(): Promise<void> {
  console.log("severity mapping + helpers");
  testSeverityMapping();

  console.log("replication-degraded + run-at-risk-eviction vocabulary + detectors");
  testReplicationVocabularyAndDetectors();

  console.log("event wiring completeness (structural guard)");
  testEventWiringCompleteness();
  testEveryEventIsProducedSomewhere();
  testRestoreAppliedAlertContent();

  console.log("channel-kind wiring completeness (structural guard)");
  testChannelKindWiringCompleteness();

  console.log("validateChannel (per-kind)");
  testValidateChannel();

  console.log("deliverPayload SSRF re-check (send-time default-deny)");
  await testDeliverPayloadSsrf();

  console.log("validateRule");
  testValidateRule();

  console.log("ruleSelects + resolveDelivery (routing)");
  testRuleSelects();
  testResolveDelivery();

  console.log("channel formatters (redaction-safe surface)");
  testFormatters();

  console.log("redactChannelSecretForRead (list read redacts the sealed apiKey)");
  testRedactChannelSecretForRead();
}
