// Validates the SIEM audit-log push feature's PURE + drain-internal logic:
// the three format shapers (correct envelopes, the batch cap, the wire shapes the design doc documents),
// the bespoke egress-secure sender (send-time SSRF re-screen, the header carries the secret and the body
// NEVER does), the sealed-secret round-trip + AAD domain separation (a push ciphertext must not decrypt
// under the destination's AAD), the DO's cursor advance-on-2xx/hold-on-failure + bounded trail + derived
// failureCount, and the full cron drain pass end to end (runSiemPushPass) against a fake scheduler + a
// mocked fetch. The admin ROUTER surface (owner gate, dual control, audit, redaction) is validated
// separately in test/validate-siem-push-router.ts. No network. Run:
//   node test/validate-siem-push.ts

import { shapeRawJson, shapeSplunkHec, shapeDatadog, shapeNdjson, shapeJsonArray, shapeCef, shapeLeef, shapeGelf, shapeForFormat, buildSyntheticPushEvent, SIEM_PUSH_BATCH_CAP, type PushCursorMeta } from "../src/cron/siem-push-shape.ts";
import { runSiemPushPass, fetchPushConfig, deliverResolvedPush, type ResolvedPushConfig } from "../src/cron/siem-push-pass.ts";
import { deliverSiemPush } from "../src/notify/siem-push-sender.ts";
import { wrapConfigSecret, unwrapConfigSecret, resolveConfigSecret, maybeWrapConfigSecret, PUSH_SECRET_AAD, PUSH_S3_SECRET_AAD, type WrappedSecret } from "../src/admin/config-secret.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
// PUSH_FORMATS comes from scheduler-do-limits.ts, the ONE authority buildPushRecord itself validates
// against, and never from a copy: a list this file re-typed could agree with itself while the engine
// enforced something else.
import { PUSH_FORMATS } from "../src/sched/scheduler-do-limits.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";

// ALL_FORMATS is the single source of truth for the per-format loops below (mirrors the PushFormat union), so
// a new format is exercised by every loop from one edit rather than several hand-literal lists drifting apart.
const ALL_FORMATS = ["raw-json", "ndjson", "json-array", "splunk-hec", "datadog", "cef", "leef", "gelf"] as const;

// "Mirrors the PushFormat union" was a COMMENT, not a check. A ninth format added to the engine and not to
// this literal would be covered by no loop in this file, and every loop would still pass -- the suite would
// report green over an entirely untested format. assertFormatListComplete ties the list to the DO's own
// runtime allow-list (the set buildPushRecord actually validates against) in BOTH directions.
//
// Deliberately a RUNTIME assertion, not a type-level one: tsconfig.json has "include": ["src"], so nothing
// under test/ is typechecked at all and a compile-time guard placed here would never run.
function assertFormatListComplete(ok: (label: string, cond: boolean) => void): void {
  const listed = [...ALL_FORMATS].sort();
  const enforced = [...PUSH_FORMATS].sort();
  ok(
    `format matrix completeness: ALL_FORMATS (${listed.length}) is EXACTLY the DO's enforced PUSH_FORMATS (${enforced.length}) -- a new format cannot be silently untested`,
    listed.length === enforced.length && listed.every((f, i) => f === enforced[i]),
  );
  // A suite that loops over an EMPTY list passes every loop while proving nothing. Refuse that outright.
  ok("format matrix completeness: the format list is non-empty", listed.length > 0);
}

// decodeBody renders a captured fetch body (a Uint8Array from the S3 client, or a string) back to text for
// the body-content assertions.
function decodeBody(body: unknown): string {
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  return String(body ?? "");
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
async function throwsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    ok(label, false);
  } catch {
    ok(label, true);
  }
}

// ---- fixtures ------------------------------------------------------------------------------------------
function fakeEvent(seq: number, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq,
    ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
    actorSubject: "https://acct.cloudflareaccess.com|sub-of-owner@example.com",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "access-policy" },
    prevHash: `sha384:${"a".repeat(96)}`,
    hash: `sha384:${"b".repeat(96)}`,
    ...overrides,
  };
}

import { MockStorage } from "./mock-storage.ts";

const OWNER_CALLER = { method: "token" as const, email: null, subject: null, groups: [] };

async function main(): Promise<void> {
  console.log("format matrix completeness: the per-format loops cover every format the engine accepts");
  assertFormatListComplete(ok);

  console.log("shapers: envelope correctness (the documented wire shapes)");
  {
    const events = [fakeEvent(101), fakeEvent(102)];
    const meta: PushCursorMeta = { afterSeq: 100, nextAfterSeq: 102, headSeq: 150, headHash: "sha384:head" };

    const raw = shapeRawJson(events, meta);
    const rawDoc = JSON.parse(raw.body) as { kind: string; v: number; afterSeq: number; nextAfterSeq: number; headSeq: number; headHash: string; count: number; events: unknown[] };
    ok("raw-json: kind/v pin the schema (the pull feed's own shape)", rawDoc.kind === "downpipe-audit-feed" && rawDoc.v === 1);
    ok("raw-json: cursor meta round-trips", rawDoc.afterSeq === 100 && rawDoc.nextAfterSeq === 102 && rawDoc.headSeq === 150 && rawDoc.headHash === "sha384:head");
    ok("raw-json: count + events", rawDoc.count === 2 && rawDoc.events.length === 2);
    ok("raw-json: content-type", raw.contentType === "application/json");

    const hec = shapeSplunkHec(events, meta);
    const hecLines = hec.body.split("\n");
    ok("splunk-hec: one HEC object per event, newline-concatenated", hecLines.length === 2);
    const hecDoc0 = JSON.parse(hecLines[0]!) as { time: number; source: string; sourcetype: string; event: { seq: number } };
    ok("splunk-hec: source/sourcetype", hecDoc0.source === "downpipes" && hecDoc0.sourcetype === "downpipe:audit");
    ok("splunk-hec: time is epoch SECONDS", hecDoc0.time === Math.floor(Date.parse(events[0]!.ts) / 1000));
    ok("splunk-hec: event carries the full audit record", hecDoc0.event.seq === 101);

    const dd = shapeDatadog(events, meta);
    const ddDoc = JSON.parse(dd.body) as Array<{ ddsource: string; service: string; message: string; status: string; seq: number; action: string; outcome: string }>;
    ok("datadog: a JSON array (not NDJSON)", Array.isArray(ddDoc) && ddDoc.length === 2);
    ok(
      "datadog: ddsource/service/message + the flattened event fields",
      ddDoc[0]!.ddsource === "downpipes" && ddDoc[0]!.service === "downpipe-engine" && ddDoc[0]!.seq === 101 && ddDoc[0]!.action === "dest-config-set" && ddDoc[0]!.message.includes("dest-config-set"),
    );
    // status maps the outcome so Datadog's severity facet is accurate (never defaulting every event
    // to "info" for lack of the field).
    ok("datadog: a success outcome maps status:info", ddDoc[0]!.outcome === "success" && ddDoc[0]!.status === "info");
    {
      const outcomeEvents = [fakeEvent(201, { outcome: "success" }), fakeEvent(202, { outcome: "denied" }), fakeEvent(203, { outcome: "failed" })];
      const ddOutcomes = JSON.parse(shapeDatadog(outcomeEvents, meta).body) as Array<{ outcome: string; status: string }>;
      ok("datadog: success -> status:info", ddOutcomes[0]!.outcome === "success" && ddOutcomes[0]!.status === "info");
      ok("datadog: denied -> status:warning", ddOutcomes[1]!.outcome === "denied" && ddOutcomes[1]!.status === "warning");
      ok("datadog: failed -> status:error (never read as a success in Datadog's severity facet)", ddOutcomes[2]!.outcome === "failed" && ddOutcomes[2]!.status === "error");
    }

    // ndjson: one RAW event object per line (the split-friendly default).
    const nd = shapeNdjson(events, meta);
    const ndLines = nd.body.split("\n");
    ok("ndjson: one raw event object per line, application/x-ndjson", ndLines.length === 2 && nd.contentType === "application/x-ndjson");
    ok("ndjson: each line is the RAW audit event (seq round-trips, no wrapper)", (JSON.parse(ndLines[0]!) as { seq: number }).seq === 101 && !("kind" in JSON.parse(ndLines[0]!)));

    // json-array: a bare [event, ...] array (not NDJSON).
    const ja = shapeJsonArray(events, meta);
    const jaDoc = JSON.parse(ja.body) as Array<{ seq: number }>;
    ok("json-array: a bare JSON array of the raw events, application/json", Array.isArray(jaDoc) && jaDoc.length === 2 && jaDoc[0]!.seq === 101 && ja.contentType === "application/json");

    // cef: one ArcSight CEF line per event; 7 mandatory header fields; the action is the Device Event Class ID.
    const cef = shapeCef(events, meta);
    const cefLines = cef.body.split("\n");
    ok("cef: one line per event, text/plain", cefLines.length === 2 && cef.contentType === "text/plain; charset=utf-8");
    ok("cef: the header carries version 0, our vendor/product and the action as the Device Event Class ID", cefLines[0]!.startsWith("CEF:0|Maelstrom AI|Downpipes|") && cefLines[0]!.includes("|dest-config-set|"));
    ok("cef: the extension maps the scalar + custom fields (rt/suser/src/act/cs*/cn1/flexString1)", cefLines[0]!.includes("suser=owner@example.com") && cefLines[0]!.includes("act=dest-config-set") && cefLines[0]!.includes("cn1Label=seq") && cefLines[0]!.includes("cn1=101") && cefLines[0]!.includes("flexString1Label=hash"));

    // leef: one IBM LEEF 2.0 line per event; the explicit '^' delimiter; the reserved + plain keys.
    const leef = shapeLeef(events, meta);
    const leefLines = leef.body.split("\n");
    ok("leef: one line per event, text/plain", leefLines.length === 2 && leef.contentType === "text/plain; charset=utf-8");
    ok("leef: the header declares LEEF:2.0, our vendor/product, the action EventID and the '^' delimiter", leefLines[0]!.startsWith("LEEF:2.0|Maelstrom AI|Downpipes|") && leefLines[0]!.includes("|dest-config-set|^|"));
    ok("leef: the attributes use the '^' delimiter with reserved + plain keys (devTime/usrName/src/action/seq)", leefLines[0]!.includes("devTime=") && leefLines[0]!.includes("^usrName=owner@example.com") && leefLines[0]!.includes("^action=dest-config-set") && leefLines[0]!.includes("^seq=101"));

    // gelf: one Graylog GELF 1.1 object per line; flat _-prefixed custom fields; never _id.
    const gelf = shapeGelf(events, meta);
    const gelfLines = gelf.body.split("\n");
    const gelfDoc0 = JSON.parse(gelfLines[0]!) as Record<string, unknown>;
    ok("gelf: one GELF object per line, application/json", gelfLines.length === 2 && gelf.contentType === "application/json");
    ok("gelf: version/host/short_message mandatory + timestamp is epoch SECONDS", gelfDoc0.version === "1.1" && gelfDoc0.host === "downpipes" && typeof gelfDoc0.short_message === "string" && gelfDoc0.timestamp === Date.parse(events[0]!.ts) / 1000);
    ok("gelf: custom fields are FLAT and _-prefixed (target flattened), and the reserved _id is never emitted", gelfDoc0._seq === 101 && gelfDoc0._action === "dest-config-set" && "_targetKind" in gelfDoc0 && !("_id" in gelfDoc0));

    ok(
      "shapeForFormat dispatches identically to the direct call, for EVERY format",
      ALL_FORMATS.every((f) => shapeForFormat(f, events, meta).body === (f === "raw-json" ? raw : f === "ndjson" ? nd : f === "json-array" ? ja : f === "splunk-hec" ? hec : f === "datadog" ? dd : f === "cef" ? cef : f === "leef" ? leef : gelf).body),
    );
  }

  console.log("\nshapers: batch cap (Datadog's tightest limit is 1000 events / 5 MB; SIEM_PUSH_BATCH_CAP sits well under it)");
  {
    ok("SIEM_PUSH_BATCH_CAP is comfortably under Datadog's 1000-event cap", SIEM_PUSH_BATCH_CAP < 1000);
    const many = Array.from({ length: SIEM_PUSH_BATCH_CAP + 250 }, (_, i) => fakeEvent(i + 1));
    const meta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: many.length, headSeq: many.length, headHash: "h" };
    const rawCapped = JSON.parse(shapeRawJson(many, meta).body) as { events: unknown[]; count: number };
    ok("raw-json caps at SIEM_PUSH_BATCH_CAP even when handed more", rawCapped.events.length === SIEM_PUSH_BATCH_CAP && rawCapped.count === SIEM_PUSH_BATCH_CAP);
    ok("splunk-hec caps at SIEM_PUSH_BATCH_CAP", shapeSplunkHec(many, meta).body.split("\n").length === SIEM_PUSH_BATCH_CAP);
    ok("datadog caps at SIEM_PUSH_BATCH_CAP", (JSON.parse(shapeDatadog(many, meta).body) as unknown[]).length === SIEM_PUSH_BATCH_CAP);
    // Every format enforces the cap itself (not only the caller): a line-based format yields exactly cap
    // lines; an array/raw-json format yields exactly cap elements.
    for (const f of ALL_FORMATS) {
      const shaped = shapeForFormat(f, many, meta);
      const n = f === "json-array" || f === "datadog" ? (JSON.parse(shaped.body) as unknown[]).length : f === "raw-json" ? (JSON.parse(shaped.body) as { events: unknown[] }).events.length : shaped.body.split("\n").length;
      ok(`${f} caps at SIEM_PUSH_BATCH_CAP even when handed more`, n === SIEM_PUSH_BATCH_CAP);
    }
    // A realistic WORST-CASE byte-size check: every event carries generously-sized bounded free-text fields
    // (a restore reason at its REASON_MAX_LEN=1000 cap), and a full-cap batch still serialises comfortably
    // under Datadog's 5 MB request limit (the widest of the three shapes, since it repeats the field names).
    const worstCase = Array.from({ length: SIEM_PUSH_BATCH_CAP }, (_, i) =>
      fakeEvent(i + 1, {
        target: { kind: "restore", runId: `run-${i}-${"x".repeat(40)}`, redirectBinding: "SOME_BINDING_NAME", planHash: `sha384:${"c".repeat(96)}`, isLatest: true, reason: "R".repeat(1000), approverEmail: "approver@example.com", approverSubject: "sub-approver" },
      }),
    );
    const worstBody = shapeDatadog(worstCase, meta).body;
    ok(`a full-cap batch of worst-case-sized events serialises under Datadog's 5 MB cap (got ${worstBody.length} bytes)`, worstBody.length < 5_000_000);
  }

  console.log("\ndeliverSiemPush: the auth header carries the secret; the body NEVER does (non-negotiable invariant 1)");
  {
    const events = [fakeEvent(1), fakeEvent(2), fakeEvent(3)];
    const meta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 3, headSeq: 3, headHash: "h" };
    const SECRET = "xoxb-super-secret-hec-token-DO-NOT-LEAK-9f3a7c21";
    const realFetch = globalThis.fetch;
    // captures is an APPEND-ONLY log (never a nullable `let` reassigned inside the closure): reading the
    // last entry via array indexing sidesteps a TypeScript control-flow narrowing hazard where a bare `let`
    // reassigned only inside an opaquely-invoked closure gets narrowed to `never` at a later read (the same
    // hazard validate-beacon-emit.ts's resetPosted() comment documents for the simpler equality-only case).
    const captures: Array<{ headers: Record<string, string>; body: string }> = [];
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    try {
      for (const format of ALL_FORMATS) {
        captures.length = 0;
        const shaped = shapeForFormat(format, events, meta);
        const r = await deliverSiemPush("https://siem.example.com/ingest", shaped.body, shaped.contentType, "Authorization", SECRET);
        const last = captures[captures.length - 1];
        ok(`${format}: deliverSiemPush reports ok:true + the status on a 200`, r.ok === true && r.status === 200);
        ok(`${format}: the configured auth header carries the secret`, last?.headers.Authorization === SECRET);
        ok(`${format}: the request BODY never contains the secret`, last?.body.includes(SECRET) !== true);
        ok(`${format}: the content-type matches the shaper's`, last?.headers["content-type"] === shaped.contentType);
      }
      // A custom header name (Datadog's DD-API-KEY) carries the secret under that exact name.
      captures.length = 0;
      const dd = shapeForFormat("datadog", events, meta);
      await deliverSiemPush("https://http-intake.logs.example.com/api/v2/logs", dd.body, dd.contentType, "DD-API-KEY", SECRET);
      const ddLast = captures[captures.length - 1];
      ok("a non-default header name (DD-API-KEY) carries the secret under that exact name", ddLast?.headers["DD-API-KEY"] === SECRET);
      ok("the body still never contains the secret under a custom header name", ddLast?.body.includes(SECRET) !== true);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliverSiemPush: send-time SSRF re-screen (defence in depth; invariant 3)");
  {
    const r1 = await deliverSiemPush("https://169.254.169.254/latest/meta-data/", "{}", "application/json", "Authorization", "s");
    ok("an internal-literal (cloud metadata) target is refused before any fetch, never throws", r1.ok === false && r1.code === "internal-sink-blocked");
    const r2 = await deliverSiemPush("https://127.0.0.1/x", "{}", "application/json", "Authorization", "s");
    ok("a loopback target is refused", r2.ok === false && r2.code === "internal-sink-blocked");
    const r3 = await deliverSiemPush("not a url", "{}", "application/json", "Authorization", "s");
    ok("an unparseable url is refused (url-invalid), never throws", r3.ok === false && r3.code === "url-invalid");
  }

  console.log("\nsealed-secret round-trip + AAD domain separation (invariant 2's crypto half)");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const SECRET = "dd-api-key-abcdef0123456789";
    const wrapped = await wrapConfigSecret(KEY, SECRET, PUSH_SECRET_AAD);
    ok("wrap+unwrap round-trips under the push AAD", (await unwrapConfigSecret(KEY, wrapped, PUSH_SECRET_AAD)) === SECRET);
    await throwsAsync("a push ciphertext does NOT decrypt under the DEST (default) AAD -- domain separation", async () => unwrapConfigSecret(KEY, wrapped));
    const wrapped2 = await maybeWrapConfigSecret(KEY, SECRET, PUSH_SECRET_AAD);
    ok("maybeWrapConfigSecret(aad) with a key produces an envelope", typeof wrapped2 !== "string");
    ok("resolveConfigSecret(aad) resolves it back to plaintext", (await resolveConfigSecret(KEY, wrapped2, PUSH_SECRET_AAD)) === SECRET);
    await throwsAsync("resolveConfigSecret with the WRONG (default/dest) aad fails to open a push envelope", async () => resolveConfigSecret(KEY, wrapped2 as WrappedSecret));
    // Existing 2-arg call sites (every destination credential call) are BYTE-IDENTICAL: no aad passed still
    // means CONFIG_SECRET_AAD, so this change is additive, not a behaviour change for existing callers.
    const destWrapped = await wrapConfigSecret(KEY, SECRET);
    ok("a 2-arg wrap (no aad argument) still uses CONFIG_SECRET_AAD (back-compat, unchanged)", (await unwrapConfigSecret(KEY, destWrapped)) === SECRET);
    ok("maybeWrapConfigSecret with NO key still floors to plaintext (unchanged back-compat path)", (await maybeWrapConfigSecret(undefined, SECRET, PUSH_SECRET_AAD)) === SECRET);
  }

  console.log("\nDO: cursor advances on 2xx, holds on failure; bounded trail; failureCount derived from the trail (invariant 2's storage half)");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await dobj.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true }, OWNER_CALLER);
    ok("cursor starts at 0", (await dobj.getSiemPushCursor()) === 0);
    // Every drain outcome carries the config's generation id (the straggler guard). Read it once here; the
    // real drain reads it from the config it just fetched, so this mirrors production.
    const gen0 = (await dobj.getSiemPushRecordRaw())!.gen;
    ok("the stored config carries a generation id (crypto.randomUUID)", typeof gen0 === "string" && gen0.length > 0);

    const view0 = await dobj.getSiemPushView();
    ok("getSiemPushView NEVER carries the secret, its ciphertext OR the gen (invariant 5's DO-level half)", !JSON.stringify(view0).includes("sekret-value") && !("authHeaderValue" in view0) && !("gen" in view0));
    ok("getSiemPushView reports the set fields honestly", view0.present === true && view0.endpoint === "https://siem.example.com/ingest" && view0.format === "raw-json" && view0.authHeaderName === "Authorization" && view0.enabled === true);

    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 5, fromSeq: 0, toSeq: 50, gen: gen0 });
    ok("a 2xx advances the cursor to toSeq", (await dobj.getSiemPushCursor()) === 50);

    await dobj.recordSiemPushOutcome({ ok: false, httpStatus: 503, reason: "http-5xx", count: 3, fromSeq: 50, toSeq: 80, gen: gen0 });
    ok("a failure HOLDS the cursor (at-least-once retry next tick)", (await dobj.getSiemPushCursor()) === 50);
    const trail1 = await dobj.getSiemPushTrail();
    ok("both attempts landed on the trail, in order", trail1.length === 2 && trail1[0]!.ok === true && trail1[1]!.ok === false && trail1[1]!.reason === "http-5xx");

    const audit1 = await dobj.readAudit(new URLSearchParams());
    const failure1 = audit1.events.find((e) => e.action === "push-delivery-failure");
    ok("a push-delivery-failure audit event was recorded", failure1 !== undefined);
    ok(
      "its target is the CLOSED push-destination shape: op + failureCount only, no free-form field",
      failure1?.target.kind === "push-destination" && (failure1.target as { op?: string }).op === "delivery-failure" && (failure1.target as { failureCount?: number }).failureCount === 1,
    );

    await dobj.recordSiemPushOutcome({ ok: false, httpStatus: 500, reason: "http-5xx", count: 3, fromSeq: 50, toSeq: 80, gen: gen0 });
    ok("cursor still held after a second consecutive failure", (await dobj.getSiemPushCursor()) === 50);
    // readAudit (like GET /admin/audit) returns NEWEST-first; latestFailureCount finds the highest-seq
    // push-delivery-failure entry regardless of array order, so this does not depend on that convention.
    const latestFailureCount = async (): Promise<number | undefined> => {
      const failures = (await dobj.readAudit(new URLSearchParams())).events.filter((e) => e.action === "push-delivery-failure");
      const latest = failures.reduce((a, b) => (b.seq > a.seq ? b : a));
      return (latest.target as { failureCount?: number }).failureCount;
    };
    ok("the second consecutive failure's failureCount is 2", (await latestFailureCount()) === 2);

    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 2, fromSeq: 50, toSeq: 90, gen: gen0 });
    ok("a subsequent success advances the cursor again", (await dobj.getSiemPushCursor()) === 90);

    // MONOTONIC: an overlapping tick whose toSeq is LOWER than the current cursor never regresses it.
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 1, fromSeq: 20, toSeq: 40, gen: gen0 });
    ok("a lower toSeq from an overlapping tick does NOT regress the cursor (max, never backward)", (await dobj.getSiemPushCursor()) === 90);

    await dobj.recordSiemPushOutcome({ ok: false, httpStatus: 500, reason: "http-5xx", count: 1, fromSeq: 90, toSeq: 95, gen: gen0 });
    ok("failureCount resets to 1 after an intervening success (CONSECUTIVE, not cumulative)", (await latestFailureCount()) === 1);

    for (let i = 0; i < 60; i++) await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 1, fromSeq: i, toSeq: i + 1, gen: gen0 });
    ok("the trail never exceeds its 50-entry cap", (await dobj.getSiemPushTrail()).length === 50);

    // Clearing wipes the cursor + trail (a destination configured again later starts clean).
    ok("clearSiemPushDestination succeeds for an owner", (await dobj.clearSiemPushDestination(OWNER_CALLER)).ok === true);
    ok("clear wipes the cursor", (await dobj.getSiemPushCursor()) === 0);
    ok("clear wipes the trail", (await dobj.getSiemPushTrail()).length === 0);
    ok("clear wipes the config (getSiemPushView reports present:false)", (await dobj.getSiemPushView()).present === false);
    const auditCleared = (await dobj.readAudit(new URLSearchParams())).events;
    ok("push-destination-cleared was recorded", auditCleared.some((e) => e.action === "push-destination-cleared"));
  }

  console.log("\nKEEP-SECRET: an absent/empty authHeaderValue on a later set keeps the existing sealed secret; a first set with no secret is rejected");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    // A first-ever set with NO secret is rejected (there is no existing secret to keep).
    await throwsAsync("a FIRST set with no authHeaderValue is rejected (needs a secret to create)", async () =>
      dobj.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", enabled: true }, OWNER_CALLER),
    );
    ok("nothing was stored by the rejected first create", (await dobj.getSiemPushRecordRaw()) === null);

    // Create WITH a secret, then set again WITHOUT one to toggle enabled + edit the format.
    await dobj.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "kept-secret-xyz", enabled: true }, OWNER_CALLER);
    const rec1 = (await dobj.getSiemPushRecordRaw())!;
    ok("the create stored the secret verbatim (DO holds no wrap key -> plaintext floor)", rec1.authHeaderValue === "kept-secret-xyz");

    await dobj.setSiemPushDestination({ endpoint: "https://siem2.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", enabled: false }, OWNER_CALLER);
    const rec2 = (await dobj.getSiemPushRecordRaw())!;
    ok("KEEP-SECRET: the auth header value is preserved across a set that omits it", rec2.authHeaderValue === "kept-secret-xyz");
    ok("KEEP-SECRET: the non-secret fields WERE updated (endpoint/format/header name/enabled)", rec2.endpoint === "https://siem2.example.com/ingest" && rec2.format === "datadog" && rec2.authHeaderName === "DD-API-KEY" && rec2.enabled === false);
    ok("the gen changed on the keep-secret replace (a fresh generation on every set)", rec2.gen !== rec1.gen);

    // "Still delivers": the kept secret resolves through the drain's read path to the original value.
    const resolved = await fetchPushConfig(
      { fetch: async () => new Response(JSON.stringify({ record: rec2 }), { status: 200 }) } as unknown as Parameters<typeof fetchPushConfig>[0],
      undefined,
    );
    ok("KEEP-SECRET still delivers: fetchPushConfig resolves the kept secret for the sender", resolved?.authHeaderValue === "kept-secret-xyz");

    // An explicit empty-string authHeaderValue is treated the same as absent (keep).
    await dobj.setSiemPushDestination({ endpoint: "https://siem2.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", authHeaderValue: "", enabled: true }, OWNER_CALLER);
    ok("KEEP-SECRET: an explicit EMPTY authHeaderValue also keeps the existing secret", (await dobj.getSiemPushRecordRaw())!.authHeaderValue === "kept-secret-xyz");

    // A later set WITH a new secret replaces it.
    await dobj.setSiemPushDestination({ endpoint: "https://siem2.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", authHeaderValue: "new-secret-abc", enabled: true }, OWNER_CALLER);
    ok("a set WITH a new secret replaces the kept one (rotation is re-enter)", (await dobj.getSiemPushRecordRaw())!.authHeaderValue === "new-secret-abc");
  }

  console.log("\nFORBIDDEN AUTH HEADER NAME: content-type (and runtime-controlled headers) are rejected at the DO");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    for (const name of ["content-type", "Content-Type", "CONTENT-TYPE", "host", "content-length", "connection"]) {
      await throwsAsync(`buildPushRecord/set rejects the forbidden auth header name "${name}"`, async () =>
        dobj.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: name, authHeaderValue: "s", enabled: true }, OWNER_CALLER),
      );
    }
    ok("nothing was stored by any forbidden-header rejection", (await dobj.getSiemPushRecordRaw()) === null);
    // A legitimate custom header name (DD-API-KEY) is NOT forbidden.
    await dobj.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", authHeaderValue: "s", enabled: true }, OWNER_CALLER);
    ok("DD-API-KEY (a real vendor header) is accepted", (await dobj.getSiemPushRecordRaw())!.authHeaderName === "DD-API-KEY");
  }

  console.log("\nSTRAGGLER: a delivery in flight when the owner clears/reconfigures cannot advance a stale cursor onto a new destination");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await dobj.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true }, OWNER_CALLER);
    const genA = (await dobj.getSiemPushRecordRaw())!.gen;
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 1, fromSeq: 0, toSeq: 50, gen: genA });
    ok("destination A drained to cursor 50", (await dobj.getSiemPushCursor()) === 50);

    // (i) Straggler after a plain CLEAR: no current config -> the outcome is dropped entirely.
    await dobj.clearSiemPushDestination(OWNER_CALLER);
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 3, fromSeq: 50, toSeq: 90, gen: genA });
    ok("a straggler after a clear is a NO-OP: no config, cursor stays wiped at 0", (await dobj.getSiemPushCursor()) === 0);
    ok("a straggler after a clear writes no trail entry (no live destination to describe)", (await dobj.getSiemPushTrail()).length === 0);

    // (ii) A NEW destination B configured after the clear starts at cursor 0; A's straggler cannot advance it.
    await dobj.setSiemPushDestination({ endpoint: "https://siem-b.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", authHeaderValue: "s2", enabled: true }, OWNER_CALLER);
    const genB = (await dobj.getSiemPushRecordRaw())!.gen;
    ok("the fresh destination B starts at cursor 0 (fresh-create reset)", (await dobj.getSiemPushCursor()) === 0);
    ok("B's gen differs from A's", genB !== genA);
    // The in-flight straggler from A (genA) arrives while B (genB) is live: gen mismatch -> dropped.
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 3, fromSeq: 50, toSeq: 90, gen: genA });
    ok("A's straggler CANNOT advance B's cursor (gen mismatch -> no-op): cursor stays 0, no events skipped", (await dobj.getSiemPushCursor()) === 0);
    ok("A's straggler writes no trail entry on B", (await dobj.getSiemPushTrail()).length === 0);
    // A live outcome for B (genB) advances B's own cursor normally.
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 2, fromSeq: 0, toSeq: 20, gen: genB });
    ok("a live (matching-gen) outcome advances B's cursor normally", (await dobj.getSiemPushCursor()) === 20);

    // (iii) An in-place REPLACE keeps the cursor but changes gen, so a pre-replace straggler is dropped.
    await dobj.setSiemPushDestination({ endpoint: "https://siem-b.example.com/ingest", format: "datadog", authHeaderName: "DD-API-KEY", enabled: false }, OWNER_CALLER);
    ok("an in-place replace KEEPS the cursor (not a fresh create)", (await dobj.getSiemPushCursor()) === 20);
    const genB2 = (await dobj.getSiemPushRecordRaw())!.gen;
    ok("the in-place replace minted a new gen", genB2 !== genB);
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 5, fromSeq: 20, toSeq: 999, gen: genB });
    ok("a straggler from before the in-place replace is dropped (stale gen): cursor unchanged at 20", (await dobj.getSiemPushCursor()) === 20);
  }

  console.log("\nbuildSyntheticPushEvent: a clearly-synthetic, shape-conformant event for the test-send route");
  {
    const synthetic = buildSyntheticPushEvent();
    const meta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 0, headSeq: 0, headHash: "" };
    ok("shapes cleanly under every format (no throw)", ALL_FORMATS.every((f) => typeof shapeForFormat(f, [synthetic], meta).body === "string"));
    ok("is unambiguously labelled as a test in its detail field", synthetic.target.kind === "engine-state" && synthetic.target.detail.toLowerCase().includes("test"));
  }

  console.log("\nrunSiemPushPass: full drain integration (opt-in gate; cursor advance/hold; false-green on a genuine fault)");
  {
    interface FakeState {
      record: { endpoint: string; format: "raw-json" | "splunk-hec" | "datadog"; authHeaderName: string; authHeaderValue: unknown; enabled: boolean; gen: string } | null;
      lastPushedSeq: number;
      events: AuditEvent[];
      recorded: Array<{ ok: boolean; httpStatus?: number; reason?: string; count: number; fromSeq: number; toSeq: number; gen?: string }>;
    }
    type Sched = Parameters<typeof runSiemPushPass>[1];
    function fakeScheduler(state: FakeState, opts?: { throwPath?: string }): Sched {
      return {
        fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
          const url = new URL(typeof input === "string" ? input : input.toString());
          if (opts?.throwPath && url.pathname === opts.throwPath) throw new Error(`simulated DO ${url.pathname} unavailable`);
          const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200 });
          if (url.pathname === "/push-config") return json({ record: state.record });
          if (url.pathname === "/push") return json({ present: state.record !== null, lastPushedSeq: state.lastPushedSeq, trail: [] });
          if (url.pathname === "/audit/export") {
            const afterSeq = Number(url.searchParams.get("afterSeq") ?? "0");
            const limit = Number(url.searchParams.get("limit") ?? "500");
            const matching = state.events.filter((e) => e.seq > afterSeq).slice(0, limit);
            const headSeq = state.events.length > 0 ? state.events[state.events.length - 1]!.seq : 0;
            return json({ events: matching, headSeq, headHash: "sha384:head" });
          }
          if (url.pathname === "/push-record") {
            state.recorded.push(JSON.parse(String(init?.body ?? "{}")) as FakeState["recorded"][number]);
            return json({ ok: true });
          }
          throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
        },
      } as unknown as Sched;
    }
    const env = { CONFIG_WRAP_KEY: undefined } as unknown as Env;
    const realFetch = globalThis.fetch;

    {
      // loadConfigWrapKey runs inside the pass's own try, so a malformed CONFIG_WRAP_KEY (present but not
      // base64url-of-32-bytes) throws loudly -- by design, so a misconfigured key is never mistaken for
      // "unset" -- but that throw must land on this pass's false-green path (return false), never escape
      // runSiemPushPass uncaught. A malformed key throws before any DO round-trip, so no route on the fake
      // scheduler is ever hit (throwing on any fetch proves that).
      const badKeyEnv = { CONFIG_WRAP_KEY: "not-valid-base64url-of-32-bytes" } as unknown as Env;
      const uncalledScheduler = { fetch: async (): Promise<Response> => { throw new Error("the DO must never be reached when CONFIG_WRAP_KEY is malformed"); } } as unknown as Sched;
      ok("a malformed CONFIG_WRAP_KEY returns false (the false-green signal), never a throw out of the pass", (await runSiemPushPass(badKeyEnv, uncalledScheduler)) === false);
    }
    {
      const state: FakeState = { record: null, lastPushedSeq: 0, events: [], recorded: [] };
      ok("opt-in: no destination configured -> true (silent no-op)", (await runSiemPushPass(env, fakeScheduler(state))) === true);
      ok("no outcome recorded when unconfigured", state.recorded.length === 0);
    }
    {
      const state: FakeState = { record: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: false, gen: "gen-disabled" }, lastPushedSeq: 0, events: [], recorded: [] };
      ok("opt-in: configured but DISABLED -> true (silent no-op)", (await runSiemPushPass(env, fakeScheduler(state))) === true);
      ok("no outcome recorded when disabled", state.recorded.length === 0);
    }
    {
      const state: FakeState = {
        record: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-ok" },
        lastPushedSeq: 0,
        events: [fakeEvent(1), fakeEvent(2), fakeEvent(3)],
        recorded: [],
      };
      // An append-only log, not a nullable `let` (see the captures[] note in the deliverSiemPush section
      // above): avoids the same TypeScript narrowing hazard.
      const captures: Array<{ headers: Record<string, string>; body: string }> = [];
      globalThis.fetch = (async (_url, init) => {
        captures.push({ headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
        return new Response("ok", { status: 200 });
      }) as typeof fetch;
      try {
        ok("a successful drain completes (true)", (await runSiemPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      const last = captures[captures.length - 1];
      ok("a request was actually captured", captures.length === 1);
      ok("the outbound request carried the secret in the configured header", last?.headers.Authorization === "sekret-value");
      ok("the outbound body never contains the secret", last?.body.includes("sekret-value") !== true);
      ok("a 2xx recorded ok:true and the full batch's seq span", state.recorded[0]?.ok === true && state.recorded[0]?.fromSeq === 0 && state.recorded[0]?.toSeq === 3 && state.recorded[0]?.count === 3);
      ok("the recorded outcome carries the config's gen (the straggler guard threaded through the drain)", state.recorded[0]?.gen === "gen-ok");

      // Nothing new since the cursor: a second run with no new events is a no-op completion.
      state.recorded = [];
      state.lastPushedSeq = 3;
      ok("nothing new since the cursor -> true, no record posted", (await runSiemPushPass(env, fakeScheduler(state))) === true && state.recorded.length === 0);
    }
    {
      // A failing SIEM endpoint: the pass still COMPLETES (true); the outcome is recorded as a failure and
      // the cursor (asserted via the DO-level test above) would hold. This proves the pass-level contract:
      // a customer-endpoint rejection is not a pass fault.
      const state: FakeState = {
        record: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-reject" },
        lastPushedSeq: 0,
        events: [fakeEvent(1)],
        recorded: [],
      };
      globalThis.fetch = (async () => new Response("nope", { status: 503 })) as typeof fetch;
      try {
        ok("a rejected delivery still completes the pass (true)", (await runSiemPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      ok("the failure is recorded with ok:false + a coarse reason (never a raw body)", state.recorded[0]?.ok === false && state.recorded[0]?.reason === "http-5xx");
    }
    {
      // A genuine DO round-trip fault (the audit export is unreadable) is a PASS fault: false, the
      // false-green signal drive() folds into passErrors. Distinct from a customer-endpoint failure above.
      const state: FakeState = {
        record: { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-fault" },
        lastPushedSeq: 0,
        events: [fakeEvent(1)],
        recorded: [],
      };
      ok("a DO round-trip fault (audit export unreadable) returns false (the false-green signal)", (await runSiemPushPass(env, fakeScheduler(state, { throwPath: "/audit/export" }))) === false);
    }
    {
      // DRAIN TAIL TRY/CATCH: a contract-violating throw from the shape/deliver tail must NOT escape
      // the pass and must NOT silently skip the tick: it records a FAILURE (ok:false, so the cursor never
      // advances) and returns false (the false-green signal). A genuine tail throw is forced with a stored
      // format the exhaustive shaper does not handle (a real cross-version contract violation): the switch
      // returns undefined, so `shaped.body` throws INSIDE the tail (the audit export + everything above it
      // serialise cleanly, so this isolates the throw to the tail, not the DO round-trips).
      const state: FakeState = {
        record: { endpoint: "https://siem.example.com/ingest", format: "bogus-format" as "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-tail" },
        lastPushedSeq: 0,
        events: [fakeEvent(1)],
        recorded: [],
      };
      const passResult = await runSiemPushPass(env, fakeScheduler(state));
      ok("a shape/deliver tail throw returns false (never escapes the pass, never skips silently)", passResult === false);
      ok("the tail throw recorded a FAILURE outcome (ok:false), so the cursor never advances", state.recorded.length === 1 && state.recorded[0]?.ok === false && state.recorded[0]?.reason === "shape-or-deliver-fault");
    }
  }

  console.log("\nINJECTION SAFETY (invariant 2): a crafted field cannot break the grammar, forge an event, or inject a record boundary");
  {
    const injMeta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 2, headSeq: 2, headHash: "h" };
    // A hostile event: the crafted values carry the CEF/LEEF delimiters (| = ^), a forged record header, and
    // raw CR/LF (the record-boundary vector). action stays a valid closed-enum (never operator input).
    const evil = fakeEvent(1, {
      actorEmail: "attacker=x|CEF:0|forged\nCEF:0|forged2|P|1|inject|n|9|",
      actorSubject: "sub^bad=evil\r\nnewline",
      sourceIp: "1.2.3.4\n5.6.7.8",
      target: { kind: "downpipe", id: "dp^|=\nevil", name: "nm\r\nLEEF:2.0|x" },
    });
    const benign = fakeEvent(2);

    // CEF: escaping. Two events -> exactly two lines (a crafted newline never adds a record); a single crafted
    // event carries NO raw CR/LF; the crafted '=' is escaped to '\=' so it cannot split a key=value.
    ok("CEF: a crafted newline cannot add a record (two events -> exactly two lines)", shapeCef([evil, benign], injMeta).body.split("\n").length === 2);
    ok("CEF: a single crafted event carries NO raw CR/LF (newline escaped to the literal two-char form)", !/[\r\n]/.test(shapeCef([evil], injMeta).body));
    ok("CEF: the crafted '=' in a value is escaped to '\\=' (cannot split a key=value pair)", shapeCef([evil], injMeta).body.includes("suser=attacker\\=x"));

    // LEEF: avoidance. Two events -> two lines; a single crafted event has no raw CR/LF; the crafted '^'/'='
    // are neutralised to '_' (LEEF has no escaping) so they cannot inject the delimiter or a spurious key.
    ok("LEEF: a crafted delimiter/newline cannot add a record or a field (two events -> exactly two lines)", shapeLeef([evil, benign], injMeta).body.split("\n").length === 2);
    ok("LEEF: a single crafted event carries NO raw CR/LF", !/[\r\n]/.test(shapeLeef([evil], injMeta).body));
    ok("LEEF: the crafted '^'/'=' in a value are neutralised to '_' (cannot inject the delimiter)", shapeLeef([evil], injMeta).body.includes("usrName=attacker_x_"));

    // GELF: JSON-encoded, so structurally safe. No raw CR/LF; the crafted value round-trips exactly inside a
    // JSON string; keys stay _-prefixed and the reserved _id is never emitted.
    const gelfBody = shapeGelf([evil], injMeta).body;
    const gelfDoc = JSON.parse(gelfBody) as Record<string, unknown>;
    ok("GELF: a single crafted event is one line with NO raw CR/LF (newline JSON-escaped)", !/[\r\n]/.test(gelfBody));
    ok("GELF: the crafted value round-trips inside a JSON string (structurally safe), keys stay _-prefixed, no _id", gelfDoc._actorEmail === evil.actorEmail && "_hash" in gelfDoc && !("_id" in gelfDoc));

    // ndjson / json-array: JSON-encoded raw events, so a crafted newline is escaped and cannot split an event.
    ok("ndjson: a crafted newline cannot split one event into two (two events -> exactly two lines)", shapeNdjson([evil, benign], injMeta).body.split("\n").length === 2);
    ok("json-array: the body is one valid JSON array of two events regardless of crafted content", (JSON.parse(shapeJsonArray([evil, benign], injMeta).body) as unknown[]).length === 2);
  }

  console.log("\n3-WAY AAD separation (invariant 3): dest / push-header / push-s3 ciphertexts never cross-open");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const SEC = "s3-secret-key-DO-NOT-LEAK-42";
    const destW = await wrapConfigSecret(KEY, SEC); // CONFIG_SECRET_AAD (the archive credential, default)
    const headerW = await wrapConfigSecret(KEY, SEC, PUSH_SECRET_AAD); // the push auth header secret
    const s3W = await wrapConfigSecret(KEY, SEC, PUSH_S3_SECRET_AAD); // the push s3 sink secret
    ok("a push-s3 ciphertext opens under its OWN aad", (await unwrapConfigSecret(KEY, s3W, PUSH_S3_SECRET_AAD)) === SEC);
    await throwsAsync("a push-s3 ciphertext does NOT open under the DEST aad", async () => unwrapConfigSecret(KEY, s3W));
    await throwsAsync("a push-s3 ciphertext does NOT open under the push-HEADER aad", async () => unwrapConfigSecret(KEY, s3W, PUSH_SECRET_AAD));
    await throwsAsync("a push-HEADER ciphertext does NOT open under the push-s3 aad", async () => unwrapConfigSecret(KEY, headerW, PUSH_S3_SECRET_AAD));
    await throwsAsync("a DEST ciphertext does NOT open under the push-s3 aad", async () => unwrapConfigSecret(KEY, destW, PUSH_S3_SECRET_AAD));
    ok("resolveConfigSecret(push-s3 aad) resolves the s3 secret back to plaintext", (await resolveConfigSecret(KEY, s3W, PUSH_S3_SECRET_AAD)) === SEC);
  }

  console.log("\nS3-drop sink: deliverResolvedPush PUTs one NDJSON object via the archive S3 client (no bespoke SigV4); ok on 2xx, hold on failure");
  {
    const s3cfg: ResolvedPushConfig = {
      endpoint: "",
      format: "ndjson",
      authHeaderName: "Authorization",
      authHeaderValue: "",
      enabled: true,
      gen: "g-s3",
      sink: "s3",
      authInUrl: false,
      s3: { endpoint: "https://s3.example.com", bucket: "audit-bucket", region: "us-east-1", accessKeyId: "AKIA-DISTINCT-KEYID", secretAccessKey: "s3-secret-DO-NOT-LEAK-77", prefix: "downpipes-audit" },
    };
    const evs = [fakeEvent(10), fakeEvent(11)];
    const drainMeta: PushCursorMeta = { afterSeq: 9, nextAfterSeq: 11, headSeq: 11, headHash: "h" };
    const captures: Array<{ url: string; method: string | undefined; body: string }> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), method: init?.method, body: decodeBody(init?.body) });
      return new Response("", { status: 200 });
    }) as typeof fetch;
    try {
      const result = await deliverResolvedPush(s3cfg, evs, drainMeta);
      ok("the s3 drain reports ok:true on a 200 PUT (the cursor then advances exactly like http on 2xx)", result.ok === true);
      ok("exactly one S3 PUT was made (reusing S3Destination.put)", captures.length === 1 && captures[0]!.method === "PUT");
      const putBody = captures[0]!.body;
      ok("the PUT body is NDJSON: one raw audit event object per line", putBody.split("\n").length === 2 && (JSON.parse(putBody.split("\n")[0]!) as { seq: number }).seq === 10);
      ok("the PUT body NEVER contains the s3 secret", !putBody.includes("s3-secret-DO-NOT-LEAK-77"));
      ok("the object key rides under the prefix and carries the batch seq span (<from>-<to>.ndjson)", captures[0]!.url.includes("downpipes-audit") && captures[0]!.url.includes("9-11.ndjson"));
    } finally {
      globalThis.fetch = realFetch;
    }
    // A failing PUT (the S3 client throws on a non-2xx) yields ok:false + a coarse reason, so the cursor holds.
    globalThis.fetch = (async () => new Response("denied", { status: 403 })) as typeof fetch;
    try {
      const failResult = await deliverResolvedPush(s3cfg, evs, drainMeta);
      // A 403 denial from an S3 sink is classified into the closed S3 class set, naming the operator
      // action (a bucket policy / broken credential) rather than a generic failure.
      ok("a failed s3 PUT is ok:false with a CLOSED class (cursor holds, retry next tick), never a throw", failResult.ok === false && failResult.reason === "s3-auth-denied");
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\nS3 KEEP-SECRET (independent branch): the s3 secret and the http header secret have independent lifecycles");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    // A FIRST s3 set with no s3 secret is rejected (nothing to keep).
    await throwsAsync("a FIRST s3 set with no s3 secret is rejected (needs a secret to create)", async () =>
      dobj.setSiemPushDestination({ format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.example.com", bucket: "b", region: "r", accessKeyId: "AKIA-DISTINCT-KEYID" } }, OWNER_CALLER),
    );
    ok("nothing was stored by the rejected first s3 create", (await dobj.getSiemPushRecordRaw()) === null);

    // Create an s3 sink WITH an s3 secret, then edit the bucket WITHOUT re-supplying it (keep-secret).
    await dobj.setSiemPushDestination({ format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.example.com", bucket: "b", region: "r", accessKeyId: "AKIA-DISTINCT-KEYID", secretAccessKey: "s3-secret-1" } }, OWNER_CALLER);
    const r1 = (await dobj.getSiemPushRecordRaw())!;
    ok("the s3 create stored the s3 secret verbatim (DO plaintext floor) and sink s3", r1.sink === "s3" && r1.s3Target?.secretAccessKey === "s3-secret-1");
    await dobj.setSiemPushDestination({ format: "ndjson", sink: "s3", enabled: false, s3Target: { endpoint: "https://s3.example.com", bucket: "b2", region: "r", accessKeyId: "AKIA-DISTINCT-KEYID" } }, OWNER_CALLER);
    const r2 = (await dobj.getSiemPushRecordRaw())!;
    ok("S3 KEEP-SECRET: the s3 secret is preserved across a set that omits it", r2.s3Target?.secretAccessKey === "s3-secret-1");
    ok("S3 KEEP-SECRET: the non-secret s3 fields updated (bucket b -> b2) and enabled toggled off", r2.s3Target?.bucket === "b2" && r2.enabled === false);
    // A set WITH a new s3 secret rotates it (rotation is re-enter).
    await dobj.setSiemPushDestination({ format: "ndjson", sink: "s3", enabled: true, s3Target: { endpoint: "https://s3.example.com", bucket: "b2", region: "r", accessKeyId: "AKIA-DISTINCT-KEYID", secretAccessKey: "s3-secret-2" } }, OWNER_CALLER);
    ok("a set WITH a new s3 secret rotates it", (await dobj.getSiemPushRecordRaw())!.s3Target?.secretAccessKey === "s3-secret-2");
    const v = await dobj.getSiemPushView();
    ok("getSiemPushView carries the s3 LOCATION (endpoint/bucket/region) but NEVER the s3 access key id or secret", v.sink === "s3" && v.s3?.bucket === "b2" && v.s3?.region === "r" && !JSON.stringify(v).includes("AKIA-DISTINCT-KEYID") && !JSON.stringify(v).includes("s3-secret-2"));

    // Independence: the http header secret keep-secret is untouched by the s3 branch. A fresh http destination
    // keeps its header secret across a secretless edit even though the s3 branch also exists.
    const dobj2 = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await dobj2.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "ndjson", sink: "http", authHeaderName: "Authorization", authHeaderValue: "header-secret-1", enabled: true }, OWNER_CALLER);
    // The format CHANGES across the secretless edit (that is the point: a format change must not lose the
    // header secret), but it can no longer be cef: pushSinkFormatError now refuses cef and leef anywhere other
    // than syslog-tls, matching the console's own validator. splunk-hec is an equally arbitrary second format
    // and keeps this assertion about the secret rather than about the cross-field rule.
    await dobj2.setSiemPushDestination({ endpoint: "https://siem.example.com/ingest", format: "splunk-hec", sink: "http", authHeaderName: "Authorization", enabled: false }, OWNER_CALLER);
    ok("the http header keep-secret still holds independently (a secretless http edit keeps the header secret)", (await dobj2.getSiemPushRecordRaw())!.authHeaderValue === "header-secret-1");
  }

  console.log("\nURL-TOKEN (authInUrl, invariant 4): the token is spliced into the url, the auth header is NOT sent, the body never carries it");
  {
    const TOKEN = "devo-url-token-DO-NOT-LEAK-abc123";
    const cfg: ResolvedPushConfig = { endpoint: "https://intake.example.com/in", format: "ndjson", authHeaderName: "Authorization", authHeaderValue: TOKEN, enabled: true, gen: "g", sink: "http", authInUrl: true };
    const urlMeta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" };
    const captures: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), headers: { ...(init?.headers as Record<string, string>) }, body: decodeBody(init?.body) });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    try {
      const r = await deliverResolvedPush(cfg, [fakeEvent(1)], urlMeta);
      const last = captures[captures.length - 1];
      ok("the url-token delivery reports ok:true on a 200", r.ok === true && r.status === 200);
      ok("the token is spliced into the request URL (a trailing path segment)", last?.url.includes(TOKEN) === true && last?.url.startsWith("https://intake.example.com/in/") === true);
      ok("NO auth header is sent (the token rides in the url only)", last !== undefined && !Object.keys(last.headers).some((h) => h.toLowerCase() === "authorization"));
      ok("only the content-type header rides alongside", last?.headers["content-type"] === "application/x-ndjson");
      ok("the request body never contains the token", last?.body.includes(TOKEN) !== true);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\nGELF over http (item 1): N events -> N requests, never a newline-joined batch (Graylog drops a batched body by default)");
  {
    const cfg: ResolvedPushConfig = { endpoint: "https://graylog.example.com/gelf", format: "gelf", authHeaderName: "Authorization", authHeaderValue: "gelf-secret-DO-NOT-LEAK", enabled: true, gen: "g", sink: "http", authInUrl: false };
    const gelfMeta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 3, headSeq: 3, headHash: "h" };
    const evs = [fakeEvent(1), fakeEvent(2), fakeEvent(3)];
    const captures: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), headers: { ...(init?.headers as Record<string, string>) }, body: decodeBody(init?.body) });
      return new Response("ok", { status: 202 });
    }) as typeof fetch;
    try {
      const r = await deliverResolvedPush(cfg, evs, gelfMeta);
      ok("3 GELF events -> exactly 3 HTTP requests (never one newline-joined batch)", captures.length === 3);
      ok("the whole-batch result reports ok:true (the last request's status) once every request succeeds", r.ok === true && r.status === 202);
      ok("every request body is exactly ONE GELF JSON object (no embedded newline)", captures.every((c) => !c.body.includes("\n") && (JSON.parse(c.body) as { version: string }).version === "1.1"));
      ok("each request's body carries exactly that event's seq (event i -> _seq i)", (JSON.parse(captures[0]!.body) as { _seq: number })._seq === 1 && (JSON.parse(captures[1]!.body) as { _seq: number })._seq === 2 && (JSON.parse(captures[2]!.body) as { _seq: number })._seq === 3);
      ok("every request carries the ONE configured auth header", captures.every((c) => c.headers.Authorization === "gelf-secret-DO-NOT-LEAK"));
      ok("every request targets the same configured endpoint", captures.every((c) => c.url === "https://graylog.example.com/gelf"));
    } finally {
      globalThis.fetch = realFetch;
    }

    // A failure partway through the batch (event 2 of 3) fails the WHOLE result (cursor holds, all 3 retry
    // next tick) and stops sending further events, rather than reporting a partial success or hammering a
    // sink that has already shown itself down.
    const captures2: Array<{ body: string }> = [];
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures2.push({ body: decodeBody(init?.body) });
      return captures2.length === 2 ? new Response("nope", { status: 500 }) : new Response("ok", { status: 202 });
    }) as typeof fetch;
    try {
      const r2 = await deliverResolvedPush(cfg, evs, gelfMeta);
      ok("a mid-batch failure fails the WHOLE gelf result (ok:false), so the cursor holds and all 3 retry", r2.ok === false && r2.status === 500);
      ok("the loop stops at the first failure (2 requests sent, not 3)", captures2.length === 2);
    } finally {
      globalThis.fetch = realFetch;
    }

    // URL-TOKEN + GELF together: the per-event loop still splices the token and omits the auth header on
    // every request, mirroring the generic http branch's authInUrl behaviour.
    const tokenCfg: ResolvedPushConfig = { ...cfg, authInUrl: true, authHeaderValue: "gelf-url-token-DO-NOT-LEAK" };
    const captures3: Array<{ url: string; headers: Record<string, string> }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures3.push({ url: String(input), headers: { ...(init?.headers as Record<string, string>) } });
      return new Response("ok", { status: 202 });
    }) as typeof fetch;
    try {
      await deliverResolvedPush(tokenCfg, evs, gelfMeta);
      ok("gelf + url-token: every one of the 3 requests carries the spliced token url", captures3.length === 3 && captures3.every((c) => c.url.endsWith("/gelf/gelf-url-token-DO-NOT-LEAK")));
      ok("gelf + url-token: NO request carries the auth header (the token rides in the url only)", captures3.every((c) => !Object.keys(c.headers).some((h) => h.toLowerCase() === "authorization")));
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\nsyslog-tls sink: the drain-dispatch guard holds the cursor when the target is missing (the full RFC 5424/6587 transport + injection guard is validated in validate-siem-syslog.ts)");
  {
    // A syslog-tls config with NO syslog target holds the cursor with a clean coarse reason, never a throw and
    // never a socket dial. The socket transport itself (framing, MSG bytes, the injection guard, failure
    // classes) is mocked and asserted byte-for-byte in test/validate-siem-syslog.ts (the socket cannot run
    // under Node), so this file keeps only the drain's sink-dispatch concern.
    const cfg: ResolvedPushConfig = { endpoint: "", format: "cef", authHeaderName: "Authorization", authHeaderValue: "", enabled: true, gen: "g", sink: "syslog-tls", authInUrl: false };
    const r = await deliverResolvedPush(cfg, [fakeEvent(1)], { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" });
    ok("syslog-tls with no target is ok:false with a target-missing reason (the cursor holds), never a throw", r.ok === false && r.reason === "syslog-target-missing");
  }

  console.log(failures === 0 ? "\nSIEM PUSH (engine-internal) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
