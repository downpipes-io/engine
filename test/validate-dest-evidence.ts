// Validates the DESTINATION subsystem's support-pack evidence.
//
// Stored/env destination config SILENTLY DROPPED. Every destination-config read is fail-safe by
// DISCARDING: a corrupted assumeRole policy is dropped and the engine then signs with the long-lived
// PRINCIPAL (so every cross-account write is AccessDenied forever), a malformed WORM policy is dropped while
// the console still claims immutability, a typo'd DEST_BURST / DEST_STORAGE_CLASS / DEST_ADDRESSING falls
// back silently. The drop is correct; its invisibility is the bug. This proves the DROP EVENT is named in a
// closed vocabulary, recorded (stored half) or derivable (env half), and carries no value.
//
// Destination DEGRADATION on runs that SUCCEEDED. Store backpressure driving the pacer down, multipart
// retries, aborted requests against a black-holed endpoint, conditional-PUT conflicts (two engines fighting
// over one RUNLOG) and the dedup-defeating HEAD that collapses a 403 to "absent" and re-uploads the whole
// archive are all swallowed by design. This proves each one is COUNTED on the fault path, exposed for the run
// row via Destination.destIo(), and flushed to the DO's bounded admin-counter aggregate.
//
// REDACTION IS THE POINT: customer sentinels (a bucket, a key, an IAM ARN, an externalId, a live secret, an
// endpoint) are planted at every fault site and asserted NEVER to appear in any record, any wire body, or any
// counter name. The S3 driver is driven over a stubbed global fetch; no network.
//
// Run: node test/validate-dest-evidence.ts

import { ADMIN_COUNTER_NAMES, applyAdminCounters, DROPPED_WRITE_KINDS } from "../src/admin/diag-records.ts";
import { pendingDroppedWrites, resetPendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { anomalyBumps, classifyEnvDestAnomalies, classifyStoredDestAnomalies, DEST_CONFIG_ANOMALIES, STORED_ANOMALY_COUNTERS } from "../src/dest/config-anomalies.ts";
import { DEST_IO_COUNTERS, destIoBumps, flushDestIo, pendingDestIo, resetPendingDestIo } from "../src/dest/dest-io.ts";
import { buildDestination, fetchDestConfig } from "../src/dest/factory.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { DEFAULT_DEST_RATE_PER_SEC, DestPacer, destPacerFromEnv } from "../src/dest/pace.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---------------------------------------------------------------------------------------------------
// The customer sentinels. Every one of these is planted at a fault site below. NONE may reach a record.
// ---------------------------------------------------------------------------------------------------
const BUCKET = "acme-prod-payroll-archive";
const CUSTOMER_KEY = "seg/0001-ACME-PAYROLL";
const ENDPOINT_HOST = "s3.acme-internal.example.com";
const IAM_ARN = "arn:aws:iam::123456789012:role/acme-backup-robot";
const EXTERNAL_ID = "acme-external-id-7f3a";
const LIVE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REQUEST_ID = "TXHJ8Q2ZKP0OPAQUE9";
const SENTINELS = [BUCKET, CUSTOMER_KEY, ENDPOINT_HOST, IAM_ARN, EXTERNAL_ID, LIVE_SECRET, REQUEST_ID, "acme", "GLACIER", "banana"];

// leaks reports every sentinel present anywhere in a serialised record. The whole redaction claim of this
// subsystem reduces to this function returning [] for every recorded artefact.
function leaks(v: unknown): string[] {
  const s = JSON.stringify(v) ?? "";
  return SENTINELS.filter((x) => s.includes(x));
}

// ===================================================================================================
// G185 (a): the STORED destination config -- the drop event, classified and counted
// ===================================================================================================
console.log("stored destination config: the silently-discarded intent is named");

// A stored row where EVERY optional field is corrupt, each corruption carrying a customer sentinel. This is
// the exact shape fetchDestConfig discards field by field today, saying nothing.
const CORRUPT_STORED = {
  endpoint: `https://${ENDPOINT_HOST}`,
  bucket: BUCKET,
  region: "ap-southeast-2",
  accessKeyId: "AKIAACME000000000001",
  secretAccessKey: LIVE_SECRET,
  // a WORM policy that lost its retention window: the console still shows immutability ON
  worm: { mode: "compliance", retentionDays: 0, note: CUSTOMER_KEY },
  // an assumeRole policy whose ARN corrupted (the "arn:aws:iam::<12 digits>:role/" prefix is mangled): the
  // engine drops the policy and falls back to signing with the long-lived PRINCIPAL
  assumeRole: { roleArn: `CORRUPTED-${IAM_ARN}`, externalId: EXTERNAL_ID },
  // a storage class outside the immediately-readable allow-list
  storageClass: "GLACIER",
  // an addressing style that is not one of auto|path|vhost
  addressing: "banana",
};

const storedAnomalies = classifyStoredDestAnomalies(CORRUPT_STORED, true);
ok("worm-policy-dropped is named", storedAnomalies.includes("worm-policy-dropped"));
ok("assume-role-policy-dropped is named (the AccessDenied-forever fault)", storedAnomalies.includes("assume-role-policy-dropped"));
ok("storage-class-dropped is named", storedAnomalies.includes("storage-class-dropped"));
ok("addressing-dropped is named", storedAnomalies.includes("addressing-dropped"));
ok("a COMPLETE corrupt row reports no missing-field anomaly", !storedAnomalies.some((a) => a.startsWith("missing-field")));
ok("every member is in the closed vocabulary", storedAnomalies.every((a) => (DEST_CONFIG_ANOMALIES as readonly string[]).includes(a)));
ok("REDACTION: no sentinel reaches the stored anomalies", leaks(storedAnomalies).length === 0);

// A row that is missing its required fields: the read THROWS, and no backup can run at all.
const missing = classifyStoredDestAnomalies({ worm: null, assumeRole: undefined }, false);
ok("missing endpoint/bucket/region/accessKeyId/secret are all named", ["missing-field-endpoint", "missing-field-bucket", "missing-field-region", "missing-field-access-key-id", "missing-field-secret"].every((a) => missing.includes(a as never)));
ok("an ABSENT optional field is not an anomaly (absent is honest)", !missing.includes("worm-policy-dropped") && !missing.includes("assume-role-policy-dropped"));

// A clean, fully-valid row must be silent: no anomaly, no counter, no wire body.
const clean = classifyStoredDestAnomalies(
  { endpoint: `https://${ENDPOINT_HOST}`, bucket: BUCKET, region: "ap-southeast-2", accessKeyId: "AKIA1", secretAccessKey: LIVE_SECRET, worm: { mode: "governance", retentionDays: 30 }, assumeRole: { roleArn: IAM_ARN, externalId: EXTERNAL_ID }, storageClass: "STANDARD_IA", addressing: "vhost" },
  true,
);
ok("a VALID row (valid ARN, valid WORM, allow-listed class) reports nothing", clean.length === 0 && Object.keys(anomalyBumps(clean)).length === 0);

// The counter names must be in the DO's closed vocabulary, or applyAdminCounters drops them on the floor.
const bumps = anomalyBumps(storedAnomalies);
ok("every stored-anomaly counter name is in ADMIN_COUNTER_NAMES", Object.keys(bumps).every((n) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(n)));
ok("the five missing-field members collapse to ONE dest-config-incomplete counter", anomalyBumps(missing)["dest-config-incomplete"] === 5);
ok("REDACTION: no sentinel reaches the counter tally", leaks(bumps).length === 0);
const folded = applyAdminCounters(undefined, bumps, "2026-07-11T00:00:00.000Z");
ok("the DO applier accepts the stored-anomaly counters", folded["dest-config-assume-role-policy-dropped"]?.count === 1 && folded["dest-config-worm-policy-dropped"]?.count === 1);
ok("REDACTION: no sentinel survives into the DO aggregate", leaks(folded).length === 0);
ok("every mapped counter name is a member of ADMIN_COUNTER_NAMES", Object.values(STORED_ANOMALY_COUNTERS).every((n) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(n)));

// ---------------------------------------------------------------------------------------------------
// G185 (a) end to end: fetchDestConfig must POST the drop to the DO, with the sentinels nowhere in the body
// ---------------------------------------------------------------------------------------------------
console.log("stored config: fetchDestConfig records the drop at the read-for-use site");

const posted: Array<{ path: string; body: string }> = [];
const stubScheduler = {
  fetch: async (url: string, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    if (u.pathname === "/dest-config") return new Response(JSON.stringify({ config: CORRUPT_STORED }), { status: 200 });
    posted.push({ path: u.pathname, body: String(init?.body ?? "") });
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  },
} as unknown as DurableObjectStub;

resetPendingDroppedWrites();
const resolved = await fetchDestConfig(stubScheduler);
ok("the corrupt fields are still DROPPED (behaviour unchanged, fail-safe)", resolved !== null && resolved.worm === undefined && resolved.assumeRole === undefined && resolved.storageClass === undefined && resolved.addressing === undefined);
ok("the drop was POSTed to /diag/admin-counters", posted.some((p) => p.path === "/diag/admin-counters"));
const anomalyBody = posted.find((p) => p.path === "/diag/admin-counters")?.body ?? "";
ok("the posted body names the discarded FIELDS", anomalyBody.includes("dest-config-assume-role-policy-dropped") && anomalyBody.includes("dest-config-worm-policy-dropped"));
ok("REDACTION: the posted body carries NO sentinel (no ARN, externalId, bucket, endpoint or secret)", SENTINELS.every((s) => !anomalyBody.includes(s)));

// A DO that is DOWN must not lose the fact silently: the dropped write is itself counted.
resetPendingDroppedWrites();
const deadScheduler = {
  fetch: async (url: string): Promise<Response> => {
    if (new URL(url).pathname === "/dest-config") return new Response(JSON.stringify({ config: CORRUPT_STORED }), { status: 200 });
    return new Response("nope", { status: 503 });
  },
} as unknown as DurableObjectStub;
await fetchDestConfig(deadScheduler);
ok("a DROPPED anomaly write is itself counted (the pack never reads a false green)", (pendingDroppedWrites()["admin-counter"] ?? 0) > 0);
ok("the dropped-write kind is in the closed vocabulary", (DROPPED_WRITE_KINDS as readonly string[]).includes("admin-counter"));
resetPendingDroppedWrites();

// A read that FAULTS must never break the backup path it observes.
const throwingScheduler = {
  fetch: async (url: string): Promise<Response> => {
    if (new URL(url).pathname === "/dest-config") return new Response(JSON.stringify({ config: CORRUPT_STORED }), { status: 200 });
    throw new Error("DO unreachable");
  },
} as unknown as DurableObjectStub;
let survived = true;
try {
  await fetchDestConfig(throwingScheduler);
} catch {
  survived = false;
}
ok("a THROWING diagnostic write never breaks the config read", survived);
resetPendingDroppedWrites();

// ===================================================================================================
// The ENV knobs -- derivable at pack-build time, so no write can lose them
// ===================================================================================================
console.log("env knobs: the silent fallback is derivable from env");

const envAnomalies = classifyEnvDestAnomalies({
  DEST_RATE_PER_SEC: "fifty", // a typo: the pacer silently uses the default rate
  DEST_BURST: "-3", // invalid: same
  DEST_WORM_MODE: "complianace", // a typo: WORM is armed NOWHERE while the deploy believes it is on
  DEST_WORM_RETENTION_DAYS: "0", // not a positive integer
  DEST_STORAGE_CLASS: "GLACIER", // outside the immediately-readable allow-list
  DEST_ADDRESSING: "banana",
});
ok("rate-knob-invalid is derived", envAnomalies.includes("rate-knob-invalid"));
ok("burst-knob-invalid is derived (DEST_BURST, recorded nowhere today)", envAnomalies.includes("burst-knob-invalid"));
ok("worm-mode-invalid is derived", envAnomalies.includes("worm-mode-invalid"));
ok("worm-retention-days-invalid is derived", envAnomalies.includes("worm-retention-days-invalid"));
ok("storage-class-unsupported is derived", envAnomalies.includes("storage-class-unsupported"));
ok("addressing-invalid is derived", envAnomalies.includes("addressing-invalid"));
ok("every member is in the closed vocabulary", envAnomalies.every((a) => (DEST_CONFIG_ANOMALIES as readonly string[]).includes(a)));
ok("REDACTION: no sentinel reaches the env anomalies", leaks(envAnomalies).length === 0);

const halfWorm = classifyEnvDestAnomalies({ DEST_WORM_MODE: "compliance" });
ok("a HALF-SET WORM pair reports worm-policy-partial (intent armed nowhere)", halfWorm.includes("worm-policy-partial") && !halfWorm.includes("worm-mode-invalid"));
const cleanEnv = classifyEnvDestAnomalies({ DEST_RATE_PER_SEC: "25", DEST_BURST: "10", DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "30", DEST_STORAGE_CLASS: "STANDARD_IA", DEST_ADDRESSING: "path" });
ok("a fully-valid env reports nothing", cleanEnv.length === 0);
ok("an UNSET env reports nothing (absent is honest, not an anomaly)", classifyEnvDestAnomalies({}).length === 0);
// The classifier's verdict must be the verdict the pacer ACTED on, or the diagnosis is a fiction: a knob this
// calls invalid must be a knob destPacerFromEnv actually fell back on (and vice versa).
ok("rate-knob-invalid agrees with the pacer's own fallback", destPacerFromEnv({ DEST_RATE_PER_SEC: "fifty" }).effectiveRate() === DEFAULT_DEST_RATE_PER_SEC);
ok("a VALID rate knob is honoured by the pacer and reported clean", destPacerFromEnv({ DEST_RATE_PER_SEC: "25" }).effectiveRate() === 25 && !classifyEnvDestAnomalies({ DEST_RATE_PER_SEC: "25" }).includes("rate-knob-invalid"));

// ===================================================================================================
// destination DEGRADATION on a run that SUCCEEDS
// ===================================================================================================
console.log("destination degradation: the swallowed branches are counted");

type Reply = { status: number; body?: string; headers?: Record<string, string> } | { throws: Error };
let queue: Reply[] = [];
function stubFetch(replies: Reply[]): void {
  queue = [...replies];
  (globalThis as { fetch: unknown }).fetch = async (): Promise<Response> => {
    const r = queue.shift();
    if (r === undefined) throw new Error("stub fetch: no reply queued");
    if ("throws" in r) throw r.throws;
    return new Response(r.body ?? "", { status: r.status, headers: { "x-amz-request-id": REQUEST_ID, ...(r.headers ?? {}) } });
  };
}
const realFetch = globalThis.fetch;

function s3(opts?: { pacer?: DestPacer }): S3Destination {
  return new S3Destination(`https://${ENDPOINT_HOST}`, BUCKET, "ap-southeast-2", "AKIAACME000000000001", LIVE_SECRET, {
    ...(opts?.pacer !== undefined ? { pacer: opts.pacer } : {}),
    fetchTimeoutMs: 5,
  });
}

// -- store backpressure: the pacer HALVES its rate and the run still succeeds --
resetPendingDestIo();
{
  const pacer = new DestPacer({ ratePerSec: 50, burst: 50 });
  const d = s3({ pacer });
  // Two 503s (the store pushing back), then a clean 200: exactly the "slow night" a green run hides.
  stubFetch([{ status: 503 }, { status: 429 }, { status: 200, headers: { etag: '"abc"' } }]);
  await d.put(CUSTOMER_KEY, new Uint8Array([1])).catch(() => {});
  await d.put(CUSTOMER_KEY, new Uint8Array([1])).catch(() => {});
  await d.put(CUSTOMER_KEY, new Uint8Array([1]));
  const io = d.destIo();
  ok("throttleObservations counts the store's 503/429 pushback", io.throttleObservations === 2);
  ok("minEffectiveRatePerSec records the WORST pace the store drove us to", io.minEffectiveRatePerSec !== undefined && io.minEffectiveRatePerSec < 50);
  ok("REDACTION: the degradation snapshot carries no sentinel", leaks(io).length === 0);
  ok("REDACTION: the snapshot has no string field at all", Object.values(io).every((v) => typeof v === "number"));
}

// -- the dedup-defeating HEAD: a 403 collapses to "absent" and the segment RE-UPLOADS --
{
  const d = s3();
  stubFetch([{ status: 403 }]);
  const present = await d.exists(CUSTOMER_KEY);
  ok("exists() still collapses a 403 to absent (behaviour unchanged)", present === false);
  ok("headNon200CollapsedToAbsent counts the dedup-defeating collapse", d.destIo().headNon200CollapsedToAbsent === 1);
  stubFetch([{ status: 404 }]);
  const d404 = s3();
  await d404.exists(CUSTOMER_KEY);
  ok("a genuine 404 is NOT a degradation (absent really is absent)", d404.destIo().headNon200CollapsedToAbsent === 0);
}

// -- conditional-PUT conflict: two engines fighting over one RUNLOG --
{
  const d = s3();
  stubFetch([{ status: 412 }]);
  const res = await d.putConditional("RUNLOG", new Uint8Array([1]), { ifNoneMatch: "*" });
  ok("a 412 still returns ok:false (behaviour unchanged)", res.ok === false);
  ok("conditionalPutConflicts counts the lost precondition", d.destIo().conditionalPutConflicts === 1);
}

// -- a black-holed endpoint: the request is aborted at the fetch bound --
{
  const d = s3();
  (globalThis as { fetch: unknown }).fetch = (_i: unknown, init?: { signal?: AbortSignal }): Promise<Response> =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    });
  await d.put(CUSTOMER_KEY, new Uint8Array([1])).catch(() => {});
  ok("timeouts counts a request aborted at the fetch bound (a black-holed endpoint)", d.destIo().timeouts === 1);
}

// -- an unparseable Retry-After: the engine backs off on a guess instead of the store's instruction --
{
  const { throttleError } = await import("../src/dest/s3-multipart.ts");
  const { DestIo } = await import("../src/dest/dest-io.ts");
  const io = new DestIo();
  throttleError("part 1 of x", new Response("", { status: 503, headers: { "retry-after": "in a little while" } }), io);
  ok("retryAfterUnparseable counts a Retry-After the engine cannot read", io.snapshot().retryAfterUnparseable === 1);
  const io2 = new DestIo();
  const e = throttleError("part 1 of x", new Response("", { status: 503, headers: { "retry-after": "30" } }), io2) as Error & { retryAfterMs?: number };
  ok("a PARSEABLE Retry-After is honoured and is not a degradation", e.retryAfterMs === 30_000 && io2.snapshot().retryAfterUnparseable === 0);
}

// -- a multipart step RE-ISSUED after a transient 503: the run succeeds, having quietly re-sent the part --
{
  const d = s3();
  // A size-less stream takes the multipart path. The initiate 503s once, then succeeds: exactly the retry
  // that leaves no trace today, on an upload that finishes green.
  stubFetch([
    { status: 503 },
    { status: 200, body: "<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>" },
    { status: 200, headers: { etag: '"part1"' } },
    { status: 200, body: "<CompleteMultipartUploadResult/>" },
  ]);
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new Uint8Array([1, 2, 3]));
      c.close();
    },
  });
  await d.putStream(CUSTOMER_KEY, body);
  const io = d.destIo();
  ok("retryAttemptsTotal counts a multipart step re-issued after a transient fault", io.retryAttemptsTotal === 1);
  ok("the run SUCCEEDED while degraded (the invisible slow/expensive night)", io.throttleObservations === 1);
  ok("REDACTION: no sentinel in the degraded-but-successful run's record", leaks(io).length === 0);
}

// -- a clean destination says nothing at all --
{
  const d = s3();
  stubFetch([{ status: 200, headers: { etag: '"abc"' } }]);
  await d.put(CUSTOMER_KEY, new Uint8Array([1]));
  const io = d.destIo();
  ok("a HEALTHY destination reports zero degradation", io.throttleObservations === 0 && io.retryAttemptsTotal === 0 && io.timeouts === 0 && io.conditionalPutConflicts === 0 && io.headNon200CollapsedToAbsent === 0);
}

// ---------------------------------------------------------------------------------------------------
// The degradation tally reaches the DO, and a dropped flush is itself recorded
// ---------------------------------------------------------------------------------------------------
console.log("degradation: the tally is flushed to the DO's bounded aggregate");

ok("every DEST_IO counter maps to a name in ADMIN_COUNTER_NAMES", Object.values(DEST_IO_COUNTERS).every((n) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(n)));
ok("the isolate tally is non-empty after the degradations above", Object.keys(pendingDestIo()).length > 0);
const wire = destIoBumps();
ok("the wire tally's keys are exactly the closed counter names", Object.keys(wire).every((n) => (Object.values(DEST_IO_COUNTERS) as string[]).includes(n)));
ok("REDACTION: the wire tally carries no sentinel", leaks(wire).length === 0);
ok("the wire tally's values are all clamped non-negative ints", Object.values(wire).every((v) => Number.isInteger(v) && v >= 0));

resetPendingDroppedWrites();
const flushed: string[] = [];
const flushScheduler = {
  fetch: async (url: string, init?: RequestInit): Promise<Response> => {
    flushed.push(String(init?.body ?? ""));
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  },
} as unknown as DurableObjectStub;
await flushDestIo(flushScheduler);
ok("the degradation tally is POSTed to the DO", flushed.length === 1 && flushed[0]!.includes("dest-io-"));
ok("REDACTION: the flushed body carries no sentinel", SENTINELS.every((s) => !flushed[0]!.includes(s)));
ok("a successful flush CLEARS the isolate tally (no double counting)", Object.keys(pendingDestIo()).length === 0);
const foldedIo = applyAdminCounters(undefined, JSON.parse(flushed[0]!).bumps, "2026-07-11T00:00:00.000Z");
ok("the DO applier accepts the degradation counters", (foldedIo["dest-io-throttled"]?.count ?? 0) > 0);
ok("REDACTION: no sentinel survives into the DO aggregate", leaks(foldedIo).length === 0);

// A DO that is DOWN: the tally must be RE-PENDED (never lost) and the loss itself counted.
resetPendingDestIo();
resetPendingDroppedWrites();
{
  const d = s3();
  stubFetch([{ status: 412 }]);
  await d.putConditional("RUNLOG", new Uint8Array([1]), { ifNoneMatch: "*" });
}
const deadFlush = { fetch: async (): Promise<Response> => new Response("nope", { status: 503 }) } as unknown as DurableObjectStub;
await flushDestIo(deadFlush);
ok("a DROPPED degradation flush re-pends the tally (evidence is never lost)", (pendingDestIo().conditionalPutConflicts ?? 0) === 1);
ok("a DROPPED degradation flush is itself counted", (pendingDroppedWrites()["admin-counter"] ?? 0) > 0);
// ...and a later healthy flush lands it.
const okFlush: string[] = [];
await flushDestIo({ fetch: async (_u: string, i?: RequestInit): Promise<Response> => { okFlush.push(String(i?.body ?? "")); return new Response("{}", { status: 200 }); } } as unknown as DurableObjectStub);
ok("a later healthy flush lands the re-pended evidence", okFlush.length > 0 && okFlush[0]!.includes("dest-io-conditional-put-conflict"));
resetPendingDroppedWrites();
resetPendingDestIo();

// buildDestination is the piggy-back point: it flushes whatever the previous instance left pending.
{
  const d = s3();
  stubFetch([{ status: 412 }]);
  await d.putConditional("RUNLOG", new Uint8Array([1]), { ifNoneMatch: "*" });
  const built: string[] = [];
  const env = {
    DEST_KIND: "s3",
    DEST_ENDPOINT: `https://${ENDPOINT_HOST}`,
    DEST_BUCKET: BUCKET,
    DEST_REGION: "ap-southeast-2",
    DEST_ACCESS_KEY_ID: "AKIA1",
    DEST_SECRET_ACCESS_KEY: LIVE_SECRET,
    SCHEDULER: {
      idFromName: () => "id",
      get: () => ({ fetch: async (_u: string, i?: RequestInit): Promise<Response> => { built.push(String(i?.body ?? "")); return new Response("{}", { status: 200 }); } }),
    },
  } as unknown as Env;
  await buildDestination(env);
  // buildDestination now makes TWO documented diagnostic writes: the degradation-tally flush (asserted
  // here) and the destination BUILD-health observation (a success posts once per isolate, which is
  // what clears a standing "unbuildable since" streak). Assert the flush is among them rather than pinning the
  // call count, and assert the build-health post carries only its closed outcome.
  ok("buildDestination flushes the previous instance's degradation tally", built.some((b) => b.includes("dest-io-conditional-put-conflict")));
  ok("buildDestination records its own BUILD-health outcome", built.some((b) => b.includes('"ok":true')));
  ok("REDACTION: the piggy-backed body carries no sentinel", SENTINELS.every((s) => !built[0]!.includes(s)));
}

// A context with NO scheduler binding cannot flush: the loss must be counted, never silently dropped.
resetPendingDestIo();
resetPendingDroppedWrites();
{
  const d = s3();
  stubFetch([{ status: 412 }]);
  await d.putConditional("RUNLOG", new Uint8Array([1]), { ifNoneMatch: "*" });
  const env = { DEST_KIND: "s3", DEST_ENDPOINT: `https://${ENDPOINT_HOST}`, DEST_BUCKET: BUCKET, DEST_REGION: "ap-southeast-2", DEST_ACCESS_KEY_ID: "AKIA1", DEST_SECRET_ACCESS_KEY: LIVE_SECRET } as unknown as Env;
  await buildDestination(env);
  ok("an unflushable context counts the loss (absence of evidence never reads as absence of degradation)", (pendingDroppedWrites()["admin-counter"] ?? 0) > 0);
}
resetPendingDestIo();
resetPendingDroppedWrites();

// ---------------------------------------------------------------------------------------------------
// DEAD VOCABULARY: endpoint-unparseable, vhost-bucket-unsafe and endpoint-not-https were
// declared DEST_BUILD_CAUSES with no producer. destBuildFaultOf classifies on the ERROR TYPE and never on the
// message (deliberately: the message carries the endpoint and the bucket), and all three of these throws were
// PLAIN Errors from s3-addressing.ts -- so they landed in the destination BUILD-health record as the residual
// cause "other". "Every backup has been failing to even build its destination since Tuesday" was in the pack;
// WHY was not, and each of the three has a different one-line operator fix.
//
// THE REAL ENTRY POINT: buildDestination(env) -- the single call every run, drill, replicate and restore makes.
// The cause is read back off the health record the DO is posted, not off the thrown error.
{
  const causes: string[] = [];
  const envFor = (over: Record<string, unknown>): Env =>
    ({
      DEST_KIND: "s3",
      DEST_ENDPOINT: `https://${ENDPOINT_HOST}`,
      DEST_BUCKET: BUCKET,
      DEST_REGION: "ap-southeast-2",
      DEST_ACCESS_KEY_ID: "AKIA1",
      DEST_SECRET_ACCESS_KEY: LIVE_SECRET,
      ...over,
      SCHEDULER: {
        idFromName: () => "id",
        get: () => ({
          fetch: async (_u: string, i?: RequestInit): Promise<Response> => {
            causes.push(String(i?.body ?? ""));
            return new Response("{}", { status: 200 });
          },
        }),
      },
    }) as unknown as Env;

  // 1. An endpoint that is not a URL at all (a paste that lost its scheme).
  let threw = false;
  await buildDestination(envFor({ DEST_ENDPOINT: `${ENDPOINT_HOST}/not-a-url` })).catch(() => {
    threw = true;
  });
  ok("build: an unparseable endpoint still fails the build loud (behaviour unchanged)", threw);
  ok('build: the unparseable endpoint is recorded as endpoint-unparseable (not the residual "other")', causes.some((c) => c.includes('"cause":"endpoint-unparseable"')));

  // 2. A non-https endpoint (the cleartext-credential refusal).
  causes.length = 0;
  threw = false;
  await buildDestination(envFor({ DEST_ENDPOINT: `http://${ENDPOINT_HOST}` })).catch(() => {
    threw = true;
  });
  ok("build: a non-https endpoint still fails the build loud (behaviour unchanged)", threw);
  ok('build: the non-https endpoint is recorded as endpoint-not-https (not the residual "other")', causes.some((c) => c.includes('"cause":"endpoint-not-https"')));

  // 3. An explicit vhost addressing whose bucket would break out of the request host: a SECURITY refusal that
  // read as an anonymous "other" in the pack.
  causes.length = 0;
  threw = false;
  await buildDestination(envFor({ DEST_ADDRESSING: "vhost", DEST_BUCKET: `${BUCKET}/evil.example` })).catch(() => {
    threw = true;
  });
  ok("build: a host-confusing vhost bucket still fails the build loud (behaviour unchanged)", threw);
  ok('build: the unsafe vhost bucket is recorded as vhost-bucket-unsafe (not the residual "other")', causes.some((c) => c.includes('"cause":"vhost-bucket-unsafe"')));

  // 4. An endpoint that ALREADY carries the bucket as its leading label: the provider console's per-bucket
  // URL pasted into DEST_ENDPOINT. This arm reaches buildDestination the way no console-set destination can,
  // because the console save runs a live probe and a doubled host never resolves, so a stored config cannot
  // be in this state. An ENV-configured destination has no such probe, so this is the path that actually
  // carried the defect into a running fleet: before the guard the request went to
  // "<bucket>.<bucket>.s3.ap-southeast-2.amazonaws.com" and failed as a DNS lookup, which the pack could
  // only ever report as a network fault against credentials that were never wrong.
  causes.length = 0;
  threw = false;
  await buildDestination(envFor({ DEST_ADDRESSING: "vhost", DEST_ENDPOINT: `https://${BUCKET}.s3.ap-southeast-2.amazonaws.com` })).catch(() => {
    threw = true;
  });
  ok("build: a doubled (per-bucket) endpoint fails the build loud rather than resolving to a doubled host", threw);
  ok('build: the doubled endpoint is recorded as vhost-bucket-doubled (not the residual "other", and not vhost-bucket-unsafe)', causes.some((c) => c.includes('"cause":"vhost-bucket-doubled"')));

  // REDACTION: the health post carries the closed cause and no endpoint, bucket or credential.
  ok("REDACTION: no build-health post carries a sentinel", causes.every((c) => SENTINELS.every((s) => !c.includes(s))));
}
resetPendingDestIo();
resetPendingDroppedWrites();
globalThis.fetch = realFetch;

console.log(failures === 0 ? "\nall dest evidence checks passed" : `\n${failures} check(s) FAILED`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
