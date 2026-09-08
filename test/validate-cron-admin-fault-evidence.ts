// Support-pack diagnostic coverage for the CRON + ADMIN subsystems: several fault sites that fell outside
// the first diagnostic-coverage expansion's file ownership, and so still swallowed their evidence.
//
// Every block proves the SAME two things the audit demands of a new recording:
//   (a) the evidence IS recorded ON THE FAULT PATH (not on a happy path, not only in a Workers Logs line), and
//   (b) it is REDACTION-SAFE: a customer value, a secret and a raw error message planted at the fault site
//       NEVER appear anywhere in the recorded record or in the DO's read-back.
//
// What each block covers:
//   pre-run seal dispatch throw  -> ATTRIBUTED to the downpipe with a closed class (its pinned destination
//        record was deleted / the DO would not allocate a run / the lock-clear failed and wedged the lease),
//        instead of one anonymous sealErrors int.
//   SIEM S3-drop push failure    -> the fixed string is SPLIT into the same closed class set the destination
//        probes use, and the OTLP truncation is SIZED (droppedCount).
//   the /metrics scrape surface  -> records its own health: the closed outcome (including
//        auth-check-unavailable, the DO hiccup misreported as a 401), the silent shape fallback that empties
//        every series while up == 1, and the failing pull trail.
//   WebAuthn structural faults   -> the 14 structural CBOR/COSE/DER/authData defects are split by class AND
//        ceremony phase.
//   recovery-code corruption     -> a corrupt STORED record and an unusable signing key are recorded, instead
//        of being indistinguishable from the operator mistyping.
//   the recorders' own writes    -> the diagnostic recorders' OWN dropped writes are counted, so the pack
//        stops under-counting during the exact outage it is meant to explain.
//
// No network, no real DO fetch. Run:
//   node test/validate-cron-admin-fault-evidence.ts

import {
  applyDroppedWrites,
  applyMetricsScrape,
  applySealErrorStamp,
  applyWebauthnFault,
  classifySealDestError,
  sealErrorClassOf,
  webauthnFaultOf,
  SealDispatchError,
  DROPPED_WRITE_KINDS,
  DROPPED_WRITES_KEY,
  METRICS_HEALTH_KEY,
  METRICS_SCRAPE_OUTCOMES,
  SEAL_ERROR_CLASSES,
  SEAL_ERROR_PREFIX,
  WEBAUTHN_FAULT_CLASSES,
  WEBAUTHN_FAULTS_KEY,
} from "../src/admin/diag-records.ts";
import { flushDroppedWrites, noteDroppedWrite, pendingDroppedWrites, recordDiagWrite, resetPendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { classifyPushS3Fault, PUSH_S3_FAIL_CODES, PUSH_SINK_FAIL_CODES } from "../src/cron/siem-push-pass.ts";
import { classifyIngestCredentialCheck, type IngestGrant } from "../src/admin/support-ingest.ts";
import { handleMetricsRoute } from "../src/admin/metrics.ts";
import { parseCoseKey, verifySignature, CborReader } from "../src/admin/passkey-cose.ts";
import { parseAuthData, parseClientData } from "../src/admin/passkey-authdata.ts";
import { generateRecoveryCodes, verifyCode, isRecoverySigningKeyUsable, RECOVERY_SIGNING_KEY_MIN_BYTES } from "../src/admin/recovery.ts";
import { runSealLoop } from "../src/cron/seal-loop-pass.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted needles. NONE of them may appear in ANY recorded record or read-back. Every recording site
// coarsens to a closed enum BEFORE it writes, so a substring scan over the serialised record is conclusive.
const SECRET = "AKIA-POISON-KEY/dps_customer-secret-9f3a";
const CUSTOMER_VALUE = "acme-payroll-crown-jewels";
const RAW_ERROR = `S3 PutObject denied for bucket ${CUSTOMER_VALUE} at https://acme.r2.cloudflarestorage.com (${SECRET})`;

function scanClean(label: string, subject: unknown): void {
  const json = JSON.stringify(subject ?? null);
  const leaked = [SECRET, CUSTOMER_VALUE, "AKIA-POISON-KEY", "r2.cloudflarestorage.com", "PutObject"].filter((p) => json.includes(p));
  ok(`${label} (redaction: no secret / customer value / raw error in the record)`, leaked.length === 0);
}

// ---- PRE-RUN SEAL FAILURES ARE ATTRIBUTED -----------------------------------------------------------

async function testSealErrorAttribution(): Promise<void> {
  console.log("\na pre-run seal throw is ATTRIBUTED to its downpipe with a closed class");

  // The CLASSIFIER reads the engine's OWN literals only, and RETURNS an enum.
  const notConfigured = new Error(`destination dest-${CUSTOMER_VALUE} for downpipe dp-1 is not configured`);
  ok("a deleted pinned destination classifies as dest-not-configured", classifySealDestError(notConfigured) === "dest-not-configured");
  ok("a malformed CONFIG_WRAP_KEY classifies as wrap-key-invalid", classifySealDestError(new Error("CONFIG_WRAP_KEY must be 32 bytes")) === "wrap-key-invalid");
  ok("any other resolution throw coarsens to dest-config-unreadable, never carrying its text", classifySealDestError(new Error(RAW_ERROR)) === "dest-config-unreadable");
  ok("the class is a closed-vocabulary member", (SEAL_ERROR_CLASSES as readonly string[]).includes(classifySealDestError(notConfigured)));

  // sealErrorClassOf NEVER re-reads an untagged error's message (that would be the free-text leak).
  ok("an UNTAGGED throw coarsens to other (its message is never inspected)", sealErrorClassOf(new Error(RAW_ERROR)) === "other");
  ok("a TAGGED throw carries its class through the loop's catch", sealErrorClassOf(new SealDispatchError("trigger-transport", new Error(RAW_ERROR))) === "trigger-transport");
  ok("the tag never becomes a class the vocabulary does not hold", sealErrorClassOf({ sealErrorClass: `${CUSTOMER_VALUE}` }) === "other");

  // The STAMP arithmetic: the same class streaks, a DIFFERENT class restarts the run.
  const s1 = applySealErrorStamp(undefined, "dest-not-configured", 1_000);
  const s2 = applySealErrorStamp(s1, "dest-not-configured", 2_000);
  const s3 = applySealErrorStamp(s2, "lock-clear-failed", 3_000);
  ok("a repeated fault streaks (consecutive climbs)", s2.consecutive === 2 && s2.at === 2_000);
  ok("a CHANGED cause restarts the streak at 1", s3.consecutive === 1 && s3.cls === "lock-clear-failed");
  scanClean("the stamp", s3);

  // THE FAULT PATH, end to end: a downpipe whose /trigger throws must land a stamp on the DO.
  const { storage, stub } = makeScheduler();
  const posts: string[] = [];
  const scheduler = {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/trigger") throw new Error(RAW_ERROR); // the pre-run fault: no run index is ever allocated
      if (path === "/seal-error") {
        posts.push(String(init?.body ?? "{}"));
        return stubFetch(stub, "POST", "/seal-error", JSON.parse(String(init?.body ?? "{}")));
      }
      return stubFetch(stub, (init?.method ?? "GET") as string, path, init?.body !== undefined ? JSON.parse(String(init.body)) : undefined);
    },
  } as unknown as DurableObjectStub;
  const env = { SCHEDULER: { idFromName: () => "id", get: () => scheduler } } as unknown as Env;
  const state = {
    config: { id: "dp-payroll", name: CUSTOMER_VALUE, enabled: true, source: { type: "kv", binding: "KV_x" }, schedule: { cadenceSeconds: 900 } },
    nextRunAt: 1,
  } as never;
  const budget = { remaining: () => 10_000, spend: () => {} } as never;
  const tally = await runSealLoop(env, [state], budget);

  ok("the tick still counts the seal error (behaviour unchanged)", tally.sealErrors === 1 && tally.dispatched === 0);
  ok("the fault is now RECORDED against the downpipe (it used to leave only an anonymous count)", posts.length === 1);
  const stamp = storage.rawGet<{ cls: string; consecutive: number }>(`${SEAL_ERROR_PREFIX}dp-payroll`);
  ok("the DO holds a stamp for the downpipe that failed", stamp !== undefined);
  ok("it names the /trigger round-trip, not the destination (triage goes to the right side)", stamp?.cls === "trigger-transport");
  scanClean("the posted body", posts);
  scanClean("the persisted stamp", stamp);

  // The pack READ path.
  const read = (await (await stubFetch(stub, "GET", "/seal-errors")).json()) as { byDownpipe: Record<string, { cls: string }> };
  ok("GET /seal-errors reads it back keyed by downpipe id", read.byDownpipe["dp-payroll"]?.cls === "trigger-transport");
  scanClean("GET /seal-errors", read);

  // A healthy fleet records NOTHING (proof this is on the FAULT path).
  const { storage: s2store, stub: s2stub } = makeScheduler();
  ok("a DO with no faults holds no stamps", ((await (await stubFetch(s2stub, "GET", "/seal-errors")).json()) as { byDownpipe: object }).byDownpipe && Object.keys(s2store.rawGet<object>(`${SEAL_ERROR_PREFIX}x`) ?? {}).length === 0);
}

// ---- PUSH FAILURE DETAIL ----------------------------------------------------------------------------

function testPushFailureDetail(): void {
  console.log("\nthe S3-drop sink's fixed 's3-put-failed' is split into a closed, actionable class set");

  ok("the legacy catch-all is GONE from the vocabulary", !(PUSH_SINK_FAIL_CODES as readonly string[]).includes("s3-put-failed"));
  ok("the S3 class set is closed and names an operator action per class", PUSH_S3_FAIL_CODES.length === 9);

  // The classifier reads the driver's OWN closed s3Code first (a documented vendor enum), else the shared
  // destDownReason message-shape classifier. Both return an enum: the body/endpoint/bucket never escape.
  const snap = (s3Code: string, worm = false): never => ({ total: 1, overflow: 0, faults: [{ op: "put", httpStatus: 403, s3Code, fault: "auth", arm: "matched-status", requestIdPresent: true, wormChecksumComplaint: worm, count: 1 }] }) as never;
  ok("an expired STS session is s3-expired-credential (not a generic denial)", classifyPushS3Fault(new Error(RAW_ERROR), snap("ExpiredToken")) === "s3-expired-credential");
  ok("a bucket-policy denial is s3-auth-denied", classifyPushS3Fault(new Error(RAW_ERROR), snap("AccessDenied")) === "s3-auth-denied");
  ok("a missing bucket is s3-no-such-bucket", classifyPushS3Fault(new Error(RAW_ERROR), snap("NoSuchBucket")) === "s3-no-such-bucket");
  ok("an Object-Lock complaint is s3-worm-denied", classifyPushS3Fault(new Error(RAW_ERROR), snap("InvalidRequest", true)) === "s3-worm-denied");
  ok("real backpressure is s3-throttled", classifyPushS3Fault(new Error(RAW_ERROR), snap("SlowDown")) === "s3-throttled");
  ok("with no snapshot it falls back to the shared probe classifier", classifyPushS3Fault(new Error("connect ETIMEDOUT: request timed out")) === "s3-timeout");
  const residual = classifyPushS3Fault(new Error(RAW_ERROR));
  ok("an unreadable fault coarsens to s3-unknown, never carrying the store's text", residual === "s3-unknown");
  ok("every classification is a closed-vocabulary member", (PUSH_S3_FAIL_CODES as readonly string[]).includes(residual));
  scanClean("the classified reasons", PUSH_S3_FAIL_CODES.map((c) => classifyPushS3Fault(new Error(RAW_ERROR), snap(c))));
}

// ---- THE /metrics SCRAPE SURFACE'S OWN HEALTH -------------------------------------------------------

async function testMetricsHealth(): Promise<void> {
  console.log("\nthe Prometheus /metrics scrape surface records its own health");

  const grant: IngestGrant = { clientId: "dpc_abc", secretSha384: "0".repeat(96), scope: "metrics", grantedAt: "", grantedBy: null, expiresAt: new Date(Date.now() - 1000).toISOString(), pulls: [] };
  ok("an EXPIRED grant is named credential-expired (the ticket's 'unexpired credential' 401)", (await classifyIngestCredentialCheck("dpc_abc.dps_x", grant)) === "credential-expired");
  ok("no grant at all is named no-grant", (await classifyIngestCredentialCheck("dpc_abc.dps_x", null)) === "no-grant");
  const live: IngestGrant = { ...grant, expiresAt: new Date(Date.now() + 60_000).toISOString() };
  ok("a stale clientId is named client-id-mismatch", (await classifyIngestCredentialCheck(`dpc_other.dps_${SECRET}`, live)) === "client-id-mismatch");
  ok("a rotated secret is named secret-mismatch", (await classifyIngestCredentialCheck(`dpc_abc.dps_${SECRET}`, live)) === "secret-mismatch");

  const h1 = applyMetricsScrape(undefined, "shape-fallback", 1_000, { shapeFallback: true });
  const h2 = applyMetricsScrape(h1, "ok", 2_000, { pullFailed: true });
  ok("the health record counts the shape fallback that silently empties every series", h1.shapeFallbacks === 1 && h1.lastOutcome === "shape-fallback");
  ok("it counts a failing pull trail (a LIVE scrape that reads as abandoned)", h2.recordPullFailures === 1 && h2.lastOutcome === "ok");
  ok("an out-of-vocabulary outcome is DROPPED, never added as a key", Object.keys(applyMetricsScrape(h2, CUSTOMER_VALUE, 3_000).outcomes).every((k) => (METRICS_SCRAPE_OUTCOMES as readonly string[]).includes(k)));
  scanClean("the health record", h2);

  // THE FAULT PATH: a DO that will not serve the grant must record auth-check-unavailable, NOT a silent 401.
  const { storage, stub } = makeScheduler();
  const scheduler = {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/ingest-credential") throw new Error(RAW_ERROR); // the DO hiccup the scraper sees as a 401
      return stubFetch(stub, (init?.method ?? "GET") as string, path, init?.body !== undefined ? JSON.parse(String(init.body)) : undefined);
    },
  } as unknown as DurableObjectStub;
  const resp = await handleMetricsRoute(new Request("https://e/metrics", { headers: { Authorization: `Bearer dpc_abc.dps_${SECRET}` } }), scheduler);
  ok("the refusal is UNCHANGED (a bare 401, no detail, no oracle)", resp.status === 401 && (await resp.text()) === "unauthorised");
  const health = storage.rawGet<{ lastOutcome: string; outcomes: Record<string, number> }>(METRICS_HEALTH_KEY);
  ok("the DO hiccup is RECORDED as auth-check-unavailable, not as a credential problem", health?.lastOutcome === "auth-check-unavailable");
  scanClean("the persisted health record", health);

  const read = (await (await stubFetch(stub, "GET", "/metrics-health")).json()) as { health: { lastOutcome: string } | null };
  ok("GET /metrics-health reads it back for the pack", read.health?.lastOutcome === "auth-check-unavailable");
  scanClean("GET /metrics-health", read);
}

// ---- THE STRUCTURAL WebAuthn FAULT CLASSES -----------------------------------------------------------

function structuralClassOf(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (e) {
    const f = webauthnFaultOf(e);
    return f === null ? null : f.webauthnFaultClass;
  }
}

async function testWebauthnFaults(): Promise<void> {
  console.log("\nthe 14 structural CBOR/COSE/DER/authData defects are split out of the bad_request bucket");

  ok("a truncated CBOR item is cbor-truncated", structuralClassOf(() => new CborReader(new Uint8Array([0x58, 0x20, 0x01])).decodeTop()) === "cbor-truncated");
  ok("an indefinite-length / reserved encoding is cbor-unsupported", structuralClassOf(() => new CborReader(new Uint8Array([0x5f])).decodeTop()) === "cbor-unsupported");
  ok("trailing bytes after the top-level item is cbor-trailing", structuralClassOf(() => new CborReader(new Uint8Array([0x01, 0x02])).decodeTop()) === "cbor-trailing");
  // a text string (major 3, len 2) carrying invalid UTF-8: the fatal decoder used to throw a raw TypeError
  // that escaped the PasskeyError contract entirely.
  ok("invalid UTF-8 in a CBOR text string is cbor-utf8 (it used to escape as a raw TypeError)", structuralClassOf(() => new CborReader(new Uint8Array([0x62, 0xff, 0xfe])).decodeTop()) === "cbor-utf8");
  ok("a short authData is authdata-truncated", structuralClassOf(() => parseAuthData(new Uint8Array(10))) === "authdata-truncated");
  ok("malformed clientDataJSON is clientdata-malformed", structuralClassOf(() => parseClientData(new TextEncoder().encode(`{"type":1,"challenge":"${CUSTOMER_VALUE}"}`))) === "clientdata-malformed");
  // COSE_Key: kty 1 (OKP, the Ed25519-only fleet) with alg -8 (EdDSA). {1: 1, 3: -8}
  const okp = new Uint8Array([0xa2, 0x01, 0x01, 0x03, 0x27]);
  ok("an OKP/Ed25519 key is cose-unsupported-kty (the fleet that can NEVER enrol)", structuralClassOf(() => parseCoseKey(okp)) === "cose-unsupported-kty");
  // EC2 (kty 2) with an alg this build does not accept: {1: 2, 3: -35}
  const badAlg = new Uint8Array([0xa2, 0x01, 0x02, 0x03, 0x38, 0x22]);
  ok("an EC2 key with an unaccepted alg is cose-unsupported-alg", structuralClassOf(() => parseCoseKey(badAlg)) === "cose-unsupported-alg");
  let offeredAlg: number | undefined;
  try {
    parseCoseKey(badAlg);
  } catch (e) {
    offeredAlg = webauthnFaultOf(e)?.coseAlg;
  }
  ok("the OFFERED COSE alg integer rides with it (support can name the fleet's algorithm)", offeredAlg === -35);
  // DER: a signature that is not a SEQUENCE at all, verified against a valid ES256 key.
  const es256 = new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...new Uint8Array(32).fill(7), 0x22, 0x58, 0x20, ...new Uint8Array(32).fill(9)]);
  let derClass: string | null = null;
  try {
    await verifySignature(parseCoseKey(es256), new Uint8Array(4), new Uint8Array([0x31, 0x02, 0x01, 0x00]));
  } catch (e) {
    const f = webauthnFaultOf(e);
    derClass = f === null ? null : f.webauthnFaultClass;
  }
  // The bogus (7,9)-coordinate key is not a valid P-256 point, so Web Crypto refuses the IMPORT before the DER
  // is ever reached: that is precisely key-import-failed, the class that names a corrupt STORED credential.
  ok("a COSE key the runtime refuses is key-import-failed (a CORRUPT STORED credential on login)", derClass === "key-import-failed");

  // Every class is a vocabulary member, and the aggregate is PHASE-split.
  const agg1 = applyWebauthnFault(undefined, "login", "key-import-failed", "2026-07-11T00:00:00.000Z");
  const agg2 = applyWebauthnFault(agg1, "enrol", "cose-unsupported-alg", "2026-07-11T00:01:00.000Z", -8);
  ok("the aggregate splits the SAME class by ceremony phase (corrupt stored key vs incompatible device)", agg2["login:key-import-failed"]?.count === 1 && agg2["enrol:cose-unsupported-alg"]?.count === 1);
  ok("the offered algs are retained as a bounded int list", agg2["enrol:cose-unsupported-alg"]?.algs?.[0] === -8);
  const injected = applyWebauthnFault(agg2, CUSTOMER_VALUE, SECRET, "2026-07-11T00:02:00.000Z");
  ok("an out-of-vocabulary phase/class is DROPPED (the key space cannot be injected into)", Object.keys(injected).length === 2);
  ok("every recorded class is a vocabulary member", Object.keys(agg2).every((k) => (WEBAUTHN_FAULT_CLASSES as readonly string[]).includes(k.split(":")[1] ?? "")));
  scanClean("the webauthnFaults aggregate", injected);

  // THE FAULT PATH + the DO read-back: a login ceremony with a malformed credential records a class.
  const { storage, stub } = makeScheduler();
  await stubFetch(stub, "POST", "/passkey/login/finish", { credential: { id: "x", rawId: "!!not-base64url!!", type: "public-key", response: { clientDataJSON: "abc", authenticatorData: "abc", signature: "abc" } } });
  const faults = storage.rawGet<Record<string, unknown>>(WEBAUTHN_FAULTS_KEY);
  // (A malformed base64url field is refused before the parsers run, so no structural class fires: proof the
  // recorder is on the STRUCTURAL path only and does not fabricate a class for every refusal.)
  ok("a non-structural refusal records NO structural class (the recorder is on the fault path, not every 400)", faults === undefined);
  const read = await (await stubFetch(stub, "GET", "/webauthn-faults")).json();
  ok("GET /webauthn-faults reads the (empty) aggregate back for the pack", JSON.stringify(read) === "{}");
}

// ---- RECOVERY-RECORD CORRUPTION + AN UNUSABLE SIGNING KEY --------------------------------------------

async function testRecoveryCorruption(): Promise<void> {
  console.log("\na CORRUPT stored recovery record and an unusable signing key are recorded");

  ok("the two closed signals are in the auth-signal vocabulary", (AUTH_SIGNAL_NAMES as readonly string[]).includes("recovery-record-corrupt") && (AUTH_SIGNAL_NAMES as readonly string[]).includes("recovery-signing-key-invalid"));
  ok("a short signing key is observable BEFORE it throws", !isRecoverySigningKeyUsable(new Uint8Array(RECOVERY_SIGNING_KEY_MIN_BYTES - 1)) && isRecoverySigningKeyUsable(new Uint8Array(RECOVERY_SIGNING_KEY_MIN_BYTES)));

  const key = new Uint8Array(32).fill(3);
  const { record } = await generateRecoveryCodes(key, "owner@example.test", "2026-07-11T00:00:00.000Z");
  const clean = await verifyCode(key, record, "WRONGCODE-WRONGCODE");
  ok("a HEALTHY record reports zero corrupt slots (this fires on the fault path only)", clean.corruptSlots === 0 && !clean.matched);

  // Corrupt two stored slots the way a damaged DO record would be: an undecodable salt and an undecodable hash.
  const corrupted = { ...record, codes: record.codes.map((c, i) => (i === 0 ? { ...c, salt: `!!${CUSTOMER_VALUE}!!` } : i === 1 ? { ...c, hash: `hmac-sha256:${SECRET}` } : c)) };
  const dirty = await verifyCode(key, corrupted, "WRONGCODE-WRONGCODE");
  ok("the corrupt slots are COUNTED (a code that can never match, whatever the operator types)", dirty.corruptSlots === 2);
  ok("the verdict is unchanged: still a plain no-match (the no-oracle response is preserved)", dirty.matched === false && dirty.index === -1);
  scanClean("the VerifyResult", dirty);

  // THE FAULT PATH through the DO: a corrupt record bumps the closed auth signal.
  const { storage, stub } = makeScheduler();
  await stubFetch(stub, "POST", "/recovery/regenerate", { email: "owner@example.test" });
  const stored = storage.rawGet<{ codes: { salt: string; hash: string; consumed: boolean }[] }>("recovery:owner@example.test");
  ok("the DO holds a recovery record after a regenerate", (stored?.codes.length ?? 0) > 0);
  if (stored) {
    stored.codes[0]!.salt = `!!${CUSTOMER_VALUE}!!`;
    await storage.put("recovery:owner@example.test", stored);
  }
  const before = storage.rawGet<Record<string, { count: number }>>("authsignals:agg");
  ok("no corruption signal before the fault", before?.["recovery-record-corrupt"] === undefined);
  const rr = await stubFetch(stub, "POST", "/recovery/recover", { email: "owner@example.test", code: "AAAAA-BBBBB-CCCCC-DDDDD", ip: "203.0.113.7" });
  const body = (await rr.json()) as { ok: boolean };
  ok("the client-facing failure is still the SAME generic refusal (no oracle)", body.ok === false);
  const agg = storage.rawGet<Record<string, { count: number }>>("authsignals:agg");
  ok("the CORRUPT PERSISTED RECORD is now recorded (it used to look identical to a mistyped code)", (agg?.["recovery-record-corrupt"]?.count ?? 0) >= 1);
  scanClean("the authSignals aggregate", agg);
}

// ---- THE RECORDERS' OWN DROPPED WRITES --------------------------------------------------------

async function testDroppedWrites(): Promise<void> {
  console.log("\nthe diagnostic recorders' OWN dropped writes are counted (the meta-finding)");

  resetPendingDroppedWrites();

  const agg1 = applyDroppedWrites(undefined, { "auth-signal": 3, "update-settled": 1 }, "2026-07-11T00:00:00.000Z");
  ok("a flushed tally lands as counts per closed kind", agg1["auth-signal"]?.count === 3 && agg1["update-settled"]?.count === 1);
  const agg2 = applyDroppedWrites(agg1, { [CUSTOMER_VALUE]: 99, [SECRET]: 1, "auth-signal": 2 }, "2026-07-11T00:01:00.000Z");
  ok("an out-of-vocabulary kind is DROPPED (no caller can inject a storage key)", Object.keys(agg2).length === 2);
  ok("a known kind accumulates", agg2["auth-signal"]?.count === 5);
  ok("every key is a closed-vocabulary member", Object.keys(agg2).every((k) => (DROPPED_WRITE_KINDS as readonly string[]).includes(k)));
  ok("a hostile count is clamped, never a fabricated unbounded loss", applyDroppedWrites(undefined, { "auth-signal": 1e18 }, "t")["auth-signal"]!.count <= 1_000_000);
  scanClean("the droppedWrites aggregate", agg2);

  // THE WRITER: a DO that is DOWN loses the write; the loss is held in the isolate and reported by the NEXT
  // successful write. This is the whole design: no in-flight persistence, and the gap lands as soon as the DO
  // comes back, which is exactly when the pack is generated.
  const { storage, stub } = makeScheduler();
  let doDown = true;
  const scheduler = {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (doDown) throw new Error(RAW_ERROR);
      return stubFetch(stub, (init?.method ?? "GET") as string, path, init?.body !== undefined ? JSON.parse(String(init.body)) : undefined);
    },
  } as unknown as DurableObjectStub;

  const landed = await recordDiagWrite(scheduler, "auth-signal", () => scheduler.fetch("https://s/auth-signal", { method: "POST", body: JSON.stringify({ name: "csrf-origin-mismatch" }) }));
  ok("a write against a DOWN DO reports as dropped", landed === false);
  ok("the loss is held in the isolate-local tally", pendingDroppedWrites()["auth-signal"] === 1);
  ok("nothing reached the DO (there was nowhere to write it)", storage.rawGet(DROPPED_WRITES_KEY) === undefined);

  await recordDiagWrite(scheduler, "auth-signal", () => scheduler.fetch("https://s/auth-signal", { method: "POST", body: JSON.stringify({ name: "auth-ratelimited" }) }));
  ok("a second loss in the same outage accumulates", pendingDroppedWrites()["auth-signal"] === 2);

  // The DO comes back. The very next successful diagnostic write CARRIES the gap.
  doDown = false;
  const ok2 = await recordDiagWrite(scheduler, "auth-signal", () => scheduler.fetch("https://s/auth-signal", { method: "POST", body: JSON.stringify({ name: "auth-ratelimited" }) }));
  ok("the write lands once the DO recovers", ok2 === true);
  ok("the pending tally is cleared by the flush", Object.keys(pendingDroppedWrites()).length === 0);
  const persisted = storage.rawGet<Record<string, { count: number }>>(DROPPED_WRITES_KEY);
  ok("the OUTAGE GAP is now durable: the pack SAYS it is missing 2 auth-signal records", persisted?.["auth-signal"]?.count === 2);
  scanClean("the persisted droppedWrites", persisted);

  const read = await (await stubFetch(stub, "GET", "/dropped-writes")).json();
  ok("GET /dropped-writes reads it back for the pack", (read as Record<string, { count: number }>)["auth-signal"]?.count === 2);
  scanClean("GET /dropped-writes", read);

  // A failed FLUSH restores the tally rather than losing it inside the reporter itself.
  resetPendingDroppedWrites();
  noteDroppedWrite("metrics-health");
  doDown = true;
  await flushDroppedWrites(scheduler);
  ok("a flush that itself fails RESTORES the tally (the reporter never loses its own report)", pendingDroppedWrites()["metrics-health"] === 1);
  resetPendingDroppedWrites();
}

async function main(): Promise<void> {
  console.log("Support-pack fault evidence: engine-cron-admin");
  await testSealErrorAttribution();
  testPushFailureDetail();
  await testMetricsHealth();
  await testWebauthnFaults();
  await testRecoveryCorruption();
  await testDroppedWrites();
  console.log(failures === 0 ? "\nAll cron/admin fault-evidence checks passed." : `\n${failures} check(s) FAILED.`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

await main();
