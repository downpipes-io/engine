// Prove the RESTORE leg reads back from an Azure Blob destination.
//
// WHY THIS IS A SEPARATE CLOSURE FROM THE WRITE. test/validate-azure-blob.ts grades the client against the
// Azure wire protocol: put, get, conditional put, block staging, listing, delete. That is the destination
// in isolation. It says nothing about whether a RESTORE, which goes through the dest factory, the verifying
// reader and the apply path, ever reaches that client at all. The two are wired by
// providerForEndpoint -> buildDestination, and a destination that writes perfectly and is never dispatched
// to on the read side is a destination customers cannot recover from. Google Cloud Storage closed its write
// and its direct-read in different rounds here for the same reason.
//
// WHAT THIS FILE PROVES, end to end, with no credential and no network:
//   1. buildDestination dispatches an Azure endpoint to the Azure client, not to the S3 one.
//   2. A sealed archive WRITTEN through the Azure client is RESTORED back through it, bytes matching, with
//      the archive bytes travelling over the Azure wire (Shared Key signed GETs against the container).
//   3. Every key the read leg asks for is a key the write leg stored under the same name, so the two legs
//      cannot disagree about encoding.
//   4. An object missing at the Azure destination fails the restore in the RIGHT class: a missing run-tree
//      object as availability (which routes the 3-2-1 replica walk), a missing segment as integrity (which
//      must never fall through to a replica).
//   5. The optional diagnostic accessors the Azure client does not implement are tolerated by their callers
// rather than assumed present, and the one it DOES implement (destIo,) answers.
//   6. A metered build charges the slice budget for Azure requests, which is what makes the sliced seal and
//      the 3-2-1 replication pass yield before the platform subrequest cap.
//
// THE MOCK IS DEFINED HERE RATHER THAN IMPORTED, and that is the local convention rather than duplication
// for its own sake. Cross-file test imports in this suite come only from files named as harnesses, shared
// fixtures or oracles (validate-audit-harness.ts, validate-posture-shared.ts). validate-azure-blob.ts is a
// runnable validator: it executes its whole suite at module top level and calls process.exit, so importing
// it would run that suite inside this one and let its verdict decide this file's exit code.
//
// Run: node test/validate-azure-restore.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { runRestore } from "../src/admin/restore.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { AzureBlobDestination } from "../src/dest/azure-blob.ts";
import { buildDestination, type RuntimeDestConfig } from "../src/dest/factory.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import type { Meter } from "../src/meter.ts";
import { REASON_INTEGRITY, REASON_OBJECT_MISSING } from "../src/restore-reasons.ts";
import { multipartAbortFlag } from "../src/seal/runstate-helpers.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

const ACCOUNT = "acct";
const ENDPOINT = `https://${ACCOUNT}.blob.core.windows.net`;
const CONTAINER = "archive";
const KEY_B64 = "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk=";
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_azure_restore";
const KVSET: Record<string, string> = { a: "alpha-value", b: "beta-value", "user:42": "gamma-value-longer" };

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

interface Blob {
  body: Uint8Array;
  etag: string;
}

/** An in-memory Azure Blob service, modelled on the one in validate-azure-blob.ts: it answers the shapes
 *  Azure answers (404 for an absent blob, a quoted ETag, a List Blobs document with NextMarker) and records
 *  every request, so a proof can assert the WIRE traffic rather than only the outcome. It does not
 *  authenticate; it asserts that a Shared Key header of the right shape arrived, and the signing itself is
 *  graded character for character in validate-azure-sharedkey.ts. */
class MockAzure {
  blobs = new Map<string, Blob>();
  requests: { method: string; path: string; query: string; headers: Record<string, string> }[] = [];
  private seq = 0;

  private nextEtag(): string {
    this.seq += 1;
    return `"0x${this.seq.toString(16).padStart(16, "0")}"`;
  }

  /** The keys reached by a request of this method, in call order, with the container prefix stripped. */
  keysFor(method: string): string[] {
    return this.requests.filter((r) => r.method === method && r.path.startsWith(`/${CONTAINER}/`)).map((r) => r.path.slice(CONTAINER.length + 2));
  }

  handler = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = String(v);
    this.requests.push({ method, path: decodeURIComponent(url.pathname), query: url.search, headers });

    // Every credentialed call must carry a Shared Key Authorization header. An S3 client pointed at this
    // endpoint sends AWS4-HMAC-SHA256 and lands here, which is what a real Azure account answers too.
    if (!new RegExp(`^SharedKey ${ACCOUNT}:`).test(headers.authorization ?? "")) {
      return new Response("", { status: 403, headers: { "x-ms-error-code": "AuthenticationFailed" } });
    }

    const parts = url.pathname.replace(/^\//, "").split("/");
    const key = parts.slice(1).map(decodeURIComponent).join("/");
    const comp = url.searchParams.get("comp");

    if (comp === "list") {
      const prefix = url.searchParams.get("prefix") ?? "";
      const marker = url.searchParams.get("marker") ?? "";
      const all = [...this.blobs.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = marker === "" ? 0 : all.indexOf(marker);
      const page = all.slice(start, start + 2);
      const rest = all.slice(start + 2);
      const names = page.map((k) => `<Blob><Name>${k.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</Name></Blob>`).join("");
      const next = rest.length > 0 ? `<NextMarker>${rest[0]}</NextMarker>` : "<NextMarker />";
      return new Response(`<?xml version="1.0"?><EnumerationResults><Blobs>${names}</Blobs>${next}</EnumerationResults>`, { status: 200 });
    }

    if (method === "PUT") {
      const body = new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer());
      const etag = this.nextEtag();
      this.blobs.set(key, { body, etag });
      return new Response("", { status: 201, headers: { etag } });
    }

    const blob = this.blobs.get(key);
    if (method === "GET") {
      if (blob === undefined) return new Response("", { status: 404, headers: { "x-ms-error-code": "BlobNotFound" } });
      return new Response(blob.body as unknown as BodyInit, { status: 200, headers: { etag: blob.etag } });
    }
    if (method === "HEAD") return new Response("", { status: blob === undefined ? 404 : 200 });
    if (method === "DELETE") {
      if (blob === undefined) return new Response("", { status: 404, headers: { "x-ms-error-code": "BlobNotFound" } });
      this.blobs.delete(key);
      return new Response("", { status: 202 });
    }
    return new Response("", { status: 405 });
  };
}

function install(mock: MockAzure): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = mock.handler as unknown as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

/** MockKV is the KVNamespace surface the KV restore sink writes through, tracking a put count so a refused
 *  restore can be proven to have written nothing. */
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    if (v === undefined) return null;
    const out = new ArrayBuffer(v.byteLength);
    new Uint8Array(out).set(v);
    return out;
  }
}

// makeRecipient builds a hybrid recipient public entry and its 96-byte private identity
// (x25519 scalar(32) || ML-KEM seed(64)), matching the restore validator's idiom.
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

/** The console-set destination an Owner would store for an Azure container: the storage ACCOUNT in
 *  accessKeyId and one of its access keys in secretAccessKey, which is the credential shape the factory
 *  reuses rather than adding Azure-only fields. */
const AZURE_CFG: RuntimeDestConfig = {
  endpoint: ENDPOINT,
  bucket: CONTAINER,
  region: "",
  accessKeyId: ACCOUNT,
  secretAccessKey: KEY_B64,
};

interface Fixture {
  archive: Map<string, Uint8Array>;
  env: () => Env;
  kv: MockKV;
}

// seal builds a signed archive over KVSET and returns it with the env the engine restores under. Nothing is
// written to the destination here; each proof installs its own mock and writes through the Azure client, so
// the write leg is exercised inside the proof rather than assumed.
async function seal(): Promise<Fixture> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  const archive = await buildArchive({
    downpipeId: "dp_azure_restore",
    downpipeName: "azure-restore",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS })),
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });

  const kv = new MockKV();
  const env = (): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      [`KV_${NS}`]: kv as unknown as KVNamespace,
    }) as unknown as Env;

  return { archive, env, kv };
}

// writeArchiveThroughAzure puts every archive object into the container THROUGH the Azure client, so the
// keys the restore reads are keys this destination's own encoding produced, not entries poked into a map.
async function writeArchiveThroughAzure(archive: Map<string, Uint8Array>): Promise<string[]> {
  const dest = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64);
  const written: string[] = [];
  for (const [k, body] of archive) {
    await dest.put(k, body);
    written.push(k);
  }
  return written;
}

// ---- 1. the factory dispatches an Azure endpoint to the Azure client -------------------------------
async function dispatch(): Promise<void> {
  console.log("the restore path's destination build reaches the Azure client:");
  const dest = await buildDestination({} as unknown as Env, undefined, AZURE_CFG);
  // WOULD THIS PASS IF THE FEATURE WERE GONE? No. Without the provider dispatch in buildDestinationInner
  // the Azure config falls through to the S3 branch, so this is an S3Destination and both lines go red.
  ok("an Azure endpoint builds an AzureBlobDestination", dest instanceof AzureBlobDestination, dest.constructor.name);
  ok("...and specifically NOT the S3 client, which cannot authenticate to Azure at all", !(dest instanceof S3Destination));

  // The account is cross-checked against the endpoint host, so a credential naming a different account
  // fails at construction rather than as a 403 that names neither.
  let refused = "";
  await buildDestination({} as unknown as Env, undefined, { ...AZURE_CFG, accessKeyId: "otheracct" }).catch((e) => {
    refused = (e as Error).message;
  });
  // WOULD THIS PASS IF THE FEATURE WERE GONE? No. Drop the mismatch guard and the build succeeds, so
  // `refused` stays empty and both halves go red.
  ok("an account that disagrees with the endpoint host is refused at build time", refused !== "");
  ok("...and the refusal names both accounts", refused.includes("otheracct") && refused.includes(ACCOUNT), refused);

  await pacerIsAttachedByTheFactory();
}

// pacerIsAttachedByTheFactory proves the ADAPTIVE PACER reaches an Azure destination, and that the env knob
// that governs it is the same one that governs an S3 destination. The pacer itself is private, so it is
// observed through the only thing it makes visible: the worst effective rate the degradation snapshot
// records. A destination built with NO pacer records no rate at all, so the value is the witness.
async function pacerIsAttachedByTheFactory(): Promise<void> {
  console.log("the factory attaches the adaptive pacer to an Azure destination, from the shared env knobs:");
  const realFetch = globalThis.fetch;
  // 503 ServerBusy is Azure's own backpressure answer. The rate is set low enough that the halving lands on
  // an exact integer, and the burst matches it, so the pacer never sleeps during the test.
  globalThis.fetch = (async () => new Response("", { status: 503, headers: { "x-ms-error-code": "ServerBusy" } })) as unknown as typeof fetch;
  try {
    const env = { DEST_RATE_PER_SEC: "8", DEST_BURST: "8" } as unknown as Env;
    const dest = await buildDestination(env, undefined, AZURE_CFG);
    await dest.put("seg/x", new TextEncoder().encode("x")).catch(() => undefined);
    const io = dest.destIo?.();
    // WOULD THIS PASS IF THE FEATURE WERE GONE? No. Drop `pacer:` from the Azure branch of
    // buildDestinationInner and no rate is ever recorded, so minEffectiveRatePerSec is undefined and both
    // lines go red. Read the knob wrong and the number is 25 (the halved default), not 4.
    ok("a pacer is attached, so a throttled Azure destination records the rate it was driven down to", io?.minEffectiveRatePerSec !== undefined, JSON.stringify(io));
    ok("...and DEST_RATE_PER_SEC governs it, exactly as it governs an S3 destination (8 halved is 4)", io?.minEffectiveRatePerSec === 4, JSON.stringify(io));
    ok("...and the 503 is counted as store backpressure on the run row", io?.throttleObservations === 1, JSON.stringify(io));
  } finally {
    globalThis.fetch = realFetch;
  }
}

// ---- 2. a run written to Azure restores back out of Azure ------------------------------------------
async function roundTrip(fix: Fixture): Promise<MockAzure> {
  console.log("a sealed run written to an Azure container restores back out of it:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const written = await writeArchiveThroughAzure(fix.archive);
    const writeRequests = mock.requests.length;

    const res = (await runRestore(fix.env(), { runId: RUN_ID, confirm: true }, AZURE_CFG)) as { mode?: string; ok?: boolean; recordsRestored?: number; failures?: unknown[] };

    // WOULD THIS PASS IF THE FEATURE WERE GONE? No. With no Azure read leg the reader's first get answers
    // 403 (an S3 client) or nothing at all, the run never opens, and the apply never reaches "applied".
    ok("the restore applied", res.mode === "applied" && res.ok === true, JSON.stringify(res.mode));
    ok("...restoring every record", res.recordsRestored === Object.keys(KVSET).length, String(res.recordsRestored));
    ok("...with no failures", Array.isArray(res.failures) && res.failures.length === 0);

    let bytesMatch = true;
    for (const [name, v] of Object.entries(KVSET)) {
      const got = fix.kv.store.get(name);
      if (got === undefined || new TextDecoder().decode(got) !== v) bytesMatch = false;
    }
    // WOULD THIS PASS IF THE FEATURE WERE GONE? No. This is the recovery claim itself: a restore that
    // applied but wrote different bytes fails here, and only here.
    ok("every restored value byte-matches the sealed original", bytesMatch);
    ok("...and nothing extra was written", fix.kv.store.size === Object.keys(KVSET).length, String(fix.kv.store.size));

    // The bytes must have come off the wire, not out of the mock's map by some other route.
    const reads = mock.requests.slice(writeRequests).filter((r) => r.method === "GET");
    // WOULD THIS PASS IF THE FEATURE WERE GONE? No. If the restore read through anything other than the
    // Azure client there are no GETs after the write leg's requests, so reads is empty.
    ok("the restore issued Azure GETs after the write leg", reads.length > 0, String(reads.length));
    ok("...every one of them Shared Key signed", reads.every((r) => new RegExp(`^SharedKey ${ACCOUNT}:`).test(r.headers.authorization ?? "")));
    ok("...including the run's signed root manifest", reads.some((r) => r.path === `/${CONTAINER}/run/${RUN_ID}/root.manifest.json`), JSON.stringify(reads.map((r) => r.path)));
    ok("...and at least one content-addressed segment, which is where the record bytes live", reads.some((r) => r.path.startsWith(`/${CONTAINER}/seg/`)));

    // 3. The two legs must agree on key naming: the client encodes the path for the URL and signs it raw,
    // so a key that round-trips wrong is a key the restore cannot address.
    const readKeys = new Set(mock.keysFor("GET"));
    const unknown = [...readKeys].filter((k) => !written.includes(k));
    // WOULD THIS PASS IF THE FEATURE WERE GONE? No. Break the encode/decode agreement in the client's send()
    // and the read leg asks for a mangled key that the write leg never stored, which lands in `unknown`.
    ok("every key the restore read is a key the write leg stored under that same name", unknown.length === 0, JSON.stringify(unknown));
    return mock;
  } finally {
    restore();
  }
}

// ---- 4. a missing object at the Azure destination fails the restore, in the RIGHT class -------------
//
// THE CLASS IS THE POINT, and the first draft of this proof got it wrong. Asserting only "the restore did
// not report success" passes even when the client's 404 handling is broken, because the reader hashes what
// it is given and a zero-byte object fails that hash anyway. Measured: replacing `return null` on a 404 with
// an empty GetResult left every such assertion green.
//
// What the 404-reads-as-absent behaviour actually decides is the REASON, and the reason decides the 3-2-1
// walk. A missing run-tree object must classify as the availability reason REASON_OBJECT_MISSING, which
// isReplicaFallbackReason routes to the next destination: that is the whole DR payoff. A missing content-
// addressed segment of a present, signed run must classify as REASON_INTEGRITY, which is deliberately NOT in
// the fallback set (INT-3: a completeness shortfall of a signed run is a tamper-equivalent signal and must
// never be waved past to a replica). Under the broken 404 both collapse to integrity, so a run simply absent
// from the primary would never reach its replica and the operator would be told the archive was corrupt.
async function missingObjectFails(): Promise<void> {
  console.log("an object missing at the Azure destination fails the restore, in the class that decides the 3-2-1 walk:");

  // A missing RUN-TREE object: the availability case, the one a replica can serve.
  const treeCase = await restoreWithout(() => `run/${RUN_ID}/root.manifest.json`);
  ok("a missing run-tree object fails the restore", treeCase.ok !== true, JSON.stringify(treeCase));
  // WOULD THIS PASS IF THE FEATURE WERE GONE? No, and this is the line that binds. Make the Azure client
  // answer anything but null on a 404 and the reason becomes REASON_INTEGRITY, which is not a fallback
  // reason, so the run never reaches its replica. Measured against that exact mutation.
  ok("...as the AVAILABILITY reason, which is what routes the 3-2-1 replica walk", treeCase.reason === REASON_OBJECT_MISSING, String(treeCase.reason));
  ok("...and wrote nothing to the sink", treeCase.putCount === 0, String(treeCase.putCount));

  // A missing SEGMENT of a present, signed run: the completeness case, which must NEVER fall back.
  const segCase = await restoreWithout((mock) => [...mock.blobs.keys()].find((k) => k.startsWith("seg/")) ?? "");
  ok("a missing content-addressed segment fails the restore", segCase.ok !== true, JSON.stringify(segCase));
  // WOULD THIS PASS IF THE FEATURE WERE GONE? No. Remove the INT-3 seg/ arm in restore-open.ts's store
  // closure and a gone segment reads as the plain availability reason, so this goes red and a
  // tamper-equivalent signal starts falling through to a replica.
  ok("...as the INTEGRITY reason, so a signed run's missing bytes never fall through to a replica", segCase.reason === REASON_INTEGRITY, String(segCase.reason));
  ok("...and wrote nothing to the sink", segCase.putCount === 0, String(segCase.putCount));

  // WOULD THIS PASS IF THE FEATURE WERE GONE? No. It is the distinction itself: under a broken 404 both
  // cases report integrity, and this is the one line that sees them collapse into each other.
  ok("the two absences are told APART, rather than collapsing into one reason", treeCase.reason !== segCase.reason, `${treeCase.reason} / ${segCase.reason}`);
}

/** restoreWithout seals a fresh run, writes it to a fresh Azure container through the Azure client, removes
 *  the one object `pick` names, and restores. Returns the outcome plus how many writes reached the sink, so
 *  a refused restore can be proven to have applied nothing. */
async function restoreWithout(pick: (mock: MockAzure) => string): Promise<{ ok?: boolean; reason?: string; putCount: number }> {
  const fix = await seal();
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    await writeArchiveThroughAzure(fix.archive);
    const victim = pick(mock);
    if (victim === "" || !mock.blobs.has(victim)) {
      // A fixture that removed nothing would grade nothing, so it is a failure rather than a quiet pass.
      ok(`the archive holds the object this case removes (${victim === "" ? "none named" : victim})`, false);
      return { putCount: fix.kv.putCount };
    }
    mock.blobs.delete(victim);
    try {
      const res = (await runRestore(fix.env(), { runId: RUN_ID, confirm: true }, AZURE_CFG)) as { ok?: boolean; reason?: string };
      return { ...res, putCount: fix.kv.putCount };
    } catch (e) {
      return { ok: false, reason: `THREW: ${(e as Error).message}`, putCount: fix.kv.putCount };
    }
  } finally {
    restore();
  }
}

// ---- 5. the accessors Azure does not implement are tolerated, never assumed ------------------------
async function optionalAccessorsTolerated(): Promise<void> {
  console.log("the optional diagnostic accessors the Azure client omits are tolerated by their callers:");
  // Typed as the INTERFACE, because that is the question: a caller holding a Destination is the one that has
  // to survive the absence. The concrete class does not declare these at all.
  const dest: Destination = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64);
  // These are OPTIONAL on the Destination interface and are honestly absent here rather than fabricated as
  // zero, which is the convention seal/run-fault-report.ts states for a driver that cannot answer.
  ok("multipartAbortFailures is absent (Azure stages blocks, it has no S3 multipart upload to strand)", typeof dest.multipartAbortFailures !== "function");
  ok("destFaults is absent (the S3 fault ring is an S3 <Code> vocabulary)", typeof dest.destFaults !== "function");
  // destIo MOVED from absent to present, and the line is kept rather than deleted because the
  // absence it used to assert was the gap: the degradation vocabulary is not S3-specific the way the fault
  // ring's <Code> table is, so an Azure destination that was throttled or black-holed had nowhere to say so
  // and read as healthy. It is now implemented, and a caller reading it on a fresh instance must get the
  // clean snapshot rather than nothing.
  ok("destIo is now PRESENT, because the degradation counters are shared machinery and not an S3 vocabulary", typeof dest.destIo === "function");
  const fresh = dest.destIo?.();
  ok("...and a destination that has issued no request reports a clean snapshot", fresh?.throttleObservations === 0 && fresh?.timeouts === 0, JSON.stringify(fresh));
  ok("...carrying no pacer rate at all, since nothing has been observed to pace", fresh?.minEffectiveRatePerSec === undefined, JSON.stringify(fresh));

  let threw = false;
  let flag: Record<string, unknown> = {};
  try {
    flag = multipartAbortFlag(dest);
  } catch {
    threw = true;
  }
  // WOULD THIS PASS IF THE FEATURE WERE GONE? No. multipartAbortFlag feature-detects the accessor; call it
  // unguarded and this throws a TypeError, so `threw` goes true and the line goes red. That is the exact
  // shape a run against an Azure destination would hit at completion.
  ok("the seal driver's stranded-parts read tolerates the absence rather than throwing", !threw);
  ok("...and stamps nothing on the run row, so no fault is invented", Object.keys(flag).length === 0, JSON.stringify(flag));
}

// ---- 6. a metered build charges the slice budget for Azure requests ---------------------------------
async function meteredBuildCharges(): Promise<void> {
  console.log("a metered Azure destination charges the slice budget, so a sliced pass can yield:");
  const mock = new MockAzure();
  const restoreFetch = install(mock);
  try {
    let spent = 0;
    const meter: Meter = {
      spend(n = 1) {
        spent += n;
      },
    };
    const dest = await buildDestination({} as unknown as Env, meter, AZURE_CFG);
    await dest.put("seg/metered", utf8("x"));
    await dest.get("seg/metered");
    await dest.exists("seg/metered");
    // WOULD THIS PASS IF THE FEATURE WERE GONE? No. Before the meter was threaded through, an Azure
    // destination spent the invocation's subrequests without ever moving the budget, so `spent` stayed 0
    // and the replication pass never yielded. Removing either the factory's meter argument or the client's
    // spend takes this to 0.
    ok("every Azure request charged the meter", spent === 3, String(spent));
  } finally {
    restoreFetch();
  }
}

console.log("azure restore leg\n");
await dispatch();
const fixture = await seal();
await roundTrip(fixture);
await missingObjectFails();
await optionalAccessorsTolerated();
await meteredBuildCharges();

console.log(failures === 0 ? "\nAZURE RESTORE PASS" : `\n${failures} check(s) FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
