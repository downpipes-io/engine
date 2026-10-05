// The canary's classified ailing cause must reach the support pack.
//
// A flight that cannot complete finalises "ailing" with a closed CanaryAilingCause (canary/cycle.ts): the
// destDownReason class of the thrown write or read (auth, worm-refused, throttled, timeout, network, tls,
// other), or probe-mismatch. canaryComplete stores it on the destination's lastCheck (scheduler-do-canary.ts),
// and the pack's canary section (fetchCanaryHealth, admin/support-sections-seal.ts) projected only the
// aggregate status, the transitions and deadDetail. So an expired key pair, a WORM refusal and a throttling
// store all read "ailing" in the pack, with nothing to tell them apart.
//
// With the change getCanaryTransitions returns ailingDetail for each destination ailing now, and the pack
// projects { at, ailingCause, failedAspects }: an ISO timestamp, a closed cause (or causeAbsent) and closed
// aspect keys. A row names no destination.
//
// Run: node test/validate-canary-ailing-cause-pack.ts

import { readFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519.js";
import { fetchCanaryHealth } from "../src/admin/support-sections-seal.ts";
import { runCanaryCycle } from "../src/canary/cycle.ts";
import type { CanaryCheckResult, CanaryFlightPlan } from "../src/canary/types.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { DEST_DOWN_REASONS } from "../src/dest/classify.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

// The destination's id and label are customer values: neither may appear in an ailingDetail row.
const DEST_ID = "acme-ledger-dest";
const DEST_LABEL = "Acme payroll archive";
const ROW_KEYS = new Set(["at", "ailingCause", "causeAbsent", "failedAspects"]);

function makeDO(): { stub: DurableObjectStub; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(String(input), init)) } as unknown as DurableObjectStub;
  return { stub, storage };
}

async function seedDest(storage: MockStorage): Promise<void> {
  await storage.put("destinations", { list: [{ id: DEST_ID, label: DEST_LABEL, endpoint: "https://x.example", bucket: "acme-bucket", region: "auto", accessKeyId: "k", secretAccessKey: "s", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }], defaultId: DEST_ID });
}

let clock = 5_000_000;
async function fly(stub: DurableObjectStub, results: CanaryCheckResult[]): Promise<void> {
  const post = (path: string, body: unknown): Promise<Response> => stub.fetch(`https://scheduler.internal${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  await post("/canary/run-now", {});
  clock += 1_000_000;
  const due = (await (await post("/canary/due", { nowMs: clock })).json()) as { due: boolean; run?: CanaryFlightPlan };
  if (!due.due || !due.run) throw new Error("the canary was expected to be due");
  await post("/canary/complete", { run: due.run, results });
}

const ailing = (cause: string | undefined, aspect: string): CanaryCheckResult =>
  ({ status: "ailing", durationMs: 7, destinationId: DEST_ID, aspects: [{ key: aspect, outcome: "fail", detail: "x" }], byteDelta: null, deadReason: null, ...(cause !== undefined ? { ailingCause: cause } : {}) }) as CanaryCheckResult;

type Row = Record<string, unknown> & { ailingCause?: string; causeAbsent?: boolean; failedAspects?: string[]; at?: string };
const rowsOf = (pack: Record<string, unknown>): Row[] => (Array.isArray(pack.ailingDetail) ? (pack.ailingDetail as Row[]) : []);
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const rowShapeOk = (r: Row | undefined): boolean => r !== undefined && Object.keys(r).every((k) => ROW_KEYS.has(k)) && (r.at === undefined || ISO.test(r.at));

// An S3 wire that refuses every request with 403 AccessDenied: a revoked or rotated key pair.
function deniedWire(): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response("<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>", { status: 403, headers: { "x-amz-request-id": "REQ1" } })) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

async function main(): Promise<void> {
  console.log("A. every cause a flight can produce reaches the pack:");
  const cycleSrc = readFileSync(new URL("../src/canary/cycle.ts", import.meta.url), "utf8");
  const literal = [...cycleSrc.matchAll(/ailingCause: "([a-z-]+)"/g)].map((m) => m[1]!);
  const derived = /ailingCause: destDownReason\(/.test(cycleSrc) ? [...DEST_DOWN_REASONS] : [];
  const causes = [...new Set([...literal, ...derived])].sort();
  ok(`population: ${causes.length} producible causes (${causes.join(", ")})`, causes.length >= 8 && causes.includes("probe-mismatch"));
  const carried: string[] = [];
  let shapesOk = 0;
  for (const cause of [...causes, "unreachable"]) {
    const { stub, storage } = makeDO();
    await seedDest(storage);
    await fly(stub, [ailing(cause, "write-probe")]);
    const pack = await fetchCanaryHealth(stub);
    const row = rowsOf(pack)[0];
    if (row?.ailingCause === cause && (row.failedAspects ?? []).includes("write-probe")) carried.push(cause);
    if (rowShapeOk(row) && typeof row?.at === "string") shapesOk++;
  }
  ok(`every cause rides with its failed aspect (${carried.length} of ${causes.length + 1}, with the legacy unreachable)`, carried.length === causes.length + 1);
  ok(`every row carries only at, the cause and the aspects, with an ISO at (${shapesOk} of ${causes.length + 1})`, shapesOk === causes.length + 1);

  console.log("B. a real flight against a store that refuses the key pair:");
  {
    const xk = x25519.keygen();
    const env = {
      DEST_KIND: "s3",
      DEST_ENDPOINT: "https://s3.us-east-1.amazonaws.com",
      DEST_BUCKET: "acme-archive",
      DEST_REGION: "us-east-1",
      DEST_ACCESS_KEY_ID: "AKIAEXAMPLEEXAMPLE",
      DEST_SECRET_ACCESS_KEY: "example-secret-not-real",
      SIGNER_PRIVATE: b64urlEncode(concat(rand(32), rand(32))),
      BREAK_GLASS_PUBLIC: b64urlEncode(concat(xk.publicKey, mlkemKeygen(rand(64)).encapKey)),
    } as unknown as Env;
    const empty = { fetch: async () => new Response("{}", { status: 200 }) } as unknown as DurableObjectStub;
    const restore = deniedWire();
    let result: CanaryCheckResult;
    try {
      result = await runCanaryCycle(env, empty, { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", runSeq: 1, destinationId: null, cleanupRunId: null });
    } finally {
      restore();
    }
    ok(`the flight finalises ailing with the auth cause (got ${result.status}/${result.ailingCause ?? "none"})`, result.status === "ailing" && result.ailingCause === "auth");
    const { stub, storage } = makeDO();
    await seedDest(storage);
    await fly(stub, [{ ...result, destinationId: DEST_ID }]);
    const pack = await fetchCanaryHealth(stub);
    ok("the pack's aggregate status is ailing", pack.status === "ailing");
    const row = rowsOf(pack)[0];
    ok("canary.ailingDetail names the cause: auth", row?.ailingCause === "auth");
    ok("and the failed aspect: write-probe", (row?.failedAspects ?? []).includes("write-probe"));
    const text = JSON.stringify(rowsOf(pack));
    ok("REDACTION: the row names no destination, bucket, endpoint or key", !text.includes(DEST_ID) && !text.includes(DEST_LABEL) && !text.includes("acme-archive") && !text.includes("amazonaws") && !text.includes("AKIA") && !text.includes("AccessDenied"));
  }

  console.log("C. controls:");
  {
    const { stub, storage } = makeDO();
    await seedDest(storage);
    await fly(stub, [ailing("SNTL-U5 free text sntl@example.invalid", "seal")]);
    const pack = await fetchCanaryHealth(stub);
    const row = rowsOf(pack)[0];
    ok("a stored cause outside the vocabulary is not forwarded", !JSON.stringify(pack).includes("SNTL-U5"));
    ok("it rides as causeAbsent with its closed aspect", row?.causeAbsent === true && row.ailingCause === undefined && (row.failedAspects ?? []).includes("seal"));
  }
  {
    // The pack's own gate, over a DO view it does not trust: text in each slot is dropped.
    const hostile = { fetch: async () => new Response(JSON.stringify({ enabled: true, status: "ailing", transitions: [], ailingDetail: [{ destinationId: DEST_ID, at: `when ${DEST_LABEL} failed`, ailingCause: "auth", failedAspects: ["write-probe", "SNTL-aspect", "write-probe"], note: "SNTL-note" }] })) } as unknown as DurableObjectStub;
    const pack = await fetchCanaryHealth(hostile);
    const row = rowsOf(pack)[0];
    ok("a hostile view keeps only the closed cause and aspects: no destination id, text time, unknown aspect or extra key", rowShapeOk(row) && row?.at === undefined && row?.ailingCause === "auth" && (row.failedAspects ?? []).join(",") === "write-probe" && !JSON.stringify(pack).includes("SNTL") && !JSON.stringify(pack).includes(DEST_ID));
  }
  {
    const { stub, storage } = makeDO();
    await seedDest(storage);
    await fly(stub, [{ status: "alive", durationMs: 5, destinationId: DEST_ID, aspects: [], byteDelta: 0, deadReason: null }]);
    ok("an alive destination has no ailingDetail", rowsOf(await fetchCanaryHealth(stub)).length === 0);
  }
  {
    const { stub, storage } = makeDO();
    await seedDest(storage);
    await fly(stub, [{ status: "dead", durationMs: 6, destinationId: DEST_ID, aspects: [{ key: "decrypt-integrity", outcome: "fail", detail: "x" }], byteDelta: 1, deadReason: "decrypt-integrity: 1 byte strayed" }]);
    const pack = await fetchCanaryHealth(stub);
    ok("a dead destination stays in deadDetail and is not in ailingDetail", rowsOf(pack).length === 0 && Array.isArray(pack.deadDetail));
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-canary-ailing-cause-pack (${failures} failure(s))`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
