// Axis residency, Tier 1: the engine-behaviour half of the two-region data-residency
// proof, net-zero and deploy-free. It drives the REAL selection and fan-out code against in-memory
// destinations the HARNESS tags with a jurisdiction the engine does not have, and asserts what the engine
// actually does at the seam the design identifies.
//
// The headline finding is a DETECT, not a green: the engine has no jurisdiction model and no jurisdiction
// guard anywhere on the destination-write plane. The word `jurisdiction` occurs once in the engine source
// (src/admin/bindings-sync.ts:99), and there it renders a SOURCE R2 binding for a reconcile-deploy; it never
// touches a destination. So the eu-gdpr "Backups can be pinned to an EU region you choose, so a backup copy
// need not become a third-country transfer" claim (src/admin/frameworks.ts:146, checkId
// destination-configured) holds ONLY for a downpipe whose EVERY destination is an EU-jurisdiction bucket. For
// a mixed or a failed-over EU downpipe the record crosses the boundary, silently, on a green run.
//
// What this proves, over the real engine functions, with a HARNESS-owned jurisdiction tag the engine cannot
// read (the harness owns the in-memory store, so it knows exactly which jurisdiction each write landed in):
//   A  fan-out replicate copies an EU-origin run into a default-jurisdiction store (crossing), driving the
//      real mirrorRunToReplica (src/seal/replicate.ts:669) enumerated by the real allDestinationIds
//      (src/sched/destinations.ts:32-35, src/seal/replicate.ts:218,737).
//   B  the real selectSealDestination (src/cron/seal-dispatch.ts:144, loop :162-190) hands back the
//      NON-EU replica when the EU primary is down, observed two ways (the per-tick probe cache seam, and the
//      real destinationReachable put-probe over a genuinely-refusing EU endpoint). This is the load-bearing
//      disproof: no guard by OBSERVATION of the real selector, not merely by grep.
//   C  the config path has no jurisdiction field and no guard and no warning (correct-by-inspection, made
//      executable: it reads the ABSENCE at src/dest/factory.ts:31-60 and the grep-once fact).
//   D  REFUTER (default-FAIL): an all-EU fan-out is NOT reported as crossing, so A and B are not vacuously
//      always-crossing and the crossing detector is two-sided.
//   E  the credited protection that DOES hold: a single-destination pinned EU downpipe whose record is gone
//      fails LOUD (src/cron/seal-dispatch.ts:86-93,155-158), never a silent fallback to a different bucket.
//   F  REFUTER (default-FAIL): the cross-region S3 redirect is genuinely REFUSED, not followed
//      (src/dest/s3-read-ops.ts:72-74), so no redirect vector silently re-homes a read across a region.
//
// Net-zero: in-process over in-memory doubles, the jurisdiction tags are the harness's OWN Map, the signer +
// recipients are HARNESS-MINTED (crypto.subtle Ed25519 + mldsaKeygen; x25519.keygen() plus a random ML-KEM
// seed), the records are fake, and the "down" primary and the redirect are injected into a HARNESS-owned
// fetch, never a real endpoint. No estate, bucket, network, seed, spend or deploy; teardown is process exit.
// Run: node test/validate-residency-tier1.ts

import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { x25519 } from "@noble/curves/ed25519.js";
import { utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { allDestinationIds, type DownpipeState, primaryDestinationId } from "../src/sched/scheduler-do.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { mirrorRunToReplica } from "../src/seal/replicate.ts";
import { destinationReachable, selectSealDestination } from "../src/index.ts";
import { MemoryDestination } from "./memdest.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- the harness-owned jurisdiction tag (the engine has NO field for this) -------------------------------
// jurisdictionOf is the harness's OWN label for each destination id, of its own choosing, invisible to the
// engine. Ground truth for "did this record cross the boundary" is read from HERE and from the in-memory
// stores the harness owns, never from any engine self-report.
type Jurisdiction = "eu" | "default";
const jurisdictionOf = new Map<string, Jurisdiction>();

// TaggedStore is an in-memory Destination carrying its harness id + jurisdiction, for the cells that drive a
// Destination double directly (the replicate copy). It is the shipped MemoryDestination with a label bolted
// on; the engine only ever sees the Destination contract, never the label.
class TaggedStore extends MemoryDestination {
  readonly id: string;
  readonly jurisdiction: Jurisdiction;
  constructor(id: string, jurisdiction: Jurisdiction) {
    super();
    this.id = id;
    this.jurisdiction = jurisdiction;
    jurisdictionOf.set(id, jurisdiction);
  }
}

// storeHoldsRun reads (from the harness-owned store) whether a run's customer bytes landed here: its run-tree
// objects, its content-addressed data segments, and a RUNLOG entry. A crossing is this returning true for a
// store the harness tagged "default".
async function storeHoldsRun(store: MemoryDestination, runId: string): Promise<{ tree: boolean; seg: boolean; runlog: boolean; holds: boolean }> {
  const keys = [...store.entries().keys()];
  const tree = keys.some((k) => k.startsWith(`run/${runId}/`));
  const seg = keys.some((k) => k.startsWith("seg/"));
  const rl = await store.get("_RECOVERY/RUNLOG");
  const runlog = rl ? parseRunlog(rl.body).some((e) => e.runId === runId) : false;
  return { tree, seg, runlog, holds: tree && seg && runlog };
}

// crossedToNonEu is the crossing detector, keyed on the harness tag: a record present in a store the harness
// tagged "default" is a crossing. Two-sided by construction: it is FALSE for an eu-tagged store (Cell D).
async function crossedToNonEu(store: TaggedStore, runId: string): Promise<boolean> {
  const held = await storeHoldsRun(store, runId);
  return jurisdictionOf.get(store.id) === "default" && held.holds;
}

// selectedId flattens a selectSealDestination result into one comparable string. The shipped signature is
// `{ destConfig; destinationId: string | undefined } | { allDown: true; tried }` (seal-dispatch.ts:149), so
// there are two non-id outcomes and they are kept distinct: "<allDown>" is the selector refusing outright,
// "<none>" is a selection that carried no id at all. Neither is a destination id and neither is a key in
// jurisdictionOf, so both still fail the id equality AND the jurisdiction lookup in every cell below; the
// flattening makes the comparison total without softening any assertion.
function selectedId(sel: Awaited<ReturnType<typeof selectSealDestination>>): string {
  if ("allDown" in sel) return "<allDown>";
  return sel.destinationId ?? "<none>";
}

// ---- harness-minted keys + a real sealed run (no customer key, ever) -------------------------------------
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function makeRecipient(role: string): RecipientEntry {
  const xk = x25519.keygen();
  return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(rand(64)).encapKey } };
}
async function makeSigner(): Promise<Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
}
// buildRealRun seals a genuine archive (run-tree + content-addressed seg/ data) via the REAL buildArchive, so
// the replicate copy moves real sealed customer bytes, not a stand-in. runId is a valid ULID (buildArchive
// decodes it). The records are fake; the recipients + signer are harness-minted.
async function buildRealRun(signer: Signer, runId: string): Promise<Map<string, Uint8Array>> {
  return buildArchive({
    downpipeId: "dp-eu",
    downpipeName: "residency-test",
    cadence: "3600s",
    runId,
    master: rand(32),
    recipients: [makeRecipient("break-glass"), makeRecipient("operational")],
    signer,
    records: [
      { sourceType: "kv", name: "personal:a", value: utf8("value-a-personal-data"), namespace: "eu-ns" },
      { sourceType: "kv", name: "personal:b", value: utf8("value-b-personal-data-longer"), namespace: "eu-ns" },
    ],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
}
function entryFor(runId: string, index: number, prevRunId: string | null): RunlogEntry {
  return { index, runId, downpipeId: "dp-eu", time: "2026-06-13T00:00:00.000Z", recordCount: 2, prevRunId, status: "active" };
}

// ---- scheduler-DO + env stubs (the shapes validate-drive-budget drives selectSealDestination with) -------
function makeSchedulerStub(fetchFn: (url: string, init?: RequestInit) => Promise<Response>): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return fetchFn(url, init);
    },
  } as unknown as DurableObjectStub;
}
function makeEnv(stub: DurableObjectStub, extra?: Partial<Env>): Env {
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ...extra } as unknown as Env;
}
type StoredCfg = { endpoint: string; bucket: string; region: string; accessKeyId: string; secretAccessKey: string } | null;
// destConfigStub serves /dest-config?id=<id> from a harness-owned map (id -> config or null), and returns a
// benign 200 for the engine's best-effort diagnostic writes so buildDestination's health recorder never
// throws. It is a HARNESS data structure; the engine reads a config off it exactly as it reads the real DO.
function destConfigStub(configs: Map<string, StoredCfg>): DurableObjectStub {
  return makeSchedulerStub(async (url: string) => {
    const u = new URL(url);
    if (u.pathname === "/dest-config") {
      const id = u.searchParams.get("id");
      const cfg = id !== null ? configs.get(id) ?? null : null;
      return new Response(JSON.stringify({ config: cfg }), { headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }); // diag writes etc.
  });
}
function fanState(id: string, destinationIds: string[]): DownpipeState {
  return {
    config: { id, name: `dp ${id}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] }, destinationIds },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  } as unknown as DownpipeState;
}

// ---------------------------------------------------------------------------------------------------------
// Cell A: the fan-out replicate copies an EU-origin run into the default-jurisdiction store (a crossing).
// Drives the REAL mirrorRunToReplica (replicate.ts:669) with verify:true, from an eu-tagged origin to a
// default-tagged replica, for a downpipe whose destinationIds the REAL allDestinationIds enumerates as
// [eu, default] with no jurisdiction filter. Two-sided: a run whose bytes do NOT reach the default store
// would mean a guard exists and the finding is wrong, so absence of the copy fails the cell.
// ---------------------------------------------------------------------------------------------------------
async function cellA(signer: Signer): Promise<void> {
  console.log("-- Cell A: fan-out replicate copies an EU-origin run into a default-jurisdiction store (crossing) --");
  const euOrigin = new TaggedStore("dst-eu-A", "eu");
  const defaultReplica = new TaggedStore("dst-default-A", "default");
  const RUN = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

  // The real fan-out enumerates every configured destination with no jurisdiction consideration.
  const ids = allDestinationIds({ destinationIds: [euOrigin.id, defaultReplica.id] });
  ok("allDestinationIds enumerates the mixed fan-out as [eu, default], the non-EU id a first-class member (destinations.ts:32-35)", JSON.stringify(ids) === JSON.stringify([euOrigin.id, defaultReplica.id]));
  ok("primaryDestinationId is the EU id; the default replica is a replicate target (replicate.ts:218,737)", primaryDestinationId({ destinationIds: ids }) === euOrigin.id);

  const archive = await buildRealRun(signer, RUN);
  for (const [k, v] of archive) await euOrigin.put(k, v);
  const originSegs = [...euOrigin.entries().keys()].filter((k) => k.startsWith("seg/"));
  ok("the EU origin sealed a real run with data segments under seg/ (sanity)", originSegs.length > 0);

  // Drive the real per-replica copy (verify:true runs the shipped keyless post-copy integrity verify).
  let threw = false;
  try {
    await mirrorRunToReplica(euOrigin, defaultReplica, signer, entryFor(RUN, 1, null), { verify: true });
  } catch {
    threw = true;
  }
  ok("the real mirrorRunToReplica copied the EU run to the default replica and passed the post-copy verify (no throw)", !threw);

  const held = await storeHoldsRun(defaultReplica, RUN);
  ok("the default-jurisdiction store now holds the run-tree objects (crossed)", held.tree);
  ok("the default-jurisdiction store now holds the DATA segments (independently restorable copy, not manifests-only)", held.seg);
  ok("the default-jurisdiction store now holds the RUNLOG entry (rendered by the console as a healthy copy)", held.runlog);
  const rep = defaultReplica.entries();
  const byteIdentical = originSegs.every((k) => rep.has(k) && new TextDecoder().decode(rep.get(k)!) === new TextDecoder().decode(euOrigin.entries().get(k)!));
  ok("the copied segment bytes are byte-identical to the EU origin (the SAME personal data, now in a non-EU store)", byteIdentical);

  ok("crossing detector: the EU run reached the NON-EU store (the DETECT, observed on the real copy path)", (await crossedToNonEu(defaultReplica, RUN)) === true);
  // Two-sidedness note: the same detector returns FALSE for an eu-tagged store, exercised in Cell D.
}

// ---------------------------------------------------------------------------------------------------------
// Cell B (LOAD-BEARING): the real selectSealDestination returns the NON-EU destination on failover.
// Handed a mixed fan-out [eu-primary, default-replica] with the EU primary down, the real selector at
// seal-dispatch.ts:162-190 (the `for (const id of ids)` loop returning the first reachable, no jurisdiction
// comparison) hands back the default-jurisdiction id. Observed TWO ways over the SAME real function: the
// per-tick probe-cache seam (the down verdict is a real parameter of the real function), and the real
// destinationReachable put-probe over a genuinely-refusing EU endpoint (a harness-owned fetch). Two-sided:
// an allDown result or the EU id fails the cell; a guard would refute the finding here rather than be assumed.
// ---------------------------------------------------------------------------------------------------------
async function cellB(): Promise<void> {
  console.log("-- Cell B: the real selectSealDestination returns the NON-EU id on failover (the headline disproof) --");
  const EU_ID = "dst-eu-B";
  const DEFAULT_ID = "dst-default-B";
  jurisdictionOf.set(EU_ID, "eu");
  jurisdictionOf.set(DEFAULT_ID, "default");
  const EU_HOST = "eu-primary.harness-residency.example";
  const DEFAULT_HOST = "default-replica.harness-residency.example";
  const configs = new Map<string, StoredCfg>([
    [EU_ID, { endpoint: `https://${EU_HOST}`, bucket: "eu-bucket", region: "auto", accessKeyId: "AKIAHARNESS", secretAccessKey: "harness-secret" }],
    [DEFAULT_ID, { endpoint: `https://${DEFAULT_HOST}`, bucket: "default-bucket", region: "auto", accessKeyId: "AKIAHARNESS", secretAccessKey: "harness-secret" }],
  ]);
  const stub = destConfigStub(configs);
  const env = makeEnv(stub);
  const state = fanState("dp-mixed-B", [EU_ID, DEFAULT_ID]);

  // Observation 1: the per-tick probe cache (the shipped seam validate-drive-budget drives it through). The
  // EU primary probed DOWN, the default replica UP; the real loop iterates in config order and returns the
  // first reachable. This is the real selectSealDestination's real return, not a reimplementation.
  {
    const budget = new SliceBudget({ subrequests: 700 });
    const probeCache = new Map<string, boolean>([[EU_ID, false], [DEFAULT_ID, true]]);
    const sel = await selectSealDestination(env, stub, state, { budget, probeCache });
    const returned = selectedId(sel);
    ok("[cache seam] selectSealDestination did NOT report allDown (a healthy replica was reachable)", !("allDown" in sel));
    ok("[cache seam] the returned destinationId is the default-jurisdiction replica, not the EU primary", returned === DEFAULT_ID);
    ok("[cache seam] the run's ORIGIN copy therefore seals to a NON-EU bucket (the acute crossing, observed)", returned !== "<allDown>" && jurisdictionOf.get(returned) === "default");
  }

  // Observation 2: the REAL put-probe. No probe cache, so selectSealDestination runs the real
  // buildDestination + real destinationReachable + real S3Destination.put for each id. The EU endpoint host
  // refuses the write (403) and the default endpoint host accepts it (200), injected into a harness-owned
  // globalThis.fetch (no real network). The EU primary is genuinely unwritable, exactly the down-primary case.
  {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      const host = new URL(url).host;
      if (host === EU_HOST) return new Response("<Error><Code>AccessDenied</Code></Error>", { status: 403 }); // the EU primary refuses the write: DOWN
      return new Response("", { status: 200, headers: { etag: '"1"' } }); // the default replica accepts the write: UP
    }) as typeof fetch;
    try {
      // A direct probe first, to prove the harness-owned fetch genuinely makes the EU endpoint unwritable and
      // the default endpoint writable (the down-primary substrate is real, not asserted).
      const euDest = new S3Destination(`https://${EU_HOST}`, "eu-bucket", "auto", "AKIAHARNESS", "harness-secret");
      const defDest = new S3Destination(`https://${DEFAULT_HOST}`, "default-bucket", "auto", "AKIAHARNESS", "harness-secret");
      ok("[real probe] the EU primary endpoint genuinely refuses the write (destinationReachable false)", (await destinationReachable(euDest, undefined, EU_ID)) === false);
      ok("[real probe] the default replica endpoint genuinely accepts the write (destinationReachable true)", (await destinationReachable(defDest, undefined, DEFAULT_ID)) === true);

      const budget = new SliceBudget({ subrequests: 700 });
      const sel = await selectSealDestination(env, stub, state, { budget });
      const returned = selectedId(sel);
      ok("[real probe] selectSealDestination fell over the down EU primary to the reachable replica (not allDown)", !("allDown" in sel));
      ok("[real probe] the real selector returned the default-jurisdiction id after a REAL failover probe", returned === DEFAULT_ID);
      ok("[real probe] no jurisdiction guard fired: the run seals its ORIGIN to a NON-EU bucket (seal-dispatch.ts:162-190)", returned !== "<allDown>" && jurisdictionOf.get(returned) === "default");
    } finally {
      globalThis.fetch = realFetch;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------
// Cell C: the config path has no jurisdiction field, no guard, no warning (correct-by-inspection).
// Proves a negative, but executably: it reads the ABSENCE in the real source, so it is a re-runnable gate and
// not prose. Grounds: RuntimeDestConfig (factory.ts:31-60), RawDestConfigBody (router-destinations.ts:26),
// the grep-once fact (jurisdiction only at bindings-sync.ts:99-100, a SOURCE binding), and residency copy
// only in frameworks.ts (compliance text, never logic).
// ---------------------------------------------------------------------------------------------------------
function cellC(): void {
  console.log("-- Cell C: the config path carries no jurisdiction field and no guard (correct-by-inspection, executable) --");
  const read = (rel: string): string => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
  const factory = read("../src/dest/factory.ts");
  const cfgStart = factory.indexOf("export interface RuntimeDestConfig");
  const runtimeCfg = cfgStart > -1 ? factory.slice(cfgStart, factory.indexOf("\n}", cfgStart)) : "";
  ok("RuntimeDestConfig exists (factory.ts:31-60)", runtimeCfg.includes("endpoint") && runtimeCfg.includes("bucket") && runtimeCfg.includes("region"));
  ok("RuntimeDestConfig has NO jurisdiction field (a pinned EU bucket is only the endpoint string)", !/jurisdiction/i.test(runtimeCfg) && !/residency/i.test(runtimeCfg) && !/sovereign/i.test(runtimeCfg));

  const routerDest = read("../src/admin/router-destinations.ts");
  const rawBody = routerDest.slice(routerDest.indexOf("type RawDestConfigBody"), routerDest.indexOf(";", routerDest.indexOf("type RawDestConfigBody")));
  ok("the untrusted POST body RawDestConfigBody has NO jurisdiction field (router-destinations.ts:26)", rawBody.length > 0 && !/jurisdiction/i.test(rawBody));
  ok("no validator on the destination write path compares two destinations' jurisdictions (no such token in the router)", !/jurisdiction/i.test(routerDest));

  // The grep-once fact, made executable across the whole engine source tree.
  const srcRoot = fileURLToPath(new URL("../src/", import.meta.url));
  const jurisdictionHits = grepTree(srcRoot, /jurisdiction/i).filter((h) => !h.file.endsWith("env.d.ts"));
  const nonBindingHits = jurisdictionHits.filter((h) => !h.file.endsWith("admin/bindings-sync.ts"));
  ok("the ONLY jurisdiction occurrence in the engine is in bindings-sync.ts (a SOURCE R2 binding, never a destination)", jurisdictionHits.length > 0 && nonBindingHits.length === 0);
  const residencyHits = grepTree(srcRoot, /residency|sovereignt|in-region/i);
  const nonFrameworksResidency = residencyHits.filter((h) => !h.file.endsWith("admin/frameworks.ts"));
  ok("residency/sovereignty/in-region appear ONLY in the compliance copy (frameworks.ts), never in engine logic", residencyHits.length > 0 && nonFrameworksResidency.length === 0);

  const frameworks = read("../src/admin/frameworks.ts");
  ok("the eu-gdpr promise under test is present (frameworks.ts:146): pinned to an EU region, no third-country transfer", frameworks.includes("pinned to an EU region") && frameworks.includes("third-country transfer"));
}
// grepTree walks a source tree and returns { file, line } for each regex hit, so Cell C's negatives are
// proven against the real files rather than asserted. Read-only; used only to establish absence.
function grepTree(root: string, re: RegExp): Array<{ file: string; line: number }> {
  const out: Array<{ file: string; line: number }> = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const p = `${dir}/${name}`;
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (p.endsWith(".ts")) {
        const lines = readFileSync(p, "utf8").split("\n");
        lines.forEach((l, i) => {
          if (re.test(l)) out.push({ file: p, line: i + 1 });
        });
      }
    }
  };
  walk(root.replace(/\/$/, ""));
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// Cell D (REFUTER, default-FAIL): an all-EU fan-out is NOT reported as crossing.
// Repeats A and B with every destination tagged eu. No default-jurisdiction store exists to reach, so the
// crossing detector must return FALSE and the failover return must be an EU id. This makes A and B
// non-vacuous (the detector is not always-red) and makes the design's point precise: the ONLY thing keeping
// the all-EU case in-region is that every destination is EU, not any engine behaviour.
// ---------------------------------------------------------------------------------------------------------
async function cellD(signer: Signer): Promise<void> {
  console.log("-- Cell D (REFUTER, default-FAIL): an all-EU fan-out is NOT reported as crossing --");
  let refuterHeld = true; // default-FAIL: any observed crossing in the all-EU case flips this and fails the cell

  // D.A: the replicate copy between two eu-tagged stores reaches no default store.
  const euA = new TaggedStore("dst-eu-D-a", "eu");
  const euB = new TaggedStore("dst-eu-D-b", "eu");
  const RUN = "01ARZ3NDEKTSV4RRFFQ69G5FB1";
  const archive = await buildRealRun(signer, RUN);
  for (const [k, v] of archive) await euA.put(k, v);
  await mirrorRunToReplica(euA, euB, signer, entryFor(RUN, 1, null), { verify: true });
  const euBHolds = await storeHoldsRun(euB, RUN);
  ok("the all-EU replica DID receive the run (the copy path is exercised, not skipped)", euBHolds.holds);
  const crossedA = (await crossedToNonEu(euA, RUN)) || (await crossedToNonEu(euB, RUN));
  ok("crossing detector reports NO crossing for the all-EU replicate (two-sided: FALSE where A returned TRUE)", crossedA === false);
  if (crossedA) refuterHeld = false;

  // D.B: the failover selection over two eu destinations returns an EU id.
  const EU1 = "dst-eu-D-1";
  const EU2 = "dst-eu-D-2";
  jurisdictionOf.set(EU1, "eu");
  jurisdictionOf.set(EU2, "eu");
  const configs = new Map<string, StoredCfg>([
    [EU1, { endpoint: "https://eu-1.harness-residency.example", bucket: "eu1", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" }],
    [EU2, { endpoint: "https://eu-2.harness-residency.example", bucket: "eu2", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" }],
  ]);
  const stub = destConfigStub(configs);
  const env = makeEnv(stub);
  const budget = new SliceBudget({ subrequests: 700 });
  const probeCache = new Map<string, boolean>([[EU1, false], [EU2, true]]); // EU-1 down, EU-2 up
  const sel = await selectSealDestination(env, stub, fanState("dp-alleu-D", [EU1, EU2]), { budget, probeCache });
  const returned = selectedId(sel);
  ok("the all-EU failover returned a reachable destination (EU-2), not allDown", returned === EU2);
  const crossedB = returned !== "<allDown>" && jurisdictionOf.get(returned) === "default";
  ok("the failover return is an EU id: NO crossing on an all-EU fan-out (two-sided vs Cell B)", crossedB === false && jurisdictionOf.get(returned) === "eu");
  if (crossedB) refuterHeld = false;

  ok("REFUTER HELD: the all-EU configuration is NOT reported as crossing (the disproof is not vacuously always-crossing)", refuterHeld === true);
}

// ---------------------------------------------------------------------------------------------------------
// Cell E: the credited protection that DOES hold: a single-destination pinned EU downpipe fails LOUD.
// A downpipe pinned to a SINGLE EU destination whose config record is gone takes the fail-loud single-dest
// path (seal-dispatch.ts:155-158 -> resolveDestForState :86-93), which THROWS rather than falling back to the
// env / account default (which could be non-EU). This is the safe configuration, and the assertion is
// two-sided: a resolvable pin returns exactly that pinned id (its own jurisdiction), never a second bucket.
// ---------------------------------------------------------------------------------------------------------
async function cellE(): Promise<void> {
  console.log("-- Cell E: a single-destination pinned EU downpipe fails LOUD rather than crossing (credited protection) --");
  const EU_PIN = "dst-eu-E";
  jurisdictionOf.set(EU_PIN, "eu");

  // The pinned EU destination's record is GONE (deleted / dangling): the stub returns {config:null} for it.
  const goneStub = destConfigStub(new Map<string, StoredCfg>([[EU_PIN, null]]));
  const goneEnv = makeEnv(goneStub);
  let threw = false;
  let leaked: string | undefined;
  try {
    const sel = await selectSealDestination(goneEnv, goneStub, fanState("dp-pin-gone-E", [EU_PIN]), {});
    leaked = !("allDown" in sel) ? sel.destinationId : "<allDown>";
  } catch {
    threw = true;
  }
  ok("a single pinned EU destination whose record is gone THROWS (fail-loud, seal-dispatch.ts:86-93)", threw);
  ok("it did NOT silently resolve a different (env/account-default) bucket (no crossing on a broken pin)", !threw ? false : leaked === undefined);

  // Two-sided: a resolvable single EU pin returns exactly that id and no other (single-dest path, no probe,
  // no failover, so no second bucket to cross to).
  const okStub = destConfigStub(new Map<string, StoredCfg>([[EU_PIN, { endpoint: "https://eu-pin.harness-residency.example", bucket: "eu", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" }]]));
  const okEnv = makeEnv(okStub);
  const sel = await selectSealDestination(okEnv, okStub, fanState("dp-pin-ok-E", [EU_PIN]), {});
  const returned = selectedId(sel);
  ok("a resolvable single EU pin returns exactly that pinned id (single-dest path, seal-dispatch.ts:155-158)", returned === EU_PIN);
  ok("the single-dest return stays in the EU (no other bucket exists to fail over to)", returned !== "<allDown>" && jurisdictionOf.get(returned) === "eu");
}

// ---------------------------------------------------------------------------------------------------------
// Cell F (REFUTER, default-FAIL): the cross-region S3 redirect is genuinely REFUSED, not followed.
// A 301/307 from an S3 endpoint almost always means the bucket lives in another region; the real read op
// (s3-read-ops.ts:72-74, driven through S3Destination.get) refuses to follow it and throws, so a mis-regioned
// or interposed redirect FAILS the read rather than silently re-homing it. Default-FAIL: the redirect must be
// blocked (a throw, no body returned). Two-sided: a normal 200 DOES return its body, and a 404 returns null,
// so the block is specific to the redirect and not a broken read.
// ---------------------------------------------------------------------------------------------------------
async function cellF(): Promise<void> {
  console.log("-- Cell F (REFUTER, default-FAIL): the cross-region S3 redirect is REFUSED, not followed --");
  const HOST = "eu-read.harness-residency.example";
  const dest = new S3Destination(`https://${HOST}`, "eu-bucket", "auto", "AKIAHARNESS", "harness-secret");
  const KEY = "run/01ARZ3NDEKTSV4RRFFQ69G5FAV/root.manifest.json";
  const realFetch = globalThis.fetch;

  let redirectBlocked = false; // default-FAIL: only set true when the redirect genuinely throws with no body

  // 1) A cross-region 301 with a Location pointing at ANOTHER region: the read must throw and return nothing.
  globalThis.fetch = (async (): Promise<Response> => new Response("<Error><Code>PermanentRedirect</Code></Error>", { status: 301, headers: { location: "https://eu-bucket.s3.eu-west-1.amazonaws.com/" + KEY } })) as typeof fetch;
  try {
    let body: unknown;
    let threw = false;
    try {
      body = await dest.get(KEY);
    } catch (e) {
      threw = true;
      redirectBlocked = threw && /unexpected redirect/i.test(String((e as Error).message)) && body === undefined;
    }
    ok("a cross-region 301 redirect on a credentialed GET is REFUSED (throws 'unexpected redirect')", threw);
    ok("the redirect target was NOT followed: no cross-region body was returned", body === undefined);

    // headStatus (the destination preflight probe) refuses the redirect too.
    let headThrew = false;
    try {
      await dest.headStatus(KEY);
    } catch (e) {
      headThrew = /unexpected redirect/i.test(String((e as Error).message));
    }
    ok("a 301 redirect on the HEAD preflight is likewise refused (not followed)", headThrew);

    // 2) Two-sided: a NORMAL 200 with a body + etag IS returned (the block is specific to the redirect).
    globalThis.fetch = (async (): Promise<Response> => new Response(utf8("real-eu-bytes"), { status: 200, headers: { etag: '"abc"', "content-length": "13" } })) as typeof fetch;
    const goodRead = await dest.get(KEY);
    ok("a normal 200 read still returns its body (the refusal is specific to the redirect, not a broken read)", goodRead !== null && new TextDecoder().decode(goodRead.body) === "real-eu-bytes");

    // 3) Two-sided: a 404 is the normal absent answer (null), not a false block.
    globalThis.fetch = (async (): Promise<Response> => new Response("", { status: 404 })) as typeof fetch;
    const absent = await dest.get(KEY);
    ok("a 404 read returns null (normal absent), so the redirect refusal is not a blanket failure", absent === null);
  } finally {
    globalThis.fetch = realFetch;
  }

  ok("REFUTER HELD: the cross-region redirect is genuinely blocked (no read silently re-homed across a region)", redirectBlocked === true);
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  await cellA(signer);
  await cellB();
  cellC();
  await cellD(signer);
  await cellE();
  await cellF();

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nRESIDENCY TIER-1 VECTORS PASS (the engine is jurisdiction-blind on fan-out and failover; the credited protections hold; refuters cleared)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
