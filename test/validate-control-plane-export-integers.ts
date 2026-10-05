// The signed control-plane export must be signable for every value the write paths accept, and a pass that
// cannot sign must say so where an operator looks. In-memory doubles only: no network, no deploy.
//
// A signed object holds integers only (src/format/canonjson.ts, and the Go reader's canonjson.go): a float has
// no one text form that every port writes. The export carries destination cost rates, and a rate is often
// fractional (R2 Class A operations are 4.5 per million). A raw 4.5 in the export made canonicalJSON throw, so
// the export pass threw on every tick and no recovery artefact was ever written, while the only trace was a
// log line.
//
// What this proves:
//  - A FRACTIONAL RATE IS EXPORTED. A destination saved through the real write path with fractional rates
//    reaches a signed, verified artefact in the bucket, written by the real cron pass, and every rate reads
//    back through the import with exactly the same value.
//  - EARLIER EXPORTS READ UNCHANGED. Integer rates stay JSON numbers, so an export an earlier engine wrote
//    (integer rates only) has the same form and imports the same. A rate string that is not the one form the
//    engine writes refuses the whole pricing object rather than storing a guessed rate.
//  - THE CLASS GUARD. Every numeric input a write path accepts is swept with fractional and out-of-range
//    values. Whatever the write path does with each (refuse, drop, keep), the export afterwards must sign.
//    A census then walks every numeric leaf of a fully populated export: each path must be one the sweep
//    drives, or one the engine mints itself (a timestamp, a counter). A new numeric export field fails here
//    until it is classified, so the next field of this kind is caught by a test, not by an estate.
//  - A PASS THAT CANNOT SIGN IS LOUD. It records the closed class "unsignable" in the export-health record
//    and the cron ledger, the environment-self-backup posture check fails and says why, and the support
//    pack carries the class. Any other pass-level throw records "pass-fault".
//
// Run: node test/validate-control-plane-export-integers.ts

import { runControlPlaneExportPass } from "../src/cron/control-plane-pass.ts";
import { applyCronHealth, drainCronFaultLedger } from "../src/cron/cron-fault-ledger.ts";
import { CONTROL_PLANE_PREFIX, type ControlPlaneExport, type ExportedDestination, serialiseControlPlaneExport, signControlPlaneExport, verifyControlPlaneSignature } from "../src/admin/control-plane.ts";
import { fetchCronHealth } from "../src/admin/support-sections-faults.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { budgetFromEnv } from "../src/seal/budget.ts";
import type { Env } from "../src/env.d.ts";
import type { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { StoredDestination } from "../src/sched/scheduler-do-base.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";
import { makeConfig, makeScheduler } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The break-glass token caller: the engine's own owner authority, so the owner-gated write paths run.
const OWNER = { method: "token" as const, email: null, subject: null, groups: [], role: "owner" as const };

const RATE_KEYS = ["storagePerGBMonth", "classAPerMillion", "classBPerMillion", "egressPerGB"] as const;

// A destination submission buildDestRecord accepts; overrides tune one field.
function destConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    endpoint: "https://acct.r2.cloudflarestorage.com",
    bucket: "archive",
    region: "auto",
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey: "a-secret-value",
    verifiedAt: 1_700_000_000_000,
    deleteProbe: "ok",
    ...overrides,
  };
}

// signs reports whether the export has a canonical form, which is the precondition for signing it.
function signs(exp: ControlPlaneExport): boolean {
  try {
    serialiseControlPlaneExport(exp);
    return true;
  } catch {
    return false;
  }
}

// An in-memory R2 bucket with the calls R2Destination makes.
class MemR2 {
  readonly objs = new Map<string, Uint8Array>();
  async put(key: string, value: ArrayBuffer | Uint8Array): Promise<{ key: string; etag: string }> {
    this.objs.set(key, value instanceof Uint8Array ? value.slice() : new Uint8Array(value.slice(0)));
    return { key, etag: "e" };
  }
  async get(key: string): Promise<{ arrayBuffer: () => Promise<ArrayBuffer>; etag: string } | null> {
    const b = this.objs.get(key);
    return b === undefined ? null : { arrayBuffer: async () => b.slice().buffer, etag: "e" };
  }
  async head(key: string): Promise<{ key: string } | null> {
    return this.objs.has(key) ? { key } : null;
  }
  async delete(key: string): Promise<void> {
    this.objs.delete(key);
  }
  async list(opts: { prefix?: string }): Promise<{ objects: { key: string }[]; truncated: false }> {
    const prefix = opts.prefix ?? "";
    return { objects: [...this.objs.keys()].filter((k) => k.startsWith(prefix)).sort().map((key) => ({ key })), truncated: false };
  }
}

// passScheduler fronts the REAL SchedulerDO. It answers the destination-config read with a deploy-time record,
// so the env R2 binding is the store, and optionally replaces the export slice. Every other route is the DO's.
function passScheduler(dobj: SchedulerDO, exportFor?: () => Promise<Response>): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
      if (url.pathname === "/control-plane/export" && exportFor !== undefined) return exportFor();
      if (url.pathname === "/dest-config") {
        const id = url.searchParams.get("id");
        return Response.json({ config: { id: id ?? "deploy", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "" } });
      }
      return dobj.fetch(new Request(url.toString(), init));
    },
  } as unknown as DurableObjectStub;
}

async function runPass(dobj: SchedulerDO, r2: MemR2, signerB64: string, exportFor?: () => Promise<Response>): Promise<void> {
  const stub = passScheduler(dobj, exportFor);
  const namespace = { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, DEST_KIND: "r2", DEST_R2: r2, SIGNER_PRIVATE: signerB64 } as unknown as Env;
  await runControlPlaneExportPass(env, stub as never, budgetFromEnv(env));
}

// importDest runs the DO's own import projection for one exported destination (the reconcile and the estate
// import both go through it). It is a mixin method off the shared surface type, so the test reaches it by cast.
function importDest(dobj: SchedulerDO, d: ExportedDestination): StoredDestination {
  return (dobj as unknown as { reconciledDestination(d: ExportedDestination): StoredDestination }).reconciledDestination(d);
}

async function selfBackupCheck(dobj: SchedulerDO): Promise<{ status: string; detail: string } | undefined> {
  const { report } = await dobj.computePostureReport({});
  return report.checks.find((c) => c.id === "environment-self-backup");
}

// ---- 1. a fractional rate reaches a signed, written export, and reads back exactly -------------------------

const FRACTIONAL_RATES = { storagePerGBMonth: 0.015, classAPerMillion: 4.5, classBPerMillion: 0.36, egressPerGB: 0 };

async function fractionalRateIsExported(signerB64: string): Promise<void> {
  console.log("a fractional destination rate reaches a signed, written export");
  const { stub: dobj } = makeScheduler();
  await dobj.addDownpipe(makeConfig("dp-1"));
  await dobj.putDest({ label: "R2", config: destConfig({ pricing: { ...FRACTIONAL_RATES, currency: "USD", source: "preset" } }) }, OWNER);
  const exp = await dobj.buildControlPlaneExport();
  ok("the export built from a destination with a 4.5 rate has a canonical form", signs(exp));
  const signer = await loadSigner(signerB64);
  let sigOk = false;
  try {
    sigOk = await verifyControlPlaneSignature(exp, await signControlPlaneExport(signer, exp), verifierFrom(signer));
  } catch {
    sigOk = false;
  }
  ok("the export signs and the signature verifies", sigOk);

  // The real cron pass, against the real DO routes, writes the artefact to the bucket.
  drainCronFaultLedger();
  const r2 = new MemR2();
  await runPass(dobj, r2, signerB64);
  const body = [...r2.objs.keys()].find((k) => k.startsWith(CONTROL_PLANE_PREFIX) && k.endsWith(".json"));
  ok("the export pass writes a recovery artefact to the bucket", body !== undefined);
  ok("the artefact has its detached signature beside it", body !== undefined && r2.objs.has(`${body}.sig`));
  const health = await dobj.getControlPlaneExportHealth();
  ok("the export health records a write with no fault", health?.wroteAny === true && health.skipped === undefined);
  ok("the cron ledger records no pass-level throw", drainCronFaultLedger().cpExport?.passThrew !== true);
  const check = await selfBackupCheck(dobj);
  ok("the environment-self-backup check passes", check?.status === "pass");
  if (body === undefined) return;

  // The written bytes verify, and the import reads every rate back as the same double.
  const written = JSON.parse(new TextDecoder().decode(r2.objs.get(body)!)) as ControlPlaneExport;
  const sigText = new TextDecoder().decode(r2.objs.get(`${body}.sig`)!).trim();
  ok("the written artefact verifies against the engine signer", await verifyControlPlaneSignature(written, sigText, verifierFrom(signer)));
  const d = written.destinations[0]!;
  const p = d.pricing as Record<string, unknown>;
  ok("an integer rate stays a JSON number", p.egressPerGB === 0);
  ok("a fractional rate rides as its shortest round-trip decimal string", p.classAPerMillion === "4.5" && p.storagePerGBMonth === "0.015" && p.classBPerMillion === "0.36");
  const { stub: fresh } = makeScheduler();
  const back = importDest(fresh, d).pricing;
  ok("the import reads every rate back as exactly the value saved", back !== undefined && RATE_KEYS.every((k) => Object.is(back[k], FRACTIONAL_RATES[k])));
  ok("the import keeps the currency and the source", back?.currency === "USD" && back.source === "preset");
}

// ---- 2. earlier exports read unchanged, and a non-canonical rate string is refused ----------------------------

async function earlierExportsReadUnchanged(): Promise<void> {
  console.log("an export an earlier engine wrote reads unchanged");
  const { stub: dobj } = makeScheduler();
  const rates = { storagePerGBMonth: 15, classAPerMillion: 4, classBPerMillion: 0, egressPerGB: 9 };
  await dobj.putDest({ label: "R2", config: destConfig({ pricing: { ...rates, currency: "USD" } }) }, OWNER);
  const exp = await dobj.buildControlPlaneExport();
  const p = exp.destinations[0]!.pricing as Record<string, unknown>;
  ok("integer rates are exported as JSON numbers, the form an earlier engine wrote", RATE_KEYS.every((k) => p[k] === rates[k]));

  const base = exp.destinations[0]!;
  const imported = (pricing: unknown): StoredDestination["pricing"] => importDest(dobj, { ...base, pricing } as ExportedDestination).pricing;
  const earlier = imported({ ...rates, currency: "USD" });
  ok("an earlier engine's integer rates import as the same numbers", earlier !== undefined && RATE_KEYS.every((k) => earlier[k] === rates[k]));
  // Exactly one form per value: an integer in string form, a padded decimal, a negative, an exponent that
  // overflows or a word is not what the engine writes, so the pricing is dropped (and the drop recorded).
  for (const bad of ["4", "4.50", "-1.5", "1e400", "abc", " 4.5"]) {
    ok(`a rate string ${JSON.stringify(bad)} refuses the whole pricing object`, imported({ ...rates, classAPerMillion: bad }) === undefined);
  }
}

// ---- 3. the class guard: every numeric input, swept with fractional values, still signs -----------------------

// A deterministic generator (mulberry32), so a red names the same values on every run.
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Values a signed object cannot carry as a JSON number: fractions of every magnitude, and numbers past the
// 2^53 - 1 ceiling. Twenty seeded fractions join the fixed list.
function awkwardValues(): number[] {
  const fixed = [0.5, 4.5, 0.015, 0.1 + 0.2, 1e-7, Number.MIN_VALUE, 123456.789, 2 ** 53 + 2, 1e300];
  const r = prng(0x5eed);
  const seeded = Array.from({ length: 20 }, () => Math.floor(r() * 10 ** Math.floor(r() * 9)) + [0.25, 0.5, 0.125, 0.001][Math.floor(r() * 4)]!);
  return [...fixed, ...seeded];
}

// A PROBE drives one numeric input through its real write path with one value. The write may refuse (it
// throws), drop the field or keep the value; the guard only asks that the export signs afterwards. Each probe
// names the export paths it covers, which the census below checks against, and a GOOD value: the probe run
// with it must succeed and put the path in the export, so a probe the write path refuses for another reason
// (a missing capability, a rule the fixture breaks) cannot pass by never reaching the field.
interface Probe {
  paths: string[];
  good: number;
  run: (dobj: SchedulerDO, v: number) => Promise<void>;
}

const withSchedule = (w: Record<string, unknown>): Partial<DownpipeConfig> => ({ schedule: { cron: "0 3 * * *", timeZone: "UTC", blackoutWindows: [{ days: [1, 2], startMinute: 60, endMinute: 120, ...w }] as never } });
const addPipe = (over: Partial<DownpipeConfig>) => async (dobj: SchedulerDO): Promise<void> => {
  await dobj.addDownpipe(makeConfig("dp-probe", over), OWNER);
};

const PROBES: Probe[] = [
  ...RATE_KEYS.map((k) => ({ paths: [`destinations[].pricing.${k}`], good: 4, run: async (dobj: SchedulerDO, v: number) => void (await dobj.putDest({ label: "R2", config: destConfig({ pricing: { ...FRACTIONAL_RATES, [k]: v } }) }, OWNER)) })),
  { paths: ["destinations[].worm.retentionDays"], good: 30, run: async (dobj, v) => void (await dobj.putDest({ label: "R2", config: destConfig({ worm: { mode: "governance", retentionDays: v } }) }, OWNER)) },
  { paths: ["destinations[].assumeRole.durationSeconds"], good: 3600, run: async (dobj, v) => void (await dobj.putDest({ label: "S3", config: destConfig({ endpoint: "https://s3.us-east-1.amazonaws.com", region: "us-east-1", assumeRole: { roleArn: "arn:aws:iam::123456789012:role/downpipes", externalId: "ext-id-value", durationSeconds: v } }) }, OWNER)) },
  { paths: ["downpipes[].cadenceSeconds"], good: 7200, run: (dobj, v) => addPipe({ cadenceSeconds: v })(dobj) },
  { paths: ["downpipes[].restoreTestCadenceSeconds"], good: 172800, run: (dobj, v) => addPipe({ restoreTestCadenceSeconds: v })(dobj) },
  { paths: ["downpipes[].retention.keepRuns"], good: 5, run: (dobj, v) => addPipe({ retention: { keepRuns: v } })(dobj) },
  { paths: ["downpipes[].retention.keepDays"], good: 30, run: (dobj, v) => addPipe({ retention: { keepDays: v } })(dobj) },
  { paths: ["downpipes[].schedule.blackoutWindows[].startMinute"], good: 30, run: (dobj, v) => addPipe(withSchedule({ startMinute: v }))(dobj) },
  { paths: ["downpipes[].schedule.blackoutWindows[].endMinute"], good: 150, run: (dobj, v) => addPipe(withSchedule({ endMinute: v }))(dobj) },
  { paths: ["downpipes[].schedule.blackoutWindows[].days[]"], good: 3, run: (dobj, v) => addPipe(withSchedule({ days: [v] }))(dobj) },
  { paths: ["orgPolicy.attendedCadenceDays"], good: 30, run: async (dobj, v) => void (await dobj.setAttendedCadenceDays({ attendedCadenceDays: v }, OWNER)) },
];

// Paths the engine mints itself and never takes from input: the layout version, timestamps from Date.now,
// the config-history id and the audit sequence. Each is an integer by construction.
const ENGINE_MINTED = new Set(["v", "configVersion", "priorAuditHead.headSeq", "destinations[].setAt", "destinations[].verifiedAt", "discovery.setAt"]);

// numericPaths lists every numeric leaf of a value, with array indices folded to [].
function numericPaths(v: unknown, at: string, out: Set<string>): Set<string> {
  if (typeof v === "number") out.add(at);
  else if (Array.isArray(v)) for (const x of v) numericPaths(x, `${at}[]`, out);
  else if (typeof v === "object" && v !== null) for (const [k, x] of Object.entries(v)) numericPaths(x, at === "" ? k : `${at}.${k}`, out);
  return out;
}

async function classGuard(): Promise<void> {
  console.log("the class guard: every numeric input swept with fractional values still signs");
  const values = awkwardValues();
  for (const probe of PROBES) {
    const { stub: control } = makeScheduler();
    await control.addDownpipe(makeConfig("dp-1"));
    let controlError = "";
    try {
      await probe.run(control, probe.good);
    } catch (e) {
      controlError = (e as Error).message;
    }
    const reached = numericPaths(await control.buildControlPlaneExport(), "", new Set());
    ok(`${probe.paths.join(", ")}: the probe with the good value ${probe.good} reaches the export${controlError !== "" ? ` (refused: ${controlError})` : ""}`, controlError === "" && probe.paths.every((p) => reached.has(p)));
    const unsignable: number[] = [];
    for (const v of values) {
      const { stub: dobj } = makeScheduler();
      await dobj.addDownpipe(makeConfig("dp-1"));
      try {
        await probe.run(dobj, v);
      } catch {
        // The write path refused the value. That is a correct outcome; the export below must still sign.
      }
      if (!signs(await dobj.buildControlPlaneExport())) unsignable.push(v);
    }
    ok(`${probe.paths.join(", ")}: the export signs after every one of ${values.length} awkward values${unsignable.length > 0 ? ` (unsignable after ${unsignable.slice(0, 3).join(", ")})` : ""}`, unsignable.length === 0);
  }

  // Every accepted pricing value reads back exactly, including the ones past the integer ceiling.
  const { stub: dobj } = makeScheduler();
  const lost: number[] = [];
  for (const v of values) {
    await dobj.putDest({ id: "dest-sweep", label: "R2", config: destConfig({ pricing: { ...FRACTIONAL_RATES, classAPerMillion: v } }) }, OWNER);
    const exp = await dobj.buildControlPlaneExport();
    const wire = JSON.parse(JSON.stringify(exp)) as ControlPlaneExport;
    const back = importDest(dobj, wire.destinations.find((d) => d.id === "dest-sweep")!).pricing;
    if (!Object.is(back?.classAPerMillion, v)) lost.push(v);
  }
  ok(`a Class A rate reads back exactly for all ${values.length} awkward values${lost.length > 0 ? ` (lost ${lost.slice(0, 3).join(", ")})` : ""}`, lost.length === 0);

  // The census: a fully populated export, every numeric leaf classified.
  const { stub: full } = makeScheduler();
  await full.addDownpipe(makeConfig("dp-full", { restoreTestCadenceSeconds: 172_800, retention: { keepRuns: 5, keepDays: 30 }, ...withSchedule({}) }), OWNER);
  await full.putDest({ label: "R2", config: destConfig({ pricing: { storagePerGBMonth: 15, classAPerMillion: 4, classBPerMillion: 1, egressPerGB: 2 }, worm: { mode: "governance", retentionDays: 30 } }) }, OWNER);
  await full.putDest({ label: "S3", config: destConfig({ endpoint: "https://s3.us-east-1.amazonaws.com", region: "us-east-1", assumeRole: { roleArn: "arn:aws:iam::123456789012:role/downpipes", externalId: "ext-id-value", durationSeconds: 3600 } }) }, OWNER);
  await full.setAttendedCadenceDays({ attendedCadenceDays: 30 }, OWNER);
  const census = [...numericPaths(await full.buildControlPlaneExport(), "", new Set())];
  const probed = new Set(PROBES.flatMap((p) => p.paths));
  const unclassified = census.filter((p) => !probed.has(p) && !ENGINE_MINTED.has(p));
  ok(`every numeric leaf of the export is swept or engine-minted (${census.length} paths)${unclassified.length > 0 ? `; unclassified: ${unclassified.join(", ")}` : ""}`, unclassified.length === 0);
  // The census would pass vacuously over a thin fixture. Each probed path must be present in it.
  const absent = [...probed].filter((p) => !census.includes(p));
  ok(`the fixture populates every swept path${absent.length > 0 ? `; absent: ${absent.join(", ")}` : ""}`, absent.length === 0);
}

// ---- 4. a pass that cannot sign is loud ---------------------------------------------------------------------

async function unsignablePassIsLoud(signerB64: string): Promise<void> {
  console.log("a pass that cannot sign records a closed fault class where an operator looks");
  const { stub: dobj } = makeScheduler();
  await dobj.addDownpipe(makeConfig("dp-1"));
  await dobj.putDest({ label: "R2", config: destConfig() }, OWNER);
  const r2 = new MemR2();
  // A clean pass first, so the failure below cannot hide behind "no export has been written yet".
  await runPass(dobj, r2, signerB64);
  ok("a clean pass writes and the check passes", (await selfBackupCheck(dobj))?.status === "pass");

  // A later configuration carries a value the signed export cannot hold. The value is placed in the slice
  // directly, because every write path now refuses or encodes it: this is the next field of the kind.
  drainCronFaultLedger();
  const poisoned = async (): Promise<Response> => {
    // A copy: the slice shares the stored config objects, and the value must not reach the DO's own record.
    const exp = structuredClone(await dobj.buildControlPlaneExport());
    (exp.downpipes[0] as { cadenceSeconds: number }).cadenceSeconds = 4.5;
    exp.configContentHash = "sha384:changed";
    return Response.json(exp);
  };
  await runPass(dobj, r2, signerB64, poisoned);
  const health = await dobj.getControlPlaneExportHealth();
  ok("the export health names the closed class unsignable", health?.skipped === "unsignable" && health.wroteAny === false);
  const delta = drainCronFaultLedger();
  ok("the cron ledger names the closed class unsignable", delta.cpExport?.passThrew === true && (delta.cpExport as { passFault?: string }).passFault === "unsignable");
  const check = await selfBackupCheck(dobj);
  ok("the environment-self-backup check fails while an export exists from before", check?.status === "fail");
  ok("the check says the export cannot be signed", check !== undefined && /cannot be signed/.test(check.detail));

  // The support pack carries the class from the cron-health record.
  const folded = applyCronHealth(undefined, delta, Date.now(), 900_000);
  const pack = await fetchCronHealth({ fetch: async () => Response.json(folded) } as unknown as DurableObjectStub);
  ok("the support pack carries the class", JSON.stringify((pack.cpExport as { passFaultByClass?: unknown } | undefined)?.passFaultByClass) === JSON.stringify({ unsignable: 1 }));

  // Any other pass-level throw is "pass-fault".
  await runPass(dobj, r2, signerB64, async () => new Response("not json", { status: 500 }));
  ok("a throw that is not a canonical-form refusal records pass-fault", (await dobj.getControlPlaneExportHealth())?.skipped === "pass-fault");
  ok("the ledger names pass-fault", (drainCronFaultLedger().cpExport as { passFault?: string } | undefined)?.passFault === "pass-fault");
  ok("the check says the pass stopped with a fault", /stopped with a fault/.test((await selfBackupCheck(dobj))?.detail ?? ""));

  // The fault clears on the next pass that writes.
  await runPass(dobj, r2, signerB64, async () => {
    const exp = await dobj.buildControlPlaneExport();
    exp.configContentHash = "sha384:changed-again";
    return Response.json(exp);
  });
  const healed = await dobj.getControlPlaneExportHealth();
  ok("a pass that writes clears the fault", healed?.wroteAny === true && healed.skipped === undefined && (await selfBackupCheck(dobj))?.status === "pass");
}

async function main(): Promise<void> {
  const signerB64 = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));
  await fractionalRateIsExported(signerB64);
  await earlierExportsReadUnchanged();
  await classGuard();
  await unsignablePassIsLoud(signerB64);
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-control-plane-export-integers (${failures} failure(s))`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
