// Validates the control-plane export PASS end to end (src/cron/control-plane-pass.ts runControlPlaneExportPass)
// against the REAL SchedulerDO routes and an in-memory R2 bucket. No network, no deploy.
//
// What it proves:
//  - SEALING FOLLOWS THE KEYS. The export is sealed whenever the engine holds a break-glass OR a config
//    recipient public key, and the old opt-out flag no longer writes cleartext. It is cleartext only when the
//    engine holds no recipient key at all, and the export state and the environment-self-backup posture check
//    then say so.
//  - AUTO-HEAL STILL OPENS IT. A config-recipient-only export opens with the config-recipient private.
//  - THE CHANGE GATE HOLDS. The DO keeps the recipient-pin hash the pass posts, so an unchanged tick writes
//    nothing. Before, the DO dropped it, every tick wrote a new generation at the SAME version, and the
//    auto-heal refused the bucket as ambiguous.
//  - AN UNCHANGED TICK KEEPS THE LAST OUTCOME, so a healthy export does not read as "did not reach every
//    destination", and the recipient-pin drift reaches the posture record.
//  - A RE-EXPORT AT THE SAME VERSION (a recipient added) supersedes the earlier generation, so the bucket
//    still holds one artefact at the latest version.
//  - AN UPGRADED BACKLOG CLEARS. Released engines from 0.3.0 wrote one generation per tick at one version. A
//    backlog larger than one tick's budget clears over several ticks, because the gate stays open while
//    purge debt remains. Before, the first purge stopped on the budget and the gate closed for good.
//  - ONLY THIS ENGINE'S GENERATIONS ARE PURGED. A sibling signed by another signer, one naming another
//    account, or one with no signature stays, and the auto-heal still refuses the version as ambiguous.
//  - A LAGGARD DESTINATION IS RETRIED. A destination whose write failed gets the export on the next tick,
//    and only it is written. A destination the budget cut off gets an ok:false row, so the posture check
//    cannot pass, and the next tick writes it.
//  - THE PURGE LEAVES LATER DESTINATIONS THEIR BUDGET. A large backlog in one destination no longer cuts off
//    the destinations after it.
//
// Run: node test/validate-control-plane-export-sealing.ts

import { runControlPlaneExportPass } from "../src/cron/control-plane-pass.ts";
import { buildControlPlaneArtefactToWrite, isSealedControlPlaneExport, sealedArtefactKey, unsealAndResignForAutoHeal } from "../src/admin/control-plane-seal.ts";
import { CONTROL_PLANE_PREFIX, type ControlPlaneExport, controlPlaneArtefactKey, controlPlaneDestCredFingerprint, selectLatestControlPlaneExport, selectLatestSealedControlPlaneExport } from "../src/admin/control-plane.ts";
import { loadControlPlaneExportRecipients, loadIdentity, loadSigner } from "../src/keys-env.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import { budgetFromEnv } from "../src/seal/budget.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { DESTINATIONS_KEY } from "../src/sched/scheduler-do-records.ts";
import type { Env } from "../src/env.d.ts";
import type { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { makeConfig, makeScheduler } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// An in-memory R2 bucket with the five calls R2Destination makes.
class MemR2 {
  readonly objs = new Map<string, Uint8Array>();
  async put(key: string, value: ArrayBuffer | Uint8Array): Promise<{ key: string; etag: string }> {
    this.objs.set(key, value instanceof Uint8Array ? value.slice() : new Uint8Array(value.slice(0)));
    return { key, etag: "e" };
  }
  async get(key: string): Promise<{ arrayBuffer: () => Promise<ArrayBuffer>; etag: string } | null> {
    const b = this.objs.get(key);
    if (b === undefined) return null;
    return { arrayBuffer: async () => b.slice().buffer, etag: "e" };
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
  cpKeys(): string[] {
    return [...this.objs.keys()].filter((k) => k.startsWith(CONTROL_PLANE_PREFIX)).sort();
  }
}

// makeRecipientKeys generates one hybrid recipient the way the key ceremony does and returns the env forms:
// the 1600-byte public and the 96-byte private identity, both base64url.
function makeRecipientKeys(): { pub: string; priv: string } {
  const x25519Scalar = crypto.getRandomValues(new Uint8Array(32));
  const mlkemSeed = crypto.getRandomValues(new Uint8Array(64));
  const pub = concat(x25519PublicFromScalar(x25519Scalar), mlkemKeygen(mlkemSeed).encapKey);
  return { pub: b64urlEncode(pub), priv: b64urlEncode(concat(x25519Scalar, mlkemSeed)) };
}

// The export slice the DO would build. exportedAt is fresh on every call, as the DO's is, so two passes
// at the same version name two distinct objects.
function makeExport(configVersion: number, destIds: string[] = ["d1"], accountId = "acct-source"): ControlPlaneExport {
  const dest = (id: string) => ({ id, label: "R2", endpoint: "https://acct.r2.cloudflarestorage.com", bucket: `b-${id}`, region: "auto", accessKeyId: "AK1", secret: { reestablish: true }, setAt: 1_700_000_000_000, setBy: null, verifiedAt: 1_700_000_000_001, deleteProbe: "ok" });
  return {
    v: 1,
    exportedAt: new Date().toISOString(),
    configVersion,
    configContentHash: `sha384:config-${configVersion}`,
    engineAccountId: accountId,
    priorAuditHead: { headSeq: 3, headHash: "sha384:head" },
    downpipes: [{ id: "dp-1", name: "prod-kv" }],
    destinations: destIds.map(dest),
    defaultDestinationId: "d1",
    roles: [{ subject: "oidc:sub", email: "owner@example.com", role: "owner", grantedBy: "boot", grantedAt: "2026-07-05T00:00:00.000Z" }],
    groupRoles: [],
    customRoles: [],
    idpConnections: [],
    notifyChannels: [],
    notifyRules: [],
    discovery: null,
    orgPolicy: { requireConfigApproval: false },
    reestablish: ["destination-credentials", "idp-secrets", "session-keys", "passkeys"],
  } as unknown as ControlPlaneExport;
}

// passScheduler fronts the REAL SchedulerDO. It answers only the two reads a unit test must supply: the export
// slice (a fixture, so no destination and role seeding is needed) and the destination config (a deploy-time
// record for the id asked, so the env R2 binding is the store: resolveDestination answers a source:"deploy"
// row with the env-backed destination, and answers an id with no row as not configured). Every other route,
// including the export state and health records, is the DO's own.
function passScheduler(dobj: SchedulerDO, exportFor: () => ControlPlaneExport, onDestConfig?: (id: string | null) => void): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
      if (url.pathname === "/control-plane/export") return Response.json(exportFor());
      if (url.pathname === "/dest-config") {
        const id = url.searchParams.get("id");
        onDestConfig?.(id);
        return Response.json({ config: { id: id ?? "deploy", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "" } });
      }
      return dobj.fetch(new Request(url.toString(), init));
    },
  } as unknown as DurableObjectStub;
}

function makeEnv(stub: DurableObjectStub, r2: MemR2 | RoutedR2, keys: Record<string, string>): Env {
  const namespace = { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, DEST_KIND: "r2", DEST_R2: r2, ...keys } as unknown as Env;
}

async function runPass(env: Env, stub: DurableObjectStub, subrequests?: number): Promise<void> {
  await runControlPlaneExportPass(env, stub as never, budgetFromEnv(env, subrequests !== undefined ? { subrequests } : undefined));
}

// RoutedR2 gives each destination its own bucket. Every destination resolves to the env R2 binding in this
// harness, so the scheduler stub names the destination whose config the pass just read, and every call
// until the next config read goes to that destination's bucket. The pass handles destinations one at a time.
class RoutedR2 {
  current = "";
  readonly buckets = new Map<string, MemR2>();
  failPutOnce = new Set<string>();
  bucket(id: string): MemR2 {
    let b = this.buckets.get(id);
    if (b === undefined) {
      b = new MemR2();
      this.buckets.set(id, b);
    }
    return b;
  }
  async put(key: string, value: ArrayBuffer | Uint8Array): Promise<{ key: string; etag: string }> {
    if (this.failPutOnce.delete(this.current)) throw new Error("simulated network fault");
    return this.bucket(this.current).put(key, value);
  }
  get(key: string) {
    return this.bucket(this.current).get(key);
  }
  head(key: string) {
    return this.bucket(this.current).head(key);
  }
  delete(key: string) {
    return this.bucket(this.current).delete(key);
  }
  list(opts: { prefix?: string }) {
    return this.bucket(this.current).list(opts);
  }
}

// seedGenerations writes count copies of one signed generation at one version, under distinct past
// timestamps, the way a released engine left one generation per tick. The bytes are one real artefact, so
// each copy verifies under the signer that made it.
async function seedGenerations(r2: MemR2, count: number, version: number, signer: Awaited<ReturnType<typeof loadSigner>>, recipients: ReturnType<typeof loadControlPlaneExportRecipients>, opts: { accountId?: string; noSig?: boolean; startMs?: number } = {}): Promise<string[]> {
  const exp = makeExport(version, ["d1"], opts.accountId ?? "acct-source");
  const art = await buildControlPlaneArtefactToWrite(exp, signer, recipients, () => crypto.getRandomValues(new Uint8Array(16)));
  const keys: string[] = [];
  for (let i = 0; i < count; i++) {
    const iso = new Date((opts.startMs ?? Date.UTC(2026, 8, 1)) + i * 900_000).toISOString();
    const base = controlPlaneArtefactKey(version, iso);
    const key = art.sealed ? sealedArtefactKey(base) : base;
    await r2.put(key, art.bodyBytes);
    if (opts.noSig !== true) await r2.put(`${key}.sig`, utf8(art.sigText));
    keys.push(key);
  }
  return keys;
}

function sealedGenerations(r2: MemR2): string[] {
  return r2.cpKeys().filter((k) => k.endsWith(".sealed.json"));
}

function parsed(r2: MemR2, key: string): unknown {
  return JSON.parse(new TextDecoder().decode(r2.objs.get(key)!));
}

async function main(): Promise<void> {
  const signerB64 = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));
  const signer = await loadSigner(signerB64);
  const bg = makeRecipientKeys();
  const cfg = makeRecipientKeys();

  console.log("control-plane export: a config recipient alone seals the export, and auto-heal opens it");
  {
    const { stub: dobj } = makeScheduler();
    const r2 = new MemR2();
    const sched = passScheduler(dobj, () => makeExport(4));
    const env = makeEnv(sched, r2, { SIGNER_PRIVATE: signerB64, CONFIG_RECIPIENT_PUBLIC: cfg.pub });
    await runPass(env, sched);
    const keys = r2.cpKeys();
    const sealedKeys = keys.filter((k) => k.endsWith(".sealed.json"));
    ok("one sealed generation is written", sealedKeys.length === 1);
    ok("no cleartext generation is written", selectLatestControlPlaneExport(keys).kind === "none");
    const art = sealedKeys.length === 1 ? parsed(r2, sealedKeys[0]!) : null;
    ok("the artefact is a sealed control-plane export", isSealedControlPlaneExport(art));
    if (isSealedControlPlaneExport(art)) {
      ok("it is sealed to the config recipient only", art.recipients.length === 1 && art.recipients[0]!.role === "config");
      ok("the roster is not readable in the bucket", !JSON.stringify(art).includes("owner@example.com"));
      const healed = await unsealAndResignForAutoHeal(art, signer, loadIdentity(cfg.priv));
      ok("the config-recipient private opens it for the auto-heal", healed.exp.configVersion === 4 && healed.exp.roles[0]?.email === "owner@example.com");
    }
    const state = await dobj.getControlPlaneExportState();
    ok("the export state records the sealed form", state?.sealed === true);
  }

  console.log("control-plane export: the old opt-out flag no longer writes cleartext");
  {
    const { stub: dobj } = makeScheduler();
    const r2 = new MemR2();
    const sched = passScheduler(dobj, () => makeExport(4));
    const env = makeEnv(sched, r2, { SIGNER_PRIVATE: signerB64, BREAK_GLASS_PUBLIC: bg.pub, CONFIG_RECIPIENT_PUBLIC: cfg.pub, CONTROL_PLANE_EXPORT_SEALING_DISABLED: "1" });
    await runPass(env, sched);
    const keys = r2.cpKeys();
    const sel = selectLatestSealedControlPlaneExport(keys);
    ok("the export is sealed with the flag set", sel.kind === "ok" && selectLatestControlPlaneExport(keys).kind === "none");
    const art = sel.kind === "ok" ? parsed(r2, sel.jsonKey) : null;
    ok("break-glass is recipient #0 and the config recipient is #1", isSealedControlPlaneExport(art) && art.recipients.map((r) => r.role).join(",") === "break-glass,config");
  }

  console.log("control-plane export: no recipient key at all writes signed cleartext, and the posture check says so");
  {
    const { stub: dobj, storage } = makeScheduler();
    const r2 = new MemR2();
    const sched = passScheduler(dobj, () => makeExport(4));
    const env = makeEnv(sched, r2, { SIGNER_PRIVATE: signerB64 });
    await runPass(env, sched);
    const keys = r2.cpKeys();
    ok("a cleartext generation is written (a recovery artefact still exists)", selectLatestControlPlaneExport(keys).kind === "ok");
    ok("no sealed generation is written", selectLatestSealedControlPlaneExport(keys).kind === "none");
    const state = await dobj.getControlPlaneExportState();
    ok("the export state records the cleartext form", state?.sealed === false);
    // The posture check reads that record. Seed the one destination and one downpipe the check needs to apply.
    await storage.put(DESTINATIONS_KEY, { list: [{ id: "d1", secretAccessKey: "k", endpoint: "https://x.r2", bucket: "b1", region: "auto", accessKeyId: "AK1" }], defaultId: "d1" });
    await dobj.addDownpipe(makeConfig("dp-1"));
    const { report } = await dobj.computePostureReport({});
    const check = report.checks.find((c) => c.id === "environment-self-backup");
    ok("the environment-self-backup check says the export is not encrypted", check !== undefined && /not encrypted/.test(check.detail) && /key ceremony/.test(check.detail));
  }

  console.log("control-plane export: an unchanged tick writes nothing and keeps the last outcome");
  {
    const { stub: dobj } = makeScheduler();
    const r2 = new MemR2();
    const sched = passScheduler(dobj, () => makeExport(9));
    const env = makeEnv(sched, r2, { SIGNER_PRIVATE: signerB64, BREAK_GLASS_PUBLIC: bg.pub, CONFIG_RECIPIENT_PUBLIC: cfg.pub });
    await runPass(env, sched);
    await new Promise((r) => setTimeout(r, 5)); // a later tick: a different exportedAt, so a rewrite names a new object
    await runPass(env, sched);
    const keys = r2.cpKeys();
    ok("the export state keeps the recipient-pin hash", typeof (await dobj.getControlPlaneExportState())?.recipientPinHash === "string");
    ok("two ticks at one version leave ONE sealed generation", keys.filter((k) => k.endsWith(".sealed.json")).length === 1);
    ok("the auto-heal selection is unambiguous", selectLatestSealedControlPlaneExport(keys).kind === "ok");
    const health = await dobj.getControlPlaneExportHealth();
    ok("the second tick is recorded as unchanged", health?.skipped === "unchanged");
    ok("the unchanged tick keeps the last write outcome", health?.wroteAny === true && health.perDest.length === 1 && health.perDest[0]!.ok === true);
    // The same record path, driven directly, so it does not depend on the gate above firing: an unchanged
    // skip posted over a written outcome keeps that outcome.
    {
      const { stub: d2 } = makeScheduler();
      const post = (body: unknown): Promise<Response> => d2.fetch(new Request("https://scheduler.internal/control-plane/export-health", { method: "POST", body: JSON.stringify(body) }));
      await post({ wroteAny: true, configVersion: 3, perDest: [{ id: "d1", ok: true }] });
      await post({ skipped: "unchanged", wroteAny: false, configVersion: 3, perDest: [] });
      const h = await d2.getControlPlaneExportHealth();
      ok("the DO keeps the written outcome under an unchanged skip", h?.skipped === "unchanged" && h.wroteAny === true && h.perDest.length === 1);
    }


    console.log("control-plane export: a recipient added at the same version supersedes the earlier generation");
    const op = makeRecipientKeys();
    const env2 = makeEnv(sched, r2, { SIGNER_PRIVATE: signerB64, BREAK_GLASS_PUBLIC: bg.pub, CONFIG_RECIPIENT_PUBLIC: cfg.pub, OPERATIONAL_PUBLIC: op.pub });
    await new Promise((r) => setTimeout(r, 5));
    await runPass(env2, sched);
    const keys2 = r2.cpKeys();
    ok("the pin move re-exports and the bucket still holds ONE sealed generation at the version", keys2.filter((k) => k.endsWith(".sealed.json")).length === 1 && keys2.filter((k) => k.endsWith(".sealed.json.sig")).length === 1);
    ok("the new generation is not the earlier one", keys2.join() !== keys.join() && selectLatestSealedControlPlaneExport(keys2).kind === "ok");
    const health2 = await dobj.getControlPlaneExportHealth();
    ok("the recipient-pin drift reaches the health record", health2?.recipientPinDrift?.matches === false && health2.recipientPinDrift.added === 1);
  }

  const recipientsBoth = loadControlPlaneExportRecipients(bg.pub, cfg.pub);
  const keysBoth = { SIGNER_PRIVATE: signerB64, BREAK_GLASS_PUBLIC: bg.pub, CONFIG_RECIPIENT_PUBLIC: cfg.pub };

  console.log("control-plane export: an upgraded backlog of same-version generations clears over several ticks");
  {
    const { stub: dobj } = makeScheduler();
    const r2 = new MemR2();
    const sched = passScheduler(dobj, () => makeExport(9));
    const env = makeEnv(sched, r2, keysBoth);
    await seedGenerations(r2, 120, 9, signer, recipientsBoth);
    // The pointer a released engine leaves: its route dropped the recipient-pin hash.
    await dobj.setControlPlaneExportState({ configVersion: 9, configContentHash: "sha384:config-9", exportedAt: "2026-09-02T00:00:00.000Z", destCredHash: await controlPlaneDestCredFingerprint(makeExport(9)) });
    const kinds: string[] = [];
    let settledAt = -1;
    for (let tick = 1; tick <= 12; tick++) {
      await new Promise((r) => setTimeout(r, 2));
      await runPass(env, sched, 200);
      const sel = selectLatestSealedControlPlaneExport(r2.cpKeys());
      kinds.push(sel.kind);
      if (sel.kind === "ok" && settledAt < 0) settledAt = tick;
    }
    console.log(`    selection per tick: ${kinds.join(" ")}`);
    ok("one tick's budget cannot clear the backlog (the first tick still reads ambiguous)", kinds[0] === "ambiguous");
    ok("later ticks finish the purge, and the auto-heal selection becomes unambiguous", settledAt > 1);
    ok("the bucket ends with ONE sealed generation and its signature", sealedGenerations(r2).length === 1 && r2.cpKeys().length === 2);
    const state = await dobj.getControlPlaneExportState();
    ok("no purge debt is left in the export state", state !== null && (state.purgeDebt ?? []).length === 0 && state.destKeys?.d1 === sealedGenerations(r2)[0]);
    const health = await dobj.getControlPlaneExportHealth();
    ok("the settled export reads as written to every destination", health?.wroteAny === true && health.perDest.length === 1 && health.perDest[0]!.ok === true);
  }

  console.log("control-plane export: only this engine's generations are purged");
  {
    const { stub: dobj } = makeScheduler();
    const r2 = new MemR2();
    const sched = passScheduler(dobj, () => makeExport(9));
    const env = makeEnv(sched, r2, keysBoth);
    const other = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
    await seedGenerations(r2, 2, 9, signer, recipientsBoth, { startMs: Date.UTC(2026, 8, 1) });
    const foreign = await seedGenerations(r2, 1, 9, other, recipientsBoth, { startMs: Date.UTC(2026, 8, 2) });
    const otherAccount = await seedGenerations(r2, 1, 9, signer, recipientsBoth, { accountId: "acct-other", startMs: Date.UTC(2026, 8, 3) });
    const unsigned = await seedGenerations(r2, 1, 9, signer, recipientsBoth, { noSig: true, startMs: Date.UTC(2026, 8, 4) });
    await runPass(env, sched);
    const left = sealedGenerations(r2);
    ok("the two generations this engine signed are removed", left.length === 4);
    ok("a sibling signed by another signer stays", left.includes(foreign[0]!) && r2.objs.has(`${foreign[0]!}.sig`));
    ok("a sibling naming another account stays", left.includes(otherAccount[0]!));
    ok("a sibling with no signature stays", left.includes(unsigned[0]!));
    ok("the auto-heal still refuses the version as ambiguous", selectLatestSealedControlPlaneExport(r2.cpKeys()).kind === "ambiguous");
    const state = await dobj.getControlPlaneExportState();
    ok("kept foreign siblings are not purge debt (the gate closes)", (state?.purgeDebt ?? []).length === 0);
  }

  console.log("control-plane export: a destination whose write failed is retried next tick, and only it is written");
  {
    const { stub: dobj } = makeScheduler();
    const routed = new RoutedR2();
    const sched = passScheduler(dobj, () => makeExport(5, ["d1", "d2"]), (id) => {
      routed.current = id ?? "";
    });
    const env = makeEnv(sched, routed, keysBoth);
    routed.failPutOnce.add("d2");
    await runPass(env, sched);
    const d1First = sealedGenerations(routed.bucket("d1"));
    ok("tick 1 writes d1", d1First.length === 1);
    ok("tick 1 fails d2", sealedGenerations(routed.bucket("d2")).length === 0);
    const h1 = await dobj.getControlPlaneExportHealth();
    ok("tick 1 records d2 as failed", h1?.perDest.find((d) => d.id === "d2")?.ok === false && h1.perDest.length === 2);
    await new Promise((r) => setTimeout(r, 2));
    await runPass(env, sched);
    ok("tick 2 writes d2", sealedGenerations(routed.bucket("d2")).length === 1 && selectLatestSealedControlPlaneExport(routed.bucket("d2").cpKeys()).kind === "ok");
    ok("tick 2 does not rewrite d1", sealedGenerations(routed.bucket("d1")).join() === d1First.join());
    const h2 = await dobj.getControlPlaneExportHealth();
    ok("tick 2 records both destinations as written", h2?.wroteAny === true && h2.perDest.length === 2 && h2.perDest.every((d) => d.ok));
    await new Promise((r) => setTimeout(r, 2));
    await runPass(env, sched);
    const h3 = await dobj.getControlPlaneExportHealth();
    ok("tick 3 is unchanged and writes nothing", h3?.skipped === "unchanged" && sealedGenerations(routed.bucket("d1")).length === 1 && sealedGenerations(routed.bucket("d2")).length === 1);
  }

  console.log("control-plane export: a destination the budget cuts off gets a failed row, and the next tick writes it");
  {
    const { stub: dobj, storage } = makeScheduler();
    const routed = new RoutedR2();
    const ids = Array.from({ length: 16 }, (_, i) => `d${i + 1}`);
    const sched = passScheduler(dobj, () => makeExport(6, ids), (id) => {
      routed.current = id ?? "";
    });
    const env = makeEnv(sched, routed, keysBoth);
    await runPass(env, sched, 50);
    const written1 = ids.filter((id) => sealedGenerations(routed.bucket(id)).length === 1);
    const h1 = await dobj.getControlPlaneExportHealth();
    ok("the budget cuts off some destinations in tick 1", written1.length > 0 && written1.length < ids.length);
    ok("every destination has a row, and a cut-off one reads ok:false", h1 !== null && h1.perDest.length === ids.length && h1.perDest.filter((d) => !d.ok).length === ids.length - written1.length);
    await storage.put(DESTINATIONS_KEY, { list: ids.map((id) => ({ id, secretAccessKey: "k", endpoint: "https://x.r2", bucket: `b-${id}`, region: "auto", accessKeyId: "AK1" })), defaultId: "d1" });
    await dobj.addDownpipe(makeConfig("dp-1"));
    const { report } = await dobj.computePostureReport({});
    const check = report.checks.find((c) => c.id === "environment-self-backup");
    ok("the environment-self-backup check fails while a destination holds no current export", check?.status === "fail" && /did not reach every destination/.test(check.detail));
    const firstKeys = new Map(written1.map((id) => [id, sealedGenerations(routed.bucket(id))[0]!]));
    await new Promise((r) => setTimeout(r, 2));
    await runPass(env, sched, 200);
    ok("tick 2 writes every cut-off destination", ids.every((id) => sealedGenerations(routed.bucket(id)).length === 1));
    ok("tick 2 leaves the destinations written in tick 1 alone", written1.every((id) => sealedGenerations(routed.bucket(id))[0] === firstKeys.get(id)));
    const h2 = await dobj.getControlPlaneExportHealth();
    ok("tick 2 records every destination as written", h2?.perDest.length === ids.length && h2.perDest.every((d) => d.ok));
  }

  console.log("control-plane export: a large backlog in one destination does not cut off the next one");
  {
    const { stub: dobj } = makeScheduler();
    const routed = new RoutedR2();
    const sched = passScheduler(dobj, () => makeExport(7, ["d1", "d2"]), (id) => {
      routed.current = id ?? "";
    });
    const env = makeEnv(sched, routed, keysBoth);
    await seedGenerations(routed.bucket("d1"), 150, 7, signer, recipientsBoth);
    await runPass(env, sched, 200);
    ok("d2 gets the export in the same tick as d1's purge", sealedGenerations(routed.bucket("d2")).length === 1);
    const h = await dobj.getControlPlaneExportHealth();
    ok("both destinations read as written", h?.perDest.length === 2 && h.perDest.every((d) => d.ok));
    const state = await dobj.getControlPlaneExportState();
    ok("d1's unfinished purge is recorded as debt", (state?.purgeDebt ?? []).includes("d1"));
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-control-plane-export-sealing (${failures} failure(s))`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
