// Validates the deploy-time destination id with its stored row gone, on the real paths, and the two refusals
// of the singular route (the router's POST /admin/destination, the DO's POST /dest-config) around that row.
//
// THE DEFECT THIS PINS. The "deploy" row can be gone while downpipes still name "deploy": the singular clear
// ({config: null}) removes the default row, which is "deploy" once the first console destination seeded it,
// and a downpipe can name "deploy" after that. An estate can also hold that state from an engine whose
// singular clear had no pin check. Before this fix, resolveDestination read an id with no stored row as
// not-configured, so with DEST_R2 bound those downpipes were refused on the seal choice, replication and the
// restore drill, and the support pack's roster count called them dangling. That is the engine 0.3.5 fault
// class the resolver exists to end.
//
// THE SINGULAR ROUTE'S TWO REFUSALS.
//   - The clear is refused while a downpipe names the default: removeDest's in-use guard, the same text.
//     Without it the clear removed a destination that downpipes still named.
//   - A config is refused while the default is the deploy-time destination. Without it the set stored the new
//     bucket under the reserved id "deploy": a default-routed downpipe sealed to the new bucket and recorded
//     "deploy", every read by that id (restore, drill, replication, prune) went to the DEST_R2 bucket, which
//     does not hold those runs, and a downpipe that names "deploy" kept sealing to the DEST_R2 bucket. The
//     second world proves the refusal, that nothing moved, and that the two plural steps the refusal names
//     move the backups to the new bucket.
//
// HOW IT WAS MISSED. Every resolver test seeded the "deploy" row. None cleared the default while a downpipe
// named it.
//
// WHAT THIS DRIVES. A real SchedulerDO over MockStorage and its own routes, the real seal dispatch
// (cron/seal-dispatch.ts runDownpipe, buffered), one real cron invocation (cron/drive.ts drive: replication and
// the scheduled restore test), and the real signed support pack over the same DO. The platform is in memory:
// one KV namespace, the DEST_R2 binding, and a console S3 destination that refuses any unsigned request.
// Nothing leaves the process: a request to any other origin throws. A virtual clock lets the world span days.
//
// The checks of the first world, in order: the singular clear is refused while the downpipe names "deploy";
// with the row gone as an earlier engine's clear left it (written to storage), the row is gone while the downpipe names the id (population); the resolver serves the
// id from the binding, and refuses it only as deploy-binding-missing with no env destination; the roster set
// the dangling count reads follows the resolver; the next run seals to "deploy"; the pack counts no dangling
// reference (top level, cronHealth, destResolution); replication holds the run on both legs; the drill ran
// and passed with no pre-drill skip; the pack says "deploy" resolves with no stored row.
//
// Run: node test/validate-deploy-row-cleared.ts

import { callerHeaders } from "../src/admin/router-audit.ts";
import type { AuthMethod, Role } from "../src/admin/identity.ts";
import { fetchDestinationIdSet } from "../src/admin/support-sections-config.ts";
import { signedSupportBundle } from "../src/admin/support.ts";
import { recordCronHealth } from "../src/cron/cron-fault-ledger.ts";
import { drive } from "../src/cron/drive.ts";
import { runDownpipe } from "../src/cron/seal-dispatch.ts";
import { b64urlEncode, sha256Hex, utf8 } from "../src/crypto/bytes.ts";
import { resolveDestination } from "../src/dest/factory.ts";
import { signV4, type SigV4Creds } from "../src/dest/sigv4.ts";
import type { Env } from "../src/env.d.ts";
import { DESTINATIONS_KEY, type DestinationCollection } from "../src/sched/scheduler-do-base.ts";
import { DEPLOY_DEFAULT_SET_REFUSAL } from "../src/sched/scheduler-do-dest-config.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeConfig, DownpipeState, RunHistoryEntry } from "../src/sched/types.ts";
import { makeSupportRecipient } from "../tools/generate-support-keypair.ts";
import { liveRunSealNamespace } from "../tools/support-corpus/harness.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

type Dict = Record<string, unknown>;
let failures = 0;
// Written to stdout directly: the world runs inside quietly(), which mutes console.log for the engine's own lines.
function ok(label: string, cond: boolean): void {
  process.stdout.write(`  ${cond ? "ok  " : "FAIL"} ${label}\n`);
  if (!cond) failures++;
}

// ---- The virtual clock. Date.now() and a no-argument new Date() read it; an explicit time is untouched. ----
const RealDate = Date;
let clockOffset = 0;
function installClock(startAt: number): void {
  clockOffset = startAt - RealDate.now();
  class VirtualDate extends RealDate {
    constructor(...args: unknown[]) {
      if (args.length === 0) super(RealDate.now() + clockOffset);
      else super(...(args as [string | number | Date]));
    }
    static override now(): number {
      return RealDate.now() + clockOffset;
    }
  }
  globalThis.Date = VirtualDate as unknown as DateConstructor;
}
function advance(ms: number): void {
  clockOffset += ms;
}

async function quietly<T>(fn: () => Promise<T>): Promise<T> {
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const mute = (): void => {};
  Object.assign(console, { log: mute, info: mute, warn: mute, error: mute });
  try {
    return await fn();
  } finally {
    Object.assign(console, saved);
  }
}

// ---- The platform fakes. ----
class KvFake {
  readonly store = new Map<string, Uint8Array>();
  constructor(entries: Record<string, string>) {
    for (const [k, v] of Object.entries(entries)) this.store.set(k, utf8(v));
  }
  async list(o?: { prefix?: string; limit?: number }): Promise<{ keys: Array<{ name: string }>; list_complete: true }> {
    const names = [...this.store.keys()].filter((k) => k.startsWith(o?.prefix ?? "")).sort();
    return { keys: names.slice(0, o?.limit ?? names.length).map((name) => ({ name })), list_complete: true };
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v === undefined ? null : (v.slice().buffer as ArrayBuffer);
  }
  async getWithMetadata(k: string): Promise<{ value: ArrayBuffer | null; metadata: null }> {
    return { value: await this.get(k), metadata: null };
  }
}

// The R2 binding, with R2's documented preconditions (onlyIf etagDoesNotMatch "*" and etagMatches).
class R2Fake {
  readonly store = new Map<string, { bytes: Uint8Array; etag: string }>();
  private seq = 0;
  async put(key: string, value: ArrayBuffer | ArrayBufferView | ReadableStream | string, options?: { onlyIf?: R2Conditional }): Promise<{ etag: string; key: string; size: number } | null> {
    const existing = this.store.get(key);
    const c = options?.onlyIf;
    if (c?.etagDoesNotMatch === "*" && existing) return null;
    if (c?.etagMatches !== undefined && (!existing || existing.etag !== c.etagMatches)) return null;
    const bytes = value instanceof ReadableStream ? new Uint8Array(await new Response(value).arrayBuffer()) : typeof value === "string" ? utf8(value) : value instanceof ArrayBuffer ? new Uint8Array(value.slice(0)) : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    const etag = `r2-${++this.seq}`;
    this.store.set(key, { bytes, etag });
    return { etag, key, size: bytes.length };
  }
  async get(key: string): Promise<{ key: string; etag: string; httpEtag: string; size: number; arrayBuffer(): Promise<ArrayBuffer>; body: ReadableStream } | null> {
    const r = this.store.get(key);
    if (!r) return null;
    const snap = r.bytes.slice();
    return { key, etag: r.etag, httpEtag: `"${r.etag}"`, size: snap.length, arrayBuffer: async () => snap.buffer, body: new Response(snap).body! };
  }
  async head(key: string): Promise<{ key: string; etag: string; httpEtag: string; size: number } | null> {
    const r = this.store.get(key);
    return r ? { key, etag: r.etag, httpEtag: `"${r.etag}"`, size: r.bytes.length } : null;
  }
  async delete(keys: string | string[]): Promise<void> {
    for (const k of Array.isArray(keys) ? keys : [keys]) this.store.delete(k);
  }
  async list(o?: { prefix?: string }): Promise<R2Objects> {
    const objects = [...this.store.keys()]
      .filter((k) => k.startsWith(o?.prefix ?? ""))
      .sort()
      .map((key) => ({ key, size: this.store.get(key)!.bytes.length, etag: this.store.get(key)!.etag }) as unknown as R2Object);
    return { objects, truncated: false, delimitedPrefixes: [] } as unknown as R2Objects;
  }
}

const S3_ENDPOINT = "https://s3.deploy-row.example.test";
const S3_BUCKET = "deploy-row-offsite";
const S3_CREDS: SigV4Creds = { accessKeyID: "AKIDDEPLOYROWEXAMPLE", secretKey: "deploy-row-secret-access-key-EXAMPLE", region: "us-east-1", service: "s3" };

// A stateful S3 bucket. It recomputes each request's SigV4 signature from the headers the request says it signed
// and refuses a mismatch, so a write the engine did not sign correctly cannot count as a held copy. It models
// what the seal, replication, restore and pack paths call: object-lock read (none set), ListObjectsV2 (one
// page), a conditional PUT, GET, HEAD and DELETE. Any other request answers 500 and is recorded.
class S3Fake {
  readonly store = new Map<string, { bytes: Uint8Array; etag: string }>();
  readonly refusals: string[] = [];
  private seq = 0;
  async handle(method: string, u: URL, headers: Record<string, string>, body: Uint8Array): Promise<Response> {
    const auth = headers.authorization ?? "";
    const signed = (/SignedHeaders=([^,]+)/.exec(auth)?.[1] ?? "").split(";");
    const canon: Record<string, string> = {};
    for (const h of signed) canon[h] = h === "host" ? u.host : (headers[h] ?? "");
    const payloadHash = headers["x-amz-content-sha256"] ?? "";
    const hashOk = payloadHash === "UNSIGNED-PAYLOAD" || payloadHash === (await sha256Hex(body));
    const unsignedAmz = Object.keys(headers).some((h) => h.startsWith("x-amz-") && !signed.includes(h));
    const expect = auth === "" ? "" : await signV4(method, u.pathname, u.search.replace(/^\?/, ""), canon, payloadHash, headers["x-amz-date"] ?? "", S3_CREDS);
    if (auth === "" || !hashOk || unsignedAmz || expect !== auth) {
      this.refusals.push(`${method} ${u.pathname}: signature`);
      return new Response("<Error><Code>SignatureDoesNotMatch</Code></Error>", { status: 403 });
    }
    const parts = u.pathname.split("/").slice(1);
    if (parts[0] !== S3_BUCKET) return new Response("<Error><Code>NoSuchBucket</Code></Error>", { status: 404 });
    const key = parts.slice(1).map(decodeURIComponent).join("/");
    const q = u.searchParams;
    if (method === "GET" && q.has("object-lock")) return new Response("<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>", { status: 404 });
    if (method === "GET" && q.get("list-type") === "2") {
      const keys = [...this.store.keys()].filter((k) => k.startsWith(q.get("prefix") ?? "")).sort();
      const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
      return new Response(`<ListBucketResult>${keys.map((k) => `<Contents><Key>${esc(k)}</Key><Size>${this.store.get(k)!.bytes.length}</Size><ETag>${this.store.get(k)!.etag}</ETag></Contents>`).join("")}<KeyCount>${keys.length}</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>`, { status: 200 });
    }
    if (method === "PUT" && !q.has("partNumber")) {
      const existing = this.store.get(key);
      if (headers["if-none-match"] === "*" && existing) return new Response(null, { status: 412 });
      const im = headers["if-match"];
      if (im !== undefined && (!existing || existing.etag !== im)) return new Response(null, { status: 412 });
      const etag = `"s3-${++this.seq}"`;
      this.store.set(key, { bytes: body, etag });
      return new Response(null, { status: 200, headers: { etag } });
    }
    if (method === "GET" || method === "HEAD") {
      const r = this.store.get(key);
      if (!r) return new Response(method === "HEAD" ? null : "<Error><Code>NoSuchKey</Code></Error>", { status: 404 });
      return new Response(method === "HEAD" ? null : r.bytes.slice(), { status: 200, headers: { etag: r.etag, "content-length": String(r.bytes.length) } });
    }
    if (method === "DELETE") {
      this.store.delete(key);
      return new Response(null, { status: 204 });
    }
    this.refusals.push(`unmodelled ${method} ${u.search}`);
    return new Response("<Error><Code>InternalError</Code></Error>", { status: 500 });
  }
}

// ---- The world. ----
type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; role: Role };
const OWNER: Caller = { method: "token", email: "owner@deploy-row.example", subject: null, groups: [], role: "owner" };
const SOURCE = { type: "kv", binding: "KV_UPLOADS", namespaceId: "ns", include: [], exclude: [] } as unknown as DownpipeConfig["source"];

interface World {
  env: Env;
  scheduler: DurableObjectStub;
  storage: MockStorage;
  s3: S3Fake;
  close(): void;
}

async function makeWorld(startAt: number): Promise<World> {
  installClock(startAt);
  const op = await makeSupportRecipient();
  const bg = await makeSupportRecipient();
  const vendor = await makeSupportRecipient();
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  const env = {
    SIGNER_PRIVATE: b64urlEncode(crypto.getRandomValues(new Uint8Array(64))),
    OPERATIONAL_PUBLIC: b64urlEncode(op.recipientPublic),
    OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
    BREAK_GLASS_PUBLIC: b64urlEncode(bg.recipientPublic),
    VENDOR_SUPPORT_PUBLIC: b64urlEncode(vendor.recipientPublic),
    CONFIG_WRAP_KEY: b64urlEncode(crypto.getRandomValues(new Uint8Array(32))),
    DEST_R2: new R2Fake() as unknown as R2Bucket,
    // The buffered seal (one invocation per run), so the world needs no RUNSEAL Durable Object to seal. RUNSEAL is
    // still bound, as every committed wrangler.toml binds it.
    SLICED_RUNS_DISABLED: "1",
    RUNSEAL: liveRunSealNamespace(),
    CF_ACCOUNT_ID: "acct-deploy-row",
    CF_VERSION_METADATA: { id: "cfv-deploy-row-001", tag: "v1" },
    SCHEDULER: { idFromName: () => ({}), get: () => scheduler } as unknown as DurableObjectNamespace,
    KV_UPLOADS: new KvFake({ "uploads/0001": "one", "uploads/0002": "two" }),
  } as unknown as Env;
  const s3 = new S3Fake();
  const s3Origin = new URL(S3_ENDPOINT).origin;
  const prior = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    if (url.origin !== s3Origin) throw new Error(`deploy-row world: unexpected network egress to ${url.origin}`);
    const headers: Record<string, string> = {};
    new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    const raw = init?.body ?? (input instanceof Request ? input.body : null);
    const body = raw === null || raw === undefined ? new Uint8Array(0) : new Uint8Array(await new Response(raw as BodyInit).arrayBuffer());
    return s3.handle((init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase(), url, headers, body);
  }) as typeof fetch;
  return {
    env,
    scheduler,
    storage,
    s3,
    close: () => {
      globalThis.fetch = prior;
      globalThis.Date = RealDate;
      clockOffset = 0;
    },
  };
}

async function doJson(w: World, path: string, init?: RequestInit): Promise<unknown> {
  const resp = await w.scheduler.fetch(`https://scheduler.internal${path}`, init);
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(`deploy-row world: ${init?.method ?? "GET"} ${path} answered ${resp.status}: ${JSON.stringify(body)}`);
  return body;
}

function ownerPost(w: World, path: string, body: unknown): Promise<unknown> {
  return doJson(w, path, { method: "POST", headers: callerHeaders(OWNER), body: JSON.stringify(body) });
}

// ownerFetch is ownerPost for a call that may be refused: it returns the status and the error text, never throws.
async function ownerFetch(w: World, path: string, body: unknown): Promise<{ status: number; error: string; body: Dict }> {
  const resp = await w.scheduler.fetch(`https://scheduler.internal${path}`, { method: "POST", headers: callerHeaders(OWNER), body: JSON.stringify(body) });
  const parsed = ((await resp.json().catch(() => ({}))) ?? {}) as Dict;
  return { status: resp.status, error: typeof parsed.error === "string" ? parsed.error : "", body: parsed };
}

function r2Keys(w: World): string[] {
  return [...(w.env.DEST_R2 as unknown as R2Fake).store.keys()];
}

async function sealOnce(w: World, id: string): Promise<void> {
  const state = ((await doJson(w, "/downpipes")) as DownpipeState[]).find((d) => d.config.id === id);
  if (state === undefined) throw new Error(`deploy-row world: no downpipe ${id}`);
  await runDownpipe(w.env, state);
  await recordCronHealth(w.scheduler, 300_000);
}

// deployDefaultSetWorld drives the singular SET while the default is the deploy-time destination: refused
// with a 400 that names the plural steps, nothing moves, and the named steps move the backups.
async function deployDefaultSetWorld(): Promise<void> {
  // With no row stored yet, the router's envDestConfigured is what says the default is the env destination.
  // Its own world, so a set that lands cannot change the state the checks below start from.
  const e = await makeWorld(Date.now() - 86_400_000);
  try {
    const s3Only = { endpoint: S3_ENDPOINT, bucket: S3_BUCKET, region: S3_CREDS.region, accessKeyId: S3_CREDS.accessKeyID, secretAccessKey: S3_CREDS.secretKey, addressing: "path", deleteProbe: "ok" };
    const envOnly = await quietly(() => ownerFetch(e, "/dest-config", { config: s3Only, envDestConfigured: true }));
    ok("with no row stored and the env destination declared, the singular set is refused and stores nothing", envOnly.status === 400 && envOnly.error === DEPLOY_DEFAULT_SET_REFUSAL && (await e.storage.get(DESTINATIONS_KEY)) === undefined);
  } finally {
    e.close();
  }
  const w = await makeWorld(Date.now() - 3 * 86_400_000);
  const s3Config = { endpoint: S3_ENDPOINT, bucket: S3_BUCKET, region: S3_CREDS.region, accessKeyId: S3_CREDS.accessKeyID, secretAccessKey: S3_CREDS.secretKey, addressing: "path", deleteProbe: "ok" };
  const histOf = async (id: string): Promise<RunHistoryEntry[]> => ((await doJson(w, `/history?id=${id}`)) as { entries: RunHistoryEntry[] }).entries;
  try {
    await quietly(async () => {
      // A default-routed downpipe seals once to the DEST_R2 bucket. The first plural add seeds the "deploy" row
      // as the default; the added S3 row is removed again, so "deploy" is the only row and the default.
      await ownerPost(w, "/downpipes", { id: "kv-uploads", name: "uploads", enabled: true, cadenceSeconds: 86_400, source: SOURCE });
      advance(86_400_000);
      await sealOnce(w, "kv-uploads");
      const added = (await ownerPost(w, "/destinations", { label: "offsite", config: s3Config, envDestConfigured: true })) as { destinations: Array<{ id: string; source?: string }> };
      await ownerPost(w, "/destinations/remove", { id: added.destinations.find((d) => d.source !== "deploy")?.id ?? "" });
      const before = (await doJson(w, "/destinations")) as { destinations: Array<{ id: string; source?: string; bucket?: string }>; defaultId: string };
      ok("DEPLOY DEFAULT POPULATION: the \"deploy\" row is the only row and the default", before.defaultId === "deploy" && before.destinations.length === 1 && before.destinations[0]?.source === "deploy");

      // The singular set of the new bucket, as a script that moves backups to a new bucket calls it.
      const set = await ownerFetch(w, "/dest-config", { config: s3Config });
      const after = (await doJson(w, "/destinations")) as { destinations: Array<{ id: string; source?: string; bucket?: string }>; defaultId: string };
      ok("the singular set is refused (400) with the text that names the plural steps", set.status === 400 && set.error === DEPLOY_DEFAULT_SET_REFUSAL);
      ok("the refused set stores nothing: the \"deploy\" row keeps source deploy and no bucket", JSON.stringify(after) === JSON.stringify(before));

      // Nothing moved: the next run seals to the DEST_R2 bucket under "deploy", and the S3 bucket stays empty.
      const r2Before = r2Keys(w).length;
      advance(86_400_000);
      await sealOnce(w, "kv-uploads");
      const h1 = await histOf("kv-uploads");
      ok("after the refusal the run seals to the DEST_R2 bucket and records \"deploy\"; the new bucket holds nothing", h1[0]?.status === "ok" && h1[0]?.destinationId === "deploy" && r2Keys(w).length > r2Before && w.s3.store.size === 0);

      // The two steps the refusal names: add the new bucket, then make it the default.
      const added2 = (await ownerPost(w, "/destinations", { label: "new bucket", config: s3Config, envDestConfigured: true })) as { destinations: Array<{ id: string; source?: string }> };
      const newId = added2.destinations.find((d) => d.source !== "deploy")?.id ?? "";
      await ownerPost(w, "/destinations/default", { id: newId });
      const r2AtMove = r2Keys(w).length;
      advance(86_400_000);
      await sealOnce(w, "kv-uploads");
      const h2 = await histOf("kv-uploads");
      ok("the named steps move the backups: the next run seals to the new bucket and records its id; DEST_R2 gains nothing", newId !== "" && h2[0]?.status === "ok" && h2[0]?.destinationId === newId && w.s3.store.size > 0 && r2Keys(w).length === r2AtMove);
      ok("the earlier runs keep \"deploy\" as their recorded origin", h2.slice(1).every((e) => e.status === "ok" && e.destinationId === "deploy"));

      // NEGATIVE CONTROL: with a console destination as the default, the singular set updates it in place.
      const inPlace = await ownerFetch(w, "/dest-config", { config: s3Config });
      const moved = (await doJson(w, "/destinations")) as { destinations: Array<{ id: string }>; defaultId: string };
      ok("NEGATIVE CONTROL: the singular set is allowed (200) when the default is a console destination, and keeps its id", inPlace.status === 200 && moved.defaultId === newId && moved.destinations.length === 2);
    });
  } finally {
    w.close();
  }
}

async function main(): Promise<void> {
  console.log("validate-deploy-row-cleared\n");
  const w = await makeWorld(Date.now() - 3 * 86_400_000);
  try {
    await quietly(async () => {
      // One KV downpipe on the default (the deploy-time R2 binding) seals once.
      await ownerPost(w, "/downpipes", { id: "kv-uploads", name: "uploads", enabled: true, cadenceSeconds: 86_400, source: SOURCE });
      advance(86_400_000);
      await sealOnce(w, "kv-uploads");
      // A console S3 destination is added (the router has already probed it live), then the downpipe fans out to
      // ["deploy", <s3>].
      const added = (await ownerPost(w, "/destinations", { label: "offsite", config: { endpoint: S3_ENDPOINT, bucket: S3_BUCKET, region: S3_CREDS.region, accessKeyId: S3_CREDS.accessKeyID, secretAccessKey: S3_CREDS.secretKey, addressing: "path", deleteProbe: "ok" }, envDestConfigured: true })) as { destinations: Array<{ id: string; source?: string }> };
      const s3Id = added.destinations.find((d) => d.source !== "deploy")?.id ?? "";
      await ownerPost(w, "/downpipes", { id: "kv-uploads", name: "uploads", enabled: true, cadenceSeconds: 86_400, source: SOURCE, destinationIds: ["deploy", s3Id] });
      // The singular clear of the DEFAULT row, which is "deploy", is refused while the downpipe names it.
      const pinnedClear = await ownerFetch(w, "/dest-config", { config: null });
      const pinnedRoster = (await doJson(w, "/destinations")) as { destinations: Array<{ id: string }>; defaultId: string };
      ok("the singular clear is refused (400, in use, names the downpipe) while a downpipe names the default, and the row stays", pinnedClear.status === 400 && /^destination is in use by 1 downpipe\(s\): uploads\./.test(pinnedClear.error) && pinnedRoster.defaultId === "deploy" && pinnedRoster.destinations.some((d) => d.id === "deploy"));
      // The state that clear left on an engine with no pin check: the "deploy" row removed and the S3 row
      // promoted, written to the collection as that clear wrote it. No route of this engine reaches it: the
      // clear is refused above, and a downpipe cannot name "deploy" once its row is gone.
      const carried = (await w.storage.get(DESTINATIONS_KEY)) as DestinationCollection;
      await w.storage.put(DESTINATIONS_KEY, { ...carried, list: carried.list.filter((d) => d.id !== "deploy"), defaultId: s3Id });

      const roster = (await doJson(w, "/destinations")) as { destinations: Array<{ id: string }> };
      const named = ((await doJson(w, "/downpipes")) as DownpipeState[]).find((d) => d.config.id === "kv-uploads")?.config.destinationIds ?? [];
      ok("POPULATION: the \"deploy\" row is gone, the S3 row stays, and the downpipe still names both", !roster.destinations.some((d) => d.id === "deploy") && roster.destinations.some((d) => d.id === s3Id) && s3Id !== "" && JSON.stringify(named) === JSON.stringify(["deploy", s3Id]));

      const bound = await resolveDestination(w.env, w.scheduler, "deploy");
      ok("with DEST_R2 bound, \"deploy\" resolves to the env binding without its row", bound.ok === true && bound.branch === "deploy-env-binding");
      const noEnv = await resolveDestination({} as unknown as Env, w.scheduler, "deploy");
      ok("with no env destination, \"deploy\" is refused as deploy-binding-missing, never not-configured", noEnv.ok === false && noEnv.branch === "deploy-binding-missing");
      ok("the roster set the dangling count reads follows the resolver (\"deploy\" is in it while DEST_R2 is bound, and only then)", (await fetchDestinationIdSet(w.scheduler, w.env))?.has("deploy") === true && (await fetchDestinationIdSet(w.scheduler, {} as unknown as Env))?.has("deploy") === false);

      // The next day's run, then one real cron invocation: replication and the scheduled restore test.
      advance(86_400_000);
      await sealOnce(w, "kv-uploads");
      await drive(w.env);
      const hist = ((await doJson(w, "/history?id=kv-uploads")) as { entries: RunHistoryEntry[] }).entries;
      ok("the next run seals to \"deploy\" (history is newest first)", hist.length === 2 && hist[0]?.status === "ok" && hist[0]?.destinationId === "deploy");

      const pack = (await signedSupportBundle(w.env, w.scheduler)).bundle as Dict;
      const cronHealth = (pack.cronHealth ?? {}) as Dict;
      const destResolution = (pack.destResolution ?? {}) as Dict;
      ok("the pack counts no dangling reference anywhere (top level, cronHealth, destResolution)", pack.danglingDestinationRefs === undefined && cronHealth.danglingDestinationRefs === undefined && destResolution.danglingRefs === undefined);
      const dp = ((pack.downpipes ?? []) as Dict[]).find((d) => d.id === "kv-uploads") ?? {};
      const legs = (((dp.replication ?? {}) as Dict).destinations ?? []) as Dict[];
      ok("the replication pass holds the run on both legs", legs.length === 2 && legs.every((l) => l.ok === true));
      const skips = ((cronHealth.restoreTest ?? {}) as Dict).skips as Dict | undefined;
      ok("the restore drill ran and passed, with no pre-drill skip", dp.lastRestoreTestOk === true && (skips === undefined || Object.keys(skips).length === 0));
      const deployRow = ((destResolution.resolution ?? []) as Dict[]).find((r) => r.id === "deploy");
      ok("the pack says \"deploy\" resolves with no stored row", deployRow?.stored === false && deployRow?.ok === true && deployRow?.branch === "deploy-env-binding");
      ok("the S3 bucket checked every signature and refused nothing, and holds objects", w.s3.refusals.length === 0 && w.s3.store.size > 0);
    });
  } finally {
    w.close();
  }
  await deployDefaultSetWorld();
  console.log(failures === 0 ? "\nDEPLOY ROW CLEARED PASS\n" : `\nDEPLOY ROW CLEARED FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
