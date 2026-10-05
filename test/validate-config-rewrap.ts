// Validates the key-install re-wrap: when POST /keys/install (or POST /keys/add-config-recovery) sets
// CONFIG_WRAP_KEY, every credential the scheduler DO already holds as plaintext is sealed under that key, and
// every read path still works afterwards.
//
// WHY THIS EXISTS. The first run stores the read-only discovery token and a destination secret BEFORE the key
// install, because Connect and Destination come before Keys. The engine sealed a credential only at its save,
// so both sat on the Durable Object plaintext floor until the operator saved them again. The install now runs
// admin/config-rewrap.ts over sched/config-secret-sweep.ts.
//
// What is graded:
//   1. FRESH STORE THEN INSTALL. A first-run store (the discovery token and destinations written through the
//      DO's own routes with no key, beside every other class the wrap covers) is fully sealed by the install:
//      each class under its own label, the deploy placeholder and the unwrapped PagerDuty key left alone, every
//      other field of each record unchanged (a push record keeps its gen).
//   2. READS STILL WORK. Every class is read back through the engine's own read path (fetchDestConfig, the
//      discovery resolver, both push drains, the JSM and ServiceNow senders, the IdP resolver) and yields the
//      original value. Negative control: the same reads with no key fail, so the envelopes are real.
//   3. IDEMPOTENT. A second install (a confirmed re-key that keeps the wrap key) seals nothing, reports every
//      credential as already wrapped, and leaves each envelope byte-identical.
//   4. MIXED STORE. Credentials already sealed are counted and left byte-identical; the rest are sealed.
//   5. FAILURE PART WAY. One swap refused: that credential stays the exact plaintext and still reads, the others
//      are sealed, the install still answers 200, and the audit row says failed with the class. A pass that
//      dies after four swaps leaves each credential either its plaintext or an envelope that opens to it, and
//      the next install seals the rest. A rollout reset is ridden out, including one that lost the answer to a
//      swap that had landed. A key that will not load, a census the DO cannot answer, and a credential saved
//      again between the census and the swap each leave storage as it was, and none fails the install.
//   6. POST /keys/add-config-recovery seals when it installs the wrap key, and does nothing when it does not.
//   7. NO SECRET MATERIAL in the response, the audit feed or the engine log; an engine with no credential gets
//      no audit row; the posture check reads pass once the pass is done.
//   8. The DO swap refuses a malformed request and never writes an envelope over a credential of another class.
// No real network and no real deploy: a stubbed fetch records the secret PUTs.
// Run: node test/validate-config-rewrap.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { CONFIG_SECRET_AAD, DISCOVERY_SECRET_AAD, IDP_SECRET_AAD, isWrappedSecret, JSM_SECRET_AAD, loadConfigWrapKey, OTLP_PUSH_SECRET_AAD, PUSH_S3_SECRET_AAD, PUSH_SECRET_AAD, resolveConfigSecret, SERVICENOW_SECRET_AAD, type WrappedSecret, wrapConfigSecret } from "../src/admin/config-secret.ts";
import { rewrapStoredConfigSecrets } from "../src/admin/config-rewrap.ts";
import { CALLER_HEADER, encodeCaller } from "../src/admin/identity.ts";
import { resolveIdpSecret } from "../src/admin/oidc-store.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { resolveDiscoveryTokenDetailed } from "../src/admin/router-helpers.ts";
import { fetchOtlpPushConfig } from "../src/cron/otlp-push-pass.ts";
import { fetchPushConfig } from "../src/cron/siem-push-pass.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { fetchDestConfig } from "../src/dest/factory.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/index.ts";
import { deliver as deliverJsm } from "../src/notify/channels/jsm.ts";
import { deliver as deliverServiceNow } from "../src/notify/channels/servicenow.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify/types.ts";
import { censusConfigSecrets, type ConfigSecretClass, refOf, swapConfigSecret } from "../src/sched/config-secret-sweep.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function recipientPair(): { pub: string; priv: string } {
  const kp = x25519.keygen();
  const seed = randomBytes(64);
  return { pub: b64urlEncode(concat(kp.publicKey, ml_kem1024.keygen(seed).publicKey)), priv: b64urlEncode(concat(kp.secretKey, seed)) };
}

const SIGNER_PRIVATE = b64urlEncode(concat(randomBytes(32), randomBytes(32)));
const BREAK_GLASS = recipientPair();
const CONFIG = recipientPair();
const WRAP_KEY_B64 = b64urlEncode(randomBytes(32));
const WRAP_KEY = loadConfigWrapKey(WRAP_KEY_B64) as Uint8Array;
const TOKEN = "cfat-test-edit-workers-token-rewrap";
const INSTALL_BODY = { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, configRecipientPublic: CONFIG.pub, configRecipientPrivate: CONFIG.priv, configWrapKey: WRAP_KEY_B64 };
// The env of an engine that already holds every key, for the confirmed re-key that KEEPS the wrap key.
const KEYED_ENV = { SIGNER_PRIVATE: "sentinel-existing-signer", BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass", CONFIG_RECIPIENT_PUBLIC: CONFIG.pub, CONFIG_RECIPIENT_PRIVATE: CONFIG.priv, CONFIG_WRAP_KEY: WRAP_KEY_B64 };

// One plaintext value per stored credential. Each is distinctive so a search of any output for it is exact.
const P = {
  dest1: "dest-secret-access-key-PLAINTEXT-one",
  dest2: "dest-secret-access-key-PLAINTEXT-two",
  legacy: "legacy-destconfig-secret-PLAINTEXT",
  disc: "cfdisc_PLAINTEXT_token_value_abcdefghij",
  pushHeader: "Splunk hec-token-PLAINTEXT-header",
  pushS3: "push-s3-secret-PLAINTEXT-key",
  otlp: "Bearer otlp-token-PLAINTEXT-value",
  jsm: "genie-key-PLAINTEXT-token",
  sn: "servicenow-password-PLAINTEXT",
  idp: "idp-client-secret-PLAINTEXT-value",
} as const;
const PD_ROUTING_KEY = "pagerduty-routing-key-never-wrapped";
const ALL_PLAINTEXT: string[] = Object.values(P);
const CREDENTIAL_COUNT = ALL_PLAINTEXT.length; // 10: three destination records, and one each for the other seven classes

const OWNER = { method: "token" as const, email: null, subject: null, role: "owner" as const, groups: [] as string[] };
const EMISSION: NotifyEmission = { event: "backup-failure", severity: "critical", downpipeId: "pipe-1", downpipeName: "Prod KV", detail: "Prod KV last run failed", at: "2026-06-09T00:00:00.000Z" };
const OPAQUE_ROLLOUT = "internal error; reference = n3rmrlv4r241rk2ob8u84pfq";
const NAMED_RESET = "Durable Object reset because its code was updated.";

type Intercept = (path: string, init: RequestInit | undefined, forward: () => Promise<Response>) => Promise<Response | undefined>;
interface Engine {
  env: Env;
  storage: MockStorage;
  dobj: SchedulerDO;
  stub: DurableObjectStub;
  intercept: Intercept | null;
  adminToken: string;
}

let engineSeq = 0;
function makeEngine(extra: Record<string, unknown> = {}): Engine {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const adminToken = `admin-rewrap-${++engineSeq}`;
  const engine = { storage, dobj, intercept: null, adminToken } as unknown as Engine;
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as URL).toString();
      const forward = () => dobj.fetch(new Request(url, init));
      if (engine.intercept !== null) {
        const r = await engine.intercept(new URL(url).pathname, init, forward);
        if (r !== undefined) return r;
      }
      return forward();
    },
  } as unknown as DurableObjectStub;
  engine.stub = stub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  engine.env = { SCHEDULER: namespace, ADMIN_TOKEN: adminToken, CF_ACCOUNT_ID: "acct-rewrap", WORKER_NAME: "downpipe-engine", ...extra } as unknown as Env;
  return engine;
}

async function doPost(e: Engine, path: string, body: unknown): Promise<Response> {
  return e.dobj.fetch(new Request(`https://scheduler.internal${path}`, { method: "POST", headers: { [CALLER_HEADER]: encodeCaller(OWNER), "content-type": "application/json" }, body: JSON.stringify(body) }));
}

interface Seeded {
  destIds: string[]; // the two console destinations, in the order added
}

// seedFirstRun writes the store a first run leaves BEFORE the key install: the discovery token and two
// destinations through the DO's own routes (as the router forwards them when the engine holds no wrap key, so
// they land as plaintext), beside a deploy-time placeholder, the legacy record, and one credential of every
// other class the wrap covers, in the shapes their DO writers store.
async function seedFirstRun(e: Engine): Promise<Seeded> {
  // The DO mirrors each audit append to the console; the seeding rows are not what this validator grades.
  const saved = console.log;
  console.log = () => {};
  try {
    return await seedFirstRunQuiet(e);
  } finally {
    console.log = saved;
  }
}

async function seedFirstRunQuiet(e: Engine): Promise<Seeded> {
  const disc = await doPost(e, "/sources/discovery-token", { token: P.disc, accountsSeen: [{ id: "acct-rewrap", name: "Rewrap" }] });
  if (!disc.ok) throw new Error(`seeding the discovery token failed: ${disc.status} ${await disc.text()}`);
  const now = Date.now();
  const destIds: string[] = [];
  for (const [label, secret, bucket, envDest] of [["Primary", P.dest1, "backups", true], ["Replica", P.dest2, "replica", false]] as const) {
    const resp = await doPost(e, "/destinations", { label, envDestConfigured: envDest, config: { endpoint: "https://acct.r2.cloudflarestorage.com", bucket, region: "auto", accessKeyId: `AKID${label.toUpperCase()}`, secretAccessKey: secret, verifiedAt: now, deleteProbe: "ok" } });
    if (!resp.ok) throw new Error(`seeding destination ${label} failed: ${resp.status} ${await resp.text()}`);
  }
  const coll = (await e.storage.get<{ list: Array<{ id: string; source?: string }> }>("destinations"))!;
  for (const d of coll.list) if (d.source !== "deploy") destIds.push(d.id);
  await e.storage.put("destConfig", { endpoint: "https://legacy.r2.cloudflarestorage.com", bucket: "legacy", region: "auto", accessKeyId: "AKIDLEGACY", secretAccessKey: P.legacy, setAt: now, setBy: null, verifiedAt: now, deleteProbe: "ok" });
  await e.storage.put("siemPushConfig", { endpoint: "https://siem.example.com/services/collector", format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: P.pushHeader, enabled: true, sink: "s3", s3Target: { endpoint: "https://s3.example.com", bucket: "audit-drop", region: "us-east-1", accessKeyId: "AKIDPUSH", secretAccessKey: P.pushS3 }, setAt: now, setBy: null, gen: "gen-siem-1" });
  await e.storage.put("otlpPushConfig", { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: P.otlp, enabled: true, setAt: now, setBy: null, gen: "gen-otlp-1" });
  await e.storage.put("notify-channel:c-jsm", { id: "c-jsm", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: P.jsm, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
  await e.storage.put("notify-channel:c-sn", { id: "c-sn", kind: "servicenow", name: "SNOW", url: "https://instance.service-now.com/api/now/table/em_event", username: "svc_downpipes", apiKey: P.sn, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
  await e.storage.put("notify-channel:c-pd", { id: "c-pd", kind: "pagerduty", name: "Pager", routingKey: PD_ROUTING_KEY, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });
  await e.storage.put("idpsecret:okta", P.idp);
  return { destIds };
}

interface Drive {
  status: number;
  body: Record<string, unknown>;
  text: string;
  puts: string[];
  auditText: string;
  rewrapRows: Array<{ seq: number; outcome: string; target: Record<string, unknown> }>;
  keysInstalledSeq: number | undefined;
  logs: string;
}

// driveRoute POSTs one body to an admin route as the ADMIN_TOKEN owner, with the global fetch stubbed so the
// secret PUTs land in a recorder and the console log captured, then reads the audit feed back.
async function driveRoute(e: Engine, route: string, body: Record<string, unknown>): Promise<Drive> {
  const puts: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PUT" && /\/secrets$/.test(url)) {
      const parsed = JSON.parse(String(init?.body ?? "{}")) as { name?: string };
      puts.push(parsed.name ?? "");
      return new Response(JSON.stringify({ success: true, result: { name: parsed.name } }), { status: 200 });
    }
    if (method === "DELETE" && /\/secrets\/[A-Z_]+$/.test(url)) return new Response(JSON.stringify({ success: true }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  const logLines: string[] = [];
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const capture = (...args: unknown[]) => logLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  console.log = capture;
  console.info = capture;
  console.warn = capture;
  console.error = capture;
  let status = 0;
  let text = "";
  let auditText = "";
  try {
    const resp = await handleAdmin(new Request(`https://engine.example/admin${route}`, { method: "POST", headers: { authorization: `Bearer ${e.adminToken}`, "content-type": "application/json" }, body: JSON.stringify(body) }), e.env);
    status = resp.status;
    text = await resp.text();
    const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=200", { method: "GET", headers: { authorization: `Bearer ${e.adminToken}` } }), e.env);
    auditText = await auditResp.text();
  } finally {
    globalThis.fetch = realFetch;
    Object.assign(console, saved);
  }
  // Ascending by seq, whatever order the feed pages in.
  const events = ((JSON.parse(auditText) as { events?: Array<{ seq: number; action: string; outcome: string; target: Record<string, unknown> }> }).events ?? []).sort((a, b) => a.seq - b.seq);
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    parsed = {};
  }
  return {
    status,
    body: parsed,
    text,
    puts,
    auditText,
    rewrapRows: events.filter((ev) => ev.action === "config-secrets-rewrapped").map((ev) => ({ seq: ev.seq, outcome: ev.outcome, target: ev.target })),
    keysInstalledSeq: events.filter((ev) => ev.action === "keys-installed" && ev.outcome === "success").map((ev) => ev.seq).pop(),
    logs: logLines.join("\n"),
  };
}

function rewrapOf(d: Drive): { ok?: boolean; wrapped?: number; alreadyWrapped?: number; leftPlaintext?: number; failedClasses?: string[]; fault?: string } {
  return (d.body.rewrap ?? {}) as { ok?: boolean; wrapped?: number; alreadyWrapped?: number; leftPlaintext?: number; failedClasses?: string[]; fault?: string };
}

// storedCredentials reads every credential slot straight from storage, keyed by a stable name.
async function storedCredentials(e: Engine, s: Seeded): Promise<Record<string, unknown>> {
  const coll = (await e.storage.get<{ list: Array<{ id: string; secretAccessKey: unknown }> }>("destinations"))!;
  const byId = new Map(coll.list.map((d) => [d.id, d.secretAccessKey]));
  const push = (await e.storage.get<{ authHeaderValue: unknown; s3Target: { secretAccessKey: unknown } }>("siemPushConfig"))!;
  return {
    dest1: byId.get(s.destIds[0]!),
    dest2: byId.get(s.destIds[1]!),
    legacy: (await e.storage.get<{ secretAccessKey: unknown }>("destConfig"))!.secretAccessKey,
    disc: (await e.storage.get<{ token: unknown }>("discoveryConfig"))!.token,
    pushHeader: push.authHeaderValue,
    pushS3: push.s3Target.secretAccessKey,
    otlp: (await e.storage.get<{ authHeaderValue: unknown }>("otlpPushConfig"))!.authHeaderValue,
    jsm: (await e.storage.get<{ apiKey: unknown }>("notify-channel:c-jsm"))!.apiKey,
    sn: (await e.storage.get<{ apiKey: unknown }>("notify-channel:c-sn"))!.apiKey,
    idp: await e.storage.get<unknown>("idpsecret:okta"),
  };
}

const LABEL: Record<keyof typeof P, Uint8Array> = {
  dest1: CONFIG_SECRET_AAD,
  dest2: CONFIG_SECRET_AAD,
  legacy: CONFIG_SECRET_AAD,
  disc: DISCOVERY_SECRET_AAD,
  pushHeader: PUSH_SECRET_AAD,
  pushS3: PUSH_S3_SECRET_AAD,
  otlp: OTLP_PUSH_SECRET_AAD,
  jsm: JSM_SECRET_AAD,
  sn: SERVICENOW_SECRET_AAD,
  idp: IDP_SECRET_AAD,
};

// everyCredentialIntact is the crash-safety property: each slot is EITHER its exact plaintext OR an envelope
// that opens under its own label to that plaintext. Returns the count of each, or null when a slot is neither.
async function everyCredentialIntact(e: Engine, s: Seeded): Promise<{ plaintext: number; wrapped: number } | null> {
  const stored = await storedCredentials(e, s);
  let plaintext = 0;
  let wrapped = 0;
  for (const name of Object.keys(P) as Array<keyof typeof P>) {
    const v = stored[name];
    if (v === P[name]) {
      plaintext++;
      continue;
    }
    if (!isWrappedSecret(v)) return null;
    try {
      if ((await resolveConfigSecret(WRAP_KEY, v, LABEL[name])) !== P[name]) return null;
    } catch {
      return null;
    }
    wrapped++;
  }
  return { plaintext, wrapped };
}

function noSecretIn(text: string): boolean {
  return ALL_PLAINTEXT.every((p) => !text.includes(p)) && !text.includes(WRAP_KEY_B64) && !text.includes(CONFIG.priv) && !text.includes(SIGNER_PRIVATE);
}

// captureSend stubs the network for one notify delivery and returns the Authorization header it sent. The DoH
// resolve screen is answered PUBLIC so the case stays about the credential.
async function captureSend(run: () => Promise<{ ok: boolean }>): Promise<{ ok: boolean; authorization: string | undefined }> {
  const realFetch = globalThis.fetch;
  let authorization: string | undefined;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    if (String(input).startsWith("https://cloudflare-dns.com/dns-query?")) return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }), { status: 200 });
    authorization = (init?.headers as Record<string, string> | undefined)?.Authorization;
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  try {
    const r = await run();
    return { ok: r.ok, authorization };
  } finally {
    globalThis.fetch = realFetch;
  }
}

async function channelOf(e: Engine, id: string): Promise<NotifyChannel> {
  return (await e.storage.get<NotifyChannel>(`notify-channel:${id}`))!;
}

async function main(): Promise<void> {
  console.log("-- 1. a first-run store (credentials saved before any key) is fully sealed by the key install --");
  const e1 = makeEngine();
  const s1 = await seedFirstRun(e1);
  {
    const before = await censusConfigSecrets(e1.storage);
    ok(`anti-vacuity: the seeded store holds ${CREDENTIAL_COUNT} plaintext credentials and no envelope`, before.plaintext.length === CREDENTIAL_COUNT && before.wrapped === 0);
    ok("anti-vacuity: the discovery token and both destinations went through the DO's own writers as plaintext", (await storedCredentials(e1, s1)).disc === P.disc && (await storedCredentials(e1, s1)).dest1 === P.dest1);
    const censusClasses = new Set(before.plaintext.map((p) => p.cls));
    const expected: ConfigSecretClass[] = ["destination", "discovery-token", "siem-push-header", "siem-push-s3", "otlp-push-header", "notify-jsm", "notify-servicenow", "idp-client-secret"];
    ok("the census covers every class the wrap is used for", expected.every((c) => censusClasses.has(c)) && censusClasses.size === expected.length);
    ok("the census skips the deploy placeholder (it holds no credential)", !before.plaintext.some((p) => p.slot === "list:deploy"));
    ok("the census skips the PagerDuty routing key (no save seals it, so no sweep may)", !before.plaintext.some((p) => p.value === PD_ROUTING_KEY));

    const pushBefore = (await e1.storage.get<Record<string, unknown>>("siemPushConfig"))!;
    const d = await driveRoute(e1, "/keys/install", INSTALL_BODY);
    ok("the install returns 200", d.status === 200);
    ok("the install PUT CONFIG_WRAP_KEY (this is the install that sets it)", d.puts.includes("CONFIG_WRAP_KEY"));
    const r = rewrapOf(d);
    ok(`the response reports all ${CREDENTIAL_COUNT} sealed, none already sealed, none left`, r.ok === true && r.wrapped === CREDENTIAL_COUNT && r.alreadyWrapped === 0 && r.leftPlaintext === 0 && (r.failedClasses ?? []).length === 0);
    const after = await censusConfigSecrets(e1.storage);
    ok("storage now holds no plaintext credential and every one as an envelope", after.plaintext.length === 0 && after.wrapped === CREDENTIAL_COUNT);
    const intact = await everyCredentialIntact(e1, s1);
    ok("each envelope opens under ITS OWN class label to the original value", intact !== null && intact.wrapped === CREDENTIAL_COUNT && intact.plaintext === 0);
    const dump = JSON.stringify([...e1.storage.raw().entries()]);
    ok("no seeded plaintext credential remains anywhere in storage (the PagerDuty key excepted)", ALL_PLAINTEXT.every((p) => !dump.includes(p)) && dump.includes(PD_ROUTING_KEY));
    const deploy = (await e1.storage.get<{ list: Array<{ id: string; secretAccessKey: unknown }> }>("destinations"))!.list.find((x) => x.id === "deploy");
    ok("the deploy placeholder still holds its empty credential", deploy !== undefined && deploy.secretAccessKey === "");
    const pushAfter = (await e1.storage.get<Record<string, unknown>>("siemPushConfig"))!;
    const { authHeaderValue: _a, s3Target: s3a, ...restAfter } = pushAfter as { authHeaderValue: unknown; s3Target: Record<string, unknown> };
    const { authHeaderValue: _b, s3Target: s3b, ...restBefore } = pushBefore as { authHeaderValue: unknown; s3Target: Record<string, unknown> };
    const { secretAccessKey: _c, ...s3RestAfter } = s3a;
    const { secretAccessKey: _d, ...s3RestBefore } = s3b;
    ok("every other field of the push record is unchanged, gen included (a delivery in flight still records)", JSON.stringify(restAfter) === JSON.stringify(restBefore) && JSON.stringify(s3RestAfter) === JSON.stringify(s3RestBefore) && pushAfter.gen === "gen-siem-1");
    ok("exactly ONE config-secrets-rewrapped audit row, outcome success", d.rewrapRows.length === 1 && d.rewrapRows[0]!.outcome === "success");
    const t = d.rewrapRows[0]?.target ?? {};
    ok("the row carries the counts on the key-ceremony target", t.kind === "key-ceremony" && t.wrapped === CREDENTIAL_COUNT && t.alreadyWrapped === 0 && t.leftPlaintext === 0 && t.failedClasses === undefined);
    ok("the row follows the keys-installed row", d.keysInstalledSeq !== undefined && (d.rewrapRows[0]?.seq ?? 0) > d.keysInstalledSeq);
    ok("NO SECRET in the response", noSecretIn(d.text));
    ok("NO SECRET in the audit feed", noSecretIn(d.auditText));
    ok("NO SECRET in the engine log, which does record the pass", noSecretIn(d.logs) && d.logs.includes("config-secrets-rewrapped: wrapped 10"));
  }

  console.log("\n-- 2. every read path still returns the original value, and fails without the key --");
  {
    const env = { ...e1.env, CONFIG_WRAP_KEY: WRAP_KEY_B64 } as unknown as Env;
    const d1 = await fetchDestConfig(e1.stub, s1.destIds[0], WRAP_KEY);
    const d2 = await fetchDestConfig(e1.stub, s1.destIds[1], WRAP_KEY);
    ok("fetchDestConfig opens both destination credentials", d1?.secretAccessKey === P.dest1 && d2?.secretAccessKey === P.dest2);
    const legacy = (await e1.storage.get<{ secretAccessKey: string | WrappedSecret }>("destConfig"))!;
    ok("the legacy record's credential opens under the destination label", (await resolveConfigSecret(WRAP_KEY, legacy.secretAccessKey)) === P.legacy);
    const disc = await resolveDiscoveryTokenDetailed(e1.stub, env);
    ok("the discovery resolver opens the discovery token", disc.token === P.disc && disc.doFault === false);
    const push = await fetchPushConfig(e1.stub, WRAP_KEY);
    ok("the SIEM push drain opens the header secret and the S3 key", push?.authHeaderValue === P.pushHeader && push.s3?.secretAccessKey === P.pushS3);
    const otlp = await fetchOtlpPushConfig(e1.stub, WRAP_KEY);
    ok("the OTLP push drain opens its header secret", otlp?.authHeaderValue === P.otlp);
    const jsmSend = await captureSend(async () => deliverJsm(env, await channelOf(e1, "c-jsm"), EMISSION));
    ok("the JSM sender opens the GenieKey and sends it", jsmSend.ok && jsmSend.authorization === `GenieKey ${P.jsm}`);
    const snSend = await captureSend(async () => deliverServiceNow(env, await channelOf(e1, "c-sn"), EMISSION));
    ok("the ServiceNow sender opens the password and sends it", snSend.ok && snSend.authorization === `Basic ${btoa(`svc_downpipes:${P.sn}`)}`);
    ok("the IdP resolver opens the client secret", (await resolveIdpSecret(e1.storage, "okta", WRAP_KEY)) === P.idp);

    // NEGATIVE CONTROL: the same reads with no key. A read path that ignored the envelope would pass above for
    // the wrong reason; these show each value really is sealed and each read really opens it.
    const noKey = { ...e1.env } as unknown as Env;
    let destThrew = false;
    try {
      await fetchDestConfig(e1.stub, s1.destIds[0], undefined);
    } catch {
      destThrew = true;
    }
    ok("CONTROL: fetchDestConfig with no key refuses the sealed credential", destThrew);
    const discNoKey = await resolveDiscoveryTokenDetailed(e1.stub, noKey);
    ok("CONTROL: the discovery resolver with no key reports a fault, not the token", discNoKey.token !== P.disc && discNoKey.doFault === true);
    const jsmNoKey = await captureSend(async () => deliverJsm(noKey, await channelOf(e1, "c-jsm"), EMISSION));
    ok("CONTROL: the JSM sender with no key sends nothing", !jsmNoKey.ok && jsmNoKey.authorization === undefined);
    let crossOpened = true;
    try {
      await resolveConfigSecret(WRAP_KEY, (await e1.storage.get<{ token: WrappedSecret }>("discoveryConfig"))!.token, CONFIG_SECRET_AAD);
    } catch {
      crossOpened = false;
    }
    ok("CONTROL: the discovery envelope does not open under the destination label (each class keeps its own)", !crossOpened);
  }

  console.log("\n-- 3. a second install is idempotent --");
  {
    const before = JSON.stringify(await storedCredentials(e1, s1));
    Object.assign(e1.env, KEYED_ENV);
    const d = await driveRoute(e1, "/keys/install", { ...INSTALL_BODY, confirmRekey: true });
    ok("the confirmed re-key returns 200 and keeps the wrap key (no CONFIG_WRAP_KEY PUT)", d.status === 200 && !d.puts.includes("CONFIG_WRAP_KEY"));
    const r = rewrapOf(d);
    ok(`the second pass seals nothing and counts all ${CREDENTIAL_COUNT} as already sealed`, r.ok === true && r.wrapped === 0 && r.alreadyWrapped === CREDENTIAL_COUNT && r.leftPlaintext === 0);
    ok("every envelope is byte-identical after the second pass", JSON.stringify(await storedCredentials(e1, s1)) === before);
    ok("the second pass leaves one success row with zero sealed", d.rewrapRows.length === 2 && d.rewrapRows[1]!.outcome === "success" && d.rewrapRows[1]!.target.wrapped === 0 && d.rewrapRows[1]!.target.alreadyWrapped === CREDENTIAL_COUNT);
  }

  console.log("\n-- 4. a mixed store: sealed credentials are counted and left alone, the rest are sealed --");
  {
    const e = makeEngine(KEYED_ENV);
    const s = await seedFirstRun(e);
    const preDisc = await wrapConfigSecret(WRAP_KEY, P.disc, DISCOVERY_SECRET_AAD);
    const preIdp = await wrapConfigSecret(WRAP_KEY, P.idp, IDP_SECRET_AAD);
    const preJsm = await wrapConfigSecret(WRAP_KEY, P.jsm, JSM_SECRET_AAD);
    await e.storage.put("discoveryConfig", { ...(await e.storage.get<Record<string, unknown>>("discoveryConfig"))!, token: preDisc });
    await e.storage.put("idpsecret:okta", preIdp);
    await e.storage.put("notify-channel:c-jsm", { ...(await channelOf(e, "c-jsm")), apiKey: preJsm });
    const d = await driveRoute(e, "/keys/install", { ...INSTALL_BODY, confirmRekey: true });
    const r = rewrapOf(d);
    ok("a kept-key install on a mixed store seals the 7 plaintext and counts the 3 envelopes", d.status === 200 && r.ok === true && r.wrapped === 7 && r.alreadyWrapped === 3 && r.leftPlaintext === 0);
    const stored = await storedCredentials(e, s);
    ok("the three envelopes that were already there are byte-identical", JSON.stringify(stored.disc) === JSON.stringify(preDisc) && JSON.stringify(stored.idp) === JSON.stringify(preIdp) && JSON.stringify(stored.jsm) === JSON.stringify(preJsm));
    const intact = await everyCredentialIntact(e, s);
    ok("every credential is now an envelope that opens to its value", intact !== null && intact.wrapped === CREDENTIAL_COUNT);
  }

  console.log("\n-- 5a. one swap refused: that credential stays plaintext and working, the others are sealed --");
  {
    const e = makeEngine();
    const s = await seedFirstRun(e);
    let refusedSwaps = 0;
    e.intercept = async (path, init) => {
      if (path === "/config-secrets/swap" && (JSON.parse(String(init?.body)) as { cls?: string }).cls === "discovery-token") {
        refusedSwaps++;
        throw new Error("the scheduler refused this write");
      }
      return undefined;
    };
    const d = await driveRoute(e, "/keys/install", INSTALL_BODY);
    e.intercept = null;
    const r = rewrapOf(d);
    ok("anti-vacuity: the refusal was injected exactly once (a real fault is not retried)", refusedSwaps === 1);
    ok("the install still returns 200 (the keys are in)", d.status === 200 && d.puts.includes("CONFIG_WRAP_KEY"));
    ok("the report names one credential left, of the discovery class", r.ok === false && r.wrapped === CREDENTIAL_COUNT - 1 && r.leftPlaintext === 1 && JSON.stringify(r.failedClasses) === JSON.stringify(["discovery-token"]));
    ok("the discovery token is still its exact plaintext", (await storedCredentials(e, s)).disc === P.disc);
    const intact = await everyCredentialIntact(e, s);
    ok("every credential is its plaintext or an envelope that opens to it (1 and 9)", intact !== null && intact.plaintext === 1 && intact.wrapped === CREDENTIAL_COUNT - 1);
    const disc = await resolveDiscoveryTokenDetailed(e.stub, { ...e.env, CONFIG_WRAP_KEY: WRAP_KEY_B64 } as unknown as Env);
    ok("the plaintext discovery token still reads with the key configured", disc.token === P.disc);
    ok("the audit row says failed, with the class and no value", d.rewrapRows.length === 1 && d.rewrapRows[0]!.outcome === "failed" && JSON.stringify(d.rewrapRows[0]!.target.failedClasses) === JSON.stringify(["discovery-token"]) && noSecretIn(d.auditText));
  }

  console.log("\n-- 5b. a pass that dies after four swaps leaves nothing broken, and the next install finishes --");
  {
    const e = makeEngine();
    const s = await seedFirstRun(e);
    let swaps = 0;
    const dying = {
      fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : (input as URL).toString();
        if (new URL(url).pathname === "/config-secrets/swap" && ++swaps > 4) throw new Error("the isolate was torn down");
        return e.stub.fetch(url, init);
      },
    } as unknown as DurableObjectStub;
    const r = await rewrapStoredConfigSecrets(() => dying, WRAP_KEY_B64);
    ok("anti-vacuity: the pass reached the fifth swap and died there", swaps > 4 && r.wrapped === 4);
    const intact = await everyCredentialIntact(e, s);
    ok("CRASH SAFETY: every credential is its exact plaintext or an envelope that opens to it (4 sealed, 6 plaintext)", intact !== null && intact.wrapped === 4 && intact.plaintext === CREDENTIAL_COUNT - 4);
    Object.assign(e.env, KEYED_ENV);
    const d = await driveRoute(e, "/keys/install", { ...INSTALL_BODY, confirmRekey: true });
    const r2 = rewrapOf(d);
    ok("the next install seals the remaining 6 and counts the 4", r2.ok === true && r2.wrapped === CREDENTIAL_COUNT - 4 && r2.alreadyWrapped === 4);
    const done = await everyCredentialIntact(e, s);
    ok("after it, every credential is an envelope that opens to its value", done !== null && done.wrapped === CREDENTIAL_COUNT);
  }

  console.log("\n-- 5c. the rollout reset is ridden out, including a swap that landed and lost its answer --");
  {
    const e = makeEngine();
    const s = await seedFirstRun(e);
    let censusResets = 1;
    let swapResets = 1;
    let lostAnswers = 1;
    e.intercept = async (path, init, forward) => {
      if (path === "/config-secrets/census" && censusResets > 0) {
        censusResets--;
        throw new Error(OPAQUE_ROLLOUT);
      }
      if (path === "/config-secrets/swap") {
        const cls = (JSON.parse(String(init?.body)) as { cls?: string }).cls;
        if (cls === "siem-push-s3" && swapResets > 0) {
          swapResets--;
          throw new Error(NAMED_RESET);
        }
        if (cls === "otlp-push-header" && lostAnswers > 0) {
          lostAnswers--;
          await forward(); // the swap LANDS in the DO...
          throw new Error(NAMED_RESET); // ...and the reset loses the answer
        }
      }
      return undefined;
    };
    const d = await driveRoute(e, "/keys/install", INSTALL_BODY);
    e.intercept = null;
    const r = rewrapOf(d);
    ok("anti-vacuity: all three resets were injected and consumed", censusResets === 0 && swapResets === 0 && lostAnswers === 0);
    ok(`every credential is sealed through the resets (${CREDENTIAL_COUNT} wrapped, none left)`, r.ok === true && r.wrapped === CREDENTIAL_COUNT && r.leftPlaintext === 0);
    ok("the swap whose answer was lost is counted as this pass's work, not as already sealed", r.alreadyWrapped === 0);
    const intact = await everyCredentialIntact(e, s);
    ok("every credential opens to its value", intact !== null && intact.wrapped === CREDENTIAL_COUNT);
  }

  console.log("\n-- 5d. a key that will not load: nothing changes, the install is not failed --");
  {
    const e = makeEngine({ ...KEYED_ENV, CONFIG_WRAP_KEY: "sentinel-not-a-wrap-key" });
    const s = await seedFirstRun(e);
    const before = JSON.stringify(await storedCredentials(e, s));
    const d = await driveRoute(e, "/keys/install", { ...INSTALL_BODY, confirmRekey: true });
    const r = rewrapOf(d);
    ok("the install returns 200", d.status === 200);
    ok("the report says key-unusable, all 10 left, none sealed", r.ok === false && r.fault === "key-unusable" && r.wrapped === 0 && r.leftPlaintext === CREDENTIAL_COUNT);
    ok("storage is unchanged", JSON.stringify(await storedCredentials(e, s)) === before);
    ok("the audit row says failed with the fault", d.rewrapRows.length === 1 && d.rewrapRows[0]!.outcome === "failed" && d.rewrapRows[0]!.target.rewrapFault === "key-unusable");
  }

  console.log("\n-- 5e. a census the DO cannot answer: nothing changes, the install is not failed --");
  {
    const e = makeEngine();
    const s = await seedFirstRun(e);
    const before = JSON.stringify(await storedCredentials(e, s));
    e.intercept = async (path) => (path === "/config-secrets/census" ? new Response("{}", { status: 500 }) : undefined);
    const d = await driveRoute(e, "/keys/install", INSTALL_BODY);
    e.intercept = null;
    const r = rewrapOf(d);
    ok("the install returns 200 with the fault census-failed", d.status === 200 && r.ok === false && r.fault === "census-failed");
    ok("storage is unchanged", JSON.stringify(await storedCredentials(e, s)) === before);
    ok("the audit row says failed with the fault", d.rewrapRows.length === 1 && d.rewrapRows[0]!.outcome === "failed" && d.rewrapRows[0]!.target.rewrapFault === "census-failed");
  }

  console.log("\n-- 5e2. a census row the Worker cannot name is counted as left, never sealed and never hidden --");
  {
    const e = makeEngine();
    const s = await seedFirstRun(e);
    let doctored = 0;
    e.intercept = async (path, _init, forward) => {
      if (path !== "/config-secrets/census") return undefined;
      doctored++;
      const census = (await (await forward()).json()) as { plaintext: Array<Record<string, unknown>>; wrapped: number };
      census.plaintext.push({ cls: "webhook-url", slot: "", ref: "0".repeat(96), value: "https://hooks.example/secret-path" });
      return new Response(JSON.stringify(census), { status: 200, headers: { "content-type": "application/json" } });
    };
    const d = await driveRoute(e, "/keys/install", INSTALL_BODY);
    e.intercept = null;
    const r = rewrapOf(d);
    ok("anti-vacuity: the census answer was doctored", doctored === 1);
    ok("the 10 real credentials are sealed and the unnamed row is counted as left, so the report is not ok", r.wrapped === CREDENTIAL_COUNT && r.leftPlaintext === 1 && r.ok === false);
    ok("every real credential opens to its value", (await everyCredentialIntact(e, s))?.wrapped === CREDENTIAL_COUNT);
  }

  console.log("\n-- 5f. a credential saved again between the census and its swap is left as the save wrote it --");
  {
    const e = makeEngine();
    const s = await seedFirstRun(e);
    const NEWER = "dest-secret-access-key-SAVED-AFTER-CENSUS";
    let resaved = 0;
    e.intercept = async (path, init) => {
      const body = path === "/config-secrets/swap" ? (JSON.parse(String(init?.body)) as { slot?: string }) : {};
      if (body.slot === `list:${s.destIds[0]}` && resaved === 0) {
        resaved++;
        const coll = (await e.storage.get<{ list: Array<{ id: string; secretAccessKey: unknown }> }>("destinations"))!;
        await e.storage.put("destinations", { ...coll, list: coll.list.map((x) => (x.id === s.destIds[0] ? { ...x, secretAccessKey: NEWER } : x)) });
      }
      return undefined;
    };
    const d = await driveRoute(e, "/keys/install", INSTALL_BODY);
    e.intercept = null;
    const r = rewrapOf(d);
    ok("anti-vacuity: the concurrent save was injected", resaved === 1);
    ok("the report leaves that one destination, sealing the other 9", r.wrapped === CREDENTIAL_COUNT - 1 && r.leftPlaintext === 1 && JSON.stringify(r.failedClasses) === JSON.stringify(["destination"]));
    ok("the newer save is stored verbatim, not overwritten by the envelope of the older value", (await storedCredentials(e, s)).dest1 === NEWER);
  }

  console.log("\n-- 6. POST /keys/add-config-recovery seals when it installs the wrap key, and only then --");
  {
    const keyed = { SIGNER_PRIVATE: "sentinel-existing-signer", BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass" };
    const e = makeEngine(keyed);
    const s = await seedFirstRun(e);
    const recipientOnly = await driveRoute(e, "/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: CONFIG.pub, configRecipientPrivate: CONFIG.priv });
    ok("an add of the recovery pair alone returns 200 with no rewrap and no row", recipientOnly.status === 200 && recipientOnly.body.rewrap === undefined && recipientOnly.rewrapRows.length === 0);
    ok("and leaves every credential plaintext", (await everyCredentialIntact(e, s))?.plaintext === CREDENTIAL_COUNT);
    Object.assign(e.env, { CONFIG_RECIPIENT_PUBLIC: CONFIG.pub, CONFIG_RECIPIENT_PRIVATE: CONFIG.priv });
    const wrapAdd = await driveRoute(e, "/keys/add-config-recovery", { token: TOKEN, configWrapKey: WRAP_KEY_B64 });
    const r = rewrapOf(wrapAdd);
    ok("an add of the wrap key returns 200, PUTs only CONFIG_WRAP_KEY, and seals all 10", wrapAdd.status === 200 && wrapAdd.puts.join(",") === "CONFIG_WRAP_KEY" && r.ok === true && r.wrapped === CREDENTIAL_COUNT);
    ok("every credential opens to its value", (await everyCredentialIntact(e, s))?.wrapped === CREDENTIAL_COUNT);
    ok("one success row, and no secret in the response or the feed", wrapAdd.rewrapRows.length === 1 && wrapAdd.rewrapRows[0]!.outcome === "success" && noSecretIn(wrapAdd.text) && noSecretIn(wrapAdd.auditText));
  }

  console.log("\n-- 7. an engine with no credential gets no row; the posture check passes once the pass is done --");
  {
    const empty = makeEngine();
    const d = await driveRoute(empty, "/keys/install", INSTALL_BODY);
    const r = rewrapOf(d);
    ok("a first install on an empty engine reports nothing to do", d.status === 200 && r.ok === true && r.wrapped === 0 && r.alreadyWrapped === 0 && r.leftPlaintext === 0);
    ok("and writes no config-secrets-rewrapped row (only what was seen is recorded)", d.rewrapRows.length === 0);

    const e = makeEngine();
    await seedFirstRun(e);
    const pre = await e.dobj.computePostureReport({ configWrapKeyConfigured: true });
    const preCheck = pre.report.checks.find((c) => c.id === "dest-cred-encryption");
    ok("CONTROL: before the pass the destination-credential check fails", preCheck !== undefined && preCheck.autoStatus === "fail");
    await driveRoute(e, "/keys/install", INSTALL_BODY);
    const post = await e.dobj.computePostureReport({ configWrapKeyConfigured: true });
    const postCheck = post.report.checks.find((c) => c.id === "dest-cred-encryption");
    ok("after it the check passes, with the deploy placeholder present and not counted", postCheck !== undefined && postCheck.autoStatus === "pass");
  }

  console.log("\n-- 8. the DO swap refuses a malformed request and never crosses classes --");
  {
    const st = new MockStorage();
    await st.put("discoveryConfig", { token: P.disc, setAt: 0, setBy: null, accountsSeen: [], selected: [], engineAccountId: null });
    await st.put("notify-channel:c1", { id: "c1", kind: "servicenow", apiKey: P.jsm });
    const env = await wrapConfigSecret(WRAP_KEY, P.disc, DISCOVERY_SECRET_AAD);
    const ref = await refOf(P.disc);
    ok("an unknown class is refused", (await swapConfigSecret(st, { cls: "webhook", slot: "", ref, wrapped: env })) === "refused");
    ok("a ref that is not a SHA-384 hex digest is refused", (await swapConfigSecret(st, { cls: "discovery-token", slot: "", ref: "abc", wrapped: env })) === "refused");
    ok("an envelope with an extra field is refused", (await swapConfigSecret(st, { cls: "discovery-token", slot: "", ref, wrapped: { ...env, extra: P.disc } })) === "refused");
    ok("a plaintext string in place of an envelope is refused", (await swapConfigSecret(st, { cls: "discovery-token", slot: "", ref, wrapped: P.disc })) === "refused");
    ok("an over-long slot is refused", (await swapConfigSecret(st, { cls: "idp-client-secret", slot: "x".repeat(201), ref, wrapped: env })) === "refused");
    ok("a notify class with no channel id is refused", (await swapConfigSecret(st, { cls: "notify-jsm", slot: "", ref, wrapped: env })) === "refused");
    ok("nothing was written by any refusal", (await st.get<{ token: unknown }>("discoveryConfig"))!.token === P.disc);
    const jsmRef = await refOf(P.jsm);
    const jsmEnv = await wrapConfigSecret(WRAP_KEY, P.jsm, JSM_SECRET_AAD);
    ok("a JSM swap aimed at a channel that is now ServiceNow is left alone (changed)", (await swapConfigSecret(st, { cls: "notify-jsm", slot: "c1", ref: jsmRef, wrapped: jsmEnv })) === "changed" && (await st.get<{ apiKey: unknown }>("notify-channel:c1"))!.apiKey === P.jsm);
    ok("a swap for a record that is gone reads absent", (await swapConfigSecret(st, { cls: "otlp-push-header", slot: "", ref, wrapped: env })) === "absent");
    ok("a well-formed swap stores the envelope", (await swapConfigSecret(st, { cls: "discovery-token", slot: "", ref, wrapped: env })) === "swapped" && isWrappedSecret((await st.get<{ token: unknown }>("discoveryConfig"))!.token));
    ok("the same swap again reads swapped (its own envelope), a different envelope reads already-wrapped", (await swapConfigSecret(st, { cls: "discovery-token", slot: "", ref, wrapped: env })) === "swapped" && (await swapConfigSecret(st, { cls: "discovery-token", slot: "", ref, wrapped: await wrapConfigSecret(WRAP_KEY, P.disc, DISCOVERY_SECRET_AAD) })) === "already-wrapped");
  }

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nCONFIG-REWRAP PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
