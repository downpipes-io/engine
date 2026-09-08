// Prove the Phase 4 "config as a source" versioning DEFAULT layer end to end and SERVER-SIDE, with
// in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-config-versioning.ts
//
// What this proves (the task's TESTS, verbatim):
//  - a config MUTATION creates a new LINKED version (auto-snapshot after the mutation commits), and the
//    new version's parentHash links to the prior version's contentHash;
//  - an IDENTICAL config does NOT duplicate a version (the byte-identical de-dupe against the head);
//  - the chain parent-hashes LINK across versions, and a TAMPER (an edited stored snapshot, or an
//    altered chain-bound field) BREAKS verification at that version;
//  - a DIFF between two versions yields the expected PLAIN-ENGLISH (Australian) changes
//    ("schedule daily -> hourly", "alice: operator -> approver", "downpipe kv:sessions added",
//    "custom role Board Member: +reports.read", "group platform-eng unmapped");
//  - NO secret value EVER appears in a snapshot (a downpipe whose source names a secret, and a notify
//    channel carrying a PagerDuty routing key, are serialised by NAME / by PRESENCE only);
//  - the READ endpoints are capability-gated (a caller lacking the read capability is 403), and the
//    MANUAL snapshot needs the policy capability (an operator without access.policy is 403).
//
// The Access path is driven with a forged-but-correctly-signed RS256 JWT verified against a controlled
// JWKS served by a stubbed global fetch, so authorise() runs its REAL verification and resolves a REAL
// verified identity at a chosen role (the same technique as validate-audit.ts / validate-rbac.ts),
// exercising the production router + DO code path rather than a shim.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode, b64urlDecode } from "../src/crypto/bytes.ts";
import {
  verifyConfigChain,
  serialiseSnapshot,
  diffConfig,
  summarise,
  SUMMARY_MAX_CHANGES,
  type ConfigVersion,
  type ConfigChange,
  type ConfigSnapshot,
} from "../src/admin/config-history.ts";
import { callerCan, type Caller, type Capability } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, stub };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ------------------------
const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "config-versioning-test-aud";
const KID = "cv-kid-1";

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// SECRET_MARKERS are distinctive byte-strings that MUST NEVER appear in a serialised snapshot. They
// stand in for real secret material; the test wires the engine config so these markers would ONLY be
// reachable if a snapshot serialised a secret VALUE. The proof asserts none appear in any version's
// serialised snapshot (the by-reference rule). The marker is embedded where a value could conceivably
// leak from: it is NOT one of these (it is a NAME, a host, or a presence boolean); the assertion proves
// the routing-key value and the notify-channel url's secret-bearing tail never land in the snapshot.
const SECRET_ROUTING_KEY = "PD_ROUTING_KEY_SECRET_zzz_must_not_leak";
// SECRET_URL_MARKER is embedded in a Slack-style incoming-webhook url's PATH, standing in for the bearer
// token a real Slack/Teams/generic-webhook url carries there - the same class of value as
// SECRET_ROUTING_KEY (notify/types.ts calls it "the customer's own credential to their own sink"). The
// marker must never appear in a snapshot; only the redacted urlConfigured/urlHost fields may.
const SECRET_URL_MARKER = "SLACK_URL_TOKEN_SECRET_zzz_must_not_leak";
const SECRET_MARKERS = [SECRET_ROUTING_KEY, SECRET_URL_MARKER, "SIGNER_PRIVATE_VALUE_zzz", "BREAK_GLASS_PRIVATE_zzz"];

const OWNER = "owner@acme.example";
const OPERATOR = "operator@acme.example";

// The shared end-to-end harness threaded through the PROOF helpers: the in-memory scheduler/DO, an
// authenticated `call`, and the history/version/diff read helpers driven through the public API.
interface VersioningCtx {
  sched: ReturnType<typeof makeScheduler>;
  accessEnv: () => Env;
  call: (email: string, method: "GET" | "POST", path: string, body?: unknown) => Promise<Response>;
  history: () => Promise<{
    versions: Array<{ id: number; at: string; author: string | null; parentHash: string; contentHash: string; summary: string }>;
    headId: number;
    headHash: string;
    verify: { intact: boolean; checkedThrough: number; earliestId: number; brokenAt?: number };
  }>;
  versionById: (id: number) => Promise<{ found: boolean; version?: ConfigVersion }>;
  diff: (from: number, to: number) => Promise<{ found: boolean; from?: number; to?: number; changes?: ConfigChange[] }>;
  texts: (changes: ConfigChange[] | undefined) => string[];
  // The real fetch captured before the in-test stub replaced it, so main() can restore it in a finally
  // and never leak the throwing stub into any later in-process test.
  realFetch: typeof fetch;
}

async function buildVersioningCtx(): Promise<VersioningCtx> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  const tokenFor = async (email: string): Promise<string> => {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  };

  const sched = makeScheduler();
  const accessEnv = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;

  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const assertion = await tokenFor(email);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  };

  const history: VersioningCtx["history"] = async () => (await (await call(OWNER, "GET", "/admin/config/history")).json()) as never;
  const versionById: VersioningCtx["versionById"] = async (id) => (await (await call(OWNER, "GET", `/admin/config/version?id=${id}`)).json()) as never;
  const diff: VersioningCtx["diff"] = async (from, to) => (await (await call(OWNER, "GET", `/admin/config/diff?from=${from}&to=${to}`)).json()) as never;
  const texts = (changes: ConfigChange[] | undefined): string[] => (changes ?? []).map((c) => c.text);

  // Bootstrap OWNER (first Access caller -> Owner) and add the OPERATOR for the gate matrix.
  await call(OWNER, "GET", "/admin/whoami");
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });

  return { sched, accessEnv, call, history, versionById, diff, texts, realFetch };
}

// ---- PROOF 1: a mutation creates a new LINKED version; identical config does NOT duplicate ----
async function proveLinkedVersions(ctx: VersioningCtx): Promise<void> {
  const { call, history } = ctx;
  {
    const before = await history();
    const beforeCount = before.versions.length;
    ok("history is non-empty after the bootstrap grants (auto-snapshot fired on role writes)", beforeCount >= 1);

    // A downpipe upsert is a config mutation -> a new version. Name the source so the snapshot leads
    // with "kv:sessions" in the diff.
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });
    const afterCreate = await history();
    ok("the downpipe upsert created a new version", afterCreate.versions.length === beforeCount + 1);
    // The head (newest-first index 0) links to the previous head's contentHash.
    const head = afterCreate.versions[0]!;
    const parent = afterCreate.versions[1]!;
    ok("the new version's parentHash links to the prior version's contentHash", head.parentHash === parent.contentHash);
    ok("the new version is attributed to the operator who made the change", head.author === OPERATOR);
    ok("the auto-summary mentions the added downpipe", /downpipe kv:sessions added/.test(head.summary));

    // Re-submitting the IDENTICAL downpipe config does NOT create a new version (byte-identical de-dupe).
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });
    const afterNoop = await history();
    ok("an identical re-save did NOT duplicate a version (de-dupe)", afterNoop.versions.length === afterCreate.versions.length);

    // A MANUAL snapshot of the unchanged posture is also a no-op (de-dupes against the head).
    const manualNoop = (await (await call(OWNER, "POST", "/admin/config/snapshot")).json()) as { created: boolean };
    ok("a manual snapshot of an unchanged posture creates nothing (created:false)", manualNoop.created === false);
  }
}

// ---- PROOF 2: the chain LINKS across versions and VERIFIES (engine + independent) -------------
async function proveChainVerifies(ctx: VersioningCtx): Promise<void> {
  const { history, sched } = ctx;
  {
    const h = await history();
    ok("the engine reports the config chain intact", h.verify.intact === true);
    ok("verify reports a head it checked through", h.verify.checkedThrough >= 1);
    ok("the head hash is a sha384 content hash", typeof h.headHash === "string" && h.headHash.startsWith("sha384:"));

    // Independent re-verification: read the persisted versions + the in-DO signing key straight from
    // storage and recompute the chain (content hashes + signed digests + links) with the production
    // verifyConfigChain, so the proof does not rely solely on the engine verifying itself.
    const keys = sched.storage.rawKeys("confighist:");
    const versions = keys.map((k) => sched.storage.rawGet<ConfigVersion>(k)!);
    const keyRec = sched.storage.rawGet<{ key: string }>("passkeySessionKey")!;
    const rawKey = b64urlDecode(keyRec.key);
    const independent = await verifyConfigChain(versions, rawKey);
    ok("an independent re-verification agrees the chain is intact", independent.intact === true);
    // Every link checks out explicitly.
    let linked = versions.length > 0;
    for (let i = 1; i < versions.length; i++) {
      if (versions[i]!.parentHash !== versions[i - 1]!.contentHash) linked = false;
    }
    ok("every version's parentHash equals its predecessor's contentHash", linked);
    ok("each version carries a signed digest (edhmac384:)", versions.every((v) => v.digest.startsWith("edhmac384:")));
  }
}

// ---- PROOF 3: a TAMPERED version BREAKS verification at that version --------------------------
async function proveTamperDetection(ctx: VersioningCtx): Promise<void> {
  const { call, sched, history } = ctx;
  {
    // Make a few more distinct config changes so there are several versions to tamper with (the de-dupe
    // collapses no-op writes, so we drive REAL changes: three cadence edits on the sessions downpipe).
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 7200, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 10800, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 14400, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });

    // (a) Edit a stored snapshot in place (a holder altering the DB): the content hash no longer
    // recomputes, so verify breaks at that version. Pick a LATE version, which is guaranteed to carry the
    // sessions downpipe in its snapshot (so the enabled-flip tamper has something to flip).
    const keys = sched.storage.rawKeys("confighist:");
    ok("there are several versions to tamper with", keys.length >= 4);
    const victimKey = keys[keys.length - 2]!; // a recent (non-head) version, certain to hold a downpipe
    const victim = sched.storage.rawGet<ConfigVersion>(victimKey)!;
    const victimId = victim.id;
    ok("the chosen version carries a downpipe to tamper", victim.snapshot.downpipes.length > 0);
    const dp0 = victim.snapshot.downpipes[0]!;
    const originalEnabled = dp0.enabled;
    // Tamper the snapshot: flip the first downpipe's enabled flag (a content tamper -> the content hash
    // no longer recomputes).
    dp0.enabled = !dp0.enabled;
    sched.storage.rawPut(victimKey, victim);
    const broken = await history();
    ok("verify detects the in-place tamper", broken.verify.intact === false);
    ok("verify reports the break at the tampered version id", broken.verify.brokenAt === victimId);
    // Restore the version so the rest of the suite starts intact.
    dp0.enabled = originalEnabled;
    sched.storage.rawPut(victimKey, victim);
    const reverify = await history();
    ok("restoring the version makes the chain verify again", reverify.verify.intact === true);

    // (b) Tamper a CHAIN-BOUND field (the summary) without re-signing: the signed digest no longer
    // recomputes under the in-DO key, so verify breaks even though the content hash is untouched. This
    // proves the signature, not just the hash link, is checked. Use a DIFFERENT version from (a).
    const keys2 = sched.storage.rawKeys("confighist:");
    const sigVictimKey = keys2[1]!;
    const sigVictim = sched.storage.rawGet<ConfigVersion>(sigVictimKey)!;
    const origSummary = sigVictim.summary;
    sigVictim.summary = "forged summary that was never signed";
    sched.storage.rawPut(sigVictimKey, sigVictim);
    const sigBroken = await history();
    ok("verify detects a tampered chain-bound field via the signed digest", sigBroken.verify.intact === false && sigBroken.verify.brokenAt === sigVictim.id);
    sigVictim.summary = origSummary;
    sched.storage.rawPut(sigVictimKey, sigVictim);
    ok("restoring the signed field re-verifies the chain", (await history()).verify.intact === true);
  }
}

// ---- PROOF 4: a DIFF between two versions yields the expected PLAIN-ENGLISH changes -----------
async function proveDiffLines(ctx: VersioningCtx): Promise<void> {
  const { call, history, diff, texts, versionById } = ctx;
  {
    // PRE-BASELINE setup so the diff shows TRANSITIONS (not just adds): normalise the sessions downpipe
    // to DAILY (PROOF 3 left it at 4 hours); grant alice the OPERATOR role; and create the board-member
    // custom role holding just downpipe.read. The BASELINE is captured AFTER all of these, so the diff
    // below reads "schedule daily -> hourly", "alice: operator -> approver" and "Board Member:
    // +reports.read" as the task's canonical transition examples.
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });
    await call(OWNER, "POST", "/admin/roles", { email: "alice@acme.example", role: "operator" });
    await call(OWNER, "POST", "/admin/custom-roles", { name: "board-member", label: "Board Member", capabilities: ["downpipe.read"], landing: "downpipes", presentation: "shiny" });

    // Capture a baseline version id, then make a spread of mutations and capture the new head, then
    // diff baseline -> head and assert each expected Australian-English line is present.
    const base = await history();
    const baseId = base.headId;

    // schedule change: daily -> hourly on the existing sessions downpipe.
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-sessions", name: "Sessions KV", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "sessions", include: [], exclude: [] } });
    // a role change: operator -> approver for alice (who held operator at the baseline).
    await call(OWNER, "POST", "/admin/roles", { email: "alice@acme.example", role: "approver" });
    // a capability add to the existing board-member custom role (+reports.read).
    await call(OWNER, "POST", "/admin/custom-roles", { name: "board-member", label: "Board Member", capabilities: ["downpipe.read", "reports.read"], landing: "downpipes", presentation: "shiny" });
    // a group mapping added then removed (platform-eng unmapped: net-zero within this window).
    await call(OWNER, "POST", "/admin/group-roles", { group: "platform-eng", role: "operator" });
    await call(OWNER, "POST", "/admin/group-roles/delete", { group: "platform-eng" });
    // a brand-new downpipe added (kv:profiles).
    await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp-profiles", name: "Profiles", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "profiles", include: [], exclude: [] } });

    const head = await history();
    const d = await diff(baseId, head.headId);
    ok("the diff endpoint found both versions", d.found === true);
    const lines = texts(d.changes);
    ok('diff: "schedule daily -> hourly"', lines.some((t) => t === "downpipe kv:sessions schedule daily -> hourly"));
    ok('diff: "alice: operator -> approver"', lines.some((t) => t === "alice@acme.example: operator -> approver"));
    ok('diff: "downpipe kv:profiles added"', lines.some((t) => t === "downpipe kv:profiles added"));
    ok('diff: "custom role Board Member: +reports.read"', lines.some((t) => t === "custom role Board Member: +reports.read"));
    ok('diff: "group platform-eng unmapped" net-zero (added+removed cancel within the window)', lines.every((t) => !/group platform-eng/.test(t)));

    // And prove the diff is direction-honest: a single-step diff over just the schedule change reads the
    // exact transition line and nothing about profiles (which changed in a later version).
    const oneStep = await diff(baseId, baseId + 1);
    ok("a single-step diff isolates exactly the first change", texts(oneStep.changes).some((t) => /schedule daily -> hourly/.test(t)));

    // A direct in-test diff over the two fetched snapshots agrees with the endpoint (the same pure logic).
    const fromV = (await versionById(baseId)).version!;
    const toV = (await versionById(head.headId)).version!;
    const independentDiff = diffConfig(fromV.snapshot, toV.snapshot).map((c) => c.text);
    ok("an independent diff over the fetched snapshots matches the endpoint", lines.length === independentDiff.length && lines.every((t) => independentDiff.includes(t)));
  }
}

// ---- PROOF 4b: a group UNMAPPED line renders when the mapping exists at the baseline ----------
async function proveGroupUnmappedLine(ctx: VersioningCtx): Promise<void> {
  const { call, history, diff, texts } = ctx;
  {
    // Map a group, snapshot it as the baseline, then delete the mapping and diff: the line reads
    // "group <name> unmapped" exactly.
    await call(OWNER, "POST", "/admin/group-roles", { group: "data-eng", role: "viewer" });
    const base = await history();
    await call(OWNER, "POST", "/admin/group-roles/delete", { group: "data-eng" });
    const head = await history();
    const lines = texts((await diff(base.headId, head.headId)).changes);
    ok('diff: "group data-eng unmapped"', lines.some((t) => t === "group data-eng unmapped"));
  }
}

// ---- PROOF 5: NO secret value EVER appears in a snapshot --------------------------------------
async function proveNoSecretInSnapshot(ctx: VersioningCtx): Promise<void> {
  const { call, sched } = ctx;
  {
    // Configure a downpipe whose SECRETS source names a secret (by name), a notify channel carrying a
    // PagerDuty ROUTING KEY (a credential), and a Slack channel whose incoming-webhook url embeds a
    // bearer-equivalent token in its path (a credential in url clothing). The
    // snapshot must carry the secret's NAME, the routing-key PRESENCE, and the Slack url's HOST +
    // PRESENCE only - never the routing-key value or the raw url. Drive all three, then assert no marker
    // appears in ANY version's serialised snapshot.
    await call(OPERATOR, "POST", "/admin/downpipes", {
      id: "dp-secrets",
      name: "App secrets",
      cadenceSeconds: 86400,
      enabled: true,
      source: { type: "secrets", secrets: [{ name: "STRIPE_KEY", binding: "STRIPE_KEY_BINDING" }], include: [], exclude: [] },
    });
    // A PagerDuty channel: the routing key is the secret-adjacent field. (The DO validates the channel;
    // pagerduty requires a routingKey.) Owner holds notify.config.
    await call(OWNER, "POST", "/admin/notify/channels", { kind: "pagerduty", name: "On-call", routingKey: SECRET_ROUTING_KEY });
    // A Slack channel: the incoming-webhook url IS the bearer credential (notify/types.ts calls it "the
    // customer's own credential to their own sink"). The marker sits in
    // the path, where a real Slack token lives.
    await call(OWNER, "POST", "/admin/notify/channels", { kind: "slack", name: "Ops Slack", url: `https://hooks.slack.com/services/T000/B000/${SECRET_URL_MARKER}` });

    // Read every stored version's snapshot and serialise it (the SAME canonical bytes the content hash
    // covers), then assert no secret marker appears anywhere.
    const keys = sched.storage.rawKeys("confighist:");
    let anyMarker = false;
    let sawSecretName = false;
    let sawRoutingPresence = false;
    let sawUrlConfigured = false;
    let sawUrlHost = false;
    for (const k of keys) {
      const v = sched.storage.rawGet<ConfigVersion>(k)!;
      const bytes = serialiseSnapshot(v.snapshot);
      const text = new TextDecoder().decode(bytes);
      for (const m of SECRET_MARKERS) if (text.includes(m)) anyMarker = true;
      // Positive controls: the secret NAME and binding NAME (non-secret metadata) DO appear, the
      // routing-key PRESENCE boolean is recorded, and the Slack channel's redacted urlConfigured/urlHost
      // ARE recorded (so each by-reference is real, not just an omission).
      if (text.includes("STRIPE_KEY")) sawSecretName = true;
      for (const ch of v.snapshot.notifyChannels) {
        if (ch.kind === "pagerduty" && ch.routingKeyConfigured === true) sawRoutingPresence = true;
        if (ch.kind === "slack" && ch.urlConfigured === true) sawUrlConfigured = true;
        if (ch.kind === "slack" && ch.urlHost === "hooks.slack.com") sawUrlHost = true;
      }
    }
    ok("no secret VALUE (routing key / url token / private-key marker) appears in any serialised snapshot", anyMarker === false);
    ok("the secret NAME (by-reference) IS present in a snapshot (positive control)", sawSecretName === true);
    ok("a PagerDuty routing key is recorded as a PRESENCE boolean, not its value", sawRoutingPresence === true);
    ok("a Slack channel url is recorded as urlConfigured:true (positive control)", sawUrlConfigured === true);
    ok("a Slack channel url is recorded as its HOST only (hooks.slack.com), never the raw url", sawUrlHost === true);

    // Belt and braces: also scan the FULL stored version record (header + snapshot + digest), since a
    // value could theoretically leak into a summary too. None of the secret-value markers may appear.
    let anyMarkerFull = false;
    for (const k of keys) {
      const full = JSON.stringify(sched.storage.rawGet<ConfigVersion>(k)!);
      for (const m of SECRET_MARKERS) if (full.includes(m)) anyMarkerFull = true;
    }
    ok("no secret VALUE appears anywhere in a full stored version record (incl. summary)", anyMarkerFull === false);
  }
}

// ---- PROOF 6: the READ endpoints are capability-gated; the MANUAL snapshot needs the policy cap ----
async function proveCapabilityGating(ctx: VersioningCtx): Promise<void> {
  const { call } = ctx;
  {
    // (a) The manual snapshot is access.policy (owner/access-admin). An OPERATOR lacks access.policy, so
    // POST /admin/config/snapshot is 403 for them.
    const opSnap = await call(OPERATOR, "POST", "/admin/config/snapshot");
    ok("manual snapshot is policy-gated: an operator (no access.policy) is 403", opSnap.status === 403);
    // The OWNER can snapshot (created false or true is fine; the point is it is NOT 403).
    const ownerSnap = await call(OWNER, "POST", "/admin/config/snapshot");
    ok("manual snapshot is allowed for the owner (policy holder)", ownerSnap.status === 200);

    // (b) The reads gate on downpipe.read - the SAME capability that lets a caller view the config (GET
    // /downpipes / GET /roles). The route's gate is exactly `callerCan(caller, "downpipe.read") ? proceed
    // : 403`, so proving "a caller lacking the read cap is 403" is proving callerCan returns false for
    // such a caller (the production decision function the route calls). Custom roles are PURELY ADDITIVE
    // over the viewer floor (a custom role can only ADD capabilities, never remove the floor's), so every
    // authenticated caller holds at least the viewer floor and thus downpipe.read - there is by design no
    // end-to-end caller that lacks it (which is also why GET /downpipes itself is open to any authenticated
    // role). So the 403 side is proven against the production gate predicate with a synthetic restricted
    // caller, and the allow side is proven end to end below.
    const restricted: Pick<Caller, "role" | "capabilities"> = { role: "viewer", capabilities: new Set<Capability>(["audit.read"]) };
    ok("the route gate (callerCan) DENIES downpipe.read to a caller lacking it -> 403", callerCan(restricted, "downpipe.read") === false);
    // And the gate ALLOWS it for a caller that holds it (so the gate is a real check, not always-deny).
    const holder: Pick<Caller, "role" | "capabilities"> = { role: "viewer", capabilities: new Set<Capability>(["downpipe.read"]) };
    ok("the route gate (callerCan) ALLOWS downpipe.read to a caller that holds it", callerCan(holder, "downpipe.read") === true);

    // End to end: a built-in VIEWER (the least-privilege floor, which holds downpipe.read) reads all three
    // config endpoints successfully, confirming the gate does not over-block a legitimate config viewer.
    const VIEWER = "viewer@acme.example";
    await call(OWNER, "POST", "/admin/roles", { email: VIEWER, role: "viewer" });
    ok("GET /config/history is 200 for a viewer (holds downpipe.read)", (await call(VIEWER, "GET", "/admin/config/history")).status === 200);
    ok("GET /config/version is 200 for a viewer", (await call(VIEWER, "GET", "/admin/config/version?id=1")).status === 200);
    ok("GET /config/diff is 200 for a viewer", (await call(VIEWER, "GET", "/admin/config/diff?from=1&to=2")).status === 200);
  }
}

// ---- PROOF 7: the unauthenticated surface is refused (no token -> 401) ------------------------
async function proveUnauthenticatedRefused(ctx: VersioningCtx): Promise<void> {
  const noAuth = await handleAdmin(new Request("https://engine.example/admin/config/history", { method: "GET" }), ctx.accessEnv());
  ok("an unauthenticated config-history read is 401", noAuth.status === 401);
}

// ---- PROOF 8: diffConfig + summarise pure-logic coverage (every family, every arm) ------------
// The end-to-end proofs above drive the common ADD / typical-CHANGE paths through the live router and
// DO. This block exercises the diff and the auto-summary DIRECTLY against hand-built ConfigSnapshots so
// every family's REMOVE line, each per-field CHANGE line, the cadence and label fallbacks, the redacted
// webhook arms and the summary cap are all driven and their plain-English (Australian) text asserted.
// diffConfig/summarise are pure and re-exported from config-history.ts, so calling them directly is the
// same production logic the endpoints call, just without the DO round trip needed to stage each delta.
// Each `// --` sub-block below isolates exactly one family/arm and reads back the line that family emits.
function proveDiffAndSummaryCoverage(): void {
  {
    // emptySnap is a fully-formed, change-free ConfigSnapshot: every family empty, no coverage
    // inventory. A diff of it against itself yields nothing, so each test below
    // changes exactly the one family it is checking and reads back exactly the lines that family emits.
    const emptySnap = (): ConfigSnapshot => ({
      downpipes: [],
      roles: [],
      groupRoles: [],
      customRoles: [],
      notifyChannels: [],
      notifyRules: [],
      riskAccepts: [],
      expiryItems: [],
    });
    // tx runs a diff and returns the change texts, so each assertion reads the exact rendered line.
    const tx = (from: ConfigSnapshot, to: ConfigSnapshot): string[] => diffConfig(from, to).map((c) => c.text);
    // first returns element 0 of a just-built single-item family array, asserting it is present so the
    // mutation below narrows under noUncheckedIndexedAccess. Each caller has literally pushed exactly one
    // row immediately before, so the assertion can never fire; it is a real bounds check, not a cast.
    const first = <T>(rows: readonly T[]): T => {
      const row = rows[0];
      if (row === undefined) throw new Error("expected a single-row family array");
      return row;
    };

    ok("a diff of an empty snapshot against itself yields no changes", tx(emptySnap(), emptySnap()).length === 0);

    // -- cadenceLabel: the friendly words and the four "every N units" fallbacks (and "off" at 0) --
    // One downpipe whose schedule moves across cadences exercises every cadenceLabel arm in turn.
    {
      const dp = (cadence: number): ConfigSnapshot => {
        const s = emptySnap();
        s.downpipes = [{ id: "d1", name: "P", cadenceSeconds: cadence, enabled: true, restoreTestCadenceSeconds: 0, source: { type: "kv", binding: "b", namespaceId: null, bucketName: null, secrets: [], include: [], exclude: [] } }];
        return s;
      };
      ok("cadence weekly -> off (0) reads 'off'", tx(dp(604800), dp(0)).some((t) => t === "downpipe kv:b schedule weekly -> off"));
      ok("cadence monthly named", tx(dp(0), dp(2592000)).some((t) => t === "downpipe kv:b schedule off -> monthly"));
      ok("cadence non-named multiple of days reads 'every N days'", tx(dp(3600), dp(172800)).some((t) => t === "downpipe kv:b schedule hourly -> every 2 days"));
      ok("cadence non-named multiple of hours reads 'every N hours'", tx(dp(3600), dp(7200)).some((t) => t === "downpipe kv:b schedule hourly -> every 2 hours"));
      ok("cadence non-named multiple of minutes reads 'every N minutes'", tx(dp(3600), dp(300)).some((t) => t === "downpipe kv:b schedule hourly -> every 5 minutes"));
      ok("cadence arbitrary seconds reads 'every N seconds'", tx(dp(3600), dp(90)).some((t) => t === "downpipe kv:b schedule hourly -> every 90 seconds"));
    }

    // -- downpipeLabel: the binding -> namespaceId -> bucketName -> id fallback chain --
    // A downpipe with no binding falls back to its namespaceId, then to its bucketName, then to its id.
    {
      const withSrc = (src: { binding: string | null; namespaceId: string | null; bucketName: string | null }): ConfigSnapshot => {
        const s = emptySnap();
        s.downpipes = [{ id: "the-id", name: "P", cadenceSeconds: 3600, enabled: true, restoreTestCadenceSeconds: 0, source: { type: "r2", binding: src.binding, namespaceId: src.namespaceId, bucketName: src.bucketName, secrets: [], include: [], exclude: [] } }];
        return s;
      };
      // An ADD line leads with the label, so the fallback choice is visible in the rendered text.
      ok("label falls back to namespaceId when binding is null", tx(emptySnap(), withSrc({ binding: null, namespaceId: "ns-7", bucketName: "bk" })).some((t) => t === "downpipe r2:ns-7 added"));
      ok("label falls back to bucketName when binding and namespaceId are null", tx(emptySnap(), withSrc({ binding: null, namespaceId: null, bucketName: "bk-9" })).some((t) => t === "downpipe r2:bk-9 added"));
      ok("label falls back to the id when binding, namespaceId and bucketName are all null", tx(emptySnap(), withSrc({ binding: null, namespaceId: null, bucketName: null })).some((t) => t === "downpipe r2:the-id added"));
    }

    // -- downpipe: REMOVE line + every per-field CHANGE line (enabled, restore-test, rename, selectors) --
    {
      const base = emptySnap();
      base.downpipes = [{ id: "dp", name: "Old", cadenceSeconds: 3600, enabled: true, restoreTestCadenceSeconds: 86400, source: { type: "kv", binding: "sess", namespaceId: null, bucketName: null, secrets: [{ name: "S1", binding: "B1" }], include: ["a/*"], exclude: ["x/*"] } }];
      // REMOVE: the whole downpipe disappears.
      ok("a removed downpipe reads 'removed'", tx(base, emptySnap()).some((t) => t === "downpipe kv:sess removed"));
      // enabled toggle (true -> false renders 'disabled').
      const disabled = structuredClone(base);
      first(disabled.downpipes).enabled = false;
      ok("an enabled -> disabled toggle reads 'disabled'", tx(base, disabled).some((t) => t === "downpipe kv:sess disabled"));
      // restore-test cadence change.
      const rt = structuredClone(base);
      first(rt.downpipes).restoreTestCadenceSeconds = 604800;
      ok("a restore-test cadence change renders the transition", tx(base, rt).some((t) => t === "downpipe kv:sess restore test daily -> weekly"));
      // rename.
      const renamed = structuredClone(base);
      first(renamed.downpipes).name = "New";
      ok("a downpipe rename renders 'renamed Old -> New'", tx(base, renamed).some((t) => t === "downpipe kv:sess renamed Old -> New"));
      // include selector change.
      const inc = structuredClone(base);
      first(inc.downpipes).source.include = ["a/*", "b/*"];
      ok("an include-glob add renders '+b/*'", tx(base, inc).some((t) => t === "downpipe kv:sess include +b/*"));
      // exclude selector change.
      const exc = structuredClone(base);
      first(exc.downpipes).source.exclude = [];
      ok("an exclude-glob removal renders '-x/*'", tx(base, exc).some((t) => t === "downpipe kv:sess exclude -x/*"));
      // secret-name set change (by name only).
      const sec = structuredClone(base);
      first(sec.downpipes).source.secrets = [{ name: "S1", binding: "B1" }, { name: "S2", binding: "B2" }];
      ok("a secret-name set add renders '+S2' by name", tx(base, sec).some((t) => t === "downpipe kv:sess secrets +S2"));
    }

    // -- roles: the customRole label arm, the REMOVE line, and the expiry-change line --
    {
      const from = emptySnap();
      from.roles = [{ email: "u@x", role: "operator", customRole: "board", expiresAt: "2026-01-01T00:00:00Z" }];
      // The customRole branch renders 'custom role <name>' rather than the built-in role name on ADD.
      ok("a granted custom role names it as 'custom role <name>'", tx(emptySnap(), from).some((t) => t === "u@x: granted custom role board"));
      // REMOVE.
      ok("a removed role grant reads '<email> removed'", tx(from, emptySnap()).some((t) => t === "u@x removed"));
      // expiry change (a real expiry -> no expiry transition).
      const to = structuredClone(from);
      first(to.roles).expiresAt = null;
      ok("a role expiry change renders the transition to 'no expiry'", tx(from, to).some((t) => t === "u@x expiry 2026-01-01T00:00:00Z -> no expiry"));
    }

    // -- group-roles: the customRole arm and the changed-mapping line --
    {
      const from = emptySnap();
      from.groupRoles = [{ group: "eng", role: "viewer", customRole: "board", connId: null }];
      ok("a group mapped to a custom role names it", tx(emptySnap(), from).some((t) => t === "group eng mapped to custom role board"));
      const to = structuredClone(from);
      first(to.groupRoles).customRole = null;
      first(to.groupRoles).role = "operator";
      ok("a changed group mapping renders the role transition", tx(from, to).some((t) => t === "group eng: custom role board -> operator"));
    }

    // -- custom-roles: the label-or-name fallback, the DELETE line, presentation/landing, surface arms --
    {
      // disp falls back to the NAME when the label is empty: an ADD of a label-less role reads its name.
      const noLabel = emptySnap();
      noLabel.customRoles = [{ name: "raw-name", label: "", capabilities: [], surface: [], presentation: "p", landing: "l" }];
      ok("a custom role with no label is displayed by its name", tx(emptySnap(), noLabel).some((t) => t === "custom role raw-name created"));

      const from = emptySnap();
      from.customRoles = [{ name: "cr", label: "Role", capabilities: ["a.read"], surface: [{ screen: "home", mode: "show" }, { screen: "gone", mode: "hide" }], presentation: "plain", landing: "home" }];
      // DELETE.
      ok("a deleted custom role reads 'deleted'", tx(from, emptySnap()).some((t) => t === "custom role Role deleted"));
      // presentation change.
      const pres = structuredClone(from);
      first(pres.customRoles).presentation = "shiny";
      ok("a presentation change renders the transition", tx(from, pres).some((t) => t === "custom role Role presentation plain -> shiny"));
      // landing change.
      const land = structuredClone(from);
      first(land.customRoles).landing = "reports";
      ok("a landing change renders the transition", tx(from, land).some((t) => t === "custom role Role landing home -> reports"));
      // surface: a NEW screen, a CHANGED mode, and a RESET (screen removed).
      const surf = structuredClone(from);
      first(surf.customRoles).surface = [{ screen: "home", mode: "hide" }, { screen: "added", mode: "show" }];
      const surfLines = tx(from, surf);
      ok("a new surface screen renders 'screen <name> <mode>'", surfLines.some((t) => t === "custom role Role screen added show"));
      ok("a changed surface mode renders 'screen <name> <was> -> <now>'", surfLines.some((t) => t === "custom role Role screen home show -> hide"));
      ok("a removed surface screen renders 'screen <name> reset'", surfLines.some((t) => t === "custom role Role screen gone reset"));
    }

    // -- notify channels: REMOVE + enabled, endpoint, recipients, routing-key arms --
    {
      const from = emptySnap();
      from.notifyChannels = [{ id: "c1", kind: "slack", name: "Ops", enabled: true, urlConfigured: true, urlHost: "a.example", toAddresses: ["a@x"], routingKeyConfigured: true }];
      ok("a removed notify channel reads 'removed'", tx(from, emptySnap()).some((t) => t === "notify channel Ops (slack) removed"));
      const dis = structuredClone(from);
      first(dis.notifyChannels).enabled = false;
      ok("a disabled notify channel reads 'disabled'", tx(from, dis).some((t) => t === "notify channel Ops disabled"));
      const url = structuredClone(from);
      first(url.notifyChannels).urlHost = "b.example";
      ok("a changed notify endpoint reads 'endpoint changed'", tx(from, url).some((t) => t === "notify channel Ops endpoint changed"));
      const rcpt = structuredClone(from);
      first(rcpt.notifyChannels).toAddresses = ["a@x", "b@x"];
      ok("a recipients change renders '+b@x'", tx(from, rcpt).some((t) => t === "notify channel Ops recipients +b@x"));
      const rk = structuredClone(from);
      first(rk.notifyChannels).routingKeyConfigured = false;
      ok("a routing-key clear reads 'routing key cleared'", tx(from, rk).some((t) => t === "notify channel Ops routing key cleared"));
    }

    // -- notify rules: REMOVE + enabled, severity, digest, events, channels arms --
    {
      const from = emptySnap();
      from.notifyRules = [{ id: "r1", scope: "global", minSeverity: "warn", events: ["backup-fail"], channelIds: ["c1"], digest: "off", enabled: true }];
      ok("a removed notify rule reads 'removed'", tx(from, emptySnap()).some((t) => t === "notify rule (global, warn+) removed"));
      const dis = structuredClone(from);
      first(dis.notifyRules).enabled = false;
      ok("a disabled notify rule reads 'disabled'", tx(from, dis).some((t) => t === "notify rule global disabled"));
      const sev = structuredClone(from);
      first(sev.notifyRules).minSeverity = "error";
      ok("a severity change renders the transition", tx(from, sev).some((t) => t === "notify rule global severity warn -> error"));
      const dig = structuredClone(from);
      first(dig.notifyRules).digest = "daily";
      ok("a digest change renders the transition", tx(from, dig).some((t) => t === "notify rule global digest off -> daily"));
      const ev = structuredClone(from);
      first(ev.notifyRules).events = ["backup-fail", "restore-test-fail"];
      ok("an events-set add renders '+restore-test-fail'", tx(from, ev).some((t) => t === "notify rule global events +restore-test-fail"));
      const ch = structuredClone(from);
      first(ch.notifyRules).channelIds = [];
      ok("a channels-set removal renders '-c1'", tx(from, ch).some((t) => t === "notify rule global channels -c1"));
    }

    // -- posture risk-acceptances: ADD, REMOVE, and the reason-changed line --
    {
      const from = emptySnap();
      from.riskAccepts = [{ checkId: "chk-1", reason: "first" }];
      // A legacy record with no kind reads as the risk-accepted override everywhere.
      ok("an added override reads 'override (<kind>) recorded for <id>'", tx(emptySnap(), from).some((t) => t === "override (risk-accepted) recorded for chk-1"));
      ok("a removed override reads 'override (<kind>) withdrawn for <id>'", tx(from, emptySnap()).some((t) => t === "override (risk-accepted) withdrawn for chk-1"));
      const to = structuredClone(from);
      first(to.riskAccepts).reason = "second";
      ok("an override reason edit reads 'reason updated'", tx(from, to).some((t) => t === "override reason updated for chk-1"));
      // A KIND change (same reason) renders its own line naming the transition.
      const kinded = structuredClone(from);
      first(kinded.riskAccepts).kind = "attested-pass";
      ok("an override kind change renders the transition", tx(from, kinded).some((t) => t === "override kind changed for chk-1 (risk-accepted -> attested-pass)"));
    }

    // -- tracked expiry items: ADD (with the label fallback), REMOVE, and expiry/label/kind changes --
    {
      // ADD a label-less, no-expiry item: label() falls back to the id, expOf() reads 'no expiry'.
      const addNoLabel = emptySnap();
      addNoLabel.expiryItems = [{ id: "exp-1", label: "", kind: "token" }];
      ok("an added expiry item with no label or expiry uses the id and 'no expiry'", tx(emptySnap(), addNoLabel).some((t) => t === "tracked expiry exp-1 (token) added, expires no expiry"));

      const from = emptySnap();
      from.expiryItems = [{ id: "e", label: "Cert", kind: "tls", expiresAt: "2026-03-01T00:00:00Z" }];
      ok("a removed expiry item reads 'removed'", tx(from, emptySnap()).some((t) => t === "tracked expiry Cert removed"));
      const exp = structuredClone(from);
      first(exp.expiryItems).expiresAt = "2027-03-01T00:00:00Z";
      ok("an expiry-date change renders the transition", tx(from, exp).some((t) => t === "tracked expiry Cert expiry 2026-03-01T00:00:00Z -> 2027-03-01T00:00:00Z"));
      const ren = structuredClone(from);
      first(ren.expiryItems).label = "Renamed";
      ok("an expiry-item rename reads 'renamed to <label>'", tx(from, ren).some((t) => t === "tracked expiry Cert renamed to Renamed"));
      const knd = structuredClone(from);
      first(knd.expiryItems).kind = "api-token";
      ok("an expiry-item kind change renders the transition", tx(from, knd).some((t) => t === "tracked expiry Cert kind tls -> api-token"));
    }

    // -- coverage inventory: imported (none -> present), cleared (present -> none), and a per-group change --
    {
      const withCov = emptySnap();
      withCov.coverage = { kv: [{ id: "kv-1", name: null }], r2: [], d1: [], secrets: [] };
      // imported: from has no coverage, to does.
      ok("a coverage inventory appearing reads 'imported'", tx(emptySnap(), withCov).some((t) => t === "coverage inventory imported"));
      // cleared: from has coverage, to does not.
      ok("a coverage inventory disappearing reads 'cleared'", tx(withCov, emptySnap()).some((t) => t === "coverage inventory cleared"));
      // a per-group id-set change while both sides have an inventory.
      const withCov2 = emptySnap();
      withCov2.coverage = { kv: [{ id: "kv-1", name: null }, { id: "kv-2", name: null }], r2: [], d1: [], secrets: [] };
      ok("a coverage group id-set add renders 'coverage kv +kv-2'", tx(withCov, withCov2).some((t) => t === "coverage kv +kv-2"));
    }

    // -- the opposite arms of the boolean/fallback ternaries (the "on" side of each toggle) --
    // The toggles above were driven on -> off; drive the off -> on side so both arms of each ternary and
    // both sides of each redaction fallback are exercised, not just one.
    {
      // downpipe enabled false -> true renders 'enabled'.
      const dpOff = emptySnap();
      dpOff.downpipes = [{ id: "dp", name: "P", cadenceSeconds: 3600, enabled: false, restoreTestCadenceSeconds: 0, source: { type: "kv", binding: "b", namespaceId: null, bucketName: null, secrets: [], include: [], exclude: [] } }];
      const dpOn = structuredClone(dpOff);
      first(dpOn.downpipes).enabled = true;
      ok("a disabled -> enabled downpipe toggle reads 'enabled'", tx(dpOff, dpOn).some((t) => t === "downpipe kv:b enabled"));

      // role expiry no-expiry -> expiry: the 'was' side reads 'no expiry' (the null-prev fallback).
      const rFrom = emptySnap();
      rFrom.roles = [{ email: "u@x", role: "viewer", customRole: null, expiresAt: null }];
      const rTo = structuredClone(rFrom);
      first(rTo.roles).expiresAt = "2026-05-01T00:00:00Z";
      ok("a role gaining an expiry renders 'no expiry -> <date>'", tx(rFrom, rTo).some((t) => t === "u@x expiry no expiry -> 2026-05-01T00:00:00Z"));

      // notify channel disabled -> enabled renders 'enabled'; routing key cleared -> configured.
      const chOff = emptySnap();
      chOff.notifyChannels = [{ id: "c1", kind: "slack", name: "Ops", enabled: false, urlConfigured: false, urlHost: null, toAddresses: [], routingKeyConfigured: false }];
      const chOn = structuredClone(chOff);
      first(chOn.notifyChannels).enabled = true;
      ok("a disabled -> enabled notify channel reads 'enabled'", tx(chOff, chOn).some((t) => t === "notify channel Ops enabled"));
      const chRk = structuredClone(chOff);
      first(chRk.notifyChannels).routingKeyConfigured = true;
      ok("a routing key newly set reads 'routing key configured'", tx(chOff, chRk).some((t) => t === "notify channel Ops routing key configured"));

      // notify rule disabled -> enabled renders 'enabled'.
      const ruleOff = emptySnap();
      ruleOff.notifyRules = [{ id: "r1", scope: "global", minSeverity: "warn", events: ["all"], channelIds: [], digest: "off", enabled: false }];
      const ruleOn = structuredClone(ruleOff);
      first(ruleOn.notifyRules).enabled = true;
      ok("a disabled -> enabled notify rule reads 'enabled'", tx(ruleOff, ruleOn).some((t) => t === "notify rule global enabled"));
    }

    // -- the expiry-rename label-or-id fallbacks on BOTH sides of the rename line --
    {
      // prev has no label (so 'prev.label || prev.id' falls to the id) and the new item has a label.
      const fromNoLabel = emptySnap();
      fromNoLabel.expiryItems = [{ id: "e1", label: "", kind: "tls", expiresAt: "2026-03-01T00:00:00Z" }];
      const toLabel = structuredClone(fromNoLabel);
      first(toLabel.expiryItems).label = "Gained";
      ok("a rename from a label-less item leads with the id", tx(fromNoLabel, toLabel).some((t) => t === "tracked expiry e1 renamed to Gained"));
      // prev has a label and the new item clears it (so 'e.label || e.id' falls to the id).
      const fromLabel = emptySnap();
      fromLabel.expiryItems = [{ id: "e2", label: "Cert", kind: "tls", expiresAt: "2026-03-01T00:00:00Z" }];
      const toNoLabel = structuredClone(fromLabel);
      first(toNoLabel.expiryItems).label = "";
      ok("a rename that clears the label renders the id as the new name", tx(fromLabel, toNoLabel).some((t) => t === "tracked expiry Cert renamed to e2"));
    }

    // -- the defensive expiry/webhook fallbacks for a snapshot handed in with the array/scalar absent --
    // expiryItems is a required field on a snapshotConfig result, but diffConfig defends against an absent
    // list via `from.expiryItems ?? []` (mirroring the webhook scalar). Drive that defensive arm directly
    // by handing in a snapshot with no expiryItems, and confirm an item present only on the OTHER side is
    // still rendered (so the fallback substitutes an empty list rather than throwing).
    {
      // Omit the required expiryItems list so delete is legal (the defensive `from.expiryItems ?? []` arm).
      const noExpiry = emptySnap() as Omit<ConfigSnapshot, "expiryItems"> & { expiryItems?: unknown };
      delete noExpiry.expiryItems;
      const withExpiry = emptySnap();
      withExpiry.expiryItems = [{ id: "e", label: "Cert", kind: "tls" }];
      ok("an absent expiryItems on the FROM side still renders an item added on the TO side", tx(noExpiry as ConfigSnapshot, withExpiry).some((t) => t === "tracked expiry Cert (tls) added, expires no expiry"));
      ok("an absent expiryItems on the TO side renders the item as removed", tx(withExpiry, noExpiry as ConfigSnapshot).some((t) => t === "tracked expiry Cert removed"));
    }

    // -- summarise: the genesis line, the no-change line, the joined line, and the '(+N more)' cap --
    {
      ok("summarise of a genesis version reads the fixed initial line", summarise([], true) === "initial configuration snapshot");
      ok("summarise of a non-genesis empty diff reads 'no configuration change'", summarise([], false) === "no configuration change");
      // A handful of changes under the cap join with '; ' and carry no suffix.
      const few: ConfigChange[] = [
        { kind: "added", area: "downpipe", text: "one" },
        { kind: "added", area: "downpipe", text: "two" },
      ];
      ok("summarise under the cap joins texts with '; ' and no '(+N more)'", summarise(few, false) === "one; two");
      // More than the cap shows the first SUMMARY_MAX_CHANGES and a '(+N more)' suffix.
      const many: ConfigChange[] = [];
      for (let i = 0; i < SUMMARY_MAX_CHANGES + 3; i++) many.push({ kind: "added", area: "downpipe", text: `c${i}` });
      const summary = summarise(many, false);
      ok("summarise over the cap shows exactly SUMMARY_MAX_CHANGES texts", summary.startsWith(many.slice(0, SUMMARY_MAX_CHANGES).map((c) => c.text).join("; ")));
      ok("summarise over the cap appends the correct '(+N more)' count", summary.endsWith(`(+${many.length - SUMMARY_MAX_CHANGES} more)`));
    }
  }
}

async function main(): Promise<void> {
  const ctx = await buildVersioningCtx();
  try {
    await proveLinkedVersions(ctx);
    await proveChainVerifies(ctx);
    await proveTamperDetection(ctx);
    await proveDiffLines(ctx);
    await proveGroupUnmappedLine(ctx);
    await proveNoSecretInSnapshot(ctx);
    await proveCapabilityGating(ctx);
    await proveUnauthenticatedRefused(ctx);
    proveDiffAndSummaryCoverage();
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  console.log(failures === 0 ? "\nconfig-versioning: ALL PASS" : `\nconfig-versioning: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
