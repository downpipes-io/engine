// Validate the assurance licence: a token signed by the pinned vendor key resolves to its
// granted tier; a tampered token, an expired token and a wrong-key token all FAIL OPEN to
// tier 'community'; an absent token or absent pinned key fail open with the right closed-set
// reason. Then prove the fail-open INVARIANT behaviourally: a mock backup and a real restore
// both proceed regardless of the licence state, because neither path ever consults the
// licence. Run:
//   node test/validate-licence.ts
// In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, } from "../src/crypto/pq.ts";
import { loadSigner, } from "../src/keys-env.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { b64urlEncode, b64urlDecode, concat, utf8 } from "../src/crypto/bytes.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { verifyLicence, verifyLicenceToken, readLicence, effectiveSignerPin } from "../src/admin/licence.ts";
import { buildStatus } from "../src/admin/status.ts";
import { DEFAULT_LICENCE_SIGNER_PUBLIC } from "../src/licence-pins.ts";
import { runBackup, type RunConfig, type RunClock } from "../src/seal/pipeline.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { runRestore } from "../src/admin/restore.ts";
import { MemoryDestination } from "./memdest.ts";
import type { Env } from "../src/env.d.ts";
import type { SourceAdapter, SourceRecord, Selector } from "../src/sources/types.ts";
import type { RestoreResult } from "../src/admin/restore-types.ts";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// mintToken signs a claims object EXACTLY as the vendor issuer does: canonicalise, sign the
// canonical body bytes with the hybrid signer, and join base64url(body) . base64url(sig).
// Returning the body bytes too lets a test tamper with the body while keeping the signature.
async function mintToken(signer: Signer, claims: unknown): Promise<{ token: string; bodyB64: string; sigB64: string }> {
  const body = canonicalJSON(claims);
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, body);
  const bodyB64 = b64urlEncode(body);
  const sigB64 = b64urlEncode(sig);
  return { token: `${bodyB64}.${sigB64}`, bodyB64, sigB64 };
}

// A trivial in-memory source for the fail-open backup proof: one buffered KV record.
class OneRecordSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private value: Uint8Array;
  constructor(value: string) {
    this.value = utf8(value);
  }
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: "k", value: this.value, namespace: "ns" };
  }
  async estimate(_sel: Selector): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: this.value.length };
  }
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// MockR2 serves a sealed archive map through the R2 binding surface the R2 destination reads,
// the same idiom the restore validator uses, so the real runRestore opens the run.
class MockR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}
class MockKV {
  store = new Map<string, Uint8Array>();
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string, _t?: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

async function main(): Promise<void> {
  // The vendor signer (pinned). Build a SIGNER_PRIVATE-shaped private so loadSigner derives
  // the public halves the engine pins as LICENCE_SIGNER_PUBLIC.
  const vendorPrivB64 = b64urlEncode(concat(rand(32), rand(32)));
  const vendor = await loadSigner(vendorPrivB64);
  const pinnedPublic = b64urlEncode(concat(vendor.edPublic, vendor.mldsaPublic));

  // A DIFFERENT vendor key, for the wrong-key case.
  const otherPrivB64 = b64urlEncode(concat(rand(32), rand(32)));
  const other = await loadSigner(otherPrivB64);

  const future = new Date(Date.now() + 365 * 86400_000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  const past = new Date(Date.now() - 86400_000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  const enterpriseFeatures = ["dashboard", "managed-drill", "priority-support"];

  // ---- PROOF 1: a VALID token resolves to its granted tier ----
  const goodClaims = { account: "acme", tier: "enterprise", notAfter: future, features: enterpriseFeatures };
  const good = await mintToken(vendor, goodClaims);
  const valid = await verifyLicence({ LICENCE_TOKEN: good.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("valid licence -> tier enterprise", valid.tier === "enterprise" && valid.valid === true);
  ok("valid licence echoes notAfter", valid.notAfter === future);
  ok("valid licence echoes the verified features", JSON.stringify(valid.features) === JSON.stringify(enterpriseFeatures));
  ok("valid licence carries no reason", valid.reason === undefined);

  // A second enterprise token with a DIFFERENT signed body (a leaner feature list) resolves likewise. It
  // is the env-side token throughout PROOF 8; its distinct features are what tell it apart from the good
  // token once both carry the enterprise tier (the control plane only ever mints enterprise).
  const ent = await mintToken(vendor, { account: "acme", tier: "enterprise", notAfter: future, features: ["dashboard"] });
  const entStatus = await verifyLicence({ LICENCE_TOKEN: ent.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("second enterprise licence -> tier enterprise", entStatus.tier === "enterprise" && entStatus.valid === true);

  // ---- PROOF 2: a TAMPERED token fails open to community ----
  // Alter the signed body but keep the original signature: the hybrid verify must fail and the
  // engine must degrade to community, never trust the altered claims. Here the tamper rewrites the
  // signed account to forge a grant for a different account.
  const tamperedBodyBytes = canonicalJSON({ ...goodClaims, account: "attacker" }); // account-forge attempt
  const tamperedToken = `${b64urlEncode(tamperedBodyBytes)}.${good.sigB64}`;
  const tampered = await verifyLicence({ LICENCE_TOKEN: tamperedToken, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("tampered licence -> community", tampered.tier === "community" && tampered.valid === false);
  ok("tampered licence reason is the signature reason", tampered.reason === "licence signature did not verify under the pinned vendor key");

  // Garbage in the token slot also fails open (bad base64url / wrong part count).
  const garbage = await verifyLicence({ LICENCE_TOKEN: "not-a-token", LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("garbage licence -> community/malformed", garbage.tier === "community" && garbage.reason === "licence malformed");

  // ---- PROOF 3: an EXPIRED token fails open to community but echoes notAfter ----
  const expiredTok = await mintToken(vendor, { account: "acme", tier: "enterprise", notAfter: past, features: enterpriseFeatures });
  const expired = await verifyLicence({ LICENCE_TOKEN: expiredTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("expired licence -> community", expired.tier === "community" && expired.valid === false);
  ok("expired licence reason is 'licence expired'", expired.reason === "licence expired");
  ok("expired licence still echoes notAfter", expired.notAfter === past);

  // ---- PROOF 4: a WRONG-KEY token fails open to community ----
  // Sign with the other vendor key, pin the real one: both hybrid halves fail under the pin.
  const wrongKeyTok = await mintToken(other, goodClaims);
  const wrongKey = await verifyLicence({ LICENCE_TOKEN: wrongKeyTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("wrong-key licence -> community", wrongKey.tier === "community" && wrongKey.valid === false);
  ok("wrong-key licence reason is the signature reason", wrongKey.reason === "licence signature did not verify under the pinned vendor key");
  // The mirror: the SAME token DOES verify under the key that signed it (sanity that the
  // failure above is the pin, not a broken signer).
  const underOwnKey = await verifyLicence({ LICENCE_TOKEN: wrongKeyTok.token, LICENCE_SIGNER_PUBLIC: b64urlEncode(concat(other.edPublic, other.mldsaPublic)) } as unknown as Env);
  ok("the wrong-key token verifies under its OWN key (signer is sound)", underOwnKey.valid === true && underOwnKey.tier === "enterprise");

  // ---- PROOF 5: absence fails open with the right closed-set reasons ----
  const noToken = await verifyLicence({ LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("no token -> community/no licence configured", noToken.tier === "community" && noToken.reason === "no licence configured");
  // With the vendor pin BAKED (DEFAULT_LICENCE_SIGNER_PUBLIC filled), "no env pin" now resolves the
  // baked canonical key, so this test token (signed by the TEST vendor key) fails the SIGNATURE check,
  // the same community fail-open with the signature reason. The no-pin closed-set reason is still
  // covered below via verifyLicenceToken with an explicitly undefined pin.
  const noPin = await verifyLicence({ LICENCE_TOKEN: good.token } as unknown as Env);
  ok("no env pin -> baked pin verifies -> community/signature mismatch (fail-open)", noPin.tier === "community" && noPin.reason === "licence signature did not verify under the pinned vendor key");
  const badPin = await verifyLicence({ LICENCE_TOKEN: good.token, LICENCE_SIGNER_PUBLIC: "!!!not-base64url!!!" } as unknown as Env);
  ok("invalid pinned key -> community/pinned vendor key invalid", badPin.tier === "community" && badPin.reason === "pinned vendor key invalid");

  // readLicence (the route entry) never throws and mirrors verifyLicence for a valid token.
  const viaRoute = await readLicence({ LICENCE_TOKEN: good.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("readLicence returns the same status for a valid token", viaRoute.tier === "enterprise" && viaRoute.valid === true);

  // ---- PROOF 6: FAIL-OPEN INVARIANT, a backup proceeds regardless of the licence ----
  // runBackup must NEVER consult the licence. Put a TAMPERED licence (and a wrong-key one) in
  // env and confirm a backup still seals records. The licence env is present and broken; the
  // backup must not care.
  const signer: Signer = vendor; // any sound signer to seal with
  const bgRec = makeRecipient("break-glass");
  const dest = new MemoryDestination();
  const cfg: RunConfig = {
    downpipeId: "dp",
    downpipeName: "dp",
    cadence: "3600s",
    selector: { include: [], exclude: [] },
    recipients: [bgRec.entry],
  };
  const clock: RunClock = {
    runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    runlogIndex: 1,
    prevRunId: null,
    now: "2026-06-07T00:00:01.000Z",
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
    master: rand(32),
  };
  // The presence of a broken licence in the environment is irrelevant to runBackup, whose
  // signature does not even take env; this asserts the SEAL path is licence-free by running
  // it to completion while a tampered token sits in a parallel env object. Note: this is a
  // structural proof, not an injection one. The broken env is never threaded into runBackup
  // because its signature has no env parameter (see the import above). If a future change adds
  // an env parameter or a licence check inside runBackup, this assertion will no longer guard
  // the invariant and the seal path must be re-proven by passing the broken env directly.
  const brokenEnv = { LICENCE_TOKEN: tamperedToken, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env;
  void (await verifyLicence(brokenEnv)); // the licence is community here, yet:
  const summary = await runBackup([new OneRecordSource("hello-backup")], cfg, signer, dest, clock);
  ok("backup proceeds under a broken licence (records sealed)", summary.records === 1 && summary.bytes === utf8("hello-backup").length);
  ok("backup wrote the run manifest regardless of licence", dest.entries().has(`run/${clock.runId}/root.manifest.json`));

  // ---- PROOF 7: FAIL-OPEN INVARIANT, a restore proceeds regardless of the licence ----
  // Seal a small KV set, then drive the REAL runRestore with a broken/absent licence in env
  // and confirm it verifies and restores. Restore is on the recovery path: it is gated only
  // by OPERATIONAL_PRIVATE, never by the licence.
  const op = makeRecipient("operational");
  const KVSET: Record<string, string> = { a: "alpha", "user:1": "one" };
  const NS = "ns_throwaway";
  const archive = await buildArchive({
    downpipeId: "dp_r",
    downpipeName: "dp_r",
    cadence: "3600s",
    runId: "01BX5ZZKBKACTAV9WEVGEMMVRY",
    master: rand(32),
    recipients: [makeRecipient("break-glass").entry, op.entry],
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
  const r2 = new MockR2();
  for (const [k, b] of archive) r2.store.set(k, b);
  const restoreKV = new MockKV();
  // The restore env carries the signer + the operational read-back key AND a broken/expired
  // licence. The broken licence must NOT block or alter the restore.
  const restoreEnv = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: vendorPrivB64,
    OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
    LICENCE_TOKEN: expiredTok.token, // expired -> community
    LICENCE_SIGNER_PUBLIC: pinnedPublic,
    [`KV_${NS}`]: restoreKV as unknown as KVNamespace,
  } as unknown as Env;
  // Sanity: the licence really is community in this env.
  ok("restore env licence is community (expired)", (await verifyLicence(restoreEnv)).tier === "community");
  const applied = (await runRestore(restoreEnv, { runId: "01BX5ZZKBKACTAV9WEVGEMMVRY", confirm: true })) as RestoreResult;
  ok("restore proceeds under a community licence (records restored)", applied.ok === true && applied.recordsRestored === 2);
  let bytesMatch = true;
  for (const [name, v] of Object.entries(KVSET)) {
    const got = restoreKV.store.get(name);
    if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
  }
  ok("restore round-trip bytes match under a broken licence", bytesMatch);

  // And with NO licence at all the restore is identical (recovery is licence-independent).
  const r2b = new MockR2();
  for (const [k, b] of archive) r2b.store.set(k, b);
  const restoreKV2 = new MockKV();
  const noLicenceEnv: Partial<Env> = { ...restoreEnv };
  delete noLicenceEnv.LICENCE_TOKEN;
  delete noLicenceEnv.LICENCE_SIGNER_PUBLIC;
  noLicenceEnv.DEST_R2 = r2b as unknown as R2Bucket;
  (noLicenceEnv as Record<string, unknown>)[`KV_${NS}`] = restoreKV2 as unknown as KVNamespace;
  const applied2 = (await runRestore(noLicenceEnv as unknown as Env, { runId: "01BX5ZZKBKACTAV9WEVGEMMVRY", confirm: true })) as RestoreResult;
  ok("restore proceeds with NO licence configured at all", applied2.ok === true && applied2.recordsRestored === 2);

  // ---- PROOF 8: CONSOLE ACTIVATION + DO-resolution (no CLI) ----
  // verifyLicenceToken is the shared verify path used by the env wrapper, readLicence's DO-resolution
  // and the router's verify-before-store. A valid result is tagged with its source for the console; a
  // call with no source tag omits the field.
  const direct = await verifyLicenceToken(good.token, pinnedPublic, "console");
  ok("verifyLicenceToken valid -> tier enterprise + source console", direct.valid && direct.tier === "enterprise" && direct.source === "console");
  const directNoSrc = await verifyLicenceToken(good.token, pinnedPublic);
  ok("verifyLicenceToken without source omits the field", directNoSrc.valid && directNoSrc.source === undefined);
  // verify-before-store reasons the router surfaces verbatim (the activation refusal path):
  const refuseExpired = await verifyLicenceToken(expiredTok.token, pinnedPublic, "console");
  ok("activation of an expired token is refusable (valid=false, reason 'licence expired')", !refuseExpired.valid && refuseExpired.reason === "licence expired");
  const refuseNoPin = await verifyLicenceToken(good.token, undefined, "console");
  ok("activation with no pinned vendor key is refusable (reason names the unpinned key)", !refuseNoPin.valid && refuseNoPin.reason === "pinned vendor key not configured");

  // A minimal scheduler DO stub: answers GET /licence-token with the given record (or {token:null}).
  // throwIt makes the fetch reject, to prove a DO hiccup degrades to the env path (fail-open).
  const mockScheduler = (rec: { token?: string | null; setAt?: number; setBy?: string | null } | null, throwIt = false): DurableObjectStub =>
    ({
      fetch: async (input: string | URL | Request): Promise<Response> => {
        if (throwIt) throw new Error("DO unavailable");
        const u = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        if (u.endsWith("/licence-token")) return new Response(JSON.stringify(rec ?? { token: null }), { headers: { "content-type": "application/json" } });
        return new Response("not found", { status: 404 });
      },
    }) as unknown as DurableObjectStub;

  // Both tokens are ENTERPRISE (the control plane mints nothing else), so the tier alone cannot tell them
  // apart. The env carries the lean-features token (ent: features ["dashboard"]); the DO carries the good
  // token (features enterpriseFeatures, three items). The DO (console-activated) token must WIN, proven by
  // the RESOLVED FEATURES being the DO token's, and it must carry the who/when provenance, exactly as the
  // console-set destination wins over env.
  const envEnt = { LICENCE_TOKEN: ent.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env;
  const doWins = await readLicence(envEnt, mockScheduler({ token: good.token, setAt: 1234, setBy: "owner@example.io" }));
  ok(
    "DO-stored token WINS over env (DO good-token features, not the env token's lean features)",
    doWins.valid === true && doWins.tier === "enterprise" && JSON.stringify(doWins.features) === JSON.stringify(enterpriseFeatures),
  );
  ok("DO-stored token is tagged source=console", doWins.source === "console");
  ok("DO-stored token carries setAt/setBy provenance (never the token)", doWins.setAt === 1234 && doWins.setBy === "owner@example.io");

  // A console token that is EXPIRED stays authoritative: community + source console, NO fallback to the
  // still-valid env token (the operator's console choice is the active one).
  const doExpired = await readLicence(envEnt, mockScheduler({ token: expiredTok.token, setAt: 1, setBy: "owner@example.io" }));
  ok("expired DO token -> community (does NOT fall back to the valid env token)", doExpired.tier === "community" && doExpired.valid === false);
  ok("expired DO token keeps source=console + the expired reason", doExpired.source === "console" && doExpired.reason === "licence expired");

  // No console token (record absent) -> fall back to the deploy-time env token (source deploy). The env
  // token's lean features confirm it is the env token that resolved, not the DO good token.
  const doAbsent = await readLicence(envEnt, mockScheduler({ token: null }));
  ok(
    "absent DO token -> env token used (enterprise, lean features, source deploy)",
    doAbsent.tier === "enterprise" && doAbsent.valid === true && doAbsent.source === "deploy" && JSON.stringify(doAbsent.features) === JSON.stringify(["dashboard"]),
  );

  // A DO READ FAILURE must never break the fail-open read: fall through to the env token.
  const doThrew = await readLicence(envEnt, mockScheduler(null, true));
  ok(
    "DO read failure -> falls back to the env token (fail-open)",
    doThrew.tier === "enterprise" && doThrew.valid === true && JSON.stringify(doThrew.features) === JSON.stringify(["dashboard"]),
  );

  // No scheduler at all -> the env path (source deploy), unchanged from the legacy callers.
  const noSched = await readLicence(envEnt);
  ok("no scheduler -> env token (source deploy)", noSched.tier === "enterprise" && noSched.source === "deploy" && JSON.stringify(noSched.features) === JSON.stringify(["dashboard"]));

  // No env token AND no DO token -> the plain Community default, with NO source (nothing is configured).
  const nothing = await readLicence({ LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env, mockScheduler({ token: null }));
  ok("no env + no DO token -> community/no licence configured, no source", nothing.tier === "community" && nothing.reason === "no licence configured" && nothing.source === undefined);

  // ---- PROOF 9: COMPILE-TIME BAKED VENDOR PIN (effectiveSignerPin resolution + no regression) ----
  // The vendor's licence-signer PUBLIC is the same for every customer and never changes, so it can be
  // BAKED into the build (DEFAULT_LICENCE_SIGNER_PUBLIC, src/licence-pins.ts) and used when the customer
  // sets no LICENCE_SIGNER_PUBLIC env override. effectiveSignerPin resolves: non-empty env override WINS,
  // else the baked default, else undefined. The shipped constant is FILLED with the vendor's canonical
  // licence-signer public (the bake is ACTIVE), so the shipped state resolves the baked pin; the
  // both-empty branch is covered through the injected mirror.
  //
  // resolveWith mirrors effectiveSignerPin's resolution rule but with an INJECTED baked value, so the
  // baked-default branch can be exercised without mutating the "" module constant. It is asserted to agree
  // with the REAL effectiveSignerPin on every case the real (empty) constant can reach.
  const resolveWith = (envPin: string | undefined, baked: string): string | undefined => {
    const override = typeof envPin === "string" ? envPin.trim() : "";
    if (override) return override;
    const b = baked.trim();
    if (b) return b;
    return undefined;
  };

  // The shipped constant is FILLED with the vendor's canonical hybrid public: base64url of exactly
  // 2624 bytes (ed25519 32 || ML-DSA-87 public 2592), the layout parseVerifier expects.
  ok("DEFAULT_LICENCE_SIGNER_PUBLIC ships FILLED with the 2624-byte hybrid public", DEFAULT_LICENCE_SIGNER_PUBLIC.length > 0 && b64urlDecode(DEFAULT_LICENCE_SIGNER_PUBLIC).length === 2624);

  // (a) ENV OVERRIDE WINS regardless of the baked default. The real effectiveSignerPin returns the env
  // value (here pinnedPublic) whatever the baked constant is; the injected mirror confirms the env wins
  // even when a DIFFERENT non-empty baked value is present.
  ok("effectiveSignerPin: non-empty env override is returned (real helper)", effectiveSignerPin({ LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env) === pinnedPublic);
  ok("resolution: env override wins over a (different) baked default", resolveWith(pinnedPublic, "AAAA-baked-different") === pinnedPublic);
  // And the override path actually VERIFIES a token signed by the override key (env wins end-to-end), even
  // with a different baked pin present (the demo, which sets LICENCE_SIGNER_PUBLIC, is unaffected).
  const envWinsStatus = await verifyLicenceToken(good.token, resolveWith(pinnedPublic, b64urlEncode(concat(other.edPublic, other.mldsaPublic))), "deploy");
  ok("env override verifies the token signed by the override key (override wins end-to-end)", envWinsStatus.valid === true && envWinsStatus.tier === "enterprise");

  // (b) ENV EMPTY but the BAKED DEFAULT set to a real test key: the baked default is resolved AND verifies
  // a token signed by that baked key, exactly what a release with the constant filled does, no env pin set.
  const bakedTestPin = pinnedPublic; // the vendor signer's public twin, as the baked constant would hold
  ok("resolution: empty env -> the baked default is used", resolveWith("", bakedTestPin) === bakedTestPin && resolveWith(undefined, bakedTestPin) === bakedTestPin);
  const bakedVerifies = await verifyLicenceToken(good.token, resolveWith(undefined, bakedTestPin), "deploy");
  ok("baked default verifies a token signed by the baked key (no env pin set)", bakedVerifies.valid === true && bakedVerifies.tier === "enterprise");
  // A whitespace-only env value does not shadow the baked default (treated as absent).
  ok("resolution: whitespace-only env does not shadow the baked default", resolveWith("   ", bakedTestPin) === bakedTestPin);

  // (c) SHIPPED STATE: env absent/empty -> the BAKED canonical pin is resolved (never undefined now).
  ok("effectiveSignerPin: env absent -> the baked pin (shipped state)", effectiveSignerPin({} as unknown as Env) === DEFAULT_LICENCE_SIGNER_PUBLIC);
  ok("effectiveSignerPin: empty-string env does not shadow the baked pin", effectiveSignerPin({ LICENCE_SIGNER_PUBLIC: "" } as unknown as Env) === DEFAULT_LICENCE_SIGNER_PUBLIC);
  // The both-empty branch (a build with the constant blanked) still resolves undefined -> the unchanged
  // community fail-open with the closed-set no-pin reason; covered through the injected mirror + a
  // direct undefined-pin call so the reason can never silently drift.
  ok("resolution: both empty -> undefined", resolveWith("", "") === undefined && resolveWith(undefined, "") === undefined);
  const bothEmpty = await verifyLicenceToken(good.token, resolveWith(undefined, ""), "deploy");
  ok("both empty -> community 'pinned vendor key not configured' (mirror branch)", bothEmpty.tier === "community" && bothEmpty.valid === false && bothEmpty.reason === "pinned vendor key not configured");
  // And the full env entry with no env pin now verifies under the BAKED key: this test token is signed
  // by the TEST vendor key, so it fails the signature check, still community fail-open.
  const verifyLicenceNoPin = await verifyLicence({ LICENCE_TOKEN: good.token } as unknown as Env);
  ok("verifyLicence with no env pin -> baked pin -> community/signature mismatch", verifyLicenceNoPin.tier === "community" && verifyLicenceNoPin.reason === "licence signature did not verify under the pinned vendor key");

  // ---- PROOF 10: STATUS REPORTS THE PIN HONESTLY (updated for the ACTIVE bake) ----
  // The silent-downgrade the warning was built for (a LICENCE_TOKEN present with NO pin anywhere) is
  // retired by the baked canonical pin: the shipped state always has a pin, so signerPinConfigured is
  // true with no env var and the licenceSignerWarning can no longer be raised from env alone. The
  // warning branch stays in buildStatus as a guard for a build with the constant blanked.
  //
  // (a) token present + NO env pin -> the BAKED pin reads configured, no warning; the licence still
  // fails open to community here because this test token is signed by the TEST vendor key.
  const downgradeEnv = { LICENCE_TOKEN: good.token } as unknown as Env;
  const downgradeStatus = buildStatus(downgradeEnv, 0);
  ok("status: token present + no env pin -> signerPinConfigured true (baked)", downgradeStatus.signerPinConfigured === true);
  ok("status: token present + no env pin -> NO licenceSignerWarning (pin is baked)", downgradeStatus.licenceSignerWarning === undefined);
  ok("status: the no-env-pin env is community via signature mismatch (fail-open intact)", (await verifyLicence(downgradeEnv)).tier === "community" && (await verifyLicence(downgradeEnv)).reason === "licence signature did not verify under the pinned vendor key");

  // (b) token present + a valid env pin -> signerPinConfigured true + NO warning (and the licence verifies).
  const pinnedStatus = buildStatus({ LICENCE_TOKEN: good.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env, 0);
  ok("status: token present + valid pin -> signerPinConfigured true", pinnedStatus.signerPinConfigured === true);
  ok("status: token present + valid pin -> NO licenceSignerWarning", pinnedStatus.licenceSignerWarning === undefined);

  // (c) NO token at all -> no warning regardless of pin presence (nothing to downgrade), and presence-only:
  // a pin set with no token still reports signerPinConfigured true (this is presence, not validity).
  const noTokenStatus = buildStatus({ LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env, 0);
  ok("status: no token -> no warning even with a pin set", noTokenStatus.licenceSignerWarning === undefined && noTokenStatus.signerPinConfigured === true);
  const bareStatus = buildStatus({} as unknown as Env, 0);
  ok("status: no token + no env pin -> no warning, signerPinConfigured true (baked)", bareStatus.licenceSignerWarning === undefined && bareStatus.signerPinConfigured === true);

  // (d) presence-only, not validity: an INVALID (unparseable) pin still reads signerPinConfigured true and
  // suppresses the warning here (presence is what the onboarding probe reports; GET /admin/licence reports
  // the verdict). This mirrors the rest of buildStatus (a malformed SIGNER_PRIVATE still reads configured).
  const invalidPinStatus = buildStatus({ LICENCE_TOKEN: good.token, LICENCE_SIGNER_PUBLIC: "!!!not-base64url!!!" } as unknown as Env, 0);
  ok("status: token + an invalid (but present) pin -> signerPinConfigured true (presence not validity)", invalidPinStatus.signerPinConfigured === true && invalidPinStatus.licenceSignerWarning === undefined);

  // (e) LICENCE-BINDING-ON-CLAIM: status.cfAccountId, so the console can send it with a
  // self-serve claim. Presence-safe: honestly omitted when CF_ACCOUNT_ID is unset or blank (the common
  // single-account deployment that never sets it), reported trimmed when it is set.
  const withAccountId = buildStatus({ CF_ACCOUNT_ID: "acct-123" } as unknown as Env, 0);
  ok("status: cfAccountId reported when CF_ACCOUNT_ID is set", withAccountId.cfAccountId === "acct-123");
  ok("status: no CF_ACCOUNT_ID -> cfAccountId honestly absent", bareStatus.cfAccountId === undefined);
  const blankAccountId = buildStatus({ CF_ACCOUNT_ID: "   " } as unknown as Env, 0);
  ok("status: a whitespace-only CF_ACCOUNT_ID reads as absent, not a blank string", blankAccountId.cfAccountId === undefined);

  // (e-2) LICENCE-BINDING-ON-CLAIM FOLLOW-UP: the second source. No customer deployment ever
  // writes CF_ACCOUNT_ID (not wrangler.toml, not the deploy script), so (e) above never fires for a stock
  // self-serve engine. verifiedCfAccountId is the engine's OWN proof, persisted in the scheduler DO the
  // first time an attach or an update-apply succeeds (see engine/src/sched/scheduler-do-account-config.ts
  // recordVerifiedEngineAccount), and threaded through as a buildStatus option exactly like the other
  // DO-owned facts (expiryWarnings, restorabilityProven, ...).
  const withVerifiedOnly = buildStatus({} as unknown as Env, 0, { verifiedCfAccountId: "acct-verified-456" });
  ok("status: cfAccountId reported from verifiedCfAccountId when CF_ACCOUNT_ID is unset", withVerifiedOnly.cfAccountId === "acct-verified-456");
  ok("status: neither source -> cfAccountId honestly absent (unchanged)", buildStatus({} as unknown as Env, 0, {}).cfAccountId === undefined);
  const blankVerified = buildStatus({} as unknown as Env, 0, { verifiedCfAccountId: "   " });
  ok("status: a whitespace-only verifiedCfAccountId reads as absent, not a blank string", blankVerified.cfAccountId === undefined);
  // env.CF_ACCOUNT_ID ALWAYS WINS when set, exactly as the field's own doc comment states: an operator who
  // has hand-set the var is authoritative even if the DO also holds an (older, or differently-derived)
  // proof, so the two can never disagree in the console's favour of the wrong one.
  const bothSet = buildStatus({ CF_ACCOUNT_ID: "acct-env-wins" } as unknown as Env, 0, { verifiedCfAccountId: "acct-verified-456" });
  ok("status: env.CF_ACCOUNT_ID wins over verifiedCfAccountId when both are set", bothSet.cfAccountId === "acct-env-wins");

  // ---- PROOF 11: NEW diagnostic signals for the support pack (reasonCode / env-DO fallback / account claim) ----
  // reasonCode splits the coarse "licence malformed" reason into CLOSED causes (the human `reason` strings
  // asserted above are UNCHANGED); the pack reads reasonCode to tell a tamper from a stale client from a
  // future tier from a bad expiry. Each maps to a distinct, reliably-triggerable fault.
  ok("reasonCode: no token -> 'no-token'", (await verifyLicence({ LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env)).reasonCode === "no-token");
  ok("reasonCode: token + explicitly undefined pin -> 'no-pin' (blanked-constant branch)", (await verifyLicenceToken(good.token, undefined, "deploy")).reasonCode === "no-pin");
  ok("reasonCode: token + no env pin -> 'signature' (the baked pin verified and mismatched)", (await verifyLicence({ LICENCE_TOKEN: good.token } as unknown as Env)).reasonCode === "signature");
  ok("reasonCode: token + invalid pin -> 'pin-invalid'", (await verifyLicence({ LICENCE_TOKEN: good.token, LICENCE_SIGNER_PUBLIC: "!!!not-base64url!!!" } as unknown as Env)).reasonCode === "pin-invalid");
  ok("reasonCode: wrong segment count -> 'segments' (and the human reason stays 'licence malformed')", garbage.reasonCode === "segments" && garbage.reason === "licence malformed");
  ok("reasonCode: tampered body (signature mismatch) -> 'signature'", tampered.reasonCode === "signature");
  ok("reasonCode: expired -> 'expired'", expired.reasonCode === "expired");

  // The remaining reasonCodes need a token that VERIFIES but carries a bad body, so sign RAW bytes with the
  // vendor key (mintToken always canonicalises; these deliberately do not). An undecodable segment is caught
  // before verify.
  const signRaw = async (bytes: Uint8Array): Promise<string> => `${b64urlEncode(bytes)}.${b64urlEncode(await hybridSign(vendor.edPrivate, vendor.mldsaSecret, bytes))}`;
  ok("reasonCode: an undecodable segment -> 'decode'", (await verifyLicenceToken("@@@@.AAAA", pinnedPublic)).reasonCode === "decode");
  const nonJson = await signRaw(new TextEncoder().encode("this is not json at all"));
  ok("reasonCode: a verifying token with a non-JSON body -> 'body-malformed'", (await verifyLicenceToken(nonJson, pinnedPublic)).reasonCode === "body-malformed");
  const badShape = await signRaw(canonicalJSON({ account: "a", tier: "enterprise", notAfter: 123, features: [] }));
  ok("reasonCode: a verifying token whose claims fail validation (non-future tier) -> 'body-malformed'", (await verifyLicenceToken(badShape, pinnedPublic)).reasonCode === "body-malformed");
  const nonCanon = await signRaw(new TextEncoder().encode(`{"tier":"enterprise","account":"acme","notAfter":"${future}","features":[]}`));
  ok("reasonCode: a verifying token with a non-canonical body -> 'not-canonical'", (await verifyLicenceToken(nonCanon, pinnedPublic)).reasonCode === "not-canonical");
  // A NON-STRING tier (a number, not an unrecognised tier NAME) is a shape fault, not a future tier: isTier's
  // typeof guard rejects it before the known-tier-set lookup runs, so it takes the SAME body-malformed path as
  // any other wrong-typed field, distinct from "galactic" below (a string, just not in the known seven).
  const numericTier = await signRaw(canonicalJSON({ account: "a", tier: 42, notAfter: future, features: [] }));
  ok("reasonCode: a non-string tier -> 'body-malformed', not 'future-tier'", (await verifyLicenceToken(numericTier, pinnedPublic)).reasonCode === "body-malformed");

  // A well-formed, correctly-SIGNED body carrying a tier this engine does not know is a FUTURE tier: still
  // fail closed to community, but classified distinctly from a corrupt body ("engine too old for licence").
  const futureTierTok = await mintToken(vendor, { account: "acme", tier: "galactic", notAfter: future, features: [] });
  const futureTier = await verifyLicence({ LICENCE_TOKEN: futureTierTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("future/unknown tier -> community + reasonCode 'future-tier', and the tier value never leaks", futureTier.tier === "community" && futureTier.valid === false && futureTier.reasonCode === "future-tier" && !JSON.stringify(futureTier).includes("galactic"));

  // A signed body whose notAfter is a string but unparseable is fail-closed with a DISTINCT reasonCode from
  // a shape-malformed body (so "your expiry field is garbage" is not confused with "the token is corrupt").
  const badExpiryTok = await mintToken(vendor, { account: "acme", tier: "enterprise", notAfter: "not-a-real-date", features: [] });
  const badExpiry = await verifyLicence({ LICENCE_TOKEN: badExpiryTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("unparseable expiry -> community + reasonCode 'unparseable-expiry'", badExpiry.tier === "community" && badExpiry.valid === false && badExpiry.reasonCode === "unparseable-expiry");

  // envTokenPresent (readLicence only): a console token masking a present env token becomes visible.
  const maskEnv = { LICENCE_TOKEN: ent.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env;
  const masked = await readLicence(maskEnv, mockScheduler({ token: good.token, setAt: 9, setBy: null }));
  ok("readLicence flags envTokenPresent when source=console AND an env token exists (stale-console mask)", masked.source === "console" && masked.envTokenPresent === true);
  const noEnvMask = await readLicence({ LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env, mockScheduler({ token: good.token, setAt: 9, setBy: null }));
  ok("readLicence: no env token -> envTokenPresent false + no doReadFellBack on a clean DO read", noEnvMask.source === "console" && noEnvMask.envTokenPresent === false && noEnvMask.doReadFellBack === undefined);

  // doReadFellBack (readLicence only): a DO read that THREW and fell back to the env token is now attributable.
  const fellBack = await readLicence(maskEnv, mockScheduler(null, true));
  ok("readLicence flags doReadFellBack when the DO read threw and it fell back to the env token", fellBack.source === "deploy" && fellBack.doReadFellBack === true && fellBack.envTokenPresent === true);

  // accountClaimMatchesEngine: the signed account claim vs the engine's own CF_ACCOUNT_ID, as a BOOLEAN only
  // (the claim account VALUE is never surfaced, no-custody).
  const acctTok = await mintToken(vendor, { account: "acct-in-licence", tier: "enterprise", notAfter: future, features: [] });
  const acctMatch = await verifyLicence({ LICENCE_TOKEN: acctTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "acct-in-licence" } as unknown as Env);
  ok("accountClaimMatchesEngine true when the claim account == CF_ACCOUNT_ID", acctMatch.valid === true && acctMatch.accountClaimMatchesEngine === true);
  const acctMiss = await verifyLicence({ LICENCE_TOKEN: acctTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "a-different-account" } as unknown as Env);
  ok("accountClaimMatchesEngine false for a mismatch, and the claim account value never surfaces", acctMiss.valid === true && acctMiss.accountClaimMatchesEngine === false && !JSON.stringify(acctMiss).includes("acct-in-licence"));
  const acctUnknown = await verifyLicence({ LICENCE_TOKEN: acctTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("accountClaimMatchesEngine omitted when the engine account tag is unknown (honestly absent)", acctUnknown.valid === true && acctUnknown.accountClaimMatchesEngine === undefined);

  // ---- LICENCE-BINDING-ON-CLAIM: boundAccounts membership, with the v1 fallback intact ----
  // A self-serve token's `account` is a Stripe customer id, never a Cloudflare account. boundAccounts is
  // the list the engine's own account tag is actually checked against once it is present and non-empty.
  const boundTok = await mintToken(vendor, { account: "cus_stripe123", tier: "business-3", notAfter: future, features: [], boundAccounts: ["acct-a", "acct-b"] });
  const boundHit = await verifyLicence({ LICENCE_TOKEN: boundTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "acct-b" } as unknown as Env);
  ok("boundAccounts: true when the engine's account is IN the list (not the first entry either)", boundHit.valid === true && boundHit.accountClaimMatchesEngine === true);
  const boundMiss = await verifyLicence({ LICENCE_TOKEN: boundTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "acct-c" } as unknown as Env);
  ok("boundAccounts: false when the engine's account is NOT in the list, even though it differs from `account` too", boundMiss.valid === true && boundMiss.accountClaimMatchesEngine === false && !JSON.stringify(boundMiss).includes("acct-a"));
  // The Stripe customer id itself must never match: a self-serve customer's own billing id is not a
  // Cloudflare account, and the whole point of this design is that it must never be compared as one.
  const boundVsBilling = await verifyLicence({ LICENCE_TOKEN: boundTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "cus_stripe123" } as unknown as Env);
  ok("boundAccounts: the billing account id is never treated as a bound Cloudflare account", boundVsBilling.accountClaimMatchesEngine === false);
  // An EMPTY boundAccounts list (a self-serve token minted at checkout, before any claim bound it) is
  // treated exactly like an absent one: fall back to the legacy single-account comparison rather than
  // reading an empty list as "matches nothing forever" or "matches everything".
  const emptyBoundTok = await mintToken(vendor, { account: "cus_stripe456", tier: "business-1", notAfter: future, features: [], boundAccounts: [] });
  const emptyBoundFallback = await verifyLicence({ LICENCE_TOKEN: emptyBoundTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "cus_stripe456" } as unknown as Env);
  ok("boundAccounts: an empty list falls back to the legacy account===engineAccountTag comparison", emptyBoundFallback.accountClaimMatchesEngine === true);
  // A pre-existing token with NO boundAccounts key at all (every token minted before this field existed,
  // including every current Enterprise/operator-mint token) must keep verifying and keep the v1 behaviour
  // byte-for-byte: this is the compatibility guarantee the whole field addition depends on.
  const noBoundKey = await mintToken(vendor, { account: "acct-legacy", tier: "enterprise", notAfter: future, features: [] });
  const noBoundResult = await verifyLicence({ LICENCE_TOKEN: noBoundKey.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "acct-legacy" } as unknown as Env);
  ok("boundAccounts absent entirely: verifies exactly as v1 did (no regression for a pre-existing token)", noBoundResult.valid === true && noBoundResult.accountClaimMatchesEngine === true);
  // A malformed boundAccounts (present but not a string array) fails the whole body closed, the same
  // shape discipline `features` already gets: never silently ignored and never a fabricated match/miss.
  const malformedBound = await mintToken(vendor, { account: "acct-x", tier: "business-1", notAfter: future, features: [], boundAccounts: [1, 2, 3] });
  const malformedBoundResult = await verifyLicence({ LICENCE_TOKEN: malformedBound.token, LICENCE_SIGNER_PUBLIC: pinnedPublic, CF_ACCOUNT_ID: "acct-x" } as unknown as Env);
  ok("boundAccounts: a non-string-array value fails the body closed (body-malformed), never ignored", malformedBoundResult.tier === "community" && malformedBoundResult.reasonCode === "body-malformed");

  // ---- PROOF 12: the SEVEN-TIER contract (estate-banded self-serve licensing) ----
  // Pricing restart: business-1/-3/-10/-25 and msp are
  // the known tiers, each verifying to its own granted tier exactly like enterprise always has; their band
  // + service entitlements ride as ordinary feature strings (opaque to the engine, never parsed or
  // enforced -- see docs/CONTROL-PLANE.md). The old starter/growth/business ids are DELETED, not aliased
  // (zero customers, zero minted tokens at the time of the rename; no-legacy). community stays the
  // fail-open default. An unrecognised tier (proven earlier as "galactic", PROOF 11) is UNCHANGED by
  // this widening: the known set is seven members, everything outside it is still future-tier.
  const bandFeaturesFor: Record<string, string[]> = {
    "business-1": ["estates:1", "restore-priority", "standard-support"],
    "business-3": ["estates:3", "restore-priority", "expedited-support"],
    "business-10": ["estates:10", "restore-priority", "priority-support", "drill-review"],
    "business-25": ["estates:25", "restore-priority", "priority-support", "drill-review"],
    msp: ["estates:10", "restore-priority", "msp-operator-contact"],
  };
  for (const tier of ["business-1", "business-3", "business-10", "business-25", "msp"]) {
    const features = bandFeaturesFor[tier]!;
    const tok = await mintToken(vendor, { account: "acme", tier, notAfter: future, features });
    const status = await verifyLicence({ LICENCE_TOKEN: tok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
    ok(`valid ${tier} licence -> tier ${tier}, valid, band features echoed verbatim`, status.tier === tier && status.valid === true && JSON.stringify(status.features) === JSON.stringify(features));
    // Each new tier fails open + expires + tampers exactly like enterprise always has (the verify path
    // is tier-agnostic; these are not per-tier code branches to separately prove one at a time, but a
    // spot check that the widened isTier set did not accidentally special-case one of the five bands).
    const expiredTok = await mintToken(vendor, { account: "acme", tier, notAfter: past, features });
    const expiredStatus = await verifyLicence({ LICENCE_TOKEN: expiredTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
    ok(`expired ${tier} licence -> community (fail-open, unchanged across tiers)`, expiredStatus.tier === "community" && expiredStatus.reason === "licence expired");
  }
  // community itself: still never a minted grant in practice, but a well-formed community token still
  // verifies (isTier accepts it, exactly as before this change) -- proving the widened known-tier set is
  // additive, not a narrowing of what already worked.
  const communityTok = await mintToken(vendor, { account: "acme", tier: "community", notAfter: future, features: [] });
  const communityStatus = await verifyLicence({ LICENCE_TOKEN: communityTok.token, LICENCE_SIGNER_PUBLIC: pinnedPublic } as unknown as Env);
  ok("a well-formed community-tier token still verifies (community remains a known, valid tier)", communityStatus.tier === "community" && communityStatus.valid === true);

  console.log(failures === 0 ? "\nALL LICENCE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
