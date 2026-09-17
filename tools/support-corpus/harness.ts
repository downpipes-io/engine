// Support-pack fault->bundle CORPUS HARNESS.
//
// Purpose: produce a LABELLED corpus of REAL v:2 support bundles, one per induced fault
// scenario, for the diagnostics-bot's measurement gate (accuracy / Wilson-LB precision /
// silent-miss) and for the coverage matrix (fault CAPTURED in the pack ∧ SURFACED by the bot).
//
// Fidelity model (the F1/F2 lesson -- hand-shaped fixtures mask real bugs):
//   - `buildSupportBundle` / `signedSupportBundle` run REAL (the same projection + closed-vocab
//     gates + real hybrid signing a deployed engine runs).
//   - `runPreflight` + `buildStatus` run REAL: the source-bindings / source-liveness / destination
//     / signer / recipients probes execute their real code against the scenario env; the
//     destination probe performs a real (stubbed-network) S3 HEAD through the real classifier.
//   - The scheduler DO is a route double (the same seam `test/validate-support.ts` validates);
//     every canned payload copies shapes that the REAL DO write-paths are validated to produce
//     (validate-slice / validate-source-faults / validate-support) or that were captured LIVE
//     (diaglab corpus / real-engine fixtures).
//   - ALL network egress is intercepted; an unmatched request THROWS (no accidental cloud calls).
//
// Scenario labels carry the EXPECTED diagnosis class + escalation + signals; the bot-side scorer
// (diagnostics-bot/scripts/score-corpus.ts) enforces them. Engine-side `capture` assertions prove
// the evidence FIELD is present in the bundle (the CAPTURED half) before the bot ever runs.

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { signedSupportBundle, sealedSupportBundle } from "../../src/admin/support.ts";
import { isTier } from "../../src/admin/licence.ts";
import { wrapConfigSecret, type WrappedSecret } from "../../src/admin/config-secret.ts";
import { b64urlDecode, b64urlEncode, concat, sha256Hex, utf8 } from "../../src/crypto/bytes.ts";
import { loadSigner, verifierFrom } from "../../src/keys-env.ts";
import { hybridVerify } from "../../src/crypto/sign.ts";
import { canonicalJSON } from "../../src/format/canonjson.ts";
import { signerFingerprint } from "../../src/format/writer.ts";
import { parseIdentity } from "../../src/crypto/keys.ts";
import { parseWraps, openCapsule } from "../../src/crypto/capsule.ts";
import { hkdfSha384, aesGcmOpen } from "../../src/crypto/primitives.ts";
import { makeSupportRecipient } from "../generate-support-keypair.ts";
import type { Env } from "../../src/env.d.ts";

// ---------------------------------------------------------------------------
// Types

/** A DO route table: pathname -> JSON payload (or a function of the URL + parsed POST body). */
export type RouteValue = unknown | ((url: URL, body: unknown) => unknown);
export type Routes = Record<string, RouteValue>;

/** A network-interception rule (matched in order against the full request URL). */
export interface NetRule {
  re: RegExp;
  status: number;
  body?: string;
  headers?: Record<string, string>;
}

/** The mutable per-scenario world: env + DO routes + network rules. */
export interface World {
  env: Record<string, unknown>;
  routes: Routes;
  net: NetRule[];
}

export interface Scenario {
  id: string;
  title: string;
  domain: string;
  /** Expected PRIMARY diagnosis class (the bot's closed RootCauseClass vocabulary). */
  trueClass: string;
  isFault: boolean;
  /** Expected escalateToHuman verdict. */
  expectEscalate: boolean;
  /** Signals that MUST fire (bot SIGNAL_KEYS names). */
  expectSignals?: string[];
  /** Signals that must NOT fire (discrimination assertions). */
  expectAbsentSignals?: string[];
  /** Out-of-band corroboration the scorer passes to diagnose() (deploy ledger / CoR health). */
  corroboration?: Record<string, unknown>;
  /** Mutate the healthy world into the faulted one. */
  mutate: (w: World) => void;
  /** Engine-side CAPTURE assertions: return failure strings when expected evidence is absent. */
  capture?: (bundle: Record<string, unknown>) => string[];
}

/** One emitted corpus row (superset of the measure-chaos row contract). */
export interface CorpusRow {
  id: string;
  title: string;
  domain: string;
  trueClass: string;
  isFault: boolean;
  expectEscalate: boolean;
  expectSignals: string[];
  expectAbsentSignals: string[];
  corroboration?: Record<string, unknown>;
  innerBody: unknown;
}

// ---------------------------------------------------------------------------
// Key material (generated fresh per emit run; never persisted)

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** An x25519+ML-KEM-1024 recipient public (the BREAK_GLASS_PUBLIC / VENDOR_SUPPORT_PUBLIC form). */
function recipientPublicB64(): string {
  const xPriv = x25519.utils.randomSecretKey();
  const xPub = x25519.getPublicKey(xPriv);
  const kem = ml_kem1024.keygen(randomBytes(64));
  return b64urlEncode(concat(xPub, kem.publicKey));
}

export interface HarnessKeys {
  signerB64: string;
  breakGlassPubB64: string;
  vendorPubB64: string;
  wrapKey: Uint8Array;
  wrapKeyB64: string;
  wrappedDestSecret: WrappedSecret;
}

export async function makeKeys(): Promise<HarnessKeys> {
  const wrapKey = rand(32);
  return {
    signerB64: b64urlEncode(concat(rand(32), rand(32))),
    breakGlassPubB64: recipientPublicB64(),
    vendorPubB64: recipientPublicB64(),
    wrapKey,
    wrapKeyB64: b64urlEncode(wrapKey),
    wrappedDestSecret: await wrapConfigSecret(wrapKey, "corpus-destination-secret-key"),
  };
}

// ---------------------------------------------------------------------------
// Fake platform objects (the lowest seam: where the real platform would be)

/** A healthy KV namespace binding: the liveness probe's list({limit:1}) answers. */
export function liveKvNamespace(): unknown {
  return {
    list: async () => ({ keys: [], list_complete: true }),
    get: async () => null,
    getWithMetadata: async () => ({ value: null, metadata: null }),
  };
}

/** A KV namespace whose backing resource was DELETED at the platform. */
export function deletedKvNamespace(): unknown {
  return {
    list: async () => {
      throw new Error("KV GET failed: 404 not found; namespace was deleted");
    },
    get: async () => {
      throw new Error("KV GET failed: 404 not found; namespace was deleted");
    },
  };
}

// ---------------------------------------------------------------------------
// The HEALTHY world

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export const DEST_HOST = "acct-corpus.r2.cloudflarestorage.com";

/** Healthy network: the destination S3 endpoint answers HEAD _RECOVERY/RUNLOG with 200. */
function healthyNet(): NetRule[] {
  return [{ re: new RegExp(DEST_HOST.replace(/\./g, "\\.")), status: 200, body: "" }];
}

function healthyEnv(keys: HarnessKeys): Record<string, unknown> {
  return {
    SIGNER_PRIVATE: keys.signerB64,
    BREAK_GLASS_PUBLIC: keys.breakGlassPubB64,
    VENDOR_SUPPORT_PUBLIC: keys.vendorPubB64,
    CONFIG_WRAP_KEY: keys.wrapKeyB64,
    SCHEDULER: {},
    RUNSEAL: undefined,
    CF_ACCOUNT_ID: "acct-corpus-lab",
    CF_VERSION_METADATA: { id: "cfv-current-001", tag: "v7" },
    // The healthy fleet's one KV source binding (present + live).
    UPLOADS_KV: liveKvNamespace(),
  };
}

/**
 * The clean-healthy DO route table: one KV downpipe, recent ok run, verified seal, alerting
 * configured + delivering, no fault ring entries, intact audit chain, fresh control-plane export.
 * Every value deliberately chosen so NO bot signal fires -- the emit loop empirically enforces
 * this (a signal firing on this baseline is either an unrealistic default or a bot false-positive;
 * both are findings).
 */
function healthyRoutes(now: number, keys: HarnessKeys): Routes {
  const iso = (t: number): string => new Date(t).toISOString();
  return {
    "/downpipes": [
      {
        config: {
          id: "dp1",
          name: "uploads",
          enabled: true,
          cadenceSeconds: 3600,
          source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "ns-uploads", include: ["uploads/*"], exclude: [] },
        },
        lastRunId: "01RUNOK",
        inFlight: false,
        nextRunAt: now + 30 * MIN,
        cronResolve: { class: "ok", at: now + 30 * MIN },
        lastRestoreTestAt: now - 6 * HOUR,
        lastRestoreTestOk: true,
      },
    ],
    "/history": {
      byDownpipe: {
        dp1: [
          {
            runId: "01RUNOK",
            index: 7,
            startedAt: iso(now - 55 * MIN),
            status: "ok",
            recordCount: 42,
            bytes: 65536,
            durationMs: 1200,
            recordsSkipped: 0,
            recordsIncomplete: 0,
            destinationId: "d-primary",
            sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: 8, at: now - 54 * MIN },
          },
          {
            runId: "01RUNPRV",
            index: 6,
            startedAt: iso(now - 115 * MIN),
            status: "ok",
            recordCount: 41,
            bytes: 64000,
            durationMs: 1100,
            recordsSkipped: 0,
            recordsIncomplete: 0,
            destinationId: "d-primary",
            sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: 8, at: now - 114 * MIN },
          },
        ],
      },
    },
    "/notify/history": [
      { seq: 2, ts: iso(now - 50 * MIN), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
      { seq: 1, ts: iso(now - 2 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
    ],
    "/notify/channels": [{ id: "ch-live", kind: "webhook", url: "https://hooks.example/ok", enabled: true }],
    "/notify/rules": [{ events: "all", minSeverity: "warn", scope: { kind: "global" }, channelIds: ["ch-live"] }],
    "/notify/digest-pending": { count: 0 },
    "/notify/health": { passSkips: 0, recordSkips: 0, parseRejects: 0, feedbackFails: 0 },
    "/notify/cooldowns": { cooldownMs: 3_600_000, alert: [], replication: [] },
    "/canary/transitions": { enabled: true, status: "alive", deadDestinations: 0, transitionCount: 0, transitions: [] },
    "/control-plane/recovery-status": {
      recoveryRequired: false,
      configEmpty: false,
      resumeApplied: false,
      deploy: {
        engineVersion: "0.1.0",
        cfVersionId: "cfv-current-001",
        cfVersionIdAbsent: false,
        baselineEstablished: true,
        changesObserved: 0,
        firstSeenAt: iso(now - 30 * DAY),
        lastSeenAt: iso(now - 5 * MIN),
      },
      exportHealth: { at: iso(now - 20 * MIN), wroteAny: true, configVersion: 7, perDest: [{ id: "d-primary", ok: true }] },
    },
    "/control-plane/export-state": { configVersion: 7, exportedAt: iso(now - 20 * MIN) },
    "/control-plane/export": { destinations: [{ id: "d-primary", secret: { wrapped: keys.wrappedDestSecret } }] },
    "/replication": { byDownpipe: { dp1: { "d-primary": { holdsRunId: "01RUNOK", holdsIndex: 7, lastOk: true, lastAttemptAt: now - 54 * MIN } } } },
    "/seal-faults": { faults: [] },
    "/tick-info": { lastTickAt: now - 3 * MIN },
    "/update-status": { settledHighWaterMark: "0.1.0" },
    "/sources/discovery-config": { config: { engineAccountId: "acct-corpus-lab" } },
    "/scheduler-signals": {
      ticks: [
        // budgetSpent 300 > the free-plan 50-subrequest ceiling: a tick that SURVIVED spending past the
        // cap is the engine's positive paid-plan proof (planTier.paidPlanProven) -- a real fleet that has
        // completed real backups has one, so the healthy baseline carries it.
        { at: now - 8 * MIN, intervalMs: 300_000, due: 1, dispatched: 1, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 300, budgetRemaining: 400, overBudget: false },
        { at: now - 3 * MIN, intervalMs: 300_000, due: 0, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 12, budgetRemaining: 688, overBudget: false },
      ],
      dueIndex: { at: now - 3 * MIN, indexEntriesBeforeRebuild: 1, indexEntriesRequired: 1, dpTotal: 1, matched: true },
      runlog: { counter: 9, maxHistoryIndex: 7 },
      storageFaults: { total: 0, valueTooLarge: 0, putFailed: 0 },
    },
    "/beacon-state": {},
    "/destinations": {
      destinations: [{ id: "d-primary", label: "Primary R2", endpointHost: DEST_HOST, bucket: "corpus-archive", addressing: "path" }],
      defaultId: "d-primary",
    },
    "/expiry/warnings": { expiryWarnings: 0, cleanupPending: 0 },
    "/policy/break-glass-disposal": { bootstrapConsumed: true, breakGlassTokenRetired: false },
    // The healthy lockout pre-flight (defects 31/45, another pass): an Owner passkey enrolled and
    // DEMONSTRATED, recovery codes ready, and every stored role record readable. This route answers the
    // `lockoutPosture` section; without it the baseline would carry a block asserting the account has no Owner.
    "/policy/lockout-preflight": { passkeyOwnerEnrolled: true, passkeyOwnerEvidence: "demonstrated", passkeyWitnessSince: iso(now - 30 * DAY), recoveryReady: true, recoveryReadyReason: "ok", secondOwner: true, rosterUnreadable: 0 },
    "/dest-status": { present: true, endpointHost: DEST_HOST },
    "/dest-config": {
      config: {
        endpoint: `https://${DEST_HOST}`,
        bucket: "corpus-archive",
        region: "auto",
        accessKeyId: "AKIACORPUSLAB",
        secretAccessKey: keys.wrappedDestSecret,
      },
    },
    "/sso-failures": {},
    "/sso-failures-by-kind": {},
    "/auth-signals": {},
    "/auth-posture": {
      sessionSigningKey: { present: true, ageMs: 3 * DAY, adequateLength: true },
      doPlaintextSecretsMissing: 0,
      adminCredentialPaths: { passkeyCredentials: 1, enabledIdpConnections: 1 },
    },
    "/audit/export": (url: URL) => {
      const action = url.searchParams.get("action");
      if (action !== null) return { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(now - MIN) };
      return {
        events: [
          { seq: 11, ts: iso(now - 2 * DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
          { seq: 12, ts: iso(now - DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h11", hash: "sha384:h12" },
        ],
        headSeq: 12,
        headHash: "sha384:h12",
        exportedAt: iso(now - MIN),
      };
    },
    "/audit/verify": { intact: true, checkedThrough: 12, earliestSeq: 1, rolledOver: false, rolledOverCount: 0, auditCount: 12, auditNearCap: false, verify: { at: iso(now - MIN), entriesChecked: 12, durationMs: 3, complete: true } },
    "/drive-budget-yield": { count: 0 },
    "/config-snapshot-health": { count: 0 },
    "/config-history-health": { count: 4, headId: 4, verify: { intact: true, checkedThrough: 4, earliestId: 1 } },
    "/change-control/refusals": { count: 0 },
    "/licence-activation-refusal": { count: 0 },
    "/expiry": [],
    "/status-baseline": { version: "0.1.0", cfVersionId: "cfv-current-001", at: now - 7 * DAY },
    "/ingest-credential": { grant: null },
    "/reconcile-inventory": {},
  };
}

export function healthyWorld(now: number, keys: HarnessKeys): World {
  return { env: healthyEnv(keys), routes: healthyRoutes(now, keys), net: healthyNet() };
}

// ---------------------------------------------------------------------------
// Execution

function stubFromRoutes(routes: Routes): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> } {
  return {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const v = routes[url.pathname];
      if (v === undefined) return new Response(JSON.stringify({}));
      const body = init?.body !== undefined ? (JSON.parse(String(init.body)) as unknown) : undefined;
      const payload = typeof v === "function" ? (v as (u: URL, b: unknown) => unknown)(url, body) : v;
      if (payload instanceof Response) return payload;
      return new Response(JSON.stringify(payload));
    },
  };
}

/** Intercept ALL global fetch: matched rule answers; anything else throws (no silent egress). */
function installNet(rules: NetRule[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : String(input);
    for (const r of rules) {
      if (r.re.test(url)) return new Response(r.body ?? "", { status: r.status, headers: r.headers ?? {} });
    }
    throw new Error(`corpus-harness: unexpected network egress to ${url}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

export interface EmitResult {
  row: CorpusRow;
  captureFailures: string[];
  signatureVerified: boolean;
}

/** Build one scenario's world, emit its REAL signed bundle, and run the capture assertions. */
export async function emitScenario(s: Scenario, keys: HarnessKeys): Promise<EmitResult> {
  const now = Date.now();
  const w = healthyWorld(now, keys);
  s.mutate(w);
  const restore = installNet(w.net);
  let signed: { bundle: Record<string, unknown>; signature: string | null };
  try {
    signed = (await signedSupportBundle(w.env as unknown as Env, stubFromRoutes(w.routes) as never)) as unknown as {
      bundle: Record<string, unknown>;
      signature: string | null;
    };
  } finally {
    restore();
  }

  // Independently re-verify the hybrid signature over the canonical body (real-crypto proof).
  let signatureVerified = false;
  if (typeof signed.signature === "string" && signed.signature !== "" && typeof (w.env as { SIGNER_PRIVATE?: string }).SIGNER_PRIVATE === "string") {
    const signer = await loadSigner((w.env as { SIGNER_PRIVATE: string }).SIGNER_PRIVATE);
    const verifier = verifierFrom(signer);
    signatureVerified = await hybridVerify(verifier, canonicalJSON(signed.bundle), b64urlDecode(signed.signature));
  }

  const captureFailures = s.capture ? s.capture(signed.bundle) : [];
  return {
    row: {
      id: s.id,
      title: s.title,
      domain: s.domain,
      trueClass: s.trueClass,
      isFault: s.isFault,
      expectEscalate: s.expectEscalate,
      expectSignals: s.expectSignals ?? [],
      expectAbsentSignals: s.expectAbsentSignals ?? [],
      ...(s.corroboration !== undefined ? { corroboration: s.corroboration } : {}),
      innerBody: signed.bundle,
    },
    captureFailures,
    signatureVerified,
  };
}

// ---------------------------------------------------------------------------
// Sealed-envelope capture

// The AAD and HKDF-info domain separators of the support-bundle seal; must match
// src/admin/support.ts exactly (the same constants the vendor opener pins).
const SEAL_AAD = "downpipe/engine support-bundle v1";
const SEAL_INFO = "downpipe/engine support-bundle-key v1";

/**
 * One SEALED emission per emit run: the per-scenario loop exercises signedSupportBundle only, so
 * without this the corpus would never prove the ENVELOPE-level contract the intake side consumes,
 * the clear-signed band manifest on a sealed pack. It generates a real vendor support recipient the
 * way tools/emit-real-support-bundle.ts does (KEEPING the private half), seals a healthy-world
 * bundle through the engine's own sealedSupportBundle, and asserts the whole manifest contract
 * harness-side: presence, exact kind, the hybrid signature under the CARRIED keys, the recomputed
 * fingerprint, the bodySha256 binding to the raw ciphertext bytes, agreement of volumes and licence
 * with the unsealed inner bundle, and the envelope `v` mirroring the body `v`. Returns failure
 * strings; the emit run exits non-zero on any.
 */
export async function emitSealedBandCheck(): Promise<string[]> {
  const failures: string[] = [];
  const check = (label: string, cond: boolean): void => {
    if (!cond) failures.push(label);
  };

  const vendor = await makeSupportRecipient();
  const keys = await makeKeys();
  const w = healthyWorld(Date.now(), keys);
  w.env["VENDOR_SUPPORT_PUBLIC"] = b64urlEncode(vendor.recipientPublic);
  const restore = installNet(w.net);
  let sealed: Record<string, unknown>;
  try {
    sealed = (await sealedSupportBundle(w.env as unknown as Env, stubFromRoutes(w.routes) as never)) as Record<string, unknown>;
  } finally {
    restore();
  }
  check("sealed emission produced the sealed envelope kind", sealed["kind"] === "downpipe-support-bundle-sealed");

  // The manifest contract, asserted directly (not via the opener, so a shared bug cannot self-confirm).
  const manifest = sealed["manifest"] as Record<string, unknown> | undefined;
  const manifestSignature = sealed["manifestSignature"];
  check("sealed envelope carries the band manifest", typeof manifest === "object" && manifest !== null);
  check("sealed envelope carries the manifest signature", typeof manifestSignature === "string" && manifestSignature !== "");
  if (typeof manifest !== "object" || manifest === null || typeof manifestSignature !== "string") return failures;
  check("manifest kind is the exact domain label", manifest["kind"] === "downpipe-support-band-manifest");

  const sp = (manifest["signerPublic"] ?? {}) as Record<string, unknown>;
  const ed = typeof sp["ed"] === "string" ? b64urlDecode(sp["ed"]) : new Uint8Array(0);
  const mldsa = typeof sp["mldsa"] === "string" ? b64urlDecode(sp["mldsa"]) : new Uint8Array(0);
  check("carried signer publics have the exact hybrid lengths (32/2592)", ed.length === 32 && mldsa.length === 2592);
  check("manifest signature verifies under the CARRIED keys", await hybridVerify({ ed, mldsa }, canonicalJSON(manifest), b64urlDecode(manifestSignature)));
  check("fingerprint recomputed from the carried keys matches the manifest field", manifest["signerFingerprint"] === (await signerFingerprint({ ed, mldsa })));
  check("bodySha256 equals the sha256 of the raw ciphertext bytes", typeof sealed["ciphertext"] === "string" && manifest["bodySha256"] === (await sha256Hex(b64urlDecode(sealed["ciphertext"] as string))));

  // Unseal with the retained private half and compare the manifest to the inner bundle.
  const capsule = sealed["capsule"] as Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>;
  const k = await openCapsule(parseWraps(capsule), parseIdentity(vendor.identity), utf8(SEAL_AAD));
  const dek = await hkdfSha384(k, new Uint8Array(0), utf8(SEAL_INFO), 32);
  const plain = await aesGcmOpen(dek, b64urlDecode(sealed["iv"] as string), b64urlDecode(sealed["ciphertext"] as string), utf8(SEAL_AAD));
  k.fill(0);
  const inner = JSON.parse(new TextDecoder().decode(plain)) as { v?: number; signerFingerprint?: string; bundle: Record<string, unknown> };

  check("envelope v mirrors the body v", sealed["v"] === (inner.bundle as { v?: number }).v);
  check("manifest signer fingerprint matches the inner bundle's", manifest["signerFingerprint"] === inner.signerFingerprint);

  // volumes: the healthy world has a measured estate, so the manifest must carry the exact pair the
  // inner rollup holds; a faulted rollup would have to read null (never zero-filled).
  const innerVolumes = inner.bundle["volumes"] as { totalProtectedBytes?: unknown; accounts?: unknown } | null;
  const mv = manifest["volumes"] as { totalProtectedBytes?: unknown; accounts?: unknown } | null;
  if (innerVolumes !== null && typeof innerVolumes === "object" && Number.isSafeInteger(innerVolumes.totalProtectedBytes) && Number.isSafeInteger(innerVolumes.accounts)) {
    check(
      "manifest volumes equals the inner rollup pair",
      mv !== null && typeof mv === "object" && mv.totalProtectedBytes === innerVolumes.totalProtectedBytes && mv.accounts === innerVolumes.accounts,
    );
  } else {
    check("manifest volumes is null when the inner rollup is not measurable", mv === null);
  }

  // licence: presence must agree, and the tier rides exactly when the inner tier is a member of the
  // closed vocabulary (the same isTier the engine gates with).
  const innerLicence = inner.bundle["licence"] as { tier?: unknown } | null;
  const mlic = (manifest["licence"] ?? {}) as { present?: unknown; tier?: unknown };
  check("manifest licence.present agrees with the inner bundle", mlic.present === (innerLicence != null));
  const expectedTier = innerLicence !== null && isTier(innerLicence.tier) ? innerLicence.tier : undefined;
  check("manifest licence.tier agrees with the inner bundle (closed vocabulary only)", mlic.tier === expectedTier);

  return failures;
}
