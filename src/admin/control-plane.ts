// The SchedulerDO control-plane SIGNED EXPORT + no-custody projection.
//
// All control-plane state (every downpipe, schedule, RBAC role, IdP/dest config, the discovery token,
// the audit chain) lives in ONE singleton SQLite Durable Object. A storage loss of that DO is total
// control-plane amnesia: backups silently STOP and the first caller silently re-bootstraps to Owner.
// The customer's DATA survives (every archive is self-describing in the destination bucket), but the
// OPERATIONS plane does not, and there is no bucket->DO reconcile path.
//
// This module is the PURE (no-`this`, no-env) core of the recovery layer: it defines the additive
// `_RECOVERY/CONTROL-PLANE/` namespace (NO `downpipe/0.1.0` format change -- this is a separate artefact,
// never read by the archive reader / Go CLI / conformance vectors), the no-custody export shape, the
// canonical serialisation, the detached hybrid signature (the SAME Ed25519 + ML-DSA-87 scheme the
// archive root is signed with, so the operator's pinned verifier checks it too), and the structural
// NO-CUSTODY assertion that proves an export carries no plaintext secret.
//
// NO-CUSTODY IS THE HEART. A customer secret leaves the DO ONLY as a CONFIG_WRAP_KEY-wrapped envelope
// (a WrappedSecret, decryptable only by the Worker secret that SURVIVES the wipe). With no
// CONFIG_WRAP_KEY set, a secret is OMITTED and the artefact records `reestablish:true` for it. The
// session signing key and the recovery-code HMACs are NEVER exported (so every session re-auths after a
// DR -- desired). RBAC is subject-keyed, so an Access/OIDC Owner is restored immediately.

// TYPE-ONLY (erased at build; no runtime edge, no cycle): the per-destination export-fault vocabulary is
// OWNED by the module that CLASSIFIES the fault, so the record and the classifier cannot drift apart -- the
// AUTO_HEAL_REFUSAL_CODES lesson, where a hand-copied literal union silently fell behind its own source.
import type { CpExportFailClass } from "../cron/cron-fault-ledger.ts";
import { b64urlDecode, b64urlEncode } from "../crypto/bytes.ts";
import { type HybridVerifier, type HybridVerifyVerdict, hybridSign, hybridVerifyDetailed } from "../crypto/sign.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { Signer } from "../format/writer.ts";
import type { TestDeleteProbe } from "../sched/sched-fault-ledger.ts";
import { isWrappedSecret, type WrappedSecret } from "./config-secret.ts";

// CONTROL_PLANE_PREFIX is the additive recovery namespace in the destination bucket. It is timestamped
// and immutable (WORM-safe): each export is a NEW object, never an overwrite, so multiple generations
// survive and a bucket-write attacker can delete/downgrade but never forge (no SIGNER_PRIVATE).
export const CONTROL_PLANE_PREFIX = "_RECOVERY/CONTROL-PLANE/";

// CONTROL_PLANE_EXPORT_V pins the export layout for forward compatibility.
export const CONTROL_PLANE_EXPORT_V = 1 as const;

// ControlPlaneExportState is the persisted "last export" pointer (the change-gate the cron pass reads):
// the config-version id + content hash the last signed export covered, and when. It holds no secret.
// destCredHash (CPR needs-logging: export-change-gate-misses-cred-rotation) is a fingerprint over the
// export's destination CREDENTIAL material (accessKeyId + the WRAPPED/omitted secret envelope, never
// plaintext), folded into the change-gate so a destination-credential ROTATION -- which does NOT bump the
// config-version content hash -- still triggers a fresh signed export (otherwise the recovery artefact keeps
// a stale, undecryptable credential). Optional so a pointer written before this field existed still reads.
export interface ControlPlaneExportState {
  configVersion: number;
  configContentHash: string;
  exportedAt: string;
  destCredHash?: string;
  // recipientPinHash is part of the CHANGE GATE, and it has to be, or the pin it guards is useless.
  //
  // Adding a recipient changes neither the config content hash nor the destination-credential
  // fingerprint, so without this the gate would classify a recipient swap as "unchanged", skip the
  // export, and leave the last signed artefact recording the OLD, correct set indefinitely. An attacker
  // adding their own public key would be preserved from detection by the very record meant to catch them.
  recipientPinHash?: string;
}

// controlPlaneRecipientPinHash hashes a recipient pin to one comparable string, so the export change-gate
// re-fires the moment the recipient set moves. Fingerprints are already one-way hashes of PUBLIC material,
// so this is a hash of hashes and carries nothing secret.
export async function controlPlaneRecipientPinHash(pin: { breakGlass: string | null; operational: string | null; config: string | null }): Promise<string> {
  const bytes = canonicalJSON([pin.breakGlass, pin.operational, pin.config]);
  const digest = await crypto.subtle.digest("SHA-384", bytes as unknown as ArrayBuffer);
  return `sha384:${[...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// controlPlaneDestCredFingerprint hashes the export's destination CREDENTIAL material so the export
// change-gate re-fires on a credential rotation. It canonicalises only the credential-bearing fields
// (id + accessKeyId + the ExportedSecret union, which is a WrappedSecret envelope or a reestablish marker --
// never a plaintext secret), so the fingerprint changes when a secret is re-wrapped (new iv/ct) or an
// accessKeyId changes, and is stable otherwise. Redaction-safe: it is a one-way SHA-384 hex over
// already-wrapped/omitted material, and even its input carries no plaintext.
export async function controlPlaneDestCredFingerprint(exp: ControlPlaneExport): Promise<string> {
  const material = exp.destinations.map((d) => ({ id: d.id, accessKeyId: d.accessKeyId, secret: d.secret }));
  const bytes = canonicalJSON(material);
  const digest = await crypto.subtle.digest("SHA-384", bytes as unknown as ArrayBuffer);
  return `sha384:${[...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// controlPlaneArtefactKey builds the timestamped artefact key: `_RECOVERY/CONTROL-PLANE/<paddedVersion>-<iso>.json`.
// The config version is zero-padded so a lexicographic bucket list returns generations in order, and the
// ISO timestamp disambiguates two exports of the same version. The `.sig` sibling holds the detached signature.
export function controlPlaneArtefactKey(configVersion: number, iso: string): string {
  const v = String(Math.max(0, Math.floor(configVersion))).padStart(12, "0");
  // The ISO timestamp is filesystem/key-safe (colons -> dashes) so the key is portable across stores.
  const safeIso = iso.replace(/:/g, "-");
  return `${CONTROL_PLANE_PREFIX}${v}-${safeIso}.json`;
}

// ---- The no-custody export shape ----------------------------------------------------------------

// ExportedSecret is how a customer secret rides in the artefact: EITHER a CONFIG_WRAP_KEY-wrapped
// envelope (recoverable only by the surviving Worker secret) OR the omission marker { reestablish:true }
// (no envelope was available -- no CONFIG_WRAP_KEY, or the secret was plaintext at rest -- so the operator
// must re-enter it after reconcile). A plaintext secret string is NEVER a valid ExportedSecret.
export type ExportedSecret = { wrapped: WrappedSecret } | { reestablish: true };

// ExportedDestination is a StoredDestination projected to its NON-SECRET fields plus the wrapped-or-omitted
// principal secret. The accessKeyId is the public credential half (a username-class identifier, stored
// plaintext at rest, never wrapped). The secretAccessKey and any STS externalId are credential-class:
// the secret rides ONLY as an ExportedSecret; the externalId is always omitted (reestablish).
export interface ExportedDestination {
  id: string;
  label: string;
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secret: ExportedSecret;
  setAt: number;
  setBy: string | null;
  verifiedAt: number;
  deleteProbe: TestDeleteProbe;
  worm?: unknown;
  objectLock?: "enforced" | "not-enforced" | "unknown";
  // assumeRole is projected to its NON-SECRET roleArn + durationSeconds only; the externalId
  // (credential-class) is dropped and recorded as needing re-establishment.
  assumeRole?: { roleArn: string; durationSeconds?: number; externalIdReestablish: true };
  addressing?: unknown;
  storageClass?: string;
  pricing?: unknown;
  // azureEntra is the Microsoft Entra service principal's DIRECTORY and APPLICATION ids, and it rides
  // whole because neither is a secret. The principal's client secret is secretAccessKey, which rides as
  // the ExportedSecret above like every other destination credential, so a reconciled Entra destination
  // needs exactly one thing re-entered when no envelope was available, and it is the same one thing a
  // reconciled Shared Key destination needs. Omitting these ids instead would reconcile the destination as
  // a SHARED KEY one, silently changing which identity backups are written as.
  azureEntra?: unknown;
}

// ExportedRole is a bound or pending role grant. A bound grant carries its stable subject (so an
// Access/OIDC Owner is restored to the same authority); a pending invite carries subject "".
export interface ExportedRole {
  subject: string;
  email: string;
  role: string;
  grantedBy: string;
  grantedAt: string;
  expiresAt?: string;
  customRole?: string;
}

// ExportedDiscovery is the account-discovery selection WITHOUT the read-only API token (omitted +
// reestablish): which accounts the token saw, which are browsed, and which is the engine's own.
export interface ExportedDiscovery {
  setAt: number;
  setBy: string | null;
  accountsSeen: { id: string; name: string }[];
  selected: string[];
  engineAccountId: string | null;
  tokenReestablish: true;
}

// ExportedIdpConnection is a NON-SECRET descriptor of an identity-provider connection, carried so a recovery
// operator has an INVENTORY of what to re-establish. An IdP connection is AUTHORITY (it declares which issuer
// may authenticate operators), so it is NEVER auto-applied by a reconcile -- the operator recreates it in the
// console from this checklist (mirroring how RBAC and posture overrides are re-established by a human). The
// confidential client secret is never exported (secretReestablish); the engine holds it write-only and it is
// re-entered. `identity` is the anchor the operator recognises: the issuer (oidc), the authorize URL (oauth2)
// or the IdP entity id (saml). No field here is a secret, so an export carrying it stays no-custody.
export interface ExportedIdpConnection {
  id: string;
  kind: string; // "oidc" | "oauth2" | "saml"
  label: string;
  presetId: string;
  enabled: boolean;
  identity: string;
  clientId?: string; // oidc / oauth2 only (public half); absent for saml
  secretReestablish?: true; // oidc / oauth2 only (a confidential client secret to re-enter); absent for saml
}

// ExportedNotifyChannel is a NON-SECRET descriptor of a notification channel for the recovery inventory. A
// webhook / Slack / Teams URL and a PagerDuty routing key are BEARER credentials (the token usually rides in
// the URL path or query), so they are NEVER carried: only the host (for recognition) plus a presence boolean,
// exactly as the config snapshot redacts them. secretReestablish marks a channel whose URL / routing key must
// be re-entered. A reconcile never auto-applies these (a channel with no secret cannot send; re-established by
// hand), so they are inventory for the checklist. toAddresses are the customer's own addresses, not a secret.
export interface ExportedNotifyChannel {
  id: string;
  kind: string;
  name: string;
  enabled: boolean;
  urlConfigured: boolean;
  urlHost: string | null;
  routingKeyConfigured: boolean;
  toAddresses: string[];
  allowInternalSink?: boolean;
  secretReestablish?: true;
}

// ExportedNotifyRule is a notification routing rule projected to its non-secret fields: scope, severity floor,
// selected events, target channel ids, digest cadence and enablement. All routing metadata, never a secret.
export interface ExportedNotifyRule {
  id: string;
  scope: string; // "global" | "downpipe:<id>"
  minSeverity: string;
  events: string[]; // ["all"] for the all-sentinel
  channelIds: string[];
  digest: string; // "off" | "daily" | "weekly"
  enabled: boolean;
}

// ExportedOrgPolicy carries the non-secret governance gate flags so the reconciled DO restores the same
// posture (dual-control on/off, change-number requirement, break-glass retire). The bootstrap latch is
// re-armed by the reconcile itself (not copied from the export), so it is not carried here.
export interface ExportedOrgPolicy {
  requireConfigApproval: boolean;
  requireChangeNumber?: boolean;
  breakGlassTokenRetired?: boolean;
  // attendedCadenceDays rides the export so a reconciled estate restores the proof rhythm its operator chose.
  // It is safe to carry BECAUSE due is computed from each downpipe's own proof history, which does NOT survive
  // into a fresh account: a recovered estate lands in the never-verified state, not the overdue state, so
  // restoring the interval cannot alert during the recovery itself (Objection 2 in the design).
  attendedCadenceDays?: number;
}

// ControlPlaneExport is the whole signed artefact (the JSON written to the bucket). The detached .sig
// covers canonicalJSON(this object). It carries the priorAuditHead so the reconcile can write a
// control-plane-reconciled BRIDGE event chaining the (now-gone) old audit chain to the new one.
export interface ControlPlaneExport {
  v: typeof CONTROL_PLANE_EXPORT_V;
  exportedAt: string; // RFC-3339 millis
  configVersion: number; // the head config-history id (0 when none), for naming + change-gating
  configContentHash: string; // the head config version's contentHash (or genesis), the change-gate key
  engineAccountId: string | null; // non-secret account id (display/scoping), when known
  priorAuditHead: { headSeq: number; headHash: string };
  downpipes: unknown[]; // DownpipeConfig[] -- non-secret account metadata (binding NAMES only, no values)
  destinations: ExportedDestination[];
  defaultDestinationId: string | null;
  roles: ExportedRole[];
  groupRoles: unknown[]; // GroupRoleEntry[] -- non-secret
  customRoles: unknown[]; // CustomRole[] -- non-secret
  // idpConnections is a non-secret INVENTORY of identity-provider connections for the recovery checklist; it
  // is never auto-applied by a reconcile (an IdP connection is authority, re-established by hand). The client
  // secret is never carried (secretReestablish). Additive: an export built before this field is simply absent.
  idpConnections: ExportedIdpConnection[];
  // notifyChannels / notifyRules are a non-secret INVENTORY of alert routing for the recovery checklist; a
  // channel's URL / routing key is redacted (host + presence) and re-entered, never carried, and a reconcile
  // never auto-applies them. Additive: an export built before these fields is simply absent.
  notifyChannels: ExportedNotifyChannel[];
  notifyRules: ExportedNotifyRule[];
  discovery: ExportedDiscovery | null;
  orgPolicy: ExportedOrgPolicy;
  // reestablish lists the secret CATEGORIES that could not be exported no-custody and must be re-entered
  // after a reconcile (e.g. "destination-credentials", "discovery-token", "idp-secrets",
  // "notify-routing-secrets", "session-keys", "passkeys"). It is human-facing guidance, never a secret.
  reestablish: string[];
  // recipientPin is the set of recipient fingerprints this engine was sealing archives to when the export
  // was written, and it is here rather than in Durable Object storage on purpose.
  //
  // The structural gates require exactly one break-glass recipient and then permit any number of others
  // (format/structural-gates.ts), so a compromised engine, or a mis-set OPERATIONAL_PUBLIC, can add an
  // attacker's public key to every future run and the archives still verify, restore and attest clean. The
  // obvious guard is to pin the expected set and compare, but pinning it in the DO is theatre: the actor who
  // can add a recipient controls the deployed code, therefore the DO, therefore the pin and the check.
  //
  // Recording it in the SIGNED export moves the record off the engine. The export is written to the
  // destination every tick, is signed, and can sit under object lock, so a divergence between what the
  // engine reports today and what a past signed export recorded is visible to anyone reading the bucket,
  // including the offline reader, and is not something the engine can retroactively rewrite.
  //
  // Fingerprints only. These are dpr1: hashes of PUBLIC recipient encodings, so the field carries nothing
  // secret and nothing that helps an attacker who does not already hold the public keys.
  recipientPin?: { breakGlass: string | null; operational: string | null; config: string | null };
}

// serialiseControlPlaneExport is the ONE canonical byte form, used for BOTH the bucket object body and
// the signature. canonicalJSON sorts object keys and forbids non-integer numbers, so the bytes are
// reproducible across the sign and an external re-verify.
export function serialiseControlPlaneExport(exp: ControlPlaneExport): Uint8Array {
  return canonicalJSON(exp);
}

// signControlPlaneExport attaches a DETACHED hybrid signature over the canonical export bytes (b64url).
export async function signControlPlaneExport(signer: Signer, exp: ControlPlaneExport): Promise<string> {
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, serialiseControlPlaneExport(exp));
  return b64urlEncode(sig);
}

// verifyControlPlaneSignatureDetailed is verifyControlPlaneSignature with the verdict it used to throw
// away. TOTAL: it never throws, and it returns the closed HybridVerifyVerdict.
//
// WHY THIS EXISTS. verifyControlPlaneSignature returns a bare `false` for four completely different worlds,
// and the manual recovery routes rendered ONE refusal for all of them -- on the disaster-recovery path, where
// the customer is rebuilding a wiped estate and the verdicts have OPPOSITE remedies:
//
//   sig-decode        the .sig FILE is truncated / half-written. Re-copy the signature. Nothing is wrong.
//   verifier-invalid  the KEY will not import: the kit's signer.pub is corrupt (bit rot, a partially restored
//                     file, the wrong same-size key). Re-copy the key. The export is INTACT.
//   ed25519-mismatch  the export does not match the key: the wrong kit, or someone ALTERED the artefact.
//   mldsa-mismatch    the classical half verified and the post-quantum half did not: a partial/mixed signer
//                     rotation. Never tamper, never random corruption.
//
// The routes previously proxied this with a pure length check on the SIGNATURE STRING, which cannot see the
// key at all -- so a right-length CORRUPT signer.pub was reported as tamper ("the export was modified") when
// the truth was "your kit file is damaged, take another copy". That inversion is the ticket this gap names.
//
// NO-CUSTODY: the return type is a closed 5-member union. No signature material, no verifier bytes and no
// export content can leave through it.
export async function verifyControlPlaneSignatureDetailed(exp: ControlPlaneExport, sig: string, verifier: HybridVerifier): Promise<HybridVerifyVerdict> {
  let bytes: Uint8Array;
  try {
    bytes = b64urlDecode(sig);
  } catch {
    return "sig-decode"; // not base64url at all: the signature FILE is damaged, and nothing was ever checked
  }
  return await hybridVerifyDetailed(verifier, serialiseControlPlaneExport(exp), bytes);
}

// verifyControlPlaneSignature re-derives the canonical bytes and verifies BOTH hybrid halves against the
// operator-pinned verifier (the signer's public halves). It NEVER throws (hybridVerify is total); a
// malformed signature decodes to nothing and fails closed. The boolean form, for the callers that only need
// yes/no; the recovery routes take the detailed verdict above.
export async function verifyControlPlaneSignature(exp: ControlPlaneExport, sig: string, verifier: HybridVerifier): Promise<boolean> {
  return (await verifyControlPlaneSignatureDetailed(exp, sig, verifier)) === "ok";
}

// SECRET_FIELD_NAMES is the denylist of field names that, if they ever carried a PLAINTEXT string in an
// export, would be a no-custody violation. The export builder is redaction-safe by construction (it
// whitelists fields and only ever emits a WrappedSecret envelope or a reestablish marker); this walk is
// the independent defence-in-depth assertion (and the test's no-custody gate).
const SECRET_FIELD_NAMES = new Set<string>([
  "token",
  "secretAccessKey",
  "secret", // a destination's secret must be an ExportedSecret object, NEVER a plaintext string
  "externalId",
  "clientSecret",
  "routingKey",
  "sessionKey",
  "signingKey",
  "privateKey",
  "recoveryCode",
]);

// isPermittedSecretFieldShape gates what a SECRET_FIELD_NAMES field may carry in an export, besides an
// absent value (empty string / null): a WrappedSecret envelope, or the ExportedSecret union
// ({wrapped: WrappedSecret} | {reestablish: true}). Anything else -- an arbitrary object that could nest a
// plaintext under a non-secret-named subfield -- is refused. This is the SHAPE half of the no-custody
// assertion: the string check catches a plaintext string, this catches a smuggled object. Each permitted
// object form is EXACT (a single expected key), so no extra field can ride alongside it.
// isExactWrappedSecret is isWrappedSecret PLUS an exact key-set check (v/iv/ct only). isWrappedSecret is
// deliberately NON-exact (it gates DO-storage reads and must tolerate a forward-compat field), but here --
// the no-custody export gate -- an envelope carrying an EXTRA key could hide a plaintext the walker would
// otherwise skip (it short-circuits on a WrappedSecret shape), so the export assertion demands the exact form.
function isExactWrappedSecret(v: unknown): boolean {
  return isWrappedSecret(v) && Object.keys(v).length === 3;
}

function isPermittedSecretFieldShape(v: unknown): boolean {
  if (v === null) return true;
  if (isExactWrappedSecret(v)) return true;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length === 1 && o.reestablish === true) return true;
    if (keys.length === 1 && isExactWrappedSecret(o.wrapped)) return true;
  }
  return false;
}

// assertNoPlaintextSecretInExport walks the parsed export and THROWS if any secret-named field carries a
// plaintext string OR any non-permitted object shape. A secret-named field must be a WrappedSecret, the
// ExportedSecret union ({wrapped}|{reestablish}), or absent (null / empty string); never a bare string and
// never an arbitrary object that could hide a plaintext. This is the no-custody invariant, asserted
// structurally so it holds even if a future projection change accidentally let a value through.
export function assertNoPlaintextSecretInExport(value: unknown, path = "$"): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) assertNoPlaintextSecretInExport(value[i], `${path}[${i}]`);
    return;
  }
  // An EXACT WrappedSecret (v/iv/ct only) is the permitted encrypted form; do not recurse into its iv/ct
  // (they are b64url ciphertext, not plaintext secrets). A WrappedSecret-SHAPED object carrying an extra key
  // is NOT short-circuited here: it falls through and is walked, so a plaintext smuggled under an extra
  // (e.g. secret-named) key is still caught.
  if (isExactWrappedSecret(value)) return;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_FIELD_NAMES.has(k)) {
      if (typeof v === "string") {
        if (v.length > 0) throw new Error(`no-custody violation: plaintext secret field "${k}" at ${path}`);
        // an empty string is treated as absent (a not-configured secret), allowed
      } else if (!isPermittedSecretFieldShape(v)) {
        throw new Error(`no-custody violation: secret field "${k}" at ${path} is neither a wrapped envelope nor a reestablish marker`);
      }
    }
    assertNoPlaintextSecretInExport(v, `${path}.${k}`);
  }
}

// isControlPlaneExport is a shape gate for a parsed (untrusted) artefact body read back from a bucket,
// before its signature is verified. It checks the version pin and the presence of the structural fields
// the reconcile depends on; the full per-field validation happens in the DO reconcile (which never
// trusts the bytes until the signature verifies anyway).
export function isControlPlaneExport(v: unknown): v is ControlPlaneExport {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.v === CONTROL_PLANE_EXPORT_V &&
    typeof o.exportedAt === "string" &&
    typeof o.configContentHash === "string" &&
    Array.isArray(o.downpipes) &&
    Array.isArray(o.destinations) &&
    Array.isArray(o.roles) &&
    typeof o.priorAuditHead === "object" &&
    o.priorAuditHead !== null
  );
}

// ---- AUTO-RECONCILE-ON-DETECT (the safe auto-heal) ----------------------------------------------
//
// When the cron health pass detects amnesia (config empty but the bucket has runs), the auto-heal scans
// the bucket's recovery namespace and re-applies the LATEST signed export -- but ONLY the no-authority
// "resume" slice (downpipes/schedules/dest-config), so backups RESUME with zero human latency while the
// authority slice (RBAC, the silence-killer latch, the first-Owner bootstrap arm) stays gated behind a
// break-glass confirm. The functions below are the PURE selection primitives the cron pass uses to find,
// disambiguate and reject candidate exports; the verification (signature, no-custody) reuses the existing
// verifyControlPlaneSignature / assertNoPlaintextSecretInExport, and the apply lives in the DO mixin.

// parseControlPlaneArtefactVersion extracts the zero-padded config version from a recovery-artefact key
// (`_RECOVERY/CONTROL-PLANE/<pad12 version>-<iso>.json`). Returns the version integer, or null when the
// key is not a well-formed `.json` artefact under the prefix (a `.sig` sibling, a foreign object, a
// malformed name). The 12-digit pad means a lexicographic key sort is also a version sort.
export function parseControlPlaneArtefactVersion(key: string): number | null {
  if (!key.startsWith(CONTROL_PLANE_PREFIX) || !key.endsWith(".json")) return null;
  // A SEALED generation (`…-<iso>.sealed.json`, S5) also ends with `.json`, but it is NOT a plaintext
  // candidate: it must never be misparsed and handed to the plaintext auto-heal (which would fail the
  // shape check and refuse anyway, but this is the explicit guard). The sealed auto-heal scans it separately.
  if (key.endsWith(".sealed.json")) return null;
  const rest = key.slice(CONTROL_PLANE_PREFIX.length);
  const m = /^(\d{12})-/.exec(rest);
  if (m === null) return null;
  const v = Number(m[1]);
  return Number.isFinite(v) ? v : null;
}

// parseControlPlaneSealedArtefactVersion is the SEALED counterpart: it parses ONLY `…-<iso>.sealed.json`
// keys (never a `.sealed.json.sig` sibling or a plaintext `.json`), returning the padded config version. The
// sealed auto-heal uses this to find sealed generations; the plaintext scanner deliberately skips them (above).
export function parseControlPlaneSealedArtefactVersion(key: string): number | null {
  if (!key.startsWith(CONTROL_PLANE_PREFIX) || !key.endsWith(".sealed.json")) return null;
  const rest = key.slice(CONTROL_PLANE_PREFIX.length);
  const m = /^(\d{12})-/.exec(rest);
  if (m === null) return null;
  const v = Number(m[1]);
  return Number.isFinite(v) ? v : null;
}

// ControlPlaneCandidate is the result of scanning the recovery namespace for the export to auto-apply:
//   { kind:"ok" }        -- a single, signed latest-generation artefact to verify + stage.
//   { kind:"none" }      -- no recovery export exists (nothing to auto-heal; manual reconcile only).
//   { kind:"ambiguous" } -- MORE THAN ONE distinct artefact claims the SAME latest generation. After a
//        total wipe the engine has no memory of which is genuine, so it REFUSES to pick (a bucket-write
//        attacker could otherwise steer the choice); the operator runs the manual break-glass reconcile.
//   { kind:"unsigned" }  -- the latest artefact has no `.sig` sibling, so it cannot be verified; REFUSE
//        rather than fall back to an older generation (an older-generation fallback is a downgrade vector).
export type ControlPlaneCandidate =
  | { kind: "ok"; jsonKey: string; sigKey: string; version: number }
  | { kind: "none" }
  | { kind: "ambiguous"; version: number; count: number }
  | { kind: "unsigned"; version: number; jsonKey: string };

// selectLatestControlPlaneExport picks the SINGLE signed latest-generation export to auto-apply from a
// bucket key listing, or a refusal verdict. It is deliberately strict: it takes the highest config
// version present, REFUSES if more than one distinct artefact claims that version (ambiguity -- the
// engine cannot safely disambiguate after amnesia), and REFUSES if the chosen artefact has no detached
// signature (it never falls back to an older, possibly-rolled-back generation). The caller still verifies
// the signature + no-custody before staging, so a forged body at the top version makes the whole auto-heal
// refuse (fail-safe to the manual path), never silently restore.
export function selectLatestControlPlaneExport(keys: string[]): ControlPlaneCandidate {
  const sigKeys = new Set(keys.filter((k) => k.endsWith(".json.sig")));
  const jsonCandidates: { key: string; version: number }[] = [];
  for (const k of keys) {
    const version = parseControlPlaneArtefactVersion(k);
    if (version !== null) jsonCandidates.push({ key: k, version });
  }
  if (jsonCandidates.length === 0) return { kind: "none" };
  const maxVersion = jsonCandidates.reduce((m, c) => Math.max(m, c.version), -1);
  const top = jsonCandidates.filter((c) => c.version === maxVersion);
  // AMBIGUITY: the change-gated export pass writes at most one artefact per config version, so two
  // distinct artefacts at the SAME top version is an anomaly (an injected sibling, or two engines writing
  // the same bucket). The engine cannot pick safely after a wipe, so refuse and steer to manual reconcile.
  if (top.length > 1) return { kind: "ambiguous", version: maxVersion, count: top.length };
  const jsonKey = top[0]!.key;
  const sigKey = `${jsonKey}.sig`;
  if (!sigKeys.has(sigKey)) return { kind: "unsigned", version: maxVersion, jsonKey };
  return { kind: "ok", jsonKey, sigKey, version: maxVersion };
}

// selectLatestSealedControlPlaneExport is the SEALED counterpart of selectLatestControlPlaneExport: it
// scans for `.sealed.json` generations (with their `.sealed.json.sig` siblings) and returns the single latest
// signed one, or a refusal verdict (none / ambiguous / unsigned) with the SAME discipline: no older-generation
// fallback, refuse on ambiguity, refuse an unsigned latest. The auto-heal prefers a sealed generation over a
// plaintext one when any sealed export exists (sealing supersedes plaintext), which also sidesteps a
// plaintext-vs-sealed version collision during the enable transition.
export function selectLatestSealedControlPlaneExport(keys: string[]): ControlPlaneCandidate {
  const sigKeys = new Set(keys.filter((k) => k.endsWith(".sealed.json.sig")));
  const candidates: { key: string; version: number }[] = [];
  for (const k of keys) {
    const version = parseControlPlaneSealedArtefactVersion(k);
    if (version !== null) candidates.push({ key: k, version });
  }
  if (candidates.length === 0) return { kind: "none" };
  const maxVersion = candidates.reduce((m, c) => Math.max(m, c.version), -1);
  const top = candidates.filter((c) => c.version === maxVersion);
  if (top.length > 1) return { kind: "ambiguous", version: maxVersion, count: top.length };
  const jsonKey = top[0]!.key;
  const sigKey = `${jsonKey}.sig`;
  if (!sigKeys.has(sigKey)) return { kind: "unsigned", version: maxVersion, jsonKey };
  return { kind: "ok", jsonKey, sigKey, version: maxVersion };
}

// plaintextGenerationKeysToPurge lists the PLAINTEXT recovery generations to delete when sealing is enabled:
// each `.json` body that parses as a plaintext generation, plus its `.json.sig` sibling when present. It
// returns ONLY plaintext keys (parseControlPlaneArtefactVersion skips `.sealed.json`), so a SEALED generation
// is NEVER in the purge set. Sealing only closes the metadata once the readable plaintext is gone; the caller
// purges best-effort per destination AFTER a successful sealed write there (so a destination never loses its
// only recovery artefact), and a WORM/object-lock denial simply leaves the plaintext (the off-account sealing
// floor still guards a downgrade). Pure + testable.
export function plaintextGenerationKeysToPurge(keys: string[]): string[] {
  const present = new Set(keys);
  const out: string[] = [];
  for (const k of keys) {
    if (parseControlPlaneArtefactVersion(k) !== null) {
      out.push(k);
      const sig = `${k}.sig`;
      if (present.has(sig)) out.push(sig);
    }
  }
  return out;
}

// candidateVersionMatchesExport is the cross-check selectLatestControlPlaneExport cannot do on its own:
// candidate.version comes from the UNAUTHENTICATED bucket-key filename (a bucket-write attacker chooses
// it), while exp.configVersion is inside the signed body. The exporter derives both from the SAME integer
// at write time (controlPlaneArtefactKey(exp.configVersion, ...)), so a genuine artefact always satisfies
// this; a real, old, validly-signed export copied to a freshly-fabricated higher-version key never does
// (its body's configVersion still names its true, older generation). Pure/no-env, so the caller can assert
// it right after signature verification, before staging anything.
export function candidateVersionMatchesExport(candidate: { version: number }, exp: ControlPlaneExport): boolean {
  return typeof exp.configVersion === "number" && Number.isFinite(exp.configVersion) && exp.configVersion === candidate.version;
}

// sameControlPlaneAccount decides whether an export was produced by the SAME Cloudflare account it is being
// imported into. It is TRUE only when both ids are known AND equal; a null/empty on either side (an export
// built before the engine knew its account, or a fresh engine that has not yet discovered its own) is treated
// as NOT the same, so the estate import fails SAFE to the cross-account path (imported downpipes disabled
// until each source is re-pointed). Pure, so the import's account-identity branch is testable in isolation.
export function sameControlPlaneAccount(exportAccountId: string | null, currentAccountId: string | null): boolean {
  return (
    typeof exportAccountId === "string" &&
    exportAccountId.length > 0 &&
    typeof currentAccountId === "string" &&
    currentAccountId.length > 0 &&
    exportAccountId === currentAccountId
  );
}

// StagedControlPlane is the verified export the auto-heal parked in the DO for the break-glass confirm.
// It carries the export + its detached signature (so the Worker can RE-VERIFY before the authority
// restore), the bucket key it came from, the config version, when it was staged, and whether the
// no-authority RESUME slice has already been auto-applied (so backups have resumed). It holds no plaintext
// secret (the export is no-custody by construction; a dest secret rides only as a wrapped envelope).
export interface StagedControlPlane {
  export: ControlPlaneExport;
  signature: string;
  sourceKey: string;
  version: number;
  stagedAt: string;
  resumeApplied: boolean;
  // Resume-apply OUTCOME diagnostics (CPR needs-logging: autoheal-resume-malformed-downpipe-skip +
  // stale-generation-rollback-after-wipe). When the tolerant auto-heal resume applies the slice, it records
  // how many downpipes were EXPECTED vs how many were SKIPPED (a malformed config is skipped so one bad
  // downpipe never blocks the fleet resuming), the GENERATION it applied (= this export's configVersion, so
  // a signed-but-stale rollback after a wipe is visible) and WHEN. All ints/timestamps, no secret. Optional:
  // absent until the resume actually runs.
  resumeSkipped?: number;
  appliedVersion?: number;
  appliedAt?: string;
}

// AUTO_HEAL_REFUSAL_CODES is the CLOSED reason vocabulary for why the cron auto-heal REFUSED to apply a
// recovery export (stepping back to the manual break-glass path). It is the redaction-safe companion to the
// free-text `reason` (which, on the shape-check path, can embed a secret field name / a JSON path), so the
// support pack can surface WHY the auto-heal refused ("did my control plane recover?") without the
// free text. This runtime tuple is the SINGLE SOURCE OF TRUTH: AutoHealRefusalCode derives from it, and the
// support pack's projection allowlist (support-sections-audit.ts) imports it rather than re-listing the
// codes, so a new refusal reason can never silently drop out of the pack the way "sealed-no-op-key" once did.
export const AUTO_HEAL_REFUSAL_CODES = [
  "no-signer", // the engine has no SIGNER_PRIVATE to verify a candidate
  "no-export", // no signed control-plane export was found in the bucket
  "ambiguous", // multiple artefacts claim the latest generation (cannot disambiguate after a wipe)
  "unsigned", // the latest export has no detached signature
  "unreadable", // the export or its signature could not be read back
  "shape-check", // the export failed the no-custody / shape gate
  "signature", // the export failed signature verification (forged / signer rotated)
  "version-mismatch", // the filename-derived version does not match the signed body's own configVersion (a relabelled/replayed export)
  "sealed-no-op-key", // the latest export is SEALED and this engine has no operational key to open it (break-glass-only posture); recover offline
  // REMOVED: `resume-failed`. A refusal code recorded here LATCHES the auto-heal off -- the health
  // pass reads `if (status.refused !== null) return;` and steps back to the manual break-glass path -- and a
  // resume slice that did not apply is deliberately RETRIED on the next tick, precisely so a transient DO fault
  // cannot strand a customer's recovery in manual. Writing this code would therefore have CHANGED RECOVERY
  // BEHAVIOUR (one blip = no more auto-heal, ever), which is why no site ever wrote it and no site should. The
  // fact itself is not lost: the resume refusal is projected to its own closed class at the site that holds it
  // (cron-fault-ledger noteResumeApplyRefusal) and rides in cronHealth, where it does not disarm anything.
] as const;
export type AutoHealRefusalCode = (typeof AUTO_HEAL_REFUSAL_CODES)[number];

// AUTO_HEAL_SUB_CAUSES is the SECOND axis of the auto-heal refusal: the code says
// WHICH GATE refused; the sub-cause says WHY, and the difference between them is the difference between a
// shrug and a repair.
//
// THE GAP. Backups stay stopped after control-plane amnesia. The pack carries refusedCode and nothing else:
//   "signature"   is a truncated .sig, a rotated signer, and a genuinely tampered artefact -- three incidents,
//                 one code. One means re-copy a file, one means check your key, and one means you have been
//                 attacked; the pack could not tell an operator which.
//   "unreadable"  is a JSON parse fault, a shape-field failure, and a version pin -- collapsed the same way.
//   the sealed-open failure is filed under "shape-check", which erases the actual cause entirely: a
//                 not-a-recipient (this engine's key is not in the capsule), a KEM failure, an AEAD failure
//                 (the body is corrupt or the wrong key opened it) or a corrupt body all read the same.
//
// NO-CUSTODY: every member is a fixed engine token. Nothing derived from the artefact's CONTENT -- no field
// value, no bucket key, no JSON path -- may ever ride here. The shape-field member deliberately says only THAT
// a structural field failed, never WHICH; the free-text `reason` that names it is, and stays, unprojected.
export const AUTO_HEAL_SUB_CAUSES = [
  // --- the SEALED open (today: silently filed as shape-check) ---
  "not-recipient", // the capsule holds no wrap for this engine's operational key: it was sealed to someone else. Recovery is OFFLINE with the break-glass identity, and no retry here will ever work
  "kem-fail", // the KEM decapsulation failed: the operational key does not match the wrap it was offered
  "aead-fail", // the content key opened and the BODY would not decrypt under it: the ciphertext is corrupt
  "body-corrupt", // the body decrypted and is not a control-plane export at all
  // --- the UNREADABLE artefact ---
  "json-parse", // the bytes are not valid JSON: a TRUNCATED object (a half-written PUT), not a signature problem
  "shape-field", // valid JSON that is not a control-plane export: a producer/consumer drift. The FIELD is never named
  "version-pin", // the artefact declares a version this engine will not read
  // --- the SIGNATURE (the three that most need separating) ---
  "sig-decode", // the .sig file is the wrong LENGTH: truncated or half-written. NOT tamper -- take another copy
  "ed25519-mismatch", // NEITHER half verified: the wrong signer key, or the export was modified. Tamper can reach only this one
  "ed25519-only-mismatch", // the POST-QUANTUM half verified and the classical half did not: the ML-DSA half checked these exact bytes under the pinned key, so the artefact is INTACT and the Ed25519 half of the KEY is damaged (or the signer was partially rotated). Never tamper
  "mldsa-mismatch", // the classical half VERIFIED and the post-quantum half did not: a partial / mixed signer rotation, which cannot be random corruption
  "verifier-invalid", // this engine's OWN signer key would not load, so nothing could be checked. The KEY is broken, not the artefact
] as const;
export type AutoHealSubCause = (typeof AUTO_HEAL_SUB_CAUSES)[number];

// CandidateScan is what the auto-heal SAW in the recovery namespace before it picked (or refused). Every count
// is a fact about the bucket LISTING, never its contents.
//
//   artefactsSeen          keys in the recovery prefix at all. ZERO with refusedCode "no-export" means the
//                          namespace is empty; NON-ZERO with "no-export" means artefacts are THERE and not one
//                          of them parses as a generation -- which is the HAND-RENAMED artefact case, silently
//                          ignored today (an operator "tidying up" a bucket can disarm their own recovery).
//   malformedNames         keys that are in the prefix and do not parse as a generation. The count of the above.
//   unsignedCandidates     generations with no .sig sibling: they can never be auto-applied.
//   conflictingAtLatestGen how many artefacts claim the LATEST generation. This is the whole content of the
//                          "ambiguous" refusal, which today says only that it happened -- "two artefacts claim
//                          the latest generation" was not something the code could express.
export interface CandidateScan {
  artefactsSeen: number;
  malformedNames: number;
  unsignedCandidates: number;
  conflictingAtLatestGen: number;
}

// ControlPlaneRecoveryRecord is the DO-stored auto-heal state: EITHER a staged export (the happy path) OR
// a refusal marker (the auto-heal found nothing it could safely apply, so it recorded why and stepped back
// to the manual break-glass path). Storing the refusal stops the cron re-probing + re-alerting every tick.
// `code` is the closed AutoHealRefusalCode (redaction-safe); `reason` stays the operator-facing free text.
export interface ControlPlaneRecoveryRecord {
  staged?: StagedControlPlane;
  // G218: subCause is the closed WHY behind the code, and scan is what the candidate pass actually saw in the
  // bucket. Both are optional (an older record, or a refusal with nothing to add, carries neither).
  refused?: { reason: string; at: string; code?: AutoHealRefusalCode; subCause?: AutoHealSubCause; scan?: CandidateScan };
}

// AmnesiaProbeClass is the CLOSED outcome vocabulary of the cron health pass's amnesia-detection attempt.
// It is the recovery latch's own self-diagnosis: the two blind spots (a wipe leaving only a console-set
// destination = no bucket to probe; a bucket whose account-global RUNLOG is absent/unreadable = misread as
// a brand-new account) previously left NO signal, so a support engineer could not tell "healthy new account"
// from "amnesia the latch could not confirm". Redaction-safe (a closed enum).
export type AmnesiaProbeClass =
  | "not-empty" // the control plane is not empty -> healthy, no amnesia
  | "runs-present" // config empty + the destination bucket's RUNLOG exists -> amnesia CONFIRMED (latch fires)
  | "runlog-absent" // config empty + no RUNLOG in the bucket -> read as a brand-new account (a false-negative if it was really a wipe)
  | "probe-error" // config empty + the RUNLOG existence probe threw (unreadable bucket) -> undetermined
  | "no-resolvable-dest"; // config empty + NO destination resolved to probe (console-only dest after a wipe) -> un-probeable amnesia

// ControlPlaneAmnesiaProbe is the DO-stored record of the last amnesia-detection attempt. Redaction-safe:
// a closed probe-class enum + a clamped timestamp, nothing else.
export interface ControlPlaneAmnesiaProbe {
  probe: AmnesiaProbeClass;
  at: string;
}

// ControlPlaneDeployObservation is the DETERMINISTIC per-tick deploy-identity record (CPR needs-logging:
// version-change-observation-gated / -first-poll-baseline / cfversionid-absent-redeploy-invisible). The cron
// drives it from the Worker (which holds env.CF_VERSION_METADATA); the DO compares the observed identity to
// the stored one and records a baseline (first observation) vs a change (a real deploy). It answers owner-#1
// ("did a deploy drop my bindings?") without depending on someone polling GET /admin/status. Redaction-safe:
// an engine-version string, an opaque cf deploy id, booleans, counts and timestamps, never a secret.
export interface ControlPlaneDeployObservation {
  engineVersion: string;
  cfVersionId?: string; // env.CF_VERSION_METADATA.id (changes every `wrangler deploy`); absent under env-fallback/local
  cfVersionIdAbsent: boolean; // true when no cf deploy id is available (a redeploy is then only visible via engineVersion)
  firstSeenAt: string;
  lastSeenAt: string;
  baselineEstablished: boolean; // true once the first observation established the baseline (so a later change is a real deploy, not a first-poll artefact)
  changesObserved: number; // how many deploy-identity changes have been observed since the baseline
  lastChangeAt?: string; // when the most recent change was observed
}

// ExportSkipReason is the CLOSED reason the control-plane export pass SKIPPED writing a fresh recovery
// generation this tick (leaving the last generation stale). Redaction-safe enum.
export const EXPORT_SKIP_REASONS = [
  "no-signer", // no SIGNER_PRIVATE, so no verifiable artefact can be produced
  "budget-yield", // the subrequest budget yielded before/partway through the export (recovery hygiene runs last)
  "no-destination", // no destination configured to write the recovery artefact to
  "unchanged", // the head posture is unchanged since the last export (the change-gate correctly skipped)
  // Sealing is ENABLED and no recipient public key resolved. sealControlPlaneExport throws on a zero-
  // recipient set, and that throw escaped into the pass-level catch -- so the engine wrote NO recovery
  // artefact at all, on every tick, forever, and the export-health record simply never advanced. The posture
  // check then said "no signed export of your configuration has been written yet" and could not say why it
  // never would be. The remedy (run the key ceremony) is nothing like the other four.
  "empty-recipient-set",
] as const;
export type ExportSkipReason = (typeof EXPORT_SKIP_REASONS)[number];

// ControlPlaneExportHealth is the DO-stored outcome of the last control-plane export pass (CPR needs-logging:
// export-budget-starved-stale-generation + export-per-dest-write-fault). It records whether the pass wrote a
// fresh generation, the closed skip reason when it did not, and the PER-DESTINATION write outcome so a
// partial write (one dest rejected the recovery artefact) is visible. Redaction-safe: a timestamp, a closed
// enum, ints and per-dest {id, ok} booleans (the id is the customer's own console label), never a secret.
export interface ControlPlaneExportHealth {
  at: string;
  skipped?: ExportSkipReason;
  wroteAny: boolean;
  configVersion?: number; // the config generation the export covered (when it wrote / attempted)
  // G202: `reason` is the CLOSED cause a destination refused the recovery artefact (only on ok:false). Without
  // it the self-backup posture check could say "some copies of your configuration are stale or missing" and
  // could not say WHICH destination, nor whether it was a WORM lock (permanent, needs a new key scheme), a
  // rotated CONFIG_WRAP_KEY (the credential cannot be opened at all) or a network blip (self-healing).
  perDest: Array<{ id: string; ok: boolean; reason?: CpExportFailClass }>;
  // The per-dest list is clamped at 64 rows at write time. Without these two fields a large-fleet
  // reader could not tell a destination that was ABSENT from one whose row was DROPPED -- and this record is
  // what decides the self-backup posture check's allDestinationsWrote, so a truncated-away FAILED destination
  // read as fully covered (a missing recovery copy, invisible). perDestTotal is the TRUE uncapped count.
  perDestTotal?: number;
  perDestTruncated?: true;
  // recipientPinDrift compares the recipient fingerprints the engine was sealing to on THIS pass against
  // the set the PREVIOUS signed export recorded. It rides the health record because the comparison can only
  // be made where the recipient publics are readable, which is the cron (env bindings), while the posture
  // check runs in the Durable Object, which holds no env.
  //
  // Counts, not fingerprints. The pin itself is already in the signed export; repeating the values here
  // would put a second copy in the support pack for no gain, and the check only needs to know THAT the set
  // moved and by how much.
  recipientPinDrift?: { matches: boolean; added: number; removed: number };
}

// ControlPlaneImportOutcome is the DO-stored outcome of the last ESTATE IMPORT. Persisted because the
// import's own answer is a one-shot HTTP response body that is long gone by the time a support pack exists.
//
// THE TWO STATES IT SEPARATES, which were byte-identical in the pack (and in the DO, and in the audit trail):
//
//   crossAccount && !accountIdAbsent   a GENUINE cross-account import. Both sides named an account and the
//                                      accounts differ, so every downpipe landed disabled. Remedy: re-point
//                                      every source in the new account.
//   accountIdAbsent                    NEITHER side could name an account. sameControlPlaneAccount fails SAFE
//                                      on the null, so crossAccount comes back TRUE and every downpipe lands
//                                      disabled ANYWAY -- an import that "succeeded" and after which not one
//                                      backup runs. Remedy: there is nothing to re-point. Set CF_ACCOUNT_ID
//                                      (or take a fresh export from an engine that knows its account) and
//                                      re-import. Telling this customer to re-point every source is a day of
//                                      work that fixes nothing.
//
// downpipesDisabled is carried explicitly rather than inferred, so the pack states the CONSEQUENCE ("nothing
// is running") as a fact rather than asking the reader to re-derive it from the other two.
//
// NO-CUSTODY: three booleans, two counts and a clamped timestamp. The account ids themselves NEVER ride here
// (they are the customer's Cloudflare account identifiers, and the pack needs the RELATION, not the values).
export interface ControlPlaneImportOutcome {
  at: string;
  crossAccount: boolean;
  accountIdAbsent: boolean;
  downpipesDisabled: boolean;
  downpipes: number;
  destinations: number;
}

// scanControlPlaneCandidates is the PURE census of the recovery namespace: what the auto-heal actually
// saw before it picked or refused. It is deliberately separate from the two selectors (which decide) so that
// the counts are available on EVERY refusal branch, including the ones that return before a selector runs.
//
// It answers the two questions the refusal codes could not:
//
//   "a hand-renamed artefact is silently ignored"  -> artefactsSeen > 0 with malformedNames == artefactsSeen
//        and a "no-export" refusal. The bucket has recovery artefacts in it and NOT ONE of them parses as a
//        generation, so the auto-heal reports the same "no signed control-plane export was found" as a
//        genuinely empty bucket. An operator tidying up a bucket can disarm their own recovery, and both the
//        engine and the pack would say only that there was nothing there.
//   "'ambiguous' cannot say two artefacts claim the latest generation" -> conflictingAtLatestGen is that
//        number, which is the entire content of the ambiguity and was simply not expressible.
//
// Counts only: no key, no name, no version string ever leaves this function.
//
// @param keys - the bucket listing of the recovery prefix (never retained).
// @returns the four counts.
export function scanControlPlaneCandidates(keys: string[]): CandidateScan {
  // Signature siblings are not artefacts; they are counted only as the presence of a signature for one.
  const isSig = (k: string): boolean => k.endsWith(".sig");
  const artefacts = keys.filter((k) => !isSig(k));
  const sigKeys = new Set(keys.filter(isSig));

  const generations: { key: string; version: number }[] = [];
  let malformedNames = 0;
  for (const k of artefacts) {
    const version = parseControlPlaneSealedArtefactVersion(k) ?? parseControlPlaneArtefactVersion(k);
    if (version === null) malformedNames++;
    else generations.push({ key: k, version });
  }

  const unsignedCandidates = generations.filter((g) => !sigKeys.has(`${g.key}.sig`)).length;

  // The SEALED regime supersedes plaintext, so ambiguity is counted within the regime that would actually be
  // chosen -- exactly as the auto-heal chooses. Counting across both would report a plaintext-vs-sealed pair
  // (which is the NORMAL state during the sealing transition) as a conflict, and a signal that fires on a
  // healthy transition is worse than no signal.
  const sealed = generations.filter((g) => parseControlPlaneSealedArtefactVersion(g.key) !== null);
  const regime = sealed.length > 0 ? sealed : generations;
  let conflictingAtLatestGen = 0;
  if (regime.length > 0) {
    const maxVersion = regime.reduce((m, g) => Math.max(m, g.version), -1);
    const top = regime.filter((g) => g.version === maxVersion);
    if (top.length > 1) conflictingAtLatestGen = top.length;
  }

  return { artefactsSeen: artefacts.length, malformedNames, unsignedCandidates, conflictingAtLatestGen };
}
