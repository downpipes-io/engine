// The Durable Object half of the key-install re-wrap: a census of every console-set credential the scheduler
// DO holds, and a compare-and-swap that replaces ONE plaintext credential with its sealed envelope.
//
// WHY IT EXISTS. The router seals a credential under CONFIG_WRAP_KEY at the moment it is saved, and only when
// the engine holds that key. The first run stores the read-only discovery token and a destination secret
// BEFORE the key install sets CONFIG_WRAP_KEY, so both used to stay on the Durable Object plaintext floor
// until the operator saved them again. The key install now calls this census and swaps each plaintext value
// for an envelope the Worker sealed (admin/config-rewrap.ts).
//
// THE KEY NEVER ENTERS THE DO. This module holds no key and runs no crypto beyond a SHA-384 comparison digest.
// The Worker reads the census, seals each value, proves the envelope opens, and posts the envelope back. The
// DO only checks that the stored value is still the plaintext the Worker sealed, then stores the envelope.
//
// EVERY STORE THAT USES THE WRAP, read from the write sites (each maybeWrapConfigSecret call in src/admin):
//   destination        DESTINATIONS_KEY list[].secretAccessKey, and the legacy DEST_CONFIG_KEY record
//                      (router-destinations.ts, CONFIG_SECRET_AAD). Includes the Azure Entra client secret,
//                      which is the same field. The source:"deploy" placeholder holds no credential.
//   discovery-token    DISCOVERY_KEY .token (router-discovery.ts, DISCOVERY_SECRET_AAD)
//   siem-push-header   SIEM_PUSH_CONFIG_KEY .authHeaderValue (router-push.ts, PUSH_SECRET_AAD)
//   siem-push-s3       SIEM_PUSH_CONFIG_KEY .s3Target.secretAccessKey (router-push.ts, PUSH_S3_SECRET_AAD)
//   otlp-push-header   OTLP_PUSH_CONFIG_KEY .authHeaderValue (router-otlp-push.ts, OTLP_PUSH_SECRET_AAD)
//   notify-jsm         notify-channel:<id> .apiKey on a jsm channel (router-ops.ts, JSM_SECRET_AAD)
//   notify-servicenow  notify-channel:<id> .apiKey on a servicenow channel (router-ops.ts, SERVICENOW_SECRET_AAD)
//   idp-client-secret  idpsecret:<id> (router-identity.ts, IDP_SECRET_AAD)
// Deliberately NOT here: a pending dual-control record (owner action or config change) that captured a
// secret. Those records carry an integrity binding over their params, so rewriting a param would make the
// approval refuse. They keep what they captured, and the live record they write on approval is counted by
// the next census.
//
// CRASH SAFETY. A swap is one storage put of the one record that holds the credential, so each credential is
// either still its plaintext (which every read path accepts, with or without a key) or the envelope (which
// every read path opens with the key). There is no state in between. A sweep that stops part way leaves the
// credentials it had not reached as plaintext, and they still work.

import { isWrappedSecret, type WrappedSecret } from "../admin/config-secret.ts";
import { SECRET_PREFIX } from "../admin/oidc-store-kv.ts";
import { NOTIFY_CHANNEL_PREFIX } from "../notify.ts";
import { OTLP_PUSH_CONFIG_KEY, type OtlpPushDestinationRecord, type PushDestinationRecord, SIEM_PUSH_CONFIG_KEY, type DestinationCollection, type DestinationConfig } from "./scheduler-do-limits.ts";
import { DEST_CONFIG_KEY, DESTINATIONS_KEY, DISCOVERY_KEY, type DiscoveryConfig } from "./scheduler-do-records.ts";

// CONFIG_SECRET_CLASSES is the closed set of credential classes the census reports. Each class is one
// domain-separation AAD in admin/config-secret.ts; the Worker maps a class to its AAD, and a class it does not
// know is refused rather than sealed under a guess.
export const CONFIG_SECRET_CLASSES = [
  "destination",
  "discovery-token",
  "siem-push-header",
  "siem-push-s3",
  "otlp-push-header",
  "notify-jsm",
  "notify-servicenow",
  "idp-client-secret",
] as const;
export type ConfigSecretClass = (typeof CONFIG_SECRET_CLASSES)[number];
const CLASS_SET: ReadonlySet<string> = new Set(CONFIG_SECRET_CLASSES);

export function isConfigSecretClass(v: unknown): v is ConfigSecretClass {
  return typeof v === "string" && CLASS_SET.has(v);
}

// The slot names ONE credential inside its class: a destination id (prefixed "list:"), the literal "legacy" for
// the pre-multi-destination record, a notify channel id, an IdP connection id, or "" for a singleton record.
const LEGACY_DEST_SLOT = "legacy";
const DEST_SLOT_PREFIX = "list:";
const SLOT_MAX = 200;

// PlaintextConfigSecret is one credential still on the plaintext floor. value IS the secret: this row crosses
// only the internal DO route the key install reads, and never a console-reachable one.
export interface PlaintextConfigSecret {
  cls: ConfigSecretClass;
  slot: string;
  ref: string; // SHA-384 hex of the value: the compare-and-swap names the plaintext it sealed without resending it
  value: string;
}

export interface ConfigSecretCensus {
  plaintext: PlaintextConfigSecret[];
  wrapped: number; // credentials already held as an envelope
}

// SweepStorage is the get/put/list subset of DurableObjectStorage this module needs, so a validator can drive
// it over the shared in-memory double.
export interface SweepStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  list<T>(opts: { prefix: string }): Promise<Map<string, T>>;
}

// refOf is the SHA-384 hex digest of a plaintext credential. It is a comparison handle only, held for the
// length of one key install, and never stored.
export async function refOf(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-384", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// isPlaintextCredential: a non-empty string is a credential on the floor. An empty string is the absence of
// one (the deploy placeholder destination, a push record with no header secret), so there is nothing to seal.
function isPlaintextCredential(v: unknown): v is string {
  return typeof v === "string" && v !== "";
}

// censusConfigSecrets reads every store listed in the header and returns each plaintext credential with its
// class and slot, plus the count of credentials already sealed. It writes nothing.
export async function censusConfigSecrets(storage: SweepStorage): Promise<ConfigSecretCensus> {
  const plaintext: PlaintextConfigSecret[] = [];
  let wrapped = 0;
  const see = async (cls: ConfigSecretClass, slot: string, v: unknown): Promise<void> => {
    if (isWrappedSecret(v)) {
      wrapped++;
      return;
    }
    if (isPlaintextCredential(v)) plaintext.push({ cls, slot, ref: await refOf(v), value: v });
  };

  const coll = await storage.get<DestinationCollection>(DESTINATIONS_KEY);
  if (coll !== undefined && Array.isArray(coll.list)) {
    for (const d of coll.list) {
      if (d === null || typeof d !== "object" || d.source === "deploy" || typeof d.id !== "string" || d.id === "") continue;
      await see("destination", `${DEST_SLOT_PREFIX}${d.id}`, d.secretAccessKey);
    }
  }
  // The legacy single-destination record is read only to seed an empty collection (loadDestinations), but it
  // still holds the credential it was saved with, so it is part of the floor.
  const legacy = await storage.get<DestinationConfig>(DEST_CONFIG_KEY);
  if (legacy !== undefined && legacy !== null && typeof legacy === "object") await see("destination", LEGACY_DEST_SLOT, legacy.secretAccessKey);

  const disc = await storage.get<DiscoveryConfig>(DISCOVERY_KEY);
  if (disc !== undefined && disc !== null && typeof disc === "object") await see("discovery-token", "", disc.token);

  const push = await storage.get<PushDestinationRecord>(SIEM_PUSH_CONFIG_KEY);
  if (push !== undefined && push !== null && typeof push === "object") {
    await see("siem-push-header", "", push.authHeaderValue);
    if (push.s3Target !== undefined && push.s3Target !== null && typeof push.s3Target === "object") await see("siem-push-s3", "", push.s3Target.secretAccessKey);
  }

  const otlp = await storage.get<OtlpPushDestinationRecord>(OTLP_PUSH_CONFIG_KEY);
  if (otlp !== undefined && otlp !== null && typeof otlp === "object") await see("otlp-push-header", "", otlp.authHeaderValue);

  const channels = await storage.list<{ id?: unknown; kind?: unknown; apiKey?: unknown }>({ prefix: NOTIFY_CHANNEL_PREFIX });
  for (const [key, ch] of channels) {
    if (ch === null || typeof ch !== "object") continue;
    const cls = ch.kind === "jsm" ? "notify-jsm" : ch.kind === "servicenow" ? "notify-servicenow" : null;
    if (cls === null) continue;
    await see(cls, key.slice(NOTIFY_CHANNEL_PREFIX.length), ch.apiKey);
  }

  const idpSecrets = await storage.list<unknown>({ prefix: SECRET_PREFIX });
  for (const [key, v] of idpSecrets) await see("idp-client-secret", key.slice(SECRET_PREFIX.length), v);

  return { plaintext, wrapped };
}

// SwapOutcome is what one compare-and-swap found:
//   swapped          the stored value was the plaintext the Worker sealed; the envelope is now stored (a
//                    retry that finds this same envelope stored also reads as swapped)
//   already-wrapped  the stored value is an envelope already (a save or another sweep got there first)
//   changed          the stored value is a DIFFERENT plaintext (saved after the census); left as it is
//   absent           the record or the credential is gone; nothing to seal
//   refused          the request was malformed (unknown class, bad slot, not an exact envelope); nothing written
export type SwapOutcome = "swapped" | "already-wrapped" | "changed" | "absent" | "refused";

export interface SwapRequest {
  cls?: unknown;
  slot?: unknown;
  ref?: unknown;
  wrapped?: unknown;
}

// isExactEnvelope is isWrappedSecret plus an exact key set, so an envelope with an extra field cannot carry
// anything else into storage.
function isExactEnvelope(v: unknown): v is WrappedSecret {
  return isWrappedSecret(v) && Object.keys(v).length === 3;
}

// judge compares the value stored now with the plaintext the Worker sealed. The stored value being THIS
// envelope already reads as "swapped": that is a retried swap whose first attempt landed before the rollout
// reset lost its answer, and the retry must not count it as someone else's work.
async function judge(current: unknown, ref: string, envelope: WrappedSecret): Promise<SwapOutcome | "match"> {
  if (isWrappedSecret(current)) return current.iv === envelope.iv && current.ct === envelope.ct ? "swapped" : "already-wrapped";
  if (!isPlaintextCredential(current)) return "absent";
  return (await refOf(current)) === ref ? "match" : "changed";
}

// swapConfigSecret replaces ONE plaintext credential with the envelope, but only while the stored value is
// still the plaintext the Worker sealed (compared by digest). Every other field of the record is written back
// unchanged, including a push record's gen, so a delivery in flight still records its outcome.
//
// The caller runs this inside blockConcurrencyWhile: the digest is an await between the read and the write,
// and no other handler may change the record in that gap.
export async function swapConfigSecret(storage: SweepStorage, req: SwapRequest): Promise<SwapOutcome> {
  if (!isConfigSecretClass(req.cls)) return "refused";
  if (typeof req.slot !== "string" || req.slot.length > SLOT_MAX) return "refused";
  if (typeof req.ref !== "string" || !/^[0-9a-f]{96}$/.test(req.ref)) return "refused";
  if (!isExactEnvelope(req.wrapped)) return "refused";
  const { slot, ref } = req;
  const envelope: WrappedSecret = { v: 1, iv: req.wrapped.iv, ct: req.wrapped.ct };

  switch (req.cls) {
    case "destination": {
      if (slot === LEGACY_DEST_SLOT) {
        const rec = await storage.get<DestinationConfig>(DEST_CONFIG_KEY);
        if (rec === undefined || rec === null || typeof rec !== "object") return "absent";
        const v = await judge(rec.secretAccessKey, ref, envelope);
        if (v !== "match") return v;
        await storage.put(DEST_CONFIG_KEY, { ...rec, secretAccessKey: envelope });
        return "swapped";
      }
      if (!slot.startsWith(DEST_SLOT_PREFIX)) return "refused";
      const id = slot.slice(DEST_SLOT_PREFIX.length);
      const coll = await storage.get<DestinationCollection>(DESTINATIONS_KEY);
      if (coll === undefined || coll === null || !Array.isArray(coll.list)) return "absent";
      const idx = coll.list.findIndex((d) => d !== null && typeof d === "object" && d.id === id && d.source !== "deploy");
      if (idx < 0) return "absent";
      const v = await judge(coll.list[idx]!.secretAccessKey, ref, envelope);
      if (v !== "match") return v;
      await storage.put(DESTINATIONS_KEY, { ...coll, list: coll.list.map((d, i) => (i === idx ? { ...d, secretAccessKey: envelope } : d)) });
      return "swapped";
    }
    case "discovery-token": {
      const rec = await storage.get<DiscoveryConfig>(DISCOVERY_KEY);
      if (rec === undefined || rec === null || typeof rec !== "object") return "absent";
      const v = await judge(rec.token, ref, envelope);
      if (v !== "match") return v;
      await storage.put(DISCOVERY_KEY, { ...rec, token: envelope });
      return "swapped";
    }
    case "siem-push-header":
    case "siem-push-s3": {
      const rec = await storage.get<PushDestinationRecord>(SIEM_PUSH_CONFIG_KEY);
      if (rec === undefined || rec === null || typeof rec !== "object") return "absent";
      if (req.cls === "siem-push-header") {
        const v = await judge(rec.authHeaderValue, ref, envelope);
        if (v !== "match") return v;
        await storage.put(SIEM_PUSH_CONFIG_KEY, { ...rec, authHeaderValue: envelope });
        return "swapped";
      }
      if (rec.s3Target === undefined || rec.s3Target === null || typeof rec.s3Target !== "object") return "absent";
      const v = await judge(rec.s3Target.secretAccessKey, ref, envelope);
      if (v !== "match") return v;
      await storage.put(SIEM_PUSH_CONFIG_KEY, { ...rec, s3Target: { ...rec.s3Target, secretAccessKey: envelope } });
      return "swapped";
    }
    case "otlp-push-header": {
      const rec = await storage.get<OtlpPushDestinationRecord>(OTLP_PUSH_CONFIG_KEY);
      if (rec === undefined || rec === null || typeof rec !== "object") return "absent";
      const v = await judge(rec.authHeaderValue, ref, envelope);
      if (v !== "match") return v;
      await storage.put(OTLP_PUSH_CONFIG_KEY, { ...rec, authHeaderValue: envelope });
      return "swapped";
    }
    case "notify-jsm":
    case "notify-servicenow": {
      if (slot === "") return "refused";
      const key = `${NOTIFY_CHANNEL_PREFIX}${slot}`;
      const ch = await storage.get<{ kind?: unknown; apiKey?: unknown }>(key);
      if (ch === undefined || ch === null || typeof ch !== "object") return "absent";
      // The class must still match the channel's kind: a channel re-created as the other kind carries a
      // credential for the other AAD, and sealing it under this one would make it unreadable.
      if (ch.kind !== (req.cls === "notify-jsm" ? "jsm" : "servicenow")) return "changed";
      const v = await judge(ch.apiKey, ref, envelope);
      if (v !== "match") return v;
      await storage.put(key, { ...ch, apiKey: envelope });
      return "swapped";
    }
    case "idp-client-secret": {
      if (slot === "") return "refused";
      const key = `${SECRET_PREFIX}${slot}`;
      const v = await judge(await storage.get<unknown>(key), ref, envelope);
      if (v !== "match") return v;
      await storage.put(key, envelope);
      return "swapped";
    }
  }
}
