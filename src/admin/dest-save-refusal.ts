// dest-save-refusal.ts -- the closed vocabulary for a REFUSED destination save, shared by the router that
// records it (router-destinations.ts), the scheduler DO that writes the row (scheduler-do-audit.ts) and the
// support pack's projection (support-sections-audit.ts). A leaf: it imports nothing from the router or the DO.
//
// A refused add, edit, singular set or singular clear answered 400 and recorded nothing, so a pack from a
// customer who had tried three times showed no attempt. Each refusal now writes ONE failed dest-config-set or
// dest-config-cleared row whose target carries a class from this list, never the engine's sentence (which can
// quote the submitted endpoint, bucket or a store's own error text).

export const DEST_SAVE_REFUSALS = [
  "assume-role-invalid", // the STS AssumeRole policy was submitted but is unusable
  "azure-entra-invalid", // the Microsoft Entra service principal was submitted but is unusable
  "endpoint-not-https", // the endpoint is not an https URL
  "endpoint-unusable", // a well-known store this engine cannot write to (the ADLS Gen2 dfs endpoint)
  "endpoint-invalid", // the endpoint does not parse as a URL
  "endpoint-private", // the endpoint is an internal, private, loopback or link-local address
  "missing-fields", // the bucket or a credential half is absent
  "entra-not-azure", // an Entra service principal on an endpoint that is not Azure Blob
  "addressing-invalid", // the addressing style is not auto, path or vhost
  "storage-class-unsupported", // a storage class that is not immediately readable
  "assume-role-region", // an AssumeRole policy with a region that is not a real AWS region
  "provider-field-refused", // a field the store (Google Cloud Storage or Azure Blob) cannot honour
  "probe-failed", // the live write probe failed; probeClass and probeStatus say how
  "wrap-key-misconfigured", // the engine's CONFIG_WRAP_KEY is unusable
  "worm-policy-invalid", // an immutability policy was submitted but is unusable
  "worm-not-enforceable", // an immutability policy on a bucket that cannot enforce it
  "store-refused", // the scheduler refused the verified destination (a guard, a validator or a change-control rule)
  "clear-in-use", // the singular clear: downpipes still name the default destination
  "clear-orphan-guard", // the singular clear: the default holds the only proven copy of runs
  "clear-refused", // the singular clear was refused for another reason
  "remove-in-use", // the plural remove: downpipes still name the destination
  "remove-orphan-guard", // the plural remove: the destination holds the only proven copy of runs
] as const;
export type DestSaveRefusal = (typeof DEST_SAVE_REFUSALS)[number];
export const DEST_SAVE_REFUSAL_SET: ReadonlySet<string> = new Set(DEST_SAVE_REFUSALS);

// The live probe's closed failure class (owned by the probe classifier), and the providers an endpoint can name.
import { isRegionHint } from "../dest/fault-log.ts";
import { DEST_PROBE_FAIL_CLASSES, type DestProbeFailClass } from "../sched/sched-fault-admin-ledger.ts";
export type { DestProbeFailClass };
export const DEST_PROBE_FAIL_CLASS_SET: ReadonlySet<string> = new Set(DEST_PROBE_FAIL_CLASSES);
export const DEST_REFUSAL_PROVIDERS = ["r2", "s3", "gcs", "azure"] as const;
export type DestRefusalProvider = (typeof DEST_REFUSAL_PROVIDERS)[number];
export const DEST_REFUSAL_PROVIDER_SET: ReadonlySet<string> = new Set(DEST_REFUSAL_PROVIDERS);

/** What the router sends the scheduler to record: closed members and numbers only. */
export interface DestRefusalDetail {
  op: "set" | "clear";
  refusal: DestSaveRefusal;
  id?: string;
  provider?: DestRefusalProvider;
  probeClass?: DestProbeFailClass;
  probeStatus?: number;
  /** The AWS region token a redirected write probe named (closed region shape, never the URL). */
  regionHint?: string;
}

const ID_SLUG = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * sanitiseDestRefusal re-validates a detail at the scheduler boundary, so a drifted caller on the internal route
 * cannot land free text in the chain. An unknown refusal class returns null (nothing is recorded). An id that is
 * not a plain slug is recorded as "unminted" so the row still says it was an edit.
 */
export function sanitiseDestRefusal(raw: unknown): DestRefusalDetail | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.refusal !== "string" || !DEST_SAVE_REFUSAL_SET.has(r.refusal)) return null;
  const out: DestRefusalDetail = { op: r.op === "clear" ? "clear" : "set", refusal: r.refusal as DestSaveRefusal };
  if (typeof r.id === "string" && r.id !== "") out.id = ID_SLUG.test(r.id) ? r.id : "unminted";
  if (typeof r.provider === "string" && DEST_REFUSAL_PROVIDER_SET.has(r.provider)) out.provider = r.provider as DestRefusalProvider;
  if (typeof r.probeClass === "string" && DEST_PROBE_FAIL_CLASS_SET.has(r.probeClass)) out.probeClass = r.probeClass as DestProbeFailClass;
  if (typeof r.probeStatus === "number" && Number.isInteger(r.probeStatus) && r.probeStatus >= 100 && r.probeStatus <= 599) out.probeStatus = r.probeStatus;
  if (isRegionHint(r.regionHint)) out.regionHint = r.regionHint;
  return out;
}
