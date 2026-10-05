// The per-destination-id evidence the support pack's destResolution section carries (from engine 0.3.7).
//
// THE GAP IT CLOSES. On engine 0.3.5 a downpipe whose destinationIds named the deploy-time destination
// ("deploy") beside a console destination never wrote to the deploy-time binding: every consumer read the
// resolver's null for that id as "not configured". A reader with only the pack saw replication "not-configured"
// and "origin-dest-unconfigured" and a deleteProbe "other", and inferred the wrong cause, because the pack said
// nothing about HOW each id resolved. This module answers that directly:
//   - resolution: every configured id (each stored row, and every id a downpipe names, including ids with no
//     row) resolved through the real resolveDestination, with the branch it took and its closed refusal;
//   - collection: each stored row's source, the kind the engine would build, whether it is the default, which
//     fields are set (booleans only), and the basis of its deleteProbe verdict;
//   - danglingRefs: each (downpipe, destination id) pair the resolver refuses, and why;
//   - ioTimeouts: which destination id each request timeout hit (dest/dest-io-attribution.ts).
//
// NO-CUSTODY. A destination id is the customer's own label (the class replication[] and downpipes[] already
// carry). Every other field is a closed enum, a boolean or a clamped int: the endpoint, bucket, region and
// credential are read inside dest/factory.ts and never leave it. Every field is re-gated here, at the pack
// boundary, whatever the resolver or the DO returned.

import { DEST_BUILD_CAUSES, destBuildFaultOf } from "../dest/build-health.ts";
import { projectDestIoTimeouts } from "../dest/dest-io-attribution.ts";
import { DEST_RESOLUTION_BRANCHES, type DestResolutionBranch, inspectStoredDestination, resolveDestination } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { TEST_DELETE_PROBES, TEST_STATUS_CLASSES } from "../sched/sched-fault-ledger.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { doURL } from "../do-url.ts";
import { resolveDestKind } from "./status.ts";
import { gateClosed } from "./support-shared.ts";

// How many ids the section resolves, and how many dangling pairs it lists. Above either, it says so.
export const DEST_EVIDENCE_IDS_CAP = 64;
export const DEST_EVIDENCE_DANGLING_CAP = 64;
const ID_MAX = 128;

const BRANCH_SET: ReadonlySet<string> = new Set([...DEST_RESOLUTION_BRANCHES, "error"]);
const REFUSAL_SET: ReadonlySet<string> = new Set(["not-configured", "deploy-binding-missing"]);
const BUILD_CAUSE_SET: ReadonlySet<string> = new Set(DEST_BUILD_CAUSES);
const KIND_SET: ReadonlySet<string> = new Set(["r2", "s3", "gcs", "azure"]);
const STATUS_CLASS_SET: ReadonlySet<string> = new Set(TEST_STATUS_CLASSES);
const DELETE_PROBE_SET: ReadonlySet<string> = new Set(TEST_DELETE_PROBES);

/** A stored row as the DO's redaction-safe /destinations view returns it. */
export interface DestEvidenceStoredRow {
  id?: unknown;
  isDefault?: unknown;
  source?: unknown;
  deleteProbe?: unknown;
  deleteStatusClass?: unknown;
}
/** The slice of a roster row the evidence reads: the ids a downpipe names. */
export interface DestEvidenceDownpipe {
  config?: { id?: unknown; destinationId?: unknown; destinationIds?: unknown };
}

function cleanId(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  let out = "";
  for (const ch of v) {
    const c = ch.charCodeAt(0);
    if (c >= 0x20 && c !== 0x7f) out += ch;
  }
  out = out.slice(0, ID_MAX);
  return out === "" ? undefined : out;
}

// namedIds reads the ids a downpipe's own config names: destinationIds (the list) supersedes the legacy
// destinationId, exactly as the run path reads them.
function namedIds(config: DestEvidenceDownpipe["config"]): string[] {
  if (config === undefined) return [];
  const list = Array.isArray(config.destinationIds) ? config.destinationIds : typeof config.destinationId === "string" ? [config.destinationId] : [];
  const out: string[] = [];
  for (const raw of list) {
    const id = cleanId(raw);
    if (id !== undefined && !out.includes(id)) out.push(id);
  }
  return out;
}

type Resolved = { branch: DestResolutionBranch | "error"; ok: boolean; reason?: string; cause?: string };

async function resolveOne(env: Env, scheduler: DurableObjectStub, id: string | null, wrapKey: Uint8Array | undefined): Promise<Resolved> {
  try {
    const res = await resolveDestination(env, scheduler, id, wrapKey);
    return res.ok ? { branch: res.branch, ok: true } : { branch: res.branch, ok: false, reason: res.reason };
  } catch (e) {
    // The config plane could not answer (the DO read, an incomplete row, a credential that would not open).
    // The closed build cause rides; the message, which can embed an endpoint or a bucket, never does.
    return { branch: "error", ok: false, cause: destBuildFaultOf(e).cause };
  }
}

// gateResolved is the pack-boundary gate over one resolution: every field is a closed member or it is dropped.
function gateResolved(r: Resolved): Record<string, unknown> {
  return {
    branch: gateClosed(r.branch, BRANCH_SET) ?? "error",
    ok: r.ok === true,
    ...(gateClosed(r.reason, REFUSAL_SET) !== undefined ? { reason: gateClosed(r.reason, REFUSAL_SET) } : {}),
    ...(gateClosed(r.cause, BUILD_CAUSE_SET) !== undefined ? { cause: gateClosed(r.cause, BUILD_CAUSE_SET) } : {}),
  };
}

/**
 * gatherDestIdEvidence builds the per-destination-id evidence for the destResolution section. It never throws:
 * a fault in one id's resolution is that id's "error" row, and a fault in a whole read is a flag beside the
 * data that was read.
 *
 * @param env - the Worker environment.
 * @param scheduler - the scheduler DO stub.
 * @param stored - the stored rows from the DO's /destinations view (already read by the caller), or null when
 *   that read faulted.
 * @param downpipes - the downpipe roster, or undefined when the caller has none (the named ids are then absent).
 * @returns the fields to merge into destResolution.
 */
export async function gatherDestIdEvidence(env: Env, scheduler: DurableObjectStub, stored: DestEvidenceStoredRow[] | null, downpipes: DestEvidenceDownpipe[] | undefined): Promise<Record<string, unknown>> {
  let wrapKey: Uint8Array | undefined;
  try {
    wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
  } catch {
    wrapKey = undefined; // a malformed key: each enveloped credential then resolves to its own "error" row
  }
  const storedRows = (stored ?? []).flatMap((r) => {
    const id = cleanId(r.id);
    return id === undefined ? [] : [{ ...r, id }];
  });
  // The configured ids: every stored row, then every id a downpipe names that no row carries.
  const named = new Map<string, number>();
  for (const d of downpipes ?? []) for (const id of namedIds(d.config)) named.set(id, (named.get(id) ?? 0) + 1);
  const all: string[] = [];
  for (const r of storedRows) if (!all.includes(r.id)) all.push(r.id);
  for (const id of named.keys()) if (!all.includes(id)) all.push(id);
  const ids = all.slice(0, DEST_EVIDENCE_IDS_CAP);

  const resolvedById = new Map<string, Resolved>();
  const resolution: Array<Record<string, unknown>> = [];
  for (const id of ids) {
    const r = await resolveOne(env, scheduler, id, wrapKey);
    resolvedById.set(id, r);
    resolution.push({ id, stored: storedRows.some((s) => s.id === id), namedBy: named.get(id) ?? 0, ...gateResolved(r) });
  }
  const defaultResolution = gateResolved(await resolveOne(env, scheduler, null, wrapKey));

  // The redacted collection: one row per stored destination. kind is what the engine would build: the env kind
  // for the deploy-time row, the endpoint's provider for a console row. deleteProbeBasis says whether the
  // deleteProbe verdict was measured at all: the deploy-time row is seeded with "other" and never probed.
  const envKind = resolveDestKind(env, false, undefined).destKind;
  const collection: Array<Record<string, unknown>> = [];
  for (const r of storedRows.slice(0, DEST_EVIDENCE_IDS_CAP)) {
    let inspected: Awaited<ReturnType<typeof inspectStoredDestination>> = null;
    let inspectFailed = false;
    try {
      inspected = await inspectStoredDestination(scheduler, r.id);
    } catch {
      inspectFailed = true;
    }
    const source = inspected?.source ?? (r.source === "deploy" ? "deploy" : "console");
    const kind = gateClosed(source === "deploy" ? (envKind ?? undefined) : (inspected?.provider ?? undefined), KIND_SET);
    const fieldsSet = inspected?.fieldsSet;
    collection.push({
      id: r.id,
      source,
      ...(kind !== undefined ? { kind } : {}),
      isDefault: r.isDefault === true,
      ...(fieldsSet !== undefined ? { fieldsSet: Object.fromEntries(Object.entries(fieldsSet).map(([k, v]) => [k, v === true])) } : {}),
      ...(inspectFailed ? { fieldsUnreadable: true } : {}),
      ...(gateClosed(r.deleteProbe, DELETE_PROBE_SET) !== undefined ? { deleteProbe: gateClosed(r.deleteProbe, DELETE_PROBE_SET) } : {}),
      deleteProbeBasis: source === "deploy" ? "seeded-unprobed" : "probed",
      ...(gateClosed(r.deleteStatusClass, STATUS_CLASS_SET) !== undefined ? { deleteStatusClass: gateClosed(r.deleteStatusClass, STATUS_CLASS_SET) } : {}),
    });
  }

  // danglingRefs: what each refused reference points at. One row per (downpipe, destination id) the resolver
  // refuses, with its closed reason.
  const danglingRefs: Array<Record<string, unknown>> = [];
  let danglingTotal = 0;
  for (const d of downpipes ?? []) {
    const dpId = cleanId(d.config?.id);
    if (dpId === undefined) continue;
    for (const id of namedIds(d.config)) {
      const r = resolvedById.get(id);
      if (r === undefined || r.ok) continue;
      danglingTotal++;
      if (danglingRefs.length < DEST_EVIDENCE_DANGLING_CAP) danglingRefs.push({ downpipeId: dpId, destinationId: id, ...gateResolved(r) });
    }
  }

  let ioTimeouts: Record<string, unknown> | undefined;
  let ioTimeoutsUnavailable = false;
  try {
    const resp = await scheduler.fetch(doURL("/dest-io-timeouts"), { method: "GET" });
    if (resp.ok) ioTimeouts = projectDestIoTimeouts(await resp.json());
    else ioTimeoutsUnavailable = true;
  } catch {
    ioTimeoutsUnavailable = true;
  }

  return {
    resolution,
    ...(all.length > ids.length ? { resolutionTruncated: true, resolutionDropped: all.length - ids.length } : {}),
    defaultResolution,
    collection,
    ...(danglingRefs.length > 0 ? { danglingRefs } : {}),
    ...(danglingTotal > danglingRefs.length ? { danglingRefsTruncated: true, danglingRefsDropped: danglingTotal - danglingRefs.length } : {}),
    ...(ioTimeouts !== undefined ? { ioTimeouts } : {}),
    ...(ioTimeoutsUnavailable ? { ioTimeoutsUnavailable: true } : {}),
  };
}
