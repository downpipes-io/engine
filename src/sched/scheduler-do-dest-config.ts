// The archive-destination config subsystem (console-set, owner-exclusive primary + replica
// destinations and their status) is a mixin. DestConfigMixin layers these over a base whose `this`
// is SchedulerDOSurface. The OPT-IN dual-control change-control gate (setRequireConfigApproval + the
// propose/dry-run/approve/reject path + the pending-change inbox) lives in the sibling
// ./scheduler-do-change-control.ts (ChangeControlMixin), and the texts removeDest returns live in
// ./dest-removal-text.ts, kept separate so neither file exceeds the module-size guardrail and each
// text has one source.

import { gateLockFacts } from "../dest/lock-facts.ts";
import { isWrappedSecret, type WrappedSecret } from "../admin/config-secret.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { boundDestPruneMap, type DestPruneState, foldRetentionRecordIntoDestPrune } from "../cron/retention-dest-prune.ts";
import type { RetentionPassRecord } from "../cron/retention-record.ts";
import { validateAddressing, validateAssumeRolePolicy, validateAzureEntraDirectory, validateStorageClass, validateWormPolicyValue } from "../dest/factory.ts";
import { isInternalSinkHost } from "../notify/types.ts";
import { appendDestBlockerRefusalAudit, type DestBlockerFacts } from "./dest-remove-refusal-audit.ts";
import { destInUseRefusal, destOrphanRefusal, destRemovedNotice, type RemovalRisk } from "./dest-removal-text.ts";
import { allDestinationIds } from "./destinations.ts";
import { noteDestinationsChanged } from "./runlog-floor.ts";
import { classifyDestProbeRefusal, destCoercionClasses, recordAdminRefusal, recordCapTruncation, recordConfigCoercion, recordDestResolveFallback, TEST_DELETE_PROBES, TEST_STATUS_CLASSES, type TestDeleteProbe, type TestStatusClass } from "./sched-fault-ledger.ts";
import { AuthError, DEPLOY_DEST_ID, DEST_CONFIG_KEY, DESTINATIONS_KEY, type DestinationCollection, type DestinationConfig, type DestReplState, type DestStatusView, PRIOR_DEFAULT_IDS_MAX, type RunHistoryEntry, type SchedulerDOCtor, type StoredDestination, validateDestPricing } from "./scheduler-do-base.ts";

const TEST_DELETE_PROBE_SET: ReadonlySet<string> = new Set(TEST_DELETE_PROBES);

// A dest-change audit record's before/after summary: the destination ids (identifiers, not display labels, capped at
// DEST_ID_SUMMARY_MAX) and the default id, never a row's configuration. DEST_AUDIT_BEFORE_KEY holds the summary
// the most recent saveDestinations replaced, until the audit record that follows it reads it.
const DEST_AUDIT_BEFORE_KEY = "dest:audit-before";
const DEST_ID_SUMMARY_MAX = 32;
interface DestIdSummary {
  ids: string[];
  defaultId: string;
}
function destIdSummary(c: DestinationCollection | undefined): DestIdSummary {
  return { ids: (c?.list ?? []).map((d) => d.id).slice(0, DEST_ID_SUMMARY_MAX), defaultId: c?.defaultId ?? "" };
}

// The per-destination retention-prune sidecar lives under ONE key as a { [destId]: DestPruneState }
// map ("" = the default slot on an estate with no console destination), bounded to the freshest
// DEST_PRUNE_MAP_MAX rows. Pure diagnostic REFERENCE data (closed enums + clamped counts), structurally
// distinct from every dp:/hist:/repl:/signal: key and never read by any seal/restore path.
const DEST_PRUNE_KEY = "signal:dest-prune";

// classifyDestRejectReason maps a buildDestRecord throw to a CLOSED reject-reason class for the audit
// (never the submitted endpoint/bucket/credential): the two shape errors buildDestRecord raises, else the
// catch-all invalid-config. Used to record a dest-set-validation-reject event without leaking the value.
export function classifyDestRejectReason(e: unknown): "endpoint-not-https" | "missing-fields" | "invalid-config" {
  const msg = e instanceof Error ? e.message : "";
  if (msg.includes("https URL")) return "endpoint-not-https";
  if (msg.includes("bucket, a region")) return "missing-fields";
  return "invalid-config";
}

// rememberPriorDefault records an OUTGOING console default on the collection, most recent first,
// de-duplicated and bounded at PRIOR_DEFAULT_IDS_MAX (overflow drops the oldest). Pure, so the
// removal guard's memory can be driven without a DO.
//
// It is called at BOTH places the default moves: the explicit setDefaultDest repoint, and the silent
// promotion inside removeDest when the destination being removed IS the default. The second one
// matters as much as the first -- a two-destination estate that removes its default promotes the
// survivor, and the removed one is gone anyway, but the SURVIVOR later becomes a prior default in its
// own right when the estate repoints again.
//
// An id equal to the incoming default is not recorded (a no-op repoint remembers nothing), and an
// empty id is ignored (an estate with no destination has no default to remember).
export function rememberPriorDefault(prior: readonly string[] | undefined, outgoingId: string, incomingId: string): string[] {
  if (outgoingId === "" || outgoingId === incomingId) return [...(prior ?? [])];
  return [outgoingId, ...(prior ?? []).filter((x) => x !== outgoingId)].slice(0, PRIOR_DEFAULT_IDS_MAX);
}

// defaultRoutedOriginOf answers the question uncoveredOriginRuns has to answer about a history row
// that carries NO destinationId: could the destination being removed have been the one it sealed to?
//
// A default-routed run seals to whatever the console default was AT THE TIME, and that is not
// recorded anywhere on the row. The answer is therefore "yes" for the current default and for every
// destination remembered as a PRIOR default, and "no" for a destination that has never been the
// default (it cannot have received a default-routed run, so a legitimate removal of a
// never-defaulted replica is not blocked by this arm).
export function couldHaveTakenDefaultRoutedRuns(id: string, defaultId: string | undefined, priorDefaultIds: readonly string[] | undefined): boolean {
  if (defaultId !== undefined && id === defaultId) return true;
  return (priorDefaultIds ?? []).includes(id);
}

// DEPLOY_DEFAULT_SET_REFUSAL is the singular set's refusal while the default is the deploy-time destination
// (setDestConfig). It names the two plural steps that move backups to a new bucket.
export const DEPLOY_DEFAULT_SET_REFUSAL =
  "the default destination is the deploy-time destination. The deploy sets it, so this route cannot change it. First add the new bucket as a destination (POST /admin/destinations), then make it the default (POST /admin/destinations/default).";

// replProof turns one destination's replication record into "does it hold the run at this index": inside its
// PROVEN window [holdsFrom, holdsIndex] (a record with no floor proves no window), or listed in holdsAbove,
// the ring runs it holds above that window. Pure.
function replProof(st: DestReplState): (index: number) => boolean {
  const from = st.holdsFrom ?? Number.POSITIVE_INFINITY;
  const above = new Set(Array.isArray(st.holdsAbove) ? st.holdsAbove : []);
  return (index) => (from <= index && index <= st.holdsIndex) || above.has(index);
}

export function DestConfigMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- archive-destination config (console-set; owner-exclusive; no CLI, no redeploy) ----------

    // loadDestinations reads the multi-destination collection, lazily MIGRATING the legacy single
    // record into it as the "default" on first read so an existing deployment keeps its destination
    // with no operator action. It always returns a well-formed collection: defaultId points at a real
    // entry whenever the list is non-empty (a dangling default is healed to the first entry); an empty
    // list means no destination is configured at all.
    async loadDestinations(): Promise<DestinationCollection> {
      const stored = (await this.state.storage.get(DESTINATIONS_KEY)) as DestinationCollection | undefined;
      if (stored && Array.isArray(stored.list) && stored.list.length > 0) {
        const dangling = !stored.list.some((d) => d.id === stored.defaultId);
        const defaultId = dangling ? stored.list[0]!.id : stored.defaultId;
        // A stored defaultId that names NO live destination is HEALED to the first entry on every read --
        // the data-loss case: the heal is right (a run must never write nowhere) and it silently REPOINTS
        // every downpipe that follows the default -- "my backups are landing in the wrong bucket", with the
        // run row showing the destination actually used and nothing anywhere saying the ENGINE chose it.
        // Recorded as a closed class (never the endpoint, bucket or credential); best-effort, never throws.
        if (dangling) await recordDestResolveFallback(this.state.storage, "dangling-default-healed");
        // priorDefaultIds is CARRIED THROUGH rather than dropped. Every mutator round-trips the
        // collection through loadDestinations -> saveDestinations, so a field this reader did not
        // rebuild would be erased by the next unrelated edit, and the removal guard would lose the
        // record it depends on at the first destination rename.
        return { list: stored.list, defaultId, ...(Array.isArray(stored.priorDefaultIds) ? { priorDefaultIds: stored.priorDefaultIds.filter((x): x is string => typeof x === "string") } : {}) };
      }
      const legacy = (await this.state.storage.get(DEST_CONFIG_KEY)) as DestinationConfig | undefined;
      if (legacy) {
        const seeded: DestinationCollection = { list: [{ ...legacy, id: "default", label: legacy.bucket || "Archive" }], defaultId: "default" };
        await this.state.storage.put(DESTINATIONS_KEY, seeded);
        return seeded;
      }
      return { list: [], defaultId: "" };
    }

    // saveDestinations is the one writer every destination mutation goes through, so it is also where a
    // repointed or removed destination's RUNLOG anti-rollback floor is reset (sched/runlog-floor.ts): a
    // floor describes one bucket, and a new bucket must not inherit it.
    async saveDestinations(c: DestinationCollection): Promise<void> {
      const before = (await this.state.storage.get(DESTINATIONS_KEY)) as DestinationCollection | undefined;
      await this.state.storage.put(DESTINATIONS_KEY, c);
      // The id set and default BEFORE this save, read back by the next successful auditDestChange so the
      // dest-change record carries a before/after summary rather than only its op (from engine 0.3.7).
      await this.state.storage.put(DEST_AUDIT_BEFORE_KEY, destIdSummary(before));
      await noteDestinationsChanged(this.state.storage, before, c, Date.now());
    }

    // getDestConfigById resolves a destination's full config (the run path's credential source). With
    // no id (legacy callers, the drill, an unassigned downpipe) it returns the DEFAULT. With an id it
    // returns that exact destination or null, a dangling reference resolves to null so the run FAILS
    // loudly rather than silently writing to the wrong (default) bucket and splitting the archive.
    async getDestConfigById(id?: string | null): Promise<DestinationConfig | null> {
      const { list, defaultId } = await this.loadDestinations();
      if (list.length === 0) return null;
      if (id) return list.find((d) => d.id === id) ?? null;
      return list.find((d) => d.id === defaultId) ?? null;
    }

    // destStatusOf is the redaction-safe view of one stored destination: where backups go (endpoint
    // host + bucket + region), its id/label/default flag, who set it and when, and the last probe.
    // NEVER the access key or its id.
    destStatusOf(d: StoredDestination, defaultId: string): DestStatusView {
      let endpointHost = d.endpoint;
      try {
        endpointHost = new URL(d.endpoint).host;
      } catch {
        // A malformed stored endpoint still reports honestly (it would also fail the run); the raw
        // value is operator-supplied configuration, not a secret.
      }
      // authMode/assumeRoleArn/azureEntra: non-secret authentication posture. NEVER the externalId, the
      // Entra CLIENT SECRET or the stored credential. The two Entra ids are surfaced so the console can
      // seed its edit form: this boundary rebuilds the stored config from the submitted body, so a
      // destination re-saved from a form that could not show its principal would be stored without one.
      const authMode: "keys" | "sts" | "entra" = d.azureEntra ? "entra" : d.assumeRole ? "sts" : "keys";
      return { present: true, id: d.id, label: d.label, isDefault: d.id === defaultId, endpointHost, bucket: d.bucket, region: d.region, setAt: d.setAt, setBy: d.setBy, verifiedAt: d.verifiedAt, deleteProbe: d.deleteProbe, ...(d.deleteStatusClass ? { deleteStatusClass: d.deleteStatusClass } : {}), ...(d.worm ? { worm: d.worm } : {}), ...(d.objectLock ? { objectLock: d.objectLock } : {}), ...(d.defaultRetention !== undefined ? { defaultRetention: d.defaultRetention } : {}), ...(d.lockMode !== undefined ? { lockMode: d.lockMode } : {}), ...(d.lockRetentionDays !== undefined ? { lockRetentionDays: d.lockRetentionDays } : {}), ...(d.checksumRequired === true ? { checksumRequired: true as const } : {}), authMode, ...(d.assumeRole ? { assumeRoleArn: d.assumeRole.roleArn } : {}), ...(d.azureEntra ? { azureEntra: { tenantId: d.azureEntra.tenantId, clientId: d.azureEntra.clientId } } : {}), ...(d.addressing ? { addressing: d.addressing } : {}), ...(d.storageClass ? { storageClass: d.storageClass } : {}), ...(d.pricing ? { pricing: d.pricing } : {}), ...(d.source ? { source: d.source } : {}) };
    }

    // getDestStatus is the redaction-safe view of the DEFAULT destination (back-compat shape: the
    // singular /dest-status route and /status read it). The prune sidecar row is joined even on an
    // env-configured estate (present: false): there is no StoredDestination row to hang the view on, but
    // the sidecar's default slot ("") still answers "is retention working", and without this join an
    // env-only estate's prune telemetry would never surface anywhere.
    async getDestStatus(): Promise<DestStatusView> {
      const { list, defaultId } = await this.loadDestinations();
      const prune = await this.destPruneMap();
      const d = list.find((x) => x.id === defaultId);
      if (d === undefined) {
        const envRow = prune[""];
        return { present: false, ...(envRow !== undefined ? { lastPrune: envRow } : {}) };
      }
      const row = prune[d.id];
      return { ...this.destStatusOf(d, defaultId), ...(row !== undefined ? { lastPrune: row } : {}) };
    }

    // listDestStatus is the redaction-safe view of EVERY destination plus which id is the default
    // (the console's Destinations list), each joined with its prune sidecar row when one exists.
    async listDestStatus(): Promise<{ destinations: DestStatusView[]; defaultId: string | null }> {
      const { list, defaultId } = await this.loadDestinations();
      const prune = await this.destPruneMap();
      const destinations = list.map((d) => {
        const row = prune[d.id];
        return { ...this.destStatusOf(d, defaultId), ...(row !== undefined ? { lastPrune: row } : {}) };
      });
      return { destinations, defaultId: list.length ? defaultId : null };
    }

    // destPruneMap reads the per-destination retention-prune sidecar rows, keyed by destination id
    // ("" = the default slot on an estate with no console destination). Empty until a pass first posts a
    // record; honest absence is a distinct posture from "the pass ran and did nothing".
    async destPruneMap(): Promise<Record<string, DestPruneState>> {
      return (await this.state.storage.get<Record<string, DestPruneState>>(DEST_PRUNE_KEY)) ?? {};
    }

    // foldDestPruneRecord folds ONE retention pass record into the sidecar rows. Called at the DO's
    // POST /retention-record write boundary AFTER sanitiseRetentionPassRecord has re-run on the posted
    // body (the recordRetentionPass pattern); the pure fold re-checks the closed vocabularies again and
    // coarsens a drifted defer class to "other". The default slot "" is resolved to the CURRENT console
    // default's id so pinned and default-routed prunes of the same bucket share one row; an estate with
    // no console destination keeps "" (the slot getDestStatus joins for the env-configured fallback).
    // Bounded to the freshest DEST_PRUNE_MAP_MAX rows, evictions counted (dest-prune-map), the same
    // discipline as the reconcile signal map.
    async foldDestPruneRecord(rec: RetentionPassRecord): Promise<void> {
      const { defaultId } = await this.loadDestinations();
      const folded = foldRetentionRecordIntoDestPrune(await this.destPruneMap(), rec, defaultId);
      const { map, evicted } = boundDestPruneMap(folded);
      if (evicted > 0) await recordCapTruncation(this.state.storage, "dest-prune-map", evicted);
      await this.state.storage.put(DEST_PRUNE_KEY, map);
    }

    // buildDestRecord validates an incoming destination submission into a stored record (throws -> 400).
    // The router has already proved it live-writable; this is shape defence in depth.
    buildDestRecord(config: unknown, id: string, label: string, caller: { email: string | null } | null): StoredDestination {
      const c = (config ?? {}) as { endpoint?: unknown; bucket?: unknown; region?: unknown; accessKeyId?: unknown; secretAccessKey?: unknown; verifiedAt?: unknown; deleteProbe?: unknown; deleteStatusClass?: unknown; worm?: unknown; objectLock?: unknown; defaultRetention?: unknown; lockMode?: unknown; lockRetentionDays?: unknown; checksumRequired?: unknown; assumeRole?: unknown; addressing?: unknown; storageClass?: unknown; pricing?: unknown; azureEntra?: unknown };
      const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
      const endpoint = str(c.endpoint);
      const bucket = str(c.bucket);
      const region = str(c.region);
      const accessKeyId = str(c.accessKeyId);
      // The secret arrives either as a plaintext string (no CONFIG_WRAP_KEY, the legacy floor) or as a
      // WrappedSecret envelope the router already encrypted (the DO never holds the key). Both are stored
      // verbatim; anything else collapses to "" and is rejected below. The empty string is the only
      // "missing" case (a valid envelope object is never ""), so the existing non-empty guard still holds.
      const secretAccessKey: string | WrappedSecret =
        typeof c.secretAccessKey === "string" ? c.secretAccessKey : isWrappedSecret(c.secretAccessKey) ? c.secretAccessKey : "";
      if (!/^https:\/\/[^\s]+$/.test(endpoint)) throw new Error("the destination endpoint must be an https URL");
      // SSRF screen, defence in depth. admin/router-destinations.ts screens the endpoint an
      // operator SUBMITTED, but this build path alone checks only the shape and the scheme, so any path into
      // the DO that is not that router would store an endpoint nothing had classified: a dual-control approval
      // executing a queued change, a control-plane heal, or a direct DO call. The same classifier the router
      // and the webhook sinks use runs here on the value about to be STORED, so the record cannot hold a
      // private/loopback/link-local endpoint however it arrived.
      //
      // It throws the generic Error class, so classifyDestRejectReason files it as invalid-config rather than
      // a new audit reason: the precise refusal message belongs to the router (the boundary an operator
      // actually sees), and widening the closed audit vocabulary for a defence-in-depth twin would buy
      // nothing the router's own ssrf-endpoint-refused signal does not already record.
      let endpointHost: string;
      try {
        endpointHost = new URL(endpoint).hostname;
      } catch {
        throw new Error("the destination endpoint must be an https URL");
      }
      if (isInternalSinkHost(endpointHost)) {
        throw new Error("the destination endpoint resolves to an internal/private/loopback/link-local address (incl. cloud metadata); these are refused");
      }
      if (bucket === "" || region === "" || accessKeyId === "" || secretAccessKey === "") {
        throw new Error("the destination needs a bucket, a region and both credential halves");
      }
      // pricing is OPTIONAL operator config for the cost estimate; sanitised here, omitted when absent.
      const pricing = validateDestPricing(c.pricing);
      // worm is the OPTIONAL immutability policy, re-validated as defence in depth (the router already
      // validated it); a malformed value is dropped (fail-safe: no false protection). objectLock is the
      // live verdict the router's probe captured, persisted so the redaction-safe status can report REAL
      // enforcement without re-probing on every read.
      const worm = validateWormPolicyValue(c.worm);
      const objectLock = c.objectLock === "enforced" || c.objectLock === "not-enforced" || c.objectLock === "unknown" ? c.objectLock : undefined;
      // defaultRetention is kept only as a real boolean and only beside "enforced", the same gate the router
      // applies, so no path into the DO can store a retention rule on a bucket that applies no lock.
      const defaultRetention = objectLock === "enforced" && typeof c.defaultRetention === "boolean" ? c.defaultRetention : undefined;
      // The default rule's mode and period, re-gated against the closed vocabulary beside "enforced" only.
      const lockFacts = gateLockFacts(objectLock, c.lockMode, c.lockRetentionDays);
      // assumeRole is the OPTIONAL STS policy, re-validated as defence in depth (the router validated it +
      // the region already). A malformed value is dropped (fail-safe). When present, the stored
      // accessKeyId/secretAccessKey are the assume-role principal; the run path mints temp creds per slice.
      const assume = validateAssumeRolePolicy(c.assumeRole);
      const addressing = validateAddressing(c.addressing);
      const storageClass = validateStorageClass(c.storageClass);
      // azureEntra is the OPTIONAL Entra service principal, re-validated here as defence in depth (the
      // router validated and refused it already). Non-secret: the client secret is secretAccessKey, which
      // arrives wrapped-or-plaintext through the one path above. A malformed value is dropped, fail-safe.
      const azureEntra = validateAzureEntraDirectory(c.azureEntra);
      return {
        id,
        label: label.trim() || bucket,
        endpoint,
        bucket,
        region,
        accessKeyId,
        secretAccessKey,
        setAt: Date.now(),
        setBy: caller?.email ? caller.email : null,
        verifiedAt: typeof c.verifiedAt === "number" && Number.isFinite(c.verifiedAt) ? c.verifiedAt : Date.now(),
        // The closed TestDeleteProbe vocabulary, re-gated on the DO write like every other closed
        // field. Coercing to a two-member enum would fold a "transient" probe verdict (a
        // busy store, a dropped socket) into "ok" -- a claim that the destination PRUNES, which the probe has
        // not established. An absent or out-of-vocabulary value keeps the "ok" default.
        deleteProbe: typeof c.deleteProbe === "string" && TEST_DELETE_PROBE_SET.has(c.deleteProbe) ? (c.deleteProbe as TestDeleteProbe) : "ok",
        // The status class behind a delete probe that was not "ok", re-gated like deleteProbe; absent otherwise.
        ...(c.deleteProbe !== "ok" && TEST_DELETE_PROBE_SET.has(c.deleteProbe as string) && typeof c.deleteStatusClass === "string" && (TEST_STATUS_CLASSES as readonly string[]).includes(c.deleteStatusClass) ? { deleteStatusClass: c.deleteStatusClass as TestStatusClass } : {}),
        ...(worm !== null ? { worm } : {}),
        ...(objectLock !== undefined ? { objectLock } : {}),
        ...(defaultRetention !== undefined ? { defaultRetention } : {}),
        ...lockFacts,
        // Only the literal true is kept (the probe learned it); anything else is "not learned", fail-safe in
        // the cheap direction: the destination relearns it on its first refused write.
        ...(c.checksumRequired === true ? { checksumRequired: true as const } : {}),
        ...(assume !== null ? { assumeRole: assume } : {}),
        ...(addressing !== undefined ? { addressing } : {}),
        ...(storageClass !== undefined ? { storageClass } : {}),
        ...(azureEntra !== null ? { azureEntra } : {}),
        ...(pricing !== null ? { pricing } : {}),
      };
    }

    // summariseDestConfig builds the REDACTION-SAFE inbox summary for a destination owner action: the verb +
    // the destination HOST and BUCKET only, NEVER the secret access key (which is in the replay params, like
    // the config-change webhook url, but must never reach the inbox or the audit). A null/clear config reads
    // "clear". It reads only the submitted config's non-secret fields, so an approver sees WHERE backups would
    // be repointed without the credential ever being surfaced. It lives with the destination-config helpers:
    // the owner-action gate (DualControlMixin) calls it through `this` for the dest
    // owner-action inbox summary, exactly as the routing-config dest routes do.
    summariseDestConfig(verb: string, config: unknown): string {
      if (config === null || typeof config !== "object") return `${verb} (clear)`;
      const c = config as { endpoint?: unknown; bucket?: unknown; region?: unknown; worm?: unknown; assumeRole?: unknown; azureEntra?: unknown };
      let host = "";
      if (typeof c.endpoint === "string") {
        try {
          host = new URL(c.endpoint).host;
        } catch {
          host = ""; // a malformed endpoint never leaks; the live verify already ran in the router
        }
      }
      const bucket = typeof c.bucket === "string" ? c.bucket : "";
      const region = typeof c.region === "string" && c.region !== "" ? c.region : "auto";
      // Surface a configured immutability policy in the approval summary: a WORM policy (especially
      // compliance mode) is an irreversible, cost-bearing commitment the second approver must see before
      // they approve, exactly as they see WHERE backups would be repointed. Non-secret (mode + days only).
      const worm = validateWormPolicyValue(c.worm);
      const wormNote = worm ? ` + immutability ${worm.mode} ${worm.retentionDays}d` : "";
      // Surface the authentication mode (and the non-secret role ARN) so the second approver sees whether
      // this destination authenticates with a stored key or by assuming an STS role. The externalId is never
      // shown (credential-class).
      const assume = validateAssumeRolePolicy(c.assumeRole);
      // The Entra principal is named for the same reason the role ARN is: the second approver is being
      // asked to approve WHICH identity backups will be written as, and "a stored account key" and "a
      // service principal in this directory" are different answers with different revocation stories.
      // Both ids are identifiers, never the secret.
      const entra = validateAzureEntraDirectory(c.azureEntra);
      const authNote = assume ? ` + auth STS role ${assume.roleArn}` : entra ? ` + auth Entra app ${entra.clientId} in tenant ${entra.tenantId}` : "";
      return `${verb}: ${bucket || "(bucket)"} at ${host || "(host)"} [${region}]${wormNote}${authNote}`;
    }

    // auditDestChange records a dest-config mutation with the REDACTION-SAFE `dest-change` target (op +
    // operator labels + closed flags/ints only), so the support pack can diagnose the config-change modes the
    // bare dest-config-set/-cleared action name could not: a FORCED-orphan removal (dest-removed-force-
    // orphans-runs), a silent default PROMOTION (dest-default-promotion-silent-redirect), and a REJECTED set
    // (dest-set-validation-reject). The action name + allowlist + semantics are unchanged (still
    // dest-config-set / dest-config-cleared); only the target gains detail, and this is a VERSIONED record of
    // each set/clear/default/remove in the tamper-evident chain (dest-config-not-versioned). outcome is
    // "failed" for a rejected set, "success" otherwise.
    async auditDestChange(
      caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null,
      action: "dest-config-set" | "dest-config-cleared",
      detail: {
        op: "set" | "clear" | "default" | "remove";
        id?: string;
        fromDefaultId?: string;
        toDefaultId?: string;
        force?: boolean;
        uncoveredOriginRunCount?: number;
        rejectReason?: "endpoint-not-https" | "missing-fields" | "invalid-config";
        // This list is the WHOLE contract between the caller below and the target literal, and it is
        // enumerated twice (once here, once as a spread). A field present on the caller, on
        // AuditDestChangeTarget and on the support-pack projection but missing from either copy here is
        // silently dropped: a spread of an object literal into a typed parameter gets no excess-property
        // check, so nothing fails loudly. Anything added to the target type must be added in BOTH places below.
        affectedDownpipeNames?: string[];
      },
    ): Promise<void> {
      // Before/after: AFTER is the collection now; BEFORE is what the save that preceded this record replaced.
      // A rejected set saved nothing, so its before is its after. The stashed before is consumed here.
      const after = destIdSummary(await this.loadDestinations());
      const stashed = await this.state.storage.get<DestIdSummary>(DEST_AUDIT_BEFORE_KEY);
      await this.state.storage.delete(DEST_AUDIT_BEFORE_KEY);
      const before = !detail.rejectReason && stashed !== undefined ? stashed : after;
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action,
        outcome: detail.rejectReason ? "failed" : "success",
        target: {
          kind: "dest-change",
          op: detail.op,
          idsBefore: before.ids,
          idsAfter: after.ids,
          ...(before.defaultId !== "" ? { defaultBefore: before.defaultId } : {}),
          ...(after.defaultId !== "" ? { defaultAfter: after.defaultId } : {}),
          ...(detail.id ? { id: detail.id } : {}),
          ...(detail.fromDefaultId ? { fromDefaultId: detail.fromDefaultId } : {}),
          ...(detail.toDefaultId ? { toDefaultId: detail.toDefaultId } : {}),
          ...(detail.force !== undefined ? { force: detail.force } : {}),
          ...(detail.uncoveredOriginRunCount !== undefined ? { uncoveredOriginRunCount: detail.uncoveredOriginRunCount } : {}),
          ...(detail.rejectReason ? { rejectReason: detail.rejectReason } : {}),
          ...(detail.affectedDownpipeNames !== undefined && detail.affectedDownpipeNames.length > 0 ? { affectedDownpipeNames: detail.affectedDownpipeNames } : {}),
        },
      });
    }

    // setDestConfig is the SINGULAR set/clear, mapped onto the DEFAULT destination (back-compat for the
    // /destination route). config:null clears the default (promoting the next remaining destination, if
    // any, so unassigned downpipes still resolve one); a config updates the default in place (keeping
    // its id), or creates the first destination when none exists. OWNER-EXCLUSIVE (defence in depth).
    //
    // Two refusals keep this route from moving backups without a record of where they went:
    //   - A config while the default is the deploy-time destination (the stored "deploy" row, or no stored
    //     destination while the router reports an env destination in envDestConfigured). An in-place update
    //     would store the new bucket under the reserved id "deploy". A default-routed downpipe then seals to
    //     the new bucket and records "deploy" as the origin, and every read by that id (restore, drill,
    //     replication, prune) resolves "deploy" to the env binding, which does not hold those runs. A
    //     downpipe that names "deploy" keeps sealing to the deploy-time bucket. The plural add seeds the
    //     "deploy" row and stamps the history before the new destination joins, so the refusal names it.
    //   - A clear while downpipes name the default, or while the default holds the only proven copy of runs.
    //     These are removeDest's in-use and orphan guards on the same scan (removalScan), with the same text.
    //     This route has no force; the plural remove is the one override.
    async setDestConfig(
      req: { config?: unknown; envDestConfigured?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<DestStatusView> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may set or clear the archive destination");
      const coll = await this.loadDestinations();
      if (req.config === null && coll.defaultId !== "") {
        const { pinned, pinnedIds, atRisk } = await this.removalScan(coll.defaultId, coll);
        // Each refusal also writes the row that says what blocked it (the destination, the downpipes that name it,
        // the runs at risk), so the pack answers "why was the clear refused" without the sentence.
        if (pinned.length > 0) {
          await recordAdminRefusal(this.state.storage, "dest-remove-guard", "in-use");
          await this.recordBlockerRefusal(caller, { refusal: "clear-in-use", destinationId: coll.defaultId, pinnedDownpipeIds: pinnedIds, atRiskRunCount: atRisk.count });
          throw new Error(destInUseRefusal(pinned, atRisk));
        }
        // The orphan guard, as in removeDest. This route has no force: a clear that would drop the only proven
        // copy of runs is refused, and the plural remove (with force) is the one override.
        if (atRisk.count > 0) {
          await recordAdminRefusal(this.state.storage, "dest-remove-guard", "orphan-guard");
          await this.recordBlockerRefusal(caller, { refusal: "clear-orphan-guard", destinationId: coll.defaultId, pinnedDownpipeIds: pinnedIds, atRiskRunCount: atRisk.count });
          throw new Error(destOrphanRefusal(atRisk));
        }
      }
      if (req.config !== null) {
        const current = coll.list.find((d) => d.id === coll.defaultId);
        const deployDefault = current !== undefined ? current.id === DEPLOY_DEST_ID || current.source === "deploy" : req.envDestConfigured === true;
        if (deployDefault) {
          await recordAdminRefusal(this.state.storage, "dest-set", "guardrail");
          throw new Error(DEPLOY_DEFAULT_SET_REFUSAL);
        }
      }
      if (req.config === null) {
        // Clearing the default silently PROMOTES the next remaining destination: record the before/after
        // default so a "backups quietly redirected" fault is diagnosable (dest-default-promotion-silent-redirect).
        const fromDefaultId = coll.defaultId;
        coll.list = coll.list.filter((d) => d.id !== coll.defaultId);
        coll.defaultId = coll.list[0]?.id ?? "";
        await this.saveDestinations(coll);
        await this.auditDestChange(caller, "dest-config-cleared", { op: "clear", ...(fromDefaultId ? { id: fromDefaultId } : {}), ...(fromDefaultId ? { fromDefaultId } : {}), ...(coll.defaultId ? { toDefaultId: coll.defaultId } : {}) });
        return this.getDestStatus();
      }
      const existingDefault = coll.list.find((d) => d.id === coll.defaultId);
      const id = existingDefault?.id ?? "default";
      let rec: StoredDestination;
      try {
        rec = this.buildDestRecord(req.config, id, existingDefault?.label ?? "Archive", caller);
      } catch (e) {
        // A submission that failed validation at set time: record it (dest-set-validation-reject) with a
        // CLOSED reason class (never the submitted endpoint/bucket/credential), then rethrow (400 unchanged).
        await this.auditDestChange(caller, "dest-config-set", { op: "set", id, rejectReason: classifyDestRejectReason(e) });
        // The audit event rides the excerpt only when the caller is attributable and the excerpt is
        // projected; the REFUSAL COUNT is what answers "I cannot get past Verify and save" and "verify keeps
        // failing and I forget the reason". Closed route x closed reason, counted; never the submitted value.
        await recordAdminRefusal(this.state.storage, "dest-set", classifyDestProbeRefusal(e));
        throw e;
      }
      coll.list = [...coll.list.filter((d) => d.id !== id), rec];
      if (!coll.list.some((d) => d.id === coll.defaultId)) coll.defaultId = id;
      await this.saveDestinations(coll);
      await this.auditDestChange(caller, "dest-config-set", { op: "set", id });
      return this.getDestStatus();
    }

    // backfillDefaultRoutedRuns stamps every OK, default-routed history row (destinationId undefined) with
    // a CONCRETE outgoing destination id, across every downpipe's ring. It is called at the one moment
    // "undefined" stops safely meaning "the current default": right before the account default itself
    // moves (a fresh env-backed destination is seeded, or an existing default is repointed away). Without
    // it, a row that recorded no origin because nothing needed one yet is read forever after as "wherever
    // the default points today" -- by the removal guard AND by every drill/restore read
    // (destinationForRun/destinationsForRun fall back to primaryDestinationId(config), the downpipe's OWN
    // pin, which an unpinned downpipe never has either) -- so a default change silently reassigns history
    // that never moved a byte. The sharpest case is runs sealed to a deploy-time bucket, reassigned to a
    // brand-new empty one the instant it becomes the console default, but the mechanism is the plain
    // default-repoint case the priorDefaultIds comment already
    // names; this closes it at the SOURCE rather than asking every reader to consult a remembered list of
    // prior defaults that the drill/restore path never did.
    //
    // Returns the number of rows rewritten (0 is common and cheap: an estate whose downpipes are all
    // pinned, or that has sealed nothing yet, touches nothing).
    async backfillDefaultRoutedRuns(outgoingDefaultId: string): Promise<number> {
      if (outgoingDefaultId === "") return 0;
      const histMap = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      let rewritten = 0;
      for (const [key, ring] of histMap) {
        let changed = false;
        const next = ring.map((e) => {
          if (e.status === "ok" && e.destinationId === undefined) {
            changed = true;
            rewritten++;
            return { ...e, destinationId: outgoingDefaultId };
          }
          return e;
        });
        if (changed) await this.state.storage.put(key, next);
      }
      return rewritten;
    }

    // ensureDeployDestSeeded registers the ONE synthetic source:"deploy" destination (DEPLOY_DEST_ID)
    // standing in for the deploy-time/env-configured destination, the FIRST time a console-managed
    // destination is about to join it. envDestConfigured is the ROUTER's own read of the env (the DO has
    // no env binding access and cannot establish this fact itself; router-destinations.ts derives it the
    // same way GET /destination already does). A no-op once any console destination already exists
    // (list.length > 0): either "deploy" is already seeded, or the estate genuinely never had a deploy-time
    // destination and its first console add should become the default exactly as it always has (putDest's
    // own branch, unchanged).
    //
    // ORDER MATTERS: the seed, the default assignment and the history backfill all complete and are saved
    // here, before putDest appends the destination the operator actually submitted, so that add's own
    // "first destination becomes the default" branch sees a non-empty list with a non-empty defaultId
    // already set and leaves it alone -- the new destination joins as a plain, non-default member, never
    // silently inheriting runs it has never held a byte of.
    async ensureDeployDestSeeded(
      envDestConfigured: boolean,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ seeded: boolean; backfilled: number }> {
      const coll = await this.loadDestinations();
      if (coll.list.length > 0 || !envDestConfigured) return { seeded: false, backfilled: 0 };
      const now = Date.now();
      const rec: StoredDestination = {
        id: DEPLOY_DEST_ID,
        label: "Deploy-time destination",
        source: "deploy",
        endpoint: "",
        bucket: "",
        region: "",
        accessKeyId: "",
        secretAccessKey: "",
        setAt: now,
        setBy: caller?.email ?? null,
        verifiedAt: now,
        deleteProbe: "other",
      };
      coll.list = [rec];
      coll.defaultId = DEPLOY_DEST_ID;
      await this.saveDestinations(coll);
      const backfilled = await this.backfillDefaultRoutedRuns(DEPLOY_DEST_ID);
      await this.auditDestChange(caller, "dest-config-set", { op: "set", id: DEPLOY_DEST_ID });
      return { seeded: true, backfilled };
    }

    // putDest adds a NEW destination (no id) or updates an existing one (id present) in the collection.
    // The first destination added becomes the default. OWNER-EXCLUSIVE; the router has verified it live.
    // A caller-supplied id of DEPLOY_DEST_ID is refused: that id is reserved for the one engine-minted
    // synthetic record ensureDeployDestSeeded creates, never a console-submitted destination.
    async putDest(
      req: { id?: unknown; label?: unknown; config?: unknown; envDestConfigured?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ destinations: DestStatusView[]; defaultId: string | null }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may add or edit a destination");
      // Seed the synthetic deploy-time destination FIRST, in the same
      // gated call as the add, so the two can never be split across two separate owner approvals under
      // dual control. envDestConfigured is the router's own env read (router-destinations.ts); it is a
      // no-op (ensureDeployDestSeeded) once any console destination already exists.
      await this.ensureDeployDestSeeded(req.envDestConfigured === true, caller);
      const coll = await this.loadDestinations();
      const existingId = typeof req.id === "string" && req.id.trim() !== "" ? req.id.trim() : null;
      if (existingId === DEPLOY_DEST_ID) throw new Error("that destination id is reserved");
      const id = existingId ?? `dest-${crypto.randomUUID().slice(0, 8)}`;
      const label = typeof req.label === "string" ? req.label : "";
      let rec: StoredDestination;
      try {
        rec = this.buildDestRecord(req.config, id, label, caller);
      } catch (e) {
        // Record a rejected add/edit (dest-set-validation-reject) with a CLOSED reason, then rethrow (400).
        await this.auditDestChange(caller, "dest-config-set", { op: "set", id, rejectReason: classifyDestRejectReason(e) });
        await recordAdminRefusal(this.state.storage, "dest-set", classifyDestProbeRefusal(e));
        throw e;
      }
      // The ACCEPTED-BUT-NARROWED half: buildDestRecord DROPS a malformed optional fail-safe (a garbled
      // worm / objectLock / assumeRole / addressing / storageClass) and validateDestPricing COERCES a
      // negative/NaN rate to 0 -- and the save returns 200 with a success audit either way. That is how "we
      // configured WORM and it shows nothing" and "our cost projection is nonsense" happen with a clean audit
      // trail. destCoercionClasses is the PURE detector over the SUBMITTED SHAPE; it returns closed classes
      // and the submitted values (endpoint, bucket, credential) never leave it.
      for (const cls of destCoercionClasses(req.config)) await recordConfigCoercion(this.state.storage, "destination", cls);
      coll.list = [...coll.list.filter((d) => d.id !== id), rec];
      if (coll.list.length === 1 || coll.defaultId === "") coll.defaultId = id;
      await this.saveDestinations(coll);
      await this.auditDestChange(caller, "dest-config-set", { op: "set", id });
      return this.listDestStatus();
    }

    // recordBlockerRefusal writes the failed dest-config-cleared row for a clear or remove that a guard refused,
    // with the facts that blocked it (dest-remove-refusal-audit.ts). It is observation only: a failure to write
    // it never changes the refusal the caller sees.
    async recordBlockerRefusal(
      caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null,
      facts: DestBlockerFacts,
    ): Promise<void> {
      try {
        await appendDestBlockerRefusalAudit(this.state.storage, (d) => this.appendAudit(d), caller, facts, Date.now());
      } catch {
        // site-fault-waiver: src/sched/scheduler-do-dest-config.ts:DestConfigMixin.recordBlockerRefusal:catch:1 -- the row is observation only; the refusal the caller sees was decided before it, and the dest-remove-guard counter beside it still counts the attempt
      }
    }

    // removalScan is the scan both removal paths run before they remove a destination: the names of the
    // downpipes that name it (the in-use guard) and its orphan risk (the runs whose only proven copy is
    // here). removeDest and the singular clear in setDestConfig both call it, so the two paths refuse on the
    // same facts with the same text.
    async removalScan(id: string, coll: DestinationCollection): Promise<{ pinned: string[]; pinnedIds: string[]; atRisk: RemovalRisk }> {
      const downpipes = await this.listDownpipes();
      // The orphan-risk scan runs FIRST, before either guard, because the in-use refusal needs it too.
      // The refusal loop this closes: with both destinations on a downpipe, "in use" said "reassign"; the
      // operator took this destination off, the downpipe then had one destination, replication stopped, and
      // the orphan guard asked for the second destination the operator had just removed. The in-use refusal
      // now says whether runs here are still uncopied, and that they need this destination kept on until
      // replication has copied them.
      const nameById = new Map(downpipes.map((p) => [p.config.id, p.config.name]));
      // Pass the PRE-REMOVAL default so the scan can attribute default-routed (unpinned) runs to it: an
      // unpinned downpipe seals to whatever the default is and records no origin id, so removing the sole
      // console default must still count those runs. coll.defaultId is the default that was in
      // force when every existing run sealed; the caller's promotion repoints it only AFTER its guards.
      // fanOutById is how many destinations each downpipe is CONFIGURED to write to. The replicate
      // pass runs only at two or more, so this is what decides whether "wait for replication" is a
      // real instruction for a given at-risk downpipe or a wait that can never end. sealedRunsById is each
      // downpipe's count of successful runs, which the scan compares with its history ring to count the
      // runs that have left the ring.
      const fanOutById = new Map(downpipes.map((p) => [p.config.id, allDestinationIds(p.config).length]));
      const sealedRunsById = new Map(downpipes.map((p) => [p.config.id, p.sealedRuns ?? 0]));
      // liveIds is every destination still configured. Only these can hold a copy: a removed destination's
      // replication record proves nothing, and a run whose origin is not among them lives only where a live
      // destination is proven to hold it.
      const liveIds = coll.list.map((d) => d.id);
      const atRisk = await this.uncoveredOriginRuns(id, nameById, coll.defaultId, { ...(coll.priorDefaultIds !== undefined ? { priorDefaultIds: coll.priorDefaultIds } : {}), fanOutById, sealedRunsById, liveIds });
      // Refuse to remove a destination a downpipe explicitly PINS (as primary OR replica): it would fail
      // that downpipe's run/replication (a pinned dangling id never silently falls back).
      const pinnedDownpipes = downpipes.filter((p) => allDestinationIds(p.config).includes(id));
      return { pinned: pinnedDownpipes.map((p) => p.config.name), pinnedIds: pinnedDownpipes.map((p) => p.config.id), atRisk };
    }

    // removeDest deletes a destination by id. Removing the default promotes the next remaining one so
    // unassigned downpipes always resolve a destination. OWNER-EXCLUSIVE. Two guards refuse it: a downpipe
    // that names the destination (in-use, no force), and runs whose only proven copy is here (orphan-guard,
    // force overrides it). Both refusals name the step that ends them, in the order that works.
    async removeDest(
      id: string,
      force: boolean,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ destinations: DestStatusView[]; defaultId: string | null; notice?: string }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may remove a destination");
      const coll = await this.loadDestinations();
      if (!coll.list.some((d) => d.id === id)) throw new Error("no such destination");
      const { pinned, pinnedIds, atRisk } = await this.removalScan(id, coll);
      if (pinned.length > 0) {
        // The console must not SUBSTRING-MATCH this prose to tell "in use" from the orphan guard: record
        // the closed class engine-side so the two remove refusals are separable in the pack without the prose.
        // The in-use text never contains the orphan guard's "only proven copy" phrase, which the console and
        // classifyDestProbeRefusal key on.
        await recordAdminRefusal(this.state.storage, "dest-remove-guard", "in-use");
        await this.recordBlockerRefusal(caller, { refusal: "remove-in-use", destinationId: id, pinnedDownpipeIds: pinnedIds, atRiskRunCount: atRisk.count, forced: force });
        throw new Error(destInUseRefusal(pinned, atRisk));
      }
      // Refuse (unless forced) to remove a destination that is the only PROVEN copy of backed-up runs: with
      // 3-2-1 failover a run may have SEALED here (this destination is its recorded origin) and not yet been
      // replicated elsewhere. Removing it would orphan those runs (its credentials go too, so the bytes
      // become unreadable). A run is "safe" when another destination's proven window contains it.
      // The count is computed REGARDLESS of `force`: a non-force removal REFUSES when > 0, a FORCE removal
      // PROCEEDS but RECORDS the count as the data-loss magnitude of the drop (dest-removed-force-orphans-runs).
      if (!force && atRisk.count > 0) {
        // THE DATA-LOSS GUARD firing. Counted as its own closed class (orphan-guard), so the pack can
        // prove the engine REFUSED to drop the only proven copy rather than the operator giving up.
        await recordAdminRefusal(this.state.storage, "dest-remove-guard", "orphan-guard");
        await this.recordBlockerRefusal(caller, { refusal: "remove-orphan-guard", destinationId: id, pinnedDownpipeIds: pinnedIds, atRiskRunCount: atRisk.count, forced: force });
        throw new Error(destOrphanRefusal(atRisk));
      }
      // Removing the current default silently PROMOTES the next remaining destination: capture before/after.
      const fromDefaultId = coll.defaultId;
      coll.list = coll.list.filter((d) => d.id !== id);
      if (coll.defaultId === id) coll.defaultId = coll.list[0]?.id ?? "";
      const toDefaultId = coll.defaultId;
      // The SILENT PROMOTION moves the default too, so it is remembered on the same terms as an
      // explicit repoint. The destination just removed is not what matters here (it is gone, and the
      // guard above already had its say): what matters is that a LATER repoint away from the promoted
      // survivor must find the survivor in this list.
      const promotedPrior = rememberPriorDefault(coll.priorDefaultIds, fromDefaultId, toDefaultId);
      if (promotedPrior.length > 0) coll.priorDefaultIds = promotedPrior;
      await this.saveDestinations(coll);
      // The destination just removed is gone from the list, so a
      // default-routed row that recorded no origin must stop meaning "the default", which after this
      // promotion means the SURVIVOR -- a destination that never held these bytes either. Backfilling to
      // the id just removed makes the fact honest: destinationForRun/destinationsForRun then resolve it,
      // find no configured destination under that id, and report REASON_ORIGIN_REMOVED (router-sources.ts
      // withRunDestFallback) instead of silently trying the survivor's bucket and reporting a bare
      // "object missing" for a run the operator (via force) already knew was leaving custody.
      await this.backfillDefaultRoutedRuns(fromDefaultId);
      // A FORCE removal that drops the only proven copy must carry the NAMES, not only the COUNT, so an
      // incident timeline can say WHICH downpipes lost their last copy. The names are the customer's own
      // downpipe labels (the class downpipes[] already carries), capped at 5 -- the same cap the refusal prose
      // above already shows the operator, so this reveals nothing new to anyone and answers the whole question.
      const affected = force && atRisk.count > 0 ? atRisk.names.slice(0, 5) : [];
      await this.auditDestChange(caller, "dest-config-cleared", { op: "remove", id, ...(fromDefaultId ? { fromDefaultId } : {}), ...(toDefaultId ? { toDefaultId } : {}), force, uncoveredOriginRunCount: atRisk.count, ...(affected.length > 0 ? { affectedDownpipeNames: affected } : {}) });
      // The response states what the removal cost, when it cost something: the runs force dropped, and the
      // older runs outside the run history that no guard could count.
      const notice = destRemovedNotice(force, atRisk);
      return { ...(await this.listDestStatus()), ...(notice !== undefined ? { notice } : {}) };
    }

    // uncoveredOriginRuns counts the backed-up runs whose ONLY proven copy is the given destination: ok runs
    // recorded with it as their seal ORIGIN (plus, when it IS the current default, the default-routed runs
    // that recorded no origin), for which no OTHER destination's replication state (repl:<dp>) proves it
    // holds that run. It is the safety check behind destination removal, cheap (the history rings + repl
    // state already in DO storage, no destination I/O). The proof is per run: another destination holds a
    // run when the run's index is inside that destination's PROVEN window [holdsFrom, holdsIndex]. The
    // replicate backlog records holdsIndex only as the highest CONTIGUOUS run a destination holds (no gap
    // below) and holdsFrom as the floor that walk started at, and a seal completion advances holdsIndex only
    // when no run between is missing there (recordReplicationState), so every index inside the window is a
    // run that destination holds. Counting per run (not per downpipe) is what lets the count fall as
    // replication copies a backlog oldest first, so the refusal can report progress truthfully.
    //   SCOPE: it scans LIVE downpipes' history rings. Runs whose downpipe was already DELETED have no ring
    //   and are not considered, removing a destination that is the sole origin of a deleted downpipe's runs
    //   is not blocked (those runs are already outside the managed-history custody guarantee). Runs that
    //   have LEFT the ring (older than its RING_CAP newest rows) are not in it either: they are counted
    //   separately as olderOutsideHistory, for every downpipe with an origin run here, so the refusal and
    //   the removal notice can state them. Replication copies only ring runs, so nothing copies those.
    //   DEFAULT-ROUTED runs: an UNPINNED downpipe seals to whatever the current default is and
    //   records NO origin id (destinationId undefined -- there is no failover-chosen origin to record). The
    //   console wizard leaves downpipes unpinned, so this is the common case. Such a run's only proven copy
    //   is the default itself, so when the destination being removed IS the current default (id === defaultId)
    //   a default-routed ok run counts as one of its origin runs. A run recorded to some OTHER id -- and any
    //   default-routed run while a NON-default destination is removed -- is left out (it never sealed there),
    //   so a legitimate multi-destination remove is unaffected. An absent defaultId keeps the recorded-origin-
    //   only behaviour for the isolated read-side scan; the removal path always supplies the pre-removal default.
    //
    //   A DEFAULT-ROUTED RUN IS ATTRIBUTED TO EVERY DESTINATION THAT HAS EVER BEEN THE DEFAULT, not
    //   only to the current one. The row records no origin, so the destination it sealed to cannot be
    //   read back; using the CURRENT default alone meant that repointing the default from A to B and
    //   then removing A -- the ordinary order of a destination migration, and the order the refusal's
    //   own "reassign those downpipes" advice pushes an operator toward -- reported ZERO at-risk runs
    //   and removed the only copy of every backup silently. `couldHaveTakenDefaultRoutedRuns` reads
    //   the collection's remembered default history so a former default stays a candidate origin.
    //   A destination that has NEVER been the default is unaffected: it cannot have taken a
    //   default-routed run, so removing a never-defaulted replica is not blocked by this arm.
    //
    //   THE LAST HOLDER OF A RUN WHOSE ORIGIN IS GONE. With `liveIds` (the configured destinations), a run
    //   whose recorded origin is NOT live also counts here when this destination is proven to hold it (its
    //   own window or holdsAbove). Its origin was removed earlier, so this destination may be the last copy.
    //   Counting only origin runs let an operator remove the origin (the replica held the runs), then the
    //   replica, and orphan every run with no refusal. A run whose origin IS live is held by that origin,
    //   so removing a replica of it is never blocked by this arm.
    //
    //   ONLY LIVE DESTINATIONS PROVE A COPY. A removed destination keeps its `repl:` entry. Its window must not
    //   count as "held elsewhere": the bytes left custody with its credentials. Without `liveIds` (the
    //   isolated read-side scan) every recorded destination is treated as live, the behaviour before.
    //
    //   A destination proves a run by its window [holdsFrom, holdsIndex] OR by its holdsAbove list: the ring
    //   runs it holds above the window. One run that no destination can source freezes the window below it,
    //   so without the list the newer runs a replica does hold stayed in this count until that run left
    //   the ring (up to RING_CAP runs).
    //
    //   `unreplicable` counts the at-risk runs whose downpipe fans out to FEWER THAN TWO destinations.
    //   For those the refusal's "wait for replication" is not slow, it is impossible: replicateBacklog
    //   returns at `allDestinationIds(config).length < 2` before it reads anything, so no tick will
    //   ever copy them. It is reported so the message can name the step that makes replication run
    //   instead of naming a wait that cannot end.
    async uncoveredOriginRuns(
      id: string,
      nameById: Map<string, string>,
      defaultId?: string,
      opts?: { priorDefaultIds?: readonly string[]; fanOutById?: Map<string, number>; sealedRunsById?: Map<string, number>; liveIds?: readonly string[] },
    ): Promise<RemovalRisk> {
      // listAllByPrefix pages the whole prefix (not a single raw storage.list page) so a fleet with more
      // than one DO_LIST_PAGE of downpipes cannot truncate this removal safety scan at the first ~1000
      // entries and silently under-count the runs whose only copy is the destination being removed.
      const histMap = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      // Pre-fetch every replication-state record in one paged scan rather than a sequential storage.get per
      // downpipe inside the loop, so the removal safety check stays O(N) reads instead of O(2N).
      const replMap = await this.listAllByPrefix<Record<string, DestReplState>>("repl:");
      let count = 0;
      let unreplicable = 0;
      let olderOutsideHistory = 0;
      const names: string[] = [];
      // The removal target could have taken default-routed runs when it is the current default OR a
      // remembered prior one. On such a destination, default-routed ok runs (destinationId undefined)
      // join the origin set; on a never-defaulted destination they do not.
      const removingDefault = couldHaveTakenDefaultRoutedRuns(id, defaultId, opts?.priorDefaultIds);
      const live = opts?.liveIds !== undefined ? new Set(opts.liveIds) : undefined;
      const isLive = (destId: string): boolean => live === undefined || live.has(destId);
      for (const [k, ring] of histMap) {
        const dpId = k.slice("hist:".length);
        const repl = replMap.get(`repl:${dpId}`) ?? {};
        const ownState = repl[id];
        const own = ownState !== undefined ? replProof(ownState) : undefined;
        // Runs whose recorded origin is gone and which this destination is proven to hold: it may be their last copy.
        const orphanedHere = (e: RunHistoryEntry): boolean => e.destinationId !== undefined && e.destinationId !== id && !isLive(e.destinationId) && own?.(e.index) === true;
        const originRuns = ring.filter((e) => e.status === "ok" && e.runId && (e.destinationId === id || (removingDefault && e.destinationId === undefined) || orphanedHere(e)));
        if (originRuns.length === 0) continue;
        // Runs of this downpipe that sealed but are no longer in its ring. They may have sealed here, so they
        // are stated; the count is exact for every account (the sealed-run counter predates the first release).
        const okInRing = ring.filter((e) => e.status === "ok" && e.runId).length;
        if (originRuns.some((e) => !orphanedHere(e))) olderOutsideHistory += Math.max(0, (opts?.sealedRunsById?.get(dpId) ?? 0) - okInRing);
        // Another destination holds an origin run only when its PROVEN window [holdsFrom, holdsIndex] contains
        // the run's index. The holdsFrom lower bound guards against a ring-floor over-claim: a replica whose
        // observation only started at the ring floor cannot prove it holds a below-floor origin run. A record
        // with no proven floor (a legacy record, or one that holds nothing) proves nothing, so the removal is
        // BLOCKED (the safe direction: never let a "covered elsewhere" verdict drop the only copy).
        // Only a destination that is still configured proves anything (a removed one's record is stale).
        // holdsAbove adds the runs it holds above a window a missing run froze.
        const proofs = Object.entries(repl)
          .filter(([destId]) => destId !== id && isLive(destId))
          .map(([, st]) => replProof(st));
        const uncovered = originRuns.filter((e) => !proofs.some((holds) => holds(e.index))).length;
        if (uncovered > 0) {
          count += uncovered;
          names.push(nameById.get(dpId) ?? dpId);
          // Fewer than two configured destinations means the replicate pass skips this downpipe
          // entirely, so its at-risk runs can never be copied anywhere by waiting. An absent entry
          // (a ring whose downpipe is not in the map) is treated as unreplicable: the safe direction
          // is to describe the wait as impossible rather than to promise one that may not run.
          if ((opts?.fanOutById?.get(dpId) ?? 0) < 2) unreplicable += uncovered;
        }
      }
      return { count, names, unreplicable, olderOutsideHistory };
    }

    // setDefaultDest makes an existing destination the default. OWNER-EXCLUSIVE.
    async setDefaultDest(
      id: string,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ destinations: DestStatusView[]; defaultId: string | null }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may set the default destination");
      const coll = await this.loadDestinations();
      if (!coll.list.some((d) => d.id === id)) throw new Error("no such destination");
      // An explicit default repoint: record before/after so a "backups now write elsewhere" change is
      // diagnosable, the same signal as the silent promotion on clear/remove (dest-default-promotion).
      const fromDefaultId = coll.defaultId;
      // THE OUTGOING DEFAULT IS REMEMBERED, and this line is the whole of the fix for the silent
      // orphan-guard walk-past. Every default-routed run already sealed to fromDefaultId, and its
      // history row records no origin, so from this instant the ONLY record that fromDefaultId can
      // hold their sole copy is this list. Without it, removing fromDefaultId next reads as a clean,
      // guard-approved removal of a destination holding the only copy of every backup the estate has.
      const priorDefaultIds = rememberPriorDefault(coll.priorDefaultIds, fromDefaultId, id);
      coll.defaultId = id;
      if (priorDefaultIds.length > 0) coll.priorDefaultIds = priorDefaultIds;
      await this.saveDestinations(coll);
      // priorDefaultIds above protects the REMOVAL guard, but a
      // default-routed run's history row (destinationId undefined) is ALSO what drill/restore reads
      // (destinationForRun/destinationsForRun), and that read never consulted priorDefaultIds -- it falls
      // straight to primaryDestinationId(config), which an unpinned downpipe never has either, so it would
      // still have resolved every pre-repoint run against the NEW default. Backfilling those rows to the
      // OUTGOING default here, in the same call that moves it, closes that read-path gap at the source: a
      // drill of an old run keeps reading fromDefaultId, byte-identical to before this repoint, forever.
      await this.backfillDefaultRoutedRuns(fromDefaultId);
      await this.auditDestChange(caller, "dest-config-set", { op: "default", id, ...(fromDefaultId ? { fromDefaultId } : {}), toDefaultId: id });
      return this.listDestStatus();
    }

  };
}
