// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the archive-destination config
// subsystem (console-set, owner-exclusive primary + replica destinations and their status) extracted
// from the SchedulerDO god module into a mixin. DestConfigMixin layers these over a base whose `this`
// is SchedulerDOSurface; dispatch and `this` binding are byte-identical. The destConfig/destinations
// keys, the owner-exclusive gates and the dest-record build/validate path are unchanged. No storage
// key, route, status code, response body or auth gate changed. The OPT-IN dual-control change-control
// gate (setRequireConfigApproval + the propose/dry-run/approve/reject path + the pending-change inbox)
// that previously shared this file lives in the sibling ./scheduler-do-change-control.ts
// (ChangeControlMixin), split out so neither file exceeds the module-size guardrail.

import { isWrappedSecret, type WrappedSecret } from "../admin/config-secret.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { boundDestPruneMap, type DestPruneState, foldRetentionRecordIntoDestPrune } from "../cron/retention-dest-prune.ts";
import type { RetentionPassRecord } from "../cron/retention-record.ts";
import { validateAddressing, validateAssumeRolePolicy, validateAzureEntraDirectory, validateStorageClass, validateWormPolicyValue } from "../dest/factory.ts";
import { allDestinationIds } from "./destinations.ts";
import { classifyDestProbeRefusal, destCoercionClasses, recordAdminRefusal, recordCapTruncation, recordConfigCoercion, recordDestResolveFallback, TEST_DELETE_PROBES, type TestDeleteProbe } from "./sched-fault-ledger.ts";
import { AuthError, DEPLOY_DEST_ID, DEST_CONFIG_KEY, DESTINATIONS_KEY, type DestinationCollection, type DestinationConfig, type DestReplState, type DestStatusView, PRIOR_DEFAULT_IDS_MAX, type RunHistoryEntry, type SchedulerDOCtor, type StoredDestination, validateDestPricing } from "./scheduler-do-base.ts";

const TEST_DELETE_PROBE_SET: ReadonlySet<string> = new Set(TEST_DELETE_PROBES);

// The per-destination retention-prune sidecar (B61) lives under ONE key as a { [destId]: DestPruneState }
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
        // G090 (the data-loss one): a stored defaultId that names NO live destination is HEALED to the first
        // entry on every read. The heal is right (a run must never write nowhere) and it silently REPOINTS
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

    async saveDestinations(c: DestinationCollection): Promise<void> {
      await this.state.storage.put(DESTINATIONS_KEY, c);
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
      return { present: true, id: d.id, label: d.label, isDefault: d.id === defaultId, endpointHost, bucket: d.bucket, region: d.region, setAt: d.setAt, setBy: d.setBy, verifiedAt: d.verifiedAt, deleteProbe: d.deleteProbe, ...(d.worm ? { worm: d.worm } : {}), ...(d.objectLock ? { objectLock: d.objectLock } : {}), authMode, ...(d.assumeRole ? { assumeRoleArn: d.assumeRole.roleArn } : {}), ...(d.azureEntra ? { azureEntra: { tenantId: d.azureEntra.tenantId, clientId: d.azureEntra.clientId } } : {}), ...(d.addressing ? { addressing: d.addressing } : {}), ...(d.storageClass ? { storageClass: d.storageClass } : {}), ...(d.pricing ? { pricing: d.pricing } : {}), ...(d.source ? { source: d.source } : {}) };
    }

    // getDestStatus is the redaction-safe view of the DEFAULT destination (back-compat shape: the
    // singular /dest-status route and /status read it). The prune sidecar row is joined even on an
    // env-configured estate (present: false): there is no StoredDestination row to hang the view on, but
    // the sidecar's default slot ("") still answers "is retention working", and without this join an
    // env-only estate's prune telemetry would never surface anywhere (B61).
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
    // (the console's Destinations list), each joined with its prune sidecar row when one exists (B61).
    async listDestStatus(): Promise<{ destinations: DestStatusView[]; defaultId: string | null }> {
      const { list, defaultId } = await this.loadDestinations();
      const prune = await this.destPruneMap();
      const destinations = list.map((d) => {
        const row = prune[d.id];
        return { ...this.destStatusOf(d, defaultId), ...(row !== undefined ? { lastPrune: row } : {}) };
      });
      return { destinations, defaultId: list.length ? defaultId : null };
    }

    // destPruneMap reads the per-destination retention-prune sidecar rows (B61), keyed by destination id
    // ("" = the default slot on an estate with no console destination). Empty until a pass first posts a
    // record; honest absence is a distinct posture from "the pass ran and did nothing".
    async destPruneMap(): Promise<Record<string, DestPruneState>> {
      return (await this.state.storage.get<Record<string, DestPruneState>>(DEST_PRUNE_KEY)) ?? {};
    }

    // foldDestPruneRecord folds ONE retention pass record into the sidecar rows (B61). Called at the DO's
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
      const c = (config ?? {}) as { endpoint?: unknown; bucket?: unknown; region?: unknown; accessKeyId?: unknown; secretAccessKey?: unknown; verifiedAt?: unknown; deleteProbe?: unknown; worm?: unknown; objectLock?: unknown; assumeRole?: unknown; addressing?: unknown; storageClass?: unknown; pricing?: unknown; azureEntra?: unknown };
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
        // G246 (R5): the closed TestDeleteProbe vocabulary, re-gated on the DO write like every other closed
        // field. It used to coerce to a two-member enum, which would have folded a "transient" probe verdict (a
        // busy store, a dropped socket) into "ok" -- a claim that the destination PRUNES, which the probe had
        // not established. An absent or out-of-vocabulary value keeps the historical "ok" default.
        deleteProbe: typeof c.deleteProbe === "string" && TEST_DELETE_PROBE_SET.has(c.deleteProbe) ? (c.deleteProbe as TestDeleteProbe) : "ok",
        ...(worm !== null ? { worm } : {}),
        ...(objectLock !== undefined ? { objectLock } : {}),
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
    // be repointed without the credential ever being surfaced. It lives with the destination-config helpers
    // (engine-sys-struct-06): the owner-action gate (DualControlMixin) calls it through `this` for the dest
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

    async auditDest(caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null, action: "dest-config-set" | "dest-config-cleared"): Promise<void> {
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action,
        outcome: "success",
        target: { kind: "access-policy" },
      });
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
        // G036 / DROPPED-FIELD: this list is the WHOLE contract between the caller below and the
        // target literal, and it is enumerated twice (once here, once as a spread). affectedDownpipeNames was
        // added to the caller, to AuditDestChangeTarget and to the support-pack projection and NOT to either
        // copy here, so the removal path computed the names and this method dropped them on the floor. A
        // spread of an object literal into a typed parameter gets no excess-property check, which is exactly
        // why nothing failed. Anything added to the target type must be added in BOTH places below.
        affectedDownpipeNames?: string[];
      },
    ): Promise<void> {
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action,
        outcome: detail.rejectReason ? "failed" : "success",
        target: {
          kind: "dest-change",
          op: detail.op,
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
    async setDestConfig(
      req: { config?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<DestStatusView> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may set or clear the archive destination");
      const coll = await this.loadDestinations();
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
        // G126/G146: the audit event rides the excerpt only when the caller is attributable and the excerpt is
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
    // that never moved a byte. The mechanism is the plain default-repoint case the priorDefaultIds comment
    // already names; this closes it at the SOURCE rather than asking every reader to consult a remembered
    // list of prior defaults that the drill/restore path never did.
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
      // DEST-REPLACE-REASSIGN: seed the synthetic deploy-time destination FIRST, in the same
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
        await recordAdminRefusal(this.state.storage, "dest-set", classifyDestProbeRefusal(e)); // G126/G146
        throw e;
      }
      // G297: the ACCEPTED-BUT-NARROWED half. buildDestRecord DROPS a malformed optional fail-safe (a garbled
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

    // removeDest deletes a destination by id. Removing the default promotes the next remaining one so
    // unassigned downpipes always resolve a destination. OWNER-EXCLUSIVE. (A guard against removing a
    // destination a downpipe explicitly references is added with per-downpipe assignment.)
    async removeDest(
      id: string,
      force: boolean,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ destinations: DestStatusView[]; defaultId: string | null }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may remove a destination");
      const coll = await this.loadDestinations();
      if (!coll.list.some((d) => d.id === id)) throw new Error("no such destination");
      const downpipes = await this.listDownpipes();
      // Refuse to remove a destination a downpipe explicitly PINS (as primary OR replica): it would fail
      // that downpipe's run/replication (a pinned dangling id never silently falls back). Reassign first.
      const pinned = downpipes.filter((p) => allDestinationIds(p.config).includes(id)).map((p) => p.config.name);
      if (pinned.length > 0) {
        // Record the closed class engine-side (dest-remove-guard/in-use) so the two remove refusals are
        // separable in the pack without matching on the refusal prose.
        await recordAdminRefusal(this.state.storage, "dest-remove-guard", "in-use");
        throw new Error(`destination is in use by ${pinned.length} downpipe(s): ${pinned.slice(0, 5).join(", ")}${pinned.length > 5 ? ", …" : ""}. Reassign them first.`);
      }
      // Refuse (unless forced) to remove a destination that is the only PROVEN copy of backed-up runs: with
      // 3-2-1 failover a run may have SEALED here (this destination is its recorded origin) and not yet been
      // replicated elsewhere. Removing it would orphan those runs (its credentials go too, so the bytes
      // become unreadable). A run is "safe" when another destination's replication state is caught up past
      // it; the replicate pass copies the backlog every tick, so this clears itself, wait, reassign, or
      // pass force to drop them deliberately.
      // Compute the orphan-risk count REGARDLESS of `force`: a non-force removal REFUSES when > 0 (unchanged),
      // a FORCE removal PROCEEDS but RECORDS the count as the data-loss magnitude of the drop (dest-removed-
      // force-orphans-runs). The extra scan only runs on a rare owner-initiated forced drop.
      const nameById = new Map(downpipes.map((p) => [p.config.id, p.config.name]));
      // Pass the PRE-REMOVAL default so the scan can attribute default-routed (unpinned) runs to it: an
      // unpinned downpipe seals to whatever the default is and records no origin id, so removing the sole
      // console default must still count those runs (G-P0-065). coll.defaultId is the default that was in
      // force when every existing run sealed; the promotion below only repoints it AFTER this guard.
      // fanOutById is how many destinations each downpipe is CONFIGURED to write to. The replicate
      // pass runs only at two or more, so this is what decides whether "wait for replication" is a
      // real instruction for a given at-risk downpipe or a wait that can never end.
      const fanOutById = new Map(downpipes.map((p) => [p.config.id, allDestinationIds(p.config).length]));
      const atRisk = await this.uncoveredOriginRuns(id, nameById, coll.defaultId, { ...(coll.priorDefaultIds !== undefined ? { priorDefaultIds: coll.priorDefaultIds } : {}), fanOutById });
      if (!force && atRisk.count > 0) {
        // G126: THE DATA-LOSS GUARD firing. Counted as its own closed class (orphan-guard), so the pack can
        // prove the engine REFUSED to drop the only proven copy rather than the operator giving up.
        await recordAdminRefusal(this.state.storage, "dest-remove-guard", "orphan-guard");
        // THE REMEDY NAMED HAS TO BE ONE THAT EXISTS. "Wait for replication" is true only for a
        // downpipe that fans out to two or more destinations; below that, replicateBacklog returns
        // before it reads anything and no tick will ever copy these runs, so telling the operator to
        // wait names a step that cannot complete. When every at-risk run is in that state the message
        // names the step that MAKES replication run -- give those downpipes a second destination --
        // and it is deliberately named before force, which is the only other thing that clears the
        // guard and destroys the copies to do it.
        const waitClause =
          atRisk.unreplicable === atRisk.count
            ? `Replication cannot copy them as things stand: the replicate pass only runs for a downpipe configured with two or more destinations, and ${atRisk.names.length === 1 ? "that downpipe writes" : "those downpipes write"} to one. Add a second destination to ${atRisk.names.length === 1 ? "it" : "them"} so the pass has somewhere to mirror to, wait for it to catch up, then remove this one`
            : atRisk.unreplicable > 0
              ? `Wait for replication to copy them to another destination (the map shows "N of M copies") -- though ${atRisk.unreplicable} of these runs belong to downpipes configured with only one destination, which the replicate pass skips, so those need a second destination added before any wait can help. Or reassign those downpipes`
              : `Wait for replication to copy them to another destination (the map shows "N of M copies"), reassign those downpipes`;
        throw new Error(
          `destination is the only proven copy of ${atRisk.count} backed-up run(s) (${atRisk.names.slice(0, 5).join(", ")}${atRisk.names.length > 5 ? ", …" : ""}). ${waitClause}, or remove with force to drop those copies.`,
        );
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
      // DEST-REPLACE-REASSIGN: the destination just removed is gone from the list, so a
      // default-routed row that recorded no origin must stop meaning "the default", which after this
      // promotion means the SURVIVOR -- a destination that never held these bytes either. Backfilling to
      // the id just removed makes the fact honest: destinationForRun/destinationsForRun then resolve it,
      // find no configured destination under that id, and report REASON_ORIGIN_REMOVED (router-sources.ts
      // withRunDestFallback) instead of silently trying the survivor's bucket and reporting a bare
      // "object missing" for a run the operator (via force) already knew was leaving custody.
      await this.backfillDefaultRoutedRuns(fromDefaultId);
      // G036: a FORCE removal that dropped the only proven copy carried the COUNT and not the NAMES, so an
      // incident timeline could not say WHICH downpipes lost their last copy. The names are the customer's own
      // downpipe labels (the class downpipes[] already carries), capped at 5 -- the same cap the refusal prose
      // above already shows the operator, so this reveals nothing new to anyone and answers the whole question.
      const affected = force && atRisk.count > 0 ? atRisk.names.slice(0, 5) : [];
      await this.auditDestChange(caller, "dest-config-cleared", { op: "remove", id, ...(fromDefaultId ? { fromDefaultId } : {}), ...(toDefaultId ? { toDefaultId } : {}), force, uncoveredOriginRunCount: atRisk.count, ...(affected.length > 0 ? { affectedDownpipeNames: affected } : {}) });
      return this.listDestStatus();
    }

    // uncoveredOriginRuns counts the backed-up runs whose ONLY proven copy is the given destination: ok runs
    // recorded with it as their seal ORIGIN (plus, when it IS the current default, the default-routed runs
    // that recorded no origin -- G-P0-065), for which no OTHER destination's replication state (repl:<dp>)
    // is caught up to that run's index. It is the safety check behind destination removal, cheap (the
    // history rings + repl state already in DO storage, no destination I/O). The holdsIndex comparison is the
    // best proof the authority plane has without reading a bucket; the replicate backlog advances holdsIndex
    // only to the highest CONTIGUOUS run a destination holds (no gap below), so "holdsIndex >= maxOriginIndex"
    // truthfully means that destination holds those runs.
    //   SCOPE: it scans LIVE downpipes' history rings. Runs whose downpipe was already DELETED have no ring
    //   and are not considered, removing a destination that is the sole origin of a deleted downpipe's runs
    //   is not blocked (those runs are already outside the managed-history custody guarantee).
    //   DEFAULT-ROUTED runs (G-P0-065): an UNPINNED downpipe seals to whatever the current default is and
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
    //   `unreplicable` counts the at-risk runs whose downpipe fans out to FEWER THAN TWO destinations.
    //   For those the refusal's "wait for replication" is not slow, it is impossible: replicateBacklog
    //   returns at `allDestinationIds(config).length < 2` before it reads anything, so no tick will
    //   ever copy them. It is reported so the message can name the step that makes replication run
    //   instead of naming a wait that cannot end.
    async uncoveredOriginRuns(
      id: string,
      nameById: Map<string, string>,
      defaultId?: string,
      opts?: { priorDefaultIds?: readonly string[]; fanOutById?: Map<string, number> },
    ): Promise<{ count: number; names: string[]; unreplicable: number }> {
      // listAllByPrefix pages the whole prefix (not a single raw storage.list page) so a fleet with more
      // than one DO_LIST_PAGE of downpipes cannot truncate this removal safety scan at the first ~1000
      // entries and silently under-count the runs whose only copy is the destination being removed.
      const histMap = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      // Pre-fetch every replication-state record in one paged scan rather than a sequential storage.get per
      // downpipe inside the loop, so the removal safety check stays O(N) reads instead of O(2N).
      const replMap = await this.listAllByPrefix<Record<string, DestReplState>>("repl:");
      let count = 0;
      let unreplicable = 0;
      const names: string[] = [];
      // The removal target could have taken default-routed runs when it is the current default OR a
      // remembered prior one. On such a destination, default-routed ok runs (destinationId undefined)
      // join the origin set; on a never-defaulted destination they do not.
      const removingDefault = couldHaveTakenDefaultRoutedRuns(id, defaultId, opts?.priorDefaultIds);
      for (const [k, ring] of histMap) {
        const dpId = k.slice("hist:".length);
        const originRuns = ring.filter((e) => e.status === "ok" && e.runId && (e.destinationId === id || (removingDefault && e.destinationId === undefined)));
        if (originRuns.length === 0) continue;
        const maxOriginIndex = originRuns.reduce((m, e) => Math.max(m, e.index), -1);
        const minOriginIndex = originRuns.reduce((m, e) => Math.min(m, e.index), Number.POSITIVE_INFINITY);
        const repl = replMap.get(`repl:${dpId}`) ?? {};
        // Another destination covers these origin runs only when its PROVEN window [holdsFrom, holdsIndex]
        // CONTAINS the whole [minOriginIndex, maxOriginIndex] span: holdsIndex >= the max AND holdsFrom <=
        // the min. The holdsFrom lower bound is the ring-floor over-claim fix (BD-RETENTION-HOLDSINDEX-
        // RINGFLOOR-OVERCLAIM): a replica whose observation only started at the ring floor cannot prove it
        // holds a below-floor origin run, so it must not count as a covering copy. A record with no proven
        // floor (a legacy record, or one that holds nothing) contributes +Infinity => not covering, so the
        // removal is BLOCKED (the safe direction: never let a "covered elsewhere" verdict drop the only copy).
        const coveredElsewhere = Object.entries(repl).some(([destId, st]) => destId !== id && st.holdsIndex >= maxOriginIndex && (st.holdsFrom ?? Number.POSITIVE_INFINITY) <= minOriginIndex);
        if (!coveredElsewhere) {
          count += originRuns.length;
          names.push(nameById.get(dpId) ?? dpId);
          // Fewer than two configured destinations means the replicate pass skips this downpipe
          // entirely, so its at-risk runs can never be copied anywhere by waiting. An absent entry
          // (a ring whose downpipe is not in the map) is treated as unreplicable: the safe direction
          // is to describe the wait as impossible rather than to promise one that may not run.
          if ((opts?.fanOutById?.get(dpId) ?? 0) < 2) unreplicable += originRuns.length;
        }
      }
      return { count, names, unreplicable };
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
      // DEST-REPLACE-REASSIGN: priorDefaultIds above protects the REMOVAL guard, but a
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
