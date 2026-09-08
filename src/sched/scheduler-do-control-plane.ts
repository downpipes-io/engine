// INFRA-1 (FIX-PLAN §4) -- the control-plane RECOVERY subsystem on the SchedulerDO.
//
// The SchedulerDO is the SINGLE authority plane: a storage loss of it is total control-plane amnesia
// (backups silently stop; the first caller silently re-bootstraps to Owner). This mixin adds the three
// recovery pieces that live INSIDE the DO:
//   (1) buildControlPlaneExport -- the no-custody config slice the cron pass signs + writes to every
//       destination as `_RECOVERY/CONTROL-PLANE/<version>-<iso>.json` (+ `.sig`). It NEVER emits a
//       plaintext secret: a dest credential rides only as a CONFIG_WRAP_KEY-wrapped envelope (decryptable
//       only by the Worker secret that survives the wipe) or is omitted + marked reestablish; the session
//       signing key and recovery-code HMACs are never exported.
//   (2) the controlPlaneRecoveryRequired LATCH (in OrgPolicy) -- set when the bucket has runs but the DO is
//       empty (amnesia), it BLOCKS the silent Access/passkey re-bootstrap (whoami reports recovery-required,
//       not Owner). The bare-token break-glass is unaffected, so the reconcile can still run.
//   (3) reconcileControlPlane -- the break-glass-gated, signature-verified rebuild that runs inside
//       blockConcurrencyWhile, refuses unless the DO is EMPTY and holds no authority (no force overwrite), re-arms bootstrapConsumed,
//       clears the latch, and writes a control-plane-reconciled BRIDGE audit event chaining the (now-gone)
//       old chain head to the new one.
//
// The SIGNING + the bucket I/O live in the Worker (cron/control-plane-pass.ts), because the DO holds no
// env (no SIGNER_PRIVATE, no CONFIG_WRAP_KEY, no destination handle). This mixin only PRODUCES the
// no-custody slice and CONSUMES a verified one; it never touches a key or a bucket. Layered over a base
// whose `this` is SchedulerDOSurface, so it reaches listDownpipes / loadDestinations / appendAudit /
// writeOrgPolicy / addDownpipe through `this` exactly like every sibling mixin.

import { CONFIG_GENESIS_PREV_HASH } from "../admin/config-history.ts";
import { isWrappedSecret } from "../admin/config-secret.ts";
import type {
  ControlPlaneExport,
  ControlPlaneExportState,
  ControlPlaneRecoveryRecord,
  ExportedDestination,
  ExportedDiscovery,
  ExportedIdpConnection,
  ExportedNotifyChannel,
  ExportedNotifyRule,
  ExportedRole,
  ExportedSecret,
} from "../admin/control-plane.ts";
import { candidateVersionMatchesExport } from "../admin/control-plane.ts";
import { type AuthMethod, type CustomRole, type RoleEntry, rolePendingKey, roleSubjectKey } from "../admin/identity.ts";
import type { IdpConnection } from "../admin/idpconn-types.ts";
import { listIdpConnections } from "../admin/oidc-store.ts";
import { validateAddressing, validateAzureEntraDirectory, validateStorageClass, validateWormPolicyValue } from "../dest/factory.ts";
import type { NotifyChannel } from "../notify/types.ts";
import type { NotifyRule } from "../notify-routing.ts";
import { classifyResumeSkip, recordImportFieldDrop, recordResumeDestinations, recordResumeSkip, recordStagedApplyRefusal } from "./sched-fault-ledger.ts";
import {
  AuthError,
  CONTROL_PLANE_EXPORT_STATE_KEY,
  CONTROL_PLANE_STAGED_KEY,
  CUSTOM_ROLE_PREFIX,
  type DestinationCollection,
  DISCOVERY_KEY,
  type DownpipeConfig,
  GROUP_ROLE_PREFIX,
  type GroupRoleEntry,
  type MutationCaller,
  type SchedulerDOCtor,
  type StoredDestination,
  validateDestPricing,
} from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

// projectExportedIdpConnection whitelists a STABLE, non-secret descriptor of an IdP connection for the export
// inventory -- explicit fields only, never a spread, so no unexpected field (a secret) can ride in. The
// client secret is held write-only and re-entered, never carried. `identity` is the anchor the operator
// recognises: the issuer (oidc), the authorize URL (oauth2), or the IdP entity id (saml). oidc/oauth2 carry
// the public clientId + a secretReestablish marker; saml has neither (it has no client secret).
function projectExportedIdpConnection(c: IdpConnection): ExportedIdpConnection {
  if (c.kind === "saml") {
    return { id: c.id, kind: c.kind, label: c.label, presetId: c.presetId, enabled: c.enabled, identity: c.idpEntityId };
  }
  return {
    id: c.id,
    kind: c.kind,
    label: c.label,
    presetId: c.presetId,
    enabled: c.enabled,
    identity: c.kind === "oidc" ? c.issuer : c.authorizeUrl,
    clientId: c.clientId,
    secretReestablish: true,
  };
}

// notifyUrlHost extracts ONLY the host (hostname + non-default port) from a channel URL, for the redacted
// export descriptor -- the same discipline the config snapshot uses. It drops the scheme, path, query and any
// userinfo, because a webhook URL's secret typically lives in the path or query (a Slack/Teams/generic token).
function notifyUrlHost(url: string): string | null {
  try {
    const u = new URL(url);
    return u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return null;
  }
}

// projectExportedNotifyChannel whitelists a NON-SECRET descriptor of a notification channel for the export
// inventory: the URL and the PagerDuty routing key are bearer credentials, carried ONLY as host + a presence
// boolean (never the raw value), so the channel is re-established by hand (secretReestablish). Explicit
// fields only, never a spread.
function projectExportedNotifyChannel(c: NotifyChannel): ExportedNotifyChannel {
  const urlConfigured = typeof c.url === "string" && c.url.length > 0;
  const routingKeyConfigured = typeof c.routingKey === "string" && c.routingKey.length > 0;
  const out: ExportedNotifyChannel = {
    id: c.id,
    kind: c.kind,
    name: c.name,
    enabled: c.enabled,
    urlConfigured,
    urlHost: typeof c.url === "string" ? notifyUrlHost(c.url) : null,
    routingKeyConfigured,
    toAddresses: c.toAddresses ?? [],
  };
  if (c.allowInternalSink === true) out.allowInternalSink = true;
  if (urlConfigured || routingKeyConfigured) out.secretReestablish = true;
  return out;
}

// projectExportedNotifyRule projects a routing rule to its non-secret fields (scope as a stable scalar, the
// severity floor, the selected events, the target channel ids, the digest cadence and enablement).
function projectExportedNotifyRule(r: NotifyRule): ExportedNotifyRule {
  return {
    id: r.id,
    scope: r.scope.kind === "downpipe" ? `downpipe:${r.scope.downpipeId}` : "global",
    minSeverity: r.minSeverity,
    events: r.events === "all" ? ["all"] : [...r.events],
    channelIds: [...r.channelIds],
    digest: typeof r.digest === "string" ? r.digest : "off",
    enabled: r.enabled,
  };
}

// MutationCallerLike is the forwarded-caller shape the reconcile/latch routes receive (the same shape the
// other owner-gated DO methods take).
type CallerLike = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null;

export function ControlPlaneMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- (1) the no-custody signed-export SLICE -------------------------------------------------

    // exportSecretFor projects a destination's stored principal secret into an ExportedSecret: the wrapped
    // envelope rides along (recoverable only by the surviving CONFIG_WRAP_KEY) ONLY when it is genuinely a
    // WrappedSecret at rest; a plaintext-at-rest secret (no CONFIG_WRAP_KEY was set when it was saved) is
    // OMITTED and marked reestablish. NO PLAINTEXT SECRET ever leaves the DO this way.
    exportSecretFor(secret: string | { v: 1; iv: string; ct: string }): ExportedSecret {
      return isWrappedSecret(secret) ? { wrapped: secret } : { reestablish: true };
    }

    // projectExportedDestination whitelists the NON-SECRET fields of a StoredDestination and attaches the
    // wrapped-or-omitted principal secret. The accessKeyId is the public credential half (username-class).
    // An STS externalId is credential-class and is always dropped (externalIdReestablish), like the secret.
    projectExportedDestination(d: StoredDestination): ExportedDestination {
      const out: ExportedDestination = {
        id: d.id,
        label: d.label,
        endpoint: d.endpoint,
        bucket: d.bucket,
        region: d.region,
        accessKeyId: d.accessKeyId,
        secret: this.exportSecretFor(d.secretAccessKey),
        setAt: d.setAt,
        setBy: d.setBy,
        verifiedAt: d.verifiedAt,
        deleteProbe: d.deleteProbe,
      };
      if (d.worm !== undefined) out.worm = d.worm;
      if (d.objectLock !== undefined) out.objectLock = d.objectLock;
      if (d.assumeRole !== undefined) {
        out.assumeRole = {
          roleArn: d.assumeRole.roleArn,
          ...(d.assumeRole.durationSeconds !== undefined ? { durationSeconds: d.assumeRole.durationSeconds } : {}),
          externalIdReestablish: true,
        };
      }
      if (d.addressing !== undefined) out.addressing = d.addressing;
      if (d.storageClass !== undefined) out.storageClass = d.storageClass;
      if (d.pricing !== undefined) out.pricing = d.pricing;
      // The Entra directory and application ids are identifiers, not credentials, so unlike the STS
      // externalId they ride whole rather than as a re-establish marker. The principal's client secret is
      // secretAccessKey and has already been projected through exportSecretFor above.
      if (d.azureEntra !== undefined) out.azureEntra = d.azureEntra;
      return out;
    }

    // buildControlPlaneExport assembles the no-custody export SLICE (no signature; the Worker signs it).
    // It is redaction-safe by construction (every field is whitelisted; secrets become wrapped envelopes
    // or reestablish markers), so an external assertNoPlaintextSecretInExport over the result always passes.
    async buildControlPlaneExport(): Promise<ControlPlaneExport> {
      const states = await this.listDownpipes();
      const downpipes: DownpipeConfig[] = states.map((s) => s.config);
      const { list: destList, defaultId } = await this.loadDestinations();
      const destinations = destList.map((d) => this.projectExportedDestination(d));

      const bound = await this.listRoleEntries();
      const pending = await this.listPendingEntries();
      const roles: ExportedRole[] = [
        ...bound.map((e) => ({
          subject: e.subject,
          email: e.email,
          role: e.role,
          grantedBy: e.grantedBy,
          grantedAt: e.grantedAt,
          ...(e.expiresAt !== undefined ? { expiresAt: e.expiresAt } : {}),
          ...(e.customRole !== undefined ? { customRole: e.customRole } : {}),
        })),
        // A pending invite has no bound subject yet; carry it with subject "" so a reconcile can re-seed it.
        ...pending.map((p) => ({
          subject: "",
          email: p.email,
          role: p.role,
          grantedBy: p.grantedBy,
          grantedAt: p.grantedAt,
          ...(p.expiresAt !== undefined ? { expiresAt: p.expiresAt } : {}),
          ...(p.customRole !== undefined ? { customRole: p.customRole } : {}),
        })),
      ];

      const groupRoles = await this.listGroupRoleEntries();
      const customRoles = [...(await this.listCustomRoleRecords()).values()];

      // IdP connections: a NON-SECRET inventory for the recovery checklist. listIdpConnections returns the
      // redacted records (no secret value); projectExportedIdpConnection whitelists a stable descriptor. These
      // are NEVER auto-applied by a reconcile -- an IdP connection is authority, re-established by hand.
      const idpConnections = (await listIdpConnections(this.idpKv)).map(projectExportedIdpConnection);

      // Notify channels + rules: a NON-SECRET inventory of alert routing for the recovery checklist. A
      // channel's URL / routing key is redacted (host + presence) and re-entered; a reconcile never
      // auto-applies these (a channel with no secret cannot send), so they are inventory, not restored state.
      const notifyChannels = (await this.listNotifyChannelsRaw()).map(projectExportedNotifyChannel);
      const notifyRules = (await this.listNotifyRulesRaw()).map(projectExportedNotifyRule);

      // Discovery: carry the NON-SECRET selection; the read-only API token is omitted + reestablish.
      const discoveryCfg = await this.getDiscoveryConfig();
      const discovery: ExportedDiscovery | null = discoveryCfg
        ? {
            setAt: discoveryCfg.setAt,
            setBy: discoveryCfg.setBy,
            accountsSeen: discoveryCfg.accountsSeen,
            selected: discoveryCfg.selected,
            engineAccountId: discoveryCfg.engineAccountId,
            tokenReestablish: true,
          }
        : null;

      const policy = await this.readOrgPolicy();
      const versions = await this.listConfigVersions();
      const head = versions.length > 0 ? versions[versions.length - 1]! : null;
      // THROUGH auditHeadTrust AND NOT loadAuditHead, because this value is not a report, it is the anchor a
      // reconcile RESTORES FROM. The trust rule derives the true head from the chain rather than trusting a
      // stored pointer whose count may read zero, so a disaster-recovery artefact never anchors the recovered
      // chain at seq 0. The export's SHAPE is unchanged; only what feeds this field is derived rather than read.
      const { head: auditHead } = await this.auditHeadTrust();

      // The secret CATEGORIES that could not ride no-custody and must be re-entered after a reconcile.
      const reestablish: string[] = [];
      if (destinations.some((d) => "reestablish" in d.secret || d.assumeRole !== undefined)) reestablish.push("destination-credentials");
      if (discovery !== null) reestablish.push("discovery-token");
      // IdP client secrets, notify routing secrets, the session signing key, recovery-code HMACs and
      // passkeys are NEVER exported (they are re-established / re-enrolled after a DR). Surface them so the
      // recovery banner tells the operator exactly what to re-do.
      reestablish.push("idp-secrets", "notify-routing-secrets", "session-keys", "passkeys");

      return {
        v: 1,
        exportedAt: nowMillisISO(),
        configVersion: head?.id ?? 0,
        configContentHash: head?.contentHash ?? CONFIG_GENESIS_PREV_HASH,
        engineAccountId: discoveryCfg?.engineAccountId ?? null,
        priorAuditHead: { headSeq: auditHead.headSeq, headHash: auditHead.headHash },
        downpipes,
        destinations,
        defaultDestinationId: destList.length > 0 ? defaultId : null,
        roles,
        groupRoles,
        customRoles,
        idpConnections,
        notifyChannels,
        notifyRules,
        discovery,
        orgPolicy: {
          requireConfigApproval: policy.requireConfigApproval === true,
          ...(policy.requireChangeNumber !== undefined ? { requireChangeNumber: policy.requireChangeNumber } : {}),
          ...(policy.breakGlassTokenRetired !== undefined ? { breakGlassTokenRetired: policy.breakGlassTokenRetired } : {}),
          ...(policy.attendedCadenceDays !== undefined ? { attendedCadenceDays: policy.attendedCadenceDays } : {}),
        },
        reestablish,
      };
    }

    // getControlPlaneExportState reads the last-export pointer (null when nothing has been exported yet).
    async getControlPlaneExportState(): Promise<ControlPlaneExportState | null> {
      return (await this.state.storage.get<ControlPlaneExportState>(CONTROL_PLANE_EXPORT_STATE_KEY)) ?? null;
    }

    // setControlPlaneExportState records that the cron pass wrote a signed export covering this version/hash.
    async setControlPlaneExportState(s: ControlPlaneExportState): Promise<void> {
      await this.state.storage.put(CONTROL_PLANE_EXPORT_STATE_KEY, s);
    }

    // recordControlPlaneExported appends the engine-driven audit row (who-less; the cron is the actor) that
    // a signed export was written, so the trail shows the recovery artefact is being maintained.
    async recordControlPlaneExported(configVersion: number): Promise<void> {
      await this.appendAudit({
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "control-plane-exported",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      void configVersion; // the version rides the structured log only; the field-less target stays redaction-safe
    }

    // ---- (2) the silence-killing recovery-required LATCH ----------------------------------------

    // getControlPlaneRecoveryRequired reads the latch (default false). When true, whoami BLOCKS the silent
    // Access/passkey re-bootstrap to Owner (the single read point the bootstrap path consults).
    async getControlPlaneRecoveryRequired(): Promise<{ required: boolean; reason: string | null }> {
      const policy = await this.readOrgPolicy();
      return { required: policy.controlPlaneRecoveryRequired === true, reason: policy.controlPlaneRecoveryReason ?? null };
    }

    // setControlPlaneRecoveryRequired LATCHES the recovery-required flag and records the reason, and (only
    // on the false->true transition) appends a CRITICAL engine-driven control-plane-empty audit event so the
    // amnesia is loud, never silent. Idempotent. MERGE-writes so the other policy flags are untouched.
    //
    // runlogSeed (RUNLOG-FORKS-ON-THE-RECOVERY-PATH): the caller's own verified read of
    // the surviving destination's RUNLOG high-water mark, carried here so the counter can be anchored to the
    // document it numbers BEFORE the next trigger() allocates. Applied as a MONOTONIC MAX, never a straight
    // overwrite: this path is reached only on a plane the amnesia probe just proved empty, so runlogCounter
    // is 0 here in the overwhelming case, but taking the max costs nothing and removes any argument that a
    // stale or low seed (a race against a concurrent recovery, a retried tick) could regress an already
    // -anchored counter.
    async setControlPlaneRecoveryRequired(reason: string, runlogSeed?: number): Promise<void> {
      const already = (await this.readOrgPolicy()).controlPlaneRecoveryRequired === true;
      await this.writeOrgPolicy({ controlPlaneRecoveryRequired: true, controlPlaneRecoveryReason: reason });
      if (!already) {
        await this.appendAudit({
          actorEmail: null,
          actorMethod: "engine",
          sourceIp: null,
          action: "control-plane-empty",
          outcome: "failed",
          target: { kind: "access-policy" },
        });
      }
      if (typeof runlogSeed === "number" && Number.isInteger(runlogSeed) && runlogSeed > 0) {
        const current = (await this.state.storage.get<number>("runlogCounter")) ?? 0;
        if (runlogSeed > current) await this.state.storage.put("runlogCounter", runlogSeed);
      }
    }

    // clearControlPlaneRecoveryRequired releases the latch (called by a successful reconcile). MERGE-writes.
    async clearControlPlaneRecoveryRequired(): Promise<void> {
      await this.writeOrgPolicy({ controlPlaneRecoveryRequired: false, controlPlaneRecoveryReason: "" });
    }

    // controlPlaneIsEmpty reports whether the control plane carries NO recoverable config (no downpipes AND
    // no destinations). This is the amnesia signal the cron health pass keys on: an empty control plane while
    // the destination bucket still has runs means the DO was wiped (a brand-new account has no runs either).
    async controlPlaneIsEmpty(): Promise<boolean> {
      const downpipes = await this.listDownpipes();
      if (downpipes.length > 0) return false;
      const { list } = await this.loadDestinations();
      return list.length === 0;
    }

    // ---- (3) the break-glass-gated, signature-verified RECONCILE --------------------------------

    // The reconcile is split into APPLY HELPERS so the cron AUTO-HEAL can re-apply only the NO-AUTHORITY
    // slice (downpipes/dest/discovery -- backups resume with no human) while the AUTHORITY slice (RBAC +
    // clear latch + re-arm bootstrap + bridge) stays behind a break-glass confirm. reconcileControlPlane
    // (the manual out-of-band path) composes BOTH, so its behaviour is unchanged.

    // applyResumeDownpipes restores the schedules via addDownpipe (the SINGLE apply path: validates,
    // persists, maintains the due-index + alarm), so the reconciled schedules are armed exactly as a fresh
    // upsert would. When tolerant (the auto-heal path) a single malformed config is logged-and-skipped so
    // one bad downpipe never blocks the rest of the fleet from resuming; the strict path (manual reconcile)
    // surfaces the throw. Returns the count actually applied.
    //
    // The synthetic OWNER caller below is not a new bypass: this replays a signature-verified export of
    // the account's OWN previously-accepted state (every real call site is break-glass-gated -- see
    // reconcileControlPlane / applyControlPlaneAuthoritySlice), never a live edit a caller is requesting,
    // so there is no narrower caller authority to check it against. `prior` is null for every downpipe
    // immediately after a wipe, so addDownpipe's scheduledtest.config re-check would otherwise read ANY
    // exported non-default cadence (a customised cadence, or an explicit opt-out) as a "change" and fail
    // closed on a null caller, silently dropping that downpipe under the tolerant auto-heal path or
    // aborting the whole reconcile under the strict path. Owner holds scheduledtest.config
    // (ROLE_CAPABILITIES), so this exempts the replay without a new capability or bypass flag.
    async applyResumeDownpipes(exp: ControlPlaneExport, tolerant: boolean): Promise<number> {
      const replayCaller: MutationCaller = { method: "access", email: null, subject: null, role: "owner", groups: [] };
      let dpCount = 0;
      for (const config of exp.downpipes) {
        try {
          await this.addDownpipe(config as DownpipeConfig, replayCaller);
          dpCount++;
        } catch (e) {
          if (!tolerant) throw e;
          // best-effort resume: skip a malformed downpipe so the rest of the fleet still resumes.
          // G103: this skip is the "one of my backups never came back" ticket. Until now it survived only as
          // the integer resumeSkipped, so support could say HOW MANY were dropped but never WHICH or WHY, and
          // the customer's downpipe simply did not exist any more. File the downpipe's own id (the label class
          // the pack already carries) against a closed reason class; the throw's message, which interpolates
          // config values, is read only to SELECT that class and is never stored.
          await recordResumeSkip(this.state.storage, (config as { id?: unknown }).id, classifyResumeSkip(e));
        }
      }
      return dpCount;
    }

    // applyResumeDestinations writes the destination collection (the secret rides as the wrapped envelope
    // when present; an omitted secret is stored as "" so the run path fails LOUDLY until re-entered, never
    // silently signing with garbage). The defaultId is restored when it names a real entry. Returns the count.
    async applyResumeDestinations(exp: ControlPlaneExport): Promise<number> {
      const list: StoredDestination[] = exp.destinations.map((d) => this.reconciledDestination(d));
      const defaultId = list.some((d) => d.id === exp.defaultDestinationId) ? (exp.defaultDestinationId as string) : (list[0]?.id ?? "");
      const coll: DestinationCollection = { list, defaultId };
      await this.saveDestinations(coll);
      // G103 (silent re-point): when the exported default destination is NOT in the imported set, the default
      // falls back to whatever destination happens to be FIRST. Every downpipe that pinned nothing then writes
      // to a bucket the operator never chose ("backups land in an unexpected bucket"), and the recovery said
      // nothing. Record the fact, plus the destinations whose secret was not in the export (they cannot run
      // until re-entered). Ids are the customer's own labels; no credential, endpoint or bucket rides.
      const repointed = typeof exp.defaultDestinationId === "string" && exp.defaultDestinationId.length > 0 && !list.some((d) => d.id === exp.defaultDestinationId);
      const reestablish = list.filter((d) => d.secretAccessKey === "").map((d) => d.id);
      if (repointed || reestablish.length > 0) await recordResumeDestinations(this.state.storage, { defaultRepointed: repointed, reestablishDestIds: reestablish });
      // G103 (silent field strip): the import re-validates the optional non-secret config through the live
      // validators, so a value this build no longer accepts is DROPPED. That is right, and it means an
      // account's WORM retention posture can vanish inside the recovery that was supposed to restore it. Count
      // the dropped FIELD (a fixed engine vocabulary); the refused value never rides.
      for (let i = 0; i < exp.destinations.length; i++) {
        const src = exp.destinations[i]!;
        const out = list[i]!;
        if (src.worm !== undefined && out.worm === undefined) await recordImportFieldDrop(this.state.storage, "worm");
        if (src.addressing !== undefined && out.addressing === undefined) await recordImportFieldDrop(this.state.storage, "addressing");
        if (src.storageClass !== undefined && out.storageClass === undefined) await recordImportFieldDrop(this.state.storage, "storageClass");
        if (src.pricing !== undefined && out.pricing === undefined) await recordImportFieldDrop(this.state.storage, "pricing");
      }
      return list.length;
    }

    // applyResumeDiscovery restores the NON-SECRET discovery selection; the read-only API token is never
    // exported, so it is stored empty (an API-source run then fails LOUDLY until the operator re-sets it).
    async applyResumeDiscovery(exp: ControlPlaneExport): Promise<void> {
      if (exp.discovery === null) return;
      await this.state.storage.put(DISCOVERY_KEY, {
        token: "", // never exported; an empty token makes API-source runs fail LOUDLY until re-set
        setAt: exp.discovery.setAt,
        setBy: exp.discovery.setBy,
        accountsSeen: exp.discovery.accountsSeen,
        selected: exp.discovery.selected,
        engineAccountId: exp.discovery.engineAccountId,
      });
    }

    // applyAuthorityRoles restores the RBAC authority: bound grants by their stable subject (so an
    // Access/OIDC Owner is restored to the SAME authority -- never a "whoever calls first" bootstrap),
    // pending invites by email, plus the group->role and custom-role catalogues. Returns the count.
    async applyAuthorityRoles(exp: ControlPlaneExport): Promise<number> {
      let roleCount = 0;
      for (const r of exp.roles) {
        if (r.subject !== "") {
          const entry: RoleEntry = {
            subject: r.subject,
            email: r.email,
            role: r.role as RoleEntry["role"],
            grantedBy: r.grantedBy,
            grantedAt: r.grantedAt,
            ...(r.expiresAt !== undefined ? { expiresAt: r.expiresAt } : {}),
            ...(r.customRole !== undefined ? { customRole: r.customRole } : {}),
          };
          await this.state.storage.put(roleSubjectKey(r.subject), entry);
        } else {
          await this.state.storage.put(rolePendingKey(r.email), {
            email: r.email,
            role: r.role,
            grantedBy: r.grantedBy,
            grantedAt: r.grantedAt,
            ...(r.expiresAt !== undefined ? { expiresAt: r.expiresAt } : {}),
            ...(r.customRole !== undefined ? { customRole: r.customRole } : {}),
          });
        }
        roleCount++;
      }
      for (const g of exp.groupRoles as GroupRoleEntry[]) await this.state.storage.put(`${GROUP_ROLE_PREFIX}${g.group}`, g);
      for (const c of exp.customRoles as CustomRole[]) await this.state.storage.put(`${CUSTOM_ROLE_PREFIX}${c.name}`, c);
      return roleCount;
    }

    // armAuthorityOrgPolicy restores the org-policy gate flags, RE-ARMS bootstrapConsumed (so a
    // post-reconcile caller cannot mint a rogue Owner over the restored roles) and CLEARS the
    // recovery-required latch, in one merged write (the silence is un-latched now the plane is rebuilt).
    // SECURITY (ASVS V6): breakGlassTokenRetired is DELIBERATELY re-applied from THIS DO's own current value,
    // never from the import -- an export is a point-in-time capture that may predate an Owner's retire, so
    // trusting it would let a reconcile/apply-staged (driven by a stale or attacker-retained export) silently
    // UN-RETIRE a token the Owner believed permanently disposed of. That transition may only happen through
    // the owner-gated, one-way setBreakGlassTokenRetired.
    async armAuthorityOrgPolicy(exp: ControlPlaneExport): Promise<void> {
      const currentRetired = await this.getBreakGlassTokenRetired();
      await this.writeOrgPolicy({
        requireConfigApproval: exp.orgPolicy.requireConfigApproval,
        ...(exp.orgPolicy.requireChangeNumber !== undefined ? { requireChangeNumber: exp.orgPolicy.requireChangeNumber } : {}),
        ...(exp.orgPolicy.attendedCadenceDays !== undefined ? { attendedCadenceDays: exp.orgPolicy.attendedCadenceDays } : {}),
        breakGlassTokenRetired: currentRetired,
        bootstrapConsumed: true,
        controlPlaneRecoveryRequired: false,
        controlPlaneRecoveryReason: "",
      });
    }

    // writeReconcileBridge writes the control-plane-reconciled BRIDGE audit event: the old hash chain is
    // gone (wiped with the DO), so this is the first event of the NEW chain, and its presence + the export's
    // priorAuditHead (returned to the caller) are the durable seam tying the new chain back to the pre-wipe head.
    async writeReconcileBridge(caller: NonNullable<CallerLike>): Promise<void> {
      await this.appendAudit({
        actorEmail: caller.email,
        actorMethod: "token",
        sourceIp: caller.sourceIp ?? null,
        action: "control-plane-reconciled",
        outcome: "success",
        target: { kind: "access-policy" },
      });
    }

    // reconcileControlPlane rebuilds the DO from a VERIFIED export slice (the router proves the break-glass
    // token + verifies the signature BEFORE calling this; the DO re-asserts the caller is the bare-token
    // break-glass as defence in depth). It REFUSES unless the control plane is empty AND the role table is
    // empty; there is no force overwrite (importing over a live estate is a separate, dual-control
    // operation, not a recovery, so it never clobbers a live plane's config or authority). The rebuild runs inside
    // blockConcurrencyWhile so no other handler interleaves mid-rebuild. It re-arms bootstrapConsumed (so a
    // post-reconcile caller cannot bootstrap a rogue Owner over the restored roles), clears the
    // recovery-required latch, consumes any staged auto-heal record, and writes a control-plane-reconciled
    // BRIDGE audit event referencing the export's priorAuditHead.
    async reconcileControlPlane(
      exp: ControlPlaneExport,
      caller: CallerLike,
    ): Promise<{ ok: true; downpipes: number; destinations: number; roles: number; bridgedFrom: { headSeq: number; headHash: string } }> {
      // Defence in depth: only the bare-token break-glass may reconcile (the router already gated it).
      if (caller === null || caller.method !== "token") {
        throw new AuthError("forbidden: control-plane reconcile requires the break-glass token");
      }
      // Recovery rebuilds a WIPED plane; it never overwrites a live one. Refuse if any config OR any
      // authority survives -- the role-table check mirrors applyControlPlaneAuthoritySlice (below) so the
      // manual path can never clobber existing authority the way an unguarded reconcile could: a
      // fresh-bootstrap Owner present, or a since-revoked operator a stale export would re-grant. There is
      // no force overwrite; importing over a live estate is a separate dual-control operation, not a recovery.
      if (!(await this.controlPlaneIsEmpty())) {
        throw new Error("control plane is not empty; a recovery import rebuilds a wiped plane, it does not overwrite a live one");
      }
      if (!(await this.roleTableIsEmpty())) {
        // Reaching this line means the plane IS empty (the check above) and authority SURVIVED, which is not
        // amnesia at all: whoami does not degrade a caller over a non-empty role table
        // (scheduler-do-rbac-authority.ts, the empty-table gate), so a real Owner is still signed in and the
        // cron's own no-authority resume slice restores the configuration without any human. The exit is
        // therefore the acknowledge, once the plane is back.
        throw new Error(
          "the role table is not empty; a recovery import refuses to overwrite existing authority. Your operator roles survived, so the plane was not wiped and this import is not your route: the scheduled health pass re-applies the configuration from the signed export on its own (it restores no authority), and once at least one downpipe or destination is back an owner clears the banner with POST /admin/control-plane/acknowledge-recovery",
        );
      }
      return await this.blockConcurrencyWhile(async () => {
        const dpCount = await this.applyResumeDownpipes(exp, false);
        const destN = await this.applyResumeDestinations(exp);
        const roleCount = await this.applyAuthorityRoles(exp);
        await this.applyResumeDiscovery(exp);
        await this.armAuthorityOrgPolicy(exp);
        await this.writeReconcileBridge(caller);
        // The staged auto-heal record (if any) has now been superseded by this explicit reconcile.
        await this.state.storage.delete(CONTROL_PLANE_STAGED_KEY);
        return { ok: true as const, downpipes: dpCount, destinations: destN, roles: roleCount, bridgedFrom: exp.priorAuditHead };
      });
    }

    // acknowledgeControlPlaneRecovery (CP-RECOVERY-LATCH-NO-CLEAR-PATH-AFTER-ORGANIC-RESUME) is
    // the NARROW escape reconcileControlPlane and applyControlPlaneAuthoritySlice cannot be: once a latched
    // plane organically un-empties -- the break-glass token is exempt from the recoveryRequired degrade
    // (resolveAuthority short-circuits it to owner before the latch is ever consulted), so break-glass-driven
    // activity during a latch can freely create downpipes/roles while recoveryRequired stays set -- BOTH of
    // the only routes that ever clear the latch refuse forever, because both require the plane AND the role
    // table to be empty. There is then no in-product way out: the banner is permanent even though the plane
    // has, in fact, recovered.
    //
    // REJECTED ALTERNATIVES (recorded here because the next reader of this
    // function needs to see why the obvious options are not what it does):
    //   * A dual-control "reconcile over a live plane" route (accept an export + confirmation even when the
    //     plane is non-empty) was rejected: it would let a signed-but-STALE export overwrite live downpipes,
    //     destinations or roles, silently reverting real customer changes or resurrecting revoked authority --
    //     the exact "recovery import overwrites a live estate" hazard the existing refusal exists to prevent.
    //     Reintroducing that hazard behind a confirmation checkbox is not a narrower fix, it is the same fix
    //     this row said not to build.
    //   * "Proceed when the export is verified equal to current state" was rejected: real state constantly
    //     drifts by fields an export cannot reproduce byte-for-byte (audit chain head, run counters, a role
    //     granted by break-glass AFTER the export was pulled, as happened here) so the equivalence check would
    //     still refuse in exactly the organic-resume case this exists to fix, while adding a fragile, easy-to-
    //     get-wrong comparison surface for no working benefit.
    //   * A plain unconditional latch clear was rejected because of the DEADLOCK
    //     (scheduler-do-rbac-authority.ts G061): if the role table is EMPTY (the plane un-emptied only via
    //     downpipes/destinations, never a role grant) and bootstrapConsumed is already spent, clearing the
    //     latch would not restore an Owner -- it would just remove the ONE signal (the recovery-required
    //     banner) that currently tells the customer why every caller resolves to viewer. That would trade a
    //     named, visible lockout for a silent, unnamed one. So this method REFUSES when the role table is
    //     empty (below), by construction never reaching the deadlock state; the break-glass reconcile stays
    //     the only remedy there.
    //
    // GUARD: only an authenticated caller may acknowledge (never the bare break-glass token -- if an owner
    // can authenticate at all, the role table is already non-empty, per whoami's own roleTableIsEmpty gate,
    // so there is always a real Owner to ask). Clears ONLY the two latch fields via the SAME
    // clearControlPlaneRecoveryRequired reconcile already uses; it never calls armAuthorityOrgPolicy, so
    // bootstrapConsumed is NEVER touched by this path and can never be re-armed by it. Writes a DISTINCT
    // audit action (control-plane-recovery-acknowledged) so the trail can tell an acknowledge-only clear
    // apart from a genuine reconcile carrying bridgedFrom.
    async acknowledgeControlPlaneRecovery(caller: CallerLike): Promise<{ ok: true; acknowledged: true }> {
      if (caller === null || caller.method === "token") {
        throw new AuthError("forbidden: acknowledging a recovered control plane requires an authenticated owner, not the break-glass token");
      }
      const latch = await this.getControlPlaneRecoveryRequired();
      if (!latch.required) {
        throw new Error("no recovery in effect; nothing to acknowledge");
      }
      // The deadlock guard: refuse over an empty role table so this can never trade a visible latch for the
      // silent G061 deadlock (empty table + spent bootstrap = every caller resolves to viewer, unexplained).
      if (await this.roleTableIsEmpty()) {
        // The guard reflects the G061 deadlock reasoning above. The tail message is conditional, because
        // "use the break-glass reconcile instead" is true on only one side of it: reconcileControlPlane
        // refuses a NON-EMPTY plane (above), so on an estate whose plane came back while the role table
        // stayed empty -- the break-glass token can create downpipes during a latch without granting any
        // role, which is precisely how that state arises -- that route would refuse them too.
        const planeEmpty = await this.controlPlaneIsEmpty();
        throw new Error(
          planeEmpty
            ? "the role table is empty; acknowledging would clear the one signal explaining why every caller is a viewer -- use the break-glass reconcile instead"
            : "the role table is empty; acknowledging would clear the one signal explaining why every caller is a viewer. The break-glass reconcile is NOT open to you either: it rebuilds a wiped plane and yours is no longer empty. Grant an owner role with the break-glass token first, then acknowledge as that owner",
        );
      }
      await this.clearControlPlaneRecoveryRequired();
      await this.appendAudit({
        actorEmail: caller.email,
        actorMethod: caller.method,
        sourceIp: caller.sourceIp ?? null,
        action: "control-plane-recovery-acknowledged",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return { ok: true as const, acknowledged: true as const };
    }

    // importControlPlaneDefinition is the CROSS-ENVIRONMENT estate import (the recovery keystone). Unlike the
    // same-account break-glass reconcile above, it is run BY a legitimately bootstrapped Owner on a FRESH engine
    // (the operator deployed a new engine, bootstrapped themselves, and is now importing the estate they lost),
    // and it GRANTS NO AUTHORITY: it rebuilds ONLY the DEFINITION (downpipes, destinations, discovery selection)
    // from a KIT-verified export. The Worker verified the export against the operator's OFFLINE signer.pub before
    // calling -- that is TAMPER EVIDENCE, not an authority root (whoever holds a public key could sign a
    // forgery), which is EXACTLY why no authority is imported. RBAC, group/custom roles, IdP trust and any
    // gate-weakening org policy are NEVER applied here -- the export's roles/idpConnections/notify/orgPolicy are
    // the operator's re-establish CHECKLIST. The operator's own bootstrap Owner stays the sole authority.
    //
    // crossAccount: when the export is from a DIFFERENT Cloudflare account, every native resource id in it is
    // foreign, so the imported downpipes are DISABLED until each source is re-pointed in the new account.
    //
    // GUARDS: the caller must be a REAL authenticated Owner (the Worker gates access.policy), never the bare
    // break-glass token (that is the same-account reconcile's path, not this one); and the plane must be FRESH
    // (no downpipes, no destinations -- the estate is not yet imported). The role table is NOT required empty:
    // the operator's bootstrap Owner is present, and their authority is never touched.
    // accountIdAbsent (G218): the export, or this engine, could not NAME its Cloudflare account. sameControlPlane
    // Account fails SAFE on a null on either side, so crossAccount comes back TRUE and every imported downpipe
    // lands DISABLED -- a "successful" import after which NOT ONE BACKUP RUNS. The customer sees their whole
    // estate back on the screen and nothing happening, and the difference between "this really is a different
    // account, re-point your sources" and "the export predates account discovery, so we could not tell" was
    // nowhere: both produced the same disabled roster. It rides on the response (which the console renders) and
    // into the pack, so the pack can say which of the two happened.
    async importControlPlaneDefinition(
      exp: ControlPlaneExport,
      crossAccount: boolean,
      caller: CallerLike,
      accountIdAbsent = false,
    ): Promise<{ ok: true; downpipes: number; destinations: number; downpipesDisabled: boolean; accountIdAbsent: boolean; authorityImported: false; bridgedFrom: { headSeq: number; headHash: string } }> {
      // Defence in depth: the import is by an authenticated Owner (the Worker gated access.policy), NOT the
      // bare break-glass token. A null or token caller is refused (a bare-token holder uses the reconcile path).
      if (caller === null || caller.method === "token") {
        throw new AuthError("forbidden: the estate import requires an authenticated Owner, not the break-glass token");
      }
      if (!(await this.controlPlaneIsEmpty())) {
        throw new Error("the control plane is not fresh; the estate import rebuilds a fresh engine, it does not merge into an existing estate");
      }
      return await this.blockConcurrencyWhile(async () => {
        // Cross-account: force every imported downpipe DISABLED (its native resource ids belong to the old
        // account; nothing may run until each source is re-pointed), by projecting enabled:false onto each.
        const definition: ControlPlaneExport = crossAccount
          ? { ...exp, downpipes: exp.downpipes.map((d) => ({ ...(d as DownpipeConfig), enabled: false })) }
          : exp;
        const dpCount = await this.applyResumeDownpipes(definition, false);
        const destN = await this.applyResumeDestinations(exp);
        await this.applyResumeDiscovery(exp);
        // NO AUTHORITY: roles, group/custom roles, IdP connections and the export's org policy are NOT applied.
        // The bridge event ties the new audit chain back to the pre-wipe head (the operator's own bootstrap
        // remains untouched; there is no bootstrap re-arm and no org-policy import that could weaken a gate).
        await this.writeReconcileBridge(caller);
        // G218: PERSIST the outcome, not only the response body (a one-shot artefact the operator's browser
        // consumes and drops, gone by the time the support pack is generated). A genuine cross-account import
        // and an accountIdAbsent one both disable every downpipe (the fail-safe null compare), but they carry
        // opposite remedies: re-point every source, or set the account id and re-import. This record is what
        // lets the pack tell the two apart.
        await this.recordControlPlaneImportOutcome({ crossAccount, accountIdAbsent, downpipesDisabled: crossAccount, downpipes: dpCount, destinations: destN });
        return { ok: true as const, downpipes: dpCount, destinations: destN, downpipesDisabled: crossAccount, accountIdAbsent, authorityImported: false as const, bridgedFrom: exp.priorAuditHead };
      });
    }

    // ---- (4) AUTO-RECONCILE-ON-DETECT (the safe auto-heal) --------------------------------------
    //
    // SAFETY MODEL. The signed export proves AUTHENTICITY but NOT FRESHNESS after a total DO wipe: the
    // engine retains no memory of the latest generation, so a destination-bucket-write attacker could prune
    // to an OLDER signed export (an engine-undetectable rollback). Re-instating a backup JOB from such an
    // export is operationally benign (it grants NO authority; a stale dest secret rides wrapped/reestablish
    // and fails loud). Re-granting RBAC/Owner from a rolled-back export could hand authority to a
    // since-revoked subject. So the auto-heal AUTO-APPLIES ONLY the no-authority RESUME slice
    // (downpipes/schedules/dest/discovery) -- backups resume immediately -- and STAGES the rest for a
    // break-glass human confirm. The silence-killer latch STAYS SET through the auto-heal, so authority is
    // NEVER silently re-bootstrapped to whoever calls first.

    // applyControlPlaneResumeSlice re-applies ONLY the no-authority resume slice (downpipes/dest/discovery)
    // from the staged export, so BACKUPS RESUME without a human. It grants NO authority: it does NOT restore
    // RBAC, does NOT clear the silence-killer latch and does NOT re-arm the first-Owner bootstrap, so a wiped
    // plane stays locked to recovery-required viewers (no silent re-bootstrap) until a break-glass confirm.
    // GUARD: the recovery latch MUST be set (only auto-resume while a detected amnesia is in effect) and a
    // staged export must be present. Idempotent (addDownpipe upserts, saveDestinations overwrites); it marks
    // the staged record resumeApplied so the cron does not re-run it, and records a control-plane-resumed
    // audit event. The whole apply runs inside blockConcurrencyWhile.
    async applyControlPlaneResumeSlice(): Promise<{ ok: true; downpipes: number; downpipesExpected: number; resumeSkipped: number; appliedVersion: number; destinations: number } | { ok: false; reason: string }> {
      const latch = await this.getControlPlaneRecoveryRequired();
      if (!latch.required) {
        await recordStagedApplyRefusal(this.state.storage, "no-latch");
        return { ok: false, reason: "no recovery in effect (the latch is not set)" };
      }
      const rec = await this.getControlPlaneRecoveryRecord();
      if (rec === null || rec.staged === undefined) {
        await recordStagedApplyRefusal(this.state.storage, "no-staged");
        return { ok: false, reason: "no staged export to resume from" };
      }
      const staged = rec.staged;
      // DEFENCE IN DEPTH: the cron's runControlPlaneAutoHeal already refuses to stage a filename-version /
      // signed-configVersion mismatch (a relabelled/replayed export), but this apply must not rely on that
      // upstream check alone -- re-assert it here too, so the invariant holds even if a future caller ever
      // stages an export by a path other than the hardened auto-heal.
      if (!candidateVersionMatchesExport({ version: staged.version }, staged.export)) {
        // G103: the recovery now STALLS here on every cron tick, forever, and the pack's recovery section says
        // only that a resume has not happened. The class is the whole diagnosis (a relabelled or replayed
        // export), and it was recorded nowhere.
        await recordStagedApplyRefusal(this.state.storage, "version-mismatch");
        return { ok: false, reason: "staged export version mismatch" };
      }
      return await this.blockConcurrencyWhile(async () => {
        const dpCount = await this.applyResumeDownpipes(staged.export, true);
        const destN = await this.applyResumeDestinations(staged.export);
        await this.applyResumeDiscovery(staged.export);
        // Resume-apply DIAGNOSTICS (CPR needs-logging: autoheal-resume-malformed-downpipe-skip +
        // stale-generation-rollback-after-wipe). The tolerant apply SKIPS a malformed downpipe so one bad
        // config never blocks the fleet; record how many were expected vs how many were skipped, and the
        // GENERATION this export applied (a signed-but-stale rollback after a wipe is then visible next to
        // the head config version). Ints only; no config value.
        const expected = staged.export.downpipes.length;
        const resumeSkipped = Math.max(0, expected - dpCount);
        const appliedVersion = staged.export.configVersion;
        // Mark the resume applied so the cron does not re-resume every tick; the latch + empty role table
        // (untouched here) keep authority gated until the break-glass confirm.
        await this.state.storage.put(CONTROL_PLANE_STAGED_KEY, {
          staged: { ...staged, resumeApplied: true, resumeSkipped, appliedVersion, appliedAt: nowMillisISO() },
        } satisfies ControlPlaneRecoveryRecord);
        await this.appendAudit({
          actorEmail: null,
          actorMethod: "engine",
          sourceIp: null,
          action: "control-plane-resumed",
          outcome: "success",
          target: { kind: "access-policy" },
        });
        return { ok: true as const, downpipes: dpCount, downpipesExpected: expected, resumeSkipped, appliedVersion, destinations: destN };
      });
    }

    // applyControlPlaneAuthoritySlice is the BREAK-GLASS-GATED authority restore the operator confirms: it
    // restores RBAC from the STAGED export (the Worker re-verified its signature before calling), re-arms
    // bootstrapConsumed, CLEARS the silence-killer latch and writes the control-plane-reconciled BRIDGE
    // event. It is the rollback-defence checkpoint (a human re-asserts the staged generation is the right
    // one). GUARD: only the bare-token break-glass; the recovery latch must be set; a staged export must be
    // present; and the role table MUST be empty (it never clobbers existing authority). It also (re-)applies
    // the resume slice so authority can be restored even if the cron never ran it. Runs in blockConcurrencyWhile.
    async applyControlPlaneAuthoritySlice(
      caller: CallerLike,
    ): Promise<{ ok: true; roles: number; bridgedFrom: { headSeq: number; headHash: string } }> {
      if (caller === null || caller.method !== "token") {
        throw new AuthError("forbidden: the control-plane authority restore requires the break-glass token");
      }
      const latch = await this.getControlPlaneRecoveryRequired();
      if (!latch.required) throw new Error("no recovery in effect; nothing staged to confirm");
      const rec = await this.getControlPlaneRecoveryRecord();
      if (rec === null || rec.staged === undefined) throw new Error("no staged export to confirm");
      if (!(await this.roleTableIsEmpty())) {
        // CP-RECOVERY-LATCH defect 23, the sibling of reconcileControlPlane's refusal above and reached by the
        // same accounts. Refusal unchanged, remedy now named, and split on the plane's own emptiness because
        // the two halves have different next steps rather than different wording.
        const planeEmpty = await this.controlPlaneIsEmpty();
        throw new Error(
          planeEmpty
            ? "the role table is not empty; refusing to overwrite existing authority during recovery. Your operator roles survived, so there is no access to restore here: the staged export's no-authority resume slice puts the configuration back on the next health pass, and an owner then clears the banner with POST /admin/control-plane/acknowledge-recovery"
            : "the role table is not empty; refusing to overwrite existing authority during recovery. Your operator roles survived and your configuration is already back, so nothing here needs restoring: an owner clears the banner with POST /admin/control-plane/acknowledge-recovery",
        );
      }
      // DEFENCE IN DEPTH: same re-assertion as applyControlPlaneResumeSlice -- never trust a staged
      // record's filename-version/signed-body pairing implicitly, even though only the hardened cron
      // auto-heal stages one today.
      if (!candidateVersionMatchesExport({ version: rec.staged.version }, rec.staged.export)) {
        throw new Error("staged export version mismatch");
      }
      const exp = rec.staged.export;
      return await this.blockConcurrencyWhile(async () => {
        // Ensure the resume slice is in place (idempotent) so a confirm before the cron resumed still works.
        await this.applyResumeDownpipes(exp, true);
        await this.applyResumeDestinations(exp);
        await this.applyResumeDiscovery(exp);
        const roleCount = await this.applyAuthorityRoles(exp);
        await this.armAuthorityOrgPolicy(exp);
        await this.writeReconcileBridge(caller);
        await this.state.storage.delete(CONTROL_PLANE_STAGED_KEY);
        return { ok: true as const, roles: roleCount, bridgedFrom: exp.priorAuditHead };
      });
    }

    // reconciledDestination rebuilds a StoredDestination from an ExportedDestination: the wrapped secret
    // rides back when present; an omitted secret becomes "" (loud-fail-until-re-entered, never silent). The
    // STS externalId was never exported, so a reconciled STS destination needs its externalId re-entered.
    reconciledDestination(d: ExportedDestination): StoredDestination {
      const secretAccessKey = "wrapped" in d.secret ? d.secret.wrapped : "";
      // Re-validate the optional non-secret config fields through the SAME validators the store path uses
      // (defence in depth: a malformed value in an imported artefact is dropped, never trusted blindly).
      const worm = validateWormPolicyValue(d.worm);
      const addressing = validateAddressing(d.addressing);
      const storageClass = validateStorageClass(d.storageClass);
      const pricing = validateDestPricing(d.pricing);
      const azureEntra = validateAzureEntraDirectory(d.azureEntra);
      return {
        id: d.id,
        label: d.label,
        endpoint: d.endpoint,
        bucket: d.bucket,
        region: d.region,
        accessKeyId: d.accessKeyId,
        secretAccessKey,
        setAt: d.setAt,
        setBy: d.setBy,
        verifiedAt: d.verifiedAt,
        deleteProbe: d.deleteProbe,
        ...(worm !== null ? { worm } : {}),
        ...(d.objectLock !== undefined ? { objectLock: d.objectLock } : {}),
        ...(d.assumeRole !== undefined ? { assumeRole: { roleArn: d.assumeRole.roleArn, ...(d.assumeRole.durationSeconds !== undefined ? { durationSeconds: d.assumeRole.durationSeconds } : {}) } } : {}),
        ...(addressing !== undefined ? { addressing } : {}),
        ...(storageClass !== undefined ? { storageClass } : {}),
        ...(azureEntra !== null ? { azureEntra } : {}),
        ...(pricing !== null ? { pricing } : {}),
      };
    }
  };
}
