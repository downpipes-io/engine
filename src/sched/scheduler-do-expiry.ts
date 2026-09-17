// The Credential and key expiry tracker. ExpiryMixin layers these methods over a base whose `this` is
// SchedulerDOSurface, so they call `this.appendAudit` / `this.requireCapability` / `this.state` directly.
// The tracked items live under the `expiry:` prefix in this DO; writes are gated by the same expiry.config
// re-check in the same order throughout.

import { countCleanupPending, countWarnings, crossingThreshold, daysRemainingFor, EXPIRY_COOLDOWN_PREFIX, EXPIRY_PREFIX, type ExpiryItem, type ExpiryKind, type ExpiryLifecycleClass, type ExpiryStatus, expiryRowAnomalies, expiryStatuses, laddersFor, shouldNotifyExpiry, validateExpiryItem } from "../admin/expiry.ts";
import type { AuthMethod, Capability, Role } from "../admin/identity.ts";
import { cadenceEntryFor, isSecretRotationId, ROTATION_PREFIX, type RotationMarker, rotationItemId, rotationNowISO, SECRET_ROTATION_CADENCES } from "../admin/secret-rotation.ts";
import { log } from "../log.ts";
import { classifyExpiryItem, recordExpiryObserveFault, recordStorageAnomaly } from "./sched-fault-ledger.ts";
import type { ExpiryCooldown, ExpiryEmission, SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

export function ExpiryMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Credential and key expiry tracker -------------------------------------------------
    // The tracked items live under the `expiry:` prefix in THIS DO, keyed by `expiry:<id>`. Writes are
    // gated by the router on expiry.config AND re-checked here from the forwarded caller
    // (requireCapability, defence in depth like requireNotifyConfig). The route returns the COMPUTED
    // ExpiryStatus projection (the daysRemaining + state view), never the raw items, so a reader always
    // sees the same shape the cron and status compute. The cron's transition-based credential-expiry
    // emission uses a per-item last-notified threshold record under `expiry-cooldown:<id>`, exactly the
    // ALERT_COOLDOWN_PREFIX discipline. NO-CUSTODY: an ExpiryItem carries only redaction-safe metadata
    // (label, kind, expiry, source, note); the type has no field that could hold a secret.

    // listExpiryItemsRaw reads the whole item set once (small: tracked credentials, not runs).
    async listExpiryItemsRaw(): Promise<ExpiryItem[]> {
      const map = await this.state.storage.list<ExpiryItem>({ prefix: EXPIRY_PREFIX });
      const items = [...map.values()];
      // A stored row whose expiresAt does not parse reads GREEN for ever (stateFor(NaN) -> "ok") and never
      // crosses a notify rung (crossingThreshold(NaN) -> null): a safe-default read that destroys the
      // evidence it was taken on. This is the one place every expiry read passes through, so the anomaly is
      // counted here. Throttled (the status probe reads this on a hot path) and best-effort: a diagnostic
      // must never break the read it observes. Counts only, never the row.
      //
      // The UNKNOWN-KIND anomaly is deliberately NOT counted, and expiryRowAnomalies still reports it because
      // it is a true statement about the rows: it is simply not a FAULT. An off-vocabulary kind is not
      // skipped by the kind-aware ladder -- laddersFor is TOTAL, so a garbled kind takes the default 30-day
      // ladder rather than being dropped, and the row is still counted, still laddered and still warned
      // about. The only kind check in the system is at WRITE time (isExpiryKind), and that refusal has its
      // own producer (stored-expiry-write-rejected). Counting a skip the code does not perform would be a
      // false alarm that devalues every true signal beside it.
      const anomalies = expiryRowAnomalies(items);
      if (anomalies.unparseableTimestamp > 0) void this.recordAdminCountersThrottled(["stored-expiry-unparseable-timestamp"]);
      return items;
    }

    // listExpiryStatuses serves GET /expiry: the computed ExpiryStatus[] (daysRemaining + state),
    // soonest-first. Any authenticated role may read it (the router gates). It computes from the stored
    // items at the DO clock, so the console never re-derives daysRemaining and the cron/status agree.
    async listExpiryStatuses(): Promise<ExpiryStatus[]> {
      const items = await this.listExpiryItemsRaw();
      return expiryStatuses(items, Date.now());
    }

    // addExpiryItem validates and upserts a tracked item. expiry.config re-checked.
    // The shape is validated by the shared validateExpiryItem (a bounded id/label, a valid kind, a
    // parseable expiry, manual/observed source, an optional bounded note). The id is the operator's own
    // key (a stable handle they can update/delete by), validated as a safe storage-key fragment. It
    // returns the stored ExpiryItem. Records NOTHING to the audit chain: like a notify channel, a tracked
    // expiry item is configuration, not a first-class privileged action, and it carries no secret to
    // attribute. A re-add for the same id overwrites (a natural "update the expiry" edit).
    async addExpiryItem(
      raw: unknown,
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<ExpiryItem> {
      this.requireCapability(caller, "expiry.config");
      const v = validateExpiryItem(raw);
      if (!v.ok) throw new Error(v.reason);
      // Carry an operator-set note forward when this edit does not supply one. The note is write-only
      // (never returned to the console, expiry.ts projectMeta), so an edit that leaves the note blank
      // cannot resend it; without this the full put below would overwrite the item and silently drop the
      // stored note. Mirrors the observed-refresh path's own note carry-forward. Only the note needs it:
      // purpose IS returned, so the console resends it, and a genuinely new item has no existing note.
      let item = v.item;
      if (item.note === undefined) {
        const existing = (await this.state.storage.get<ExpiryItem>(`${EXPIRY_PREFIX}${item.id}`)) ?? null;
        if (existing?.note !== undefined) item = { ...item, note: existing.note };
      }
      await this.state.storage.put(`${EXPIRY_PREFIX}${item.id}`, item);
      return item;
    }

    // deleteExpiryItem removes a tracked item by id (expiry.config re-checked), idempotent (deleting an
    // absent item returns deleted:false). It also drops the per-item notification cooldown so a later
    // item re-added under the same id starts with a clean transition slate (no stale last-notified rung
    // lingering), mirroring removeDownpipe dropping the alert cooldown.
    async deleteExpiryItem(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      this.requireCapability(caller, "expiry.config");
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id is required");
      const deleted = await this.state.storage.delete(`${EXPIRY_PREFIX}${req.id}`);
      await this.state.storage.delete(`${EXPIRY_COOLDOWN_PREFIX}${req.id}`);
      return { deleted };
    }

    // seedSecretRotationItems keeps the credential-lifecycle registry's rotation:<id> rows
    // in step with which of the seven cadenced secrets (secret-rotation.ts) are in service, on every
    // reconcile tick. The DO holds no env of its own; the router resolves the live bindings + the public-
    // key fingerprints (SIGNER_PRIVATE/BREAK_GLASS_PUBLIC/OPERATIONAL_PUBLIC) on the Worker side and
    // forwards them in the reconcile request body.
    //
    // For each cadence entry still in service: an absent marker is seeded with at=now (the conservative
    // baseline: a fresh install or upgrade is never assumed overdue on day one), matching the
    // control-plane's own "unmarked = just seeded" precedent. A public-key entry whose CURRENT fingerprint
    // differs from the STORED one is a rotation the engine can observe directly (a new key was installed),
    // so its baseline resets to now WITHOUT an operator attestation; the very first fingerprint seen is
    // recorded without resetting the baseline (nothing about a first observation implies a rotation just
    // happened). A bearer/destination credential never carries a fingerprint (no-custody): its baseline
    // only ever moves via POST /admin/secrets/rotated (confirmSecretRotation).
    //
    // A secret no longer in service (the binding was removed, or -- ADMIN_TOKEN only -- the operator set
    // ADMIN_TOKEN_DISABLED or retired the break-glass token) has its tracked row and marker DROPPED rather
    // than left ticking down on a secret this deployment no longer uses, mirroring observeLicence's
    // delete-on-clear.
    async seedSecretRotationItems(forwarded: { presentBindings?: Record<string, boolean>; fingerprints?: Record<string, string | null>; adminTokenDisabled?: boolean }): Promise<void> {
      const present = forwarded.presentBindings ?? {};
      const fingerprints = forwarded.fingerprints ?? {};
      const adminTokenDisabled = forwarded.adminTokenDisabled === true;
      const breakGlassRetired = await this.getBreakGlassTokenRetired();
      for (const entry of SECRET_ROTATION_CADENCES) {
        const markerKey = `${ROTATION_PREFIX}${entry.id}`;
        const bound = entry.bindings.some((b) => present[b] === true);
        const inService = bound && !(entry.id === "admin_token" && (adminTokenDisabled || breakGlassRetired));
        if (!inService) {
          await this.state.storage.delete(markerKey);
          await this.deleteObservedItem(rotationItemId(entry.id));
          continue;
        }
        const existing = (await this.state.storage.get<RotationMarker>(markerKey)) ?? null;
        let marker: RotationMarker;
        if (existing === null) {
          const fp = entry.fingerprintBinding !== undefined ? (fingerprints[entry.fingerprintBinding] ?? null) : null;
          marker = { at: rotationNowISO(), actor: null, ...(fp !== null ? { fingerprint: fp } : {}) };
          await this.state.storage.put(markerKey, marker);
        } else {
          marker = existing;
          if (entry.fingerprintBinding !== undefined) {
            const fp = fingerprints[entry.fingerprintBinding] ?? null;
            if (fp !== null && marker.fingerprint !== undefined && marker.fingerprint !== fp) {
              // A rotation OBSERVED, not attested: the installed key's fingerprint moved.
              marker = { at: rotationNowISO(), actor: null, fingerprint: fp };
              await this.state.storage.put(markerKey, marker);
            } else if (fp !== null && marker.fingerprint === undefined) {
              // A marker that predates fingerprint tracking: record the baseline without resetting `at`.
              marker = { ...marker, fingerprint: fp };
              await this.state.storage.put(markerKey, marker);
            }
          }
        }
        const expiresAt = new Date(Date.parse(marker.at) + entry.cadenceDays * 24 * 60 * 60 * 1000).toISOString();
        await this.upsertObservedItem({
          id: rotationItemId(entry.id),
          label: entry.label,
          kind: entry.kind,
          lifecycleClass: "functional",
          purpose: "Planned rotation per the documented schedule",
          expiresAt,
        });
      }
    }

    // confirmSecretRotation serves POST /admin/secrets/rotated (router-keys.ts, owner-exclusive keys.
    // ceremony + rate-limited): an operator attests they rotated a bearer or destination credential the
    // engine cannot fingerprint (a public-key secret is refused here; its rotation is engine-observed by
    // seedSecretRotationItems instead). Moves the marker's baseline to now, re-seeds the tracked row so
    // posture reads clean immediately, and audits the confirmation by secret id only -- never a value.
    async confirmSecretRotation(
      body: { secret?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; expiresAt: string }> {
      this.requireCapability(caller, "keys.ceremony");
      const id = body.secret;
      if (!isSecretRotationId(id)) throw new Error("secret must be one of the tracked rotation ids");
      const entry = cadenceEntryFor(id);
      if (entry.kind !== "credential") throw new Error(`${id} is fingerprint-observed and cannot be confirmed manually`);
      const at = rotationNowISO();
      const marker: RotationMarker = { at, actor: caller?.email ?? null };
      await this.state.storage.put(`${ROTATION_PREFIX}${entry.id}`, marker);
      const expiresAt = new Date(Date.parse(at) + entry.cadenceDays * 24 * 60 * 60 * 1000).toISOString();
      await this.upsertObservedItem({
        id: rotationItemId(entry.id),
        label: entry.label,
        kind: entry.kind,
        lifecycleClass: "functional",
        purpose: "Planned rotation per the documented schedule",
        expiresAt,
      });
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ?? null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "secret-rotation-confirmed",
        outcome: "success",
        target: { kind: "secret-rotation", secretId: entry.id },
      });
      return { ok: true, expiresAt };
    }

    // reconcileExpiry is the INTERNAL transition detector the cron driver calls each tick (mirroring
    // reconcileAlerts). It is a near no-op (one storage list) when no item is tracked. Otherwise, for
    // each item it computes daysRemaining and the lowest NOTIFICATION RUNG reached, and emits a
    // credential-expiry notification ONLY when the item has crossed a NEW (lower) rung than last notified
    // (shouldNotifyExpiry), recording the new rung in the per-item cooldown so the next tick does not
    // re-spam. An item that is no longer approaching (it was edited further out, or never reached a rung)
    // has its cooldown cleared so a future descent re-alerts. It returns redaction-safe emissions (the
    // event/severity, a null downpipeId since expiry is account-level, and a one-line detail of the label
    // + days-remaining) for the Worker to route out-of-band; the DO does NO network I/O (the same
    // separation as reconcileAlerts and the seal). The detail carries ONLY the label + a day count,
    // never a secret. severity is warning (the fixed credential-expiry severity); an EXPIRED item is also
    // warning per the contract's mapping, surfaced by the detail wording.
    async reconcileExpiry(forwarded?: { presentBindings?: Record<string, boolean>; fingerprints?: Record<string, string | null>; adminTokenDisabled?: boolean }): Promise<{ emissions: ExpiryEmission[] }> {
      // Secret-rotation cadence: seed/refresh the seven cadenced secrets' tracked rows BEFORE the ladder
      // walk below, so a newly-seeded or freshly-observed-rotated item is laddered on the SAME tick it
      // changes, exactly like every other observed item already is.
      await this.seedSecretRotationItems(forwarded ?? {});
      const items = await this.listExpiryItemsRaw();
      if (items.length === 0) return { emissions: [] };
      const now = Date.now();
      const emissions: ExpiryEmission[] = [];
      for (const item of items) {
        const cooldownKey = `${EXPIRY_COOLDOWN_PREFIX}${item.id}`;
        const cooldown = (await this.state.storage.get<ExpiryCooldown>(cooldownKey)) ?? null;
        // The first notification rung is kind-aware (laddersFor): a certificate/licence earns the 60-day
        // rung, everything else starts at 30. The COARSE state boundary stays 30 for all kinds (expiry.ts).
        const ladder = laddersFor(item.kind);
        const daysRemaining = daysRemainingFor(item.expiresAt, now);
        // A corrupt row's unparseable-timestamp anomaly is counted ONCE, at listExpiryItemsRaw above: that
        // is the ONE place every expiry read passes through, so a corrupt row is seen on a status read as
        // well as on this reconcile pass, and it is seen even in the weeks when the cron never fires.
        // Counting it a second time HERE would double it on exactly the path that matters most -- the
        // reconcile reads the items through that chokepoint and then walks them again in this loop -- and a
        // doubled count would misstate how many rows are corrupt.
        const rung = shouldNotifyExpiry(daysRemaining, cooldown?.threshold, ladder);
        if (rung !== null) {
          // Build the redaction-safe one-liner: the label + the urgency. An expired item (daysRemaining
          // <= 0) reads "has expired"; an approaching one reads "expires in N day(s)". Neither carries a
          // secret; the label is the operator's own redaction-safe description and the count is an integer.
          const detail = daysRemaining <= 0
            ? `${item.label} has expired`
            : `${item.label} expires in ${daysRemaining} day${daysRemaining === 1 ? "" : "s"}`;
          emissions.push({ id: item.id, detail });
          await this.state.storage.put(cooldownKey, { threshold: rung, at: now } satisfies ExpiryCooldown);
        } else if (cooldown !== null && crossingThreshold(daysRemaining, ladder) === null) {
          // The item is no longer approaching (back above the highest rung, e.g. the expiry was pushed
          // out): clear the cooldown so a future descent alerts from the top of the ladder again.
          await this.state.storage.delete(cooldownKey);
        }
      }
      return { emissions };
    }

    // expiryWarningCount serves the status probe: the count of approaching+expired items, computed from
    // the stored items at the DO clock. It is a single prefix list and an integer; it carries no item
    // and no secret. status.ts surfaces it presence-safe as expiryWarnings.
    // `expiryWarnings` counts the rows whose state is approaching or expired, and a row whose stored
    // `expiresAt` does not parse is NEITHER: `stateFor(NaN)` answers "ok". So a row damaged by truncation, a
    // zero value, a wrong type, encoding corruption or a valid-shape-wrong-value edit reads identically to
    // an account tracking nothing at all -- the count alone does not tell the operator anything changed.
    //
    // The unparseable-timestamp anomaly is already counted at listExpiryItemsRaw, the chokepoint every
    // expiry read passes through. `expiryUnreadable` carries that count onto the surface the console badges
    // from, so a row the engine cannot assess shows up as a figure of its own rather than as silence.
    //
    // It is a SEPARATE figure and not folded into `expiryWarnings`, because "expires soon" and "cannot be
    // read" are different tickets: the first is renewed on a schedule and the second is a damaged record that
    // renewing will not fix. Folding them would trade one conflation for another.
    async expiryWarningCount(): Promise<{ expiryWarnings: number; cleanupPending: number; expiryUnreadable: number }> {
      const items = await this.listExpiryItemsRaw();
      const statuses = expiryStatuses(items, Date.now());
      const expiryUnreadable = expiryRowAnomalies(items).unparseableTimestamp;
      if (expiryUnreadable > 0) await recordStorageAnomaly(this.state.storage, "expiry-row-unreadable-surfaced");
      return { expiryWarnings: countWarnings(statuses), cleanupPending: countCleanupPending(statuses), expiryUnreadable };
    }

    // upsertObservedItem writes an engine-OBSERVED expiry item directly under expiry:<id> (credential
    // lifecycle registry). It BYPASSES change-control (there is no human caller; an observed item must
    // never be dual-control-queued) AND the expiry.config capability gate (the engine is the author, and
    // the SOURCE artefact was already gated at its own write: a SAML/IdP connection under keys.ceremony,
    // a mint under owner, an attach under keys.ceremony, a licence under owner). It is the ONLY producer
    // of source:"observed". It validates through the shared validateExpiryItem (defence in depth), stamps
    // observedAt, MERGES an operator's existing note/purpose on the same id (so an auto-refresh never
    // clobbers operator context), and does NOT call autoSnapshotConfig (a per-cert/licence/mint observe
    // must not trigger an unbounded snapshot, nor a snapshot with a null caller). It NEVER throws OUT:
    // every caller additionally try/catches it so a malformed or failed observation degrades to "no
    // observation this tick" (fail-open), never failing the host operation it piggy-backs on. The item
    // carries only redaction-safe metadata (no secret, no fingerprint) by the type's construction.
    async upsertObservedItem(partial: {
      id: string;
      label: string;
      kind: ExpiryKind;
      expiresAt?: string; // omit for a no-expiry observed item (e.g. a never-expiring Cloudflare token)
      lifecycleClass?: ExpiryLifecycleClass;
      purpose?: string; // engine-supplied default purpose; an operator's own purpose (if set) is preserved
      permissionSummary?: string;
      usageLink?: { kind: "destination" | "idpConnection" | "sourceBinding"; refId: string };
      tokenRef?: string;
      usedAt?: string;
      cleanupState?: "pending" | "attested-deleted";
    }): Promise<void> {
      try {
        const key = `${EXPIRY_PREFIX}${partial.id}`;
        const existing = (await this.state.storage.get<ExpiryItem>(key)) ?? null;
        const raw: Record<string, unknown> = {
          id: partial.id,
          label: partial.label,
          kind: partial.kind,
          source: "observed",
          observedAt: nowMillisISO(),
          // An absent expiresAt is the no-expiry case; noExpiry lets validateExpiryItem accept it for the
          // kinds where that is legal (never a certificate/licence, which always carry a date).
          ...(partial.expiresAt !== undefined ? { expiresAt: partial.expiresAt } : { noExpiry: true }),
          ...(partial.lifecycleClass !== undefined ? { lifecycleClass: partial.lifecycleClass } : {}),
          ...(partial.permissionSummary !== undefined ? { permissionSummary: partial.permissionSummary } : {}),
          ...(partial.usageLink !== undefined ? { usageLink: partial.usageLink } : {}),
          ...(partial.tokenRef !== undefined ? { tokenRef: partial.tokenRef } : {}),
          ...(partial.usedAt !== undefined ? { usedAt: partial.usedAt } : {}),
          ...(partial.cleanupState !== undefined ? { cleanupState: partial.cleanupState } : {}),
          // Carry forward operator-set context so an auto-refresh does not erase it; fall back to an
          // engine-supplied default purpose only when the operator has not set one of their own.
          ...(existing?.note !== undefined ? { note: existing.note } : {}),
          ...(existing?.purpose !== undefined ? { purpose: existing.purpose } : (partial.purpose !== undefined ? { purpose: partial.purpose } : {})),
        };
        const v = validateExpiryItem(raw);
        if (!v.ok) {
          // A REJECTED observation means this credential is not tracked at all, so the warning ladder
          // can never arm for it and the lapse is discovered when the cert dies. The rejection reason is
          // operator-facing free text and stays in Workers Logs; the pack gets the closed kind + fault class.
          await recordExpiryObserveFault(this.state.storage, classifyExpiryItem(partial.id), "validate-rejected");
          // The same fact is also raised as the pack's HEADLINE counter beside the richer per-kind
          // expiryObserveFaults row -- the same alarm-bell-plus-detail split the cron counters already use
          // elsewhere. A non-zero counter here says plainly "an item the engine tried to enrol was refused
          // at write time, so NO warning can ever fire for it", which is the fact a support engineer needs
          // before they read anything else in the credentials surface. Counts only: never the item.
          await this.bumpAdminCounterLocal("stored-expiry-write-rejected");
          log("error", `observed expiry item rejected for ${partial.id}: ${v.reason}`);
          return;
        }
        await this.state.storage.put(key, v.item);
      } catch (e) {
        // The upsert THREW, so the tracked row is stale or absent and the countdown silently froze.
        await recordExpiryObserveFault(this.state.storage, classifyExpiryItem(partial.id), "storage-fault");
        log("error", `upsertObservedItem failed for ${partial.id}: ${(e as Error).message}`);
      }
    }

    // deleteObservedItem drops an engine-observed item + its cooldown when its source artefact is removed
    // (an IdP connection deleted, a licence cleared, an ingest credential revoked). Fail-open.
    async deleteObservedItem(id: string): Promise<void> {
      try {
        await this.state.storage.delete(`${EXPIRY_PREFIX}${id}`);
        await this.state.storage.delete(`${EXPIRY_COOLDOWN_PREFIX}${id}`);
      } catch (e) {
        log("error", `deleteObservedItem failed for ${id}: ${(e as Error).message}`);
      }
    }

    // observeLicence is the INTERNAL hook the router calls after a licence is activated/cleared: it writes
    // or refreshes the observed `licence` expiry item from the licence token's own notAfter (an artefact
    // the engine already holds and verifies, no secret to retain), or deletes it when the licence falls
    // back to community (notAfter null). It is CONDITIONAL, when the stored expiresAt already matches, it
    // skips the write (a no-op refresh costs only one read), so it stays cheap if the router ever calls it
    // on a hot path. Fail-open: a hiccup degrades to "no observation", never affecting the licence response.
    async observeLicence(body: { notAfter?: unknown }): Promise<{ ok: true }> {
      try {
        const notAfter = typeof body.notAfter === "string" && Number.isFinite(Date.parse(body.notAfter)) ? body.notAfter : null;
        if (notAfter === null) {
          // An UNPARSEABLE date is not the same fact as "no licence expiry". Both delete the tracked row
          // (which is the safe behaviour), but only one of them means the console silently stopped warning
          // about a licence that is still expiring. Record the date-shaped case; never the date value itself.
          if (typeof body.notAfter === "string" && body.notAfter.length > 0) await recordExpiryObserveFault(this.state.storage, "licence", "unparseable-date");
          await this.deleteObservedItem("licence");
          return { ok: true };
        }
        const existing = (await this.state.storage.get<ExpiryItem>(`${EXPIRY_PREFIX}licence`)) ?? null;
        if (existing && existing.expiresAt === notAfter) return { ok: true }; // unchanged: no write
        await this.upsertObservedItem({ id: "licence", label: "Assurance licence", kind: "licence", lifecycleClass: "functional", expiresAt: notAfter });
      } catch (e) {
        await recordExpiryObserveFault(this.state.storage, "licence", "storage-fault");
        log("error", `observeLicence failed: ${(e as Error).message}`);
      }
      return { ok: true };
    }

    // observeAttach is the INTERNAL hook the router calls AFTER a source attach has succeeded and been
    // post-verified: it records the spent EPHEMERAL Cloudflare attach token as a redaction-safe registry
    // row (kind:token, lifecycleClass:ephemeral, cleanupState:pending) so the operator is reminded to
    // delete it in Cloudflare. It receives ONLY the PUBLIC token id (account-owned tokens), its expires_on,
    // a permission SUMMARY (the needed-capability labels) and the attached source NAMES, never the token
    // value. Keyed by the token id, so re-attaching with the SAME token refreshes the same pending row; a
    // user-owned token (no id) uses a per-attach fallback id and the copy cannot name WHICH token to delete.
    // Fail-open: a hiccup degrades to "no cleanup row this attach", never affecting the attach.
    async observeAttach(body: { tokenId?: unknown; expiresOn?: unknown; permissionSummary?: unknown; sourcesAttached?: unknown }): Promise<{ ok: true }> {
      try {
        const tokenId = typeof body.tokenId === "string" && body.tokenId.length > 0 ? body.tokenId : undefined;
        const expiresOn = typeof body.expiresOn === "string" && Number.isFinite(Date.parse(body.expiresOn)) ? body.expiresOn : undefined;
        const permissionSummary = typeof body.permissionSummary === "string" ? body.permissionSummary : undefined;
        const attached = Array.isArray(body.sourcesAttached) ? (body.sourcesAttached as unknown[]).filter((s): s is string => typeof s === "string") : [];
        const id = tokenId !== undefined ? `attach-token-${tokenId}` : `attach-token-${Date.now()}`;
        await this.upsertObservedItem({
          id,
          label: "Cloudflare attach/deploy token",
          kind: "token",
          lifecycleClass: "ephemeral",
          cleanupState: "pending",
          usedAt: nowMillisISO(),
          purpose: attached.length > 0
            ? `Used once to attach: ${attached.join(", ")}. Delete it in Cloudflare once the attach is confirmed.`
            : "One-shot attach/deploy token. Delete it in Cloudflare once the attach is confirmed.",
          ...(expiresOn !== undefined ? { expiresAt: expiresOn } : {}),
          ...(tokenId !== undefined ? { tokenRef: tokenId } : {}),
          ...(permissionSummary !== undefined ? { permissionSummary } : {}),
        });
      } catch (e) {
        log("error", `observeAttach failed: ${(e as Error).message}`);
      }
      return { ok: true };
    }

    // cleanupAttest flips an ephemeral item's cleanupState to "attested-deleted" after the operator
    // confirms (in the console) they deleted the spent credential in Cloudflare. It is an operator
    // ATTESTATION ONLY, the engine holds no Cloudflare API token and cannot verify Cloudflare-side state,
    // so it never reads "verified". expiry.config is RE-CHECKED here (defence in depth; the router gates
    // first). Idempotent: attesting an absent item is a no-op. Audited with a closed, secret-free target
    // (the item id + the PUBLIC token id descriptor, never a value).
    async cleanupAttest(
      body: { id?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; updated: boolean }> {
      this.requireCapability(caller, "expiry.config");
      const id = typeof body.id === "string" ? body.id : "";
      if (id.length === 0) throw new Error("id is required");
      const key = `${EXPIRY_PREFIX}${id}`;
      const existing = await this.state.storage.get<ExpiryItem>(key);
      if (!existing) return { ok: true, updated: false };
      const updated: ExpiryItem = { ...existing, cleanupState: "attested-deleted" };
      await this.state.storage.put(key, updated);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "expiry-cleanup-attested",
        outcome: "success",
        target: { kind: "credential-cleanup", itemId: id, ...(existing.tokenRef !== undefined ? { tokenRef: existing.tokenRef } : {}) },
      });
      return { ok: true, updated: true };
    }
  };
}
