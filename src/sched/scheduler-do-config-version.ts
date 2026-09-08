// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the config-as-a-source versioning
// subsystem (Phase 4, the DEFAULT self-contained history layer) extracted from the SchedulerDO god
// module into a mixin. ConfigVersionMixin layers these methods over a base whose `this` is
// SchedulerDOSurface, so gatherConfigSnapshot keeps reading the per-subsystem state (now resident in
// sibling mixins) through `this` exactly as before; dispatch and `this` binding are byte-identical. The
// CONFIG_HISTORY_* keys, the hash chain and the snapshot/diff shapes are unchanged. No storage key,
// route, status code, response body or auth gate changed.

import { buildConfigVersion, CONFIG_GENESIS_PREV_HASH, CONFIG_HISTORY_CAP, CONFIG_HISTORY_PREFIX, type ConfigBodyScan, type ConfigChainVerdict, type ConfigChange, type ConfigSnapshot, type ConfigVersion, configHistoryKey, diffConfig, type SnapshotInput, scanConfigBodies, serialiseSnapshot, snapshotConfig, summarise, verifyConfigChain, verifyConfigChainUnkeyed } from "../admin/config-history.ts";
import { COVERAGE_INVENTORY_KEY, type ResourceInventory } from "../admin/coverage.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { POSTURE_ACCEPT_PREFIX, type RiskAccept } from "../admin/posture.ts";
import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { log } from "../log.ts";
import { classifySnapshotFailure, recordChainVerdict, recordRefusal, recordStorageAnomaly } from "./sched-fault-ledger.ts";
import { CONFIG_HISTORY_HEAD_KEY, CONFIG_HISTORY_KEY_FP_KEY, CONFIG_SNAPSHOT_FAILURE_KEY, type ConfigHistoryHead, type ConfigSnapshotFailureState, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { bytesEqualLocal, nowMillisISO } from "./scheduler-helpers.ts";

export function ConfigVersionMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Config-as-a-source versioning (Phase 4, the DEFAULT self-contained layer) --------------
    // downpipes versions its OWN governance configuration so an operator gets git-style history plus a
    // plain-English diff over their backup setup. The hash-chained, signed version records live under the
    // `confighist:` prefix in THIS DO, a dedicated keyspace SEPARATE from the data-backup R2 archive and
    // from the `audit:` chain; the chain reuses the SAME crypto primitives (sha384 content hash, plus an
    // HMAC signed digest keyed by the engine's OWN in-DO session-signing key, the construction the audit
    // and session paths already rely on). It is PURELY ADDITIVE observability: a version is captured AFTER
    // a config mutation has already committed (auto-snapshot, best-effort) or on a manual snapshot, and
    // nothing here gates, blocks or alters how config is applied (an approval/deploy gate is a separate,
    // later item). SECRETS BY REFERENCE ONLY: snapshotConfig copies a closed set of named, non-secret
    // metadata (the same data GET /downpipes / GET /notify return), never a secret value.

    // gatherSnapshotInput reads every versionable record the DO holds and projects it into the normalised,
    // stable-key-ordered ConfigSnapshot (snapshotConfig). It reuses the DO's existing list helpers so a
    // snapshot sees exactly the live posture (the same records the read routes serve). A null coverage
    // (no inventory stored) is the honest-unknown state, distinct from a stored-but-empty inventory.
    async gatherConfigSnapshot(): Promise<ConfigSnapshot> {
      // All reads below are independent (none feeds another) until the SnapshotInput assembly, so they run
      // in parallel. This turns the round-trip latency from the sum of every read into the slowest single
      // read, which matters because gatherConfigSnapshot is on the hot path (every auto-snapshot and dry-run).
      // listRoles returns the full people ROSTER (bound members AND pending invitations), keyed by email for
      // the diff, so a grant made by email (a pending invite) and a later re-grade are both versioned and
      // diffable even before the invitee authenticates.
      // expiryItems are the tracked credential/key expiry items, folded in so a gated expiry change has a
      // coherent diff (F2).
      const [downpipes, roles, groupRoles, customRoleRecords, notifyChannels, notifyRules, acceptMap, expiryItems, inventoryRaw] = await Promise.all([
        this.listDownpipes(),
        this.listRoles(),
        this.listGroupRoleEntries(),
        this.listCustomRoleRecords(),
        this.listNotifyChannelsRaw(),
        this.listNotifyRulesRaw(),
        this.state.storage.list<RiskAccept>({ prefix: POSTURE_ACCEPT_PREFIX }),
        this.listExpiryItemsRaw(),
        this.state.storage.get<ResourceInventory>(COVERAGE_INVENTORY_KEY),
      ]);
      const customRoles = [...customRoleRecords.values()];
      const riskAccepts = [...acceptMap.values()];
      const inventory = inventoryRaw ?? null;
      const input: SnapshotInput = {
        // Each list is handed to snapshotConfig as the live record; snapshotConfig reads ONLY the named
        // fields it projects (never a spread), so an extra field on a record cannot ride into the snapshot.
        downpipes: downpipes.map((d) => d.config),
        roles: roles.map((r) => ({ email: r.email, role: r.role, ...(r.customRole !== undefined ? { customRole: r.customRole } : {}), ...(r.expiresAt !== undefined ? { expiresAt: r.expiresAt } : {}) })),
        groupRoles: groupRoles.map((g) => ({ group: g.group, role: g.role, ...(g.customRole !== undefined ? { customRole: g.customRole } : {}), ...(g.connId !== undefined ? { connId: g.connId } : {}) })),
        customRoles: customRoles.map((c) => ({ name: c.name, label: c.label, capabilities: c.capabilities, surface: c.surface, presentation: c.presentation, landing: c.landing })),
        notifyChannels: notifyChannels.map((c) => ({ id: c.id, kind: c.kind, name: c.name, enabled: c.enabled, ...(c.url !== undefined ? { url: c.url } : {}), ...(c.toAddresses !== undefined ? { toAddresses: c.toAddresses } : {}), ...(c.routingKey !== undefined ? { routingKey: c.routingKey } : {}) })),
        notifyRules: notifyRules.map((r) => ({ id: r.id, scope: r.scope, minSeverity: r.minSeverity, events: r.events, channelIds: r.channelIds, ...(r.digest !== undefined ? { digest: r.digest } : {}), enabled: r.enabled })),
        riskAccepts: riskAccepts.map((a) => ({ checkId: a.checkId, ...(a.kind !== undefined ? { kind: a.kind } : {}), reason: a.reason })),
        // The raw url is handed in; snapshotConfig redacts it to host + presence (never the path/query/token).
        // expiresAt is optional on an ExpiryItem (a no-expiry credential omits it); the config snapshot
        // shape is now optional too, and the diff renders an absent expiry as "no expiry".
        expiryItems: expiryItems.map((e) => ({ id: e.id, label: e.label, kind: e.kind, ...(e.expiresAt !== undefined ? { expiresAt: e.expiresAt } : {}) })),
        coverage: inventory === null ? null : { kv: inventory.kv, r2: inventory.r2, d1: inventory.d1, secrets: inventory.secrets },
      };
      return snapshotConfig(input);
    }

    // listConfigVersions reads the whole version chain in ascending id order (the `confighist:` keys are
    // zero-padded so the storage list is numeric order), defending the ordering invariant with an explicit
    // numeric sort so a future storage change cannot silently reorder the chain the verify depends on.
    async listConfigVersions(): Promise<ConfigVersion[]> {
      const map = await this.state.storage.list<ConfigVersion>({ prefix: CONFIG_HISTORY_PREFIX });
      return [...map.values()].sort((a, b) => a.id - b.id);
    }

    // snapshotConfigNow captures the CURRENT governance posture as a new hash-chained, signed version, IF
    // it differs from the head version. It is the one write path for both the auto-snapshot (called after a
    // successful mutation) and the manual snapshot. DE-DUPE: if the serialised current snapshot is
    // byte-identical to the head version's snapshot, nothing is stored (the head already records this
    // posture) and { created:false } is returned, so a re-save of an unchanged posture never churns a
    // version. Otherwise it allocates the next id from the head's id (so the seq stays monotonic even after
    // a retention rollover deletes old versions), links parentHash to the head's contentHash (or genesis
    // for the first version), builds the auto-summary from the diff against the head, signs the record with
    // the in-DO key, persists it under `confighist:<id>`, and enforces the retention cap. author is the
    // verified email that triggered the capture (null for the bare-token break-glass or an internal
    // capture). It returns the created version (or { created:false }).
    async snapshotConfigNow(author: string | null): Promise<{ created: false } | { created: true; version: ConfigVersion }> {
      const snapshot = await this.gatherConfigSnapshot();
      const existing = await this.listConfigVersions();
      const head = existing.length > 0 ? existing[existing.length - 1]! : null;
      // DE-DUPE on the byte-identical serialised snapshot (the same canonical form the content hash covers),
      // so an idempotent re-save (or a mutation that did not actually change the versionable posture) does
      // not create a duplicate version. The comparison is over bytes, not the hash, so it cannot be fooled
      // by a hash that was tampered after the fact.
      if (head !== null) {
        const headBytes = serialiseSnapshot(head.snapshot);
        const curBytes = serialiseSnapshot(snapshot);
        if (bytesEqualLocal(headBytes, curBytes)) return { created: false };
      }
      const id = (head?.id ?? 0) + 1;
      const parentHash = head !== null ? head.contentHash : CONFIG_GENESIS_PREV_HASH;
      // The auto-summary is built from the plain-English diff against the head (or the genesis note for the
      // first version). It is redaction-safe (the diff reads only the snapshot's named metadata).
      const changes: ConfigChange[] = head !== null ? diffConfig(head.snapshot, snapshot) : [];
      const summary = summarise(changes, head === null);
      const key = await this.sessionSigningKey();
      const version = await buildConfigVersion(snapshot, id, nowMillisISO(), author, summary, parentHash, key);
      await this.state.storage.put(configHistoryKey(id), version);
      // G313 (R6): commit the HEAD ANCHOR in the same storage turn as the version (the DO is single-threaded, so
      // there is no torn read). It is what makes a TAIL DELETION visible: every verify pass walks the retained
      // versions and can only see a break BETWEEN two of them, so removing the newest versions leaves the
      // survivors linked and the chain reads intact. The anchor is an unkeyed witness that the head was once
      // higher, and a rollover (which prunes the OLDEST) can never lower it.
      await this.state.storage.put(CONFIG_HISTORY_HEAD_KEY, { headId: id, headContentHash: version.contentHash } satisfies ConfigHistoryHead);
      // Retention: bound the version history so it cannot grow DO storage without limit (the same
      // discipline as the audit chain). The count after this put is the existing versions plus one; once it
      // exceeds the cap, roll the oldest off. The id stays monotonic (a rolled version's id is never
      // reused), and the retained chain stays verifiable from its new earliest version.
      const countAfter = existing.length + 1;
      if (countAfter > CONFIG_HISTORY_CAP) {
        await this.rollOverConfigHistory(existing.map((v) => configHistoryKey(v.id)), countAfter - CONFIG_HISTORY_CAP);
      }
      return { created: true, version };
    }

    // autoSnapshotConfig is the BEST-EFFORT wrapper every config-mutating method calls after its write has
    // committed. It NEVER throws and NEVER alters the mutation's result: a snapshot is read-only
    // observability taken after the fact, so a failure to capture it (a storage hiccup, a key-load error)
    // must not fail or roll back the mutation the operator just performed. Any error is swallowed to a
    // console line and the mutation's own response is returned unchanged by the caller. The author is the
    // verified email of the caller that drove the mutation (null for the bare-token break-glass).
    async autoSnapshotConfig(author: string | null): Promise<void> {
      try {
        await this.snapshotConfigNow(author);
      } catch (e) {
        // Observability only: the mutation already committed. Log coarsely (no secret, no snapshot) and
        // carry on, so a config change is never blocked by a versioning hiccup.
        log("error", `config snapshot (best-effort) failed: ${(e as Error).message}`);
        // OBSERVE the swallowed failure (config-snapshot-best-effort-gap): a config change that silently never
        // got versioned is otherwise invisible. Bump a diagnostic counter (a count + the last failure time)
        // the support pack surfaces. Best-effort-WITHIN-best-effort: a counter hiccup is swallowed too, so a
        // versioning fault can never cascade into (or block) the mutation path this method must never disturb.
        try {
          // Read through the VALIDATING reader, not raw storage.get<T>, so a malformed stored count cannot be
          // coerced by JavaScript's `+` operator into a corrupted value; getConfigSnapshotHealth normalises
          // and books the G105 coercion on the way past.
          const prior = await this.getConfigSnapshotHealth();
          await this.state.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: prior.count + 1, lastAt: nowMillisISO() } satisfies ConfigSnapshotFailureState);
          // G037: the count says N config changes were never versioned; the ROOT CAUSE lived only in the
          // Workers Logs line above, which remote support structurally cannot read. classifySnapshotFailure
          // reads the throw ONLY to select a closed class (signing-key | storage | shape) and returns it -- and
          // signing-key is the one that matters: it means NO config change can EVER be versioned until the key
          // is fixed, which is a completely different ticket from a transient storage blip.
          await recordRefusal(this.state.storage, "config-snapshot", classifySnapshotFailure(e));
        } catch {
          /* swallow: observability must never destabilise the mutation path autoSnapshotConfig guards */
        }
      }
    }

    // getConfigSnapshotHealth reads the cumulative config auto-snapshot failure tally (config-snapshot-best-
    // effort-gap): a count + the last failure time, defaulting to 0 / null when absent (no failures observed).
    // Read by the support pack so an un-versioned config change (a swallowed autoSnapshotConfig fault) is
    // visible. Closed shape only; no secret, no snapshot.
    async getConfigSnapshotHealth(): Promise<ConfigSnapshotFailureState> {
      const m = (await this.state.storage.get<{ count?: unknown; lastAt?: unknown }>(CONFIG_SNAPSHOT_FAILURE_KEY)) ?? null;
      const count = m !== null && typeof m.count === "number" && Number.isFinite(m.count) && m.count > 0 ? Math.floor(m.count) : 0;
      // Gated on PARSING, not merely on being a non-empty string, for the reason stated at
      // getChangeControlRefusals: the writer only ever stores nowMillisISO(), so a value that does not parse
      // did not come from the engine and must not be returned verbatim out of a corrupt record.
      const lastAtRaw = m !== null && typeof m.lastAt === "string" && m.lastAt.length > 0 ? m.lastAt : null;
      const lastAt = lastAtRaw !== null && !Number.isNaN(Date.parse(lastAtRaw)) ? lastAtRaw : null;
      // G105: the same present-but-malformed coercion readEmergencyChangeMarker books, on the tally that says
      // how many config changes committed and were never versioned. The pack surfaces this block only when
      // count > 0, so the coerced zero is not a low number, it is an ABSENT block: identical to an account
      // whose every snapshot succeeded. Counted only when a record is PRESENT (absent = none observed).
      const coerced = m !== null && count === 0;
      if (coerced) await recordStorageAnomaly(this.state.storage, "marker-corrupt-defaulted");
      // A coerced record's timestamp is dropped rather than carried, for the reason stated at the sibling.
      if (coerced) return { count, lastAt: null, coerced: true as const };
      return { count, lastAt };
    }

    // configHistorySigningKeyRotated distinguishes a rotated/lost in-DO config-history signing key from genuine
    // content tamper (config-history-session-key-regen). The config-history digests are HMAC'd with the in-DO
    // session key; if that key is regenerated/lost, EVERY digest fails verifyConfigChain -- indistinguishable
    // from content tamper. It persists a NON-SECRET fingerprint (a SHA-384 prefix, one-way) of the live key
    // ONCE (baseline); thereafter a fingerprint that has DRIFTED means the key rotated. Only the derived
    // boolean ever leaves the DO -- never the fingerprint, never the key. On the first call it establishes the
    // baseline and returns false (nothing to compare yet).
    async configHistorySigningKeyRotated(key: Uint8Array): Promise<boolean> {
      const fp = hexEncode(await sha384(key)).slice(0, 32); // one-way, 128-bit commitment; never the key
      const stored = (await this.state.storage.get<string>(CONFIG_HISTORY_KEY_FP_KEY)) ?? null;
      if (stored === null) {
        await this.state.storage.put(CONFIG_HISTORY_KEY_FP_KEY, fp);
        // G105: establishing the baseline OPENS a structural false-negative window. Until the next comparison
        // there is nothing to detect a key regeneration against, so configIntegrity.signingKeyRotated reads
        // false whether or not the key just changed. A baseline (re-)established on an account that already
        // has config history is the shape of a LOST fingerprint key, which is exactly the state a
        // regeneration would leave. Count it; the fingerprint itself never leaves the DO.
        await recordStorageAnomaly(this.state.storage, "config-key-fp-baselined");
        return false; // baseline established; nothing to compare against yet
      }
      return stored !== fp;
    }

    // configHistoryUnkeyedVerdict runs the KEY-FREE integrity pass over the whole retained chain (G313, R5): the
    // body recompute, the parent-hash link and the id contiguity, none of which involve the in-DO HMAC key. It is
    // consulted ONLY when the key fingerprint has drifted, and it is what licenses (or refuses) the
    // signing-key-rotated verdict's claim that nothing was tampered. An unhashable body throws exactly as the
    // keyed verify does; that is already the missing-version case, and it must not be reported as "clean".
    // configHistoryHeadAnchorVerdict compares the RETAINED head against the head anchor this DO committed at the
    // last snapshot (CONFIG_HISTORY_HEAD_KEY). It is the one check that can see a TAIL DELETION -- the deletion
    // an attacker actually performs, because the newest versions are the ones recording what they just did --
    // and it needs NO key: the anchor is an unkeyed witness already in storage. Retention prunes the OLDEST
    // versions and never lowers headId, so a retained head below the anchor (or at it under a different content
    // hash) is a removed or rewritten tail. An absent anchor (a chain that predates it, or a DO whose storage was
    // wiped whole) says nothing and is treated as intact: this check only ever speaks from evidence it holds.
    async configHistoryHeadAnchorVerdict(all: ConfigVersion[]): Promise<{ intact: boolean; brokenAt?: number; causeClass?: string }> {
      const anchor = (await this.state.storage.get<ConfigHistoryHead>(CONFIG_HISTORY_HEAD_KEY)) ?? null;
      if (anchor === null || typeof anchor.headId !== "number" || anchor.headId <= 0) return { intact: true };
      const head = all.length > 0 ? all[all.length - 1]! : null;
      const truncated = head === null || head.id < anchor.headId || (head.id === anchor.headId && head.contentHash !== anchor.headContentHash);
      return truncated ? { intact: false, brokenAt: anchor.headId, causeClass: "head-truncated" } : { intact: true };
    }

    async configHistoryUnkeyedVerdict(all: ConfigVersion[], expectGenesis: boolean): Promise<ConfigChainVerdict> {
      try {
        return await verifyConfigChainUnkeyed(all, { expectGenesis });
      } catch {
        return { intact: false, checkedThrough: -1, earliestId: all.length > 0 ? all[0]!.id : -1, causeClass: "missing-version" };
      }
    }

    // configHistoryHealth is the LIGHTWEIGHT config-history integrity read for the support pack: it recomputes
    // the chain verdict (the same verify configHistoryList runs) but returns ONLY the verdict + a
    // signingKeyRotated flag + head/count, NOT the whole version list (which can be up to CONFIG_HISTORY_CAP
    // snapshots). signingKeyRotated (config-history-session-key-regen) distinguishes a rotated in-DO signing
    // key (recoverable context) from a genuine brokenAt (content tamper), so a support diagnosis of a failed
    // config-history verify is not left guessing. Redaction-safe: integers, booleans and an id only.
    //
    // G098: it ALSO carries the BODY-RETENTION scan. Everything above is about the chain's headers; a version
    // whose SNAPSHOT BODY is gone still links, still lists, and still shows in the console as a version you
    // could roll back to. The scan runs FIRST and the verify is guarded, deliberately: verifyConfigChain
    // hashes each snapshot, so a missing body makes it THROW, which is why verifyFaulted exists to say the
    // chain could not be checked at all, a different (and worse) statement than "the chain is broken at
    // version N".
    async configHistoryHealth(): Promise<{
      count: number;
      headId: number;
      bodies: ConfigBodyScan;
      verify: { intact: boolean; checkedThrough: number; earliestId: number; brokenAt?: number; signingKeyRotated?: boolean; unkeyedIntact?: boolean; unkeyedCause?: string; unkeyedBrokenAt?: number; verifyFaulted?: boolean; headTruncated?: boolean; headTruncatedAt?: number };
    }> {
      const all = await this.listConfigVersions();
      const key = await this.sessionSigningKey();
      const expectGenesis = all.length === 0 || all[0]!.id === 1;
      const bodies = scanConfigBodies(all);
      let verdict: ConfigChainVerdict;
      let verifyFaulted = false;
      try {
        verdict = await verifyConfigChain(all, key, { expectGenesis });
      } catch {
        // The verify itself died (a gone body cannot be hashed). Report it as NOT intact and say WHY, rather
        // than throwing the probe away: bodies.missing beside this is the whole diagnosis.
        verifyFaulted = true;
        // G313: a MISSING BODY is its own cause class. verifyConfigChain hashes each snapshot, so a version
        // whose body is gone makes the verify THROW rather than report. A gone body is a lost rollback point,
        // not a tamper; they need opposite answers.
        verdict = { intact: false, checkedThrough: -1, earliestId: all.length > 0 ? all[0]!.id : -1, causeClass: "missing-version" };
      }
      // G313 (R4): the rotated-key fact is read BEFORE the latch, not after it, so a regenerated or lost in-DO
      // key is never filed as a forgery.
      const signingKeyRotated = await this.configHistorySigningKeyRotated(key);
      // G313 (R5): AND THE KEY FACT MAY NOT SPEAK FOR THE WHOLE CHAIN ON ITS OWN. verifyConfigChain returns at the
      // FIRST break, so with the key gone it dies on version 1's digest and never examines 2..N -- while
      // signing-key-rotated told support "nothing was tampered at all". The key can be destroyed by an OWNER
      // BUTTON (terminate-all-sessions deletes the passkey session key), so pressing it turned every
      // config-history tamper into the row that says nothing happened. The content hashes, the parent links and
      // the id contiguity need NO key: run them over the WHOLE chain, and let the key fact claim non-tamper only
      // when they come back clean. Only computed when the key HAS drifted (the ordinary estate pays nothing).
      const unkeyed = signingKeyRotated ? await this.configHistoryUnkeyedVerdict(all, expectGenesis) : undefined;
      // R6: and the HEAD ANCHOR, which is the only check that can see the newest versions being deleted.
      const headAnchor = await this.configHistoryHeadAnchorVerdict(all);
      await recordChainVerdict(this.state.storage, "config-history", verdict, signingKeyRotated, unkeyed, headAnchor);
      const head = all.length > 0 ? all[all.length - 1]! : null;
      return {
        count: all.length,
        headId: head !== null ? head.id : -1,
        bodies,
        verify: {
          intact: verdict.intact,
          checkedThrough: verdict.checkedThrough,
          earliestId: verdict.earliestId,
          ...(verdict.brokenAt !== undefined ? { brokenAt: verdict.brokenAt } : {}),
          // Carried only when the live key fingerprint has DRIFTED from the stored baseline: a verify failure
          // whose signingKeyRotated is true is a key rotation, not tamper. A boolean only (never the fingerprint).
          ...(signingKeyRotated ? { signingKeyRotated: true } : {}),
          // R5: and beside it, what the KEY-FREE pass found over the whole chain. Without this the configIntegrity
          // block could not tell "the owner signed everyone out" from "the owner signed everyone out AND a version
          // was rewritten", which is the state the whole latch exists to expose. A boolean, a closed cause and a
          // clamped id: no snapshot, hash or actor.
          ...(unkeyed !== undefined ? { unkeyedIntact: unkeyed.intact } : {}),
          ...(unkeyed !== undefined && unkeyed.intact === false && unkeyed.causeClass !== undefined ? { unkeyedCause: unkeyed.causeClass } : {}),
          ...(unkeyed !== undefined && unkeyed.intact === false && unkeyed.brokenAt !== undefined ? { unkeyedBrokenAt: unkeyed.brokenAt } : {}),
          ...(verifyFaulted ? { verifyFaulted: true } : {}),
          // R7: THE ANCHOR SPEAKS IN THE VERDICT, not only in the latch. A DELETED TAIL leaves the retained
          // versions linking perfectly, so the keyed verify alone reads intact:true; the head anchor's verdict
          // rides with the verify it qualifies, so a truncated tail is visible in the same block a customer reads.
          ...(headAnchor.intact === false ? { headTruncated: true } : {}),
          ...(headAnchor.intact === false && headAnchor.brokenAt !== undefined ? { headTruncatedAt: headAnchor.brokenAt } : {}),
        },
      };
    }

    // rollOverConfigHistory prunes the oldest version records when the retained count exceeds the cap,
    // mirroring rollOverAudit. existingKeys is the ascending-ordered list of version keys BEFORE the latest
    // put (the newest version was just written under a higher key, so it is never a prune candidate);
    // dropCount is how many of the oldest to remove. It carries only keys, never record content, so it is
    // redaction-safe, and it runs inside the same DO single-threaded storage turn as the put.
    async rollOverConfigHistory(existingKeys: string[], dropCount: number): Promise<void> {
      if (dropCount <= 0) return;
      for (const k of existingKeys.slice(0, dropCount)) await this.state.storage.delete(k);
    }

    // manualConfigSnapshot serves POST /config/snapshot: an explicit, on-demand capture of the current
    // posture. The router gates it on access.policy (the owner/policy level); the DO re-resolves the
    // caller's authority from its own tables (requireCapabilityResolved, defence in depth like the other
    // policy writes) so a router bug cannot let an unauthorised caller force a capture, then captures via
    // the shared snapshotConfigNow (so it de-dupes against the head exactly like an auto-snapshot). It
    // returns whether a new version was created (false when the posture was unchanged since the head) and,
    // when created, the new version's id/at/summary so the console can confirm.
    async manualConfigSnapshot(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ created: boolean; id?: number; at?: string; summary?: string }> {
      await this.requireCapabilityResolved(caller, "access.policy");
      const author = caller?.email ? caller.email : null;
      const result = await this.snapshotConfigNow(author);
      if (!result.created) return { created: false };
      return { created: true, id: result.version.id, at: result.version.at, summary: result.version.summary };
    }

    // configHistoryList serves GET /config/history: the version list newest-first with the chain head and a
    // verify verdict, so the console can render a git-style history AND show that the chain is intact (or
    // the first broken version). Each row carries only the redaction-safe header fields (id, at, author,
    // parentHash, contentHash, summary), NOT the full snapshot (GET /config/version/:id returns one
    // snapshot). The verify recomputes every content hash AND signed digest under the in-DO key and links
    // the chain, the on-screen proof of tamper-evidence for the config history.
    async configHistoryList(): Promise<{
      versions: Array<{ id: number; at: string; author: string | null; parentHash: string; contentHash: string; summary: string }>;
      headId: number;
      headHash: string;
      verify: { intact: boolean; checkedThrough: number; earliestId: number; brokenAt?: number; headTruncated?: boolean; headTruncatedAt?: number };
    }> {
      const all = await this.listConfigVersions();
      const key = await this.sessionSigningKey();
      // The chain never rolls over to a non-genesis baseline in practice (the cap is far above any realistic
      // config-change count), but be honest if it has: expect genesis only when the earliest retained
      // version is still id 1, so a documented rollover is not reported as a spurious break.
      const expectGenesis = all.length === 0 || all[0]!.id === 1;
      const verdict = await verifyConfigChain(all, key, { expectGenesis });
      // G313 (R4): the SAME rotated-key consultation the health probe makes. A latch written from this route must
      // not claim a forgery on an estate whose signing key was simply regenerated. (R5) And the SAME key-free pass
      // beside it: this route latches too, so a rotated key must not mask a tamper here either.
      const rotated = await this.configHistorySigningKeyRotated(key);
      // R7: the SIBLING READER, which is the screen the customer is actually looking at. The head-anchor
      // verdict rides out with the verify block here too, so a truncated tail is visible wherever the chain's
      // status is shown, not only in the internal latch.
      const headAnchor = await this.configHistoryHeadAnchorVerdict(all);
      await recordChainVerdict(this.state.storage, "config-history", verdict, rotated, rotated ? await this.configHistoryUnkeyedVerdict(all, expectGenesis) : undefined, headAnchor);
      const head = all.length > 0 ? all[all.length - 1]! : null;
      return {
        versions: [...all].reverse().map((v) => ({ id: v.id, at: v.at, author: v.author, parentHash: v.parentHash, contentHash: v.contentHash, summary: v.summary })),
        headId: head !== null ? head.id : -1,
        headHash: head !== null ? head.contentHash : CONFIG_GENESIS_PREV_HASH,
        verify: {
          intact: verdict.intact,
          checkedThrough: verdict.checkedThrough,
          earliestId: verdict.earliestId,
          ...(verdict.brokenAt !== undefined ? { brokenAt: verdict.brokenAt } : {}),
          ...(headAnchor.intact === false ? { headTruncated: true } : {}),
          ...(headAnchor.intact === false && headAnchor.brokenAt !== undefined ? { headTruncatedAt: headAnchor.brokenAt } : {}),
        },
      };
    }

    // configVersionById serves GET /config/version?id=N: the FULL stored version record (header + the
    // normalised snapshot), so the console can show the exact posture at that point and seed a diff. A
    // missing/non-numeric/absent id is a 404-shaped { error } (mapped to a 400 by the fetch() catch via a
    // throw would be wrong here, so it returns the error in-band); an unknown id returns { found:false }.
    async configVersionById(idRaw: string | null): Promise<{ found: false } | { found: true; version: ConfigVersion }> {
      const id = idRaw !== null ? Number(idRaw) : NaN;
      if (!Number.isInteger(id) || id < 1) return { found: false };
      const version = (await this.state.storage.get<ConfigVersion>(configHistoryKey(id))) ?? null;
      if (version === null) return { found: false };
      return { found: true, version };
    }

    // configDiff serves GET /config/diff?from=A&to=B: the plain-English (Australian) change list between two
    // stored versions. It loads both versions' snapshots and runs the pure diffConfig (the same logic the
    // auto-summary uses), so a console can render "schedule daily -> hourly", "alice: operator -> approver",
    // "downpipe kv:sessions added", etc. An absent/unknown from or to returns { found:false } (the console
    // shows "version not found"); from and to may be in any order (the diff reads from -> to as given, so
    // the caller picks the direction). It reads only the snapshots' named metadata, never a secret.
    async configDiff(
      fromRaw: string | null,
      toRaw: string | null,
    ): Promise<{ found: false } | { found: true; from: number; to: number; changes: ConfigChange[] }> {
      const fromId = fromRaw !== null ? Number(fromRaw) : NaN;
      const toId = toRaw !== null ? Number(toRaw) : NaN;
      if (!Number.isInteger(fromId) || !Number.isInteger(toId) || fromId < 1 || toId < 1) return { found: false };
      const fromV = (await this.state.storage.get<ConfigVersion>(configHistoryKey(fromId))) ?? null;
      const toV = (await this.state.storage.get<ConfigVersion>(configHistoryKey(toId))) ?? null;
      if (fromV === null || toV === null) return { found: false };
      return { found: true, from: fromId, to: toId, changes: diffConfig(fromV.snapshot, toV.snapshot) };
    }
  };
}
