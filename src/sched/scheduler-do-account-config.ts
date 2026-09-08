// The console-set account-config subsystems: account-discovery API token + selected accounts, the
// assurance licence record, and the safe-apply update-lifecycle bookkeeping. AccountConfigMixin layers
// these over a base whose `this` is SchedulerDOSurface.

import { isWrappedSecret, type WrappedSecret } from "../admin/config-secret.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { compareSemver } from "../admin/updates.ts";
import { SELECTABLE_TOKEN_SOURCE_TYPES } from "./config-validate.ts";
import { recordAdminRefusal, recordConfigCoercion, recordRefusal } from "./sched-fault-ledger.ts";
import { AuthError, DISCOVERY_KEY, type DiscoveryAccountSeen, type DiscoveryConfig, ENGINE_ACCOUNT_VERIFIED_KEY, LICENCE_ACTIVATION_REFUSAL_KEY, LICENCE_KEY, type LicenceActivationRefusalState, type LicenceTokenRecord, type SchedulerDOCtor, UPDATE_HISTORY_CAP, UPDATE_KEY, type UpdateLast, type UpdatePending, type UpdateRecord, type VerifiedEngineAccount } from "./scheduler-do-base.ts";

// CF_API_TOKEN_RE is the single shape check for a pasted Cloudflare API token: the printable
// token-character set, bounded 20..300. Named at module scope so the bound is not an opaque inline
// literal and a future change to the accepted token shape moves only this constant.
const CF_API_TOKEN_RE = /^[A-Za-z0-9_.-]{20,300}$/;

// LICENCE_REFUSAL_REASON_CODES is the CLOSED set of reason codes recordLicenceActivationRefusal will store
// (failed-activation-no-trace). It mirrors the admin LicenceReasonCode union PLUS "malformed-token" (the pre-
// verify shape reject, which has no verify reasonCode), "internal-error" (the G081 backstop code, meaning
// "this is OUR fault, not your token"), and "supersedes-current-term" (a genuinely signed, unexpired token
// whose term ends EARLIER than the active licence). It is duplicated here on purpose (the DO must not import
// the admin licence module) so the DO defensively bounds its own input: only a member of this closed
// vocabulary is stored, so a licence VALUE or free text can never ride into the counter. An out-of-vocabulary
// code is dropped to undefined, which also skips the bounded refusal ring below, so keeping this set complete
// matters for more than the label.
const LICENCE_REFUSAL_REASON_CODES = new Set<string>([
  "no-token", "no-pin", "pin-invalid", "segments", "decode", "signature", "body-malformed",
  "not-canonical", "unparseable-expiry", "future-tier", "expired", "malformed-token", "internal-error",
  "supersedes-current-term",
]);

// stickyUpdateFields carries the MONOTONIC or never-cleared fields of the update record forward through
// every read-modify-write: the R8 anti-rollback floors (the per-component map + its legacy engine-scalar
// mirror), the R9 freshness watermark (sequence + issuedAt), the console component's last outcome, and the
// bounded outcome history. Each is included only when set, so an absent field stays absent. setUpdatePending
// advances the freshness pair and setUpdateSettled bumps the floors / appends history by spreading this FIRST
// then overriding the relevant field; claimUpdateAlert/claimRollbackNeeded spread it unchanged. Centralised
// so a future record write cannot silently drop the anti-rollback floor, the replay watermark or a
// component's history (which would re-open the very gaps R8/R9 and the per-component split close).
function stickyUpdateFields(rec: UpdateRecord): Partial<UpdateRecord> {
  return {
    ...(rec.settledHighWaterMark != null ? { settledHighWaterMark: rec.settledHighWaterMark } : {}),
    ...(rec.floors != null ? { floors: rec.floors } : {}),
    ...(rec.lastConsole != null ? { lastConsole: rec.lastConsole } : {}),
    ...(rec.history != null ? { history: rec.history } : {}),
    ...(rec.lastChannelSeq != null ? { lastChannelSeq: rec.lastChannelSeq } : {}),
    ...(rec.lastChannelIssuedAt != null ? { lastChannelIssuedAt: rec.lastChannelIssuedAt } : {}),
  };
}

// semverMax keeps the R8 high-water mark MONOTONIC: it returns `candidate` only when it is strictly greater
// than the stored mark, otherwise the stored mark is kept (an equal, lower, or uncomparable candidate never
// lowers the floor). The first-ever settle (no stored mark) adopts the candidate. Pure.
function semverMax(current: string | undefined, candidate: string): string {
  if (typeof current !== "string" || current.trim() === "") return candidate;
  return compareSemver(candidate, current) === 1 ? candidate : current;
}

export function AccountConfigMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- account-discovery config (console-set read-only API token; no CLI, no redeploy) ----------

    async getDiscoveryConfig(): Promise<DiscoveryConfig | null> {
      return ((await this.state.storage.get(DISCOVERY_KEY)) as DiscoveryConfig | undefined) ?? null;
    }

    // getDiscoveryStatus is the presence-only view every authenticated reader may see: who enabled
    // account browsing and when, which accounts the token saw, which are browsed, and which account
    // is the engine's own. NEVER the token.
    async getDiscoveryStatus(): Promise<{
      present: boolean;
      setAt?: number;
      setBy?: string | null;
      accountsSeen?: DiscoveryAccountSeen[];
      selected?: string[];
      engineAccountId?: string | null;
      enabledSources?: string[];
    }> {
      const c = await this.getDiscoveryConfig();
      if (!c) return { present: false };
      return { present: true, setAt: c.setAt, setBy: c.setBy, accountsSeen: c.accountsSeen, selected: c.selected, engineAccountId: c.engineAccountId, enabledSources: c.enabledSources ?? [] };
    }

    // setDiscoveryToken stores (or, with token:null, clears) the customer's read-only API token.
    // OWNER-EXCLUSIVE, re-resolved here (defence in depth over the router's gate). The router has
    // already VERIFIED the token live against the Cloudflare API and passes the accounts it listed;
    // the DO validates shapes, applies the single-account defaults (one visible account is
    // auto-selected and presumed the engine's own; several await an explicit choice), stores, and
    // audits who flipped it, never the value. THROWS -> 400 with the plain reason.
    async setDiscoveryToken(
      req: { token?: unknown; accountsSeen?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ present: boolean; setAt?: number; setBy?: string | null; accountsSeen?: DiscoveryAccountSeen[]; selected?: string[]; engineAccountId?: string | null }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may set or clear the discovery token");
      if (req.token === null) {
        await this.state.storage.delete(DISCOVERY_KEY);
        await this.appendAudit({
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "discovery-token-cleared",
          outcome: "success",
          target: { kind: "access-policy" },
        });
        return { present: false };
      }
      // The token arrives WRAPPED whenever CONFIG_WRAP_KEY is configured: the router seals it under
      // DISCOVERY_SECRET_AAD before forwarding, so the DO stores ciphertext and a storage read no longer
      // yields a live estate-wide credential. isWrappedSecret is a pure shape check with no crypto, which
      // is what makes it safe in here (a DO has no env and therefore no key).
      //
      // The CF_API_TOKEN_RE guard is defence-in-depth against a malformed value reaching storage, and it
      // can only run on a value the DO can actually see. That is not a loss: on the wrapped path the ROUTER
      // has already run validateDeployToken AND verified the token live against the Cloudflare API before
      // sealing it, so the shape was proved earlier and by a stronger check. On the unwrapped path (no wrap
      // key configured, the back-compat floor) the guard is unchanged.
      const wrapped = isWrappedSecret(req.token);
      if (!wrapped) {
        const plain = typeof req.token === "string" ? req.token.trim() : "";
        if (!CF_API_TOKEN_RE.test(plain)) {
          throw new Error("that does not look like a Cloudflare API token (paste the token value itself, not its name or id)");
        }
      }
      const token: string | WrappedSecret = wrapped ? (req.token as WrappedSecret) : (req.token as string).trim();
      const seenRaw = Array.isArray(req.accountsSeen) ? req.accountsSeen : [];
      // G297: the 100-account TRUNCATION. An org with more than 100 Cloudflare accounts has its tail cut here,
      // the write returns 200, the audit records success, and "account X is in my org but Downpipes refuses
      // it" becomes unanswerable -- the accounts were dropped, not refused. Count the dropped rows (a count;
      // never an account id).
      if (seenRaw.length > 100) await recordConfigCoercion(this.state.storage, "discovery-accounts-seen", "truncated-over-cap", seenRaw.length - 100);
      const accountsSeen: DiscoveryAccountSeen[] = [];
      for (const a of seenRaw.slice(0, 100)) {
        const id = (a as { id?: unknown }).id;
        const name = (a as { name?: unknown }).name;
        if (typeof id === "string" && id !== "") {
          accountsSeen.push({ id, name: typeof name === "string" && name !== "" ? name : id });
        }
      }
      // G297: entries the loop above SKIPPED (no usable id) are dropped silently too. Count them separately
      // from the truncation: a shape drop and a cap drop are different tickets.
      {
        const kept = accountsSeen.length;
        const considered = Math.min(seenRaw.length, 100);
        if (considered > kept) await recordConfigCoercion(this.state.storage, "discovery-accounts-seen", "unknown-id", considered - kept);
      }
      if (accountsSeen.length === 0) throw new Error("the token cannot list any account (check its read scopes)");
      const single = accountsSeen.length === 1;
      const cfg: DiscoveryConfig = {
        token,
        setAt: Date.now(),
        setBy: caller?.email ? caller.email : null,
        accountsSeen,
        selected: single ? [accountsSeen[0]!.id] : [],
        engineAccountId: single ? accountsSeen[0]!.id : null,
      };
      await this.state.storage.put(DISCOVERY_KEY, cfg);
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "discovery-token-set",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return this.getDiscoveryStatus();
    }

    // setDiscoveryAccounts updates WHICH accounts are browsed + which is the engine's own. The ids
    // must be among accountsSeen (an id the token never listed is refused, so the selection can
    // never reference an account the operator did not see verified). Owner-exclusive + audited.
    async setDiscoveryAccounts(
      req: { selected?: unknown; engineAccountId?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ present: boolean; setAt?: number; setBy?: string | null; accountsSeen?: DiscoveryAccountSeen[]; selected?: string[]; engineAccountId?: string | null }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may choose the browsed accounts");
      const c = await this.getDiscoveryConfig();
      if (!c) throw new Error("no discovery token is set");
      const known = new Set(c.accountsSeen.map((a) => a.id));
      const selectedRaw = Array.isArray(req.selected) ? req.selected : [];
      const selected = [...new Set(selectedRaw.filter((x): x is string => typeof x === "string" && known.has(x)))];
      // G297: THE "I SELECTED THREE ACCOUNTS AND ONLY TWO SHOW UP" TICKET. An id that is not in accountsSeen is
      // FILTERED OUT here and the write still returns 200 with a success audit -- the operator is told it
      // worked. Count the dropped ids (a count; never an account id). De-duplication is not a drop, so compare
      // against the DISTINCT submitted set.
      {
        const distinctSubmitted = new Set(selectedRaw.filter((x): x is string => typeof x === "string")).size;
        if (distinctSubmitted > selected.length) await recordConfigCoercion(this.state.storage, "discovery-selected", "unknown-id", distinctSubmitted - selected.length);
      }
      if (selected.length === 0) throw new Error("choose at least one account to browse");
      const engineAccountId = typeof req.engineAccountId === "string" && known.has(req.engineAccountId) ? req.engineAccountId : null;
      // G297: an engineAccountId the engine cannot resolve is silently COERCED TO NULL (the engine then has no
      // idea which account it lives in). Counted as the same closed unknown-id class.
      if (req.engineAccountId !== undefined && engineAccountId === null) await recordConfigCoercion(this.state.storage, "discovery-selected", "unknown-id", 1);
      await this.state.storage.put(DISCOVERY_KEY, { ...c, selected, engineAccountId });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "discovery-accounts-set",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return this.getDiscoveryStatus();
    }

    // setEnabledSources records WHICH token-authenticated source types (cf-config / workers / stream /
    // images / artifacts) the operator has ADDED on the Sources screen, so the create-downpipe wizard
    // offers only added types (the same add-then-protect discipline a bound source already has). Owner-
    // exclusive (re-resolved HERE, defence in depth over the router gate) + audited. The full desired set
    // is written each call (SET semantics, idempotent), and a type outside the known token-source set is
    // REFUSED, so an unknown string can never be stored. Requires a discovery config (a token): a token source is read
    // with that token, so adding one without it is meaningless. THROWS -> 400 with the plain reason.
    async setEnabledSources(
      req: { sources?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ present: boolean; setAt?: number; setBy?: string | null; accountsSeen?: DiscoveryAccountSeen[]; selected?: string[]; engineAccountId?: string | null; enabledSources?: string[] }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may add or remove a Cloudflare-wide source");
      const c = await this.getDiscoveryConfig();
      if (!c) throw new Error("no discovery token is set; connect your account first, then add Cloudflare-wide sources");
      // DERIVED from the config validator's own allow-list, never restated. An operator can only usefully
      // "add" a source type a downpipe config may then select, so a type this set accepts and the validator
      // refuses is a control that appears to work and protects nothing. That is what a second hand-written
      // copy of the artifacts beta gate risked: it lived here, in config-validate.ts, and in the console.
      const allowed = new Set(SELECTABLE_TOKEN_SOURCE_TYPES);
      const reqRaw = Array.isArray(req.sources) ? req.sources : [];
      // POSTCONDITION: a source type outside the closed set is REFUSED, not filtered out.
      // G297 recorded this as a counted drop: the write returned 200, the audit recorded success, and the
      // type never appeared in the wizard, which the G297 comment itself described as reading to the customer
      // as "I added it and it never appeared". A counted drop is only visible in a support pack nobody opens
      // until the customer has already lost the time. Nothing legitimate sits outside this set -- the console's
      // radio group can emit only its members, and the set is DERIVED from the config validator's own
      // allow-list, so a type this call accepted and the validator refused would be a control that appears to
      // work and protects nothing. The version-skew case the old comment defended (a newer console against an
      // older engine) is better served by a plain refusal naming the type than by a success that is not one.
      // An ABSENT or empty sources list still clears every type, which is the legitimate way to select none.
      const submitted = [...new Set(reqRaw)];
      const rejected = submitted.filter((x) => typeof x !== "string" || !allowed.has(x));
      if (rejected.length > 0) {
        // The message names the offending values so a skewed console says something useful. They are the
        // caller's own submission echoed back, never a token or a stored secret, and they are bounded: at
        // most five are quoted and each is cut to 40 characters, so a crafted list cannot inflate the reply.
        const shown = rejected.slice(0, 5).map((x) => (typeof x === "string" ? x.slice(0, 40) : typeof x)).join(", ");
        throw new Error(`not a source type this engine can add: ${shown}. Choose from ${SELECTABLE_TOKEN_SOURCE_TYPES.join(", ")}`);
      }
      const enabledSources = submitted.filter((x): x is string => typeof x === "string");
      await this.state.storage.put(DISCOVERY_KEY, { ...c, enabledSources });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "discovery-sources-set",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return this.getDiscoveryStatus();
    }

    // ---- engine-account verification (LICENCE-BINDING-ON-CLAIM follow-up,) -------------
    // The gap this closes: DISCOVERY_KEY.engineAccountId only ever gets set when an operator pastes a
    // read-only discovery token (or picks the account by hand) on the Sources screen, and CF_ACCOUNT_ID
    // is an opt-in env var no deploy path writes -- so a stock self-serve engine that has only ever
    // attached a source or applied an update through the console (never touched Sources' account
    // browsing) has NO record of its own Cloudflare account anywhere, and GET /admin/status has nothing
    // to send with a licence claim. attach.ts and cf-deploy.ts both already read
    // /accounts/{a}/workers/scripts/{name} for the engine's OWN script name before writing to it (the
    // safety mechanism that refuses to touch a stranger); a successful attach or promote is therefore
    // already PROOF this account owns that script, the same certainty CF_ACCOUNT_ID gives when hand-set.
    // recordVerifiedEngineAccount persists exactly that proof, once, the first time either path succeeds.

    // getVerifiedEngineAccount reads the persisted proof (or null if none has landed yet). INTERNAL-ONLY
    // (reached by the router's own scheduler.fetch on the status read and by the account resolvers),
    // never a secret: an account id is the customer's own, already visible in their own CF dashboard.
    async getVerifiedEngineAccount(): Promise<VerifiedEngineAccount | null> {
      return ((await this.state.storage.get(ENGINE_ACCOUNT_VERIFIED_KEY)) as VerifiedEngineAccount | undefined) ?? null;
    }

    // recordVerifiedEngineAccount stores the proof. NOT owner-gated: unlike setDiscoveryToken/
    // setDiscoveryAccounts (an operator HANDING the engine a credential or a choice), this is the engine
    // recording a fact it just proved to ITSELF against the live Cloudflare API; the caller is the
    // router's own post-write bookkeeping (observeAttachSideEffects, the update-apply "promoted" arms),
    // never a request body an outside caller controls. NEVER OVERWRITTEN once set: the account a running
    // Worker script lives in cannot change under it, so a second call (every later attach/apply) is a
    // cheap idempotent no-op, not a fresh audit row each time. A blank/malformed accountId is dropped
    // silently (accountId stays null in the return; nothing is stored) rather than refused with a throw,
    // because this runs as best-effort bookkeeping AFTER the attach/apply it verifies has already
    // succeeded and must never turn that success into a 500.
    async recordVerifiedEngineAccount(req: { accountId?: unknown; via?: unknown }): Promise<{ accountId: string | null }> {
      const accountId = typeof req.accountId === "string" ? req.accountId.trim() : "";
      if (accountId === "") return { accountId: null };
      const via: VerifiedEngineAccount["via"] = req.via === "update-apply" ? "update-apply" : "attach";
      const existing = await this.getVerifiedEngineAccount();
      if (existing !== null) return { accountId: existing.accountId }; // already proven; never overwritten
      const record: VerifiedEngineAccount = { accountId, verifiedAt: Date.now(), via };
      await this.state.storage.put(ENGINE_ACCOUNT_VERIFIED_KEY, record);
      // actorMethod "engine" (AuditActorMethod's widening for exactly this shape, see audit-types.ts and
      // audit-status.ts's engine-observed events), NOT "access": G346's structural gate refuses any
      // "access" row that hard-codes sourceIp:null, because "access" means a human authenticated through
      // Cloudflare Access, who always has a real address to capture. This row has no caller at all -- the
      // engine recording a fact it proved to itself -- which "engine" states honestly instead of
      // impersonating an anonymous human.
      await this.appendAudit({
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "engine-account-verified",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return { accountId };
    }

    // ---- assurance licence (console-activated; DO-stored; fail-open; no CLI) ----------------------

    // getLicenceRecord reads the console-activated licence record (the token + activation provenance).
    // INTERNAL-ONLY: reached exclusively by the router's own scheduler.fetch when resolving the effective
    // licence (readLicence), never an admin route, so it may carry the token. Absent -> null.
    async getLicenceRecord(): Promise<LicenceTokenRecord | null> {
      return ((await this.state.storage.get(LICENCE_KEY)) as LicenceTokenRecord | undefined) ?? null;
    }

    // setLicenceToken stores (or, with token:null, clears) the console-activated licence token. OWNER-
    // EXCLUSIVE, re-resolved here (defence in depth over the router's gate). The router has already
    // VERIFIED the token live against the pinned vendor signer (verify-before-store); the DO re-checks the
    // owner, shape-checks the token, stores it, and audits who pinned/cleared it, never the token bytes.
    // THROWS -> 400 with the plain reason. Returns presence + who/when (never the token).
    async setLicenceToken(
      req: { token?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ present: boolean; setAt?: number; setBy?: string | null }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may activate or remove the licence");
      if (req.token === null) {
        await this.state.storage.delete(LICENCE_KEY);
        await this.appendAudit({
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "licence-cleared",
          outcome: "success",
          target: { kind: "access-policy" },
        });
        return { present: false };
      }
      const token = typeof req.token === "string" ? req.token.trim() : "";
      // Shape only (the router already proved the signature): two non-empty base64url-no-pad segments,
      // dot-joined, within a generous bound (the hybrid body+sig is a few kB of base64url). This is a
      // defence-in-depth guard against a malformed value reaching storage, not the trust decision.
      if (token.length < 32 || token.length > 20000 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
        // G037: THIS BRANCH WAS INVISIBLE. The router posts /licence-activation-refusal on ITS refusal path, so
        // a token the router accepted and the DO then rejected on shape never touched the counter at all: the
        // customer's "I pasted my licence and it still says community" had no record whatsoever. Route it
        // through the SAME recorder as every other refusal, with the closed pre-verify code.
        await this.recordLicenceActivationRefusal({ reasonCode: "malformed-token" });
        throw new Error("that does not look like a licence token (paste the licence token value from your activation email)");
      }
      const record: LicenceTokenRecord = { token, setAt: Date.now(), setBy: caller?.email ? caller.email : null };
      await this.state.storage.put(LICENCE_KEY, record);
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "licence-activated",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return { present: true, setAt: record.setAt, setBy: record.setBy };
    }

    // recordLicenceActivationRefusal bumps the cumulative console-activation refusal tally (failed-activation-
    // no-trace): POST /admin/licence refuses a token that does not verify (typo, wrong signer, expired,
    // malformed shape) and stores NOTHING today, so a customer insisting "I activated my licence" is
    // undiagnosable. The router posts here on the refusal branch. Closed shape only: a cumulative count, the
    // last refusal time, and the last CLOSED reason code (the LicenceReasonCode classification, or
    // "malformed-token" for the pre-verify shape reject) -- validated against the closed set so a value can
    // never ride in. INTERNAL (the router's own scheduler.fetch); the router swallows any error (fail-open,
    // the licence gates nothing), so a persist hiccup never affects activation.
    async recordLicenceActivationRefusal(req: { reasonCode?: unknown }): Promise<{ ok: true }> {
      const prior = ((await this.state.storage.get(LICENCE_ACTIVATION_REFUSAL_KEY)) as LicenceActivationRefusalState | undefined) ?? null;
      const raw = typeof req.reasonCode === "string" ? req.reasonCode : "";
      const reasonCode = LICENCE_REFUSAL_REASON_CODES.has(raw) ? raw : undefined; // only the closed set reaches storage
      const rec: LicenceActivationRefusalState = {
        count: (prior?.count ?? 0) + 1,
        lastAt: Date.now(),
        ...(reasonCode !== undefined ? { lastReasonCode: reasonCode } : {}),
      };
      await this.state.storage.put(LICENCE_ACTIVATION_REFUSAL_KEY, rec);
      // G037: {count, lastAt, lastReasonCode} COLLAPSES a mixed-cause retry storm. A customer who tried five
      // times with THREE different causes reads as count=5 and one code -- and the code kept is the LAST one,
      // i.e. the one they got right before giving up, which is the least informative. The bounded ring keeps
      // the SEQUENCE ("expired, expired, wrong-signer" is a completely different story from "malformed x5").
      // Closed codes only, and only ones already in LICENCE_REFUSAL_REASON_CODES; never the token.
      if (reasonCode !== undefined) {
        await recordRefusal(this.state.storage, "licence-activation", reasonCode);
        await recordAdminRefusal(this.state.storage, "licence", "shape-rejected");
      }
      return { ok: true };
    }

    // getLicenceActivationRefusal returns the last-recorded activation-refusal tally, or null when no
    // activation has ever been refused. Redaction-safe (a count + a timestamp + a closed reason code).
    async getLicenceActivationRefusal(): Promise<LicenceActivationRefusalState | null> {
      return ((await this.state.storage.get(LICENCE_ACTIVATION_REFUSAL_KEY)) as LicenceActivationRefusalState | undefined) ?? null;
    }

    // ---- safe-apply update lifecycle (bookkeeping only) ------------------------------------------
    // These record the two-phase apply's state; the PRIVILEGED act (the Cloudflare deploy) is gated by
    // keys.ceremony AND the one-shot deploy token in the ROUTER, never here. The DO only stores version
    // ids + outcomes + who/when, never the token. Reached by the router's own scheduler.fetch.
    async getUpdateRecord(): Promise<UpdateRecord> {
      const raw = (await this.state.storage.get(UPDATE_KEY)) as UpdateRecord | undefined;
      if (!raw) return { pending: null, last: null };
      // READ-TIME MIGRATION (the migrateCanaryState precedent): before multi-component updates the R8
      // anti-rollback floor was the single engine scalar settledHighWaterMark; it is now the per-component
      // floors map, and a legacy record carrying only the scalar reads as floors = { engine: scalar }. The
      // migrated shape persists on the next write (stickyUpdateFields carries floors forward) and the
      // scalar stays dual-written as the floors.engine mirror, so every legacy reader keeps working.
      if (raw.floors === undefined && typeof raw.settledHighWaterMark === "string" && raw.settledHighWaterMark.trim() !== "") {
        return { ...raw, floors: { engine: raw.settledHighWaterMark } };
      }
      return raw;
    }
    async setUpdatePending(p: UpdatePending): Promise<UpdateRecord> {
      const rec = await this.getUpdateRecord();
      // R9: ADVANCE the freshness watermark from the descriptor this promote accepted. The route only promotes
      // after checkChannelFreshness passed (so these are already >= the stored values), and this is the DO's
      // sole internal caller, so a present claim is taken forward (the gate guarantees monotonicity).
      const advance: Partial<UpdateRecord> = {
        ...(typeof p.channelSeq === "number" && Number.isFinite(p.channelSeq) ? { lastChannelSeq: p.channelSeq } : {}),
        ...(typeof p.channelIssuedAt === "string" && p.channelIssuedAt.trim() !== "" ? { lastChannelIssuedAt: p.channelIssuedAt } : {}),
      };
      // A FRESH pending starts a new verification, so any prior "rollback needed" flag is moot, clear it (a
      // stale queued-console intent on a superseded pending goes with it: the new pending carries its OWN
      // consoleQueued when its apply asked for the console). The sticky fields (floors + freshness watermark
      // + console history) are carried forward, then the freshness pair is advanced (later-wins spread).
      const next: UpdateRecord = { pending: p, last: rec.last, ...(rec.lastAlertedVersion != null ? { lastAlertedVersion: rec.lastAlertedVersion } : {}), ...stickyUpdateFields(rec), ...advance };
      await this.state.storage.put(UPDATE_KEY, next);
      return next;
    }
    async setUpdateSettled(last: UpdateLast): Promise<UpdateRecord> {
      const rec = await this.getUpdateRecord();
      // Multi-component: which component settled. Absent reads as the engine (every legacy caller), so the
      // engine path below is byte-compatible; a "console" record routes to the console's own slots.
      const component = typeof last.component === "string" && last.component !== "" ? last.component : "engine";
      // R8: a SUCCESSFUL settle ("applied") advances THAT component's monotonic anti-rollback floor to the
      // version just trusted, the semver recommendedVersion (NEVER the Cloudflare version-id in toVersion).
      // Any other outcome (rolled-back / expired / superseded / refused) leaves the floor untouched.
      // G219: applied-unconfirmed advances the floor exactly as applied does. The floor is the ANTI-ROLLBACK
      // watermark (it stops an older version being applied over a newer one), and an unconfirmed apply still
      // PROMOTED that version -- Cloudflare's API accepted the deploy, only the read-back confirmation failed.
      // Treating it as un-applied would LOWER the anti-rollback guard for a version that is very probably
      // live, which is the wrong direction to be wrong in. rollback-failed and rollback-failed-still-split
      // deliberately do NOT advance it: those versions were rejected, they are just still (wrongly) serving.
      const applyLanded = last.outcome === "applied" || last.outcome === "applied-unconfirmed";
      const settledVersion = applyLanded && typeof last.recommendedVersion === "string" ? last.recommendedVersion.trim() : "";
      const floors = { ...(rec.floors ?? {}) };
      if (settledVersion !== "") floors[component] = semverMax(floors[component], settledVersion);
      const floorFields: Partial<UpdateRecord> = {
        ...(Object.keys(floors).length > 0 ? { floors } : {}),
        // The legacy scalar stays dual-written as the ENGINE floor's mirror (deployed readers of the flat
        // field keep seeing the engine's floor; the console's floor lives only in the map).
        ...(floors.engine !== undefined && floors.engine !== "" ? { settledHighWaterMark: floors.engine } : {}),
      };
      // R9: a settle that is itself the accepting act for a channel descriptor (a console-only apply, which
      // records no engine pending) advances the freshness watermark exactly as setUpdatePending does.
      const advance: Partial<UpdateRecord> = {
        ...(typeof last.channelSeq === "number" && Number.isFinite(last.channelSeq) ? { lastChannelSeq: last.channelSeq } : {}),
        ...(typeof last.channelIssuedAt === "string" && last.channelIssuedAt.trim() !== "" ? { lastChannelIssuedAt: last.channelIssuedAt } : {}),
      };
      // The bounded multi-component outcome ring: every settled outcome appended newest-last, capped.
      const history = [...(rec.history ?? []), { ...last, component }].slice(-UPDATE_HISTORY_CAP);
      if (component === "console") {
        // CONSOLE settle: record it in the console's own slot; the ENGINE's pending/last are untouched (a
        // console outcome must never clobber the engine's rollback-target resolution). A consumed queue is
        // stripped from a still-present engine pending (the settle that ran the console just resolved it).
        const pending = rec.pending ? { ...rec.pending, ...(rec.pending.consoleQueued != null ? { consoleQueued: null } : {}) } : null;
        const next: UpdateRecord = {
          pending,
          last: rec.last,
          ...(rec.lastAlertedVersion != null ? { lastAlertedVersion: rec.lastAlertedVersion } : {}),
          ...(rec.rollbackNeeded != null ? { rollbackNeeded: rec.rollbackNeeded } : {}),
          ...stickyUpdateFields(rec),
          ...floorFields,
          ...advance,
          lastConsole: { ...last, component },
          history,
        };
        await this.state.storage.put(UPDATE_KEY, next);
        return next;
      }
      // ENGINE settle. Settling (keep OR rollback OR expire/supersede) RESOLVES the pending, so the
      // "rollback needed" flag is cleared: the engine is now on a settled version (the console no longer
      // needs the urgent prompt). The sticky fields are carried forward; the floor override applies the
      // bump (later-wins spread). A queued console intent on the pending is resolved here too: a NON-applied
      // engine outcome ABORTS it with an honest console record (the release was not applied, so the console
      // component never ran); an APPLIED outcome leaves the router to run the console next (it posts the
      // console's own settled record, component:"console", right after).
      const queued = rec.pending?.consoleQueued;
      const abortConsole = queued != null && last.outcome !== "applied";
      const abortedConsoleRecord: UpdateLast | undefined = abortConsole
        ? {
            outcome: "refused",
            component: "console",
            recommendedVersion: queued.version,
            at: last.at,
            by: last.by,
            reason: "the engine update did not settle as applied, so the queued console component was not applied; the console is unchanged",
          }
        : undefined;
      const next: UpdateRecord = {
        pending: null,
        last: { ...last, component },
        ...(rec.lastAlertedVersion != null ? { lastAlertedVersion: rec.lastAlertedVersion } : {}),
        ...stickyUpdateFields(rec),
        ...floorFields,
        ...advance,
        ...(abortedConsoleRecord !== undefined ? { lastConsole: abortedConsoleRecord } : {}),
        history: abortedConsoleRecord !== undefined ? [...history, abortedConsoleRecord].slice(-UPDATE_HISTORY_CAP) : history,
      };
      await this.state.storage.put(UPDATE_KEY, next);
      return next;
    }

    // confirmUpdateSettled (0.1.5 UX design §3) is the hourly canary's BACKGROUND CONFIRMATION of a KEEP
    // that was decided via the self-check (confirmationPending:true on the engine's `last` record) rather
    // than a singing canary. It flips the flag off ONLY when `last` is STILL the exact settled outcome
    // awaiting confirmation for THIS recommendedVersion (a tokenless, semver-shaped match -- the same
    // discriminator claimRollbackNeeded's escalation uses against ENGINE_VERSION), so a superseded or
    // already-confirmed record is a clean no-op rather than a stale write. This is bookkeeping only, never a
    // new settle: it does NOT touch floors, history or the freshness watermark (nothing was newly trusted,
    // the trust was already recorded; this only closes the loop on it), and it needs no token (a keep is
    // never a deploy). Reached exclusively by the cron's own scheduler.fetch (notify-passes.ts
    // confirmUpdateIfSettled); no caller/auth is read.
    async confirmUpdateSettled(req: { recommendedVersion?: unknown }): Promise<{ cleared: boolean }> {
      const recommendedVersion = typeof req.recommendedVersion === "string" ? req.recommendedVersion.trim() : "";
      if (recommendedVersion === "") return { cleared: false };
      const rec = await this.getUpdateRecord();
      const last = rec.last;
      if (last?.outcome !== "applied" || last.confirmationPending !== true || last.recommendedVersion !== recommendedVersion) {
        return { cleared: false };
      }
      const next: UpdateRecord = {
        pending: rec.pending,
        last: { ...last, confirmationPending: false },
        ...(rec.lastAlertedVersion != null ? { lastAlertedVersion: rec.lastAlertedVersion } : {}),
        ...(rec.rollbackNeeded != null ? { rollbackNeeded: rec.rollbackNeeded } : {}),
        ...stickyUpdateFields(rec),
      };
      await this.state.storage.put(UPDATE_KEY, next);
      return { cleared: true };
    }

    // claimRollbackNeeded is the FOLD 1 one-shot critical-alert dedupe, run inside one read-modify-write so two
    // concurrent canary ticks cannot both page. The cron calls it when the hourly canary finds a PROMOTED-but-
    // unsettled new version UNHEALTHY and the running engine IS that promoted version (so the bad new code is
    // genuinely live). It records the rollbackNeeded flag (the console surfaces an URGENT one-click-rollback
    // prompt) and returns shouldAlert:true ONLY the first time it is observed for a given recommendedVersion, so
    // a persistently-failing unsettled version pages once, not every hour. It NEVER deploys (the engine holds no
    // deploy credential, the rollback itself stays a human-confirmed one-click); it is pure bookkeeping.
    async claimRollbackNeeded(req: { recommendedVersion?: unknown; toVersion?: unknown; canaryVerdict?: unknown }): Promise<{ shouldAlert: boolean }> {
      const recommendedVersion = typeof req.recommendedVersion === "string" ? req.recommendedVersion.trim() : "";
      const toVersion = typeof req.toVersion === "string" ? req.toVersion.trim() : "";
      const canaryVerdict = typeof req.canaryVerdict === "string" ? req.canaryVerdict : "ailing";
      if (recommendedVersion === "") return { shouldAlert: false };
      const rec = await this.getUpdateRecord();
      // Only meaningful while a verification is genuinely unsettled (the cron also checks, this is defence in
      // depth): if there is no pending, the version was already settled and no rollback page is warranted.
      if (!rec.pending) return { shouldAlert: false };
      const already = rec.rollbackNeeded?.recommendedVersion === recommendedVersion;
      const next: UpdateRecord = {
        pending: rec.pending,
        last: rec.last,
        ...(rec.lastAlertedVersion != null ? { lastAlertedVersion: rec.lastAlertedVersion } : {}),
        ...stickyUpdateFields(rec), // carry the R8 floor + R9 watermark forward (never drop them on a claim)
        rollbackNeeded: { recommendedVersion, toVersion, canaryVerdict, at: Date.now() },
      };
      await this.state.storage.put(UPDATE_KEY, next);
      return { shouldAlert: !already };
    }

    // claimUpdateAlert is the W3 one-shot dedupe, run inside one read-modify-write so two concurrent cron
    // ticks cannot both fire for the same version. It alerts ONLY when the recommended version differs from
    // the last-alerted one (a genuinely NEW version, or the first ever), and on a positive claim it RECORDS
    // the version so the next tick is silent for the same version. A blank/missing version never claims (no
    // spurious alert). It returns { shouldAlert } and never throws meaningfully (the caller is fail-open
    // regardless); the cron fires the notification only on shouldAlert:true. Pure bookkeeping, it touches
    // no data or recovery path.
    async claimUpdateAlert(req: { recommendedVersion?: unknown }): Promise<{ shouldAlert: boolean }> {
      const version = typeof req.recommendedVersion === "string" ? req.recommendedVersion.trim() : "";
      if (version === "") return { shouldAlert: false };
      const rec = await this.getUpdateRecord();
      if (rec.lastAlertedVersion === version) return { shouldAlert: false }; // already alerted for this version
      const next: UpdateRecord = { pending: rec.pending, last: rec.last, lastAlertedVersion: version, ...stickyUpdateFields(rec), ...(rec.rollbackNeeded != null ? { rollbackNeeded: rec.rollbackNeeded } : {}) };
      await this.state.storage.put(UPDATE_KEY, next);
      return { shouldAlert: true };
    }
  };
}
