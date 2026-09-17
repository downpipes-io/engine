// The native external-IdP subsystem: the OIDC storage adapter, revocation axes, session mint and
// OIDC/OAuth2 route handlers, plus the SAML SP metadata, SP-initiated start and the ACS. IdpMixin layers
// these over a base whose `this` is SchedulerDOSurface, so the SAML ACS mints via `this.nativeSessionIssue`
// and the handlers use `this.idpKv`. Keys use the oidcgroups:/idpEpoch:/sessionEpochSub:/seenassertion:
// prefixes; the emailVerified bind-gate, the assertion replay guard and the session-bound revocation apply
// throughout.

import { AUTH_METHOD_USAGE_KEY, isAdminAuthMethod } from "../admin/auth-method-usage.ts";
import { AUTH_SIGNAL_NAME_SET, AUTH_SIGNALS_KEY, type AuthSignalAgg, bumpAuthSignalEntry } from "../admin/auth-signals.ts";
import { type AuthMethod, isConnId } from "../admin/identity.ts";
import type { IdpConnection, IdpConnectionProposal, Oauth2Connection, OidcClientAuth, OidcConnection, SecretRef } from "../admin/idpconn.ts";
import { redactIdpConn } from "../admin/idpconn.ts";
import { SAML_CERTS_MAX, validateSamlCerts } from "../admin/idpconn-validators.ts";
import type { ResolvedPrincipal } from "../admin/oidc.ts";
import { buildProposalFromPreset, listPresets, missingRequiredVars, presetById } from "../admin/oidc-presets.ts";
import { isWrappedSecret, loadConfigWrapKey } from "../admin/config-secret.ts";
import { createIdpConnection, deleteIdpConnection, deleteIdpSecret, getIdpConnectionRaw, getIdpSecret, handleOauth2Callback, handleOauth2Start, handleOidcCallback, handleOidcStart, type KvStorage, listIdpConnections, putIdpSecret, setIdpConnectionEnabled, updateSamlSigningCerts } from "../admin/oidc-store.ts";
import type { ClaimBoundary, ClaimDropTally } from "../admin/posture-counters.ts";
import { certNotAfter, } from "../admin/saml/response.ts";
import { classifySsoFailure, SSO_FAIL_CODES, type SsoFailCode } from "../admin/sso-failure-class.ts";
import { log } from "../log.ts";
import { recordExpiryObserveFault, recordStorageAnomaly, recordVocabDrop } from "./sched-fault-ledger.ts";
import { IDP_EPOCH_PREFIX, OIDC_GROUPS_PREFIX, PASSKEY_CRED_PREFIX, type SchedulerDOCtor, SESSION_EPOCH_SUB_PREFIX } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";
import type { SessionClient } from "./scheduler-do-session.ts";

// AUTH_SIGNAL_THROTTLE_MS bounds how often a HOT-READ-PATH auth signal may hit storage (see
// recordAuthSignalThrottled). One minute: long enough that a request storm costs one write, short enough that
// "is it still happening" stays answerable from lastAt.
const AUTH_SIGNAL_THROTTLE_MS = 60_000;

// AUTH_SIGNAL_PENDING_FLUSH bounds how many events the throttle will hold in memory for one name before it
// writes early. The throttle accumulates the hits it defers rather than dropping them, so this is the
// ceiling on both the in-memory tally and, more importantly, on what an isolate eviction costs.
//
// The deferred tally is an instance field. A Durable Object is evicted when idle and restarted on every
// deploy (this engine ships self-updates), and eviction destroys instance fields while durable storage
// survives. A large ceiling would let a fleet-wide lockout that ends inside its own throttle window, and is
// then evicted before the pack is built, persist as a single event indistinguishable from one stale browser
// tab.
//
// At 25, the throttle writes once per 26 events rather than once per window, so at most 25 events of one
// name can ever be lost to an eviction: a 600-failure lockout survives a restart as at least 575. The
// storage cost stays O(events / 26), so a request storm still cannot drive a write per request, and the
// counts a support engineer reads are event counts.
const AUTH_SIGNAL_PENDING_FLUSH = 25;

// The ceiling on how many events one auth-method-use write may stand for. The router's throttle holds at
// most METHOD_USE_PENDING_FLUSH (25) deferred requests per method before it writes, so a well-behaved edge never
// sends more than that; this bounds what a drifted or hostile edge could add in one call. A clamp, not a policy.
const AUTH_METHOD_USE_MAX_EVENTS = 100;

// The bounded SSO sign-in failure aggregate for support diagnosis. One DO key holding a map keyed by the
// closed classifier code -> { count (capped), lastAt }. Keys are bounded by the ~10-member code set, so a
// flood of failed sign-ins cannot grow storage (the DoS-amplification guard: an attacker spamming bad
// assertions just re-bumps a counter, it never adds rows or an audit-chain entry); the count is capped so it
// cannot grow unboundedly either. Only the code / count / time are ever stored, never the raw failure reason
// (which may interpolate an issuer, connId or error message). The pack applies a recency window on lastAt,
// so a stale code ages out of the diagnosis.
type SsoFailureAgg = Record<string, { count: number; lastAt: string }>;
const SSO_FAILURES_KEY = "ssofailures:agg";
const SSO_FAIL_COUNT_CAP = 1000;
// The per-connection-kind breakdown of the same classified SSO failures. The global aggregate above answers
// "which failure code", this answers "on which protocol" (oidc / oauth2 / saml), the single most valuable
// extra axis for the pack. It is deliberately keyed by the closed connKind enum, not the operator-chosen
// connId slug: connKind is a fixed vocabulary already projected by the configEvents excerpt
// (idpConnectionFields), whereas the connId is kept out of the pack by design. So this stays redaction-safe
// by construction (closed enum keys, at the outer and inner level) and bounded to 3 kinds x ~10 codes = ~30
// entries, the same DoS-amplification floor as the global aggregate (a flood of bad assertions re-bumps a
// counter, never grows storage or the audit chain).
type SsoFailureByKind = Record<string, SsoFailureAgg>;
const SSO_FAILURES_BY_KIND_KEY = "ssofailures:bykind";
const SSO_CONN_KINDS = new Set(["oidc", "oauth2", "saml"]);

// ---- the per-connection axis ---------------------------------------------------------------------
//
// "SAML sign-ins are failing intermittently" on a tenant with two SAML connections: the pack shows the code
// and the count and cannot say which connection, so support cannot tell "your second IdP's cert rolled" from
// "both are broken". The connId is deliberately kept out of the pack (it is an operator-chosen slug and can
// carry a tenant name), so the axis is an opaque stable ordinal instead: the first connection this DO ever
// records against becomes `conn-1`, the next `conn-2`, and the assignment never changes. Support says "conn-2
// is the one failing"; the customer maps it back from their own console, where the mapping is theirs to see.
// The connId -> ordinal map lives only in DO storage and never rides in the pack; only the ordinal does.
const SSO_CONN_ORDINALS_KEY = "ssofailures:connordinals";
const SSO_FAILURES_BY_CONN_KEY = "ssofailures:byconn";
// The ordinal ceiling: a tenant with more connections than this stops minting new ordinals (the fleet-wide
// fact is already made), so a churn of created-and-deleted connections cannot grow the map without bound.
const SSO_CONN_ORDINAL_CAP = 24;
type SsoConnOrdinals = Record<string, number>;
type SsoFailureByConn = Record<string, SsoFailureAgg>;

export function IdpMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // recordSsoFail is the BEST-EFFORT diagnostic record for a failed interactive sign-in. It NEVER throws and
    // never alters the sign-in error path (the caller has already decided to fail). It classifies the free-text
    // reason to a CLOSED code and then DISCARDS the reason, incrementing that code's capped counter + timestamp in
    // the single bounded aggregate key. See SsoFailureAgg for the DoS-amplification / no-custody rationale.
    // connKind is the optional protocol of the connection the failure happened on (oidc / oauth2 / saml). When
    // it is a member of the closed set the same classified failure is also bumped in the per-kind breakdown so the
    // pack can say "your SAML sign-ins are failing on signature, your OIDC on issuer". An absent/unknown kind (an
    // early request-shape failure before the connection resolved) records only the global aggregate. connKind is a
    // closed enum, never the connId slug, so no operator-chosen identifier is ever stored.
    async recordSsoFail(reason: string, connKind?: string, connId?: string): Promise<void> {
      await this.recordSsoFailCode(classifySsoFailure(reason), connKind, connId);
    }

    // recordSsoFailCode is the same recorder for a failure whose code is already a closed member -- the paths
    // that are known by where they failed rather than by parsing a message (start-failure and
    // metadata-failure). It is the single write path both recordSsoFail and the path recorders share, so the
    // code-set guard, the caps and the redaction boundary exist exactly once. Never throws.
    async recordSsoFailCode(code: SsoFailCode, connKind?: string, connId?: string): Promise<void> {
      try {
        // Defence in depth: an out-of-vocabulary code is DROPPED, so no caller-derived string can add a key.
        if (!(SSO_FAIL_CODES as readonly string[]).includes(code)) return;
        const map = (await this.state.storage.get<SsoFailureAgg>(SSO_FAILURES_KEY)) ?? {};
        const prev = map[code];
        map[code] = { count: Math.min(SSO_FAIL_COUNT_CAP, (prev?.count ?? 0) + 1), lastAt: nowMillisISO() };
        await this.state.storage.put(SSO_FAILURES_KEY, map);
        // Per-connection-KIND breakdown: only a member of the closed enum is bucketed (defence-in-depth on the
        // redaction), so a bogus kind can never add an outer key. Bounded to 3 kinds x the ~12-code set.
        if (typeof connKind === "string" && SSO_CONN_KINDS.has(connKind)) {
          const byKind = (await this.state.storage.get<SsoFailureByKind>(SSO_FAILURES_BY_KIND_KEY)) ?? {};
          const sub = byKind[connKind] ?? {};
          const prevK = sub[code];
          sub[code] = { count: Math.min(SSO_FAIL_COUNT_CAP, (prevK?.count ?? 0) + 1), lastAt: nowMillisISO() };
          byKind[connKind] = sub;
          await this.state.storage.put(SSO_FAILURES_BY_KIND_KEY, byKind);
        }
        // The per-connection axis, keyed by the opaque ordinal (never the connId). This is what lets
        // support say "conn-2 is the one whose cert rolled" on a tenant with two SAML connections, which the
        // kind axis structurally cannot.
        if (typeof connId === "string" && connId !== "") {
          const ordinal = await this.ssoConnOrdinal(connId);
          if (ordinal !== null) {
            const byConn = (await this.state.storage.get<SsoFailureByConn>(SSO_FAILURES_BY_CONN_KEY)) ?? {};
            const sub = byConn[ordinal] ?? {};
            const prevC = sub[code];
            sub[code] = { count: Math.min(SSO_FAIL_COUNT_CAP, (prevC?.count ?? 0) + 1), lastAt: nowMillisISO() };
            byConn[ordinal] = sub;
            await this.state.storage.put(SSO_FAILURES_BY_CONN_KEY, byConn);
          }
        }
      } catch {
        // A diagnostic counter must never break or slow the auth-failure response beyond best-effort.
      }
    }

    // ssoConnOrdinal maps a connId to its STABLE OPAQUE ordinal ("conn-1", "conn-2", ...), minting one on
    // first sight. THE REDACTION CHOKEPOINT for the per-connection axis: the connId goes IN and only the
    // ordinal comes OUT, so no caller of the recorders above can ever put an operator-chosen slug into a
    // counter key. Returns null past the ordinal cap (a churn of created/deleted connections cannot grow the
    // map without bound). The connId -> ordinal map itself is DO-side only and is never projected.
    async ssoConnOrdinal(connId: string): Promise<string | null> {
      const map = (await this.state.storage.get<SsoConnOrdinals>(SSO_CONN_ORDINALS_KEY)) ?? {};
      const existing = map[connId];
      if (typeof existing === "number") return `conn-${existing}`;
      const used = Object.values(map).filter((n) => typeof n === "number");
      if (used.length >= SSO_CONN_ORDINAL_CAP) return null;
      const next = used.length === 0 ? 1 : Math.max(...used) + 1;
      map[connId] = next;
      await this.state.storage.put(SSO_CONN_ORDINALS_KEY, map);
      return `conn-${next}`;
    }

    // readSsoFailuresByConn returns the per-connection breakdown for the pack (GET /sso-failures-by-conn).
    // Redaction-safe by construction: the outer keys are the opaque ordinals this DO minted, the inner
    // keys the closed code set, the values int counts + timestamps. The connId appears nowhere.
    async readSsoFailuresByConn(): Promise<SsoFailureByConn> {
      return (await this.state.storage.get<SsoFailureByConn>(SSO_FAILURES_BY_CONN_KEY)) ?? {};
    }

    // readSsoFailures returns the bounded aggregate for the support pack's projection (GET /sso-failures). The
    // stored value is already redaction-safe by construction (closed code keys + int counts + timestamps).
    async readSsoFailures(): Promise<SsoFailureAgg> {
      return (await this.state.storage.get<SsoFailureAgg>(SSO_FAILURES_KEY)) ?? {};
    }

    // readSsoFailuresByKind returns the per-connection-kind breakdown (GET /sso-failures-by-kind). Redaction-
    // safe by construction: the outer keys are the closed connKind enum, the inner keys the closed classifier code
    // set, values int counts + timestamps. Empty until a classified failure carried a known connKind.
    async readSsoFailuresByKind(): Promise<SsoFailureByKind> {
      return (await this.state.storage.get<SsoFailureByKind>(SSO_FAILURES_BY_KIND_KEY)) ?? {};
    }

    // recordAuthSignal is the best-effort recorder for a closed-vocabulary auth/RBAC defensive-branch event.
    // Like recordSsoFail it never throws and never alters the auth decision (the caller has already decided). It
    // bumps the named counter in the single bounded aggregate; an out-of-vocabulary name is dropped (defence in
    // depth, so no caller can inject a key). See admin/auth-signals.ts for the DoS / no-custody rationale. It lives
    // on the IdpMixin (next to recordSsoFail) but is declared on the surface so the base rate-limiter and the
    // recovery / rbac mixins can record too. `name` is typed string (the POST /auth-signal route forwards a client
    // string); the closed-set guard is the redaction boundary, and the validate suites pin every internal literal.
    // recordAuthSignalThrottled is recordAuthSignal for the signals that fire on a hot read path (the RBAC
    // authority resolution runs on every authenticated request, so a caller with one corrupt grant would
    // otherwise drive a storage write per request, forever). It throttles the storage write to at most one per
    // name per AUTH_SIGNAL_THROTTLE_MS per DO isolate; it does not throttle the count. Signals that fire on a
    // write or a ceremony keep the plain recordAuthSignal.
    //
    // A hit inside an open window must still count as a real event rather than collapse to one per window:
    // treating a hit inside the window as a no-op would make a fleet-wide lockout of hundreds of rejected
    // session verifies inside one minute read back identical to a single stale browser tab, understating the
    // very outage the signal exists to surface.
    //
    // So the deferred events are accumulated in a per-isolate tally and flushed with the next write (and on
    // the pack read, below): the storage-write rate stays exactly one write per name per window, so the DoS
    // property (a request storm cannot drive a write per request) holds, while the counts are real event
    // counts and capSaturated becomes reachable on the signals it would otherwise miss. The tally is an int
    // per closed name, never persisted, and it holds nothing but a count.
    async recordAuthSignalThrottled(name: string): Promise<void> {
      const now = Date.now();
      const last = this.authSignalThrottle.get(name);
      const pending = this.authSignalPending.get(name) ?? 0;
      if (last !== undefined && now - last < AUTH_SIGNAL_THROTTLE_MS && pending < AUTH_SIGNAL_PENDING_FLUSH) {
        // Inside the open window: defer the WRITE, keep the EVENT. The flush ceiling bounds how much a storm
        // can hold in memory, and how much an isolate eviction could cost, at one extra write per that many.
        this.authSignalPending.set(name, pending + 1);
        return;
      }
      this.authSignalThrottle.set(name, now);
      this.authSignalPending.delete(name);
      await this.recordAuthSignalN(name, pending + 1);
    }

    // flushAuthSignalPending writes out every event the throttle deferred and has not yet flushed. It runs on
    // the PACK READ (readAuthSignals), which is the only moment the deferred tail must be on disk: a storm that
    // STOPS inside its window would otherwise leave its last window's events in memory with no later hit to
    // carry them out, and the pack -- built minutes later, from the same DO instance -- would under-report the
    // very burst it was built to explain. Best-effort; never throws.
    async flushAuthSignalPending(): Promise<void> {
      if (this.authSignalPending.size === 0) return;
      const due = [...this.authSignalPending.entries()];
      this.authSignalPending.clear();
      for (const [name, n] of due) {
        if (n > 0) await this.recordAuthSignalN(name, n);
      }
    }

    // The per-isolate throttle window. Instance-scoped (never shared across DO instances) and never persisted.
    authSignalThrottle = new Map<string, number>();

    // The per-isolate DEFERRED EVENT TALLY: how many hits of each throttled name have happened inside the open
    // window and are not yet on disk. A closed name -> int. Instance-scoped, never persisted, and it can hold
    // nothing but a count.
    authSignalPending = new Map<string, number>();

    // authSignalChain serialises the aggregate's read-modify-write. Several call sites are deliberately
    // fire-and-forget (`void this.recordAuthSignal(...)`, the established idiom for a signal recorded from a
    // synchronous authority-resolution path), and two such calls in the same turn would otherwise both read
    // the same map and the second put would clobber the first, silently losing a bump. The chain is
    // instance-scoped and never persisted; a rejection can never propagate (recordAuthSignal already swallows
    // its own faults).
    authSignalChain: Promise<void> = Promise.resolve();

    async recordAuthSignal(name: string): Promise<void> {
      return this.recordAuthSignalN(name, 1);
    }

    // recordAuthSignalN is recordAuthSignal carrying how many events this write stands for: one for an
    // ordinary bump, N when the throttle is flushing a window it deferred. Same serialisation, same closed-set
    // redaction boundary, same best-effort contract.
    async recordAuthSignalN(name: string, n: number): Promise<void> {
      const next = this.authSignalChain.then(() => this.recordAuthSignalSerial(name, n));
      this.authSignalChain = next.catch(() => {});
      return next;
    }

    async recordAuthSignalSerial(name: string, n = 1): Promise<void> {
      try {
        // An out-of-vocabulary name is dropped, which is the correct redaction posture (no caller string may
        // become a storage key) but also a blind spot: after a partial rollout across edges, a newer edge can
        // emit a name this DO's set does not hold, the counter silently stops incrementing, and the pack
        // reads a quiet auth aggregate during the very lockout it exists to explain. Count the drop (never the
        // token, which is arbitrary drift content) so component skew is one line in the pack.
        if (!AUTH_SIGNAL_NAME_SET.has(name)) {
          await recordVocabDrop(this.state.storage, "auth-signal");
          return;
        }
        const map = (await this.state.storage.get<AuthSignalAgg>(AUTH_SIGNALS_KEY)) ?? {};
        // The bump carries the temporal shape: without it, a large burst an hour ago and a month-long trickle
        // would produce identical rows (same count band, same lastAt shape), and the count would silently
        // saturate at the cap. bumpAuthSignalEntry ages a 14-slot day ring, latches firstAt, and sets
        // capSaturated the moment the counter stops moving. Still counts only: no identity, IP or email is
        // representable in this record, which is the property the whole aggregate rests on.
        map[name] = bumpAuthSignalEntry(map[name], Date.now(), nowMillisISO(), n);
        await this.state.storage.put(AUTH_SIGNALS_KEY, map);
      } catch {
        // A diagnostic counter must never break or slow the auth path beyond best-effort.
      }
    }

    // readAuthSignals returns the bounded aggregate for the pack projection (GET /auth-signals). Redaction-safe
    // by construction: closed event-name keys + int counts + timestamps.
    //
    // It flushes the throttle's deferred tally first. A burst that ends inside its own throttle window leaves
    // its events in memory with no later hit to carry them out, so without this the pack would under-report
    // the burst -- by the whole burst, if it fitted inside one window, which is precisely the fleet-lockout
    // shape. The flush is best-effort and the read answers whatever is on disk either way.
    async readAuthSignals(): Promise<AuthSignalAgg> {
      await this.flushAuthSignalPending();
      return (await this.state.storage.get<AuthSignalAgg>(AUTH_SIGNALS_KEY)) ?? {};
    }

    // recordAuthMethodUse records one authenticated admin request's credential path -- the closed AuthMethod
    // resolveCaller established -- against the same bounded day-ring the auth signals use. It answers the
    // post-incident question the pack could not otherwise answer: "was this estate behind Access when the
    // change was made, and how long did it run on the shared break-glass token?"
    //
    // It is a posture record, not a fault signal: it lives under its own key and its own closed vocabulary
    // rather than in AUTH_SIGNAL_NAMES, so the ordinary traffic of a healthy estate can never be read as a
    // defensive branch firing. `n` is the number of requests this write stands for (the router throttles the
    // write, never the event), clamped, so a poll storm costs one write and still counts honestly.
    //
    // Serialised on the same chain as the auth-signal aggregate: both are fire-and-forget read-modify-writes from
    // the request path, and two in one turn would otherwise read the same map and clobber each other. Best-effort
    // and never throwing: the request has already been authorised.
    //
    // No-custody: an out-of-vocabulary method name is dropped (the redaction boundary), so the key space is the
    // five closed members and nothing a caller sends can become a storage key. The value holds counts and stamps.
    async recordAuthMethodUse(method: string, n: number): Promise<void> {
      const next = this.authSignalChain.then(() => this.recordAuthMethodUseSerial(method, n));
      this.authSignalChain = next.catch(() => {});
      return next;
    }

    async recordAuthMethodUseSerial(method: string, n: number): Promise<void> {
      try {
        if (!isAdminAuthMethod(method)) {
          // An edge that emits a method this build does not hold would otherwise stop the counter silently,
          // and the pack would read a posture that never changed. Count the drop, never the token.
          await recordVocabDrop(this.state.storage, "auth-signal");
          return;
        }
        const events = Number.isFinite(n) ? Math.max(1, Math.min(AUTH_METHOD_USE_MAX_EVENTS, Math.floor(n))) : 1;
        const map = (await this.state.storage.get<AuthSignalAgg>(AUTH_METHOD_USAGE_KEY)) ?? {};
        map[method] = bumpAuthSignalEntry(map[method], Date.now(), nowMillisISO(), events);
        await this.state.storage.put(AUTH_METHOD_USAGE_KEY, map);
      } catch {
        // A posture counter must never break or slow the auth path beyond best-effort.
      }
    }

    // readAuthMethodUsage returns the bounded per-method aggregate for the pack projection (it rides GET
    // /auth-posture). Redaction-safe by construction: closed method-name keys + int counts + timestamps.
    async readAuthMethodUsage(): Promise<AuthSignalAgg> {
      return (await this.state.storage.get<AuthSignalAgg>(AUTH_METHOD_USAGE_KEY)) ?? {};
    }

    // doPlaintextSecretsMissing counts the confidential (do-plaintext) OIDC/OAuth2 connections whose stored
    // idpsecret:<id> is absent. A confidential connection with no stored secret cannot complete the code
    // exchange, so its sign-in fails at token time (do-plaintext-secret-missing) and is otherwise invisible until
    // a user tries. Presence-only: a count, never a secret value or a connId. pkce-public connections hold no
    // secret and are excluded, as are SAML (which pins a cert, not a client secret).
    async doPlaintextSecretsMissing(): Promise<number> {
      return (await this.doPlaintextSecretsMissingConns()).length;
    }

    // doPlaintextSecretsMissingConns is the same probe with the per-connection axis: which connections are
    // secretless, named by their opaque ordinal. The bare count answers "one of your connections cannot
    // complete a code exchange" and leaves the operator to guess which -- the case where recreating a
    // connection drops the secret on exactly one of several. Ordinals only, never a connId and never a secret
    // (this reads only for presence; the value is never touched).
    async doPlaintextSecretsMissingConns(): Promise<string[]> {
      const conns = await listIdpConnections(this.idpKv);
      const missing: string[] = [];
      for (const c of conns) {
        if ((c.kind === "oidc" || c.kind === "oauth2") && c.secretRef.mode === "do-plaintext" && (await getIdpSecret(this.idpKv, c.id)) === undefined) {
          const ordinal = await this.ssoConnOrdinal(c.id);
          missing.push(ordinal ?? "conn-over-cap");
        }
      }
      return missing;
    }

    // adminCredentialPaths counts the alternative (non-token) admin sign-in paths that still work: the number
    // of registered passkeys and the number of enabled IdP connections. When the operator disables / retires
    // the ADMIN_TOKEN break-glass (status.tokenFallbackDisabled) and both of these are zero and Cloudflare
    // Access is not configured, there is no way back in - the account is locked out. Presence counts only
    // (never a credential, a public key, an email or a connId), so the pack can flag the lockout risk without
    // holding anything sensitive. SAML connections count too (an enabled SAML SP is a sign-in path); the
    // passkey count is the raw registered-credential rows across all members.
    async adminCredentialPaths(): Promise<{ passkeyCredentials: number; enabledIdpConnections: number }> {
      const creds = await this.state.storage.list({ prefix: PASSKEY_CRED_PREFIX });
      const conns = await listIdpConnections(this.idpKv);
      return { passkeyCredentials: creds.size, enabledIdpConnections: conns.filter((c) => c.enabled).length };
    }

    // ==== Native external-IdP (OIDC): storage adapter, revocation axes, session mint, route handlers ==========
    //
    // ARCHITECTURE: connection custody (the idpconn:/idpsecret:/oidcstate: records) and the session mint live in
    // THIS DO; the IdP network round-trips (discovery, the code->token exchange, the JWKS fetch) run INSIDE the DO
    // too, which is sound for the two shipped custody floors (do-plaintext + pkce-public) because they need no env
    // binding - only storage (the secret in idpsecret:) and the global fetch (which a DO has). The secrets-store
    // and private-key-jwt modes need env.SECRETS_STORE / an engine-held key, which the DO constructor does NOT
    // receive; oidc-store.ts already REFUSES those modes with a clear reason, and wiring them is a router-side
    // follow-up (resolve the secret in the router, pass it in). The ROUTER owns the web edge only.


    // idpKv adapts this DO's DurableObjectStorage to the KvStorage interface oidc-store.ts is written over (the
    // same get/put/delete/list subset the validator drives with an in-memory mock), so the PRODUCTION path is the
    // path under test. The shapes already line up; this is a thin explicit binding (not a structural cast) so the
    // adaptation is visible. list() is forwarded with the prefix option the store passes.
    get idpKv(): KvStorage {
      const storage = this.state.storage;
      return {
        get: <T>(key: string): Promise<T | undefined> => storage.get<T>(key),
        put: <T>(key: string, value: T): Promise<void> => storage.put<T>(key, value),
        delete: (key: string): Promise<boolean> => storage.delete(key),
        list: <T>(opts?: { prefix?: string }): Promise<Map<string, T>> => storage.list<T>(opts ?? {}),
      };
    }

    async getIdpEpoch(connId: string): Promise<number> {
      const n = await this.state.storage.get<number>(`${IDP_EPOCH_PREFIX}${connId}`);
      if (typeof n === "number" && Number.isFinite(n) && n >= 0) return n;
      // A stored epoch that reads back corrupt coerces to 0, which means "kill no sessions" -- so "we disabled
      // that connection but a session kept working" would leave no trace anywhere. The safe default stays (a
      // scheduler must not crash on a corrupt byte); the heal is counted instead. `undefined` is the ordinary
      // never-bumped case and is not an anomaly.
      if (n !== undefined) await recordStorageAnomaly(this.state.storage, "epoch-corrupt-defaulted");
      return 0;
    }
    // bumpIdpEpoch stamps NOW, killing every session minted through the connection before this moment
    // (disable / delete / secret rotate).
    async bumpIdpEpoch(connId: string, nowMs: number): Promise<void> {
      await this.state.storage.put(`${IDP_EPOCH_PREFIX}${connId}`, nowMs);
    }
    async getSessionEpochSub(subject: string): Promise<number> {
      const n = await this.state.storage.get<number>(`${SESSION_EPOCH_SUB_PREFIX}${subject}`);
      return typeof n === "number" && Number.isFinite(n) && n >= 0 ? n : 0;
    }
    // bumpSessionEpochSub stamps NOW to deprovision a single principal (every session for that exact subject dies).
    async bumpSessionEpochSub(subject: string, nowMs: number): Promise<void> {
      await this.state.storage.put(`${SESSION_EPOCH_SUB_PREFIX}${subject}`, nowMs);
    }

    // nativeSessionIssue mints a v3 native-IdP (oidc/saml) session for a VERIFIED principal (the callback/ACS has run
    // the guarded exchange + id_token verification, so the subject/email/groups here are IdP-proven, not request
    // input). It REFUSES a principal with no usable email (the v3 token requires a non-empty canonical email - a
    // subject-only session is a SAML-phase concern), BINDS a pending invite ONLY when emailVerified is true (the
    // email_verified gate; the bind is forced here, the single trusted point, so an unverified email authenticates
    // as the immutable subject but never claims an invite), snapshots the verified groups for the per-request
    // re-read, and mints the v3 token (method "oidc", the VERBATIM subject, the connId, the per-email epoch). The
    // connId + subject revocation axes are enforced at verify; iat (stamped by signSession) is all they need.
    async nativeSessionIssue(
      // The minimal verified-principal shape shared by ResolvedPrincipal (oidc) and SamlPrincipal (saml): the
      // VERBATIM prefixed subject (oidc:/saml:), the canonical email or null, the IdP-asserted verified flag, and
      // the bounded groups. The subject is taken as-is, never re-derived (the cross-method anti-forge property).
      principal: { subject: string; email: string | null; emailVerified: boolean; groups: string[] },
      connId: string,
      method: "oidc" | "saml",
      // nowMs is the FLOW-START instant (captured before the callback/ACS network + parse work), used as the
      // session iat so a revocation (idpEpoch / sessionEpochSub) stamped DURING the in-flight login still exceeds
      // the iat and kills the session (closing the mint-after-bump TOCTOU). signSession derives exp from it too.
      nowMs: number,
      // sessionNotOnOrAfter: the IdP-asserted session upper bound (epoch ms) when the assertion
      // carried one, else null/undefined. signSession caps exp at min(nowMs + SESSION_TTL_MS, this), so a native
      // session never outlives the IdP session. SAML passes the AuthnStatement bound; OIDC passes nothing today
      // (capping at the id_token exp is a recorded best-effort follow-up, not enforced here).
      sessionNotOnOrAfter?: number | null,
      priorToken?: unknown,
      // client: the coarse provenance recorded beside the session so it can be listed and ended singly.
      client?: SessionClient,
    ): Promise<{ ok: true; token: string } | { ok: false; reason: string }> {
      const email = this.normaliseEmail(principal.email);
      if (!email) {
        // A verified principal with no usable email is refused here (the single trusted mint chokepoint). Record
        // the bounded signal so an "IdP without the email scope / emailless service-token sign-in" lockout is visible.
        await this.recordAuthSignal("emailless-assertion");
        return { ok: false, reason: "the IdP asserted no usable email; grant the email scope on this connection" };
      }
      const subject = this.normaliseSubject(principal.subject);
      if (!subject) {
        // A verified principal whose subject is pathological / empty is refused. Record the bounded signal.
        await this.recordAuthSignal("subject-unusable");
        return { ok: false, reason: "the resolved subject is not a usable key" };
      }
      // email_verified-gated bind: force the pending-invite bind (allowEmailBind=true) only when the IdP verified
      // the email. An unverified email still mints a session below, but binds no invite (anti-takeover). Record
      // the skipped-bind on the unverified-email path so a "my invited user signed in but never got their role"
      // ticket is diagnosable (the IdP is not asserting email_verified). Only the closed event name is stored.
      // An owner invite may only bind on a genuinely-verified email. OIDC/OAuth2 carry the IdP's own
      // email_verified; a SAML connection is genuine only under emailVerifiedPolicy "require-flag" (the assertion
      // carried the verified flag), not "trust-idp" (verified-by-policy, no flag). Compute the strength once; a
      // weakly-verified owner bind is refused inside resolveBoundEntry (lesser roles are unaffected).
      let emailVerifiedStrong = method === "oidc";
      if (method === "saml") {
        const mintConn = await getIdpConnectionRaw(this.idpKv, connId);
        emailVerifiedStrong = mintConn?.kind === "saml" && mintConn.emailVerifiedPolicy === "require-flag";
      }
      const bound = principal.emailVerified ? await this.resolveBoundEntry(subject, email, true, emailVerifiedStrong) : undefined;
      if (!principal.emailVerified) await this.recordAuthSignal("email-verified-bind-blocked");
      // subject-rekey-role-loss: this verified login has no role bound for its subject (resolveBoundEntry
      // matched neither an existing role:sub:<subject> nor a pending/legacy email grant), yet the same email holds
      // a role under a different subject. That is the signature of an IdP subject rekey: the user's sub claim
      // changed, so their role binding (keyed on the immutable subject) is orphaned and they silently drop to
      // viewer. Recorded once at login (only when this subject is unbound, so a normally-bound login skips the
      // scan) so a "my user changed nothing but lost their access" ticket is diagnosable. Only the closed event
      // name is stored - never the email or either subject. Best-effort: the read/record never blocks the mint.
      if (bound === undefined && principal.emailVerified) {
        try {
          const entries = await this.listRoleEntries();
          if (entries.some((e) => e.email === email && e.subject !== subject)) await this.recordAuthSignal("subject-rekey-role-loss");
        } catch {
          // A diagnostic scan must never break the session mint.
        }
      }
      // Snapshot the verified groups for the per-request role re-read (groups stay out of the cookie).
      //
      // This is where a SAML group is actually dropped, and the tally names why. SAML groups ride verbatim out
      // of the assertion (collectIdentity returns every value of the configured groups attribute, unbounded),
      // so this bound is the SAML front door's first and only one. The tally records both the drop kind
      // (over-long, control char, past the cap) and the boundary, never the group itself, so "the user is in
      // the right AD group and gets viewer" is diagnosable for SAML, the one interactive sign-in kind whose
      // groups this engine bounds itself. The OIDC/OAuth2 principals arrive here already bounded by their own
      // parse boundaries (oidc.ts boundGroups, oauth2.ts addGroup, identical limits), which tally at that
      // boundary, so passing the method through as the boundary cannot mis-file a drop, and on those paths
      // there is nothing left to drop.
      const claimDrops: ClaimDropTally = new Set<string>();
      const boundary: ClaimBoundary = method === "saml" ? "saml" : "oidc-token";
      const boundedGroups = this.boundGroupList(principal.groups, claimDrops, boundary);
      if (claimDrops.size > 0) void this.recordAdminCounters({ bumps: Object.fromEntries([...claimDrops].map((n) => [n, 1])) });
      // Some asserted group names were dropped by bounding (empty / over-long / an ASCII control character), so a
      // role keyed on a dropped group would be silently lost. Record the bounded signal once per login (not per
      // request) so a "my group-mapped users lost their role" ticket is diagnosable (group-control-char-dropped).
      if (boundedGroups.length < principal.groups.length) await this.recordAuthSignal("group-name-dropped");
      // group-claim-dropped-role-loss: the login asserted (bounded) groups but none of them matched a
      // configured group -> role mapping, so a user who relies on group-mapped access resolves to no group role
      // (silent role loss). This is read once at login (only when groups were actually asserted, so the common
      // no-groups login skips the mapping read) rather than on the per-request role hot path. groupRoleFor is the
      // same resolver the request path uses, so the signal reflects real resolution. Only the closed event name is
      // stored - never a group name. Best-effort: it never blocks the mint.
      if (boundedGroups.length > 0) {
        try {
          // Scope the mapping to this connection (a scoped mapping applies only to its connId), so the
          // signal reflects the same connection-scoped resolution the request path (roleForCaller) computes.
          const mapping = (await this.listGroupRoleEntries()).filter((m) => m.connId === undefined || m.connId === connId);
          if (this.groupRoleFor(boundedGroups, mapping) === null) await this.recordAuthSignal("zero-role-groups");
        } catch {
          // A diagnostic mapping read must never break the session mint.
        }
      }
      await this.state.storage.put(`${OIDC_GROUPS_PREFIX}${subject}`, boundedGroups);
      const key = await this.sessionSigningKey();
      // End the session this browser presented before the epoch read below, so the token minted here
      // carries the bumped epoch and the presented one fails verification from now on.
      await this.revokePresentedSession(priorToken, nowMs);
      // Cap the session at the IdP bound when present (a finite number). Absent/non-finite leaves signSession's
      // default 12h absolute TTL.
      const idpExp = typeof sessionNotOnOrAfter === "number" && Number.isFinite(sessionNotOnOrAfter) ? sessionNotOnOrAfter : undefined;
      const token = await this.mintSessionRecorded(key, { method, email, subject, connId, epoch: await this.getSessionEpoch(email), ...(idpExp !== undefined ? { exp: idpExp } : {}) }, nowMs, client);
      return { ok: true, token };
    }

    // idpProviders is the PRE-AUTH display DTO for the sign-in screen: the id + label + kind + presetId of every
    // ENABLED connection, and NOTHING else (no issuer, clientId, endpoints or secretRef). It is reachable before
    // authentication (you need it to render the "Sign in with X" buttons), so it must leak no internal config;
    // disabled connections are omitted (their button must not show). The console composes the button text + icon
    // from label + presetId.
    async idpProviders(): Promise<{ ok: true; providers: Array<{ id: string; label: string; kind: "oidc" | "oauth2" | "saml"; presetId: string }> }> {
      const conns = await listIdpConnections(this.idpKv);
      const providers = conns.filter((c) => c.enabled).map((c) => ({ id: c.id, label: c.label, kind: c.kind, presetId: c.presetId }));
      return { ok: true, providers };
    }

    // idpConnCreate creates a connection (keys.ceremony-gated, owner-exclusive: a group can confer access-admin,
    // so connection CRUD is gated on the owner-reserved keys.ceremony, never access.policy). The proposal is run
    // through the shared pure validator inside createIdpConnection; the do-plaintext client secret (when supplied)
    // is stored WRITE-ONLY under idpsecret:<id>; the create is audited without any secret. Returns the REDACTED
    // connection (no secret value ever leaves the DO).
    async idpConnCreate(
      body: { presetId?: unknown; vars?: unknown; proposal?: unknown; id?: unknown; label?: unknown; clientId?: unknown; secret?: unknown; secretMode?: unknown; clientAuth?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; conn: IdpConnection } | { ok: false; reason: string }> {
      await this.requireCapabilityResolved(caller, "keys.ceremony");
      // The console NEVER builds the proposal itself: the preset logic is the engine's single source of truth and
      // the no-customer-CLI rule keeps the privileged build server-side. The console sends {presetId, vars,
      // clientId, secret} and the engine builds + validates + stores. A raw {proposal} is still accepted for the
      // advanced / SAML / generic path (the console builds those structurally, not from an oidc-presets template).
      let proposal: IdpConnectionProposal;
      if (typeof body.presetId === "string") {
        const preset = presetById(body.presetId);
        if (preset === undefined) return { ok: false, reason: `unknown preset "${body.presetId}"` };
        const vars: Record<string, string> = {};
        if (body.vars !== null && typeof body.vars === "object") {
          for (const [k, v] of Object.entries(body.vars as Record<string, unknown>)) if (typeof v === "string") vars[k] = v;
        }
        const missing = missingRequiredVars(preset, vars);
        if (missing.length > 0) return { ok: false, reason: `provide the required value(s): ${missing.join(", ")}` };
        // Absent means "use the preset default"; present-but-wrong-shape is refused, never quietly replaced
        // with the default. Otherwise {"label": 42} would silently save a connection called "Okta", and a
        // clientAuth of "hmac" would silently save one authenticating with client_secret_post -- an auth-root
        // setting the operator did not choose, which the console would then show back to them as though it
        // were theirs. Each check names the field so the refusal is actionable.
        if (body.id !== undefined && typeof body.id !== "string") return { ok: false, reason: "id must be a string when supplied (omit it to use the preset id)" };
        if (body.label !== undefined && typeof body.label !== "string") return { ok: false, reason: "label must be a string when supplied (omit it to use the preset label)" };
        if (body.clientId !== undefined && typeof body.clientId !== "string") return { ok: false, reason: "clientId must be a string" };
        if (body.secretMode !== undefined && body.secretMode !== "pkce-public" && body.secretMode !== "do-plaintext") {
          return { ok: false, reason: 'secretMode must be "pkce-public" or "do-plaintext" when supplied' };
        }
        if (body.clientAuth !== undefined && body.clientAuth !== "pkce_public" && body.clientAuth !== "client_secret_basic" && body.clientAuth !== "client_secret_post") {
          return { ok: false, reason: 'clientAuth must be "pkce_public", "client_secret_basic" or "client_secret_post" when supplied' };
        }
        const clientId = typeof body.clientId === "string" ? body.clientId : "";
        const secretMode: SecretRef["mode"] = body.secretMode === "pkce-public" ? "pkce-public" : "do-plaintext";
        const clientAuth: OidcClientAuth = body.clientAuth === "pkce_public" ? "pkce_public" : body.clientAuth === "client_secret_basic" ? "client_secret_basic" : "client_secret_post";
        // An operator may run SEVERAL connections of one provider (two Entra tenants), so an explicit id/label
        // overrides the preset-id default. The id is isConnId-bounded by validateIdpConnection downstream.
        const creds: { id?: string; label?: string; clientId: string; secretRef: SecretRef; clientAuth: OidcClientAuth } = { clientId, secretRef: { mode: secretMode }, clientAuth };
        if (typeof body.id === "string") creds.id = body.id;
        if (typeof body.label === "string") creds.label = body.label;
        proposal = buildProposalFromPreset(preset, vars, creds);
      } else {
        proposal = body.proposal as IdpConnectionProposal;
      }
      const created = await createIdpConnection(this.idpKv, proposal, caller?.email ?? null, nowMillisISO());
      if (!created.ok) {
        // private-key-jwt-unsupported: the connection was refused. When the operator requested private_key_jwt
        // client authentication (not wired in this build - the pure validator rejects it at config time), record
        // the bounded signal so a "my private-key-JWT connection will not save" ticket is diagnosable from the pack
        // rather than only surfacing as a failed idp-connection-change audit row. Keyed off the requested
        // clientAuth (a closed enum on the proposal), never the reason string; only the closed event name is stored.
        if ((proposal as { clientAuth?: unknown }).clientAuth === "private_key_jwt") await this.recordAuthSignal("private-key-jwt-unsupported");
        return created;
      }
      // The secret arrives ALREADY SEALED whenever CONFIG_WRAP_KEY is configured (the router wraps it under
      // IDP_SECRET_AAD), so the DO stores an opaque envelope and never sees the key. A bare string is the
      // back-compat floor and is stored as-is; anything else is neither shape and is ignored, as before.
      const secretToStore = typeof body.secret === "string" && body.secret.length > 0 ? body.secret : isWrappedSecret(body.secret) ? body.secret : null;
      if (secretToStore !== null && created.conn.kind !== "saml" && created.conn.secretRef.mode === "do-plaintext") {
        await putIdpSecret(this.idpKv, created.conn.id, secretToStore);
      }
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null, actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access", sourceIp: caller?.sourceIp ?? null,
        action: "idp-connection-change", outcome: "success",
        target: { kind: "idpconnection", connId: created.conn.id, connKind: created.conn.kind, op: "create" },
      });
      // Credential lifecycle registry: auto-OBSERVE a SAML signing cert's expiry from the connection's
      // pinned PEMs (PUBLIC data, reads no secret). Track the MAX notAfter across rollover certs so the
      // row reflects "SSO still works until the last cert lapses". Best-effort + fail-open: a parse miss or
      // upsert hiccup never fails the connection create. A cert rollover is realised as delete + recreate
      // (there is no IdP connection edit route), which re-observes the new MAX here.
      if (created.conn.kind === "saml") {
        try {
          let maxNotAfter: number | null = null;
          for (const pem of created.conn.idpSigningCerts) {
            const na = certNotAfter(pem);
            if (na !== null && (maxNotAfter === null || na > maxNotAfter)) maxNotAfter = na;
          }
          if (maxNotAfter !== null) {
            await this.upsertObservedItem({
              id: `idp-cert-${created.conn.id}`,
              label: `SAML signing cert, ${created.conn.label}`,
              kind: "certificate",
              lifecycleClass: "functional",
              expiresAt: new Date(maxNotAfter).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
              usageLink: { kind: "idpConnection", refId: created.conn.id },
            });
          } else {
            // Certs were pinned but none parsed to a usable notAfter, so there is nothing to count down from
            // and this connection is silently absent from the expiry ladder -- the "our SAML cert expired with
            // no warning" failure mode, months before it would land.
            await recordExpiryObserveFault(this.state.storage, "saml-cert", "no-cert-date");
          }
        } catch (e) {
          // The observe can throw while the create still carries on (correctly, fail-open), which would
          // otherwise leave the credential untracked with nothing recording that fact. Record the fault instead.
          await recordExpiryObserveFault(this.state.storage, "saml-cert", "storage-fault");
          log("error", `SAML cert observe failed for ${created.conn.id}: ${(e as Error).message}`);
        }
      }
      // Auto-observe a confidential OIDC/OAuth2 client-secret expiry the same way the SAML cert notAfter is
      // tracked, so a secret lapse warns on the credential-lifecycle ladder before it surfaces as a login
      // outage. The expiry is the operator-declared secretExpiresAt on the connection (redaction-safe metadata,
      // never the secret value, which the engine holds write-only and cannot read an expiry off). Only a
      // confidential client has a secret to expire (pkce-public holds nothing), and only when the operator
      // declared a date. Best-effort + fail-open: a hiccup never fails the create. The row is keyed
      // idp-secret-<id>, kind credential, linked to the connection so the console renders "what breaks".
      if ((created.conn.kind === "oidc" || created.conn.kind === "oauth2") && created.conn.secretRef.mode !== "pkce-public" && created.conn.secretExpiresAt !== undefined) {
        await this.upsertObservedItem({
          id: `idp-secret-${created.conn.id}`,
          label: `IdP client secret, ${created.conn.label}`,
          kind: "credential",
          lifecycleClass: "functional",
          expiresAt: created.conn.secretExpiresAt,
          usageLink: { kind: "idpConnection", refId: created.conn.id },
        });
      }
      return created;
    }

    // idpPresets returns the display-only preset catalogue (listPresets: ids/labels/vendors/requiredVars/notes, no
    // secrets) for the console's add-connection picker. keys.ceremony-gated like the rest of connection management.
    // The engine - not the console - owns the preset templates AND builds the proposal from them (idpConnCreate),
    // so the preset logic has one source of truth and the console never constructs a connection itself.
    async idpPresets(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; presets: ReturnType<typeof listPresets> }> {
      await this.requireCapabilityResolved(caller, "keys.ceremony");
      return { ok: true, presets: listPresets() };
    }

    // idpConnList returns every stored connection REDACTED, for the owner's management UI (keys.ceremony-gated;
    // the PRE-AUTH login buttons use idpProviders, not this). A secretRef can only ever surface as {mode, ref?}.
    async idpConnList(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; connections: IdpConnection[] }> {
      await this.requireCapabilityResolved(caller, "keys.ceremony");
      return { ok: true, connections: await listIdpConnections(this.idpKv) };
    }

    // idpConnDelete removes the connection + its paired secret and bumps the idpEpoch so its live sessions die.
    //
    // It reports whether it actually removed anything (`deleted`), which is why the signature is a union of
    // three outcomes rather than two. A delete of a valid-shaped but absent connId is not a refusal -- it
    // passes every gate and every validator, so `ok` is rightly true -- and it is not a change either:
    // `existed` is false, nothing was removed, and the audit below is deliberately skipped. Without the
    // `deleted` field the two states would be the same response, so a caller could not tell "I removed a
    // connection" from "there was nothing to remove" -- and a no-op delete must never be read as a change to
    // who can sign in. The spelling matches the sibling patterns elsewhere: the roles delete returns
    // { deleted: true } only when a member was really removed (router-rbac.ts:144), and the passkey
    // credential revoke (router-account-session.ts:116) reads the same field the same way.
    async idpConnDelete(
      body: { connId?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; deleted: boolean } | { ok: false; reason: string }> {
      await this.requireCapabilityResolved(caller, "keys.ceremony");
      const connId = typeof body.connId === "string" ? body.connId : "";
      if (!isConnId(connId)) return { ok: false, reason: "invalid connId" };
      const conn = await getIdpConnectionRaw(this.idpKv, connId);
      const connKind = conn?.kind ?? "oidc";
      const existed = await deleteIdpConnection(this.idpKv, connId);
      await deleteIdpSecret(this.idpKv, connId);
      await this.bumpIdpEpoch(connId, Date.now());
      // Credential lifecycle registry: drop the auto-observed SAML cert AND OIDC/OAuth2 client-secret expiry
      // rows for this connection (only one of the two can exist per connection kind; deleting both is safe).
      await this.deleteObservedItem(`idp-cert-${connId}`);
      await this.deleteObservedItem(`idp-secret-${connId}`);
      if (existed) {
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null, actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access", sourceIp: caller?.sourceIp ?? null,
          action: "idp-connection-change", outcome: "success",
          target: { kind: "idpconnection", connId, connKind, op: "delete" },
        });
      }
      // `deleted` is exactly the condition the audit above is guarded on, so the response and the audit trail
      // agree: a run that wrote an audit row says deleted:true, and one that wrote none says deleted:false.
      return { ok: true, deleted: existed };
    }

    // idpConnSetEnabled flips the enabled flag; DISABLING bumps the idpEpoch so the connection's live sessions die.
    async idpConnSetEnabled(
      body: { connId?: unknown; enabled?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true } | { ok: false; reason: string }> {
      await this.requireCapabilityResolved(caller, "keys.ceremony");
      const connId = typeof body.connId === "string" ? body.connId : "";
      if (!isConnId(connId)) return { ok: false, reason: "invalid connId" };
      const conn = await getIdpConnectionRaw(this.idpKv, connId);
      if (conn === undefined) return { ok: false, reason: "connection not found" };
      const enabled = body.enabled === true;
      await setIdpConnectionEnabled(this.idpKv, connId, enabled);
      if (!enabled) await this.bumpIdpEpoch(connId, Date.now());
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null, actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access", sourceIp: caller?.sourceIp ?? null,
        action: "idp-connection-change", outcome: "success",
        target: { kind: "idpconnection", connId, connKind: conn.kind, op: enabled ? "enable" : "disable" },
      });
      return { ok: true };
    }

    // connectionRemovalPreflight (lockout guard) is the DO-side facts the router needs to decide whether
    // deleting or disabling connId would strand the tenant with no way back in. lastEnabledConnection is true when
    // connId is the only currently-enabled connection (so removing/disabling it leaves zero native sign-in paths);
    // the other two are the non-token, non-connection ways in the DO can see (an Owner's passkey, acknowledged
    // recovery codes). CF Access (an env fact) and the token-disabled/retired state are added by the router (which
    // alone sees the env + the break-glass latch), exactly as POST /policy/require-access splits DO vs env facts.
    // Read-only + fail-safe (a connection-list hiccup returns lastEnabledConnection:false so the guard never
    // false-refuses a legitimate delete on a transient error; the delete's own gates still apply).
    async connectionRemovalPreflight(connId: string): Promise<{ lastEnabledConnection: boolean; passkeyOwnerEnrolled: boolean; recoveryReady: boolean }> {
      let lastEnabledConnection = false;
      try {
        const conns = await listIdpConnections(this.idpKv);
        const enabled = conns.filter((c) => c.enabled);
        lastEnabledConnection = enabled.length > 0 && enabled.every((c) => c.id === connId);
      } catch {
        // The fail-safe is right (never false-refuse a legitimate delete on a transient read fault), but it
        // also silently disarms the guard that stops an account removing its last sign-in path. A persistent
        // read fault here is how an account locks itself out with every gate reporting green.
        await recordStorageAnomaly(this.state.storage, "preflight-read-failed");
        lastEnabledConnection = false; // fail-safe: never refuse on a read hiccup
      }
      const pf = await this.lockoutPreflight();
      return { lastEnabledConnection, passkeyOwnerEnrolled: pf.passkeyOwnerEnrolled, recoveryReady: pf.recoveryReady };
    }

    // idpConnSamlCertUpdate is the zero-downtime SAML signing-cert rollover edit. A cert rollover could
    // otherwise mean delete + recreate the connection, which bumps the idpEpoch (killing every live session)
    // and, under dual control, queues twice (a delete approval then a create approval) with a broken-login
    // window in between. The assertion verifier already iterates the pinned idpSigningCerts array (<=8
    // overlapping certs), so a rollover is instead modelled as an in-place edit of that array: append the new
    // IdP cert (addCerts) so assertions signed by either the old or the new key verify during the overlap, then
    // later replace (certs) to prune the retired cert once the IdP has fully cut over. It is keys.ceremony-gated
    // (owner-exclusive: a signing cert is the SAML trust root - an attacker who could add a cert could forge
    // assertions, so this is the same account-takeover class as create/enable) and is wired through the same
    // dual-control owner-action gate (idp-conn-cert) as the other connection-management ops, so a single
    // rollover takes at most one approval, not two. Crucially it does not bump the idpEpoch: refreshing the
    // trust anchor for the same IdP must not log everyone out, which is the whole point of zero-downtime. The
    // new cert array is run through the shared validateSamlCerts (the create path's exact gate) so a rollover
    // can never store a cert create would have rejected, and the credential-lifecycle cert-expiry row is
    // re-observed to the new max notAfter (best-effort, fail-open). Returns the redacted connection.
    async idpConnSamlCertUpdate(
      body: { connId?: unknown; addCerts?: unknown; certs?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; conn: IdpConnection } | { ok: false; reason: string }> {
      await this.requireCapabilityResolved(caller, "keys.ceremony");
      const connId = typeof body.connId === "string" ? body.connId : "";
      if (!isConnId(connId)) return { ok: false, reason: "invalid connId" };
      const conn = await getIdpConnectionRaw(this.idpKv, connId);
      if (conn === undefined) return { ok: false, reason: "connection not found" };
      if (conn.kind !== "saml") return { ok: false, reason: "cert rollover applies only to a SAML connection" };
      // Two modes, mutually exclusive: replace (certs = the full new array, the prune-after-cutover step) takes
      // precedence; otherwise append (addCerts merged onto the existing array, the overlap step). Either way the
      // result is run through validateSamlCerts, which de-dupes and enforces 1..SAML_CERTS_MAX valid PEMs, so an
      // append that would exceed the cap and one carrying a malformed PEM are both clean refusals with no
      // partial write. The capacity check below runs first so an over-capacity append is told about the
      // capacity, rather than given the generic "not PEM X.509" refusal.
      let nextRaw: unknown;
      if (body.certs !== undefined) {
        nextRaw = body.certs;
      } else if (body.addCerts !== undefined) {
        if (!Array.isArray(body.addCerts)) return { ok: false, reason: "addCerts must be an array of PEM X.509 certificates" };
        // The append arm answers about the merged array, whose size the operator does not otherwise see.
        // validateSamlCerts names the capacity but knows only the merged length; how much was already pinned is
        // what turns the refusal into an action. Answered here before the merge; the shared gate below is
        // unchanged.
        if (conn.idpSigningCerts.length + body.addCerts.length > SAML_CERTS_MAX) {
          return { ok: false, reason: `this connection already pins ${conn.idpSigningCerts.length} signing certificate(s), so appending ${body.addCerts.length} more would exceed the ${SAML_CERTS_MAX}-certificate limit. Take the Replace step to make the certificate(s) you pasted the whole pinned set, which prunes the retired ones, or remove certificates that are no longer in use first` };
        }
        nextRaw = [...conn.idpSigningCerts, ...body.addCerts];
      } else {
        return { ok: false, reason: "provide addCerts (append a rollover cert) or certs (replace the full set)" };
      }
      const validated = validateSamlCerts(nextRaw);
      if (!validated.ok) return validated;
      const wrote = await updateSamlSigningCerts(this.idpKv, connId, validated.certs);
      if (!wrote) return { ok: false, reason: "connection not found" };
      const updated = await getIdpConnectionRaw(this.idpKv, connId);
      // Re-observe the SAML cert expiry from the NEW pinned set (MAX notAfter across the overlap), mirroring the
      // create path so the lifecycle row reflects "SSO works until the last cert lapses". Fail-open: a parse miss
      // never fails the rollover.
      if (updated !== undefined && updated.kind === "saml") {
        try {
          let maxNotAfter: number | null = null;
          for (const pem of updated.idpSigningCerts) {
            const na = certNotAfter(pem);
            if (na !== null && (maxNotAfter === null || na > maxNotAfter)) maxNotAfter = na;
          }
          if (maxNotAfter !== null) {
            await this.upsertObservedItem({
              id: `idp-cert-${connId}`,
              label: `SAML signing cert, ${updated.label}`,
              kind: "certificate",
              lifecycleClass: "functional",
              expiresAt: new Date(maxNotAfter).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
              usageLink: { kind: "idpConnection", refId: connId },
            });
          }
        } catch (e) {
          log("error", `SAML cert re-observe failed for ${connId}: ${(e as Error).message}`);
        }
      }
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null, actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access", sourceIp: caller?.sourceIp ?? null,
        action: "idp-connection-change", outcome: "success",
        target: { kind: "idpconnection", connId, connKind: "saml", op: "update" },
      });
      return { ok: true, conn: redactIdpConn(updated ?? conn) };
    }

    // idpOidcStart is the PRE-AUTH /start handler: it loads the connection, then mints PKCE + state + nonce + the
    // login-CSRF txnId and the authorize URL (handleOidcStart, which persists the single-use state record). The
    // router sets the txn cookie + 302s to the returned authorizeUrl. No caller (the user is not signed in yet).
    async idpOidcStart(
      body: { connId?: unknown; redirectUri?: unknown; returnTo?: unknown },
    ): Promise<{ ok: true; authorizeUrl: string; state: string; txnId: string } | { ok: false; reason: string }> {
      const connId = typeof body.connId === "string" ? body.connId : "";
      if (!isConnId(connId)) return { ok: false, reason: "invalid connId" };
      const redirectUri = typeof body.redirectUri === "string" ? body.redirectUri : "";
      const returnTo = typeof body.returnTo === "string" ? body.returnTo : "/";
      const conn = await getIdpConnectionRaw(this.idpKv, connId);
      if (conn === undefined) return { ok: false, reason: "connection not found" };
      // Dispatch by protocol: an OIDC connection mints PKCE+nonce + (maybe) resolves discovery; an OAuth2
      // (GitHub-class) connection mints state (+ PKCE only if it opts in), no nonce, no discovery. Both return
      // the same {authorizeUrl, state, txnId} shape the router 302s with.
      if (conn.kind === "oidc") return handleOidcStart(this.idpKv, conn, redirectUri, returnTo, fetch, Date.now());
      if (conn.kind === "oauth2") return handleOauth2Start(this.idpKv, conn, redirectUri, returnTo, Date.now());
      return { ok: false, reason: "this connection kind does not support interactive sign-in" };
    }

    // idpOidcCallback wraps the OIDC/OAuth2 callback so every failure path (request-shape, connection, and the
    // funnelled verify/store failures) records a bounded, classified SSO failure for the support pack.
    // recordSsoFail is best-effort and never throws, so this wrapping adds no new failure mode.
    async idpOidcCallback(
      body: { connId?: unknown; code?: unknown; state?: unknown; txnId?: unknown; iss?: unknown; sourceIp?: unknown; userAgent?: unknown; configWrapKey?: unknown },
    ): Promise<{ ok: true; token: string; returnTo: string } | { ok: false; reason: string }> {
      const r = await this.idpOidcCallbackImpl(body);
      if (!r.ok) {
        // Resolve the connection kind for the per-kind SSO breakdown: a best-effort extra read taken only on
        // the failure path. An invalid/unknown connId yields no kind, so the failure records only the global
        // aggregate. The connKind is a closed enum; the operator-chosen connId slug is never stored.
        const connId = typeof body.connId === "string" ? body.connId : "";
        const conn = isConnId(connId) ? await getIdpConnectionRaw(this.idpKv, connId) : undefined;
        await this.recordSsoFail(r.reason, conn?.kind);
        // The counters above are neither ordered nor on the hash chain, so an unresolvable state (login CSRF),
        // a failed RFC 9207 iss bind, a rejected id_token, a refused tenant or hd gate and a failed OAuth2
        // userinfo leg would otherwise all leave the tamper-evident record silent. appendAuthnFailureAudit is
        // the shared recorder and its own comment carries the coalescing argument and the resolved-connection rule.
        // actorMethod is "oidc" for the OAuth2 kind too, matching the idp-sign-in SUCCESS row this same path
        // writes below (connKind carries the oauth2 distinction): a failure that named its method differently
        // from the success beside it would be its own small lie. The connection read is the one recordSsoFail
        // already takes here, so no failing path gains a storage read or a timing step another lacks.
        await this.appendAuthnFailureAudit({ ceremony: "sso-callback", actorMethod: "oidc", sourceIp: typeof body.sourceIp === "string" && body.sourceIp.length > 0 ? body.sourceIp : null, ...(conn !== undefined && (conn.kind === "oidc" || conn.kind === "oauth2") ? { connKind: conn.kind, connId } : {}) });
      }
      return r;
    }
    // idpOidcCallbackImpl is the pre-auth /callback handler: it runs handleOidcCallback (single-use state
    // consume, login-CSRF + RFC 9207 binds, guarded exchange + id_token verify, all inside the DO), then mints
    // the v3 oidc session for the verified principal and audits the sign-in. Only the cookie token + the
    // returnTo cross back to the router; the verified principal (subject, email, groups) never leaves the DO.
    async idpOidcCallbackImpl(
      body: { connId?: unknown; code?: unknown; state?: unknown; txnId?: unknown; iss?: unknown; sourceIp?: unknown; userAgent?: unknown; priorToken?: unknown; configWrapKey?: unknown },
    ): Promise<{ ok: true; token: string; returnTo: string } | { ok: false; reason: string }> {
      const connId = typeof body.connId === "string" ? body.connId : "";
      if (!isConnId(connId)) return { ok: false, reason: "invalid connId" };
      // The coarse source IP, forwarded by the router from the edge CF-Connecting-IP (the recovery-code
      // body-forward pattern). A client sign-in carries no normal caller header, so this is the only way
      // "where someone signed in from" reaches the trail, the most valuable IP to record. Null when absent.
      const sourceIp = typeof body.sourceIp === "string" && body.sourceIp.length > 0 ? body.sourceIp : null;
      const conn = await getIdpConnectionRaw(this.idpKv, connId);
      if (conn === undefined) return { ok: false, reason: "connection not found" };
      // Capture the flow-start instant ONCE: it is the id_token-validation clock, the state-TTL clock AND the
      // session iat, so a revocation (disable/delete/deprovision) that lands during the network round-trips below
      // outranks the minted session's iat and the existing not-before gates kill it (the mint-after-bump TOCTOU).
      const nowMs = Date.now();
      // THE WRAP KEY IS FORWARDED, NOT HELD: read into a local, used for one unwrap, dropped. It arrives on
      // this request because the token exchange runs HERE, inside a DO whose constructor takes only `state`.
      // The reasoning and the residual are at the forwarding site (router-idp-web.ts). Absent is the
      // back-compat floor and is not an error; MALFORMED throws out of loadConfigWrapKey rather than reading
      // as absent, which would downgrade a sign-in to the misleading "no stored client secret".
      let wrapKey: Uint8Array | undefined;
      try {
        wrapKey = loadConfigWrapKey(typeof body.configWrapKey === "string" ? body.configWrapKey : undefined);
      } catch (e) {
        return { ok: false, reason: `CONFIG_WRAP_KEY is malformed (${(e as Error).name})` };
      }
      const code = typeof body.code === "string" ? body.code : "";
      const state = typeof body.state === "string" ? body.state : "";
      const txnId = typeof body.txnId === "string" ? body.txnId : "";
      // Dispatch by protocol. Both branches return the same {principal, returnTo} so the v3 mint below is shared
      // (an Oauth2Principal is structurally a ResolvedPrincipal). The OIDC branch carries the RFC 9207 iss param;
      // OAuth2 has none.
      let result: { ok: true; principal: ResolvedPrincipal; returnTo: string } | { ok: false; reason: string; code?: "tenant_not_accepted" | "hd_not_accepted" };
      if (conn.kind === "oidc") {
        const params: { connId: string; code: string; state: string; txnId: string; iss?: string } = {
          connId, code, state, txnId,
          ...(typeof body.iss === "string" ? { iss: body.iss } : {}),
        };
        const getConn = async (id: string): Promise<OidcConnection | undefined> => {
          const c = await getIdpConnectionRaw(this.idpKv, id);
          return c !== undefined && c.kind === "oidc" ? c : undefined;
        };
        result = await handleOidcCallback(this.idpKv, params, getConn, fetch, nowMs, wrapKey);
      } else if (conn.kind === "oauth2") {
        const getConn = async (id: string): Promise<Oauth2Connection | undefined> => {
          const c = await getIdpConnectionRaw(this.idpKv, id);
          return c !== undefined && c.kind === "oauth2" ? c : undefined;
        };
        result = await handleOauth2Callback(this.idpKv, { connId, code, state, txnId }, getConn, fetch, nowMs, wrapKey);
      } else {
        return { ok: false, reason: "this connection kind does not support interactive sign-in" };
      }
      if (!result.ok) {
        // oidc-entra-multitenant-misconfig: a token whose tenant id is not in the connection's
        // acceptedTenantIds records a distinct bounded signal (an Entra /common misconfiguration), so it is
        // diagnosable apart from the generic "issuer" SSO-failure bucket. Only the closed event name is stored.
        if (result.code === "tenant_not_accepted") await this.recordAuthSignal("oidc-tenant-not-accepted");
        // Google hd gate: a verified id_token whose hd claim did not match the connection's required Workspace
        // domain records its own bounded signal, distinct from the generic issuer bucket, so a "why can't I
        // sign in with my personal account" support case is diagnosable the same way.
        if (result.code === "hd_not_accepted") await this.recordAuthSignal("oidc-hd-not-accepted");
        return { ok: false, reason: result.reason };
      }
      // The id_token verified and one or more of its claims was bounded away (an over-long or control-char
      // group, a group list past the 200 cap, an unusable acr/amr/auth_time). The sign-in succeeds -- with a
      // lesser role than the dropped group would have conferred -- so the recording has to happen here, on the
      // success path, or it happens nowhere. The counters name the boundary and the drop kind; the claim value
      // never leaves the bounder. Best-effort: it never blocks the mint.
      if (Array.isArray(result.principal.claimDrops) && result.principal.claimDrops.length > 0) {
        void this.recordAdminCounters({ bumps: Object.fromEntries(result.principal.claimDrops.map((n) => [n, 1])) });
      }
      const minted = await this.nativeSessionIssue(result.principal, connId, "oidc", nowMs, undefined, body.priorToken, { sourceIp: typeof body.sourceIp === "string" ? body.sourceIp : null, userAgent: typeof body.userAgent === "string" ? body.userAgent : null });
      if (!minted.ok) return minted;
      // The opt-in coarse-context check, after the mint so it can never affect the sign-in.
      // recordSignInContext is a policy-gated no-op by default; the raw IP is used only to derive the
      // coarse prefix and is never stored. The flag rides the response so the router (which holds env)
      // fires the redaction-safe sign-in-new-context notify, the same two-phase shape recovery-code uses.
      const newSignInContext = await this.recordSignInContext(result.principal.subject, sourceIp);
      await this.appendAudit({
        actorSubject: result.principal.subject, actorEmail: result.principal.email, actorMethod: "oidc",
        sourceIp, action: "idp-sign-in", outcome: "success",
        target: { kind: "idpconnection", connId, connKind: conn.kind, op: "signin" },
        // Record the IdP's advisory acr/amr/auth_time on the sign-in event (non-gating; it never
        // influenced the mint above). Omitted when the IdP asserted none.
        ...(result.principal.authContext !== undefined ? { advisory: result.principal.authContext } : {}),
      });
      return { ok: true, token: minted.token, returnTo: result.returnTo, ...(newSignInContext ? { newSignInContext: true } : {}) };
    }

  };
}
