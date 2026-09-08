// engine-sys-struct: the native SAML SP mixin, MOVED VERBATIM out of scheduler-do-idp.ts so neither
// file exceeds the module-size guardrail (the R6 sign-in-context wiring tipped the combined module
// over 800). Same mixin discipline as every sibling: `this` is SchedulerDOSurface, so the methods
// reach nativeSessionIssue / recordSignInContext / appendAudit / recordSsoFail exactly as the single
// class did; the assembly chains IdpSamlMixin right after IdpMixin in scheduler-do.ts. A leaf the
// assembly depends on, never the reverse (madge 0 cycles). No behaviour, route, storage key, status
// code or response change: the method bodies are byte-identical moves.

import { isConnId } from "../admin/identity.ts";
import { drainIdpCertObservation } from "../admin/idp-cert-health.ts";
import type { SamlConnection } from "../admin/idpconn.ts";
import { consumeSamlRequest, getIdpConnectionRaw, putSamlRequest } from "../admin/oidc-store.ts";
import { buildRedirectUrl } from "../admin/saml/authn-request.ts";
import { buildSpMetadata } from "../admin/saml/metadata.ts";
import { verifySamlResponse } from "../admin/saml/response.ts";
import { drainSamlSignals } from "../admin/saml-signals.ts";
import { b64urlEncode } from "../crypto/bytes.ts";
import { type SchedulerDOCtor, SEEN_ASSERTION_PREFIX } from "./scheduler-do-base.ts";

export function IdpSamlMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Native external-IdP (SAML SP): metadata + SP-initiated start + the ACS ===========================
    // SP-initiated only in v1 (allowIdpInitiated is stored in the connection and respected by the assertion
    // verifier; the ACS enforces SP-initiated by requiring a server-minted RelayState record, so IdP-initiated
    // assertions are rejected at the record.requestId binding before the verifier runs). The ACS is a
    // CROSS-ORIGIN IdP POST carrying NO SameSite cookie, so the anti-CSRF/replay defence is the opaque single-use
    // RelayState (recovered from the request store) + the assertion InResponseTo bound to the AuthnRequest ID this
    // SP actually minted. The XML pipeline runs in saml/* (no env, no network: Web Crypto + the POSTed bytes); the
    // DO does state custody + the SAME nativeSessionIssue the OIDC path uses (method "saml", subject saml:<...>).

    // drainSamlSignalsToAggregate folds the pure SAML pipeline's isolate-local signal ledger into the bounded
    // auth-signal aggregate the pack already carries (G316 / G276 / G203). The ledger is a SET, so one hostile
    // document that trips the same gate a thousand times yields ONE write per sign-in attempt, not a thousand.
    // Best-effort and never throwing: recordAuthSignal already swallows its own faults and DROPS any name outside
    // AUTH_SIGNAL_NAMES, which is the redaction boundary.
    async drainSamlSignalsToAggregate(): Promise<void> {
      for (const name of drainSamlSignals()) await this.recordAuthSignal(name);
    }

    // samlConnFor loads a connection and narrows it to SAML, else undefined.
    async samlConnFor(connId: string): Promise<SamlConnection | undefined> {
      const c = await getIdpConnectionRaw(this.idpKv, connId);
      return c !== undefined && c.kind === "saml" ? c : undefined;
    }

    // samlRequestId mints an XML-ID-safe AuthnRequest ID: an XML Name must NOT start with a digit, so it is
    // "_" + 32 hex chars (high-entropy, fixed length). It is the InResponseTo the SP binds the response to.
    samlRequestId(): string {
      const b = crypto.getRandomValues(new Uint8Array(16));
      let hex = "";
      for (const x of b) hex += x.toString(16).padStart(2, "0");
      return `_${hex}`;
    }

    // idpSamlMetadata returns the SP EntityDescriptor (the public document the customer uploads to their IdP - no
    // secret). acsUrl is the canonical ACS the router serves, passed in (the DO has no public origin).
    async idpSamlMetadata(body: { connId?: unknown; acsUrl?: unknown }): Promise<{ ok: true; metadata: string } | { ok: false; reason: string }> {
      const connId = typeof body.connId === "string" ? body.connId : "";
      // G140: the metadata path was entirely UNCOUNTED. The SP EntityDescriptor is what the customer uploads
      // INTO their IdP, so a refusal here is where a SAML rollout silently stalls -- and the SSO aggregate is
      // written only by the ACS, so the pack showed nothing at all. Record the closed metadata-failure code
      // (best-effort; the returned refusal is unchanged) with the connection's OPAQUE ORDINAL where one is
      // resolvable, never the connId.
      if (!isConnId(connId)) {
        await this.recordSsoFailCode("metadata-failure", "saml");
        return { ok: false, reason: "invalid connId" };
      }
      const acsUrl = typeof body.acsUrl === "string" ? body.acsUrl : "";
      const conn = await this.samlConnFor(connId);
      if (conn === undefined) {
        await this.recordSsoFailCode("metadata-failure", "saml", connId);
        return { ok: false, reason: "SAML connection not found" };
      }
      return { ok: true, metadata: buildSpMetadata(conn, acsUrl) };
    }

    // idpSamlStart mints the AuthnRequest (single-use request id + opaque RelayState + issueInstant), builds the
    // HTTP-Redirect URL, and PERSISTS the SP-initiated request record keyed by the RelayState. The router 302s to
    // the returned URL. RelayState is b64url(16 CSPRNG octets) = 22 chars, well under the binding's 80-byte cap.
    async idpSamlStart(body: { connId?: unknown; returnTo?: unknown; acsUrl?: unknown }): Promise<{ ok: true; redirectUrl: string; browserBind: string } | { ok: false; reason: string }> {
      const connId = typeof body.connId === "string" ? body.connId : "";
      // G140: THE START PATH WAS ENTIRELY UNCOUNTED. "Users clicking our old SSO link get an error page" is a
      // deleted or disabled connection refusing at /start -- and because the SSO aggregate is written only by
      // the ACS wrapper, the pack showed ZERO SSO failures while every sign-in attempt died. Record the closed
      // start-failure code on each refusal (best-effort; the returned refusal is byte-identical), attributed to
      // the connection's OPAQUE ORDINAL where one is resolvable, never the connId.
      if (!isConnId(connId)) {
        await this.recordSsoFailCode("start-failure", "saml");
        return { ok: false, reason: "invalid connId" };
      }
      const returnTo = typeof body.returnTo === "string" ? body.returnTo : "/";
      const acsUrl = typeof body.acsUrl === "string" ? body.acsUrl : "";
      const conn = await this.samlConnFor(connId);
      if (conn === undefined) {
        await this.recordSsoFailCode("start-failure", "saml", connId);
        return { ok: false, reason: "SAML connection not found" };
      }
      if (!conn.enabled) {
        await this.recordSsoFailCode("start-failure", "saml", connId);
        return { ok: false, reason: "connection is disabled" };
      }
      const nowMs = Date.now();
      const requestId = this.samlRequestId();
      const relayState = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
      // browserBind: the forced-login / session-fixation defence. It is stored in the record AND returned so the
      // router drops it in the __Host- saml-txn cookie; the ACS requires the cookie to match before minting.
      const browserBind = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const issueInstant = new Date(nowMs).toISOString();
      // G203: buildRedirectUrl THROWS when the stored SSO URL is unusable or the DEFLATE leg faults, and the
      // throw propagates out of the start route as a bare 500 -- the "SAML sign-in button dead-ends" ticket, with
      // ZERO SSO failures in the pack because recordSsoFail is only ever written by the ACS. The pure builder has
      // noted the closed class; drain it here on BOTH paths, then re-throw so the caller's behaviour is unchanged.
      let redirectUrl: string;
      try {
        redirectUrl = await buildRedirectUrl(conn, { id: requestId, issueInstant, acsUrl, relayState });
      } catch (e) {
        await this.drainSamlSignalsToAggregate();
        // G140: the SAME start-path blindness on the THROW leg (an unusable stored SSO URL, a DEFLATE fault):
        // the bare 500 propagates and nothing entered the SSO aggregate. Counted with the closed code + ordinal
        // before the re-throw, so the caller's behaviour is unchanged.
        await this.recordSsoFailCode("start-failure", "saml", connId);
        throw e;
      }
      await this.drainSamlSignalsToAggregate();
      await putSamlRequest(this.idpKv, relayState, { connId, requestId, returnTo, createdAt: nowMs, browserBind });
      return { ok: true, redirectUrl, browserBind };
    }

    // idpSamlAcs is the ACS handler. It CONSUMES the single-use RelayState record (delete-before-return); a
    // missing record (replay / IdP-initiated / a RelayState this SP never minted) rejects, which ENFORCES
    // SP-initiated-only in v1. Then it verifies the SAMLResponse via the module pipeline (parser -> pinned-cert
    // signature -> consume, with InResponseTo bound to the minted request id and Recipient/Destination bound to
    // acsUrl), mints the v3 saml session (the shared hardened mint, flow-start nowMs), audits, and returns the
    // token + returnTo. No caller (pre-auth). connId is re-checked against the record (no cross-connection ACS).
    // idpSamlAcs wraps the ACS so EVERY failure path records a bounded, classified SSO-failure for the support
    // pack. The impl keeps its side effects (single-use RelayState consume, seen-assertion put, session mint) and
    // its externally-visible behaviour unchanged; recordSsoFail is best-effort and never throws.
    async idpSamlAcs(body: { connId?: unknown; samlResponse?: unknown; relayState?: unknown; acsUrl?: unknown; browserBind?: unknown; sourceIp?: unknown }): Promise<{ ok: true; token: string; returnTo: string } | { ok: false; reason: string }> {
      const r = await this.idpSamlAcsImpl(body);
      // The ACS is the SAML sign-in endpoint, so EVERY failure here is a SAML failure regardless of whether the
      // specific connection resolved (P1): attribute it to the saml kind (a closed enum, never the connId).
      // G140: the ACS failure now also carries the connection's OPAQUE ORDINAL, so "SAML sign-ins failing
      // intermittently" on a two-SAML-connection tenant finally says WHICH one. The connId is passed only into
      // ssoConnOrdinal (the redaction chokepoint) and never becomes a counter key or a pack field.
      if (!r.ok) await this.recordSsoFail(r.reason, "saml", typeof body.connId === "string" ? body.connId : undefined);
      // G316 / G276: DRAIN the pure pipeline's signal ledger on EVERY outcome, not just the failing one. That is
      // load-bearing in both directions: an ATTACK shape (a duplicate ID, a DTD probe) fires on a response that
      // then fails, and a SILENT DEGRADATION (a dropped email, an uncapped session) fires on one that SUCCEEDS --
      // and the degradation being invisible precisely BECAUSE the sign-in worked is the whole gap. Best-effort:
      // recordAuthSignal never throws and drops any name outside the closed vocabulary.
      await this.drainSamlSignalsToAggregate();
      return r;
    }
    async idpSamlAcsImpl(body: { connId?: unknown; samlResponse?: unknown; relayState?: unknown; acsUrl?: unknown; browserBind?: unknown; sourceIp?: unknown }): Promise<{ ok: true; token: string; returnTo: string } | { ok: false; reason: string }> {
      const connId = typeof body.connId === "string" ? body.connId : "";
      if (!isConnId(connId)) return { ok: false, reason: "invalid connId" };
      // The coarse source IP, forwarded by the router from the edge CF-Connecting-IP (the body-forward
      // pattern; an SP-POST ACS carries no normal caller header). "Where someone signed in from" is the
      // most valuable IP to record; null when absent.
      const sourceIp = typeof body.sourceIp === "string" && body.sourceIp.length > 0 ? body.sourceIp : null;
      const samlResponse = typeof body.samlResponse === "string" ? body.samlResponse : "";
      const relayState = typeof body.relayState === "string" ? body.relayState : "";
      const acsUrl = typeof body.acsUrl === "string" ? body.acsUrl : "";
      const browserBind = typeof body.browserBind === "string" ? body.browserBind : "";
      const nowMs = Date.now();
      const record = await consumeSamlRequest(this.idpKv, relayState, nowMs);
      if (record === null) {
        // P3 (saml-idp-initiated-blocked): the ACS assertion carried no server-minted RelayState record. This is
        // the SP-initiated-only enforcement point - an IdP-initiated assertion, a replayed RelayState, or an
        // expired one all funnel here. Record the bounded signal so a "our IdP-initiated SSO tile does nothing"
        // ticket is diagnosable APART from the seen-assertion replay bucket below (the two shared saml/replay
        // before this finer code existed). Only the closed event name is stored, never the RelayState value.
        await this.recordAuthSignal("saml-relaystate-missing");
        return { ok: false, reason: "unknown, expired or already-used SAML request (this SP is SP-initiated only)" };
      }
      if (record.connId !== connId) return { ok: false, reason: "RelayState connId does not match the ACS connId" };
      // Browser binding (forced-login / session-fixation, CWE-384): the ACS browser MUST carry the __Host- saml-txn
      // cookie set at /start, matching the value stored in this SP-initiated record. An attacker-captured assertion
      // replayed into a victim's browser carries no matching cookie, so it cannot mint a session in that browser.
      // The record was already consumed (single-use) above, so even a mismatch cannot be retried.
      if (record.browserBind.length === 0 || record.browserBind !== browserBind) return { ok: false, reason: "SAML browser binding mismatch (possible forced-login)" };
      const conn = await this.samlConnFor(connId);
      if (conn === undefined) return { ok: false, reason: "SAML connection not found" };
      if (!conn.enabled) return { ok: false, reason: "connection is disabled" };
      const result = await verifySamlResponse(samlResponse, conn, { acsUrl, expectedInResponseTo: record.requestId, nowMs });
      // G053: DRAIN the pinned-cert health observation the (pure) verifier just computed, BEFORE the failure
      // return -- because the failure IS the evidence: a connection whose every pinned cert is unparseable
      // fails here, and that is precisely the record support needs. Best-effort and never throwing.
      await this.recordIdpCertHealth(drainIdpCertObservation());
      if (!result.ok) return { ok: false, reason: result.reason };
      // SAML assertion ONE-TIME-USE cache (defence in depth on top of the single-use RelayState + the InResponseTo
      // bind + the browser-binding cookie, which are the PRIMARY replay defences): refuse a previously-seen
      // assertion id within its validity window. Keyed by connId + the assertion id; the value is notOnOrAfter so
      // the alarm sweep can prune it (and a replay past the window already fails consumeAssertion's Conditions).
      const seenKey = `${SEEN_ASSERTION_PREFIX}${connId}:${result.assertionId}`;
      const seenExp = await this.state.storage.get<number>(seenKey);
      if (typeof seenExp === "number" && nowMs < seenExp) return { ok: false, reason: "SAML assertion already consumed (replay)" };
      await this.state.storage.put(seenKey, result.notOnOrAfter);
      // G271: the assertion VERIFIED and an advisory claim was BOUNDED AWAY (an over-length AuthnContextClassRef,
      // an unparseable AuthnInstant). The sign-in SUCCEEDS, so the recording has to happen here, on the success
      // path, or it happens nowhere -- which is exactly why the SAML front door recorded nothing. Mirrors the
      // OIDC/OAuth2 callback's recorder. The counters name the boundary and the drop KIND; the claim value never
      // leaves the bounder. Best-effort: it never blocks the mint.
      if (Array.isArray(result.principal.claimDrops) && result.principal.claimDrops.length > 0) {
        void this.recordAdminCounters({ bumps: Object.fromEntries(result.principal.claimDrops.map((n) => [n, 1])) });
      }
      const minted = await this.nativeSessionIssue(result.principal, connId, "saml", nowMs, result.sessionNotOnOrAfter);
      if (!minted.ok) return minted;
      // R6 (V6.3.5): same opt-in coarse-context check as the OIDC success block; see the note there.
      const newSignInContext = await this.recordSignInContext(result.principal.subject, sourceIp);
      await this.appendAudit({
        actorSubject: result.principal.subject, actorEmail: result.principal.email, actorMethod: "saml",
        sourceIp, action: "idp-sign-in", outcome: "success",
        target: { kind: "idpconnection", connId, connKind: "saml", op: "signin" },
        // V6.8.4: record the IdP's advisory AuthnContextClassRef/AuthnInstant on the sign-in event (non-gating;
        // it never influenced the mint above). Omitted when the assertion carried no AuthnContext.
        ...(result.principal.authContext !== undefined ? { advisory: result.principal.authContext } : {}),
      });
      return { ok: true, token: minted.token, returnTo: record.returnTo, ...(newSignInContext ? { newSignInContext: true } : {}) };
    }
  };
}
