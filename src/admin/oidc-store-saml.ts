// The SAML SP-initiated single-use request record, factored out of the DO-side OIDC store (oidc-store.ts). The
// ACS is a CROSS-ORIGIN IdP POST that carries NO SameSite cookie, so the anti-CSRF/replay defence here is an
// OPAQUE RelayState plus a browser-bind cookie, mirroring the OIDC state discipline. The symbols are
// re-exported from oidc-store.ts so importers are unchanged.
//
// Node 25 strip-types + Workers compatible: no Node builtins, no enums, explicit fields, error-as-value.

import type { KvStorage } from "./oidc-store-kv.ts";
import { DEFAULT_STATE_TTL_MS } from "./oidc-store-kv.ts";

// SamlRequestRecord is the single-use SP-initiated state for one SAML AuthnRequest. The ACS is a CROSS-ORIGIN
// IdP POST that carries NO SameSite cookie, so the anti-CSRF/replay defence is: an OPAQUE RelayState the SP
// mints + the IdP echoes back, looked up here to recover the connId + the post-login returnTo, AND the
// AuthnRequest ID the assertion's InResponseTo MUST equal (single-use binds the response to a request THIS SP
// actually made). createdAt is the mint time in epoch millis for the TTL.
export interface SamlRequestRecord {
  connId: string;
  requestId: string; // the AuthnRequest ID; the assertion InResponseTo must echo it (SP-initiated binding)
  returnTo: string;
  createdAt: number;
  // browserBind is the high-entropy value ALSO dropped in the __Host- saml-txn cookie at /start; the ACS
  // requires the cookie to equal this before minting a session. It binds the assertion to the browser that
  // STARTED the login, closing forced-login / session-fixation (an attacker-captured assertion replayed into a
  // victim's browser carries no matching cookie) - the SAML analogue of the OIDC txn-cookie/txnId cross-check.
  browserBind: string;
}

const SAML_REQ_PREFIX = "samlreq:";
function samlReqKey(relayState: string): string {
  return SAML_REQ_PREFIX + relayState;
}

// putSamlRequest persists the request record under samlreq:<relayState>. relayState is the high-entropy opaque
// token the SP puts in the redirect and the IdP echoes back verbatim in the ACS POST.
export async function putSamlRequest(storage: KvStorage, relayState: string, record: SamlRequestRecord): Promise<void> {
  await storage.put(samlReqKey(relayState), record);
}

// consumeSamlRequest is the SINGLE-USE primitive for the ACS, identical in discipline to consumeOidcState: it
// reads the record, DELETES it BEFORE returning (so a replayed ACS POST finds nothing on the second call - the
// DO is single-threaded, so get-then-delete is atomic), and returns the record only when it existed AND is
// within createdAt + ttl. An IdP-initiated assertion (no RelayState, or one the SP never minted) finds nothing.
export async function consumeSamlRequest(
  storage: KvStorage,
  relayState: string,
  nowMs: number,
  ttlMs: number = DEFAULT_STATE_TTL_MS,
): Promise<SamlRequestRecord | null> {
  const key = samlReqKey(relayState);
  const record = await storage.get<SamlRequestRecord>(key);
  await storage.delete(key);
  if (record === undefined) return null;
  if (record.createdAt + ttlMs <= nowMs) return null;
  return record;
}

// sweepSamlRequests prunes abandoned SP-initiated request records (a user who started a SAML login and never
// completed the ACS POST leaves one behind), exactly like sweepOidcStates. The single-use + TTL check in
// consumeSamlRequest is the security guarantee; this is opportunistic cleanup so storage cannot grow unbounded.
export async function sweepSamlRequests(
  storage: KvStorage,
  nowMs: number,
  ttlMs: number = DEFAULT_STATE_TTL_MS,
): Promise<number> {
  const map = await storage.list<SamlRequestRecord>({ prefix: SAML_REQ_PREFIX });
  const expired: string[] = [];
  for (const [key, record] of map) {
    if (record.createdAt + ttlMs <= nowMs) expired.push(key);
  }
  // Each delete is independent, so run them in parallel rather than serialising one round-trip per
  // key, which would inflate the alarm-handler wall-clock time linearly with the abandoned-request count.
  await Promise.all(expired.map((key) => storage.delete(key)));
  return expired.length;
}
