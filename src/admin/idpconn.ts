// The shared IdP-connection config substrate for native external-IdP SSO. ONE discriminated union
// (kind: "oidc" | "oauth2" | "saml") stored as `idpconn:<id>` in the scheduler DO, created/edited ONLY by
// the owner-exclusive keys.ceremony capability (a connection is an authentication trust root, and a group
// can confer access-admin, so access.policy is NOT enough), and redaction-safe for the console + audit.
//
// SECURITY: the stored record NEVER holds a client SECRET VALUE. A confidential client's secret lives
// out-of-band: nowhere for a PKCE-public client; a Cloudflare Secrets Store binding (referenced by NAME)
// for "secrets-store"; a separate DO key (idpsecret:<id>, write-only, never read back to the console) for
// the "do-plaintext" floor; or a private-key reference for private_key_jwt. The record carries only a
// `secretRef` DESCRIPTOR (mode + an optional non-secret reference), so the whole record is safe to return
// to the operator's own console and to record (minus the value) in the audit trail.
//
// This module is PURE (types + a validator that returns a reason, never throws + a redactor), mirroring
// identity.ts's validateCustomRole discipline: the DO maps a non-ok validation result to a 400 and stamps
// createdBy/createdAt on an ok result. Node 25 strip-types + Workers compatible; no enums, explicit fields.

// The discriminated-union TYPES live in idpconn-types.ts (a pure-type sibling) so this file and
// idpconn-validators.ts can both depend on them without a runtime cycle. Re-exported here verbatim so every
// importer of idpconn.ts keeps the same surface. The per-kind validators (validateOidc / validateOauth2 /
// validateSaml), the validateSecretRef helper, the shared string-coercion primitives and the bounds live in
// idpconn-validators.ts. They are all MOVED, not rewritten; this file keeps redactIdpConn and the
// validateIdpConnection dispatcher.
export type {
  IdpConnection,
  IdpConnectionProposal,
  Oauth2Connection,
  OidcClientAuth,
  OidcConnection,
  SamlConnection,
  SecretMode,
  SecretRef,
} from "./idpconn-types.ts";

import type { IdpConnection, IdpConnectionProposal, SecretRef } from "./idpconn-types.ts";
import type { ValidateResult } from "./idpconn-validators.ts";
import { boundedStr, isConnId, LABEL_MAX, PRESET_ID_MAX, str, validateOauth2, validateOidc, validateSaml } from "./idpconn-validators.ts";

// redactIdpConn returns a console/audit-safe view of a stored connection. The record already holds NO
// secret value (only a secretRef descriptor), so this is defence-in-depth: it returns the record verbatim
// except it asserts the secretRef carries only {mode, ref?} and strips anything else that ever crept in.
// It is applied on EVERY read/list/audit path so a future field addition cannot silently leak a value.
export function redactIdpConn(conn: IdpConnection): IdpConnection {
  const safeRef = (r: SecretRef): SecretRef => (r.ref !== undefined ? { mode: r.mode, ref: r.ref } : { mode: r.mode });
  if (conn.kind === "saml") {
    // SAML carries public signing certs (safe) and no client secret; pass through.
    return conn;
  }
  return { ...conn, secretRef: safeRef(conn.secretRef) };
}

// validateIdpConnection is the PURE guardrail shared by the DO create/edit path and any re-check, so the
// two can never compute the rules differently. It returns a fully-formed (minus createdBy/createdAt) record
// or a reason. It NEVER throws. existingIds lets it reject an id collision on create (the caller passes the
// other connections' ids; for an edit it passes the set minus the connection being edited).
export function validateIdpConnection(proposal: IdpConnectionProposal, existingIds: ReadonlySet<string>): ValidateResult {
  // id
  const id = str(proposal.id);
  if (id === null || !isConnId(id)) return { ok: false, reason: "id must be 1 to 64 chars of lowercase letters, digits and hyphen (no leading/trailing hyphen)" };
  if (existingIds.has(id)) return { ok: false, reason: `a connection with id "${id}" already exists` };
  // label
  const label = boundedStr(proposal.label, LABEL_MAX);
  if (label === null) return { ok: false, reason: `label must be 1 to ${LABEL_MAX} characters` };
  // presetId
  const presetId = boundedStr(proposal.presetId, PRESET_ID_MAX);
  if (presetId === null) return { ok: false, reason: "presetId must be a non-empty string" };
  // enabled
  if (typeof proposal.enabled !== "boolean") return { ok: false, reason: "enabled must be a boolean" };
  const enabled = proposal.enabled;
  const base = { id, label, presetId, enabled };

  const kind = proposal.kind;
  if (kind === "oidc") return validateOidc(proposal, base);
  if (kind === "oauth2") return validateOauth2(proposal, base);
  if (kind === "saml") return validateSaml(proposal, base);
  return { ok: false, reason: `unknown connection kind: ${typeof kind === "string" ? kind : "<non-string>"}` };
}

// The remainder of the validation logic (validateSecretRef, validateOidc, validateOauth2, validateSaml and
// their bounds) lives in idpconn-validators.ts; the dispatcher above imports the three per-kind validators.
