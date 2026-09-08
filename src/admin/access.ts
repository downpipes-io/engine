import { b64urlDecode } from "../crypto/bytes.ts";
import { GROUP_NAME_MAX, GROUPS_MAX } from "./groups-bounds.ts";
import { type ClaimDropTally, claimDropCounter } from "./posture-counters.ts";

// Cloudflare Access JWT verification. Access puts a signed assertion in the
// cf-access-jwt-assertion header; trusting its mere presence is an auth bypass, so this
// verifies the RS256 signature against the account's Access public keys and checks the
// issuer (the team domain), the audience (the Access application AUD tag) and the expiry.
// RS256 verification is done with Web Crypto (RSASSA-PKCS1-v1_5 / SHA-256), available in
// the Workers runtime.

interface JWK {
  kid: string;
  kty: string;
  n: string;
  e: string;
  alg?: string;
}
interface JWKS {
  keys: JWK[];
}

export interface AccessResult {
  ok: boolean;
  email?: string;
  // subject is the STABLE, immutable principal the engine authorises on (ASVS V10.3.3 / V10.5.2):
  // iss + "|" + sub, where sub is Cloudflare Access's immutable opaque user id and iss the team
  // issuer (folded in to avoid a cross-tenant sub collision). It is read ONLY from the RS256-verified
  // payload, so it is authentic, and it is OPTIONAL here: a token with no `sub` claim (a service token
  // carries common_name/sub differently, or a misconfigured IdP) yields NO subject key at all, exactly
  // as an emailless token yields no email key. auth.ts then REJECTS a subjectless Access assertion the
  // same way it rejects an emailless one (it is never folded into the bare-token owner break-glass).
  // The email is retained for DISPLAY and AUDIT only; authorisation never keys on it.
  subject?: string;
  // exp is the verified JWT expiry (epoch seconds). It is only meaningful on a successful
  // verification (the verifier has already checked it is in the future), and it is threaded
  // out so GET /admin/whoami can show the honest session expiry without re-parsing the token.
  exp?: number;
  // groups is the OPTIONAL identity-provider group/team list Cloudflare Access emits in the
  // RS256-verified payload when the IdP is configured to send groups. It is read ONLY from the
  // signed payload (so the values are authentic) and is OPTIONAL: a token without a groups claim
  // (Access not configured to send groups, or no IdP) yields no groups key at all, which keeps
  // group-mapping purely additive (the engine falls back to the per-email role table unchanged).
  // It is bounded defensively (see verifyAccessJWT): non-array/non-string entries are dropped,
  // each is trimmed and length-capped, the list is deduped and capped to a sane maximum.
  groups?: string[];
  // identityProvider is an OPTIONAL honest hint of the federated IdP when the token carries one
  // (Access may emit an `idp` field). It is absent (not fabricated) when the token does not carry
  // it; it is surfaced to the customer's own console so the role's BASIS can be shown honestly.
  identityProvider?: string;
  reason?: string;
  // claimDrops (G271) is the bounded set of CLOSED counter names naming which claims this token asserted and
  // the engine DROPPED at the bounding boundary (an over-long or control-char group, a group list past the
  // cap, an unusable idp hint). It is diagnostic only: it never changes the verdict, and it carries no value
  // -- only which KIND of drop happened. auth.ts forwards it to the injected sink; nothing else reads it.
  claimDrops?: string[];
}

// GROUPS_MAX and GROUP_NAME_MAX bound the carried group list. They are shared (the OIDC, OAuth2 and Access
// paths use the identical limits) from groups-bounds.ts so the bounding can never drift between the paths.

// boundGroups defensively normalises a raw groups claim into a trusted string[]: it accepts only an
// array, keeps only string entries, trims each, drops empties and any over GROUP_NAME_MAX, drops any
// name carrying an ASCII control character (0x00-0x1F or 0x7F), dedupes (first occurrence wins, order
// preserved), and caps the result to GROUPS_MAX. Anything that is not a non-empty array of usable
// strings yields undefined (the honest "no groups" signal), so an absent or malformed claim is
// indistinguishable from "Access sent no groups" downstream. The input is already authentic (it comes
// from the RS256-verified payload); this only bounds it. The control-char rejection matches the DO's
// normaliseGroup so the two normalisers agree: a control-char group never survives parsing on either
// side, and a later DO storage key (grouprole:<group>) stays a safe, single-line fragment.
//
// G271: `drops` is the bounded out-parameter that finally makes the drop VISIBLE. Every branch below discards
// a group the customer's IdP DID assert, and a discarded group is byte-identical, downstream, to a group the
// IdP never sent -- which is why "the user is in the right AD group but gets viewer" has been undiagnosable.
// The tally records the closed KIND of the drop (over-length / control-char / past the list cap), never the
// name: the name is customer IdP data and, on this boundary, attacker-influenceable. Drop-not-truncate stands.
function boundGroups(raw: unknown, drops?: ClaimDropTally): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    const g = entry.trim();
    if (g.length === 0) continue;
    if (g.length > GROUP_NAME_MAX) {
      drops?.add(claimDropCounter("access-jwt", "group-overlength"));
      continue;
    }
    let control = false;
    for (let i = 0; i < g.length; i++) {
      const c = g.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) {
        control = true;
        break;
      }
    }
    if (control) {
      drops?.add(claimDropCounter("access-jwt", "group-control-char"));
      continue;
    }
    if (seen.has(g)) continue; // a duplicate is not a drop: the group IS carried, once
    if (out.length >= GROUPS_MAX) {
      // THE CAP. The token asserted more usable groups than the engine will carry, so the groups past the cap
      // were never considered for role mapping at all. On a tenant whose users hold 200+ AD groups this is the
      // whole ticket, and it recorded nothing. Keep scanning so one flag covers the rest of the list.
      drops?.add(claimDropCounter("access-jwt", "groups-list-capped"));
      continue;
    }
    seen.add(g);
    out.push(g);
  }
  return out.length > 0 ? out : undefined;
}

export interface AccessOptions {
  teamDomain: string; // e.g. "maelstrom" for maelstrom.cloudflareaccess.com, or the full host
  aud: string; // the Access application AUD tag
  fetchCerts: (certsUrl: string) => Promise<JWKS>;
  now: number; // epoch seconds
}

// JWKS_REASON (G200) are the FIXED internal literals fetchAndImportKey returns when the Access key path itself
// is unavailable. They are constants, never interpolated: the underlying cause (a fetch TypeError, a status
// code, an importKey DOMException) is read ONLY to SELECT one of these and is then DISCARDED, so no message,
// certs URL, team domain or response body can ride to the recorder. accessDenySignal maps each to its closed
// cf-access-jwks-* auth-signal name.
export const JWKS_REASON = {
  hostRefused: "jwks host refused", // the SSRF pin rejected the resolved certs host (not an https *.cloudflareaccess.com)
  fetchFailed: "jwks fetch failed", // the fetch never completed (network / DNS / egress)
  nonOk: "jwks endpoint returned a non-2xx", // the endpoint answered and refused us
  noKeys: "jwks carried no keys array", // the body parsed but is not a JWKS
  importFailed: "jwks key import failed", // a key was selected but importKey refused its bytes
} as const;

// classifyJwksThrow coarsens a THROW from the JWKS fetch path (opts.fetchCerts, i.e. auth.ts's fetchCertsCached)
// to one of the fixed JWKS_REASON literals. It reads the message ONLY to match the engine's OWN literals (the
// ones fetchCertsCached itself throws) and RETURNS a constant; the text never leaves this function. Anything it
// does not recognise is a transport fault (a fetch TypeError carries a runtime-authored message), which is the
// honest default: the fetch did not complete.
//
// @param e - the thrown value.
// @returns one of the fixed JWKS_REASON literals.
export function classifyJwksThrow(e: unknown): string {
  const m = e instanceof Error ? e.message : "";
  if (m.includes("Access certs endpoint refused")) return JWKS_REASON.hostRefused;
  if (m.includes("Access certs fetch failed")) return JWKS_REASON.nonOk;
  if (m.includes("Access JWKS missing keys array")) return JWKS_REASON.noKeys;
  return JWKS_REASON.fetchFailed;
}

// accessDenySignal maps a verifyAccessJWT failure REASON to a CLOSED support-signal name (P3 + G200 + G231), so
// the support pack can diagnose WHY a Cloudflare Access assertion was refused - the front door most operators
// sign in through - without the reason string (which interpolates an issuer/aud/alg/typ) ever reaching the pack.
//
// ORDERED, FIRST-MATCH-WINS, and the ANCHORED-PREFIX rules come FIRST (the sso-failure-class.ts discipline).
// This is load-bearing, not style: three of the reasons INTERPOLATE ATTACKER-CONTROLLED TEXT from the presented
// JWT - `unexpected alg <header.alg>`, `unexpected token type <header.typ>` and `issuer <payload.iss> != ...`.
// The previous rule order led with a whole-string `includes("aud mismatch")`, so a token whose header carried
// `alg: "aud mismatch"` classified its OWN refusal as cf-access-aud-mismatch and would have sent support to
// re-check CF_ACCESS_AUD on a healthy application. Matching each interpolating reason on its FIXED PREFIX means
// the attacker-chosen tail can no longer steer the diagnosis.
//
// G231 splits the old catch-all cf-access-verify-failed into its actionable sub-causes (skew / alg / typ /
// signature / malformed), which are different tickets with different fixes; cf-access-verify-failed remains as
// the residual bucket. G200 adds the cf-access-jwks-* family, the Access KEY PATH being unavailable at all.
// Every branch returns a member of the closed AUTH_SIGNAL_NAMES vocabulary. The caller emits it best-effort; it
// never gates auth, and the caller's 401 stays generic (no class is ever oracled back).
//
// @param reason - the internal reason literal from verifyAccessJWT (never surfaced to a caller).
// @returns the closed auth-signal name.
export function accessDenySignal(reason: string): string {
  // --- anchored-prefix rules for the reasons that interpolate UNTRUSTED token fields ---
  if (reason.startsWith("unexpected alg")) return "cf-access-verify-failed-alg";
  if (reason.startsWith("unexpected token type")) return "cf-access-verify-failed-typ";
  if (reason.startsWith("issuer ")) return "cf-access-issuer-mismatch";
  if (reason.startsWith("signing key")) return "cf-access-key-unknown"; // "signing key not found" / "... unexpected kty"
  // --- the JWKS availability family (G200): fixed literals, no interpolation ---
  if (reason.startsWith("jwks ")) {
    if (reason === JWKS_REASON.hostRefused) return "cf-access-jwks-host-refused";
    if (reason === JWKS_REASON.nonOk) return "cf-access-jwks-non-2xx";
    if (reason === JWKS_REASON.noKeys) return "cf-access-jwks-no-keys";
    if (reason === JWKS_REASON.importFailed) return "cf-access-jwks-import-failed";
    return "cf-access-jwks-fetch-failed";
  }
  // --- whole-string rules: these reasons carry NO interpolation ---
  if (reason === "aud mismatch") return "cf-access-aud-mismatch";
  if (reason === "expired") return "cf-access-verify-failed-expired";
  if (reason === "not yet valid") return "cf-access-verify-failed-nbf";
  if (reason === "bad signature") return "cf-access-verify-failed-signature";
  if (reason === "malformed JWT" || reason === "undecodable JWT" || reason === "no kid") return "cf-access-verify-failed-malformed-jwt";
  // The team-host SSRF guard's reason is an assertCloudflareAccessHost message (operator-config text, not
  // attacker text), matched last so no anchored rule above can be shadowed by it.
  if (reason.includes("team domain")) return "cf-access-issuer-mismatch";
  return "cf-access-verify-failed"; // the residual bucket (unchanged)
}

function decodeJSON(part: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
}

export function teamHost(teamDomain: string): string {
  return teamDomain.includes(".") ? teamDomain : `${teamDomain}.cloudflareaccess.com`;
}

// assertCloudflareAccessHost rejects a resolved team host that is not a *.cloudflareaccess.com
// subdomain. CF_ACCESS_TEAM_DOMAIN is an operator-supplied environment variable; a misconfigured
// or hostile value could redirect the JWKS fetch to an attacker-controlled host, letting the
// attacker supply their own public keys and forge tokens (SSRF / V1.3.6). The check is a strict
// suffix match on ".cloudflareaccess.com" and a label-count guard: the resolved host must be of
// the form "<label>.cloudflareaccess.com" (no scheme, no path, no port, no bare "cloudflareaccess.com").
export function assertCloudflareAccessHost(host: string): void {
  const suffix = ".cloudflareaccess.com";
  if (!host.endsWith(suffix)) {
    throw new Error(`team domain resolves to "${host}", which is not a *.cloudflareaccess.com host`);
  }
  // The label before the suffix must be non-empty (guards against the bare "cloudflareaccess.com"
  // edge case where endsWith would pass but there is no subdomain label).
  const label = host.slice(0, host.length - suffix.length);
  if (label.length === 0 || label.includes(".")) {
    // A label containing "." would indicate a deeper subdomain (e.g. "evil.sub.cloudflareaccess.com")
    // which is not a valid Access team domain. Cloudflare Access team domains are exactly one label.
    throw new Error(`team domain resolves to "${host}", which is not a single-label *.cloudflareaccess.com host`);
  }
}

// AccessHeader / AccessPayload are the decoded (still UNTRUSTED until the signature verifies) JWT
// header and payload shapes the verifier reads.
interface AccessHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}
// The payload may carry an OPTIONAL `groups` array (Cloudflare Access emits it when the IdP is
// configured to send groups) and an OPTIONAL `idp` hint. Both are bounded AFTER the signature
// verifies, so only signed claims are ever trusted. `sub` is the immutable Access user id (an
// opaque UUID); it is read from the SIGNED payload and folded with iss into the stable subject,
// never trusted from anywhere unsigned.
interface AccessPayload {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  email?: string;
  sub?: unknown;
  groups?: unknown;
  idp?: unknown;
}

// verifyStructureAndClaims runs every PRE-CRYPTO check: the three-part split, the header/payload
// decode, the alg/kid/typ header guards, the iss/aud/exp/nbf claim checks, and the team-host SSRF
// guard (V1.3.6). It returns the decoded header+payload+issuer on success, or a {reason} on the
// first failure, so verifyAccessJWT never reaches the crypto path with an unverified claim wrong.
function verifyStructureAndClaims(
  token: string,
  opts: AccessOptions,
): { header: AccessHeader; payload: AccessPayload; issuer: string; headerB64: string; payloadB64: string; sigB64: string } | { reason: string } {
  const parts = token.split(".");
  if (parts.length !== 3) return { reason: "malformed JWT" };
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: AccessHeader;
  let payload: AccessPayload;
  try {
    header = decodeJSON(headerB64) as AccessHeader;
    payload = decodeJSON(payloadB64) as AccessPayload;
  } catch {
    return { reason: "undecodable JWT" };
  }
  if (header.alg !== "RS256") return { reason: `unexpected alg ${header.alg}` };
  if (!header.kid) return { reason: "no kid" };
  // V9.2.2: reject a present-and-wrong typ header. Cloudflare Access tokens carry typ:"JWT"; a
  // token whose typ is present but is not "JWT" (e.g. typ:"JWE") signals a different token
  // structure or a type-confusion attempt. Tokens with NO typ header are still accepted: some IdPs
  // omit the field and there is no ambiguity when the alg, iss, aud and signature all check out.
  if (header.typ !== undefined && header.typ !== "JWT") return { reason: `unexpected token type ${header.typ}` };

  const issuer = `https://${teamHost(opts.teamDomain)}`;
  if (payload.iss !== issuer) return { reason: `issuer ${payload.iss} != ${issuer}` };
  const auds = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
  if (!auds.includes(opts.aud)) return { reason: "aud mismatch" };
  if (typeof payload.exp !== "number" || payload.exp <= opts.now) return { reason: "expired" };
  if (typeof payload.nbf === "number" && payload.nbf > opts.now) return { reason: "not yet valid" };

  // V1.3.6: assert the resolved team host is a *.cloudflareaccess.com subdomain before fetching
  // certs. A misconfigured CF_ACCESS_TEAM_DOMAIN could otherwise redirect the JWKS fetch to an
  // attacker-controlled host, letting the attacker supply their own public keys and forge tokens.
  try {
    assertCloudflareAccessHost(teamHost(opts.teamDomain));
  } catch (e) {
    return { reason: e instanceof Error ? e.message : "invalid team domain" };
  }
  return { header, payload, issuer, headerB64, payloadB64, sigB64 };
}

// fetchAndImportKey fetches the JWKS, selects the entry matching the token's kid, rejects any
// non-RSA key (XC-L4) BEFORE importKey, and imports the RSA verify key. It returns the imported
// CryptoKey or a {reason} on the first failure.
async function fetchAndImportKey(opts: AccessOptions, issuer: string, kid: string): Promise<CryptoKey | { reason: string }> {
  // G200: the JWKS fetch used to THROW straight out of verifyAccessJWT (a cloudflareaccess.com blip, a DNS/egress
  // fault, a non-2xx, a JWKS whose shape changed, or an SSRF-pin refusal on a bad CF_ACCESS_TEAM_DOMAIN), so
  // authorise() unwound into a 500 and NOTHING reached accessDenySignal: an Access outage was indistinguishable
  // from no traffic in the pack. Catch it here and coarsen it to a FIXED literal, so it becomes an ordinary
  // {reason} refusal that the deny sink records as a closed cf-access-jwks-* signal. The caller still fails
  // CLOSED (an unverifiable token is never admitted); it now fails closed with EVIDENCE instead of a 500.
  let jwks: JWKS;
  try {
    jwks = await opts.fetchCerts(`${issuer}/cdn-cgi/access/certs`);
  } catch (e) {
    return { reason: classifyJwksThrow(e) };
  }
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (!jwk) return { reason: "signing key not found" };
  // XC-L4: reject any JWKS entry whose kty is not "RSA" BEFORE passing it to importKey.
  // importKey is asked to produce an RSASSA-PKCS1-v1_5 key; feeding it a non-RSA JWK (e.g.
  // kty:"EC" or kty:"oct") may throw a runtime error or, on some runtimes, coerce the key
  // material into an unexpected shape. Failing early with a clean rejection is safer than
  // relying on the runtime to reject the coercion at importKey time, and it makes the
  // control flow explicit: only RSA keys may ever verify an RS256 token here.
  if (jwk.kty !== "RSA") return { reason: `signing key has unexpected kty "${jwk.kty}"; expected RSA` };
  // G200: importKey REJECTS (a DOMException) on a malformed / non-RSA-shaped JWK entry -- a JWKS the shape guard
  // admitted (it is an object with a keys array) but whose selected key is unusable. That rejection also used to
  // escape as a 500. Coarsen it to the fixed import-failed literal: every token signed under that kid is
  // unverifiable, which is a DIFFERENT ticket from "the endpoint is unreachable".
  try {
    return await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  } catch {
    return { reason: JWKS_REASON.importFailed };
  }
}

// boundSubject folds iss + "|" + sub into the STABLE principal (ASVS V10.3.3 / V10.5.2), or returns
// undefined when there is no usable sub. sub is the immutable Access user id; iss (already checked to
// equal the team issuer) is folded in so two tenants' subs can never collide. A token with no usable
// `sub` yields NO subject (honestly absent, like an absent email), and auth.ts rejects it; it is
// NEVER fabricated from email. The value becomes a DO storage-key fragment (role:sub:<subject>) so it
// is bounded to GROUP_NAME_MAX and rejected if it carries an ASCII control character (single-line).
function boundSubject(issuer: string, sub: unknown): string | undefined {
  const subTrimmed = typeof sub === "string" ? sub.trim() : "";
  if (subTrimmed.length === 0 || subTrimmed.length > GROUP_NAME_MAX) return undefined;
  for (let i = 0; i < subTrimmed.length; i++) {
    const c = subTrimmed.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return undefined;
  }
  return `${issuer}|${subTrimmed}`;
}

// extractSignedClaims builds the success AccessResult from the now-AUTHENTIC payload: the email (for
// display/audit), the bounded stable subject, the verified exp, and the bounded OPTIONAL groups/idp
// claims. exactOptionalPropertyTypes: each optional key is included only when it carries a value, so
// a token without groups/idp yields a result with those keys ABSENT (the honest "no groups" signal
// that keeps group-mapping additive and Access purely optional).
function extractSignedClaims(payload: AccessPayload, issuer: string): AccessResult {
  const drops: ClaimDropTally = new Set<string>();
  const groups = boundGroups(payload.groups, drops);
  // The idp hint is surfaced verbatim to the customer's own console, so bound its length for symmetry
  // with the group bound (a signed-but-pathological token must not carry an unbounded string onward):
  // a non-empty trimmed string up to GROUP_NAME_MAX, else undefined (honestly absent, never fabricated).
  const idpTrimmed = typeof payload.idp === "string" ? payload.idp.trim() : "";
  const idp = idpTrimmed.length > 0 && idpTrimmed.length <= GROUP_NAME_MAX ? idpTrimmed : undefined;
  // G271: a PRESENT but unusable idp hint is a drop, not an absence. An absent claim is not recorded (that is
  // the ordinary state of an Access app with no IdP hint configured, and recording it would be pure noise).
  if (idp === undefined && idpTrimmed.length > 0) drops.add(claimDropCounter("access-jwt", "idp-hint"));
  const subject = boundSubject(issuer, payload.sub);
  return {
    ok: true,
    ...(payload.email ? { email: payload.email } : {}),
    ...(subject !== undefined ? { subject } : {}),
    ...(typeof payload.exp === "number" ? { exp: payload.exp } : {}),
    ...(groups !== undefined ? { groups } : {}),
    ...(idp !== undefined ? { identityProvider: idp } : {}),
    ...(drops.size > 0 ? { claimDrops: [...drops] } : {}),
  };
}

// verifyAccessJWT returns ok only for a token whose signature verifies under a current Access key and
// whose iss/aud/exp/nbf all check out. It is a thin orchestrator over verifyStructureAndClaims (the
// pre-crypto checks), fetchAndImportKey (JWKS fetch + key selection + import), the RS256 verify, and
// extractSignedClaims (the post-verify claim parsing).
export async function verifyAccessJWT(token: string, opts: AccessOptions): Promise<AccessResult> {
  const pre = verifyStructureAndClaims(token, opts);
  if ("reason" in pre) return { ok: false, reason: pre.reason };

  const key = await fetchAndImportKey(opts, pre.issuer, pre.header.kid!);
  if ("reason" in key) return { ok: false, reason: key.reason };

  const signed = new TextEncoder().encode(`${pre.headerB64}.${pre.payloadB64}`);
  // A malformed signature segment must fail CLOSED as a clean rejection, never an unhandled 500:
  // b64urlDecode throws on non-base64url chars, and crypto.subtle.verify THROWS (rather than
  // returning false) on a signature whose byte length is wrong for the RSA key. Live-caught: a
  // non-base64 signature 500'd instead of 401'ing. Any throw here means "not a valid signature".
  let verified: boolean;
  try {
    verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlDecode(pre.sigB64), signed);
  } catch {
    return { ok: false, reason: "bad signature" };
  }
  if (!verified) return { ok: false, reason: "bad signature" };

  // The signature has verified, so the payload's claims are AUTHENTIC and may now be trusted.
  return extractSignedClaims(pre.payload, pre.issuer);
}
