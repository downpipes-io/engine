// Issuer and fetch-endpoint safety screens for the native OIDC Relying Party. Split out of oidc-verify.ts
// (it grew past the module-size budget) but unchanged in behaviour: these are the SSRF and
// cross-method-collision guards the verifier and the connection-config validators share. The functions are
// re-exported from oidc-verify.ts so existing importers are unaffected.
//
// SECURITY DISCIPLINE (mirrors oidc-verify.ts; the validator encodes the attacks):
//  - iss is rejected at BOTH config and verify time if it names a cloudflareaccess.com / IP-literal /
//    localhost / non-https host, so a native subject can never collide with the bare issuer|sub of a
//    Cloudflare Access subject.
//  - assertSafeIssuer is the config-time gate (the operator-supplied issuer must be a canonical https URL).
//  - issuerLooksUnsafe is the spelling-agnostic verify-time screen (it also handles a bare-host issuer).
//  - assertSafeFetchEndpoint is the host-CATEGORY SSRF guard for the jwks_uri / token / userinfo URLs.
//
// Node 25 strip-types + Workers-runtime compatible: Web Crypto only, no Node builtins, no enums.

// isIpLiteral rejects an IPv4 dotted-quad or an IPv6 literal (bracketed or not), tolerating a trailing dot.
// Real IdP hosts are domain names; an IP-literal issuer/endpoint is a classic SSRF-to-internal target, so
// we refuse all of them rather than try to enumerate private ranges. Callers normalise obfuscated IPv4
// spellings (decimal/hex/octal) through the URL parser BEFORE calling this, so only the canonical
// dotted-quad reaches here.
export function isIpLiteral(host: string): boolean {
  let h = host;
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  if (h.includes(":")) return true; // IPv6 literal
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h);
}

// canonicalHost normalises a URL hostname for the NAME-based screens (localhost / cloudflareaccess): it
// lowercases and strips a single trailing dot, so a fully-qualified "localhost." (which resolves to
// 127.0.0.1) is screened the same as "localhost". The IP-literal screen handles brackets + the trailing dot
// itself; this keeps the string comparisons honest against the trailing-dot bypass.
export function canonicalHost(hostname: string): string {
  const h = hostname.toLowerCase();
  return h.endsWith(".") ? h.slice(0, -1) : h;
}

// assertSafeIssuer rejects an issuer that is not a plain https host, or that is an IP literal / localhost
// / a *.cloudflareaccess.com host / carries embedded credentials. The cloudflareaccess reject is the
// cross-method-collision guard: a Cloudflare Access subject is the bare iss+"|"+sub (access.ts), so an
// OIDC connection whose issuer was a cloudflareaccess host could mint a subject that, after the
// connection-id prefix is stripped by a bug, resembles an Access principal; refusing the host removes the
// hazard at the root. Called at CONFIG time when a connection is saved (the operator-supplied issuer must
// be a canonical https URL). Verify-time defence is issuerLooksUnsafe (below), which is spelling-agnostic
// so it also screens a bare-host issuer spelling (Google emits "accounts.google.com" with no scheme).
// Throws on any violation.
export function assertSafeIssuer(raw: string): void {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`issuer is not a valid absolute URL: ${raw}`);
  }
  if (u.protocol !== "https:") throw new Error(`issuer must be https: ${raw}`);
  if (u.username.length > 0 || u.password.length > 0) throw new Error(`issuer must not contain credentials: ${raw}`);
  const host = canonicalHost(u.hostname);
  if (host === "cloudflareaccess.com" || host.endsWith(".cloudflareaccess.com")) {
    throw new Error(`issuer must not be a cloudflareaccess.com host (it would collide with the Access subject namespace): ${raw}`);
  }
  if (host === "localhost" || host.endsWith(".localhost")) throw new Error(`issuer must not be localhost: ${raw}`);
  if (isIpLiteral(host)) throw new Error(`issuer must not be an IP literal: ${raw}`);
}

// assertSafeFetchEndpoint is the SSRF guard for the jwks_uri / token / userinfo URLs the caller will
// fetch. It is host-CATEGORY, not host-EQUALITY: a real IdP legitimately serves its JWKS from a different
// host than its issuer (Google's issuer is accounts.google.com but its JWKS is on www.googleapis.com), so
// requiring jwks-host == issuer-host would break conformant providers. Instead we require https and
// refuse IP-literals / localhost / cloudflareaccess hosts. The discovery fetch itself is pinned to the
// issuer host by the caller, so a malicious discovery document still cannot point the engine at an
// arbitrary internal host without tripping this guard. Throws on any violation.
export function assertSafeFetchEndpoint(raw: string): void {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`endpoint is not a valid absolute URL: ${raw}`);
  }
  if (u.protocol !== "https:") throw new Error(`endpoint must be https: ${raw}`);
  const host = canonicalHost(u.hostname);
  if (host === "cloudflareaccess.com" || host.endsWith(".cloudflareaccess.com")) throw new Error(`endpoint must not be a cloudflareaccess.com host: ${raw}`);
  if (host === "localhost" || host.endsWith(".localhost")) throw new Error(`endpoint must not be localhost: ${raw}`);
  if (isIpLiteral(host)) throw new Error(`endpoint must not be an IP literal: ${raw}`);
}

// issuerLooksUnsafe is the spelling-agnostic verify-time screen: it refuses a matched issuer that names a
// cloudflareaccess.com host, an IP literal, or localhost, whether the value is a full https URL or a bare
// host (Google's "accounts.google.com"). It is defence in depth on top of the config-time assertSafeIssuer
// and the unconditional oidc:<connId>| subject prefix (which already makes a native subject disjoint from
// the Access bare issuer|sub). It does not URL-parse, so it never rejects a legitimate bare-host issuer.
export function issuerLooksUnsafe(s: string): boolean {
  const low = s.toLowerCase();
  if (low.includes("cloudflareaccess.com")) return true;
  // Extract the host whether s is a full URL or a bare host, then NORMALISE it through the URL parser so a
  // decimal (2130706433), hex (0x7f.0.0.1), octal, trailing-dot or IPv4-mapped-IPv6 literal collapses to
  // its canonical host and is caught by the IP/localhost screens below (matching assertSafeIssuer). On a
  // parse failure we fall back to the best-effort split so the screen still fires for a bare host.
  const rawHost = low.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split("/")[0]!.split("?")[0]!.split("#")[0]!.split("@").pop()!;
  let host = canonicalHost(rawHost.split(":")[0]!);
  try {
    host = canonicalHost(new URL(`https://${rawHost}`).hostname);
  } catch {
    // keep the best-effort split host
  }
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (isIpLiteral(host)) return true;
  return false;
}
