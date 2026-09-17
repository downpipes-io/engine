// The engine's outbound network policy in one place (ASVS V13.2.5, V15.3.2).
//
// FIXED HOSTS. The vendor endpoints the engine reaches on its own initiative are enumerated here and nowhere
// else: the Cloudflare API and GraphQL, the DNS-over-HTTPS resolver the egress screen uses, the update
// channel, and the Entra token host. Every module that used to carry its own literal imports the constant
// from here, so a new vendor host has to be added to this list to exist, and validate-outbound-policy refuses
// a literal that appears anywhere else. Operator-CONFIGURED hosts (a webhook, a SIEM sink, an S3-compatible
// endpoint, an IdP) are not fixed and are screened at their own boundaries (isInternalSinkHost and the
// resolve screen in notify/types.ts, assertSafeFetchEndpoint for an IdP); an allowlist of those is the
// operator's, not the vendor's, and is a separate control.
//
// REDIRECTS. No outbound call the engine makes follows a redirect. Workers fetch forwards the Authorization
// header on a same-origin redirect, and every fixed-host call here carries a bearer, so a 3xx from any of
// them is treated as a failed call (redirect: "manual" makes the runtime return the 3xx rather than follow
// it, and every site's non-ok branch then refuses it). The one deliberate exception is the source byte
// fetch's single bounded hop for Cloudflare Stream (sources/byte-fetch.ts), which is gated on the source's
// own allow-list predicate and strips the bearer across origins.
export const CF_API_BASE = "https://api.cloudflare.com/client/v4";
export const CF_GRAPHQL_URL = `${CF_API_BASE}/graphql`;
export const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
export const UPDATE_CHANNEL_HOST = "update.downpipes.io";
export const ENTRA_LOGIN_HOST = "login.microsoftonline.com";

// FIXED_EGRESS_HOSTS is the closed set a "fixed" call may reach: exact hosts, plus the suffixes whose
// left-most label is a customer- or region-specific value (an Access team, a Stream customer subdomain, an
// STS region) rather than an operator choice.
export const FIXED_EGRESS_HOSTS: { readonly exact: readonly string[]; readonly suffixes: readonly string[] } = {
  exact: ["api.cloudflare.com", "cloudflare-dns.com", UPDATE_CHANNEL_HOST, ENTRA_LOGIN_HOST],
  suffixes: [".cloudflareaccess.com", ".cloudflarestream.com", ".amazonaws.com"],
};

/** isFixedEgressHost says whether a hostname is one the engine reaches on its own initiative. */
export function isFixedEgressHost(host: string): boolean {
  const h = host.toLowerCase();
  return FIXED_EGRESS_HOSTS.exact.includes(h) || FIXED_EGRESS_HOSTS.suffixes.some((s) => h.endsWith(s) && h.length > s.length);
}

// isFixedEgressHostExact matches only FIXED_EGRESS_HOSTS.exact, never a wildcard suffix. The notify-channel
// egress allowlist screen (screenEgressAllowlist, ASVS V13.2.4) uses this instead of isFixedEgressHost: the
// suffixes (.amazonaws.com, .cloudflareaccess.com, .cloudflarestream.com) name a customer- or region-chosen
// left-most label, so any tenant can register a host under one of them. A notify channel's url is a
// CUSTOMER-TYPED value, so treating the whole suffix as an engine-owned host would let a customer point a
// channel at another tenant's (or an attacker's) subdomain of one of these suffixes and have it always pass,
// skipping an operator's configured allowlist entirely. assertEgressHost keeps the wildcard suffixes: there
// the target is engine-chosen (the account's own S3/STS/Access/Stream endpoint), never a customer-typed url.
export function isFixedEgressHostExact(host: string): boolean {
  return FIXED_EGRESS_HOSTS.exact.includes(host.toLowerCase());
}

/**
 * assertEgressHost refuses a URL whose host is not in the fixed set. It is the pin a call site applies when
 * the URL came from configuration or from a fetched document (the update channel manifest's artefact URL,
 * the UPDATE_CHANNEL_URL var) rather than from a constant in this file. Throws with the host named, never
 * the full URL (it can carry a query).
 */
export function assertEgressHost(url: string): URL {
  const u = new URL(url);
  if (u.protocol !== "https:") throw new Error(`outbound call refused: ${u.hostname} is not https`);
  if (!isFixedEgressHost(u.hostname)) throw new Error(`outbound call refused: ${u.hostname} is not a host the engine is permitted to reach`);
  return u;
}
