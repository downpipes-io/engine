// The inbound TLS floor (ASVS V12.1.1): only TLS 1.2 and 1.3 may carry a request into the engine.
//
// WHY THE ENGINE HAS TO DO THIS ITSELF. TLS terminates at the Cloudflare edge, and the edge's minimum version
// is a ZONE setting. The four hosts Maelstrom operates are pinned to a 1.2 floor and measured as such, but the
// engine and console deploy into the CUSTOMER'S account on the customer's zone, and a Cloudflare zone starts
// on a 1.0 floor. The product holds no zone-write credential by design, so it cannot set that floor for the
// customer; what it can do is refuse to serve a request that arrived over a version below it, and say exactly
// which dashboard setting fixes it. The edge reports the negotiated version on req.cf.tlsVersion.
//
// FAIL-OPEN ON A MISSING SIGNAL, deliberately: a request with no cf object (local dev, the test harness) or an
// unknown version string passes through. The floor refuses only what it can positively read as below it.

const BELOW_FLOOR: ReadonlySet<string> = new Set(["SSLv3", "TLSv1", "TLSv1.1"]);

/** inboundTlsBelowFloor returns the negotiated version when it is positively below TLS 1.2, else null. */
export function inboundTlsBelowFloor(req: Request): string | null {
  const v = (req as unknown as { cf?: { tlsVersion?: unknown } }).cf?.tlsVersion;
  return typeof v === "string" && BELOW_FLOOR.has(v) ? v : null;
}

/** tlsFloorResponse is the 426 an under-floor request receives: plain text, no secret, the remedy named. */
export function tlsFloorResponse(version: string): Response {
  return new Response(
    `This connection used ${version}. downpipes requires TLS 1.2 or 1.3.\nIn the Cloudflare dashboard set SSL/TLS -> Edge Certificates -> Minimum TLS Version to 1.2 on this zone and keep TLS 1.3 enabled.\n`,
    { status: 426, headers: { "content-type": "text/plain; charset=utf-8", upgrade: "TLS/1.2, TLS/1.3", "cache-control": "no-store" } },
  );
}

// The plaintext refusal (ASVS V12.3.1): the engine never serves a request that arrived over http://, and never
// falls back to it. Behind the edge every request is https unless the customer's zone has "Always Use HTTPS"
// off, which is the zone default. A credential-bearing or admin request over plaintext is refused outright
// rather than redirected, because a redirect would have already carried the bearer or cookie in clear; a
// credential-free navigation is sent to the https form of the same URL. The loopback hosts are the wrangler
// dev seam and pass through.
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** plaintextVerdict says what to do with a request whose URL scheme is http://: refuse, redirect, or nothing. */
export function plaintextVerdict(req: Request, url: URL): "refuse" | "redirect" | null {
  if (url.protocol !== "http:" || LOOPBACK_HOSTS.has(url.hostname)) return null;
  const credentialed = req.headers.has("authorization") || req.headers.has("cookie");
  const sensitive = url.pathname.startsWith("/admin") || url.pathname.startsWith("/scim") || url.pathname.startsWith("/metrics");
  return credentialed || sensitive || (req.method !== "GET" && req.method !== "HEAD") ? "refuse" : "redirect";
}

export function plaintextRefusedResponse(): Response {
  return new Response(JSON.stringify({ error: "https required", detail: "This request arrived over plaintext http. downpipes serves its API over https only; in the Cloudflare dashboard turn on SSL/TLS -> Edge Certificates -> Always Use HTTPS for this zone." }), { status: 400, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

export function plaintextRedirectResponse(url: URL): Response {
  return new Response(null, { status: 308, headers: { location: `https://${url.host}${url.pathname}${url.search}`, "cache-control": "no-store" } });
}
