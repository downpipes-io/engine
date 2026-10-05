// doh-stub: answers the engine's DoH resolver queries inside a test's own fetch stub.
//
// The send-time resolve screen (screenResolvedSinkHost in src/notify/types.ts) asks cloudflare-dns.com's
// json API about a hostname before the archive destination, the beacon and the OIDC fetch send to it. A
// test that stubs fetch calls dohReply first, so those queries get an answer without taking a scripted reply
// meant for the target, and without leaving the machine.
//
//

// PUBLIC_DNS_ANSWER is the default answer: one public A record (203.0.113.10, TEST-NET-3) and no AAAA, so the
// screen reads resolved-public and lets the request through.
export const PUBLIC_DNS_ANSWER: { readonly a: readonly string[]; readonly aaaa: readonly string[] } = { a: ["203.0.113.10"], aaaa: [] };

// isDohQuery reports whether a request is a query to the engine's DoH resolver.
export function isDohQuery(input: RequestInfo | URL): boolean {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
  return url.startsWith("https://cloudflare-dns.com/dns-query");
}

// dohReply answers a DoH query from `dns` (default PUBLIC_DNS_ANSWER) and returns null for any other request.
export function dohReply(input: RequestInfo | URL, dns: { readonly a?: readonly string[]; readonly aaaa?: readonly string[] } = PUBLIC_DNS_ANSWER): Response | null {
  if (!isDohQuery(input)) return null;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
  const type = new URL(url).searchParams.get("type");
  const list = type === "AAAA" ? (dns.aaaa ?? []) : (dns.a ?? []);
  const Answer = list.map((data) => ({ type: type === "AAAA" ? 28 : 1, data }));
  return new Response(JSON.stringify({ Status: 0, Answer }), { status: 200, headers: { "content-type": "application/dns-json" } });
}
