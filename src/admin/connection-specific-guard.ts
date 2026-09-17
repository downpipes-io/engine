// Connection-specific request headers: the engine neither sends nor accepts them.
//
// WHY A WORKER HAS TO CHECK. Hop-by-hop fields belong to one TCP connection and must not survive a proxy.
// The Cloudflare edge strips them on HTTP/2 and rejects transfer-encoding on HTTP/3 outright, but it
// forwards proxy-connection to the origin over HTTP/3. Nothing in the engine reads that field, so it is
// inert, but "inert" is a note and a refusal is a control: any request carrying one of these names is
// answered 400 before routing.
//
// "connection" is deliberately NOT in the set: the edge itself sets `connection: Keep-Alive` on every
// request it delivers to the origin, so refusing it would refuse all traffic. "te" is the one field a
// client may legitimately send end to end, and only with the exact value "trailers".
const REFUSED_NAMES: readonly string[] = ["transfer-encoding", "keep-alive", "upgrade", "proxy-connection"];

/** connectionSpecificHeaderRefusal names the offending header, or returns undefined when the request is clean. */
export function connectionSpecificHeaderRefusal(headers: Headers): string | undefined {
  for (const name of REFUSED_NAMES) if (headers.has(name)) return name;
  const te = headers.get("te");
  if (te !== null && te.trim().toLowerCase() !== "trailers") return "te";
  return undefined;
}

/** connectionSpecificRefusedResponse is the fixed 400: it names the class, never the value. */
export function connectionSpecificRefusedResponse(): Response {
  return new Response("malformed request: connection-specific header\n", {
    status: 400,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
