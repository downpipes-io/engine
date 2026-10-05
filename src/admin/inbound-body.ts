// Bounded reads of an inbound request body, for the routes that run before the authorise() gate.
//
// The pre-auth sign-in routes (recovery sign-in, the passkey ceremonies, the SAML ACS POST) take a body from a
// caller who has no identity yet, and each forwards it to the account's single SchedulerDO. A plain
// req.json() or req.text() reads the whole body first, so a 20 MB body was held in the Worker and again in
// the DO (ASVS v5.0.0-15.2.2, CWE-770). readBoundedRequestText refuses a declared Content-Length over the cap
// before it reads a byte. It also counts the bytes it actually reads, because a chunked body declares no
// length. So it holds at most the cap plus one chunk before it refuses.

import { noteSiteFault } from "./site-faults.ts";

/**
 * The byte cap for a body on the pre-auth /admin/auth/* routes. The largest legitimate body is a passkey
 * register/finish with an attestation certificate chain, a few KiB.
 */
export const PRE_AUTH_MAX_BODY_BYTES = 64 * 1024;

/**
 * The byte cap for the SAML ACS form POST. A signed SAMLResponse with a certificate and a group list is
 * tens of KiB after base64 and form encoding, so this cap is larger than the /admin/auth/* cap.
 */
export const SAML_ACS_MAX_BODY_BYTES = 512 * 1024;

/**
 * Reads the request body as UTF-8 text, or returns null when the body is larger than maxBytes.
 * A declared Content-Length over the cap is refused before any read. The byte count of the body as read
 * is also checked, so a body with no Content-Length, or one that sends more than it declared, is refused
 * as soon as it passes the cap.
 */
export async function readBoundedRequestText(req: Request, maxBytes: number): Promise<string | null> {
  const header = req.headers.get("content-length");
  const declared = header === null || header.trim() === "" ? Number.NaN : Number(header);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await req.body?.cancel().catch((e: unknown) => noteSiteFault("admin.inbound-body-cancel", e));
    return null;
  }
  if (req.body === null) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch((e: unknown) => noteSiteFault("admin.inbound-body-cancel", e));
      return null;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/** The 413 answer for a pre-auth body over its cap. It names no route detail and carries no-store. */
export function bodyTooLargeResponse(): Response {
  return new Response(JSON.stringify({ ok: false, reason: "body_too_large" }), { status: 413, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
