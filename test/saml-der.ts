// Minimal DER encoders shared by the SAML response/real-world validators to build a real, structurally-valid,
// self-signed X.509 certificate wrapping an RSA public key. The SP IGNORES the cert signature (it only walks
// out the SubjectPublicKeyInfo plus the validity window), so the cert need only be a STRUCTURALLY valid X.509
// the DER walk can descend; the callers nonetheless sign the TBS for real (a genuine self-signed cert), which
// also proves the DER walk steps PAST a real signature-algorithm/issuer/validity/subject to the SPKI.
//
// Kept here (not inside any one validator) so the byte-for-byte identical suite has a single home: a change to
// the encoding is made once and exercised by every SAML validator that imports it. The cert-builder wrappers
// themselves stay in each validator because their validity windows differ.

export function derLen(len: number): number[] {
  if (len < 0x80) return [len];
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = n >>> 8;
  }
  return [0x80 | bytes.length, ...bytes];
}
export function derTlv(tag: number, content: number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}
export function derSeq(...items: number[][]): number[] {
  const content: number[] = [];
  for (const it of items) content.push(...it);
  return derTlv(0x30, content);
}
export function derInt(bytes: number[]): number[] {
  // Ensure a positive integer: if the top bit is set, prepend 0x00.
  const b = bytes.length === 0 ? [0] : bytes.slice();
  if ((b[0]! & 0x80) !== 0) b.unshift(0x00);
  return derTlv(0x02, b);
}
export function derOid(bytes: number[]): number[] {
  return derTlv(0x06, bytes);
}
export function derNull(): number[] {
  return [0x05, 0x00];
}
export function derGeneralizedTime(s: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
  return derTlv(0x18, bytes);
}
export function derUtf8(s: string): number[] {
  const enc = new TextEncoder().encode(s);
  return derTlv(0x0c, Array.from(enc));
}
export function derExplicit0(content: number[]): number[] {
  return derTlv(0xa0, content);
}
export function derBitString(bytes: Uint8Array): number[] {
  return derTlv(0x03, [0x00, ...Array.from(bytes)]); // 0 unused bits
}

// OID 1.2.840.113549.1.1.11 == sha256WithRSAEncryption, encoded.
export const OID_SHA256_RSA = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
// OID 2.5.4.3 == commonName.
export const OID_CN = [0x55, 0x04, 0x03];
