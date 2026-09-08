/**
 * toArrayBuffer copies a Uint8Array's logical bytes into a standalone ArrayBuffer. A
 * Uint8Array may be a window onto a larger pooled buffer (byteOffset>0 or byteLength<buffer
 * size); handing a binding the raw .buffer would write those extra bytes, so copy the view.
 *
 * It always copies, even when the view already spans its whole buffer, so the result never aliases the
 * input and a later write to either cannot be seen by the other. Use it at any boundary that takes an
 * ArrayBuffer (a KV or R2 put), never as a cheap cast: the copy costs a full allocation.
 */
export function toArrayBuffer(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}
