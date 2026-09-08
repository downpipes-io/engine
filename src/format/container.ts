import { noteFailStage, noteStreamFault } from "./integrity-fault-ledger.ts";
import { CONTAINER_VERSION, MAGIC_DPE, MAGIC_SEG } from "./version.ts";

// Container framing (SPEC 7.1): a sealed .seg or .dpe is a 4-byte magic, a 1-byte
// version, then the STREAM payload. The magic and version are framing only.

/** Container header size: 4-byte magic plus 1-byte version. */
export const HEADER_SIZE = 5;

/**
 * Frames a payload into a container (SPEC 7.1): the 4-byte magic, the 1-byte container version,
 * then the payload.
 *
 * @param magic - the 4-byte container magic (MAGIC_SEG or MAGIC_DPE).
 * @param payload - the STREAM payload to wrap.
 * @returns the framed container bytes.
 */
export function frame(magic: Uint8Array, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out.set(magic, 0);
  out[4] = CONTAINER_VERSION;
  out.set(payload, HEADER_SIZE);
  return out;
}

function unframe(magic: Uint8Array, b: Uint8Array): Uint8Array {
  // These are three distinct CONTAINER FRAMING faults with three different causes: a short container is a
  // TRUNCATED object (the store ate the write); a bad magic is the wrong object entirely; an unsupported
  // version is an engine ROLLBACK reading a newer archive. The receivedBytes int is the truncation
  // magnitude; no key and no byte of content ever rides.
  if (b.length < HEADER_SIZE) {
    noteStreamFault({ leg: "decrypt-open", cls: "container-framing", receivedBytes: b.length, expectedBytes: HEADER_SIZE });
    noteFailStage("root-structure");
    throw new Error("container shorter than the 5-byte header");
  }
  for (let i = 0; i < 4; i++) {
    if (b[i] !== magic[i]) {
      noteStreamFault({ leg: "decrypt-open", cls: "container-framing", receivedBytes: b.length });
      noteFailStage("root-structure");
      throw new Error("bad container magic");
    }
  }
  if (b[4] !== CONTAINER_VERSION) {
    // An engine that has been rolled back under a newer archive. The label is the FIXED product vocabulary
    // shape ("downpipe/<major>.x"), derived from the container version byte, never a manifest value.
    noteFailStage("format-version", "typed", `downpipe/${b[4]}.x`);
    throw new Error(`unsupported container version 0x${b[4]!.toString(16)}`);
  }
  return b.subarray(HEADER_SIZE);
}

/**
 * Unframes a .seg container, checking the DPS1 magic and version and returning the payload.
 *
 * @param b - the framed .seg container bytes.
 * @returns the STREAM payload (the bytes after the 5-byte header).
 * @throws Error when the container is shorter than the 5-byte header, or its magic or version byte
 *   does not match.
 */
export function unframeSeg(b: Uint8Array): Uint8Array {
  return unframe(MAGIC_SEG, b);
}

/**
 * Unframes a .dpe container, checking the DPE1 magic and version and returning the payload.
 *
 * @param b - the framed .dpe container bytes.
 * @returns the STREAM payload (the bytes after the 5-byte header).
 * @throws Error when the container is shorter than the 5-byte header, or its magic or version byte
 *   does not match.
 */
export function unframeDpe(b: Uint8Array): Uint8Array {
  return unframe(MAGIC_DPE, b);
}
