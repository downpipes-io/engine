// Container-framing gate: forward-compat version + wrong-object magic + truncation (recovery-redundancy /
// cross-version, net-zero). Every sealed .seg / .dpe object is framed as magic(4) || version(1) || payload
// (SPEC 7.1); the magic + version are PLAINTEXT framing checked BEFORE decryption. Cross-version compat
// is blocked for a CRAFTED archive because the manifest formatVersion is signed -- but the CONTAINER version
// gate (container.ts unframe) is a net-zero-testable pure function, and its three distinct refusals
// (truncation vs bad-magic vs unsupported-version -- "three different fixes") were untested. This asserts them
// directly, default-FAIL: a round-trip works; a NEWER container version is refused as "unsupported container
// version" (a rolled-back engine reading a newer archive refuses cleanly, never mis-parses); a .dpe object read
// as a .seg is refused as "bad container magic" (no container-type confusion); a buffer short of the 5-byte
// header is refused as truncated; and all three errors are DISTINCT. It also asserts the HEADER_SIZE BOUNDARY (a
// header-only container of exactly 5 bytes unframes to an empty payload, NOT short-rejected) and the
// fault CLASSIFICATION each refusal writes to the integrity-fault ledger (the label that rides into the customer
// support pack: container-framing / root-structure / format-version) -- a focused Stryker run on container.ts
// showed those were the surviving mutants (the security rejections were killed, the classification labels were
// not). Net-zero: pure functions, no seal, no IO. Run: node test/validate-container-version-gate.ts
import { frame, HEADER_SIZE, unframeDpe, unframeSeg } from "../src/format/container.ts";
import { drainIntegrityFaultLedger, resetIntegrityFaultLedger } from "../src/format/integrity-fault-ledger.ts";
import { CONTAINER_VERSION, MAGIC_DPE, MAGIC_SEG } from "../src/format/version.ts";

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function threw(fn: () => void): string {
  try { fn(); return ""; } catch (e) { return e instanceof Error ? e.message : String(e); }
}
// Capture the integrity-fault-ledger telemetry a refusal writes (the classification that rides into the support
// pack). The throw itself is asserted separately; here we want the recorded label.
function snapAfterThrow(fn: () => void): ReturnType<typeof drainIntegrityFaultLedger> {
  resetIntegrityFaultLedger();
  try { fn(); } catch { /* intentional: the refusal is asserted elsewhere; capture its classification */ }
  return drainIntegrityFaultLedger();
}

let assertions = 0;
let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  assertions++;
  console.log(cond ? `  ok   ${label}${detail ? ` (${detail})` : ""}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}

function main(): void {
  const payload = rand(200);

  // Control: a correctly-framed .seg and .dpe container round-trip to the exact payload (not vacuous).
  const seg = frame(MAGIC_SEG, payload);
  ok("CONTROL: a .seg container (DPS1 || 0x01 || payload) unframes to the exact payload", bytesEqual(unframeSeg(seg), payload) && seg.length === HEADER_SIZE + payload.length && seg[4] === CONTAINER_VERSION);
  const dpe = frame(MAGIC_DPE, payload);
  ok("CONTROL: a .dpe container (DPE1 || 0x01 || payload) unframes to the exact payload", bytesEqual(unframeDpe(dpe), payload));

  // FORWARD-COMPAT (the B7 property at the net-zero-testable layer): a container claiming a NEWER version byte
  // must be refused as "unsupported container version" -- a rolled-back engine reading a newer archive refuses
  // cleanly, it never mis-parses the newer framing as v1.
  const newer = new Uint8Array(seg);
  newer[4] = CONTAINER_VERSION + 1; // 0x02
  const vErr = threw(() => unframeSeg(newer));
  ok("FORWARD-COMPAT: a NEWER container version (0x02) is REFUSED as 'unsupported container version' -- a rolled-back reader never mis-parses a newer archive", vErr.includes("unsupported container version"), vErr.slice(0, 60));

  // WRONG-OBJECT MAGIC: a .dpe object read through the .seg path is refused as "bad container magic" -- the two
  // container types are not interchangeable (no container-type confusion, e.g. a recipient blob read as a segment).
  const mErr = threw(() => unframeSeg(dpe));
  ok("TYPE SAFETY: a .dpe container read as a .seg is REFUSED as 'bad container magic' (no container-type confusion)", mErr.includes("bad container magic"), mErr.slice(0, 60));

  // TRUNCATION: a buffer shorter than the 5-byte header is refused as truncated (the store ate the write),
  // distinctly from a tamper.
  const tErr = threw(() => unframeSeg(rand(HEADER_SIZE - 1)));
  ok("TRUNCATION: a container shorter than the 5-byte header is REFUSED as truncated (distinct from a tamper)", tErr.includes("shorter than"), tErr.slice(0, 60));

  // The three container-framing faults are DISTINCTLY classified (three different fixes, not one
  // opaque 'integrity check failed'), so an operator sees WHICH fault occurred.
  ok("DISTINCT CLASSIFICATION: unsupported-version, bad-magic and truncation are three DISTINCT refusals", vErr !== "" && mErr !== "" && tErr !== "" && vErr !== mErr && mErr !== tErr && vErr !== tErr);

  // BOUNDARY (kills the `b.length < HEADER_SIZE` off-by-one): a header-only container of EXACTLY HEADER_SIZE bytes
  // (magic + version, empty payload) is NOT rejected as short -- it unframes to an empty payload. A `<=` would
  // wrongly reject a genuine empty-payload segment.
  const headerOnly = frame(MAGIC_SEG, new Uint8Array(0));
  ok("BOUNDARY: a header-only container (exactly HEADER_SIZE bytes) unframes to an EMPTY payload, not short-rejected", headerOnly.length === HEADER_SIZE && unframeSeg(headerOnly).length === 0);

  // FAULT CLASSIFICATION: each refusal must ALSO be classified correctly in the integrity-fault ledger
  // -- the label that rides into the customer support pack -- not merely thrown. A mislabel regression collapses
  // the "three different fixes" distinction back to one opaque failure. Assert the recorded telemetry per fault.
  const shortSnap = snapAfterThrow(() => unframeSeg(rand(HEADER_SIZE - 1)));
  ok("CLASSIFY truncation: a short container records a container-framing stream fault (leg decrypt-open, expected 5B) + a root-structure fail-stage", shortSnap.streamFaults[0]?.cls === "container-framing" && shortSnap.streamFaults[0]?.leg === "decrypt-open" && shortSnap.streamFaults[0]?.expectedBytes === HEADER_SIZE && shortSnap.failStages["root-structure"] === 1);

  const magicSnap = snapAfterThrow(() => unframeSeg(dpe));
  ok("CLASSIFY wrong-magic: a bad-magic container records a container-framing stream fault (leg decrypt-open)", magicSnap.streamFaults[0]?.cls === "container-framing" && magicSnap.streamFaults[0]?.leg === "decrypt-open");

  const verSnap = snapAfterThrow(() => { const n = new Uint8Array(seg); n[4] = CONTAINER_VERSION + 1; unframeSeg(n); });
  ok("CLASSIFY version: an unsupported version records a format-version fail-stage, classified 'typed', with the fixed MAJOR label downpipe/2.x (never a manifest value)", verSnap.failStages["format-version"] === 1 && verSnap.classifiedBy["typed"] === 1 && verSnap.formatVersionSeen === "downpipe/2.x");

  console.log(failures === 0
    ? `\nCONTAINER-FRAMING GATE OK: forward-compat (a newer container version is refused, never mis-parsed), type safety (.dpe != .seg), truncation, the HEADER_SIZE boundary, and the correct support-pack CLASSIFICATION for each refusal. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
