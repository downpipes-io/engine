// Validates decodeULID against the Go reference spec (downpipe/internal/spec/ulid.go).
// The Go DecodeULID rejects a first character above '7' because 26*5 = 130 bits and
// any value 8-Z in position 0 sets bit 128 or higher, overflowing the 128-bit ULID
// space. Without this check, distinct runId strings silently collapse to the same
// 16-byte HKDF salt, and the TS reader opens archives the Go reader refuses.
// Run with: node test/validate-ulid.ts

import { classifyRunIdMalformation, decodeULID, isValidRunId, RUNID_MALFORM_KINDS } from "../src/format/ulid.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function throws(label: string, fn: () => unknown, fragment: string): void {
  try {
    fn();
    console.log(`  FAIL ${label} (expected throw, got none)`);
    failures++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const pass = msg.includes(fragment);
    console.log(pass ? `  ok   ${label}` : `  FAIL ${label} (error "${msg}" does not contain "${fragment}")`);
    if (!pass) failures++;
  }
}

function hexBytes(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function main(): Promise<void> {
  // --- overflow rejections ---

  // First character '8' decodes to value 8 (binary 01000), which sets bit 128.
  // The remaining 25 zeros contribute nothing to the top bits, so this is the
  // smallest overflowing ULID string.
  throws(
    "reject '8' + 25 zeros (bit 128 set)",
    () => decodeULID("8" + "0".repeat(25)),
    "overflows 128 bits",
  );

  // 'Z' is the highest Crockford character (value 31, binary 11111). All 26 'Z'
  // characters produces the maximum possible 130-bit value; top 2 bits both set.
  throws(
    "reject 26 x 'Z' (bits 128-129 set)",
    () => decodeULID("Z".repeat(26)),
    "overflows 128 bits",
  );

  // --- canonical decode ---

  // The Go suite's default run id, pinned in validate-reader.ts as DEFAULT_RUN_ID.
  // First character is '0', value 0: top 2 bits clear. Expected bytes are the
  // Crockford base32 decoding of the string, verified by hand against the Go
  // EncodeULID round-trip.
  const canonical = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  let decoded: Uint8Array;
  try {
    decoded = decodeULID(canonical);
  } catch (e) {
    console.log(`  FAIL canonical ULID threw unexpectedly: ${e}`);
    failures++;
    console.log(failures === 0 ? "\nULID TESTS PASS" : `\n${failures} FAILURE(S)`);
    if (failures > 0) process.exit(1);
    return;
  }
  ok("canonical ULID decodes to 16 bytes", decoded.length === 16);

  // Round-trip sanity: re-encode the 16 bytes via the CROCKFORD alphabet and
  // confirm we recover the original string. This keeps the test self-contained
  // without importing the encoder.
  const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  let bits = 0n;
  for (const b of decoded) bits = (bits << 8n) | BigInt(b);
  let encoded = "";
  for (let i = 0; i < 26; i++) {
    encoded = (CROCKFORD[Number(bits & 0x1fn)] ?? "") + encoded;
    bits >>= 5n;
  }
  ok("canonical ULID round-trips through decode", encoded === canonical);

  // First character '7' is value 7 (binary 00111): the highest value that does
  // NOT overflow 128 bits. Confirm it is accepted.
  const maxValid = "7" + "Z".repeat(25);
  let maxDecoded: Uint8Array | undefined;
  try {
    maxDecoded = decodeULID(maxValid);
  } catch (e) {
    console.log(`  FAIL '7'+'Z'*25 threw unexpectedly: ${e}`);
    failures++;
  }
  ok("'7' + 25 'Z' accepted (top value fitting 128 bits)", maxDecoded?.length === 16);
  // The top byte of the max-value ULID must be 0xFF (all 8 top bits set).
  ok("'7'+'Z'*25 top byte is 0xff", maxDecoded !== undefined && hexBytes(maxDecoded.slice(0, 1)) === "ff");

  // --- isValidRunId + classifyRunIdMalformation (the runId gate: a caller-supplied runId is interpolated raw
  // into object-key templates, so this is the input-side defence against a path-traversal / non-Crockford
  // payload; every branch is pinned so a mutation that weakens a check is caught, not silently survived). ---
  ok("isValidRunId(canonical) is true", isValidRunId(canonical) === true);
  ok("isValidRunId('7'+Z*25 max valid) is true", isValidRunId(`7${"Z".repeat(25)}`) === true);
  ok("isValidRunId(25 chars) is false (too short)", isValidRunId("0".repeat(25)) === false);
  ok("isValidRunId(27 chars) is false (too long)", isValidRunId("0".repeat(27)) === false);
  ok("isValidRunId(lower-cased) is false (non-Crockford)", isValidRunId("01arz3ndektsv4rrffq69g5fav") === false);
  ok("isValidRunId(overflow '8'+0*25) is false", isValidRunId(`8${"0".repeat(25)}`) === false);
  ok("isValidRunId(path-traversal payload) is false", isValidRunId(`${"../".repeat(8)}00`) === false);

  ok("classify(canonical) is null (valid)", classifyRunIdMalformation(canonical) === null);
  ok("classify(number, not a string) is length", classifyRunIdMalformation(12345) === "length");
  ok("classify(null) is length", classifyRunIdMalformation(null) === "length");
  ok("classify(undefined) is length", classifyRunIdMalformation(undefined) === "length");
  ok("classify(object) is length", classifyRunIdMalformation({}) === "length");
  ok("classify(25 chars) is length (too short)", classifyRunIdMalformation("0".repeat(25)) === "length");
  ok("classify(27 chars) is length (too long)", classifyRunIdMalformation("0".repeat(27)) === "length");
  ok("classify(lower-cased 26) is charset", classifyRunIdMalformation("01arz3ndektsv4rrffq69g5fav") === "charset");
  ok("classify('O'-transcription 26) is charset", classifyRunIdMalformation("O1ARZ3NDEKTSV4RRFFQ69G5FAV") === "charset");
  ok("classify(dot-payload 26) is charset", classifyRunIdMalformation(`..${"0".repeat(24)}`) === "charset");
  ok("classify(overflow '8'+0*25) is overflow", classifyRunIdMalformation(`8${"0".repeat(25)}`) === "overflow");
  ok("classify(overflow Z*26) is overflow", classifyRunIdMalformation("Z".repeat(26)) === "overflow");
  ok("RUNID_MALFORM_KINDS is exactly [length, charset, overflow] in order", RUNID_MALFORM_KINDS.join(",") === "length,charset,overflow");

  console.log(failures === 0 ? "\nULID TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
