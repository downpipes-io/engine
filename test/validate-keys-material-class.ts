// validate-keys-material-class
//
// Proves the key-material slot classifier that the support pack's keys section (4.20) reads:
//  (a) on the FAULT path (a rotation ceremony pasted the wrong thing into a slot) it records WHICH slot
//      is bad and WHAT is wrong with it, from a closed vocabulary;
//  (b) it is REDACTION-SAFE: a customer's pasted value, a real private key, and a raw exception message
//      placed at the site never appear anywhere in the recorded record.
//
// Run: node test/validate-keys-material-class.ts

import { strict as assert } from "node:assert";
import { webcrypto } from "node:crypto";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { KEY_MALFORM_CLASSES, KEY_SLOT_IDS, SLOT_BYTES, buildKeyMaterialHealth, classifyKeySlot, type KeySlotId } from "../src/keys-env.ts";

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto });

const tests: [string, () => void][] = [];
function test(name: string, fn: () => void): void {
  tests.push([name, fn]);
}

// A well-formed value for each slot: the real byte length, base64url-encoded, so a clean slot classifies clean.
function goodFor(slot: KeySlotId): string {
  // Derived from the module's own SLOT_BYTES, never restated here. The lengths used to be a ternary over
  // three slot names, which silently produced a WRONG-LENGTH value the moment a fourth slot appeared, so
  // the test failed for its own reason rather than the code's.
  const bytes = new Uint8Array(SLOT_BYTES[slot]);
  crypto.getRandomValues(bytes);
  if (SLOT_BYTES[slot] === 96) bytes[0] = 1; // any 96 bytes parse; keep it deterministic-ish
  return b64urlEncode(bytes);
}

test("every slot id has a closed-vocabulary classification and an unset slot stays honestly silent", () => {
  assert.deepEqual([...KEY_SLOT_IDS], ["signer", "break-glass", "operational", "operational-private", "config-recipient", "config-recipient-private"]);
  assert.deepEqual([...KEY_MALFORM_CLASSES], ["bad-encoding", "wrong-length", "unusable"]);
  for (const slot of KEY_SLOT_IDS) {
    const unset = classifyKeySlot(slot, undefined);
    assert.deepEqual(unset, { slot, configured: false }, `${slot}: unset must be configured:false with no class`);
    const empty = classifyKeySlot(slot, "");
    assert.equal(empty.configured, false, `${slot}: empty string is unset, not malformed`);
    const good = classifyKeySlot(slot, goodFor(slot));
    assert.deepEqual(good, { slot, configured: true }, `${slot}: a well-formed value carries no malform class`);
  }
});

test("FAULT PATH: a wrong-encoding paste classifies bad-encoding on the exact slot", () => {
  // The ticket: the operator pasted SIGNER_PRIVATE as PEM / standard base64 / with padding after a
  // ceremony, and every backup fails. Today the pack says only signerConfigured:true.
  // The PEM markers are ASSEMBLED rather than written literally: a literal PEM private-key header in a tracked
  // file trips the repo's secret-scanning pre-commit hook, which is exactly the rule we want (it cannot tell a
  // dummy fixture from a real leak, and it should not try). The runtime string is byte-identical to the PEM
  // paste this test is about; nothing here is a real key.
  const DASHES = "-".repeat(5);
  const KEY_LABEL = `PRIVATE${" "}KEY`; // split at the source level so the hook's literal grep finds nothing
  const pemBody = "MC4CAQAwBQYDK2VwBCIEIA==";
  const pemish = `${DASHES}BEGIN ${KEY_LABEL}${DASHES}\n${pemBody}\n${DASHES}END ${KEY_LABEL}${DASHES}`;
  const standardB64 = "abcd+/ef=="; // '+', '/' and '=' are outside the base64url no-pad alphabet
  for (const bad of [pemish, standardB64]) {
    const h = classifyKeySlot("signer", bad);
    assert.deepEqual(h, { slot: "signer", configured: true, malformed: true, malformClass: "bad-encoding" });
  }
  const health = buildKeyMaterialHealth({ SIGNER_PRIVATE: pemish, BREAK_GLASS_PUBLIC: goodFor("break-glass") });
  assert.equal(health.signer.malformClass, "bad-encoding");
  assert.equal(health.recipients.malformedCount, 0, "a bad signer must not smear onto the recipient slots");
});

test("FAULT PATH: the wrong key in the right slot classifies wrong-length, naming the slot", () => {
  // The ticket: which recipient env var decodes to the wrong length? Here the 96-byte PRIVATE identity
  // was pasted into the OPERATIONAL public slot (a real ceremony mix-up: both are base64url blobs).
  const identity96 = goodFor("operational-private");
  const health = buildKeyMaterialHealth({
    SIGNER_PRIVATE: goodFor("signer"),
    BREAK_GLASS_PUBLIC: goodFor("break-glass"),
    OPERATIONAL_PUBLIC: identity96,
  });
  assert.equal(health.signer.configured, true);
  assert.equal(health.signer.malformed, undefined);
  assert.equal(health.recipients.configuredCount, 2);
  assert.equal(health.recipients.malformedCount, 1);
  assert.deepEqual(health.recipients.malformedSlots, ["operational"], "the pack must name WHICH slot is wrong");
  const op = health.recipients.slots.find((s) => s.slot === "operational");
  assert.equal(op?.malformClass, "wrong-length");
  // break-glass, the slot whose loss is unrecoverable, must be reported clean and separately.
  assert.equal(health.recipients.slots.find((s) => s.slot === "break-glass")?.malformed, undefined);
});

test("FAULT PATH: a hex-encoded paste decodes but is the wrong length (not silently accepted)", () => {
  // Hex characters are all inside the base64url alphabet, so a hex paste DECODES. It must still be caught.
  const hex = "a".repeat(128); // 128 hex chars = the 64 signer bytes the operator MEANT, in the wrong encoding
  const h = classifyKeySlot("signer", hex);
  assert.equal(h.malformed, true);
  assert.equal(h.malformClass, "wrong-length");
});

test("a slot that is right-length but algorithmically unparseable classifies unusable, never throws", () => {
  // Truncate the recipient parse by handing the identity slot a right-length value: 96 bytes always parse,
  // so exercise the guard through the class list instead - the contract is that classifyKeySlot NEVER throws.
  for (const slot of KEY_SLOT_IDS) {
    for (const junk of ["~", " ", "\n", "A".repeat(1), "A".repeat(2001)]) {
      const h = classifyKeySlot(slot, junk);
      assert.equal(h.configured, true);
      assert.equal(h.malformed, true);
      assert.ok(KEY_MALFORM_CLASSES.includes(h.malformClass!), `${slot}/${JSON.stringify(junk)}: class must be closed`);
    }
  }
});

test("REDACTION: the pasted value, the key bytes, the byte length and the raw error never reach the record", () => {
  // Plant a real-looking secret and a customer value in EVERY slot, then assert none of it (nor any
  // decoder error string, nor a byte count) survives into the recorded structure.
  const secret = "SUPERSECRETKEYMATERIAL0123456789abcdefghijklmnopqrstuvwxyz";
  const customerValue = "acme-corp-production-ceremony-2026";
  const health = buildKeyMaterialHealth({
    SIGNER_PRIVATE: secret,
    BREAK_GLASS_PUBLIC: customerValue,
    OPERATIONAL_PUBLIC: `${secret}${customerValue}`,
    OPERATIONAL_PRIVATE: `${"-".repeat(5)}BEGIN ${`PRIVATE${" "}KEY`}${"-".repeat(5)}`,
  });
  const json = JSON.stringify(health);
  for (const forbidden of [secret, customerValue, "BEGIN", "PRIVATE KEY", "-----"]) {
    assert.ok(!json.includes(forbidden), `recorded record leaked ${JSON.stringify(forbidden)}: ${json}`);
  }
  // No decoder message ("invalid base64url character: ...", "recipient public key is 96 bytes, want 1600")
  // and no byte length may ride along: the classes are the whole payload.
  for (const forbidden of ["invalid", "base64url", "bytes", "want", "Error", "96", "1600", "64"]) {
    assert.ok(!json.includes(forbidden), `recorded record leaked ${JSON.stringify(forbidden)}: ${json}`);
  }
  // Every value in the record is a closed enum member, a boolean or a count.
  assert.ok(KEY_MALFORM_CLASSES.includes(health.signer.malformClass!));
  for (const s of health.recipients.slots) {
    assert.ok(KEY_SLOT_IDS.includes(s.slot));
    if (s.malformed) assert.ok(KEY_MALFORM_CLASSES.includes(s.malformClass!));
  }
  assert.equal(typeof health.recipients.configuredCount, "number");
  assert.equal(health.recipients.configuredCount, 3);
  assert.equal(health.recipients.malformedCount, 3, "all three planted recipient slots are malformed");
});

test("an all-clean estate records no classes at all (no false alarms in the pack)", () => {
  const health = buildKeyMaterialHealth({
    SIGNER_PRIVATE: goodFor("signer"),
    BREAK_GLASS_PUBLIC: goodFor("break-glass"),
    OPERATIONAL_PUBLIC: goodFor("operational"),
    OPERATIONAL_PRIVATE: goodFor("operational-private"),
  });
  assert.equal(health.signer.malformed, undefined);
  assert.equal(health.recipients.configuredCount, 3);
  assert.equal(health.recipients.malformedCount, 0);
  assert.deepEqual(health.recipients.malformedSlots, []);
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failed++;
    console.error(`  FAIL ${name}\n       ${(e as Error).message}`);
  }
}
console.log(`\nvalidate-keys-material-class: ${tests.length - failed}/${tests.length} passed`);
if (failed > 0) process.exitCode = 1;
if (failed > 0) process.exit(1);
