// Deploy-time key provisioning (the front-loaded deploy: everything a fresh install needs is
// generated and provisioned in one guided pass).
//
// Run by scripts/deploy.sh on a FRESH deployment (when SIGNER_PRIVATE is not yet
// set): it generates the full default key set ON THE DEPLOYER'S OWN MACHINE —
// the signer, the break-glass recipient, AND the operational read-back pair
// (default ON: it is what lets the engine PROVE backups restore — scheduled
// restore tests, drills, in-console restores, retention pruning; strict
// break-glass-only custody is the deliberate opt-out on the Keys screen). Byte
// formats are identical to the console's in-browser ceremony
// (console/src/keygen.ts), and the custody story strengthens: the break-glass
// private key is born on the operator's machine during their own deploy and
// never transits a browser tab, the vendor, or the engine. The script writes:
//
//   <out>/identity.key          the break-glass PRIVATE key (KEEP OFFLINE)
//   <out>/recovery-sheet.txt    the printable sheet (fingerprints, custody notes)
//   <out>/recipient.pub         the break-glass PUBLIC key (safe to keep anywhere)
//   <out>/signer.pub            the signer PUBLIC key (safe to keep anywhere)
//   <out>/.staging/             the values deploy.sh pipes into
//                               `wrangler secret put`, deleted by deploy.sh
//                               immediately after the puts land
//
// With --operational-only it generates JUST the operational pair into .staging
// (the upgrade path for an engine deployed break-glass-only): new runs wrap to
// it from the next tick; runs sealed before it existed stay break-glass-only.
//
// The engine never sees identity.key. There is no upload path for it anywhere.

import { mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { webcrypto } from "node:crypto";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  webcrypto.getRandomValues(out);
  return out;
}

async function sha384Hex(data: Uint8Array): Promise<string> {
  const digest = await sha384(data);
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// makeRecipient generates one hybrid recipient: x25519 scalar(32) || ML-KEM-1024
// seed(64) private; x25519 pub(32) || ML-KEM ek(1568) public. Identical bytes to
// the console ceremony's makeRecipient, so the Go offline tool and the engine
// read it as-is.
async function makeRecipient(): Promise<{ identity: Uint8Array; recipientPublic: Uint8Array; fingerprint: string }> {
  const xk = x25519.keygen();
  const mlkemSeed = randomBytes(64);
  const ek = ml_kem1024.keygen(mlkemSeed).publicKey;
  const identity = concat(xk.secretKey, mlkemSeed);
  const recipientPublic = concat(xk.publicKey, ek);
  return { identity, recipientPublic, fingerprint: "dpr1:" + (await sha384Hex(recipientPublic)) };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2).filter((a) => a !== "");
  const operationalOnly = args.includes("--operational-only");
  const outDir = args.find((a) => !a.startsWith("--"));
  if (!outDir) {
    console.error("usage: node scripts/generate-keys.ts <output-directory> [--operational-only]");
    process.exit(2);
  }

  if (operationalOnly) {
    // The upgrade path: an engine deployed break-glass-only gains automated
    // restore proof. Only the staging values are written (nothing here is
    // user-held: both halves go to the engine).
    const op = await makeRecipient();
    const staging = join(outDir, ".staging");
    mkdirSync(staging, { recursive: true });
    writeFileSync(join(staging, "operational-public.b64"), b64urlEncode(op.recipientPublic), { mode: 0o600 });
    writeFileSync(join(staging, "operational-private.b64"), b64urlEncode(op.identity), { mode: 0o600 });
    console.log("operational pair generated (automated restore proof)");
    console.log(`  operational  ${op.fingerprint}`);
    console.log("  note: runs sealed BEFORE this key existed stay break-glass-only; new runs wrap to it.");
    return;
  }

  const bg = await makeRecipient();
  const identity = bg.identity;
  const recipientPublic = bg.recipientPublic;
  const recipientFingerprint = bg.fingerprint;

  // The operational read-back pair (default ON): the engine holds both halves so
  // it can verify its own archives continuously. Strict break-glass-only shops
  // opt out on the Keys screen, not here.
  const op = await makeRecipient();

  // The CONFIG recipient: generated unconditionally, in BOTH postures, because it is not a posture choice.
  // It opens this engine's own sealed configuration export and nothing else, so an engine that removes the
  // operational key can still auto-heal its configuration after a Durable Object wipe. Offering it as a
  // choice would only invite someone to turn off their own configuration recovery for no confidentiality
  // gain, since it cannot read an archive.
  const cfg = await makeRecipient();

  // The signer: ed25519 seed(32) || ML-DSA-87 seed(32) private (the engine derives
  // the expanded key); ed25519 pub(32) || ML-DSA public(2592) public.
  const edSeed = randomBytes(32);
  const edPub = ed25519.getPublicKey(edSeed);
  const mldsaSeed = randomBytes(32);
  const mldsa = ml_dsa87.keygen(mldsaSeed);
  const signerPrivate = concat(edSeed, mldsaSeed);
  const signerPublic = concat(edPub, mldsa.publicKey);
  const signerFingerprint = "edmldsa1:" + (await sha384Hex(signerPublic));

  const generatedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  const sheet = `DOWNPIPES RECOVERY SHEET
Generated ${generatedAt} by the deploy script, on this machine.

THE ONE RULE
  identity.key (in this folder) is the break-glass private key: the sole
  recovery path for every backup this engine ever writes. Move this folder
  to offline storage (an encrypted USB drive, a password manager, a safe)
  and remove it from this machine. There is no server-side copy.
  If you set a CONFIG_WRAP_KEY to encrypt destination credentials, keep a copy of
  it too, stored SEPARATELY from identity.key.

WHERE EACH KEY WENT
  Stayed on this machine:   identity.key, this sheet
  Went to your engine:      the signer private (signs every run),
                            the break-glass PUBLIC key (wraps, never unwraps),
                            the operational pair (lets the engine PROVE backups
                            restore: scheduled tests, drills, in-console restores)
  Went to the vendor:       nothing

POSTURE
  Automated restore proof: ON (the operational key). The engine can read its own
  archives to verify them; it can never read the break-glass key. For strict
  break-glass-only custody, re-run the ceremony on the Keys screen with the
  opt-out and remove the OPERATIONAL_* secrets.

PUBLIC FINGERPRINTS (safe to record anywhere)
  break-glass   ${recipientFingerprint}
  signer        ${signerFingerprint}
  operational   ${op.fingerprint}

ANTI-ROLLBACK
  Write the latest RUNLOG index here after each run you trust, and pass it to
  restore as --min-runlog-index. Leaving it blank leaves rollback protection off:
  a rollback to an older, validly signed run will not be detected.
  min-runlog-index: ____________

CUSTODY (record your choice)
  [ ] Corporate password manager
  [ ] Encrypted USB drive plus a printed companion
  [ ] M-of-N custodian split (run the Keys screen ceremony to set one up)
  Holder(s): ______________________________  Date: ____________

VERIFY A RESTORE WORKS BEFORE YOU NEED IT
  The console's Restore screen proves restorability without writing anything;
  the offline downpipe CLI reads archives with identity.key and signer.pub.

ENVIRONMENT RECOVERY (rebuild the setup, not just the data)
  To recover your downpipes, destinations and settings after losing your account:
  deploy a fresh engine, sign in as Owner, then in the console open Settings >
  Backup configuration > "Recover an estate from a signed export". Paste the signed
  export from _RECOVERY/CONTROL-PLANE/ in your bucket, its .sig, and signer.pub
  (this folder). The engine verifies against your signer key and imports the
  definition only; it grants NO operator access, so re-grant roles and reconnect
  identity providers by hand. Downpipes from a different account arrive disabled
  until you re-point each source.
`;

  mkdirSync(outDir, { recursive: true });
  const staging = join(outDir, ".staging");
  mkdirSync(staging, { recursive: true });

  writeFileSync(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(identity)}\n`, { mode: 0o600 });
  writeFileSync(join(outDir, "recovery-sheet.txt"), sheet);
  writeFileSync(join(outDir, "recipient.pub"), `downpipe-recipient-v1 ${b64urlEncode(recipientPublic)}\n`);
  writeFileSync(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(signerPublic)}\n`);
  // The values deploy.sh pipes straight into `wrangler secret put`, then deletes.
  writeFileSync(join(staging, "signer-private.b64"), b64urlEncode(signerPrivate), { mode: 0o600 });
  writeFileSync(join(staging, "break-glass-public.b64"), b64urlEncode(recipientPublic), { mode: 0o600 });
  writeFileSync(join(staging, "operational-public.b64"), b64urlEncode(op.recipientPublic), { mode: 0o600 });
  writeFileSync(join(staging, "operational-private.b64"), b64urlEncode(op.identity), { mode: 0o600 });
  writeFileSync(join(staging, "config-recipient-public.b64"), b64urlEncode(cfg.recipientPublic), { mode: 0o600 });
  writeFileSync(join(staging, "config-recipient-private.b64"), b64urlEncode(cfg.identity), { mode: 0o600 });
  chmodSync(outDir, 0o700);

  console.log(`keys generated in ${outDir}`);
  console.log(`  break-glass  ${recipientFingerprint}`);
  console.log(`  signer       ${signerFingerprint}`);
  console.log(`  operational  ${op.fingerprint} (automated restore proof: on)`);
}

void main();
