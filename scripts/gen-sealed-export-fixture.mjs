// Generates the CROSS-IMPL conformance fixture for the sealed control-plane export: the engine (TypeScript)
// seals a known inner export to a known break-glass identity and signs the canonical sealed bytes; the Go
// reader's unseal-export test opens this exact fixture and checks the recovered inner. This is the byte-for-byte
// agreement gate that keeps a sealing bug from bricking recovery. Run from the engine root:
//   node scripts/gen-sealed-export-fixture.mjs <out-dir>
// It writes: sealed.json (the canonical signed bytes), sealed.json.sig, identity.key + signer.pub (labelled
// kit files the Go reader parses), and expected-inner.json (the inner export the Go side must recover).
//
// An optional second argument seals to an EXISTING identity.key instead of a fresh random one:
//   node scripts/gen-sealed-export-fixture.mjs <out-dir> [identity.key]
// That exists so the Go side can hold a sealed export whose recipient is the same break-glass key its
// custody fixture holds as Shamir shares, which is what lets it prove unseal-export works from a quorum
// end to end rather than only proving the flags parse. Without the argument this behaves exactly as it did,
// so regenerating the conformance fixture is unchanged.

import { readFileSync, writeFileSync } from "node:fs";
import { sealControlPlaneExport, signSealedControlPlaneExport, serialiseSealedControlPlaneExport } from "../src/admin/control-plane-seal.ts";
import { serialiseControlPlaneExport } from "../src/admin/control-plane.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { concat, b64urlEncode, b64urlDecode } from "../src/crypto/bytes.ts";
import { LABEL_IDENTITY, LABEL_SIGNER_PUBLIC } from "../src/crypto/keys.ts";

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node scripts/gen-sealed-export-fixture.mjs <out-dir> [identity.key]");
  process.exit(1);
}

// One break-glass recipient: x25519 scalar(32) || ML-KEM seed(64) private (the identity.key payload), and its
// public (x25519 pub(32) || ML-KEM ek(1568)) to seal to.
const identityIn = process.argv[3];
let identityBytes;
if (identityIn) {
  const text = readFileSync(identityIn, "utf8").trim();
  const [label, payload] = text.split(/\s+/, 2);
  if (label !== LABEL_IDENTITY || !payload) {
    console.error(`${identityIn} is not a ${LABEL_IDENTITY} file`);
    process.exit(1);
  }
  identityBytes = b64urlDecode(payload);
  if (identityBytes.length !== 96) {
    console.error(`${identityIn} carries ${identityBytes.length} bytes, not the 96 an identity.key holds`);
    process.exit(1);
  }
} else {
  identityBytes = concat(crypto.getRandomValues(new Uint8Array(32)), crypto.getRandomValues(new Uint8Array(64)));
}
const x25519Scalar = identityBytes.slice(0, 32);
const mlkemSeed = identityBytes.slice(32);
const breakGlassPub = { x25519: x25519PublicFromScalar(x25519Scalar), mlkemEk: mlkemKeygen(mlkemSeed).encapKey };

// One signer, and its public (signer.pub = ed(32) || ML-DSA(2592)).
const signer = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
const v = verifierFrom(signer);
const signerPublic = concat(v.ed, v.mldsa); // 2624 bytes

// A known inner export exercising every carried field class (downpipes, destinations with a wrapped-or-
// reestablish secret, roles, the IdP + notify inventories, discovery, org policy, reestablish list).
const inner = {
  v: 1,
  exportedAt: "2026-07-05T12:00:00.000Z",
  configVersion: 42,
  configContentHash: "sha384:fixturehash",
  engineAccountId: "acct-fixture-source",
  priorAuditHead: { headSeq: 9, headHash: "sha384:fixturehead" },
  downpipes: [{ id: "dp-fixture", name: "prod-kv-backup", cadenceSeconds: 3600, enabled: true }],
  destinations: [{ id: "dest-r2", label: "R2 primary", endpoint: "https://acct.r2.cloudflarestorage.com", bucket: "backups", region: "auto", accessKeyId: "AKIAFIXTURE", secret: { reestablish: true }, setAt: 1, setBy: "owner@fixture.example", verifiedAt: 1, deleteProbe: "ok" }],
  defaultDestinationId: "dest-r2",
  roles: [{ subject: "oidc:conn|https://idp.fixture/x|sub1", email: "owner@fixture.example", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-07-05T00:00:00.000Z" }],
  groupRoles: [],
  customRoles: [],
  idpConnections: [{ id: "okta-fixture", kind: "oidc", label: "Okta", presetId: "okta", enabled: true, identity: "https://acme.okta.com", clientId: "0oaFixture", secretReestablish: true }],
  notifyChannels: [{ id: "ch-slack", kind: "webhook", name: "SIEM webhook", enabled: true, urlConfigured: true, urlHost: "hooks.example.com", routingKeyConfigured: false, toAddresses: [], secretReestablish: true }],
  notifyRules: [{ id: "rule-fail", scope: "global", minSeverity: "warning", events: ["all"], channelIds: ["ch-slack"], digest: "off", enabled: true }],
  discovery: { setAt: 1, setBy: "owner@fixture.example", accountsSeen: [{ id: "acct-fixture-source", name: "Acme" }], selected: ["acct-fixture-source"], engineAccountId: "acct-fixture-source", tokenReestablish: true },
  orgPolicy: { requireConfigApproval: true },
  reestablish: ["destination-credentials", "discovery-token", "idp-secrets", "notify-routing-secrets", "session-keys", "passkeys"],
};

const nonceFor = () => crypto.getRandomValues(new Uint8Array(16));
const sealed = await sealControlPlaneExport(inner, [{ role: "break-glass", pub: breakGlassPub }], nonceFor);

// sign-what-you-write: the .sig is over the EXACT canonical bytes written to sealed.json, so the Go reader
// verifies over the raw file bytes (no cross-impl canonicalisation), mirroring VerifyRootBytes for archives.
const sealedBytes = serialiseSealedControlPlaneExport(sealed);
const sig = await signSealedControlPlaneExport(signer, sealed);

writeFileSync(`${outDir}/sealed.json`, sealedBytes);
writeFileSync(`${outDir}/sealed.json.sig`, sig);
writeFileSync(`${outDir}/identity.key`, `${LABEL_IDENTITY} ${b64urlEncode(identityBytes)}\n`);
writeFileSync(`${outDir}/signer.pub`, `${LABEL_SIGNER_PUBLIC} ${b64urlEncode(signerPublic)}\n`);
writeFileSync(`${outDir}/expected-inner.json`, serialiseControlPlaneExport(inner));

console.log(`fixture written to ${outDir}: sealed.json (${sealedBytes.length}B), sealed.json.sig, identity.key, signer.pub, expected-inner.json`);
console.log(`recipients: ${sealed.recipients.map((r) => `${r.role} ${r.fingerprint.slice(0, 20)}...`).join(", ")}`);
