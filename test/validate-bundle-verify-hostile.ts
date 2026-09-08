// Recovery-bundle verify: hostile-store defence-in-depth (recovery-redundancy, net-zero). Every archive carries a
// _RECOVERY/ bundle (offline recovery instructions + a SHA384SUMS over them + a detached hybrid signature over
// SHA384SUMS under the operator-pinned key). verifyBundle (bundle.ts) is the defence-in-depth path a recoverer
// relies on when using the bundle. validate-format-prims already covers the CRYPTO cases (happy path, a one-byte
// file tamper, a forged signature, the wrong signer). This covers what those do not: the security-critical
// ORDERING (the signature is verified BEFORE any SHA384SUMS line is enumerated, bundle.ts:94-95 -- so a hostile
// store cannot drive the get-loop with unsigned content) and the four parser throw sites that guard a
// validly-signed-but-hostile SHA384SUMS (a bug in the signer, or a compromised signing key):
//   - an undecodable .sig object is a MALFORMED SIGNATURE (typed integrity), never coarsened to an availability
//     "check your bucket" fault (G087);
//   - a list of more than MAX files is refused BEFORE any file is fetched (the get-loop is bounded);
//   - a line without the two-space separator is refused as malformed;
//   - a file name containing a slash ("../..") is refused as an invalid name BEFORE any store.get -- so the
//     bundle can never make the reader fetch an arbitrary / traversed path.
// Default-FAIL: each hostile bundle must be REFUSED with the specific reason; a clean control must verify. Net-zero:
// in-memory, harness-minted keys, no IO. Run: node test/validate-bundle-verify-hostile.ts
import { ab, b64urlEncode } from "../src/crypto/bytes.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { hybridSign, type HybridVerifier } from "../src/crypto/sign.ts";
import { BUNDLE_PREFIX, type ObjectStoreReader, verifyBundle } from "../src/format/bundle.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
async function sha384Hex(data: Uint8Array): Promise<string> {
  // ab() is the codebase's Web Crypto boundary narrowing (bytes.ts): every buffer here is ArrayBuffer-backed.
  const d = new Uint8Array(await crypto.subtle.digest("SHA-384", ab(data)));
  return Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("");
}
function storeOf(map: Map<string, Uint8Array>): ObjectStoreReader {
  return { get: async (k: string) => { const v = map.get(k); if (!v) throw new Error(`missing ${k}`); return v; } };
}

let assertions = 0;
let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  assertions++;
  console.log(cond ? `  ok   ${label}${detail ? ` (${detail})` : ""}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const verifier: HybridVerifier = { ed: edPublic, mldsa: mldsa.publicKey };

  // Build a bundle store: SHA384SUMS + a detached hybrid signature over it (signed by our key unless overridden)
  // + any listed files. sigTextOverride injects a corrupt .sig; signWith signs under a DIFFERENT key.
  async function bundle(
    sumsText: string,
    files: Record<string, Uint8Array>,
    opts: { sigTextOverride?: string; signWith?: { edPriv: CryptoKey; mldsaSecret: Uint8Array } } = {},
  ): Promise<ObjectStoreReader> {
    const sumsBytes = enc(sumsText);
    const map = new Map<string, Uint8Array>();
    map.set(`${BUNDLE_PREFIX}SHA384SUMS`, sumsBytes);
    let sigText: string;
    if (opts.sigTextOverride !== undefined) {
      sigText = opts.sigTextOverride;
    } else {
      const s = opts.signWith ?? { edPriv: ed.privateKey, mldsaSecret: mldsa.secretKey };
      sigText = b64urlEncode(await hybridSign(s.edPriv, s.mldsaSecret, sumsBytes));
    }
    map.set(`${BUNDLE_PREFIX}SHA384SUMS.sig`, enc(sigText));
    for (const [name, data] of Object.entries(files)) map.set(`${BUNDLE_PREFIX}${name}`, data);
    return storeOf(map);
  }

  async function refusal(fn: () => Promise<unknown>): Promise<string> {
    try { await fn(); return ""; } catch (e) { return e instanceof Error ? e.message : String(e); }
  }
  const HASH0 = "0".repeat(96); // a placeholder SHA-384 hex; the throw fires before the hash is ever compared

  // CONTROL: a valid, correctly-signed SHA384SUMS listing one real file with its true hash verifies clean.
  const fileA = enc("recovery instructions A");
  const goodSums = `${await sha384Hex(fileA)}  FORMAT.md\n`;
  const controlErr = await refusal(async () => verifyBundle(await bundle(goodSums, { "FORMAT.md": fileA }), verifier));
  ok("CONTROL: a valid, correctly-signed SHA384SUMS with a matching listed file verifies clean", controlErr === "", controlErr.slice(0, 60));

  // ORDERING (bundle.ts:94-95, security-critical): a MALFORMED SHA384SUMS signed by the WRONG key is refused at
  // the SIGNATURE gate, NOT the parser -- a hostile store cannot drive line enumeration with unsigned content.
  const otherEd = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const otherMldsa = mldsaKeygen();
  const orderErr = await refusal(async () => verifyBundle(await bundle("no-separator-here\n", {}, { signWith: { edPriv: otherEd.privateKey, mldsaSecret: otherMldsa.secretKey } }), verifier));
  ok("ORDERING: a malformed SHA384SUMS signed by the WRONG key is refused at the SIGNATURE gate (sig-before-parse), never reaching the parser", orderErr.toLowerCase().includes("did not verify"), orderErr.slice(0, 60));

  // MALFORMED SIG OBJECT (bundle.ts:88, G087): an undecodable .sig is a malformed SIGNATURE (typed integrity),
  // never a coarse availability "check your bucket credentials" fault.
  const sigErr = await refusal(async () => verifyBundle(await bundle(goodSums, { "FORMAT.md": fileA }, { sigTextOverride: "###not-base64url###" }), verifier));
  ok("MALFORMED SIG OBJECT: an undecodable .sig is refused as a malformed signature object (typed integrity, not an availability fault)", sigErr.toLowerCase().includes("signature object is malformed"), sigErr.slice(0, 60));

  // OVERSIZED LIST (bundle.ts:99): a validly-signed SHA384SUMS listing more than MAX files is refused BEFORE any
  // file is fetched, so a hostile bundle cannot drive an unbounded get loop.
  const manyLines = `${Array.from({ length: 11 }, (_, i) => `${HASH0}  file${i}.md`).join("\n")}\n`;
  const manyErr = await refusal(async () => verifyBundle(await bundle(manyLines, {}), verifier));
  ok("OVERSIZED LIST: a validly-signed SHA384SUMS listing >10 files is refused (the get loop is bounded)", manyErr.toLowerCase().includes("more than"), manyErr.slice(0, 60));

  // MALFORMED LINE (bundle.ts:104): a validly-signed line without the two-space separator is refused.
  const badLineErr = await refusal(async () => verifyBundle(await bundle(`${HASH0} FORMAT.md\n`, {}), verifier)); // ONE space
  ok("MALFORMED LINE: a validly-signed line without the two-space separator is refused as malformed", badLineErr.toLowerCase().includes("malformed sha384sums line"), badLineErr.slice(0, 60));

  // PATH TRAVERSAL (bundle.ts:108, BUNDLE_NAME_RE): a validly-signed SHA384SUMS listing a name with a slash is
  // refused as an invalid file name BEFORE any store.get -- the bundle can never make the reader fetch a traversed
  // or absolute path.
  const traversalErr = await refusal(async () => verifyBundle(await bundle(`${HASH0}  ../../etc/passwd\n`, {}), verifier));
  ok("PATH TRAVERSAL: a validly-signed name containing a slash (../..) is refused as an invalid file name (no arbitrary-path fetch)", traversalErr.toLowerCase().includes("invalid file name"), traversalErr.slice(0, 60));

  console.log(failures === 0
    ? `\nBUNDLE-VERIFY HOSTILE-STORE OK: the signature is enforced BEFORE any line is enumerated, and a validly-signed-but-hostile SHA384SUMS is refused per parser gate (malformed sig / oversized / malformed line / path-traversal name) -- defence-in-depth holds. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("BUNDLE-VERIFY-HOSTILE FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
