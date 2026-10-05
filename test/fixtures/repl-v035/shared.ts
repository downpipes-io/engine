// What the 0.3.5 replication fixture's generator and its validator share: the release commit it was built
// from, the S3 endpoint its destinations name, and the run signer, derived from a fixed label so the fixture
// carries no key. The signer is a test key and signs nothing outside these fixture buckets.

import { b64urlEncode, utf8 } from "../../../src/crypto/bytes.ts";

export const V035_COMMIT = "6a093886";
export const V035_FIXTURE_ENDPOINT = "https://s3.example.test";

// fixtureSigner returns the SIGNER_PRIVATE value (64 bytes, base64url) both files load.
export async function fixtureSigner(): Promise<string> {
  const seed = new Uint8Array(await crypto.subtle.digest("SHA-512", utf8("downpipes repl-v035 fixture signer")));
  return b64urlEncode(seed);
}
