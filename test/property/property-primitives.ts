// Property-based tests for the crypto PRIMITIVES (src/crypto/primitives.ts): the seal's core. These properties
// pin the behaviour that matters for a backup tool: AES-256-GCM round-trips and REJECTS any tamper / wrong key /
// wrong AAD / wrong nonce length; the 16-byte tag is appended; AAD is bound and an empty AAD equals no AAD;
// HKDF-SHA-384 is deterministic, returns exactly n bytes and is salt/info sensitive; HMAC-SHA-384 is
// deterministic, 48 bytes and key sensitive; SHA-384 is 48 bytes, deterministic and avalanches.
// Run: node test/property/property-primitives.ts
import fc from "fast-check";

import { aesGcmOpen, aesGcmSeal, hkdfSha384, hmacSha384, sha384 } from "../../src/crypto/primitives.ts";

let failures = 0;

async function prop(label: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ok   ${label}`);
  } catch (e) {
    console.log(`  FAIL ${label}: ${(e as Error).message}`);
    failures++;
  }
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function flip(x: Uint8Array, i: number): Uint8Array {
  const c = Uint8Array.from(x);
  c[i] = (c[i]! ^ 1) & 0xff;
  return c;
}

const bytes = fc.uint8Array({ minLength: 0, maxLength: 300 });
const nonEmpty = fc.uint8Array({ minLength: 1, maxLength: 200 });
const key32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
const nonce12 = fc.uint8Array({ minLength: 12, maxLength: 12 });

async function main(): Promise<void> {
  console.log("crypto primitives property vectors (fast-check)");

  await prop("sha384 is 48 bytes and deterministic", async () => {
    await fc.assert(
      fc.asyncProperty(bytes, async (x) => {
        const a = await sha384(x);
        const b = await sha384(Uint8Array.from(x));
        return a.length === 48 && eq(a, b);
      }),
      { numRuns: 40 },
    );
  });

  await prop("sha384 avalanches on a one-byte change", async () => {
    await fc.assert(
      fc.asyncProperty(nonEmpty, async (x) => {
        const a = await sha384(x);
        const b = await sha384(flip(x, 0));
        return !eq(a, b);
      }),
      { numRuns: 30 },
    );
  });

  await prop("aesGcm round-trips and appends a 16-byte tag", async () => {
    await fc.assert(
      fc.asyncProperty(key32, nonce12, bytes, fc.option(bytes, { nil: undefined }), async (k, n, pt, aad) => {
        const sealed = await aesGcmSeal(k, n, pt, aad);
        const opened = await aesGcmOpen(k, n, sealed, aad);
        return eq(opened, pt) && sealed.length === pt.length + 16;
      }),
      { numRuns: 50 },
    );
  });

  await prop("aesGcmOpen REJECTS any tampered byte (ciphertext or tag)", async () => {
    await fc.assert(
      fc.asyncProperty(key32, nonce12, nonEmpty, fc.nat(), async (k, n, pt, r) => {
        const sealed = await aesGcmSeal(k, n, pt, undefined);
        const bad = flip(sealed, r % sealed.length);
        try {
          await aesGcmOpen(k, n, bad, undefined);
          return false;
        } catch {
          return true;
        }
      }),
      { numRuns: 40 },
    );
  });

  await prop("aesGcmOpen REJECTS a wrong AAD (the AAD is bound)", async () => {
    await fc.assert(
      fc.asyncProperty(key32, nonce12, bytes, nonEmpty, async (k, n, pt, aad) => {
        const sealed = await aesGcmSeal(k, n, pt, aad);
        try {
          await aesGcmOpen(k, n, sealed, flip(aad, 0));
          return false;
        } catch {
          return true;
        }
      }),
      { numRuns: 30 },
    );
  });

  await prop("an empty AAD equals no AAD (both omit additionalData)", async () => {
    await fc.assert(
      fc.asyncProperty(key32, nonce12, bytes, async (k, n, pt) => {
        const sealedEmpty = await aesGcmSeal(k, n, pt, new Uint8Array(0));
        const openedUndef = await aesGcmOpen(k, n, sealedEmpty, undefined);
        return eq(openedUndef, pt);
      }),
      { numRuns: 20 },
    );
  });

  await prop("aesGcmOpen REJECTS a wrong key", async () => {
    await fc.assert(
      fc.asyncProperty(key32, key32, nonce12, bytes, async (k1, k2, n, pt) => {
        if (eq(k1, k2)) return true; // the (astronomically unlikely) equal-key draw is vacuously fine
        const sealed = await aesGcmSeal(k1, n, pt, undefined);
        try {
          await aesGcmOpen(k2, n, sealed, undefined);
          return false;
        } catch {
          return true;
        }
      }),
      { numRuns: 30 },
    );
  });

  await prop("aesGcm rejects a nonce that is not 12 bytes", async () => {
    await fc.assert(
      fc.asyncProperty(key32, fc.oneof(fc.uint8Array({ minLength: 0, maxLength: 11 }), fc.uint8Array({ minLength: 13, maxLength: 24 })), bytes, async (k, n, pt) => {
        let sealThrew = false;
        try {
          await aesGcmSeal(k, n, pt, undefined);
        } catch {
          sealThrew = true;
        }
        return sealThrew;
      }),
      { numRuns: 20 },
    );
  });

  await prop("hkdfSha384 is deterministic and returns exactly n bytes", async () => {
    await fc.assert(
      fc.asyncProperty(bytes, bytes, bytes, fc.integer({ min: 1, max: 96 }), async (ikm, salt, info, n) => {
        const a = await hkdfSha384(ikm, salt, info, n);
        const b = await hkdfSha384(Uint8Array.from(ikm), Uint8Array.from(salt), Uint8Array.from(info), n);
        return a.length === n && eq(a, b);
      }),
      { numRuns: 40 },
    );
  });

  await prop("hkdfSha384 output changes when the salt or info changes", async () => {
    await fc.assert(
      fc.asyncProperty(nonEmpty, fc.uint8Array({ minLength: 1, maxLength: 32 }), async (ikm, salt) => {
        const a = await hkdfSha384(ikm, salt, Uint8Array.from([1]), 48);
        const b = await hkdfSha384(ikm, flip(salt, 0), Uint8Array.from([1]), 48);
        const c = await hkdfSha384(ikm, salt, Uint8Array.from([2]), 48);
        return !eq(a, b) && !eq(a, c);
      }),
      { numRuns: 30 },
    );
  });

  await prop("hmacSha384 is deterministic, 48 bytes and key-sensitive", async () => {
    await fc.assert(
      fc.asyncProperty(nonEmpty, bytes, async (key, msg) => {
        const a = await hmacSha384(key, msg);
        const b = await hmacSha384(Uint8Array.from(key), Uint8Array.from(msg));
        if (a.length !== 48 || !eq(a, b)) return false;
        return !eq(a, await hmacSha384(flip(key, 0), msg));
      }),
      { numRuns: 30 },
    );
  });

  console.log(failures === 0 ? "\nall crypto primitives property vectors passed" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
