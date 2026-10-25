// ROLLBACK DEPLOY (shared by the standalone rollback, the settle auto-rollback and the ramp rollback).
// A rollback first deploys the recorded older version id. Cloudflare refuses that with code 10220 when a
// secret changed after that version was live. Only then does this module take the second route: it reads the
// older version's module, uploads it as a NEW version (the upload keeps the CURRENT bindings and secrets
// through keep_bindings), checks the transfer and the identity, and deploys the new version at 100%.
// The force flag is never sent: it would bring the older secret values back.
//
// PURE ORCHESTRATION over the injected driver, proven by validators with fakes. It throws an Error with a
// plain-words reason on any refusal; nothing is live until its last step.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { DeployDriver } from "./update-types.ts";
import { isSecretChangedRefusal, msg } from "./update-types.ts";

// RollbackIdentity names how the fetched older code was matched to the release the record says it is.
//   exact        the SHA-384 of the fetched bytes equals the recorded digest
//   build-stamp  the bytes differ but the module's build stamp names the recorded digest (a wrangler deploy)
//   not-checked  no digest is recorded for the target, so only the transfer check ran
export type RollbackIdentity = "exact" | "build-stamp" | "not-checked";

export const NOT_CHECKED_TEXT = "The identity of the prior code was not checked because no digest is recorded for that version.";

// RollbackDriver is the slice of DeployDriver a rollback uses. The upload and read-back members are optional
// so a driver that cannot take the second route still satisfies it; the second route then refuses plainly.
export type RollbackDriver = Pick<DeployDriver, "deployVersion"> & Partial<Pick<DeployDriver, "uploadVersion" | "fetchVersionModule">>;

export interface RollbackDeployResult {
  // liveVersion is the version id that is live after the deploy: the target itself, or the new version.
  liveVersion: string;
  usedFallback: boolean;
  identity?: RollbackIdentity;
  // liveSha384 is the SHA-384 of the code uploaded as the new version (present only on the second route).
  liveSha384?: string;
}

type Log = (step: string, ok: boolean, detail?: string) => void;

const MAIN_MODULE = "index.js";

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// containsAscii reports whether the ASCII text `needle` appears in `bytes` (a plain byte search, no decoding).
function containsAscii(bytes: Uint8Array, needle: string): boolean {
  const n = needle.length;
  const lower = (b: number): number => (b >= 65 && b <= 90 ? b + 32 : b);
  const want = Array.from(needle, (ch) => lower(ch.charCodeAt(0)));
  for (let i = 0; i + n <= bytes.length; i++) {
    let j = 0;
    while (j < n && lower(bytes[i + j]!) === want[j]) j++;
    if (j === n) return true;
  }
  return false;
}

// checkIdentity compares the fetched bytes with the recorded digest. Returns the identity, or null when the
// record names a digest that matches neither the bytes nor the build stamp.
function checkIdentity(bytes: Uint8Array, bytesSha384: string, recorded: string | undefined): RollbackIdentity | null {
  const want = (recorded ?? "").trim().toLowerCase();
  if (want === "") return "not-checked";
  if (bytesSha384 === want) return "exact";
  if (containsAscii(bytes, want)) return "build-stamp";
  return null;
}

// deployRollbackTarget makes `versionId` live, by the second route when Cloudflare answers 10220. Throws on
// any failure; the engine is unchanged in every thrown case.
export async function deployRollbackTarget(driver: RollbackDriver, versionId: string, recordedDigest: string | undefined, log: Log): Promise<RollbackDeployResult> {
  try {
    await driver.deployVersion(versionId);
    log("deploy-known-good", true, versionId);
    return { liveVersion: versionId, usedFallback: false };
  } catch (e) {
    // site-fault-waiver: src/admin/update-rollback-deploy.ts:deployRollbackTarget:catch:1 -- every refusal is logged here and rethrown unless it is the secret-changed refusal, which selects the second route below
    if (!isSecretChangedRefusal(e)) {
      log("deploy-known-good", false, msg(e));
      throw e;
    }
    log("deploy-known-good", false, "Cloudflare refused: a secret changed since that version was live");
  }
  log("secret-changed", true, "a secret changed since that version was live, so the prior code is uploaded as a new version that keeps the current secrets");

  if (typeof driver.fetchVersionModule !== "function" || typeof driver.uploadVersion !== "function") {
    throw new Error("a secret changed since that version was live and this deploy driver cannot upload the prior code as a new version; nothing was changed");
  }
  let fetched: Uint8Array;
  try {
    fetched = await driver.fetchVersionModule(versionId, MAIN_MODULE);
    log("fetch-prior-code", true, `${fetched.length} bytes`);
  } catch (e) {
    log("fetch-prior-code", false, msg(e));
    throw new Error(`a secret changed since that version was live and the prior code could not be read from Cloudflare (${msg(e)}); nothing was changed`);
  }
  const fetchedSha384 = hexEncode(await sha384(fetched));

  const identity = checkIdentity(fetched, fetchedSha384, recordedDigest);
  if (identity === null) {
    log("identity-check", false, "the recorded digest matches neither the bytes nor the build stamp");
    throw new Error("the prior code Cloudflare holds for that version is not the release the record says it is (its digest matches neither the bytes nor the build stamp); the rollback was refused and nothing was changed");
  }
  log("identity-check", true, identity === "not-checked" ? NOT_CHECKED_TEXT : identity);

  let newVersion: string;
  try {
    newVersion = await driver.uploadVersion(fetched, { version: versionId, mainModule: MAIN_MODULE });
    log("upload-prior-code", true, newVersion);
  } catch (e) {
    log("upload-prior-code", false, msg(e));
    throw new Error(`a secret changed since that version was live and the prior code could not be uploaded as a new version (${msg(e)}); the engine is unchanged`);
  }

  let readBack: Uint8Array;
  try {
    readBack = await driver.fetchVersionModule(newVersion, MAIN_MODULE);
  } catch (e) {
    log("transfer-check", false, msg(e));
    throw new Error(`the new version could not be read back to confirm the prior code arrived intact (${msg(e)}); nothing was made live`);
  }
  if (!sameBytes(fetched, readBack)) {
    log("transfer-check", false, "the bytes read back differ from the bytes fetched");
    throw new Error("the bytes Cloudflare holds for the new version differ from the prior code that was fetched; the rollback was refused and nothing was made live");
  }
  log("transfer-check", true, "the bytes read back equal the bytes fetched");

  try {
    await driver.deployVersion(newVersion);
    log("deploy-new-version", true, newVersion);
  } catch (e) {
    log("deploy-new-version", false, msg(e));
    throw new Error(`the prior code was uploaded as a new version but making it live failed (${msg(e)}); the previously-live version is still serving`);
  }
  return { liveVersion: newVersion, usedFallback: true, identity, liveSha384: fetchedSha384 };
}
