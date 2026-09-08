// Validates the at-rest configuration-secret envelope (src/admin/config-secret.ts): the AES-256-GCM
// wrap/unwrap round-trip, legacy plaintext pass-through (so an existing destination keeps working
// before migration), fail-loud when an envelope is present but no key is configured, tamper and
// wrong-key rejection, and the loadConfigWrapKey parsing. No network. Run: node test/validate-config-secret.ts.

import {
  DISCOVERY_SECRET_AAD,
  loadConfigWrapKey,
  wrapConfigSecret,
  unwrapConfigSecret,
  canOpenConfigSecret,
  isWrappedSecret,
  maybeWrapConfigSecret,
  resolveConfigSecret,
} from "../src/admin/config-secret.ts";
import { resolveDiscoveryTokenDetailed } from "../src/admin/router-helpers.ts";
import { b64urlEncode, b64urlDecode } from "../src/crypto/bytes.ts";
import { fetchDestConfig } from "../src/dest/factory.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
async function throwsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    ok(label, false);
  } catch {
    ok(label, true);
  }
}
function throwsSync(label: string, fn: () => unknown): void {
  try {
    fn();
    ok(label, false);
  } catch {
    ok(label, true);
  }
}

const KEY = crypto.getRandomValues(new Uint8Array(32));
const KEY_B64 = b64urlEncode(KEY);
const SECRET = "AKIAEXAMPLE/sUp3r+s3cr3t=key-with-symbols";

console.log("config-secret: loadConfigWrapKey");
ok("undefined => undefined (back-compat floor)", loadConfigWrapKey(undefined) === undefined);
ok("empty string => undefined", loadConfigWrapKey("   ") === undefined);
ok("valid 32-byte b64url => 32 bytes", loadConfigWrapKey(KEY_B64)?.length === 32);
throwsSync("wrong-length key fails loud", () => loadConfigWrapKey(b64urlEncode(new Uint8Array(16))));

console.log("config-secret: shape detection");
const env = await wrapConfigSecret(KEY, SECRET);
ok("wrap produces a v1 envelope", isWrappedSecret(env) && env.v === 1);
ok("isWrappedSecret rejects a plaintext string", !isWrappedSecret(SECRET));
ok("isWrappedSecret rejects null", !isWrappedSecret(null));
ok("isWrappedSecret rejects a partial object", !isWrappedSecret({ v: 1, iv: "x" }));

console.log("config-secret: round-trip + resolve");
ok("unwrap recovers the exact secret", (await unwrapConfigSecret(KEY, env)) === SECRET);

console.log("config-secret: canOpenConfigSecret (verdict-only probe twin)");
// The support pack's wrap-key health probe needs ONLY the verdict; this twin never decodes plaintext to a
// string and zero-fills the transient buffer, so a probe path cannot retain or surface the secret.
ok("the right key opens (true) without exposing a value", (await canOpenConfigSecret(KEY, env)) === true);
{
  const KEY_OTHER = crypto.getRandomValues(new Uint8Array(32));
  ok("a rotated/wrong key reports false (never throws)", (await canOpenConfigSecret(KEY_OTHER, env)) === false);
  const corrupt = b64urlDecode(env.ct);
  corrupt[0]! ^= 0xff;
  ok("a tampered ciphertext reports false (never throws)", (await canOpenConfigSecret(KEY, { ...env, ct: b64urlEncode(corrupt) })) === false);
  ok("an undecodable envelope reports false (never throws)", (await canOpenConfigSecret(KEY, { ...env, iv: "!!not-base64url!!" })) === false);
  ok("the verdict-only open leaves the envelope intact for the real read path", (await unwrapConfigSecret(KEY, env)) === SECRET);
}

ok("resolve passes a legacy plaintext through unchanged", (await resolveConfigSecret(KEY, "plain-legacy")) === "plain-legacy");
ok("resolve unwraps an envelope", (await resolveConfigSecret(KEY, env)) === SECRET);
await throwsAsync("resolve THROWS on an envelope with no key (fail-loud)", async () => resolveConfigSecret(undefined, env));
// A present-but-WRONG key (CONFIG_WRAP_KEY rotated after the credential was wrapped) is named as a rotation,
// not surfaced as a raw AEAD/decrypt error, so the operator restores the prior key rather than chasing a tag
// failure. The envelope is well-formed, so this is the rotated-key path, not the malformed-envelope path.
{
  const rotatedKey = crypto.getRandomValues(new Uint8Array(32));
  let rotMsg = "";
  try { await resolveConfigSecret(rotatedKey, env); } catch (e) { rotMsg = (e as Error).message; }
  ok("resolve names a CONFIG_WRAP_KEY rotation on a wrong key (not a raw decrypt error)", /CONFIG_WRAP_KEY does not decrypt|most likely rotated/.test(rotMsg));
}

console.log("config-secret: maybeWrap (the write ingress)");
ok("no key => plaintext floor (unchanged)", (await maybeWrapConfigSecret(undefined, SECRET)) === SECRET);
const wrapped = await maybeWrapConfigSecret(KEY, SECRET);
ok("with key => envelope", isWrappedSecret(wrapped));

console.log("config-secret: integrity");
const flipped = b64urlDecode(env.ct);
flipped[0] = flipped[0]! ^ 0xff;
await throwsAsync("a tampered ciphertext is rejected (GCM tag)", async () => unwrapConfigSecret(KEY, { ...env, ct: b64urlEncode(flipped) }));
const KEY2 = crypto.getRandomValues(new Uint8Array(32));
await throwsAsync("the wrong key is rejected", async () => unwrapConfigSecret(KEY2, env));
ok("two wraps of the same secret differ (random nonce)", (await wrapConfigSecret(KEY, SECRET)).iv !== (await wrapConfigSecret(KEY, SECRET)).iv);

console.log("config-secret: end-to-end through fetchDestConfig (the run path's read)");
// A minimal DurableObjectStub whose /dest-config GET returns the given stored config, so we exercise
// the exact read+unwrap path a run, drill or restore takes (no network).
const stubReturning = (config: unknown): DurableObjectStub =>
  ({ fetch: async () => new Response(JSON.stringify({ config }), { status: 200, headers: { "content-type": "application/json" } }) }) as unknown as DurableObjectStub;
const baseCfg = { endpoint: "https://s3.example.com", bucket: "archive", region: "auto", accessKeyId: "AKIAEXAMPLE" };

const wrappedStored = await wrapConfigSecret(KEY, SECRET);
const r1 = await fetchDestConfig(stubReturning({ ...baseCfg, secretAccessKey: wrappedStored }), null, KEY);
ok("fetchDestConfig unwraps a stored envelope to the plaintext credential", r1?.secretAccessKey === SECRET);
const r2 = await fetchDestConfig(stubReturning({ ...baseCfg, secretAccessKey: "legacy-plain-key" }), null, undefined);
ok("fetchDestConfig returns a legacy plaintext credential unchanged", r2?.secretAccessKey === "legacy-plain-key");
await throwsAsync("fetchDestConfig fails loud on an envelope with no key configured", async () =>
  fetchDestConfig(stubReturning({ ...baseCfg, secretAccessKey: await wrapConfigSecret(KEY, SECRET) }), null, undefined),
);

console.log("config-secret: the Cloudflare discovery token at rest");
// The discovery token was the LAST credential class stored in the clear: the DO held the raw string
// while every other secret here was sealed, so a Durable Object storage read yielded a live
// estate-wide credential. These cases pin the seventh sibling AAD and the read path that opens it.
const CF_TOKEN = "cf-test-token-value-1234567890abcdef";
const discEnv = await wrapConfigSecret(KEY, CF_TOKEN, DISCOVERY_SECRET_AAD);
ok("a discovery token round-trips under its own AAD", (await unwrapConfigSecret(KEY, discEnv, DISCOVERY_SECRET_AAD)) === CF_TOKEN);
await throwsAsync("a discovery envelope does NOT open as a destination credential", async () => unwrapConfigSecret(KEY, discEnv));
const destEnv = await wrapConfigSecret(KEY, CF_TOKEN);
await throwsAsync("a destination envelope does NOT open as a discovery token", async () => unwrapConfigSecret(KEY, destEnv, DISCOVERY_SECRET_AAD));

// The run path's actual read: resolveDiscoveryTokenDetailed over a stub DO.
const discStub = (config: unknown): DurableObjectStub =>
  ({ fetch: async () => new Response(JSON.stringify({ config }), { status: 200, headers: { "content-type": "application/json" } }) }) as unknown as DurableObjectStub;
const wrapKeyB64 = b64urlEncode(KEY);
const d1 = await resolveDiscoveryTokenDetailed(discStub({ token: discEnv }), { CONFIG_WRAP_KEY: wrapKeyB64 } as never);
ok("resolveDiscoveryTokenDetailed unwraps a sealed token", d1.token === CF_TOKEN && d1.doFault === false);
const d2 = await resolveDiscoveryTokenDetailed(discStub({ token: CF_TOKEN }), {} as never);
ok("resolveDiscoveryTokenDetailed returns a legacy plaintext token unchanged", d2.token === CF_TOKEN);
const d3 = await resolveDiscoveryTokenDetailed(discStub({ token: discEnv }), {} as never);
ok("a sealed token with NO wrap key reports a fault, never a silent no-token", d3.token === null && d3.doFault === true);

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-config-secret (${failures} failure(s))`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
