// Validates that the no-CLI key install gives a console-keyed engine the SAME key set a terminal-keyed engine
// gets: the configuration recovery pair (CONFIG_RECIPIENT_PUBLIC, CONFIG_RECIPIENT_PRIVATE) and the
// configuration wrap key (CONFIG_WRAP_KEY), as well as the signer, the break-glass public and, by choice, the
// operational pair. Before this, only the terminal ceremony (scripts/generate-keys.ts via deploy.sh) installed
// the three configuration keys. A console-keyed engine sealed its configuration export to break-glass only,
// auto-heal refused, and every console-stored credential sat on the Durable Object plaintext floor.
//
// What is graded:
//   1. installEngineSecrets PUTs all three configuration keys in BOTH postures, with the exact values sent, and
//      the recovery PRIVATE before its PUBLIC.
//   2. The installed pair is a working recipient (a capsule sealed to the public opens with the private), and
//      the installed wrap key wraps and unwraps a credential through the engine's own config-secret.ts.
//   3. VALIDATE BEFORE WRITE: a mismatched pair, a malformed wrap key and a missing configuration key are each
//      refused with ZERO network calls, tagged with the closed step and cause.
//   4. engineHolds: a key the engine already holds is KEPT, not replaced, on an install and on a confirmed
//      re-key through the real route.
//   5. POST /keys/add-config-recovery installs only what the engine lacks, and REFUSES (zero Cloudflare calls,
//      audited) to replace a key the engine already holds.
//   6. A partial recovery pair: a lone private is completed with the public derived from it (never the
//      request's new values), a lone public is refused with the recovery step, and a bound half is never
//      overwritten.
//   7. GET /admin/status reports the presence of the configuration keys, never a value, and reports the
//      recovery key as configured only when both halves are bound.
// No real network and no real deploy: a stubbed fetch records the PUTs.
// Run: node test/validate-keys-config-recovery.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { addConfigRecoverySecrets, installEngineSecrets, keyCeremonyFaultOf } from "../src/admin/attach.ts";
import { loadConfigWrapKey, unwrapConfigSecret, wrapConfigSecret } from "../src/admin/config-secret.ts";
import { buildStatus } from "../src/admin/status.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { decapsulateHybrid, encapsulateHybrid } from "../src/crypto/kem.ts";
import { loadIdentity, loadRecipientPublic } from "../src/keys-env.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A recipient pair in the exact encodings both ceremonies emit: private = x25519 scalar(32) || ML-KEM seed(64),
// public = x25519 public(32) || ML-KEM-1024 ek(1568). The public is DERIVED from the private here, as the
// ceremony does, so the pair matches.
function recipientPair(): { pub: string; priv: string } {
  const kp = x25519.keygen();
  const seed = randomBytes(64);
  return { pub: b64urlEncode(concat(kp.publicKey, ml_kem1024.keygen(seed).publicKey)), priv: b64urlEncode(concat(kp.secretKey, seed)) };
}

const edSeed = randomBytes(32);
const SIGNER_PRIVATE = b64urlEncode(concat(edSeed, randomBytes(32)));
const BREAK_GLASS = recipientPair();
const OPERATIONAL = recipientPair();
const CONFIG = recipientPair();
const OTHER = recipientPair();
const CONFIG_WRAP_KEY = b64urlEncode(randomBytes(32));
const TOKEN = "cfat-test-edit-workers-token-config-recovery";

const CFG = { configRecipientPublic: CONFIG.pub, configRecipientPrivate: CONFIG.priv, configWrapKey: CONFIG_WRAP_KEY };

interface Put { name: string; text: string }
function makeSecretsStub(): { fetch: typeof fetch; puts: Put[]; calls: string[] } {
  const puts: Put[] = [];
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push(`${method} ${url}`);
    if (method === "PUT" && /\/secrets$/.test(url)) {
      const parsed = JSON.parse(String(init?.body ?? "{}")) as { name?: string; text?: string };
      puts.push({ name: parsed.name ?? "", text: parsed.text ?? "" });
      return new Response(JSON.stringify({ success: true, result: { name: parsed.name } }), { status: 200 });
    }
    // Any secret DELETE succeeds: the two-recipient install clears OPERATIONAL_RETIRED, and the strict one
    // removes the operational pair (attach.ts removeOperationalSecrets).
    if (method === "DELETE" && /\/secrets\/[A-Z_]+$/.test(url)) return new Response(JSON.stringify({ success: true }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  return { fetch: fetchImpl, puts, calls };
}

function routeEnv(adminToken: string, extra: Record<string, unknown>): Env {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN: adminToken, WORKER_NAME: "downpipe-engine", ...extra } as unknown as Env;
}

// driveRoute POSTs one body to an admin route as the ADMIN_TOKEN owner, with the global fetch stubbed so the
// secret PUTs land in the recorder, then reads the audit feed back. Returns what a test needs to grade.
async function driveRoute(route: string, body: Record<string, unknown>, extra: Record<string, unknown>): Promise<{ status: number; body: string; puts: Put[]; cfCalls: string[]; audit: string }> {
  const ADMIN_TOKEN = `admin-${route.replace(/\W/g, "-")}`;
  const env = routeEnv(ADMIN_TOKEN, { CF_ACCOUNT_ID: "acct-config-recovery", ...extra });
  const stub = makeSecretsStub();
  const realFetch = globalThis.fetch;
  globalThis.fetch = stub.fetch;
  let status = 0;
  let text = "";
  let audit = "";
  try {
    const resp = await handleAdmin(new Request(`https://engine.example/admin${route}`, {
      method: "POST",
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    }), env);
    status = resp.status;
    text = await resp.text();
    const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { method: "GET", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
    audit = await auditResp.text();
  } finally {
    globalThis.fetch = realFetch;
  }
  return { status, body: text, puts: stub.puts, cfCalls: stub.calls.filter((c) => c.includes("api.cloudflare.com")), audit };
}

async function refusal(run: (f: typeof fetch) => Promise<unknown>): Promise<{ message: string; tag: ReturnType<typeof keyCeremonyFaultOf>; calls: number }> {
  const stub = makeSecretsStub();
  let caught: unknown = null;
  try { await run(stub.fetch); } catch (e) { caught = e; }
  return { message: caught instanceof Error ? caught.message : "", tag: keyCeremonyFaultOf(caught), calls: stub.calls.length };
}

async function main(): Promise<void> {
  console.log("-- installEngineSecrets: the configuration keys go in for BOTH postures --");
  for (const posture of ["break-glass-only", "two-recipient"] as const) {
    const stub = makeSecretsStub();
    const result = await installEngineSecrets("acct-cfg", "downpipe-engine", {
      token: TOKEN,
      signerPrivate: SIGNER_PRIVATE,
      breakGlassPublic: BREAK_GLASS.pub,
      ...(posture === "two-recipient" ? { operationalPublic: OPERATIONAL.pub, operationalPrivate: OPERATIONAL.priv } : {}),
      ...CFG,
    }, stub.fetch);
    const byName = new Map(stub.puts.map((p) => [p.name, p.text]));
    ok(`${posture}: CONFIG_RECIPIENT_PUBLIC is PUT with the value sent`, byName.get("CONFIG_RECIPIENT_PUBLIC") === CONFIG.pub);
    ok(`${posture}: CONFIG_RECIPIENT_PRIVATE is PUT with the value sent`, byName.get("CONFIG_RECIPIENT_PRIVATE") === CONFIG.priv);
    ok(`${posture}: CONFIG_WRAP_KEY is PUT with the value sent`, byName.get("CONFIG_WRAP_KEY") === CONFIG_WRAP_KEY);
    const names = stub.puts.map((p) => p.name);
    ok(`${posture}: the recovery PRIVATE is PUT before its PUBLIC (a failure between them seals nothing to a key the engine lacks)`, names.indexOf("CONFIG_RECIPIENT_PRIVATE") >= 0 && names.indexOf("CONFIG_RECIPIENT_PRIVATE") < names.indexOf("CONFIG_RECIPIENT_PUBLIC"));
    ok(`${posture}: the signer and the break-glass public are still PUT`, byName.get("SIGNER_PRIVATE") === SIGNER_PRIVATE && byName.get("BREAK_GLASS_PUBLIC") === BREAK_GLASS.pub);
    ok(`${posture}: the result reports both configuration keys as installed`, result.configured.configRecipient === "installed" && result.configured.configWrapKey === "installed");
  }

  console.log("\n-- the installed values are working keys, read by the engine's own loaders --");
  {
    const pub = loadRecipientPublic(CONFIG.pub);
    const priv = loadIdentity(CONFIG.priv);
    const enc = await encapsulateHybrid(pub);
    const dec = await decapsulateHybrid(priv, enc.cipherText);
    ok("a capsule sealed to CONFIG_RECIPIENT_PUBLIC opens with CONFIG_RECIPIENT_PRIVATE", b64urlEncode(dec) === b64urlEncode(enc.sharedSecret));
    const key = loadConfigWrapKey(CONFIG_WRAP_KEY);
    ok("CONFIG_WRAP_KEY loads as a 32-byte AES-256 key", key !== undefined && key.length === 32);
    const wrapped = await wrapConfigSecret(key as Uint8Array, "destination-secret-access-key");
    ok("a credential wrapped under CONFIG_WRAP_KEY unwraps to the same value", (await unwrapConfigSecret(key as Uint8Array, wrapped)) === "destination-secret-access-key");
  }

  console.log("\n-- installEngineSecrets: VALIDATE BEFORE WRITE for the configuration keys --");
  {
    const base = { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub };
    const mismatched = await refusal((f) => installEngineSecrets("acct-cfg", "downpipe-engine", { ...base, configRecipientPublic: OTHER.pub, configRecipientPrivate: CONFIG.priv, configWrapKey: CONFIG_WRAP_KEY }, f));
    ok("a pair whose private does not derive its public is refused", /does not match its public/.test(mismatched.message));
    ok("the mismatched pair made ZERO network calls", mismatched.calls === 0);
    ok("the mismatched pair is tagged {config-recipient-private, parse}", mismatched.tag?.step === "config-recipient-private" && mismatched.tag.cause === "parse");
    ok("the refusal carries no private value and no token", !mismatched.message.includes(CONFIG.priv) && !mismatched.message.includes(TOKEN));

    const shortKey = await refusal((f) => installEngineSecrets("acct-cfg", "downpipe-engine", { ...base, ...CFG, configWrapKey: b64urlEncode(randomBytes(16)) }, f));
    ok("a 16-byte wrap key is refused before any write", /configuration wrap key did not parse/.test(shortKey.message) && shortKey.calls === 0);
    ok("the short wrap key is tagged {config-wrap-key, parse}", shortKey.tag?.step === "config-wrap-key" && shortKey.tag.cause === "parse");

    const badPublic = await refusal((f) => installEngineSecrets("acct-cfg", "downpipe-engine", { ...base, ...CFG, configRecipientPublic: "deadbeef" }, f));
    ok("a malformed recovery public is refused before any write", /configuration recovery public did not parse/.test(badPublic.message) && badPublic.calls === 0);

    for (const field of ["configRecipientPublic", "configRecipientPrivate", "configWrapKey"] as const) {
      const missing = await refusal((f) => installEngineSecrets("acct-cfg", "downpipe-engine", { ...base, ...CFG, [field]: "" }, f));
      ok(`an install without ${field} is refused as missing, with no network call`, missing.tag?.cause === "missing" && missing.calls === 0);
    }
  }

  console.log("\n-- installEngineSecrets: a configuration key the engine already holds is KEPT --");
  {
    const stub = makeSecretsStub();
    const result = await installEngineSecrets("acct-cfg", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, ...CFG, engineHolds: { configRecipient: { held: "pair" }, configWrapKey: true } }, stub.fetch);
    ok("no configuration key is PUT when the engine holds both", !stub.puts.some((p) => p.name.startsWith("CONFIG_")));
    ok("the result reports both as kept", result.configured.configRecipient === "kept" && result.configured.configWrapKey === "kept");
    const kept = await refusal((f) => installEngineSecrets("acct-cfg", "downpipe-engine", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, ...CFG, configWrapKey: "not-a-key", engineHolds: { configRecipient: { held: "pair" }, configWrapKey: true } }, f));
    ok("a malformed value is still refused when the engine would keep its own key", kept.tag?.step === "config-wrap-key" && kept.calls === 0);
  }

  console.log("\n-- POST /keys/install: a confirmed re-key keeps the wrap key and recovery key the engine holds --");
  {
    const r = await driveRoute("/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, ...CFG, confirmRekey: true }, {
      SIGNER_PRIVATE: "sentinel-existing-signer",
      BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass",
      CONFIG_RECIPIENT_PUBLIC: "sentinel-existing-config-public",
      CONFIG_RECIPIENT_PRIVATE: "sentinel-existing-config-private",
      CONFIG_WRAP_KEY: "sentinel-existing-wrap-key",
    });
    ok("the confirmed re-key returns 200", r.status === 200);
    ok("the engine's existing CONFIG_WRAP_KEY is NOT replaced (a new one would make every wrapped credential unreadable)", !r.puts.some((p) => p.name === "CONFIG_WRAP_KEY"));
    ok("the engine's existing recovery pair is NOT replaced (a new one would strand earlier sealed exports)", !r.puts.some((p) => p.name.startsWith("CONFIG_RECIPIENT_")));
    ok("the response says both were kept", /"configRecipient":"kept"/.test(r.body) && /"configWrapKey":"kept"/.test(r.body));
    ok("the response carries no private value", !r.body.includes(CONFIG.priv) && !r.body.includes(CONFIG_WRAP_KEY) && !r.body.includes(SIGNER_PRIVATE));

    const fresh = await driveRoute("/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, ...CFG }, {});
    ok("a FIRST install on a fresh engine PUTs all three configuration keys", ["CONFIG_RECIPIENT_PRIVATE", "CONFIG_RECIPIENT_PUBLIC", "CONFIG_WRAP_KEY"].every((n) => fresh.puts.some((p) => p.name === n)));
    ok("the audit feed records the install and carries no configuration key value", /keys-installed/.test(fresh.audit) && !fresh.audit.includes(CONFIG.priv) && !fresh.audit.includes(CONFIG_WRAP_KEY));
  }

  console.log("\n-- POST /keys/add-config-recovery: adds what an already-keyed engine lacks, never replaces --");
  {
    const keyed = { SIGNER_PRIVATE: "sentinel-existing-signer", BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass" };
    const both = await driveRoute("/keys/add-config-recovery", { token: TOKEN, ...CFG }, keyed);
    ok("an engine with neither key gains both: 200", both.status === 200);
    ok("exactly the three configuration keys are PUT, and nothing else", both.puts.map((p) => p.name).join(",") === "CONFIG_RECIPIENT_PRIVATE,CONFIG_RECIPIENT_PUBLIC,CONFIG_WRAP_KEY");
    ok("the signer and the break-glass public are never written", !both.puts.some((p) => p.name === "SIGNER_PRIVATE" || p.name === "BREAK_GLASS_PUBLIC"));
    ok("the add is audited as config-recovery-added with no value in the trail", /config-recovery-added/.test(both.audit) && !both.audit.includes(CONFIG.priv) && !both.audit.includes(CONFIG_WRAP_KEY));
    ok("the response names the secrets set and carries no value", /CONFIG_WRAP_KEY/.test(both.body) && !both.body.includes(CONFIG.priv) && !both.body.includes(CONFIG_WRAP_KEY));

    const wrapOnly = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configWrapKey: CONFIG_WRAP_KEY }, { ...keyed, CONFIG_RECIPIENT_PUBLIC: CONFIG.pub, CONFIG_RECIPIENT_PRIVATE: CONFIG.priv });
    ok("an engine that lacks only the wrap key gains it alone", wrapOnly.status === 200 && wrapOnly.puts.map((p) => p.name).join(",") === "CONFIG_WRAP_KEY");

    const replaceRecipient = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv }, { ...keyed, CONFIG_RECIPIENT_PRIVATE: CONFIG.priv, CONFIG_RECIPIENT_PUBLIC: CONFIG.pub });
    ok("an add over an existing CONFIG_RECIPIENT_PRIVATE is REFUSED 400", replaceRecipient.status === 400 && /already holds the configuration recovery key/.test(replaceRecipient.body));
    ok("the refused add made ZERO Cloudflare calls", replaceRecipient.cfCalls.length === 0);
    ok("the refusal is audited as key-install-failed, cause already-configured", /key-install-failed/.test(replaceRecipient.audit) && /already-configured/.test(replaceRecipient.audit));

    const replaceWrap = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configWrapKey: CONFIG_WRAP_KEY }, { ...keyed, CONFIG_WRAP_KEY: "sentinel-existing-wrap-key" });
    ok("an add over an existing CONFIG_WRAP_KEY is REFUSED 400 with ZERO Cloudflare calls", replaceWrap.status === 400 && /already holds the configuration wrap key/.test(replaceWrap.body) && replaceWrap.cfCalls.length === 0);

    const half = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: CONFIG.pub }, keyed);
    ok("half a recovery pair is refused 400 with ZERO Cloudflare calls", half.status === 400 && /pair is incomplete/.test(half.body) && half.cfCalls.length === 0);

    const nothing = await refusal((f) => addConfigRecoverySecrets("acct-cfg", "downpipe-engine", TOKEN, {}, f));
    ok("an add with nothing to add is refused with no network call", /nothing to add/.test(nothing.message) && nothing.calls === 0);
    const mismatch = await refusal((f) => addConfigRecoverySecrets("acct-cfg", "downpipe-engine", TOKEN, { configRecipientPublic: OTHER.pub, configRecipientPrivate: CONFIG.priv }, f));
    ok("the add refuses a mismatched pair with no network call", /does not match its public/.test(mismatch.message) && mismatch.calls === 0);
  }

  // A PARTIAL recovery pair is one bound half without the other. A lone private is left when the public PUT
  // fails after the private PUT (attach.ts putConfigRecipient writes the private first). A lone public is left
  // when the private is removed, or when a terminal install stops between its two PUTs. Each case below uses
  // CONFIG as the half the engine holds and OTHER as the new pair the console sends.
  console.log("\n-- a partial recovery pair: a lone private is completed from itself, a lone public is refused --");
  {
    const keyed = { SIGNER_PRIVATE: "sentinel-existing-signer", BREAK_GLASS_PUBLIC: "sentinel-existing-break-glass" };
    const lonePrivate = { ...keyed, CONFIG_RECIPIENT_PRIVATE: CONFIG.priv, CONFIG_WRAP_KEY: "sentinel-existing-wrap-key" };
    const lonePublic = { ...keyed, CONFIG_RECIPIENT_PUBLIC: CONFIG.pub, CONFIG_WRAP_KEY: "sentinel-existing-wrap-key" };
    const recipientPuts = (puts: Put[]): Put[] => puts.filter((p) => p.name.startsWith("CONFIG_RECIPIENT_"));

    // CONFIG.pub is DERIVED from CONFIG.priv (recipientPair above), so it is the only correct public for the held
    // private. OTHER.pub is the request's new value, which must never be written for the recipient.
    const install = await driveRoute("/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv, configWrapKey: CONFIG_WRAP_KEY, confirmRekey: true }, lonePrivate);
    const installRecipient = recipientPuts(install.puts);
    ok("a retried install on a lone private returns 200", install.status === 200);
    ok("the install PUTs ONLY CONFIG_RECIPIENT_PUBLIC for the recipient", installRecipient.map((p) => p.name).join(",") === "CONFIG_RECIPIENT_PUBLIC");
    ok("the PUT public is the one derived from the held private, not the request's new public", installRecipient[0]?.text === CONFIG.pub && installRecipient[0]?.text !== OTHER.pub);
    ok("the bound CONFIG_RECIPIENT_PRIVATE is not overwritten", !install.puts.some((p) => p.name === "CONFIG_RECIPIENT_PRIVATE"));
    ok("the install answer says the recipient was repaired, not kept or installed", /"configRecipient":"repaired"/.test(install.body));

    const add = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv }, lonePrivate);
    ok("add-config-recovery on a lone private returns 200", add.status === 200);
    ok("the add PUTs exactly CONFIG_RECIPIENT_PUBLIC, derived from the held private", add.puts.map((p) => p.name).join(",") === "CONFIG_RECIPIENT_PUBLIC" && add.puts[0]?.text === CONFIG.pub);
    ok("the add answer says the recipient was repaired and names only the public", /"configRecipient":"repaired"/.test(add.body) && /"installed":\["CONFIG_RECIPIENT_PUBLIC"\]/.test(add.body));
    ok("the add answer carries no private value", !add.body.includes(CONFIG.priv) && !add.body.includes(OTHER.priv));

    const addBoth = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv, configWrapKey: CONFIG_WRAP_KEY }, { ...keyed, CONFIG_RECIPIENT_PRIVATE: CONFIG.priv });
    ok("a lone private and no wrap key: the derived public and the wrap key, nothing else", addBoth.status === 200 && addBoth.puts.map((p) => `${p.name}=${p.text === CONFIG.pub ? "derived" : p.text === CONFIG_WRAP_KEY ? "wrap" : "other"}`).join(",") === "CONFIG_RECIPIENT_PUBLIC=derived,CONFIG_WRAP_KEY=wrap");

    const badPrivate = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv }, { ...keyed, CONFIG_RECIPIENT_PRIVATE: "sentinel-not-a-key" });
    ok("a lone private that does not parse is refused 400 with ZERO Cloudflare calls", badPrivate.status === 400 && badPrivate.cfCalls.length === 0 && /does not parse/.test(badPrivate.body));

    const refused = await driveRoute("/keys/add-config-recovery", { token: TOKEN, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv }, lonePublic);
    ok("add-config-recovery on a lone public is REFUSED 400 with ZERO Cloudflare calls", refused.status === 400 && refused.cfCalls.length === 0);
    ok("the refusal says the engine holds the public without its private", /CONFIG_RECIPIENT_PUBLIC without its CONFIG_RECIPIENT_PRIVATE/.test(refused.body));
    ok("the refusal names the recovery step: delete the public in the Cloudflare dashboard, then add the keys again", /Cloudflare dashboard, delete the CONFIG_RECIPIENT_PUBLIC secret/.test(refused.body) && /then add the configuration keys again/.test(refused.body));
    ok("the refusal says the exports sealed to that public still open with break-glass", /still open with your break-glass identity\.key/.test(refused.body));
    ok("the refusal is audited as key-install-failed, cause already-configured", /key-install-failed/.test(refused.audit) && /already-configured/.test(refused.audit));

    const installOnPublic = await driveRoute("/keys/install", { token: TOKEN, signerPrivate: SIGNER_PRIVATE, breakGlassPublic: BREAK_GLASS.pub, configRecipientPublic: OTHER.pub, configRecipientPrivate: OTHER.priv, configWrapKey: CONFIG_WRAP_KEY, confirmRekey: true }, lonePublic);
    ok("a re-key on a lone public returns 200 and writes no CONFIG_RECIPIENT_* (the bound public is not overwritten)", installOnPublic.status === 200 && recipientPuts(installOnPublic.puts).length === 0);
    ok("the install answer says a partial pair was kept, not that the key is held", /"configRecipient":"kept-partial"/.test(installOnPublic.body));
  }

  console.log("\n-- GET /admin/status reports the configuration keys as presence only --");
  {
    const none = buildStatus({} as Env, 0);
    ok("an engine with neither key reports both absent", none.configKeysConfigured.recipient === false && none.configKeysConfigured.wrapKey === false);
    const all = buildStatus({ CONFIG_RECIPIENT_PRIVATE: CONFIG.priv, CONFIG_RECIPIENT_PUBLIC: CONFIG.pub, CONFIG_WRAP_KEY } as unknown as Env, 0);
    ok("an engine with both reports both present", all.configKeysConfigured.recipient === true && all.configKeysConfigured.wrapKey === true);
    const lonePrivate = buildStatus({ CONFIG_RECIPIENT_PRIVATE: CONFIG.priv } as unknown as Env, 0);
    ok("a lone private is NOT reported as a configured recovery key", lonePrivate.configKeysConfigured.recipient === false);
    ok("recipientHalves names the lone private", lonePrivate.configKeysConfigured.recipientHalves?.private === true && lonePrivate.configKeysConfigured.recipientHalves.public === false);
    const lonePublic = buildStatus({ CONFIG_RECIPIENT_PUBLIC: CONFIG.pub } as unknown as Env, 0);
    ok("a lone public is NOT reported as a configured recovery key, and recipientHalves names it", lonePublic.configKeysConfigured.recipient === false && lonePublic.configKeysConfigured.recipientHalves?.public === true && lonePublic.configKeysConfigured.recipientHalves.private === false);
    ok("a full pair reports both halves bound", all.configKeysConfigured.recipientHalves?.public === true && all.configKeysConfigured.recipientHalves.private === true);
    const text = JSON.stringify(all);
    ok("the status carries no configuration key value", !text.includes(CONFIG.priv) && !text.includes(CONFIG_WRAP_KEY));
  }

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nKEYS-CONFIG-RECOVERY PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
