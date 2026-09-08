// Journey: a cf-config restore driven with a token that is merely TOO NARROW must not report success, and
// its receipt must not hash like a clean one.
//
// THE DEFECT THIS CLOSES
// ----------------------
// The cf-config write path is fail-open per ITEM: an item Cloudflare rejects skips ITSELF and the rest of the
// surface still applies. That is right, and each refusal is classified at the skip site (cf-config-write.ts
// via classifyCfWriteSkip). Those classified skips reached `configApplied` and stopped there. They never
// reached `failures`, so `ok` and `complete` stayed true; and they were not in `result.skipped` either, so the
// receipt's recordsSkipped did not count them. The cf-config leg never fed the receipt's record list at all,
// so `allVerified` was computed over a record set holding none of the surfaces and came back VACUOUSLY true.
//
// The two ways a token can be wrong were treated oppositely, and the safer-looking one was the unsafe one.
// Supplying NO token leaves the surface OUT OF BAND, where it is reported and counted. Supplying a token that
// is merely too NARROW puts the surface in the plan, where every item is attempted and refused 401/403, and it
// was counted NOWHERE. An apply that wrote nothing returned ok:true, allVerified:true, no failures, no skipped
// count, and a receipt whose digest was IDENTICAL to a clean one.
//
// It is on the restore path, so the customer is already in trouble when they reach it; it is reachable from
// the console restore form, which asks for exactly this second edit-scoped token; and the receipt is the
// artefact the customer keeps as evidence, so the failure was not merely silent, it was attested.
//
// WHAT IS PROVEN HERE, over the REAL runRestore handler and a signed in-memory archive:
//   - a narrow-token apply reports ok:false and complete:false, with a named cf-config-surface failure whose
//     reason carries the count and the remedy;
//   - the receipt carries the surface as a record with verified:false, so allVerified is false;
//   - the receipt's summary carries the closed skip CLASS, so auth is distinguishable from quota;
//   - the refused receipt's digest DIFFERS from the clean one's with everything else held equal;
//   - THE COUNTERFACTUAL: reconstruct the receipt the OLD code would have built for that same refused apply
//     (no cf-config record, no class counts) and it hashes IDENTICALLY to the clean receipt. That is the
//     defect itself, reproduced from live results rather than described, and the direct proof that the fields
//     added here are the only thing separating the two outcomes;
//   - `entitlement` is NOT treated as a failure, because a plan that does not carry the surface leaves nothing
//     to restore. Without this the fix would redden restores that are complete with respect to the account;
//   - a clean cf-config apply still reports ok:true and carries no class counts at all.
//
// Run: node test/validate-restore-underscoped-token.ts   In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { runRestore } from "../src/admin/restore.ts";
import { restoreReceiptDigestHex } from "../src/admin/restore.ts";
import type { RestoreReceipt, RestoreResult } from "../src/admin/restore-types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";

const RUN = "01ARZ3NDEKTSV4RRFFQ69G5CB1";
const NS = "ns_narrow";
const ORIGIN = "acct-origin";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

class MockKV {
  store = new Map<string, Uint8Array>();
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> { this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v)); }
  async get(k: string): Promise<ArrayBuffer | null> { const v = this.store.get(k); return v ? toAB(v) : null; }
}
class MockR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> { const v = this.store.get(key); return v ? { etag: `"${key.length}"` } : null; }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> { this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body)); return { etag: `"${key.length}"` }; }
}

// cfDouble: an EMPTY live zone, so every snapshot item is a CREATE. `refuseWith` is the message the write
// throws, in the shape the real CfApi throws (the prefix the skip site strips, then Cloudflare's own text).
// Passing undefined gives the clean double that accepts every write.
function cfDouble(refuseWith?: string): { api: CfApi; sent: Array<{ method: string; path: string }> } {
  const sent: Array<{ method: string; path: string }> = [];
  const api: CfApi = {
    get: async () => [],
    getPage: async (): Promise<CfPage> => ({ result: [] }),
    send: async (method, path) => {
      sent.push({ method, path });
      if (refuseWith !== undefined) throw new Error(`Cloudflare API ${method} ${path}: ${refuseWith}`);
      return {};
    },
  };
  return { api, sent };
}

// A NARROW token: the account and the zone are right, the token is valid, it simply does not carry the edit
// scope for this surface. This is what Cloudflare returns, and it is the whole point of the journey: nothing
// here looks like an outage or a bad archive.
const NARROW_TOKEN_REFUSAL = "Authentication error (403): the API token lacks the edit scope for this resource";
// A PLAN gate, which must NOT be treated as a failure: there is no item to restore into an account whose plan
// does not carry the feature. classifyCfWriteSkip tests entitlement BEFORE auth for this reason.
const PLAN_GATE_REFUSAL = "not available on your plan; upgrade your plan to use this feature";

// fixedAt re-stamps a receipt's restoredAt so two receipts built milliseconds apart can be compared on their
// CONTENT. Without it every digest differs for a reason that has nothing to do with what was restored.
const FIXED_AT = "2026-06-07T00:00:02.000Z";
function fixedAt(r: RestoreReceipt): RestoreReceipt {
  return { ...r, restoredAt: FIXED_AT };
}

// asOldCode reconstructs the receipt the pre-fix engine would have produced for the SAME apply: the cf-config
// surfaces were never on the record list, and there were no class counts. It is the counterfactual, not a
// compatibility shim, and it exists so the defect can be reproduced from live results rather than asserted.
//
// allVerified is RECOMPUTED over the filtered records, because that is exactly what the old code did: one
// expression, `records.every((rec) => rec.verified)`, over a record set that held no cf-config surfaces. That
// is the whole mechanism of the defect in one line, and leaving the new value in place would smuggle the fix
// into the counterfactual and make it prove nothing.
function asOldCode(r: RestoreReceipt): RestoreReceipt {
  const { configSkipReasonCounts: _dropped, ...summary } = r.summary;
  const records = r.records.filter((rec) => rec.sourceType !== "cf-config");
  return { ...fixedAt(r), records, summary: { ...summary, allVerified: records.every((rec) => rec.verified) } };
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  const dnsSnapshot = utf8(JSON.stringify([{ type: "A", name: "new.example.com", content: "3.3.3.3", proxied: false, ttl: 1 }]));
  const records: WriteRecord[] = [
    // A KV DATA record rides alongside, so a refused cf-config leg can be shown NOT to abort the apply: the
    // data record still lands, and that is the deliberate choice (a refusal is reported, not rolled back).
    { sourceType: "kv", name: "k1", value: utf8("data-value"), namespace: NS },
    { sourceType: "cf-config", name: "dns", value: dnsSnapshot, account: ORIGIN },
  ];
  const archive = await buildArchive({
    downpipeId: "dp_narrow", downpipeName: "dp_narrow", cadence: "3600s", runId: RUN,
    master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records,
    windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  const destR2 = new MockR2();
  for (const [k, b] of archive) destR2.store.set(k, b);

  const envFor = (kv: MockKV): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: destR2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
    [`KV_${NS}`]: kv as unknown as KVNamespace,
  } as unknown as Env);

  // apply drives the REAL handler with the given CF double and returns the applied result.
  const apply = async (cf: { api: CfApi }, kv: MockKV): Promise<RestoreResult> =>
    (await runRestore(envFor(kv), { runId: RUN, confirm: true, cfConfig: { token: "narrow-token", accountId: ORIGIN } }, null, { cfApiFactory: () => cf.api })) as RestoreResult;

  // ---------------- the control: a token with the scope ----------------
  console.log("-- control: a token that DOES carry the edit scope --");
  const cleanKv = new MockKV();
  const clean = await apply(cfDouble(), cleanKv);
  ok("a clean cf-config apply reports ok:true", clean.ok === true);
  ok("a clean cf-config apply reports complete:true", clean.complete === true);
  ok("a clean cf-config apply raises no failure", clean.failures.length === 0);
  ok("a clean cf-config apply wrote the surface (one create) and the data record", (clean.configApplied ?? []).some((c) => c.surface === "dns" && c.applied === 1) && cleanKv.store.has("k1"));
  const cleanReceipt = clean.receipt;
  ok("a clean apply carries a receipt", cleanReceipt !== undefined);
  if (cleanReceipt === undefined) { if (++failures > 0) process.exitCode = 1; process.exit(1); }
  ok("the cf-config surface IS on the receipt, verified:true, via cf-config-applied", cleanReceipt.records.some((r) => r.name === "dns" && r.sourceType === "cf-config" && r.verified === true && r.via === "cf-config-applied" && r.verifiedSha384 === null));
  ok("a clean receipt states allVerified:true", cleanReceipt.summary.allVerified === true);
  ok("a clean receipt carries NO configSkipReasonCounts key at all", cleanReceipt.summary.configSkipReasonCounts === undefined);

  // ---------------- the defect: a token that is merely too narrow ----------------
  console.log("\n-- a token that is VALID but too NARROW (every item refused 401/403) --");
  const narrowKv = new MockKV();
  const narrowCf = cfDouble(NARROW_TOKEN_REFUSAL);
  const narrow = await apply(narrowCf, narrowKv);
  ok("the write WAS attempted (this is not the out-of-band path: a token was supplied)", narrowCf.sent.length === 1);
  ok("the surface applied NOTHING and skipped every item", (narrow.configApplied ?? []).some((c) => c.surface === "dns" && c.applied === 0 && c.skipped === 1));
  ok("the refusal was classified as `auth`, not guessed at", (narrow.configApplied ?? []).some((c) => c.skipReasonCounts?.auth === 1));

  ok("a narrow-token apply reports ok:FALSE", narrow.ok === false);
  ok("a narrow-token apply reports complete:FALSE", narrow.complete === false);
  const f = narrow.failures.find((x) => x.name === "dns");
  ok("the surface is a NAMED failure, classed cf-config-surface", f !== undefined && f.cls === "cf-config-surface");
  ok("the failure reason states the count and the class", f?.reason.includes("1 refused as auth") === true);
  ok("the failure reason names the remedy (widen the token's scope)", f?.reason.includes("edit scope") === true && f.reason.includes("re-run the restore"));
  ok("the apply was NOT rolled back: the data record still landed", narrowKv.store.has("k1"));

  const narrowReceipt = narrow.receipt;
  ok("a refused apply still carries a receipt (it reached the write phase)", narrowReceipt !== undefined);
  if (narrowReceipt === undefined) { if (++failures > 0) process.exitCode = 1; process.exit(1); }
  ok("the refused surface is on the receipt with verified:FALSE", narrowReceipt.records.some((r) => r.name === "dns" && r.sourceType === "cf-config" && r.verified === false));
  ok("the receipt states allVerified:FALSE", narrowReceipt.summary.allVerified === false);
  ok("the receipt carries the closed CLASS, so auth is distinguishable from quota", narrowReceipt.summary.configSkipReasonCounts?.auth === 1);

  // ---------------- the receipt digest must MOVE ----------------
  console.log("\n-- the receipt digest, with restoredAt held equal so only CONTENT differs --");
  const cleanDigest = await restoreReceiptDigestHex(fixedAt(cleanReceipt));
  const narrowDigest = await restoreReceiptDigestHex(fixedAt(narrowReceipt));
  ok("the refused receipt does NOT hash as the clean one", cleanDigest !== narrowDigest);
  ok("each receipt's own stated digest re-derives from its own core", (await restoreReceiptDigestHex(cleanReceipt)) === cleanReceipt.receiptSha384 && (await restoreReceiptDigestHex(narrowReceipt)) === narrowReceipt.receiptSha384);

  // THE COUNTERFACTUAL. Strip exactly what the pre-fix engine did not have (the cf-config record, the class
  // counts) from BOTH live receipts. If they then hash the same, the defect is reproduced: an apply that wrote
  // nothing signed byte-for-byte as an apply that wrote everything.
  const oldClean = await restoreReceiptDigestHex(asOldCode(cleanReceipt));
  const oldNarrow = await restoreReceiptDigestHex(asOldCode(narrowReceipt));
  ok("COUNTERFACTUAL: without these fields the two receipts hash IDENTICALLY (the defect, reproduced)", oldClean === oldNarrow);
  ok("COUNTERFACTUAL: and that shared old digest is neither receipt's real digest now", oldClean !== cleanDigest && oldNarrow !== narrowDigest);

  // The class counts must be INSIDE the signed and hashed core, or a tamperer strips the one field that says
  // the recovery was short and the receipt still verifies.
  const stamped: RestoreReceipt = { ...cleanReceipt, summary: { ...cleanReceipt.summary, configSkipReasonCounts: { auth: 1 } } };
  ok("configSkipReasonCounts is inside the hashed core (adding it changes the digest)", (await restoreReceiptDigestHex(stamped)) !== cleanReceipt.receiptSha384);
  const emptied: RestoreReceipt = { ...cleanReceipt, summary: { ...cleanReceipt.summary, configSkipReasonCounts: {} } };
  ok("an EMPTY class map hashes identically to an absent one (empty is not a distinct state)", (await restoreReceiptDigestHex(emptied)) === cleanReceipt.receiptSha384);

  // ---------------- entitlement is not a failure ----------------
  console.log("\n-- a PLAN gate: benign and permanent, and it must not redden the apply --");
  const planKv = new MockKV();
  const plan = await apply(cfDouble(PLAN_GATE_REFUSAL), planKv);
  ok("the refusal was classified as `entitlement`", (plan.configApplied ?? []).some((c) => c.skipReasonCounts?.entitlement === 1));
  ok("an entitlement refusal keeps ok:true (there is no item to restore into a plan without the feature)", plan.ok === true);
  ok("an entitlement refusal raises no failure", plan.failures.length === 0);
  ok("the surface stays verified:true on the receipt", plan.receipt?.records.some((r) => r.name === "dns" && r.verified === true) === true);
  ok("but the class is still ON the receipt, so the reader sees WHY nothing applied", plan.receipt?.summary.configSkipReasonCounts?.entitlement === 1);

  console.log(failures === 0 ? "\nAll under-scoped-token restore journeys passed." : `\n${failures} under-scoped-token assertion(s) FAILED.`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
