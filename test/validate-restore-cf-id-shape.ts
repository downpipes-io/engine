// validate-restore-cf-id-shape: the Cloudflare account id and zone id a restore request carries go into
// Cloudflare API paths, so they must be exactly 32 lower-case hex characters and present where a write needs
// them, and a path built from an id must keep the id as one path segment.
//
// The ids come from the restore request body (cfConfig.accountId, cfConfig.zoneId, mediaRestore.accountId).
// This file proves, in order:
//   1. the request check (restoreRequestFault) accepts real ids and refuses every crafted or absent one;
//   2. the restore routes answer a refused id with 400 before the role gate;
//   3. the restore dry-run and the restore apply (runRestore, which a caller can reach without the routes)
//      send no Cloudflare request and no media upload for a refused id, and send the exact expected path for
//      a real id;
//   4. cfWriteIds and cfRequireId give the exact refusal text for each case.
//
// An empty accountId marks a disabled leg: nothing is planned for it and nothing is sent.
//
// Run: node test/validate-restore-cf-id-shape.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { restoreRequestFault } from "../src/admin/approvals.ts";
import type { Caller } from "../src/admin/identity.ts";
import { runRestore } from "../src/admin/restore.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";
import { handleRestore } from "../src/admin/router-restore.ts";
import { concat, b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import * as reasons from "../src/admin/restore-cfconfig.ts";
import * as core from "../src/sources/cf-config-core.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const GOOD_A = "0123456789abcdef0123456789abcdef";
const GOOD_Z = "fedcba9876543210fedcba9876543210";
const RUN_ID = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
const SHAPE_TEXT = "must be 32 lower-case hex characters";

const CRAFTED: Array<[string, unknown]> = [
  ["dot-dot segment", "../../user/tokens"],
  ["bare dot-dot", ".."],
  ["bare dot", "."],
  ["encoded slash", "abc%2Fdef"],
  ["slash", "abc/def"],
  ["query", `${GOOD_A}?x=1`],
  ["fragment", `${GOOD_A}#x`],
  ["space", `${GOOD_A} `],
  ["newline", `${GOOD_A}\n`],
  ["unicode", `${GOOD_A.slice(0, 31)}é`],
  ["upper case", GOOD_A.toUpperCase()],
  ["too short", GOOD_A.slice(0, 31)],
  ["too long", `${GOOD_A}0`],
  ["number", 42],
  ["array", [GOOD_A]],
  ["null", null],
];

// Read through the namespace so that the same file also runs against an older src, where these helpers are
// missing, and reports failures instead of stopping at the import.
const missing = (name: string) => (): never => {
  throw new Error(`${name} is missing`);
};
const cfRequireId = ((core as Record<string, unknown>).cfRequireId ?? missing("cfRequireId")) as typeof core.cfRequireId;
const cfWriteIds = ((core as Record<string, unknown>).cfWriteIds ?? missing("cfWriteIds")) as typeof core.cfWriteIds;

const REFUSAL_REASON = ((reasons as Record<string, unknown>).CF_ID_REFUSAL_REASON ?? "CF_ID_REFUSAL_REASON is missing") as string;

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const toAB = (b: Uint8Array): ArrayBuffer => {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
};

class ArchiveR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> {
    return this.store.has(key) ? { etag: `"${key.length}"` } : null;
  }
}

function recipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

async function main(): Promise<void> {
  console.log("-- 1. the request check --");
  ok("no cloud legs: null", restoreRequestFault({ include: [], exclude: [] }) === null);
  ok("real cfConfig account and zone ids: null", restoreRequestFault({ cfConfig: { token: "t", accountId: GOOD_A, zoneId: GOOD_Z } }) === null);
  ok("real cfConfig account id, no zone: null", restoreRequestFault({ cfConfig: { token: "t", accountId: GOOD_A } }) === null);
  ok("real mediaRestore account id: null", restoreRequestFault({ mediaRestore: { token: "t", accountId: GOOD_A } }) === null);
  ok('empty accountId marks a disabled cfConfig leg: null', restoreRequestFault({ cfConfig: { token: "", accountId: "" } }) === null);
  ok('empty accountId marks a disabled mediaRestore leg: null', restoreRequestFault({ mediaRestore: { token: "", accountId: "" } }) === null);
  ok("absent cfConfig.accountId is refused", restoreRequestFault({ cfConfig: { token: "t" } as never }) === "cfConfig.accountId is required");
  ok("absent mediaRestore.accountId is refused", restoreRequestFault({ mediaRestore: { token: "t" } as never }) === "mediaRestore.accountId is required");
  ok("cfConfig that is not an object is refused", restoreRequestFault({ cfConfig: "x" as never }) === "cfConfig must be an object");
  for (const [label, v] of CRAFTED) {
    ok(`cfConfig.accountId ${label}`, restoreRequestFault({ cfConfig: { token: "t", accountId: v as string } }) === `cfConfig.accountId ${SHAPE_TEXT}`);
    ok(`cfConfig.zoneId ${label}`, restoreRequestFault({ cfConfig: { token: "t", accountId: GOOD_A, zoneId: v as string } }) === `cfConfig.zoneId ${SHAPE_TEXT}`);
    ok(`mediaRestore.accountId ${label}`, restoreRequestFault({ mediaRestore: { token: "t", accountId: v as string } }) === `mediaRestore.accountId ${SHAPE_TEXT}`);
  }

  console.log("\n-- 2. the restore routes answer a refused id with 400 --");
  const caller = { method: "access", email: "p@acme.example", subject: "test|p", role: "viewer", groups: [], capabilities: new Set(["downpipe.read"]) } as unknown as Caller;
  const direct = async (sub: string, body: unknown): Promise<{ status: number; error: string }> => {
    const scheduler = { fetch: async (): Promise<Response> => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }) } as unknown as DurableObjectStub;
    const r = await handleRestore({
      req: new Request(`https://engine.example/admin${sub}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
      env: {} as Env,
      url: new URL(`https://engine.example/admin${sub}`),
      scheduler,
      caller,
      sub,
      sourceIp: null,
      runtime: undefined,
    } as never);
    const text = r === null ? "" : await r.text();
    await new Promise((res) => setTimeout(res, 20));
    return { status: r?.status ?? 0, error: text };
  };
  for (const sub of ["/restore", "/restore/request"]) {
    const base = { runId: RUN_ID, confirm: true, reason: "p" };
    const badA = await direct(sub, { ...base, cfConfig: { token: "t", accountId: "../../x", zoneId: GOOD_Z } });
    ok(`POST ${sub}: crafted cfConfig.accountId is 400`, badA.status === 400 && badA.error.includes(`cfConfig.accountId ${SHAPE_TEXT}`));
    const badZ = await direct(sub, { ...base, cfConfig: { token: "t", accountId: GOOD_A, zoneId: "a/b?c" } });
    ok(`POST ${sub}: crafted cfConfig.zoneId is 400`, badZ.status === 400 && badZ.error.includes(`cfConfig.zoneId ${SHAPE_TEXT}`));
    const badM = await direct(sub, { ...base, mediaRestore: { token: "t", accountId: "a#b" } });
    ok(`POST ${sub}: crafted mediaRestore.accountId is 400`, badM.status === 400 && badM.error.includes(`mediaRestore.accountId ${SHAPE_TEXT}`));
    const absent = await direct(sub, { ...base, cfConfig: { token: "t" } });
    ok(`POST ${sub}: absent cfConfig.accountId is 400`, absent.status === 400 && absent.error.includes("cfConfig.accountId is required"));
    const absentM = await direct(sub, { ...base, mediaRestore: { token: "t" } });
    ok(`POST ${sub}: absent mediaRestore.accountId is 400`, absentM.status === 400 && absentM.error.includes("mediaRestore.accountId is required"));
    const good = await direct(sub, { ...base, cfConfig: { token: "t", accountId: GOOD_A, zoneId: GOOD_Z } });
    ok(`POST ${sub}: real ids pass the shape check (the role gate answers 403)`, good.status === 403);
    const off = await direct(sub, { ...base, cfConfig: { token: "", accountId: "" } });
    ok(`POST ${sub}: an empty accountId (disabled leg) passes the shape check (403)`, off.status === 403);
  }
  const attest = await direct("/restore/attest", { runId: RUN_ID, cfConfig: { token: "t", accountId: "../x" } });
  ok("POST /restore/attest does not run the id check (it writes nothing to Cloudflare)", attest.status !== 400 || !attest.error.includes(SHAPE_TEXT));

  console.log("\n-- 3. runRestore (dry-run and apply) with refused and real ids --");
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerB64);
  const breakGlass = recipient("break-glass");
  const op = recipient("operational");
  const archive = await buildArchive({
    downpipeId: "dp_idshape", downpipeName: "idshape", cadence: "3600s", runId: RUN_ID,
    master: rand(32), recipients: [breakGlass.entry, op.entry], signer,
    records: [
      { sourceType: "cf-config", name: "dns", value: utf8(JSON.stringify([{ type: "A", name: "new.example.com", content: "3.3.3.3", proxied: false, ttl: 1 }])), account: GOOD_A },
      { sourceType: "images", name: "img1/blob", value: utf8("PNG-BYTES-img1"), account: GOOD_A },
    ],
    windowStart: "2026-10-01T00:00:00.000Z", windowEnd: "2026-10-01T00:00:01.000Z", createdAt: "2026-10-01T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  const archiveR2 = new ArchiveR2();
  for (const [k, b] of archive) archiveR2.store.set(k, b);
  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: archiveR2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerB64,
    OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
  } as unknown as Env;

  const apiPaths: string[] = [];
  const api: CfApi = {
    get: async (p) => {
      apiPaths.push(`GET ${p}`);
      return [];
    },
    getPage: async (p): Promise<CfPage> => {
      apiPaths.push(`GET ${p}`);
      return { result: [] };
    },
    send: async (m, p) => {
      apiPaths.push(`${m} ${p}`);
      return {};
    },
  };
  const uploads: string[] = [];
  const uploader = {
    uploadImage: async (acct: string, id: string) => {
      uploads.push(`image ${acct} ${id}`);
      return { restoredId: id, remapped: false, verified: true, verifiedSha384: null, via: "blob" };
    },
    uploadStreamVideo: async () => {
      throw new Error("no stream record in this archive");
    },
  };
  const opts = { cfApiFactory: () => api, mediaUploaderFactory: () => uploader as never };
  const run = async (body: Record<string, unknown>, confirm: boolean): Promise<RestorePlan | RestoreResult> =>
    runRestore(env, { runId: RUN_ID, ...(confirm ? { confirm: true } : {}), ...body } as never, null, opts as never);

  // A foreign account or zone needs a confirmation that echoes it (the cross-account guard runs first), so
  // each case echoes its own value and it is the id check that refuses it.
  type Cf = { token: string; accountId: unknown; zoneId?: unknown; confirmDifferentAccountId?: unknown; confirmDifferentZoneId?: unknown };
  const echo = (cf: Cf): Cf => ({ ...cf, confirmDifferentAccountId: cf.accountId, confirmDifferentZoneId: cf.zoneId });
  const cfCases: Array<[string, Cf]> = [];
  for (const [label, v] of CRAFTED) {
    cfCases.push([`accountId ${label}`, { token: "t", accountId: v, zoneId: GOOD_Z }]);
    cfCases.push([`zoneId ${label}`, { token: "t", accountId: GOOD_A, zoneId: v }]);
  }
  cfCases.push(["accountId absent", { token: "t", accountId: undefined, zoneId: GOOD_Z }]);
  cfCases.push(["zoneId absent (dns is zone-scoped)", { token: "t", accountId: GOOD_A }]);
  cfCases.push(["zoneId empty (dns is zone-scoped)", { token: "t", accountId: GOOD_A, zoneId: "" }]);
  for (const [label, cf0] of cfCases) {
    const cf = echo(cf0);
    apiPaths.length = 0;
    const plan = (await run({ cfConfig: cf }, false)) as RestorePlan;
    ok(`dry-run, ${label}: no Cloudflare request, no dns diff, dns listed out of band with the id reason`, apiPaths.length === 0 && !(plan.configChanges ?? []).some((c) => c.surface === "dns") && plan.skipped.some((s) => s.name === "dns" && s.reason === `Cloudflare config, ${REFUSAL_REASON}`));
    apiPaths.length = 0;
    const res = (await run({ cfConfig: cf }, true)) as RestoreResult;
    ok(`apply, ${label}: no Cloudflare request, dns not applied, dns reported as a failure with the id reason`, apiPaths.length === 0 && !(res.configApplied ?? []).some((c) => c.surface === "dns") && res.failures.some((f) => f.name === "dns" && f.reason.includes(REFUSAL_REASON) && !f.reason.includes("lacks the edit scope")));
  }

  apiPaths.length = 0;
  const realPlan = (await run({ cfConfig: { token: "t", accountId: GOOD_A, zoneId: GOOD_Z } }, false)) as RestorePlan;
  ok("dry-run, real ids: the dns diff is computed", (realPlan.configChanges ?? []).some((c) => c.surface === "dns"));
  ok(`dry-run, real ids: every request path is under /zones/${GOOD_Z}/dns_records`, apiPaths.length > 0 && apiPaths.every((p) => p.startsWith(`GET /zones/${GOOD_Z}/dns_records`)));
  apiPaths.length = 0;
  const realRes = (await run({ cfConfig: { token: "t", accountId: GOOD_A, zoneId: GOOD_Z } }, true)) as RestoreResult;
  ok("apply, real ids: dns is applied", (realRes.configApplied ?? []).some((c) => c.surface === "dns" && c.applied === 1));
  ok(`apply, real ids: the create goes to POST /zones/${GOOD_Z}/dns_records`, apiPaths.includes(`POST /zones/${GOOD_Z}/dns_records`));
  apiPaths.length = 0;
  await run({ cfConfig: { token: "", accountId: "" } }, true);
  ok("apply, disabled leg (empty accountId): no Cloudflare request", apiPaths.length === 0);

  for (const [label, v] of [...CRAFTED, ["absent", undefined] as [string, unknown]]) {
    uploads.length = 0;
    const res = (await run({ mediaRestore: { token: "t", accountId: v, confirmDifferentAccountId: v } }, true)) as RestoreResult;
    ok(`apply, mediaRestore.accountId ${label}: no upload and the image record fails`, uploads.length === 0 && res.failures.some((f) => f.name === "img1/blob" && f.reason.includes(REFUSAL_REASON)));
  }
  uploads.length = 0;
  const mediaOk = (await run({ mediaRestore: { token: "t", accountId: GOOD_A } }, true)) as RestoreResult;
  ok("apply, real mediaRestore.accountId: the image uploads to that account", uploads.length === 1 && uploads[0]!.startsWith(`image ${GOOD_A} `) && !mediaOk.failures.some((f) => f.name === "img1/blob"));
  uploads.length = 0;
  await run({ mediaRestore: { token: "", accountId: "" } }, true);
  ok("apply, disabled media leg (empty accountId): no upload", uploads.length === 0);

  console.log("\n-- 4. cfWriteIds and cfRequireId --");
  const thrown = (fn: () => unknown): string | null => {
    try {
      fn();
      return null;
    } catch (e) {
      return (e as Error).message;
    }
  };
  for (const [label, v] of CRAFTED) {
    ok(`cfWriteIds, accountId ${label}: refused`, thrown(() => cfWriteIds({ accountId: v as string, zoneId: GOOD_Z }, "zone")) === `accountId ${SHAPE_TEXT}`);
    ok(`cfWriteIds, zoneId ${label}: refused`, thrown(() => cfWriteIds({ accountId: GOOD_A, zoneId: v as string }, "zone")) === `zoneId ${SHAPE_TEXT}`);
    ok(`cfRequireId ${label}: refused`, thrown(() => cfRequireId("mediaRestore.accountId", v)) === `mediaRestore.accountId ${SHAPE_TEXT}`);
  }
  ok("cfWriteIds, accountId absent: refused", thrown(() => cfWriteIds({ accountId: undefined as never }, "account")) === `accountId ${SHAPE_TEXT}`);
  ok("cfWriteIds, zone-scoped surface, zoneId absent: refused", thrown(() => cfWriteIds({ accountId: GOOD_A }, "zone")) === "zoneId is required to write a zone-scoped surface");
  ok("cfWriteIds, account-scoped surface, zoneId absent: account id only", JSON.stringify(cfWriteIds({ accountId: GOOD_A }, "account")) === JSON.stringify({ accountId: GOOD_A }));
  ok("cfWriteIds, real ids: unchanged", JSON.stringify(cfWriteIds({ accountId: GOOD_A, zoneId: GOOD_Z }, "zone")) === JSON.stringify({ accountId: GOOD_A, zoneId: GOOD_Z }));
  ok("cfRequireId, real id: unchanged", cfRequireId("x", GOOD_A) === GOOD_A);

  console.log(failures === 0 ? "\nRESTORE CF ID SHAPE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
