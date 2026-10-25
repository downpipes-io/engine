// Validates the rollback that still works after a secret change (src/admin/update-rollback-deploy.ts and its
// three callers: the standalone rollback, the settle auto-rollback and the ramp rollback). The REAL Cloudflare
// deploy driver (src/admin/cf-deploy.ts) runs against a stateful fake Cloudflare API, so every assertion reads
// real request shapes and real outcomes: no network, no account, no cost.
//
// The fake refuses a deployment of an older version with HTTP 400, code 10220, when a secret changed since that
// version was live (the behaviour measured against a live estate). It records every request, so the checks
// "the force flag is never sent" and "no upload without a refusal" read the traffic, not the code.
// Run: node test/validate-update-rollback-secret.ts

import { makeCfDeployDriver } from "../src/admin/cf-deploy.ts";
import { planAndPromote, settleAfterPromote, settleAfterRamp } from "../src/admin/update-apply.ts";
import { runStandaloneRollback } from "../src/admin/update-rollback.ts";
import type { HealthGate } from "../src/admin/update-types.ts";
import { hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { makeScheduler } from "./validate-rbac-harness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const ACCT = "acct1";
const SCRIPT = "downpipe-engine";
const sha = async (b: Uint8Array): Promise<string> => hexEncode(await sha384(b));

const OLD_BYTES = utf8("export default { /* the prior engine code */ };");
const BAD_BYTES = utf8("export default { /* the bad new engine code */ };");

interface Req {
  method: string;
  url: string;
  body: string;
}
interface FakeOpts {
  // ids whose plain deploy Cloudflare refuses with 10220 (a secret changed since they were live)
  stale?: Set<string>;
  // a different refusal code on the plain deploy of the target, instead of 10220
  otherRefusal?: boolean;
  // the module bytes Cloudflare holds per version id
  modules?: Record<string, Uint8Array>;
  // the bytes the read-back of an uploaded version returns instead of the uploaded bytes
  corruptReadback?: Uint8Array;
  failUpload?: boolean;
  failFetchOld?: boolean;
  failDeployNew?: boolean;
}

// fakeCf builds a stateful fake of the Cloudflare Workers API surface the driver uses.
function fakeCf(opts: FakeOpts): { fetchImpl: typeof fetch; reqs: Req[]; live: () => string; metadata: () => Record<string, unknown> | null } {
  const reqs: Req[] = [];
  const modules: Record<string, Uint8Array> = { ...(opts.modules ?? {}) };
  let live = "v-bad";
  let n = 0;
  let lastMeta: Record<string, unknown> | null = null;
  const bindings = [
    { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" },
    { type: "secret_text", name: "ADMIN_TOKEN" },
    { type: "plain_text", name: "CONSOLE_ORIGIN", text: "https://console.example" },
  ];
  const json = (o: unknown, status = 200): Response => new Response(JSON.stringify(o), { status });
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    let body = "";
    if (typeof init?.body === "string") body = init.body;
    else if (init?.body instanceof FormData) {
      const form = init.body;
      const meta = String(form.get("metadata"));
      body = meta;
      lastMeta = JSON.parse(meta) as Record<string, unknown>;
    }
    reqs.push({ method, url, body });
    if (method === "GET" && /\/deployments$/.test(url)) return json({ success: true, result: { deployments: [{ id: "d1", versions: [{ version_id: live, percentage: 100 }] }] } });
    if (method === "GET" && /\/settings$/.test(url)) return json({ success: true, result: { bindings, compatibility_date: "2026-06-01" } });
    if (method === "GET" && /\/workers\/workers\/[^/]+\/versions\//.test(url)) {
      const id = decodeURIComponent(url.split("/versions/")[1]!.split("?")[0]!);
      if (opts.failFetchOld && id === "v-old") return json({ success: false, errors: [{ code: 10007, message: "version not found" }] }, 404);
      const bytes = modules[id];
      if (bytes === undefined) return json({ success: false, errors: [{ code: 10007, message: "version not found" }] }, 404);
      const served = opts.corruptReadback !== undefined && id.startsWith("v-new") ? opts.corruptReadback : bytes;
      return json({ success: true, result: { modules: [{ name: "index.js", content_base64: Buffer.from(served).toString("base64") }] } });
    }
    if (method === "POST" && /\/versions$/.test(url)) {
      if (opts.failUpload) return json({ success: false, errors: [{ code: 10021, message: "Durable Object class missing" }] }, 400);
      const id = `v-new-${++n}`;
      const file = (init!.body as FormData).get("index.js") as Blob;
      modules[id] = new Uint8Array(await file.arrayBuffer());
      return json({ success: true, result: { id } });
    }
    if (method === "POST" && /\/deployments$/.test(url)) {
      const sent = JSON.parse(body) as { versions: Array<{ version_id: string }> };
      const id = sent.versions[0]!.version_id;
      if (opts.stale?.has(id)) return json({ success: false, errors: [{ code: 10220, message: "A secret has changed since this version was active" }] }, 400);
      if (opts.otherRefusal && id === "v-old") return json({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, 403);
      if (opts.failDeployNew && id.startsWith("v-new")) return json({ success: false, errors: [{ code: 10001, message: "deploy refused" }] }, 500);
      live = id;
      return json({ success: true, result: { id: "d2" } });
    }
    return json({ success: false }, 500);
  }) as typeof fetch;
  return { fetchImpl, reqs, live: () => live, metadata: () => lastMeta };
}

const gate = (verdict: "alive" | "dead"): HealthGate => ({ baseline: async () => "alive", flyNow: async () => verdict, selfCheck: async () => true });
const driverOf = (f: ReturnType<typeof fakeCf>) => makeCfDeployDriver({ token: "tok", accountId: ACCT, scriptName: SCRIPT, fetchImpl: f.fetchImpl });
const uploads = (f: ReturnType<typeof fakeCf>): number => f.reqs.filter((r) => r.method === "POST" && /\/versions$/.test(r.url)).length;
const deploys = (f: ReturnType<typeof fakeCf>): Req[] => f.reqs.filter((r) => r.method === "POST" && /\/deployments$/.test(r.url));
const noForce = (f: ReturnType<typeof fakeCf>): boolean => f.reqs.every((r) => !/force/i.test(r.url) && !/force/i.test(r.body));

async function main(): Promise<void> {
  const oldSha = await sha(OLD_BYTES);

  console.log("-- (control) no secret change: the plain deploy lands and nothing is uploaded --");
  {
    const f = fakeCf({ modules: { "v-old": OLD_BYTES } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: oldSha });
    ok("outcome reverted", r.outcome === "reverted");
    ok("the target itself is live", f.live() === "v-old" && r.liveVersion === "v-old");
    ok("no upload and no module fetch", uploads(f) === 0 && !f.reqs.some((q) => /include=modules/.test(q.url)));
    ok("no identity reported on the plain route", r.identity === undefined && r.liveSha384 === undefined);
    ok("the force flag is never sent", noForce(f));
  }

  console.log("-- (a) 10220 on the plain deploy: fetch, upload with keep_bindings, deploy the new id --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: oldSha });
    ok("outcome reverted", r.outcome === "reverted");
    ok("the plain deploy of the old id was tried first", deploys(f)[0] !== undefined && JSON.parse(deploys(f)[0]!.body).versions[0].version_id === "v-old");
    ok("one upload", uploads(f) === 1);
    ok("the new version is live, not the old id", f.live() === "v-new-1" && r.liveVersion === "v-new-1");
    const meta = f.metadata() as { keep_bindings?: string[]; bindings?: Array<{ name: string; type: string }> } | null;
    ok("the upload keeps the current secrets (keep_bindings names secret_text)", Array.isArray(meta?.keep_bindings) && meta!.keep_bindings.includes("secret_text"));
    ok("the upload re-sends the current non-secret bindings", meta?.bindings?.some((b) => b.name === "SCHEDULER") === true && meta?.bindings?.some((b) => b.name === "CONSOLE_ORIGIN") === true);
    ok("no secret value is sent", !f.reqs.some((q) => /ADMIN_TOKEN/.test(q.body) && /"text"/.test(q.body.split("ADMIN_TOKEN")[1]!.slice(0, 20))));
    ok("the result says a secret changed and a new version was uploaded", /secret changed/.test(r.reason ?? "") && /new version v-new-1/.test(r.reason ?? ""));
    ok("the live digest is the digest of the uploaded code", r.liveSha384 === oldSha);
    ok("the steps name the secret change", r.steps.some((s) => s.step === "secret-changed"));
    ok("(e) the force flag is never sent", noForce(f));
  }

  console.log("-- a refusal that is not 10220 does not take the second route --");
  {
    const f = fakeCf({ otherRefusal: true, modules: { "v-old": OLD_BYTES } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old" });
    ok("outcome failed with the Cloudflare reason", r.outcome === "failed" && /Authentication error/.test(r.reason ?? ""));
    ok("no upload, nothing live changed", uploads(f) === 0 && f.live() === "v-bad");
  }

  console.log("-- (c) identity: exact, build-stamp, not-checked, and a mismatching digest refuses --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: oldSha.toUpperCase() });
    ok("exact: the recorded digest equals the bytes", r.outcome === "reverted" && r.identity === "exact");
  }
  {
    const artefactDigest = "ab".repeat(48);
    const wranglerBytes = utf8(`export default {}; // build ${artefactDigest}`);
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": wranglerBytes } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: artefactDigest });
    ok("build-stamp: the bytes differ but the stamp names the recorded digest", r.outcome === "reverted" && r.identity === "build-stamp");
    ok("the result names the identity used", /build-stamp/.test(r.reason ?? ""));
    ok("the digest recorded for the new version is of the bytes uploaded", r.liveSha384 === (await sha(wranglerBytes)));
  }
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old" });
    ok("not-checked: no recorded digest still proceeds", r.outcome === "reverted" && r.identity === "not-checked" && f.live() === "v-new-1");
    ok("the result says the identity was not checked, in plain words", /identity of the prior code was not checked/i.test(r.reason ?? ""));
    ok("the run record step says not-checked", r.steps.some((s) => s.step === "identity-check" && /not checked/.test(s.detail ?? "")));
  }
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: "cd".repeat(48) });
    ok("a recorded digest that matches neither bytes nor stamp refuses", r.outcome === "failed" && /not the release the record says/.test(r.reason ?? ""));
    ok("nothing was uploaded and the live version is unchanged", uploads(f) === 0 && f.live() === "v-bad");
    ok("the refusal uses the existing failed outcome", r.outcome === "failed");
  }

  console.log("-- (b) transfer check: bytes read back from the new version must equal the bytes fetched --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES }, corruptReadback: BAD_BYTES });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: oldSha });
    ok("a mismatch refuses the rollback", r.outcome === "failed" && /differ from the prior code/.test(r.reason ?? ""));
    ok("nothing went live (the only deployment attempt was the refused plain one)", f.live() === "v-bad" && deploys(f).length === 1);
  }

  console.log("-- failures on the second route are a failed rollback with a plain reason --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES }, failFetchOld: true });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old" });
    ok("a fetch failure is a failed rollback", r.outcome === "failed" && /could not be read from Cloudflare/.test(r.reason ?? "") && uploads(f) === 0);
  }
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES }, failUpload: true });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old" });
    ok("an upload refusal is a failed rollback, no migrations sent", r.outcome === "failed" && /could not be uploaded/.test(r.reason ?? "") && !f.reqs.some((q) => /migrations/.test(q.body)) && f.live() === "v-bad");
  }
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES }, failDeployNew: true });
    const r = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old" });
    ok("a failed deploy of the new version is a failed rollback", r.outcome === "failed" && /making it live failed/.test(r.reason ?? "") && f.live() === "v-bad");
  }
  {
    // A driver with no read-back or upload cannot take the second route.
    let calls = 0;
    const { DeployRefusal } = await import("../src/admin/update-types.ts");
    const driver = {
      currentLiveVersionId: async () => "v-bad",
      uploadVersion: undefined,
      deployVersion: async () => {
        calls++;
        throw new DeployRefusal("refused", [10220]);
      },
    };
    const r = await runStandaloneRollback(driver as never, gate("alive"), { toVersion: "v-old" });
    ok("a driver that cannot upload fails plainly", r.outcome === "failed" && /cannot upload/.test(r.reason ?? "") && calls === 1);
  }

  console.log("-- the failed-rollback text does not send the owner to the Cloudflare dashboard --");
  {
    const f = fakeCf({ stale: new Set(["v-old", "v-new-1"]), modules: { "v-old": OLD_BYTES } });
    const s = await settleAfterPromote(driverOf(f), gate("dead"), { fromVersion: "v-old", toVersion: "v-bad", recommendedVersion: "0.4.0" });
    ok("a rollback that cannot land is rollback-failed", s.outcome === "rollback-failed");
    ok("the text points at the console, not the dashboard", /Roll back in the console/.test(s.reason ?? "") && !/dashboard/i.test(s.reason ?? ""));
  }

  console.log("-- (d) the settle auto-rollback takes the same second route --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const s = await settleAfterPromote(driverOf(f), gate("dead"), { fromVersion: "v-old", toVersion: "v-bad", recommendedVersion: "0.4.0", fromDigest: oldSha });
    ok("outcome rolled-back", s.outcome === "rolled-back");
    ok("the new version is live and named as the version rolled back to", f.live() === "v-new-1" && s.fromVersion === "v-new-1");
    ok("the identity is exact and the digest is returned for the record", s.rollbackIdentity === "exact" && s.liveSha384 === oldSha);
    ok("the reason says a secret changed", /secret had changed/.test(s.reason ?? ""));
    ok("the force flag is never sent", noForce(f));
  }
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const s = await settleAfterPromote(driverOf(f), gate("dead"), { fromVersion: "v-old", toVersion: "v-bad", recommendedVersion: "0.4.0", fromDigest: "cd".repeat(48) });
    ok("settle refuses on a mismatching recorded digest", s.outcome === "rollback-failed" && uploads(f) === 0 && f.live() === "v-bad");
  }
  {
    const f = fakeCf({ modules: { "v-old": OLD_BYTES } });
    const s = await settleAfterPromote(driverOf(f), gate("dead"), { fromVersion: "v-old", toVersion: "v-bad", recommendedVersion: "0.4.0" });
    ok("settle without a secret change uploads nothing and names the target", s.outcome === "rolled-back" && s.fromVersion === "v-old" && uploads(f) === 0 && s.rollbackIdentity === undefined);
  }

  console.log("-- the ramp rollback takes the same second route --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const s = await settleAfterRamp(driverOf(f), gate("dead"), { fromVersion: "v-old", toVersion: "v-bad", recommendedVersion: "0.4.0", fromDigest: oldSha });
    ok("outcome rolled-back on the new version", s.outcome === "rolled-back" && s.fromVersion === "v-new-1" && f.live() === "v-new-1" && s.rollbackIdentity === "exact");
    ok("the force flag is never sent", noForce(f));
  }

  console.log("-- (f) the digest of every deployed version is recorded --");
  {
    const artefact = utf8("export default { /* the new engine code */ };");
    const digest = await sha(artefact);
    const f = fakeCf({ modules: {} });
    const p = await planAndPromote(driverOf(f), gate("alive"), {
      artefact,
      expectedSha384: digest,
      meta: { version: "0.4.0" },
      runningVersion: "0.3.8",
      recommendedVersion: "0.4.0",
      dryRun: false,
    });
    ok("the apply promote returns the digest of the bytes it uploaded", p.outcome === "promoted" && p.uploadedSha384 === digest);

    const sched = makeScheduler();
    const post = (path: string, body: unknown): Promise<Response> =>
      sched.stub.fetch(`https://scheduler.internal${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const status = async (): Promise<{ versionDigests?: Record<string, string> }> => (await (await sched.stub.fetch("https://scheduler.internal/update-status", { method: "GET" })).json()) as { versionDigests?: Record<string, string> };
    await post("/update-pending", { fromVersion: "v-old", toVersion: p.toVersion, recommendedVersion: "0.4.0", uploadedSha384: p.uploadedSha384, promotedAt: 1, promotedBy: "o" });
    ok("the apply's digest is recorded against the new version id", (await status()).versionDigests?.[p.toVersion!] === digest);
    await post("/update-settled", { outcome: "rolled-back", recommendedVersion: "v-old", fromVersion: "v-new-9", toVersion: p.toVersion, liveSha384: oldSha, at: 2, by: "o" });
    const st = await status();
    ok("the re-uploaded rollback version's digest is recorded", st.versionDigests?.["v-new-9"] === oldSha);
    ok("the earlier digest is kept", st.versionDigests?.[p.toVersion!] === digest);
    await post("/update-alert-claim", { recommendedVersion: "9.9.9" });
    ok("the record is sticky through other writes", (await status()).versionDigests?.["v-new-9"] === oldSha);
    await post("/update-settled", { outcome: "applied", recommendedVersion: "0.4.1", fromVersion: "x", toVersion: "y", liveSha384: "ee".repeat(48), at: 3, by: "o" });
    ok("only a rolled-back outcome records a live digest", (await status()).versionDigests?.["x"] === undefined);
    for (let i = 0; i < 105; i++) await post("/update-pending", { fromVersion: "a", toVersion: `v-${i}`, recommendedVersion: "0.4.0", uploadedSha384: "ff".repeat(48), promotedAt: 1, promotedBy: "o" });
    const capped = Object.keys((await status()).versionDigests ?? {});
    ok("the record is bounded to 100 versions, newest kept", capped.length === 100 && capped.includes("v-104") && !capped.includes("v-0"));
  }

  console.log("-- a rollback to a version this engine recorded then checks it (round trip) --");
  {
    const f = fakeCf({ stale: new Set(["v-old"]), modules: { "v-old": OLD_BYTES } });
    const r1 = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: "v-old", recordedDigest: oldSha });
    f.reqs.length = 0;
    const r2 = await runStandaloneRollback(driverOf(f), gate("alive"), { toVersion: r1.liveVersion!, recordedDigest: r1.liveSha384! });
    ok("the new version id is a valid target and already live", r2.outcome === "already");
    ok("a second rollback makes no upload", uploads(f) === 0);
  }
}

await main();
verdictReached(failures);
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nALL ROLLBACK-AFTER-SECRET-CHANGE VALIDATIONS PASS");
