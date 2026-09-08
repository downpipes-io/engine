// Validates the LIVE Cloudflare DeployDriver (src/admin/cf-deploy.ts) for the safe-apply update
// harness, driven entirely with a STUB fetch (no network, no account, no cost) modelled on
// test/validate-attach.ts. This driver is untested against a real account by design (the upstream
// harness gates everything), so the validator's job is to prove the REQUEST SHAPES and the
// BINDING/SECRET PRESERVATION are correct-by-the-docs and that every opaque Cloudflare failure
// becomes a precise thrown message. Run: node test/validate-cf-deploy.ts.

import { makeCfDeployDriver } from "../src/admin/cf-deploy.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const CF = "https://api.cloudflare.com/client/v4";
const path = (url: string): string => url.replace(/^https:\/\/api\.cloudflare\.com\/client\/v4/, "");

// A realistic engine settings read: the two required Durable Objects, two secrets, a plain var, the
// R2 archive, an existing KV source, plus compatibility fields. The upload MUST preserve all of it.
const ENGINE_BINDINGS = [
  { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" },
  { type: "durable_object_namespace", name: "RUNSEAL", class_name: "RunSealDO" },
  { type: "secret_text", name: "SIGNER_PRIVATE" },
  { type: "secret_key", name: "BREAK_GLASS_KEY" },
  { type: "plain_text", name: "CONSOLE_ORIGIN", text: "https://console.example" },
  { type: "r2_bucket", name: "DEST_R2", bucket_name: "downpipe-archive" },
  { type: "kv_namespace", name: "SRC_KV_existing", namespace_id: "abc123" },
];
const COMPAT_DATE = "2026-06-01";
const COMPAT_FLAGS = ["nodejs_compat"];

const ACCT = "acct1";
const SCRIPT = "downpipe-engine";
const TOKEN = "tok-workers-edit-1234567890";

// The Cloudflare request shapes the driver constructs. The stubs capture these from the bodies it
// sends, so typing the captured values precisely lets the compiler catch a property-name typo in any
// assertion below (which an `any` would silently pass).
interface CfBinding {
  type: string;
  name: string;
  class_name?: string;
  text?: string;
  bucket_name?: string;
  namespace_id?: string;
}
interface VersionsMeta {
  bindings: CfBinding[];
  main_module: string;
  compatibility_date?: string;
  compatibility_flags?: string[];
  keep_bindings: string[];
}
interface DeploymentVersionSlice {
  version_id: string;
  percentage: number;
}
interface DeploymentsBody {
  strategy: string;
  versions: DeploymentVersionSlice[];
}

// settingsResponse is what GET /settings returns for the engine (bindings + compat fields).
function settingsResponse(): Response {
  return new Response(
    JSON.stringify({ success: true, result: { bindings: ENGINE_BINDINGS, compatibility_date: COMPAT_DATE, compatibility_flags: COMPAT_FLAGS } }),
    { status: 200 },
  );
}

// deploymentsResponse models GET /deployments: newest deployment first, each with versions[].
function deploymentsResponse(): Response {
  return new Response(
    JSON.stringify({
      success: true,
      result: {
        deployments: [
          { id: "d-2", versions: [{ version_id: "v-live" }] }, // the ACTIVE (most recent) one
          { id: "d-1", versions: [{ version_id: "v-old" }] },
        ],
      },
    }),
    { status: 200 },
  );
}

console.log("-- currentLiveVersionId: parses deployments + extracts the active version id --");
{
  const calls: string[] = [];
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(`${init?.method ?? "GET"} ${path(url)}`);
    if (/\/deployments$/.test(url)) return deploymentsResponse();
    return new Response(JSON.stringify({ success: false, errors: [{ message: "unexpected", code: 0 }] }), { status: 500 });
  }) as typeof fetch;

  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  const id = await driver.currentLiveVersionId();
  ok("returns the most recent deployment's first version id", id === "v-live");
  ok("GET the deployments endpoint for the right account+script", calls.some((c) => c === `GET /accounts/${ACCT}/workers/scripts/${SCRIPT}/deployments`));
}

console.log("-- currentLiveVersionId: empty/no deployments and CF errors throw clearly --");
{
  const emptyStub = (async () => new Response(JSON.stringify({ success: true, result: { deployments: [] } }), { status: 200 })) as typeof fetch;
  let threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: emptyStub }).currentLiveVersionId(); } catch (e) { threw = (e as Error).message; }
  ok("no deployments -> throws (nothing to roll back to)", /no deployments|no current live version/.test(threw) && /Nothing was changed/.test(threw));

  const errStub = (async () => new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 })) as typeof fetch;
  threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: errStub }).currentLiveVersionId(); } catch (e) { threw = (e as Error).message; }
  ok("a CF error body becomes a cfErr message (reason surfaces)", /Authentication error/.test(threw) && /Workers Scripts: Edit/.test(threw));

  // A deployment with no version id is a malformed result -> clear throw.
  const noVerStub = (async () => new Response(JSON.stringify({ success: true, result: { deployments: [{ id: "d-1", versions: [] }] } }), { status: 200 })) as typeof fetch;
  threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: noVerStub }).currentLiveVersionId(); } catch (e) { threw = (e as Error).message; }
  ok("a deployment without a version id throws", /did not include a version id/.test(threw));
}

console.log("-- rampVersion: dominant-slice selection returns the higher-percentage version, not versions[0] --");
{
  // A real two-version split where the SUSPECT new version is versions[0] at the SMALLER share. The
  // correct behaviour returns the DOMINANT slice (by percentage) and exposes the full set.
  const rampedStub = (async () => new Response(JSON.stringify({
    success: true,
    result: { deployments: [{ id: "d-ramp", versions: [{ version_id: "v-suspect", percentage: 20 }, { version_id: "v-known-good", percentage: 80 }] }] },
  }), { status: 200 })) as typeof fetch;
  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: rampedStub });
  const id = await driver.currentLiveVersionId();
  ok("currentLiveVersionId returns the DOMINANT slice (by %), not versions[0]", id === "v-known-good");
  const slices = await driver.currentLiveVersions!();
  ok("currentLiveVersions exposes BOTH slices", slices.length === 2 && slices.some((s) => s.versionId === "v-suspect" && s.percentage === 20) && slices.some((s) => s.versionId === "v-known-good" && s.percentage === 80));
}
{
  // A single-version deployment with no explicit percentage reads as one 100% slice (the normal shape).
  const singleStub = (async () => new Response(JSON.stringify({ success: true, result: { deployments: [{ id: "d-1", versions: [{ version_id: "v-only" }] }] } }), { status: 200 })) as typeof fetch;
  const slices = await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: singleStub }).currentLiveVersions!();
  ok("a single-version deployment reads as one 100% slice", slices.length === 1 && slices[0]!.versionId === "v-only" && slices[0]!.percentage === 100);
}

console.log("-- uploadVersion: multipart POST to /versions preserving bindings + keep_bindings --");
{
  const calls: string[] = [];
  let sentMeta: VersionsMeta | null = null;
  let moduleFilename = "";
  let moduleType = "";
  // Held on an object field rather than a bare let: the assignment happens inside the stub closure, and a
  // bare `let` would be control-flow narrowed to null (then never) at the read site below. A mutable property
  // is not narrowed that way, so the read keeps the real Uint8Array | null type.
  const captured: { module: Uint8Array | null } = { module: null };
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push(`${method} ${path(url)}`);
    if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
    if (method === "POST" && /\/versions$/.test(url)) {
      const form = init!.body as FormData;
      sentMeta = JSON.parse(String(form.get("metadata"))) as VersionsMeta;
      // The module part is appended under the main_module filename.
      const main = sentMeta.main_module;
      const part = form.get(main);
      if (part instanceof Blob) {
        moduleFilename = (part as File).name ?? "";
        moduleType = part.type;
        captured.module = new Uint8Array(await part.arrayBuffer());
      }
      return new Response(JSON.stringify({ success: true, result: { id: "v-new" } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: [{ message: "unexpected", code: 0 }] }), { status: 500 });
  }) as typeof fetch;

  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  const artefact = new Uint8Array([1, 2, 3, 4, 5]);
  const id = await driver.uploadVersion(artefact, { version: "1.2.3", mainModule: "engine.js" });

  ok("returns the created version's id", id === "v-new");
  ok("read the settings FIRST, then POSTed the versions endpoint", calls[0] === `GET /accounts/${ACCT}/workers/scripts/${SCRIPT}/settings` && calls.some((c) => c === `POST /accounts/${ACCT}/workers/scripts/${SCRIPT}/versions`));

  ok("the version POST was captured with parseable metadata", sentMeta !== null);
  const meta = sentMeta as VersionsMeta | null;
  if (meta === null) throw new Error("metadata was not captured");
  // PRESERVATION: every NON-secret binding is re-sent verbatim in the metadata.
  const sentNames = new Set(meta.bindings.map((b) => b.name));
  ok("metadata re-sends the engine's non-secret bindings verbatim (DOs, R2, var, KV source)", ["SCHEDULER", "RUNSEAL", "CONSOLE_ORIGIN", "DEST_R2", "SRC_KV_existing"].every((n) => sentNames.has(n)));
  ok("the existing KV source binding carries its namespace_id verbatim", meta.bindings.some((b) => b.name === "SRC_KV_existing" && b.namespace_id === "abc123"));

  // PRESERVATION: secrets are NOT re-sent (their values are not returned on read) but preserved
  // via keep_bindings, so the engine's signing secret + break-glass key survive the new version.
  ok("secrets are NOT re-sent as bindings", !meta.bindings.some((b) => b.type === "secret_text" || b.type === "secret_key"));
  ok("keep_bindings carries both secret types (secret_text + secret_key)", Array.isArray(meta.keep_bindings) && meta.keep_bindings.includes("secret_text") && meta.keep_bindings.includes("secret_key"));
  ok("no secret NAME leaks into the sent bindings", !JSON.stringify(meta.bindings).includes("SIGNER_PRIVATE") && !JSON.stringify(meta.bindings).includes("BREAK_GLASS_KEY"));

  // PRESERVATION: the runtime contract (compat date/flags) is carried over.
  ok("compatibility_date is carried over", meta.compatibility_date === COMPAT_DATE);
  ok("compatibility_flags are carried over", Array.isArray(meta.compatibility_flags) && meta.compatibility_flags[0] === "nodejs_compat");

  // main_module + the module file part are correct.
  ok("main_module is the declared entry module", meta.main_module === "engine.js");
  ok("the module file part is named after main_module", moduleFilename === "engine.js");
  ok("the module file part is application/javascript+module", moduleType === "application/javascript+module");
  const capturedModule = captured.module;
  ok("the module body is exactly the artefact bytes", capturedModule !== null && capturedModule.length === 5 && capturedModule[0] === 1 && capturedModule[4] === 5);
}

console.log("-- uploadVersion: main_module defaults to index.js when meta omits it --");
{
  let sentMeta: VersionsMeta | null = null;
  let filename = "";
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
    if (method === "POST" && /\/versions$/.test(url)) {
      const form = init!.body as FormData;
      const meta = JSON.parse(String(form.get("metadata"))) as VersionsMeta;
      sentMeta = meta;
      const part = form.get(meta.main_module);
      if (part instanceof Blob) filename = (part as File).name ?? "";
      return new Response(JSON.stringify({ success: true, result: { id: "v-def" } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  const id = await driver.uploadVersion(new Uint8Array([9]), { version: "2.0.0" });
  ok("defaults main_module to index.js and names the module part index.js", id === "v-def" && (sentMeta as VersionsMeta | null)?.main_module === "index.js" && filename === "index.js");
}

console.log("-- uploadVersion: settings read failure refuses BEFORE any version POST --");
{
  let posted = false;
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "POST" && /\/versions$/.test(url)) posted = true;
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    return new Response(JSON.stringify({ success: true, result: { id: "should-not-happen" } }), { status: 200 });
  }) as typeof fetch;
  let threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub }).uploadVersion(new Uint8Array([1]), { version: "1.0.0" }); } catch (e) { threw = (e as Error).message; }
  ok("a settings-read failure refuses with the reason surfaced and NEVER POSTs a version", /Authentication error/.test(threw) && /preserve its bindings/.test(threw) && posted === false);

  // Settings without a bindings array -> refuse blind (would risk dropping bindings).
  const noBindStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if ((init?.method ?? "GET") === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    return new Response(JSON.stringify({ success: true, result: { id: "x" } }), { status: 200 });
  }) as typeof fetch;
  threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: noBindStub }).uploadVersion(new Uint8Array([1]), { version: "1.0.0" }); } catch (e) { threw = (e as Error).message; }
  ok("settings without a bindings list refuses to upload blind", /without a readable bindings list/.test(threw));
}

console.log("-- uploadVersion: a non-2xx / success:false on the version POST throws --");
{
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
    if (method === "POST" && /\/versions$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10021, message: "Uploaded script too large" }] }), { status: 400 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  let threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub }).uploadVersion(new Uint8Array([1]), { version: "1.0.0" }); } catch (e) { threw = (e as Error).message; }
  ok("a CF version-upload error surfaces the reason and says the engine is unchanged", /Uploaded script too large/.test(threw) && /your engine is unchanged/.test(threw));

  // success:true but no id -> cannot promote, throw.
  const noIdStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
    if (method === "POST" && /\/versions$/.test(url)) return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: noIdStub }).uploadVersion(new Uint8Array([1]), { version: "1.0.0" }); } catch (e) { threw = (e as Error).message; }
  ok("an upload that returns no version id throws (cannot promote)", /did not return a version id/.test(threw));
}

console.log("-- deployVersion: POSTs a 100% deployment of the given id (promote) --");
{
  const calls: string[] = [];
  let sentBody: DeploymentsBody | null = null;
  let sentCT = "";
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push(`${method} ${path(url)}`);
    if (method === "POST" && /\/deployments$/.test(url)) {
      sentBody = JSON.parse(String(init!.body)) as DeploymentsBody;
      sentCT = (init!.headers as Record<string, string>)["content-type"] ?? "";
      return new Response(JSON.stringify({ success: true, result: { id: "d-new" } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  await driver.deployVersion("v-new");

  const body = sentBody as DeploymentsBody | null;
  ok("POSTed the deployments endpoint", calls.some((c) => c === `POST /accounts/${ACCT}/workers/scripts/${SCRIPT}/deployments`));
  ok("the body is a percentage strategy", body?.strategy === "percentage");
  ok("the body deploys the given version id at 100%", Array.isArray(body?.versions) && body!.versions.length === 1 && body!.versions[0]!.version_id === "v-new" && body!.versions[0]!.percentage === 100);
  ok("the request is application/json", /application\/json/.test(sentCT));
}

console.log("-- deployVersion: SAME call performs the rollback (deploys the prior id) --");
{
  let sentBody: DeploymentsBody | null = null;
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "POST" && /\/deployments$/.test(url)) {
      sentBody = JSON.parse(String(init!.body)) as DeploymentsBody;
      return new Response(JSON.stringify({ success: true, result: { id: "d-rollback" } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  // Rollback is just deployVersion(priorVersionId): the harness uses the same method both ways.
  await driver.deployVersion("v-old");
  const body = sentBody as DeploymentsBody | null;
  ok("rollback deploys the recorded prior version id at 100% via the same method", body?.versions?.[0]?.version_id === "v-old" && body.versions[0]!.percentage === 100 && body.strategy === "percentage");
}

console.log("-- deployVersion: a CF error becomes a cfErr message; the prior version stays live --");
{
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if ((init?.method ?? "GET") === "POST" && /\/deployments$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  let threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub }).deployVersion("v-new"); } catch (e) { threw = (e as Error).message; }
  ok("a deploy failure surfaces the reason and says the prior version is still serving", /Authentication error/.test(threw) && /still serving/.test(threw));

  // A non-2xx with no parseable body still throws (falls back to HTTP status in cfErr).
  const rawStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if ((init?.method ?? "GET") === "POST" && /\/deployments$/.test(url)) return new Response("not json", { status: 502 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: rawStub }).deployVersion("v-new"); } catch (e) { threw = (e as Error).message; }
  ok("an unparseable non-2xx body still throws with the HTTP status", /HTTP 502/.test(threw));
}

console.log("-- rampVersion: POSTs a TWO-version percentage split (new + prior summing to 100) --");
{
  let sentBody: DeploymentsBody | null = null;
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "POST" && /\/deployments$/.test(url)) {
      sentBody = JSON.parse(String(init!.body)) as DeploymentsBody;
      return new Response(JSON.stringify({ success: true, result: { id: "d-ramp" } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  await driver.rampVersion!("v-new", "v-old", 25);
  const body = sentBody as DeploymentsBody | null;
  ok("ramp body is a percentage strategy", body?.strategy === "percentage");
  ok("ramp sends TWO versions (new + prior)", Array.isArray(body?.versions) && body!.versions.length === 2);
  ok("ramp serves 25% to the new version", body?.versions?.find((v) => v.version_id === "v-new")?.percentage === 25);
  ok("ramp serves the remaining 75% to the prior version", body?.versions?.find((v) => v.version_id === "v-old")?.percentage === 75);
}

console.log("-- rampVersion: an out-of-range percentage is refused before any call (defence in depth) --");
{
  let called = false;
  const stub = (async (_input: RequestInfo | URL, _init?: RequestInit) => {
    called = true;
    return new Response(JSON.stringify({ success: true, result: { id: "x" } }), { status: 200 });
  }) as typeof fetch;
  const driver = makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub });
  let threw = "";
  try { await driver.rampVersion!("v-new", "v-old", 100); } catch (e) { threw = (e as Error).message; }
  ok("ramp at 100% is refused (that is the atomic promote) without a network call", /between 1 and 99/.test(threw) && called === false);
}

console.log("-- rampVersion: a CF error becomes a cfErr message; the prior version stays at 100% --");
{
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if ((init?.method ?? "GET") === "POST" && /\/deployments$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  let threw = "";
  try { await makeCfDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, fetchImpl: stub }).rampVersion!("v-new", "v-old", 30); } catch (e) { threw = (e as Error).message; }
  ok("a ramp failure surfaces the reason and says the prior version is still serving 100%", /Authentication error/.test(threw) && /still serving 100%/.test(threw));
}

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nALL CF-DEPLOY VALIDATIONS PASS");
