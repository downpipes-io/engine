// Validates the STATIC-ASSETS DeployDriver (src/admin/cf-assets-deploy.ts) for the multi-component
// update pipeline, driven entirely with a STUB fetch (no network, no account, no cost), modelled on
// test/validate-cf-deploy.ts. The driver is untested against a live account by design (the upstream
// pipeline gates everything), so this validator's job is to prove:
//   * the CONSOLE BUNDLE parse is strict (per-asset sha256 re-verified; every malformed shape refused
//     loudly with the offending path named);
//   * the MANIFEST HASH matches wrangler's recipe EXACTLY -- blake3(base64(bytes) + ext).hex.slice(0,32)
//     -- against vectors generated from wrangler 4.103.0's own blake3 dependency (blake3-wasm 2.1.5),
//     pinned below so the reference recipe travels with the gate;
//   * the REQUEST SHAPES (upload session -> deduplicated buckets -> version -> promote) match the
//     reference client, bindings are PRESERVED (the ENGINE service binding above all), and every opaque
//     Cloudflare failure becomes a precise, actionable thrown message with nothing half-applied.
// Run: node test/validate-assets-deploy.ts

import { parseConsoleBundle, makeCfAssetsDeployDriver, assetManifestHash, CONSOLE_BUNDLE_FORMAT, type ConsoleBundle } from "../src/admin/cf-assets-deploy.ts";
import { utf8, base64Encode, sha256Hex } from "../src/crypto/bytes.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const CF = "https://api.cloudflare.com/client/v4";
const path = (url: string): string => url.replace(CF, "").replace(/\?.*$/, "");
const ACCT = "acct1";
const SCRIPT = "downpipe-console";
const TOKEN = "tok-workers-edit-1234567890";
// The engine's own script name: the ownership proof requires the console's live bindings to include a
// service binding pointing at it (matches CONSOLE_BINDINGS below).
const ENGINE_SCRIPT = "downpipe-engine";

// ---- wrangler-derived manifest-hash vectors (the load-bearing recipe) ------------------------------
// Each expected hash was computed with wrangler 4.103.0's OWN hasher (blake3-wasm 2.1.5) running the
// exact hashFile recipe: blake3(base64(fileBytes) + extensionWithoutDot).hex.slice(0, 32). Pinned here
// (rather than importing the transitive blake3-wasm) so the reference recipe is part of the gate and a
// drift in EITHER implementation fails loudly. The dotfile case pins the path.extname edge (no ext).
const WRANGLER_HASH_VECTORS: Array<{ content: Uint8Array; assetPath: string; hash: string }> = [
  { content: utf8("<h1>hi</h1>"), assetPath: "/index.html", hash: "e5e943f01929441dfbb0d4956a759fda" },
  { content: utf8("console.log(1);"), assetPath: "/app.js", hash: "9de4ebf0de975f33c87bf2b96327373b" },
  { content: utf8("body{}"), assetPath: "/tokens.css", hash: "622e1fa69535c6ed5e3a85e2ccaafd15" },
  { content: new Uint8Array([0, 1, 2, 3, 4]), assetPath: "/data/blob.bin", hash: "b27c9fca35fafb6ae38b1d1b6efd56d3" },
  { content: new Uint8Array(0), assetPath: "/empty.txt", hash: "f9bc91770fa5e997cbd47fba833629fc" },
  { content: utf8("ok"), assetPath: "/.wellknown", hash: "429d0bea2d15840799f84037b991d15c" },
  { content: new Uint8Array(1048576).fill(0x41), assetPath: "/big.js", hash: "6431c8aeec967429978c69d119e682ec" },
];

// ---- console-bundle fixture builders ---------------------------------------------------------------
const WORKER_SOURCE = utf8('export default { fetch() { return new Response("console shell"); } };');

interface RawAsset {
  path: string;
  contentType: string;
  sha256: string;
  b64: string;
}
async function rawAsset(assetPath: string, contentType: string, bytes: Uint8Array): Promise<RawAsset> {
  return { path: assetPath, contentType, sha256: await sha256Hex(bytes), b64: base64Encode(bytes) };
}

const ASSET_HTML = utf8("<!doctype html><h1>console</h1>");
const ASSET_JS = utf8("export const app = 1;");
const ASSET_CSS = utf8(":root { --teal: #0aa; }");

async function makeRawBundle(over: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return {
    format: CONSOLE_BUNDLE_FORMAT,
    version: "0.2.0",
    worker: { mainModule: "worker.js", sourceB64: base64Encode(WORKER_SOURCE) },
    config: { compatibilityDate: "2026-06-01", runWorkerFirst: true, limits: { cpu_ms: 50 } },
    assets: [
      await rawAsset("/index.html", "text/html; charset=utf-8", ASSET_HTML),
      await rawAsset("/app.js", "text/javascript", ASSET_JS),
      await rawAsset("/tokens.css", "text/css", ASSET_CSS),
    ],
    ...over,
  };
}
const encode = (bundle: Record<string, unknown>): Uint8Array => utf8(JSON.stringify(bundle));

// expectParseError parses a (deliberately broken) raw bundle and asserts the refusal names the problem.
async function expectParseError(label: string, raw: Record<string, unknown>, want: RegExp): Promise<void> {
  let threw = "";
  try {
    await parseConsoleBundle(encode(raw));
  } catch (e) {
    threw = (e as Error).message;
  }
  ok(`parse refuses: ${label}`, want.test(threw) && /nothing was changed/.test(threw));
}

async function main(): Promise<void> {
  console.log("-- assetManifestHash: matches wrangler's blake3 recipe on the pinned vectors --");
  for (const v of WRANGLER_HASH_VECTORS) {
    const got = assetManifestHash(v.content, v.assetPath);
    ok(`recipe match for ${v.assetPath} (32-hex, wrangler-derived)`, got === v.hash && /^[0-9a-f]{32}$/.test(got));
  }

  console.log("-- parseConsoleBundle: the happy path decodes + verifies every asset --");
  {
    const bundle = await parseConsoleBundle(encode(await makeRawBundle()));
    ok("version + worker parse", bundle.version === "0.2.0" && bundle.worker.mainModule === "worker.js" && bundle.worker.source.length === WORKER_SOURCE.length);
    ok("static config parses (compat date + run_worker_first + cpu limit)", bundle.config.compatibilityDate === "2026-06-01" && bundle.config.runWorkerFirst === true && bundle.config.cpuMs === 50);
    ok("all three assets decode with verified sha256", bundle.assets.length === 3 && bundle.assets[0]!.bytes.length === ASSET_HTML.length);
    ok("assets carry canonical re-encoded base64 (upload payload source)", bundle.assets[1]!.b64 === base64Encode(ASSET_JS));
    // A config-less bundle still parses (all static config optional).
    const bare = await parseConsoleBundle(encode(await makeRawBundle({ config: undefined })));
    ok("a config-less bundle parses (static config all-optional)", bare.config.compatibilityDate === undefined && bare.config.runWorkerFirst === undefined && bare.config.cpuMs === undefined);
  }

  console.log("-- parseConsoleBundle: strict refusals (loud, path-named, nothing returned) --");
  {
    let threw = "";
    try {
      await parseConsoleBundle(utf8("{ not json"));
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("parse refuses: not JSON", /not valid JSON/.test(threw));
    try {
      await parseConsoleBundle(utf8('"a string"'));
      threw = "";
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("parse refuses: not an object", /not a JSON object/.test(threw));
  }
  await expectParseError("wrong format string", await makeRawBundle({ format: "downpipe-console-bundle/9" }), /declares format/);
  await expectParseError("missing version", await makeRawBundle({ version: "" }), /declares no version/);
  await expectParseError("missing worker", await makeRawBundle({ worker: undefined }), /no worker module/);
  await expectParseError("missing worker mainModule", await makeRawBundle({ worker: { sourceB64: base64Encode(WORKER_SOURCE) } }), /no mainModule/);
  await expectParseError("missing worker source", await makeRawBundle({ worker: { mainModule: "worker.js", sourceB64: "" } }), /has no source/);
  await expectParseError("undecodable worker source", await makeRawBundle({ worker: { mainModule: "worker.js", sourceB64: "@@@@" } }), /does not decode/);
  await expectParseError("no assets", await makeRawBundle({ assets: [] }), /lists no assets/);
  await expectParseError("path without leading slash", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), path: "a.js" }] }), /malformed path/);
  await expectParseError("path with a dot-dot segment", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), path: "/../a.js" }] }), /malformed path/);
  {
    const a = await rawAsset("/a.js", "text/javascript", ASSET_JS);
    await expectParseError("duplicate asset path", await makeRawBundle({ assets: [a, a] }), /twice/);
  }
  await expectParseError("missing contentType", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "", ASSET_JS)) }] }), /no contentType/);
  await expectParseError("malformed sha256", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), sha256: "abc" }] }), /no usable sha256/);
  await expectParseError("missing content", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), b64: "" }] }), /has no content/);
  await expectParseError("undecodable content (bad char)", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), b64: "%%%%" }] }), /does not decode/);
  await expectParseError("undecodable content (bad length)", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), b64: "abcde" }] }), /does not decode/);
  await expectParseError("undecodable content (misplaced padding)", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), b64: "a===" }] }), /does not decode/);
  await expectParseError("undecodable content (non-canonical trailing bits)", await makeRawBundle({ assets: [{ ...(await rawAsset("/a.js", "text/javascript", ASSET_JS)), b64: "ab==" }] }), /does not decode/);
  {
    // The load-bearing one: content that decodes fine but does NOT match its declared sha256.
    const lying = { ...(await rawAsset("/app.js", "text/javascript", ASSET_JS)), b64: base64Encode(ASSET_CSS) };
    await expectParseError("asset sha256 mismatch (verify-before-anything)", await makeRawBundle({ assets: [lying] }), /does not match its declared sha256/);
  }
  {
    // Over the asset-count bound: 1001 entries of the same tiny file under distinct paths.
    const tiny = await rawAsset("/x0.js", "text/javascript", ASSET_JS);
    const many = Array.from({ length: 1001 }, (_v, i) => ({ ...tiny, path: `/x${i}.js` }));
    await expectParseError("over the asset-count bound", await makeRawBundle({ assets: many }), /over the 1000 bound/);
  }

  // ---- the parsed fixture + a realistic console settings read for the driver flows ---------------
  const BUNDLE: ConsoleBundle = await parseConsoleBundle(encode(await makeRawBundle()));
  const HASH_BY_PATH = new Map(BUNDLE.assets.map((a) => [a.path, assetManifestHash(a.bytes, a.path)]));
  // The console's live bindings: the ENGINE service binding (the one that must NEVER drop), the assets
  // binding identity, a var, and a secret (proving keep_bindings works for the console too).
  const CONSOLE_BINDINGS = [
    { type: "service", name: "ENGINE", service: "downpipe-engine" },
    { type: "assets", name: "ASSETS" },
    { type: "plain_text", name: "DEMO_BANNER", text: "off" },
    { type: "secret_text", name: "CONSOLE_SECRET" },
  ];
  const settingsResponse = (): Response =>
    new Response(JSON.stringify({ success: true, result: { bindings: CONSOLE_BINDINGS, compatibility_date: "2025-01-01", compatibility_flags: ["nodejs_compat"] } }), { status: 200 });

  interface VersionsMeta {
    main_module: string;
    bindings: Array<{ type: string; name: string; service?: string }>;
    keep_bindings: string[];
    compatibility_date?: string;
    compatibility_flags?: string[];
    limits?: { cpu_ms?: number };
    assets?: { jwt?: string; config?: { run_worker_first?: boolean } };
  }

  console.log("-- uploadVersion happy path: settings FIRST, session, buckets, version (bindings preserved) --");
  {
    const calls: string[] = [];
    const captured: {
      manifest: Record<string, { hash: string; size: number }> | null;
      uploadAuths: string[];
      uploadParts: Array<{ field: string; filename: string; type: string; text: string }>;
      meta: VersionsMeta | null;
      moduleType: string;
      moduleName: string;
    } = { manifest: null, uploadAuths: [], uploadParts: [], meta: null, moduleType: "", moduleName: "" };
    // Two buckets so the loop + the completion-on-final-bucket handling are both real.
    const h1 = HASH_BY_PATH.get("/index.html")!;
    const h2 = HASH_BY_PATH.get("/app.js")!;
    const h3 = HASH_BY_PATH.get("/tokens.css")!;
    let uploadsSeen = 0;
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push(`${method} ${path(url)}`);
      if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
      if (method === "POST" && /\/assets-upload-session$/.test(url)) {
        captured.manifest = (JSON.parse(String(init!.body)) as { manifest: Record<string, { hash: string; size: number }> }).manifest;
        return new Response(JSON.stringify({ success: true, result: { jwt: "session-jwt", buckets: [[h1, h2], [h3]] } }), { status: 200 });
      }
      if (method === "POST" && /\/workers\/assets\/upload/.test(url)) {
        ok("bucket upload uses the base64=true query", /base64=true/.test(url));
        captured.uploadAuths.push((init!.headers as Record<string, string>).authorization ?? "");
        const form = init!.body as FormData;
        for (const [field, value] of form.entries()) {
          if (value instanceof Blob) {
            captured.uploadParts.push({ field, filename: (value as File).name, type: value.type, text: await (value as Blob).text() });
          }
        }
        uploadsSeen++;
        // Only the FINAL bucket's response carries the completion token.
        return new Response(JSON.stringify({ success: true, result: uploadsSeen === 2 ? { jwt: "completion-jwt" } : {} }), { status: 200 });
      }
      if (method === "POST" && /\/versions$/.test(url)) {
        const form = init!.body as FormData;
        captured.meta = JSON.parse(String(form.get("metadata"))) as VersionsMeta;
        const part = form.get(captured.meta.main_module);
        if (part instanceof Blob) {
          captured.moduleType = part.type;
          captured.moduleName = (part as File).name;
        }
        return new Response(JSON.stringify({ success: true, result: { id: "cv-new" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: false, errors: [{ message: "unexpected", code: 0 }] }), { status: 500 });
    }) as typeof fetch;

    const driver = makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub });
    const id = await driver.uploadVersion(BUNDLE);
    ok("returns the created console version's id", id === "cv-new");
    ok("reads the console settings FIRST (refuse-early ordering)", calls[0] === `GET /accounts/${ACCT}/workers/scripts/${SCRIPT}/settings`);
    ok("the session is opened on the console script's assets-upload-session", calls[1] === `POST /accounts/${ACCT}/workers/scripts/${SCRIPT}/assets-upload-session`);
    const manifest = captured.manifest;
    ok("the manifest maps every asset path to { hash, size }", manifest !== null && Object.keys(manifest).length === 3 && manifest["/index.html"]?.hash === h1 && manifest["/index.html"]?.size === ASSET_HTML.length);
    ok("every manifest hash is the 32-hex wrangler recipe", manifest !== null && Object.values(manifest).every((m) => /^[0-9a-f]{32}$/.test(m.hash)));
    ok("both buckets uploaded under the SESSION token", captured.uploadAuths.length === 2 && captured.uploadAuths.every((a) => a === "Bearer session-jwt"));
    const htmlPart = captured.uploadParts.find((p) => p.field === h1);
    ok("a bucket part is keyed AND named by the manifest hash", htmlPart !== undefined && htmlPart.filename === h1);
    ok("a bucket part's body is the BASE64 TEXT of the file", htmlPart !== undefined && htmlPart.text === base64Encode(ASSET_HTML));
    ok("a bucket part carries the asset's contentType", htmlPart !== undefined && htmlPart.type === "text/html; charset=utf-8");
    const meta = captured.meta;
    if (meta === null) throw new Error("version metadata was not captured");
    ok("main_module is the bundle's shell worker", meta.main_module === "worker.js" && captured.moduleName === "worker.js");
    ok("the module part is application/javascript+module", captured.moduleType === "application/javascript+module");
    const names = new Set(meta.bindings.map((b) => b.name));
    ok("the ENGINE service binding is preserved VERBATIM", meta.bindings.some((b) => b.name === "ENGINE" && b.type === "service" && b.service === "downpipe-engine"));
    ok("the assets binding identity + vars are preserved", names.has("ASSETS") && names.has("DEMO_BANNER"));
    ok("the console secret is NOT re-sent but kept via keep_bindings", !names.has("CONSOLE_SECRET") && meta.keep_bindings.includes("secret_text"));
    ok("assets.jwt is the COMPLETION token (not the session token)", meta.assets?.jwt === "completion-jwt");
    ok("run_worker_first rides inside assets.config", meta.assets?.config?.run_worker_first === true);
    ok("compatibility_date comes from the artefact's static config", meta.compatibility_date === "2026-06-01");
    ok("compatibility_flags carry over from the live script", Array.isArray(meta.compatibility_flags) && meta.compatibility_flags[0] === "nodejs_compat");
    ok("the cpu limit rides from the artefact's static config", meta.limits?.cpu_ms === 50);
  }

  console.log("-- uploadVersion: full dedup (no buckets) uses the session token as completion --");
  {
    let uploadPosted = false;
    let sentJwt = "";
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
      if (method === "POST" && /\/assets-upload-session$/.test(url)) return new Response(JSON.stringify({ success: true, result: { jwt: "session-is-completion", buckets: [] } }), { status: 200 });
      if (method === "POST" && /\/workers\/assets\/upload/.test(url)) {
        uploadPosted = true;
        return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
      }
      if (method === "POST" && /\/versions$/.test(url)) {
        const meta = JSON.parse(String((init!.body as FormData).get("metadata"))) as VersionsMeta;
        sentJwt = meta.assets?.jwt ?? "";
        return new Response(JSON.stringify({ success: true, result: { id: "cv-dedup" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    const id = await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub }).uploadVersion(BUNDLE);
    ok("an all-deduplicated release uploads NO buckets and still versions", id === "cv-dedup" && uploadPosted === false);
    ok("the session token doubles as the completion token", sentJwt === "session-is-completion");
  }

  console.log("-- uploadVersion refusals: fail-safe at every step, nothing half-applied --");
  {
    // Settings-read failure -> refusal BEFORE the session is even opened.
    let sessionPosted = false;
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "POST" && /\/assets-upload-session$/.test(url)) sessionPosted = true;
      if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }) as typeof fetch;
    let threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub }).uploadVersion(BUNDLE);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("a settings-read failure refuses BEFORE any upload (reason surfaced)", /Authentication error/.test(threw) && /preserve its bindings/.test(threw) && sessionPosted === false);
  }
  {
    // Settings without a bindings list -> refuse blind (would risk dropping the ENGINE binding).
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET" && /\/settings$/.test(String(input))) return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }) as typeof fetch;
    let threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub }).uploadVersion(BUNDLE);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("settings without a bindings list refuses to upload blind", /without a readable bindings list/.test(threw));
  }
  {
    // An unknown binding type -> clean refusal (never a version that silently drops it).
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET" && /\/settings$/.test(String(input))) {
        return new Response(JSON.stringify({ success: true, result: { bindings: [{ type: "service", name: "ENGINE", service: ENGINE_SCRIPT }, { type: "future_widget", name: "W" }] } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }) as typeof fetch;
    let threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub }).uploadVersion(BUNDLE);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("an unknown binding type refuses cleanly (names it; nothing uploaded)", /future_widget/.test(threw) && /Nothing was uploaded/.test(threw));
  }
  // The session/upload/version failure family: each refuses with the reason + "console is unchanged".
  async function uploadFailureCase(label: string, mutate: (url: string, method: string) => Response | null, want: RegExp, alsoWant?: RegExp): Promise<void> {
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const mutated = mutate(url, method);
      if (mutated) return mutated;
      if (method === "GET" && /\/settings$/.test(url)) return settingsResponse();
      if (method === "POST" && /\/assets-upload-session$/.test(url)) {
        return new Response(JSON.stringify({ success: true, result: { jwt: "session-jwt", buckets: [[HASH_BY_PATH.get("/index.html")!]] } }), { status: 200 });
      }
      if (method === "POST" && /\/workers\/assets\/upload/.test(url)) return new Response(JSON.stringify({ success: true, result: { jwt: "completion-jwt" } }), { status: 200 });
      if (method === "POST" && /\/versions$/.test(url)) return new Response(JSON.stringify({ success: true, result: { id: "cv" } }), { status: 200 });
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    let threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub }).uploadVersion(BUNDLE);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok(label, want.test(threw) && (alsoWant === undefined || alsoWant.test(threw)));
  }
  await uploadFailureCase(
    "a rejected manifest refuses with the reason (console unchanged)",
    (url, method) => (method === "POST" && /\/assets-upload-session$/.test(url) ? new Response(JSON.stringify({ success: false, errors: [{ code: 10021, message: "manifest too large" }] }), { status: 400 }) : null),
    /manifest too large/,
    /console is unchanged/,
  );
  await uploadFailureCase(
    "a session without a token refuses (cannot upload)",
    (url, method) => (method === "POST" && /\/assets-upload-session$/.test(url) ? new Response(JSON.stringify({ success: true, result: { buckets: [] } }), { status: 200 }) : null),
    /returned no token/,
  );
  await uploadFailureCase(
    "a bucket-upload failure refuses (staged assets never serve)",
    (url, method) => (method === "POST" && /\/workers\/assets\/upload/.test(url) ? new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 }) : null),
    /Authentication error/,
    /console is unchanged/,
  );
  await uploadFailureCase(
    "a requested hash outside the verified bundle refuses",
    (url, method) => (method === "POST" && /\/assets-upload-session$/.test(url) ? new Response(JSON.stringify({ success: true, result: { jwt: "session-jwt", buckets: [["feedfacefeedfacefeedfacefeedface"]] } }), { status: 200 }) : null),
    /not in the verified console bundle/,
  );
  await uploadFailureCase(
    "a missing completion token after the final bucket refuses",
    (url, method) => (method === "POST" && /\/workers\/assets\/upload/.test(url) ? new Response(JSON.stringify({ success: true, result: {} }), { status: 200 }) : null),
    /did not return an asset-upload completion token/,
  );
  await uploadFailureCase(
    "a rejected version POST refuses (nothing deployed)",
    (url, method) => (method === "POST" && /\/versions$/.test(url) ? new Response(JSON.stringify({ success: false, errors: [{ code: 10021, message: "Uploaded script too large" }] }), { status: 400 }) : null),
    /Uploaded script too large/,
    /console is unchanged/,
  );
  await uploadFailureCase(
    "a version POST without an id refuses (cannot promote)",
    (url, method) => (method === "POST" && /\/versions$/.test(url) ? new Response(JSON.stringify({ success: true, result: {} }), { status: 200 }) : null),
    /did not return a version id/,
  );

  console.log("-- deployVersion: the atomic 100% promote (and the SAME call rolls back) --");
  {
    let sentBody: { strategy?: string; versions?: Array<{ version_id: string; percentage: number }> } | null = null;
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if ((init?.method ?? "GET") === "GET" && /\/settings$/.test(url)) return settingsResponse();
      if ((init?.method ?? "GET") === "POST" && /\/deployments$/.test(url)) {
        sentBody = JSON.parse(String(init!.body)) as typeof sentBody;
        return new Response(JSON.stringify({ success: true, result: { id: "d-new" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    const driver = makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub });
    await driver.deployVersion("cv-new");
    const body = sentBody as { strategy?: string; versions?: Array<{ version_id: string; percentage: number }> } | null;
    ok("promote posts a 100% percentage deployment of the given id", body?.strategy === "percentage" && body?.versions?.[0]?.version_id === "cv-new" && body?.versions?.[0]?.percentage === 100);
    await driver.deployVersion("cv-prior"); // rollback is the same call with the prior id
    const body2 = sentBody as { versions?: Array<{ version_id: string }> } | null;
    ok("rollback deploys the recorded prior console version via the same method", body2?.versions?.[0]?.version_id === "cv-prior");
  }
  {
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET" && /\/settings$/.test(String(input))) return settingsResponse();
      if ((init?.method ?? "GET") === "POST" && /\/deployments$/.test(String(input))) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    let threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub }).deployVersion("cv-new");
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("a failed promote says the previously-live console version is still serving", /Authentication error/.test(threw) && /previously-live console version is still serving/.test(threw));
  }

  console.log("-- the ownership proof: no ENGINE service binding pointing at this engine -> refuse every mutation --");
  {
    // ownershipStub serves settings whose service binding points at a DIFFERENT engine (another install's
    // console -- the exact hazard a defaulted CONSOLE_WORKER_NAME creates on a -demo engine), and counts
    // every mutating call so the refusal is proven to happen BEFORE anything is touched.
    const makeOwnershipStub = (bindings: Array<Record<string, unknown>>): { stub: typeof fetch; mutations: () => number } => {
      let mutations = 0;
      const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        if (method === "GET" && /\/settings$/.test(url)) {
          return new Response(JSON.stringify({ success: true, result: { bindings } }), { status: 200 });
        }
        if (method === "POST") mutations++;
        return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
      }) as typeof fetch;
      return { stub, mutations: () => mutations };
    };
    const otherEngine = [{ type: "service", name: "ENGINE", service: "someone-elses-engine" }, { type: "assets", name: "ASSETS" }];
    const noService = [{ type: "assets", name: "ASSETS" }, { type: "plain_text", name: "X", text: "y" }];
    for (const [label, bindings] of [["points at another engine", otherEngine], ["has no service binding at all", noService]] as const) {
      const up = makeOwnershipStub(bindings as Array<Record<string, unknown>>);
      let threw = "";
      try {
        await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: up.stub }).uploadVersion(BUNDLE);
      } catch (e) {
        threw = (e as Error).message;
      }
      ok(`uploadVersion refuses when the console ${label} (names CONSOLE_WORKER_NAME, nothing touched)`, /no service binding pointing at this engine/.test(threw) && /CONSOLE_WORKER_NAME/.test(threw) && up.mutations() === 0);
      const dep = makeOwnershipStub(bindings as Array<Record<string, unknown>>);
      threw = "";
      try {
        await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: dep.stub }).deployVersion("cv-any");
      } catch (e) {
        threw = (e as Error).message;
      }
      ok(`deployVersion (promote/rollback) refuses when the console ${label} (nothing deployed)`, /no service binding pointing at this engine/.test(threw) && dep.mutations() === 0);
    }
  }

  console.log("-- currentLiveVersionId / currentLiveVersions: the rollback-target read --");
  {
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET" && /\/deployments$/.test(String(input))) {
        return new Response(JSON.stringify({ success: true, result: { deployments: [{ versions: [{ version_id: "cv-live" }] }, { versions: [{ version_id: "cv-old" }] }] } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    const driver = makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub });
    ok("returns the ACTIVE deployment's version id", (await driver.currentLiveVersionId()) === "cv-live");
    const slices = await driver.currentLiveVersions();
    ok("a single-version deployment reads as one 100% slice", slices.length === 1 && slices[0]!.percentage === 100);
  }
  {
    // A (never-ours, out-of-band) split still reports the dominant slice + the full set.
    const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET" && /\/deployments$/.test(String(input))) {
        return new Response(JSON.stringify({ success: true, result: { deployments: [{ versions: [{ version_id: "cv-a", percentage: 30 }, { version_id: "cv-b", percentage: 70 }] }] } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: false }), { status: 500 });
    }) as typeof fetch;
    const driver = makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: stub });
    ok("a split reports the DOMINANT slice as the live version", (await driver.currentLiveVersionId()) === "cv-b");
    ok("the full slice set is exposed", (await driver.currentLiveVersions()).length === 2);
  }
  {
    const emptyStub = (async () => new Response(JSON.stringify({ success: true, result: { deployments: [] } }), { status: 200 })) as typeof fetch;
    let threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: emptyStub }).currentLiveVersionId();
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("no deployments -> throws (nothing to roll back to)", /no deployments|no current live console version/.test(threw) && /Nothing was changed/.test(threw));
    const noVerStub = (async () => new Response(JSON.stringify({ success: true, result: { deployments: [{ versions: [] }] } }), { status: 200 })) as typeof fetch;
    threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: noVerStub }).currentLiveVersionId();
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("a deployment without a version id throws", /did not include a version id/.test(threw));
    const errStub = (async () => new Response("not json", { status: 502 })) as typeof fetch;
    threw = "";
    try {
      await makeCfAssetsDeployDriver({ token: TOKEN, accountId: ACCT, scriptName: SCRIPT, engineScriptName: ENGINE_SCRIPT, fetchImpl: errStub }).currentLiveVersionId();
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("an unparseable non-2xx body still throws with the HTTP status", /HTTP 502/.test(threw));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nALL ASSETS-DEPLOY VALIDATIONS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
