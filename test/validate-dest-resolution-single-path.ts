// A CLASS GUARD over destination-id resolution. A downpipe names its destinations by id, and three kinds of id
// exist: a console-stored destination, the synthetic deploy-time destination (DEPLOY_DEST_ID, "deploy"), and an
// id with no record. dest/factory.ts fetchDestConfig answers the first with a config and BOTH of the other two
// with the same null, so any caller that resolves an id through it and reads null as "not configured" reads the
// deploy-time destination as missing. That is how the fan-out seal, replication, retention, the orphan reconcile
// and the scheduled drill all stopped serving "deploy" on engine 0.3.5.
//
// The fix is structural: resolveDestination (dest/factory.ts) is the one resolver, and it keeps the three apart.
// This gate makes a second resolver impossible to add without going red:
//   1. SOURCE SCAN: no src file outside dest/factory.ts calls fetchDestConfig, and none outside it (and the
//      scheduler DO that serves the route) reads the DO's /dest-config route directly.
//   2. CONSUMER REGISTRY: every module that resolves a destination id imports a resolver entry point. A zero
//      needs a population that could have held it, so the registry is checked to be non-empty and each member
//      to exist.
//   3. RESOLVER TABLE: resolveDestination answers every (id, stored rows, env) shape with the expected branch.
//   4. THE GATE CAN FAIL: the scanner is run over planted regressions (a direct call, a direct route read) and
//      must flag each; a comment that merely mentions the function must not be flagged.
//
// Run: node test/validate-dest-resolution-single-path.ts

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { DEST_RESOLUTION_BRANCHES, type DestResolution, resolveDestination } from "../src/dest/factory.ts";
import { DEPLOY_DEST_ID } from "../src/dest/dest-resolution.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "src");

// The one module allowed to call fetchDestConfig and to read the /dest-config route.
const RESOLVER_MODULE = "src/dest/factory.ts";
// The scheduler DO SERVES the route; its files name it as a route key, never as a read for use.
const ROUTE_SERVER_PREFIX = "src/sched/";

// The modules that resolve a destination id, and the resolver entry point each must import. A new consumer is
// added here; a consumer removed from src makes this gate red until it is removed here too.
const CONSUMERS: ReadonlyArray<{ file: string; path: string; via: readonly string[] }> = [
  { file: "src/cron/seal-dispatch.ts", path: "seal choice and fan-out failover", via: ["resolveDestination"] },
  { file: "src/seal/replicate.ts", path: "replication, target and origin (stranded runs)", via: ["resolveDestination"] },
  { file: "src/canary/cycle.ts", path: "canary", via: ["resolveDestination"] },
  { file: "src/admin/router-sources.ts", path: "restore and drill read walk", via: ["resolveDestination"] },
  { file: "src/cron/restore-test-pass.ts", path: "scheduled drill", via: ["resolveDestForState"] },
  { file: "src/admin/router-pipelines.ts", path: "manual drill", via: ["withRunDestFallback"] },
  { file: "src/admin/router-restore.ts", path: "restore, blind test, attest", via: ["withRunDestFallback"] },
  { file: "src/cron/retention-pass.ts", path: "scheduled retention prune", via: ["resolveDestination"] },
  { file: "src/admin/router-retention-prune.ts", path: "on-demand retention prune", via: ["resolveDestination"] },
  { file: "src/cron/reconcile-pass.ts", path: "orphan reconcile", via: ["resolveDestination"] },
  { file: "src/cron/control-plane-pass.ts", path: "control-plane export", via: ["resolveDestination", "resolveDefaultDestConfig"] },
  { file: "src/admin/router-destinations.ts", path: "destination verify", via: ["resolveDestination"] },
  { file: "src/admin/router-posture.ts", path: "WORM posture over written destinations", via: ["resolveDestination"] },
];

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

// codeLines drops comment-only lines and trailing line comments, so a comment that DISCUSSES fetchDestConfig
// is not a call. A "//" inside a string (a URL) is kept: a trailing comment is only cut at " // ".
function codeLines(text: string): string[] {
  const out: string[] = [];
  let inBlock = false;
  for (const raw of text.split("\n")) {
    let line = raw;
    if (inBlock) {
      const end = line.indexOf("*/");
      if (end === -1) continue;
      line = line.slice(end + 2);
      inBlock = false;
    }
    const t = line.trim();
    if (t.startsWith("//") || t.startsWith("*")) continue;
    if (t.startsWith("/*")) {
      if (!t.includes("*/")) inBlock = true;
      continue;
    }
    const cut = line.indexOf(" // ");
    out.push(cut === -1 ? line : line.slice(0, cut));
  }
  return out;
}

interface Finding {
  file: string;
  line: string;
  rule: "direct-fetchDestConfig" | "direct-dest-config-route";
}

// scan is the gate itself, a pure function of (relative path, text), so the planted regressions below run it.
export function scan(rel: string, text: string): Finding[] {
  const findings: Finding[] = [];
  if (rel === RESOLVER_MODULE) return findings;
  const lines = codeLines(text);
  lines.forEach((line, i) => {
    if (/\bfetchDestConfig\s*\(/.test(line)) findings.push({ file: rel, line: line.trim(), rule: "direct-fetchDestConfig" });
    if (!rel.startsWith(ROUTE_SERVER_PREFIX) && /["'`][^"'`]*\/dest-config(\?|["'`])/.test(line)) {
      // A POST to the route is the console's SET/CLEAR of a destination (router-destinations.ts), a write that
      // resolves nothing. Only a read of the route is a second resolver.
      const call = lines.slice(i, i + 4).join(" ");
      if (!/method:\s*"POST"/.test(call)) findings.push({ file: rel, line: line.trim(), rule: "direct-dest-config-route" });
    }
  });
  return findings;
}

function sourceScan(): void {
  console.log("-- 1. source scan: one resolver --");
  const files = walk(SRC);
  ok(`POPULATION: the scan read the engine source (${files.length} .ts files)`, files.length > 300);
  const factory = readFileSync(join(ROOT, RESOLVER_MODULE), "utf8");
  ok("POPULATION: the resolver module defines fetchDestConfig and resolveDestination", /export async function fetchDestConfig\(/.test(factory) && /export async function resolveDestination\(/.test(factory));
  ok("POPULATION: the resolver module is the one that reads the /dest-config route", /scheduler\.internal\/dest-config/.test(factory));
  const findings = files.flatMap((f) => {
    const rel = relative(ROOT, f).split("\\").join("/");
    return scan(rel, readFileSync(f, "utf8"));
  });
  for (const f of findings) console.log(`       ${f.rule}: ${f.file}: ${f.line.slice(0, 140)}`);
  ok("no src file outside dest/factory.ts calls fetchDestConfig", findings.every((f) => f.rule !== "direct-fetchDestConfig"));
  ok("no src file outside dest/factory.ts (and the DO that serves it) reads the /dest-config route (a POST that sets one is a write)", findings.every((f) => f.rule !== "direct-dest-config-route"));
}

function consumerRegistry(): void {
  console.log("-- 2. consumer registry: every id-resolving path imports a resolver entry point --");
  ok(`POPULATION: the registry names ${CONSUMERS.length} consumers`, CONSUMERS.length >= 12);
  for (const c of CONSUMERS) {
    let text = "";
    try {
      text = readFileSync(join(ROOT, c.file), "utf8");
    } catch {
      ok(`${c.path}: ${c.file} exists`, false);
      continue;
    }
    const imports = codeLines(text).filter((l) => /^\s*import\b/.test(l) || /^\s*[\w\s,{}]*\}\s*from\s/.test(l)).join("\n");
    const uses = c.via.some((v) => new RegExp(`\\b${v}\\b`).test(imports) && new RegExp(`\\b${v}\\s*\\(`).test(codeLines(text).join("\n")));
    ok(`${c.path}: ${c.file} imports and calls ${c.via.join(" or ")}`, uses);
  }
}

// ---------------------------------------------------------------------------------------------------------
// 3. The resolver table. A scheduler stub answering /dest-config as the DO's getDestConfigById does.
// ---------------------------------------------------------------------------------------------------------
const CONSOLE_ROW = { id: "dest-s3", label: "S3", endpoint: "https://s3.example.test", bucket: "b", region: "us-east-1", accessKeyId: "AKID", secretAccessKey: "not-a-real-secret", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" };
const DEPLOY_ROW = { id: DEPLOY_DEST_ID, label: "Deploy-time destination", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "other" };

function stub(list: Array<Record<string, unknown>>, defaultId: string): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.pathname === "/dest-config") {
        const id = u.searchParams.get("id");
        if (list.length === 0) return Response.json({ config: null });
        return Response.json({ config: id ? (list.find((d) => d.id === id) ?? null) : (list.find((d) => d.id === defaultId) ?? null) });
      }
      return Response.json({ ok: true });
    },
  } as unknown as DurableObjectStub;
}

const R2_ENV = { DEST_R2: {} } as unknown as Env;
const S3_ENV = { DEST_ENDPOINT: "https://env.example.test", DEST_BUCKET: "b", DEST_REGION: "auto", DEST_ACCESS_KEY_ID: "k", DEST_SECRET_ACCESS_KEY: "s" } as unknown as Env;
const NO_ENV = {} as unknown as Env;
const BOTH = [DEPLOY_ROW, CONSOLE_ROW];

type Expect = { ok: true; branch: DestResolution["branch"] } | { ok: false; reason: string };
const TABLE: ReadonlyArray<{ label: string; env: Env; list: Array<Record<string, unknown>>; defaultId: string; id: string | null | undefined; expect: Expect }> = [
  { label: "\"deploy\" with the R2 binding", env: R2_ENV, list: BOTH, defaultId: "deploy", id: "deploy", expect: { ok: true, branch: "deploy-env-binding" } },
  { label: "\"deploy\" with DEST_* S3 variables", env: S3_ENV, list: BOTH, defaultId: "deploy", id: "deploy", expect: { ok: true, branch: "deploy-env-binding" } },
  { label: "\"deploy\" while a console destination is the default", env: R2_ENV, list: BOTH, defaultId: "dest-s3", id: "deploy", expect: { ok: true, branch: "deploy-env-binding" } },
  { label: "\"deploy\" named with no env destination", env: NO_ENV, list: BOTH, defaultId: "deploy", id: "deploy", expect: { ok: false, reason: "deploy-binding-missing" } },
  { label: "a console-stored id", env: R2_ENV, list: BOTH, defaultId: "deploy", id: "dest-s3", expect: { ok: true, branch: "console-stored" } },
  { label: "a console-stored id with no env destination", env: NO_ENV, list: BOTH, defaultId: "deploy", id: "dest-s3", expect: { ok: true, branch: "console-stored" } },
  { label: "an id with no record", env: R2_ENV, list: BOTH, defaultId: "deploy", id: "gone", expect: { ok: false, reason: "not-configured" } },
  { label: "the default when it is the deploy-time record", env: R2_ENV, list: BOTH, defaultId: "deploy", id: undefined, expect: { ok: true, branch: "deploy-env-binding" } },
  { label: "the default when it is the deploy-time record, no env (the build names the variable)", env: NO_ENV, list: BOTH, defaultId: "deploy", id: null, expect: { ok: true, branch: "deploy-env-binding" } },
  { label: "the default when it is a console destination", env: R2_ENV, list: BOTH, defaultId: "dest-s3", id: undefined, expect: { ok: true, branch: "console-stored" } },
  { label: "the default with no stored destinations", env: R2_ENV, list: [], defaultId: "", id: undefined, expect: { ok: true, branch: "env-no-collection" } },
  { label: "an empty-string id reads as the default", env: R2_ENV, list: BOTH, defaultId: "deploy", id: "", expect: { ok: true, branch: "deploy-env-binding" } },
];

async function resolverTable(): Promise<void> {
  console.log("-- 3. resolver table --");
  const seen = new Set<string>();
  for (const row of TABLE) {
    const res = await resolveDestination(row.env, stub(row.list, row.defaultId), row.id);
    seen.add(res.branch);
    const pass = row.expect.ok ? res.ok && res.branch === row.expect.branch : !res.ok && res.reason === row.expect.reason;
    ok(`${row.label}: ${row.expect.ok ? row.expect.branch : row.expect.reason}`, pass);
    if (res.ok && res.branch === "deploy-env-binding") ok(`${row.label}: the override is null (the env-backed destination)`, res.config === null);
    if (res.ok && res.branch === "console-stored") ok(`${row.label}: the override is the stored config`, res.config !== null && res.config.bucket === "b");
  }
  ok("the table reaches every branch of the closed vocabulary", DEST_RESOLUTION_BRANCHES.every((b) => seen.has(b)));
}

function gateCanFail(): void {
  console.log("-- 4. the gate can fail: planted regressions --");
  const plantedCall = scan("src/canary/cycle.ts", "const destCfg = await fetchDestConfig(scheduler, ctx.run.destinationId, wrapKey);\n");
  ok("a direct fetchDestConfig(..., id) call in a consumer is flagged", plantedCall.some((f) => f.rule === "direct-fetchDestConfig"));
  const plantedRoute = scan("src/cron/retention-pass.ts", 'const r = await scheduler.fetch("https://scheduler.internal/dest-config?id=" + encodeURIComponent(id));\n');
  ok("a direct read of the /dest-config route in a consumer is flagged", plantedRoute.some((f) => f.rule === "direct-dest-config-route"));
  const plantedDoUrl = scan("src/seal/replicate.ts", 'const r = await scheduler.fetch(doURL("/dest-config"), { method: "GET" });\n');
  ok("a doURL(\"/dest-config\") read in a consumer is flagged", plantedDoUrl.some((f) => f.rule === "direct-dest-config-route"));
  const write = scan("src/admin/router-destinations.ts", 'return scheduler.fetch(doURL("/dest-config"), {\n  method: "POST",\n  body: JSON.stringify({ config: null }),\n});\n');
  ok("NEGATIVE CONTROL: a POST that sets or clears a destination is not a read, and is not flagged", write.length === 0);
  const comment = scan("src/seal/replicate.ts", "// fetchDestConfig(scheduler, id) used to answer null here\n  /* fetchDestConfig(x) */\n");
  ok("NEGATIVE CONTROL: a comment that mentions fetchDestConfig( is not flagged", comment.length === 0);
  const resolverItself = scan(RESOLVER_MODULE, "return fetchDestConfig(scheduler, id);\n");
  ok("NEGATIVE CONTROL: the resolver module itself is exempt", resolverItself.length === 0);
}

async function main(): Promise<void> {
  sourceScan();
  consumerRegistry();
  await resolverTable();
  gateCanFail();
  console.log(failures === 0 ? "\nDEST RESOLUTION SINGLE PATH PASS\n" : `\nDEST RESOLUTION SINGLE PATH FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
