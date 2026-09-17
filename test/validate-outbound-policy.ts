// validate-outbound-policy: the engine's outbound network policy holds across the whole source tree
// (ASVS V13.2.5, V15.3.2). A census, not a sample: every outbound call site in src/ is found and graded.
//
//   (1) REDIRECTS. Every outbound fetch states redirect: "manual" in its own RequestInit, or is one of the
//       named wrappers whose init is built with it above the call. A new call site that says nothing about
//       redirects fails this gate until it does.
//   (2) FIXED HOSTS. The vendor hosts live in src/lib/outbound.ts and nowhere else: a literal
//       api.cloudflare.com, cloudflare-dns.com, update.downpipes.io or login.microsoftonline.com anywhere
//       else in src/ is refused, so a host cannot drift back into a module.
//   (3) ANTI-VACUITY. The census must find at least OUTBOUND_SITES_FLOOR call sites (the tree carries more
//       than fifty), so an empty walk cannot pass.
//   --self-test plants a bare fetch and a stray host literal in a scratch tree and proves both are found.
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verdictReached } from "./lib/verdict-guard.ts";

const OUTBOUND_SITES_FLOOR = 40;
const VENDOR_LITERALS = ["api.cloudflare.com", "cloudflare-dns.com", "update.downpipes.io", "login.microsoftonline.com"];
// Call sites whose RequestInit is a variable built with redirect: "manual" earlier in the same function, or
// a wrapper that itself forwards to a screened site. Each names the file and the exact call text.
const WRAPPED_SITES: ReadonlyArray<{ file: string; call: string; why: string }> = [
  { file: "src/sources/cf-config-core.ts", call: "fetchImpl(`${CF_API_BASE}${path}`, init)", why: "init is built with redirect: manual in makeCfApi" },
  { file: "src/dest/s3.ts", call: "fetch(input, { ...sendInit, signal: controller.signal })", why: "sendInit spreads the caller's init, which s3.ts and s3-read-ops.ts build with redirect: manual" },
  { file: "src/sources/byte-fetch.ts", call: "doFetch(t, { range: \"bytes=0-0\" }, meter)", why: "doFetch forwards to the redirect: manual fetch at byte-fetch.ts, the one bounded Stream hop" },
  { file: "src/sources/byte-fetch.ts", call: "doFetch(t, {}, meter)", why: "as above" },
  { file: "src/sources/byte-fetch.ts", call: "doFetch(t, extra, meter)", why: "as above" },
  { file: "src/sources/chaos-fault.ts", call: "realFetch(input, init)", why: "a pass-through wrapper: the caller's init carries the policy" },
];

let failures = 0;
function ok(label: string, cond: boolean): void { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`); if (!cond) failures++; }

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts") && !p.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

// The outbound call shape: fetch( / fetchImpl( / doFetch( / realFetch( that is NOT a method call (.fetch(),
// NOT a handler or interface declaration (fetch(req: / fetch(input:), and NOT inside a comment.
const CALL = /(^|[^.\w])(fetch|fetchImpl|doFetch|realFetch)\(/;
function callText(src: string, at: number): string {
  // From the opening paren, take the balanced argument list.
  let depth = 0;
  for (let i = at; i < src.length; i++) {
    const c = src[i];
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return src.slice(at, i + 1); }
  }
  return src.slice(at);
}

interface Census { sites: number; bareSites: string[]; strayLiterals: string[] }
function census(root: string): Census {
  let sites = 0;
  const bareSites: string[] = [];
  const strayLiterals: string[] = [];
  for (const file of walk(join(root, "src"))) {
    const rel = file.slice(root.length + 1);
    const src = readFileSync(file, "utf8");
    const lines = src.split("\n");
    lines.forEach((rawLine, i) => {
      const t = rawLine.trim();
      if (t.startsWith("//") || t.startsWith("*")) return;
      // A trailing comment can mention fetch() without making a call.
      const line = rawLine.replace(/\s\/\/.*$/, "");
      // oidc-presets.ts carries the Entra ISSUER templates an operator's OIDC connection is seeded from: the
      // engine calls the issuer the operator saved (screened as a configured host), never this literal.
      if (rel !== "src/lib/outbound.ts" && rel !== "src/admin/oidc-presets.ts" && VENDOR_LITERALS.some((h) => line.includes(h))) strayLiterals.push(`${rel}:${i + 1}`);
      const m = CALL.exec(line);
      if (!m) return;
      // Declarations and handlers are not calls.
      if (/fetch\((req|input|request)\b\s*[:)]/.test(line) || /async fetch\(/.test(line)) return;
      sites++;
      const lineStart = lines.slice(0, i).reduce((n, l) => n + l.length + 1, 0);
      const at = lineStart + line.indexOf("(", m.index + m[1]!.length + m[2]!.length);
      const call = callText(src, at);
      const wrapped = WRAPPED_SITES.some((w) => w.file === rel && line.includes(w.call));
      if (!wrapped && !/redirect\s*:/.test(call)) bareSites.push(`${rel}:${i + 1}`);
    });
  }
  return { sites, bareSites, strayLiterals };
}

function selfTest(): void {
  const root = mkdtempSync(join(tmpdir(), "outbound-policy-"));
  try {
    mkdirSync(join(root, "src", "lib"), { recursive: true });
    writeFileSync(join(root, "src", "lib", "outbound.ts"), 'export const CF_API_BASE = "https://api.cloudflare.com/client/v4";\n');
    writeFileSync(join(root, "src", "good.ts"), 'export async function g(u: string) { const r = await fetch(u, { method: "GET", redirect: "manual" }); return r.ok; }\n');
    writeFileSync(join(root, "src", "bad.ts"), 'export async function b(u: string) { const r = await fetch(u, { method: "GET" }); return r.ok; }\nconst X = "https://api.cloudflare.com/client/v4";\n');
    const c = census(root);
    ok("self-test: the planted bare fetch is found", c.bareSites.length === 1 && c.bareSites[0]!.startsWith("src/bad.ts:"));
    ok("self-test: the compliant fetch is not reported", !c.bareSites.some((s) => s.startsWith("src/good.ts")));
    ok("self-test: the stray vendor literal is found and outbound.ts's own is not", c.strayLiterals.length === 1 && c.strayLiterals[0]!.startsWith("src/bad.ts:"));
    ok("self-test: both sites are counted", c.sites === 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function main(): void {
  if (process.argv.includes("--self-test")) {
    console.log("\noutbound policy self-test");
    selfTest();
  }
  console.log("\noutbound policy census over src/");
  const c = census(process.cwd());
  ok(`the census found at least ${OUTBOUND_SITES_FLOOR} outbound call sites (found ${c.sites})`, c.sites >= OUTBOUND_SITES_FLOOR);
  ok(`every outbound call states redirect: "manual" or is a named wrapper${c.bareSites.length ? ` (bare: ${c.bareSites.join(", ")})` : ""}`, c.bareSites.length === 0);
  ok(`no vendor host literal outside src/lib/outbound.ts${c.strayLiterals.length ? ` (stray: ${c.strayLiterals.join(", ")})` : ""}`, c.strayLiterals.length === 0);
  console.log(failures === 0 ? "\nOUTBOUND POLICY CENSUS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
main();
