// Validates that every call site of a MULTI-SITE safety guard is HELD, not just the one site whose
// author was looking at it. Five guard families, thirty-five call sites, none of which had a gate over
// more than a fraction of itself.
//
// WHY THIS EXISTS. The key-ceremony reset ladder was applied to SIX call sites and its gate drove ONE, so
// deleting the argument that carries the fix from the other five would reproduce a severe defect and red
// nothing. The general question this raises is cheap to ask: FOR EVERY REPAIR, IS THE SET OF SITES THE FIX
// TOUCHES EQUAL TO THE SET OF SITES THE GATE DRIVES.
//
// IT IS NOT. Every one of the thirty-five sites below was mutated on its own, serially, against the eleven
// members that fail when all thirty-five are broken at once. TWELVE OF THE THIRTY-FIVE WERE KILLED BY
// NOTHING: deleting all twelve together left the engine's entire validate chain green.
// Twelve safety call sites across five independent families, deleted simultaneously, and nothing caught it.
//
// WHAT THE TWELVE WERE, because a count is not a finding:
//   src/admin/oidc.ts:145            the SSRF screen INSIDE guardedOidcFetch, the single choke point every
//                                    OIDC and OAuth2 discovery / jwks / token / userinfo fetch goes through
//   src/admin/idp-test-shared.ts:85  the same screen on the read-only IdP test probe
//   src/admin/router-identity.ts     the no-custody re-assertion on export-download, estate-import and
//     :275, :315, :419               estate-import-sealed (three of that route file's six)
//   src/admin/control-plane-seal.ts:173  the no-custody re-assertion on the sealed-envelope open
//   src/cron/control-plane-pass.ts:690   the same on the CRON auto-heal path, which no operator watches
//   src/sched/scheduler-do-roster.ts:48,:49   the roster ghost and never-ran cap-truncation bookings
//   src/sched/scheduler-do-observability.ts:359  the reconcile-signal-map cap-truncation booking
//   src/sched/scheduler-do-canary.ts:112 the dest-excluded-by-cap canary loss: the destinations past
//                                    CANARY_MAX_DESTS are never flown and support reads full coverage
//   src/admin/restore-sinks.ts:389   guardTarget on the SECRETS sink, one of the four sinks in the
//                                    function whose own comment calls it "the single reserved-binding
//                                    choke point"; the other three are held and this one was not
//
// WHAT IS GRADED HERE, in two halves.
//   A. BEHAVIOURAL, over the three unheld sites a unit test can actually reach. Each is TWO-SIDED: a
//      TREATMENT that only the deleted guard refuses, and a CONTROL that a SECOND, surviving screen
//      refuses anyway. The control is the load-bearing one. guardedOidcFetch carries isInternalSinkHost
//      immediately after the line under test, so a treatment of "an internal IP is refused" would pass
//      with the guard deleted and this file would be a gate that has never seen its defect. The
//      treatments here are therefore the cases ONLY assertSafeFetchEndpoint refuses: a plain-http host
//      and a cloudflareaccess.com host.
//   B. SOURCE CENSUS for the nine that behaviour cannot reach without a live Cloudflare fault, a cron
//      tick or a signed control-plane artefact, and because a count is the only thing that notices an
//      ELEVENTH site being added without the guard. Every census reconciles read + comment-dropped +
//      quoted-dropped against the RAW occurrence count exactly, so a sweep that silently loses a site
//      cannot read as a complete one. It also grades the NEGATIVE direction: no call may name a surface
//      or kind outside its declared closed vocabulary, which is what an over-fix looks like here.
//
// Run: node test/validate-multisite-guard-completeness.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { guardedOidcFetch } from "../src/admin/oidc.ts";
import { screenFetchUrl } from "../src/admin/idp-test-shared.ts";
import { resolveSink } from "../src/admin/restore-sinks.ts";
import { RESERVED_BINDINGS } from "../src/sched/config-validate.ts";
import { CAP_TRUNCATION_SURFACES } from "../src/sched/sched-fault-core.ts";
import { CANARY_LOSS_KINDS } from "../src/sched/sched-fault-ledger.ts";
import type { ShardRecord } from "../src/format/manifest.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

// ---- the reader, which asserts its own accounting ------------------------------------------------
//
// Splits a source file into CODE, COMMENT and QUOTED views of equal length, so an identifier's raw
// occurrence count must equal the sum of the three. This repo has lost a sweep to a scanner reading a
// comment as code and to a regex with an apostrophe that opened a phantom string; the reconciliation
// below is what makes either of those a FAILURE rather than a smaller number nobody questions.
interface Views {
  raw: string;
  code: string; // comments AND string literals blanked: the view identifiers are counted in
  codeNC: string; // comments blanked, string LITERALS KEPT: the view a closed vocabulary is read from
  comment: string;
  quoted: string;
}
function views(src: string): Views {
  const code = src.split("");
  const comment = new Array<string>(src.length).fill(" ");
  const quoted = new Array<string>(src.length).fill(" ");
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      let j = i;
      while (j < n && src[j] !== "\n") {
        comment[j] = src[j] as string;
        code[j] = " ";
        j++;
      }
      i = j;
      continue;
    }
    if (c === "/" && d === "*") {
      let j = i;
      while (j < n && !(src[j] === "*" && src[j + 1] === "/")) {
        comment[j] = src[j] as string;
        code[j] = " ";
        j++;
      }
      for (let k = j; k < Math.min(j + 2, n); k++) {
        comment[k] = src[k] as string;
        code[k] = " ";
      }
      i = j + 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      let j = i + 1;
      quoted[i] = c;
      code[i] = " ";
      while (j < n) {
        if (src[j] === "\\") {
          quoted[j] = src[j] as string;
          code[j] = " ";
          if (j + 1 < n) {
            quoted[j + 1] = src[j + 1] as string;
            code[j + 1] = " ";
          }
          j += 2;
          continue;
        }
        if (src[j] === q) {
          quoted[j] = src[j] as string;
          code[j] = " ";
          j++;
          break;
        }
        quoted[j] = src[j] as string;
        code[j] = " ";
        j++;
      }
      i = j;
      continue;
    }
    i++;
  }
  const joinedCode = code.join("");
  const joinedComment = comment.join("");
  const joinedQuoted = quoted.join("");
  // codeNC is the raw text with COMMENT spans blanked and everything else, strings included, left alone.
  const nc = src.split("");
  for (let k = 0; k < src.length; k++) if (joinedComment[k] !== " ") nc[k] = " ";
  return { raw: src, code: joinedCode, codeNC: nc.join(""), comment: joinedComment, quoted: joinedQuoted };
}
const cache = new Map<string, Views>();
function read(rel: string): Views {
  const hit = cache.get(rel);
  if (hit) return hit;
  const v = views(readFileSync(join(SRC, rel), "utf8"));
  cache.set(rel, v);
  return v;
}
function count(hay: string, name: string): number {
  return (hay.match(new RegExp(`\\b${name}\\b`, "g")) ?? []).length;
}
// callSites counts `name(` in the CODE view only, never counting the declaration itself.
function callSites(v: Views, name: string): number {
  let n = 0;
  for (const line of v.code.split("\n")) {
    if (/^\s*(export\s+)?(async\s+)?function\s/.test(line) && line.includes(`${name}(`)) continue;
    n += (line.match(new RegExp(`\\b${name}\\s*\\(`, "g")) ?? []).length;
  }
  return n;
}
// reconciled asserts the accounting rule for one identifier in one file and returns whether it held.
function reconciled(rel: string, name: string): boolean {
  const v = read(rel);
  const raw = count(v.raw, name);
  const sum = count(v.code, name) + count(v.comment, name) + count(v.quoted, name);
  ok(`accounting holds for ${name} in ${rel}: raw ${raw} = code + comment + quoted ${sum}`, raw === sum && raw > 0);
  return raw === sum && raw > 0;
}

async function main(): Promise<void> {
  console.log("MULTI-SITE GUARD COMPLETENESS\n");

  // =================================================================================================
  // A1. src/admin/oidc.ts:145 -- the SSRF screen inside guardedOidcFetch.
  // =================================================================================================
  console.log("A1. guardedOidcFetch screens the URL BEFORE it fetches (src/admin/oidc.ts)");
  {
    const seen: string[] = [];
    const doFetch = (async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;

    async function attempt(url: string): Promise<{ threw: boolean; fetched: number }> {
      const before = seen.length;
      try {
        await guardedOidcFetch(url, { method: "GET" }, doFetch);
        return { threw: false, fetched: seen.length - before };
      } catch {
        return { threw: true, fetched: seen.length - before };
      }
    }

    // TREATMENT: only assertSafeFetchEndpoint refuses these. isInternalSinkHost does not screen a public
    // name on plain http, and it does not know cloudflareaccess.com. Both flip when the guard is deleted.
    const httpPublic = await attempt("http://idp.example.com/.well-known/openid-configuration");
    ok("TREATMENT a plain-http endpoint on a PUBLIC host is refused", httpPublic.threw);
    ok("TREATMENT and it is refused BEFORE the fetch, so nothing left the engine", httpPublic.fetched === 0);
    const cfAccess = await attempt("https://acme.cloudflareaccess.com/cdn-cgi/access/certs");
    ok("TREATMENT a cloudflareaccess.com endpoint is refused", cfAccess.threw);
    ok("TREATMENT and it too is refused before the fetch", cfAccess.fetched === 0);
    const noScheme = await attempt("idp.example.com/jwks");
    ok("TREATMENT an endpoint that is not an absolute URL is refused", noScheme.threw);

    // CONTROLS, which pass either way and are what stop this cell from reading as "refuse everything".
    const good = await attempt("https://accounts.example.com/.well-known/jwks.json");
    ok("CONTROL a conformant https endpoint is fetched", !good.threw && good.fetched === 1);
    const meta = await attempt("https://169.254.169.254/latest/meta-data/");
    ok("CONTROL the cloud-metadata address stays refused (the second screen)", meta.threw && meta.fetched === 0);
  }

  // =================================================================================================
  // A2. src/admin/idp-test-shared.ts:85 -- the same screen on the read-only IdP test probe.
  // =================================================================================================
  console.log("\nA2. screenFetchUrl screens a probe URL before any fetch (src/admin/idp-test-shared.ts)");
  {
    const HTTPS_REASON = "the URL must be https and must not be an IP literal, localhost, or a cloudflareaccess.com host";
    ok("TREATMENT a plain-http probe URL is refused", screenFetchUrl("http://idp.example.com/.well-known/openid-configuration") === HTTPS_REASON);
    ok("TREATMENT a cloudflareaccess.com probe URL is refused", screenFetchUrl("https://acme.cloudflareaccess.com/cdn-cgi/access/certs") === HTTPS_REASON);
    ok("TREATMENT an https IP-literal probe URL is refused by THIS screen's category", screenFetchUrl("https://203.0.113.9/jwks") === HTTPS_REASON);
    ok("CONTROL a conformant https probe URL is allowed", screenFetchUrl("https://accounts.example.com/.well-known/jwks.json") === null);
    ok("CONTROL an RFC1918 host stays refused by the internal-host screen", screenFetchUrl("https://10.0.0.4/jwks") !== null);
    ok("CONTROL a URL that does not parse is still refused", screenFetchUrl("not a url") === "the URL is not a valid absolute URL");
  }

  // =================================================================================================
  // A3. src/admin/restore-sinks.ts:389 -- guardTarget on the SECRETS sink.
  // =================================================================================================
  console.log("\nA3. resolveSink guards the operator's target binding on EVERY sink (src/admin/restore-sinks.ts)");
  {
    const RESERVED = "ADMIN_TOKEN";
    ok("the binding used as the treatment really is reserved", RESERVED_BINDINGS.has(RESERVED));
    function rec(sourceType: string, name: string): ShardRecord {
      return { kind: "record", sourceType, name, keyNameHash: "h", recordId: "r", plaintextSize: 1, plaintextSha384: "s", recordHash: "rh", codec: "raw", segments: [] } as unknown as ShardRecord;
    }
    function refusal(sourceType: string, name: string, binding: string): string {
      const env = { ADMIN_TOKEN: "x", KV_ns: {}, R2_b: {}, D1_db: {}, SECRETS: {} } as unknown as Env;
      try {
        resolveSink(env, rec(sourceType, name), { binding }, false);
        return "";
      } catch (e) {
        return e instanceof Error ? e.message : String(e);
      }
    }
    const RESERVED_MSG = "target binding is reserved";
    ok("TREATMENT a SECRETS record with a reserved target binding is refused", refusal("secrets", "SOME_SECRET", RESERVED) === RESERVED_MSG);
    ok("CONTROL a KV record with a reserved target binding is refused", refusal("kv", "k", RESERVED) === RESERVED_MSG);
    ok("CONTROL an R2 record with a reserved target binding is refused", refusal("r2", "o", RESERVED) === RESERVED_MSG);
    ok("CONTROL a D1 record with a reserved target binding is refused", refusal("d1", "db/rows", RESERVED) === RESERVED_MSG);
    ok("CONTROL an ordinary SECRETS target is NOT refused as reserved", refusal("secrets", "SOME_SECRET", "SECRETS") !== RESERVED_MSG);
  }

  // =================================================================================================
  // B1. CENSUS: assertNoPlaintextSecretInExport, the no-custody re-assertion.
  // =================================================================================================
  console.log("\nB1. CENSUS: every no-custody re-assertion site is present (assertNoPlaintextSecretInExport)");
  {
    const expected: Array<[string, number]> = [
      ["admin/router-identity.ts", 6],
      ["admin/control-plane-seal.ts", 3],
      ["cron/control-plane-pass.ts", 1],
    ];
    let total = 0;
    for (const [rel, n] of expected) {
      reconciled(rel, "assertNoPlaintextSecretInExport");
      const got = callSites(read(rel), "assertNoPlaintextSecretInExport");
      ok(`${rel} carries ${n} no-custody re-assertion call site(s)`, got === n);
      total += got;
    }
    ok("the no-custody re-assertion is applied at TEN call sites in all", total === 10);

    // Each refusal SURFACE in the route file must have its guard: a surface booking cls "no-custody"
    // with no assertNoPlaintextSecretInExport above it is a surface that can no longer refuse one.
    const ri = read("admin/router-identity.ts");
    const lines = ri.code.split("\n");
    const surfaces: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/cls:\s*"no-custody"/.test(ri.raw.split("\n")[i] ?? "")) continue;
      const m = (ri.raw.split("\n")[i] ?? "").match(/surface:\s*"([a-z-]+)"/);
      if (m) surfaces.push(m[1] as string);
      const window = lines.slice(Math.max(0, i - 8), i).join("\n");
      ok(`the no-custody refusal at router-identity.ts:${i + 1} has its guard above it`, /assertNoPlaintextSecretInExport\s*\(/.test(window));
    }
    ok("all six no-custody surfaces are named", surfaces.length === 6);
    ok("and they are the six the route file declares", ["export-download", "estate-import", "estate-import-sealed", "reconcile", "reconcile-sealed", "apply-staged"].every((s) => surfaces.includes(s)));
  }

  // =================================================================================================
  // B2. CENSUS: assertSafeFetchEndpoint, the SSRF screen.
  // =================================================================================================
  console.log("\nB2. CENSUS: every SSRF-screen site is present (assertSafeFetchEndpoint)");
  {
    const expected: Array<[string, number]> = [
      ["admin/idpconn-validators.ts", 5],
      ["admin/oidc.ts", 2],
      ["admin/idp-test-shared.ts", 1],
    ];
    let total = 0;
    for (const [rel, n] of expected) {
      reconciled(rel, "assertSafeFetchEndpoint");
      const got = callSites(read(rel), "assertSafeFetchEndpoint");
      ok(`${rel} carries ${n} SSRF-screen call site(s)`, got === n);
      total += got;
    }
    ok("the SSRF screen is applied at EIGHT call sites in all", total === 8);
    ok("guardedOidcFetch screens its url on its FIRST statement", /export async function guardedOidcFetch\([^)]*\): Promise<GuardedResponse> \{\s*\n\s*assertSafeFetchEndpoint\(url\);/.test(read("admin/oidc.ts").raw));
  }

  // =================================================================================================
  // B3. CENSUS: recordCapTruncation, against its own closed vocabulary.
  // =================================================================================================
  console.log("\nB3. CENSUS: every declared cap-truncation SURFACE has a site that books it");
  {
    const files = ["sched/scheduler-do-roster.ts", "sched/scheduler-do-observability.ts", "sched/scheduler-do-control-plane-records.ts", "sched/scheduler-do-support-diag.ts", "sched/scheduler-do-dest-config.ts", "sched/sched-fault-core.ts"];
    let sites = 0;
    const booked = new Set<string>();
    for (const rel of files) {
      reconciled(rel, "recordCapTruncation");
      const v = read(rel);
      for (const line of v.codeNC.split("\n")) {
        for (const m of line.matchAll(/recordCapTruncation\s*\(\s*[^,]+,\s*"([a-z-]+)"/g)) booked.add(m[1] as string);
      }
      sites += callSites(v, "recordCapTruncation"); // callSites already skips the declaration line
    }
    ok("the cap-truncation booking is applied at EIGHT call sites", sites === 8);
    for (const s of CAP_TRUNCATION_SURFACES) ok(`the declared surface "${s}" is booked by a call site`, booked.has(s));
    ok("NEGATIVE: no call books a surface outside the declared vocabulary", [...booked].every((b) => (CAP_TRUNCATION_SURFACES as readonly string[]).includes(b)));
    ok("and the vocabulary is exactly as long as the set of booked surfaces", booked.size === CAP_TRUNCATION_SURFACES.length);
  }

  // =================================================================================================
  // B4. CENSUS: recordCanaryLoss, against its own closed vocabulary.
  // =================================================================================================
  console.log("\nB4. CENSUS: every declared canary-loss KIND has a site that books it");
  {
    const rel = "sched/scheduler-do-canary.ts";
    reconciled(rel, "recordCanaryLoss");
    const v = read(rel);
    const booked = new Set<string>();
    for (const line of v.codeNC.split("\n")) {
      for (const m of line.matchAll(/recordCanaryLoss\s*\(\s*[^,]+,\s*"([a-z-]+)"/g)) booked.add(m[1] as string);
    }
    ok("the canary-loss booking is applied at FIVE call sites", callSites(v, "recordCanaryLoss") === 5);
    for (const k of CANARY_LOSS_KINDS) ok(`the declared kind "${k}" is booked by a call site`, booked.has(k));
    ok("NEGATIVE: no call books a kind outside the declared vocabulary", [...booked].every((b) => (CANARY_LOSS_KINDS as readonly string[]).includes(b)));
    ok("dest-excluded-by-cap is booked WITH the uncovered destination labels, or the record cannot name them", /recordCanaryLoss\([^)]*"dest-excluded-by-cap",\s*[A-Za-z_$][\w$]*\)/.test(v.codeNC));
  }

  // =================================================================================================
  // B5. CENSUS: guardTarget, the reserved-binding choke point.
  // =================================================================================================
  console.log("\nB5. CENSUS: every restore write binding passes the reserved-binding choke point (guardTarget)");
  {
    reconciled("admin/restore-sinks.ts", "guardTarget");
    reconciled("admin/restore-plan.ts", "guardTarget");
    const sinks = read("admin/restore-sinks.ts");
    ok("restore-sinks.ts carries FOUR guarded bindings, one per write sink", callSites(sinks, "guardTarget") === 4);
    ok("restore-plan.ts guards the secrets target before it routes to out-of-band", callSites(read("admin/restore-plan.ts"), "guardTarget") === 1);
    for (const t of ["kv:", "r2:", "SECRETS", "d1:"]) {
      ok(`the ${t} sink resolves its binding through guardTarget`, new RegExp(`guardTarget\\([^\\n]*${t.replace(/[:$]/g, "\\$&")}`).test(sinks.codeNC));
    }
  }

  console.log(failures === 0 ? "\nMULTI-SITE GUARD COMPLETENESS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
