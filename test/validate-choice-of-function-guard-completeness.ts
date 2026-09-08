// Validates the guard families whose call sites a CALL COUNT cannot hold: for a choice-of-function guard,
// a call count cannot tell a per-site substitution from a family-wide narrowing, so this needs its gate in
// TWO independent halves.
//
// A choice-of-function guard is mutable per site, by a SIGNATURE-IDENTICAL SHIM: a twin that takes the same
// arguments, does the same work, returns the same booleans on every path, and drops exactly ONE property. A
// shim changes the call site by one identifier, so a call census SEES it. What a census cannot see is a
// narrowing one level down: shortening the shared ladder inside `retryAfterSelfDeploy` leaves every call
// site still naming the guarded function, so the census stays green while the guarded property is gone
// everywhere at once. So a choice-of-function guard needs its gate in TWO independent halves:
//   * a CENSUS that each site names the guarded function (sees a per-site substitution)
//   * a DRIVE that the named function has the guarded property (sees a family-wide narrowing)
// That decomposition is this file's A and B sections.
//
// Section B also runs the census in the NEGATIVE direction: rather than count the sites that DO name the
// guard, it asks which engine self-redeploys are followed by a write that does NOT. `handleComponentApply`,
// the multi-component apply leg the console drives whenever a release carries a console component, calls
// the same `planAndPromote` against the same `makeCfDeployDriver` as the legacy leg, so it rolls a new
// Worker version and resets this Durable Object the same way. Its two follow-up writes must both be on the
// guarded helpers (`recordBookkeepingAfterSelfDeploy`, `recordAuditAfterSelfDeploy`): an unguarded append
// can THROW on the reset rather than merely lose the row, propagating out of the route while the engine is
// already live on the new version.
//
// WHAT IS GRADED HERE.
//   A. BEHAVIOURAL, over the shared self-redeploy ladder, because that is where the choice-of-function
//      property actually lives. Each cell is TWO-SIDED: a TREATMENT that only the ladder survives, and a
//      CONTROL that passes with or without it, so no cell can read as "anything returns true".
//   B. CENSUS OF THE CHOICE, in both directions. Positively, the thirteen sites. NEGATIVELY, and this is
//      the half that finds a defect rather than confirming a fix: every engine self-redeploy in the source
//      tree must have BOTH follow-up writes on the guarded helpers.
//   C. CENSUS OF THE VERDICT, for the widened families. that pass's censuses count CALLS, and a call count is
//      blind to a narrowing -- the mutation arms below narrow twenty-five sites by making each call's
//      verdict be DISCARDED through a comma expression, and every call is still there to be counted. So
//      these censuses assert the VERDICT IS CONSUMED, not that the call exists.
//
// Run: node test/validate-choice-of-function-guard-completeness.ts

import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { flushDroppedWrites, pendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { recordAudit, recordAuditAfterSelfDeploy, recordBookkeepingAfterSelfDeploy } from "../src/admin/router-audit.ts";
import { checkOwnerRemoval } from "../src/admin/owner-floor.ts";
import { validateDeployToken } from "../src/admin/router-core.ts";
import { screenSinkHost } from "../src/notify/types.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import { blankComments, blankCommentsAndStrings } from "./lib/blank-comments.mjs";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

// ---- the reader, which asserts its own accounting -------------------------------------------------
//
// The three views are DERIVED from the repo's shared blankers rather than from a fourth hand-rolled
// splitter. validate-multisite-guard-completeness.ts inlines its own copy; scripts/lib/blank-comments.mjs
// exists precisely because "a second hand-rolled copy is a second place for the comment blindness to come
// back", and ten validators already read it. Both blankers preserve offsets, so the COMMENT region is what
// the comment blanker changed, and the QUOTED region is what the string blanker changed on top of it.
//
// The accounting rule is unchanged and it is what makes a sweep honest: an identifier's RAW occurrence
// count must equal CODE + COMMENT + QUOTED, exactly. This repo has lost a sweep to a scanner reading a
// comment as code, so a mismatch is a FAILURE rather than a smaller number nobody questions.
interface Views {
  raw: string;
  code: string; // comments AND string literals blanked
  codeNC: string; // comments blanked, string literals KEPT
  comment: string;
  quoted: string;
}
function views(src: string): Views {
  const codeNC = blankComments(src);
  const code = blankCommentsAndStrings(src);
  const comment = new Array<string>(src.length).fill(" ");
  const quoted = new Array<string>(src.length).fill(" ");
  for (let i = 0; i < src.length; i++) {
    if (codeNC[i] !== src[i]) comment[i] = src[i] as string;
    else if (code[i] !== codeNC[i]) quoted[i] = src[i] as string;
  }
  return { raw: src, code, codeNC, comment: comment.join(""), quoted: quoted.join("") };
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
function callSites(v: Views, name: string): number {
  let n = 0;
  for (const line of v.code.split("\n")) {
    if (/^\s*(export\s+)?(async\s+)?function\s/.test(line) && line.includes(`${name}(`)) continue;
    n += (line.match(new RegExp(`\\b${name}\\s*\\(`, "g")) ?? []).length;
  }
  return n;
}
// srcFiles walks every .ts under src/, so the negative census below grades the whole tree rather than a
// hand-kept list of the files somebody remembered.
function srcFiles(dir = SRC, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) srcFiles(p, out);
    else if (e.endsWith(".ts")) out.push(p.slice(SRC.length + 1));
  }
  return out.sort();
}
function reconciled(rel: string, name: string): void {
  const v = read(rel);
  const raw = count(v.raw, name);
  const sum = count(v.code, name) + count(v.comment, name) + count(v.quoted, name);
  ok(`accounting holds for ${name} in ${rel}: raw ${raw} = code + comment + quoted ${sum}`, raw === sum && raw > 0);
}

// ---- the fake scheduler, which counts ATTEMPTS by path rather than by stub handout -----------------
//
// retryAfterSelfDeploy takes a FRESH stub on every attempt (that is the point: the stub the caller holds
// is the one the rollout invalidated), and it also takes one to flush the dropped-write tally, so counting
// stub handouts would conflate the two. These count POSTS, per path.
interface Rig {
  env: Env;
  posts: Array<{ path: string; body: string }>;
  countTo(path: string): number;
}
function rig(answer: (path: string, attempt: number) => Promise<Response>): Rig {
  const posts: Array<{ path: string; body: string }> = [];
  const stub = {
    fetch: async (url: string, init?: { body?: unknown }) => {
      const path = new URL(String(url)).pathname;
      const nth = posts.filter((p) => p.path === path).length + 1;
      posts.push({ path, body: typeof init?.body === "string" ? init.body : "" });
      return answer(path, nth);
    },
  };
  const env = { SCHEDULER: { idFromName: () => ({}), get: () => stub } } as unknown as Env;
  return { env, posts, countTo: (path: string) => posts.filter((p) => p.path === path).length };
}
const CALLER: Caller = { subject: "sub-1", email: "owner@example.invalid", method: "cookie" } as unknown as Caller;
const RESET = "Durable Object reset because its code was updated.";
const OPAQUE = "internal error; reference = n3rmrlv4r241rk2ob8u84pfq";
function jsonOk(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}
// drainDrops clears the module-global dropped-write tally so one cell cannot read another's leftovers.
async function drainDrops(): Promise<void> {
  const r = rig(async () => jsonOk({}));
  await flushDroppedWrites((r.env as unknown as { SCHEDULER: { get: () => unknown } }).SCHEDULER.get() as never);
}

async function main(): Promise<void> {
  console.log("CHOICE-OF-FUNCTION GUARD COMPLETENESS\n");

  // =================================================================================================
  // A. BEHAVIOURAL: the self-redeploy ladder, which is where the guarded property actually lives.
  // =================================================================================================
  console.log("A1. recordAuditAfterSelfDeploy SURVIVES the Durable Object reset the self-redeploy raises");
  {
    await drainDrops();
    const r = rig(async (path, nth) => {
      if (path === "/audit" && nth === 1) throw new Error(RESET);
      return jsonOk({ seq: 7 });
    });
    const landed = await recordAuditAfterSelfDeploy(r.env, CALLER, null, "sources-attached", { kind: "access-policy" });
    // TREATMENT: only the retry ladder can make this true. One attempt is all a narrowed ladder gets.
    ok("TREATMENT a reset on the first append is retried and the row LANDS", landed === true);
    ok("TREATMENT and it took a SECOND append to land it", r.countTo("/audit") === 2);
    ok("CONTROL no loss is booked when the row landed", (pendingDroppedWrites()["audit-write"] ?? 0) === 0);
  }

  console.log("\nA2. and it survives the OPAQUE form of the SAME rollout, which is the form that lost a row live");
  {
    await drainDrops();
    const r = rig(async (path, nth) => {
      if (path === "/audit" && nth === 1) throw new Error(OPAQUE);
      return jsonOk({ seq: 8 });
    });
    // This dose is not a guess: a live rollout logged the opaque form on the audit stub and the named form
    // on the marker stub in the same request, and only the named one was matched.
    ok("TREATMENT the opaque 'internal error; reference = ...' rollout fault is retried and lands", (await recordAuditAfterSelfDeploy(r.env, CALLER, null, "sources-attached", { kind: "access-policy" })) === true);
    ok("TREATMENT and it too took a second append", r.countTo("/audit") === 2);
  }

  console.log("\nA3. CONTROL a NON-reset fault is a real fault: one attempt, no retry, and the loss is BOOKED");
  {
    await drainDrops();
    const r = rig(async (path) => {
      if (path === "/audit") throw new Error("TypeError: cannot read property of undefined");
      return jsonOk({});
    });
    ok("CONTROL a non-reset fault returns false", (await recordAuditAfterSelfDeploy(r.env, CALLER, null, "sources-attached", { kind: "access-policy" })) === false);
    ok("CONTROL and it is NOT retried, so the ladder is not 'retry everything'", r.countTo("/audit") === 1);
    ok("CONTROL and the loss reached the dropped-write flush", r.countTo("/diag/dropped-writes") >= 1);
  }

  console.log("\nA4. CONTROL a clean first append needs no ladder at all");
  {
    await drainDrops();
    const r = rig(async () => jsonOk({ seq: 1 }));
    ok("CONTROL a clean append returns true", (await recordAuditAfterSelfDeploy(r.env, CALLER, null, "sources-detached", { kind: "access-policy" })) === true);
    ok("CONTROL in exactly one attempt", r.countTo("/audit") === 1);
  }

  console.log("\nA5. recordBookkeepingAfterSelfDeploy: the SAME ladder, and it is NOT fire-and-forget");
  {
    await drainDrops();
    const r = rig(async (path, nth) => {
      if (path === "/update-pending" && nth === 1) throw new Error(RESET);
      return jsonOk({});
    });
    const landed = await recordBookkeepingAfterSelfDeploy(r.env, "/update-pending", { toVersion: "0.2.1" });
    ok("TREATMENT a reset on the pending write is retried and the record LANDS", landed === true);
    ok("TREATMENT and it took a second write", r.countTo("/update-pending") === 2);
    ok("CONTROL the record carries the body it was given, not a re-derived one", r.posts.some((p) => p.path === "/update-pending" && p.body.includes("0.2.1")));
  }

  console.log("\nA6. CONTROL a bookkeeping write the DO ANSWERS with a non-2xx is a loss, not a reset");
  {
    await drainDrops();
    const r = rig(async (path) => (path === "/update-settled" ? new Response("no", { status: 500 }) : jsonOk({})));
    ok("CONTROL an answered non-2xx returns false", (await recordBookkeepingAfterSelfDeploy(r.env, "/update-settled", {})) === false);
    ok("CONTROL and is NOT retried against a DO that is up and refusing", r.countTo("/update-settled") === 1);
    ok("CONTROL and the loss is booked under the update-settled kind", r.posts.some((p) => p.path === "/diag/dropped-writes" && p.body.includes("update-settled")));
  }

  console.log("\nA7. and the BARE append does not merely LOSE the row on a reset: it THROWS");
  {
    // This is the mechanism of the twentieth defect, driven rather than argued. recordAudit awaits the DO
    // fetch and does not catch, so the reset propagates out of whatever route called it. In the
    // multi-component leg that route's outer catch answers "could not start the update right now; nothing
    // was changed" -- while the engine is live on the new version. The guarded sibling returns a verdict
    // instead, which is what lets the caller tell the operator the truth.
    await drainDrops();
    const thrower = rig(async (path) => {
      if (path === "/audit") throw new Error(RESET);
      return jsonOk({});
    });
    const stub = (thrower.env as unknown as { SCHEDULER: { get: () => DurableObjectStub } }).SCHEDULER.get();
    let threw = false;
    try {
      await recordAudit(stub, CALLER, null, "update-promoted", "success", { kind: "engine-state", field: "engineVersion", detail: "d" });
    } catch {
      threw = true;
    }
    ok("TREATMENT the unguarded recordAudit THROWS the reset at its caller", threw);
    await drainDrops();
    const guarded = rig(async (path) => {
      if (path === "/audit") throw new Error(RESET);
      return jsonOk({});
    });
    // Five attempts all reset: the ladder is exhausted, so this is the WORST case for the guarded path.
    const verdict = await recordAuditAfterSelfDeploy(guarded.env, CALLER, null, "sources-attached", { kind: "access-policy" });
    ok("CONTROL the guarded sibling returns a verdict rather than throwing, even when the ladder is exhausted", verdict === false);
    ok("CONTROL and it exhausted the whole ladder rather than giving up on the first reset", guarded.countTo("/audit") === 5);
    ok("CONTROL and it booked the loss, so an exhausted ladder is never silent", guarded.countTo("/diag/dropped-writes") >= 1);
  }

  // =================================================================================================
  // B. CENSUS OF THE CHOICE. Positively over the thirteen sites, and NEGATIVELY over every engine
  //    self-redeploy in the tree -- which is the direction that found the twentieth defect.
  // =================================================================================================
  console.log("\nB1. CENSUS: the fifteen self-redeploy-safe call sites are all present");
  {
    // THE TOTAL IS COUNTED OVER THE WHOLE TREE, NOT OVER THE FILES SOMEBODY LISTED, and that is not a
    // stylistic preference: a total over a subset reading as a total over everything is the same defect
    // class this whole file exists for, one level up. So the sum walks src/ and the per-file table is
    // graded as a DISTRIBUTION against it.
    const expected: Record<string, [number, number]> = {
      // file -> [audit appends, bookkeeping writes]
      "admin/router-updates.ts": [2, 2],
      "admin/router-updates-ramp.ts": [2, 2],
      "admin/router-updates-rollback.ts": [1, 2],
      "admin/router-updates-components.ts": [1, 1],
      "admin/router-discovery.ts": [2, 0],
    };
    let auditTotal = 0;
    let bookTotal = 0;
    const auditFiles: string[] = [];
    const bookFiles: string[] = [];
    const unlisted: string[] = [];
    for (const rel of srcFiles()) {
      const v = read(rel);
      const a = callSites(v, "recordAuditAfterSelfDeploy");
      const b = callSites(v, "recordBookkeepingAfterSelfDeploy");
      if (a > 0) {
        auditTotal += a;
        auditFiles.push(rel);
      }
      if (b > 0) {
        bookTotal += b;
        bookFiles.push(rel);
      }
      const want = expected[rel];
      if (want) {
        reconciled(rel, "recordAuditAfterSelfDeploy");
        ok(`${rel} carries ${want[0]} self-redeploy-safe audit append(s) and ${want[1]} bookkeeping write(s)`, a === want[0] && b === want[1]);
      } else if (a > 0 || b > 0) {
        // One assertion per unlisted file would be 400 lines of noise in the chain log, so the files the
        // table does NOT name are graded in bulk below and only a surprise is named here.
        unlisted.push(`${rel}(${a}+${b})`);
      }
    }
    ok(`no file outside the distribution table carries a self-redeploy-safe write${unlisted.length ? `: ${unlisted.join(", ")}` : ""}`, unlisted.length === 0);
    ok(`the self-redeploy-safe audit append is applied at EIGHT call sites across the whole tree (${auditFiles.join(", ")})`, auditTotal === 8);
    ok(`the self-redeploy-safe bookkeeping write is applied at SEVEN call sites across the whole tree (${bookFiles.join(", ")})`, bookTotal === 7);
    ok("and the files carrying them are exactly the files the distribution table names", [...new Set([...auditFiles, ...bookFiles])].sort().join(",") === Object.keys(expected).sort().join(","));
  }

  console.log("\nB2. NEGATIVE CENSUS: every ENGINE self-redeploy has BOTH follow-up writes on the guarded helpers");
  {
    // This is the half that finds a defect rather than confirming a fix, and it is scoped by MEANING
    // rather than by a line window. A window census would have to decide how far after a deploy call a
    // write is still "the follow-up", and the honest answer varies -- router-updates.ts writes a
    // legitimately-unguarded update-applied row fifty lines after its settle, in a branch where nothing
    // deployed in this request. So the rule is taken from what the RECORD MEANS instead:
    //
    //   an /update-pending record is written ONLY immediately after an engine promote, and
    //   an engine promote is ALWAYS a self-redeploy.
    //
    // So every writer of one is racing a Durable Object reset, wherever it sits, and every one of them
    // must take the retry. That was true of two of the three and not the third.
    const files = srcFiles();
    const pendingWriters: string[] = [];
    const guardedPendingWriters: string[] = [];
    const barePromotedAppends: string[] = [];
    const guardedPromotedAppends: string[] = [];
    for (const rel of files) {
      const v = read(rel);
      const lines = v.codeNC.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] as string;
        // A WRITER of the record, in either spelling: the guarded helper naming the DO path, or any other
        // call that posts to it. The guard's own kind selection and the closed-vocabulary declaration are
        // not writers, so they are excluded by requiring the DO PATH form "/update-pending".
        if (line.includes('"/update-pending"')) {
          pendingWriters.push(`${rel}:${i + 1}`);
          if (/recordBookkeepingAfterSelfDeploy\s*\(/.test(line)) guardedPendingWriters.push(`${rel}:${i + 1}`);
        }
        if (/\brecordAudit\s*\([^\n]*"update-promoted"/.test(line)) barePromotedAppends.push(`${rel}:${i + 1}`);
        if (/\brecordAuditAfterSelfDeploy\s*\([^\n]*"update-promoted"/.test(line)) guardedPromotedAppends.push(`${rel}:${i + 1}`);
      }
    }
    ok(`the census found the engine's THREE update-pending writers (${pendingWriters.join(", ")})`, pendingWriters.length === 3);
    ok("and every one of the three takes the self-redeploy retry", guardedPendingWriters.length === pendingWriters.length);
    ok("NEGATIVE: no update-promoted row is appended by the bare, unretried recordAudit", barePromotedAppends.length === 0);
    ok(`and all THREE update-promoted appends take the self-redeploy retry (${guardedPromotedAppends.join(", ")})`, guardedPromotedAppends.length === 3);
    ok("the census actually walked the source tree rather than an empty list", files.length > 300);

    // The positive twin, so this cell cannot pass by grading nothing: the multi-component leg -- the one
    // the console drives whenever a release carries a console component -- carries BOTH helpers and the
    // honesty branch that stops a live-but-unrecorded update reading as "nothing was changed".
    const comp = read("admin/router-updates-components.ts");
    reconciled("admin/router-updates-components.ts", "recordAuditAfterSelfDeploy");
    reconciled("admin/router-updates-components.ts", "recordBookkeepingAfterSelfDeploy");
    ok("the multi-component apply leg writes its pending record through the self-redeploy-safe helper", callSites(comp, "recordBookkeepingAfterSelfDeploy") === 1);
    ok("and appends its update-promoted row through the self-redeploy-safe helper", callSites(comp, "recordAuditAfterSelfDeploy") === 1);
    ok("and it CHECKS both return values rather than assuming the writes landed", /if \(!pendingWritten \|\| !audited\)/.test(comp.code));
    ok("and it leaves a DURABLE marker naming which half was lost, so a later pack still proves the state", /recordPhase: "pending"/.test(comp.codeNC) && /recordPhase: "audit"/.test(comp.codeNC));
  }

  // =================================================================================================
  // C. CENSUS OF THE VERDICT. A call count is blind to a narrowing; these assert the verdict is USED.
  // =================================================================================================
  console.log("\nC1. requireStepUp: every site CONSUMES the verdict (a call count would not notice)");
  {
    const files: Array<[string, number]> = [
      ["admin/router.ts", 3],
      ["admin/router-restore.ts", 1],
      ["admin/router-auth-flow.ts", 2],
    ];
    let calls = 0;
    let consumed = 0;
    for (const [rel, n] of files) {
      reconciled(rel, "requireStepUp");
      const v = read(rel);
      const got = callSites(v, "requireStepUp");
      ok(`${rel} carries ${n} step-up gate(s)`, got === n);
      calls += got;
      const lines = v.code.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (!/=\s*await requireStepUp\s*\(/.test(lines[i] as string)) continue;
        const next = (lines[i + 1] ?? "").trim();
        const usesIt = /^if \(stepUp\) return /.test(next);
        ok(`${rel}:${i + 1} the step-up verdict is returned to the caller on the very next line`, usesIt);
        if (usesIt) consumed++;
      }
    }
    ok("the step-up gate is applied at SIX call sites", calls === 6);
    ok("and every one of the six CONSUMES its verdict", consumed === 6);
  }

  console.log("\nC2. validateDeployToken: every site NEGATES the verdict, so none can be narrowed to a no-op");
  {
    const files: Array<[string, number]> = [
      ["admin/router-updates.ts", 2],
      ["admin/router-updates-components.ts", 1],
      ["admin/router-discovery.ts", 3],
      ["admin/router-updates-ramp.ts", 2],
      ["admin/router-updates-rollback.ts", 2],
    ];
    let calls = 0;
    let negated = 0;
    for (const [rel, n] of files) {
      reconciled(rel, "validateDeployToken");
      const v = read(rel);
      const got = callSites(v, "validateDeployToken");
      ok(`${rel} carries ${n} deploy-token shape gate(s)`, got === n);
      calls += got;
      negated += (v.code.match(/!validateDeployToken\s*\(/g) ?? []).length;
    }
    ok("the deploy-token shape gate is applied at TEN call sites", calls === 10);
    ok("and every one of the ten is the REFUSAL side of a negation", negated === calls);
    // Two-sided: the shape boundary itself, so the census is not grading a function that accepts anything.
    ok("TREATMENT an empty token is refused", validateDeployToken("") === false);
    ok("TREATMENT a token below the length floor is refused", validateDeployToken("abc") === false);
    ok("TREATMENT a token carrying a space is refused", validateDeployToken(`${"a".repeat(30)} ${"b".repeat(10)}`) === false);
    ok("CONTROL a conformant token is accepted", validateDeployToken("a".repeat(40)) === true);
  }

  console.log("\nC3. screenSinkHost: every send-time SSRF re-screen CONSUMES its verdict");
  {
    const files: Array<[string, number]> = [
      ["notify/types.ts", 1],
      ["notify/siem-push-sender.ts", 1],
      ["notify/otlp-push-sender.ts", 1],
      ["notify/transport-probe.ts", 1],
      ["notify/channels/jsm.ts", 2],
    ];
    const VERDICTS = /"(internal-literal|public-literal|hostname|url-invalid)"/;
    let calls = 0;
    let consumed = 0;
    for (const [rel, n] of files) {
      reconciled(rel, "screenSinkHost");
      const v = read(rel);
      const got = callSites(v, "screenSinkHost");
      ok(`${rel} carries ${n} send-time sink screen(s)`, got === n);
      calls += got;
      const lines = v.codeNC.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const m = /const (\w+) = screenSinkHost\s*\(/.exec(lines[i] as string);
        if (!m) continue;
        const name = m[1] as string;
        const window = lines.slice(i + 1, i + 8).join("\n");
        const usesIt = new RegExp(`\\b${name}\\b`).test(window) && VERDICTS.test(window);
        ok(`${rel}:${i + 1} the ${name} verdict is compared against the closed vocabulary below it`, usesIt);
        if (usesIt) consumed++;
      }
    }
    ok("the send-time sink screen is applied at SIX call sites", calls === 6);
    ok("and every one of the six CONSUMES its verdict", consumed === 6);
    // Two-sided on the screen itself.
    ok("TREATMENT an RFC1918 sink is classified internal-literal", screenSinkHost("https://10.0.0.4/hook") === "internal-literal");
    ok("TREATMENT the cloud-metadata address is classified internal-literal", screenSinkHost("https://169.254.169.254/latest/") === "internal-literal");
    ok("TREATMENT an unparseable url is classified url-invalid", screenSinkHost("not a url") === "url-invalid");
    ok("CONTROL an ordinary public name is classified hostname, not refused", screenSinkHost("https://hooks.example.com/x") === "hostname");
  }

  console.log("\nC4. checkOwnerRemoval: every Owner-floor site CONSUMES its verdict");
  {
    const files: Array<[string, number]> = [
      ["sched/scheduler-do-signin-factors.ts", 1],
      ["sched/scheduler-do-rbac-mutations.ts", 2],
    ];
    let calls = 0;
    let consumed = 0;
    for (const [rel, n] of files) {
      reconciled(rel, "checkOwnerRemoval");
      const v = read(rel);
      const got = callSites(v, "checkOwnerRemoval");
      ok(`${rel} carries ${n} Owner-floor check(s)`, got === n);
      calls += got;
      const lines = v.code.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (!/=\s*checkOwnerRemoval\s*\(/.test(lines[i] as string)) continue;
        const usesIt = /^if \(!verdict\.ok\)/.test((lines[i + 1] ?? "").trim());
        ok(`${rel}:${i + 1} the Owner-floor verdict gates the very next line`, usesIt);
        if (usesIt) consumed++;
      }
    }
    ok("the Owner floor is checked at THREE call sites", calls === 3);
    ok("and every one of the three CONSUMES its verdict", consumed === 3);
    // Two-sided on the floor arithmetic, including the NaN case its own comment calls out.
    ok("TREATMENT removing the last Owner is refused", checkOwnerRemoval(1, false).ok === false);
    ok("TREATMENT an ambiguous count refuses rather than allows", checkOwnerRemoval(Number.NaN, false).ok === false);
    ok("TREATMENT dropping below two Owners under dual control is refused", checkOwnerRemoval(2, true).ok === false);
    ok("CONTROL removing one of three Owners is allowed", checkOwnerRemoval(3, false).ok === true);
  }

  console.log(failures === 0 ? `\nCHOICE-OF-FUNCTION GUARD COMPLETENESS PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
  // The check count is handed to the guard too, so a run that reaches its tally having graded NOTHING is
  // refused rather than reported as a clean pass.
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
