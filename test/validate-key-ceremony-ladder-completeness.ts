// Validates that EVERY key-ceremony audit append which follows a Cloudflare secret write carries the
// DO-reset retry ladder, not just the one append whose loss was reproduced live.
//
// WHY THIS EXISTS. A key install could return 200, write all four secrets and leave no keys-installed row on
// a contiguous chain: each Cloudflare secret PUT rolls a NEW WORKER VERSION, a new version replaces the
// script, and replacing a Worker's script RESETS its Durable Objects, so the append that follows races the
// rollout. The fix applies a retry ladder that rides out both the NAMED reset message and the OPAQUE form the
// runtime actually raises, at all SIX call sites that follow a secret PUT or DELETE and so sit in the same
// rollout window.
//
// THE GATE ONLY EVER SAW ONE OF THE SIX. test/validate-keys-install.ts drives POST /keys/install and nothing
// else, so deleting the `afterSecretWrite` argument from break-glass rotate, add-operational, break-glass-only
// or either half-keyed failure row reproduced the defect on that route and RED NOTHING. The remedy is a single
// optional argument at each site, which is the easiest thing in this file for a refactor to drop, and the loss
// it causes is silent by construction: the route still answers 200 and the operator sees nothing.
//
// WHAT IS GRADED HERE.
//   A. BEHAVIOURAL, the three success routes the existing gate never drives. Each is driven three ways: the
//      OPAQUE rollout fault measured live (TREATMENT), the NAMED reset (CONTROL), and a genuine fault
//      (CONTROL). A passing treatment with a failing control would mean "retry everything", which is not the
//      property; the real fault must still end the loop at exactly one attempt and lose its row.
//   B. SOURCE CENSUS over src/admin/router-keys.ts, because behaviour cannot reach the two half-keyed FAILURE
//      rows without a Cloudflare fault injected mid-ceremony, and because a count is what notices a SEVENTH
//      secret-writing site being added without the ladder. The census reconciles read + comment-dropped
//      against the raw occurrence count exactly, so a shortfall small enough to look like noise cannot pass
//      as a complete sweep.
//
// It is a race live (one install in seven), so it is graded deterministically here: the reset is INJECTED.
// Run: node test/validate-key-ceremony-ladder-completeness.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// The exact encodings the in-browser ceremony emits: a recipient public is x25519 public(32) ||
// ML-KEM-1024 ek(1568); an operational private identity is x25519 scalar(32) || ML-KEM seed(64).
const bgKp = x25519.keygen();
const BREAK_GLASS_PUBLIC = b64urlEncode(concat(bgKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const bgKp2 = x25519.keygen();
const BREAK_GLASS_PUBLIC_NEW = b64urlEncode(concat(bgKp2.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const opKp = x25519.keygen();
const OPERATIONAL_PUBLIC = b64urlEncode(concat(opKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const OPERATIONAL_PRIVATE = b64urlEncode(concat(randomBytes(32), randomBytes(64)));
const SIGNER_PRIVATE_SENTINEL = "sentinel-signer-private-never-put-by-these-routes";

const TOKEN = "cfat-test-edit-workers-token-1234567890";

// The two throw forms the version rollout takes, and one that is a REAL fault. The opaque one is the string
// carried on a live request that lost a row; the named one is what the runtime says when it names the reset.
const OPAQUE_ROLLOUT = "internal error; reference = n3rmrlv4r241rk2ob8u84pfq";
const NAMED_RESET = "Durable Object reset because its code was updated.";
const REAL_FAULT = "the audit Durable Object refused this append";

// A recording secrets stub: every PUT and DELETE against the dedicated secrets endpoint succeeds. Anything
// else 500s, so a route that reached an endpoint this test did not expect fails rather than passing quietly.
function makeSecretsStub(): { fetch: typeof fetch; puts: string[]; dels: string[] } {
  const puts: string[] = [];
  const dels: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PUT" && /\/secrets$/.test(url)) {
      const parsed = JSON.parse(String(init?.body ?? "{}")) as { name?: string };
      puts.push(parsed.name ?? "");
      return new Response(JSON.stringify({ success: true, result: { name: parsed.name } }), { status: 200 });
    }
    if (method === "DELETE" && /\/secrets\/[A-Z_]+$/.test(url)) {
      dels.push(url.split("/").pop() ?? "");
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  return { fetch: fetchImpl, puts, dels };
}

interface Arm {
  status: number;
  auditPosts: number;
  consumed: boolean;
  rows: number;
  seqOk: boolean;
  outcomes: string[];
  puts: string[];
  dels: string[];
}

// driveRoute drives one key-ceremony route end to end through the REAL handleAdmin, with `throwMessage`
// raised on the FIRST audit POST and the DO recovering after it. One throw is deliberately fewer than the
// ladder's budget, so a passing arm means the retry ran rather than that the budget happened to be large.
async function driveRoute(opts: {
  route: string;
  body: Record<string, unknown>;
  action: string;
  envExtra: Record<string, string>;
  throwMessage: string;
}): Promise<Arm> {
  const ADMIN_TOKEN = `ladder-${opts.action}-${Math.random().toString(36).slice(2, 10)}`;
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  let throwsLeft = 1;
  let auditPosts = 0;
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as URL).toString();
      if (init?.method === "POST" && new URL(url).pathname === "/audit") {
        auditPosts++;
        if (throwsLeft > 0) {
          throwsLeft--;
          throw new Error(opts.throwMessage);
        }
      }
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  const env = {
    SCHEDULER: namespace,
    ADMIN_TOKEN,
    CF_ACCOUNT_ID: "acct-ladder",
    WORKER_NAME: "downpipe-engine",
    ...opts.envExtra,
  } as unknown as Env;

  const secretsStub = makeSecretsStub();
  const realFetch = globalThis.fetch;
  globalThis.fetch = secretsStub.fetch;
  let status = 0;
  let auditText = "";
  try {
    const resp = await handleAdmin(
      new Request(`https://engine.example/admin${opts.route}`, {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify(opts.body),
      }),
      env,
    );
    status = resp.status;
    const auditResp = await handleAdmin(
      new Request(`https://engine.example/admin/audit?action=${opts.action}&limit=50`, {
        method: "GET",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      }),
      env,
    );
    auditText = await auditResp.text();
  } finally {
    globalThis.fetch = realFetch;
  }
  const parsed = JSON.parse(auditText) as { events?: Array<{ action?: string; outcome?: string; seq?: number }> };
  const rows = (parsed.events ?? []).filter((e) => e.action === opts.action);
  return {
    status,
    auditPosts,
    consumed: throwsLeft === 0,
    rows: rows.length,
    seqOk: rows.length > 0 && rows.every((r) => typeof r.seq === "number"),
    outcomes: rows.map((r) => r.outcome ?? ""),
    puts: secretsStub.puts,
    dels: secretsStub.dels,
  };
}

// ---- source census helpers -----------------------------------------------------------------------------
// stripComments removes // and /* */ comments while keeping string and template literals intact, and returns
// the removed text alongside the code, so an occurrence count can be reconciled exactly: read (in code) plus
// comment-dropped (in the removed text) must equal the raw count. A sweep that silently loses a site is the
// failure this reconciliation exists to make impossible.
function stripComments(src: string): { code: string; comments: string } {
  let code = "";
  let comments = "";
  let i = 0;
  let mode: "code" | "line" | "block" | "single" | "double" | "tick" = "code";
  while (i < src.length) {
    const c = src[i] ?? "";
    const n = src[i + 1] ?? "";
    if (mode === "code") {
      if (c === "/" && n === "/") { mode = "line"; comments += c; i++; continue; }
      if (c === "/" && n === "*") { mode = "block"; comments += c; i++; continue; }
      if (c === "'") mode = "single";
      else if (c === '"') mode = "double";
      else if (c === "`") mode = "tick";
      code += c;
      i++;
      continue;
    }
    if (mode === "line") {
      if (c === "\n") { mode = "code"; code += c; i++; continue; }
      comments += c;
      i++;
      continue;
    }
    if (mode === "block") {
      if (c === "*" && n === "/") { mode = "code"; comments += "*/"; i += 2; continue; }
      comments += c;
      i++;
      continue;
    }
    // inside a string/template literal
    if (c === "\\") { code += c + n; i += 2; continue; }
    if ((mode === "single" && c === "'") || (mode === "double" && c === '"') || (mode === "tick" && c === "`")) mode = "code";
    code += c;
    i++;
  }
  return { code, comments };
}

function countOccurrences(hay: string, needle: string): number {
  let n = 0;
  let from = 0;
  for (;;) {
    const at = hay.indexOf(needle, from);
    if (at === -1) return n;
    n++;
    from = at + needle.length;
  }
}

// callsOf finds every invocation of `name(` in already-comment-stripped code, balance-matching parentheses
// (and skipping string literals) so a multi-line call with nested calls or object literals is read whole,
// then splits its argument list at top level. Declarations are excluded by the caller.
function callsOf(code: string, name: string): string[][] {
  const out: string[][] = [];
  const needle = `${name}(`;
  let from = 0;
  for (;;) {
    const at = code.indexOf(needle, from);
    if (at === -1) return out;
    from = at + needle.length;
    const before = code[at - 1] ?? "";
    if (/[A-Za-z0-9_$.]/.test(before)) continue; // a longer identifier that merely ends with this name
    let depth = 0;
    let i = at + name.length; // at the "("
    let mode: "code" | "single" | "double" | "tick" = "code";
    const args: string[] = [];
    let cur = "";
    for (; i < code.length; i++) {
      const c = code[i] ?? "";
      if (mode !== "code") {
        cur += c;
        if (c === "\\") { cur += code[i + 1] ?? ""; i++; continue; }
        if ((mode === "single" && c === "'") || (mode === "double" && c === '"') || (mode === "tick" && c === "`")) mode = "code";
        continue;
      }
      if (c === "'") { mode = "single"; cur += c; continue; }
      if (c === '"') { mode = "double"; cur += c; continue; }
      if (c === "`") { mode = "tick"; cur += c; continue; }
      if (c === "(" || c === "[" || c === "{") {
        depth++;
        if (depth === 1 && c === "(") continue; // the call's own opening paren
        cur += c;
        continue;
      }
      if (c === ")" || c === "]" || c === "}") {
        depth--;
        if (depth === 0 && c === ")") { args.push(cur); break; }
        cur += c;
        continue;
      }
      if (c === "," && depth === 1) { args.push(cur); cur = ""; continue; }
      cur += c;
    }
    out.push(args.map((a) => a.trim()).filter((a, idx) => !(idx === args.length - 1 && a === "")));
  }
}

async function main(): Promise<void> {
  // ---- A. BEHAVIOURAL: the three secret-writing SUCCESS routes the existing gate never drives ------------
  const routes = [
    {
      label: "POST /keys/rotate (break-glass-rotated)",
      route: "/keys/rotate",
      action: "break-glass-rotated",
      body: { token: TOKEN, breakGlassPublic: BREAK_GLASS_PUBLIC_NEW },
      envExtra: { SIGNER_PRIVATE: SIGNER_PRIVATE_SENTINEL, BREAK_GLASS_PUBLIC },
      expectPuts: ["BREAK_GLASS_PUBLIC"],
    },
    {
      label: "POST /keys/add-operational (operational-added)",
      route: "/keys/add-operational",
      action: "operational-added",
      body: { token: TOKEN, operationalPublic: OPERATIONAL_PUBLIC, operationalPrivate: OPERATIONAL_PRIVATE },
      envExtra: { SIGNER_PRIVATE: SIGNER_PRIVATE_SENTINEL, BREAK_GLASS_PUBLIC },
      expectPuts: ["OPERATIONAL_PUBLIC", "OPERATIONAL_PRIVATE"],
    },
    {
      label: "POST /keys/break-glass-only (operational-removed)",
      route: "/keys/break-glass-only",
      action: "operational-removed",
      // confirmDiscardStranded skips the custody discard-guard, which is a DIFFERENT property with its own
      // gate (validate-keys-discard-guard.ts); this cell is about the append that follows the deletes.
      body: { token: TOKEN, confirmDiscardStranded: true },
      envExtra: { SIGNER_PRIVATE: SIGNER_PRIVATE_SENTINEL, BREAK_GLASS_PUBLIC, OPERATIONAL_PUBLIC, OPERATIONAL_PRIVATE },
      expectPuts: ["OPERATIONAL_RETIRED"],
    },
  ];

  for (const r of routes) {
    console.log(`\n-- ${r.label}: the append rides out the rollout its OWN secret write causes --`);

    // TREATMENT: the opaque form measured live. This arm is what fails if the route's `env` argument is
    // dropped, which is the defect on this route exactly.
    const opaque = await driveRoute({ route: r.route, body: r.body, action: r.action, envExtra: r.envExtra, throwMessage: OPAQUE_ROLLOUT });
    ok(`${r.action}: anti-vacuity, the opaque rollout throw was actually injected and consumed`, opaque.consumed);
    ok(`${r.action}: the route still returns 200 through the rollout fault (the operator never sees the retry)`, opaque.status === 200);
    ok(`${r.action}: the secret write genuinely landed (${r.expectPuts.join(" + ")})`, r.expectPuts.every((n) => opaque.puts.includes(n) || opaque.dels.includes(n)));
    ok(`${r.action}: the append was RETRIED rather than abandoned on attempt one`, opaque.auditPosts >= 2);
    ok(`${r.action}: the row LANDED despite the reset, exactly once, with a numeric seq`, opaque.rows === 1 && opaque.seqOk);
    ok(`${r.action}: the landed row records the SUCCESS outcome, not a failure`, opaque.outcomes.join(",") === "success");

    // CONTROL 1: the NAMED reset must still be ridden out, so the ladder is not keyed only to the opaque form.
    const named = await driveRoute({ route: r.route, body: r.body, action: r.action, envExtra: r.envExtra, throwMessage: NAMED_RESET });
    ok(`${r.action}: anti-vacuity, the named reset throw was actually injected and consumed`, named.consumed);
    ok(`${r.action}: CONTROL, the NAMED reset is retried and the row lands`, named.auditPosts >= 2 && named.rows === 1);

    // CONTROL 2: a genuine fault must STILL end the loop at exactly one attempt. Without this a ladder that
    // retried everything would pass the treatment, and "retry everything" is not the property.
    const real = await driveRoute({ route: r.route, body: r.body, action: r.action, envExtra: r.envExtra, throwMessage: REAL_FAULT });
    ok(`${r.action}: anti-vacuity, the real-fault throw was actually injected and consumed`, real.consumed);
    ok(`${r.action}: CONTROL, a REAL fault is not retried (exactly one append attempt)`, real.auditPosts === 1);
    ok(`${r.action}: CONTROL, a real fault loses the row rather than being papered over`, real.rows === 0);
    ok(`${r.action}: CONTROL, a real fault still returns 200 (the secret is written; the audit is best-effort)`, real.status === 200);
  }

  // ---- B. SOURCE CENSUS: every secret-writing append carries the ladder, and no other one does -----------
  console.log("\n-- the census: which key-ceremony appends carry the ladder, read from the source --");
  {
    const fs = await import("node:fs/promises");
    const raw = await fs.readFile(new URL("../src/admin/router-keys.ts", import.meta.url), "utf8");
    const { code, comments } = stripComments(raw);

    // THE RECONCILIATION, first, because every count below is worthless without it: read plus comment-dropped
    // must equal the raw occurrence count EXACTLY. A shortfall of one or two looks like noise and is the kind
    // nobody checks, so it is asserted rather than eyeballed.
    for (const needle of ["auditChecked(", "recordKeyCeremonyFailure("]) {
      const rawN = countOccurrences(raw, needle);
      const codeN = countOccurrences(code, needle);
      const commentN = countOccurrences(comments, needle);
      ok(`reconciliation: ${needle} read ${codeN} + comment-dropped ${commentN} === raw ${rawN}`, codeN + commentN === rawN && rawN > 0);
    }

    // auditChecked: one DECLARATION plus its call sites. The declaration is excluded by name so a call count
    // is a call count.
    const auditCalls = callsOf(code, "auditChecked").filter((args) => !(args[0] ?? "").startsWith("scheduler: DurableObjectStub"));
    ok("the census found call sites of auditChecked to classify", auditCalls.length >= 10);

    // The ladder is carried by a SEVENTH argument (afterSecretWrite: Env). Classify every call by whether it
    // has one, and by the action + outcome literals it names.
    const withLadder = auditCalls.filter((a) => a.length >= 7);
    const site = (a: string[]) => `${(a[3] ?? "").replace(/"/g, "")}/${(a[4] ?? "").replace(/"/g, "")}`;

    // One laddered call is not a route: recordKeyCeremonyFailure FORWARDS its own optional parameter, so the
    // failure rows inherit the ladder from their callers rather than deciding it themselves. It is separated
    // here rather than lumped in, because "the helper forwards it" and "this route passes it" are two
    // different properties and a census that conflated them could not tell which one broke.
    const forwarders = withLadder.filter((a) => (a[6] ?? "") === "afterSecretWrite");
    ok("the failure-row helper FORWARDS the ladder parameter rather than swallowing it, exactly once", forwarders.length === 1);

    const routeLaddered = withLadder.filter((a) => (a[6] ?? "") !== "afterSecretWrite");
    const laddered = routeLaddered.map(site).sort().join(",");
    ok(
      "EXACTLY the four secret-writing SUCCESS appends carry the ladder",
      laddered === "break-glass-rotated/success,keys-installed/success,operational-added/success,operational-removed/success",
    );
    ok("every laddered route call passes the route's Env as the seventh argument", routeLaddered.every((a) => (a[6] ?? "") === "env"));

    // The denials deliberately do NOT: they return before any network call, so there is no version rollout to
    // race, and a ladder there would be noise. This is the direction that catches "put env on everything".
    const denials = auditCalls.filter((a) => (a[4] ?? "") === '"denied"');
    ok("every DENIED append exists and none of them carries the ladder", denials.length >= 5 && denials.every((a) => a.length === 6));

    // The two half-keyed FAILURE rows: a ceremony that died AFTER reaching Cloudflare has already rolled a
    // version, and that row is the only durable evidence a half-keyed engine leaves. Behaviour cannot reach
    // these without a Cloudflare fault injected mid-ceremony, so they are held by the census.
    const failCalls = callsOf(code, "recordKeyCeremonyFailure").filter((a) => !(a[0] ?? "").startsWith("scheduler: DurableObjectStub"));
    const failLaddered = failCalls.filter((a) => a.length >= 6);
    ok("the census found the key-ceremony FAILURE row call sites", failCalls.length >= 6);
    ok("the failure rows raised AFTER Cloudflare was reached carry the ladder", failLaddered.length === 4 && failLaddered.every((a) => (a[5] ?? "") === "env"));
    ok("the PREFLIGHT failure rows, which return before any network call, do not", failCalls.length - failLaddered.length === 2);

    // And the argument has to mean something: auditChecked must route through the checked ladder when it is
    // supplied, or every count above would be counting a parameter nobody reads.
    ok("auditChecked routes a laddered append through recordAuditCheckedAfterSelfDeploy", /if \(afterSecretWrite !== undefined\) \{[\s\S]{0,400}?recordAuditCheckedAfterSelfDeploy\(afterSecretWrite,/.test(code));
    ok("and it keeps the numeric-seq discriminator on the plain path", /typeof appended\?\.seq !== "number"/.test(code));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nKEY-CEREMONY LADDER COMPLETENESS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
