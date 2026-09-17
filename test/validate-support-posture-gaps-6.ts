// Prove the ENGINE half of the POSTURE support-pack gaps: the FRESHNESS leg and the FOURTH sibling
// producer of the missing-source-IP wolf cry.
//
// THE BAR IS THE DISCRIMINATION TEST, AND THE DRIVE IS THE REAL ENTRY POINT. Both gaps resist the same two
// mistakes, so this file refuses both by construction:
//
//  1. THE SIBLING SITE. The missing-source-IP fix must land on every producer, not just the three obvious ones:
//     a fourth (the ACCESS first-owner bootstrap, which fires on the console's very first call to a healthy
//     engine) keeps bumping the counter otherwise. So the last section here is a STRUCTURAL GATE, not a single
//     patch: it reads the engine's own source and fails if ANY audit draft with an attributed human actor
//     hard-codes a null source IP.
//  2. THE SELF-CERTIFYING TEST. A freshness suite driven with hand-built claims -- shapes the resolver can pass
//     through -- never exercises a shape the resolver ERASES, which is the whole gap. Every
//     freshness state below is resolved by loadVerifiedChannel, the one real resolver, from a REAL
//     hybrid-signed channel verified under a pinned signer, and is then handed to freshnessRefusal exactly as
//     router-updates.ts:288-329 hands it over.
//
//   node test/validate-support-posture-gaps-6.ts

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { loadVerifiedChannel } from "../src/admin/updates.ts";
import { freshnessRefusal } from "../src/admin/router-updates-shared.ts";
import { ADMIN_COUNTER_NAMES, ADMIN_COUNTERS_KEY, type AdminCounters } from "../src/admin/diag-records.ts";
import { AUDIT_PREFIX } from "../src/admin/audit.ts";
import type { AuditEvent } from "../src/admin/audit-types.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

// ============================================================================================================
// "WAS REPLAY PROTECTION ACTIVE WHEN THAT UPDATE APPLIED?"
//
// The pack could not say, and worse: it read CLEAN on the state where it was NOT active. loadVerifiedChannel
// sanitises the signed freshness claim to well-typed-or-absent, so a TYPE-malformed claim (a sequence shipped
// as the string "12", an issuedAt shipped as an epoch number) was erased before the freshness check ever saw
// it. The check could therefore only ever observe ABSENT -- and it filed that absence under the MALFORMED
// name, a fact it never tested. Meanwhile the harmful state recorded NOTHING: no watermark yet (the state of
// every engine in the fleet, since the current channel is freshness-less), the opt-in max-age staleness guard
// ON, an issuedAt of the wrong type, therefore a guard running on nothing and a stale descriptor applied.
// ============================================================================================================

// A hostile value planted IN the malformed claims, so the redaction assertion is a real one: if any recorded
// row echoed the claim it would carry this string.
const HOSTILE = "acme-health.example/not-a-date";

interface SignedEnv {
  env: Env;
  fetchFor: (body: Uint8Array, sig: Uint8Array) => (u: string) => Promise<Uint8Array | null>;
  sign: (body: Uint8Array) => Promise<Uint8Array>;
}

async function signedChannelEnv(): Promise<SignedEnv> {
  const edSeed = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSeed);
  const edPrivate = await crypto.subtle.importKey(
    "pkcs8",
    concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), edSeed),
    "Ed25519",
    false,
    ["sign"],
  );
  const mldsa = mldsaKeygen();
  const signerPublic = b64urlEncode(concat(edPublic, new Uint8Array(mldsa.publicKey)));
  return {
    env: { UPDATE_CHANNEL_URL: "https://update.downpipes.io/channel.json", UPDATE_SIGNER_PUBLIC: signerPublic } as unknown as Env,
    sign: (body: Uint8Array) => hybridSign(edPrivate, mldsa.secretKey, body),
    fetchFor: (body: Uint8Array, sig: Uint8Array) => async (u: string) => (u.endsWith(".sig") ? utf8(b64urlEncode(sig) + "\n") : body),
  };
}

// resolveAndCheck drives the REAL chain the console's POST /admin/update/apply drives:
//   loadVerifiedChannel(env, fetch, degraded)   <- router-updates.ts:288 (the ONLY resolver of a channel claim)
//   noteUpdateDegradations(scheduler, degraded) <- router-updates.ts:289 (folded into adminCounters)
//   freshnessRefusal(art, floor.freshness, ..., onDegraded) <- router-updates.ts:329
// and returns exactly the pack rows (adminCounters names) that apply would have written, plus whether the
// descriptor was REFUSED. Nothing here is hand-built: the claim comes out of the product's own resolver.
async function resolveAndCheck(
  sc: SignedEnv,
  channelBody: Record<string, unknown>,
  freshness: { lastSeq?: number; lastIssuedAt?: string; maxAgeMs?: number },
): Promise<{ rows: Record<string, number>; refused: boolean; sequence: unknown; issuedAt: unknown }> {
  const body = utf8(JSON.stringify(channelBody));
  const sig = await sc.sign(body);
  const degraded = new Set<string>();
  const art = await loadVerifiedChannel(sc.env, sc.fetchFor(body, sig), degraded);
  if ("error" in art) throw new Error(`the signed channel did not resolve: ${art.error}`);
  const names: string[] = [...degraded];
  const refusal = freshnessRefusal(art, freshness, undefined, (n) => names.push(...n));
  const rows: Record<string, number> = {};
  for (const n of names) rows[n] = (rows[n] ?? 0) + 1;
  return { rows, refused: refusal !== null, sequence: art.sequence, issuedAt: art.issuedAt };
}

const ART = { version: "0.2.0", url: "https://update.downpipes.io/engine-0.2.0.mjs", sha384: "a".repeat(96) };
const base = (extra: Record<string, unknown>): Record<string, unknown> => ({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [ART], ...extra });
const STALE_INSTANT = "2020-09-13T12:26:40Z"; // epoch 1_600_000_000, far outside any 30-day window
const MAX_AGE_30D = { maxAgeMs: 30 * 86_400_000 };
// FRESH_INSTANT IS DERIVED FROM THE CLOCK RATHER THAN WRITTEN DOWN, because a fixed literal instant
// eventually falls outside MAX_AGE_30D and [P] stops being a clean claim at all: the assertion that a clean
// signed claim resolves with the claim intact and records no degradation would then fail on fixture ageing,
// not on a product regression in the freshness check, and this file is the worst place for that confusion,
// because the whole distinction it exists to draw is fresh against stale and it already carries
// STALE_INSTANT one line above. An hour
// back is far enough inside a 30-day window to be unambiguous and far enough from now to survive a
// runner whose clock is a little behind. The seconds shape matches what the resolver is handed
// elsewhere in this file, so the assertion still compares like for like.
const FRESH_INSTANT = new Date(Date.now() - 3_600_000).toISOString().replace(/\.\d{3}Z$/, "Z");

async function g332(): Promise<void> {
  console.log("freshness: a claim the RESOLVER erased is now recorded AT the erasure");
  const sc = await signedChannelEnv();

  // ---- NO WATERMARK. Every engine in the fleet today (the current channel is freshness-less, so nothing has
  // ever advanced lastSeq/lastIssuedAt). This is where the check is structurally blind: its degradation arms
  // are both `else if (state.lastSeq/lastIssuedAt !== undefined)`, so with no watermark it says NOTHING.
  const P = await resolveAndCheck(sc, base({ sequence: 12, issuedAt: FRESH_INSTANT }), MAX_AGE_30D);
  const Q = await resolveAndCheck(sc, base({ sequence: "12", issuedAt: FRESH_INSTANT }), MAX_AGE_30D);
  const R = await resolveAndCheck(sc, base({ sequence: 12, issuedAt: 1_600_000_000 }), MAX_AGE_30D);
  const Rp = await resolveAndCheck(sc, base({ sequence: 12, issuedAt: STALE_INSTANT }), MAX_AGE_30D);

  ok("[P] a clean signed claim resolves with the claim intact and records no degradation", P.sequence === 12 && P.issuedAt === FRESH_INSTANT && Object.keys(P.rows).length === 0 && !P.refused);
  ok("[Q] the resolver ERASES a string sequence (the product's own behaviour, unchanged)", Q.sequence === undefined);
  ok("[Q] and now RECORDS the erasure, with no watermark", JSON.stringify(Q.rows) === JSON.stringify({ "update-degraded-freshness-sequence-malformed": 1 }));
  ok("[Q != P] a broken sequence claim no longer reads exactly like a clean one", JSON.stringify(Q.rows) !== JSON.stringify(P.rows));
  ok("[R] the resolver ERASES a numeric issuedAt", R.issuedAt === undefined);
  ok("[R] and now RECORDS it, with no watermark and the max-age guard ON", JSON.stringify(R.rows) === JSON.stringify({ "update-degraded-freshness-issuedat-unparseable": 1 }));
  // THE PROOF OF HARM. R and R' are the SAME instant, one shipped as a number and one as a string. With the
  // opt-in max-age staleness guard ON, R' is REFUSED (the descriptor is stale). R is APPLIED, because the guard
  // ran on nothing. Before this change both apply paths wrote the same empty row set, so the pack read CLEAN on
  // the apply where replay protection was NOT in force. The refusal is unchanged (backward tolerance is
  // deliberate); what changed is that the pack can now tell the two apart.
  ok("[R'] the SAME instant as a parseable string IS refused by the max-age guard", Rp.refused === true);
  ok("[R] the type-malformed twin is still APPLIED (behaviour unchanged) ...", R.refused === false);
  ok("[R != R'] ... but it is no longer SILENT: the unenforced guard is now a row", Object.keys(R.rows).length === 1 && JSON.stringify(R.rows) !== JSON.stringify(P.rows));

  // ---- WATERMARK PRESENT. The old code collapsed "the publisher shipped a broken sequence claim (our release
  // bug)" and "this is an ordinary legacy descriptor with no sequence (nothing to fix)" onto ONE counter name.
  const WM = { lastSeq: 11, lastIssuedAt: "2026-07-10T00:00:00Z" };
  const S = await resolveAndCheck(sc, base({ sequence: "12", issuedAt: FRESH_INSTANT }), WM);
  const T = await resolveAndCheck(sc, base({ issuedAt: FRESH_INSTANT }), WM);
  ok("[S] a MALFORMED sequence with a watermark records the malformed row", JSON.stringify(S.rows) === JSON.stringify({ "update-degraded-freshness-sequence-malformed": 1 }));
  ok("[T] an ABSENT sequence (an ordinary legacy descriptor) records the ABSENT row", JSON.stringify(T.rows) === JSON.stringify({ "update-degraded-freshness-sequence-absent": 1 }));
  ok("[S != T] our release bug and a legacy descriptor are no longer the same row", JSON.stringify(S.rows) !== JSON.stringify(T.rows));
  ok("[S] an ERASED claim is never ALSO filed as a claim the publisher never made", S.rows["update-degraded-freshness-sequence-absent"] === undefined);

  const U = await resolveAndCheck(sc, base({ sequence: 12, issuedAt: 1_600_000_000 }), WM);
  const V = await resolveAndCheck(sc, base({ sequence: 12, issuedAt: HOSTILE }), WM);
  const W = await resolveAndCheck(sc, base({ sequence: 12 }), WM);
  ok("[U] a numeric issuedAt with a watermark records the present-but-unusable row", JSON.stringify(U.rows) === JSON.stringify({ "update-degraded-freshness-issuedat-unparseable": 1 }));
  ok("[V] an unparseable STRING issuedAt records the same row (same publisher bug, same remedy)", JSON.stringify(V.rows) === JSON.stringify({ "update-degraded-freshness-issuedat-unparseable": 1 }));
  ok("[W] an ABSENT issuedAt records the ABSENT row instead", JSON.stringify(W.rows) === JSON.stringify({ "update-degraded-freshness-issuedat-absent": 1 }));
  ok("[U != W] a broken timestamp claim and a legacy descriptor are no longer the same row", JSON.stringify(U.rows) !== JSON.stringify(W.rows));

  // CLOSED VOCABULARY + NO CUSTODY. Every row name is an admitted counter, and the hostile claim value that
  // caused the row never rides in it.
  const every = [P, Q, R, Rp, S, T, U, V, W].flatMap((s) => Object.keys(s.rows));
  ok("every freshness row is an admitted ADMIN_COUNTER_NAMES member", every.every((n) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(n)));
  ok("no-custody: the malformed claim VALUE never enters a row", !JSON.stringify([P, Q, R, Rp, S, T, U, V, W].map((s) => s.rows)).includes("acme-health"));

  // THE WIRING, asserted against the route's own source: a row nobody folds into the pack is not a row.
  const route = readFileSync(path.join(SRC, "admin", "router-updates.ts"), "utf8");
  const ramp = readFileSync(path.join(SRC, "admin", "router-updates-ramp.ts"), "utf8");
  ok("POST /update/apply passes the degraded set to the resolver and folds it into adminCounters", route.includes("loadVerifiedChannel(env, undefined, degraded)") && route.includes("noteUpdateDegradations(scheduler, [...degraded])"));
  ok("POST /update/ramp does the same", ramp.includes("loadVerifiedChannel(env, undefined, degraded)") && ramp.includes("noteUpdateDegradations(scheduler, [...degraded])"));
}

// ============================================================================================================
// THE FOURTH SIBLING. "Why do some of our audit rows have no source IP?"
//
// The counter answers that question with {count, lastAt}: a static count is a bounded historical population, a
// recent lastAt is a capture path failing now. It only answers it if a HEALTHY engine reads zero. It did not:
// on a fresh Access-fenced estate the console's very first call (GET /admin/whoami) IS the first-owner
// bootstrap, that bootstrap appends an ATTRIBUTED HUMAN audit row, and the address the engine was holding was
// dropped on the floor -- so the newly onboarded customer, who is exactly the customer who raises this ticket,
// read as an ongoing capture failure, permanently.
// ============================================================================================================

const EDGE_IP = "203.0.113.47";
const MISSING_SOURCE_IP_COUNTER = "audit-human-event-missing-source-ip";

async function g346(): Promise<void> {
  console.log("the ACCESS first-owner bootstrap now carries the address the router already held");
  const signer = await makeSigner();
  try {
    // A fresh Access-fenced engine: an EMPTY DO, a real RS256 Access JWT verified against a controlled JWKS,
    // the PRODUCTION handleAdmin. The counters are read from the DO's own aggregate key, which is the same key
    // the pack's adminCounters gatherer projects from.
    const drive = async (edgeIp: string | null): Promise<{ counters: AdminCounters; audit: AuditEvent[] }> => {
      const sched = makeScheduler();
      const env = { ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD } as unknown as Env;
      const assertion = await signer.tokenFor("owner@acme-health.example");
      const headers: Record<string, string> = { "cf-access-jwt-assertion": assertion };
      if (edgeIp !== null) headers["CF-Connecting-IP"] = edgeIp;
      // THE REAL CLIENT CALL: console/src/lib/api/client-downpipes.ts whoami(t) -> GET /admin/whoami, the first
      // call the console makes on every load. On an empty role table this IS the first-owner bootstrap.
      const resp = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers }), env);
      if (resp.status !== 200) throw new Error(`whoami did not answer 200: ${resp.status}`);
      const counters = ((await sched.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY)) ?? {}) as AdminCounters;
      const audit = [...(await sched.storage.list<AuditEvent>({ prefix: AUDIT_PREFIX })).values()];
      return { counters, audit };
    };

    // STATE H: a HEALTHY engine. The edge sends the address on every request.
    const H = await drive(EDGE_IP);
    const bootstrapH = H.audit.find((e) => e.action === "bootstrap-consumed");
    ok("[H] the console's first whoami bootstraps the owner and appends the bootstrap-consumed row", bootstrapH !== undefined);
    ok("[H] that row is an ATTRIBUTED HUMAN event (an email, the access method)", bootstrapH?.actorEmail === "owner@acme-health.example" && bootstrapH?.actorMethod === "access");
    ok("[H] and it now CARRIES the address the router read off the edge header", bootstrapH?.sourceIp === EDGE_IP);
    ok("[H] a healthy engine records NO capture fault (the wolf cry is gone)", (H.counters[MISSING_SOURCE_IP_COUNTER] as unknown) === undefined);

    // STATE F: a REAL capture failure. Identical drive, no edge address.
    const F = await drive(null);
    const bootstrapF = F.audit.find((e) => e.action === "bootstrap-consumed");
    ok("[F] with no address to capture, the row is honestly blank", bootstrapF?.sourceIp === null);
    ok("[F] and the capture fault IS counted", (F.counters[MISSING_SOURCE_IP_COUNTER] as { count?: number } | undefined)?.count === 1);
    ok("[H != F] healthy and failing are no longer the same pack row", JSON.stringify(H.counters[MISSING_SOURCE_IP_COUNTER] ?? null) !== JSON.stringify(F.counters[MISSING_SOURCE_IP_COUNTER] ?? null));

    // NO CUSTODY: the address never enters the counter aggregate, in either state.
    ok("no-custody: no address rides in the counter aggregate", !JSON.stringify([H.counters, F.counters]).includes("203.0.113"));
    ok("the counter name is an admitted ADMIN_COUNTER_NAMES member", (ADMIN_COUNTER_NAMES as readonly string[]).includes(MISSING_SOURCE_IP_COUNTER));
  } finally {
    signer.restoreFetch();
  }
}

// ============================================================================================================
// THE STRUCTURAL GATE. Patching one more producer of the same defect is not a fix, so this reads the engine's
// own source: every audit draft whose actor is ATTRIBUTED (an email or a
// subject) and whose method is HUMAN must take its source IP from a caller/record/param field. A hard-coded
// null is allowed ONLY where the actor is the engine itself, or where the event is genuinely unattributed (a
// failed authn ceremony has no verified person and no session to take an address from).
// ============================================================================================================

function srcFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...srcFiles(p));
    else if (e.name.endsWith(".ts")) out.push(p);
  }
  return out;
}

// Extract the balanced text of every audit-draft literal: the argument of appendAudit(...) and of the
// drafts.push(...) that feeds it (audit-status.ts builds its engine-observed drafts that way).
function draftLiterals(text: string): { at: number; body: string }[] {
  const out: { at: number; body: string }[] = [];
  for (const m of text.matchAll(/(?:appendAudit|drafts\.push)\(\{/g)) {
    const start = (m.index ?? 0) + m[0].length - 1;
    let depth = 0;
    let end = start;
    for (let i = start; i < text.length; i++) {
      const c = text[i];
      if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    out.push({ at: text.slice(0, start).split("\n").length, body: text.slice(start, end + 1) });
  }
  return out;
}

function structuralGate(): void {
  console.log("structural gate -- no attributed human audit draft may hard-code a null source IP");
  const offenders: string[] = [];
  const missing: string[] = [];
  for (const file of srcFiles(SRC)) {
    const text = readFileSync(file, "utf8");
    const rel = path.relative(SRC, file);
    for (const { at, body } of draftLiterals(text)) {
      const field = (name: string): string | null => {
        const m = body.match(new RegExp(`\\b${name}\\s*:\\s*([^,\\n}]+)`));
        return m ? (m[1] ?? "").trim() : null;
      };
      const sourceIp = field("sourceIp");
      // The draft must SAY something about the address: an omitted field is the shape that started this.
      if (sourceIp === null && !/\bsourceIp\s*,/.test(body)) {
        missing.push(`${rel}:${at}`);
        continue;
      }
      if (sourceIp !== "null") continue; // threaded from a caller / record / param: fine
      const method = field("actorMethod");
      const engineActor = method === '"engine"' || method === '"token"';
      const unattributed = field("actorEmail") === "null" && field("actorSubject") === "null";
      if (!engineActor && !unattributed) offenders.push(`${rel}:${at} (actorMethod ${method ?? "?"})`);
    }
  }
  ok(`no audit draft omits sourceIp entirely${missing.length > 0 ? ` -- ${missing.join(", ")}` : ""}`, missing.length === 0);
  ok(`no attributed human audit draft hard-codes sourceIp: null${offenders.length > 0 ? ` -- ${offenders.join(", ")}` : ""}`, offenders.length === 0);

  // The two helpers that OWN a default `sourceIp = null` parameter are the ones a caller can silently drop the
  // address into (that is exactly what the bootstrap did). Every call must pass it explicitly.
  const dropped: string[] = [];
  for (const file of srcFiles(SRC)) {
    const text = readFileSync(file, "utf8");
    const rel = path.relative(SRC, file);
    for (const m of text.matchAll(/\bthis\.(markBootstrapConsumed|generateRecoveryFor)\(([^)]*)\)/g)) {
      const args = (m[2] ?? "").split(",").filter((a) => a.trim() !== "");
      if (args.length < 3) dropped.push(`${rel}:${text.slice(0, m.index ?? 0).split("\n").length} (${m[1]})`);
    }
  }
  ok(`every markBootstrapConsumed / generateRecoveryFor call passes the source IP${dropped.length > 0 ? ` -- ${dropped.join(", ")}` : ""}`, dropped.length === 0);
}

async function main(): Promise<void> {
  await g332();
  await g346();
  structuralGate();
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURES`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
