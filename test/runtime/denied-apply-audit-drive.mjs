// denied-apply-audit pass: the DRIVEN settlement of "does an unauthorised restore APPLY record its denied-apply
// audit row?", against the production admin router + production SchedulerDO in a real workerd isolate.
//
// The engine's own comment (src/admin/router-restore.ts, the confirm:true branch) promises that an
// unauthorised apply "always yields the 403 + the denied-apply audit and a security-relevant denial is
// never masked by a 429". This drive settles that promise directly, in an isolated workerd isolate.
//
// WHAT IT DRIVES, in one isolate, in order:
//   0. baseline the audit head via the ADMIN_TOKEN.
//   1. grant an "operator" role to a test email (break-glass owner). Its SUCCESS row is one known positive.
//   2. mint that email a session token through the DO method the passkey login path itself calls.
//   3. PRECONDITION: GET /admin/whoami on that session must report role "operator". The live spec throws
//      here on a mis-provisioned persona, BEFORE its first graded step, which is the exact trap this drive
//      refuses to fall into: a precondition failure must never be reported as a missing audit row.
//   4. THE SUBJECT: POST /admin/restore { confirm:true, runId:<synthetic ULID> } on the operator session.
//   5. KNOWN POSITIVE of the right kind: POST /admin/roles on the SAME session, refused, which the router
//      records through the SAME recordAudit helper into the SAME DO (role-change/denied).
//   6. NEGATIVE CONTROL ON THE SUBJECT ROUTE: a MALFORMED runId apply on the same session, which is
//      refused 400 BEFORE the gate and must therefore record NOTHING. This separates "the gate was
//      reached and did not audit" from "the request never reached the gate".
//   7. the audit read WIDENED: unfiltered, by action, by outcome, by actor, by afterSeq, by time window,
//      and through the uncapped compliance export. Each is reported separately.
//   8. NEGATIVE CONTROL ON THE READER: a filter that must match nothing, so a reader that answers
//      "found" to everything is caught.
//
// Assertions are on the EXACT row (actor, action, outcome, target.runId), never on existence or a count.
//
// Run: node test/runtime/denied-apply-audit-drive.mjs

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "denied-apply-audit-admin-worker.ts");
const OUTFILE = join(here, ".bundle", "denied-apply-audit-admin-worker.js");

const ADMIN_TOKEN = "denied-apply-audit-local-isolate-token-not-a-real-credential";
const CONSOLE_ORIGIN = "https://console.denied-apply-audit.invalid";
const OPERATOR_EMAIL = "denied-apply-audit-operator@example.invalid";
const SESSION_COOKIE = "__Host-downpipes_session";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** The harness's own makeSyntheticRunId, reproduced: 26 Crockford chars, first in 0..7 (fits 128 bits). */
function makeSyntheticRunId() {
  const bytes = randomBytes(26);
  let out = "";
  for (let i = 0; i < 26; i++) {
    const b = bytes[i] ?? 0;
    out += i === 0 ? CROCKFORD[b & 0x07] : CROCKFORD[b & 0x1f];
  }
  return out;
}

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}\n      ${detail}`);
}

async function main() {
  const built = await build({
    entryPoints: [ENTRY],
    outfile: OUTFILE,
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    conditions: ["workerd", "browser"],
    // cloudflare:sockets is a workerd BUILT-IN module (the SIEM syslog sender's TCP transport). esbuild
    // cannot resolve it and must not try: workerd provides it at runtime, exactly as in the real deploy.
    external: ["cloudflare:sockets"],
    keepNames: true,
    legalComments: "none",
    write: true,
    logLevel: "silent",
    sourcemap: false,
  });
  if (built.errors.length > 0) throw new Error(`esbuild failed:\n${built.errors.map((e) => e.text).join("\n")}`);

  const mf = new Miniflare({
    modules: true,
    script: readFileSync(OUTFILE, "utf8"),
    scriptPath: OUTFILE,
    compatibilityDate: "2026-06-01",
    durableObjects: { SCHEDULER: { className: "SchedulerDO", useSQLite: true } },
    bindings: { ADMIN_TOKEN, CONSOLE_ORIGIN },
    log: new Log(LogLevel.WARN),
  });
  await mf.ready;

  const call = async (method, path, { body, bearer, cookie, origin, headers } = {}) => {
    const h = { ...(headers ?? {}) };
    if (body !== undefined) h["content-type"] = "application/json";
    if (bearer !== undefined) h.authorization = `Bearer ${bearer}`;
    if (cookie !== undefined) h.cookie = `${SESSION_COOKIE}=${cookie}`;
    if (origin !== undefined) h.origin = origin;
    const r = await mf.dispatchFetch(`https://engine.denied-apply-audit.invalid${path}`, {
      method,
      headers: h,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let json = null;
    try {
      json = text.length ? JSON.parse(text) : null;
    } catch {
      /* non-JSON */
    }
    return { status: r.status, json, text };
  };

  // TWO readers, deliberately. The break-glass ADMIN_TOKEN is the reader the live journey uses, but the
  // bare-token path is rate-limited to ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW (10) per IP per minute, so a
  // widened read that spends it answers 429 with an empty events array: an ABSENCE THAT IS NOT A FINDING,
  // and the exact way a widened read could lie. The token reader is spent sparingly on the reads that
  // mirror the journey, and the rest go through the operator's own session (a plain operator holds
  // audit.read), which is a second independent reader on the same chain. Every read asserts status 200.
  const readAudit = (query, bearer = ADMIN_TOKEN) => call("GET", `/admin/audit${query}`, { bearer });
  let readAuditAsOperator = null; // bound once the session is minted
  const runIdOf = (e) => (e && typeof e.target === "object" && e.target !== null && typeof e.target.runId === "string" ? e.target.runId : undefined);
  const describe = (e) => `seq=${e.seq} action=${e.action} outcome=${e.outcome} actor=${e.actorEmail ?? e.actorSubject ?? "?"} runId=${runIdOf(e) ?? "-"}`;

  try {
    // ---- 0. baseline -----------------------------------------------------------------------------
    const head0 = await readAudit("?limit=1");
    if (head0.status !== 200) throw new Error(`baseline audit read answered ${head0.status}: ${head0.text.slice(0, 200)}`);
    const baselineSeq = head0.json.headSeq;
    const tStart = new Date().toISOString();
    console.log(`\n[denied-apply-audit] baseline headSeq=${baselineSeq} at ${tStart}\n`);

    // ---- 1. grant the operator role (break-glass owner) -------------------------------------------
    const grant = await call("POST", "/admin/roles", { body: { email: OPERATOR_EMAIL, role: "operator" }, bearer: ADMIN_TOKEN });
    if (grant.status !== 200) throw new Error(`role grant answered ${grant.status}: ${grant.text.slice(0, 300)}`);

    // ---- 2. mint the operator a session -----------------------------------------------------------
    const issued = await call("POST", "/do/passkey/session/issue", { body: { email: OPERATOR_EMAIL } });
    if (issued.status !== 200 || issued.json?.ok !== true) throw new Error(`session issue answered ${issued.status}: ${issued.text.slice(0, 200)}`);
    const sessionToken = issued.json.token;
    readAuditAsOperator = (query) => call("GET", `/admin/audit${query}`, { cookie: sessionToken });

    // ---- 3. PRECONDITION: the session really is a plain operator ----------------------------------
    const who = await call("GET", "/admin/whoami", { cookie: sessionToken });
    const role = who.json?.role;
    record(
      "precondition-operator-role",
      who.status === 200 && role === "operator",
      `GET /admin/whoami on the minted session -> ${who.status} role="${role}" email="${who.json?.email}". A role holding restore.apply could not exercise the denial, so this gates everything below.`,
    );
    if (!(who.status === 200 && role === "operator")) throw new Error("precondition failed: the session is not a plain operator; nothing below would mean anything");

    // ---- 4. THE SUBJECT: the unauthorised apply ---------------------------------------------------
    const runId = makeSyntheticRunId();
    const apply = await call("POST", "/admin/restore", {
      body: { runId, confirm: true, target: { binding: "RESTORE_KV" } },
      cookie: sessionToken,
      origin: CONSOLE_ORIGIN,
    });
    record(
      "wire-403-restore-apply",
      apply.status === 403 && apply.json?.error === "forbidden" && apply.json?.required === "restore.apply",
      `POST /admin/restore (confirm:true) as operator -> ${apply.status} error="${apply.json?.error}" required="${apply.json?.required}" have="${apply.json?.have}" runId=${runId}`,
    );

    // ---- 5. KNOWN POSITIVE: a refused role write on the same session, same DO, same recordAudit ----
    const deniedRoleWrite = await call("POST", "/admin/roles", {
      body: { email: "denied-apply-audit-victim@example.invalid", role: "owner" },
      cookie: sessionToken,
      origin: CONSOLE_ORIGIN,
    });

    // ---- 6. NEGATIVE CONTROL on the subject route: malformed runId, refused BEFORE the gate --------
    const malformed = await call("POST", "/admin/restore", {
      body: { runId: "../../not-a-ulid", confirm: true },
      cookie: sessionToken,
      origin: CONSOLE_ORIGIN,
    });
    record(
      "malformed-runid-400-before-the-gate",
      malformed.status === 400,
      `POST /admin/restore (confirm:true, malformed runId) -> ${malformed.status} error="${malformed.json?.error}". This one must leave NO restore-apply row, which is what tells a pre-gate rejection apart from a gate that failed to audit.`,
    );

    // ---- 7. NEGATIVE CONTROL ON THE READER, run FIRST so it cannot be starved by the token budget ----
    // An action never driven in this isolate must come back EMPTY with a 200. Asserting the STATUS as well
    // as the emptiness is the whole point: a 429 or a 401 also returns zero events, so a control that reads
    // only the length would pass on a reader that had stopped answering.
    const neverHappened = await readAuditAsOperator("?action=downpipe-delete&limit=200");
    const neverEvents = Array.isArray(neverHappened.json?.events) ? neverHappened.json.events : [];
    record(
      "reader-negative-control",
      neverHappened.status === 200 && neverEvents.length === 0,
      `GET /admin/audit?action=downpipe-delete -> ${neverHappened.status} with ${neverEvents.length} event(s); must be 200 AND empty, else the reader either answers "found" to anything or is not answering at all`,
    );
    // POSITIVE CONTROL ON THE SAME READER, immediately after: the same reader, same window, must be able to
    // return a row. A reader that answers empty to EVERYTHING would satisfy the negative control alone.
    const readerAlive = await readAuditAsOperator("?action=role-change&limit=200");
    const aliveEvents = Array.isArray(readerAlive.json?.events) ? readerAlive.json.events : [];
    record(
      "reader-positive-control",
      readerAlive.status === 200 && aliveEvents.length > 0,
      `GET /admin/audit?action=role-change -> ${readerAlive.status} with ${aliveEvents.length} event(s); the same reader that answered EMPTY above must answer NON-EMPTY here, else its emptiness proves nothing`,
    );

    // ---- 8. the audit read, WIDENED ---------------------------------------------------------------
    const tEnd = new Date().toISOString();
    const reads = {
      "unfiltered-session": await readAuditAsOperator("?limit=500"),
      "by-outcome-session": await readAuditAsOperator("?outcome=denied&limit=200"),
      "by-actor-session": await readAuditAsOperator(`?actor=${encodeURIComponent(OPERATOR_EMAIL)}&limit=200`),
      "by-afterSeq-session": await readAuditAsOperator(`?afterSeq=${baselineSeq}&limit=200`),
      "by-time-window-session": await readAuditAsOperator(`?from=${encodeURIComponent(tStart)}&to=${encodeURIComponent(tEnd)}&limit=200`),
      // The two that mirror the live journey's own read, on the SAME reader it uses (the ADMIN_TOKEN).
      "by-action-ADMIN_TOKEN": await readAudit("?action=restore-apply&limit=200"),
      "by-action-and-afterSeq-ADMIN_TOKEN": await readAudit(`?action=restore-apply&afterSeq=${baselineSeq}&limit=200`),
    };
    const exportRead = await call("GET", "/admin/audit/export?action=restore-apply", { cookie: sessionToken });

    // The EXACT row: actor + action + outcome + this run's runId. Never existence, never a count.
    const isTheRow = (e) => e.action === "restore-apply" && e.outcome === "denied" && e.actorEmail === OPERATOR_EMAIL && runIdOf(e) === runId;
    for (const [name, r] of Object.entries(reads)) {
      const events = Array.isArray(r.json?.events) ? r.json.events : [];
      const hit = events.find(isTheRow);
      record(
        `audit-read-${name}`,
        r.status === 200 && hit !== undefined,
        `${r.status} ${events.length} event(s); exact row (action=restore-apply, outcome=denied, actor=${OPERATOR_EMAIL}, runId=${runId}) ${hit ? `FOUND: ${describe(hit)}` : "NOT FOUND"}`,
      );
    }
    {
      const events = Array.isArray(exportRead.json?.events) ? exportRead.json.events : [];
      const hit = events.find(isTheRow);
      record("audit-read-uncapped-export", exportRead.status === 200 && hit !== undefined, `${exportRead.status} ${events.length} event(s); exact row ${hit ? `FOUND: ${describe(hit)}` : "NOT FOUND"}`);
    }

    const all = reads["unfiltered-session"].json?.events ?? [];
    // The known positive: the refused role write by the SAME actor on the SAME DO.
    const positive = all.find((e) => e.action === "role-change" && e.outcome === "denied" && e.actorEmail === OPERATOR_EMAIL);
    record(
      "known-positive-role-change-denied-same-actor-same-do",
      positive !== undefined,
      `POST /admin/roles as the operator -> ${deniedRoleWrite.status}; its router-recorded denial row ${positive ? `FOUND: ${describe(positive)}` : "NOT FOUND (then the READER is at fault, not the product)"}`,
    );
    // A second known positive of the other kind: a SUCCESS row, written by the DO at its commit point.
    const positiveSuccess = all.find((e) => e.action === "role-change" && e.outcome === "success");
    record(
      "known-positive-role-change-success",
      positiveSuccess !== undefined,
      `the break-glass owner's grant of "operator" ${positiveSuccess ? `FOUND: ${describe(positiveSuccess)}` : "NOT FOUND"}`,
    );

    // NEGATIVE CONTROL on the malformed apply: it must have left no row of its own.
    const malformedRows = all.filter((e) => e.action === "restore-apply" && runIdOf(e) === "../../not-a-ulid");
    record(
      "malformed-runid-left-no-audit-row",
      malformedRows.length === 0,
      `restore-apply rows carrying the malformed runId: ${malformedRows.length} (must be 0: that rejection precedes the gate)`,
    );

    // ---- 9. THE OTHER HALF OF THE QUOTED CONTRACT: a denial must never be MASKED BY A 429 -----------
    // "an unauthorised apply always yields the 403 + the denied-apply audit and a security-relevant denial
    // is never masked by a 429" (router-restore.ts, the confirm:true branch). Drive the operator over its
    // own per-caller window (RATE_LIMIT_MAX_PER_WINDOW = 120 mutating requests / 60s) with DRY RUNS, which
    // it is entitled to and which are rate-limited in their own branch, then attempt the apply again with
    // a fresh synthetic runId. It must still be 403 with a fresh audit row, not a 429.
    let burnt = 0;
    let sawDryRunLimit = false;
    for (let i = 0; i < 160 && !sawDryRunLimit; i++) {
      const dry = await call("POST", "/admin/restore", { body: { runId: makeSyntheticRunId(), confirm: false }, cookie: sessionToken, origin: CONSOLE_ORIGIN });
      burnt++;
      if (dry.status === 429) sawDryRunLimit = true;
    }
    if (!sawDryRunLimit) {
      record("rate-limited-denial-not-masked", false, `COULD NOT CHECK: ${burnt} dry runs did not exhaust the caller's window, so the 429 state was never reached and this contract is untested here`);
    } else {
      const runId2 = makeSyntheticRunId();
      const applyLimited = await call("POST", "/admin/restore", { body: { runId: runId2, confirm: true, target: { binding: "RESTORE_KV" } }, cookie: sessionToken, origin: CONSOLE_ORIGIN });
      const after = await readAuditAsOperator("?action=restore-apply&limit=200");
      const afterEvents = Array.isArray(after.json?.events) ? after.json.events : [];
      const hit2 = afterEvents.find((e) => e.action === "restore-apply" && e.outcome === "denied" && e.actorEmail === OPERATOR_EMAIL && runIdOf(e) === runId2);
      record(
        "rate-limited-denial-not-masked",
        applyLimited.status === 403 && applyLimited.json?.required === "restore.apply" && hit2 !== undefined,
        `after ${burnt} dry runs took the caller into its 429 window, the unauthorised apply answered ${applyLimited.status} error="${applyLimited.json?.error}" required="${applyLimited.json?.required}" and its exact row (runId=${runId2}) ${hit2 ? `FOUND: ${describe(hit2)}` : "NOT FOUND"}`,
      );
    }

    console.log("\n[denied-apply-audit] every audit row this isolate wrote:");
    for (const e of all) console.log(`   ${describe(e)}`);
  } finally {
    await mf.dispose();
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n[denied-apply-audit] ${results.length - failed.length}/${results.length} checks passed`);
  process.exitCode = failed.length === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error(`[denied-apply-audit] DRIVE FAULT: ${e?.stack ?? e}`);
  process.exitCode = 2;
});
