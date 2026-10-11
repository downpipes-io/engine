// validate-audit-flood-eviction: a caller who may not act must not be able to push an Owner's audit rows off
// the retained chain. The chain keeps AUDIT_CAP rows and rollOverAudit deletes the oldest ones, so every
// unthrottled, uncoalesced row a low-privilege or anonymous caller can write is one Owner row closer to
// eviction.
//
// CHECK A drives the real router as a Viewer on POST /admin/downpipes/delete (not a step-up route). The gate
// refuses, and the refusal is recorded. It sends enough refused requests to pass AUDIT_CAP and asserts the safe
// outcome: every Owner row written before the flood is still on the chain, OR the flood added at most
// FLOOD_ROW_BOUND rows (the refusals were coalesced).
//
// CHECK B drives the real router with no session on POST /admin/auth/recovery (the recovery-code sign-in). It
// measures the rows each attempt writes and the limits that apply (per IP, and across IPs in one window), then
// runs a single source IP at its real admitted rate, on a simulated clock, until the flood has written
// AUDIT_CAP rows. It asserts the same safe outcome: the pre-existing Owner rows survive, OR the attempts were
// coalesced to at most FLOOD_ROW_BOUND rows.
//
// The fix folds both writers (src/sched/audit-fold.ts), so these cases were added beside the two above:
//   - CHECK A2: many Viewer accounts flood refusals in one window; CHECK B4 and B5: many IPv4 sources, and many
//     addresses in one IPv6 /64, flood the recovery sign-in in one window. Each writes more attempts than
//     AUDIT_CAP, so one row per attempt would have evicted the oldest Owner row; each must not move it.
//   - CHECK B0 and CHECK C: one normal failed recovery attempt still writes its own row with attempts 1, and
//     once the pending counts are written the folded rows' attempts sum to the attempts made.
//   - CHECK D: one refused request still writes its own denied row with deniedAttempts 1, and a Viewer's later
//     refusals are counted onto a row whose deniedAttempts sum to the requests made.
//   - CHECK E: a failed passkey sign-in from 334 IPs, 30 attempts each, in one window. The authn-failure rows
//     share the fold's per-minute budget, so the flood writes at most AUTHN_WINDOW_ROWS rows and cannot move
//     the oldest Owner row. One failure alone still writes its own row, and the counts sum to the attempts.
//   - CHECK F: a slow fill of all three refused-attempt writers (recovery, failed passkey sign-in, Viewer
//     refusals) for two simulated days. The hourly ceiling bounds the rows to about 31 an hour in all, so the
//     oldest Owner row stays. One failure of each kind alone still writes its own row with a count of 1, and
//     once the pending counts are written the rows sum to the attempts made.
//   - CHECK G: the denied fold has its own hourly ceiling, an overflow row, and stored counts. G1: a sign-in
//     flood that spends the sign-in ceiling does not stop a Viewer's refusal from writing its denied row in the
//     same hour. G2: refusals past the denied ceiling are written on a denied-overflow row with their count.
//     G3: a restart in the hour (a new SchedulerDO on the same storage) loses no pending count of any fold.
//     G4: after a restart, the alarm alone writes the pending counts.

import { AUDIT_CAP, AUDIT_PREFIX, type AuditEvent } from "../src/admin/audit.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { __advanceAuditFoldClockForTest, DENIED_FOLD_ROWS_PER_WINDOW, RECOVERY_FOLD_ROWS_PER_WINDOW } from "../src/sched/audit-fold.ts";
import { AUTH_RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS } from "../src/sched/scheduler-do-limits.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { buildContext, OWNER, VIEWER } from "./validate-audit-harness.ts";

// A coalescing fix writes one row per window or per burst. 100 rows for a flood of more than AUDIT_CAP
// requests is a factor of 100 below one row per request, and far below the cap.
const FLOOD_ROW_BOUND = 100;

const out = (s: string): void => {
  process.stdout.write(`${s}\n`);
};
let failures = 0;
function ok(label: string, cond: boolean): void {
  out(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The audit mirror writes one structured log line per committed row. Drop those lines so the run stays
// readable; everything this validator prints goes through `out`.
const realConsoleLog = console.log;
console.log = (...a: unknown[]): void => {
  const line = String(a[0]);
  if (line.includes('"source":"downpipe-audit"') || line.includes('"service":"downpipe-engine"')) return;
  realConsoleLog(...a);
};

// A simulated clock, so Check B can run a single IP at its real per-minute rate for hours in seconds.
const realDateNow = Date.now.bind(Date);
let skewMs = 0;
// frozenAt pins the clock, so a flood that takes longer than a minute of real time stays in one window.
let frozenAt: number | null = null;
Date.now = (): number => frozenAt ?? realDateNow() + skewMs;

async function buildWorld() {
  const { ctx, realFetch } = await buildContext();
  const env = ctx.accessEnv();
  const tokens = new Map<string, string>();
  async function asUser(email: string, path: string, body: unknown, ip = "198.51.100.7"): Promise<Response> {
    if (!tokens.has(email)) tokens.set(email, await ctx.tokenFor(email));
    return handleAdmin(
      new Request(`https://engine.example${path}`, {
        method: "POST",
        headers: { "cf-access-jwt-assertion": tokens.get(email)!, "content-type": "application/json", "CF-Connecting-IP": ip },
        body: JSON.stringify(body),
      }),
      env,
    );
  }
  async function getAsOwner(path: string): Promise<Response> {
    return handleAdmin(new Request(`https://engine.example${path}`, { headers: { "cf-access-jwt-assertion": await ctx.tokenFor(OWNER) } }), env);
  }
  async function anonRecovery(ip: string, email: string): Promise<Response> {
    return handleAdmin(
      new Request("https://engine.example/admin/auth/recovery", {
        method: "POST",
        headers: { "content-type": "application/json", "CF-Connecting-IP": ip },
        body: JSON.stringify({ email, code: "AAAA-BBBB-CCCC" }),
      }),
      env,
    );
  }
  // A failed passkey sign-in through the real router. The DO refuses the unknown challenge and records an
  // authn-failure row (ceremony passkey-login). CONSOLE_ORIGIN is set because the ceremony needs an origin.
  const passkeyEnv = { ...env, CONSOLE_ORIGIN: "https://console.example" } as typeof env;
  async function anonPasskey(ip: string): Promise<Response> {
    return handleAdmin(
      new Request("https://engine.example/admin/auth/login/finish", {
        method: "POST",
        headers: { "content-type": "application/json", "CF-Connecting-IP": ip },
        body: JSON.stringify({ challengeId: "not-a-real-challenge", credentialId: "nope", clientDataJSON: "e30", authenticatorData: "AA", signature: "AA" }),
      }),
      passkeyEnv,
    );
  }
  const rows = (): AuditEvent[] => ctx.sched.storage.rawKeys(AUDIT_PREFIX).map((k) => ctx.sched.storage.rawGet<AuditEvent>(k)!);
  const count = (): number => ctx.sched.storage.rawKeys(AUDIT_PREFIX).length;

  // Real Owner actions on top of the harness bootstrap (first sign-in + three grants): one more grant and one
  // downpipe delete of an id that does not exist (the router records it as failed, attributed to the Owner).
  const g = await asUser(OWNER, "/admin/roles", { email: "marker@acme.example", role: "operator" });
  await g.arrayBuffer();
  const d = await asUser(OWNER, "/admin/downpipes/delete", { id: "owner-marker-downpipe" });
  await d.arrayBuffer();
  const ownerRows = rows().filter((e) => e.actorEmail === OWNER);
  return { ctx, realFetch, asUser, getAsOwner, anonRecovery, anonPasskey, rows, count, ownerRows, seedStatuses: [g.status, d.status] };
}

function tally(m: Record<number, number>, s: number): void {
  m[s] = (m[s] ?? 0) + 1;
}

// The count a folded row carries: attempts on a recovery row, deniedAttempts on a router denied row.
function recoveryAttempts(e: AuditEvent): number {
  return e.target.kind === "authn-attempt" && e.target.ceremony === "recovery" ? e.target.attempts : 0;
}
function deniedAttempts(e: AuditEvent): number {
  return typeof e.target.deniedAttempts === "number" ? e.target.deniedAttempts : 0;
}
const isRecoveryFailure = (e: AuditEvent): boolean => e.action === "recovery-code-used" && e.outcome !== "success";

// The rows one fold may write in one window of a flood: the budget plus, for recovery, one overflow row per
// outcome.
const RECOVERY_WINDOW_ROWS = RECOVERY_FOLD_ROWS_PER_WINDOW + 2;

// The bounds checks E, F and G hold the fix to, stated here rather than imported so they also run, and fail,
// against a tree that predates them. They match AUTHN_FOLD_ROWS_PER_WINDOW (2), SIGN_IN_FOLD_ROWS_PER_HOUR
// (20) and DENIED_FOLD_ROWS_PER_HOUR (9) plus the hourly overflow rows (one per recovery outcome, one denied)
// in audit-fold.ts.
const AUTHN_WINDOW_ROWS = 2;
const DENIED_HOURLY_ROWS = 9 + 1;
const HOURLY_ROWS = 20 + 2 + DENIED_HOURLY_ROWS;
const passkeyAttempts = (e: AuditEvent): number => (e.action === "authn-failure" && e.target.kind === "authn-attempt" && e.target.ceremony === "passkey-login" ? e.target.attempts : 0);
const isPasskeyRow = (e: AuditEvent): boolean => passkeyAttempts(e) > 0;

// Each check runs in its own process (CHECK=A to G; the default runs all seven as children), because
// the router caches the Access JWKS for the process and each harness context mints a fresh signing key.
const which = process.env.CHECK;
if (which === undefined) {
  const { spawnSync } = await import("node:child_process");
  let rc = 0;
  let failedChildren = 0;
  let children = 0;
  for (const c of ["A", "B", "C", "D", "E", "F", "G"]) {
    const r = spawnSync(process.execPath, [new URL(import.meta.url).pathname], { stdio: "inherit", env: { ...process.env, CHECK: c } });
    children++;
    if (r.status !== 0) {
      rc = 1;
      failedChildren++;
    }
  }
  // The children print their own assertions and verdicts; the parent's verdict is how many of them failed.
  verdictReached(failedChildren, children);
  process.exit(rc);
}

// ---------------------------------------------------------------------------------------------------------
if (which === "A") {
out("CHECK A: Viewer floods refused POST /admin/downpipes/delete");
  const w = await buildWorld();
  out(`  seed Owner statuses (roles, downpipes/delete): ${w.seedStatuses.join(", ")}`);
  const ownerSeqs = w.ownerRows.map((e) => e.seq);
  out(`  pre-flood rows ${w.count()}, Owner rows ${ownerSeqs.length} (seqs ${ownerSeqs.join(",")})`);
  ok("at least five Owner rows exist before the flood", ownerSeqs.length >= 5);

  const n = AUDIT_CAP + 50;
  const before = w.count();
  const headBefore = w.rows().at(-1)!.seq;
  const statuses: Record<number, number> = {};
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const r = await w.asUser(VIEWER, "/admin/downpipes/delete", { id: `flood-${i}` });
    tally(statuses, r.status);
    await r.arrayBuffer();
  }
  const ms = Math.round(performance.now() - t0);
  const after = w.rows();
  const written = after.at(-1)!.seq - headBefore;
  const retainedOwner = after.filter((e) => e.actorEmail === OWNER).map((e) => e.seq);
  const lostOwner = ownerSeqs.filter((s) => !retainedOwner.includes(s));
  const viewerRows = after.filter((e) => e.actorEmail === VIEWER).length;
  out(`  requests ${n}, statuses ${JSON.stringify(statuses)}, 429s ${statuses[429] ?? 0}, ${ms} ms`);
  out(`  rows written by the flood ${written} (retained count before ${before}, after ${after.length}, cap ${AUDIT_CAP})`);
  out(`  Viewer rows retained ${viewerRows}; Owner rows retained ${retainedOwner.length} of ${ownerSeqs.length}; evicted Owner seqs ${lostOwner.join(",") || "(none)"}`);
  const verify = (await (await w.getAsOwner("/admin/audit/verify")).json()) as Record<string, unknown>;
  out(`  verify ${JSON.stringify(verify)}`);
  ok(
    `CHECK A safe: every pre-flood Owner row retained (${retainedOwner.length}/${ownerSeqs.length}) OR flood rows <= ${FLOOD_ROW_BOUND} (${written})`,
    lostOwner.length === 0 || written <= FLOOD_ROW_BOUND,
  );

  // A2: many accounts, one window. Any signed-in subject with no role row is a Viewer, so a population of
  // accounts is a population of Viewers. The budget, not the actor key, is what bounds this.
  const ACTORS = 400;
  const PER_ACTOR = 30;
  const tokens: string[] = [];
  for (let i = 0; i < ACTORS; i++) tokens.push(await w.ctx.tokenFor(`flood-viewer-${i}@evil.example`));
  const envA2 = w.ctx.accessEnv();
  skewMs += RATE_LIMIT_WINDOW_MS + 1_000;
  const headA2 = w.rows().at(-1)!.seq;
  const a2: Record<number, number> = {};
  for (let r = 0; r < PER_ACTOR; r++) {
    for (let i = 0; i < ACTORS; i++) {
      const res = await handleAdmin(
        new Request("https://engine.example/admin/downpipes/delete", {
          method: "POST",
          headers: { "cf-access-jwt-assertion": tokens[i]!, "content-type": "application/json", "CF-Connecting-IP": `198.18.${i >> 8}.${i & 255}` },
          body: JSON.stringify({ id: `a2-${r}` }),
        }),
        envA2,
      );
      tally(a2, res.status);
      await res.arrayBuffer();
    }
  }
  const afterA2 = w.rows();
  const writtenA2 = afterA2.at(-1)!.seq - headA2;
  const ownerA2 = afterA2.filter((e) => e.actorEmail === OWNER).map((e) => e.seq);
  out(`  A2 ${ACTORS} Viewer accounts x ${PER_ACTOR} refused requests in one window: statuses ${JSON.stringify(a2)}; rows written ${writtenA2}; Owner rows retained ${ownerA2.length} of ${ownerSeqs.length}`);
  ok(`A2: ${ACTORS * PER_ACTOR} refusals from ${ACTORS} accounts write at most ${DENIED_FOLD_ROWS_PER_WINDOW} rows in the window (${writtenA2})`, writtenA2 <= DENIED_FOLD_ROWS_PER_WINDOW);
  ok("A2: the many-account flood does not move the oldest Owner row", ownerSeqs.every((q) => ownerA2.includes(q)));
  skewMs = 0;
  globalThis.fetch = w.realFetch;
}

// ---------------------------------------------------------------------------------------------------------
if (which === "B") {
out("CHECK B: no session, POST /admin/auth/recovery");
  skewMs = 0;
  const w = await buildWorld();
  const ownerSeqs = w.ownerRows.map((e) => e.seq);
  out(`  pre-flood rows ${w.count()}, Owner rows ${ownerSeqs.length} (seqs ${ownerSeqs.join(",")})`);
  ok("at least five Owner rows exist before the recovery flood", ownerSeqs.length >= 5);
  const headBefore = w.rows().at(-1)!.seq;
  const head = (): number => w.rows().at(-1)!.seq;

  // B0: one normal failed attempt, nothing else in the window. It gets its own row, counting one attempt.
  const b0 = await w.anonRecovery("192.0.2.5", "someone@acme.example");
  await b0.arrayBuffer();
  const b0rows = w.rows().filter((e) => e.seq > headBefore);
  out(`  B0 one failed attempt: status ${b0.status}; rows ${b0rows.length} ${JSON.stringify(b0rows.map((e) => ({ outcome: e.outcome, sourceIp: e.sourceIp, target: e.target })))}`);
  ok(
    "B0: a single failed recovery attempt writes one row, from its source, with attempts 1",
    b0.status === 401 && b0rows.length === 1 && b0rows[0]!.outcome === "failed" && b0rows[0]!.sourceIp === "192.0.2.5" && recoveryAttempts(b0rows[0]!) === 1,
  );

  // B1: one IP, one window, 40 attempts. Rows per status.
  const b1: Record<number, number> = {};
  let rowsPer401 = 0;
  let rowsPer429 = 0;
  for (let i = 0; i < 40; i++) {
    const h0 = head();
    const r = await w.anonRecovery("192.0.2.10", "owner@acme.example");
    await r.arrayBuffer();
    await new Promise((res) => setTimeout(res, 0));
    tally(b1, r.status);
    if (r.status === 401) rowsPer401 += head() - h0;
    if (r.status === 429) rowsPer429 += head() - h0;
  }
  const last = w.rows().slice(-30);
  const outcomes: Record<string, number> = {};
  for (const e of last) outcomes[`${e.action}/${e.outcome}/actor=${e.actorEmail ?? "null"}`] = (outcomes[`${e.action}/${e.outcome}/actor=${e.actorEmail ?? "null"}`] ?? 0) + 1;
  out(`  B1 one IP, 40 attempts in one window: statuses ${JSON.stringify(b1)}; rows from 401s ${rowsPer401}, rows from 429s ${rowsPer429}`);
  out(`  B1 last 30 rows: ${JSON.stringify(outcomes)}`);

  // B2: many IPs in the SAME window. Is there an overall cap across IPs?
  const b2: Record<number, number> = {};
  const h2 = head();
  for (let ipn = 0; ipn < 20; ipn++) {
    for (let i = 0; i < AUTH_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      const r = await w.anonRecovery(`192.0.2.${100 + ipn}`, `spray${i}@evil.example`);
      await r.arrayBuffer();
      tally(b2, r.status);
    }
  }
  out(`  B2 20 IPs x ${AUTH_RATE_LIMIT_MAX_PER_WINDOW} attempts in one window: statuses ${JSON.stringify(b2)}; rows written ${head() - h2}`);

  // B3: one IP at its real admitted rate (AUTH_RATE_LIMIT_MAX_PER_WINDOW per RATE_LIMIT_WINDOW_MS), on the
  // simulated clock, until the recovery flood alone has written AUDIT_CAP rows (or 400 windows pass).
  let windows = 0;
  let attempts = 0;
  let firstOwnerEvictedAt: { attempts: number; windows: number } | null = null;
  let allOwnerEvictedAt: { attempts: number; windows: number } | null = null;
  const b3: Record<number, number> = {};
  const t0 = performance.now();
  while (head() - headBefore < AUDIT_CAP + 50 && windows < 400) {
    skewMs += RATE_LIMIT_WINDOW_MS;
    windows++;
    for (let i = 0; i < AUTH_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      const r = await w.anonRecovery("192.0.2.10", "owner@acme.example");
      await r.arrayBuffer();
      tally(b3, r.status);
      attempts++;
    }
    const firstKey = w.ctx.sched.storage.rawKeys(AUDIT_PREFIX)[0];
    const earliest = firstKey ? w.ctx.sched.storage.rawGet<AuditEvent>(firstKey)!.seq : 0;
    if (firstOwnerEvictedAt === null && earliest > ownerSeqs[0]!) firstOwnerEvictedAt = { attempts, windows };
    if (allOwnerEvictedAt === null && earliest > ownerSeqs.at(-1)!) allOwnerEvictedAt = { attempts, windows };
  }
  const ms = Math.round(performance.now() - t0);
  const written = head() - headBefore;
  const after = w.rows();
  const retainedOwner = after.filter((e) => e.actorEmail === OWNER).map((e) => e.seq);
  const lostOwner = ownerSeqs.filter((s) => !retainedOwner.includes(s));
  out(`  B3 one IP, ${windows} simulated windows (${windows} min), ${attempts} attempts: statuses ${JSON.stringify(b3)}; ${ms} ms`);
  out(`  B3 rows written since seed ${written}; retained ${after.length}; Owner rows retained ${retainedOwner.length} of ${ownerSeqs.length}`);
  out(`  B3 first Owner row evicted after ${JSON.stringify(firstOwnerEvictedAt)}; last Owner row evicted after ${JSON.stringify(allOwnerEvictedAt)}`);
  out(`  B3 rollover record ${JSON.stringify(w.ctx.sched.storage.rawGet("auditRollover"))}`);

  // B4 and B5: more sources than AUDIT_CAP / AUTH_RATE_LIMIT_MAX_PER_WINDOW, each at its full admitted rate, in
  // ONE window. One row per attempt would write more than AUDIT_CAP rows. B5 puts every source in one IPv6 /64.
  const SOURCES = Math.ceil(AUDIT_CAP / AUTH_RATE_LIMIT_MAX_PER_WINDOW) + 6;
  const manySources = async (label: string, ipOf: (n: number) => string): Promise<AuditEvent[]> => {
    skewMs += RATE_LIMIT_WINDOW_MS + 1_000;
    const h = head();
    const st: Record<number, number> = {};
    for (let n = 0; n < SOURCES; n++) {
      for (let i = 0; i < AUTH_RATE_LIMIT_MAX_PER_WINDOW; i++) {
        const r = await w.anonRecovery(ipOf(n), `spray${i}@evil.example`);
        await r.arrayBuffer();
        tally(st, r.status);
      }
    }
    const rowsNow = w.rows();
    const ownerNow = rowsNow.filter((e) => e.actorEmail === OWNER).map((e) => e.seq);
    out(`  ${label} ${SOURCES} sources x ${AUTH_RATE_LIMIT_MAX_PER_WINDOW} attempts in one window: statuses ${JSON.stringify(st)}; rows written ${head() - h}; Owner rows retained ${ownerNow.length} of ${ownerSeqs.length}`);
    ok(`${label}: ${SOURCES * AUTH_RATE_LIMIT_MAX_PER_WINDOW} attempts write at most ${RECOVERY_WINDOW_ROWS} rows in the window (${head() - h})`, head() - h <= RECOVERY_WINDOW_ROWS);
    ok(`${label}: the flood does not move the oldest Owner row`, ownerSeqs.every((q) => ownerNow.includes(q)));
    return rowsNow.filter((e) => e.seq > h);
  };
  await manySources("B4 IPv4", (n) => `203.0.${n >> 8}.${n & 255}`);
  await manySources("B5 one IPv6 /64", (n) => `2001:db8:5:6::${n.toString(16)}`);
  skewMs = 0;
  ok(
    `CHECK B safe: every pre-flood Owner row retained (${retainedOwner.length}/${ownerSeqs.length}) OR recovery flood rows <= ${FLOOD_ROW_BOUND} (${written})`,
    lostOwner.length === 0 || written <= FLOOD_ROW_BOUND,
  );
  globalThis.fetch = w.realFetch;
}

// ---------------------------------------------------------------------------------------------------------
if (which === "C") {
  out("CHECK C: recovery fold arithmetic, one source");
  skewMs = 0;
  const w = await buildWorld();
  const h0 = w.rows().at(-1)!.seq;
  const IP = "198.51.100.50";
  const first = await w.anonRecovery(IP, "c0@acme.example");
  await first.arrayBuffer();
  const one = w.rows().filter((e) => e.seq > h0);
  ok("C: one normal failed recovery attempt writes one row with attempts 1", one.length === 1 && one[0]!.outcome === "failed" && recoveryAttempts(one[0]!) === 1);
  // Seven more from the same source in the same window: the per-IP limiter admits five a minute, so four more
  // fail on the code and three are throttled. Distinct emails keep the per-email bucket out of it.
  for (let i = 1; i <= 7; i++) {
    const r = await w.anonRecovery(IP, `c${i}@acme.example`);
    await r.arrayBuffer();
  }
  const burst = w.rows().filter((e) => e.seq > h0);
  out(`  C burst of 8 attempts: rows ${burst.length} ${JSON.stringify(burst.map((e) => [e.outcome, recoveryAttempts(e)]))}`);
  ok("C: the burst writes one row per outcome, not one per attempt", burst.length === 2 && burst.filter((e) => e.outcome === "failed").length === 1 && burst.filter((e) => e.outcome === "denied").length === 1);
  // Two windows on, the next attempt from anywhere writes the pending counts.
  skewMs += 3 * RATE_LIMIT_WINDOW_MS;
  const probe = await w.anonRecovery("198.51.100.51", "probe@acme.example");
  await probe.arrayBuffer();
  const all = w.rows().filter((e) => e.seq > h0 && isRecoveryFailure(e));
  const sum = all.reduce((n, e) => n + recoveryAttempts(e), 0);
  const fromIp = (o: string): number => all.filter((e) => e.sourceIp === IP && e.outcome === o).reduce((n, e) => n + recoveryAttempts(e), 0);
  out(`  C after the sweep: rows ${all.length}, attempts ${sum} (failed from the source ${fromIp("failed")}, denied ${fromIp("denied")})`);
  ok("C: the folded rows' attempts sum to the 9 attempts made", sum === 9);
  ok("C: and the source's own rows hold its 5 failed and 3 throttled attempts", fromIp("failed") === 5 && fromIp("denied") === 3);
  // One IPv6 /64 is one source: 40 addresses in it, one attempt each, in a quiet window, write one row per
  // outcome. The recovery IP bucket also keys the /64, so after RECOVERY_RATE_MAX_PER_IP failed attempts the
  // rest are throttled: one failed row and one denied row, both from that /64.
  skewMs += 3 * RATE_LIMIT_WINDOW_MS;
  const h6 = w.rows().at(-1)!.seq;
  for (let n = 0; n < 40; n++) {
    const r = await w.anonRecovery(`2001:db8:7:8:${(n + 1).toString(16)}::1`, `v6-${n}@acme.example`);
    await r.arrayBuffer();
  }
  const v6 = w.rows().filter((e) => e.seq > h6);
  out(`  C one /64, 40 addresses: rows ${JSON.stringify(v6.map((e) => [e.outcome, e.sourceIp, recoveryAttempts(e)]))}`);
  ok(
    "C: 40 addresses in one IPv6 /64 write one failed row and one denied row (the IP bucket throttles the /64), each from an address in that /64",
    v6.length === 2 &&
      v6.filter((e) => e.outcome === "failed").length === 1 &&
      v6.filter((e) => e.outcome === "denied").length === 1 &&
      v6.every((e) => (e.sourceIp ?? "").startsWith("2001:db8:7:8:")),
  );
  skewMs = 0;
  globalThis.fetch = w.realFetch;
}

// ---------------------------------------------------------------------------------------------------------
if (which === "D") {
  out("CHECK D: denied fold arithmetic, one Viewer");
  skewMs = 0;
  const w = await buildWorld();
  const h0 = w.rows().at(-1)!.seq;
  const first = await w.asUser(VIEWER, "/admin/downpipes/delete", { id: "d-0" });
  await first.arrayBuffer();
  const one = w.rows().filter((e) => e.seq > h0);
  out(`  D one refused request: status ${first.status}; rows ${JSON.stringify(one.map((e) => ({ action: e.action, outcome: e.outcome, actor: e.actorEmail, target: e.target })))}`);
  ok(
    "D: one refused request writes one denied row, attributed to the Viewer, with deniedAttempts 1",
    first.status === 403 && one.length === 1 && one[0]!.outcome === "denied" && one[0]!.actorEmail === VIEWER && deniedAttempts(one[0]!) === 1,
  );
  // Nine more refusals in the same window, on two routes: no row of their own.
  const nine: Record<number, number> = {};
  for (let i = 1; i <= 9; i++) {
    const r = await w.asUser(VIEWER, i % 2 === 0 ? "/admin/downpipes/delete" : "/admin/downpipes", { id: `d-${i}`, name: `d-${i}` });
    tally(nine, r.status);
    await r.arrayBuffer();
  }
  out(`  D nine more refusals: statuses ${JSON.stringify(nine)}`);
  ok("D: the nine are all refused", nine[403] === 9);
  const burst = w.rows().filter((e) => e.seq > h0);
  ok("D: nine more refusals in the window write no row of their own", burst.length === 1);
  // Two windows on, the next router audit write of any kind (an Owner's downpipe delete here, which the router
  // records) writes the pending count.
  skewMs += 3 * RATE_LIMIT_WINDOW_MS;
  const g = await w.asUser(OWNER, "/admin/downpipes/delete", { id: "owner-later" });
  await g.arrayBuffer();
  const viewerRows = w.rows().filter((e) => e.seq > h0 && e.actorEmail === VIEWER && e.outcome === "denied");
  const sum = viewerRows.reduce((n, e) => n + deniedAttempts(e), 0);
  out(`  D after the sweep: Viewer denied rows ${viewerRows.length} ${JSON.stringify(viewerRows.map((e) => [e.action, deniedAttempts(e)]))}; Owner delete status ${g.status}`);
  ok("D: the Viewer's denied rows' deniedAttempts sum to the 10 refused requests", sum === 10 && viewerRows.length === 2);
  skewMs = 0;
  globalThis.fetch = w.realFetch;
}

// ---------------------------------------------------------------------------------------------------------
if (which === "E") {
  out("CHECK E: failed passkey sign-in, many IPs");
  const w = await buildWorld();
  const ownerSeqs = w.ownerRows.map((e) => e.seq);
  const h0 = w.rows().at(-1)!.seq;
  const first = await w.anonPasskey("192.0.2.60");
  await first.arrayBuffer();
  const one = w.rows().filter((e) => e.seq > h0);
  out(`  E0 one failed sign-in: status ${first.status}; rows ${JSON.stringify(one.map((e) => [e.action, e.outcome, passkeyAttempts(e)]))}`);
  ok("E: one failed passkey sign-in writes one authn-failure row with attempts 1", one.length === 1 && isPasskeyRow(one[0]!) && passkeyAttempts(one[0]!) === 1);
  // 334 IPs, each at the per-IP sign-in limit, in ONE window: the clock is pinned for the flood.
  __advanceAuditFoldClockForTest(3 * RATE_LIMIT_WINDOW_MS);
  frozenAt = realDateNow() + RATE_LIMIT_WINDOW_MS;
  const SOURCES = Math.ceil(AUDIT_CAP / AUTH_RATE_LIMIT_MAX_PER_WINDOW);
  const h1 = w.rows().at(-1)!.seq;
  const st: Record<number, number> = {};
  let made = 1;
  for (let n = 0; n < SOURCES; n++) {
    for (let i = 0; i < AUTH_RATE_LIMIT_MAX_PER_WINDOW; i++) {
      const r = await w.anonPasskey(`198.18.${n >> 8}.${n & 255}`);
      await r.arrayBuffer();
      tally(st, r.status);
      made++;
    }
  }
  frozenAt = null;
  const flood = w.rows().filter((e) => e.seq > h1);
  const ownerNow = w.rows().filter((e) => e.actorEmail === OWNER).map((e) => e.seq);
  out(`  E1 ${SOURCES} IPs x ${AUTH_RATE_LIMIT_MAX_PER_WINDOW} failed sign-ins in one window: statuses ${JSON.stringify(st)}; rows written ${flood.length}; Owner rows retained ${ownerNow.length} of ${ownerSeqs.length}`);
  ok(`E: ${SOURCES * AUTH_RATE_LIMIT_MAX_PER_WINDOW} failed sign-ins write at most ${AUTHN_WINDOW_ROWS} rows in the window (${flood.length})`, flood.length <= AUTHN_WINDOW_ROWS);
  ok("E: the flood does not move the oldest Owner row", ownerSeqs.every((q) => ownerNow.includes(q)));
  // Two windows on, one more failure carries what the flood left pending.
  __advanceAuditFoldClockForTest(3 * RATE_LIMIT_WINDOW_MS);
  const tail = await w.anonPasskey("192.0.2.61");
  await tail.arrayBuffer();
  made++;
  const sum = w.rows().filter((e) => e.seq > h0).reduce((n, e) => n + passkeyAttempts(e), 0);
  out(`  E2 after the tail: passkey-login attempts on the chain ${sum}, attempts made ${made}`);
  ok(`E: the authn-failure rows' attempts sum to the ${made} failed sign-ins`, sum === made);
  globalThis.fetch = w.realFetch;
}

// ---------------------------------------------------------------------------------------------------------
if (which === "F") {
  out("CHECK F: two simulated days of refused attempts from all three writers");
  const w = await buildWorld();
  const ownerSeqs = w.ownerRows.map((e) => e.seq);
  // F0: one failure of each kind, alone in a quiet window.
  __advanceAuditFoldClockForTest(3 * RATE_LIMIT_WINDOW_MS);
  const h0 = w.rows().at(-1)!.seq;
  const r0 = await w.anonRecovery("192.0.2.70", "f0@acme.example");
  await r0.arrayBuffer();
  const p0 = await w.anonPasskey("192.0.2.71");
  await p0.arrayBuffer();
  const d0 = await w.asUser(VIEWER, "/admin/downpipes/delete", { id: "f0" });
  await d0.arrayBuffer();
  const f0 = w.rows().filter((e) => e.seq > h0);
  out(`  F0 one of each: statuses ${r0.status},${p0.status},${d0.status}; rows ${JSON.stringify(f0.map((e) => [e.action, e.outcome, recoveryAttempts(e) || passkeyAttempts(e) || deniedAttempts(e)]))}`);
  ok("F: one failed recovery sign-in alone writes its own row with attempts 1", f0.filter((e) => isRecoveryFailure(e)).length === 1 && f0.some((e) => isRecoveryFailure(e) && recoveryAttempts(e) === 1));
  ok("F: one failed passkey sign-in alone writes its own row with attempts 1", f0.filter(isPasskeyRow).length === 1 && f0.some((e) => passkeyAttempts(e) === 1));
  ok("F: one refused request alone writes its own denied row with deniedAttempts 1", f0.filter((e) => e.outcome === "denied").length === 1 && f0.some((e) => e.actorEmail === VIEWER && deniedAttempts(e) === 1));
  // F1: every simulated minute for two days, three recovery attempts from new IPs, one failed passkey sign-in
  // and three refused requests from three Viewer accounts. Only the fold's clock moves, so the sessions and
  // the per-IP limiters see real time, and each attempt comes from a fresh source.
  const MINUTES = 2 * 24 * 60;
  const viewers = ["fill-viewer-0@evil.example", "fill-viewer-1@evil.example", "fill-viewer-2@evil.example"];
  const made = { recovery: 1, passkey: 1, denied: 1 };
  const hFill = w.rows().at(-1)!.seq;
  const st: Record<number, number> = {};
  for (let m = 0; m < MINUTES; m++) {
    __advanceAuditFoldClockForTest(RATE_LIMIT_WINDOW_MS);
    for (let k = 0; k < 3; k++) {
      const n = m * 3 + k;
      const r = await w.anonRecovery(`10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`, `fill-${n}@acme.example`);
      await r.arrayBuffer();
      tally(st, r.status);
      made.recovery++;
    }
    const p = await w.anonPasskey(`10.200.${(m >> 8) & 255}.${m & 255}`);
    await p.arrayBuffer();
    tally(st, p.status);
    made.passkey++;
    for (const v of viewers) {
      const d = await w.asUser(v, "/admin/downpipes/delete", { id: `fill-${m}` });
      await d.arrayBuffer();
      tally(st, d.status);
      made.denied++;
    }
  }
  const afterFill = w.rows();
  const writtenFill = afterFill.at(-1)!.seq - hFill;
  const ownerFill = afterFill.filter((e) => e.actorEmail === OWNER).map((e) => e.seq);
  out(`  F1 ${MINUTES} simulated minutes: statuses ${JSON.stringify(st)}; rows written ${writtenFill}; retained ${afterFill.length}; Owner rows retained ${ownerFill.length} of ${ownerSeqs.length}`);
  ok(`F: two days of refused attempts write at most ${HOURLY_ROWS} rows an hour (${writtenFill} in 48 hours)`, writtenFill <= 48 * HOURLY_ROWS + 3);
  ok("F: the two-day fill does not move the oldest Owner row", ownerSeqs.every((q) => ownerFill.includes(q)));
  // F2: the counts. Each round moves the fold clock past an hour and sends one more attempt of each kind, which
  // lets the waiting and overflow counts reach the chain. The rows must then sum to every attempt made.
  let sums = { recovery: 0, passkey: 0, denied: 0 };
  let rounds = 0;
  for (; rounds < 12; rounds++) {
    __advanceAuditFoldClockForTest(61 * RATE_LIMIT_WINDOW_MS);
    const r = await w.anonRecovery(`10.250.0.${rounds}`, `probe-${rounds}@acme.example`);
    await r.arrayBuffer();
    const p = await w.anonPasskey(`10.251.0.${rounds}`);
    await p.arrayBuffer();
    const d = await w.asUser(viewers[0]!, "/admin/downpipes/delete", { id: `probe-${rounds}` });
    await d.arrayBuffer();
    made.recovery++;
    made.passkey++;
    made.denied++;
    const since = w.rows().filter((e) => e.seq > h0);
    sums = {
      recovery: since.reduce((n, e) => n + (isRecoveryFailure(e) ? recoveryAttempts(e) : 0), 0),
      passkey: since.reduce((n, e) => n + passkeyAttempts(e), 0),
      denied: since.reduce((n, e) => n + (e.outcome === "denied" ? deniedAttempts(e) : 0), 0),
    };
    if (sums.recovery === made.recovery && sums.passkey === made.passkey && sums.denied === made.denied) break;
  }
  out(`  F2 after ${rounds + 1} catch-up round(s): counted ${JSON.stringify(sums)}, made ${JSON.stringify(made)}`);
  ok("F: the recovery rows' attempts sum to the recovery attempts made", sums.recovery === made.recovery);
  ok("F: the passkey rows' attempts sum to the failed sign-ins made", sums.passkey === made.passkey);
  ok("F: the denied rows' deniedAttempts sum to the refused requests made", sums.denied === made.denied);
  globalThis.fetch = w.realFetch;
}

// ---------------------------------------------------------------------------------------------------------
if (which === "G") {
  out("CHECK G: the denied fold's own ceiling, its overflow row, and stored counts");
  const w = await buildWorld();
  let ipn = 0;
  const freshIp = (): string => {
    ipn++;
    return `10.${(ipn >> 16) & 255}.${(ipn >> 8) & 255}.${ipn & 255}`;
  };
  const recovery = async (): Promise<void> => {
    const r = await w.anonRecovery(freshIp(), `g-${ipn}@acme.example`);
    await r.arrayBuffer();
  };
  const passkey = async (): Promise<void> => {
    const r = await w.anonPasskey(freshIp());
    await r.arrayBuffer();
  };
  const refuse = async (email: string, id: string): Promise<number> => {
    const r = await w.asUser(email, "/admin/downpipes/delete", { id });
    await r.arrayBuffer();
    return r.status;
  };
  const isDeniedOverflow = (e: AuditEvent): boolean => (e.action as string) === "denied-overflow";
  const nextHour = (): void => __advanceAuditFoldClockForTest(61 * RATE_LIMIT_WINDOW_MS);

  // G1: a fresh hour. Twelve minutes of failed recovery and passkey sign-ins from fresh IPs: four sign-in rows a
  // minute or more, so the flood reaches any hourly ceiling up to 48 rows. Then a Viewer is refused once.
  nextHour();
  const h1 = w.rows().at(-1)!.seq;
  for (let m = 0; m < 12; m++) {
    __advanceAuditFoldClockForTest(RATE_LIMIT_WINDOW_MS);
    for (let k = 0; k < 4; k++) await recovery();
    await passkey();
  }
  __advanceAuditFoldClockForTest(RATE_LIMIT_WINDOW_MS);
  const hProbe = w.rows().at(-1)!.seq;
  const probeIp = "192.0.2.200";
  const probe = await w.anonRecovery(probeIp, "g-probe@acme.example");
  await probe.arrayBuffer();
  const signInRows = w.rows().filter((e) => e.seq > h1 && e.seq <= hProbe).length;
  const probeOwn = w.rows().filter((e) => e.seq > hProbe && e.sourceIp === probeIp).length;
  out(`  G1 sign-in flood: rows written ${signInRows}; a further failed recovery sign-in from a new IP wrote ${probeOwn} row(s) of its own`);
  ok("G1: the sign-in flood reached its hourly ceiling (a new source's failure gets no row of its own)", probeOwn === 0);
  const hDenied = w.rows().at(-1)!.seq;
  const g1Status = await refuse(VIEWER, "g1");
  const g1 = w.rows().filter((e) => e.seq > hDenied && e.outcome === "denied" && e.actorEmail === VIEWER);
  out(`  G1 one refusal after the flood: status ${g1Status}; Viewer denied rows ${JSON.stringify(g1.map((e) => [e.action, deniedAttempts(e)]))}`);
  ok("G1: the refusal still writes its own denied row in the same hour, with deniedAttempts 1", g1Status === 403 && g1.length === 1 && deniedAttempts(g1[0]!) === 1);

  // G2: a fresh hour. Twelve minutes, five Viewer accounts refused twice a minute each: 120 refusals.
  nextHour();
  const accounts = ["g2-viewer-0@evil.example", "g2-viewer-1@evil.example", "g2-viewer-2@evil.example", "g2-viewer-3@evil.example", "g2-viewer-4@evil.example"];
  const h2 = w.rows().at(-1)!.seq;
  let refusals = 0;
  for (let m = 0; m < 12; m++) {
    __advanceAuditFoldClockForTest(RATE_LIMIT_WINDOW_MS);
    for (const a of accounts) {
      for (let k = 0; k < 2; k++) {
        await refuse(a, `g2-${m}-${k}`);
        refusals++;
      }
    }
  }
  // The router's denied rows only: the first router write of the hour also writes what G1 left pending on the
  // sign-in folds.
  const isRouterDenied = (e: AuditEvent): boolean => e.outcome === "denied" && !isRecoveryFailure(e);
  const hourRows = w.rows().filter((e) => e.seq > h2 && isRouterDenied(e));
  const overflowRows = hourRows.filter(isDeniedOverflow);
  out(`  G2 ${refusals} refusals in one hour: denied rows ${hourRows.length}, of them denied-overflow ${JSON.stringify(overflowRows.map((e) => ({ actor: e.actorEmail, method: e.actorMethod, outcome: e.outcome, target: e.target })))}`);
  ok(`G2: the hour's refusals write at most ${DENIED_HOURLY_ROWS} rows (${hourRows.length})`, hourRows.length <= DENIED_HOURLY_ROWS);
  ok(
    "G2: refusals past the denied ceiling are written on a denied-overflow row, with no actor, outcome denied and a count",
    overflowRows.length === 1 && overflowRows[0]!.actorEmail === null && overflowRows[0]!.actorMethod === "engine" && overflowRows[0]!.outcome === "denied" && deniedAttempts(overflowRows[0]!) >= 1,
  );
  let made = refusals;
  let counted = 0;
  for (let round = 0; round < 6 && counted !== made; round++) {
    nextHour();
    await refuse(accounts[0]!, `g2-probe-${round}`);
    made++;
    counted = w.rows().filter((e) => e.seq > h2 && isRouterDenied(e)).reduce((n, e) => n + deniedAttempts(e), 0);
  }
  out(`  G2 after the catch-up: deniedAttempts on the chain ${counted}, refusals made ${made}`);
  ok("G2: the denied and denied-overflow rows' counts sum to the refusals made", counted === made);

  // G3: a fresh hour. Pending counts on all three folds, then a restart before any of them is written.
  nextHour();
  const h3 = w.rows().at(-1)!.seq;
  const g3ip = "192.0.2.230";
  const sends = { recovery: 0, passkey: 0, denied: 0 };
  for (let i = 0; i < 4; i++) {
    const r = await w.anonRecovery(g3ip, `g3-${i}@acme.example`);
    await r.arrayBuffer();
    sends.recovery++;
    await passkey();
    sends.passkey++;
    await refuse(VIEWER, `g3-${i}`);
    sends.denied++;
  }
  const sumsSince = (h: number) => {
    const since = w.rows().filter((e) => e.seq > h);
    return {
      recovery: since.reduce((n, e) => n + (isRecoveryFailure(e) ? recoveryAttempts(e) : 0), 0),
      passkey: since.reduce((n, e) => n + passkeyAttempts(e), 0),
      denied: since.reduce((n, e) => n + (e.outcome === "denied" ? deniedAttempts(e) : 0), 0),
    };
  };
  out(`  G3 before the restart: counted ${JSON.stringify(sumsSince(h3))}, made ${JSON.stringify(sends)}`);
  w.ctx.sched.restart();
  let g3 = sumsSince(h3);
  for (let round = 0; round < 4; round++) {
    __advanceAuditFoldClockForTest(3 * RATE_LIMIT_WINDOW_MS);
    await recovery();
    sends.recovery++;
    await passkey();
    sends.passkey++;
    await refuse(VIEWER, `g3-after-${round}`);
    sends.denied++;
    g3 = sumsSince(h3);
    if (g3.recovery === sends.recovery && g3.passkey === sends.passkey && g3.denied === sends.denied) break;
  }
  out(`  G3 after the restart: counted ${JSON.stringify(g3)}, made ${JSON.stringify(sends)}`);
  ok("G3: after a restart in the hour the recovery rows sum to the attempts made", g3.recovery === sends.recovery);
  ok("G3: after a restart in the hour the passkey rows sum to the failed sign-ins made", g3.passkey === sends.passkey);
  ok("G3: after a restart in the hour the denied rows sum to the refusals made", g3.denied === sends.denied);

  // G4: a fresh hour. Pending counts, a restart, and then no further attempt: the alarm writes them.
  nextHour();
  const h4 = w.rows().at(-1)!.seq;
  const g4ip = "192.0.2.240";
  const g4 = { recovery: 0, passkey: 0, denied: 0 };
  for (let i = 0; i < 3; i++) {
    const r = await w.anonRecovery(g4ip, `g4-${i}@acme.example`);
    await r.arrayBuffer();
    g4.recovery++;
    await passkey();
    g4.passkey++;
    await refuse(VIEWER, `g4-${i}`);
    g4.denied++;
  }
  w.ctx.sched.restart();
  __advanceAuditFoldClockForTest(3 * RATE_LIMIT_WINDOW_MS);
  await w.ctx.sched.current().alarm();
  const g4sums = sumsSince(h4);
  out(`  G4 after a restart and one alarm: counted ${JSON.stringify(g4sums)}, made ${JSON.stringify(g4)}`);
  ok("G4: the alarm writes every pending count left before the restart", g4sums.recovery === g4.recovery && g4sums.passkey === g4.passkey && g4sums.denied === g4.denied);
  globalThis.fetch = w.realFetch;
}

Date.now = realDateNow;
console.log = realConsoleLog;
out(failures === 0 ? "validate-audit-flood-eviction: PASS" : `validate-audit-flood-eviction: FAIL (${failures})`);
verdictReached(failures);
process.exitCode = failures === 0 ? 0 : 1;
