// validate-signin-baseline-lapse.ts
//
// SEEN_CONTEXT_TTL_MS (90 days) bounds the R6 unusual-location baseline (ASVS V6.3.5, opt-in): the small
// per-operator set of COARSE network prefixes a sign-in is compared against. A row prunes at exactly the
// TTL. When the TTL prunes the LAST row, the sign-in is classified as a BASELINE LAPSE, distinct from a
// first-ever sign-in: the next sign-in from ANY network must still alert, and must not silently become the
// new baseline.
//
// `signin-context-baseline-lapsed` joins the auth-signal vocabulary's closed set alongside the sibling
// abstention `signin-context-skipped` (no readable source IP) in the same method, and it explains an ALERT
// rather than an absence: "why did a new-location warning fire from my own office?" -- because the operator
// had not signed in for ninety days.
//
// THE CONTROLS, and what each is for:
//   - THE INJECTION IS PROVEN BEFORE ANY ZERO IT REPORTS IS TRUSTED. The dose is elapsed time, injected at
//     the boundary the product actually reads (SeenContext.lastAt against now). A known positive comes
//     first: just under the TTL a seeded row must SURVIVE and just over it must be PRUNED. If the injection
//     did nothing, both would read the same and every later measurement would be worthless.
//   - DOSE-RESPONSE over nine doses spanning the edge, over DISTINCT operators, not a point test.
//   - THE EDGE IS EXACTLY THE TTL: at TTL-1ms nothing has lapsed, at TTL exactly the lapse is declared.
//   - POSITION CONTROL: what IS recorded is unmoved by the dose (the current prefix at now, the cap, the
//     absence of any raw IP).
//   - INTERNAL DIFFERENTIAL: one other live row versus none, same TTL, same prefix.
//   - EXTERNAL DIFFERENTIAL: the sibling abstention in the same method is declared, and was.
//   - INSTRUMENT CONTROL: that declared sibling books on THIS rig in THIS session, so a zero for the new
//     signal would be a result rather than a dead probe.
//   - THE INVERSION SENTINEL, which must be REACHED rather than absent: the attacker sign-in after a
//     dormancy MUST alert. An assertion that merely counts absences would hold over a blank page.
//   - NEGATIVE CONTROLS THAT MUST CLASSIFY DIFFERENTLY: a genuinely first-ever sign-in, a stored set of
//     only MALFORMED rows, and a returning live prefix must none of them read as a lapse.
//   - REDACTION: the aggregate must carry the closed name and an int, never a prefix, IP, email or subject.
//   - THROTTLE HONESTY (G270): two lapses inside one throttle window must count TWO, not one window.
//
// No network, no deploy, no estate. Run:
//   node test/validate-signin-baseline-lapse.ts
import { evaluateSignInContext, SEEN_CONTEXT_CAP, SEEN_CONTEXT_TTL_MS, type SeenContext } from "../src/admin/sign-in-context.ts";
import { AUTH_SIGNAL_NAMES, AUTH_SIGNALS_KEY } from "../src/admin/auth-signals.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";
import { readFileSync } from "node:fs";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const HOUR = 3_600_000;
const DAY = 86_400_000;
const NOW = 1_800_000_000_000;
const TOKEN = "signin-baseline-lapse-admin-token";

function makeStack(): { storage: MockStorage; stub: DurableObjectStub; env: Env } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { storage, stub, env: { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN } as unknown as Env };
}

async function optIn(env: Env): Promise<number> {
  const r = await handleAdmin(
    new Request("https://engine.example/admin/config/signin-context-policy", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ notifyNewSignInContext: true }),
    }),
    env,
  );
  return r.status;
}

async function signIn(stub: DurableObjectStub, email: string, sourceIp: string | null): Promise<boolean> {
  const r = await stub.fetch("https://do/signin-context", {
    method: "POST",
    body: JSON.stringify({ email, sourceIp }),
    headers: { "content-type": "application/json" },
  });
  return ((await r.json()) as { newContext?: boolean }).newContext === true;
}

type SignalRow = { count?: number };
async function readSignals(storage: MockStorage): Promise<Record<string, SignalRow>> {
  return ((await storage.get(AUTH_SIGNALS_KEY)) ?? {}) as Record<string, SignalRow>;
}

// ageStoredBaseline rewinds every stored context row by `by` ms, which is precisely what a dormancy of that
// length leaves behind. It returns how many rows it moved so a silent no-op cannot pass as a dose.
async function ageStoredBaseline(storage: MockStorage, by: number): Promise<number> {
  let moved = 0;
  for (const [k, v] of (await storage.list({ prefix: "signinctx:" })).entries()) {
    const rows = (v as SeenContext[]).map((c) => ({ prefix: c.prefix, lastAt: c.lastAt - by }));
    await storage.put(k, rows);
    moved += rows.length;
  }
  return moved;
}

async function main(): Promise<void> {
  // ---- 0. THE INJECTION'S KNOWN POSITIVE, before anything reads a zero ------------------------------
  {
    const under = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: NOW - (SEEN_CONTEXT_TTL_MS - HOUR) }], "198.51.100.0/24", NOW);
    const over = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: NOW - (SEEN_CONTEXT_TTL_MS + HOUR) }], "198.51.100.0/24", NOW);
    ok("INSTRUMENT: an hour under the TTL the seeded row SURVIVES the prune", under.updated.length === 2);
    ok("INSTRUMENT: an hour over the TTL the seeded row is PRUNED (so the dose reaches the code)", over.updated.length === 1);
  }

  // ---- 1. DOSE-RESPONSE over elapsed time, spanning the edge ---------------------------------------
  {
    const doses: Array<[string, number, boolean]> = [
      ["0", 0, false],
      ["1 day", DAY, false],
      ["30 days", 30 * DAY, false],
      ["89 days", 89 * DAY, false],
      ["TTL-1ms", SEEN_CONTEXT_TTL_MS - 1, false],
      ["TTL exactly", SEEN_CONTEXT_TTL_MS, true],
      ["TTL+1ms", SEEN_CONTEXT_TTL_MS + 1, true],
      ["180 days", 180 * DAY, true],
      ["365 days", 365 * DAY, true],
    ];
    for (const [label, dose, expectLapsed] of doses) {
      // A DISTINCT operator per dose: one prefix apiece, so no dose can borrow another's baseline.
      const seeded: SeenContext[] = [{ prefix: "203.0.113.0/24", lastAt: NOW - dose }];
      const v = evaluateSignInContext(seeded, "198.51.100.0/24", NOW);
      ok(`dose ${label}: baselineLapsed is ${String(expectLapsed)}`, v.baselineLapsed === expectLapsed);
      // An unrecognised prefix alerts at every dose.
      ok(`dose ${label}: an unrecognised prefix ALERTS`, v.isNew === true);
    }
  }

  // ---- 2. THE EXACT EDGE, and the same-prefix direction ---------------------------------------------
  {
    const justUnder = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: NOW - (SEEN_CONTEXT_TTL_MS - 1) }], "203.0.113.0/24", NOW);
    const atEdge = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: NOW - SEEN_CONTEXT_TTL_MS }], "203.0.113.0/24", NOW);
    ok("EDGE: at TTL-1ms the operator's OWN prefix is still live and does not alert", justUnder.isNew === false && justUnder.baselineLapsed === false);
    ok("EDGE: at the TTL exactly the same prefix reads as new again, uniformly with the module's own rule", atEdge.isNew === true && atEdge.baselineLapsed === true);
  }

  // ---- 3. POSITION CONTROL: what is RECORDED is unmoved by the dose ---------------------------------
  {
    for (const dose of [0, 30 * DAY, SEEN_CONTEXT_TTL_MS + DAY, 365 * DAY]) {
      const v = evaluateSignInContext([{ prefix: "203.0.113.0/24", lastAt: NOW - dose }], "198.51.100.0/24", NOW);
      const cur = v.updated.find((c) => c.prefix === "198.51.100.0/24");
      ok(`POSITION: dose ${dose}ms still records the current prefix at now, within the cap`, cur?.lastAt === NOW && v.updated.length <= SEEN_CONTEXT_CAP);
    }
  }

  // ---- 4. INTERNAL DIFFERENTIAL: the same TTL, the same prefix, one other live row versus none ------
  {
    const expired = { prefix: "203.0.113.0/24", lastAt: NOW - (SEEN_CONTEXT_TTL_MS + HOUR) };
    const withOtherLive = evaluateSignInContext([expired, { prefix: "192.0.2.0/24", lastAt: NOW - DAY }], "198.51.100.0/24", NOW);
    const withNoneLive = evaluateSignInContext([expired], "198.51.100.0/24", NOW);
    ok("DIFFERENTIAL: an unrecognised prefix alerts while one other row is live", withOtherLive.isNew === true);
    ok("DIFFERENTIAL: and alerts identically when the last row has gone (the two no longer disagree)", withNoneLive.isNew === true);
    ok("DIFFERENTIAL: only the second is a LAPSE, so the two states stay distinguishable", withOtherLive.baselineLapsed === false && withNoneLive.baselineLapsed === true);
  }

  // ---- 5. NEGATIVE CONTROLS that must classify DIFFERENTLY -------------------------------------------
  {
    const firstEver = evaluateSignInContext([], "198.51.100.0/24", NOW);
    ok("NEGATIVE: a genuinely first-ever sign-in is not a lapse and does not alert", firstEver.isNew === false && firstEver.baselineLapsed === false);
    // Malformed rows are not evidence that an operator ever had a baseline, so they must not manufacture one.
    const malformed = evaluateSignInContext(
      [{ prefix: "", lastAt: NOW - DAY }, { prefix: "203.0.113.0/24", lastAt: Number.NaN }] as unknown as SeenContext[],
      "198.51.100.0/24",
      NOW,
    );
    ok("NEGATIVE: a stored set of only MALFORMED rows is not a lapse", malformed.isNew === false && malformed.baselineLapsed === false);
    const returning = evaluateSignInContext([{ prefix: "198.51.100.0/24", lastAt: NOW - DAY }], "198.51.100.0/24", NOW);
    ok("NEGATIVE: a returning live prefix is neither new nor a lapse", returning.isNew === false && returning.baselineLapsed === false);
    const nullRow = evaluateSignInContext([null] as unknown as SeenContext[], "198.51.100.0/24", NOW);
    ok("NEGATIVE: a null row is dropped without manufacturing a lapse", nullRow.isNew === false && nullRow.baselineLapsed === false);
  }

  // ---- 6. THE INVERSION SENTINEL, driven through the REAL DO ----------------------------------------
  {
    const { storage, stub, env } = makeStack();
    ok("the owner opt-in applies", (await optIn(env)) === 200);
    const first = await signIn(stub, "op@acme.example", "203.0.113.10");
    ok("SENTINEL: the operator's first sign-in baselines silently", first === false);
    const moved = await ageStoredBaseline(storage, SEEN_CONTEXT_TTL_MS + DAY);
    ok("SENTINEL: the dose reached storage (rows moved, so a silent no-op cannot pass)", moved === 1);
    const attacker = await signIn(stub, "op@acme.example", "198.51.100.77");
    // This is the check that must be reached, on a live-shaped rig.
    ok("SENTINEL: after a dormancy the UNRECOGNISED sign-in ALERTS", attacker === true);
    const sig = await readSignals(storage);
    ok("SENTINEL: the lapse is booked exactly once", sig["signin-context-baseline-lapsed"]?.count === 1);
    const victim = await signIn(stub, "op@acme.example", "203.0.113.10");
    ok("SENTINEL: the operator's own return is still judged against a live set, so it is a second alert not a first", victim === true);
    ok("SENTINEL: the operator's own return is NOT a second lapse", sig["signin-context-baseline-lapsed"]?.count === 1 && (await readSignals(storage))["signin-context-baseline-lapsed"]?.count === 1);
  }

  // ---- 7. INSTRUMENT + EXTERNAL DIFFERENTIAL: the declared sibling books on THIS rig ------------------
  {
    const { storage, stub, env } = makeStack();
    await optIn(env);
    await signIn(stub, "op@acme.example", null);
    const sig = await readSignals(storage);
    ok("INSTRUMENT: the SIBLING abstention in the same method books on this rig, in this session", sig["signin-context-skipped"]?.count === 1);
    ok("INSTRUMENT: and the lapse signal is absent here, so the two are not one counter", sig["signin-context-baseline-lapsed"] === undefined);
    ok("DIFFERENTIAL: both abstentions are members of the one closed vocabulary", AUTH_SIGNAL_NAMES.includes("signin-context-skipped") && AUTH_SIGNAL_NAMES.includes("signin-context-baseline-lapsed"));
  }

  // ---- 8. REDACTION: counts only, never a prefix, an IP, an email or a subject -----------------------
  {
    const { storage, stub, env } = makeStack();
    await optIn(env);
    await signIn(stub, "op@acme.example", "203.0.113.10");
    await ageStoredBaseline(storage, SEEN_CONTEXT_TTL_MS + DAY);
    await signIn(stub, "op@acme.example", "198.51.100.77");
    const dump = JSON.stringify(await readSignals(storage));
    ok("REDACTION: the aggregate carries no coarse prefix and no raw IP", !dump.includes("/24") && !dump.includes("198.51.100.77") && !dump.includes("203.0.113"));
    ok("REDACTION: the aggregate carries no email or subject", !dump.includes("op@acme.example") && !dump.includes("passkey|"));
    ok("REDACTION: it does carry the closed name and an int count", dump.includes("signin-context-baseline-lapsed") && typeof (await readSignals(storage))["signin-context-baseline-lapsed"]?.count === "number");
  }

  // ---- 9. THROTTLE HONESTY: two lapses in one window count TWO -------------------------------------
  {
    const { storage, stub, env } = makeStack();
    await optIn(env);
    // Two DISTINCT operators, each baselined then aged out, both lapsing inside one throttle window.
    await signIn(stub, "a@acme.example", "203.0.113.10");
    await signIn(stub, "b@acme.example", "192.0.2.10");
    const moved = await ageStoredBaseline(storage, SEEN_CONTEXT_TTL_MS + DAY);
    ok("THROTTLE: both operators' baselines were aged", moved === 2);
    await signIn(stub, "a@acme.example", "198.51.100.77");
    await signIn(stub, "b@acme.example", "198.51.100.78");
    // The DO throttles the WRITE and keeps the EVENT; the pack read flushes the deferred tail.
    const flushed = await stub.fetch("https://do/auth-signals", { method: "GET" });
    const agg = (await flushed.json()) as { signals?: Record<string, SignalRow> };
    const row = (agg.signals ?? (agg as unknown as Record<string, SignalRow>))["signin-context-baseline-lapsed"];
    ok("THROTTLE: two lapses inside one window count TWO, not one window", row?.count === 2);
  }

  // ---- 10. STRUCTURAL GUARD: the wiring cannot be silently removed -----------------------------------
  {
    const session = readFileSync(new URL("../src/sched/scheduler-do-session.ts", import.meta.url), "utf8");
    ok("WIRING: recordSignInContext books the lapse signal", session.includes('recordAuthSignalThrottled("signin-context-baseline-lapsed")'));
    ok("WIRING: it books it on the verdict's own flag, not on a re-derivation", session.includes("verdict.baselineLapsed"));
    const mod = readFileSync(new URL("../src/admin/sign-in-context.ts", import.meta.url), "utf8");
    ok("WIRING: the lapse is keyed on rows the TTL pruned, not on an empty live set", mod.includes("prunedByTtl") && mod.includes("live.length === 0 && prunedByTtl > 0"));
  }

  console.log(failures === 0 ? "\nSIGN-IN BASELINE LAPSE (R6 / V6.3.5) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

void main();
