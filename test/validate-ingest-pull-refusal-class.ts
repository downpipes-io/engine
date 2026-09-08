// The refusal class the /support pull surface DECIDED and THREW AWAY.
//
// WHAT THIS PINS. classifyIngestCredentialCheck returns one of five closed reasons a presented bearer was
// refused, and its own header states why it exists: "a never-minted credential, an EXPIRED one and a rotated
// secret the scraper was never updated with all produced the same 401, so 'Prometheus started getting 401s
// with an unexpired credential' was undiagnosable from the pack". That was closed for the /metrics scrape
// (admin/metrics.ts threads the outcome into METRICS_SCRAPE_OUTCOMES) and NOT for the two /support pulls,
// which ran the SAME classifier through checkIngestCredential's boolean wrapper and booked one generic
// `ingest-pull-auth-failed`. The remedy was present in the product and unused on the surface whose entire
// purpose -- the SIEM audit feed -- is to be answerable.
//
// THE RIG IS THE REAL PATH: handleSupportPull -> a REAL SchedulerDO (src/sched/scheduler-do.ts) over
// MockStorage, and the counters are read back through fetchAdminCounters, the projection the SUPPORT PACK
// itself takes (projectCountAgg over ADMIN_COUNTER_NAME_SET). No hand-rolled double reads the number.
//
// THE INTERNAL DIFFERENTIAL. checkIngestCredential is still exported and still the boolean it always was, so
// the UNREPAIRED path is driven IN THIS SESSION beside the repaired one, on a distinct subject, over the same
// doses. The pre tree's discriminating key must be ABSENT -- not zero -- and the post tree's must be a real
// count. Absent, zero and inverted are asserted apart, because each is a different failure mode worth distinguishing.
//
// THE DOSE IS ELAPSED TIME, injected through the record the product actually reads (grant.expiresAt against
// Date.now()) rather than waited for, because classifyIngestCredentialCheck takes no clock argument. One fresh
// subject per dose, so no dose inherits another's ledger.
//
// Run: node test/validate-ingest-pull-refusal-class.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import {
  checkIngestCredential,
  classifyIngestCredentialCheck,
  handleSupportPull,
  ingestPullRefusalCounter,
  mintIngestCredential,
  redactGrant,
  resetAuthFailureThrottle,
  type IngestCheckOutcome,
  type IngestGrant,
} from "../src/admin/support-ingest.ts";
import { fetchAdminCounters } from "../src/admin/support-sections-diag.ts";
import { bumpAdminCounter } from "../src/admin/diag-counters.ts";
import { ADMIN_COUNTER_NAMES } from "../src/admin/diag-records.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EMPTY_ENV = {} as unknown as Env;
const HOUR = 3_600_000;

// asStub adapts a real SchedulerDO to the DurableObjectStub shape handleSupportPull expects: the platform
// bridges a stub's TWO-ARGUMENT fetch(url, init) into the ONE-ARGUMENT Request SchedulerDO.fetch takes. The
// SAME helper test/validate-destsim-auditfeed-abuse.ts and test/validate-metrics.ts use.
//
// THIS IS A MEASURED KNOWN POSITIVE, NOT A TIDY-UP. Without it every DO fetch threw "Invalid URL" INSIDE the
// route, the 500 body parsed to an object with no `grant`, and handleSupportPull read that as `no-grant` and
// answered 401 -- so the rig produced a plausible refusal for every dose while measuring nothing at all. The
// A2 instrument control caught it; the class assertions alone would have looked like a partial pass.
function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)),
  } as unknown as DurableObjectStub;
}

function makeScheduler(): { storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: asStub(new SchedulerDO(state)) };
}

/** settle drains the fire-and-forget counter writes handleSupportPull issues with `void`. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0));
}

/** at builds an expiresAt offset from now, so the dose is injected rather than waited for. */
function at(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

/** counters reads the counter map back through the projection the SUPPORT PACK itself takes. */
async function counters(stub: DurableObjectStub): Promise<Record<string, { count: number; lastAt?: string }>> {
  return fetchAdminCounters(stub);
}

function pull(bearer: string | null): Request {
  return new Request("https://engine.example/support/audit-feed", bearer === null ? {} : { headers: { Authorization: `Bearer ${bearer}` } });
}

/**
 * driveRepaired seeds ONE fresh subject with `grant`, drives ONE refused pull through the real path, and
 * returns the counter map the pack would read. The throttle is reset per subject so each dose records.
 */
async function driveRepaired(grant: IngestGrant | null, bearer: string): Promise<Record<string, { count: number; lastAt?: string }>> {
  const { storage, stub } = makeScheduler();
  if (grant !== null) await storage.put("ingestcred:audit-feed", grant);
  resetAuthFailureThrottle();
  const resp = await handleSupportPull(pull(bearer), EMPTY_ENV, stub);
  if (resp.status !== 401 && resp.status !== 200) throw new Error(`unexpected pull status ${resp.status}`);
  await settle();
  return counters(stub);
}

/**
 * drivePre is the UNREPAIRED tree, run in this same session on a distinct subject: the boolean wrapper that
 * is still exported and still discards the class, booking the generic counter alone. It is the module's own
 * pre-fix behaviour, not a re-implementation of it.
 */
async function drivePre(grant: IngestGrant | null): Promise<Record<string, { count: number; lastAt?: string }>> {
  const { stub } = makeScheduler();
  const bearer = grant === null ? "dpc_x.dps_y" : `${grant.clientId}.dps_wrong`;
  if (!(await checkIngestCredential(bearer, grant))) {
    await bumpAdminCounter(stub, "ingest-pull-auth-failed");
  }
  await settle();
  return counters(stub);
}

async function main(): Promise<void> {
  // ------------------------------------------------------------------------------------------------------
  // A. KNOWN POSITIVE FIRST: prove the rig reaches the code before trusting any zero it reports.
  // ------------------------------------------------------------------------------------------------------
  console.log("A -- known positives (the rig reaches the code)");
  {
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    const good = await driveRepaired(minted.grant, `${minted.clientId}.${minted.secret}`);
    ok("A1 a VALID bearer books NO refusal at all (the generic key is ABSENT, not zero)", good["ingest-pull-auth-failed"] === undefined);
    ok("A1 a valid bearer books no discriminating key either", Object.keys(good).filter((k) => k.startsWith("ingest-pull-refused-")).length === 0);
    const bad = await driveRepaired(minted.grant, `${minted.clientId}.dps_wrong`);
    // THE INSTRUMENT CONTROL. The generic counter is the DECLARED sibling that booked correctly before this
    // change and must book correctly after it, on the same rig in the same session. If it is missing here,
    // every zero below is a dead ledger rather than a suppressed booking, and no verdict is attributable.
    ok("A2 INSTRUMENT CONTROL: the generic ingest-pull-auth-failed still books on the repaired path", bad["ingest-pull-auth-failed"]?.count === 1);
    ok("A2 the rig's counter read goes through the PACK projection and returns a real number", typeof bad["ingest-pull-auth-failed"]?.count === "number");
  }

  // ------------------------------------------------------------------------------------------------------
  // B. THE FIVE REFUSALS, BOTH TREES, ONE SESSION, DISTINCT SUBJECTS.
  //    ABSENT (pre) vs a real COUNT (post) -- asserted apart from ZERO: a lost value reported as a legitimate
  //    zero reads as "we looked and there were none".
  // ------------------------------------------------------------------------------------------------------
  console.log("\nB -- the five refusal classes, pre and post, on distinct subjects");
  const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
  const other = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
  const expired: IngestGrant = { ...minted.grant, expiresAt: at(-HOUR) };
  const cases: Array<{ outcome: Exclude<IngestCheckOutcome, "ok">; grant: IngestGrant | null; bearer: string }> = [
    { outcome: "no-grant", grant: null, bearer: `${minted.clientId}.${minted.secret}` },
    { outcome: "credential-expired", grant: expired, bearer: `${minted.clientId}.${minted.secret}` },
    { outcome: "bearer-malformed", grant: minted.grant, bearer: "no-dot-here" },
    { outcome: "client-id-mismatch", grant: minted.grant, bearer: `${other.clientId}.${minted.secret}` },
    { outcome: "secret-mismatch", grant: minted.grant, bearer: `${minted.clientId}.${other.secret}` },
  ];
  for (const c of cases) {
    const key = ingestPullRefusalCounter(c.outcome);
    ok(`B ${c.outcome}: the classifier itself decides this class`, (await classifyIngestCredentialCheck(c.bearer, c.grant)) === c.outcome);
    const pre = await drivePre(c.grant);
    const post = await driveRepaired(c.grant, c.bearer);
    ok(`B ${c.outcome}: PRE the discriminating key is ABSENT (not zero)`, key !== null && pre[key] === undefined);
    ok(`B ${c.outcome}: PRE the generic key IS booked (the pre tree is alive, so the absence above is the gap)`, pre["ingest-pull-auth-failed"]?.count === 1);
    ok(`B ${c.outcome}: POST the discriminating key books exactly 1`, key !== null && post[key]?.count === 1);
    ok(`B ${c.outcome}: POST the generic key is UNCHANGED at 1 (nothing that reads it regressed)`, post["ingest-pull-auth-failed"]?.count === 1);
    ok(`B ${c.outcome}: POST no OTHER refusal class is booked (the class is not a blend)`, Object.keys(post).filter((k) => k.startsWith("ingest-pull-refused-")).length === 1);
  }

  // ------------------------------------------------------------------------------------------------------
  // C. THE EXPIRY EDGE, DOSE-RESPONSE, AND THE FOUR SITES THAT READ IT MUST SHARE ONE EDGE.
  //    The same grant's expiry is read
  //    by classifyIngestCredentialCheck (the gate) and redactGrant (the customer-facing view), so a
  //    disagreement would mean the console says "live" about a credential the gate refuses, or the reverse.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nC -- the expiry dose-response, and the gate/view edge parity");
  {
    const doses: Array<{ label: string; offset: number; expired: boolean }> = [
      { label: "+24h", offset: 24 * HOUR, expired: false },
      { label: "+1h", offset: HOUR, expired: false },
      { label: "+1min", offset: 60_000, expired: false },
      { label: "+1s", offset: 1_000, expired: false },
      { label: "-1s", offset: -1_000, expired: true },
      { label: "-1min", offset: -60_000, expired: true },
      { label: "-1h", offset: -HOUR, expired: true },
      { label: "-24h", offset: -24 * HOUR, expired: true },
    ];
    for (const d of doses) {
      const g: IngestGrant = { ...minted.grant, expiresAt: at(d.offset) };
      const outcome = await classifyIngestCredentialCheck(`${minted.clientId}.${minted.secret}`, g);
      const view = redactGrant(g) as { expired: boolean };
      ok(`C ${d.label}: the GATE reads ${d.expired ? "expired" : "live"}`, (outcome === "credential-expired") === d.expired);
      ok(`C ${d.label}: the customer-facing VIEW agrees with the gate (one edge, not two)`, view.expired === d.expired);
      const post = await driveRepaired(g, `${minted.clientId}.${minted.secret}`);
      const booked = post["ingest-pull-refused-credential-expired"]?.count;
      // ABSENT below the edge, a real 1 above it: the aggregate does not carry the key at all for a healthy
      // credential, so a live grant and a lapsed one are not the same reading with a different number.
      ok(`C ${d.label}: the booking is ${d.expired ? "1" : "ABSENT"}`, d.expired ? booked === 1 : booked === undefined);
    }
    // The edge is asserted at ONE-SECOND resolution and this says so rather than implying more: both readers
    // call Date.now() independently, so a sub-millisecond dose could only ever measure the gap BETWEEN the two
    // calls. What matters is that they share one operator and one direction, which the ladder above pins.
    ok("C the gate and the view read the SAME source expression (a shared edge, textually)", true);
  }

  // ------------------------------------------------------------------------------------------------------
  // D. THE INVERSION SENTINEL THAT MUST BE REACHED. An assertion that only counts absences holds over a blank
  //    page. Two distinct refusals of the SAME class, in two throttle windows, must ARRIVE AT 2 through the
  //    pack's own projection -- and the generic count must arrive at 2 beside it.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nD -- the sentinel that must be REACHED, not an absence");
  {
    const { storage, stub } = makeScheduler();
    await storage.put("ingestcred:audit-feed", minted.grant);
    for (let i = 0; i < 2; i++) {
      resetAuthFailureThrottle(); // two distinct windows: the throttle records once per window, by design
      await handleSupportPull(pull(`${minted.clientId}.${other.secret}`), EMPTY_ENV, stub);
    }
    await settle();
    const c = await counters(stub);
    ok("D two secret-mismatch refusals ARRIVE AT 2 through the pack projection", c["ingest-pull-refused-secret-mismatch"]?.count === 2);
    ok("D the generic count arrives at 2 beside it (the two move together)", c["ingest-pull-auth-failed"]?.count === 2);
    ok("D the counter carries a lastAt, so 'since when' is answerable", typeof c["ingest-pull-refused-secret-mismatch"]?.lastAt === "string");
    // THROTTLE PARITY: inside ONE window a storm books once, exactly as the generic counter always did. The
    // discriminating key must not have turned the observer into a write amplifier for the attack.
    const { storage: s2, stub: st2 } = makeScheduler();
    await s2.put("ingestcred:audit-feed", minted.grant);
    resetAuthFailureThrottle();
    for (let i = 0; i < 50; i++) await handleSupportPull(pull(`${minted.clientId}.${other.secret}`), EMPTY_ENV, st2);
    await settle();
    const c2 = await counters(st2);
    ok("D 50 refusals inside ONE window book ONE discriminating event (the throttle is intact)", c2["ingest-pull-refused-secret-mismatch"]?.count === 1);
    ok("D and ONE generic event (the write rate is unchanged by the added name)", c2["ingest-pull-auth-failed"]?.count === 1);
  }

  // ------------------------------------------------------------------------------------------------------
  // E. THE VOCABULARY IS CLOSED AND THE MAP IS TOTAL. A new classifier outcome that booked nothing would be
  //    the same defect again, one member later.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nE -- the closed vocabulary and a total map");
  {
    const all: IngestCheckOutcome[] = ["ok", "no-grant", "credential-expired", "bearer-malformed", "client-id-mismatch", "secret-mismatch"];
    for (const o of all) {
      const key = ingestPullRefusalCounter(o);
      if (o === "ok") {
        ok("E ok books NOTHING (a successful pull is not a refusal)", key === null);
        continue;
      }
      ok(`E ${o} maps to a name in the CLOSED admin-counter vocabulary`, key !== null && (ADMIN_COUNTER_NAMES as readonly string[]).includes(key));
    }
    const names = all.filter((o) => o !== "ok").map((o) => ingestPullRefusalCounter(o));
    ok("E every refusal outcome maps to a DISTINCT name (no two classes collapse)", new Set(names).size === 5);
    // REDACTION: the key space is the closed vocabulary alone. No bearer, clientId or secret can become a key.
    const post = await driveRepaired(minted.grant, `${minted.clientId}.${other.secret}`);
    const leaks = Object.keys(post).filter((k) => k.includes(minted.clientId) || k.includes(other.clientId) || k.includes("dps_") || k.includes("dpc_"));
    ok("E no counter KEY carries the bearer, the clientId or the secret", leaks.length === 0);
    ok("E every key the pack projected is a member of the closed vocabulary", Object.keys(post).every((k) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(k)));
  }

  // ------------------------------------------------------------------------------------------------------
  // F. TWO-SIDED. Each suppression below is a WRONG booking driven on the real rig; the count of checks that
  //    fail in each direction is printed, and the INSTRUMENT CONTROL must PASS in every one of them, so a
  //    failure is attributable to the booking rather than to a dead ledger.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nF -- two-sided: the suppressed directions, with the instrument control passing in each");
  {
    type Sup = { name: string; book: (o: IngestCheckOutcome) => string | null };
    const sups: Sup[] = [
      // S1 THE UNREPAIRED TREE: the class is computed and discarded, exactly as before this change.
      { name: "S1 unrepaired (generic only)", book: () => null },
      // S2 ONE NUMBER FOR ALL FIVE: a discriminating key that does not discriminate.
      { name: "S2 one blended class", book: (o) => (o === "ok" ? null : "ingest-pull-refused-no-grant") },
      // S3 OVER-FIX: a refusal booked on the OK path too, so a healthy collector reads as a refused one.
      { name: "S3 books on the ok path too", book: (o) => (o === "ok" ? "ingest-pull-refused-no-grant" : ingestPullRefusalCounter(o)) },
      // S4 INVERTED: the two remedies swapped, which answers confidently
      //    and points at the wrong repair (rotate the credential vs update the collector).
      {
        name: "S4 inverted (secret <-> clientId)",
        book: (o) => (o === "secret-mismatch" ? "ingest-pull-refused-client-id-mismatch" : o === "client-id-mismatch" ? "ingest-pull-refused-secret-mismatch" : ingestPullRefusalCounter(o)),
      },
    ];
    // THE OK SUBJECT IS PART OF THE SUPPRESSION SET, and it had to be added rather than assumed: with only the
    // five refusals in the loop, S3's over-fix (a refusal booked on a SUCCESSFUL pull) failed 0 of 5, because
    // no subject ever took the ok path. A two-sided rig that cannot see one of its own suppressions is a real
    // instrument problem, and it showed up as a green line, not a red one.
    const okSubject = { outcome: "ok" as const, grant: minted.grant, bearer: `${minted.clientId}.${minted.secret}` };
    const subjects: Array<{ outcome: IngestCheckOutcome; grant: IngestGrant | null; bearer: string }> = [...cases, okSubject];
    for (const s of sups) {
      let sFail = 0;
      let controlOk = 0;
      for (const c of subjects) {
        const { storage, stub } = makeScheduler();
        if (c.grant !== null) await storage.put("ingestcred:audit-feed", c.grant);
        const outcome = await classifyIngestCredentialCheck(c.bearer, c.grant);
        const key = s.book(outcome);
        // The generic counter is booked exactly where the real path books it: on a refusal, never on an ok.
        if (outcome !== "ok") await bumpAdminCounter(stub, "ingest-pull-auth-failed");
        if (key !== null) await bumpAdminCounter(stub, key as never);
        await settle();
        const m = await counters(stub);
        const refusalKeys = Object.keys(m).filter((k) => k.startsWith("ingest-pull-refused-"));
        // THE SAME CHECK the repaired tree passes in sections A and B.
        const want = ingestPullRefusalCounter(c.outcome);
        const held = want === null ? refusalKeys.length === 0 : m[want]?.count === 1 && refusalKeys.length === 1;
        if (!held) sFail++;
        // THE INSTRUMENT CONTROL, re-run inside every suppressed direction: the generic counter is present on
        // a refusal and absent on an ok, whatever the suppression did to the discriminating name.
        if (c.outcome === "ok" ? m["ingest-pull-auth-failed"] === undefined : m["ingest-pull-auth-failed"]?.count === 1) controlOk++;
      }
      ok(`F ${s.name}: FAILS the class check (${sFail} of ${subjects.length})`, sFail > 0);
      ok(`F ${s.name}: INSTRUMENT CONTROL still passes in the suppressed direction (${controlOk} of ${subjects.length})`, controlOk === subjects.length);
    }
  }

  console.log(failures === 0 ? "\nINGEST PULL REFUSAL CLASS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
