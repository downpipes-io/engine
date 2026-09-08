// validate-dest-replace-reassignment: "Replace from the console" on a deploy-time-bound destination (a single
// deploy-time DEST_R2 binding, or DEST_* env vars, no console record yet) is the only console path from
// that binding to a console-managed destination. Adding the FIRST console destination made it the
// account default immediately (putDest: `if (coll.list.length === 1 || coll.defaultId === "") coll.defaultId
// = id`), and every run already sealed under the deploy-time binding had recorded NO origin id
// (destinationId undefined -- an unpinned downpipe's default-routed run, selectSealDestination's own
// documented shape). Both readers that have to attribute an undefined destinationId to a real bucket --
// the removal guard (uncoveredOriginRuns) AND the drill/restore read path (destinationForRun /
// destinationsForRun, which falls back to primaryDestinationId(config), a per-DOWNPIPE pin an unpinned
// downpipe never has either) -- resolved it as "whichever destination is the default RIGHT NOW". So the
// instant the new destination became default: a drill of any prior run read "object missing" (it looked
// in the empty new bucket), and the removal guard, asked to remove that SAME empty new bucket, answered
// "destination is the only proven copy of 19 backed-up run(s)" -- a true count attributed to the wrong
// bucket, with the real 19 runs' 2,256 objects sitting untouched in the deploy-time bucket the whole time.
//
// This validator drives directly against the real SchedulerDO mixin (DestConfigMixin) and the
// real read-for-use chokepoint (fetchDestConfig) with an in-memory storage double, no network, no deploy:
//   1. ensureDeployDestSeeded registers a synthetic source:"deploy" destination (DEPLOY_DEST_ID = "deploy")
//      standing in for the env-configured binding the FIRST time a console destination joins it, sets it
//      (not the new one) as the account default, and BACKFILLS every existing default-routed OK run to
//      destinationId:"deploy" -- a permanent, concrete fact instead of an inference from "the default now".
//   2. fetchDestConfig (dest/factory.ts) treats a source:"deploy" record as "no console override" (null),
//      the exact value that already builds the env-backed Destination, so resolving "deploy" is BYTE-
//      IDENTICAL to today's single-destination env fallback.
//   3. backfillDefaultRoutedRuns is ALSO run by setDefaultDest and by removeDest's silent default
//      promotion (both pre-existing default-repoint paths), closing the same read-path gap for an
//      ordinary console-to-console default change, not only the deploy-time transition.
//
// Nothing here touches an estate: an in-memory DO storage double, the real SchedulerDO mixin dispatched
// through its own real HTTP routes (dobj.fetch), and pure functions.
// Run: node test/validate-dest-replace-reassignment.ts

import { callerHeaders } from "../src/admin/router-audit.ts";
import type { AuthMethod, Role } from "../src/admin/identity.ts";
import { fetchDestConfig } from "../src/dest/factory.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { DEPLOY_DEST_ID } from "../src/sched/scheduler-do-limits.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; role: Role };
const OWNER: Caller = { method: "token", email: "owner@acme.example", subject: null, groups: [], role: "owner" };

function makeDO(seed: Record<string, unknown>): { dobj: SchedulerDO; storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(seed)) storage.seed(k, v);
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  // The real HTTP route dispatch (dobj.fetch), so fetchDestConfig/destinationForRun exercise the SAME
  // /dest-config, /downpipes/dest-for-run and /downpipes/dests-for-run routes the Worker calls in
  // production, not a hand-rolled stand-in for them.
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  return { dobj, storage, scheduler };
}

function unpinnedDownpipe(id: string, name: string): Record<string, unknown> {
  return {
    config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] } },
    nextRunAt: 0,
    lastRunId: `run-${id}-latest`,
    inFlight: false,
  };
}

// DEFAULT-ROUTED history rows: status ok, NO destinationId key at all -- exactly what selectSealDestination
// records for an unpinned downpipe (primaryDestinationId(config) is undefined when nothing is pinned).
function defaultRoutedRing(n: number, from = 0): Array<Record<string, unknown>> {
  return Array.from({ length: n }, (_, i) => ({ runId: `run-${from + i}`, index: from + i, startedAt: "2026-09-01T00:00:00.000Z", status: "ok" }));
}

async function caught(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e as Error;
  }
}

function newDestBody(id: string | undefined, label: string, envDestConfigured: boolean): Record<string, unknown> {
  return {
    ...(id ? { id } : {}),
    label,
    config: { endpoint: "https://acct.r2.cloudflarestorage.com", bucket: `bk-${label}`, region: "auto", accessKeyId: "AK", secretAccessKey: "SK" },
    envDestConfigured,
  };
}

async function main(): Promise<void> {
  // ==============================================================================================
  // 1. THE REHEARSAL SEQUENCE ITSELF: 19 runs sealed to a deploy-time binding, then "Replace from the
  //    console" adds archive-2 -- reproducing the exact failure observed in rehearsal.
  // ==============================================================================================
  console.log("-- the rehearsal sequence: 19 deploy-time runs, then the console's first add --");
  {
    const { dobj, storage, scheduler } = makeDO({
      "dp:kv-rehearsal": unpinnedDownpipe("kv-rehearsal", "KV rehearsal"),
      "hist:kv-rehearsal": defaultRoutedRing(19),
    });

    // Pre-fix ground truth: no console destination exists yet, so BOTH reads have nothing to go on but
    // "the default", and there is no default at all -- fetchDestConfig(undefined) must therefore report
    // "no console destination" (null), which is what lets a single-destination deployment build straight
    // from env. This is the state a real deploy-time-only estate is in before anyone opens Destinations.
    const preAdd = await fetchDestConfig(scheduler, undefined);
    ok("before any console destination exists, fetchDestConfig(default) is null (env fallback applies)", preAdd === null);

    // "Replace from the console": POST /destinations with NO id (destination-cards-actions.ts's
    // renderDeployFallback passes no editId for a deploy-bound destination) and envDestConfigured:true
    // (router-destinations.ts's own env read, buildStatus(env,0).destConfigured).
    const putResp = await scheduler.fetch("https://scheduler.internal/destinations", {
      method: "POST",
      headers: callerHeaders(OWNER),
      body: JSON.stringify(newDestBody(undefined, "archive-2", true)),
    });
    ok("the add is accepted", putResp.ok);
    const putBody = (await putResp.json()) as { destinations: Array<{ id: string; label: string; isDefault?: boolean; source?: string }>; defaultId: string | null };

    // THE INVARIANT: the deploy-time binding is now a REAL destination (source:"deploy"), it stays the
    // default (nothing repoints without an explicit Make-default), and the new one joins alongside it --
    // "add", not "replace". Without the fix, putDest's own "first destination becomes the default"
    // branch would make archive-2 (the ONLY entry `coll.list` had ever held) the default instead.
    ok("the deploy-time binding is now listed as a real destination", putBody.destinations.some((d) => d.id === DEPLOY_DEST_ID && d.source === "deploy"));
    ok("the deploy-time binding is STILL the default (the add did not silently repoint it)", putBody.defaultId === DEPLOY_DEST_ID);
    const archive2 = putBody.destinations.find((d) => d.label === "archive-2");
    ok("archive-2 was added alongside it, not made default", archive2 !== undefined && archive2.isDefault !== true);

    // THE READ PATH. Without the fix, entry.destinationId is undefined and primaryDestinationId(an
    // UNPINNED downpipe's config) is ALSO undefined, so destinationForRun/destinationsForRun fall to
    // "the current default" -- archive-2, empty, and every drill of the 19 prior runs would answer "object
    // missing", byte for byte. With the fix, the backfill during the seed stamps every one
    // of those rows with the CONCRETE id "deploy" before archive-2 ever entered the collection.
    const forRunResp = await scheduler.fetch("https://scheduler.internal/downpipes/dest-for-run?runId=run-5");
    const { destinationId } = (await forRunResp.json()) as { destinationId: string | null };
    ok("a prior run's recorded destination is the deploy-time binding, never the brand-new empty one", destinationId === DEPLOY_DEST_ID);

    // fetchDestConfig("deploy") must resolve exactly like "no console override" (null): building the SAME
    // env-backed Destination a single-destination deployment always had, not an S3 client from blank
    // placeholder fields (which would throw config-incomplete if this guard were missing).
    const deployCfg = await fetchDestConfig(scheduler, DEPLOY_DEST_ID);
    ok('fetchDestConfig("deploy") returns null (env fallback), never throws on the blank placeholder fields', deployCfg === null);

    // THE ORPHAN GUARD must protect the ACTUAL holder, "deploy", and free the genuinely-empty archive-2 immediately
    // -- never the reverse, where the guard fires on an empty new destination while the true holder is unprotected.
    const removeArchive2 = await caught(() => dobj.removeDest(archive2!.id, false, OWNER));
    ok("archive-2 (genuinely empty) is freely removable with no orphan-guard refusal", removeArchive2 === null);
    const removeDeploy = await caught(() => dobj.removeDest(DEPLOY_DEST_ID, false, OWNER));
    ok(
      "removing the deploy-time binding IS refused as the only proven copy of the 19 real runs, with the true count",
      removeDeploy !== null && /only proven copy of 19 backed-up run/.test(removeDeploy.message),
    );

    // Storage-level confirmation, not just the return value: a refusal that still deleted the record
    // would be worse than no refusal.
    const coll = storage.rawGet<{ list: Array<{ id: string }> }>("destinations");
    ok("the deploy-time binding is still stored after the refused removal", coll?.list.some((d) => d.id === DEPLOY_DEST_ID) === true);
  }

  // ==============================================================================================
  // 2. A RUN SEALED WHILE THE NEW DESTINATION EXISTS, THEN THE RUNLOG-HOLE SHAPE: an unpinned
  //    downpipe stays pinned to nothing, so it keeps sealing to the account default (still "deploy"
  //    post-fix, unlike the pre-fix tree where the add itself moved the default). The hole found only
  //    opens when the DEFAULT itself is explicitly repointed to the new destination
  //    without a byte moving -- exactly what the setDefaultDest path in section 3 exercises.
  // ==============================================================================================
  console.log("-- a run sealed after the add keeps sealing to the deploy-time binding, unpinned --");
  {
    const { scheduler } = makeDO({
      "dp:kv-rehearsal": unpinnedDownpipe("kv-rehearsal", "KV rehearsal"),
      "hist:kv-rehearsal": defaultRoutedRing(19),
    });
    await scheduler.fetch("https://scheduler.internal/destinations", { method: "POST", headers: callerHeaders(OWNER), body: JSON.stringify(newDestBody(undefined, "archive-2", true)) });
    // A fresh seal after the add: selectSealDestination's ids.length<=1 branch still resolves
    // primaryDestinationId(config) (undefined, still unpinned) and fetchDestConfig(undefined) still
    // resolves the default -- "deploy", unchanged. The NEW destination never receives a byte unless the
    // operator explicitly promotes it (setDefaultDest) or pins a downpipe to it, which is precisely
    // "add", not "replace": nothing about where existing downpipes write changes underneath them.
    const cfg = await fetchDestConfig(scheduler, undefined);
    ok("an unpinned downpipe still resolves to the env-backed destination after the add (default unmoved)", cfg === null);
  }

  // ==============================================================================================
  // 3. THE GENERAL CASE: an EXPLICIT default repoint between two REAL console destinations must not
  //    strand a prior run's read either -- the same mechanism, driven through setDefaultDest, which
  //    is how a real fan-out/replicate migration (the ordinary order of a destination
  //    migration) actually moves the default once "deploy" is a real member of the collection.
  // ==============================================================================================
  console.log("-- setDefaultDest repoint: the read path (not just the removal guard) follows the backfill --");
  {
    const { dobj, scheduler } = makeDO({
      "dp:kv-rehearsal": unpinnedDownpipe("kv-rehearsal", "KV rehearsal"),
      "hist:kv-rehearsal": defaultRoutedRing(19),
    });
    await scheduler.fetch("https://scheduler.internal/destinations", { method: "POST", headers: callerHeaders(OWNER), body: JSON.stringify(newDestBody(undefined, "archive-2", true)) });
    // Explicit promotion: the operator (or the console's Make-default lever) repoints the account
    // default from "deploy" to the new destination.
    await dobj.setDefaultDest("dest-archive-2", OWNER).catch(() => {
      /* id is engine-minted; resolved below from the list if this literal guess is wrong */
    });
    const listed = (await (await scheduler.fetch("https://scheduler.internal/destinations")).json()) as { destinations: Array<{ id: string; label: string }> };
    const archive2Id = listed.destinations.find((d) => d.label === "archive-2")!.id;
    await dobj.setDefaultDest(archive2Id, OWNER);

    // Without backfillDefaultRoutedRuns, destinationForRun for these 19 rows would resolve archive-2 (today's
    // default), even though "deploy" still holds every byte and archive-2 remains empty -- the read-path half
    // of the same risk the priorDefaultIds comment in scheduler-do-limits.ts already names for the removal guard.
    const forRunResp = await scheduler.fetch("https://scheduler.internal/downpipes/dest-for-run?runId=run-3");
    const { destinationId } = (await forRunResp.json()) as { destinationId: string | null };
    ok("after an explicit default repoint, a prior run STILL resolves to the destination that actually holds it", destinationId === DEPLOY_DEST_ID);

    // The removal guard (priorDefaultIds) and the read path now agree: removing "deploy" is refused for the
    // same 19 runs, from either angle.
    const removeDeploy = await caught(() => dobj.removeDest(DEPLOY_DEST_ID, false, OWNER));
    ok("removing the now-superseded deploy-time binding is still refused (priorDefaultIds + the backfill agree)", removeDeploy !== null && /only proven copy of 19 backed-up run/.test(removeDeploy.message));
  }

  console.log(failures === 0 ? "\nVALIDATE-DEST-REPLACE-REASSIGNMENT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
