// A site-fault batch whose drain fails is kept and sent again, never lost (admin/site-faults.ts).
//
// The drains take the isolate's pending rows before they write. When the write fails, returnSiteFaultBatch
// puts the batch back, merged with any row noted while the write was in flight, records the drain's own
// fault, and holds the next attempt to one per SITE_FAULT_FLUSH_MIN_MS. This validator drives both drains
// with an explicit clock:
//   - the POST to the scheduler answers 503, then throws: the rows and their counts stay pending, a row
//     noted during the POST is merged in, the drain's own row is recorded with its class, and no second
//     POST goes out inside the window;
//   - once the window opens, one POST carries every kept row, and nothing is pending after it;
//   - the scheduler DO's own drain: a storage write that throws keeps the batch, and the next write stores it;
//   - CONTROL: a drain with no scheduler binding takes nothing.
//
// Run: node test/validate-site-fault-drain-retry.ts

import { drainSiteFaultsToScheduler, drainSiteFaultsToStorage, hasPendingSiteFaults, noteSiteFault, peekSiteFaults, readSiteFaults, SITE_FAULT_FLUSH_MIN_MS, SITE_FAULTS_KEY, type SiteFaults } from "../src/admin/site-faults.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

// A scheduler stub whose answer the test sets per call. Each POST body is kept.
function schedulerStub(answer: () => Response): { stub: DurableObjectStub; posts: SiteFaults[] } {
  const posts: SiteFaults[] = [];
  const stub = {
    fetch: async (_url: string, init?: RequestInit): Promise<Response> => {
      posts.push((JSON.parse(String(init?.body ?? "{}")) as { faults: SiteFaults }).faults);
      return answer();
    },
  } as unknown as DurableObjectStub;
  return { stub, posts };
}

function memStorage(failPuts: number): { get<T>(k: string): Promise<T | undefined>; put<T>(k: string, v: T): Promise<void>; map: Map<string, unknown> } {
  const map = new Map<string, unknown>();
  let left = failPuts;
  return {
    map,
    get: async <T>(k: string) => map.get(k) as T | undefined,
    put: async <T>(k: string, v: T) => {
      if (left > 0) {
        left--;
        throw new RangeError("storage write refused");
      }
      map.set(k, v);
    },
  };
}

async function main(): Promise<void> {
  const T = 10 * SITE_FAULT_FLUSH_MIN_MS;

  console.log("\n-- 1. the POST to the scheduler answers 503 --");
  noteSiteFault("repl.root-parse", new SyntaxError("x"));
  noteSiteFault("repl.root-parse", new SyntaxError("x"));
  let noteDuringPost = true;
  const refused = schedulerStub(() => {
    if (noteDuringPost) noteSiteFault("repl.root-parse", new SyntaxError("x"));
    noteDuringPost = false;
    return new Response("busy", { status: 503 });
  });
  await drainSiteFaultsToScheduler(refused.stub, false, T);
  ok("one POST went out, carrying the two rows noted before it", refused.posts.length === 1 && refused.posts[0]?.["repl.root-parse"]?.count === 2, refused.posts);
  let held = peekSiteFaults();
  ok("the batch is kept, merged with the row noted during the POST (count 3, class syntax)", held["repl.root-parse"]?.count === 3 && held["repl.root-parse"]?.lastCls === "syntax", held);
  ok("the drain records its own fault as do-remote", held["diag.site-fault-drain-post"]?.count === 1 && held["diag.site-fault-drain-post"]?.lastCls === "do-remote", held);
  ok("rows are pending", hasPendingSiteFaults());

  await drainSiteFaultsToScheduler(refused.stub, false, T + 1_000);
  ok("no second POST inside the window after a failed drain", refused.posts.length === 1, refused.posts.length);

  console.log("\n-- 2. the POST throws --");
  const T2 = T + SITE_FAULT_FLUSH_MIN_MS;
  const throwing = {
    fetch: async (): Promise<Response> => {
      throw new TypeError("network lost");
    },
  } as unknown as DurableObjectStub;
  await drainSiteFaultsToScheduler(throwing, false, T2);
  held = peekSiteFaults();
  ok("the batch is kept with its counts after a thrown POST", held["repl.root-parse"]?.count === 3 && held["diag.site-fault-drain-post"]?.count === 2, held);
  ok("the drain's own row now carries the thrown class (type)", held["diag.site-fault-drain-post"]?.lastCls === "type", held);

  console.log("\n-- 3. the window opens and the scheduler accepts --");
  const accepted = schedulerStub(() => new Response("{}", { status: 200 }));
  await drainSiteFaultsToScheduler(accepted.stub, false, T2 + SITE_FAULT_FLUSH_MIN_MS);
  ok("one POST carries every kept row", accepted.posts.length === 1 && accepted.posts[0]?.["repl.root-parse"]?.count === 3 && accepted.posts[0]?.["diag.site-fault-drain-post"]?.count === 2, accepted.posts);
  ok("nothing is pending after an accepted drain", !hasPendingSiteFaults() && Object.keys(peekSiteFaults()).length === 0, peekSiteFaults());

  console.log("\n-- 4. the scheduler DO's own drain: a storage write throws --");
  const T3 = T2 + 3 * SITE_FAULT_FLUSH_MIN_MS;
  noteSiteFault("repl.runlog-read", new Error("x"));
  const storage = memStorage(1);
  await drainSiteFaultsToStorage(storage, false, T3);
  held = peekSiteFaults();
  ok("nothing was stored", !storage.map.has(SITE_FAULTS_KEY));
  ok("the batch is kept and the drain records diag.site-fault-drain-storage as range", held["repl.runlog-read"]?.count === 1 && held["diag.site-fault-drain-storage"]?.lastCls === "range", held);
  await drainSiteFaultsToStorage(storage, false, T3 + 1_000);
  ok("no second write inside the window", !storage.map.has(SITE_FAULTS_KEY));
  await drainSiteFaultsToStorage(storage, false, T3 + SITE_FAULT_FLUSH_MIN_MS);
  const stored = (await readSiteFaults(storage)).faults;
  ok("the next write stores the kept rows", stored["repl.runlog-read"]?.count === 1 && stored["diag.site-fault-drain-storage"]?.count === 1, stored);
  ok("nothing is pending after it", !hasPendingSiteFaults());

  console.log("\n-- 5. CONTROL: no scheduler binding --");
  noteSiteFault("repl.runlog-read", new Error("x"));
  await drainSiteFaultsToScheduler(null, true, T3 + 10 * SITE_FAULT_FLUSH_MIN_MS);
  ok("a drain with no scheduler takes nothing: the row stays pending", peekSiteFaults()["repl.runlog-read"]?.count === 1);

  console.log(failures === 0 ? "\nSITE FAULT DRAIN RETRY PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
