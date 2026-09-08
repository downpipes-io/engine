// Prove the volume-based licensing usage rollup (computeEstateRollup, src/admin/estate.ts): a
// multi-downpipe fleet sums bytes/records from each downpipe's MOST RECENT SUCCESSFUL run only,
// byType sums correctly across downpipes of the same source type, a downpipe with no successful
// run (missing history, only failed/in-flight rows, or a currently-detached source) contributes
// zero but is still counted in `downpipes`, accounts/zones dedupe distinct Cloudflare ids, asOf
// tracks the newest run actually used, an empty fleet resolves to a real all-zero object (never
// null), a DO fault anywhere resolves the WHOLE rollup to null, and malformed roster rows are
// skipped defensively rather than crashing the aggregation.
// Run: node test/validate-estate.ts

import { computeEstateRollup } from "../src/admin/estate.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A run-history row, as fetchRunHistory projects it (the fields computeEstateRollup reads).
type Row = { status: string; index: number; startedAt?: string; recordCount?: number; bytes?: number };

// A downpipe roster row, as GET /downpipes returns it (only the fields computeEstateRollup reads;
// `binding` rides along unused, exactly as a live downpipe row would carry many fields this module
// ignores).
type Downpipe = { config: { id: string; name?: string; source: { type: string; accountId?: string; zoneId?: string; binding?: string } } };

// stub builds a minimal DurableObjectStub answering GET /downpipes and GET /history (the two
// fetches computeEstateRollup makes), from plain fixtures. throwOn simulates a DO fault on a
// named path (the fetch itself throws, matching a real network/DO failure).
function stub(downpipes: Downpipe[], byDownpipe: Record<string, Row[]>, throwOn?: string): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (throwOn !== undefined && url.pathname === throwOn) throw new Error(`injected DO fault on ${throwOn}`);
      if (url.pathname === "/downpipes") return new Response(JSON.stringify(downpipes));
      if (url.pathname === "/history") return new Response(JSON.stringify({ byDownpipe }));
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("\nan empty fleet resolves to a real all-zero object, never null:");
  {
    const est = await computeEstateRollup(stub([], {}));
    ok(
      "zero downpipes -> a real object with every field honestly zero/empty/null",
      est !== null && est.totalProtectedBytes === 0 && est.accounts === 0 && est.zones === 0 && est.downpipes === 0 && Object.keys(est.byType).length === 0 && est.asOf === null,
    );
  }

  console.log("\nmulti-downpipe fixture: byType sums, accounts/zones dedup, asOf = newest used:");
  {
    const downpipes: Downpipe[] = [
      { config: { id: "dp-kv-1", name: "uploads", source: { type: "kv", accountId: "acct-a", binding: "UPLOADS_KV" } } },
      { config: { id: "dp-kv-2", name: "sessions", source: { type: "kv", accountId: "acct-a" } } }, // SAME account as dp-kv-1 (dedup)
      { config: { id: "dp-r2-1", name: "media", source: { type: "r2", accountId: "acct-b" } } },
      { config: { id: "dp-cfg-1", name: "zone-cfg", source: { type: "cf-config", accountId: "acct-b", zoneId: "zone-1" } } },
      { config: { id: "dp-cfg-2", name: "zone-cfg-2", source: { type: "cf-config", accountId: "acct-b", zoneId: "zone-1" } } }, // SAME zone (dedup)
    ];
    const byDownpipe: Record<string, Row[]> = {
      "dp-kv-1": [{ status: "ok", index: 3, startedAt: "2026-07-01T00:00:00.000Z", recordCount: 100, bytes: 1_000 }],
      "dp-kv-2": [{ status: "ok", index: 5, startedAt: "2026-07-03T00:00:00.000Z", recordCount: 50, bytes: 500 }],
      "dp-r2-1": [{ status: "ok", index: 1, startedAt: "2026-07-02T00:00:00.000Z", recordCount: 9, bytes: 90_000 }],
      "dp-cfg-1": [{ status: "ok", index: 2, startedAt: "2026-06-30T00:00:00.000Z", recordCount: 4, bytes: 400 }],
      // dp-cfg-2 has never completed a run at all (no key in byDownpipe).
    };
    const est = await computeEstateRollup(stub(downpipes, byDownpipe));
    ok("est is non-null", est !== null);
    if (est === null) throw new Error("unreachable: est must be non-null for the rest of this block");
    ok("downpipes counts EVERY roster row, run or not", est.downpipes === 5);
    ok("totalProtectedBytes sums the latest-ok bytes of every downpipe (1000+500+90000+400)", est.totalProtectedBytes === 1_000 + 500 + 90_000 + 400);
    ok(
      "byType sums per source type across downpipes of the SAME type (kv: 2 downpipes, r2/cf-config: 1 each)",
      est.byType["kv"]?.records === 150 && est.byType["kv"]?.bytes === 1_500 && est.byType["r2"]?.records === 9 && est.byType["r2"]?.bytes === 90_000 && est.byType["cf-config"]?.records === 4 && est.byType["cf-config"]?.bytes === 400,
    );
    ok("accounts dedupes distinct Cloudflare account ids (acct-a, acct-b -> 2)", est.accounts === 2);
    ok("zones dedupes distinct Cloudflare zone ids (zone-1 shared by two downpipes -> 1)", est.zones === 1);
    ok("asOf is the newest startedAt among the runs actually used (dp-kv-2's 2026-07-03)", est.asOf === "2026-07-03T00:00:00.000Z");
  }

  console.log("\nmissing/failed runs contribute zero but are still counted in `downpipes`:");
  {
    const downpipes: Downpipe[] = [
      { config: { id: "dp-never-run", source: { type: "kv" } } }, // no key in byDownpipe at all
      { config: { id: "dp-empty-history", source: { type: "kv" } } }, // an empty rows array
      { config: { id: "dp-only-failed", source: { type: "r2" } } }, // rows exist but none are "ok"
      { config: { id: "dp-only-inflight", source: { type: "r2" } } },
      { config: { id: "dp-healthy", source: { type: "d1" } } }, // the control: one genuine success
    ];
    const byDownpipe: Record<string, Row[]> = {
      "dp-empty-history": [],
      "dp-only-failed": [
        { status: "failed", index: 1, startedAt: "2026-07-01T00:00:00.000Z" },
        { status: "failed", index: 2, startedAt: "2026-07-02T00:00:00.000Z" },
      ],
      "dp-only-inflight": [{ status: "in-flight", index: 1, startedAt: "2026-07-01T00:00:00.000Z" }],
      "dp-healthy": [{ status: "ok", index: 1, startedAt: "2026-07-01T00:00:00.000Z", recordCount: 7, bytes: 700 }],
    };
    const est = await computeEstateRollup(stub(downpipes, byDownpipe));
    ok("est is non-null", est !== null);
    if (est === null) throw new Error("unreachable");
    ok("all 5 downpipes are counted regardless of run outcome", est.downpipes === 5);
    ok("only the genuinely-healthy downpipe's bytes/records contribute", est.totalProtectedBytes === 700 && est.byType["d1"]?.records === 7);
    ok("a source type with only zero-contributing downpipes still gets a zeroed byType entry (kv/r2)", est.byType["kv"]?.bytes === 0 && est.byType["r2"]?.bytes === 0);
    ok("asOf reflects only the one genuinely-used run (never-run/failed/in-flight rows never set it)", est.asOf === "2026-07-01T00:00:00.000Z");
  }

  console.log("\na currently-detached source (a stale binding, no live env match) still counts its LAST successful run:");
  {
    // The rollup never reads env or live Cloudflare bindings at all (unlike fetchSourcesDetached, which
    // compares the roster to live bindings): a downpipe whose binding would resolve as "detached" today
    // still contributes the bytes/records of whatever its most recent SUCCESSFUL run recorded, because
    // that run genuinely completed before the source went missing. This proves the rollup's basis is
    // pure DO-held history, independent of live binding state.
    const downpipes: Downpipe[] = [{ config: { id: "dp-detached", source: { type: "kv", accountId: "acct-z", binding: "GONE_NOW_KV" } } }];
    const byDownpipe: Record<string, Row[]> = { "dp-detached": [{ status: "ok", index: 9, startedAt: "2026-06-01T00:00:00.000Z", recordCount: 42, bytes: 4_200 }] };
    const est = await computeEstateRollup(stub(downpipes, byDownpipe));
    ok("a detached-binding downpipe's last successful run still counts in full", est !== null && est.totalProtectedBytes === 4_200 && est.byType["kv"]?.records === 42 && est.accounts === 1);
  }

  console.log("\nmostRecentOk picks the GREATEST index, independent of array order or interleaved statuses:");
  {
    // Rows deliberately out of chronological order and interleaved with non-ok statuses, so a naive
    // "first ok" or "last ok in array order" pick would get the wrong one; only the greatest `index`
    // (the monotonic run identity) may win.
    const downpipes: Downpipe[] = [{ config: { id: "dp-shuffled", source: { type: "kv" } } }];
    const byDownpipe: Record<string, Row[]> = {
      "dp-shuffled": [
        { status: "ok", index: 4, startedAt: "2026-07-01T00:00:00.000Z", recordCount: 4, bytes: 400 },
        { status: "failed", index: 6, startedAt: "2026-07-02T00:00:00.000Z" }, // a LATER index but not "ok"
        { status: "ok", index: 2, startedAt: "2026-06-30T00:00:00.000Z", recordCount: 2, bytes: 200 }, // an EARLIER ok, out of order
        { status: "ok", index: 5, startedAt: "2026-07-03T00:00:00.000Z", recordCount: 5, bytes: 500 }, // the true winner
      ],
    };
    const est = await computeEstateRollup(stub(downpipes, byDownpipe));
    ok("the highest-index OK row wins regardless of array position (index 5, not 4 or 2)", est !== null && est.totalProtectedBytes === 500 && est.byType["kv"]?.records === 5);
    ok("asOf is the winning row's own startedAt (2026-07-03), not the latest row in the array (which was failed)", est?.asOf === "2026-07-03T00:00:00.000Z");
  }

  console.log("\na winning row missing recordCount/bytes/startedAt degrades those fields to 0/omitted, never throws:");
  {
    const downpipes: Downpipe[] = [{ config: { id: "dp-bare", source: { type: "kv" } } }];
    const byDownpipe: Record<string, Row[]> = { "dp-bare": [{ status: "ok", index: 1 }] }; // no recordCount/bytes/startedAt at all
    const est = await computeEstateRollup(stub(downpipes, byDownpipe));
    ok("a bare ok row contributes 0 bytes/records and leaves asOf null (no valid startedAt anywhere)", est !== null && est.totalProtectedBytes === 0 && est.byType["kv"]?.records === 0 && est.asOf === null);
  }

  console.log("\nmalformed roster rows are skipped defensively, never crash the aggregation:");
  {
    const goodDownpipe: Downpipe = { config: { id: "dp-good", source: { type: "kv" } } };
    const malformed: unknown[] = [
      goodDownpipe,
      { config: { id: "dp-no-source" } }, // config present, source missing entirely
      { config: { id: "dp-null-source", source: null } }, // source explicitly null
      { config: { id: "dp-string-source", source: "not-an-object" } }, // source not an object
      { config: { id: 123, source: { type: "kv" } } }, // id present but not a string
      { config: { id: "dp-numeric-type", source: { type: 7 } } }, // source.type present but not a string
      { config: { id: "dp-empty-type", source: { type: "" } } }, // source.type is an empty string
      { config: null }, // config not an object
      { notConfig: true }, // no config field at all
      "just a string",
      null,
      42,
    ];
    const s = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/downpipes") return new Response(JSON.stringify(malformed));
        if (url.pathname === "/history") return new Response(JSON.stringify({ byDownpipe: { "dp-good": [{ status: "ok", index: 1, startedAt: "2026-07-01T00:00:00.000Z", recordCount: 1, bytes: 10 }] } }));
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const est = await computeEstateRollup(s);
    ok("only the well-formed row is counted; every malformed shape is silently dropped, not thrown", est !== null && est.downpipes === 1 && est.totalProtectedBytes === 10);
  }

  console.log("\na source.type of '__proto__' is a plain, isolated byType key -- never prototype pollution:");
  {
    // A hostile or corrupted source.type of "__proto__" must not exploit byType's `in`/assignment
    // semantics: on a PLAIN object `{}`, `"__proto__" in {}` is true (inherited) and `obj["__proto__"] =
    // x` repoints the object's own prototype instead of creating a normal key, which would both skip
    // this type's own {records,bytes} init and leak into every other plain object in the isolate for
    // the rest of its lifetime. Object.prototype is captured before and after to prove nothing leaked.
    const beforeRecords = (Object.prototype as unknown as { records?: unknown }).records;
    const beforeBytes = (Object.prototype as unknown as { bytes?: unknown }).bytes;
    const downpipes: Downpipe[] = [{ config: { id: "dp-proto", source: { type: "__proto__" } } }];
    const byDownpipe: Record<string, Row[]> = { "dp-proto": [{ status: "ok", index: 1, startedAt: "2026-07-01T00:00:00.000Z", recordCount: 3, bytes: 300 }] };
    const est = await computeEstateRollup(stub(downpipes, byDownpipe));
    ok(
      "a '__proto__' source.type is aggregated as an ordinary, isolated byType key",
      est !== null && est.totalProtectedBytes === 300 && est.byType["__proto__"]?.records === 3 && est.byType["__proto__"]?.bytes === 300,
    );
    ok(
      "Object.prototype itself is untouched (no records/bytes leaked onto every plain object in the isolate)",
      (Object.prototype as unknown as { records?: unknown }).records === beforeRecords &&
        (Object.prototype as unknown as { bytes?: unknown }).bytes === beforeBytes &&
        !("records" in ({} as Record<string, unknown>)) &&
        !("bytes" in ({} as Record<string, unknown>)),
    );
  }

  console.log("\na /downpipes response that is not an array degrades to an empty roster, never throws:");
  {
    const s = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/downpipes") return new Response(JSON.stringify({ not: "an array" }));
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const est = await computeEstateRollup(s);
    ok("a non-array /downpipes body resolves to a real, empty rollup (not null)", est !== null && est.downpipes === 0);
  }

  console.log("\na DO fault anywhere resolves the WHOLE rollup to null (never a thrown error, never a partial number):");
  {
    const downpipes: Downpipe[] = [{ config: { id: "dp-x", source: { type: "kv" } } }];
    const estDownpipesFault = await computeEstateRollup(stub(downpipes, {}, "/downpipes"));
    ok("a /downpipes fetch fault -> null", estDownpipesFault === null);
    const estHistoryFault = await computeEstateRollup(stub(downpipes, {}, "/history"));
    ok("a /history fetch fault -> null", estHistoryFault === null);

    // A stub whose .fetch itself throws synchronously (not just an async rejection) must be caught too.
    const throwingStub = {
      fetch(): Promise<Response> {
        throw new Error("synchronous DO stub failure");
      },
    } as unknown as DurableObjectStub;
    const estSyncThrow = await computeEstateRollup(throwingStub);
    ok("a synchronously-throwing scheduler stub -> null (never propagates)", estSyncThrow === null);

    // Malformed JSON on either route must also degrade to null, never throw out of the caller.
    const badJsonStub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/downpipes") return new Response("not json");
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const estBadJson = await computeEstateRollup(badJsonStub);
    ok("malformed JSON on /downpipes -> null (the .json() parse throw is caught)", estBadJson === null);
  }

  console.log(failures === 0 ? "\nALL ESTATE ROLLUP VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
