// Meter is the subrequest accounting hook the sliced seal threads through the data path
// (design F13): every platform subrequest a source or destination makes (a list page, a
// value get, a put, a multipart part) is reported so a slice can yield before the
// per-invocation cap kills it. It lives in its own module because both the source layer
// and the destination layer report into it and neither should depend on the other.
// spend never throws; budget pressure is observed between records, never mid-call.
//
// COST (design/cost-engine Phase 3): the optional `op` tag lets a spend record WHICH
// Cloudflare resource it was, so a run keeps an EXACT per-resource operation count for the
// cost estimate, not only a subrequest total. Counts only, never content; no-custody holds.

// CfOp tags a metered subrequest by the Cloudflare resource + operation class it represents. The set is
// what the data path can OBSERVE (source reads + archive writes + control-plane reads); Worker requests,
// Worker CPU and Durable Object duration are NOT subrequests and are not seen here, so they are not tagged.
//   - kvRead / kvList: Workers KV get / list.
//   - r2ClassA: R2 mutation class (PUT, multipart part, LIST).
//   - r2ClassB: R2 read class (GET, HEAD).
//   - d1Read: a D1 read query.
//   - cfApiRead: a Cloudflare REST API read (cf-config / workers / stream / images): rate-limited
//     capacity, not a billed data operation.
//   - secretsRead: a Secrets Store get.
export type CfOp = "kvRead" | "kvList" | "r2ClassA" | "r2ClassB" | "d1Read" | "cfApiRead" | "secretsRead";

// OpCounts is the per-run tally of metered subrequests by resource, plus the grand total. subrequests is
// every metered subrequest (>= the sum of the tagged fields; an untagged spend lands only there). It feeds
// the cost estimate's platform ledger so the "cost to run the backup" is exact rather than an over-estimate.
export interface OpCounts {
  kvRead: number;
  kvList: number;
  r2ClassA: number;
  r2ClassB: number;
  d1Read: number;
  cfApiRead: number;
  secretsRead: number;
  subrequests: number;
}

// zeroOpCounts is the additive identity (a fresh all-zero tally).
export function zeroOpCounts(): OpCounts {
  return { kvRead: 0, kvList: 0, r2ClassA: 0, r2ClassB: 0, d1Read: 0, cfApiRead: 0, secretsRead: 0, subrequests: 0 };
}

// addOpCounts returns the element-wise sum of two tallies (pure), used to accumulate a slice's ops into
// the run's running total across the checkpoint.
export function addOpCounts(a: OpCounts, b: OpCounts): OpCounts {
  return {
    kvRead: a.kvRead + b.kvRead,
    kvList: a.kvList + b.kvList,
    r2ClassA: a.r2ClassA + b.r2ClassA,
    r2ClassB: a.r2ClassB + b.r2ClassB,
    d1Read: a.d1Read + b.d1Read,
    cfApiRead: a.cfApiRead + b.cfApiRead,
    secretsRead: a.secretsRead + b.secretsRead,
    subrequests: a.subrequests + b.subrequests,
  };
}

export interface Meter {
  // spend reports n platform subrequests (default 1). The optional op tags them by Cloudflare resource so
  // the run keeps an exact per-resource count; an untagged spend still counts toward the subrequest total.
  spend(n?: number, op?: CfOp): void;
}
