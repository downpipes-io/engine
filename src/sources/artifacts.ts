// Cloudflare Artifact Registry source: snapshots the account's artifact NAMESPACES and the REPOS
// within them as an inventory, one record per repo (name = "<namespace>/<repo>", value = the repo
// metadata). Like cf-config/workers/stream/images (and UNLIKE the binding sources), it reads the
// Cloudflare REST API with the engine's read-only discovery token; account-scoped, no binding.
//
// SCOPE: ALWAYS the namespace + repo INVENTORY/metadata, one record per repo (a 2-level namespaces ->
// repos expand, like expandRulesets), so it streams record-by-record and scales like KV. When the
// downpipe opts in (includeContent), ALSO the repo CONTENTS via the git-style content API: the commit
// log, every commit + reachable tree, and each reachable blob's bytes (size-gated). Cloudflare Artifact
// Registry is a git registry, so contents are content-addressed objects:
//   - "<ns>/<repo>/log": the commit/ref log (one record).
//   - "<ns>/<repo>/commit/<hash>", "<ns>/<repo>/tree/<hash>": every commit + reachable tree object.
//   - "<ns>/<repo>/blob/<hash>": each reachable file blob's bytes.
// The walk covers the FULL history (every commit in the log), not just HEAD. It is BOUNDED (a per-repo
// object cap with an honest "_truncated" marker) and dedups objects by hash. Per-repo push TOKENS
// (.../repos/{name}/tokens) are value-bearing and NOT captured. Metadata-only is the default.
//
// RESTORE is REPROVISION (like stream/images/workers): the snapshot proves the namespace/repo inventory
// (and, with content, the objects) are recoverable; the operator re-creates + re-pushes deliberately.
// resolveSink has no artifacts sink (-> reprovision); the Go reader's ReprovisionSourceType is true.
//
// FAIL-OPEN: a per-namespace repo list that throws degrades that one namespace WITH AN HONEST
// "<namespace>/_unavailable" MARKER (so the run reports recordsIncomplete > 0, never a silent drop of
// the namespace's repos, R1-1/A1); each per-repo content walk and each per-blob fetch is fail-open (a
// marker, never a void run); the namespaces list throws loudly on a broken token (a broken token is
// not a per-namespace gap).

import { captureBlob, type MediaContentOpts } from "./byte-fetch.ts";
import { type CfApi, paginate } from "./cf-config-surfaces.ts";
import { inScope } from "./selector.ts";
import { classifySourceFaultReason, faultItemId, recordIncompleteFault, recordResumeTokenDefect, recordShapeAnomaly } from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";

// A per-repo ceiling on the number of content objects (commits + trees + blobs) the walk captures, so a
// pathological repo cannot spin unbounded; past it an honest "_truncated" marker is emitted, never a
// silent drop. Far above a normal repo's working-tree object count.
export const ARTIFACTS_MAX_OBJECTS = 5000;

// Encoder is the JSON-to-bytes helper threaded through the content walk.
type Encoder = (s: string) => Uint8Array;

// BudgetLike is the structural slice of the Meter the sliced seal actually passes (a SliceBudget): it
// exposes shouldYield() so a long INTRA-repo content walk can checkpoint mid-walk instead of running to
// the platform subrequest cap and wedging the run (A2). The validator's plain Meter has no shouldYield,
// so wantsYield() returns false there and the walk runs whole, exactly as it did before this fix.
interface BudgetLike {
  shouldYield(): boolean;
}

// wantsYield reports whether the meter is a budget under pressure (its shouldYield() is true). A plain
// Meter (no shouldYield) is never under pressure here, so the walk runs to completion in one pass.
function wantsYield(meter: Meter | undefined): boolean {
  const b = meter as Partial<BudgetLike> | undefined;
  return typeof b?.shouldYield === "function" && b.shouldYield();
}

// WalkCtx encapsulates the per-repo content-walk context so the walk helpers take a single context
// parameter instead of passing base/recName/enc/seen/budget/meter individually (the 7-parameter shape
// the guardrail flags). `seen` dedups objects by hash GLOBALLY across the repo's whole history and
// `budget` is the shared remaining-object holder, both shared by reference across commits and trees.
//
// RESUMABILITY (A2): the content walk is deterministic in its record order (the commit log order, then
// each commit's depth-first tree walk), so a slice that ran out of platform budget mid-walk resumes by
// re-running the SAME walk and SKIPPING every content record up to and including the watermark
// (`skipContentUntil`). `passedContentSkip` flips true once that watermark is crossed; until then records
// are counted into `seen`/`budget` exactly as the first pass did (so dedup + the object cap stay
// correct) but NOT yielded. `pressure()` reports whether the slice budget is low, so the walk emits an
// intra-repo {mark} (and the slice checkpoints) at a fine granularity (per content record) rather than
// only at the coarse per-repo boundary.
interface WalkCtx {
  base: string; // the repo's API base path
  recName: string; // "<namespace>/<repo>", the record-name prefix
  enc: Encoder;
  seen: Set<string>; // hashes already captured (commits, trees, blobs), shared across the history
  budget: { n: number }; // remaining object budget, decremented as objects are captured
  meter?: Meter;
  passedContentSkip: boolean; // false while replaying a resumed walk up to the watermark; true once past it
  skipContentUntil?: string; // the content record name (e.g. "<ns>/<repo>/blob/<hash>") to resume after
  pressure: () => boolean; // true when the slice budget wants the walk to checkpoint and yield
  // prevRepoRecName is the "<ns>/<repo>" of the last repo whose records were ALL yielded (the repo BEFORE
  // this one), recorded as an intra-repo mark's afterRecName so a resume skips repos up to it then re-enters
  // THIS repo via the inRepo cursor. Empty when this is the first in-scope repo of the crawl.
  prevRepoRecName: string;
}

// RepoTarget identifies one repo to walk: its namespace, repo name, and the "<ns>/<repo>" record prefix.
interface RepoTarget {
  ns: string;
  repo: string;
  recName: string;
}

// ArtifactsToken is the resume cursor (R2-3 + A2): `afterRecName`, the "<ns>/<repo>" of the last repo
// whose records were ALL yielded; a resume re-lists the namespaces and repos in the same API order and
// skips every repo up to and including afterRecName, so no already-yielded repo is re-read.
//
// A2 (HIGH, can wedge a run): the per-repo content walk is itself bounded by ARTIFACTS_MAX_OBJECTS but a
// repo whose object cap is high can still exceed ONE invocation's subrequest budget; the coarse per-repo
// mark never fires inside that walk, so the run runs to the platform cap and wedges/restarts with no
// progress. So the walk also checkpoints WITHIN a repo: the optional `inRepo` cursor records the repo
// recName and `afterContent`, the content record name (e.g. "<ns>/<repo>/blob/<hash>") AFTER which to
// resume. On resume the walk re-runs that repo deterministically and skips every content record up to
// and including `afterContent` (rebuilding the dedup set + object budget as it replays), then continues.
// The resume granularity is the content record. No value bytes are ever in the token.
interface ArtifactsToken {
  afterRecName: string;
  inRepo?: { recName: string; afterContent: string };
}

// parseArtifactsToken parses a persisted resume token and asserts its shape, mirroring workers.ts's
// parseWorkersToken. A corrupt token would silently restart the whole crawl, so a malformed token throws.
// The optional `inRepo` mid-repo cursor is validated only when present (an absent cursor = resume at the
// repo boundary, the R2-3 behaviour); a present-but-malformed cursor throws rather than silently restart.
function parseArtifactsToken(token: string): ArtifactsToken {
  // G213: the raw JSON.parse SyntaxError matched no coarse-error branch, so a wedged downpipe (every slice
  // failing on the same corrupt token) read as a generic "run failed" with no route to its known remedy.
  // Each defect is recorded under its CLOSED class; the token bytes never are.
  let t: ArtifactsToken;
  try {
    t = JSON.parse(token) as ArtifactsToken;
  } catch {
    recordResumeTokenDefect("artifacts", "unparseable");
    throw new Error("malformed Artifacts resume token (unparseable)");
  }
  if (typeof t !== "object" || t === null || typeof t.afterRecName !== "string") {
    recordResumeTokenDefect("artifacts", "bad-shape");
    throw new Error("malformed Artifacts resume token");
  }
  if (t.inRepo !== undefined && (typeof t.inRepo.recName !== "string" || typeof t.inRepo.afterContent !== "string")) {
    recordResumeTokenDefect("artifacts", "bad-cursor");
    throw new Error("malformed Artifacts resume token (inRepo cursor)");
  }
  return t;
}

// ArtifactsSource is RESUMABLE: crawlFrom emits a {mark} after each fully-yielded repo (its inventory
// record plus, with content, its whole git-object walk), so the sliced seal can checkpoint between repos
// and span invocations the way it does WorkersSource. crawl() is the whole-crawl form.
export class ArtifactsSource implements SourceAdapter, ResumableSource {
  readonly sourceType = "artifacts" as const;
  readonly accountId: string;
  private api: CfApi;
  private content: MediaContentOpts;

  constructor(accountId: string, api: CfApi, content?: MediaContentOpts) {
    this.accountId = accountId;
    this.api = api;
    this.content = content ?? {};
  }

  private captureBytes(): boolean {
    return this.content.includeContent === true && this.content.bytes !== undefined;
  }

  private acct(): string {
    return encodeURIComponent(this.accountId);
  }

  private repoBase(ns: string, repo: string): string {
    return `/accounts/${this.acct()}/artifacts/namespaces/${encodeURIComponent(ns)}/repos/${encodeURIComponent(repo)}`;
  }

  // crawl() is the whole-crawl form: it delegates to crawlFrom(selector, null, meter) and drops the
  // marks, preserving the same yield-records behaviour over a full pass. The sliced seal uses crawlFrom
  // directly (it needs the marks to checkpoint between repos).
  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null, meter)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // crawlFrom is the RESUMABLE crawl. A null token starts a fresh 2-level crawl (namespaces -> repos);
  // a token re-lists the namespaces and repos in the same API order and skips every repo up to and
  // including the recorded "<ns>/<repo>" watermark, so no already-yielded repo is re-read. It emits a
  // {mark} AFTER each fully-yielded repo (its inventory record plus, with content, its whole bounded
  // git-object walk), so a slice can checkpoint between repos and span invocations rather than throwing
  // "source too large for one slice" with no progress.
  //
  // A2: the per-repo content walk ALSO checkpoints WITHIN a repo. A single repo's content walk can exceed
  // one invocation's subrequest budget (the object cap is high), so the walk emits an INTRA-repo {mark}
  // after a content record whenever the slice budget is low (pressure()), carrying an `inRepo` cursor. A
  // resume whose token has an `inRepo` cursor re-lists to that repo and replays its content walk, skipping
  // every content record up to and including the cursor (rebuilding the dedup set + object budget as it
  // replays so dedup and the cap stay correct), then continues. The repo's inventory record is NOT
  // re-yielded on such a resume (it was yielded in the slice that first reached the repo).
  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const resume = token === null ? null : parseArtifactsToken(token);
    const textEncoder = new TextEncoder();
    const enc = (s: string): Uint8Array => textEncoder.encode(s);
    // passedSkip walks past every repo up to and including the recorded watermark before yielding. The
    // namespaces and repos are re-listed in the same API order on resume, so the watermark is well-defined.
    // An EMPTY afterRecName means there is NO prior repo to skip (the interrupted repo was the first
    // in-scope repo of the crawl), so a resume whose repo watermark is "" starts already past the skip and
    // re-enters the very first in-scope repo via the inRepo cursor below.
    const skipUntil = resume === null || resume.afterRecName === "" ? undefined : resume.afterRecName;
    let passedSkip = skipUntil === undefined;
    // inRepoResume, when present, names the repo whose content walk was interrupted mid-slice and the
    // content record AFTER which to resume it. It applies to the FIRST in-scope repo encountered past the
    // repo watermark (which, by construction, is that repo).
    const inRepoResume = resume?.inRepo;
    // prevRepoRecName tracks the last repo whose records were ALL yielded, so an intra-repo {mark} can name
    // the correct repo-skip watermark. On a resume it begins at the repo watermark (the previous repo is
    // exactly afterRecName); on a fresh crawl it is empty until the first repo completes.
    let prevRepoRecName = skipUntil ?? "";
    const namespaces = (await paginate(this.api, `/accounts/${this.acct()}/artifacts/namespaces`, meter)) as Array<{ name?: string; id?: string }>;
    for (const ns of namespaces) {
      const nsName = ns?.name ?? ns?.id;
      // G110: a namespace the API returned WITHOUT a recognised name field is skipped ENTIRELY -- every repo,
      // every commit, every blob in it is absent from the archive and the run still reports ok. Count the drop.
      if (typeof nsName !== "string") { recordShapeAnomaly("artifacts:namespace"); continue; }
      let repos: unknown[];
      try {
        repos = await paginate(this.api, `/accounts/${this.acct()}/artifacts/namespaces/${encodeURIComponent(nsName)}/repos`, meter);
      } catch (e) {
        // Fail-open WITH AN HONEST MARKER (R1-1, A1): a namespace whose repo list cannot be read (a 5xx
        // that survived retry, a scope gap, or an inner CfPaginationTruncated) would otherwise SILENTLY
        // drop every repo in that namespace from the archive with no signal and the run would still report
        // "ok". Instead emit a "<namespace>/_unavailable" sentinel record (the same shape stream/images emit,
        // carrying markerKind: "_unavailable" so the seal's recordsIncomplete counter detects it from OUR
        // assertion, not by sniffing the value), so the run reports recordsIncomplete > 0 and the operator is
        // told the namespace is short, never a silent gap. The marker is yielded only past the resume
        // watermark (it is a record, so a slice that ended before this namespace re-reaches it on resume; one
        // that already passed it does not re-emit).
        // G015: the CLOSED reason class for this namespace's shortfall (auth / not-found / server-error /
        // page-cap), recorded whether or not the marker record is emitted on this pass (a resumed slice past
        // the watermark suppresses the record, but the fault still happened and must still be diagnosable).
        const nsReason = classifySourceFaultReason(e);
        recordIncompleteFault("_unavailable", nsReason, { id: await faultItemId("artifacts:repos", nsName) });
        if (passedSkip) {
          yield {
            kind: "record",
            record: { sourceType: "artifacts", name: `${nsName}/_unavailable`, value: enc(JSON.stringify({ _unavailable: `namespace repo list could not be read: ${e instanceof Error ? e.message : String(e)}` })), markerKind: "_unavailable", markerReason: nsReason },
          };
        }
        continue; // degrade just this namespace; the others are still crawled
      }
      for (const repo of repos as Array<{ name?: string; id?: string }>) {
        const rName = repo?.name ?? repo?.id;
        if (typeof rName !== "string") continue;
        const recName = `${nsName}/${rName}`;
        // Resume skip: walk past every repo up to and including the recorded watermark before yielding.
        if (!passedSkip) {
          if (recName === skipUntil) passedSkip = true;
          continue;
        }
        if (!inScope(recName, selector)) continue;
        // A mid-repo resume re-enters THIS repo's content walk skipping the already-yielded content
        // records; its inventory record + the prior repos' marks were yielded in the earlier slice, so do
        // not re-yield the inventory here. `skipContentUntil` drives the content-walk replay below.
        const midRepo = inRepoResume?.recName === recName ? inRepoResume.afterContent : undefined;
        if (midRepo === undefined) {
          yield { kind: "record", record: { sourceType: "artifacts", name: recName, value: enc(JSON.stringify({ namespace: nsName, repo })) } };
        }
        // Optional repo CONTENTS: the log + every commit/tree object + reachable blob bytes (bounded). The
        // content walk yields records AND intra-repo {mark}s (A2): a {mark} carrying an `inRepo` cursor is
        // emitted after a content record when the slice budget is low, so the slice can checkpoint mid-repo
        // and resume the walk on the next invocation rather than running to the platform cap and wedging.
        if (this.captureBytes()) {
          yield* this.repoContent({ ns: nsName, repo: rName, recName }, enc, meter, prevRepoRecName, midRepo);
        }
        // Mark AFTER all of this repo's records: a slice may end here and resume after this repo. This
        // carries no inRepo cursor, so the next slice starts at the next repo's inventory record cleanly.
        yield { kind: "mark", token: JSON.stringify({ afterRecName: recName } satisfies ArtifactsToken) };
        prevRepoRecName = recName; // this repo is now fully yielded; the next intra-repo mark skips up to it
      }
    }
  }

  // emit yields ONE content record through the resume-skip + intra-repo checkpoint discipline (A2). While
  // replaying a resumed walk (passedContentSkip false) it SUPPRESSES the record (the slice already sealed
  // it) and only flips passedContentSkip once the watermark content name is reached. Past the watermark it
  // yields the record, then, if the slice budget is low (pressure()), emits an intra-repo {mark} carrying
  // the `inRepo` cursor so the slice can checkpoint here and the next invocation resumes the walk after
  // this exact content record. The {mark} is NEVER emitted while replaying (a resumed slice must reach new
  // work before it can checkpoint again) nor for a record before the watermark.
  private *emit(ctx: WalkCtx, rec: SourceRecord): Generator<CrawlEvent> {
    if (!ctx.passedContentSkip) {
      if (rec.name === ctx.skipContentUntil) ctx.passedContentSkip = true;
      return; // replaying up to (and including) the watermark: do not re-yield
    }
    yield { kind: "record", record: rec };
    if (ctx.pressure()) {
      // An intra-repo checkpoint: the repo-skip watermark is the PREVIOUS fully-yielded repo (so the resume
      // re-lists and skips up to it), and the inRepo cursor re-enters THIS repo's walk after this exact
      // content record. afterRecName must name a repo strictly BEFORE this one (naming this repo would skip
      // it entirely); prevRepoRecName is exactly that, set by crawlFrom as it advances repo to repo.
      yield { kind: "mark", token: JSON.stringify({ afterRecName: ctx.prevRepoRecName, inRepo: { recName: ctx.recName, afterContent: rec.name } } satisfies ArtifactsToken) };
    }
  }

  // repoContent walks a repo's git objects across the FULL history (every commit in the log, not just
  // HEAD) and yields content records: the commit log, each commit + its reachable trees (as JSON
  // metadata), and each reachable file blob's bytes (size-gated). Blobs/trees/commits are deduped GLOBALLY
  // by hash, so a blob shared across many commits is captured once and history adds only its deltas.
  // Bounded by ARTIFACTS_MAX_OBJECTS (a shared budget across all commits) with an honest "_truncated"
  // marker; every step is fail-open (an unreadable log/commit/tree/blob leaves a marker, never a void run).
  //
  // A2: it yields CrawlEvent (records + intra-repo {mark}s) and honours `skipContentUntil`: on a mid-repo
  // resume it replays the SAME deterministic walk, suppressing every content record up to and including the
  // watermark (so the dedup set + object budget are rebuilt identically) before resuming live yields.
  private async *repoContent(target: RepoTarget, enc: Encoder, meter: Meter | undefined, prevRepoRecName: string, skipContentUntil?: string): AsyncIterable<CrawlEvent> {
    const { recName } = target;
    const base = this.repoBase(target.ns, target.repo);
    const ctx: WalkCtx = {
      base,
      recName,
      enc,
      seen: new Set<string>(),
      budget: { n: ARTIFACTS_MAX_OBJECTS },
      ...(meter !== undefined ? { meter } : {}),
      passedContentSkip: skipContentUntil === undefined,
      ...(skipContentUntil !== undefined ? { skipContentUntil } : {}),
      pressure: () => wantsYield(meter),
      prevRepoRecName,
    };
    // 1. The commit/ref log: the history to walk.
    let log: unknown;
    try {
      meter?.spend(1, "cfApiRead");
      log = await this.api.get(`${base}/log`);
      yield* this.emit(ctx, { sourceType: "artifacts", name: `${recName}/log`, value: enc(JSON.stringify({ log })) });
    } catch (e) {
      const logReason = classifySourceFaultReason(e); // G015: an unreadable commit log costs the WHOLE history
      recordIncompleteFault("_unavailable", logReason, { id: await faultItemId("artifacts:log", recName) });
      yield* this.emit(ctx, { sourceType: "artifacts", name: `${recName}/log`, value: enc(JSON.stringify({ _unavailable: e instanceof Error ? e.message : String(e) })), markerKind: "_unavailable", markerReason: logReason });
      return; // without the log there is nothing to walk from; the inventory record already captured the repo
    }
    const commits = this.commitHashes(log);
    // G110: the log parsed, but NOT into any shape we recognise (neither an array nor {commits:[...]}, or no
    // commit carried a hash/sha/id). commitHashes returns [] for BOTH that and a genuinely empty repo, and the
    // walk then returns silently: an ENTIRE commit history absent from the archive across months of green runs.
    // A repo whose log has content but yields no hashes is drift, not emptiness. Count it.
    if (commits.length === 0 && this.logHasEntries(log)) recordShapeAnomaly("artifacts:log-commits");
    if (commits.length === 0) return; // an empty repo (no commits): inventory + log only, nothing to walk
    // 2. Walk every commit -> tree -> blobs, with a SHARED dedup set + budget across the whole history.
    for (const commitHash of commits) {
      if (ctx.seen.has(commitHash)) continue;
      ctx.seen.add(commitHash);
      if (ctx.budget.n <= 0) {
        yield* this.emit(ctx, this.truncatedMarker(recName, enc));
        return;
      }
      let treeHash: string | undefined;
      try {
        meter?.spend(1, "cfApiRead");
        const commit = (await this.api.get(`${base}/commit/${encodeURIComponent(commitHash)}`)) as Record<string, unknown> | null;
        ctx.budget.n--;
        yield* this.emit(ctx, { sourceType: "artifacts", name: `${recName}/commit/${commitHash}`, value: enc(JSON.stringify({ commit })) });
        treeHash = this.treeHashOf(commit);
      } catch (e) {
        const commitReason = classifySourceFaultReason(e); // G015
        recordIncompleteFault("_unavailable", commitReason, { id: await faultItemId("artifacts:commit", recName) });
        yield* this.emit(ctx, { sourceType: "artifacts", name: `${recName}/commit/${commitHash}`, value: enc(JSON.stringify({ _unavailable: e instanceof Error ? e.message : String(e) })), markerKind: "_unavailable", markerReason: commitReason });
        continue; // a single unreadable commit never voids the rest of the history
      }
      if (treeHash === undefined) continue;
      const truncated = yield* this.walkTree(ctx, treeHash);
      if (truncated) return; // budget exhausted mid-walk; the marker was already yielded
    }
  }

  // truncatedMarker is the honest "stopped at the object cap" record (never a silent drop).
  private truncatedMarker(recName: string, enc: Encoder): SourceRecord {
    // G015: WHY the repo is short (the object-walk cap) and by HOW MUCH (objects walked), so the monorepo
    // question -- "is our repo fully backed up?" -- is answerable from the pack, not only from the archive.
    recordIncompleteFault("_truncated", "size-cap", { id: "artifacts:objects", pagesRead: 0, recordsAccumulated: ARTIFACTS_MAX_OBJECTS });
    return { sourceType: "artifacts", name: `${recName}/_truncated`, value: enc(JSON.stringify({ _truncated: `repo object walk exceeded ${ARTIFACTS_MAX_OBJECTS} objects` })), markerKind: "_truncated", markerReason: "size-cap" };
  }

  // walkTree walks one commit's tree (iterative, a stack of tree hashes), capturing blobs as it goes, with
  // the shared `seen` dedup set + `budget` holder so the whole-history walk stays bounded. Returns true if
  // the budget was exhausted (a "_truncated" marker was yielded and the caller should stop); false on a
  // clean finish. Fail-open per tree.
  private async *walkTree(ctx: WalkCtx, rootTree: string): AsyncGenerator<CrawlEvent, boolean> {
    const { base, recName, enc, seen, budget, meter } = ctx;
    const stack: string[] = [rootTree];
    while (stack.length > 0) {
      if (budget.n <= 0) {
        yield* this.emit(ctx, this.truncatedMarker(recName, enc));
        return true;
      }
      const th = stack.pop()!;
      if (seen.has(th)) continue;
      seen.add(th);
      let entries: Array<{ type?: unknown; hash?: unknown; name?: unknown }> = [];
      try {
        meter?.spend(1, "cfApiRead");
        const tree = (await this.api.get(`${base}/tree/${encodeURIComponent(th)}`)) as Record<string, unknown> | null;
        budget.n--;
        yield* this.emit(ctx, { sourceType: "artifacts", name: `${recName}/tree/${th}`, value: enc(JSON.stringify({ tree })) });
        entries = this.treeEntries(tree);
      } catch (e) {
        yield* this.emit(ctx, { sourceType: "artifacts", name: `${recName}/tree/${th}`, value: enc(JSON.stringify({ _unavailable: e instanceof Error ? e.message : String(e) })), markerKind: "_unavailable", markerReason: classifySourceFaultReason(e) });
        continue;
      }
      for (const ent of entries) {
        const hash = typeof ent?.hash === "string" ? ent.hash : undefined;
        if (hash === undefined || seen.has(hash)) continue;
        const isTree = ent?.type === "tree" || ent?.type === "dir";
        if (isTree) {
          stack.push(hash);
          continue;
        }
        // A blob (file): capture its bytes, size-gated, deduped, fail-open.
        seen.add(hash);
        if (budget.n <= 0) {
          yield* this.emit(ctx, this.truncatedMarker(recName, enc));
          return true;
        }
        budget.n--;
        yield* this.blob(ctx, hash);
      }
    }
    return false;
  }

  // blob captures one git blob's bytes (GET .../blob/{hash}) as a "<recName>/blob/<hash>" record,
  // size-gated by captureBlob; per-blob fail-open (a marker, never a void run). On a mid-repo resume replay
  // (A2) a blob record before the content watermark is suppressed by emit() (the slice already sealed it),
  // but the fetch is skipped first when possible: emit() suppresses the yield, yet to avoid re-spending the
  // platform budget on a blob whose record will be discarded, the replay short-circuits the byte fetch for
  // a name at or before the watermark and only the metadata records (log/commit/tree) are re-read to rebuild
  // the dedup set. Here, a blob whose name will be suppressed still skips its byte fetch.
  private async *blob(ctx: WalkCtx, hash: string): AsyncIterable<CrawlEvent> {
    const { base, recName, enc, meter } = ctx;
    const fetcher = this.content.bytes;
    if (fetcher === undefined) return;
    const name = `${recName}/blob/${hash}`;
    // Replay short-circuit: while replaying a resumed walk (passedContentSkip false) a blob's bytes would
    // be fetched only to be discarded by emit(); skip the fetch and emit a placeholder the suppression
    // consumes (it advances the watermark check without a value). This keeps replay cheap on subrequests.
    if (!ctx.passedContentSkip) {
      yield* this.emit(ctx, { sourceType: "artifacts", name, value: enc("") });
      return;
    }
    try {
      const cap = await captureBlob(fetcher, { url: `${base}/blob/${encodeURIComponent(hash)}` }, meter, { resumable: this.content.resumable ?? true });
      if (cap.skip) {
        yield* this.emit(ctx, { sourceType: "artifacts", name, value: enc(JSON.stringify({ _skipped: cap.skip.reason, size: cap.skip.size })), markerKind: "_skipped", markerReason: "size-cap" }); // G015: the size ceiling
      } else if (cap.stream) {
        yield* this.emit(ctx, { sourceType: "artifacts", name, stream: cap.stream });
      } else {
        yield* this.emit(ctx, { sourceType: "artifacts", name, value: cap.value ?? new Uint8Array(0) });
      }
    } catch (e) {
      yield* this.emit(ctx, { sourceType: "artifacts", name, value: enc(JSON.stringify({ _unavailable: e instanceof Error ? e.message : String(e) })), markerKind: "_unavailable", markerReason: classifySourceFaultReason(e) }); // G015
    }
  }

  // commitHashes extracts EVERY commit hash from the log response (newest-first as the API returns them),
  // tolerating the documented shapes (an array of commits, or {commits:[...]}, each commit a string hash
  // or {hash}/{sha}/{id}). The full list drives the whole-history walk; the caller dedups.
  private commitHashes(log: unknown): string[] {
    const arr = Array.isArray(log) ? log : Array.isArray((log as { commits?: unknown })?.commits) ? (log as { commits: unknown[] }).commits : [];
    const out: string[] = [];
    for (const c of arr) {
      if (typeof c === "string") { if (c !== "") out.push(c); continue; }
      const o = c as { hash?: unknown; sha?: unknown; id?: unknown } | undefined;
      for (const v of [o?.hash, o?.sha, o?.id]) {
        if (typeof v === "string" && v !== "") { out.push(v); break; }
      }
    }
    return out;
  }

  // logHasEntries reports whether the log response CONTAINED entries at all, so a commitHashes() result of []
  // can be told apart from a genuinely empty repo (G110): entries present but no hash extracted is API-shape
  // drift that would otherwise archive a whole history as "empty" with a clean ok. It reads the shape only.
  private logHasEntries(log: unknown): boolean {
    if (Array.isArray(log)) return log.length > 0;
    const c = (log as { commits?: unknown } | null)?.commits;
    return Array.isArray(c) && c.length > 0;
  }

  // treeHashOf reads a commit object's root tree hash, tolerating {tree} as a string or {tree:{hash}}.
  private treeHashOf(commit: Record<string, unknown> | null): string | undefined {
    const t = commit?.tree;
    if (typeof t === "string") return t;
    const h = (t as { hash?: unknown } | undefined)?.hash;
    return typeof h === "string" ? h : undefined;
  }

  // treeEntries reads a tree object's child entries, tolerating {entries:[...]} or a bare array, each
  // entry carrying a type ("tree"/"dir" vs a blob/file) and a hash.
  private treeEntries(tree: Record<string, unknown> | null): Array<{ type?: unknown; hash?: unknown; name?: unknown }> {
    const e = tree?.entries ?? tree?.children ?? tree;
    return Array.isArray(e) ? (e as Array<{ type?: unknown; hash?: unknown; name?: unknown }>) : [];
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    // A rough floor for the cost projection: at least one repo per namespace. The exact count needs a
    // full 2-level crawl, which estimate must not do (it never reads values); the namespace count is the
    // cheap upper-bound signal.
    try {
      const namespaces = (await paginate(this.api, `/accounts/${this.acct()}/artifacts/namespaces`)) as unknown[];
      // estimate cannot apply the selector without a full 2-level crawl, so the namespace floor is the
      // cheapest safe signal; a selector that scopes to a subset of repos may over-count here.
      void selector;
      return { records: namespaces.length, bytes: -1 };
    } catch {
      return { records: 0, bytes: -1 };
    }
  }
}
