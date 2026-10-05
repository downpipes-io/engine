// Leaf module of shared format types, extracted to break import cycles between
// reader.ts and freshness.ts. Type-only; no runtime behaviour lives here.

/**
 * The read side of a destination: a single get(key) returning the object's bytes (a local dir for
 * tests, an S3 or R2 client in the engine). It is the read interface the verifying reader and the
 * freshness check depend on.
 */
export interface ObjectStore {
  get(key: string): Promise<Uint8Array>;
  // list enumerates the object keys under a prefix (paging internally so the caller sees the complete
  // set in one call), for a SMALL, bounded prefix (a single run's run/<runId>/manifest/ tree). It is
  // OPTIONAL: the verifying reader and the freshness check need only get(); the at-seal shard-completeness
  // cross-check (keyless.ts, RL-VAS-05) uses it, when present, to confirm by NAME that every signed shard
  // object EXISTS -- so a durably-missing shard OUTSIDE the strided read-back sample is still caught -- with
  // ONE list per run rather than N per-shard GETs. A store that cannot list (a minimal test/offline double)
  // omits it and the sampled branch keeps only its strided GET spot-checks (the always-full path reads every
  // shard regardless). Keys are returned as a set; order is not load-bearing.
  list?(prefix: string): Promise<string[]>;
}
