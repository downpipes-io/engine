// MockStorage is the in-memory DurableObjectState["storage"] double the DO validators share, so a
// fix to its semantics (e.g. the JSON round-trip in put that mimics structured-clone, or the
// prefix list) lands in one place rather than in three diverging copies (finding engine-test-013-14).
// It implements the subset of the storage API the SchedulerDO and seal DOs use, plus a few raw
// helpers a validator uses to seed or inspect state directly.
export class MockStorage {
  private map = new Map<string, unknown>();

  // get/put/delete mirror the real storage. put deep-clones via a JSON round-trip so a stored value
  // cannot be mutated through the caller's reference, matching the structured-clone the platform does.
  // get supports BOTH platform overloads: a single key returns the value (or undefined), and an ARRAY
  // of keys returns a Map of the PRESENT keys to their values (absent keys omitted), which is the batch
  // form the DO's findRunRing read path uses (engine-src-038-03).
  async get<T>(key: string): Promise<T | undefined>;
  async get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
    if (Array.isArray(keyOrKeys)) {
      const out = new Map<string, T>();
      for (const k of keyOrKeys) if (this.map.has(k)) out.set(k, this.map.get(k) as T);
      return out;
    }
    return this.map.get(keyOrKeys) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  // delete supports BOTH platform overloads too (DurableObjectStorage.delete, workers-types): a single
  // key returns whether it existed, and an ARRAY of keys deletes each and returns the COUNT that
  // existed (not merely the array's length -- a key already absent does not count), the batch form
  // scheduler-do-routing-config.ts's demo-reset wipe uses to clear up to 1000 keys per round trip. A
  // narrower single-key-only double passed the array through map.delete() unchanged, which matched no
  // stored key and silently returned false/0 every time: the reset reported success and cleared nothing
  // (engine-test-013-14).
  async delete(key: string): Promise<boolean>;
  async delete(keys: string[]): Promise<number>;
  async delete(keyOrKeys: string | string[]): Promise<boolean | number> {
    if (Array.isArray(keyOrKeys)) {
      let n = 0;
      for (const k of keyOrKeys) if (this.map.delete(k)) n++;
      return n;
    }
    return this.map.delete(keyOrKeys);
  }

  // listCalls records the options of every list() call so a validator can assert a read strategy (e.g. that
  // a paged feed issues a BOUNDED list -- start + limit -- rather than an unbounded full-prefix scan; destsim
  // finding F5). Additive and inert for callers that never inspect it.
  readonly listCalls: Array<{ prefix?: string; start?: string; startAfter?: string; end?: string; limit?: number; reverse?: boolean }> = [];

  // list returns the entries whose key starts with the prefix, in ascending key order (the real storage lists
  // in lexicographic key order), so a prefix scan is deterministic. It faithfully honours the real
  // DurableObjectStorage.list bounds the engine relies on: `start` (INCLUSIVE lower-bound key), `startAfter`
  // (EXCLUSIVE lower-bound key -- the cursor listAllByPrefix pages with), `end` (EXCLUSIVE upper-bound key),
  // `reverse` (descending key order) and `limit` (max entries, applied AFTER ordering). A caller passing only
  // { prefix } gets exactly the prior behaviour. NOTE: `startAfter` is not optional to model -- listAllByPrefix
  // relies on it to page a >DO_LIST_PAGE prefix; a mock that ignored it would silently return only the first
  // page, repeated (the 2000-downpipe metrics scrape is the regression guard for exactly this).
  async list<T>(opts?: { prefix?: string; start?: string; startAfter?: string; end?: string; limit?: number; reverse?: boolean }): Promise<Map<string, T>> {
    this.listCalls.push({ ...(opts ?? {}) });
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((x) => x.startsWith(prefix));
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (opts?.end !== undefined) keys = keys.filter((k) => k < opts.end!);
    keys.sort();
    if (opts?.reverse === true) keys.reverse();
    if (opts?.limit !== undefined && opts.limit >= 0) keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    return out;
  }

  // Alarm tracking mirrors the platform: setAlarm stores the time, getAlarm reads it back (null when
  // unset), deleteAlarm clears it. Validators that never touch alarms simply never read it back.
  private alarm: number | null = null;
  async getAlarm(): Promise<number | null> {
    return this.alarm;
  }
  async setAlarm(t: number): Promise<void> {
    this.alarm = t;
  }
  async deleteAlarm(): Promise<void> {
    this.alarm = null;
  }

  // ---- validator-only helpers (never on the real storage) ----
  // rawGet/rawPut seed or read a key WITHOUT the put deep-clone, so a validator can inspect or
  // install the exact in-store object (e.g. a history ring it then mutates in place).
  rawGet<T>(key: string): T | undefined {
    return this.map.get(key) as T | undefined;
  }
  rawPut<T>(key: string, value: T): void {
    this.map.set(key, value);
  }
  has(key: string): boolean {
    return this.map.has(key);
  }
  countPrefix(prefix: string): number {
    let n = 0;
    for (const k of this.map.keys()) if (k.startsWith(prefix)) n++;
    return n;
  }
  raw(): Map<string, unknown> {
    return this.map;
  }
  size(): number {
    return this.map.size;
  }

  // seed is a synchronous convenience for put's semantics (deep-clone via JSON round-trip), for a
  // validator that builds its initial state in a plain (non-async) setup loop rather than awaiting
  // put() per key. Unlike rawPut, the stored value is cloned, so a caller that mutates its source
  // object after seeding does not corrupt what is on-store (engine-test-013-14 consolidation).
  seed<T>(key: string, value: T): void {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }

  // rawDelete removes a key synchronously and without the boolean "did it exist" return delete()
  // carries, for a test that just wants a key gone (e.g. simulating a hole punched in a ring).
  rawDelete(key: string): void {
    this.map.delete(key);
  }

  // rawKeys/keysWithPrefix/keys/rawListKeys are the several duplicated names validators used for the
  // same underlying operation -- read the stored keys, optionally filtered by prefix -- before this
  // consolidation (finding engine-test-013-14). rawKeys returns them lexicographically sorted (the
  // shape audit/history validators that assert ring order rely on); keysWithPrefix and keys return
  // them in map (insertion) order; rawListKeys returns every key with no filter. All four are kept,
  // under their original names, so converting a validator's local double to this shared one needed no
  // call-site rewrite.
  rawKeys(prefix = ""): string[] {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
  }
  keysWithPrefix(prefix: string): string[] {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
  keys(prefix = ""): string[] {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
  rawListKeys(): string[] {
    return [...this.map.keys()];
  }

  // rawAlarm reads the armed alarm time synchronously (mirrors getAlarm, without the Promise), for a
  // test asserting on it inline rather than awaiting.
  rawAlarm(): number | null {
    return this.alarm;
  }

  // snapshotKeyspace returns a deep, stable-ordered copy of the WHOLE keyspace (key -> JSON string), so
  // a test can assert exhaustively that an operation mutated NOTHING (every key AND value identical),
  // not just one record. Values are serialised so the comparison is by content, order-independent.
  snapshotKeyspace(): Map<string, string> {
    const out = new Map<string, string>();
    for (const k of [...this.map.keys()].sort()) out.set(k, JSON.stringify(this.map.get(k)));
    return out;
  }
}
