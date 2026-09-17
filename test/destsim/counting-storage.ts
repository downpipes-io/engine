// CountingStorage: a NEW test-only wrapper around MockStorage (test/mock-storage.ts) built for the
// destsim pull-consumer abuse validators. It instruments every list() call with the prefix requested
// and how many entries the underlying MockStorage returned for it, so a validator can prove a paging-
// cost claim ("this DO call scans O(retained), not O(limit)") with a deterministic call-count
// assertion instead of a flaky timing measurement (test/validate-destsim-auditfeed-abuse.ts, finding
// F5 in test/destsim/PULL-ABUSE-BEHAVIOUR.md).
//
// This is a NEW file that WRAPS MockStorage by composition; it does not modify mock-storage.ts, so
// every other validator that constructs a bare `new MockStorage()` is byte-for-byte unaffected. It
// implements the same storage surface SchedulerDO consumes (get/put/delete/list/getAlarm/setAlarm/
// deleteAlarm) by delegating to the wrapped instance, plus passes through the validator-only raw
// helpers (rawGet/rawPut/has/countPrefix) so a seeding routine written against MockStorage works
// unchanged against a CountingStorage.

import { MockStorage } from "../mock-storage.ts";

export interface ListCallRecord {
  prefix: string;
  resultSize: number;
}

export class CountingStorage {
  readonly inner: MockStorage;
  readonly listCalls: ListCallRecord[] = [];

  constructor(inner: MockStorage = new MockStorage()) {
    this.inner = inner;
  }

  async get<T>(key: string): Promise<T | undefined>;
  async get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
    if (Array.isArray(keyOrKeys)) return this.inner.get<T>(keyOrKeys);
    return this.inner.get<T>(keyOrKeys);
  }
  async put<T>(key: string, value: T): Promise<void> {
    return this.inner.put(key, value);
  }
  async delete(key: string): Promise<boolean> {
    return this.inner.delete(key);
  }

  // list is the ONE instrumented call: it records the requested prefix and how many entries the
  // underlying MockStorage returned for it, so a validator can read listCalls back and assert exactly
  // how much a single DO call scanned, deterministically.
  async list<T>(opts?: { prefix?: string }): Promise<Map<string, T>> {
    const result = await this.inner.list<T>(opts);
    this.listCalls.push({ prefix: opts?.prefix ?? "", resultSize: result.size });
    return result;
  }

  async getAlarm(): Promise<number | null> {
    return this.inner.getAlarm();
  }
  async setAlarm(t: number): Promise<void> {
    return this.inner.setAlarm(t);
  }
  async deleteAlarm(): Promise<void> {
    return this.inner.deleteAlarm();
  }

  // ---- pass-throughs for validator seeding/inspection (mirror MockStorage's own helpers) ----
  rawGet<T>(key: string): T | undefined {
    return this.inner.rawGet<T>(key);
  }
  rawPut<T>(key: string, value: T): void {
    this.inner.rawPut(key, value);
  }
  has(key: string): boolean {
    return this.inner.has(key);
  }
  countPrefix(prefix: string): number {
    return this.inner.countPrefix(prefix);
  }

  // listCallsFor filters the recorded calls to one prefix, so a validator reading back the scan cost
  // of (say) the "audit:" prefix is not confused by unrelated list() calls the same DO instance made.
  listCallsFor(prefix: string): ListCallRecord[] {
    return this.listCalls.filter((c) => c.prefix === prefix);
  }
}
