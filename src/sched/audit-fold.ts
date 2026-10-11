// audit-fold.ts -- the fold that turns a flood of refused attempts into a bounded number of audit rows, each
// carrying how many attempts it stands for. Three writers use it: the recovery sign-in failures
// (scheduler-do-recovery.ts), the failed passkey, SSO and step-up sign-ins (appendAuthnFailureAudit) and the
// router's denied rows (appendAuditFromRouter), both in scheduler-do-audit.ts.
//
// WHY. AUDIT_CAP is 10,000 and rollOverAudit drops the OLDEST rows. A writer that appends one row per refused
// attempt lets the refused caller push every real row off the retained chain: an anonymous caller through a
// sign-in route, a Viewer through any capability refusal.
//
// WHAT IT DOES. A key names the source of the attempts: for recovery a source and an outcome, for a failed
// sign-in the ceremony, connection and actor, for a refusal the actor.
//   - The first attempt of a key's 60 s window writes a row at once, if the budget allows.
//   - Later attempts in that window write no row. They add to the key's pending count. A fold with a flush
//     ceiling (the failed sign-ins, at 25) also writes the pending count once it reaches the ceiling, if the
//     budget allows.
//   - When the window has closed, the pending count is written as one more row: the next attempt of the same
//     key carries it, or, once a further window has passed with no such attempt, the sweep at the next call
//     writes it with the key's latest draft.
//   - The BUDGET caps the rows each fold writes in a 60 s window, whatever the number of keys. This is what
//     stops a caller with many IPs, or many accounts, from getting one row a minute for each of them.
//   - Two CEILINGS cap the rows in an hour: SIGN_IN_FOLD_ROWS_PER_HOUR for the recovery and failed sign-in
//     folds together, DENIED_FOLD_ROWS_PER_HOUR for the denied fold alone. A sign-in flood cannot spend the
//     denied fold's rows, and a flood of refusals cannot spend the sign-in folds' rows.
//   - Over the budget or the ceiling, the recovery fold adds the attempts to an overflow count for their outcome.
//     While the ceiling is open it writes that count as at most one row per outcome a minute; once the ceiling
//     is reached, at most one row per outcome an hour. The recovery keys are IP addresses a caller chooses, so
//     their counts cannot wait on their own keys.
//   - The denied fold keeps an attempt over the budget on its actor's key while its ceiling is open, so the
//     count stays with the actor. Once its ceiling is reached, the attempts go to one overflow count, written as
//     at most one denied-overflow row an hour.
//   - The failed sign-in fold keeps the attempts on their own key until a row is allowed: its keys come from
//     the tenant's own connections and roster.
// Every row carries the attempts it stands for, itself included, so the rows sum to the attempts made.
//
// WHERE IT LIVES. Every fold and ceiling is kept in Durable Object storage under AUDIT_FOLD_STORAGE_PREFIX
// and saved before the rows it hands out are appended, so a restart loses no pending count. The counts
// reach the chain at the next fold write, router audit write or alarm.

import type { AuditDraft } from "../admin/audit.ts";
import { ipSourceGroup } from "../admin/sign-in-context.ts";

// The window, the same one minute as AUTHN_FAILURE_AUDIT_WINDOW_MS and RATE_LIMIT_WINDOW_MS.
export const AUDIT_FOLD_WINDOW_MS = 60_000;

// The ceiling's window.
export const AUDIT_FOLD_HOUR_MS = 3_600_000;

// auditFoldNow is the fold's clock: Date.now, plus an offset that only a validator moves. A validator that
// reads one denied row per request puts each request in its own quiet minute this way, without moving
// Date.now, which also drives session freshness and the rate limiters.
let testOffsetMs = 0;
export function auditFoldNow(): number {
  return Date.now() + testOffsetMs;
}
export function __advanceAuditFoldClockForTest(ms: number): void {
  testOffsetMs += ms;
}

// The rows each fold may write in one window, the overflow rows not included. See the note in
// docs/security/logging-inventory.md ("Folded rows") for the arithmetic behind the figures.
//   - Recovery: 2. One real person who mistypes a code and then hits the per-email limit needs a failed row
//     and a denied row; two sources failing in the same minute is already rare.
//   - Failed sign-ins: 2. Two ceremonies or two members failing in the same minute each get a row at once.
//   - Denied: 2. A refused member gets one row a minute however many routes they try.
export const RECOVERY_FOLD_ROWS_PER_WINDOW = 2;
export const AUTHN_FOLD_ROWS_PER_WINDOW = 2;
export const DENIED_FOLD_ROWS_PER_WINDOW = 2;

// The rows a ceiling allows in an hour, the hourly overflow rows not included. A flood on all three writers at
// once, from any number of sources, writes at most 20 + 9 rows plus three hourly overflow rows (one per
// recovery outcome, one denied): 32 an hour, so 10,000 rows take 13 days.
export const SIGN_IN_FOLD_ROWS_PER_HOUR = 20;
export const DENIED_FOLD_ROWS_PER_HOUR = 9;

// The most keys a fold holds. Keys that hold nothing are dropped at every call once their window closes, so
// only keys with a row in the current window or a pending count stay. The cap bounds those. A key that cannot
// be stored is reported as dropped, for the caller to count.
export const AUDIT_FOLD_KEY_CAP = 256;

// The storage keys: `${prefix}ceiling:<name>`, `${prefix}<fold>:meta` and `${prefix}<fold>:key:<key>`.
export const AUDIT_FOLD_STORAGE_PREFIX = "auditFold:";

// One key's state: the start of its open window, the attempts no row carries yet, and the latest of them.
interface FoldKey {
  at: number;
  pending: number;
  last: AuditDraft;
}

// One row the caller must append: the draft and the attempts it stands for. `own` marks the row written for
// the attempt passed to take(), as opposed to a pending count the call flushed on the way. `key` names the key
// the row came from, or is null for an overflow row.
export interface FoldWrite {
  draft: AuditDraft;
  attempts: number;
  own: boolean;
  key: string | null;
}

// An hourly ceiling. The sign-in ceiling is shared by two folds; the denied ceiling has one.
export class AuditCeiling {
  hourAt = 0;
  rows = 0;
  // epoch counts the hours, so a fold can tell that its once-an-hour overflow row is due again.
  epoch = 0;
  // saved is the stored form, so a save writes the ceiling only when it changed.
  saved = "";
  readonly name: string;
  readonly limit: number;
  constructor(name: string, limit: number) {
    this.name = name;
    this.limit = limit;
  }
  roll(now: number): void {
    if (now - this.hourAt < AUDIT_FOLD_HOUR_MS) return;
    this.hourAt = now;
    this.rows = 0;
    this.epoch += 1;
  }
  open(): boolean {
    return this.rows < this.limit;
  }
}

interface FoldOptions {
  name: string;
  rowsPerWindow: number;
  ceiling: AuditCeiling;
  // finish turns a stored draft and its count into the draft the chain records.
  finish: (draft: AuditDraft, attempts: number) => AuditDraft;
  // overflowOf maps an attempt's draft to its overflow row's draft. Absent: over-budget attempts wait on
  // their own key.
  overflowOf?: (draft: AuditDraft) => AuditDraft;
  // overflowPastCeilingOnly: over the budget, the attempts wait on their own key while the ceiling is open,
  // and go to the overflow only once it is reached.
  overflowPastCeilingOnly?: boolean;
  // flushAt writes a key's pending count once it reaches this many, if the budget allows.
  flushAt?: number;
}

interface Overflow {
  draft: AuditDraft;
  count: number;
  minute: boolean;
  hourEpoch: number;
}

export class AuditFold {
  private readonly keys = new Map<string, FoldKey>();
  private budgetAt = 0;
  private rows = 0;
  // The overflow counts, one per outcome, so an overflow row never misstates the outcome of what it counts.
  // minute: an overflow row was written this budget window. hourEpoch: the hour whose post-ceiling overflow
  // row has been written.
  private readonly overflow = new Map<string, Overflow>();
  private readonly opts: FoldOptions;
  // The keys changed since the last save, and the stored form of the rest of the state.
  private readonly dirty = new Set<string>();
  private savedMeta = "";
  constructor(opts: FoldOptions) {
    this.opts = opts;
  }

  finish(w: FoldWrite): AuditDraft {
    return this.opts.finish(w.draft, w.attempts);
  }

  private canWrite(): boolean {
    return this.rows < this.opts.rowsPerWindow && this.opts.ceiling.open();
  }

  // overflowDraft is the overflow row's draft for an attempt that cannot have a row now, or null when the
  // attempt waits on its own key instead.
  private overflowDraft(draft: AuditDraft): AuditDraft | null {
    if (this.opts.overflowOf === undefined || (this.opts.overflowPastCeilingOnly === true && this.opts.ceiling.open())) return null;
    return this.opts.overflowOf(draft);
  }

  private noteRow(): void {
    this.rows += 1;
    this.opts.ceiling.rows += 1;
  }

  private setKey(key: string, e: FoldKey | undefined): void {
    if (e === undefined) this.keys.delete(key);
    else this.keys.set(key, e);
    this.dirty.add(key);
  }

  // take records one attempt for `key` and returns the rows to append, in order, plus how many attempts could
  // not be stored at all (the key cap was full). The caller saves the fold, then appends each row through
  // finish().
  take(key: string, draft: AuditDraft, now: number): { writes: FoldWrite[]; dropped: number } {
    const writes = this.sweep(now, key);
    const entry = this.keys.get(key);
    if (entry !== undefined && now - entry.at < AUDIT_FOLD_WINDOW_MS) {
      entry.pending += 1;
      entry.last = draft;
      this.dirty.add(key);
      if (this.opts.flushAt !== undefined && entry.pending >= this.opts.flushAt && this.canWrite()) {
        this.noteRow();
        writes.push({ draft, attempts: entry.pending, own: true, key });
        entry.pending = 0;
        entry.at = now;
      }
      return { writes, dropped: 0 };
    }
    // A new window for this key. It carries whatever its previous window left pending.
    const attempts = (entry?.pending ?? 0) + 1;
    if (this.canWrite()) {
      this.noteRow();
      writes.push({ draft, attempts, own: true, key });
      this.setKey(key, { at: now, pending: 0, last: draft });
      return { writes, dropped: 0 };
    }
    const over = this.overflowDraft(draft);
    if (over !== null) {
      this.setKey(key, undefined);
      this.addOverflow(over, attempts, writes);
      return { writes, dropped: 0 };
    }
    if (entry === undefined && this.keys.size >= AUDIT_FOLD_KEY_CAP) return { writes, dropped: 1 };
    this.setKey(key, { at: now, pending: attempts, last: draft });
    return { writes, dropped: 0 };
  }

  // sweep rolls the ceiling and the budget window, writes any overflow count that is due, and deals with every
  // other key whose window has closed: nothing pending, drop it; a pending count left for one further window,
  // write it if a row is allowed, else move it to the overflow (or leave it on its key). The key being taken
  // is skipped, because take() carries its count.
  sweep(now: number, skip?: string): FoldWrite[] {
    const writes: FoldWrite[] = [];
    this.opts.ceiling.roll(now);
    if (now - this.budgetAt >= AUDIT_FOLD_WINDOW_MS) {
      this.budgetAt = now;
      this.rows = 0;
      for (const o of this.overflow.values()) o.minute = false;
    }
    for (const o of [...this.overflow.values()]) if (o.count > 0) this.addOverflow(o.draft, 0, writes);
    for (const [k, e] of [...this.keys]) {
      if (k === skip || now - e.at < AUDIT_FOLD_WINDOW_MS) continue;
      if (e.pending === 0) {
        this.setKey(k, undefined);
      } else if (now - e.at < 2 * AUDIT_FOLD_WINDOW_MS) {
        // A source still sending carries its own count on its next row. Only a count left behind for a whole
        // further window is written by the sweep.
        continue;
      } else if (this.canWrite()) {
        this.noteRow();
        writes.push({ draft: e.last, attempts: e.pending, own: false, key: k });
        this.setKey(k, undefined);
      } else {
        const over = this.overflowDraft(e.last);
        if (over === null) continue;
        this.setKey(k, undefined);
        this.addOverflow(over, e.pending, writes);
      }
    }
    return writes;
  }

  // giveBack returns a row's attempts to the fold when its append failed, so the next row still counts them.
  giveBack(w: FoldWrite, now: number): void {
    if (w.key === null) {
      const o = this.overflow.get(w.draft.outcome);
      if (o !== undefined) o.count += w.attempts;
      return;
    }
    const e = this.keys.get(w.key);
    if (e !== undefined) {
      e.pending += w.attempts;
      this.dirty.add(w.key);
    } else this.setKey(w.key, { at: now, pending: w.attempts, last: w.draft });
  }

  // addOverflow adds attempts to the overflow count for the draft's outcome and writes the count if a row is
  // due: while the ceiling is open, the first overflow of that outcome in a budget window (it counts toward the
  // ceiling); once the ceiling is reached, the first of that outcome in the hour. Otherwise the count waits.
  private addOverflow(draft: AuditDraft, attempts: number, writes: FoldWrite[]): void {
    const o = this.overflow.get(draft.outcome) ?? { draft, count: 0, minute: false, hourEpoch: -1 };
    o.count += attempts;
    this.overflow.set(draft.outcome, o);
    if (o.count === 0) return;
    const ceiling = this.opts.ceiling;
    if (ceiling.open()) {
      if (o.minute) return;
      o.minute = true;
      ceiling.rows += 1;
    } else {
      if (o.hourEpoch === ceiling.epoch) return;
      o.hourEpoch = ceiling.epoch;
    }
    writes.push({ draft: o.draft, attempts: o.count, own: false, key: null });
    o.count = 0;
  }

  // save writes the keys changed since the last save, and the budget and overflow state if it changed.
  async save(storage: DurableObjectStorage): Promise<void> {
    const base = `${AUDIT_FOLD_STORAGE_PREFIX}${this.opts.name}:`;
    const meta = JSON.stringify({ budgetAt: this.budgetAt, rows: this.rows, overflow: [...this.overflow] });
    if (meta !== this.savedMeta) {
      await storage.put(`${base}meta`, JSON.parse(meta));
      this.savedMeta = meta;
    }
    const gone: string[] = [];
    for (const k of this.dirty) {
      const e = this.keys.get(k);
      if (e === undefined) gone.push(`${base}key:${k}`);
      else await storage.put(`${base}key:${k}`, e);
    }
    if (gone.length > 0) await storage.delete(gone);
    this.dirty.clear();
  }

  // load restores the fold from the entries listed under AUDIT_FOLD_STORAGE_PREFIX.
  load(stored: Map<string, unknown>): void {
    const base = `${AUDIT_FOLD_STORAGE_PREFIX}${this.opts.name}:`;
    const meta = stored.get(`${base}meta`) as { budgetAt: number; rows: number; overflow: [string, Overflow][] } | undefined;
    if (meta !== undefined) {
      this.budgetAt = meta.budgetAt;
      this.rows = meta.rows;
      for (const [outcome, o] of meta.overflow) this.overflow.set(outcome, o);
      this.savedMeta = JSON.stringify(meta);
    }
    for (const [k, v] of stored) if (k.startsWith(`${base}key:`)) this.keys.set(k.slice(base.length + 4), v as FoldKey);
  }
}

// The three folds of one Durable Object and the two ceilings they use. They are held beside the object rather
// than as mixin fields, so the recovery mixin and the audit mixin reach the same folds without a new
// declaration on the shared DO surface.
export interface AuditFolds {
  signIn: AuditCeiling;
  deniedCeiling: AuditCeiling;
  recovery: AuditFold;
  authn: AuditFold;
  denied: AuditFold;
}

// AUTHN_FOLD_FLUSH_AT keeps the failed sign-in writer's earlier flush: a row per 25 pending attempts, if the
// budget allows.
const AUTHN_FOLD_FLUSH_AT = 25;

const registry = new WeakMap<object, Promise<AuditFolds>>();

// auditFoldsFor returns the folds of the Durable Object that owns `state`, read from its storage on first use.
export function auditFoldsFor(state: DurableObjectState): Promise<AuditFolds> {
  const found = registry.get(state);
  if (found !== undefined) return found;
  const loading = loadAuditFolds(state.storage);
  registry.set(state, loading);
  return loading;
}

async function loadAuditFolds(storage: DurableObjectStorage): Promise<AuditFolds> {
  const signIn = new AuditCeiling("signin", SIGN_IN_FOLD_ROWS_PER_HOUR);
  const deniedCeiling = new AuditCeiling("denied", DENIED_FOLD_ROWS_PER_HOUR);
  const folds: AuditFolds = {
    signIn,
    deniedCeiling,
    recovery: new AuditFold({
      name: "recovery",
      rowsPerWindow: RECOVERY_FOLD_ROWS_PER_WINDOW,
      ceiling: signIn,
      finish: (d, n) => ({ ...d, sourceIp: d.sourceIp, target: { kind: "authn-attempt", ceremony: "recovery", attempts: n } }),
      overflowOf: (d) => ({ ...d, sourceIp: null }),
    }),
    authn: new AuditFold({
      name: "authn",
      rowsPerWindow: AUTHN_FOLD_ROWS_PER_WINDOW,
      ceiling: signIn,
      finish: (d, n) => ({ ...d, sourceIp: d.sourceIp, target: d.target.kind === "authn-attempt" ? { ...d.target, attempts: n } : d.target }),
      flushAt: AUTHN_FOLD_FLUSH_AT,
    }),
    denied: new AuditFold({
      name: "denied",
      rowsPerWindow: DENIED_FOLD_ROWS_PER_WINDOW,
      ceiling: deniedCeiling,
      finish: (d, n) => ({ ...d, sourceIp: d.sourceIp, target: { ...d.target, deniedAttempts: n } }),
      // The overflow row names no actor, action or route: it counts refusals from every actor the ceiling left
      // without a row.
      overflowOf: () => ({ actorSubject: null, actorEmail: null, actorMethod: "engine", sourceIp: null, action: "denied-overflow", outcome: "denied", target: { kind: "denied-overflow" } }),
      overflowPastCeilingOnly: true,
    }),
  };
  const stored = await storage.list<unknown>({ prefix: AUDIT_FOLD_STORAGE_PREFIX });
  for (const c of [signIn, deniedCeiling]) {
    const s = stored.get(`${AUDIT_FOLD_STORAGE_PREFIX}ceiling:${c.name}`) as { hourAt: number; rows: number; epoch: number } | undefined;
    if (s === undefined) continue;
    c.hourAt = s.hourAt;
    c.rows = s.rows;
    c.epoch = s.epoch;
    c.saved = JSON.stringify(s);
  }
  for (const f of [folds.recovery, folds.authn, folds.denied]) f.load(stored);
  return folds;
}

// saveAuditFolds writes every fold and both ceilings. A caller saves before it appends the rows a fold handed
// out, so a restart between the two can only lose those rows' counts, never write a count twice.
export async function saveAuditFolds(storage: DurableObjectStorage, folds: AuditFolds): Promise<void> {
  for (const c of [folds.signIn, folds.deniedCeiling]) {
    const s = JSON.stringify({ hourAt: c.hourAt, rows: c.rows, epoch: c.epoch });
    if (s === c.saved) continue;
    await storage.put(`${AUDIT_FOLD_STORAGE_PREFIX}ceiling:${c.name}`, JSON.parse(s));
    c.saved = s;
  }
  for (const f of [folds.recovery, folds.authn, folds.denied]) await f.save(storage);
}

// flushAuditFolds sweeps all three folds and appends what is due: the router's audit writes and the alarm call
// it, so a pending count reaches the chain even when no further refused attempt comes.
export async function flushAuditFolds(state: DurableObjectState, append: (d: AuditDraft) => Promise<unknown>): Promise<void> {
  const folds = await auditFoldsFor(state);
  const now = auditFoldNow();
  const due = [folds.recovery, folds.authn, folds.denied].map((fold) => ({ fold, writes: fold.sweep(now) }));
  await saveAuditFolds(state.storage, folds);
  for (const { fold, writes } of due) for (const w of writes) await append(fold.finish(w));
}

// recoveryFoldSource names the source a recovery attempt is folded under: ipSourceGroup's group, so an IPv6
// address by its /64, since one host commonly holds a whole /64. The row still records the attempt's own IP.
export function recoveryFoldSource(ip: string | null): string {
  return ip === null ? "none" : ipSourceGroup(ip);
}
