// Shared harness for the parser fuzz properties. Each property drives one parser that reads untrusted
// or archive input with arbitrary or mutated bytes and checks four things: it never throws a non-domain error
// (a TypeError, RangeError, ReferenceError, SyntaxError or a non-Error value is a crash, not a refusal), it
// finishes inside a time budget, it refuses malformed input with its own closed refusal class, and it
// round-trips where a writer exists. Every run uses a fixed seed, so a failure reproduces byte for byte.
//
// A property registered with knownFailing(name, ...) still runs and must fail. When it passes, the run
// fails, so the marker is removed together with the parser fix.
// Run through: node test/property/property-parsers.ts
import fc from "fast-check";

/** Fixed seed shared by every property in the harness. */
export const SEED = 0x5eed;
/** Wall-clock budget for one parser call, in milliseconds. */
export const CALL_BUDGET_MS = 2000;

export type Outcome<T> = { kind: "ok"; value: T } | { kind: "refused"; err: Error } | { kind: "crash"; err: unknown };

/**
 * True when the thrown value is a deliberate refusal: an Error that is not one of the language-level
 * failure classes that signal an unchecked assumption in the parser.
 */
export function isDomainError(e: unknown): e is Error {
  if (!(e instanceof Error)) return false;
  return !(e instanceof TypeError || e instanceof RangeError || e instanceof ReferenceError || e instanceof SyntaxError);
}

/** Runs fn and sorts the result into ok, refused (a domain error) or crash (anything else). */
export async function run<T>(fn: () => T | Promise<T>): Promise<Outcome<T>> {
  try {
    return { kind: "ok", value: await fn() };
  } catch (e) {
    return isDomainError(e) ? { kind: "refused", err: e } : { kind: "crash", err: e };
  }
}

/** Describes a crash for the shrinker's counterexample line. */
export function describe(e: unknown): string {
  return e instanceof Error ? `${e.constructor.name}: ${e.message}` : `non-Error throw ${String(e)}`;
}

/**
 * Asserts the three universal properties for one input: no crash, finished inside the budget, and, when it
 * refused, the refusal passes the parser's own class check. Throws a message the shrinker reports.
 */
export async function assertSafe<T>(label: string, fn: () => T | Promise<T>, refusalOk: (e: Error) => boolean = () => true): Promise<Outcome<T>> {
  const t0 = performance.now();
  const r = await run(fn);
  const ms = performance.now() - t0;
  if (ms > CALL_BUDGET_MS) throw new Error(`${label}: took ${Math.round(ms)} ms, over the ${CALL_BUDGET_MS} ms budget`);
  if (r.kind === "crash") throw new Error(`${label}: non-domain error ${describe(r.err)}`);
  if (r.kind === "refused" && !refusalOk(r.err)) throw new Error(`${label}: refusal outside the closed class: ${describe(r.err)}`);
  return r;
}

function failureLines(e: unknown): string {
  const lines = (e as Error).message.split("\n").filter((l) => l.trim() !== "" && !/^Hint|^Shrunk|^\{ seed/.test(l));
  return lines.map((l) => l.slice(0, 240)).slice(0, 8).join(" | ");
}

/** For total functions: any throw, domain or not, is a defect. Returns the value. */
export async function assertTotal<T>(label: string, fn: () => T | Promise<T>): Promise<T> {
  const r = await assertSafe(label, fn);
  if (r.kind !== "ok") throw new Error(`${label}: threw ${describe(r.err)}`.slice(0, 200));
  return r.value;
}

let failures = 0;
let total = 0;
let known = 0;

/** Runs one property with the shared seed and prints ok or FAIL. */
export async function prop(label: string, body: () => Promise<void>): Promise<void> {
  total++;
  try {
    await body();
    console.log(`  ok   ${label}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${label}: ${failureLines(e)}`);
  }
}

/**
 * Registers a property that must fail. The body must throw; the printed line carries the property name.
 * A body that passes fails the suite, so the marker is removed with the fix.
 */
export async function knownFailing(name: string, label: string, body: () => Promise<void>): Promise<void> {
  total++;
  try {
    await body();
  } catch (e) {
    known++;
    console.log(`  known ${name} ${label}\n         ${failureLines(e).split("Got error:").pop()?.trim().slice(0, 200) ?? ""}`);
    return;
  }
  failures++;
  console.log(`  FAIL ${name} ${label}: the property passes, remove the known-failing marker`);
}

/** Bounded fast-check parameters with the shared seed. */
export function runs(numRuns: number): fc.Parameters<unknown> {
  return { numRuns, seed: SEED, endOnFailure: false };
}

/** Counts for the final verdict line. */
export function tally(): { failures: number; total: number; known: number } {
  return { failures, total, known };
}

/** Mutations of a byte string: flip a bit, overwrite a byte, truncate, insert a byte, duplicate a slice. */
export function mutationOf(src: Uint8Array): fc.Arbitrary<Uint8Array> {
  const pos = fc.nat(Math.max(0, src.length));
  return fc.oneof(
    fc.tuple(pos, fc.integer({ min: 0, max: 7 })).map(([i, b]) => {
      const c = Uint8Array.from(src);
      if (c.length > 0) c[i % c.length] = (c[i % c.length]! ^ (1 << b)) & 0xff;
      return c;
    }),
    fc.tuple(pos, fc.integer({ min: 0, max: 255 })).map(([i, v]) => {
      const c = Uint8Array.from(src);
      if (c.length > 0) c[i % c.length] = v;
      return c;
    }),
    pos.map((n) => src.slice(0, n % (src.length + 1))),
    fc.tuple(pos, fc.integer({ min: 0, max: 255 })).map(([i, v]) => {
      const at = i % (src.length + 1);
      const c = new Uint8Array(src.length + 1);
      c.set(src.subarray(0, at), 0);
      c[at] = v;
      c.set(src.subarray(at), at + 1);
      return c;
    }),
    fc.tuple(pos, pos).map(([a, b]) => {
      const lo = Math.min(a, b) % (src.length + 1);
      const hi = Math.max(a, b) % (src.length + 1);
      const mid = src.slice(lo, hi);
      const c = new Uint8Array(src.length + mid.length);
      c.set(src.subarray(0, hi), 0);
      c.set(mid, hi);
      c.set(src.subarray(hi), hi + mid.length);
      return c;
    }),
  );
}

/** JSON-ish values that parsers meet after JSON.parse: null, scalars, arrays and small objects. */
export const jsonValue: fc.Arbitrary<unknown> = fc.jsonValue({ maxDepth: 3 });

/** Text lines that look like NDJSON entries, valid and invalid, for the line-oriented readers. */
export const ndjsonText: fc.Arbitrary<string> = fc.array(fc.oneof(fc.json(), fc.string({ maxLength: 40 }), fc.constant("null"), fc.constant("[]"), fc.constant("{}")), { maxLength: 6 }).map((ls) => ls.join("\n"));

/** Decodes bytes as UTF-8 text for building seeds from the real vectors. */
export function text(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** Encodes text as UTF-8 bytes. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Runs fn with the console silenced, for parsers that log a line for every refusal. */
export function quiet<T>(fn: () => Promise<T>): Promise<T> {
  const l = console.log;
  const w = console.warn;
  const e = console.error;
  console.log = console.warn = console.error = () => undefined;
  return fn().finally(() => {
    console.log = l;
    console.warn = w;
    console.error = e;
  });
}
