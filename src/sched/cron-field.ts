// Per-field cron term parsing, split out of cron.ts. This module holds the named sub-steps of
// parsing ONE comma-separated cron field: the step-suffix split, the body-to-range resolution, and
// the range-aware value adder. parseField in cron.ts delegates to these.

import type { CronSpec } from "./cron-types.ts";

// RANGES is the per-field [min,max] inclusive bound. Kept here (not in cron.ts) so the field-parsing
// helpers below are self-contained; cron.ts imports it for any callers that still reference it.
export const RANGES: Record<keyof CronSpec, { min: number; max: number }> = {
  minute: { min: 0, max: 59 },
  hour: { min: 0, max: 23 },
  dom: { min: 1, max: 31 },
  month: { min: 1, max: 12 },
  dow: { min: 0, max: 6 },
};

// FieldBounds carries the resolved bounds for the field being parsed, plus the dow alias state.
interface FieldBounds {
  field: keyof CronSpec;
  min: number;
  max: number;
  isDow: boolean; // day-of-week accepts 7 as a Sunday alias
  rangeMax: number; // max for range/value checks (7 for dow, else max)
}

// fieldBounds resolves the [min,max], the dow flag, and the extended rangeMax for a field.
export function fieldBounds(field: keyof CronSpec): FieldBounds {
  const { min, max } = RANGES[field];
  // day-of-week accepts 7 as an alias for Sunday (0), the common crontab convenience. We normalise
  // 7 -> 0 after range-checking against an extended max so "7" and "0-7" are both accepted.
  const isDow = field === "dow";
  const rangeMax = isDow ? 7 : max;
  return { field, min, max, isDow, rangeMax };
}

// addValue range-checks one concrete value against the field bounds and adds it to the set,
// normalising the dow-7 alias to 0. Throws on an out-of-range value (same message as before).
export function addValue(values: Set<number>, n: number, b: FieldBounds): void {
  if (!Number.isInteger(n) || n < b.min || n > b.rangeMax) {
    throw new Error(`cron ${b.field} value ${n} out of range ${b.min}-${b.max}`);
  }
  values.add(b.isDow && n === 7 ? 0 : n);
}

// ParsedStep is a single comma part split into its body and step. slash is the position of "/" in
// the original part (-1 when absent), preserved because a bare "N" with no slash is a single value
// while "N/n" is a stepped range from N to max.
interface ParsedStep {
  body: string;
  step: number;
  slash: number;
}

// parseStep splits an optional "/n" step suffix off a comma part, validating the step. Returns the
// body, the step (default 1), and the slash position. Throws on a malformed step (same messages).
export function parseStep(part: string, field: keyof CronSpec): ParsedStep {
  let body = part;
  let step = 1;
  const slash = part.indexOf("/");
  if (slash !== -1) {
    body = part.slice(0, slash).trim();
    const stepStr = part.slice(slash + 1).trim();
    if (!/^\d+$/.test(stepStr)) throw new Error(`cron ${field} step "${stepStr}" must be a positive integer`);
    step = Number(stepStr);
    if (step < 1) throw new Error(`cron ${field} step must be at least 1`);
    if (body === "") throw new Error(`cron ${field} step is missing its base (use */n, A/n, or A-B/n)`);
  }
  return { body, step, slash };
}

// parsePart parses ONE comma part (already a ParsedStep) into the values set. It resolves the body
// to a [lo, hi] range and adds the stepped values; a bare single value (no slash) is added directly.
// Behaviour is identical to the original parseField inner block.
export function parsePart(values: Set<number>, parsed: ParsedStep, b: FieldBounds): void {
  const { body, step, slash } = parsed;
  // Resolve the body to a [lo, hi] range. "*" -> the whole field range; "N" -> [N,N]; "A-B" ->
  // [A,B]. With a step present, a bare "N" means "from N to the field max" (A/n), matching cron.
  let lo: number;
  let hi: number;
  if (body === "*") {
    lo = b.min;
    hi = b.max; // a "*" step walks the natural range (max, not the dow-7 alias)
  } else if (body.includes("-")) {
    const dash = body.indexOf("-");
    const aStr = body.slice(0, dash).trim();
    const bStr = body.slice(dash + 1).trim();
    if (!/^\d+$/.test(aStr) || !/^\d+$/.test(bStr)) {
      throw new Error(`cron ${b.field} range "${body}" must be two integers A-B`);
    }
    lo = Number(aStr);
    hi = Number(bStr);
    if (lo > hi) throw new Error(`cron ${b.field} range "${body}" must have A <= B`);
    if (lo < b.min || hi > b.rangeMax) throw new Error(`cron ${b.field} range "${body}" out of range ${b.min}-${b.max}`);
  } else {
    if (!/^\d+$/.test(body)) throw new Error(`cron ${b.field} term "${body}" is not a valid number, range, or step`);
    const n = Number(body);
    if (n < b.min || n > b.rangeMax) throw new Error(`cron ${b.field} value ${n} out of range ${b.min}-${b.max}`);
    if (slash === -1) {
      // a bare single value
      addValue(values, n, b);
      return;
    }
    // "N/n" means N, N+step, ... up to the field max.
    lo = n;
    hi = b.max;
  }

  for (let v = lo; v <= hi; v += step) addValue(values, v, b);
}
