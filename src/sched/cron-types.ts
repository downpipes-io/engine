// Shared cron types, extracted from cron.ts so the field-parsing helpers (cron-field.ts) can
// reference CronSpec without importing cron.ts (which would create a cycle). cron.ts re-exports
// CronSpec, so existing importers see no change.

// FieldSpec is the parsed, pre-expanded set of allowed values for one cron field, plus whether the
// field was a bare "*" (the "no constraint" marker the dom/dow union rule needs). The allowed set
// is a Set<number> for O(1) membership in the per-minute test.
export interface FieldSpec {
  star: boolean; // true when the field was exactly "*" (used by the dom/dow union rule)
  values: Set<number>; // the concrete allowed values (always populated, even for "*")
}

// CronSpec is a fully-parsed 5-field expression. Construct it via parseCron (which validates) and
// match minutes with cronMatches; nextFireAfter wraps the whole walk.
export interface CronSpec {
  minute: FieldSpec;
  hour: FieldSpec;
  dom: FieldSpec; // day-of-month, 1-31
  month: FieldSpec; // 1-12
  dow: FieldSpec; // day-of-week, 0-6 (Sunday = 0)
}
