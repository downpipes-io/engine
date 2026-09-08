// The restore DIFF PREVIEW for the cf-config source surface registry (cf-config-surfaces.ts). Before
// confirming a restore, the operator sees exactly what each surface would change. diffConfig walks the
// CURRENT live config and the SNAPSHOT side by side and emits one ConfigChange per differing leaf, FROM
// the current value TO the snapshot value (a restore moves current -> snapshot). It is generic over any
// surface's JSON (one differ for all surfaces), with three refinements that make a real Cloudflare config
// readable: arrays of objects are matched by a stable identity key (id/name/...) rather than by position,
// so a reordered DNS/firewall list is not reported as "everything changed"; volatile server-stamped
// fields (modified_on, created_on, ...) are ignored, since a restore never sets them; and the whole diff
// is capped so a huge zone returns a bounded preview (truncated:true). It reads NOTHING and writes
// NOTHING, it is pure over the two already-fetched JSON values. Everything here was MOVED VERBATIM out of
// cf-config-surfaces.ts to keep that module a readable size; the behaviour is unchanged. cf-config-
// surfaces.ts re-exports diffConfig + ConfigDiff so its callers keep importing them by name from there.
//
// Node 25 strip-types compatible: no enums, explicit declarations.

import { asJson, type ConfigChange, isPlainObject, jsonEqual, SKIP_IN_DIFF } from "./cf-config-shared.ts";

const IDENTITY_KEYS = ["id", "name", "tag", "path", "pattern", "hostname"] as const;

// identityKey picks the field that identifies array elements so two arrays match by identity, not
// position. It returns the first candidate present (as a string/number) on EVERY element of both
// arrays, or null when no stable key fits (then the arrays diff as one whole value).
function identityKey(a: unknown[], b: unknown[]): string | null {
  const all = [...a, ...b];
  if (all.length === 0 || !all.every(isPlainObject)) return null;
  for (const key of IDENTITY_KEYS) {
    if (all.every((el) => { const v = (el as Record<string, unknown>)[key]; return typeof v === "string" || typeof v === "number"; })) return key;
  }
  return null;
}

export interface ConfigDiff {
  changes: ConfigChange[];
  truncated: boolean;
}

// MAX_DIFF_DEPTH bounds the recursive walk so a pathologically nested CF API response (deeply nested
// WAF/Access/Gateway condition trees) cannot drive recursion deep enough to overflow the V8 isolate
// call stack and crash the restore diff step. 64 levels is far past any real config shape; beyond it
// the walk records one "change" sentinel for the subtree rather than descending further.
const MAX_DIFF_DEPTH = 64;

// diffConfig diffs CURRENT (live) against SNAPSHOT, capping total changes. cap exists so a zone with
// thousands of DNS records returns a bounded, renderable preview rather than a multi-megabyte plan.
export function diffConfig(current: unknown, snapshot: unknown, cap = 500): ConfigDiff {
  const changes: ConfigChange[] = [];
  let truncated = false;
  const push = (c: ConfigChange): void => {
    if (changes.length >= cap) { truncated = true; return; }
    changes.push(c);
  };
  const walk = (path: string, cur: unknown, snap: unknown, depth: number): void => {
    if (changes.length >= cap) { truncated = true; return; }
    if (jsonEqual(cur, snap)) return;
    if (depth >= MAX_DIFF_DEPTH) {
      // Stop descending a pathologically deep subtree; record one sentinel change rather than risk a
      // call-stack overflow. The leaf compare below still reports the subtree as changed.
      push({ path: path || "(root)", action: "change", from: asJson(cur), to: asJson(snap) });
      return;
    }
    if (isPlainObject(cur) && isPlainObject(snap)) {
      const keys = new Set([...Object.keys(cur), ...Object.keys(snap)]);
      for (const k of keys) {
        if (SKIP_IN_DIFF.has(k)) continue;
        walk(path ? `${path}.${k}` : k, cur[k], snap[k], depth + 1);
      }
      return;
    }
    if (Array.isArray(cur) && Array.isArray(snap)) {
      const key = identityKey(cur, snap);
      if (key) {
        const curMap = new Map<string, unknown>();
        const snapMap = new Map<string, unknown>();
        for (const el of cur) curMap.set(String((el as Record<string, unknown>)[key]), el);
        for (const el of snap) snapMap.set(String((el as Record<string, unknown>)[key]), el);
        for (const id of new Set([...curMap.keys(), ...snapMap.keys()])) {
          walk(`${path}[${id}]`, curMap.get(id), snapMap.get(id), depth + 1);
        }
        return;
      }
      push({ path: path || "(root)", action: "change", from: asJson(cur), to: asJson(snap) });
      return;
    }
    // a leaf or a type mismatch: a present-only-in-snapshot value is an add (restore creates it), a
    // present-only-in-current value is a remove (restore deletes it), otherwise a change.
    if (cur === undefined) push({ path: path || "(root)", action: "add", from: "", to: asJson(snap) });
    else if (snap === undefined) push({ path: path || "(root)", action: "remove", from: asJson(cur), to: "" });
    else push({ path: path || "(root)", action: "change", from: asJson(cur), to: asJson(snap) });
  };
  walk("", current, snapshot, 0);
  return { changes, truncated };
}
