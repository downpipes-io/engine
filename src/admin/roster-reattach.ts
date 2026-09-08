// Roster-driven re-attach: rebuild the engine's MISSING source bindings from the persisted roster
// (the downpipe configs), the inverse of a deploy/wipe that dropped them.
//
// THE PROBLEM this closes. A bare `wrangler deploy` (not the `npm run deploy` reconcile) resets the
// worker's bindings to wrangler.toml's, dropping every console-attached source. The downpipe configs
// survive (DO storage `dp:<id>`), and so does all backup history (RUNLOG chains by downpipe id, in the
// destination bucket), so NOTHING is lost. But the live source bindings are gone, so every affected
// downpipe's next run fails with "source binding error". Recovery is: re-add exactly those bindings,
// with their ORIGINAL names and native resource ids, so each downpipe reads its source again and the
// next run continues the SAME lineage (no new downpipe, no orphaned history).
//
// THE PLAN. Given the roster (configs) and the set of binding names currently LIVE on the worker,
// compute the re-attach plan: the missing bindings we can rebuild (their native id is recorded), the
// ones already attached (idempotent skip), and the ones we CANNOT rebuild because a legacy config did
// not record the native id (the operator re-saves them from the Sources screen to backfill the id).
//
// THE CONFLICT RULE. Two downpipes can legitimately share one binding name (the same underlying
// resource): that is safe to dedup only when every claimant's native id AGREES. A downpipe config's
// source.binding/namespaceId/bucketName/databaseId/storeId are writable by any downpipe.write caller
// (not just the Owner), so a binding name alone is not proof two downpipes mean the same resource --
// and the roster's enumeration order is attacker-influenceable (a client-chosen id sorting first). So
// when two downpipes name the same binding with DIFFERENT native ids (or different source types), we
// never guess which is legitimate: the binding is excluded from toAttach entirely and surfaced in
// `conflicting` for an owner to resolve, even if it happens to be already attached right now (that is
// the only way to see the conflict BEFORE a later deploy-drop + reattach would otherwise silently pick
// one claim and redirect a live source out from under its legitimate downpipe).
//
// This module is the PURE, IO-free core (classify + map + dedup) so a validator drives every branch
// directly; the route (router-discovery.ts POST /sources/reattach-missing) is the IO shell that reads
// the roster + live bindings and runs the attach with the same prove-before-write / verify-after
// guarantee changeBindings already enforces.

import type { DownpipeConfig } from "../sched/types.ts";
import type { AttachSource } from "./attach.ts";

// UnreconstructableSource is a missing binding the roster cannot rebuild: the config records the
// binding NAME but not the native resource id attach needs (a legacy config saved before the id was
// recorded). The fix is operator-side: re-save the source so the id is captured, then re-attach.
export interface UnreconstructableSource {
  binding: string;
  type: string; // kv | r2 | d1 | secrets
  downpipes: string[]; // ids of downpipes whose next run this breaks
  reason: string; // which native id is missing
}

export interface ReattachPlan {
  // Missing bindings we CAN rebuild from the roster, deduped by binding name, sorted. Feed straight to
  // changeBindings(add=toAttach, remove=[]): every entry is a valid AttachSource carrying its native id.
  // A binding name two downpipes disagree about is NEVER here -- see `conflicting`.
  toAttach: AttachSource[];
  // Roster bindings already present on the live worker (idempotent skip; the deploy did not drop them).
  alreadyAttached: string[];
  // Missing bindings the roster cannot rebuild (no recorded native id); surfaced, never silently dropped.
  unreconstructable: UnreconstructableSource[];
  // Binding names two or more downpipes claim with DIFFERENT native ids (or types): a conflict that is
  // never auto-picked, reported even when the binding is currently alreadyAttached (see THE CONFLICT
  // RULE above).
  conflicting: ConflictingSource[];
  // The downpipe ids that reference each binding in toAttach (so the caller/audit can name what recovers).
  affects: Record<string, string[]>;
  // MALFORMED sources (G131): a downpipe whose source is binding-backed (kv/r2/d1/secrets) and whose config
  // carries NO BINDING NAME AT ALL. classifySource can present nothing to re-attach for it, so the planner's
  // `break`/`continue` used to drop it on the floor: it appears in NEITHER toAttach, NOR alreadyAttached, NOR
  // unreconstructable, NOR conflicting. "Downpipe X was silently omitted from the heal plan" is precisely
  // this, and it is the worst omission of the four -- an unreconstructable source at least TELLS the operator
  // to re-save it, whereas this one is invisible: the heal reports success and that downpipe never runs again.
  // It is not a re-attachable binding, so it does not belong in any of the other four lists; it is the plan's
  // own honesty about what it could not even consider. Downpipe ids are engine-minted.
  malformed: MalformedSource[];
}

// MalformedSource is one downpipe whose binding-backed source records no binding NAME, so the re-attach
// planner has nothing to plan for it. `type` is the closed source type; `downpipe` is the engine-minted id.
export interface MalformedSource {
  downpipe: string;
  type: string; // kv | r2 | d1 | secrets
}

// ConflictingSource is a binding NAME that two or more downpipes' configs disagree about: each claims a
// DIFFERENT native resource id (or a different source type) for the same shared Worker binding name.
// The roster alone cannot say which claim is legitimate, so this is never resolved by picking one -- it
// blocks that binding out of toAttach and is surfaced here for an owner to resolve by hand.
export interface ConflictingSource {
  binding: string;
  downpipes: string[]; // every downpipe id holding one of the disagreeing claims, sorted
  reason: string;
}

// classifySource maps ONE downpipe source to the AttachSource(s) needed to re-create its Worker
// binding(s), or flags the ones whose native id the roster did not record. Only the binding-backed
// source types are returned; cf-config / workers / stream / images / artifacts read the Cloudflare REST
// API with the discovery token (NOT a Worker binding), so a deploy never drops them and they are skipped.
// `malformed` (G131) is the third arm the caller could not previously see: a binding-backed source that
// records NO binding name. It presents nothing to re-attach, so both branches below used to `break`/`continue`
// and the source vanished from the plan entirely -- neither attachable, nor already attached, nor
// unreconstructable, nor conflicting. The heal then reports success while that downpipe stays broken forever.
// It carries the closed source TYPE only (the config has no name to carry).
export function classifySource(source: DownpipeConfig["source"]): { ok: AttachSource[]; bad: { binding: string; type: string; reason: string }[]; malformed: string[] } {
  const ok: AttachSource[] = [];
  const bad: { binding: string; type: string; reason: string }[] = [];
  const malformed: string[] = [];
  switch (source.type) {
    case "kv": {
      if (!source.binding) { malformed.push("kv"); break; } // a malformed config with no binding presents nothing to re-attach
      if (source.namespaceId) ok.push({ type: "kv", binding: source.binding, namespaceId: source.namespaceId });
      else bad.push({ binding: source.binding, type: "kv", reason: "the KV namespace id was not recorded; re-save this source from the Sources screen to capture it, then re-attach" });
      break;
    }
    case "r2": {
      if (!source.binding) { malformed.push("r2"); break; }
      if (source.bucketName) ok.push({ type: "r2", binding: source.binding, bucketName: source.bucketName });
      else bad.push({ binding: source.binding, type: "r2", reason: "the R2 bucket name was not recorded; re-save this source from the Sources screen to capture it, then re-attach" });
      break;
    }
    case "d1": {
      if (!source.binding) { malformed.push("d1"); break; }
      if (source.databaseId) ok.push({ type: "d1", binding: source.binding, databaseId: source.databaseId });
      else bad.push({ binding: source.binding, type: "d1", reason: "the D1 database id was not recorded; re-save this source from the Sources screen to capture it, then re-attach" });
      break;
    }
    case "secrets": {
      // A secrets source covers a SET of named secrets, each its own secrets_store_secret binding.
      for (const sec of source.secrets ?? []) {
        if (!sec.binding) { malformed.push("secrets"); continue; }
        if (sec.storeId) ok.push({ type: "secrets", binding: sec.binding, storeId: sec.storeId, secretName: sec.name });
        else bad.push({ binding: sec.binding, type: "secrets", reason: "the Secrets Store store id was not recorded; re-save this source from the Sources screen to capture it, then re-attach" });
      }
      break;
    }
    default:
      // cf-config / workers / stream / images / artifacts: not Worker bindings, never dropped by a deploy.
      break;
  }
  return { ok, bad, malformed };
}

// nativeIdKey identifies the ONE Cloudflare resource an AttachSource claims: its type plus native id.
// Two AttachSources for the SAME binding name are the SAME source only when this key matches; any
// mismatch means two downpipe configs disagree about what the shared binding name actually points at.
function nativeIdKey(a: AttachSource): string {
  switch (a.type) {
    case "kv": return `kv:${a.namespaceId ?? ""}`;
    case "r2": return `r2:${a.bucketName ?? ""}`;
    case "d1": return `d1:${a.databaseId ?? ""}`;
    case "secrets": return `secrets:${a.storeId ?? ""}/${a.secretName ?? ""}`;
    default: return `${a.type}:`; // defensive: classifySource never emits any other type today
  }
}

// planRosterReattach is the PURE plan: given the roster (downpipe configs) and the binding names
// currently LIVE on the worker, return what to re-attach (missing + rebuildable), what is already
// attached (skip), what cannot be rebuilt (missing native id), and what is CONFLICTING (two downpipes
// disagree about the same binding name's native id). Deduped by binding name across downpipes that
// share a source; deterministic order so the output is stable and testable.
export function planRosterReattach(downpipes: Pick<DownpipeConfig, "id" | "source">[], liveBindingNames: ReadonlySet<string>): ReattachPlan {
  const toAttachByName = new Map<string, AttachSource>();
  const affects = new Map<string, Set<string>>();
  const alreadySet = new Set<string>();
  const badByName = new Map<string, UnreconstructableSource>();
  // claimsByName tracks EVERY distinct native id claimed for a binding name, across the WHOLE roster,
  // live or missing -- so a conflict is caught even while one claim is currently attached, which is the
  // only way to warn an owner before the NEXT deploy-drop + reattach would silently pick a claim.
  const claimsByName = new Map<string, Map<string, Set<string>>>();
  // G131: the sources the plan can present NOTHING for -- a binding-backed source with no binding name.
  // Collected so the plan's own omissions are reportable rather than silent.
  const malformed: MalformedSource[] = [];

  const note = (binding: string, dpId: string) => {
    const s = affects.get(binding) ?? new Set<string>();
    s.add(dpId);
    affects.set(binding, s);
  };

  for (const dp of downpipes) {
    const { ok, bad, malformed: mal } = classifySource(dp.source);
    for (const t of mal) malformed.push({ downpipe: dp.id, type: t });
    for (const a of ok) {
      note(a.binding, dp.id);
      const claims = claimsByName.get(a.binding) ?? new Map<string, Set<string>>();
      const key = nativeIdKey(a);
      const ids = claims.get(key) ?? new Set<string>();
      ids.add(dp.id);
      claims.set(key, ids);
      claimsByName.set(a.binding, claims);

      if (liveBindingNames.has(a.binding)) {
        alreadySet.add(a.binding);
        continue;
      }
      // First downpipe to claim a binding name wins here; a second, AGREEING reference to the same
      // binding is the same source and is deduped (its downpipe is still recorded in `affects`). A
      // DISAGREEING claim is never picked -- resolved below, once every downpipe has been seen, into
      // `conflicting`, and removed from toAttach entirely.
      if (!toAttachByName.has(a.binding)) toAttachByName.set(a.binding, a);
    }
    for (const b of bad) {
      note(b.binding, dp.id);
      if (liveBindingNames.has(b.binding)) {
        alreadySet.add(b.binding); // present despite a missing recorded id: nothing to do
        continue;
      }
      const prior = badByName.get(b.binding);
      if (prior === undefined) badByName.set(b.binding, { binding: b.binding, type: b.type, downpipes: [], reason: b.reason });
    }
  }

  // A binding that is both rebuildable (from one downpipe) and unrecorded (from another) is rebuildable:
  // drop it from the unreconstructable set so the operator is not told to re-save what we can already fix.
  for (const name of toAttachByName.keys()) badByName.delete(name);

  // A binding name claimed with MORE THAN ONE distinct native id (nativeIdKey is type-prefixed, so a
  // type mismatch counts too) is a CONFLICT: never auto-pick it. Exclude it from toAttach/unreconstructable
  // and surface it instead, naming every downpipe involved -- this is the fix for the confused-deputy
  // this module never checked for: a downpipe.write-only caller planting a second, malicious claim on an
  // existing binding name must never be able to silently win the re-attach.
  const conflicting: ConflictingSource[] = [];
  for (const [binding, claims] of claimsByName) {
    if (claims.size <= 1) continue;
    toAttachByName.delete(binding);
    badByName.delete(binding);
    const downpipeIds = [...new Set([...claims.values()].flatMap((s) => [...s]))].sort();
    conflicting.push({
      binding,
      downpipes: downpipeIds,
      reason: `${claims.size} downpipes claim binding "${binding}" as different Cloudflare resources (${[...claims.keys()].sort().join(" vs ")}); refusing to auto-attach until the conflicting downpipe config(s) are corrected or removed.`,
    });
  }

  const affectsOut: Record<string, string[]> = {};
  for (const [binding, ids] of affects) affectsOut[binding] = [...ids].sort();
  for (const u of badByName.values()) u.downpipes = (affectsOut[u.binding] ?? []).slice();

  return {
    toAttach: [...toAttachByName.values()].sort((a, b) => a.binding.localeCompare(b.binding)),
    alreadyAttached: [...alreadySet].sort(),
    unreconstructable: [...badByName.values()].sort((a, b) => a.binding.localeCompare(b.binding)),
    conflicting: conflicting.sort((a, b) => a.binding.localeCompare(b.binding)),
    affects: affectsOut,
    malformed: malformed.sort((a, b) => a.downpipe.localeCompare(b.downpipe) || a.type.localeCompare(b.type)),
  };
}
