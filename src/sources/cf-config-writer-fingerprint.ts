// THE WRITER FINGERPRINT: what a restore proof was a proof OF.
//
// WHY THIS EXISTS. A live restore proof is a claim about a surface at a moment: this writer, driven this
// way, put this surface back. NO_LIVE_ROUTE_HERE already records the first way that claim rots, which is a
// harness quietly ceasing to re-run it. This closes the second way, which is the writer changing underneath
// a proof that nobody re-ran. Both were live: dns-settings stopped being re-proved when the refusal
// classifier learnt a phrase, and PROVEN_WRITE_SURFACES has carried surfaces across writer corrections
// (site_tag added to SERVER_STAMPED, using_latest_model dropped, writeSingleObject moved off the
// whole-object PATCH) with the membership untouched, because membership is a set of ids and an id does not
// notice.
//
// So a banked proof carries a fingerprint of the code path it exercised, and it stops counting when the
// fingerprint no longer matches. That third input is what lets the measured number FALL. Without it the
// ledger is a tally: rows only ever accumulate, and the count rises whatever happens to the product.
//
// WHAT GOES INTO A FINGERPRINT, and every part of it is EVALUATED from the loaded registry rather than
// scraped out of source text. This file reads no .ts file and greps nothing.
//
//   the surface's own facts        id, scope, restoreTier
//   the read                       read.toString(). A restore is diffed against a read, so a read that
//                                  changes shape can break a restore that nobody touched. dex-tests is the
//                                  recorded case: the reader was archiving the envelope as the single item,
//                                  and a restore had nothing to rebuild from.
//   the writer                     write.toString(). The SHARED engine. Twenty-seven surfaces share
//                                  writeSingleObject's body, so a change there expires all twenty-seven,
//                                  which is correct: they were proved through it.
//   what the writer DECLARES       cfWriteKind / cfWriteMethod / cfWritePath / cfWriteSpec, evaluated at
//                                  sentinel ids. This is the PER-SURFACE half, and it is the half that
//                                  decides whether a restore corrupts data: the path, the verb, the natural
//                                  key, the field rules. `keep: ["scope"]` on url-normalization is invisible
//                                  in any function body and is exactly the kind of edit that must expire a
//                                  proof.
//
// A WRITER THAT DECLARES NOTHING is fingerprinted from its function source alone, and that is a weaker
// fingerprint rather than a missing one: writeDns and the other hand-written writers carry their whole
// per-surface spec inside their own bodies, so the source IS the spec there. The list is reported by
// cfWriterFingerprints so it can shrink on purpose.
//
// WHAT MAKES A FINGERPRINT MOVE WITHOUT THE PRODUCT MOVING, stated rather than discovered later. Function
// source text comes from the running runtime, so a comment edit inside a writer body changes it, and so
// could a change in how the runtime strips types. Both make proofs EXPIRE, never the reverse: the direction
// of error is a re-run, not a false green. That trade is deliberate.
//
// House style: Australian English, no em dashes, no rule-of-three.

import type { CfConfigSurface } from "./cf-config-core.ts";
import { CF_CONFIG_SURFACES } from "./cf-config-registry.ts";

/**
 * CONSOLE_RESTORE_PATH_FILES: the layer a customer crosses that no engine-API proof touches.
 *
 * WHY A SECOND FINGERPRINT AT ALL. Every engine-side live harness reaches a surface by calling its own
 * write() directly. That is the right way to prove a WRITER and it skips everything a customer goes
 * through: decoding the snapshot, building the plan, summarising the diff the operator reads before
 * consenting, scoping the approval, and applying under it. Only the console round trip crosses that layer,
 * and it is engine code that moves independently of any writer. restore-cfconfig.ts changed on 2026-08-08,
 * which postdates every engine-API proof in the tree. A fingerprint that omitted this could not fall when
 * the layer between the customer and the writer changed, which is most of what a restore depends on.
 *
 * THE LIST IS WHOLE FILES AND THAT IS DELIBERATELY OVER-SENSITIVE. Three of the four carry restore work
 * that is not cf-config, so an unrelated edit inside them expires console-product rows. The alternative is
 * a rule that picks lines or symbols out of a file by pattern, which is a scanner reading source as data
 * and a recorded defect class in this workspace. The error direction here is a re-drive of a cell that
 * already runs on a shared estate, against a false green on the only layer a customer actually sees.
 *
 * These are paths rather than imports because this module is bundled into the Worker and may not read
 * files. The reader supplies the bytes; see test/lib/cf-restore-proofs.ts.
 */
export const CONSOLE_RESTORE_PATH_FILES: readonly string[] = [
  // decodeConfigSnapshot, summariseDiff and coarseCfReason: the whole of the cf-config half of a plan.
  // summariseDiff is what an operator consents to, so a change to its wording changes what was consented to.
  "src/admin/restore-cfconfig.ts",
  // The dry-run plan the console's "Build the restore plan" button produces, including which surfaces are
  // in scope by default.
  "src/admin/restore-plan.ts",
  // The apply leg under an approval, which is the only leg that writes.
  "src/admin/restore-apply.ts",
  // Approval scoping and the plan hash an approver signs. A restore that could be approved for a wider
  // scope than it was planned for is a product defect no writer proof would ever see.
  "src/admin/approvals.ts",
];

/** Ids substituted into every path builder, so a fingerprint is about the PATH and never about an account. */
export const FINGERPRINT_IDS = { accountId: "__ACCT__", zoneId: "__ZONE__" } as const;
/** The item id substituted into an item-path builder, for the same reason. */
export const FINGERPRINT_ITEM = "__ITEM__";

/** The facts a writer publishes about itself. Mirrors the Object.assign tags on each writer factory. */
interface DeclaredWriter {
  cfWriteKind?: string;
  cfWriteMethod?: string;
  cfWritePath?: (ids: { accountId: string; zoneId?: string }) => string;
  cfWriteSpec?: unknown;
  cfListItemPath?: (ids: { accountId: string; zoneId?: string }, id: string) => string;
  cfListUpdateMethod?: string;
}

/**
 * Canonical JSON: object keys in sorted order at every depth, so a fingerprint does not move because a
 * property was written in a different order. Arrays keep their order, which is meaningful.
 */
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(rec[k])}`).join(",")}}`;
}

/**
 * Turn a declared spec into something canonical() can hash.
 *
 * PATH BUILDERS ARE CALLED, not stringified, and the difference is the whole point. `(i) =>
 * /zones/${i.zoneId}/url_normalization` and `(i) => /zones/${i.zoneId}/settings/rum` have different
 * sources, but so do two spellings of the same path, and it is the PATH that decides which object a restore
 * writes into. A builder that will not answer with a string is stringified instead rather than dropped: a
 * spec field that vanished from the basis would be a per-surface fact the fingerprint stopped noticing.
 */
function serialise(value: unknown): unknown {
  if (typeof value === "function") {
    const fn = value as (...args: unknown[]) => unknown;
    try {
      const out = fn.length >= 2 ? fn(FINGERPRINT_IDS, FINGERPRINT_ITEM) : fn(FINGERPRINT_IDS);
      if (typeof out === "string") return out;
    } catch {
      /* falls through to the source text below */
    }
    return fn.toString();
  }
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(serialise);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = serialise(v);
  return out;
}

/** The basis a fingerprint is taken over, exported so a report can show WHAT differs rather than that it does. */
export function writerFingerprintBasis(surface: CfConfigSurface): Record<string, unknown> | null {
  if (typeof surface.write !== "function") return null;
  const w = surface.write as unknown as DeclaredWriter;
  const declared: Record<string, unknown> = {};
  if (w.cfWriteKind !== undefined) declared.kind = w.cfWriteKind;
  if (w.cfWriteMethod !== undefined) declared.method = w.cfWriteMethod;
  if (typeof w.cfWritePath === "function") declared.path = serialise(w.cfWritePath);
  if (typeof w.cfListItemPath === "function") declared.itemPath = serialise(w.cfListItemPath);
  if (w.cfListUpdateMethod !== undefined) declared.listUpdateMethod = w.cfListUpdateMethod;
  if (w.cfWriteSpec !== undefined) declared.spec = serialise(w.cfWriteSpec);
  return {
    id: surface.id,
    scope: surface.scope,
    restoreTier: surface.restoreTier,
    read: surface.read.toString(),
    write: surface.write.toString(),
    declared,
    declaresNothing: Object.keys(declared).length === 0,
  };
}

/** SHA-256 over the canonical basis. Sync and dependency-free so a validator can call it in a loop. */
async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface WriterFingerprint {
  id: string;
  /** "sha256:<hex>". Prefixed so a row that carries some other digest cannot be compared by accident. */
  fingerprint: string;
  /** True when the writer publishes no facts about itself, so the basis is its source text alone. */
  declaresNothing: boolean;
}

/**
 * Every surface that has a writer, fingerprinted. Keyed by surface id.
 *
 * DERIVED, NEVER PINNED, for the same reason the capture gate's denominator is: a fingerprint written down
 * anywhere but here is a second copy that drifts, and the drift is silent because both halves are hex.
 */
export async function cfWriterFingerprints(): Promise<Map<string, WriterFingerprint>> {
  const out = new Map<string, WriterFingerprint>();
  for (const s of CF_CONFIG_SURFACES) {
    const basis = writerFingerprintBasis(s);
    if (basis === null) continue;
    out.set(s.id, {
      id: s.id,
      fingerprint: `sha256:${await sha256Hex(canonical(basis))}`,
      declaresNothing: basis.declaresNothing === true,
    });
  }
  return out;
}
