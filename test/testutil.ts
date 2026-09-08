// Shared helpers for the validate-*.ts test scripts.

import { concat, utf8 } from "../src/crypto/bytes.ts";
import { restorePlanHash } from "../src/admin/approvals.ts";
import type { RestoreRequest } from "../src/admin/restore-types.ts";

/** Byte-for-byte equality of two Uint8Arrays. */
export function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Drain any of the body shapes a Destination get() may return into a flat Uint8Array. */
export async function toBytes(
  value: ReadableStream<Uint8Array> | ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
): Promise<Uint8Array> {
  if (value === null) return new Uint8Array(0);
  if (typeof value === "string") return utf8(value);
  if (value instanceof Uint8Array) return value.slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  if (value instanceof ReadableStream) {
    const parts: Uint8Array[] = [];
    const reader = (value as ReadableStream<Uint8Array>).getReader();
    for (;;) {
      const { done, value: chunk } = await reader.read();
      if (done) break;
      parts.push(chunk);
    }
    return concat(...parts);
  }
  // Blob
  return new Uint8Array(await (value as Blob).arrayBuffer());
}

/** A single-chunk ReadableStream over the given bytes. */
export function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

/** Cryptographically random bytes (bounded by the 64 KiB getRandomValues cap). */
export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * A deterministic large filler for bodies past the 64 KiB getRandomValues cap; the exact bytes do
 * not matter (the seal hashes whatever it is given), only that they round-trip.
 */
export function fill(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
  return b;
}

/**
 * seedBoundRole writes a BOUND role-table entry (`role:sub:<subject>`) straight into a test DO's
 * storage, so a synthetic Caller the test forges also holds that authority in the DO's OWN tables.
 *
 * Why this exists. The dual-control routes TRUST the router-forwarded role on the caller header (the
 * documented "from the router only" trust), so a test could always drive request/approve with a forged
 * Caller and no table entry at all. The SPEND-TIME identity binding cannot work that way: it re-resolves
 * the recorded maker and checker from their immutable subjects against the live tables, precisely because
 * at the spend there is no caller and no header to trust. A test that seeds an approval by two identities
 * the role table has never heard of is therefore asserting the mechanics of a ceremony that, in
 * production, could not have happened; seeding the grant makes the fixture match the world.
 */
export async function seedBoundRole(
  storage: { put<T>(key: string, value: T): Promise<void> },
  subject: string,
  email: string | null,
  role: "viewer" | "operator" | "restore-operator" | "approver" | "access-admin" | "owner",
): Promise<void> {
  await storage.put(`role:sub:${subject}`, {
    subject,
    email: email ?? "",
    role,
    grantedBy: "test-seed",
    grantedAt: "2026-01-01T00:00:00.000Z",
  });
}

/**
 * notePlanAnchor records THE PLAN ANCHOR for a plan hash through the DO's OWN `/restore/plan-seen` route,
 * which is what the dry run does before an operator can raise an approval request.
 *
 * Why a bed needs it. requestRestore REFUSES a request whose plan hash has no recorded dry run
 * (scheduler-do-restore-approval.ts): the engine will not mint an approval against a preview it cannot date,
 * because a swept anchor and one that never existed look identical in storage, and reading either as "anchor
 * to now" is what let a stale plan card be re-requested for a fresh 24 hours once per cycle, for ever. So a
 * bed that raises a request with no preceding preview is driving a sequence the product no longer permits,
 * and its assertions would be about a path no operator can take.
 *
 * Driven through the real route rather than written into storage, so this seeding cannot drift from what the
 * product records: if the anchor's key, shape or clamp changes, every bed follows it automatically.
 * Two target shapes, because the beds have two: a stub's own `fetch(url, init)` (the router-side beds), and a
 * SchedulerDO instance, whose fetch takes a Request (the beds that call the DO's methods directly).
 */
export type PlanAnchorTarget = ((url: string, init: RequestInit) => Promise<Response>) | { fetch(req: Request): Promise<Response> };

export async function notePlanAnchor(target: PlanAnchorTarget, planHash: string, plannedAtMs?: number): Promise<void> {
  const url = "https://scheduler.internal/restore/plan-seen";
  const init: RequestInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ planHash, ...(plannedAtMs !== undefined ? { plannedAt: plannedAtMs } : {}) }),
  };
  await (typeof target === "function" ? target(url, init) : target.fetch(new Request(url, init)));
}

/**
 * notePlanAnchorForRequest is notePlanAnchor for a bed that drives the ROUTER's POST /admin/restore/request:
 * it computes the plan hash from the request body exactly as restorePlanHash does, then records the anchor.
 *
 * A MALFORMED BODY IS A NO-OP, deliberately, and it mirrors the router's own ordering: the request route
 * validates runId and returns its 400 BEFORE the plan hash is computed, so a case probing that validation
 * must not be diverted into a hash-computation throw here. restorePlanHash canonicalises its binding and
 * rejects an absent/non-string runId, which is exactly the shape those cases send.
 */
export async function notePlanAnchorForRequest(send: (url: string, init: RequestInit) => Promise<Response>, body: unknown): Promise<void> {
  let planHash: string;
  try {
    planHash = await restorePlanHash(body as RestoreRequest);
  } catch {
    return;
  }
  await notePlanAnchor(send, planHash);
}
