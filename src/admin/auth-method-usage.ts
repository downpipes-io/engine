// auth-method-usage.ts -- WHICH CREDENTIAL PATH THE ESTATE ACTUALLY RAN ON, AND WHEN.
//
// THE QUESTION. "Was this estate behind Access when the change was made, and how long did it run on the shared
// break-glass token?" Post-incident, that question decides whether a governance mutation was made by a verified
// human behind Cloudflare Access or by whoever held the shared bearer, and how wide the degraded window was.
//
// WHAT THE PACK COULD SAY BEFORE THIS. Nothing. status.tokenFallbackDisabled and status.adminTokenConfigured are
// PRESENCE booleans read at pack-build time (the token CAN be used); authPosture.adminCredentialPaths is a
// CAPABILITY count (how many alternative sign-in paths EXIST). Neither says which method was USED, or when, or
// for how long. The console's amber "token fallback in use" chip is rendered from the live session and dies with
// the browser tab, and the audit excerpt deliberately carries no authn events. The one partial fact,
// configEvents[].attributed, is a per-event boolean over a handful of allowlisted CONFIG actions that separates
// "an email was attributed" from "it was not" -- it cannot date the start of a degraded posture, cannot bound its
// duration, and cannot tell Access from passkey from OIDC from SAML (all four carry an email).
//
// WHAT THIS RECORDS. The engine ALREADY classifies every admin request's credential path into the closed
// AuthMethod set (access | passkey | oidc | saml | token) in resolveCaller. This counts that, per method, on the
// SAME bounded day-ring the auth signals use: an all-time count, a firstAt, a lastAt, and 14 UTC-day buckets. A
// closed method enum x a coarse day bucket x an integer count.
//
// THIS IS NOT AN AUTH SIGNAL, and it deliberately does not live in AUTH_SIGNAL_NAMES. That vocabulary is the set
// of DEFENSIVE-BRANCH FAILURES (a fail-closed limiter, a refused assertion), and a successful admin request is a
// working path: filing one there would put a healthy estate's ordinary traffic into the aggregate the bot reads
// for "an auth branch is firing". This is a POSTURE record -- it says what the estate ran on, not that anything
// went wrong -- so it rides authPosture (section 4.19), which is exactly where the capability counts it
// completes already live.
//
// NO-CUSTODY. A closed method name, integer counts, and engine-minted ISO stamps. Never a session id, never an
// email, never a subject, never an IP, never a token. The buckets are counts of requests, and a count carries no
// identity.
//
// COST DISCIPLINE (why the throttle exists). This fires on EVERY authenticated admin request, including the
// console's status poll, so an unthrottled recorder would drive one Durable Object write per request forever --
// the exact DoS shape recordAuthSignalThrottled exists to avoid on the RBAC hot path. The router coalesces
// instead: at most ONE write per method per THROTTLE_MS per isolate, carrying the number of requests it stands
// for, with the deferred tail flushed on the pack read. Storage-write rate is bounded; the counts stay real.

import type { AuthMethod } from "./identity-roles.ts";
import { doURL } from "../do-url.ts";

/** The closed credential paths an admin request can authenticate on (identity-roles.ts AuthMethod). */
export const ADMIN_AUTH_METHODS = ["access", "passkey", "oidc", "saml", "token"] as const;
const ADMIN_AUTH_METHOD_SET: ReadonlySet<string> = new Set(ADMIN_AUTH_METHODS);

/** isAdminAuthMethod is the closed-set gate both the router and the DO apply before a method name is stored. */
export function isAdminAuthMethod(m: unknown): m is AuthMethod {
  return typeof m === "string" && ADMIN_AUTH_METHOD_SET.has(m);
}

/** The DO storage key holding the per-method usage aggregate (an AuthSignalAgg keyed by ADMIN_AUTH_METHODS). */
export const AUTH_METHOD_USAGE_KEY = "authmethodusage";

// The per-isolate write window. One minute: long enough that a poll storm costs one write, short enough that a
// method's FIRST use inside any minute lands on disk immediately (so the day bucket, the firstAt and the lastAt
// -- the facts that BOUND the degraded window -- are never deferred).
const METHOD_USE_THROTTLE_MS = 60_000;

// How many deferred EVENTS one method may hold in this isolate before the throttle gives up and writes. It
// bounds what an isolate eviction can cost: at most this many requests of that method, which makes the counts a
// LOWER BOUND by at most this much and never more. The day-bucket presence, the firstAt and the lastAt survive an
// eviction regardless (the window's first event was written immediately), so the answer does not.
const METHOD_USE_PENDING_FLUSH = 25;

// Per-isolate throttle state. Instance state of the Worker isolate, never persisted, and it can hold nothing but
// a method name and an integer.
const lastWriteAt = new Map<string, number>();
const pending = new Map<string, number>();

/**
 * noteAdminAuthMethod records ONE authenticated admin request's credential path. Best-effort and never throwing:
 * a diagnostic write must never change an auth decision that has already been made.
 *
 * @param scheduler - the scheduler DO stub.
 * @param method - the closed credential path resolveCaller established for this request.
 */
export async function noteAdminAuthMethod(scheduler: DurableObjectStub, method: AuthMethod): Promise<void> {
  if (!isAdminAuthMethod(method)) return;
  const now = Date.now();
  const last = lastWriteAt.get(method);
  const deferred = pending.get(method) ?? 0;
  if (last !== undefined && now - last < METHOD_USE_THROTTLE_MS && deferred < METHOD_USE_PENDING_FLUSH) {
    // Inside the open window: defer the WRITE, keep the EVENT.
    pending.set(method, deferred + 1);
    return;
  }
  lastWriteAt.set(method, now);
  pending.delete(method);
  await postMethodUse(scheduler, method, deferred + 1);
}

/**
 * flushAdminAuthMethodUsage writes out every event the throttle deferred and has not yet flushed. It runs at the
 * START of the support-bundle build, which is the one moment the deferred tail must be on disk: a burst of
 * break-glass traffic that STOPS inside its window would otherwise leave its last events in the isolate with no
 * later request to carry them out, and the pack -- built from the same isolate minutes later -- would under-report
 * the very usage it was built to bound. Best-effort; never throws.
 *
 * @param scheduler - the scheduler DO stub.
 */
export async function flushAdminAuthMethodUsage(scheduler: DurableObjectStub): Promise<void> {
  if (pending.size === 0) return;
  const due = [...pending.entries()];
  pending.clear();
  for (const [method, n] of due) {
    if (n > 0 && isAdminAuthMethod(method)) await postMethodUse(scheduler, method, n);
  }
}

async function postMethodUse(scheduler: DurableObjectStub, method: AuthMethod, n: number): Promise<void> {
  try {
    await scheduler.fetch(doURL("/auth-method-use"), {
      method: "POST",
      body: JSON.stringify({ method, n }),
      headers: { "content-type": "application/json" },
    });
  } catch {
    /* best-effort: the request has already been authorised, and a posture write must never fail it */
  }
}
