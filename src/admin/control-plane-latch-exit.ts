// THE EXIT SENTENCE for a latched control plane.
//
// The recovery latch has three exits and they are guarded as EXACT COMPLEMENTS. reconcileControlPlane and
// applyControlPlaneAuthoritySlice both rebuild a WIPED plane, so both refuse a NON-EMPTY role table
// (scheduler-do-control-plane.ts). acknowledgeControlPlaneRecovery clears the latch and nothing else, so it
// refuses an EMPTY one. Between them they cover every estate, which is correct as a set of guards and was a
// dead end as a set of AFFORDANCES: the console called the first two and never the third, so an account whose
// role table is non-empty -- which the last-Owner guard makes the norm -- met a refusal on everything the
// banner offered.
//
// WHAT THIS FILE IS FOR, and what it deliberately is not. It does not widen any guard, and it grants nothing.
// It answers one question -- given the plane's own two emptiness facts, WHICH exit is actually open to this
// estate -- so a refusal can name a route that will accept the operator instead of one that must refuse them.
// A 409 reading "run the manual control-plane reconcile instead", answered to an estate the manual reconcile
// refuses by its own sibling guard, is a dishonest refusal, and the operator reading it spends the worst hour
// of their year on a route that was never open.
//
// It lives in its own module rather than in router-identity.ts because that file is AT its 1000-line budget
// (scripts/max-lines-lint.mjs), the same reason router-control-plane-recovery-ack.ts was split out.

import { doURL } from "./router-helpers.ts";

// LatchEmptiness is the pair of booleans that decides the exit. Deliberately not the whole status: nothing
// here reads a reason, a count, an identity or a staged artefact, so no customer value can reach a message.
export interface LatchEmptiness {
  recoveryRequired: boolean;
  configEmpty: boolean;
  // Present only on an engine whose DO serves it (added with this repair). Absent is UNKNOWN, never false:
  // a mixed deploy must fall back to the state-free sentence rather than assert the wrong half.
  roleTableEmpty: boolean | null;
}

// readLatchEmptiness pulls the two emptiness facts off the DO's own recovery-status route (the same read the
// console banner polls). It NEVER throws: this is called from inside a refusal path, and a failed diagnostic
// read must not turn a clean 409 into a 500. An unreadable status degrades to all-unknown, which composes to
// the state-free sentence below.
export async function readLatchEmptiness(scheduler: { fetch: (u: string, i?: RequestInit) => Promise<Response> }): Promise<LatchEmptiness> {
  try {
    const resp = await scheduler.fetch(doURL("/control-plane/recovery-status"), { method: "GET" });
    if (!resp.ok) return { recoveryRequired: false, configEmpty: false, roleTableEmpty: null };
    const body = (await resp.json()) as Record<string, unknown>;
    return {
      recoveryRequired: body.recoveryRequired === true,
      configEmpty: body.configEmpty === true,
      roleTableEmpty: typeof body.roleTableEmpty === "boolean" ? body.roleTableEmpty : null,
    };
  } catch {
    return { recoveryRequired: false, configEmpty: false, roleTableEmpty: null };
  }
}

// ACKNOWLEDGE_ROUTE is the one route that clears a latch for an established account, named in full wherever a
// refusal points at it. It is quoted rather than linked because these sentences are read in a support call and
// out of a screenshot, on an estate mid-incident whose audit ring may be empty.
export const ACKNOWLEDGE_ROUTE = "POST /admin/control-plane/acknowledge-recovery";

// exitTailFor composes the remedy half of a refusal from the emptiness pair. Every branch names a route that
// the guards will actually ACCEPT for that state; the unknown branch names none rather than guessing, which
// is the whole point of the fallback (a sentence that guesses wrong is the defect, not the absence of one).
export function exitTailFor(e: LatchEmptiness): string {
  if (e.roleTableEmpty === null) {
    return `If your operator roles survived the incident, the break-glass rebuild routes are not your exit at all: they refuse a non-empty role table by design. An owner clears the banner with ${ACKNOWLEDGE_ROUTE} once the configuration is back.`;
  }
  if (!e.roleTableEmpty && !e.configEmpty) {
    return `Your operator roles survived and your configuration is already back, so there is nothing here to rebuild: an owner clears the banner with ${ACKNOWLEDGE_ROUTE}.`;
  }
  if (!e.roleTableEmpty && e.configEmpty) {
    return `Your operator roles survived, so the break-glass rebuild routes refuse this estate by design and are not your exit. The scheduled health pass re-applies the configuration from the signed export on its own, and an owner then clears the banner with ${ACKNOWLEDGE_ROUTE}.`;
  }
  if (e.roleTableEmpty && !e.configEmpty) {
    return `Your role table is empty while your configuration is back, so neither the manual reconcile (it refuses a non-empty plane) nor the acknowledge (it refuses an empty role table) is open to you. Grant an owner role with the break-glass token, then clear the banner with ${ACKNOWLEDGE_ROUTE} as that owner.`;
  }
  return "Run the manual control-plane reconcile with your signed export, its detached signature and your break-glass token.";
}

// manualReconcileTail is the remedy half alone, for a refusal that already states its own cause.
export async function manualReconcileTail(scheduler: { fetch: (u: string, i?: RequestInit) => Promise<Response> }): Promise<string> {
  return exitTailFor(await readLatchEmptiness(scheduler));
}

// nothingToConfirmMessage is the whole sentence for the apply-staged 409 that used to read "nothing is staged
// for recovery; run the manual control-plane reconcile instead". That tail was wrong: an estate with two role
// rows and no staged record was answered it, and the manual reconcile
// refuses a non-empty role table at the sibling guard, so the engine was directing the operator at the one
// route its own guard would not let them take.
export async function nothingToConfirmMessage(scheduler: { fetch: (u: string, i?: RequestInit) => Promise<Response> }): Promise<string> {
  return `nothing is staged for recovery. ${await manualReconcileTail(scheduler)}`;
}
