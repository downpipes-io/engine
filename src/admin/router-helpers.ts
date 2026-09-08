// Leaf module of small router helpers shared between admin/router.ts (the hub) and its
// route spokes (admin/licence, admin/preflight, admin/support, admin/update-gate,
// admin/restore) plus seal/verify-at-seal and seal/runstate. This breaks the
// router.ts<->spoke import cycles: the spokes import these helpers, router.ts imports the
// spokes, and neither imports the other.

import type { Env } from "../env.d.ts";
import { DISCOVERY_SECRET_AAD, loadConfigWrapKey, resolveConfigSecret, type WrappedSecret } from "./config-secret.ts";
import type { AuthVerdict, Caller, RoleSource } from "./identity.ts";
import type { CustomRole } from "./identity-rbac.ts";

// schedulerStub returns the singleton scheduler DO (one per account).
export function schedulerStub(env: Env): DurableObjectStub {
  const id = env.SCHEDULER.idFromName("account-scheduler");
  return env.SCHEDULER.get(id);
}

// doURL now lives in the dependency-free ../do-url.ts, because this module is not the leaf its header
// claims: it reaches sched/scheduler-do.ts for a type, so importing doURL from here drags a caller into
// the engine's existing import cycles. Re-exported so the call sites that import it by name from here
// are unaffected.
import { doURL } from "../do-url.ts";
export { doURL };

// recordAuthSignalEdge is the shared BEST-EFFORT recorder for a Worker-EDGE auth-signal (P3): a defensive branch
// that runs OUTSIDE the DO (a fail-closed rate-limiter outage, a break-glass-retire check that could not reach the
// DO) POSTs one CLOSED event name to the DO's bounded auth-signal aggregate, so the outage is diagnosable from the
// support pack. It NEVER throws and NEVER blocks the caller's response: the single try/catch swallows BOTH a
// synchronous fetch throw and a rejected promise (the await unwraps a rejection into the same catch). It is
// deliberately awaitable (Promise<void>) so a test can flush it, but production callers fire-and-forget with
// `void`. The DO drops an out-of-vocabulary name, so only a vocabulary member is ever stored - never a token,
// email, ip or reason. Caveat: these edge sites fire precisely when the SAME DO was unavailable, so a total
// outage may drop this write too; when the DO is merely flaky the signal still lands (strictly better than the
// prior zero durability). It lives in this leaf module so BOTH router-core and router-session (which already
// import doURL here) can share it without a spoke-to-spoke import.
export async function recordAuthSignalEdge(scheduler: DurableObjectStub, name: string): Promise<void> {
  try {
    await scheduler.fetch(doURL("/auth-signal"), { method: "POST", body: JSON.stringify({ name }), headers: { "content-type": "application/json" } });
  } catch {
    /* best-effort: a diagnostic write must never affect or delay the auth response */
  }
}

// recordAuthzRefusalEdge (G175) posts ONE closed authorisation-guard gate from a router-decided refusal into the
// DO's authzRefusals ledger. It is the EDGE twin of the DO's own recordAuthzRefusal, and it exists because one of
// the three guards this gap is about is decided in the ROUTER and never reaches the DO at all: the
// no-first-party-session refusal on POST /sessions/terminate-others returns a 400 from the router itself, so the
// DO's AuthError funnel structurally cannot see it and no ledger row could ever exist for it.
//
// `gate` is a compile-time constant chosen by the call site, never derived from a request value. The DO re-checks
// it against the closed AUTHZ_GATE_SET and records nothing for a non-member, so this internal route cannot widen
// the key space even if a future caller drifts. Fire-and-forget: the refusal has already been decided and its
// response is returned unchanged.
export async function recordAuthzRefusalEdge(scheduler: DurableObjectStub, gate: string): Promise<void> {
  try {
    await scheduler.fetch(doURL("/diag/authz-refusal"), { method: "POST", body: JSON.stringify({ gate }), headers: { "content-type": "application/json" } });
  } catch {
    /* best-effort: a diagnostic write must never affect or delay the refusal it observed */
  }
}

// resolveDiscoveryToken finds the engine's read-only Cloudflare discovery token (the "Read all resources"
// token the cf-config/workers/media crawls and the storage-analytics sizing all read with): the scheduler
// DO's stored discovery config wins, else the DISCOVERY_API_TOKEN deploy var (the IaC/env fallback). Returns
// null when neither is set. DO-first then trimmed env -- the SINGLE token resolution shared by the run path
// (seal/runstate-helpers cfConfigToken) and every admin reader (cost sizing, discovery, destinations, the
// sources spokes), so an env-only deployment resolves the token everywhere or nowhere, never half (the drift
// that left media-source runs failing on a valid env token while the admin readers saw it). Never throws: a
// DO fault falls through to the env var.
export async function resolveDiscoveryToken(scheduler: DurableObjectStub, env: Env): Promise<string | null> {
  return (await resolveDiscoveryTokenDetailed(scheduler, env)).token;
}

// resolveDiscoveryTokenDetailed is resolveDiscoveryToken with the DO-fault flag the null hides (G130).
//
// THE GAP. The resolver returns null in TWO completely different worlds: no token is configured ANYWHERE (the
// operator never pasted one -- "go to the Sources screen"), or the DO read that holds the console-set token
// THREW and the env fallback happens to be absent too ("your scheduler is unreachable; the token you set is
// probably fine"). Both render as the same preflight line, and the ticket for one is useless for the other.
// doFault is set for the second, so the preflight item can carry the closed tokenResolve discriminator.
//
// The counter bump is unchanged (an env-fallback rescue is still counted in degraded-read-discovery-config);
// this only stops the fault being INVISIBLE on the null path, which is the path where it matters most.
export async function resolveDiscoveryTokenDetailed(scheduler: DurableObjectStub, env: Env): Promise<{ token: string | null; doFault: boolean }> {
  let doFault = false;
  try {
    const resp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
    const cfg = ((await resp.json()) as { config?: { token?: string | WrappedSecret } | null }).config ?? null;
    if (cfg && cfg.token !== undefined) {
      // The stored token is an envelope whenever CONFIG_WRAP_KEY is configured, a bare string on the
      // back-compat floor. resolveConfigSecret handles both and THROWS on a present envelope with no key
      // (a dropped deploy var), which must not become a silent "no token configured": that is the exact
      // lie G051 exists to stop, so it is counted like a DO read failure and reported as a fault.
      const token = await resolveConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), cfg.token, DISCOVERY_SECRET_AAD);
      if (token.trim() !== "") return { token, doFault: false };
    }
  } catch {
    // G051: the DO could not be read, so the resolver silently falls back to the env var -- or to null, which
    // every caller renders as "no discovery token is configured". A whole class of "we set the token and
    // discovery still says there is none" tickets lives in this catch. Counted, not swallowed.
    //
    // Issued as a DIRECT fetch rather than through admin/diag-counters.ts, because that module imports doURL
    // from THIS file and routing the bump through it would close an import cycle. The wire shape is identical
    // (a closed {name: count} tally that the DO-side applyAdminCounters re-validates), so the record is the
    // same; only the loss-of-the-loss counter is forgone, and this branch is by definition one where the DO is
    // already unreachable.
    doFault = true;
    void scheduler
      .fetch(doURL("/diag/admin-counters"), { method: "POST", body: JSON.stringify({ bumps: { "degraded-read-discovery-config": 1 } }), headers: { "content-type": "application/json" } })
      .catch(() => {});
  }
  const envToken = typeof env.DISCOVERY_API_TOKEN === "string" && env.DISCOVERY_API_TOKEN.trim() !== "" ? env.DISCOVERY_API_TOKEN.trim() : null;
  return { token: envToken, doFault };
}

// AdminRuntime carries capabilities the Worker entry injects into the admin handler that the admin
// module cannot build itself without importing the seal path (which would create an import cycle). The
// fetch entry provides sealNow so POST /admin/trigger can drive the run-now seal via ctx.waitUntil
// (XC-B1/B2): the route allocates the run in the DO, then seals it in the invocation's background.
// Lives here so the route spokes can share the shape without importing router.ts; router.ts
// re-exports it so importers by name are unchanged.
export interface AdminRuntime {
  sealNow: (state: import("../sched/types.ts").DownpipeState, trig: { runId: string; index: number; prevRunId: string | null }) => void;
  // canaryNow drives an immediate canary flight for POST /admin/canary/run (the console "fly now"
  // control): the route arms the bird due in the DO, then this seals/reads/restores it in the
  // invocation's background. Optional so a direct handleAdmin call without the fetch runtime (a test)
  // still typechecks; the live fetch path always injects it, so a real fly-now always flies.
  canaryNow?: () => void;
  // waitUntil is the raw ExecutionContext capability, threaded down for handlers that run BEFORE
  // authorise() and so never receive a RouterCtx: the pre-auth passkey ceremony (handlePasskey) fires its
  // diagnostic auth-signal writes as its very LAST action before returning the ceremony's Response, with no
  // further await anywhere after them. A write like that has no ctx.waitUntil to keep it alive and no
  // remaining synchronous work to give it a scheduling window either. Optional for the same
  // reason canaryNow is: a direct handleAdmin call with no fetch runtime (a unit test) still typechecks, and
  // falls back to the pre-existing bare `void` there, unchanged.
  waitUntil?: (task: Promise<unknown>) => void;
}

// RouterCtx is the post-auth dispatch context handleAdmin builds ONCE (after authorise() and
// resolveCaller) and hands to each post-auth route spoke. It carries exactly the locals the moved case
// bodies read; the spokes are the body-only halves of the original switch, so every value here is the
// same value the inline case read in handleAdmin. Each spoke runs a sub-switch on `${req.method} ${sub}`
// and returns the route's Response, or null when no case in that spoke matched (handleAdmin then tries
// the next spoke, exactly as the original single switch fell to the next case). The auth gate and every
// per-route capability check stay inside these bodies, unmoved relative to the handler they guard.
export interface RouterCtx {
  req: Request;
  env: Env;
  url: URL;
  scheduler: DurableObjectStub;
  caller: Caller;
  // sub is the method-independent path under /admin (the same `url.pathname.replace(/^\/admin/, "")`
  // handleAdmin computed once); the sub-switches key on `${req.method} ${sub}`, byte-identical to the hub.
  sub: string;
  sourceIp: string | null;
  runtime: AdminRuntime | undefined;
  // verdict / isOnlyOwner / roleSource / customRole are only read by GET /whoami (the identity echo);
  // they are carried here so that case can move with its spoke without a second DO round trip. verdict is
  // the POSITIVE (ok:true) variant: the hub builds ctx only AFTER its `if (!verdict.ok) return 401` guard
  // has run, so by construction it is always the authenticated shape, exactly as the inline whoami case saw
  // it after that same guard narrowed it (this records that narrowing in the type, it does not change it).
  verdict: Extract<AuthVerdict, { ok: true }>;
  isOnlyOwner: boolean;
  roleSource: RoleSource;
  customRole: CustomRole | undefined;
}
