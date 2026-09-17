// chaos-fault.ts -- the in-engine SOURCE-fault injector (assessment W5). Armed ONLY by the deploy-time var
// CHAOS_SOURCE_FAULT (a JSON fault spec, e.g. {"source":"cf-config","fault":"api-fault","at":1}); UNSET =>
// FAIL-SAFE NO-OP, byte-identical to production (every helper below returns the real fetch/binding untouched
// when the var is absent or does not name this source). It wraps a source adapter's OWN read boundary -- the
// Cloudflare-API fetch (cf-config / workers / stream / images / artifacts) or the KV binding (kv) -- so a
// fault injects exactly where a real upstream fault would, and the run's fail-open-per-item + loud-fail
// handling is what gets exercised. The chaos harness (chaos/srcfault-live.mjs) checks the invariant: under an
// armed fault a run must NEVER report a clean full capture; it must fail loud or surface incompleteness.
//
// This module is PURE + unit-testable (test/validate-chaos-source-fault.ts drives it offline with a stub
// fetch/binding); the live srcfault-run.sh path is just a deploy of wrangler.chaos.toml with the var set.

export interface SourceFaultSpec {
  source: string; // "kv" | "cf-config" | "workers" | "stream" | "images" | "artifacts"
  fault: string; // "api-fault" (inject a 500) | "api-timeout" (reject the fetch) | "cursor-expiry" | "vanish-midcrawl"
  at?: number; // 1-based index of the matching call/item to fault (default 1)
  path?: string; // optional: only fault an API call whose URL contains this substring (e.g. "/schedules", "/zones/")
  faultUntilMs?: number; // optional TRANSIENT deadline (absolute epoch-ms): fault the matching call ONLY while now < this,
  // so a run that RETRIES after the deadline (a new isolate) finds no fault and succeeds -- proves park-and-resume-to-
  // SUCCESS on a transient fault. Absent => the fault is PERMANENT (a sustained outage), behaviour UNCHANGED.
}

// parseSourceFault reads CHAOS_SOURCE_FAULT fail-safe: absent / blank / malformed / missing required fields
// all return null (a no-op), so a misconfigured var can never crash a run -- it simply does not arm a fault.
export function parseSourceFault(env: { CHAOS_SOURCE_FAULT?: string } | undefined): SourceFaultSpec | null {
  const raw = env?.CHAOS_SOURCE_FAULT;
  if (typeof raw !== "string" || raw.trim() === "") return null;
  try {
    const s = JSON.parse(raw) as Partial<SourceFaultSpec>;
    if (typeof s.source !== "string" || typeof s.fault !== "string") return null;
    return {
      source: s.source,
      fault: s.fault,
      at: typeof s.at === "number" && Number.isFinite(s.at) && s.at >= 1 ? Math.floor(s.at) : 1,
      ...(typeof s.path === "string" ? { path: s.path } : {}),
      // faultUntilMs is read FAIL-SAFE: a non-number (or non-finite) is ignored, leaving the fault permanent.
      ...(typeof s.faultUntilMs === "number" && Number.isFinite(s.faultUntilMs) ? { faultUntilMs: s.faultUntilMs } : {}),
    };
  } catch {
    return null;
  }
}

// chaosSourceFetch wraps the fetch an API source uses (cf-config/workers/media). When a fault is armed FOR
// THIS source type it counts matching outbound calls and, at the Nth (`at`) match, injects the fault:
//   - "api-fault"  (default): resolves a 500 the adapter reads as an upstream error -> a fail-open marker
//                             (_unavailable), which the run surfaces as recordsIncomplete (the invariant).
//   - "api-timeout": REJECTS the fetch (a transient network fault), same fail-open outcome.
// `path`, when set, scopes the fault to calls whose URL contains it (e.g. only the /schedules read, or only
// the /zones/<id> identity read). Unarmed / a different source => the real fetch, untouched.
// When spec.faultUntilMs is set the fault is TRANSIENT: the matching call faults ONLY while nowMs() is before
// the deadline, so a retry after the deadline (a fresh isolate, its own `matched` counter) sees the real
// fetch and the run recovers to success. The clock is INJECTABLE (nowMs, default Date.now) so a test drives
// the deadline crossing WITHOUT real timers. Absent faultUntilMs => the deadline check is skipped and the
// fault is permanent.
//
// A PERMANENT FAULT IS SUSTAINED FOR THE CALL IT LANDS ON, which is what "a sustained outage" above has always
// claimed and did not do. It faulted the at-th matching call and nothing after it, so the adapter's own retry
// re-issued the same read and reached the real upstream on attempt two. That was invisible while the retry
// classifier read the thrown message: the injected body carries no status and no network vocabulary, so a
// chaos 500 classified permanent and was never retried, and one-shot was indistinguishable from sustained.
// Once the classifier began reading the status the error carries as a field (dest/classify.ts statusOnError),
// a 500 became transient and retryable, the retry rode straight past the injection, and the crawl reported a
// clean full capture under an armed fault -- the exact invariant chaos/srcfault-live.mjs exists to police.
// The engine was right and the injector was modelling a blip while calling itself an outage.
//
// It is pinned by URL rather than by sustaining every match, so the fault stays scoped to the one upstream
// resource the operator aimed at: a retry of the faulted read carries the same URL, while the surfaces either
// side of it are untouched and the run still demonstrates fail-open-per-surface. A retry is the same outage
// rather than a new matching call, so it does not advance `matched` and cannot walk the fault onto a
// neighbour. An expired TRANSIENT deadline still passes through, pin or no pin, which is what proves
// park-and-resume recovers.
export function chaosSourceFetch(
  env: { CHAOS_SOURCE_FAULT?: string } | undefined,
  sourceType: string,
  realFetch: typeof fetch = fetch,
  nowMs: () => number = Date.now,
): typeof fetch {
  const spec = parseSourceFault(env);
  if (spec === null || spec.source !== sourceType) return realFetch;
  if (spec.fault !== "api-fault" && spec.fault !== "api-timeout") return realFetch; // this helper handles only fetch faults
  let matched = 0;
  const at = spec.at ?? 1;
  // faultedUrl pins the URL the fault landed on. Null until it lands, so it can never pre-empt the `at` count.
  let faultedUrl: string | null = null;
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    if (spec.path === undefined || url.includes(spec.path)) {
      // A re-issue of the pinned URL is the adapter RETRYING the faulted read, not a new matching call, so it
      // faults again and does not advance `matched`.
      const retryOfFaulted = faultedUrl !== null && url === faultedUrl;
      if (!retryOfFaulted) matched++;
      // A TRANSIENT fault whose deadline has passed no longer faults: pass the call through so a retry succeeds.
      const expired = spec.faultUntilMs !== undefined && nowMs() >= spec.faultUntilMs;
      if ((matched === at || retryOfFaulted) && !expired) {
        faultedUrl = url;
        if (spec.fault === "api-timeout") throw new Error(`chaos source fault: ${sourceType} api-timeout at matching call ${at} (${url})`);
        return new Response(JSON.stringify({ success: false, errors: [{ message: "chaos source fault: injected 500" }] }), { status: 500 });
      }
    }
    return realFetch(input, init);
  }) as typeof fetch;
}

// chaosKVBinding wraps a KV binding for the KV-specific faults the existing srcfault scripts drive:
//   - "cursor-expiry":  the paginated list at page `at` throws (a cursor that expired mid-crawl).
//   - "vanish-midcrawl": the `at`-th value get returns null (a key deleted between list and read).
// Both are read-boundary faults the KV adapter must handle (surface incompleteness / a vanished marker),
// never silently drop. Unarmed / not a kv fault => the real binding, untouched.
export function chaosKVBinding(env: { CHAOS_SOURCE_FAULT?: string } | undefined, kv: KVNamespace): KVNamespace {
  const spec = parseSourceFault(env);
  if (spec === null || spec.source !== "kv") return kv;
  const at = spec.at ?? 1;
  // A pass-through that BINDS a native method to the real binding. A KVNamespace is a native (host) object:
  // returning its method unbound and letting it be called with `this` = the Proxy is an "illegal invocation"
  // in workerd (the detached-method lockout). So every non-faulted property is returned bound to `target`.
  const passthrough = (target: KVNamespace, prop: string | symbol): unknown => {
    const v = target[prop as keyof KVNamespace];
    return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
  };
  if (spec.fault === "cursor-expiry") {
    let listCalls = 0;
    return new Proxy(kv, {
      get(target, prop) {
        if (prop === "list") {
          return (opts?: KVNamespaceListOptions) => {
            listCalls++;
            if (listCalls === at) return Promise.reject(new Error(`chaos source fault: kv cursor-expiry at list page ${at}`));
            return (target.list as (o?: KVNamespaceListOptions) => Promise<unknown>).call(target, opts);
          };
        }
        return passthrough(target, prop);
      },
    });
  }
  if (spec.fault === "vanish-midcrawl") {
    let getCalls = 0;
    return new Proxy(kv, {
      get(target, prop) {
        if (prop === "get" || prop === "getWithMetadata") {
          const orig = target[prop as "get"] as (...a: unknown[]) => Promise<unknown>;
          return (...args: unknown[]) => {
            getCalls++;
            if (getCalls === at) {
              // Realistic vanish: real Workers KV get() returns null for a missing key, but
              // getWithMetadata() returns {value:null, metadata:null} (NEVER bare null). Matching
              // the real contract is what exercises the adapter's _vanished path instead of a
              // spurious "cannot read properties of null" that real KV could never produce.
              return Promise.resolve(prop === "getWithMetadata" ? { value: null, metadata: null } : null);
            }
            return orig.apply(target, args);
          };
        }
        return passthrough(target, prop);
      },
    });
  }
  return kv;
}
