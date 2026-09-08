import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import {
  probeAccess,
  probeApiSourceDiscoveryToken,
  probeDestination,
  probeDurableObjectsAndCron,
  probeEmail,
  probeKeys,
  probeLicence,
  probeSlicedRuns,
  probeSourceBindings,
  probeSourceResources,
  probeWorkersPlan,
} from "./preflight-probes.ts";
import type { PreflightItem, PreflightReport, PreflightStatus } from "./preflight-types.ts";
import { doURL } from "../do-url.ts";

// Preflight: AFFIRMATIVE entitlement and prerequisite verification. Onboarding must not
// HOPE a Cloudflare product is enabled and then learn otherwise from a failed backup;
// each item here is PROBED live where the platform lets us, and where it does not, the
// item says so honestly and names the deploy-time gate that covers it. This is the same
// discipline the run path applies (a scheduled backup is verified to have run, never
// assumed): a prerequisite is verified, configured-but-unproven, unconfigured, or
// failed, with the observed evidence and the remediation that names the Cloudflare
// product to enable. The console's onboarding wizard reads this; the support bundle
// embeds it. Probes are read-only and never log or return a secret value.
//
// The individual probes live in ./preflight-probes.ts; this file orchestrates them in
// the established order and folds their items into the report summary. The probe order
// is load-bearing: the Durable Objects probe runs first so later items can reference it.

export type { PreflightItem, PreflightReport, PreflightStatus };

function nowIso(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export async function runPreflight(env: Env, scheduler: DurableObjectStub): Promise<PreflightReport> {
  const items: PreflightItem[] = [];

  await probeDurableObjectsAndCron(items, scheduler);
  probeWorkersPlan(items);
  await probeDestination(items, env, scheduler);
  await probeKeys(items, env);
  await probeAccess(items, env);
  probeEmail(items, env);
  await probeSlicedRuns(items, env);
  await probeLicence(items, env, scheduler);
  // The next three probes all need the same downpipe roster; read it ONCE here rather than each
  // independently re-fetching /downpipes from the scheduler DO (a redundant DO round trip per
  // extra probe on every single preflight call). A genuine read returns the DownpipeState[];
  // anything else (an anomalous shape) is treated as "no downpipes" rather than crashing a probe,
  // and a fetch failure is passed through as null so probeSourceBindings still raises its loud
  // DO-unreachable failure (the other two treat null as "stay quiet, that failure already fired").
  let downpipes: DownpipeState[] | null = null;
  // The roster read feeds THREE probes, and a fault in it used to be invisible. probeSourceBindings
  // raises its loud DO-unreachable failure, but the other two go QUIET against a fabricated empty fleet -- and
  // a NON-ARRAY body (silently coerced to []) produces a FALSE-GREEN source-bindings item: a preflight that
  // PASSES while twenty downpipes have no bindings at all. `degraded` is set for BOTH degradations and for
  // NEITHER a genuinely empty fleet (a new account must not look like an outage).
  let degraded = false;
  try {
    const resp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
    const parsed = await resp.json();
    if (Array.isArray(parsed)) {
      downpipes = parsed as DownpipeState[];
    } else {
      downpipes = [];
      degraded = true; // the anomalous-shape coercion: the FALSE-GREEN case
    }
  } catch {
    downpipes = null;
    degraded = true;
  }
  if (degraded) void bumpAdminCounter(scheduler, "degraded-read-preflight-roster");
  await probeSourceBindings(items, env, downpipes);
  await probeSourceResources(items, env, downpipes);
  await probeApiSourceDiscoveryToken(items, env, scheduler, downpipes);

  const required = items.filter((i) => i.required);
  return {
    generatedAt: nowIso(),
    engineVersion: ENGINE_VERSION,
    summary: {
      required: required.length,
      requiredVerified: required.filter((i) => i.status === "verified").length,
      failed: items.filter((i) => i.status === "failed").length,
    },
    items,
  };
}
