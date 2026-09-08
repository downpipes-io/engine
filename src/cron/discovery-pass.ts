// cf-config discovery refresh pass for the cron driver (cron/drive.ts): probe ONE stale
// auto-mode cf-config downpipe per tick to refresh its surface set, gated on ample shared
// budget so it never starves backups/replication. Moved VERBATIM out of cron/drive.ts to
// finish the *-pass.ts split of that orchestrator; the behaviour is unchanged.

import { doURL, type schedulerStub } from "../admin/router.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { accountInDiscoveryScope, type DiscoveryScopeConfig } from "../sched/config-validate.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import type { budgetFromEnv } from "../seal/budget.ts";
import { probeCfConfig } from "../sources/cf-config-discovery.ts";
import { noteCronPass, noteDiscoverySkip } from "./cron-fault-ledger.ts";

// DISCOVERY_PROBE_RESERVE is the shared-budget headroom the cf-config discovery pass needs before it
// probes one downpipe (a probe is ~one GET per surface, ~200). Backups + replication run first and
// keep priority; discovery only runs when ample budget remains, and at most one downpipe per tick.
const DISCOVERY_PROBE_RESERVE = 250;

// runDiscoveryPass probes ONE stale auto-mode cf-config downpipe per tick to refresh its surface set.
export async function runDiscoveryPass(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>): Promise<boolean> {
  // cf-config DISCOVERY refresh (read-cost control): probe ONE stale auto-mode cf-config downpipe per
  // tick so its capture runs back up only the surfaces in USE (not one GET per every surface in the
  // registry every run). Bounded to one downpipe per tick (each probe is ~200 GETs) and gated on ample shared budget,
  // so it never starves backups/replication; the 25h staleness + */15 ticks spread the fleet. Fail-open:
  // any fault degrades to "discover next tick" and capture meanwhile fail-safes to ALL surfaces. The DO
  // returns no due downpipes when none are auto-mode cf-config with a stale cache, so the common case
  // costs one read.
  try {
    // G234: EVERY exit from this pass now records WHY. The discovery cache silently never refreshing (a
    // missing token, an account narrowed out of scope, chronic budget starvation, a CF-API 403) is the whole
    // "cf-config backups got slow and expensive" ticket -- capture fail-safes to every surface in the registry every run
    // while the cause is swallowed or an anonymous passErrors bump. The reasons are a closed vocabulary; the
    // token and the account id never enter the record.
    if (budget.remaining() < DISCOVERY_PROBE_RESERVE) {
      noteDiscoverySkip("budget-starved");
      return true; // a budget bail is not a pass FAULT: it is a deferral, and it is now a recorded one
    }
    const { due: discDue } = (await (await scheduler.fetch(doURL("/cf-config/discovery-due"), { method: "GET" })).json()) as { due: DownpipeState[] };
    const target = discDue[0];
    if (target?.config.source.type !== "cf-config" || typeof target.config.source.accountId !== "string" || target.config.source.accountId === "") {
      noteDiscoverySkip("none-due"); // the healthy quiet state, recorded so QUIET is distinguishable from BLOCKED
      return true;
    }
    const cfg = ((await (await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" })).json()) as { config?: (DiscoveryScopeConfig & { token?: string }) | null }).config ?? null;
    const envToken = typeof env.DISCOVERY_API_TOKEN === "string" ? env.DISCOVERY_API_TOKEN.trim() : "";
    const token = cfg?.token ?? (envToken !== "" ? envToken : null);
    if (token === null) {
      noteDiscoverySkip("no-token");
      return true;
    }
    // Cross-account confused-deputy re-check (ASVS V4, HI-11): `selected` can narrow AFTER this
    // downpipe was created, and this periodic refresh must not keep silently servicing a
    // since-deselected account with no further gate; skip this tick exactly as the no-token case does.
    if (!accountInDiscoveryScope(target.config.source.accountId, cfg)) {
      noteDiscoverySkip("out-of-scope");
      return true;
    }
    budget.spend(DISCOVERY_PROBE_RESERVE); // account for the ~200 probe GETs against the shared cap
    const discovery = await probeCfConfig(token, target.config.source.accountId, target.config.source.zoneId, Date.now());
    await scheduler.fetch(doURL("/cf-config/discovery"), { method: "POST", body: JSON.stringify({ id: target.config.id, discovery }) });
    log("info", `cf-config discovery refreshed for ${target.config.id}: ${discovery.present.length} present, ${discovery.empty.length} empty, ${discovery.gated.length} gated, ${discovery.unavailable.length} unavailable`);
    return true;
  } catch (e) {
    // The probe itself threw (a CF-API 403 on a rotated token, a 5xx): a SKIP with a cause, and a pass fault.
    noteDiscoverySkip("probe-failed");
    noteCronPass("discovery", false, e);
    log("error", `cf-config discovery pass skipped this tick: ${(e as Error).message}`);
    return false;
  }
}
