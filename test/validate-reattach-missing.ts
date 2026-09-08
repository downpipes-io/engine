// validate-reattach-missing: route coverage for POST /sources/reattach-missing (router-discovery.ts),
// the one-action HEAL that re-adds the engine's MISSING source bindings from the persisted roster after
// a deploy/wipe dropped them. Drives the REAL handleAdmin over a REAL SchedulerDO on in-memory storage:
// seeds downpipe configs (the roster) + the engine's live env bindings, then asserts the route's plan
// and gating. The post-token changeBindings write itself is proven in validate-attach.ts (the same
// primitive); here we cover the route's plan/gate/early-return/refuse arms.
//
// Run: node test/validate-reattach-missing.ts

import { handleAdmin } from "../src/admin/router.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A duck-typed KV binding object (get/put/list/getWithMetadata), what enumerateBoundSources reads as a
// LIVE kv source. A binding NOT placed in the env is "missing" (the deploy dropped it).
const kvLive = () => ({ get() {}, put() {}, list() {}, getWithMetadata() {} });
const dpState = (id: string, source: DownpipeConfig["source"]) => ({
  config: { id, name: id, cadenceSeconds: 3600, enabled: true, source } as DownpipeConfig,
  nextRunAt: 0,
  lastRunId: null,
  inFlight: false,
});

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor } = signer;
  const OWNER = "owner-rm@acme.example";
  const VIEWER = "viewer-rm@acme.example";

  // mk builds a fresh owner-bootstrapped scheduler, seeds the discovery config (so the engine can name
  // its own account for the attach), and returns a caller bound to an env carrying `liveBindings`.
  const mk = async (liveBindings: Record<string, unknown>, roster: ReturnType<typeof dpState>[]) => {
    const s = makeScheduler();
    const accEnv = { ...s.env, ...liveBindings, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-rm" } as unknown as Env;
    const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
      handleAdmin(new Request(`https://engine.example${path}`, {
        method,
        headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }), accEnv);
    await call(OWNER, "GET", "/admin/whoami"); // bootstrap the first Access caller as Owner
    await s.storage.put(DISCOVERY_KEY, { token: "cfat_seeded_token_1234567890", setAt: 1, setBy: OWNER, accountsSeen: [{ id: "acct-1", name: "A" }], selected: ["acct-1"], engineAccountId: "acct-1" });
    for (const st of roster) await s.storage.put(`dp:${st.config.id}`, st);
    return call;
  };
  const kvSrc = (binding: string, namespaceId?: string): DownpipeConfig["source"] => ({ type: "kv", binding, ...(namespaceId ? { namespaceId } : {}), include: [], exclude: [] } as DownpipeConfig["source"]);
  const d1Src = (binding: string): DownpipeConfig["source"] => ({ type: "d1", binding, include: [], exclude: [] } as DownpipeConfig["source"]);

  // (1) Nothing missing: the one configured source's binding is live -> reports it attached, NO token needed.
  {
    const call = await mk({ SRC_KV_LIVE: kvLive() }, [dpState("dp-live", kvSrc("SRC_KV_LIVE", "ns-live"))]);
    const r = await call(OWNER, "POST", "/admin/sources/reattach-missing", {});
    const b = (await r.json()) as { attached: string[]; alreadyAttached: string[]; unreconstructable: unknown[] };
    ok("nothing missing -> 200 with no token", r.status === 200);
    ok("nothing missing -> attached empty, alreadyAttached names the live binding", b.attached.length === 0 && b.alreadyAttached.includes("SRC_KV_LIVE"));
  }

  // (2) Missing but unreconstructable (legacy config, no native id) -> reported, NO token needed (nothing to write).
  {
    const call = await mk({}, [dpState("dp-d1", d1Src("SRC_D1_MISS"))]);
    const r = await call(OWNER, "POST", "/admin/sources/reattach-missing", {});
    const b = (await r.json()) as { attached: string[]; unreconstructable: { binding: string }[] };
    ok("only-unreconstructable -> 200 with no token", r.status === 200);
    ok("only-unreconstructable -> surfaced as needing a re-save", b.attached.length === 0 && b.unreconstructable.some((u) => u.binding === "SRC_D1_MISS"));
  }

  // (3) Missing AND rebuildable, but no deploy token -> refuse with the paste-the-token guidance (no write).
  {
    const call = await mk({}, [dpState("dp-miss", kvSrc("SRC_KV_MISS", "ns-miss"))]);
    const r = await call(OWNER, "POST", "/admin/sources/reattach-missing", {});
    const b = (await r.json()) as { error?: string };
    ok("missing+rebuildable, no token -> 400", r.status === 400);
    ok("missing+rebuildable, no token -> names the deploy token", /deploy token/.test(b.error ?? ""));
  }

  // (4) Owner-grade gate: a Viewer cannot re-attach (it rewrites the engine's bindings).
  {
    const call = await mk({}, [dpState("dp-miss", kvSrc("SRC_KV_MISS", "ns-miss"))]);
    const r = await call(VIEWER, "POST", "/admin/sources/reattach-missing", {});
    ok("a Viewer is refused (403)", r.status === 403);
  }

  // (5) Conflicting: two downpipes claim the SAME binding with a DIFFERENT namespaceId (the
  // exploit shape -- a downpipe.write-only caller plants a second claim on an existing binding name).
  // The route reports the conflict and NEVER attaches it, even though it needs no token to say so.
  {
    const call = await mk({}, [
      dpState("dp-legit", kvSrc("SRC_KV_CONFLICT", "ns-real")),
      dpState("dp-evil", kvSrc("SRC_KV_CONFLICT", "ns-attacker")),
    ]);
    const r = await call(OWNER, "POST", "/admin/sources/reattach-missing", {});
    const b = (await r.json()) as { attached: string[]; conflicting: { binding: string; downpipes: string[] }[] };
    ok("a conflicting binding -> 200 with no token (nothing left it is safe to attach)", r.status === 200);
    ok("a conflicting binding is named in the response and never attached", (b.conflicting ?? []).some((c) => c.binding === "SRC_KV_CONFLICT") && !b.attached.includes("SRC_KV_CONFLICT"));
    const conflict = b.conflicting.find((c) => c.binding === "SRC_KV_CONFLICT");
    ok("the conflict names both disagreeing downpipes", JSON.stringify(conflict?.downpipes) === JSON.stringify(["dp-evil", "dp-legit"]));
  }

  console.log(failures === 0 ? "\nvalidate-reattach-missing: ALL PASS" : `\nvalidate-reattach-missing: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
