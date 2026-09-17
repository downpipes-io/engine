// validate-downpipe-field-allowlist: a downpipe save accepts only its documented fields (ASVS V15.3.3, mass
// assignment). An unknown key at any nesting level is REFUSED naming the path, never stored and never
// dropped; the single upsert, the bulk upsert and the approval-gated propose all pass through the one pick.
// The control is a full config carrying every documented optional field, which is stored with exactly the
// keys it sent (ifMatchRev stripped, as validate-downpipe-precondition PROOF 1f already proves).
import type { DownpipeState } from "../src/sched/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { buildContext, OPERATOR, OWNER } from "./validate-config-change-control-harness.ts";

type Answer = { status: number; body: Record<string, unknown> };

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { ok, call, listDownpipes, dp } = ctx;
  try {
    async function post(email: string, path: string, body: unknown): Promise<Answer> {
      const r = await call(email, "POST", path, body);
      let parsed: Record<string, unknown> = {};
      try { parsed = (await r.json()) as Record<string, unknown>; } catch { /* non-JSON */ }
      return { status: r.status, body: parsed };
    }
    const errorOf = (a: Answer): string => (typeof a.body.error === "string" ? a.body.error : "");
    const stored = async (id: string): Promise<DownpipeState | null> => (await listDownpipes()).find((d) => d.config.id === id) ?? null;

    console.log("\n-- (a) a top-level unknown key is refused, named, and nothing is stored --");
    {
      const a = await post(OPERATOR, "/admin/downpipes", { ...dp("dpinj", "injected"), injectedField: "x" });
      ok("(a) 400", a.status === 400);
      ok("(a) the refusal names the field", errorOf(a).includes("injectedField"));
      ok("(a) no record was created", (await stored("dpinj")) === null);
    }
    console.log("\n-- (b) a server-managed name smuggled into the config is refused, not stored beside the real one --");
    {
      const b = await post(OPERATOR, "/admin/downpipes", { ...dp("dprev", "rev"), configRev: 999, createdAt: 1 });
      ok("(b) 400 naming configRev", b.status === 400 && errorOf(b).includes("configRev"));
      ok("(b) no record was created", (await stored("dprev")) === null);
    }
    console.log("\n-- (c) a nested unknown key is refused by dotted path --");
    {
      const base = dp("dpnest", "nest");
      const c1 = await post(OPERATOR, "/admin/downpipes", { ...base, source: { ...base.source, extra: "y" } });
      ok("(c) source.extra -> 400 naming source.extra", c1.status === 400 && errorOf(c1).includes("source.extra"));
      const c2 = await post(OPERATOR, "/admin/downpipes", { ...base, retention: { keepRuns: 3, extra: 1 } });
      ok("(c) retention.extra -> 400 naming retention.extra", c2.status === 400 && errorOf(c2).includes("retention.extra"));
      const c3 = await post(OPERATOR, "/admin/downpipes", { ...base, schedule: { cron: "0 3 * * *", blackoutWindows: [{ startMinute: 0, endMinute: 60, extra: true }] } });
      ok("(c) schedule.blackoutWindows[0].extra -> 400 naming the path", c3.status === 400 && errorOf(c3).includes("schedule.blackoutWindows[0].extra"));
      const c4 = await post(OPERATOR, "/admin/downpipes", JSON.parse(`{"id":"dpproto","name":"p","cadenceSeconds":3600,"enabled":true,"source":{"type":"kv","binding":"KV_p","include":[],"exclude":[]},"__proto__":{"x":1}}`));
      ok("(c) __proto__ is refused", c4.status === 400);
      ok("(c) nothing was stored for any of them", (await stored("dpnest")) === null && (await stored("dpproto")) === null);
    }
    console.log("\n-- (d) CONTROL: every documented optional field is accepted and stored with exactly the keys sent --");
    {
      const full = { ...dp("dpfull", "full"), restoreTestCadenceSeconds: 86_400, retention: { keepRuns: 5, keepDays: 30, enforce: false }, schedule: { cron: "0 3 * * *", timeZone: "UTC", blackoutWindows: [{ days: [0, 6], startMinute: 0, endMinute: 60 }] }, ifMatchRev: null };
      const d = await post(OPERATOR, "/admin/downpipes", full);
      ok("(d) 200", d.status === 200);
      const rec = await stored("dpfull");
      const expectKeys = Object.keys(full).filter((k) => k !== "ifMatchRev").sort();
      ok("(d) stored config keys equal the submitted documented keys (ifMatchRev stripped)", rec !== null && JSON.stringify(Object.keys(rec.config).sort()) === JSON.stringify(expectKeys));
    }
    console.log("\n-- (e) bulk: the bad item is refused naming the field, its sibling is applied --");
    {
      const e = await post(OPERATOR, "/admin/downpipes/bulk", { downpipes: [{ ...dp("dpbulkbad", "bad"), injectedField: 1 }, dp("dpbulkok", "ok")] });
      const results = (e.body.results ?? []) as Array<{ id: string; status: string; error?: string }>;
      const bad = results.find((r) => r.id === "dpbulkbad");
      const good = results.find((r) => r.id === "dpbulkok");
      ok("(e) the bad item is status error naming injectedField", bad?.status === "error" && (bad.error ?? "").includes("injectedField"));
      ok("(e) the sibling is applied", good?.status === "applied" && (await stored("dpbulkok")) !== null);
      ok("(e) the bad item was not stored", (await stored("dpbulkbad")) === null);
    }
    console.log("\n-- (f) with config approval on, an unknown field is refused at propose, never queued --");
    {
      const gate = await ctx.setGate(OWNER, true);
      ok("(f) the gate is on", gate.status === 200);
      const f = await post(OPERATOR, "/admin/downpipes", { ...dp("dpgated", "gated"), injectedField: "x" });
      ok("(f) 400 at propose", f.status === 400 && errorOf(f).includes("injectedField"));
      ok("(f) nothing was queued", !(await ctx.pendingChanges(OWNER)).some((c) => JSON.stringify(c).includes("dpgated")));
      await ctx.setGate(OWNER, false);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  const failures = ctx.getFailures();
  console.log(failures === 0 ? "\nDOWNPIPE FIELD ALLOWLIST VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
