// validate-cf-config-mode-gated.ts -- verifies POST /cf-config/mode is a first-class config mutation
// (cf-config-mode-set) routed through gatedConfigMutation, so it dual-gates and auto-snapshots into config
// history like a downpipe upsert. Driven through the real router and change-control handlers.
// (The capture-mode field is source-agnostic for this gate test; the gate does not depend on the source type.)

import { buildContext, OWNER, OPERATOR } from "./validate-config-change-control-harness.ts";

let pass = 0, fail = 0;
const ok = (d: string, c: boolean) => { console.log(`  ${c ? "ok  " : "FAIL"} ${d}`); c ? pass++ : fail++; };

const { ctx } = await buildContext();
const { call } = ctx;
const dpId = "cfg-mode-dp";
// Seed a downpipe to flip the mode on (OWNER holds downpipe.write; gate is OFF at bootstrap so this applies).
await call(OWNER, "POST", "/admin/downpipes", { id: dpId, name: "mode dp", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] } });

// Gate OFF (default): the mode change applies inline (200), byte-identical to the prior behaviour.
const off = await call(OWNER, "POST", "/admin/downpipes/cf-config/mode", { id: dpId, mode: "manual" });
ok("gate OFF: cf-config/mode applies inline (200 ok:true)", off.status === 200 && ((await off.json()) as { ok?: boolean }).ok === true);

// Arm dual control. The mode change now QUEUES a pending config change (202) instead of applying inline.
await ctx.setGate(OWNER, true);
const on = await call(OWNER, "POST", "/admin/downpipes/cf-config/mode", { id: dpId, mode: "auto" });
ok("gate ON -> cf-config/mode is QUEUED as a pending config change (202), not applied inline", on.status === 202);
const changeId = ((await on.json()) as { id?: string }).id ?? "";
ok("the 202 carries a pending change id", changeId.length > 0);

// A DISTINCT approver holding downpipe.write (the CHANGE_WRITE_CAPABILITY for this kind) applies it.
const approve = await call(OPERATOR, "POST", `/admin/config/changes/${changeId}/approve`);
ok("a distinct approver with downpipe.write applies the queued mode change (200)", approve.status === 200);

// Unknown downpipe is now a 400 (a config-mutation throw), consistent with every other config kind.
const unknown = await call(OWNER, "POST", "/admin/downpipes/cf-config/mode", { id: "no-such-dp", mode: "auto" });
ok("an unknown downpipe is a 400 config-mutation error (not a special 404)", unknown.status === 400);

console.log(`\n${fail === 0 ? "CF-CONFIG-MODE GATED PASS" : "CF-CONFIG-MODE GATED: " + fail + " FAIL"}: ${pass} pass / ${fail} fail`);
if (fail > 0) process.exitCode = 1;
if (fail > 0) process.exit(1);
