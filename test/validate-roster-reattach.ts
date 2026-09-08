// validate-roster-reattach: unit suite for src/admin/roster-reattach.ts, the PURE plan that rebuilds the
// engine's MISSING source bindings from the persisted roster (downpipe configs) after a deploy/wipe
// dropped them. Drives classifySource + planRosterReattach directly (no IO), asserting every branch:
// each source type's rebuild vs unreconstructable, the already-attached idempotent skip, dedup across
// downpipes that share a source, and the "rebuildable wins over unreconstructable" merge.
//
// Run: node test/validate-roster-reattach.ts

import { classifySource, planRosterReattach } from "../src/admin/roster-reattach.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const src = (s: Partial<DownpipeConfig["source"]>): DownpipeConfig["source"] => ({ include: [], exclude: [], ...s } as DownpipeConfig["source"]);
const dp = (id: string, s: Partial<DownpipeConfig["source"]>): Pick<DownpipeConfig, "id" | "source"> => ({ id, source: src(s) });

function main(): void {
  console.log("-- classifySource: each source type rebuilds from its recorded native id, or is flagged --");
  {
    const kv = classifySource(src({ type: "kv", binding: "SRC_KV", namespaceId: "ns-1" }));
    ok("kv with namespaceId rebuilds", kv.ok.length === 1 && kv.ok[0]!.type === "kv" && kv.ok[0]!.binding === "SRC_KV" && kv.ok[0]!.namespaceId === "ns-1" && kv.bad.length === 0);
    const kvNo = classifySource(src({ type: "kv", binding: "SRC_KV" }));
    ok("kv without namespaceId is unreconstructable", kvNo.ok.length === 0 && kvNo.bad.length === 1 && /namespace id/.test(kvNo.bad[0]!.reason));

    const r2 = classifySource(src({ type: "r2", binding: "SRC_R2", bucketName: "b-1" }));
    ok("r2 with bucketName rebuilds", r2.ok.length === 1 && r2.ok[0]!.bucketName === "b-1" && r2.bad.length === 0);
    const r2No = classifySource(src({ type: "r2", binding: "SRC_R2" }));
    ok("r2 without bucketName is unreconstructable", r2No.ok.length === 0 && r2No.bad.length === 1 && /bucket name/.test(r2No.bad[0]!.reason));

    const d1 = classifySource(src({ type: "d1", binding: "SRC_D1", databaseId: "db-1" }));
    ok("d1 with databaseId rebuilds", d1.ok.length === 1 && d1.ok[0]!.databaseId === "db-1" && d1.bad.length === 0);
    const d1No = classifySource(src({ type: "d1", binding: "SRC_D1" }));
    ok("d1 without databaseId is unreconstructable", d1No.ok.length === 0 && d1No.bad.length === 1 && /database id/.test(d1No.bad[0]!.reason));

    const sec = classifySource(src({ type: "secrets", secrets: [{ name: "A", binding: "SEC_A", storeId: "st-1" }, { name: "B", binding: "SEC_B" }] }));
    ok("secrets: the one with a storeId rebuilds, the one without is flagged", sec.ok.length === 1 && sec.ok[0]!.binding === "SEC_A" && sec.ok[0]!.storeId === "st-1" && sec.ok[0]!.secretName === "A" && sec.bad.length === 1 && sec.bad[0]!.binding === "SEC_B");

    const cfg = classifySource(src({ type: "cf-config", accountId: "acc" }));
    ok("cf-config (not a Worker binding) is skipped, never flagged", cfg.ok.length === 0 && cfg.bad.length === 0);
    const noBinding = classifySource(src({ type: "kv" }));
    ok("a binding source with no binding name presents nothing", noBinding.ok.length === 0 && noBinding.bad.length === 0);
    const noBindingSecret = classifySource(src({ type: "secrets", secrets: [{ name: "A", binding: "" }] }));
    ok("a secret with an empty binding is skipped", noBindingSecret.ok.length === 0 && noBindingSecret.bad.length === 0);
  }

  console.log("-- planRosterReattach: missing-rebuildable / already-attached / unreconstructable / dedup --");
  {
    const roster = [
      dp("dp1", { type: "kv", binding: "SRC_KV", namespaceId: "ns-1" }), // missing -> toAttach
      dp("dp2", { type: "r2", binding: "SRC_R2", bucketName: "b-1" }), // live -> alreadyAttached
      dp("dp3", { type: "d1", binding: "SRC_D1" }), // missing + no id -> unreconstructable
      dp("dp4", { type: "kv", binding: "SRC_KV", namespaceId: "ns-1" }), // same source as dp1 -> dedup, affects both
      dp("dp5", { type: "secrets", secrets: [{ name: "A", binding: "SEC_A", storeId: "st-1" }, { name: "B", binding: "SEC_B" }] }),
      dp("dp6", { type: "cf-config", accountId: "acc" }), // not a binding -> ignored
    ];
    const plan = planRosterReattach(roster, new Set(["SRC_R2"]));
    const names = plan.toAttach.map((a) => a.binding);
    ok("toAttach holds the missing rebuildable bindings (SEC_A, SRC_KV), sorted", JSON.stringify(names) === JSON.stringify(["SEC_A", "SRC_KV"]));
    ok("toAttach carries the recorded native ids", plan.toAttach.find((a) => a.binding === "SRC_KV")?.namespaceId === "ns-1" && plan.toAttach.find((a) => a.binding === "SEC_A")?.storeId === "st-1");
    ok("alreadyAttached holds the live binding (idempotent skip)", JSON.stringify(plan.alreadyAttached) === JSON.stringify(["SRC_R2"]));
    const unrecon = plan.unreconstructable.map((u) => u.binding);
    ok("unreconstructable holds the missing-no-id bindings (SEC_B, SRC_D1), sorted", JSON.stringify(unrecon) === JSON.stringify(["SEC_B", "SRC_D1"]));
    ok("affects records every downpipe that references a binding (SRC_KV <- dp1, dp4)", JSON.stringify(plan.affects["SRC_KV"]) === JSON.stringify(["dp1", "dp4"]));
    ok("unreconstructable carries its affected downpipes", plan.unreconstructable.find((u) => u.binding === "SRC_D1")?.downpipes.includes("dp3") === true);
  }

  console.log("-- planRosterReattach: a binding rebuildable from ANY downpipe is never told to re-save --");
  {
    const roster = [
      dp("a", { type: "kv", binding: "FOO", namespaceId: "ns-foo" }), // rebuildable
      dp("b", { type: "kv", binding: "FOO" }), // same binding, no id
    ];
    const plan = planRosterReattach(roster, new Set());
    ok("FOO is in toAttach (rebuildable wins)", plan.toAttach.length === 1 && plan.toAttach[0]!.binding === "FOO");
    ok("FOO is NOT in unreconstructable", plan.unreconstructable.length === 0);
  }

  console.log("-- planRosterReattach: an already-live binding with no recorded id needs nothing --");
  {
    const plan = planRosterReattach([dp("a", { type: "kv", binding: "LIVE_NO_ID" })], new Set(["LIVE_NO_ID"]));
    ok("a live binding (even with no id) is alreadyAttached, not unreconstructable", JSON.stringify(plan.alreadyAttached) === JSON.stringify(["LIVE_NO_ID"]) && plan.unreconstructable.length === 0 && plan.toAttach.length === 0);
  }

  console.log("-- planRosterReattach: an empty roster yields an empty plan --");
  {
    const plan = planRosterReattach([], new Set());
    ok("empty roster -> empty plan", plan.toAttach.length === 0 && plan.alreadyAttached.length === 0 && plan.unreconstructable.length === 0 && plan.conflicting.length === 0 && Object.keys(plan.affects).length === 0);
  }

  console.log("-- planRosterReattach: conflicting native ids under one binding name are NEVER auto-picked --");
  {
    // The exploit shape: a downpipe.write-only caller plants a second claim on an EXISTING binding name
    // with an attacker-chosen namespaceId. Neither claim wins; both downpipes are named in `conflicting`,
    // and the binding is excluded from toAttach so it can never be silently redirected.
    const roster = [
      dp("legit", { type: "kv", binding: "CUSTOMER_DATA", namespaceId: "ns-real" }),
      dp("-evil", { type: "kv", binding: "CUSTOMER_DATA", namespaceId: "ns-attacker" }),
    ];
    const plan = planRosterReattach(roster, new Set());
    ok("the conflicted binding is excluded from toAttach", plan.toAttach.every((a) => a.binding !== "CUSTOMER_DATA"));
    const conflict = plan.conflicting.find((c) => c.binding === "CUSTOMER_DATA");
    ok("the conflicted binding is reported in conflicting", conflict !== undefined);
    ok("conflicting names BOTH downpipes, sorted", JSON.stringify(conflict?.downpipes) === JSON.stringify(["-evil", "legit"]));
  }
  {
    // 3 downpipes, 2 agree on one namespaceId, 1 disagrees: still a conflict, not a majority-wins vote --
    // there is no safe way to tell which claim (even a 2-1 majority) is the legitimate one.
    const roster = [
      dp("a", { type: "kv", binding: "SHARED", namespaceId: "ns-1" }),
      dp("b", { type: "kv", binding: "SHARED", namespaceId: "ns-1" }),
      dp("c", { type: "kv", binding: "SHARED", namespaceId: "ns-2" }),
    ];
    const plan = planRosterReattach(roster, new Set());
    const conflict = plan.conflicting.find((c) => c.binding === "SHARED");
    ok("2-agree-1-disagree is still a conflict, not majority-wins", conflict !== undefined);
    ok("2-agree-1-disagree excludes the binding from toAttach", plan.toAttach.every((a) => a.binding !== "SHARED"));
    ok("the conflict names all three downpipes", JSON.stringify(conflict?.downpipes) === JSON.stringify(["a", "b", "c"]));
  }
  {
    // Same binding name, same id-shaped VALUE, but a different SOURCE TYPE: still a conflict -- a
    // namespaceId and a bucketName happening to equal the same string does not make them one resource.
    const roster = [
      dp("a", { type: "kv", binding: "MIXED", namespaceId: "shared-id" }),
      dp("b", { type: "r2", binding: "MIXED", bucketName: "shared-id" }),
    ];
    const plan = planRosterReattach(roster, new Set());
    ok("a mismatched type under the same binding name is a conflict", plan.conflicting.some((c) => c.binding === "MIXED"));
    ok("a type-mismatch conflict excludes the binding from toAttach", plan.toAttach.every((a) => a.binding !== "MIXED"));
  }
  {
    // The landmine-warning case: the binding is CURRENTLY live (alreadyAttached), but the roster still
    // holds a disagreeing claim. It must be surfaced NOW, before a later deploy-drop + reattach would
    // otherwise silently rebind it -- this is the only point an owner can see the poison before it detonates.
    const roster = [
      dp("legit", { type: "kv", binding: "LIVE_SHARED", namespaceId: "ns-real" }),
      dp("-evil", { type: "kv", binding: "LIVE_SHARED", namespaceId: "ns-attacker" }),
    ];
    const plan = planRosterReattach(roster, new Set(["LIVE_SHARED"]));
    ok("a live-but-conflicting binding is still flagged (preemptive landmine warning)", plan.conflicting.some((c) => c.binding === "LIVE_SHARED"));
    ok("a live-but-conflicting binding also stays in alreadyAttached (still true right now)", plan.alreadyAttached.includes("LIVE_SHARED"));
    ok("a live-but-conflicting binding is never in toAttach", plan.toAttach.every((a) => a.binding !== "LIVE_SHARED"));
  }
  {
    // Regression: the pre-existing dp1/dp4 shape (two downpipes AGREEING on the same namespaceId) must
    // still dedup cleanly into one toAttach entry, with NO conflict reported.
    const roster = [
      dp("dp1", { type: "kv", binding: "SRC_KV", namespaceId: "ns-1" }),
      dp("dp4", { type: "kv", binding: "SRC_KV", namespaceId: "ns-1" }),
    ];
    const plan = planRosterReattach(roster, new Set());
    ok("agreeing downpipes: no conflict reported", plan.conflicting.length === 0);
    ok("agreeing downpipes: the binding still dedups into toAttach once", plan.toAttach.length === 1 && plan.toAttach[0]!.binding === "SRC_KV");
  }

  console.log(failures === 0 ? "\nvalidate-roster-reattach: ALL PASS" : `\nvalidate-roster-reattach: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
