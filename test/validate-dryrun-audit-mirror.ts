// validate-dryrun-audit-mirror: a gated config change must not send a phantom audit line to the SIEM mirror.
//
// With requireConfigApproval on, proposeConfigMutation runs the real mutation as a dry run and rolls storage
// back (dryRunConfigMutation, src/sched/scheduler-do-change-control.ts). The mutation appends an audit row, and
// appendAudit mirrors every appended row to Workers Logs (src/admin/audit-mirror.ts). The rollback removed the
// row from the chain but could not recall the mirror line. So the SIEM stream showed a "success" row-change
// that never committed, and the propose row that followed carried the same seq.
//
// This validator drives the REAL SchedulerDO through the production handleAdmin router and captures the
// mirror lines. It proves:
//  - a queued role change mirrors only the propose row, and every mirrored line is a row on the stored chain;
//  - no two mirrored lines carry the same seq;
//  - a propose that is refused AFTER the dry run (the bare-token break-glass cannot propose) mirrors nothing;
//  - a propose that the dry run itself refuses mirrors nothing, and the next committed row is mirrored again
//    (the hold is released on a throw);
//  - with the gate off, an inline change is still mirrored (the hold applies only to the dry run).
//
// Run: node test/validate-dryrun-audit-mirror.ts

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { makeScheduler } from "./validate-config-change-control-harness.ts";
import { makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor } = signer;
  const s = makeScheduler();
  const ADMIN_TOKEN = "bg-dryrun-mirror-token";
  const accEnv = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN } as unknown as Env;

  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accEnv);
  };
  const tokenCall = async (method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accEnv);
  };

  // Capture the audit mirror lines (source "downpipe-audit") while fn runs; pass every other line through.
  const mirrored = async (fn: () => Promise<void>): Promise<AuditEvent[]> => {
    const lines: AuditEvent[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => {
      const text = String(a[0]);
      if (text.startsWith('{"source":"downpipe-audit"')) lines.push(JSON.parse(text) as AuditEvent);
      else orig(...a);
    };
    try {
      await fn();
    } finally {
      console.log = orig;
    }
    return lines;
  };
  const storedChain = async (): Promise<AuditEvent[]> => [...(await s.storage.list<AuditEvent>({ prefix: "audit:" })).values()];
  const label = (e: AuditEvent): string => `${e.seq}:${e.action}:${e.outcome}`;

  const OWNER = "owner-mirror@acme.example";
  const OWNER2 = "owner2-mirror@acme.example";
  const TARGET = "eve-mirror@acme.example";
  const TARGET2 = "frank-mirror@acme.example";

  try {
    ok("the first Access caller bootstraps as Owner", (await (await call(OWNER, "GET", "/admin/whoami")).json() as { role: string }).role === "owner");
    // A second Owner, seeded as a pending invite row, so dual control can be armed (the two-Owner enable floor).
    s.storage.rawPut(`role:pending:${OWNER2}`, { email: OWNER2, role: "owner", grantedBy: "seed", grantedAt: new Date().toISOString() });

    // GATE OFF: an inline role change commits, and its row is mirrored.
    let status = 0;
    const inline = await mirrored(async () => {
      status = (await call(OWNER, "POST", "/admin/roles", { email: TARGET2, role: "viewer" })).status;
    });
    ok("gate off: the inline role change applies (200)", status === 200);
    ok("gate off: the committed role-change row is mirrored", inline.some((e) => e.action === "role-change" && e.outcome === "success"));

    ok("an owner can arm the dual-control gate (200)", (await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true })).status === 200);

    // GATE ON: the role change is queued. The dry run must send no line; only the propose row is mirrored.
    const queued = await mirrored(async () => {
      status = (await call(OWNER, "POST", "/admin/roles", { email: TARGET, role: "operator" })).status;
    });
    const chain = await storedChain();
    console.log(`  mirrored: ${JSON.stringify(queued.map(label))}`);
    ok("gate on: the role change is queued (202)", status === 202);
    ok("gate on: no role-change success line is mirrored for the uncommitted change", !queued.some((e) => e.action === "role-change"));
    ok("gate on: the propose row is mirrored", queued.some((e) => e.action === "config-change-propose"));
    ok("gate on: every mirrored line is a row on the stored chain", queued.every((m) => chain.some((c) => c.hash === m.hash)));
    const seqs = queued.map((e) => e.seq);
    ok("gate on: no two mirrored lines carry the same seq", seqs.length === new Set(seqs).size);

    // A propose refused AFTER the dry run: the bare-token break-glass cannot propose under dual control.
    const refused = await mirrored(async () => {
      status = (await tokenCall("POST", "/admin/roles", { email: "gina-mirror@acme.example", role: "viewer" })).status;
    });
    ok("gate on: the bare-token propose is refused (400)", status === 400);
    ok("gate on: the refused bare-token propose mirrors no line", refused.length === 0);

    // A propose the dry run itself refuses: an unknown role fails validation inside the mutation.
    const invalid = await mirrored(async () => {
      status = (await call(OWNER, "POST", "/admin/roles", { email: "hal-mirror@acme.example", role: "not-a-role" })).status;
    });
    ok("gate on: a propose the dry run refuses is a 4xx", status >= 400 && status < 500);
    ok("gate on: the refused propose mirrors no role-change line", !invalid.some((e) => e.action === "role-change"));

    // The hold is released after a dry run, including one that threw: the next committed row is mirrored.
    const after = await mirrored(async () => {
      status = (await tokenCall("POST", "/admin/config/approval-policy", { requireConfigApproval: false })).status;
    });
    ok("the break-glass owner can disarm the gate (200)", status === 200);
    ok("after the dry runs, the next committed row is mirrored again", after.length > 0);
    const finalChain = await storedChain();
    ok("the mirrored disarm row is on the stored chain", after.every((m) => finalChain.some((c) => c.hash === m.hash)));
  } finally {
    signer.restoreFetch();
  }

  console.log(failures === 0 ? "\nVALIDATE-DRYRUN-AUDIT-MIRROR VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
