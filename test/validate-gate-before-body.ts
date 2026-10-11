// B-094: an admin route gates the caller BEFORE it reads a body field, a body that is not a JSON object
// is a 400 (never a 500), and a refused caller always leaves its denied audit row.
//
// Driven through the PRODUCTION router (handleAdmin, a forged-but-correctly-signed Access JWT, an in-memory
// SchedulerDO) as a Viewer, reading the chain back through GET /admin/audit. For each route the Viewer posts
// a body of JSON null, a JSON number and a JSON array, and then a well-formed body as the control. Every one
// must answer 403 and write exactly one denied row. The routes that must read the body before they can
// choose a gate (the restore request shapes, where a Viewer holds the capability) answer 400 instead.
// Run: node test/validate-gate-before-body.ts

import type { AuditEvent } from "../src/admin/audit.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { __advanceAuditFoldClockForTest, AUDIT_FOLD_HOUR_MS } from "../src/sched/audit-fold.ts";
import { buildContext, OWNER, VIEWER } from "./validate-audit-harness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

type Ctx = Awaited<ReturnType<typeof buildContext>>["ctx"];

async function rawPost(ctx: Ctx, email: string, path: string, text: string): Promise<Response> {
  const headers = { "cf-access-jwt-assertion": await ctx.tokenFor(email), "content-type": "application/json" };
  return handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", headers, body: text }), ctx.accessEnv());
}

// Each route: the path, the audit action a refused caller leaves, and a well-formed control body.
const GATED: Array<{ path: string; action: string; control: unknown }> = [
  { path: "/admin/roles", action: "role-change", control: { email: "x@acme.example", role: "owner" } },
  { path: "/admin/roles/delete", action: "role-change", control: { email: "x@acme.example" } },
  { path: "/admin/group-roles", action: "group-role-change", control: { group: "g", role: "viewer" } },
  { path: "/admin/group-roles/delete", action: "group-role-change", control: { group: "g" } },
  { path: "/admin/custom-roles", action: "custom-role-change", control: { name: "n" } },
  { path: "/admin/custom-roles/delete", action: "custom-role-change", control: { name: "n" } },
  { path: "/admin/downpipes", action: "downpipe-create", control: { id: "dp1", name: "n" } },
  { path: "/admin/downpipes/delete", action: "downpipe-delete", control: { id: "dp1" } },
  { path: "/admin/restore/request", action: "restore-request", control: { runId: "01JABCDEFGHJKMNPQRSTVWXYZ0" } },
  { path: "/admin/restore/approve", action: "restore-approve", control: { planHash: "abc" } },
  { path: "/admin/restore/reject", action: "restore-reject", control: { planHash: "abc" } },
  { path: "/admin/attest/session/create", action: "attest-session-started", control: {} },
  { path: "/admin/custody/send-share", action: "custody-share-emailed", control: {} },
  { path: "/admin/keys/install", action: "keys-installed", control: {} },
  { path: "/admin/keys/rotate", action: "break-glass-rotated", control: {} },
  { path: "/admin/keys/add-operational", action: "operational-added", control: {} },
  { path: "/admin/keys/add-config-recovery", action: "config-recovery-added", control: {} },
  { path: "/admin/keys/break-glass-only", action: "operational-removed", control: {} },
  { path: "/admin/keys/posture-acknowledgement", action: "posture-acknowledged", control: { posture: "operational" } },
];

// Routes whose gate is a capability a Viewer holds: the body must be read first, and a body that is not an
// object is a 400.
const BODY_FIRST = ["/admin/restore", "/admin/restore/verify"];

const BAD_BODIES: Array<[string, string]> = [
  ["null", "null"],
  ["a number", "5"],
  ["an array", "[]"],
];

// A refusal folds into its actor's row inside a one-minute window and an hourly row ceiling, so a Viewer's
// second refusal in the same minute adds a count, not a row. Moving the fold's clock past the hour puts each
// request in a window of its own, so one refusal is one row.
async function freshWindow(): Promise<void> {
  __advanceAuditFoldClockForTest(AUDIT_FOLD_HOUR_MS + 61_000);
}

function deniedCount(events: AuditEvent[], action: string): number {
  return events.filter((e) => e.action === action && e.outcome === "denied").length;
}

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { ok, readLog } = ctx;
  try {
    for (const r of GATED) {
      for (const [label, text] of BAD_BODIES) {
        await freshWindow();
        const before = deniedCount((await readLog()).events, r.action);
        let status = 0;
        try {
          status = (await rawPost(ctx, VIEWER, r.path, text)).status;
        } catch {
          status = 500;
        }
        const after = deniedCount((await readLog()).events, r.action);
        ok(`${r.path}: a Viewer posting ${label} gets 403 (got ${status})`, status === 403);
        ok(`${r.path}: a Viewer posting ${label} writes one denied ${r.action} row (${after - before})`, after - before === 1);
      }
      await freshWindow();
      const before = deniedCount((await readLog()).events, r.action);
      const control = await ctx.call(VIEWER, "POST", r.path, r.control);
      const after = deniedCount((await readLog()).events, r.action);
      ok(`${r.path}: control, a Viewer with a valid body gets 403 (got ${control.status})`, control.status === 403);
      ok(`${r.path}: control writes one denied ${r.action} row (${after - before})`, after - before === 1);
    }

    for (const path of BODY_FIRST) {
      for (const [label, text] of BAD_BODIES) {
        let status = 0;
        try {
          status = (await rawPost(ctx, VIEWER, path, text)).status;
        } catch {
          status = 500;
        }
        ok(`${path}: a Viewer posting ${label} gets 400 (got ${status})`, status === 400);
      }
    }

    // An authorised caller with a body that is not an object gets a 400 too, and no row is written.
    for (const path of ["/admin/roles", "/admin/downpipes", "/admin/restore/request"]) {
      let status = 0;
      try {
        status = (await rawPost(ctx, OWNER, path, "null")).status;
      } catch {
        status = 500;
      }
      ok(`${path}: an Owner posting null gets 400 (got ${status})`, status === 400);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  verdictReached(ctx.getFailures());
  if (ctx.getFailures() > 0) {
    console.error(`\n${ctx.getFailures()} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nGATE-BEFORE-BODY (B-094) VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
