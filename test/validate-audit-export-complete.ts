// PROOF EXPORT-COMPLETE for the D4 audit validator (finding F-W4-4): the COMPLIANCE EXPORT of the
// tamper-evident log must contain EVERY retained event, never a silent truncation. Before the fix the
// export shaped its document with pageEvents, whose Math.min(limit, AUDIT_PAGE_MAX=500) cap silently
// dropped every event older than the newest 500 while the download still presented itself as the full
// log, an integrity defect an auditor could not detect. This proof seeds a chain LONGER than that cap
// and drives the REAL GET /admin/audit/export route, asserting the document is complete (JSON and CSV),
// the oldest event (which the cap dropped) is present, the exported chain independently re-verifies, and
// the head hash pins the head. It also pins the two paths the fix keeps SEPARATE: the interactive paged
// view (GET /admin/audit) still caps at AUDIT_PAGE_MAX, and a bounded filtered probe (limit-bearing
// export query) still honours its limit, so only the whole-log compliance export became complete.
//
// The chain is seeded DIRECTLY into a FRESH DO's storage with real, fully-linked buildEvent entries
// (genesis-anchored, each prevHash = the prior entry's hash), keyed by auditKey(seq). This is the cheap
// way to exceed the cap without hundreds of crypto-bearing route appends; the entries are the exact shape
// appendAudit persists, so the export and verify read them as genuine chain entries. A fresh DO keeps the
// seeded volume out of the shared suite's chain (this proof runs alongside the others in the orchestrator).

import { handleAdmin } from "../src/admin/router.ts";
import { AUDIT_PAGE_MAX, AUDIT_PREFIX, auditKey, buildEvent, verifyChain, type AuditEvent, type AuditDraft } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";
import type { Ctx } from "./validate-audit-harness.ts";
import { makeScheduler, OWNER, TEAM, AUD } from "./validate-audit-harness.ts";

export async function runExportComplete(ctx: Ctx): Promise<void> {
  const { ok, tokenFor } = ctx;

  // A FRESH, isolated DO so the seeded volume never perturbs the shared suite's chain. The JWKS-stubbed
  // globalThis.fetch installed by buildContext is still in force, so the forged Owner token verifies for
  // real against the same controlled JWKS; we only rebind the env + call helper to THIS scheduler.
  const fresh = makeScheduler();
  const freshEnv = (): Env => ({ ...fresh.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
  async function freshCall(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), freshEnv());
  }

  // Bootstrap OWNER (first Access caller -> Owner) so the export route (any authenticated role) authorises.
  await freshCall(OWNER, "GET", "/admin/whoami");

  // Seed a chain LONGER than AUDIT_PAGE_MAX, chained onto whatever the bootstrap already recorded (so the
  // stored seqs stay contiguous from genesis and the whole chain re-verifies). TARGET = cap + 100 = 600.
  const TARGET = AUDIT_PAGE_MAX + 100;
  const existingKeys = fresh.storage.rawKeys(AUDIT_PREFIX);
  let prev: AuditEvent | null = existingKeys.length > 0 ? fresh.storage.rawGet<AuditEvent>(existingKeys[existingKeys.length - 1]!)! : null;
  let seq = prev ? prev.seq + 1 : 1;
  while (fresh.storage.rawKeys(AUDIT_PREFIX).length < TARGET) {
    const draft: AuditDraft = { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "engine-state", field: "engineVersion", detail: `0.0.${seq}` } };
    const e = await buildEvent(draft, seq, `2026-06-07T00:00:${String(seq % 60).padStart(2, "0")}.000Z`, prev);
    fresh.storage.rawPut(auditKey(seq), e);
    prev = e;
    seq++;
  }
  const stored = fresh.storage.rawKeys(AUDIT_PREFIX).length;
  ok(`seeded a retained chain larger than the AUDIT_PAGE_MAX cap (${stored} > ${AUDIT_PAGE_MAX})`, stored === TARGET && TARGET > AUDIT_PAGE_MAX);

  // ---- The compliance JSON export is COMPLETE (every retained event, not the newest 500) ----------
  {
    const resp = await freshCall(OWNER, "GET", "/admin/audit/export?format=json");
    const doc = (await resp.json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
    ok("JSON export is a download (content-disposition attachment)", /attachment/.test(resp.headers.get("content-disposition") ?? ""));
    // The crux of F-W4-4: the response carries MORE than the 500-row cap, i.e. the cap no longer truncates.
    ok(`JSON export returns MORE than AUDIT_PAGE_MAX rows (${doc.events.length} > ${AUDIT_PAGE_MAX})`, doc.events.length > AUDIT_PAGE_MAX);
    ok("JSON export returns EVERY retained event (complete, not truncated)", doc.events.length === stored);
    // The oldest events are exactly what the 500-cap silently dropped (it kept the newest 500). Their
    // presence, starting at genesis seq 1, is the direct proof the silent truncation is gone.
    ok("JSON export includes the OLDEST event (genesis seq 1), which the 500-cap dropped", doc.events[0]?.seq === 1);
    ok("JSON export events are ascending and contiguous from genesis to head", doc.events.every((e, i) => e.seq === (doc.events[0]!.seq + i)));
    ok("JSON export head seq is the true head (the last retained seq)", doc.headSeq === stored && doc.events[doc.events.length - 1]?.seq === stored);
    // The exported chain, being complete from genesis, independently re-verifies intact: an external
    // verifier holding the head hash can confirm completeness, which a truncated export would fail.
    const v = await verifyChain(doc.events);
    ok("the complete exported JSON chain independently verifies intact", v.intact === true && v.checkedThrough === stored);
    ok("JSON export carries the chain head hash (sha384) matching the head entry", doc.headHash.startsWith("sha384:") && doc.headHash === doc.events[doc.events.length - 1]?.hash);
  }

  // ---- The CSV export is ALSO complete (a spreadsheet/SIEM import must not silently truncate) ------
  {
    const resp = await freshCall(OWNER, "GET", "/admin/audit/export?format=csv");
    const text = await resp.text();
    ok("CSV export is text/csv", /text\/csv/.test(resp.headers.get("content-type") ?? ""));
    // Rows = every non-empty line, minus the header row and the trailing head-hash row = one per event.
    const lines = text.split("\r\n").filter((l) => l.length > 0);
    const dataRows = lines.length - 2; // header + trailing head row
    ok(`CSV export has one data row per retained event (${dataRows} === ${stored})`, dataRows === stored);
    ok("CSV export data rows exceed the AUDIT_PAGE_MAX cap (complete, not truncated)", dataRows > AUDIT_PAGE_MAX);
    // The oldest event (seq 1) must be a data row: its absence is exactly the silent-truncation defect.
    ok("CSV export includes the oldest event (a data row with seq 1)", lines.some((l) => l.startsWith('"1",')));
  }

  // ---- REGRESSION GUARD: the interactive paged VIEW cap is UNCHANGED (a separate path) ------------
  {
    // GET /admin/audit is the newest-first paged view (readAudit -> pageEvents); it MUST still cap at
    // AUDIT_PAGE_MAX even when asked for far more, so only the export became complete, not the UI page.
    const resp = await freshCall(OWNER, "GET", "/admin/audit?limit=100000");
    const page = (await resp.json()) as { events: AuditEvent[]; headSeq: number };
    ok(`the paged VIEW still caps at AUDIT_PAGE_MAX (${page.events.length} === ${AUDIT_PAGE_MAX})`, page.events.length === AUDIT_PAGE_MAX);
    ok("the paged view head seq is still the true head", page.headSeq === stored);
  }

  // ---- REGRESSION GUARD: a bounded, filtered EXPORT probe still honours its limit ------------------
  {
    // afterSeq + action + limit disqualifies the forward-feed fast path (action is set) yet supplies a
    // limit, so it takes the export slow path's BOUNDED branch. It must still return at most `limit`
    // ascending events after the cursor: the limit-bearing internal probes (e.g. the support pack) are
    // unchanged by the completeness fix, which applies only to the whole-log (no-limit) export.
    const resp = await freshCall(OWNER, "GET", "/admin/audit/export?afterSeq=100&action=engine-version-change&limit=50");
    const doc = (await resp.json()) as { events: AuditEvent[] };
    ok("bounded filtered export honours its limit (returns exactly 50)", doc.events.length === 50);
    ok("bounded filtered export returns only events after the cursor, ascending", doc.events.every((e) => e.seq > 100) && doc.events.every((e, i) => i === 0 || e.seq > doc.events[i - 1]!.seq));
    ok("bounded filtered export applies the action filter", doc.events.every((e) => e.action === "engine-version-change"));
  }
}
