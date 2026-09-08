// PROOF 10 / 11 / 12 for the D4 audit validator (split out of validate-audit.ts, finding
// engine-test-001-01): redaction holds (no secret material anywhere in the log); the export carries
// the chain head hash in both JSON and CSV; a filtered read narrows correctly.

import { handleAdmin } from "../src/admin/router.ts";
import { verifyChain, type AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";
import type { Ctx } from "./validate-audit-harness.ts";
import { OWNER, OPERATOR, APPROVER, TEAM, AUD, SECRET_MARKERS } from "./validate-audit-harness.ts";

export async function runRedaction(ctx: Ctx): Promise<void> {
  const { ok, call, readLog, sched, tokenFor } = ctx;

  // ---- PROOF 10: REDACTION holds (no secret material anywhere in the log) ------------------
  {
    // Drive privileged actions whose requests reference ONLY safe names, while the engine env holds
    // distinctive secret markers. Then serialise the WHOLE log and assert no marker leaked, and
    // that no reserved secret binding name (which would imply a value) appears in any target.
    const markerEnv = {
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      SIGNER_PRIVATE: SECRET_MARKERS[0],
      BREAK_GLASS_PUBLIC: SECRET_MARKERS[1],
      OPERATIONAL_PRIVATE: SECRET_MARKERS[2],
      DEST_SECRET_ACCESS_KEY: SECRET_MARKERS[3],
      DEST_KIND: "r2",
      DEST_R2: {} as unknown,
    } as unknown as Env;
    async function callEnv(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), markerEnv);
    }
    // Apply a restore (records restore-apply), create/delete a downpipe, change a role, fire status.
    await callEnv(APPROVER, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    await callEnv(OPERATOR, "POST", "/admin/downpipes", { id: "dp-secret-check", name: "secret check", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_check", include: [], exclude: [] } });
    await callEnv(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dp-secret-check" });
    await callEnv(OWNER, "POST", "/admin/roles", { email: "newhire@acme.example", role: "operator" });
    await callEnv(OWNER, "GET", "/admin/status");

    const log = await readLog();
    const serialised = JSON.stringify(log.events);
    let leaked = false;
    for (const marker of SECRET_MARKERS) {
      if (serialised.includes(marker)) {
        leaked = true;
        console.log(`    leaked secret marker found in audit log: ${marker}`);
      }
    }
    ok("no secret marker (key/value/private fingerprint) appears anywhere in the log", !leaked);
    // No reserved secret binding NAME should appear in any target (a source binding name like
    // KV_check is the customer's own non-secret config and may appear; the engine's OWN secret
    // binding names must not).
    const reservedSecretNames = ["SIGNER_PRIVATE", "BREAK_GLASS_PUBLIC", "OPERATIONAL_PRIVATE", "DEST_SECRET_ACCESS_KEY", "DEST_ACCESS_KEY_ID"];
    const targetsSerialised = JSON.stringify(log.events.map((e) => e.target));
    ok("no engine secret binding name appears in any audit target", reservedSecretNames.every((n) => !targetsSerialised.includes(n)));
    // The recorder type has no free-form field: every target is one of the closed-union kinds.
    const knownKinds = new Set(["downpipe", "run", "restore", "role", "grouprole", "customrole", "configchange", "key-ceremony", "access-policy", "dest-change", "supportcredential", "credential-cleanup", "engine-state"]);
    ok("every target is a closed-union kind (no free-form details field exists)", log.events.every((e) => knownKinds.has(e.target.kind)));
  }

  // ---- PROOF 11: the export carries the chain HEAD HASH (JSON + CSV) -----------------------
  {
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { checkedThrough: number };
    const page = await readLog();
    // JSON export.
    const jsonResp = await call(OWNER, "GET", "/admin/audit/export?format=json");
    const jsonBody = (await jsonResp.json()) as { events: AuditEvent[]; headSeq: number; headHash: string; exportedAt: string };
    ok("JSON export is a download (content-disposition attachment)", /attachment/.test(jsonResp.headers.get("content-disposition") ?? ""));
    ok("JSON export carries the chain head hash", jsonBody.headHash === page.headHash && jsonBody.headHash.startsWith("sha384:"));
    ok("JSON export head seq matches the verified head", jsonBody.headSeq === verify.checkedThrough);
    // The exported events are ascending by seq (the document order), and independently re-verify.
    const exportVerify = await verifyChain(jsonBody.events);
    ok("the exported JSON chain independently verifies intact", exportVerify.intact === true);
    // CSV export.
    const csvResp = await call(OWNER, "GET", "/admin/audit/export?format=csv");
    const csvText = await csvResp.text();
    ok("CSV export is text/csv", /text\/csv/.test(csvResp.headers.get("content-type") ?? ""));
    ok("CSV export carries the chain head hash in a head row", csvText.includes(page.headHash) && /headSeq=/.test(csvText));
    ok("CSV export has a header row with the safe columns (incl. actorSubject)", csvText.split("\r\n")[0] === '"seq","ts","actorSubject","actorEmail","actorMethod","sourceIp","action","outcome","target","prevHash","hash"');
    // Column-position pin on the head row (kills the 10-vs-11-cell misalignment, finding 002-02): the
    // head row must split into exactly 11 quoted fields and field index 10 (the hash column) must equal
    // the quoted head hash, not the prevHash column. This is the assertion whose absence let 002-02 ship.
    const headRow = csvText.split("\r\n").filter((l) => l.length > 0).at(-1) ?? "";
    const headCells = headRow.split(",");
    ok("CSV head row splits into exactly 11 comma-separated fields", headCells.length === 11);
    ok("CSV head row places the head hash in the hash column (index 10), not prevHash", headCells[10] === `"${page.headHash}"` && headCells[9] === '""');
    // The CSV must not leak a secret marker either (the redaction discipline carries to export).
    ok("no secret marker appears in the CSV export", SECRET_MARKERS.every((m) => !csvText.includes(m)));
  }

  // ---- PROOF 12: a filtered read narrows correctly ---------------------------------------
  {
    const onlyRoleChanges = await readLog("action=role-change");
    ok("filtering by action=role-change returns only role-change events", onlyRoleChanges.events.length > 0 && onlyRoleChanges.events.every((e) => e.action === "role-change"));
    const byActor = await readLog("actor=" + encodeURIComponent(APPROVER));
    ok("filtering by actor returns only that actor's events", byActor.events.length > 0 && byActor.events.every((e) => e.actorEmail === APPROVER));
    const byOutcome = await readLog("outcome=denied");
    ok("filtering by outcome=denied returns only denied events", byOutcome.events.length > 0 && byOutcome.events.every((e) => e.outcome === "denied"));
  }
}
