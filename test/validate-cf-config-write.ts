// Validates the diff-driven restore write-back for the high-value IDEMPOTENT cf-config list
// surfaces (DNS records, page rules, firewall access rules, WAF rulesets) added to
// src/sources/cf-config-surfaces.ts. The contract under test, identical to zone-settings:
//   * an UNCHANGED item -> SKIPPED, no PATCH/PUT/POST at all
//   * a CHANGED item    -> exactly the right UPDATE (PUT/PATCH) to that item's id, body = the snapshot
//   * a MISSING item    -> CREATED (POST to the collection)
//   * a LIVE EXTRA the snapshot omits -> LEFT ALONE (additive default; never deleted)
//   * NEVER a blind wholesale overwrite (no PUT of the whole collection; each item applied on its own)
//   * dry-run computes the diff and writes NOTHING
//   * an item the API rejects is SKIPPED, not fatal (fail-open per item)
// The CfApi is an IN-MEMORY double (no network, no fetch). Run: node test/validate-cf-config-write.ts.

import { surfaceById, type CfApi, type CfPage } from "../src/sources/cf-config-surfaces.ts";
import { writeListSpec } from "../src/sources/cf-config-write.ts";
import { jsonEqual, naturalKey, SKIP_IN_DIFF } from "../src/sources/cf-config-shared.ts";
import { writeSingleSetting } from "../src/sources/cf-config-write-settings.ts";
import { diffConfig } from "../src/sources/cf-config-diff.ts";
// The live-only report is only useful if the operator-facing summary renders it, so the test asserts
// the whole path from buildListOps through to the string a human reads, not just the change list.
import { summariseDiff } from "../src/admin/restore-cfconfig.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const IDS = { accountId: "acct", zoneId: "zone" };

// A recorded write the double captured: the method, the path, and the parsed body.
interface Sent {
  method: "PATCH" | "PUT" | "POST" | "DELETE";
  path: string;
  body: unknown;
}

// makeDouble builds an in-memory CfApi: GET (and the paginated getPage) serve a fixed live list for a
// matching path; send() records every write. rejectPath lets a test make one item's update fail (to
// prove fail-open). No network. liveByPath maps a collection path -> the live array it returns.
function makeDouble(liveByPath: Record<string, unknown[]>, rejectPath?: RegExp): { api: CfApi; sent: Sent[] } {
  const sent: Sent[] = [];
  const lookup = (path: string): unknown[] | undefined => {
    const base = path.split("?", 1)[0]!;
    return liveByPath[base];
  };
  const api: CfApi = {
    get: async (path) => {
      const arr = lookup(path);
      return arr ?? null;
    },
    getPage: async (path): Promise<CfPage> => {
      const arr = lookup(path) ?? [];
      // one page, no result_info -> the paginator stops after this page (short page).
      return { result: arr };
    },
    send: async (method, path, body) => {
      if (rejectPath && rejectPath.test(path)) throw new Error(`Cloudflare API ${method} ${path}: simulated rejection`);
      sent.push({ method, path, body });
      return {};
    },
  };
  return { api, sent };
}

console.log("-- DNS write(): unchanged skipped, changed -> PUT/{id}, missing -> POST, live extra kept --");
{
  // Live: A1 (unchanged vs snapshot), A2 (content changed in snapshot), EXTRA (live-only, NOT in snapshot).
  // Snapshot: A1 (same), A2 (changed content), NEW (not live).
  const live = [
    { id: "id-a1", type: "A", name: "a1.example.com", content: "1.1.1.1", proxied: true, ttl: 1, created_on: "2020", modified_on: "2021" },
    { id: "id-a2", type: "A", name: "a2.example.com", content: "2.2.2.2", proxied: false, ttl: 1 },
    { id: "id-extra", type: "A", name: "extra.example.com", content: "9.9.9.9", proxied: false, ttl: 1 },
  ];
  const snapshot = [
    { id: "id-a1", type: "A", name: "a1.example.com", content: "1.1.1.1", proxied: true, ttl: 1, created_on: "DIFFERENT", modified_on: "DIFFERENT" }, // only server-stamped fields differ -> NOT a change
    { id: "id-a2", type: "A", name: "a2.example.com", content: "2.2.2.9", proxied: false, ttl: 1 }, // content changed
    { id: "id-new", type: "A", name: "new.example.com", content: "3.3.3.3", proxied: false, ttl: 1 }, // missing live -> create
  ];
  const dns = surfaceById("dns")!;
  ok("dns surface exposes a write() (restore write-back implemented)", typeof dns.write === "function");

  // dry-run: diff only, no writes.
  const dry = makeDouble({ "/zones/zone/dns_records": live });
  const preview = await dns.write!(dry.api, IDS, snapshot, { dryRun: true });
  ok("dry-run writes nothing", dry.sent.length === 0);
  // The diff carries THREE entries: the changed record, the missing record, and the LIVE-ONLY extra
  // reported as a "remove" (which summariseDiff renders "1 live-only (left in place)"). A live-only
  // extra is reported but never applied or deleted.
  ok("diff has the changed + the missing + the live-only record (the unchanged one is not listed)", preview.changes.length === 3);
  const liveOnly = preview.changes.filter((c) => c.action === "remove");
  ok("the live-only extra IS reported, as a 'remove' action", liveOnly.length === 1);
  // The path is `${label}/${identity(item)}` and DNS identity() is the server id, so this reads
  // "dns/id-extra" rather than the hostname. The hostname rides in `from`, asserted next.
  ok("the reported live-only record is the live extra, not one of the snapshot records", liveOnly[0]!.path === "dns/id-extra");
  ok("F9: the live-only report carries the live value in `from` and nothing in `to`", liveOnly[0]!.from.includes("9.9.9.9") && liveOnly[0]!.to === "");
  ok("summariseDiff renders it as left in place, never as a deletion", summariseDiff(preview).includes("1 live-only (left in place)"));
  ok("the unchanged record (server-stamped fields aside) produces NO change", !preview.changes.some((c) => c.path.includes("id-a1")));
  ok("the changed record is an 'change'", preview.changes.some((c) => c.action === "change" && c.path.includes("id-a2")));
  ok("the missing record is an 'add'", preview.changes.some((c) => c.action === "add" && c.path.includes("id-new")));

  // apply.
  const run = makeDouble({ "/zones/zone/dns_records": live });
  const res = await dns.write!(run.api, IDS, snapshot, { dryRun: false });
  ok("apply touched exactly 2 items (1 update + 1 create)", run.sent.length === 2 && res.applied === 2);
  const update = run.sent.find((s) => s.method === "PUT");
  ok("the CHANGED record is updated with PUT to /dns_records/{its id}", !!update && update.path === "/zones/zone/dns_records/id-a2");
  ok("the update body is the snapshot record (changed content), with server-stamped fields stripped", !!update && (update.body as { content?: string }).content === "2.2.2.9" && (update.body as { id?: unknown }).id === undefined);
  const create = run.sent.find((s) => s.method === "POST");
  ok("the MISSING record is created with POST to the collection", !!create && create.path === "/zones/zone/dns_records");
  ok("the create body carries the new record's name", !!create && (create.body as { name?: string }).name === "new.example.com");
  ok("the UNCHANGED record (id-a1) is never written", !run.sent.some((s) => s.path.includes("id-a1")));
  // NO blind overwrite, NO unintended delete:
  ok("NO blind wholesale overwrite (never a PUT to the bare collection path)", !run.sent.some((s) => s.method === "PUT" && s.path === "/zones/zone/dns_records"));
  ok("the LIVE EXTRA (id-extra, absent from snapshot) is NEVER deleted or touched", !run.sent.some((s) => s.path.includes("id-extra")) && !run.sent.some((s) => s.method === "DELETE"));
}

console.log("-- DNS write(): natural-key match prevents a duplicate when the snapshot id is stale --");
{
  // The snapshot record has a STALE id (a fresh zone re-assigned ids), but the same type|name|content
  // as a live record. The write must MATCH it by natural key (not create a duplicate) and, since the
  // content is identical, SKIP it.
  const live = [{ id: "live-real-id", type: "A", name: "a.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }];
  const snapshot = [{ id: "stale-old-id", type: "A", name: "a.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }];
  const run = makeDouble({ "/zones/zone/dns_records": live });
  const res = await surfaceById("dns")!.write!(run.api, IDS, snapshot, { dryRun: false });
  ok("a stale-id but identical record matches by natural key and is SKIPPED (no duplicate create)", run.sent.length === 0 && res.applied === 0 && res.changes.length === 0);
}

console.log("-- SINGLE-SETTING writer: nine surfaces run through it, offline --");
{
  // writeSingleSetting backs the nine zone settings Cloudflare omits from its aggregate /settings
  // response. This exercises the plan-gate guard and converge-and-do-nothing behaviour offline, with
  // no live account needed.
  const PATH = "/zones/zone/settings/dp_probe";
  const w = writeSingleSetting((i) => `/zones/${i.zoneId}/settings/dp_probe`, "dp_probe");

  // CONVERGED: live already equals the snapshot, so nothing is written at all.
  const same = makeDouble({ [PATH]: [] });
  (same.api as { get: (p: string) => Promise<unknown> }).get = async () => ({ id: "dp_probe", value: "on", editable: true });
  const r1 = await w(same.api, IDS, { id: "dp_probe", value: "on" }, { dryRun: false });
  ok("an already-converged setting writes nothing and reports no change", r1.applied === 0 && r1.changes.length === 0 && same.sent.length === 0);

  // CHANGED: exactly one PATCH, to this setting's own path, carrying only the value.
  const diff = makeDouble({ [PATH]: [] });
  (diff.api as { get: (p: string) => Promise<unknown> }).get = async () => ({ id: "dp_probe", value: "off", editable: true });
  const r2 = await w(diff.api, IDS, { id: "dp_probe", value: "on" }, { dryRun: false });
  ok("a changed setting PATCHes exactly once, to its own path", r2.applied === 1 && diff.sent.length === 1 && diff.sent[0]!.method === "PATCH" && diff.sent[0]!.path === PATH);
  ok("the PATCH body carries the snapshot value and nothing else", JSON.stringify(diff.sent[0]!.body) === JSON.stringify({ value: "on" }));

  // DRY RUN: reports the change, writes nothing. The property every writer must have.
  const dry = makeDouble({ [PATH]: [] });
  (dry.api as { get: (p: string) => Promise<unknown> }).get = async () => ({ id: "dp_probe", value: "off", editable: true });
  const r3 = await w(dry.api, IDS, { id: "dp_probe", value: "on" }, { dryRun: true });
  ok("a dry run reports the change and writes nothing", r3.changes.length === 1 && r3.applied === 0 && dry.sent.length === 0);

  // NOT EDITABLE: Cloudflare marks plan-gated settings editable:false. Refuse, and say why.
  const gated = makeDouble({ [PATH]: [] });
  (gated.api as { get: (p: string) => Promise<unknown> }).get = async () => ({ id: "dp_probe", value: "off", editable: false });
  const r4 = await w(gated.api, IDS, { id: "dp_probe", value: "on" }, { dryRun: false });
  ok("a setting Cloudflare marks not-editable is refused, not attempted", r4.applied === 0 && gated.sent.length === 0 && r4.skipped[0]?.cls === "entitlement");

  // EMPTY SNAPSHOT: nothing to restore is a refusal with a reason, never a silent success.
  const empty = makeDouble({ [PATH]: [] });
  (empty.api as { get: (p: string) => Promise<unknown> }).get = async () => ({ id: "dp_probe", value: "off", editable: true });
  const r5 = await w(empty.api, IDS, {}, { dryRun: false });
  ok("a snapshot carrying no value is refused with a reason, never a silent success", r5.applied === 0 && r5.skipped.length === 1);
}

console.log("-- preferredKey / naturalKey must be STABLE under server-stamped churn --");
{
  // The generated writers fall back to naturalKey when an item has no name-like field. If that key moved
  // whenever Cloudflare restamped a timestamp, a restore would never converge: the item would read as
  // missing on every run and be created again. The fallback strips SERVER_STAMPED for exactly this
  // reason, and this pins it, because the failure would only ever be seen on a second live run.
  const a = { widget: "x", nested: { k: 1 }, created_on: "2020-01-01", modified_on: "2020-01-01", version: 1 };
  const b = { widget: "x", nested: { k: 1 }, created_on: "2026-07-26", modified_on: "2026-07-26", version: 9 };
  ok("two items differing ONLY in server-stamped fields share a natural key (so a restore converges)", naturalKey(a) === naturalKey(b));
  const c = { widget: "y", nested: { k: 1 } };
  ok("two genuinely different items do NOT share a natural key", naturalKey(a) !== naturalKey(c));
  // A named item keys on the name, so the whole-body fallback is only reached when there is no name.
  ok("a named item keys on its name, not on its whole body", naturalKey({ name: "n", volatile: 1 }) === naturalKey({ name: "n", volatile: 2 }));
}

console.log("-- AMBIGUOUS natural key: a colliding key must REFUSE, never guess which twin was meant --");
{
  // Two live Zero Trust posture rules share a name, which Cloudflare permits and which is a standard
  // one-rule-per-platform setup. The snapshot carries STALE ids, the restore-into-a-rebuilt-account case
  // natural() exists for. Both orderings are asserted because a naive match could bind the wrong twin
  // depending on Cloudflare's list ordering.
  const live = [
    { id: "live-A", name: "Disk Encryption", type: "disk_encryption", input: { os: "windows" } },
    { id: "live-B", name: "Disk Encryption", type: "disk_encryption", input: { os: "macos" } },
  ];
  const snapWin = { id: "snap-A", name: "Disk Encryption", type: "disk_encryption", input: { os: "windows" } };
  const snapMac = { id: "snap-B", name: "Disk Encryption", type: "disk_encryption", input: { os: "macos" } };
  const spec = {
    listPath: () => "/accounts/acct/things",
    itemPath: (_i: unknown, id: string) => `/accounts/acct/things/${id}`,
    identity: (it: Record<string, unknown>) => String(it.id ?? ""),
    serverId: (it: Record<string, unknown>) => (typeof it.id === "string" ? it.id : ""),
    natural: (it: Record<string, unknown>) => `things:${String(it.name ?? "")}`,
    createMethod: "POST" as const,
    updateMethod: "PUT" as const,
    body: (it: Record<string, unknown>) => it,
    label: "things",
  };
  for (const [label, snapshot] of [["windows-first", [snapWin, snapMac]], ["macos-first", [snapMac, snapWin]]] as const) {
    const d = makeDouble({ "/accounts/acct/things": live });
    const res = await writeListSpec(spec, d.api, IDS, snapshot, { dryRun: false });
    ok(`${label}: an ambiguous natural key writes NOTHING`, res.applied === 0 && d.sent.length === 0);
    ok(`${label}: every ambiguous item is reported as a conflict, never silently dropped`, res.skipped.length === 2 && res.skipped.every((x) => x.cls === "conflict"));
  }
  // Control: the SAME spec with unique names still works, so the guard has not disabled the engine.
  const uniqueLive = [{ id: "live-A", name: "Alpha", v: 1 }];
  const d2 = makeDouble({ "/accounts/acct/things": uniqueLive });
  const res2 = await writeListSpec(spec, d2.api, IDS, [{ id: "stale", name: "Alpha", v: 2 }], { dryRun: false });
  ok("control: a UNIQUE natural key still matches and updates in place", res2.applied === 1 && d2.sent[0]?.path === "/accounts/acct/things/live-A");
}

console.log("-- DNS write(): a rejected item is skipped, not fatal (fail-open per item) --");
{
  const live = [{ id: "id-1", type: "A", name: "x.example.com", content: "1.1.1.1", proxied: false, ttl: 1 }];
  const snapshot = [
    { id: "id-1", type: "A", name: "x.example.com", content: "8.8.8.8", proxied: false, ttl: 1 }, // changed -> PUT will be REJECTED
    { id: "id-2", type: "A", name: "y.example.com", content: "2.2.2.2", proxied: false, ttl: 1 }, // missing -> POST succeeds
  ];
  // Reject the PUT to id-1 only; the POST create still lands.
  const run = makeDouble({ "/zones/zone/dns_records": live }, /\/dns_records\/id-1$/);
  const res = await surfaceById("dns")!.write!(run.api, IDS, snapshot, { dryRun: false });
  ok("the rejected update is recorded as skipped (with a reason), not thrown", res.skipped.length === 1 && /id-1/.test(res.skipped[0]!.path));
  ok("the other item (the create) still applied; one bad item never fails the rest", res.applied === 1 && run.sent.some((s) => s.method === "POST"));
}

console.log("-- page-rules write(): changed -> PUT/{id}, missing -> POST, additive (no prune) --");
{
  const live = [
    { id: "pr-1", targets: [{ target: "url", constraint: { operator: "matches", value: "a.com/*" } }], actions: [{ id: "always_use_https" }], status: "active", priority: 1 },
    { id: "pr-extra", targets: [{ target: "url", constraint: { operator: "matches", value: "extra.com/*" } }], actions: [{ id: "disable_apps" }], status: "active", priority: 9 },
  ];
  const snapshot = [
    { id: "pr-1", targets: [{ target: "url", constraint: { operator: "matches", value: "a.com/*" } }], actions: [{ id: "always_use_https" }], status: "disabled", priority: 1 }, // status changed
    { id: "pr-2", targets: [{ target: "url", constraint: { operator: "matches", value: "b.com/*" } }], actions: [{ id: "forwarding_url" }], status: "active", priority: 2 }, // missing -> create
  ];
  const run = makeDouble({ "/zones/zone/pagerules": live });
  const res = await surfaceById("page-rules")!.write!(run.api, IDS, snapshot, { dryRun: false });
  ok("page-rules has a write()", typeof surfaceById("page-rules")!.write === "function");
  const upd = run.sent.find((s) => s.method === "PUT");
  ok("the changed page rule is updated with PUT to /pagerules/{id}", !!upd && upd.path === "/zones/zone/pagerules/pr-1" && (upd.body as { status?: string }).status === "disabled");
  ok("the missing page rule is created with POST to /pagerules", run.sent.some((s) => s.method === "POST" && s.path === "/zones/zone/pagerules"));
  ok("the live extra page rule is NOT deleted (additive default)", !run.sent.some((s) => s.path.includes("pr-extra")) && !run.sent.some((s) => s.method === "DELETE"));
  ok("no blind wholesale overwrite of the pagerules collection", !run.sent.some((s) => s.method === "PUT" && s.path === "/zones/zone/pagerules"));
  ok("applied is exactly 2 (one update + one create)", res.applied === 2);
}

console.log("-- firewall-access-rules write(): changed -> PATCH/{id} with mode+configuration body --");
{
  const live = [
    { id: "ar-1", mode: "block", configuration: { target: "ip", value: "1.2.3.4" }, notes: "old", scope: { type: "zone" } },
    { id: "ar-extra", mode: "challenge", configuration: { target: "ip", value: "9.9.9.9" } },
  ];
  const snapshot = [
    { id: "ar-1", mode: "whitelist", configuration: { target: "ip", value: "1.2.3.4" }, notes: "new" }, // mode+notes changed
    { id: "ar-2", mode: "block", configuration: { target: "ip", value: "5.6.7.8" } }, // missing -> create
  ];
  const run = makeDouble({ "/zones/zone/firewall/access_rules/rules": live });
  const res = await surfaceById("firewall-access-rules")!.write!(run.api, IDS, snapshot, { dryRun: false });
  ok("firewall-access-rules has a write()", typeof surfaceById("firewall-access-rules")!.write === "function");
  const upd = run.sent.find((s) => s.method === "PATCH");
  ok("the changed rule is updated with PATCH to /firewall/access_rules/rules/{id}", !!upd && upd.path === "/zones/zone/firewall/access_rules/rules/ar-1");
  ok("the PATCH body carries only mode/notes/configuration (the editable shape)", !!upd && (upd.body as { mode?: string }).mode === "whitelist" && (upd.body as { configuration?: unknown }).configuration !== undefined && (upd.body as { id?: unknown; scope?: unknown }).id === undefined);
  ok("the missing rule is created with POST", run.sent.some((s) => s.method === "POST" && s.path === "/zones/zone/firewall/access_rules/rules"));
  ok("the live extra rule is NOT deleted", !run.sent.some((s) => s.path.includes("ar-extra")) && !run.sent.some((s) => s.method === "DELETE"));
  ok("applied is exactly 2", res.applied === 2);
  // account-scoped variant routes to the account path.
  const acct = makeDouble({ "/accounts/acct/firewall/access_rules/rules": [{ id: "a-1", mode: "block", configuration: { target: "ip", value: "1.1.1.1" } }] });
  await surfaceById("account-firewall-access-rules")!.write!(acct.api, IDS, [{ id: "a-1", mode: "challenge", configuration: { target: "ip", value: "1.1.1.1" } }], { dryRun: false });
  ok("the account-scoped firewall rules write hits the /accounts path", acct.sent.some((s) => s.method === "PATCH" && s.path === "/accounts/acct/firewall/access_rules/rules/a-1"));
}

console.log("-- rulesets write(): a changed phase ruleset -> PUT/{id} { rules } (its own unit, not a whole-account overwrite) --");
{
  // The READ adapter expands rulesets to an array of full rulesets (each with .rules). The live
  // expansion: paginate index returns [{id, phase}], then GET each id returns the full ruleset.
  // We give the double both: the index path and the per-id path.
  const liveIndex = [{ id: "rs-http", phase: "http_request_firewall_custom", name: "zone" }];
  const liveFull = { id: "rs-http", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 1.2.3.4", version: "3" }] };
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/zones/zone/rulesets/rs-http") return liveFull;
      if (base === "/zones/zone/rulesets") return liveIndex;
      return null;
    },
    getPage: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/zones/zone/rulesets") return { result: liveIndex };
      return { result: [] };
    },
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  // Snapshot ruleset: same phase, but one rule's expression changed -> PUT /rulesets/rs-http { rules }.
  const snapshot = [{ id: "rs-http", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 9.9.9.9" }] }];
  const res = await surfaceById("rulesets")!.write!(api, IDS, snapshot, { dryRun: false });
  ok("rulesets has a write()", typeof surfaceById("rulesets")!.write === "function");
  const put = sent.find((s) => s.method === "PUT");
  ok("the changed ruleset's RULES are replaced via PUT /rulesets/{id} (its own idempotent unit)", !!put && put.path === "/zones/zone/rulesets/rs-http");
  ok("the PUT body is { rules } only (not the whole account/zone)", !!put && Array.isArray((put.body as { rules?: unknown }).rules) && Object.keys(put.body as object).join(",") === "rules");
  ok("the PUT rules carry the changed expression", !!put && (((put.body as { rules: Array<{ expression?: string }> }).rules[0]?.expression) === "ip.src eq 9.9.9.9"));
  ok("applied is exactly 1 (the one changed ruleset)", res.applied === 1);
}

console.log("-- rulesets write(): a live rule the snapshot lacks is NAMED and REFUSED, never deleted --");
{
  // PUT /rulesets/{id} replaces the whole rule list, so applying a snapshot that is MISSING a live rule
  // deletes it. The restore contract is additive, so the writer must refuse the ruleset and name what it
  // would have removed, not merely report a count that cannot be reviewed.
  const liveIndex = [{ id: "rs-http", phase: "http_request_firewall_custom", name: "zone" }];
  const liveFull = {
    id: "rs-http",
    phase: "http_request_firewall_custom",
    rules: [
      { id: "r1", action: "block", expression: "ip.src eq 1.2.3.4", description: "snapshot has this one" },
      { id: "r2", action: "block", expression: "ip.src eq 5.6.7.8", description: "added live after the snapshot" },
    ],
  };
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/zones/zone/rulesets/rs-http") return liveFull;
      if (base === "/zones/zone/rulesets") return liveIndex;
      return null;
    },
    getPage: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/zones/zone/rulesets") return { result: liveIndex };
      return { result: [] };
    },
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  const snapshot = [{ id: "rs-http", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 1.2.3.4", description: "snapshot has this one" }] }];
  const res = await surfaceById("rulesets")!.write!(api, IDS, snapshot, { dryRun: false });

  ok("NO PUT is issued: a live-only rule blocks the apply rather than being deleted", sent.every((x) => x.method !== "PUT"));
  ok("applied is 0", res.applied === 0);
  const removes = res.changes.filter((c) => c.action === "remove");
  ok("the live-only rule is reported as a REMOVE change, so the preview names it", removes.length === 1);
  ok("the removal names the rule, not just a count", removes[0]?.path.includes("added live after the snapshot") === true);
  ok("the removal carries the rule itself in `from`", removes[0]?.from.includes("5.6.7.8") === true);
  ok("the skip is classed live-only-rules", res.skipped.length === 1 && res.skipped[0]?.cls === "live-only-rules");
  ok("the skip reason says applying would delete them", (res.skipped[0]?.reason ?? "").includes("would delete them"));
}

console.log("-- a collection keyed on something other than `id` must still UPDATE in place --");
{
  // writeListSpec asks the spec for the live item's server id to build the update path; device-managed-
  // networks keys on `network_id` rather than `id`. This is pinned offline because a restore after a
  // delete only ever creates, so a broken update path is invisible to a round trip alone.
  const liveNet = [{ network_id: "N1", name: "corp", type: "tls", config: { tls_sockaddr: "10.0.0.1:443" } }];
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async () => null,
    getPage: async (path) => (path.split("?", 1)[0] === "/accounts/acct/devices/networks" ? { result: liveNet } : { result: [] }),
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  // Same network, changed config: matches by name, so this is an UPDATE, not a create.
  const snapshot = [{ network_id: "N1", name: "corp", type: "tls", config: { tls_sockaddr: "10.0.0.2:443" } }];
  const res = await surfaceById("device-managed-networks")!.write!(api, { accountId: "acct", zoneId: "zone" }, snapshot, { dryRun: false });

  ok("the changed item is UPDATED, not skipped for want of an id", res.applied === 1 && res.skipped.length === 0);
  const put = sent.find((x) => x.method === "PUT" || x.method === "PATCH");
  ok("the update targets the item path built from network_id", put !== undefined && put.path === "/accounts/acct/devices/networks/N1");
  ok("no CREATE was issued (that would duplicate the network)", !sent.some((x) => x.method === "POST"));
  // The id is server-assigned, so a restored object carries a NEW one: sending it back, or comparing it,
  // makes the item differ from its snapshot forever.
  ok("the item's own server id is NOT sent in the body", put !== undefined && (put.body as Record<string, unknown>).network_id === undefined);
}

console.log("-- ...and an item differing ONLY by its own server id is a no-op --");
{
  // The convergence half of the same defect. A restore creates a new object with a new network_id; if that
  // field is compared, live never equals the snapshot and the writer re-applies on every single run.
  const liveNet = [{ network_id: "NEW-AFTER-RESTORE", name: "corp", type: "tls", config: { tls_sockaddr: "10.0.0.1:443" } }];
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async () => null,
    getPage: async (path) => (path.split("?", 1)[0] === "/accounts/acct/devices/networks" ? { result: liveNet } : { result: [] }),
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  const snapshot = [{ network_id: "OLD-FROM-SNAPSHOT", name: "corp", type: "tls", config: { tls_sockaddr: "10.0.0.1:443" } }];
  const res = await surfaceById("device-managed-networks")!.write!(api, { accountId: "acct", zoneId: "zone" }, snapshot, { dryRun: false });
  ok("a stale server id alone does not make the item look changed", sent.length === 0 && res.changes.length === 0 && res.applied === 0);
}

console.log("-- nested collections: an update must not silently replace one (gateway-lists) --");
{
  // writeListSpec never deletes an ITEM. But an update sends the whole item, so a collection nested INSIDE
  // an item is replaced wholesale and any entry the snapshot lacks goes with it. That is B3's shape one
  // level down. Only surfaces that DECLARE a nested collection are guarded, because guessing which array
  // field is a collection rather than an ordinary value would refuse restores for the wrong reason.
  // The list endpoint returns NO items (that is the whole reason the surface sub-reads); the entries come
  // from /lists/{id}/items. The stub has to answer both, because the writer now reads live the same way the
  // surface does.
  const liveIndex = [{ id: "L1", name: "allow", description: "d", type: "SERIAL", count: 3 }];
  const liveItems = [{ value: "AA11", created_at: "t1" }, { value: "BB22", created_at: "t1" }, { value: "ZZ99", created_at: "t2" }];
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async () => null,
    getPage: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/accounts/acct/gateway/lists") return { result: liveIndex };
      if (base === "/accounts/acct/gateway/lists/L1/items") return { result: liveItems };
      return { result: [] };
    },
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  // Same list, description edited so the item counts as CHANGED, and ZZ99 absent from the snapshot.
  const snapshot = [{ id: "L1", name: "allow", description: "edited", type: "SERIAL", count: 2, items: [{ value: "AA11" }, { value: "BB22" }] }];
  const res = await surfaceById("gateway-lists")!.write!(api, { accountId: "acct", zoneId: "zone" }, snapshot, { dryRun: false });

  ok("NO write is issued when an update would drop a nested entry", sent.length === 0);
  ok("applied is 0", res.applied === 0);
  const removes = res.changes.filter((c) => c.action === "remove");
  ok("the lost entry is reported as a REMOVE change", removes.length === 1);
  ok("the removal NAMES the entry rather than counting them", removes[0]?.path.includes("value=ZZ99") === true);
  ok("the skip is classed live-only-rules", res.skipped.some((k) => k.cls === "live-only-rules"));
}

console.log("-- nested collections: the writer must read live the SAME way the surface does --");
{
  // writeListSpec paginates listPath itself by default, which assumes the surface's read is the same
  // plain list. gateway-lists sub-reads each list's items, so a writer that ignores the surface's reader
  // sees a live view with no `items` key at all, and the snapshot's extra key makes every list differ.
  //
  // The stub deliberately serves the entries ONLY on the sub-path, so a writer that does not use the
  // surface's reader sees a list with no items and reports a change.
  const liveIndex = [{ id: "L1", name: "allow", description: "d", type: "SERIAL", count: 2 }];
  const liveItems = [{ value: "AA11", created_at: "LATER" }, { value: "BB22", created_at: "LATER" }];
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async () => null,
    getPage: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/accounts/acct/gateway/lists") return { result: liveIndex };
      if (base === "/accounts/acct/gateway/lists/L1/items") return { result: liveItems };
      return { result: [] };
    },
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  // Identical apart from each entry's created_at, which is exactly what a restore produces.
  const snapshot = [{ id: "L1", name: "allow", description: "d", type: "SERIAL", count: 2, items: [{ value: "AA11", created_at: "EARLIER" }, { value: "BB22", created_at: "EARLIER" }] }];
  const res = await surfaceById("gateway-lists")!.write!(api, { accountId: "acct", zoneId: "zone" }, snapshot, { dryRun: false });
  ok("a list whose entries are only reachable via the sub-read is a clean no-op", sent.length === 0 && res.changes.length === 0 && res.skipped.length === 0);
  // The nested strip is not the convergence fix (jsonEqual already ignores stamped fields at any depth),
  // but it should still keep them out of the request body.
  const sentBody = sent.find((x) => x.method === "PUT")?.body as { items?: Array<Record<string, unknown>> } | undefined;
  ok("nothing was sent, so there is no body carrying nested timestamps", sentBody === undefined);
}

console.log("-- rulesets write(): an identical snapshot is a clean no-op --");
{
  // The guard above must not fire when live and snapshot agree, or every restore would refuse forever.
  const liveIndex = [{ id: "rs-http", phase: "http_request_firewall_custom", name: "zone" }];
  const rules = [{ id: "r1", action: "block", expression: "ip.src eq 1.2.3.4" }];
  const liveFull = { id: "rs-http", phase: "http_request_firewall_custom", rules };
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/zones/zone/rulesets/rs-http") return liveFull;
      if (base === "/zones/zone/rulesets") return liveIndex;
      return null;
    },
    getPage: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/zones/zone/rulesets") return { result: liveIndex };
      return { result: [] };
    },
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  const res = await surfaceById("rulesets")!.write!(api, IDS, [{ id: "rs-http", phase: "http_request_firewall_custom", rules }], { dryRun: false });
  ok("no PUT, no changes, no skips when live already matches the snapshot", sent.length === 0 && res.changes.length === 0 && res.skipped.length === 0);

  // unchanged ruleset -> no PUT.
  const sent2: Sent[] = [];
  const api2: CfApi = {
    get: async (path) => { const b = path.split("?", 1)[0]!; return b === "/zones/zone/rulesets/rs-http" ? liveFull : b === "/zones/zone/rulesets" ? liveIndex : null; },
    getPage: async (path) => (path.split("?", 1)[0] === "/zones/zone/rulesets" ? { result: liveIndex } : { result: [] }),
    send: async (method, path, body) => { sent2.push({ method, path, body }); return {}; },
  };
  // identical rules (server-stamped version aside) -> skip.
  const same = [{ id: "rs-http", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 1.2.3.4" }] }];
  const res2 = await surfaceById("rulesets")!.write!(api2, IDS, same, { dryRun: false });
  ok("an UNCHANGED ruleset writes nothing (idempotent skip)", sent2.length === 0 && res2.applied === 0 && res2.changes.length === 0);

  // a snapshot ruleset for a phase that is NOT live -> reported, but NEVER blind-created.
  const sent3: Sent[] = [];
  const api3: CfApi = {
    get: async () => liveFull,
    getPage: async (path) => (path.split("?", 1)[0] === "/zones/zone/rulesets" ? { result: [] } /* NO live rulesets */ : { result: [] }),
    send: async (method, path, body) => { sent3.push({ method, path, body }); return {}; },
  };
  const orphan = [{ id: "rs-x", phase: "http_ratelimit", rules: [{ action: "block", expression: "true" }] }];
  const res3 = await surfaceById("rulesets")!.write!(api3, IDS, orphan, { dryRun: false });
  ok("a phase with no live ruleset is reported as an add but NEVER blind-created (skipped)", sent3.length === 0 && res3.changes.some((c) => c.action === "add") && res3.skipped.length === 1);
}

console.log("-- account-rulesets write(): same diff logic but routed to /accounts/{id}/rulesets --");
{
  // The account-scoped factory differs from the zone one only in base path. A regression that
  // inverted the scope would send PUTs to /zones instead of /accounts; assert the account path.
  const liveIndex = [{ id: "rs-acct", phase: "http_request_firewall_custom", name: "account" }];
  const liveFull = { id: "rs-acct", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 1.2.3.4", version: "3" }] };
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async (path) => {
      const b = path.split("?", 1)[0]!;
      if (b === "/accounts/acct/rulesets/rs-acct") return liveFull;
      if (b === "/accounts/acct/rulesets") return liveIndex;
      return null;
    },
    getPage: async (path) => (path.split("?", 1)[0] === "/accounts/acct/rulesets" ? { result: liveIndex } : { result: [] }),
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  // changed expression -> PUT to the ACCOUNT path.
  const snapshot = [{ id: "rs-acct", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 9.9.9.9" }] }];
  const res = await surfaceById("account-rulesets")!.write!(api, IDS, snapshot, { dryRun: false });
  const put = sent.find((s) => s.method === "PUT");
  ok("the changed account ruleset is PUT to /accounts/{id}/rulesets/{id}", !!put && put.path === "/accounts/acct/rulesets/rs-acct");
  ok("the account PUT never hits a /zones path", !sent.some((s) => s.path.startsWith("/zones")));
  ok("applied is exactly 1 for the account ruleset", res.applied === 1);

  // unchanged account ruleset -> idempotent skip (no write).
  const sent2: Sent[] = [];
  const api2: CfApi = {
    get: async (path) => { const b = path.split("?", 1)[0]!; return b === "/accounts/acct/rulesets/rs-acct" ? liveFull : b === "/accounts/acct/rulesets" ? liveIndex : null; },
    getPage: async (path) => (path.split("?", 1)[0] === "/accounts/acct/rulesets" ? { result: liveIndex } : { result: [] }),
    send: async (method, path, body) => { sent2.push({ method, path, body }); return {}; },
  };
  const same = [{ id: "rs-acct", phase: "http_request_firewall_custom", rules: [{ id: "r1", action: "block", expression: "ip.src eq 1.2.3.4" }] }];
  const res2 = await surfaceById("account-rulesets")!.write!(api2, IDS, same, { dryRun: false });
  ok("an UNCHANGED account ruleset writes nothing (idempotent skip)", sent2.length === 0 && res2.applied === 0);
}

console.log("-- the ordered/reprovision surfaces deliberately stay PREVIEW-ONLY (no write path forced on) --");
{
  // members/roles/service-tokens/certs/load-balancers must NOT have a write(); they need
  // dependency-ordered create / id-remap / re-provision that a flat apply cannot do safely.
  for (const id of ["account-members", "account-roles", "access-service-tokens", "certificate-packs", "custom-certificates", "load-balancers", "lb-pools", "access-apps"]) {
    const s = surfaceById(id)!;
    ok(`${id} (ordered/reprovision) has NO write(): backup + diff-preview only`, s.write === undefined && s.restoreTier !== "idempotent");
  }
}

console.log("-- every surface that HAS a write() is gated restoreTier === 'idempotent' --");
{
  const { CF_CONFIG_SURFACES } = await import("../src/sources/cf-config-surfaces.ts");
  const withWrite = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function");
  ok("at least DNS, rulesets, account-rulesets, page-rules, firewall-access-rules have a write()", ["dns", "rulesets", "account-rulesets", "page-rules", "firewall-access-rules"].every((id) => withWrite.some((s) => s.id === id)));
  ok("EVERY surface with a write() is restoreTier idempotent (never ordered/reprovision)", withWrite.every((s) => s.restoreTier === "idempotent"));
}

// The diff preview and the write strip must agree. SERVER_STAMPED fields (id, version, zone_id, ...)
// are stripped before a write and so must NOT surface in the diff preview as spurious "change" rows.
console.log("-- diff preview ignores server-stamped fields (in lockstep with the write strip) --");
{
  ok("SKIP_IN_DIFF includes a purely server-stamped field (version)", SKIP_IN_DIFF.has("version"));
  ok("SKIP_IN_DIFF includes a stamped id/zone field", SKIP_IN_DIFF.has("id") && SKIP_IN_DIFF.has("zone_id"));
  // Two items identical but for server-stamped fields: jsonEqual treats them equal, and diffConfig
  // reports no change.
  const live = { name: "rec", content: "1.2.3.4", id: "abc", version: 3, zone_id: "z1", modified_on: "2026-01-01T00:00:00Z" };
  const snap = { name: "rec", content: "1.2.3.4", id: "def", version: 1, zone_id: "z1" };
  ok("jsonEqual ignores server-stamped + volatile fields", jsonEqual(live, snap));
  const diff = diffConfig(live, snap);
  ok("diffConfig surfaces NO change for a stamped-only difference (version/id are not 'changes')", diff.changes.length === 0);
  // A genuine editable change IS still surfaced.
  const changed = { name: "rec", content: "9.9.9.9", id: "def", version: 1 };
  const diff2 = diffConfig(live, changed);
  ok("diffConfig still surfaces a real editable change (content)", diff2.changes.some((c) => c.path.includes("content")));
}

console.log("\n-- an ABSENT nested array in the snapshot is not an EMPTY one --");
{
  // nestedLiveOnly skips a field unless BOTH sides are arrays, because a snapshot that never captured
  // the nested collection is not a snapshot that captured it as empty. Treating the absent case as empty
  // would make every live entry read as a loss, refusing every restore of that surface forever on an
  // archive that is perfectly good.
  const liveIndex = [{ id: "L1", name: "allow", description: "d", type: "SERIAL", count: 3 }];
  const liveItems = [{ value: "AA11", created_at: "t1" }, { value: "ZZ99", created_at: "t2" }];
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async () => null,
    getPage: async (path) => {
      const base = path.split("?", 1)[0]!;
      if (base === "/accounts/acct/gateway/lists") return { result: liveIndex };
      if (base === "/accounts/acct/gateway/lists/L1/items") return { result: liveItems };
      return { result: [] };
    },
    send: async (method, path, body) => { sent.push({ method, path, body }); return {}; },
  };
  // The snapshot carries NO `items` key: an older capture, from before the surface sub-read its entries.
  const snapshot = [{ id: "L1", name: "allow", description: "edited", type: "SERIAL", count: 3 }];
  const res = await surfaceById("gateway-lists")!.write!(api, { accountId: "acct", zoneId: "zone" }, snapshot, { dryRun: false });
  ok("an ABSENT nested array is not an empty one, so the update is NOT refused", !res.skipped.some((k) => k.cls === "live-only-rules"));
  ok("and no live entry is reported as lost on an archive that simply never captured them", !res.changes.some((c) => c.action === "remove"));
}

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nCF-CONFIG WRITE-BACK VECTORS PASS");
