// Governance changes that the audit chain did not record, or recorded with a gap, and now does. Each proof
// drives the PRODUCTION router (handleAdmin, a forged-but-correctly-signed Access JWT, an in-memory
// SchedulerDO) and reads the chain back through GET /admin/audit, so the row a customer's reviewer reads is
// the row under test. Run: node test/validate-audit-governance-rows.ts
//
//  - NOTIFY: an applied notification channel or rule change writes notify-channel-change / notify-rule-change
//    with the configchange target (the closed changeKind and the stored id, never the url). A refused write
//    is a denied row, and a delete of an absent id writes nothing. Before engine 0.3.7 none of these wrote a
//    row while config approval was off. A change the approval gate queues still writes config-change-propose
//    only, and the approval that applies it writes config-change-approve, never a notify row. The default rule
//    that the first channel creates writes no rule row; the channel row records it.
//  - SUPPORT BUNDLE: a bundle downloaded (GET) or generated (POST) through the admin API writes
//    a support-bundle-generated row that records the route and the seal state. Before engine 0.3.7 only the vendor's
//    credentialed pull was on the chain.
//  - INTENT GATE: the offboarding attestation (access-policy-change-intent) is gated on roles.write, the
//    capability of the removal it attests, so an access-admin's attestation is recorded. key-ceremony-intent
//    stays on keys.ceremony (Owner only). Before engine 0.3.7 both were Owner only. A body that is not a JSON
//    object is a 400 for every caller that passes the pre-gate. It was a 500 once an access-admin could reach it.
//  - SOURCE BINDINGS: sources-attached and sources-detached name the bindings the attach wrote, on the
//    source-bindings target. Before engine 0.3.7 both carried the field-less access-policy target.

import { APPROVAL_MIN_DWELL_MS } from "../src/admin/approvals.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { changeKey } from "../src/admin/change-control.ts";
import { handleAdmin } from "../src/admin/router.ts";
import type { Caller } from "../src/admin/identity.ts";
import { observeAttachSideEffects } from "../src/admin/router-discovery.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { makeSupportRecipient } from "../tools/generate-support-keypair.ts";
import { buildContext, OPERATOR, OWNER, VIEWER } from "./validate-audit-harness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { ageRecord } from "./testutil.ts";

type ConfigChangeTarget = { kind: "configchange"; id: string; changeKind: string };

function rowsOf(events: AuditEvent[], action: string): AuditEvent[] {
  return events.filter((e) => e.action === action);
}

// rawPost sends a body as written, so a proof can post text that is not JSON. The harness call() always
// JSON-encodes its body.
async function rawPost(ctx: Awaited<ReturnType<typeof buildContext>>["ctx"], email: string, path: string, text: string): Promise<Response> {
  const headers = { "cf-access-jwt-assertion": await ctx.tokenFor(email), "content-type": "application/json" };
  return handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", headers, body: text }), ctx.accessEnv());
}

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { ok, call, readLog, accessEnv, tokenFor, subjectOf } = ctx;
  try {
    // ---- NOTIFY: channel and rule changes are on the chain -------------------------------------------
    {
      const url = "https://hooks.example.com/services/T000/B000/SECRETPATHTOKEN";
      const created = await call(OPERATOR, "POST", "/admin/notify/channels", { kind: "webhook", name: "Ops hook", url });
      ok("notify: an operator creates a webhook channel (200)", created.status === 200);
      const channelId = ((await created.json()) as { id: string }).id;
      const edited = await call(OPERATOR, "POST", "/admin/notify/channels", { id: channelId, kind: "webhook", name: "Ops hook", url: `${url}2` });
      ok("notify: the operator edits the channel (200)", edited.status === 200);
      const refused = await call(VIEWER, "POST", "/admin/notify/channels", { kind: "webhook", name: "x", url: "https://evil.example.com/h" });
      ok("notify: a viewer is refused a channel write (403)", refused.status === 403);

      const rules = (await (await call(OPERATOR, "GET", "/admin/notify/rules")).json()) as Array<{ id: string }>;
      ok("notify: the first channel minted the default-on rule", rules.length === 1);
      const ruleId = rules[0]?.id ?? "";
      const ruleSet = await call(OPERATOR, "POST", "/admin/notify/rules", { id: ruleId, scope: { kind: "global" }, minSeverity: "critical", events: ["backup-failure"], channelIds: [channelId], enabled: true });
      ok("notify: the operator edits the rule (200)", ruleSet.status === 200);
      const ruleDel = await call(OPERATOR, "POST", "/admin/notify/rules/delete", { id: ruleId });
      ok("notify: the operator deletes the rule (200)", ruleDel.status === 200);
      const ruleDelAgain = await call(OPERATOR, "POST", "/admin/notify/rules/delete", { id: ruleId });
      ok("notify: a second delete of the same rule is an idempotent 200", ruleDelAgain.status === 200);
      const chDel = await call(OPERATOR, "POST", "/admin/notify/channels/delete", { id: channelId });
      ok("notify: the operator deletes the channel (200)", chDel.status === 200);

      const log = await readLog();
      const channelRows = rowsOf(log.events, "notify-channel-change");
      const ruleRows = rowsOf(log.events, "notify-rule-change");
      const channelOk = channelRows.filter((e) => e.outcome === "success");
      ok("notify: create, edit and delete each wrote one notify-channel-change success row", channelOk.length === 3);
      ok(
        "notify: the channel rows name the stored channel id and the closed change kinds",
        channelOk.every((e) => e.target.kind === "configchange" && (e.target as ConfigChangeTarget).id === channelId) &&
          channelOk.filter((e) => (e.target as ConfigChangeTarget).changeKind === "notify-channel-set").length === 2 &&
          channelOk.filter((e) => (e.target as ConfigChangeTarget).changeKind === "notify-channel-delete").length === 1,
      );
      ok("notify: the channel rows attribute the operator", channelOk.every((e) => e.actorEmail === OPERATOR && e.actorMethod === "access"));
      const denied = channelRows.filter((e) => e.outcome === "denied");
      ok("notify: the refused viewer write is one denied row with no id", denied.length === 1 && denied[0]?.actorEmail === VIEWER && (denied[0]?.target as ConfigChangeTarget).id === "");
      const ruleOk = ruleRows.filter((e) => e.outcome === "success");
      // The default rule was created by the channel create. Only the edit and the delete wrote rule rows.
      // The log is newest first, so the channel create is the lowest seq among the channel rows.
      const createSeq = Math.min(...channelOk.map((e) => e.seq));
      ok("notify: the default rule the first channel created wrote no notify-rule-change row", ruleRows.length === 2 && ruleRows.every((e) => e.seq > createSeq + 1));
      ok("notify: the rule edit and the rule delete each wrote one notify-rule-change row (the repeat delete wrote none)", ruleOk.length === 2);
      ok(
        "notify: the rule rows name the rule id and set then delete",
        ruleOk.every((e) => (e.target as ConfigChangeTarget).id === ruleId) &&
          ruleOk.map((e) => (e.target as ConfigChangeTarget).changeKind).sort().join(",") === "notify-rule-delete,notify-rule-set",
      );
      // The url is a bearer credential. No part of its path may reach the chain.
      ok("notify: no row carries any part of the webhook url", !JSON.stringify(log.events).includes("SECRETPATHTOKEN") && !JSON.stringify(log.events).includes("hooks.example.com"));
    }

    // ---- SUPPORT BUNDLE: every bundle the admin API serves is on the chain ---------------------------
    {
      const before = rowsOf((await readLog()).events, "support-bundle-generated").length;
      const dl = await call(VIEWER, "GET", "/admin/support/bundle");
      ok("bundle: a viewer downloads the support bundle (200)", dl.status === 200);
      const gen = await call(OPERATOR, "POST", "/admin/support/bundle", {});
      ok("bundle: an operator generates the support bundle (200)", gen.status === 200);
      const rows = rowsOf((await readLog()).events, "support-bundle-generated");
      ok("bundle: each served bundle wrote one support-bundle-generated row", rows.length - before === 2);
      type BundleTarget = { kind: "support-bundle"; route: string; sealed: boolean };
      const byRoute = (r: string): AuditEvent | undefined => rows.find((e) => (e.target as BundleTarget).route === r);
      ok("bundle: the download row names the route and the viewer", byRoute("download")?.actorEmail === VIEWER && byRoute("download")?.outcome === "success");
      ok("bundle: the generate row names the route and the operator", byRoute("generate")?.actorEmail === OPERATOR && byRoute("generate")?.outcome === "success");
      // No VENDOR_SUPPORT_PUBLIC in this env, so the engine served a signed-only envelope and the row says so.
      ok("bundle: the rows record that the bundle was not sealed (no vendor key set)", rows.every((e) => e.target.kind === "support-bundle" && (e.target as BundleTarget).sealed === false));
      // With a vendor support key set, the engine seals the bundle and the row records sealed:true. The
      // flag is read from the envelope the engine served, so this is the half that proves it is not a constant.
      const vendor = await makeSupportRecipient();
      const sealedEnv = { ...accessEnv(), VENDOR_SUPPORT_PUBLIC: b64urlEncode(vendor.recipientPublic) } as unknown as Env;
      const sealedResp = await handleAdmin(new Request("https://engine.example/admin/support/bundle", { headers: { "cf-access-jwt-assertion": await tokenFor(OPERATOR) } }), sealedEnv);
      const sealedBody = (await sealedResp.json()) as { kind?: string };
      ok("bundle: with a vendor key the engine serves a sealed envelope", sealedResp.status === 200 && sealedBody.kind === "downpipe-support-bundle-sealed");
      const last = rowsOf((await readLog()).events, "support-bundle-generated")[0];
      ok("bundle: the sealed download wrote a row that records sealed:true", last !== undefined && (last.target as BundleTarget).route === "download" && (last.target as BundleTarget).sealed === true);
    }

    // ---- INTENT GATE: each intent marker has its own capability --------------------------------------
    {
      const ACCESS_ADMIN = "access-admin@acme.example";
      const grant = await call(OWNER, "POST", "/admin/roles", { email: ACCESS_ADMIN, role: "access-admin" });
      ok("intent: the owner grants access-admin (200)", grant.status === 200);
      const before = (await readLog()).events.length;
      const attest = await call(ACCESS_ADMIN, "POST", "/admin/audit/intent", { action: "access-policy-change-intent" });
      ok("intent: an access-admin records the offboarding attestation (200)", attest.status === 200);
      const attestEvent = (await attest.json()) as AuditEvent;
      ok("intent: the attestation row names the access-admin", attestEvent.action === "access-policy-change-intent" && attestEvent.actorEmail === ACCESS_ADMIN && attestEvent.target.kind === "access-policy");
      const ceremony = await call(ACCESS_ADMIN, "POST", "/admin/audit/intent", { action: "key-ceremony-intent" });
      ok("intent: an access-admin is refused the key-ceremony marker (403 on keys.ceremony)", ceremony.status === 403 && ((await ceremony.json()) as { required?: string }).required === "keys.ceremony");
      const opAttest = await call(OPERATOR, "POST", "/admin/audit/intent", { action: "access-policy-change-intent" });
      ok("intent: an operator (no roles.write) is refused the attestation (403)", opAttest.status === 403);
      const opBad = await call(OPERATOR, "POST", "/admin/audit/intent", { action: "totally-made-up" });
      ok("intent: a caller with neither capability gets 403 before the body is read, not 400", opBad.status === 403);
      const ownerCeremony = await call(OWNER, "POST", "/admin/audit/intent", { action: "key-ceremony-intent" });
      const ownerAttest = await call(OWNER, "POST", "/admin/audit/intent", { action: "access-policy-change-intent" });
      ok("intent: the owner still records both markers", ownerCeremony.status === 200 && ownerAttest.status === 200);
      const badJson = await rawPost(ctx, ACCESS_ADMIN, "/admin/audit/intent", "{not json");
      ok("intent: an access-admin who posts a body that is not JSON gets a 400, not a 500", badJson.status === 400);
      const nullBody = await call(ACCESS_ADMIN, "POST", "/admin/audit/intent", null);
      ok("intent: an access-admin who posts a JSON null gets a 400, not a 500", nullBody.status === 400);
      const ownerBad = await rawPost(ctx, OWNER, "/admin/audit/intent", "not json at all");
      ok("intent: the owner who posts a body that is not JSON gets a 400", ownerBad.status === 400);
      const opBadJson = await rawPost(ctx, OPERATOR, "/admin/audit/intent", "{not json");
      ok("intent: an operator's body that is not JSON is still refused 403 before the parse", opBadJson.status === 403);
      const added = (await readLog()).events.length - before;
      ok("intent: exactly the three accepted markers were written (the refusals wrote none)", added === 3);
    }

    // ---- SOURCE BINDINGS: the attach and detach rows name the bindings --------------------------------
    // The route needs a live Cloudflare deploy token, so this drives the post-write bookkeeping it calls
    // with the result changeBindings returns, against the same live in-memory scheduler.
    {
      const owner: Caller = { method: "access", email: OWNER, subject: subjectOf(OWNER), role: "owner", groups: [] };
      const deferred = await observeAttachSideEffects(
        { env: accessEnv(), caller: owner, sourceIp: "203.0.113.5" },
        "0123456789abcdef0123456789abcdef",
        { added: ["SRC_KV_app", "SRC_R2_media"], removed: ["SRC_D1_old"], permissionSummary: "Workers Scripts:Edit" },
      );
      ok("bindings: both rows landed (auditDeferred false)", deferred === false);
      const events = (await readLog()).events;
      type BindingsTarget = { kind: "source-bindings"; bindings: string[] };
      const attached = rowsOf(events, "sources-attached")[0];
      const detached = rowsOf(events, "sources-detached")[0];
      ok("bindings: sources-attached names the two added bindings", attached?.target.kind === "source-bindings" && (attached.target as BindingsTarget).bindings.join(",") === "SRC_KV_app,SRC_R2_media");
      ok("bindings: sources-detached names the removed binding", detached?.target.kind === "source-bindings" && (detached.target as BindingsTarget).bindings.join(",") === "SRC_D1_old");
      ok("bindings: the rows attribute the owner and the source IP", attached?.actorEmail === OWNER && attached?.sourceIp === "203.0.113.5" && detached?.actorEmail === OWNER);
    }

    // ---- NOTIFY WITH CONFIG APPROVAL ON: a queued change is a propose row, not a notify row ----------
    // Runs last because it arms the gate for the rest of this chain.
    {
      const OWNER2 = "owner2@acme.example";
      ok("approval: a second owner is granted (200)", (await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" })).status === 200);
      ok("approval: the owner arms config approval (200)", (await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true })).status === 200);
      const before = (await readLog()).events;
      const queued = await call(OPERATOR, "POST", "/admin/notify/channels", { kind: "webhook", name: "Queued hook", url: "https://hooks.example.com/queued" });
      ok("approval: the channel write is queued (202)", queued.status === 202);
      const after = (await readLog()).events;
      const added = after.slice(0, after.length - before.length);
      ok("approval: the queued write recorded config-change-propose", added.some((e) => e.action === "config-change-propose" && (e.target as ConfigChangeTarget).changeKind === "notify-channel-set"));
      ok("approval: the queued write recorded no notify-channel-change row", !added.some((e) => e.action === "notify-channel-change"));
      // The approve replays the change inside the DO. It applies the channel and writes config-change-approve,
      // never notify-channel-change, so the docs say "applies at once (config approval off)".
      const changeId = ((await queued.json()) as { id: string }).id;
      // Back-date the proposal past the approval dwell, so the approve is not refused as too soon.
      ageRecord(ctx.sched.storage, changeKey(changeId), "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
      const approve = await call(OWNER2, "POST", `/admin/config/changes/${changeId}/approve`);
      ok("approval: a second person approves the queued channel (200)", approve.status === 200);
      const channels = (await (await call(OPERATOR, "GET", "/admin/notify/channels")).json()) as Array<{ name: string }>;
      ok("approval: the approved channel applied", channels.some((c) => c.name === "Queued hook"));
      const final = (await readLog()).events;
      const approvedRows = final.slice(0, final.length - after.length);
      ok("approval: the approval recorded config-change-approve with the notify-channel-set kind", approvedRows.some((e) => e.action === "config-change-approve" && (e.target as ConfigChangeTarget).changeKind === "notify-channel-set"));
      ok("approval: the approval recorded no notify-channel-change row", !approvedRows.some((e) => e.action === "notify-channel-change"));
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  const failures = ctx.getFailures();
  console.log(failures === 0 ? "\nAUDIT GOVERNANCE ROWS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
