// validate-config-change-secret-lifetime: who can READ a delivery credential out of the pending-change
// inbox, and how long the store HOLDS one, driven against the real Durable Object through the production
// router rather than reasoned about.
//
// THE FINDING, and it is a capability bypass rather than a residue. A NotifyChannel carries the customer's
// live delivery credential: the url of a webhook/Slack/Teams channel (whose ingest token usually rides in
// the path), a PagerDuty routingKey, a JSM GenieKey or ServiceNow password as apiKey. router-ops.ts gates
// GET /admin/notify/channels on notify.config for exactly that reason and says so in as many words, calling
// a channel a bearer credential rather than read-only metadata. Under the dual-control gate a channel edit
// does not go to that route: it queues as a notify-channel-set pending change, stored VERBATIM because the
// approved replay must be byte-faithful, and GET /admin/config/changes returned those records verbatim on a
// downpipe.read gate. Read off ROLE_CAPABILITIES, viewer, restore-operator and access-admin hold
// downpipe.read and hold NO notify.config, so three roles that are deliberately refused the credential on
// one route were handed it on another. Section B drives that as an attack from each of the three.
//
// AND THE STORE KEPT IT. configchange: has no TTL by design and nothing anywhere deletes a record, so a
// rejected or superseded notify-channel-set held the submitted credential indefinitely. Section C drives all
// three terminal transitions; section F sweeps the whole prefix for anything left behind.
//
// THE TWO HALVES ARE INDEPENDENT, and that is the point of splitting the sections this way. The read-path
// projection (viewConfigChange, wired into the listing and the two decision responses) is what section B
// measures; the at-rest scrub (scrubSpentChangeParams, wired into the three terminal puts) is what sections
// C and F measure. Deleting either one leaves the other's assertions green, which is what stops half a fix
// riding on no proof at all.
//
// HOW THIS FILE AVOIDS PROVING NOTHING.
//   1. Every "the credential is gone" assertion is paired with a "it was there" control taken from the SAME
//      record moments earlier, read RAW out of storage past every projection, and with a "the decision-
//      relevant params survived" control, so neither an empty queue nor an erased record can satisfy it.
//   2. Section B's redaction assertions are paired with a control that the reader could reach the route at
//      all and a control that the record still names its kind, its proposer and its diff, so a projection
//      that returned nothing would fail rather than pass.
//   3. No assertion prints a credential value or a params object. The probes are recognisable literals that
//      are only ever tested for presence or absence, so a FAILING run spills nothing either.
//
// Run: node test/validate-config-change-secret-lifetime.ts

import { CHANGE_PREFIX, changeKey, type PendingConfigChange } from "../src/admin/change-control.ts";
import { GOVERNANCE_FAULTS_KEY, governanceFaultKey } from "../src/sched/sched-fault-ledger.ts";
import { buildContext, OWNER, OPERATOR, OPERATOR2, VIEWER, ACCESS_ADMIN } from "./validate-config-change-control-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The three probes stand in for the three secret-bearing fields of a NotifyChannel. They are only ever
// tested for presence or absence and are never printed, so neither a passing nor a failing run emits one.
const URL_PROBE = "DO-NOT-LOG-cfgchange-url-token";
const RK_PROBE = "DO-NOT-LOG-cfgchange-routing-key";
const KEY_PROBE = "DO-NOT-LOG-cfgchange-api-key";
// The RESTORE-OPERATOR is the third downpipe.read holder without notify.config and is not in the shared
// harness's fixture set, so this file seeds it: the finding is about all three roles, not just the viewer.
const RESTORER = "restoreop@acme.example";

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { call, sched, setGate, pendingChanges } = ctx;
  const store = sched.storage;

  // Read the record RAW, past the listing filter and past every projection: this is what the Durable Object
  // actually holds, which is the only thing an at-rest assertion may be built on.
  const atRest = (id: string): PendingConfigChange | undefined => store.rawGet<PendingConfigChange>(changeKey(id));
  const holds = (id: string, probe: string): boolean => JSON.stringify(atRest(id)?.params ?? null).includes(probe);
  const governanceFaults = (): Record<string, { count?: number }> => store.rawGet<Record<string, { count?: number }>>(GOVERNANCE_FAULTS_KEY) ?? {};
  const integrityFailed = (): number => governanceFaults()[governanceFaultKey("change-approve", "integrity-failed")]?.count ?? 0;

  // Queue a channel set under the gate, returning the pending record's id. The 202 is asserted by the
  // caller's own control, so a route that stopped queueing cannot be mistaken for a redaction.
  const queueChannel = async (body: Record<string, unknown>): Promise<{ status: number; id: string }> => {
    const r = await call(OPERATOR, "POST", "/admin/notify/channels", body);
    const j = (await r.json()) as { id?: string };
    return { status: r.status, id: j.id ?? "" };
  };

  try {
    // ===========================================================================================
    // SECTION A: the reproduction. Everything below is vacuous unless a queued channel change really
    // does store a real credential at rest, so A asserts that rather than assuming it, once per
    // secret-bearing field.
    // ===========================================================================================
    let webhookId = "";
    let pagerdutyId = "";
    {
      // Seeded BEFORE the gate is armed, so it applies inline: once the gate is on, a role-set QUEUES like
      // every other config mutation and the fixture would never exist.
      ok("A1: a restore-operator exists, so section B covers all three refused roles", (await call(OWNER, "POST", "/admin/roles", { email: RESTORER, role: "restore-operator" })).status === 200);
      ok("A2: the dual-control gate arms", (await setGate(OWNER, true)).status === 200);

      const webhook = await queueChannel({ kind: "webhook", name: "secret-lifetime-webhook", url: `https://hooks.slack.example/services/T0/B0/${URL_PROBE}` });
      ok("A3: CONTROL, a channel set under the gate QUEUES (202) rather than applying", webhook.status === 202 && webhook.id.length > 0);
      webhookId = webhook.id;
      ok("A4: CONTROL, the queued record really holds the url credential at rest", holds(webhookId, URL_PROBE));

      const pagerduty = await queueChannel({ kind: "pagerduty", name: "secret-lifetime-pagerduty", routingKey: RK_PROBE });
      ok("A5: CONTROL, a pagerduty channel set also queues", pagerduty.status === 202 && pagerduty.id.length > 0);
      pagerdutyId = pagerduty.id;
      ok("A6: CONTROL, the queued record really holds the routing key at rest", holds(pagerdutyId, RK_PROBE));
    }

    // ===========================================================================================
    // SECTION B: THE CAPABILITY BYPASS. Three roles hold downpipe.read and not notify.config. Each is
    // refused the credential on the route that serves it, and each is driven at the inbox route that
    // used to hand it over. B1/B2 pin the asymmetry itself so B3 onwards is about a redaction and not
    // about a gate that happened to close.
    // ===========================================================================================
    {
      for (const [who, role] of [
        [VIEWER, "viewer"],
        [RESTORER, "restore-operator"],
        [ACCESS_ADMIN, "access-admin"],
      ] as const) {
        const channels = await call(who, "GET", "/admin/notify/channels");
        ok(`B1(${role}): CONTROL, the channels route REFUSES them (this is the credential gate the finding is about)`, channels.status === 403);
        const inbox = await call(who, "GET", "/admin/config/changes");
        ok(`B2(${role}): CONTROL, the inbox route ADMITS them, so B3 is about the body and not the gate`, inbox.status === 200);
        const body = await inbox.text();
        ok(`B3(${role}): the inbox body carries NO url credential`, !body.includes(URL_PROBE));
        ok(`B4(${role}): the inbox body carries NO pagerduty routing key`, !body.includes(RK_PROBE));
        // The controls that stop B3/B4 being satisfied by an empty or gutted response.
        const listed = JSON.parse(body) as PendingConfigChange[];
        const rec = listed.find((c) => c.id === webhookId);
        ok(`B5(${role}): CONTROL, the queued change is still IN their inbox`, rec !== undefined && rec.kind === "notify-channel-set");
        ok(`B6(${role}): CONTROL, it still names its proposer, so the record is projected and not emptied`, rec?.proposedBy === OPERATOR);
        ok(`B7(${role}): CONTROL, it still carries the plain-English diff the approver decides from`, (rec?.diff.length ?? 0) > 0);
        // THE REVIEWABLE PART SURVIVES, and this is the assertion that makes the redaction defensible rather
        // than merely safe. The diff line for a NEW channel reads "notify channel <name> (<kind>) added" and
        // names no endpoint, so if the projection simply deleted the url a reviewer would be asked to approve
        // an alert destination without being told where it points. The host is kept, under config-snapshot's
        // own urlHost name and through its own helper, so the reviewer sees before the change exactly what
        // the config history will show them after it.
        ok(`B8(${role}): CONTROL, the projected params still name the destination HOST, which is what a reviewer needs`, (rec?.params as { urlHost?: string } | undefined)?.urlHost === "hooks.slack.example");
      }
      // The false-positive direction, at the other end: the roles that legitimately hold notify.config must
      // still be able to read the channels route. A fix that closed the bypass by breaking that route would
      // pass every assertion above.
      ok("B9: CONTROL, an owner can still read the channels route", (await call(OWNER, "GET", "/admin/notify/channels")).status === 200);
      ok("B10: CONTROL, an operator (notify.config) can still read it too", (await call(OPERATOR, "GET", "/admin/notify/channels")).status === 200);
    }

    // ===========================================================================================
    // SECTION C: THE AT-REST SCRUB, at each of the three terminal transitions. A pending record cannot
    // be scrubbed (its params are the replay input and the contentHash pre-image), so C1 pins that a
    // still-pending record keeps everything, which is the control that stops the rest being an
    // indiscriminate erasure.
    // ===========================================================================================
    {
      ok("C1: CONTROL, a still-PENDING record keeps its params, because the approve must replay them", holds(webhookId, URL_PROBE));
      ok("C2: CONTROL, and it is not marked scrubbed", atRest(webhookId)?.paramsScrubbedAt === undefined);

      // TERMINAL 1: REJECTED. The sharpest human case, an operator withdrawing a wrong paste.
      const rejected = await call(OPERATOR2, "POST", `/admin/config/changes/${pagerdutyId}/reject`);
      ok("C3: CONTROL, the reject succeeds", rejected.status === 200);
      ok("C4: the rejected record NO LONGER holds the routing key at rest", !holds(pagerdutyId, RK_PROBE));
      ok("C5: the rejected record is marked as scrubbed", typeof atRest(pagerdutyId)?.paramsScrubbedAt === "string");
      ok("C6: CONTROL, its non-secret params survive, so C4 is a scrub and not an erasure", JSON.stringify(atRest(pagerdutyId)?.params ?? null).includes("secret-lifetime-pagerduty"));
      ok("C7: CONTROL, the record itself survives for the forensic account", atRest(pagerdutyId)?.status === "rejected");
      const rejectBody = await rejected.text();
      ok("C8: and the reject RESPONSE echoes no credential either", !rejectBody.includes(RK_PROBE));

      // TERMINAL 2: APPLIED. The scrub runs AFTER the replay, so the channel must really exist with the
      // real credential in the live config: a scrub that ran early would break the byte-faithful replay,
      // and this is the assertion that would catch it.
      const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${webhookId}/approve`);
      ok("C9: CONTROL, a distinct notify.config holder approves the channel set", approve.status === 200);
      const channelsText = await (await call(OWNER, "GET", "/admin/notify/channels")).text();
      ok("C10: CONTROL, the approved change really APPLIED, credential intact, so the scrub did not break the replay", channelsText.includes(URL_PROBE));
      ok("C11: the applied record NO LONGER holds the url at rest", !holds(webhookId, URL_PROBE));
      ok("C12: the applied record is marked as scrubbed", typeof atRest(webhookId)?.paramsScrubbedAt === "string");
      ok("C13: CONTROL, its non-secret params survive", JSON.stringify(atRest(webhookId)?.params ?? null).includes("secret-lifetime-webhook"));
      ok("C14: CONTROL, the record survives as the account of what a second identity approved", atRest(webhookId)?.status === "applied" && atRest(webhookId)?.approvedBy === OPERATOR2);
      const approveBody = await approve.text();
      ok("C15: and the approve RESPONSE echoes no credential either", !approveBody.includes(URL_PROBE));

      // TERMINAL 3: SUPERSEDED. The record an operator is likeliest to forget: approved, refused, never
      // coming back. Reached by moving the config head under a queued change.
      const supersedeTarget = await queueChannel({ kind: "webhook", name: "secret-lifetime-superseded", url: `https://hooks.slack.example/services/T1/B1/${URL_PROBE}` });
      ok("C16: CONTROL, a third channel set queues", supersedeTarget.status === 202);
      ok("C17: CONTROL, and holds the url at rest before the base moves", holds(supersedeTarget.id, URL_PROBE));
      // MOVE THE HEAD the way production does: queue a SECOND change against the same base and approve it,
      // which applies and auto-snapshots. The first change's recorded base is now stale, so its approve must
      // refuse as superseded rather than apply against a base nobody reviewed it against. A bare
      // /admin/config/snapshot does NOT work here: the snapshot route de-dupes an unchanged posture, so the
      // head never moves and a stale approve would simply apply.
      const mover = await queueChannel({ kind: "webhook", name: "secret-lifetime-mover", url: "https://mover.acme.example/hook" });
      ok("C18: CONTROL, the head-moving change queues", mover.status === 202);
      ok("C19: CONTROL, and applies, which moves the config head under the first one", (await call(OPERATOR2, "POST", `/admin/config/changes/${mover.id}/approve`)).status === 200);
      const stale = await call(OPERATOR2, "POST", `/admin/config/changes/${supersedeTarget.id}/approve`);
      ok("C20: CONTROL, the stale approve is REFUSED", stale.status >= 400);
      ok("C21: CONTROL, and the record really reached the superseded state", atRest(supersedeTarget.id)?.status === "superseded");
      ok("C22: the superseded record NO LONGER holds the url at rest", !holds(supersedeTarget.id, URL_PROBE));
      ok("C23: the superseded record is marked as scrubbed", typeof atRest(supersedeTarget.id)?.paramsScrubbedAt === "string");
      ok("C24: CONTROL, its non-secret params survive", JSON.stringify(atRest(supersedeTarget.id)?.params ?? null).includes("secret-lifetime-superseded"));
      ok("C25: CONTROL, and so does the reviewable HOST, so the at-rest scrub is the same reduction the read path applies", (atRest(supersedeTarget.id)?.params as { urlHost?: string } | undefined)?.urlHost === "hooks.slack.example");
    }

    // ===========================================================================================
    // SECTION D: THE SCRUB MUST NOT MASQUERADE AS A TAMPER. A scrubbed record's contentHash cannot
    // recompute from its params, by construction. That is safe here ONLY because canApproveChange
    // refuses every terminal status BEFORE any hash is derived, so a scrubbed record is never hashed.
    // The owner-action store had to add an explicit guard for the same situation because its expiry is
    // computed at read; this store has no clock, so the ordering does the work. Asserted, not trusted:
    // if that ordering is ever changed, D2 turns red rather than the integrity ledger filling with
    // false alarms.
    // ===========================================================================================
    {
      const spentAndScrubbed = pagerdutyId; // rejected in section C, and really scrubbed (C5)
      const before = integrityFailed();
      const again = await call(OPERATOR2, "POST", `/admin/config/changes/${spentAndScrubbed}/approve`);
      ok("D1: a second approve of a spent, scrubbed change is refused", again.status >= 400);
      ok("D2: and NOTHING is filed as integrity-failed, so a scrub cannot be mistaken for a tamper", integrityFailed() === before);
      const scrubbedReason = await again.text();

      // THE CONTROL THAT MAKES D2 MEAN SOMETHING: a spent change that carried NO secret is never scrubbed
      // at all, and the refusal must read THE SAME. Otherwise the same situation would be described two
      // ways, decided by whether the params happened to hold a credential. The control is REJECTED, matching
      // the scrubbed record's terminal state exactly: comparing a rejected record's refusal with an applied one's would
      // compare two genuinely different situations and would fail for a reason that is not about secrets.
      const plain = await call(OPERATOR, "POST", "/admin/downpipes", ctx.dp("dp_secret_plain", "plain change"));
      ok("D3: CONTROL, a secret-free change queues", plain.status === 202);
      const plainId = ((await plain.json()) as { id: string }).id;
      ok("D4: CONTROL, a distinct approver rejects it, the same terminal state the scrubbed one reached", (await call(OPERATOR2, "POST", `/admin/config/changes/${plainId}/reject`)).status === 200);
      ok("D5: CONTROL, and it was NOT scrubbed, because there was nothing secret to strip", atRest(plainId)?.paramsScrubbedAt === undefined);
      const plainReason = await (await call(OPERATOR2, "POST", `/admin/config/changes/${plainId}/approve`)).text();
      ok("D6: the refusal reads THE SAME whether the spent change was scrubbed or not", scrubbedReason === plainReason && scrubbedReason.length > 0);

      // And the tamper teeth themselves survive: a PENDING record whose params were altered is still
      // caught, so D2 has not been bought by weakening the check it is about.
      const tamperTarget = await queueChannel({ kind: "webhook", name: "secret-lifetime-tamper", url: "https://tamper.acme.example/hook" });
      ok("D7: CONTROL, a change to tamper with queues", tamperTarget.status === 202);
      const rec = atRest(tamperTarget.id)!;
      store.rawPut(changeKey(tamperTarget.id), { ...rec, params: { ...(rec.params as Record<string, unknown>), name: "tampered" } });
      const beforeTamper = integrityFailed();
      const tampered = await call(OPERATOR2, "POST", `/admin/config/changes/${tamperTarget.id}/approve`);
      ok("D8: a tampered PENDING record is still refused", tampered.status >= 400);
      ok("D9: and IS filed as integrity-failed, so the tamper teeth survive", integrityFailed() > beforeTamper);
    }

    // ===========================================================================================
    // SECTION E: the pending record that nobody ever decides, stated as a measured limit rather than
    // left for the next reader to discover. Its params ARE the replay input and the hash pre-image, so
    // they cannot be stripped while the change can still be approved, and configchange deliberately has
    // no TTL. This is the one copy that outlives everything, and it is bounded by the operator emptying
    // their own inbox.
    // ===========================================================================================
    {
      const undecided = await queueChannel({ kind: "webhook", name: "secret-lifetime-undecided", url: `https://hooks.slack.example/services/T2/B2/${URL_PROBE}` });
      ok("E1: CONTROL, an undecided change queues", undecided.status === 202);
      // Reading the inbox is the act that would sweep it if there were a sweep to run. There is not.
      await pendingChanges(OWNER);
      ok("E2: LIMIT, an undecided pending change still holds its credential at rest after an inbox read", holds(undecided.id, URL_PROBE));
      ok("E3: and it is NOT marked scrubbed, so the marker never claims something untrue", atRest(undecided.id)?.paramsScrubbedAt === undefined);
      ok("E4: but the read path still refuses to publish it to a downpipe.read holder", !(await (await call(VIEWER, "GET", "/admin/config/changes")).text()).includes(URL_PROBE));
    }

    // ===========================================================================================
    // SECTION F: the enumeration made executable. What is left in the whole prefix once every path
    // above has run, so the next change to this subsystem reports what it started or stopped keeping
    // rather than drifting.
    // ===========================================================================================
    {
      const keys = store.keysWithPrefix(CHANGE_PREFIX);
      ok("F1: CONTROL, records are RETAINED (a scrub is not a delete)", keys.length > 0);
      const records = keys.map((k) => store.rawGet<PendingConfigChange>(k)).filter((r): r is PendingConfigChange => r !== undefined);
      const terminalHolding = records
        .filter((r) => r.status === "applied" || r.status === "rejected" || r.status === "superseded")
        .filter((r) => [URL_PROBE, RK_PROBE, KEY_PROBE].some((p) => JSON.stringify(r.params ?? null).includes(p)));
      ok("F2: NO terminal config-change record anywhere in the store holds a credential", terminalHolding.length === 0);
      ok("F3: CONTROL, the store really does contain terminal records, so F2 is not vacuous", records.some((r) => r.status !== "pending"));
      ok("F4: CONTROL, and it contains a pending one too, so F2 was a filter and not an empty set", records.some((r) => r.status === "pending"));
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  // Both arguments: called bare the guard reads failures as undefined and declares a verdict that means
  // nothing, and the check count rides so a run that asserted nothing cannot report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
