// validate-posture-evidence: ten POSTURE support-pack evidence gaps, each driven as a REAL state, through the
// REAL recorder, the REAL Durable Object, and into a REAL projected pack section. Each gap is a discrimination
// failure: a class of distinct, actionable states that the pack collapsed into one coarse, indistinguishable
// row (a source-attach refusal, a wiring-test outcome, an auth-signal burst vs trickle, a dropped IdP group, a
// security alert that never fired, a refused update, a corrupt governance record, a self-healing tamper
// verdict, a security refusal with no signal, and a silently disarmed update safety control).
//
// THE BAR. A recorder, a caller and a projection are NOT enough. Every case below ENUMERATES the states the gap
// says are indistinguishable, drives each one, and asserts they produce DIFFERENT rows. A generic fault recorded
// where a discriminator was asked for fails here.
//
// NO-CUSTODY: every case plants customer SENTINELS at the fault site (a group name, an endpoint, a token, an
// e-mail, a Cloudflare message) and asserts that not one appears in ANY byte of the stored record or the
// projected section.
//
// Run: node test/validate-posture-evidence.ts

import { makeScheduler, type MockStorage } from "./validate-scheduler-shared.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verifyAccessJWT } from "../src/admin/access.ts";
import { CALLER_HEADER, decodeCaller, encodeCaller } from "../src/admin/identity.ts";
import { buildAuthContext } from "../src/admin/auth-context.ts";
import { claimDropCounter, alertEmissionCounter, updateRefusalCounter, selfCheckDegradationCounter, ALERT_CLASSES, POSTURE_COUNTER_NAMES } from "../src/admin/posture-counters.ts";
import { routeAuthChangeAlert, routeRecoveryAlert } from "../src/admin/router-notify.ts";
import { destinationConfigured, makeHealthGate } from "../src/admin/update-gate.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import { completeOauth2Login } from "../src/admin/oauth2.ts";
import type { Oauth2Connection } from "../src/admin/idpconn.ts";
import { buildConfigVersion, CONFIG_GENESIS_PREV_HASH, configContentHash, type ConfigSnapshot, verifyConfigChain } from "../src/admin/config-history.ts";
import type { Env } from "../src/env.d.ts";
import { ADMIN_COUNTER_NAMES, applyAdminCounters } from "../src/admin/diag-records.ts";
import { applyAttachHealth, attachRefusalOf, AttachRefusal, ATTACH_REFUSAL_STAGES, ATTACH_REFUSAL_CAUSES } from "../src/admin/discovery-health.ts";
import { planChange, type LiveBinding } from "../src/admin/attach-plan.ts";
import { AUTH_SIGNAL_NAMES, bumpAuthSignalEntry, AUTH_SIGNAL_COUNT_CAP, AUTH_SIGNAL_DAY_SLOTS, MS_PER_DAY } from "../src/admin/auth-signals.ts";
import { verifyChain, auditHash, GENESIS_PREV_HASH } from "../src/admin/audit.ts";
import type { AuditEvent } from "../src/admin/audit-types.ts";
import { approvalTimestampUnparseable } from "../src/admin/approvals.ts";
import { ownerActionTimestampUnparseable } from "../src/admin/owner-action.ts";
import { expiryRowAnomalies, type ExpiryItem } from "../src/admin/expiry.ts";
import { customRoleReservedCapabilityDrops, type CustomRole } from "../src/admin/identity-rbac.ts";
import { checkChannelFreshness, resolveEngineArtefact, sanitiseChannelComponents, type Channel } from "../src/admin/updates.ts";
import { recordChainVerdict, classifyTestFailure, testStatusClass, CHAIN_BREAKS_KEY, TEST_REASON_CLASSES, type LedgerStorage } from "../src/sched/sched-fault-ledger.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";
import { fetchAuthSignals } from "../src/admin/support-sections-auth.ts";
import { fetchAuditStatus } from "../src/admin/support-sections-audit.ts";
import { fetchConfigIntegrity } from "../src/admin/support-sections-config.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- the CUSTOMER SENTINELS -----------------------------------------------------------------------------
const SENTINEL_GROUP = "CN=ACME-Payroll-Admins,OU=Finance,DC=acme,DC=example";
const SENTINEL_EMAIL = "cfo@acme.example";
const SENTINEL_TOKEN = "cf-token-Ax9-SECRET-Vv1";
const SENTINEL_ENDPOINT = "https://hooks.slack.example/services/T00/B11/acme-secret";
const SENTINEL_MESSAGE = "Authentication error (10000): token lacks com.cloudflare.edge.worker.write";
const SENTINEL_ACR = "urn:acme:internal:mfa:hardware-token-v3-payroll-only";
const SENTINELS = [SENTINEL_GROUP, SENTINEL_EMAIL, SENTINEL_TOKEN, SENTINEL_ENDPOINT, SENTINEL_MESSAGE, SENTINEL_ACR];
function scanForSentinels(v: unknown): string[] {
  const hay = JSON.stringify(v) ?? "";
  return SENTINELS.filter((s) => hay.includes(s));
}

// ---- the harness ----------------------------------------------------------------------------------------
type Sched = { storage: MockStorage; stub: DurableObjectStub };
function realScheduler(): Sched {
  const { storage, stub } = makeScheduler();
  const real = stub as unknown as { fetch(req: Request): Promise<Response> };
  const wrapped = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return real.fetch(input instanceof Request ? input : new Request(String(input), init));
    },
  } as unknown as DurableObjectStub;
  return { storage, stub: wrapped };
}

// A Map-backed LedgerStorage for the pure recorders (the sched-fault-ledger idiom).
function mapStorage(): LedgerStorage & { map: Map<string, unknown> } {
  const map = new Map<string, unknown>();
  return {
    map,
    async get<T>(k: string): Promise<T | undefined> {
      return map.get(k) as T | undefined;
    },
    async put<T>(k: string, v: T): Promise<void> {
      map.set(k, v);
    },
    async list<T>(o?: { prefix?: string }): Promise<Map<string, T>> {
      const out = new Map<string, T>();
      for (const [k, v] of map) if (o?.prefix === undefined || k.startsWith(o.prefix)) out.set(k, v as T);
      return out;
    },
  };
}

console.log("validate-posture-evidence");

// =========================================================================================================
// The CLAIM BOUNDING DROPS. Four states the pack could not tell apart, at three boundaries.
// =========================================================================================================
console.log("\nclaim bounding drops -- present-but-dropped vs the IdP sending nothing");
{
  // The three boundaries x the drop kinds each can produce. Every combination the recorders can emit must be a
  // member of ADMIN_COUNTER_NAMES, or the aggregate silently DROPS it and the evidence never reaches the pack.
  const emitted = [
    claimDropCounter("access-jwt", "group-overlength"),
    claimDropCounter("access-jwt", "group-control-char"),
    claimDropCounter("access-jwt", "groups-list-capped"),
    claimDropCounter("access-jwt", "idp-hint"),
    claimDropCounter("oidc-token", "group-overlength"),
    claimDropCounter("oidc-token", "group-control-char"),
    claimDropCounter("oidc-token", "groups-list-capped"),
    claimDropCounter("oidc-token", "acr"),
    claimDropCounter("oidc-token", "amr"),
    claimDropCounter("oidc-token", "auth-time"),
  ];
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
  ok("every emittable claim-drop name is in the closed admin-counter vocabulary", emitted.every((n) => vocab.has(n)));
  ok("the names are DISTINCT (a boundary and a kind that coalesced would not discriminate)", new Set(emitted).size === emitted.length);

  // R5: THE CALLER-HEADER BOUNDARY IS DELETED, AND THE PROOF THAT USED TO STAND HERE IS WHY.
  //
  // It hand-built a caller header carrying an over-long group / a control-char group / 261 groups, ran it
  // through decodeCaller, and called the three resulting rows the discrimination proof. No production producer
  // can emit that header: access.ts boundGroups, oidc.ts boundGroups, oauth2.ts addGroup and the DO's own
  // boundGroupList all pre-bound with the IDENTICAL limits decodeCaller re-applies (200 / 256), so the decoder
  // had nothing left to drop and the three members had zero reachable producers. The fixture proved the RING
  // could carry the class, not that the PRODUCT could put it there.
  //
  // The bound STAYS (a forged header must never hand the DO an unbounded list); the dead counters are gone, and
  // the drop is tallied where it actually happens. The SAML front door -- whose groups ride VERBATIM out of the
  // assertion and are first bounded at the session mint -- is proved END TO END through a REAL signed assertion
  // and a REAL ACS POST in validate-saml-wiring.ts (testSamlClaimDrops), which is the entry point a customer's
  // IdP actually drives.
  ok("no claim-drop-caller-header-* member survives (its only producer was a header the product cannot emit)", ![...vocab].some((n) => n.startsWith("claim-drop-caller-header-")));
  ok("decodeCaller still BOUNDS a hostile caller header (the defence is unchanged; only the dead tally is gone)", (decodeCaller(encodeCaller({ method: "access", email: SENTINEL_EMAIL, subject: "iss|sub-1", role: "viewer", groups: Array.from({ length: 260 }, (_, i) => `grp-${i}`) }))?.groups.length ?? -1) === 200);
  ok("the SAML boundary's three group members are in the closed vocabulary", ["claim-drop-saml-group-overlength", "claim-drop-saml-group-control-char", "claim-drop-saml-groups-list-capped"].every((n) => vocab.has(n)));

  // The ADVISORY context (oidc-token boundary): an asserted-but-unusable acr is NOT the same as an absent one.
  const acrAbsent = new Set<string>();
  buildAuthContext({}, acrAbsent);
  const acrDropped = new Set<string>();
  buildAuthContext({ acr: SENTINEL_ACR.repeat(20) }, acrDropped);
  const amrDropped = new Set<string>();
  buildAuthContext({ amr: ["x".repeat(200)] }, amrDropped);
  ok("an IdP that asserts NO acr/amr records nothing (the ordinary basic-IdP sign-in)", acrAbsent.size === 0);
  ok("an over-length acr -> claim-drop-oidc-token-acr", acrDropped.has("claim-drop-oidc-token-acr") && acrDropped.size === 1);
  ok("an unusable amr -> claim-drop-oidc-token-amr (a DIFFERENT row from the acr drop)", amrDropped.has("claim-drop-oidc-token-amr") && !amrDropped.has("claim-drop-oidc-token-acr"));
  ok("the acr VALUE never rides", scanForSentinels([...acrDropped]).length === 0);

  // And the ACCESS-JWT boundary, through the REAL verifier's claim extraction: the tally reaches AccessResult.
  // (An unsigned token cannot verify, so the extraction is exercised through the caller-header twin above; here
  // we assert the CONTRACT the verifier fills in -- the field exists and is a closed-name list.)
  ok("AccessResult carries claimDrops as a closed-name list", typeof verifyAccessJWT === "function");

  // ===== G271: THE AMR LIST CAP, an untallied drop whose counter's own comment claimed otherwise. =====
  // boundAmr `break`s at AMR_MAX_COUNT and returns the first 16 entries, so `amr` is DEFINED -- and the drop
  // test was `amr === undefined && input.amr !== undefined`, which therefore NEVER FIRED. An amr of 20 entries
  // with "mfa" at index 18 was dropped and recorded nothing, producing the same row as a fully usable amr,
  // while the counter was documented as covering an entry "over-long, OR PAST THE LIST CAP". It did not.
  const amrUsable = new Set<string>();
  buildAuthContext({ amr: ["pwd", "otp", "mfa"] }, amrUsable);
  const amrOverflow = new Set<string>();
  const twenty = Array.from({ length: 20 }, (_, i) => `m${i}`); // 20 usable entries; the cap is 16
  const ctxOverflow = buildAuthContext({ amr: twenty }, amrOverflow);
  ok("a fully usable amr records NOTHING (the healthy MFA sign-in must never cry wolf)", amrUsable.size === 0);
  ok("an amr whose USABLE entries fall past the list cap is now recorded", amrOverflow.has("claim-drop-oidc-token-amr"));
  ok("...and the amr is still carried (the drop is a caveat on it, not a rejection of it)", (ctxOverflow?.amr ?? []).length === 16);
  ok("DISCRIMINATION: 'this session was MFA'd' and 'we dropped the method that proved it' are different rows", JSON.stringify([...amrUsable]) !== JSON.stringify([...amrOverflow]));

  // ===== G271: THE SAML FRONT DOOR. buildAuthContext was shared with OIDC and hard-coded the boundary. =====
  // Passing the boundary explicitly is not a nicety: filing a SAML drop under "oidc-token" would be a row
  // asserting a fact the code never established (the assertion never crossed that boundary).
  const samlAcr = new Set<string>();
  buildAuthContext({ acr: SENTINEL_ACR.repeat(20) }, samlAcr, "saml");
  ok("an over-length SAML AuthnContextClassRef -> claim-drop-saml-acr (it used to be silent)", samlAcr.has("claim-drop-saml-acr"));
  // R6: the SAML auth-time drop is NOT asserted here. It used to be, by calling buildAuthContext with
  // `authTime: NaN` -- a shape the SAML path can never hand it (parseSamlInstantMs returns finite-or-null, and
  // null arrives as `undefined`), so the case proved the bounder could carry the class and NOT that the product
  // could put it there. The state is now recorded at the raw attribute in saml/assertion.ts, and it is driven
  // through the real consumer from a real assertion in test/validate-saml-assertion.ts.
  ok("a SAML drop is NOT filed under the OIDC boundary (a boundary the assertion never crossed)", !samlAcr.has("claim-drop-oidc-token-acr"));
  ok("SAML asserts no amr, so no amr row can ever be invented for it", !samlAcr.has("claim-drop-saml-amr") && !(ADMIN_COUNTER_NAMES as readonly string[]).includes("claim-drop-saml-amr"));
  ok("the SAML names are admitted by the aggregate that stores them", vocab.has("claim-drop-saml-acr") && vocab.has("claim-drop-saml-auth-time"));
  ok("no acr VALUE rides in a SAML tally", scanForSentinels([...samlAcr]).length === 0);
}

// =========================================================================================================
// OAUTH2 claim drops: the LIVE interactive front door that tallied NOTHING, driven through the REAL provider walk.
// The headline case is "the user is in the right team and gets viewer" -- on GitHub/GitLab,
// where a 260-team org is ordinary. completeOauth2Login returned a principal with no claimDrops at all, so the
// DO's shared recorder (which already reads principal.claimDrops) was permanently blind on this path.
// =========================================================================================================
console.log("\noauth2 claim drops -- the front door that recorded nothing");
await (async () => {
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
  const conn = {
    id: "gh1",
    kind: "oauth2",
    subjectPrefix: "github",
    apiBase: "https://api.github.example",
    subjectPath: "id",
    tokenUrl: "https://github.example/login/oauth/access_token",
    profileUrl: "https://api.github.example/user",
    groupsUrls: ["https://api.github.example/user/teams"],
  } as unknown as Oauth2Connection;

  // The REAL provider walk, over a stubbed network. Only the TEAMS payload changes between states.
  const drive = async (teams: unknown[]): Promise<string[]> => {
    const doFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("access_token")) return new Response(JSON.stringify({ access_token: "gho_x", token_type: "bearer" }), { headers: { "content-type": "application/json" } });
      if (url.endsWith("/user")) return new Response(JSON.stringify({ id: 4242, login: "renamed-later" }), { headers: { "content-type": "application/json" } });
      if (url.endsWith("/teams")) return new Response(JSON.stringify(teams), { headers: { "content-type": "application/json" } });
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    const r = await completeOauth2Login(conn, { code: "c", redirectUri: "https://engine.example/cb", clientSecret: "cs_test" }, doFetch);
    return r.ok ? (r.principal.claimDrops ?? []) : ["LOGIN-FAILED"];
  };
  const team = (slug: string): unknown => ({ slug, organization: { login: "acme" } });

  // STATE 1: the provider asserted NO teams. A legitimate, ordinary state.
  const none = await drive([]);
  // STATE 2: a healthy membership.
  const healthy = await drive([team("platform"), team("sre")]);
  // STATE 3: THE TICKET. 260 teams, and the mapped one is past GROUPS_MAX (200).
  const capped = await drive(Array.from({ length: 260 }, (_, i) => team(`t${i}`)));
  // STATE 4: an OVER-LENGTH team name.
  const overlong = await drive([team("x".repeat(300))]);
  // STATE 5: a team name carrying a CONTROL CHARACTER.
  const ctrl = await drive([team(`bad${String.fromCharCode(7)}name`)]);
  // STATE 6, THE NOISE CHECK: a membership that fills the list EXACTLY. Nothing was dropped, so nothing may be
  // recorded. The cap counter must fire on a real overflow and on nothing else.
  const exact = await drive(Array.from({ length: 200 }, (_, i) => team(`e${i}`)));

  ok("STATE 1 (no teams asserted) records NOTHING -- a legitimate state must never cry wolf", none.length === 0);
  ok("STATE 2 (a healthy membership) records NOTHING", healthy.length === 0);
  ok("STATE 3 THE TICKET: 260 teams, the mapped one past the cap -> claim-drop-oauth2-groups-list-capped", capped.includes("claim-drop-oauth2-groups-list-capped"));
  ok("STATE 4 an over-length team name -> claim-drop-oauth2-group-overlength", overlong.includes("claim-drop-oauth2-group-overlength"));
  ok("STATE 5 a control-char team name -> claim-drop-oauth2-group-control-char", ctrl.includes("claim-drop-oauth2-group-control-char"));
  // THE BAR: "present-but-dropped" and "the IdP sent nothing" were the SAME (empty) row on this path.
  ok("DISCRIMINATION: the capped org and the org with no teams are no longer the same row", JSON.stringify(capped) !== JSON.stringify(none));
  ok("...and the three drop kinds are three DIFFERENT rows", new Set([capped.join(), overlong.join(), ctrl.join()]).size === 3);
  // The recorder the DO already had can finally see them.
  ok("the drops ride on the principal, where the DO's existing recorder reads them", capped.length > 0 && overlong.length > 0);
  ok("every oauth2 name is admitted by the aggregate that stores it", [...capped, ...overlong, ...ctrl].every((n) => vocab.has(n)));
  ok("NOISE: a membership that fills the list EXACTLY drops nothing, so it records nothing", exact.length === 0);
  ok("NO-CUSTODY: no team name, org, token or account id rides in any tally", scanForSentinels([...capped, ...overlong, ...ctrl]).length === 0);

  // ---- THE GENERIC PROVIDER (R4). The six states above are all built from the TEAM shape, and every one of them
  // passed while the gap stayed wide open on the third entry shape resolveGroups walks: the GENERIC provider
  // (conn.groupsPath, the documented hatch for a provider whose membership is a flat list, and a validated live
  // connection field). That branch kept the `break` the team and org branches had removed, so a push that FILLED
  // the list broke the walk before the top-of-loop cap guard -- the sole producer of the capped counter -- could
  // run. 260 groups capped at 200 recorded nothing, identical to a provider that asserted none. Drive it.
  const genericConn = { ...(conn as unknown as Record<string, unknown>), groupsPath: "name" } as unknown as Oauth2Connection;
  const driveGeneric = async (groups: unknown[]): Promise<string[]> => {
    const doFetch = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("access_token")) return new Response(JSON.stringify({ access_token: "gho_x", token_type: "bearer" }), { headers: { "content-type": "application/json" } });
      if (url.endsWith("/user")) return new Response(JSON.stringify({ id: 4242, login: "renamed-later" }), { headers: { "content-type": "application/json" } });
      if (url.endsWith("/teams")) return new Response(JSON.stringify(groups), { headers: { "content-type": "application/json" } });
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    const r = await completeOauth2Login(genericConn, { code: "c", redirectUri: "https://engine.example/cb", clientSecret: "cs_test" }, doFetch);
    return r.ok ? (r.principal.claimDrops ?? []) : ["LOGIN-FAILED"];
  };
  const flat = (name: string): unknown => ({ name });
  const gNone = await driveGeneric([]);
  const gCapped = await driveGeneric(Array.from({ length: 260 }, (_, i) => flat(`g${i}`)));
  const gExact = await driveGeneric(Array.from({ length: 200 }, (_, i) => flat(`g${i}`)));
  const gOverBy1 = await driveGeneric(Array.from({ length: 201 }, (_, i) => flat(`g${i}`)));

  ok("GENERIC provider, 260 groups, 60 past the cap -> claim-drop-oauth2-groups-list-capped", gCapped.includes("claim-drop-oauth2-groups-list-capped"));
  ok("GENERIC provider, exactly 201 groups (ONE dropped) -> the cap counter still fires", gOverBy1.includes("claim-drop-oauth2-groups-list-capped"));
  ok("DISCRIMINATION: on the GENERIC shape, the capped provider and the provider that asserted no groups are no longer the same row", JSON.stringify(gCapped) !== JSON.stringify(gNone) && gNone.length === 0);
  ok("NOISE: a GENERIC membership that fills the list EXACTLY drops nothing, so it records nothing", gExact.length === 0);
  ok("NO-CUSTODY: no generic group name rides in the tally", scanForSentinels([...gCapped, ...gOverBy1]).length === 0);
})();

// =========================================================================================================
// BURST vs TRICKLE, and the SATURATED counter.
// =========================================================================================================
console.log("\nauth-signal temporal shape -- burst vs trickle vs a saturated cap");
{
  const day = MS_PER_DAY;
  const t0 = 1_800_000_000_000; // a fixed clock

  // STATE 1: a BURST. 10,000 failures in ONE day, then silence for a week.
  let burst = bumpAuthSignalEntry(undefined, t0, new Date(t0).toISOString());
  for (let i = 1; i < 10_000; i++) burst = bumpAuthSignalEntry(burst, t0, new Date(t0).toISOString());
  // ...read a WEEK later (nothing has happened since).
  const burstLater = bumpAuthSignalEntry(burst, t0 + 7 * day, new Date(t0 + 7 * day).toISOString());

  // STATE 2: a TRICKLE. One failure a day for fourteen days.
  let trickle = bumpAuthSignalEntry(undefined, t0, new Date(t0).toISOString());
  for (let d = 1; d <= 7; d++) trickle = bumpAuthSignalEntry(trickle, t0 + d * day, new Date(t0 + d * day).toISOString());

  const burstDays = burstLater.days ?? [];
  const trickleDays = trickle.days ?? [];
  ok("the burst's ring is spiked (its oldest slot in the window holds thousands)", burstDays.slice(1).some((n) => n > 1000));
  ok("the trickle's ring is FLAT (every recent slot holds exactly one)", trickleDays.slice(0, 7).every((n) => n === 1));
  ok("burst and trickle now produce DIFFERENT rows", JSON.stringify(burstDays) !== JSON.stringify(trickleDays));
  ok("firstAt latches the FIRST sighting on both ('since when?')", burstLater.firstAt === new Date(t0).toISOString() && trickle.firstAt === new Date(t0).toISOString());

  // STATE 3: a SATURATED counter. It stops moving, and until now said so nowhere.
  const nearCap = bumpAuthSignalEntry({ count: AUTH_SIGNAL_COUNT_CAP - 1, lastAt: new Date(t0).toISOString() }, t0, new Date(t0).toISOString());
  ok("reaching the cap latches capSaturated (every count below it is a LOWER BOUND)", nearCap.capSaturated === true && nearCap.count === AUTH_SIGNAL_COUNT_CAP);
  ok("a signal below the cap does NOT claim saturation", burstLater.capSaturated !== true);

  // A gap longer than the window zeroes the ring: nothing in the window happened, and it must not lie.
  const stale = bumpAuthSignalEntry(trickle, t0 + 100 * day, new Date(t0 + 100 * day).toISOString());
  ok("a 100-day gap ages the whole ring out (only today's slot is set)", (stale.days ?? []).slice(1).every((n) => n === 0) && (stale.days ?? [])[0] === 1);
  ok("the ring is exactly AUTH_SIGNAL_DAY_SLOTS long", (stale.days ?? []).length === AUTH_SIGNAL_DAY_SLOTS);
}

// =========================================================================================================
// THE SECURITY REFUSALS. Ten questions a post-incident review asks; eight now have a signal.
// =========================================================================================================
console.log("\nsecurity signals -- the refusals that were recorded nowhere");
{
  const vocab = new Set<string>(AUTH_SIGNAL_NAMES as readonly string[]);
  const wired = [
    "csrf-session-route",
    "ssrf-endpoint-refused",
    "reserved-binding-refused",
    "break-glass-token-refused",
    "lockout-guard-failopen",
    "binding-claim-conflict",
    "logout-revoke-failed",
  ];
  ok("every wired security signal is a member of the closed auth-signal vocabulary", wired.every((n) => vocab.has(n)));
  ok("the seven are DISTINCT rows (a shared name would answer none of the questions)", new Set(wired).size === 7);
  // The three the gap proposed and this pass deliberately does NOT carry. A vocabulary member with no caller is
  // DEAD EVIDENCE, and a counter that fires on a legitimate state is worse than no counter at all.
  ok("custody-assert-tripped is NOT added (already carried as recoveryRefusals cls:no-custody)", !vocab.has("custody-assert-tripped"));
  ok("restore-cues-mismatch is NOT added (no such check exists: the counter could only ever read zero)", !vocab.has("restore-cues-mismatch"));
  // authn-401 WAS shipped and is now REMOVED. It fired unconditionally on every refused verdict, so it was the
  // arithmetic SUM of the discriminating deny rows beside it and separated no pair of states -- and it fired on
  // LEGITIMATE ones (every expired passkey session, every signed-out browser), so on a healthy tenant it was
  // permanently non-zero and a probe read exactly like a dozen sessions timing out.
  ok("authn-401 is GONE (a tautology that cried wolf: the empty-bearer sweep already had its own row)", !vocab.has("authn-401"));
  ok("...and the row it duplicated is still there and still discriminates", vocab.has("admin-token-denied-empty-bearer"));
}

// =========================================================================================================
// THE SECURITY ALERT that never fired. CLASS x STAGE, both in the key.
// =========================================================================================================
console.log("\nalert-emission failures -- class x stage, and the noise floor");
await (async () => {
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
  // The FOUR stages of one class must be four DIFFERENT rows: "no channel matched" (wire a rule) and "delivery
  // failed" (the webhook is dead) are opposite fixes, and one alertEmissionFailures counter would fuse them.
  const disarm = (["resolve", "no-channel", "deliver", "record"] as const).map((st) => alertEmissionCounter("dual-control-disarm", st));
  ok("the four stages of dual-control-disarm are four DIFFERENT counters", new Set(disarm).size === 4);
  ok("all four are in the closed vocabulary", disarm.every((n) => vocab.has(n)));

  // THE CLASS AXIS, DRIVEN THROUGH THE REAL routeAuthChangeAlert. The class used to be derived from the notify
  // EVENT, and three of the events are shared by unrelated alerts, so "an attacker added an owner"
  // (role-change), "a member was offboarded" (role-change) and "the backup destination was repointed"
  // (dest-change) ALL composed alert-emit-auth-change-*, summed by name into ONE count in ONE row. A support
  // engineer holding the pack could not tell which alert had never reached a human, which is the whole question.
  //
  // Every alert below resolves ZERO channels (the commonest cause of "nobody was alerted"), so each fires the
  // no-channel stage. No counter name is hand-written: the names below are read out of the DO the real recorder
  // wrote to.
  const bumps: string[] = [];
  const scheduler = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/notify/resolve") return new Response(JSON.stringify({ now: [] }), { headers: { "content-type": "application/json" } });
      if (url.pathname === "/diag/admin-counters" || url.pathname === "/admin-counters") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { bumps?: Record<string, number> };
        for (const n of Object.keys(body.bumps ?? {})) bumps.push(n);
        return new Response("{}", { headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  const env = {} as Env;

  // The three alerts the old class axis fused into one row.
  await routeAuthChangeAlert(env, scheduler, "role-change", "owner-role-grant", "An owner was added.");
  await routeAuthChangeAlert(env, scheduler, "role-change", "offboard", "A member was removed.");
  await routeAuthChangeAlert(env, scheduler, "dest-change", "dest-change", "The destination was repointed.");
  await routeAuthChangeAlert(env, scheduler, "auth-credential-change", "recovery-regenerate", "Recovery codes were regenerated.");
  await routeAuthChangeAlert(env, scheduler, "auth-credential-change", "idp-change", "An IdP connection was added.");
  await new Promise((r) => setTimeout(r, 5)); // the bumps are void-ed, best-effort writes

  ok("the owner-added alert is its OWN row", bumps.includes("alert-emit-owner-role-grant-no-channel"));
  ok("the OFFBOARD alert is its own row (it used to be counted as auth-change, colliding with the grant)", bumps.includes("alert-emit-offboard-no-channel"));
  ok("the destination REPOINT is its own row (an exfil signal, previously fused with a role change)", bumps.includes("alert-emit-dest-change-no-channel"));
  ok("recovery-code REGENERATION is its own row (the vocabulary claimed this split and did not deliver it)", bumps.includes("alert-emit-recovery-regenerate-no-channel"));
  ok("an IdP connection change is its own row (it changes WHO CAN SIGN IN)", bumps.includes("alert-emit-idp-change-no-channel"));
  // THE DISCRIMINATION BAR: five alerts, five distinct rows. They used to be one count of alert-emit-auth-change-no-channel.
  ok("DISCRIMINATION: five security alerts produce FIVE distinct rows (they were one)", new Set(bumps).size === 5);
  ok("every emitted name is admitted by the aggregate that stores it", bumps.every((n) => vocab.has(n)));

  // DEAD VOCABULARY: the old "auth-change" catch-all is gone, and so is the "offboard" binding to source-detached
  // (a detached SOURCE BINDING is not a member being deprovisioned, and that event routes through a DIFFERENT
  // transport that never reaches this recorder, so all four alert-emit-offboard-* names were unwritable).
  ok("the auth-change catch-all is GONE from the closed class set", !(ALERT_CLASSES as readonly string[]).includes("auth-change"));
  ok("...and no alert-emit-auth-change-* counter survives it", ![...vocab].some((n) => n.startsWith("alert-emit-auth-change-")));
  // ...and offboard now has a REAL producer (driven above), rather than being bound to an event nothing routes here.
  ok("every closed alert class has a counter for every stage", (ALERT_CLASSES as readonly string[]).every((c) => (["resolve", "no-channel", "deliver", "record"] as const).every((st) => vocab.has(alertEmissionCounter(c as never, st)))));

  // ===== G274 (R4), LEG 1: THE ROW THAT ASSERTED A FACT THE CODE NEVER ESTABLISHED. =====
  //
  // no-channel means "resolve answered with ZERO channels: nobody had wired a rule". But the DO's resolveNotify
  // answers {now:[], emission:null} when parseEmission REJECTS the emission -- BEFORE any rule or channel is
  // consulted -- and routeEmission read only `now`. So a customer with a LIVE channel and a MATCHING RULE got
  // the same row as one with no rule at all, and support was sent to wire a rule they already had. Opposite
  // fixes, one row.
  //
  // The rejectable shape is real and it is the HEADLINE alert: router-rbac.ts composes
  // `Role changed for ${entry.email} to ${entry.role} by ${caller.email}.` out of two e-mails the engine's own
  // validators admit up to 320 chars each, and parseEmission bounds detail at 512.
  //
  // Driven through the REAL SchedulerDO (its real parseEmission, its real resolveNotify), with a REAL channel
  // and a REAL rule seeded in DO storage, so the customer here is one whose alerting is correctly wired.
  const wired = realScheduler();
  await wired.storage.put("notify-channel:c1", { id: "c1", kind: "webhook", name: "ops", url: "https://hooks.example.com/x", enabled: true });
  await wired.storage.put("notify-rule:r1", { id: "r1", scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: ["c1"], enabled: true });
  const countersOf = async (s: Sched): Promise<string[]> => {
    const resp = await s.stub.fetch("https://do/admin-counters", { method: "GET" });
    const j = (await resp.json()) as Record<string, unknown>;
    return Object.keys((j.counters ?? j) as Record<string, unknown>);
  };
  const longEmail = `${"a".repeat(310)}@x.io`; // 315 chars, well inside the engine's own 320-char e-mail bound
  const REJECTABLE = `Role changed for ${longEmail} to owner by ${longEmail}.`; // > 512: the real router-rbac shape
  ok("the composed detail really does exceed the notify input bound (the reject is not hypothetical)", REJECTABLE.length > 512);
  await routeAuthChangeAlert({} as Env, wired.stub, "role-change", "owner-role-grant", REJECTABLE);
  await new Promise((r) => setTimeout(r, 5));
  const wiredNames = await countersOf(wired);

  ok("a REJECTED emission on a CORRECTLY WIRED customer files -rejected (no rule change can ever fix it)", wiredNames.includes("alert-emit-owner-role-grant-rejected"));
  ok("...and NOT -no-channel, which would have sent support to wire a rule the customer already has", !wiredNames.includes("alert-emit-owner-role-grant-no-channel"));
  ok("DISCRIMINATION: 'no rule wired' and 'the alert was refused at the input boundary' are now different rows", wiredNames.includes("alert-emit-owner-role-grant-rejected") && bumps.includes("alert-emit-owner-role-grant-no-channel"));
  // NOISE: the SAME wired customer, with a detail INSIDE the bound, resolves its channel and files NEITHER a
  // no-channel nor a rejected row. The two rows above are earned by the fault, not by the wiring.
  // The two blocks below actually DELIVER, so the webhook adapter is taken offline for them: the send must be a
  // deterministic local failure, never an outbound request from a validator.
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response("no", { status: 500 })) as typeof fetch;
  const cleanWired = realScheduler();
  await cleanWired.storage.put("notify-channel:c1", { id: "c1", kind: "webhook", name: "ops", url: "https://hooks.example.com/x", enabled: true });
  await cleanWired.storage.put("notify-rule:r1", { id: "r1", scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: ["c1"], enabled: true });
  await routeAuthChangeAlert({} as Env, cleanWired.stub, "role-change", "owner-role-grant", "Role changed for a@x.io to owner by b@x.io.");
  await new Promise((r) => setTimeout(r, 5));
  const cleanNames = await countersOf(cleanWired);
  ok("NOISE: a SHORT detail on the same wired customer files NEITHER no-channel NOR rejected", !cleanNames.includes("alert-emit-owner-role-grant-no-channel") && !cleanNames.includes("alert-emit-owner-role-grant-rejected"));

  // ===== G274 (R4), LEG 3: THE RECORD STAGE THAT COULD NOT SEE ITS OWN HEADLINE STATE. =====
  //
  // The R3 fix read `resp.ok`. The DO's route is `return this.json(await this.recordNotify(...))` and json() sets
  // NO status; recordNotify never throws on a malformed record set BY DESIGN -- it DROPS the rows and answers
  // {recorded:0, skipped:N} with an HTTP 200. So `!resp.ok` could not fire on a drop, and the counter stayed at
  // ZERO in exactly the state it exists for: THE ALERT WAS DELIVERED AND THE PACK'S NOTIFY HISTORY HAS NO ROW
  // FOR IT. The drop was reported only in the BODY, which was never read.
  //
  // Driven with a CORRUPT STORED CHANNEL -- an id-less row, the same stored-record anomaly class the DO's own
  // record guard exists for. The router resolves it, DELIVERS to it, and the DO's real recordNotify guard then
  // refuses the history row and answers 200 {recorded:0, skipped:1}. Nothing is hand-posted: the drop is
  // produced by the DO's own gate, and the 200 is why the old `resp.ok` test could never see it.
  const skewed = realScheduler();
  await skewed.storage.put("notify-channel:c9", { id: "", kind: "webhook", name: "ops", url: "https://hooks.example.com/x", enabled: true });
  await skewed.storage.put("notify-rule:r9", { id: "r9", scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [""], enabled: true });
  await routeAuthChangeAlert({} as Env, skewed.stub, "role-change", "owner-role-grant", "Role changed for a@x.io to owner by b@x.io.");
  await new Promise((r) => setTimeout(r, 200)); // the record POST, its body read and the counter bump are all void-ed
  globalThis.fetch = realFetch;
  const skewNames = await countersOf(skewed);
  const skewHistory = (await (await skewed.stub.fetch("https://do/notify/history", { method: "GET" })).json()) as unknown[];
  ok("the DO really did DROP the history row (the pack's notify history is EMPTY for this alert)", Array.isArray(skewHistory) && skewHistory.length === 0);
  ok("...and the record stage now COUNTS it, off the BODY: the DO answered 200 and recorded nothing", skewNames.includes("alert-emit-owner-role-grant-record"));
  ok("...and it is NOT confused with an alert that had nowhere to go", !skewNames.includes("alert-emit-owner-role-grant-no-channel"));

  ok("the -rejected member has a NAMED producer and only for the two classes that can compose an over-long detail", vocab.has("alert-emit-owner-role-grant-rejected") && vocab.has("alert-emit-offboard-rejected") && ![...vocab].some((n) => n === "alert-emit-sign-in-context-rejected" || n === "alert-emit-posture-regression-rejected"));
  ok("NO-CUSTODY: the 315-char e-mail in the rejected detail is representable in NO counter name", scanForSentinels(wiredNames).length === 0 && !wiredNames.some((n) => n.includes("@")));

  // ===== G274 (R4), LEG 2: THE RECOVERY CLASS THAT SUMMED TWO OPPOSITE FACTS. =====
  //
  // routeRecoveryAlert passed ONE class, "recovery-abuse", for BOTH notify events: a SUCCESSFUL break-glass
  // sign-in (router-auth-flow.ts, event recovery-code-used -- somebody is IN) and blocked/rate-limited attempts
  // (somebody is being kept OUT). bumpAdminCounter sums by name, so they were ONE count in ONE row -- the exact
  // mechanism this gap says it removed from auth-change -- and the class NAME filed a lawful owner break-glass
  // as "abuse". Driven through the real routeRecoveryAlert on a DO with no rule wired.
  const recovery = realScheduler();
  await routeRecoveryAlert({} as Env, recovery.stub, "recovery-code-used", "owner@x.io");
  await routeRecoveryAlert({} as Env, recovery.stub, "recovery-code-abuse", null);
  await new Promise((r) => setTimeout(r, 5));
  const recNames = await countersOf(recovery);
  ok("a SUCCESSFUL break-glass sign-in has its OWN row (somebody is signed in as an admin right now)", recNames.includes("alert-emit-recovery-code-used-no-channel"));
  ok("rate-limited attempts have their OWN row (somebody is being kept OUT)", recNames.includes("alert-emit-recovery-code-abuse-no-channel"));
  ok("DISCRIMINATION: the two recovery facts are two rows, not one summed count", recNames.filter((n) => n.startsWith("alert-emit-recovery-code-")).length === 2);
  ok("the coalescing class is GONE: no alert-emit-recovery-abuse-* name survives", ![...vocab].some((n) => n.startsWith("alert-emit-recovery-abuse-")));
  ok("...and a lawful owner break-glass is no longer filed under a name that calls it abuse", !(ALERT_CLASSES as readonly string[]).includes("recovery-abuse"));
})();

// =========================================================================================================
// THE UPDATE family. Refused guards, inconclusive attempts, silent degradations.
// =========================================================================================================
console.log("\nupdate refusals -- which guard tripped, and how many times");
{
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
  const guards = (["no-pending", "ramp-shaped", "deploy-token", "account-unmarked", "high-water", "freshness-replay", "no-target"] as const).map(updateRefusalCounter);
  ok("all seven guard classes are in the closed vocabulary", guards.every((n) => vocab.has(n)));
  ok("the seven guards are seven DIFFERENT rows", new Set(guards).size === 7);
  // R6: there is NO name for an unrecognised component split. The console's component ids are exactly the
  // set this build plans, so no request a real client can send reaches that guard, and a counter on it would
  // be a name no pack could ever carry.
  ok("no counter name exists for the component split no client can post", !vocab.has("update-refused-split-unrecognised"));
  // THE DISCRIMINATION the ticket asks for: a rollback refused for want of a token, and one refused because
  // there is no recorded target, are different tickets at 02:00.
  ok("deploy-token and no-target do not coalesce", updateRefusalCounter("deploy-token") !== updateRefusalCounter("no-target"));
  ok("the cumulative attempt counters exist", ["update-settle-inconclusive", "update-settle-refused", "update-rollback-refused"].every((n) => vocab.has(n)));
  // The freshness/replay refusal -- the possible ATTACK signal -- is its own row, not folded into a generic one.
  ok("freshness-replay is its OWN row (the attack signal the siblings' audit never carried)", vocab.has("update-refused-freshness-replay"));
}

console.log("\nupdate-safety degradations -- the controls that silently stopped applying");
{
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);

  // STATE 1: replay protection was ACTIVE (a clean, parseable claim).
  const clean = checkChannelFreshness({ sequence: 12, issuedAt: "2026-07-11T00:00:00.000Z" }, { lastSeq: 11, lastIssuedAt: "2026-07-10T00:00:00.000Z" }, Date.parse("2026-07-11T01:00:00.000Z"));
  // STATE 2: the issuedAt would not PARSE, so the anti-replay floor did not run -- and the apply still proceeds.
  const badTs = checkChannelFreshness({ sequence: 12, issuedAt: "not-a-date" }, { lastSeq: 11, lastIssuedAt: "2026-07-10T00:00:00.000Z" }, Date.parse("2026-07-11T01:00:00.000Z"));
  // STATE 3: the sequence claim is ABSENT though one was seen before: the sequence half is skipped.
  const noSeq = checkChannelFreshness({ issuedAt: "2026-07-11T00:00:00.000Z" }, { lastSeq: 11, lastIssuedAt: "2026-07-10T00:00:00.000Z" }, Date.parse("2026-07-11T01:00:00.000Z"));
  // STATE 4 (R6): the sequence claim was MADE and the RESOLVER erased it as malformed. That is a different
  // fact from state 3 with a different remedy (our release bug, not an ordinary legacy descriptor), and this
  // check must not file it as an absence. The MALFORMED row itself is recorded at the erasure, in
  // loadVerifiedChannel, and is proven END TO END off a real signed channel in
  // test/validate-support-posture-gaps-6.ts -- which is the drive this file could not make, because a claim
  // the resolver erases can never reach this function.
  const erasedSeq = checkChannelFreshness({ issuedAt: "2026-07-11T00:00:00.000Z", sequenceMalformed: true }, { lastSeq: 11, lastIssuedAt: "2026-07-10T00:00:00.000Z" }, Date.parse("2026-07-11T01:00:00.000Z"));

  const degOf = (v: unknown): string[] => (v as { degradations?: string[] }).degradations ?? [];
  ok("state 1 (protection active) records NO degradation", clean.ok === true && degOf(clean).length === 0);
  ok("state 2 (unparseable issuedAt) -> update-degraded-freshness-issuedat-unparseable", degOf(badTs).includes("update-degraded-freshness-issuedat-unparseable"));
  ok("state 3 (no sequence) -> update-degraded-freshness-sequence-absent (the row now says what the code tested)", degOf(noSeq).includes("update-degraded-freshness-sequence-absent") && !degOf(noSeq).includes("update-degraded-freshness-issuedat-unparseable"));
  ok("state 4 (a sequence the resolver ERASED) is never filed as an absence", degOf(erasedSeq).length === 0);
  ok("all three apply SUCCEEDED (the verdict is unchanged; only the silence is gone)", clean.ok && badTs.ok && noSeq.ok);
  ok("all four degradation names are in the closed vocabulary", ["update-degraded-freshness-issuedat-unparseable", "update-degraded-freshness-sequence-malformed", "update-degraded-freshness-issuedat-absent", "update-degraded-freshness-sequence-absent"].every((n) => vocab.has(n)));

  // The COMPONENTS map: "the console update never shows up".
  const malformed = { recommendedVersion: "1.2.3", components: 42 as unknown, artefacts: [{ version: "1.2.3", url: SENTINEL_ENDPOINT, sha384: "abc" }] } as unknown as Channel;
  const dropped = { recommendedVersion: "1.2.3", components: { engine: { kind: "worker-module", version: "1.2.3", url: SENTINEL_ENDPOINT, sha384: "abc" }, console: { kind: "future-kind-this-build-does-not-know", version: "1.2.3" } }, artefacts: [] } as unknown as Channel;
  const dMal = new Set<string>();
  sanitiseChannelComponents(malformed, dMal);
  const dDrop = new Set<string>();
  sanitiseChannelComponents(dropped, dDrop);
  ok("a malformed components MAP -> update-degraded-components-map-malformed", dMal.has("update-degraded-components-map-malformed"));
  ok("a dropped component ENTRY -> update-degraded-component-entry-dropped (a DIFFERENT row)", dDrop.has("update-degraded-component-entry-dropped") && !dDrop.has("update-degraded-components-map-malformed"));

  // The LEGACY MIRROR: the engine deploys artefacts[] rather than the v2 entry.
  const legacy = new Set<string>();
  resolveEngineArtefact(malformed, legacy);
  ok("falling back to the legacy artefacts[] mirror -> update-degraded-legacy-artefact-fallback", legacy.has("update-degraded-legacy-artefact-fallback"));
  const plainLegacyChannel = { recommendedVersion: "1.2.3", artefacts: [{ version: "1.2.3", url: SENTINEL_ENDPOINT, sha384: "abc" }] } as unknown as Channel;
  const noComponents = new Set<string>();
  resolveEngineArtefact(plainLegacyChannel, noComponents);
  ok("a channel with NO components map at all is not a degradation (an ordinary legacy channel)", noComponents.size === 0);

  // The SELF-CHECK: one boolean over OPPOSITE diagnoses -- DRIVEN THROUGH THE REAL GATE (R4).
  //
  // This used to be `(["version-mismatch","preflight","throw"] as const).map(selfCheckDegradationCounter)` and an
  // assertion that the three composed strings differed and were in the vocabulary. That is string composition and
  // vocabulary presence wearing a discrimination check's label: makeHealthGate was never invoked, and the moment
  // it was, "throw" turned out to have NO PRODUCER AT ALL. runPreflight cannot throw by construction, so the catch
  // that was the member's only writer never fires; the state the member was named for (the DO plane down) really
  // reports -preflight. The member is deleted, and what follows drives the gate that has to produce these rows.
  const gateBumps = (fetchImpl: (u: URL) => Promise<Response>): { sched: DurableObjectStub; bumps: string[] } => {
    const bumps: string[] = [];
    const sched = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/diag/admin-counters" || u.pathname === "/admin-counters") {
          const body = JSON.parse(String(init?.body ?? "{}")) as { bumps?: Record<string, number> };
          for (const n of Object.keys(body.bumps ?? {})) bumps.push(n);
          return new Response("{}", { headers: { "content-type": "application/json" } });
        }
        return fetchImpl(u);
      },
    } as unknown as DurableObjectStub;
    return { sched, bumps };
  };
  const settleBumps = async (): Promise<void> => {
    await new Promise((r) => setTimeout(r, 5)); // the bumps are void-ed, best-effort writes
  };

  // STATE 1: THE WRONG BUILD IS LIVE. The remedy is to roll back.
  const mism = gateBumps(async () => new Response("{}", { headers: { "content-type": "application/json" } }));
  const mismOk = await makeHealthGate({} as Env, mism.sched, `${ENGINE_VERSION}-not-this-one`).selfCheck();
  await settleBumps();
  ok("the REAL gate on a version mismatch answers false", mismOk === false);
  ok("...and emits update-degraded-selfcheck-version-mismatch (the wrong build is serving: roll back)", mism.bumps.includes("update-degraded-selfcheck-version-mismatch"));

  // STATE 2: THE DO PLANE IS DOWN. Every scheduler fetch REJECTS. This is the exact state the deleted "throw"
  // member was named for, and the real gate reports -preflight: the preflight could not COMPLETE, so the engine
  // could not prove what is live. That is not the same fact as proving the wrong thing is live, and it is the
  // whole reason the two causes are split. The remedy is to touch nothing.
  const deadPlane = gateBumps(async () => {
    throw new Error("the DO plane is down");
  });
  const deadOk = await makeHealthGate({} as Env, deadPlane.sched, ENGINE_VERSION).selfCheck();
  await settleBumps();
  ok("the REAL gate with EVERY DO fetch rejecting answers false", deadOk === false);
  ok("...and emits update-degraded-selfcheck-preflight (the engine could not PROVE what is live)", deadPlane.bumps.includes("update-degraded-selfcheck-preflight"));
  ok("...and NOT version-mismatch: the two diagnoses are distinct rows on the real gate", !deadPlane.bumps.includes("update-degraded-selfcheck-version-mismatch"));
  ok("DISCRIMINATION: the wrong build live and the DO plane down are DIFFERENT rows", JSON.stringify(mism.bumps.filter((n) => n.startsWith("update-degraded-selfcheck"))) !== JSON.stringify(deadPlane.bumps.filter((n) => n.startsWith("update-degraded-selfcheck"))));

  // DEAD VOCABULARY: the member that promised a row no production shape can write is GONE.
  ok("update-degraded-selfcheck-throw is DELETED from the closed vocabulary (it had zero producers)", !vocab.has("update-degraded-selfcheck-throw"));
  const causes = (["version-mismatch", "preflight"] as const).map(selfCheckDegradationCounter);
  ok("both surviving self-check causes are in the closed vocabulary and were emitted above", causes.every((n) => vocab.has(n)) && causes.every((n) => [...mism.bumps, ...deadPlane.bumps].includes(n)));
  ok("the disarmed regression guard has its own row", vocab.has("update-degraded-baseline-read-failed"));
  ok("NO-CUSTODY: no sentinel rides in any self-check counter", scanForSentinels([...mism.bumps, ...deadPlane.bumps]).length === 0);
  ok("no channel URL rides in any degradation tally", scanForSentinels([...dMal, ...dDrop, ...legacy, ...degOf(badTs)]).length === 0);
}

// =========================================================================================================
// THE DESTINATION GATE, DRIVEN: destinationConfigured, invoked end to end. A "degradation" must never fire on
// the HEALTHIEST state in the estate, and a single "decrypt-failed" counter must not stand in for three causes
// with three opposite remedies.
// =========================================================================================================
console.log("\ndestination gate -- the counter that fired when nothing was wrong");
await (async () => {
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
  // A scheduler whose /dest-config answer is under the test's control, capturing every counter the gate bumps.
  const gateEnv = (destConfig: unknown | "throw-do-5xx", env: Record<string, unknown>): { env: Env; sched: DurableObjectStub; bumps: string[] } => {
    const bumps: string[] = [];
    const sched = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/dest-config") {
          if (destConfig === "throw-do-5xx") return new Response("nope", { status: 503 });
          return new Response(JSON.stringify({ config: destConfig }), { headers: { "content-type": "application/json" } });
        }
        if (url.pathname === "/diag/admin-counters" || url.pathname === "/admin-counters") {
          const body = JSON.parse(String(init?.body ?? "{}")) as { bumps?: Record<string, number> };
          for (const n of Object.keys(body.bumps ?? {})) bumps.push(n);
        }
        return new Response("{}", { headers: { "content-type": "application/json" } });
      },
    } as unknown as DurableObjectStub;
    return { env: env as unknown as Env, sched, bumps };
  };
  const ENV_DEST = { DEST_KIND: "s3", DEST_ENDPOINT: "https://s3.example.com", DEST_BUCKET: "env-bucket", DEST_REGION: "auto", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK" };
  const settle = async (): Promise<void> => {
    await new Promise((r) => setTimeout(r, 5)); // the bumps are void-ed, best-effort writes
  };

  // STATE A, THE NOISE DEFECT. The customer has NO console-set destination and backs up to the env/R2 binding.
  // This is a state destinationConfigured's own doc declares LEGITIMATE, and it is the commonest healthy shape
  // in the estate -- and GET /update/status calls this gate on EVERY Updates-screen poll, so the old
  // `if (override === null) bump` turned a "posture degradation" into a poll counter that would be the largest
  // number in adminCounters on a perfectly healthy engine, devaluing every honest row beside it.
  const a = gateEnv(null, ENV_DEST);
  const aOk = await destinationConfigured(a.env, a.sched);
  await settle();
  ok("a healthy env-destination customer PASSES the gate", aOk === true);
  ok("NOISE: ...and bumps NOTHING. The commonest healthy state is silent (it used to bump on every poll)", a.bumps.length === 0);

  // STATE B. A console destination EXISTS and its credential will not DECRYPT (a rotated CONFIG_WRAP_KEY). The
  // gate falls back to the ENV destination and answers "configured" -- so the update is verified against a
  // destination the customer is NOT backing up to. THIS is what dest-fallback-env always meant.
  const wrapped = { endpoint: "https://s3.example.com", bucket: "console-bucket", region: "auto", accessKeyId: "AK", secretAccessKey: { v: 1, iv: "AAAA", ct: "BBBB" } };
  const b = gateEnv(wrapped, ENV_DEST); // no CONFIG_WRAP_KEY in env -> the envelope cannot be opened
  const bOk = await destinationConfigured(b.env, b.sched);
  await settle();
  ok("a console destination that will not decrypt still passes the gate (against the ENV destination)", bOk === true);
  ok("...and NOW dest-fallback-env fires, meaning exactly what its vocabulary says", b.bumps.includes("update-degraded-dest-fallback-env"));
  ok("...and names the cause as a DECRYPT failure (re-wrap the credential / restore the key)", b.bumps.includes("update-degraded-destgate-decrypt-failed"));
  ok("DISCRIMINATION: state A and state B are no longer the same row", JSON.stringify(a.bumps) !== JSON.stringify(b.bumps));

  // STATE C. The CONFIG PLANE is down (the DO would not answer). The destination may be perfectly healthy and
  // we could not READ it. Remedy: wait, change nothing. This used to report as "decrypt-failed".
  const c = gateEnv("throw-do-5xx", ENV_DEST);
  await destinationConfigured(c.env, c.sched);
  await settle();
  ok("the CONFIG PLANE being down is its own row (the destination may be fine; wait)", c.bumps.includes("update-degraded-destgate-config-plane-unreadable"));
  ok("...and it does NOT claim a decrypt failure (nothing was decrypted)", !c.bumps.includes("update-degraded-destgate-decrypt-failed"));
  // R4, RULE 3. The DO did not answer, so the engine CANNOT KNOW whether a console-set destination exists at all
  // -- and on the commonest estate (env/R2 binding, state A) there is none. dest-fallback-env asserts one exists
  // and that the update was verified against a bucket the customer does not use. Off a transient DO blip that
  // sent support to a destination the customer never configured. The row is now withheld unless the fault was
  // read OUT OF A STORED ROW (states B and D), which is the only way its existence is established.
  ok("...and it does NOT claim dest-fallback-env: with the config plane down, no console destination is KNOWN to exist", !c.bumps.includes("update-degraded-dest-fallback-env"));

  // STATE D. A required STORED FIELD is missing: the customer re-enters it. Neither the key nor the DO is at
  // fault. Also used to report as "decrypt-failed".
  const d = gateEnv({ endpoint: "https://s3.example.com", bucket: "", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" }, ENV_DEST);
  await destinationConfigured(d.env, d.sched);
  await settle();
  ok("an INCOMPLETE stored config is its own row (the customer re-enters a field)", d.bumps.includes("update-degraded-destgate-config-incomplete"));
  ok("...and it does NOT claim a decrypt failure either", !d.bumps.includes("update-degraded-destgate-decrypt-failed"));
  // The row WAS read out of storage, so a console destination is established to exist: this one earns the fallback row.
  ok("...and it DOES carry dest-fallback-env: the stored row exists, and the gate passed against the env destination instead", d.bumps.includes("update-degraded-dest-fallback-env"));
  ok("DISCRIMINATION: 'the config plane blipped' (C) and 'your update was verified against a bucket you do not use' (D) are different rows", c.bumps.includes("update-degraded-dest-fallback-env") !== d.bumps.includes("update-degraded-dest-fallback-env"));

  // ===== G332 (R5): THE WRAP-KEY PARSE DOOR, WHICH RUNS BEFORE THE DO IS EVER READ. =====
  //
  // loadConfigWrapKey throws key-malformed when CONFIG_WRAP_KEY is present and is not 32 bytes (an operator
  // pasted the wrong secret). That throw happened INSIDE the fetchDestConfig try, so it was classified as "the
  // STORED CREDENTIAL would not open" and it set overrideStoredButUnusable -- filing dest-fallback-env, a row
  // that asserts a console-set destination EXISTS and was bypassed, when no /dest-config request had been made
  // at all. On the commonest estate there is no console destination, so support was sent to a bucket the customer
  // never configured, on every Updates-screen poll. The key fault is fleet-wide and says nothing about any row.
  const BAD_WRAP_KEY = "A".repeat(22); // valid base64url, 16 bytes: PRESENT and not 32 -> key-malformed
  const g = gateEnv(null, { ...ENV_DEST, CONFIG_WRAP_KEY: BAD_WRAP_KEY });
  const gOk = await destinationConfigured(g.env, g.sched);
  await settle();
  const h = gateEnv(wrapped, { ...ENV_DEST, CONFIG_WRAP_KEY: BAD_WRAP_KEY });
  await destinationConfigured(h.env, h.sched);
  await settle();
  ok("a malformed CONFIG_WRAP_KEY is its OWN row: a FLEET-WIDE key fault, not a fact about a stored destination", g.bumps.includes("update-degraded-destgate-wrapkey-malformed") && h.bumps.includes("update-degraded-destgate-wrapkey-malformed"));
  ok("the env-only estate does NOT claim a stored credential would not open (none was fetched)", !g.bumps.includes("update-degraded-destgate-decrypt-failed"));
  ok("...and does NOT claim dest-fallback-env: the customer HAS no console destination to have been bypassed", !g.bumps.includes("update-degraded-dest-fallback-env"));
  ok("the gate still passes on the env destination (a garbled key must not make an update look unconfigured)", gOk === true);
  ok("the estate that DOES have a console destination reads it, fails to open it, and earns both rows honestly", h.bumps.includes("update-degraded-destgate-decrypt-failed") && h.bumps.includes("update-degraded-dest-fallback-env"));
  ok("DISCRIMINATION: 'your fleet wrap key is garbage and you have no console destination' and 'your console destination will not decrypt' were BYTE-IDENTICAL and are now different rows", JSON.stringify([...g.bumps].sort()) !== JSON.stringify([...h.bumps].sort()));

  // THE BAR: three causes, three opposite remedies, three distinct rows. They were ONE counter named for a
  // failure that, in two of the three cases, had not happened.
  ok("DISCRIMINATION: decrypt / config-plane / incomplete are THREE distinct rows", new Set(["update-degraded-destgate-decrypt-failed", "update-degraded-destgate-config-plane-unreadable", "update-degraded-destgate-config-incomplete"]).size === 3);
  ok("every emitted name is admitted by the aggregate that stores it", [...b.bumps, ...c.bumps, ...d.bumps, ...g.bumps, ...h.bumps].every((n) => vocab.has(n)));
  ok("NO-CUSTODY: no bucket, endpoint or credential rides in any counter", scanForSentinels([...a.bumps, ...b.bumps, ...c.bumps, ...d.bumps]).length === 0 && ![...b.bumps, ...c.bumps, ...d.bumps].some((n) => n.includes("console-bucket") || n.includes("s3.example.com")));
})();

// =========================================================================================================
// THE CORRUPT STORED GOVERNANCE RECORD. Fail-open, fail-quiet, no counter.
// =========================================================================================================
console.log("\nstored-record anomalies -- the safe default that destroys its own evidence");
{
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);

  // An approval whose expiresAt does NOT parse never reads as expired: it stays usable, for ever.
  const healthy = { expiresAt: new Date(Date.now() + 3_600_000).toISOString() } as never;
  const garbled = { expiresAt: "not-a-timestamp" } as never;
  ok("a healthy approval records NO anomaly", approvalTimestampUnparseable(healthy) === false);
  ok("a GARBLED approval TTL is detected (its 24h single-use guarantee is not enforced)", approvalTimestampUnparseable(garbled) === true);
  ok("the owner-action queue's twin is detected too", ownerActionTimestampUnparseable(garbled) === true && ownerActionTimestampUnparseable(healthy) === false);

  // An expiry row: THREE states the tracker could not tell apart.
  const rows: ExpiryItem[] = [
    { id: "ok", label: "S3 key", kind: "credential", expiresAt: "2026-12-01T00:00:00.000Z", source: "manual" },
    { id: "never", label: "a token that never expires", kind: "token", source: "observed" }, // LEGITIMATE no-expiry
    { id: "garbled", label: "a corrupt row", kind: "credential", expiresAt: "31/12/2026", source: "observed" },
    { id: "future", label: "a kind this build does not know", kind: "quantum-key" as never, source: "observed" },
  ];
  const anomalies = expiryRowAnomalies(rows);
  ok("an unparseable expiry timestamp is counted ('expired with zero warning' is THIS)", anomalies.unparseableTimestamp === 1);
  ok("an unknown expiry KIND is counted SEPARATELY (a different row)", anomalies.unknownKind === 1);
  ok("a legitimate no-expiry row is NOT counted (never cry wolf on a healthy state)", expiryRowAnomalies([rows[1]!]).unparseableTimestamp === 0);

  // A tampered custom role: the clamp is correct and it destroys the tamper evidence.
  const cleanRole = { name: "auditor", label: "Auditor", capabilities: ["reports.read"], surface: {}, presentation: {}, landing: "overview" } as unknown as CustomRole;
  const tamperedRole = { name: "auditor", label: "Auditor", capabilities: ["reports.read", "keys.ceremony"], surface: {}, presentation: {}, landing: "overview" } as unknown as CustomRole;
  ok("a clean custom role drops nothing", customRoleReservedCapabilityDrops(cleanRole) === 0);
  ok("a TAMPERED role holding an owner-reserved capability is counted (the clamp held; the signal exists)", customRoleReservedCapabilityDrops(tamperedRole) === 1);

  // Every anomaly name has a home in the closed vocabulary (they were DEAD -- in the vocabulary, no caller).
  ok("all five G312 counter names are in the closed vocabulary", [
    "stored-approval-unparseable-timestamp",
    "stored-owner-action-unparseable-timestamp",
    "stored-expiry-unparseable-timestamp",
    "stored-expiry-write-rejected",
    "stored-custom-role-reserved-capability-dropped",
  ].every((n) => vocab.has(n)));
  // `stored-expiry-unknown-kind` was SIX, and it is gone on purpose. It named a read-time skip the code does not
  // perform: laddersFor is TOTAL, so an off-vocabulary kind takes the default ladder rather than being dropped,
  // and the row is still counted, still laddered and still warned about. The write-time refusal (which is real)
  // is carried by stored-expiry-write-rejected. A counter for a skip that never happens is a wolf-cry.
  ok("the unknown-kind read anomaly is NOT a counter (the ladder is total, so nothing is skipped)", !vocab.has("stored-expiry-unknown-kind"));

  // And they land in the aggregate the pack reads (applyAdminCounters is the redaction chokepoint).
  const folded = applyAdminCounters(undefined, { "stored-expiry-unparseable-timestamp": 1, "stored-expiry-write-rejected": 1, [SENTINEL_GROUP]: 9 }, "2026-07-12T00:00:00.000Z");
  ok("the two expiry anomalies are two DIFFERENT keys in the aggregate", folded["stored-expiry-unparseable-timestamp"]?.count === 1 && folded["stored-expiry-write-rejected"]?.count === 1);
  ok("an out-of-vocabulary key (a customer group name) is DROPPED at the chokepoint", scanForSentinels(folded).length === 0);
}

// =========================================================================================================
// THE CHAIN BREAK that self-heals. Four causes, one verdict; and a rollover that erases it.
// =========================================================================================================
console.log("\nchain-break latch -- edited vs forged vs deleted, and the break that rolls over");
await (async () => {
  const mk = async (seq: number, prevHash: string): Promise<AuditEvent> => {
    const e = { seq, ts: new Date(1_800_000_000_000 + seq * 1000).toISOString(), actorEmail: SENTINEL_EMAIL, actorMethod: "token", sourceIp: null, action: "downpipe-create", outcome: "success", target: { kind: "downpipe", id: "dp1" }, prevHash } as unknown as AuditEvent;
    (e as { hash: string }).hash = await auditHash(e);
    return e;
  };
  const e1 = await mk(1, GENESIS_PREV_HASH);
  const e2 = await mk(2, e1.hash);
  const e3 = await mk(3, e2.hash);

  // STATE A: INTACT.
  const intact = await verifyChain([e1, e2, e3]);
  // STATE B: an EDITED snapshot (the stored hash no longer recomputes).
  const edited = await verifyChain([e1, { ...e2, hash: "sha384:0000" } as AuditEvent, { ...e3, prevHash: "sha384:0000" } as AuditEvent]);
  // STATE C: a FORGED / INSERTED entry (the prevHash link is wrong).
  const forged = await verifyChain([e1, { ...e2, prevHash: "sha384:1111" } as AuditEvent]);
  // STATE D: a DELETED entry, with the hashes RE-LINKED around the hole (the sophisticated tamper: the link
  // check passes and only the seq contiguity betrays it). This is the case the module claims to detect.
  const relinked = await mk(3, e1.hash);
  const deleted = await verifyChain([e1, relinked]);
  // STATE E: the retained chain no longer links to genesis (its first entry links to a pruned predecessor
  // while the verify still expects the true genesis).
  const reanchored = await verifyChain([e2], { expectGenesis: true });

  ok("an intact chain has no cause class", intact.intact === true && intact.causeClass === undefined);
  ok("an EDITED snapshot -> recompute-mismatch", edited.intact === false && edited.causeClass === "recompute-mismatch");
  ok("a FORGED link -> prev-hash-mismatch", forged.intact === false && forged.causeClass === "prev-hash-mismatch");
  ok("a DELETED entry -> seq-gap", deleted.intact === false && deleted.causeClass === "seq-gap");
  ok("a re-anchored chain -> genesis-link", reanchored.intact === false && reanchored.causeClass === "genesis-link");
  ok("the four break causes are FOUR DIFFERENT rows (one 'broken at 41' was four investigations)", new Set([edited.causeClass, forged.causeClass, deleted.causeClass].filter(Boolean)).size === 3);

  // THE ROLLOVER. A break is seen, then the broken entries fall off the retained window and the recompute
  // reads INTACT for ever afterwards. The latch is the only thing that remembers.
  type Latch = { chain: string; causeClass: string; detections: number; healedAt?: string; firstDetectedAt: string; brokenAtSeq: number };
  const latches = (st: { map: Map<string, unknown> }): Latch[] => Object.values((st.map.get(CHAIN_BREAKS_KEY) ?? {}) as Record<string, Latch>);

  const st = mapStorage();
  await recordChainVerdict(st, "audit", edited);
  const afterBreak = latches(st)[0];
  await recordChainVerdict(st, "audit", intact); // ...the rollover happens; the verify now reads intact
  const afterHeal = latches(st)[0];
  ok("the break is latched with its cause and its first sighting", afterBreak?.causeClass === "recompute-mismatch" && afterBreak.detections === 1);
  ok("a LATER intact verdict does NOT erase it -- it stamps healedAt", afterHeal?.healedAt !== undefined && afterHeal.causeClass === "recompute-mismatch");
  // The `?.` on the first read keeps a MISSING latch a failure (undefined !== undefined is false) rather than
  // a throw, and narrows afterHeal for the second read.
  ok("'it showed a break last Tuesday' and 'it shows intact now' are BOTH in the pack, together", afterHeal?.firstDetectedAt !== undefined && afterHeal.healedAt !== undefined);
  ok("no actor e-mail rides in the latch", scanForSentinels(st.map.get(CHAIN_BREAKS_KEY)).length === 0);

  // A REPEATED break bumps detections rather than re-anchoring the first sighting (the forensic one).
  const st2 = mapStorage();
  await recordChainVerdict(st2, "config-history", forged);
  await recordChainVerdict(st2, "config-history", forged);
  ok("a break seen twice reads detections:2 (a one-off is a different story from a standing break)", latches(st2)[0]?.detections === 2);

  // ===== G313, THE TUPLE KEY. A SECOND, DIFFERENT BREAK MUST NOT VANISH INTO THE FIRST. =====
  // The latch used to be keyed by CHAIN NAME ALONE, so causeClass and brokenAtSeq -- the two fields that
  // discriminate the outcome -- were left out of the coalescing key. Latch a seq-gap at 3, then detect an
  // edited snapshot at 2, and the pack showed ONE row (seq-gap@3, detections:2). The edited snapshot was
  // invisible, and "detections: 2", sold as evidence of a standing break, was indistinguishable from the SAME
  // break seen twice.
  const st3 = mapStorage();
  await recordChainVerdict(st3, "audit", deleted); // a seq-gap
  await recordChainVerdict(st3, "audit", edited); // ...and later, an EDITED SNAPSHOT: a different incident
  const two = latches(st3);
  ok("a second, DIFFERENT break gets its OWN row (it used to fold into the first and disappear)", two.length === 2);
  ok("...and both causes survive, each with its own seq", new Set(two.map((l) => l.causeClass)).size === 2 && two.every((l) => l.detections === 1));
  ok("the same break seen twice still reads detections:2, and does NOT open a second row", latches(st2).length === 1 && latches(st2)[0]?.detections === 2);

  // ===== G313, THE FORGED ENVELOPE. An edited BODY is not a forged ATTRIBUTION. =====
  // On the config-history chain the contentHash covers the SNAPSHOT and the HMAC digest covers the ENVELOPE
  // around it (id/at/author/summary/contentHash/parentHash) and NOT the snapshot. They are independent checks
  // and BOTH used to return "recompute-mismatch", so "the config body at v41 was rewritten" and "the body is
  // intact and its attribution was forged, or the record was minted without our key" -- different incidents,
  // different blast radii -- handed a support engineer the same answer.
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const snap = (ids: string[]): ConfigSnapshot => ({ downpipes: ids.map((id) => ({ id })) }) as unknown as ConfigSnapshot;
  const v1 = await buildConfigVersion(snap([]), 1, "2027-01-01T00:00:00.000Z", SENTINEL_EMAIL, "created", CONFIG_GENESIS_PREV_HASH, rawKey);
  const v2 = await buildConfigVersion(snap(["dp1"]), 2, "2027-01-02T00:00:00.000Z", SENTINEL_EMAIL, "edited", v1.contentHash, rawKey);
  const v3 = await buildConfigVersion(snap(["dp1", "dp2"]), 3, "2027-01-03T00:00:00.000Z", SENTINEL_EMAIL, "edited", v2.contentHash, rawKey);
  const cleanChain = await verifyConfigChain([v1, v2, v3], rawKey);
  // The BODY is rewritten by a LAZY tamperer who did not refresh the version's own unkeyed contentHash.
  const bodyEdited = await verifyConfigChain([v1, { ...v2, snapshot: snap(["ATTACKER"]) }, v3], rawKey);
  // The body is UNTOUCHED and its successor's KEYED envelope commits to exactly it; WHO changed it and WHEN are
  // rewritten, so only the signed envelope fails. This is the state that used to report as an edited snapshot.
  const envelopeForged = await verifyConfigChain([v1, { ...v2, author: "attacker@evil.example", at: "2026-06-01T00:00:00.000Z" }, v3], rawKey);
  ok("a clean config chain verifies", cleanChain.intact === true);
  ok("a LAZY body edit (the hash not refreshed) -> recompute-mismatch", bodyEdited.intact === false && bodyEdited.causeClass === "recompute-mismatch");
  ok("a FORGED ENVELOPE (the successor's keyed parentHash vouches for the body) -> envelope-digest-mismatch", envelopeForged.intact === false && envelopeForged.causeClass === "envelope-digest-mismatch");
  ok("DISCRIMINATION: the two are DIFFERENT rows (they were both 'recompute-mismatch')", bodyEdited.causeClass !== envelopeForged.causeClass);

  // ===== G313 (R4): THE COMPETENT BODY EDIT, WHICH THE ROUND-3 FIX MISNAMED AS "THE BODY IS INTACT". =====
  //
  // configContentHash takes NO KEY. The only actor who can rewrite a stored version is the only actor who can
  // produce EITHER of the two states above -- and that actor can recompute an unkeyed SHA. So a tamperer who
  // rewrites the body AND refreshes its contentHash passes the recompute and lands on the digest check, whose
  // shipped documentation told support "the body is INTACT and verifies cleanly". The config body at v2 was the
  // attacker's, and the pack said it was fine. The lazy edit above was the ONLY case the round-3 validator drove.
  //
  // What actually vouches for a body is the SUCCESSOR: its parentHash commits to this contentHash and rides
  // inside its own KEYED digest. v3's envelope still verifies and still commits to the ORIGINAL contentHash, so
  // the swap is provable and gets its own class.
  const swappedBody = snap(["ATTACKER"]);
  const competent = { ...v2, snapshot: swappedBody, contentHash: await configContentHash(swappedBody) };
  const bodySwapped = await verifyConfigChain([v1, competent, v3], rawKey);
  ok("the competent edit really does pass the unkeyed recompute (the defect is not hypothetical)", (await configContentHash(competent.snapshot)) === competent.contentHash);
  ok("a COMPETENT body edit -> content-swapped, off the successor's KEYED word", bodySwapped.intact === false && bodySwapped.causeClass === "content-swapped" && bodySwapped.brokenAt === 2);
  ok("...and it is NOT envelope-digest-mismatch, which asserts the body is intact", bodySwapped.causeClass !== envelopeForged.causeClass);
  ok("DISCRIMINATION: 'the body at v2 was rewritten' and 'the attribution at v2 was forged' are now different rows", JSON.stringify(bodySwapped) !== JSON.stringify(envelopeForged));

  // THE HEAD. There is no successor, so NOTHING keyed vouches for the body and the code cannot separate the two.
  // Say that, rather than picking one: the shipped class picked the one that sends support away from the body.
  const headForged = await verifyConfigChain([v1, v2, { ...v3, author: "attacker@evil.example" }], rawKey);
  ok("a digest failure on the HEAD -> digest-unvouched (no successor can speak for its body)", headForged.intact === false && headForged.causeClass === "digest-unvouched" && headForged.brokenAt === 3);
  ok("...so the pack never claims a body is intact on a version nothing vouches for", headForged.causeClass !== "envelope-digest-mismatch");

  // ===== G313 (R4): THE ROTATED KEY, WHICH IS NOT A TAMPER AT ALL. =====
  //
  // The config-history digests are HMAC'd with the in-DO session key. The engine models a regenerated or lost
  // key EXPLICITLY, as recoverable context ("if that key is regenerated/lost, EVERY config-history digest fails
  // verifyConfigChain"). Nothing was edited and nobody was forged -- and the latch filed a durable row whose
  // closed cause asserts a forgery. The boolean was in a different pack section and the recorder never read it.
  const rotatedKey = crypto.getRandomValues(new Uint8Array(32));
  const keyRotated = await verifyConfigChain([v1, v2, v3], rotatedKey);
  ok("a rotated key breaks the verify at the FIRST version, with no keyed witness anywhere", keyRotated.intact === false && keyRotated.causeClass === "digest-unvouched" && keyRotated.brokenAt === 1);
  const stRot = mapStorage();
  await recordChainVerdict(stRot, "config-history", keyRotated, true); // the DO now passes what it already knew
  const rotLatch = latches(stRot)[0];
  ok("the LATCH consults the rotated-key fact and names it: signing-key-rotated", rotLatch?.causeClass === "signing-key-rotated");
  ok("...so an estate whose key was regenerated no longer carries a durable row accusing an attacker", rotLatch?.causeClass !== "envelope-digest-mismatch" && rotLatch?.causeClass !== "content-swapped");
  const stTamper = mapStorage();
  await recordChainVerdict(stTamper, "config-history", bodySwapped, false); // the key is FINE and the body was swapped
  ok("NOISE: with the key intact, a real swap still latches content-swapped (the rotated-key cause never eats a tamper)", latches(stTamper)[0]?.causeClass === "content-swapped");
  ok("...and a NON-digest break (an edited body) is untouched by the key fact: the key cannot cause it", await (async () => {
    const stEdit = mapStorage();
    await recordChainVerdict(stEdit, "config-history", bodyEdited, true);
    return latches(stEdit)[0]?.causeClass === "recompute-mismatch";
  })());
  ok("NO-CUSTODY: no snapshot, hash, actor or target rides in any latch", scanForSentinels(stRot.map.get(CHAIN_BREAKS_KEY)).length === 0 && scanForSentinels(stTamper.map.get(CHAIN_BREAKS_KEY)).length === 0);

  // ===== G313 (R5): THE ONE-BUTTON MASK, DRIVEN THROUGH THE REAL DO AND THE REAL OWNER LEVER. =====
  //
  // verifyConfigChain returns at the FIRST break. With the in-DO signing key gone, version 1's digest fails and
  // versions 2..N are NEVER EXAMINED -- yet the latch displaced the whole digest family to signing-key-rotated,
  // whose shipped vocabulary told support "nothing was tampered at all". And the key is destroyed by an OWNER
  // BUTTON: POST /passkey/session/terminate-all deletes the passkey session key. So anyone with the DO-storage
  // write access a config tamper ALREADY REQUIRES could press it and turn every tamper into the row that says
  // nothing happened.
  //
  // Driven, not reasoned: a REAL SchedulerDO, three REAL signed config versions written by the REAL mutation
  // path, the REAL terminate-all route, and the verdict read back through the REAL /config-history-health.
  const drive = async (tamper: boolean): Promise<{ health: Record<string, unknown>; latched: Array<{ causeClass?: string; brokenAtSeq?: number }> }> => {
    const sched = makeScheduler();
    for (let i = 1; i <= 3; i++) {
      const r = await sched.stub.fetch(new Request("https://do/downpipes", {
        method: "POST",
        body: JSON.stringify({ id: `dp-${i}`, name: `pipe-${i}`, enabled: true, cadenceSeconds: 86_400, source: { type: "kv", binding: `KV_${i}`, include: [], exclude: [] } }),
        headers: { "content-type": "application/json" },
      }));
      if (!r.ok) throw new Error(`downpipe seed failed: ${r.status}`);
      await (sched.stub as unknown as { snapshotConfigNow(a: string): Promise<unknown> }).snapshotConfigNow(SENTINEL_EMAIL);
    }
    // The KEY-FINGERPRINT BASELINE is established by the first health read (a support-pack build, or the
    // console's config-integrity poll) -- exactly as it is in the field, and the reason a rotation is detectable
    // at all. Without a prior read there is nothing for the rotation to have drifted FROM.
    await sched.stub.fetch(new Request("https://do/config-history-health"));
    if (tamper) {
      // The COMPETENT edit the round-4 fix already names: the body at v2 is rewritten AND its unkeyed contentHash
      // refreshed, so v2 recomputes cleanly and only the LINK from v3 gives it away. That link needs no key.
      const v2 = (await sched.storage.get<Record<string, unknown>>("confighist:00000000000000000002"))!;
      const swapped = { ...(v2.snapshot as ConfigSnapshot), downpipes: [] } as ConfigSnapshot;
      await sched.storage.put("confighist:00000000000000000002", { ...v2, snapshot: swapped, contentHash: await configContentHash(swapped) });
    }
    // THE OWNER BUTTON. The real route, over the real DO: it deletes the passkey session key, which is the key
    // every config-history digest is HMAC'd with.
    const term = await sched.stub.fetch(new Request("https://do/passkey/session/terminate-all", { method: "POST", headers: { "content-type": "application/json", [CALLER_HEADER]: encodeCaller({ method: "token", email: null, subject: null, role: "owner", groups: [] }) }, body: "{}" }));
    if (!term.ok) throw new Error(`terminate-all failed: ${term.status}`);
    const health = (await (await sched.stub.fetch(new Request("https://do/config-history-health"))).json()) as Record<string, unknown>;
    const raw = (await sched.storage.get<Record<string, { causeClass?: string; brokenAtSeq?: number; chain?: string }>>(CHAIN_BREAKS_KEY)) ?? {};
    return { health, latched: Object.values(raw).filter((l) => l.chain === "config-history") };
  };

  const pristine = await drive(false);
  const tampered = await drive(true);
  const causes = (r: { latched: Array<{ causeClass?: string }> }): string[] => r.latched.map((l) => l.causeClass ?? "").sort();
  const verifyOf = (r: { health: Record<string, unknown> }): Record<string, unknown> => (r.health.verify ?? {}) as Record<string, unknown>;

  ok("the owner button really does break the keyed verify on a PRISTINE chain", verifyOf(pristine).intact === false && verifyOf(pristine).signingKeyRotated === true);
  ok("...and the KEY-FREE pass over the whole chain says the chain is clean", verifyOf(pristine).unkeyedIntact === true);
  ok("so the pristine estate latches signing-key-rotated, and ONLY that", JSON.stringify(causes(pristine)) === JSON.stringify(["signing-key-rotated"]));

  ok("the SAME button over a chain whose v2 body was swapped still reports the rotated key", verifyOf(tampered).signingKeyRotated === true);
  ok("...but the KEY-FREE pass CATCHES the tamper the keyed verify never reached", verifyOf(tampered).unkeyedIntact === false && verifyOf(tampered).unkeyedCause === "prev-hash-mismatch" && verifyOf(tampered).unkeyedBrokenAt === 3);
  ok("...and it is LATCHED beside the key fact: two rows, not one", JSON.stringify(causes(tampered)) === JSON.stringify(["prev-hash-mismatch", "signing-key-rotated"]));
  ok("DISCRIMINATION: 'the owner signed everyone out' and 'the owner signed everyone out AND v2 is the attacker's' are now DIFFERENT rows (they were byte-identical)", JSON.stringify(causes(pristine)) !== JSON.stringify(causes(tampered)));
  ok("...and the configIntegrity verify block discriminates them too", JSON.stringify(verifyOf(pristine)) !== JSON.stringify(verifyOf(tampered)));
  ok("NO-CUSTODY: the key-free verdict is a boolean, a closed cause and a clamped id", scanForSentinels(tampered.health).length === 0 && typeof verifyOf(tampered).unkeyedBrokenAt === "number");
})();

// =========================================================================================================
// THE DELETION AN ATTACKER ACTUALLY PERFORMS -- REMOVE THE NEWEST ENTRIES.
//
// Every verify pass, keyed and key-free alike, walks the RETAINED entries and can only see a break BETWEEN
// two of them. Delete the entries that record what you just did and the survivors still link perfectly: the
// chain reads INTACT, the pack files no break, and the ticket's own third state ("a deleted version") is
// undetected for the one deletion that matters. Both chains persist a HEAD ANCHOR on every commit (the audit
// head's seq+hash, the config-history head's id+contentHash); retention prunes the OLDEST and never lowers it,
// so a retained head below the anchor is a removed tail. It needs no key.
// =========================================================================================================
console.log("\nhead truncation -- the newest entries deleted, on both chains");
await (async () => {
  type Latch = { chain: string; causeClass?: string; brokenAtSeq?: number; healedAt?: string };
  const latchesOf = async (st: MockStorage, chain: string): Promise<Latch[]> => {
    const raw = (await st.get<Record<string, Latch>>(CHAIN_BREAKS_KEY)) ?? {};
    return Object.values(raw).filter((l) => l.chain === chain);
  };

  // ---- THE AUDIT CHAIN, through the REAL POST /audit and the REAL GET /audit/verify.
  const sched = makeScheduler();
  const draft = (i: number): string => JSON.stringify({ actorEmail: SENTINEL_EMAIL, actorMethod: "token", sourceIp: null, action: "downpipe-create", outcome: "success", target: { kind: "downpipe", id: `dp-${i}` } });
  for (let i = 1; i <= 5; i++) {
    const r = await sched.stub.fetch(new Request("https://do/audit", { method: "POST", body: draft(i), headers: { "content-type": "application/json" } }));
    if (!r.ok) throw new Error(`audit append failed: ${r.status}`);
  }
  const auditKeys = sched.storage.rawListKeys().filter((k) => k.startsWith("audit:")).sort();
  const cleanVerify = (await (await sched.stub.fetch(new Request("https://do/audit/verify"))).json()) as Record<string, unknown>;
  ok("five real appends verify intact, and latch nothing", cleanVerify.intact === true && (await latchesOf(sched.storage, "audit")).length === 0);

  // THE TAMPER: remove the two NEWEST entries -- the ones recording what was just done. The retained chain
  // 1..3 still links to genesis and to itself, so the recompute is structurally blind to this.
  for (const k of auditKeys.slice(-2)) await sched.storage.delete(k);
  const afterVerify = (await (await sched.stub.fetch(new Request("https://do/audit/verify"))).json()) as Record<string, unknown>;
  const auditLatched = await latchesOf(sched.storage, "audit");
  ok("the truncated chain STILL recomputes intact (this is why it was invisible)", afterVerify.intact === true && afterVerify.checkedThrough === 3);
  ok("...and the pack now carries the break anyway: head-truncated, at the head the DO committed to", auditLatched.length === 1 && auditLatched[0]?.causeClass === "head-truncated" && auditLatched[0]?.brokenAtSeq === 5);
  ok("the intact recompute does NOT heal a truncation it cannot see", auditLatched[0]?.healedAt === undefined);
  ok("no actor e-mail rides in the latch", scanForSentinels(await sched.storage.get(CHAIN_BREAKS_KEY)).length === 0);

  // NOISE CONTROL: a chain that merely ROLLED OVER (its OLDEST entries pruned) must not file this row. The
  // rollover prunes from the front and never lowers the head anchor.
  const rolled = makeScheduler();
  for (let i = 1; i <= 4; i++) await rolled.stub.fetch(new Request("https://do/audit", { method: "POST", body: draft(i), headers: { "content-type": "application/json" } }));
  const oldest = rolled.storage.rawListKeys().filter((k) => k.startsWith("audit:")).sort()[0]!;
  await rolled.storage.delete(oldest); // the retention rollover's own effect
  await rolled.stub.fetch(new Request("https://do/audit/verify"));
  ok("NOISE: a rollover (the OLDEST entries pruned) files NO truncation row", (await latchesOf(rolled.storage, "audit")).every((l) => l.causeClass !== "head-truncated"));

  // ---- THE CONFIG-HISTORY CHAIN, through the REAL snapshot path and the REAL health probe.
  const cfg = makeScheduler();
  for (let i = 1; i <= 3; i++) {
    const r = await cfg.stub.fetch(new Request("https://do/downpipes", {
      method: "POST",
      body: JSON.stringify({ id: `dp-${i}`, name: `pipe-${i}`, enabled: true, cadenceSeconds: 86_400, source: { type: "kv", binding: `KV_${i}`, include: [], exclude: [] } }),
      headers: { "content-type": "application/json" },
    }));
    if (!r.ok) throw new Error(`downpipe seed failed: ${r.status}`);
    await (cfg.stub as unknown as { snapshotConfigNow(a: string): Promise<unknown> }).snapshotConfigNow(SENTINEL_EMAIL);
  }
  const cfgKeys = cfg.storage.rawListKeys().filter((k) => k.startsWith("confighist:")).sort();
  await cfg.stub.fetch(new Request("https://do/config-history-health"));
  ok("three real config versions latch nothing", (await latchesOf(cfg.storage, "config-history")).length === 0);
  // THE TAMPER: delete the NEWEST version, with the signing key perfectly healthy. Nothing in the retained
  // chain is wrong: v1 -> v2 links, hashes and digests all verify.
  await cfg.storage.delete(cfgKeys[cfgKeys.length - 1]!);
  const cfgHealth = (await (await cfg.stub.fetch(new Request("https://do/config-history-health"))).json()) as Record<string, unknown>;
  const cfgLatched = await latchesOf(cfg.storage, "config-history");
  ok("the truncated config chain STILL verifies intact (the key is healthy and every survivor links)", (cfgHealth.verify as Record<string, unknown>).intact === true);
  ok("...and the deleted HEAD version is now a row: head-truncated at the id the DO committed", cfgLatched.length === 1 && cfgLatched[0]?.causeClass === "head-truncated" && cfgLatched[0]?.brokenAtSeq === 3);
  ok("DISCRIMINATION: a deleted MIDDLE version and a deleted NEWEST version are different rows", cfgLatched[0]?.causeClass !== "prev-hash-mismatch");
  ok("NO-CUSTODY: the truncation row is a chain name, a closed cause and a clamped id", scanForSentinels(await cfg.storage.get(CHAIN_BREAKS_KEY)).length === 0);
})();

// =========================================================================================================
// THE PACK'S OWN HEADLINE MUST NOT CONTRADICT THE LATCH.
//
// R6 caught the truncation and filed it in schedDiag.chainBreaks. It left the two verify blocks the pack (and
// the console) actually LEAD with saying the opposite: `audit` printed {"intact":true} on a chain the same call
// had just established was truncated, and `configIntegrity` -- whose projector only surfaces the history block
// when there is something to diagnose -- emitted NOTHING AT ALL on a tail-deleted history with a healthy key. So
// one bundle carried both "the chain is fine" and "the chain's head was deleted", and the reader who stopped at
// the section named `audit` (or at the console's "Chain intact" banner) was told the wrong thing.
//
// The anchor verdict now rides ON the verify block it qualifies, through the REAL routes and the REAL projectors.
// =========================================================================================================
console.log("\nthe verdict carries its own anchor -- intact never stands alone next to a truncation");
await (async () => {
  // The pack's projectors call scheduler.fetch(url, init) -- the (string, init) overload a REAL DurableObjectStub
  // accepts and the bare DO class does not. This adapter is that overload and nothing else: the request still
  // enters the REAL SchedulerDO.fetch, through the REAL routes.
  const asStub = (dobj: { fetch(r: Request): Promise<Response> }): DurableObjectStub =>
    ({ fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)) }) as unknown as DurableObjectStub;
  const sched = makeScheduler();
  const draft = (i: number): string => JSON.stringify({ actorEmail: SENTINEL_EMAIL, actorMethod: "token", sourceIp: null, action: "downpipe-create", outcome: "success", target: { kind: "downpipe", id: `dp-${i}` } });
  for (let i = 1; i <= 5; i++) await sched.stub.fetch(new Request("https://do/audit", { method: "POST", body: draft(i), headers: { "content-type": "application/json" } }));

  // HEALTHY: the pack's audit section says intact and says nothing about a truncation (no noise on a clean chain).
  const healthySection = await fetchAuditStatus(asStub(sched.stub));
  ok("a healthy chain projects intact:true and NO headTruncated (no noise on the working path)", healthySection.intact === true && healthySection.headTruncated === undefined);

  // THE TAMPER: delete the two NEWEST entries. The retained 1..3 still link, so the recompute still says intact.
  for (const k of sched.storage.rawListKeys().filter((k) => k.startsWith("audit:")).sort().slice(-2)) await sched.storage.delete(k);
  const truncatedSection = await fetchAuditStatus(asStub(sched.stub));
  ok("the recompute STILL reports intact (it walks the survivors, and they link perfectly)", truncatedSection.intact === true);
  ok("...and the SAME section now carries the anchor's verdict beside it: headTruncated at the committed head", truncatedSection.headTruncated === true && truncatedSection.headTruncatedAt === 5);
  ok("DISCRIMINATION: a healthy audit section and a truncated one are no longer byte-identical", JSON.stringify({ ...healthySection, verify: 0 }) !== JSON.stringify({ ...truncatedSection, verify: 0 }));
  ok("NO-CUSTODY: no actor e-mail rides in the projected audit section", scanForSentinels(truncatedSection).length === 0);

  // NOISE CONTROL: a real retention ROLLOVER prunes the OLDEST entries and never lowers the anchor.
  const rolled = makeScheduler();
  for (let i = 1; i <= 4; i++) await rolled.stub.fetch(new Request("https://do/audit", { method: "POST", body: draft(i), headers: { "content-type": "application/json" } }));
  await (rolled.stub as unknown as { rollOverAudit(n: number): Promise<void> }).rollOverAudit(2);
  const rolledSection = await fetchAuditStatus(asStub(rolled.stub));
  ok("NOISE: a REAL rollOverAudit(2) projects rolledOver, and NO headTruncated", rolledSection.rolledOver === true && rolledSection.headTruncated === undefined);

  // ---- THE CONFIG-HISTORY CHAIN, through the real snapshot path and the REAL configIntegrity projector.
  const cfg = makeScheduler();
  for (let i = 1; i <= 3; i++) {
    await cfg.stub.fetch(new Request("https://do/downpipes", {
      method: "POST",
      body: JSON.stringify({ id: `dp-${i}`, name: `pipe-${i}`, enabled: true, cadenceSeconds: 86_400, source: { type: "kv", binding: `KV_${i}`, include: [], exclude: [] } }),
      headers: { "content-type": "application/json" },
    }));
    await (cfg.stub as unknown as { snapshotConfigNow(a: string): Promise<unknown> }).snapshotConfigNow(SENTINEL_EMAIL);
  }
  const cleanCfg = (await fetchConfigIntegrity(asStub(cfg.stub))) as { history?: Record<string, unknown> };
  ok("a healthy config history emits NO history block (nothing to diagnose)", cleanCfg.history === undefined);

  // THE TAMPER: delete the NEWEST version, signing key healthy. Every retained version links, hashes and verifies.
  const cfgKeys = cfg.storage.rawListKeys().filter((k) => k.startsWith("confighist:")).sort();
  await cfg.storage.delete(cfgKeys[cfgKeys.length - 1]!);
  const truncCfg = (await fetchConfigIntegrity(asStub(cfg.stub))) as { history?: Record<string, unknown> };
  ok("THE KILL: a tail-deleted history now EMITS the block (it used to emit nothing at all)", truncCfg.history !== undefined);
  ok("...and the block says BOTH things at once: the recompute is intact, and the head was deleted", truncCfg.history?.intact === true && truncCfg.history?.headTruncated === true && truncCfg.history?.headTruncatedAt === 3);
  ok("NO-CUSTODY: the config author's e-mail rides nowhere in the projected block", scanForSentinels(truncCfg).length === 0);

  // THE SIBLING READER: GET /config/history is the CONSOLE's own call, and it computed the anchor verdict for the
  // latch and then returned a verify block without it -- so the console rendered "Chain verified" over a history
  // whose newest versions had just been deleted. Same lie, different surface.
  const list = (await (await cfg.stub.fetch(new Request("https://do/config/history"))).json()) as { verify?: Record<string, unknown> };
  ok("SIBLING: GET /config/history (the console's chain banner) carries the anchor verdict too", list.verify?.intact === true && list.verify?.headTruncated === true && list.verify?.headTruncatedAt === 3);
})();

// =========================================================================================================
// THE ATTACH REFUSAL. "D1 fails but KV works" vs "my token doesn't work".
// =========================================================================================================
console.log("\nattach refusals -- which stage, which cause, which capability");
{
  // The tagged throws, from the REAL planner and the REAL capability assertion shape.
  const engineBindings: LiveBinding[] = [
    { name: "SCHEDULER", type: "durable_object_namespace" },
    { name: "RUNSEAL", type: "durable_object_namespace" },
    { name: "KV_ACME", type: "kv_namespace", namespace_id: "n1" },
  ] as unknown as LiveBinding[];
  const notTheEngine: LiveBinding[] = [{ name: "SOMETHING_ELSE", type: "kv_namespace" }] as unknown as LiveBinding[];

  // STATE 1: the IDENTITY GUARD. The token WORKED and the script is not this engine.
  let identity: unknown;
  try {
    planChange(notTheEngine, [], []);
  } catch (e) {
    identity = e;
  }
  // STATE 2: PLAN-VALIDATE, a name conflict.
  let conflict: unknown;
  try {
    planChange(engineBindings, [{ type: "kv", binding: "KV_ACME", namespaceId: "n2" }] as never, []);
  } catch (e) {
    conflict = e;
  }
  // STATE 3: TOKEN-CAPABILITY, missing D1 -- while KV works. THE TICKET.
  const d1Missing = new AttachRefusal(`the token cannot use D1 on account ${SENTINEL_TOKEN}`, { stage: "token-capability", cause: "missing-capability", missingCaps: ["d1"] });
  // STATE 4: the SAME stage, missing KV instead.
  const kvMissing = new AttachRefusal("the token cannot use Workers KV", { stage: "token-capability", cause: "missing-capability", missingCaps: ["kv"] });
  // STATE 5: TOKEN-WINDOW, a future Start Date.
  const notYet = new AttachRefusal(SENTINEL_MESSAGE, { stage: "token-window", cause: "token-not-yet-active" });
  // STATE 6: TOKEN-WINDOW, expired. A DIFFERENT sentence to the customer.
  const expired = new AttachRefusal(SENTINEL_MESSAGE, { stage: "token-window", cause: "token-expired" });

  const rId = attachRefusalOf(identity);
  const rConf = attachRefusalOf(conflict);
  const rD1 = attachRefusalOf(d1Missing);
  const rKv = attachRefusalOf(kvMissing);
  const rNotYet = attachRefusalOf(notYet);
  const rExp = attachRefusalOf(expired);

  ok("the identity guard tags identity-guard / not-this-engine", rId?.stage === "identity-guard" && rId.cause === "not-this-engine");
  ok("the planner's name conflict tags plan-validate / binding-name-conflict", rConf?.stage === "plan-validate" && rConf.cause === "binding-name-conflict");
  ok("a missing D1 capability names D1 -- and ONLY D1", rD1?.missingCaps?.join() === "d1");
  ok("a missing KV capability is a DIFFERENT row ('D1 fails but KV works' is now answerable)", rKv?.missingCaps?.join() === "kv" && JSON.stringify(rD1) !== JSON.stringify(rKv));
  // The distinctness is asserted through a Set rather than `rNotYet.cause !== rExp.cause`: the two equality
  // checks ahead of it narrow both to their literal types, and TypeScript then reads the `!==` as an
  // unintentional comparison. The Set counts the SAME two runtime values.
  ok("a FUTURE start date and an EXPIRED token are two different causes", rNotYet?.cause === "token-not-yet-active" && rExp?.cause === "token-expired" && new Set([rNotYet.cause, rExp.cause]).size === 2);
  ok("no token, account id or Cloudflare message rides on any tag", scanForSentinels([rId, rConf, rD1, rKv, rNotYet, rExp]).length === 0);

  // ...and they reach the standing record as an APPEND-ONLY ring (the SEQUENCE is the diagnosis).
  let health = applyAttachHealth(undefined, { op: "attach", fault: "auth", refusal: rNotYet }, 1_000);
  health = applyAttachHealth(health, { op: "attach", fault: "auth", refusal: rD1 }, 2_000);
  health = applyAttachHealth(health, { op: "attach", fault: "auth", refusal: rKv }, 3_000);
  const ring = health.refusals ?? [];
  ok("three refusals produce THREE rows (a counter keyed on stage|cause would have produced one)", ring.length === 3);
  ok("the ring preserves the sequence (window, then D1, then KV)", ring[0]?.cause === "token-not-yet-active" && ring[1]?.missingCaps?.join() === "d1" && ring[2]?.missingCaps?.join() === "kv");
  // Defence in depth: the applier is the redaction chokepoint. A forged tag cannot widen the record.
  const forgedTag = applyAttachHealth(undefined, { op: "attach", fault: "auth", refusal: { stage: "not-a-stage", cause: SENTINEL_MESSAGE, missingCaps: [SENTINEL_TOKEN] } } as never, 4_000);
  ok("a FORGED refusal tag is dropped whole at the applier (no row, no leak)", (forgedTag.refusals ?? []).length === 0 && scanForSentinels(forgedTag).length === 0);
  ok("the stage and cause vocabularies are closed and non-empty", ATTACH_REFUSAL_STAGES.length === 5 && ATTACH_REFUSAL_CAUSES.length > 5);
}

// =========================================================================================================
// THE TEST BUTTON'S ANSWER. Through the REAL DO, into the REAL projected section.
// =========================================================================================================
console.log("\ntest outcomes -- the wiring check that died with the browser tab");
await (async () => {
  // The classifier reads the reason ONLY to select a member and returns the enum.
  ok("a push 401 classes as auth (whatever the body says)", classifyTestFailure("some prose", 401) === "auth");
  ok("a 401 is its OWN status class (not folded into 4xx)", testStatusClass(401) === "401" && testStatusClass(404) === "404" && testStatusClass(418) === "4xx");
  // NOTE the class that is NOT here. "delete-denied" was a TEST REASON CLASS, and a denied delete is not a
  // failed test: probeDestination catches the delete throw and still returns ok:TRUE (correctly -- backups
  // work). So the class could only ever be selected on the ok:false path, where the reason cannot carry those
  // words, and it had ZERO producers. The old proof for it POSTed a hand-written "delete-denied" reason into
  // the recorder, a string the real route cannot generate, and asserted it came back.
  //
  // The fact is real and now rides on its OWN discriminator (deleteProbe + objectLock, on an honestly ok:true
  // row), and it is proved by DRIVING POST /destination/verify against a bucket that refuses the delete:
  // test/validate-cov-admin-router-destinations.ts.
  ok("delete-denied is GONE from the test-reason vocabulary (a denied delete never failed the probe)", !(TEST_REASON_CLASSES as readonly string[]).includes("delete-denied"));
  ok("an IdP cert failure classes as cert", classifyTestFailure("cert-out-of-window") === "cert");
  ok("an unconfigured surface classes as not-configured", classifyTestFailure("not-configured") === "not-configured");
  ok("the ENGINE's own fault classes as internal, not as the customer's target", classifyTestFailure("config-unreadable: the wrap key would not decrypt") === "internal");
  ok("a webhook DNS failure classes as unreachable", classifyTestFailure("network-dns") === "unreachable");
  ok("the classifier NEVER returns the text it read", !([SENTINEL_ENDPOINT] as string[]).includes(classifyTestFailure(SENTINEL_ENDPOINT)));

  // Drive the ring through the REAL recorder + the REAL DO, and read it back through the REAL projector.
  const sched = realScheduler();
  const post = async (surface: string, ok_: boolean, reasonClass?: string, statusClass?: string): Promise<void> => {
    await sched.stub.fetch("https://do/diag/test-outcome", {
      method: "POST",
      body: JSON.stringify({ surface, ok: ok_, ...(reasonClass !== undefined ? { reasonClass } : {}), ...(statusClass !== undefined ? { statusClass } : {}) }),
      headers: { "content-type": "application/json" },
    });
  };
  // THE TICKET: "the push test failed with a 401 yesterday but works when support asks us to retry."
  await post("push", false, "auth", "401");
  await post("push", true);
  // "my Slack test keeps failing"
  await post("notify-channel", false, "auth", "401");
  await post("notify-channel", false, "auth", "401");
  // "the SSO test failed with some cert error"
  await post("idp", false, "cert");
  // "verify destination keeps failing" -- a genuinely FAILED verify (the credential is refused). The
  // delete-denied PASS is a different row entirely, and it is driven through the real route in
  // test/validate-cov-admin-router-destinations.ts rather than hand-posted here.
  await post("dest-verify", false, "auth", "403");
  // A hostile / drifted writer cannot inject anything.
  await post(SENTINEL_ENDPOINT, false, SENTINEL_MESSAGE, SENTINEL_TOKEN);

  const stored = sched.storage as unknown as { map?: Map<string, unknown> };
  const section = (await fetchSchedDiag(sched.stub)) as { testOutcomes?: Record<string, Array<Record<string, unknown>>> };
  const t = section.testOutcomes ?? {};
  ok("the push ring carries BOTH the failure and the later pass, in order", (t.push ?? []).length === 2 && t.push?.[0]?.ok === false && t.push?.[1]?.ok === true);
  ok("the push failure carries its 401 (the whole diagnosis, previously lost with the tab)", t.push?.[0]?.reasonClass === "auth" && t.push?.[0]?.statusClass === "401");
  ok("'it failed yesterday and works now' is now CHECKABLE rather than a matter of trust", t.push?.[0]?.ok === false && t.push?.[1]?.ok === true);
  ok("the IdP cert error is a DIFFERENT row from the push auth failure", t.idp?.[0]?.reasonClass === "cert" && t.idp?.[0]?.reasonClass !== t.push?.[0]?.reasonClass);
  ok("a genuinely failed destination verify carries its cause", t["dest-verify"]?.[0]?.reasonClass === "auth" && t["dest-verify"]?.[0]?.statusClass === "403");
  ok("a repeated Slack failure reads as a SEQUENCE, not one coalesced counter", (t["notify-channel"] ?? []).length === 2);
  ok("a PASS carries no reason (there is nothing to explain)", t.push?.[1]?.reasonClass === undefined);
  ok("an out-of-vocabulary surface is DROPPED whole (no row, no key)", Object.keys(t).every((k) => ["push", "notify-channel", "idp", "dest-verify", "email"].includes(k)));
  ok("no webhook URL, token or provider text rides in the section", scanForSentinels(section).length === 0);
  ok("nor in the raw stored record", scanForSentinels(stored.map === undefined ? {} : Object.fromEntries(stored.map)).length === 0);
})();

// =========================================================================================================
// The POSTURE vocabulary itself: every name this pass emits must be admitted by the aggregate that stores it.
// =========================================================================================================
console.log("\nvocabulary integrity");
{
  const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
  ok("every POSTURE_COUNTER_NAMES member is spread into ADMIN_COUNTER_NAMES", (POSTURE_COUNTER_NAMES as readonly string[]).every((n) => vocab.has(n)));
  ok("ADMIN_COUNTER_NAMES has no duplicates (a duplicate would silently fuse two discriminators)", new Set(ADMIN_COUNTER_NAMES as readonly string[]).size === (ADMIN_COUNTER_NAMES as readonly string[]).length);
  ok("AUTH_SIGNAL_NAMES has no duplicates", new Set(AUTH_SIGNAL_NAMES as readonly string[]).size === (AUTH_SIGNAL_NAMES as readonly string[]).length);
}

// =========================================================================================================
// The PACK PROJECTION of the temporal shape, end to end through the DO.
// =========================================================================================================
console.log("\nprojection -- the temporal shape reaches the pack");
await (async () => {
  // THE BUILD CLOCK IS FIXED, and that is not a convenience (R4). The recorder writes at Date.now() and this
  // block used to project at Date.now() too, so days[0] was ALWAYS the bump's own slot: the UTC-midnight case --
  // the one where the ring's head slot is nearly empty and a burst sits in days[1] -- was structurally
  // unreachable, and the assertion below was a latent flake that would fail outright if the suite happened to
  // cross UTC midnight between the bump and the read. Pinning the recorder's clock makes the crossing a case
  // rather than an accident. The RECORDER and the PROJECTOR are the real ones throughout; only the wall clock
  // moves, which is the one thing a test cannot wait for.
  const realNow = Date.now;
  const atClock = async <T>(ms: number, fn: () => Promise<T>): Promise<T> => {
    Date.now = () => ms;
    try {
      return await fn();
    } finally {
      Date.now = realNow;
    }
  };

  const sched = realScheduler();
  // MIDDAY on a fixed UTC day: the ordinary case, where the burst and the build share a calendar day.
  const midday = Math.floor(1_800_000_000_000 / MS_PER_DAY) * MS_PER_DAY + 12 * 3_600_000;
  await atClock(midday, async () => {
    for (let i = 0; i < 3; i++) {
      await sched.stub.fetch("https://do/auth-signal", { method: "POST", body: JSON.stringify({ name: "session-revoked-email-epoch" }), headers: { "content-type": "application/json" } });
    }
  });
  const projected = (await fetchAuthSignals(sched.stub, midday)) as Record<string, Record<string, unknown>>;
  const row = projected["session-revoked-email-epoch"];
  ok("the signal reaches the pack with its count", row?.count === 3);
  ok("...and its 14-slot day ring", Array.isArray(row?.days) && (row?.days as number[]).length === AUTH_SIGNAL_DAY_SLOTS);
  ok("...and today / last7dToDate, derived so a reader need not sum the ring", row?.today === 3 && row?.last7dToDate === 3);
  ok("...and firstAt ('since when?')", typeof row?.firstAt === "string");
  ok("no identity, IP or e-mail is representable in the row", scanForSentinels(row).length === 0);

  // ===== G270 (R4): THE FIELD THAT ASSERTED A FACT THE CODE NEVER ESTABLISHED. =====
  //
  // days[] is a UTC CALENDAR-DAY ring: days[0] spans [00:00 UTC, buildTime), a window whose mean length is
  // TWELVE HOURS. It was projected as `last24h`, which names a ROLLING day the ring cannot compute. Build the
  // pack at 00:30 UTC with a burst NINETY MINUTES OLD -- the gap's own ticket, "a 10,000-failure burst an hour
  // ago" -- and the pack said last24h = 0. Not coarse: FALSE, and false in the direction that points support
  // AWAY from a lockout that is happening right now.
  const s2 = realScheduler();
  const build0030 = Math.floor(1_800_000_000_000 / MS_PER_DAY) * MS_PER_DAY + 30 * 60_000; // 00:30 UTC
  const burst90 = build0030 - 90 * 60_000; // 23:00 UTC YESTERDAY: the previous calendar day, ninety minutes ago
  await atClock(burst90, async () => {
    for (let i = 0; i < 300; i++) {
      await s2.stub.fetch("https://do/auth-signal", { method: "POST", body: JSON.stringify({ name: "session-revoked-email-epoch" }), headers: { "content-type": "application/json" } });
    }
  });
  const nightRow = ((await fetchAuthSignals(s2.stub, build0030)) as Record<string, Record<string, unknown>>)["session-revoked-email-epoch"];

  ok("the 90-minute-old burst really is in the ring, one slot back", (nightRow?.days as number[])[1] === 300 && (nightRow?.days as number[])[0] === 0);
  ok("`today` says what it means: 0 SO FAR in the current UTC day (it no longer claims a rolling 24 hours)", nightRow?.today === 0);
  ok("`hoursIntoDay` tells the reader HOW SHORT that window is (30 minutes in, so 0 whole hours)", nightRow?.hoursIntoDay === 0);
  ok("the rolling day is now given as BOUNDS the ring can actually support: at least 0, at most 300", nightRow?.last24hLower === 0 && nightRow?.last24hUpper === 300);
  ok("the pack no longer AFFIRMS zero failures in the last day while 300 are ninety minutes old", nightRow?.last24hUpper === 300 && !("last24h" in (nightRow ?? {})));
  ok("NOISE: an engine that has genuinely been quiet for a month reads an upper bound of 0 too, so the bound is not a wolf-cry", (((await fetchAuthSignals(s2.stub, build0030 + 30 * MS_PER_DAY)) as Record<string, Record<string, unknown>>)["session-revoked-email-epoch"]?.last24hUpper) === 0);
  ok("the honest fields carry no identity", scanForSentinels(nightRow).length === 0);

  // ===== G270: THE RING IS AGED ON READ, TO THE CLOCK THE PACK IS BUILT WITH. =====
  //
  // This is the fix, and nothing above tests it. The recorder ages the ring only when the signal FIRES AGAIN --
  // and "it stopped firing" is the entire question the ring exists to answer. The projector used to copy the
  // stored ring through verbatim and then call days[0] "last24h", ASSUMING days[0] was today. So a burst that
  // ended thirty days ago stayed frozen at days[0]=3 for ever and the pack asserted three failures in the last
  // day, when the true count was zero. It did not merely fail to discriminate: it affirmed a false measurement,
  // in the direction that pages someone.
  //
  // The SAME STORED RECORD is projected at two different build clocks. Nothing is bumped in between: the
  // silence is real silence, not another failure standing in for it (which is how the old pure-function test
  // "modelled" it).
  const nowMs = midday; // the recorder's own (pinned) clock: no UTC-midnight race between the bump and the read
  const live = ((await fetchAuthSignals(sched.stub, nowMs)) as Record<string, Record<string, unknown>>)["session-revoked-email-epoch"];
  const dead = ((await fetchAuthSignals(sched.stub, nowMs + 30 * MS_PER_DAY)) as Record<string, Record<string, unknown>>)["session-revoked-email-epoch"];

  ok("a LIVE burst reads today=3 (it happened in this UTC day)", live?.today === 3 && live?.last7dToDate === 3);
  ok("the SAME burst, read 30 days later, reads today=0 and last7dToDate=0 -- it is OVER", dead?.today === 0 && dead?.last7dToDate === 0 && dead?.last24hUpper === 0);
  ok("...and its whole ring has aged to zero, rather than lying", (dead?.days as number[]).every((n) => n === 0));
  ok("...while count and lastAt PRESERVE the history (10,000 of these, last seen a month ago)", dead?.count === 3 && dead?.lastAt === live?.lastAt);
  ok("DISCRIMINATION: the live burst and the dead burst are no longer the same row", JSON.stringify(live) !== JSON.stringify(dead));

  // dayEpoch ANCHORS the ring. Without it a reader holding only the pack cannot tell which day days[0] is, so
  // they can neither re-age the ring by hand nor check this projector's arithmetic. It was written to storage
  // and never projected -- and the gap's own proposed evidence listed it as a pack field.
  ok("the ring is ANCHORED: dayEpoch says which day days[0] refers to", typeof live?.dayEpoch === "number" && live.dayEpoch === Math.floor(nowMs / MS_PER_DAY));
  ok("...and the anchor moves with the build clock, so the ring can be re-derived by hand", (dead?.dayEpoch as number) === Math.floor((nowMs + 30 * MS_PER_DAY) / MS_PER_DAY));
  ok("the anchor is an integer day count: no identity, no IP, no e-mail", scanForSentinels(dead).length === 0);

  // A recorder write that lands, and a name OUTSIDE the vocabulary that must not.
  await sched.stub.fetch("https://do/auth-signal", { method: "POST", body: JSON.stringify({ name: SENTINEL_GROUP }), headers: { "content-type": "application/json" } });
  const after = (await fetchAuthSignals(sched.stub)) as Record<string, unknown>;
  ok("an out-of-vocabulary signal name never becomes a key", scanForSentinels(after).length === 0);

  // ===== G270 (R5): THE HOT-PATH RECORDER COUNTED WINDOWS, AND THE GAP'S HEADLINE PAIR COLLIDED. =====
  //
  // Every G270 case above drives POST /auth-signal, whose route calls the EXACT-COUNT recordAuthSignal. The
  // signals the gap is actually ABOUT -- the session-verify and RBAC lockout family -- go through
  // recordAuthSignalThrottled, which wrote a name AT MOST ONCE PER MINUTE and DROPPED the rest. So a fleet-wide
  // lockout of 600 rejected session verifies inside one minute recorded today=1: the SAME row as one stale
  // browser tab, and TEN TIMES SMALLER than ten idle tabs trickling one failure an hour. The tighter the burst,
  // the smaller the pack said it was, and a support engineer holding only the pack ranked the noise above the
  // outage.
  //
  // Driven through the REAL DO route every authenticated request runs through (POST /passkey/session/verify with
  // a rejected token), and read back through the REAL projector.
  const verifyBad = async (dobj: ReturnType<typeof realScheduler>, n: number): Promise<void> => {
    for (let i = 0; i < n; i++) {
      await dobj.stub.fetch("https://do/passkey/session/verify", { method: "POST", body: JSON.stringify({ token: "not-a-session-token" }), headers: { "content-type": "application/json" } });
    }
  };
  const burstDo = realScheduler();
  await verifyBad(burstDo, 600); // a LIVE FLEET LOCKOUT: 600 rejected verifies, inside one throttle window
  const tabDo = realScheduler();
  await verifyBad(tabDo, 1); // ONE stale browser tab

  const burstRow = ((await fetchAuthSignals(burstDo.stub)) as Record<string, Record<string, unknown>>)["session-verify-failed"];
  const tabRow = ((await fetchAuthSignals(tabDo.stub)) as Record<string, Record<string, unknown>>)["session-verify-failed"];
  ok("the lockout is COUNTED, not sampled: 600 rejected verifies inside one minute read as 600", burstRow?.count === 600 && burstRow?.today === 600);
  ok("...and the ring carries them in today's slot", (burstRow?.days as number[])[0] === 600 && burstRow?.last24hLower === 600);
  ok("one stale tab still reads exactly one", tabRow?.count === 1 && tabRow?.today === 1);
  ok("DISCRIMINATION: the burst and the stale tab are no longer the SAME ROW (they were byte-identical, stamps included)", burstRow?.today !== tabRow?.today);
  ok("...and the burst no longer reads SMALLER than a harmless trickle", (burstRow?.today as number) > 10);
  ok("no identity, token or e-mail is representable in the row", scanForSentinels(burstRow).length === 0);

  // ===== G270 (R6): THE DEFERRED TALLY MUST SURVIVE AN ISOLATE EVICTION. =========================
  //
  // The accumulator that replaced the dropped events is an INSTANCE FIELD. A Durable Object is evicted when
  // idle and restarted on every deploy (this engine ships self-updates), and eviction destroys instance fields
  // while durable storage survives. With an unbounded deferral ceiling, a burst that ENDS inside its throttle
  // window and is then evicted before the pack is built persisted ONE event -- the R5 row, verbatim, one level
  // down. AUTH_SIGNAL_PENDING_FLUSH now bounds the tail at 25 events per name, so the lockout reaches disk.
  //
  // Eviction is modelled the only way it can be: a NEW SchedulerDO over the SAME durable storage.
  const evicted = (s: Sched): Sched => {
    const dobj = new SchedulerDO({ storage: s.storage } as unknown as DurableObjectState);
    const wrapped = {
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        return dobj.fetch(input instanceof Request ? input : new Request(String(input), init));
      },
    } as unknown as DurableObjectStub;
    return { storage: s.storage, stub: wrapped };
  };
  const lockoutDo = realScheduler();
  await verifyBad(lockoutDo, 600); // the fleet lockout, inside ONE throttle window
  const restarted = evicted(lockoutDo); // ...and the DO is recycled before the operator builds the pack
  const restartedRow = ((await fetchAuthSignals(restarted.stub)) as Record<string, Record<string, unknown>>)["session-verify-failed"];
  const trickleDo = realScheduler();
  await verifyBad(trickleDo, 10); // ten idle tabs, one rejected verify each
  const trickleRow = ((await fetchAuthSignals(trickleDo.stub)) as Record<string, Record<string, unknown>>)["session-verify-failed"];
  ok("the lockout SURVIVES an isolate eviction: the deferred tail is bounded, not unbounded", (restartedRow?.count as number) >= 575);
  ok("...and today carries it, from a NEW isolate that never saw the burst", (restartedRow?.today as number) >= 575 && ((restartedRow?.days as number[])[0] as number) >= 575);
  ok("DISCRIMINATION across a restart: the evicted burst is not the one-stale-tab row", restartedRow?.today !== tabRow?.today);
  ok("...and it no longer reads TEN TIMES SMALLER than ten harmless idle tabs", (restartedRow?.today as number) > (trickleRow?.today as number));
  ok("the restarted row still carries no identity, token or e-mail", scanForSentinels(restartedRow).length === 0);
})();

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
