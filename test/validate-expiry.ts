// Prove the credential and key expiry tracker (contract section 4): the pure projection + threshold
// machinery in engine/src/admin/expiry.ts, and the expiry storage/routes/reconcile in the scheduler
// DO. In-memory doubles only; no network, no deploy, no cost. Run:
//   node test/validate-expiry.ts
//
// Coverage:
//  expiryStatuses: daysRemaining (whole-day floor), state thresholds (ok / approaching <=30 /
//    expired <=0), soonest-first sort, NaN (unparseable) sorts last and reads ok.
//  countWarnings: approaching + expired counted; ok ignored.
//  crossingThreshold / shouldNotifyExpiry: the 30/14/7/1 ladder; first crossing emits; same rung
//    does not re-emit; a strictly lower rung re-emits; a pushed-out expiry clears (null) and never
//    re-emits a higher rung.
//  validateExpiryItem: id/label/kind/expiresAt/source/note boundary checks.
//  DO routes: add/list/delete round-trip via the ExpiryStatus projection; expiry.config re-check
//    (a viewer caller is refused); GET returns computed statuses; reconcile is transition-based with
//    the per-item cooldown and clears on a pushed-out expiry; GET /expiry/warnings count.

import {
  expiryStatuses,
  countWarnings,
  crossingThreshold,
  shouldNotifyExpiry,
  daysRemainingFor,
  validateExpiryItem,
  isExpiryKind,
  laddersFor,
  APPROACHING_DAYS,
  NOTIFY_THRESHOLDS_LONG,
  NOTIFY_THRESHOLDS_SHORT,
  type ExpiryItem,
} from "../src/admin/expiry.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const OWNER_HEADER = encodeCaller(OWNER_CALLER);
// A viewer holds no expiry.config (it is operator/approver/owner), so a viewer caller header lets us
// prove the DO's defence-in-depth capability re-check refuses an unauthorised write.
const VIEWER_CALLER: Caller = { method: "access", email: "v@example.au", subject: "subject-v@example.au", role: "viewer", groups: [] };
const VIEWER_HEADER = encodeCaller(VIEWER_CALLER);

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

// DAY is the ms-per-day used to build expiries a known number of days out from `now`. NOW is captured
// from the REAL clock (not a hardcoded calendar date) on purpose: the DO reconcile path exercised below
// reads the live Date.now(), so anchoring fixtures to a fixed date makes the rung assertions a time bomb
// that breaks once real time drifts past it (e.g. an inDays(12) item falls from rung 14 to rung 7). Taking
// NOW = Date.now() keeps every "N days out" fixture self-relative to the same clock the reconcile uses, so
// the suite is stable on any date. The pure-function tests below pass this NOW explicitly, so they stay
// deterministic regardless.
const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.now();
function inDays(n: number): string {
  return new Date(NOW + n * DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

async function main(): Promise<void> {
  // ---- expiryStatuses: daysRemaining + state ------------------------------------------------
  {
    const items: ExpiryItem[] = [
      { id: "a", label: "S3 key", kind: "credential", expiresAt: inDays(100), source: "manual" },
      { id: "b", label: "Signer", kind: "key", expiresAt: inDays(20), source: "manual" },
      { id: "c", label: "Licence", kind: "licence", expiresAt: inDays(-3), source: "manual" },
      { id: "d", label: "Cert", kind: "certificate", expiresAt: inDays(30), source: "manual" },
    ];
    const statuses = expiryStatuses(items, NOW);
    const byId = new Map(statuses.map((s) => [s.id, s]));
    ok("status: far-future is ok", byId.get("a")?.state === "ok");
    ok("status: far-future daysRemaining is 100", byId.get("a")?.daysRemaining === 100);
    ok("status: 20 days is approaching", byId.get("b")?.state === "approaching");
    ok("status: past expiry is expired", byId.get("c")?.state === "expired");
    ok("status: expired daysRemaining is negative", (byId.get("c")?.daysRemaining ?? 0) < 0);
    ok("status: exactly 30 days is approaching (boundary inclusive)", byId.get("d")?.state === "approaching");
    ok("status: APPROACHING_DAYS is 30", APPROACHING_DAYS === 30);
    // Soonest-first ordering: c (-3) < b (20) < d (30) < a (100).
    ok("status: sorted soonest-first", statuses.map((s) => s.id).join(",") === "c,b,d,a");
    // The projection carries only the redaction-safe fields (no note leak into the status). source is
    // now promoted into the projection so the console can badge an auto-observed item; the operator note
    // is never projected, and tokenRef appears only on an ephemeral cleanup row (item "a" is not one).
    ok("status: shape carries id/label/kind/expiresAt/daysRemaining/source/state only", Object.keys(byId.get("a")!).sort().join(",") === "daysRemaining,expiresAt,id,kind,label,source,state");
  }

  // daysRemainingFor: a whole-day floor and a NaN for an unparseable expiry.
  {
    ok("daysRemainingFor: 29.6 days floors to 29", daysRemainingFor(new Date(NOW + 29.6 * DAY).toISOString(), NOW) === 29);
    ok("daysRemainingFor: unparseable yields NaN", Number.isNaN(daysRemainingFor("not-a-date", NOW)));
  }

  // An unparseable expiry reads ok (never a false expired) and sorts last.
  {
    const items: ExpiryItem[] = [
      { id: "bad", label: "Garbled", kind: "credential", expiresAt: "not-a-date", source: "manual" },
      { id: "good", label: "Soon", kind: "key", expiresAt: inDays(5), source: "manual" },
    ];
    const statuses = expiryStatuses(items, NOW);
    ok("status: unparseable expiry reads ok (no false expired)", statuses.find((s) => s.id === "bad")?.state === "ok");
    ok("status: unparseable sorts last", statuses[statuses.length - 1]?.id === "bad");
  }

  // ---- countWarnings ------------------------------------------------------------------------
  {
    const items: ExpiryItem[] = [
      { id: "ok", label: "Far", kind: "credential", expiresAt: inDays(90), source: "manual" },
      { id: "appr", label: "Soon", kind: "key", expiresAt: inDays(10), source: "manual" },
      { id: "exp", label: "Gone", kind: "licence", expiresAt: inDays(-1), source: "manual" },
    ];
    ok("countWarnings: counts approaching + expired (2), ignores ok", countWarnings(expiryStatuses(items, NOW)) === 2);
    ok("countWarnings: empty is 0", countWarnings([]) === 0);
  }

  // ---- crossingThreshold ladder -------------------------------------------------------------
  {
    ok("ladder: thresholds are 30,14,7,1", NOTIFY_THRESHOLDS_SHORT.join(",") === "30,14,7,1");
    ok("ladder: 40 days -> null (not approaching)", crossingThreshold(40) === null);
    ok("ladder: 30 days -> 30", crossingThreshold(30) === 30);
    ok("ladder: 15 days -> 30", crossingThreshold(15) === 30);
    ok("ladder: 14 days -> 14", crossingThreshold(14) === 14);
    ok("ladder: 8 days -> 14", crossingThreshold(8) === 14);
    ok("ladder: 7 days -> 7", crossingThreshold(7) === 7);
    ok("ladder: 2 days -> 7", crossingThreshold(2) === 7);
    ok("ladder: 1 day -> 1", crossingThreshold(1) === 1);
    ok("ladder: 0 (expired) -> 1", crossingThreshold(0) === 1);
    ok("ladder: -5 (expired) -> 1", crossingThreshold(-5) === 1);
    ok("ladder: NaN -> null", crossingThreshold(Number.NaN) === null);
  }

  // ---- shouldNotifyExpiry transition gate ---------------------------------------------------
  {
    // First crossing at 30 emits.
    ok("transition: first cross to 30 emits 30", shouldNotifyExpiry(28, undefined) === 30);
    // Same rung (already notified at 30, still at 30) does not re-emit.
    ok("transition: same rung 30 does not re-emit", shouldNotifyExpiry(20, 30) === null);
    // A strictly lower rung re-emits (30 -> 14, then 14 -> 7, then 7 -> 1).
    ok("transition: 30 -> 14 re-emits 14", shouldNotifyExpiry(13, 30) === 14);
    ok("transition: 14 -> 7 re-emits 7", shouldNotifyExpiry(6, 14) === 7);
    ok("transition: 7 -> 1 re-emits 1", shouldNotifyExpiry(0, 7) === 1);
    // Already at the lowest rung (1), staying expired does not re-emit.
    ok("transition: lowest rung 1 does not re-emit", shouldNotifyExpiry(-10, 1) === null);
    // Not approaching at all is null regardless of cooldown.
    ok("transition: not approaching is null", shouldNotifyExpiry(60, undefined) === null);
    // A pushed-out expiry (last notified 7, now back at 20 -> rung 30) is a HIGHER rung, not a lower
    // one, so it does not re-emit (the urgency decreased; the cron clears the cooldown separately).
    ok("transition: pushed-out expiry (higher rung than last) does not re-emit", shouldNotifyExpiry(20, 7) === null);
  }

  // ---- validateExpiryItem -------------------------------------------------------------------
  {
    const good = validateExpiryItem({ id: "k1", label: "S3 key", kind: "credential", expiresAt: inDays(10) });
    ok("validate: a good item passes", good.ok === true);
    ok("validate: source defaults to manual when omitted", good.ok === true && good.item.source === "manual");
    ok("validate: note absent when omitted (exactOptional-safe)", good.ok === true && !("note" in good.item));
    ok("validate: bad id rejected", validateExpiryItem({ id: "has spaces", label: "x", kind: "key", expiresAt: inDays(1) }).ok === false);
    ok("validate: empty label rejected", validateExpiryItem({ id: "k", label: "  ", kind: "key", expiresAt: inDays(1) }).ok === false);
    ok("validate: bad kind rejected", validateExpiryItem({ id: "k", label: "x", kind: "nope", expiresAt: inDays(1) }).ok === false);
    ok("validate: unparseable expiresAt rejected", validateExpiryItem({ id: "k", label: "x", kind: "key", expiresAt: "soon" }).ok === false);
    ok("validate: bad source rejected", validateExpiryItem({ id: "k", label: "x", kind: "key", expiresAt: inDays(1), source: "auto" }).ok === false);
    ok("validate: control-char note rejected", validateExpiryItem({ id: "k", label: "x", kind: "key", expiresAt: inDays(1), note: "bad\x00note" }).ok === false);
    const withNote = validateExpiryItem({ id: "k", label: "x", kind: "key", expiresAt: inDays(1), note: "line1\nline2\twith tab" });
    ok("validate: multi-line note (tab + newline) allowed", withNote.ok === true && withNote.item.note === "line1\nline2\twith tab");
  }

  // ---- NEW: token kind, lifecycle class, no-expiry, tiered ladder, decoupled state ----------
  {
    // "token" is a valid kind; lifecycleClass defaults token -> ephemeral, everything else -> functional.
    ok("kind: token is a valid ExpiryKind", isExpiryKind("token"));
    const tok = validateExpiryItem({ id: "att", label: "attach token", kind: "token", source: "observed", noExpiry: true });
    ok("validate: token+observed+noExpiry passes with no date", tok.ok === true);
    ok("validate: token defaults lifecycleClass ephemeral", tok.ok === true && tok.item.lifecycleClass === "ephemeral");
    const cred = validateExpiryItem({ id: "c1", label: "x", kind: "credential", expiresAt: inDays(10) });
    ok("validate: credential defaults lifecycleClass functional", cred.ok === true && cred.item.lifecycleClass === "functional");

    // expiresAt is conditionally required: always for cert/licence; for others unless noExpiry/observed.
    ok("validate: certificate with no date rejected", validateExpiryItem({ id: "ct", label: "cert", kind: "certificate", noExpiry: true }).ok === false);
    ok("validate: licence with no date rejected", validateExpiryItem({ id: "lc", label: "lic", kind: "licence", noExpiry: true }).ok === false);
    ok("validate: credential with no date and no noExpiry rejected", validateExpiryItem({ id: "nx", label: "x", kind: "credential" }).ok === false);
    ok("validate: credential with noExpiry passes (no date)", validateExpiryItem({ id: "nx", label: "x", kind: "credential", noExpiry: true }).ok === true);

    // new field validation: lifecycleClass / usageLink / purpose / permissionSummary / cleanupState.
    ok("validate: bad lifecycleClass rejected", validateExpiryItem({ id: "x", label: "x", kind: "credential", expiresAt: inDays(5), lifecycleClass: "forever" }).ok === false);
    ok("validate: good usageLink accepted", validateExpiryItem({ id: "x", label: "x", kind: "credential", expiresAt: inDays(5), usageLink: { kind: "destination", refId: "dest-1" } }).ok === true);
    ok("validate: bad usageLink.kind rejected", validateExpiryItem({ id: "x", label: "x", kind: "credential", expiresAt: inDays(5), usageLink: { kind: "nope", refId: "dest-1" } }).ok === false);
    ok("validate: over-long purpose rejected", validateExpiryItem({ id: "x", label: "x", kind: "credential", expiresAt: inDays(5), purpose: "p".repeat(201) }).ok === false);
    ok("validate: control-char permissionSummary rejected", validateExpiryItem({ id: "x", label: "x", kind: "credential", expiresAt: inDays(5), permissionSummary: "bad\x07perm" }).ok === false);
    ok("validate: bad cleanupState rejected", validateExpiryItem({ id: "x", label: "x", kind: "token", source: "observed", noExpiry: true, cleanupState: "gone" }).ok === false);
    const eph = validateExpiryItem({ id: "spent", label: "spent token", kind: "token", source: "observed", expiresAt: inDays(2), tokenRef: "abc123def", usedAt: inDays(0), cleanupState: "pending", lifecycleClass: "ephemeral" });
    ok("validate: full ephemeral observed item passes", eph.ok === true && eph.item.cleanupState === "pending" && eph.item.tokenRef === "abc123def");

    // no-expiry status: state "no-expiry" (never ok/green), no daysRemaining, not a warning, sorts last.
    const items: ExpiryItem[] = [
      { id: "ne", label: "Okta OIDC secret", kind: "credential", source: "manual", lifecycleClass: "functional" }, // no expiresAt
      { id: "soon", label: "SAML cert", kind: "certificate", expiresAt: inDays(5), source: "observed", lifecycleClass: "functional" },
    ];
    const st = expiryStatuses(items, NOW);
    const ne = st.find((s) => s.id === "ne");
    ok("status: no-expiry item reads state no-expiry", ne?.state === "no-expiry");
    ok("status: no-expiry item has no daysRemaining", ne !== undefined && ne.daysRemaining === undefined);
    ok("status: no-expiry projects source", ne?.source === "manual");
    ok("status: no-expiry sorts last (least urgent)", st[st.length - 1]?.id === "ne");
    ok("countWarnings: no-expiry is not a warning (only the 5-day cert counts)", countWarnings(st) === 1);

    // tiered ladder: cert/licence -> LONG [60,...]; everything else -> SHORT [30,...]; default is SHORT.
    ok("ladder: LONG is 60,30,14,7,1", NOTIFY_THRESHOLDS_LONG.join(",") === "60,30,14,7,1");
    ok("ladder: SHORT is 30,14,7,1", NOTIFY_THRESHOLDS_SHORT.join(",") === "30,14,7,1");
    ok("ladder: laddersFor(certificate) is LONG", laddersFor("certificate") === NOTIFY_THRESHOLDS_LONG);
    ok("ladder: laddersFor(licence) is LONG", laddersFor("licence") === NOTIFY_THRESHOLDS_LONG);
    ok("ladder: laddersFor(credential) is SHORT", laddersFor("credential") === NOTIFY_THRESHOLDS_SHORT);
    ok("ladder: laddersFor(token) is SHORT", laddersFor("token") === NOTIFY_THRESHOLDS_SHORT);
    ok("ladder: 45 days on LONG -> 60", crossingThreshold(45, NOTIFY_THRESHOLDS_LONG) === 60);
    ok("ladder: 45 days on SHORT -> null", crossingThreshold(45, NOTIFY_THRESHOLDS_SHORT) === null);
    ok("ladder: 45 days default (SHORT) -> null", crossingThreshold(45) === null);

    // DECOUPLED state: a functional cert at 45 days alerts at the 60 rung but reads "ok" (coarse 30).
    const cert45 = expiryStatuses([{ id: "c45", label: "Cert", kind: "certificate", expiresAt: inDays(45), source: "observed" }], NOW)[0];
    ok("decoupled: cert at 45 days reads state ok (APPROACHING stays 30 for all kinds)", cert45?.state === "ok");
    ok("decoupled: APPROACHING_DAYS is still 30", APPROACHING_DAYS === 30);
    ok("decoupled: but the LONG ladder would alert it at the 60 rung", crossingThreshold(45, laddersFor("certificate")) === 60);

    // emit-once-per-newly-crossed-rung on the LONG ladder (the property is ladder-length independent).
    const L = NOTIFY_THRESHOLDS_LONG;
    ok("LONG transition: first cross to 60 emits 60", shouldNotifyExpiry(55, undefined, L) === 60);
    ok("LONG transition: same rung 60 does not re-emit", shouldNotifyExpiry(40, 60, L) === null);
    ok("LONG transition: 60 -> 30 re-emits 30", shouldNotifyExpiry(25, 60, L) === 30);
    ok("LONG transition: 30 -> 14 re-emits 14", shouldNotifyExpiry(13, 30, L) === 14);
    ok("LONG transition: not approaching (70) is null", shouldNotifyExpiry(70, undefined, L) === null);
  }

  // ---- DO routes: add / list / delete via the ExpiryStatus projection -----------------------
  {
    const { stub, storage } = makeScheduler();
    // A viewer cannot write (DO defence-in-depth capability re-check refuses; an authz refusal -> 403, 037-03).
    const denied = await fetchDO(stub, "POST", "/expiry", { id: "x", label: "x", kind: "key", expiresAt: inDays(10) }, VIEWER_HEADER);
    ok("route: viewer write refused (403)", denied.status === 403);

    // An owner can add.
    const added = await fetchDO(stub, "POST", "/expiry", { id: "s3", label: "S3 destination access key", kind: "credential", expiresAt: inDays(12) }, OWNER_HEADER);
    ok("route: owner add 200", added.status === 200);
    const item = (await added.json()) as ExpiryItem;
    ok("route: add echoes the stored item", item.id === "s3" && item.label === "S3 destination access key");
    ok("route: stored under expiry:<id>", storage.has("expiry:s3"));

    // GET returns the COMPUTED ExpiryStatus[] (daysRemaining + state), not the raw item.
    const listResp = await fetchDO(stub, "GET", "/expiry", undefined, OWNER_HEADER);
    const statuses = (await listResp.json()) as Array<{ id: string; daysRemaining: number; state: string; label: string }>;
    ok("route: GET returns computed statuses", Array.isArray(statuses) && statuses.length === 1);
    ok("route: GET status carries daysRemaining + state", typeof statuses[0]?.daysRemaining === "number" && statuses[0]?.state === "approaching");

    // Add a second item and confirm GET sorts soonest-first.
    await fetchDO(stub, "POST", "/expiry", { id: "sooner", label: "Cert", kind: "certificate", expiresAt: inDays(3) }, OWNER_HEADER);
    const list2 = (await (await fetchDO(stub, "GET", "/expiry")).json()) as Array<{ id: string }>;
    ok("route: GET sorted soonest-first (sooner before s3)", list2[0]?.id === "sooner" && list2[1]?.id === "s3");

    // GET /expiry/warnings counts approaching + expired (both items are within 30 days -> 2).
    const warn = (await (await fetchDO(stub, "GET", "/expiry/warnings")).json()) as { expiryWarnings: number };
    ok("route: GET /expiry/warnings counts 2", warn.expiryWarnings === 2);

    // Delete one (owner), idempotent on the second delete.
    const del = (await (await fetchDO(stub, "POST", "/expiry/delete", { id: "s3" }, OWNER_HEADER)).json()) as { deleted: boolean };
    ok("route: delete returns deleted:true", del.deleted === true);
    ok("route: deleted item gone from storage", !storage.has("expiry:s3"));
    const del2 = (await (await fetchDO(stub, "POST", "/expiry/delete", { id: "s3" }, OWNER_HEADER)).json()) as { deleted: boolean };
    ok("route: delete is idempotent (deleted:false the second time)", del2.deleted === false);

    // NOTE CARRY-FORWARD on a manual edit (the operator note is write-only and never returned, so an
    // edit that leaves the note blank cannot resend it; a re-add must not silently drop the stored note).
    await fetchDO(stub, "POST", "/expiry", { id: "note-keep", label: "API key", kind: "credential", expiresAt: inDays(20), note: "rotate via the vendor console" }, OWNER_HEADER);
    ok("route: add stores the operator note", (storage.rawGet<ExpiryItem>("expiry:note-keep"))?.note === "rotate via the vendor console");
    // Re-add the SAME id WITHOUT a note (the console omits a blank note); the stored note must survive.
    await fetchDO(stub, "POST", "/expiry", { id: "note-keep", label: "API key (renamed)", kind: "credential", expiresAt: inDays(45) }, OWNER_HEADER);
    const edited = storage.rawGet<ExpiryItem>("expiry:note-keep");
    ok("route: a blank-note edit KEEPS the stored note (not cleared)", edited?.note === "rotate via the vendor console");
    ok("route: the edit still applies its other changes", edited?.label === "API key (renamed)");
    // A brand-new item with no note has none (nothing to carry forward).
    await fetchDO(stub, "POST", "/expiry", { id: "note-none", label: "New key", kind: "credential", expiresAt: inDays(30) }, OWNER_HEADER);
    ok("route: a new item with no note has none", !("note" in (storage.rawGet<ExpiryItem>("expiry:note-none") ?? {})));
    // A viewer cannot delete either.
    const delDenied = await fetchDO(stub, "POST", "/expiry/delete", { id: "sooner" }, VIEWER_HEADER);
    ok("route: viewer delete refused (403)", delDenied.status === 403);
  }

  // ---- DO reconcile: transition-based with the per-item cooldown -----------------------------
  {
    const { stub, storage } = makeScheduler();
    // An item 12 days out (rung 14). First reconcile emits once.
    await fetchDO(stub, "POST", "/expiry", { id: "cred", label: "API token", kind: "credential", expiresAt: inDays(12) }, OWNER_HEADER);
    const r1 = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: Array<{ id: string; detail: string }> };
    ok("reconcile: first run emits once for the approaching item", r1.emissions.length === 1 && r1.emissions[0]?.id === "cred");
    ok("reconcile: detail is the label + days-remaining (redaction-safe)", /API token expires in \d+ days/.test(r1.emissions[0]?.detail ?? ""));
    ok("reconcile: a cooldown was recorded at rung 14", storage.rawGet<{ threshold: number }>("expiry-cooldown:cred")?.threshold === 14);

    // A SECOND reconcile at the same rung (still ~12 days; the stored expiry has not changed and the
    // cooldown is at 14) does NOT re-emit.
    const r2 = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: unknown[] };
    ok("reconcile: same rung does not re-emit", r2.emissions.length === 0);

    // Move the expiry to 5 days out (rung 7, strictly lower than 14): re-emit.
    await fetchDO(stub, "POST", "/expiry", { id: "cred", label: "API token", kind: "credential", expiresAt: inDays(5) }, OWNER_HEADER);
    const r3 = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: Array<{ id: string }> };
    ok("reconcile: a lower rung (14 -> 7) re-emits", r3.emissions.length === 1 && r3.emissions[0]?.id === "cred");
    ok("reconcile: cooldown moved to rung 7", storage.rawGet<{ threshold: number }>("expiry-cooldown:cred")?.threshold === 7);

    // Push the expiry far out (90 days, not approaching): no emit, AND the cooldown is cleared so a
    // future descent alerts from the top of the ladder again.
    await fetchDO(stub, "POST", "/expiry", { id: "cred", label: "API token", kind: "credential", expiresAt: inDays(90) }, OWNER_HEADER);
    const r4 = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: unknown[] };
    ok("reconcile: pushed-out expiry does not emit", r4.emissions.length === 0);
    ok("reconcile: cooldown cleared when no longer approaching", !storage.has("expiry-cooldown:cred"));

    // An EXPIRED item (past) emits at rung 1 with an "has expired" detail on first crossing.
    await fetchDO(stub, "POST", "/expiry", { id: "old", label: "Old cert", kind: "certificate", expiresAt: inDays(-2) }, OWNER_HEADER);
    const r5 = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: Array<{ id: string; detail: string }> };
    const oldEm = r5.emissions.find((e) => e.id === "old");
    ok("reconcile: an expired item emits at rung 1", oldEm !== undefined && /Old cert has expired/.test(oldEm.detail));
    ok("reconcile: expired cooldown is rung 1", storage.rawGet<{ threshold: number }>("expiry-cooldown:old")?.threshold === 1);
  }

  // ---- DO reconcile: kind-aware ladder (certificate/licence use the 60-day first rung) -------
  {
    const { stub, storage } = makeScheduler();
    // A CERTIFICATE 45 days out is NOT "approaching" (coarse boundary stays 30) but the cert ladder's
    // first rung is 60, so reconcile emits ONCE at rung 60 — proving the kind-aware ladder is wired
    // end-to-end through the DO, not just in the pure functions.
    await fetchDO(stub, "POST", "/expiry", { id: "cert45", label: "SAML cert", kind: "certificate", expiresAt: inDays(45) }, OWNER_HEADER);
    const rc = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: Array<{ id: string }> };
    ok("reconcile: a certificate at 45 days emits at the 60 rung (kind-aware)", rc.emissions.length === 1 && rc.emissions[0]?.id === "cert45");
    ok("reconcile: cert cooldown recorded at rung 60", storage.rawGet<{ threshold: number }>("expiry-cooldown:cert45")?.threshold === 60);
    // A CREDENTIAL at 45 days (short ladder, first rung 30) does NOT emit yet.
    await fetchDO(stub, "POST", "/expiry", { id: "cred45", label: "API key", kind: "credential", expiresAt: inDays(45) }, OWNER_HEADER);
    const rc2 = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: Array<{ id: string }> };
    ok("reconcile: a credential at 45 days does NOT emit (short ladder)", rc2.emissions.find((e) => e.id === "cred45") === undefined);
  }

  // ---- DO reconcile: empty tracker is a near no-op ------------------------------------------
  {
    const { stub } = makeScheduler();
    const r = (await (await fetchDO(stub, "POST", "/expiry/reconcile")).json()) as { emissions: unknown[] };
    ok("reconcile: no items -> no emissions", r.emissions.length === 0);
  }

  // ---- DO: ephemeral attach-token observe + cleanup attestation (credential lifecycle, Phase 3b) ----
  {
    const { stub, storage } = makeScheduler();
    // observe-attach is INTERNAL (no caller): it records a pending ephemeral cleanup row from redaction-
    // safe facts ONLY (the PUBLIC token id, expires_on, a permission summary, the attached names) — never
    // a token value. The row id is keyed by the token id so a re-attach refreshes the same row.
    await fetchDO(stub, "POST", "/expiry/observe-attach", { tokenId: "abc123def456", expiresOn: inDays(20), permissionSummary: "Workers Scripts, R2", sourcesAttached: ["SRC_KV_uploads", "SRC_R2_archive"] });
    const rawAtt = storage.rawGet<ExpiryItem>("expiry:attach-token-abc123def456");
    ok("observe-attach: pending ephemeral token row created", rawAtt?.kind === "token" && rawAtt?.lifecycleClass === "ephemeral" && rawAtt?.cleanupState === "pending");
    ok("observe-attach: source observed; PUBLIC token id stored as tokenRef (never a value)", rawAtt?.source === "observed" && rawAtt?.tokenRef === "abc123def456");
    ok("observe-attach: purpose names the attached sources", typeof rawAtt?.purpose === "string" && rawAtt.purpose.includes("SRC_KV_uploads"));
    // The computed list surfaces cleanupState + tokenRef (for the console's cleanup affordance).
    const attList = (await (await fetchDO(stub, "GET", "/expiry", undefined, OWNER_HEADER)).json()) as Array<{ id: string; cleanupState?: string; tokenRef?: string }>;
    const attRow = attList.find((s) => s.id === "attach-token-abc123def456");
    ok("observe-attach: GET surfaces cleanupState + tokenRef on the cleanup row", attRow?.cleanupState === "pending" && attRow?.tokenRef === "abc123def456");
    // cleanup-attest is gated: a viewer is refused.
    const cuDenied = await fetchDO(stub, "POST", "/expiry/cleanup-attest", { id: "attach-token-abc123def456" }, VIEWER_HEADER);
    ok("cleanup-attest: viewer refused (403)", cuDenied.status === 403);
    // An owner attests deletion -> cleanupState flips to attested-deleted (an ATTESTATION, not verified).
    const attested = (await (await fetchDO(stub, "POST", "/expiry/cleanup-attest", { id: "attach-token-abc123def456" }, OWNER_HEADER)).json()) as { updated: boolean };
    ok("cleanup-attest: owner attestation succeeds", attested.updated === true);
    ok("cleanup-attest: cleanupState is now attested-deleted", storage.rawGet<ExpiryItem>("expiry:attach-token-abc123def456")?.cleanupState === "attested-deleted");
    // Attesting an absent item is an idempotent no-op.
    const cuNoop = (await (await fetchDO(stub, "POST", "/expiry/cleanup-attest", { id: "nope" }, OWNER_HEADER)).json()) as { updated: boolean };
    ok("cleanup-attest: absent item is a no-op", cuNoop.updated === false);
    // A user-owned token (verify returns no id) gets a fallback id, carries NO tokenRef, and reads no-expiry.
    await fetchDO(stub, "POST", "/expiry/observe-attach", { permissionSummary: "Workers Scripts", sourcesAttached: ["SRC_KV_x"] });
    const allAtt = (await (await fetchDO(stub, "GET", "/expiry", undefined, OWNER_HEADER)).json()) as Array<{ id: string; tokenRef?: string; state: string; cleanupState?: string }>;
    const userOwned = allAtt.find((s) => s.id.startsWith("attach-token-") && s.id !== "attach-token-abc123def456");
    ok("observe-attach: user-owned token uses a fallback id, no tokenRef, no-expiry state", userOwned !== undefined && userOwned.tokenRef === undefined && userOwned.state === "no-expiry" && userOwned.cleanupState === "pending");
  }

  console.log(failures === 0 ? "\nEXPIRY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
