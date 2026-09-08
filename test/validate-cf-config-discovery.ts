// Validates the cf-config DISCOVERY read-cost control: the probe's present/empty/unavailable
// classification, the effective-selector logic (auto captures the discovered present set; manual and
// stale/absent fail-safe), and the staleness predicate the daily cron pass uses.

import { probeCfConfig, effectiveCfConfigSelector, discoveryIsStale, resolveCfConfigMode, DISCOVERY_MAX_AGE_MS } from "../src/sources/cf-config-discovery.ts";
import { CF_CONFIG_IDENTITY_ID, CfPaginationTruncated, CfApiError, isCfPlanEntitlementError, type CfConfigSurface } from "../src/sources/cf-config-surfaces.ts";
import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { coarseCfReason, decodeConfigSnapshot } from "../src/admin/restore-cfconfig.ts";
import { readSourceFaultLedger, resetSourceFaultLedger } from "../src/sources/source-fault-ledger.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import type { CfConfigDiscovery } from "../src/sched/types.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
const eq = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

console.log("-- isCfPlanEntitlementError: CONSERVATIVE — only a DEFINITIVE plan gate is gated; ANY ambiguity stays actionable --");
// DEFINITIVE entitlement -> gated (true). These are the Cloudflare-verified plan/entitlement signals.
ok("entitlement CODE 50002 (rulesets phase, Enterprise-only) -> gated", isCfPlanEntitlementError(400, [50002], ["not entitled to use the phase http_request_firewall_custom"]));
ok("entitlement CODE 10015 (workers not_entitled) -> gated", isCfPlanEntitlementError(403, [10015], ["workers.api.error.not_entitled"]));
ok("entitlement CODE 10016 (firewall access rules not_entitled) -> gated", isCfPlanEntitlementError(403, [10016], ["firewallaccessrules.api.not_entitled.country_block"]));
ok("entitlement MESSAGE 'not entitled' with an UNKNOWN code -> gated (message is the complete signal)", isCfPlanEntitlementError(403, [49999], ["origin.host is not entitled on this plan"]));
ok("entitlement MESSAGE 'not_entitled' with NO code -> gated", isCfPlanEntitlementError(409, [], ["something.api.not_entitled.feature"]));
// The CONSERVATIVE direction — ANY ambiguity MUST stay `unavailable` (false), because a wrong `true` would
// HIDE a real token-scope gap (a silent miss). Prove the actionable/ambiguous cases are NOT gated:
ok("token-scope 403 code 9109 'Unauthorized to access requested resource' -> NOT gated (actionable)", !isCfPlanEntitlementError(403, [9109], ["Unauthorized to access requested resource"]));
ok("auth 403 code 10000 'Authentication error' -> NOT gated (actionable)", !isCfPlanEntitlementError(403, [10000], ["Authentication error"]));
ok("a BARE 403 with no code and no entitlement message -> NOT gated (could be token-scope)", !isCfPlanEntitlementError(403, [], ["HTTP 403"]));
ok("a 5xx server error is transient -> NOT gated EVEN IF the body says 'not entitled'", !isCfPlanEntitlementError(503, [50002], ["not entitled to use the phase"]));
ok("a 429 throttle is transient -> NOT gated even with an entitlement code", !isCfPlanEntitlementError(429, [50002], ["not entitled"]));
ok("an unrecognised 'forbidden' message -> NOT gated", !isCfPlanEntitlementError(403, [], ["forbidden"]));
ok("a permission message 'insufficient permissions' -> NOT gated (actionable token-scope class)", !isCfPlanEntitlementError(403, [], ["insufficient permissions to read this resource"]));
ok("a permission message 'token does not have permission' -> NOT gated", !isCfPlanEntitlementError(403, [9109], ["The given API token does not have permission to access this zone"]));

console.log("\n-- probeCfConfig classifies each surface by outcome --");
// Stub surfaces whose read ignores the api and returns canned data / empty / throws, so classification
// is exercised without any network (the same fail-open contract the real reads have).
const stubSurfaces: CfConfigSurface[] = [
  { id: "has-data", scope: "account", restoreTier: "idempotent", read: async () => [{ x: 1 }] },
  { id: "single-object", scope: "account", restoreTier: "idempotent", read: async () => ({ enabled: true }) },
  { id: "empty-list", scope: "account", restoreTier: "idempotent", read: async () => [] },
  { id: "empty-object", scope: "account", restoreTier: "idempotent", read: async () => ({}) },
  { id: "null-value", scope: "account", restoreTier: "idempotent", read: async () => null },
  { id: "errored", scope: "account", restoreTier: "idempotent", read: async () => { throw new Error("Cloudflare API GET: 403 no plan"); } },
  // A DEFINITIVE plan/entitlement gate (CfApiError with the verdict already computed) -> gated (benign).
  { id: "plan-gated", scope: "account", restoreTier: "idempotent", read: async () => { throw new CfApiError("Cloudflare API GET /accounts/x/rulesets: not entitled to use the phase", 400, [50002], true); } },
  // A token-scope CfApiError (verdict false) -> unavailable (actionable), proving the conservative split routes
  // a permission gap AWAY from the benign bucket — the whole point of the fix is to never hide this.
  { id: "token-scope", scope: "account", restoreTier: "idempotent", read: async () => { throw new CfApiError("Cloudflare API GET /accounts/x/foo: Unauthorized to access requested resource", 403, [9109], false); } },
  { id: "truncated", scope: "account", restoreTier: "idempotent", read: async () => { throw new CfPaginationTruncated(1000, 1000); } },
  { id: "zone-only", scope: "zone", restoreTier: "idempotent", read: async () => [{ y: 2 }] },
];

const d = await probeCfConfig("tok", "acct", undefined, 1_000, { surfaces: stubSurfaces, fetchImpl: (async () => new Response("{}")) as typeof fetch, concurrency: 3 });
ok("present = surfaces with real data + truncated partials", eq(d.present, ["has-data", "single-object", "truncated"]));
ok("empty = []/{}/null", eq(d.empty, ["empty-object", "empty-list", "null-value"].sort()));
ok("gated = a DEFINITIVE plan/entitlement gate ONLY", eq(d.gated, ["plan-gated"]));
ok("unavailable = a plain errored read + a token-scope CfApiError (the conservative/actionable bucket)", eq(d.unavailable, ["errored", "token-scope"]));
ok("a token-scope gap is NOT routed to the benign gated bucket (no silent miss)", !d.gated.includes("token-scope"));
ok("zone-scoped surface skipped when no zoneId configured", !d.present.includes("zone-only") && !d.empty.includes("zone-only") && !d.gated.includes("zone-only") && !d.unavailable.includes("zone-only"));
ok("probe stamps the time it was given", d.at === 1_000);

const dz = await probeCfConfig("tok", "acct", "zone1", 2_000, { surfaces: stubSurfaces, fetchImpl: (async () => new Response("{}")) as typeof fetch });
ok("zone-scoped surface included when a zone IS configured", dz.present.includes("zone-only"));

console.log("\n-- resolveCfConfigMode: explicit wins; absent derives from include (backward-compat) --");
ok("explicit auto wins", resolveCfConfigMode({ cfConfigMode: "auto", include: ["dns"] }) === "auto");
ok("explicit manual wins", resolveCfConfigMode({ cfConfigMode: "manual", include: [] }) === "manual");
ok("absent + empty include -> auto (= all, gets the optimisation)", resolveCfConfigMode({ include: [] }) === "auto");
ok("absent + NON-empty include -> manual (operator's explicit pick is never broadened)", resolveCfConfigMode({ include: ["dns", "rulesets"] }) === "manual");

console.log("\n-- effectiveCfConfigSelector: auto captures present, manual/stale fail-safe --");
const fresh: CfConfigDiscovery = { at: 10_000, present: ["dns", "rulesets"], empty: ["spectrum-apps"], gated: ["account-waf"], unavailable: ["magic"] };
const src = (cfConfigMode?: "auto" | "manual", include: string[] = ["dns", "zone-settings"]) => ({ ...(cfConfigMode ? { cfConfigMode } : {}), include, exclude: ["filters"] });
// A registry that holds exactly the surfaces the fresh fixture classified, so the union of newly-
// registered surfaces is empty on these vectors (the present-set logic is isolated from the registry).
const mkSurface = (id: string): CfConfigSurface => ({ id, scope: "account", restoreTier: "idempotent", read: async () => null });
const fixtureSurfaces: CfConfigSurface[] = ["dns", "rulesets", "spectrum-apps", "magic"].map(mkSurface);

ok("manual mode -> operator include/exclude unchanged", eq(effectiveCfConfigSelector(src("manual"), fresh, 10_000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: ["dns", "zone-settings"], exclude: ["filters"] }));
ok(
  "auto + fresh discovery -> capture the present set (operator exclude kept), UNAVAILABLE carried as notAttempted",
  eq(effectiveCfConfigSelector(src("auto"), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: ["dns", "rulesets"], exclude: ["filters"], notAttempted: ["magic"] }),
);
ok("auto + NO discovery -> fail-safe to source include (usually [] = all)", eq(effectiveCfConfigSelector(src("auto", []), undefined, 10_000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: [], exclude: ["filters"] }));
ok("auto + STALE discovery -> fail-safe to source include", eq(effectiveCfConfigSelector(src("auto"), fresh, 10_000 + DISCOVERY_MAX_AGE_MS + 1, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: ["dns", "zone-settings"], exclude: ["filters"] }));
ok(
  "absent mode + empty include -> auto -> present set + notAttempted",
  eq(effectiveCfConfigSelector(src(undefined, []), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: ["dns", "rulesets"], exclude: ["filters"], notAttempted: ["magic"] }),
);
ok("absent mode + NON-empty include -> MANUAL -> explicit selection NOT broadened", eq(effectiveCfConfigSelector(src(undefined), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: ["dns", "zone-settings"], exclude: ["filters"] }));

console.log("\n-- G234: auto mode ACCOUNTS for the unavailable partition, and ONLY for it --");
// The whole defect: auto mode narrowed on the discovery cache and dropped the UNAVAILABLE surfaces out of
// the include set, and the crawl then skipped them before its attempted counter -- no record, no marker, no
// run-level count. `notAttempted` is what carries them to the crawl. The negative direction matters just as
// much: an EMPTY surface (the account does not use the product) and a GATED one (its plan does not include
// the product) are evidence of ABSENCE and MUST stay silent, or the fix would turn "you do not use this"
// into "we could not read this" on every run.
const g234 = effectiveCfConfigSelector(src("auto"), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces);
ok("the UNAVAILABLE surface is named in notAttempted (it was dropped because it could not be READ)", eq(g234.notAttempted, ["magic"]));
ok("it is NOT smuggled back into include (auto mode still does not spend the read)", !g234.include.includes("magic"));
ok("an EMPTY surface is NOT in notAttempted (nothing to lose, stays silent)", !(g234.notAttempted ?? []).includes("spectrum-apps"));
const gatedSel = effectiveCfConfigSelector(src("auto"), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, [...fixtureSurfaces, mkSurface("account-waf")]);
ok("a GATED surface is NOT in notAttempted (a definitive plan gate is benign, like empty)", !(gatedSel.notAttempted ?? []).includes("account-waf"));
// An operator who explicitly EXCLUDED a surface asked for it to be out of scope; a marker for it would be
// noise, not honesty. Prove exclude still wins over the unavailable partition.
const excludedMagic = effectiveCfConfigSelector({ cfConfigMode: "auto", include: [], exclude: ["magic"] }, fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces);
ok("an operator EXCLUDE still wins over the unavailable partition (no marker for a surface they excluded)", excludedMagic.notAttempted === undefined);
// A discovery with NOTHING unavailable must leave the field off entirely, so a healthy account's selector is
// byte-identical to what it was before this change.
const cleanDiscovery: CfConfigDiscovery = { at: 10_000, present: ["dns"], empty: ["rulesets", "spectrum-apps", "magic"], gated: [], unavailable: [] };
ok("no unavailable surfaces -> the field is ABSENT (a healthy account's selector is unchanged)", eq(effectiveCfConfigSelector(src("auto"), cleanDiscovery, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces), { include: ["dns"], exclude: ["filters"] }));
ok("manual mode never carries notAttempted (nothing was dropped on our initiative)", effectiveCfConfigSelector(src("manual"), fresh, 10_000, DISCOVERY_MAX_AGE_MS, fixtureSurfaces).notAttempted === undefined);
ok("a STALE cache fail-safes to ALL surfaces and carries no notAttempted (nothing is being skipped)", effectiveCfConfigSelector(src("auto"), fresh, 10_000 + DISCOVERY_MAX_AGE_MS + 1, DISCOVERY_MAX_AGE_MS, fixtureSurfaces).notAttempted === undefined);

console.log("\n-- effectiveCfConfigSelector: a newly-REGISTERED surface fails safe to captured (eng-m1) --");
// A registry that gained a surface ("workers-for-platforms") AFTER the fresh discovery ran: it is in
// none of the present/empty/unavailable partitions, so an auto-mode run must still capture it until the
// next discovery classifies it (the no-silent-drop invariant), unioned into the present set in order.
const grownSurfaces: CfConfigSurface[] = [...fixtureSurfaces, mkSurface("workers-for-platforms")];
ok(
  "auto + fresh discovery + a newly-registered surface -> present set UNION the new surface (sorted)",
  eq(effectiveCfConfigSelector(src("auto"), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, grownSurfaces), { include: ["dns", "rulesets", "workers-for-platforms"], exclude: ["filters"], notAttempted: ["magic"] }),
);
ok(
  "manual mode ignores the newly-registered surface (operator selection never broadened)",
  eq(effectiveCfConfigSelector(src("manual"), fresh, 10_000, DISCOVERY_MAX_AGE_MS, grownSurfaces), { include: ["dns", "zone-settings"], exclude: ["filters"] }),
);

// A GATED surface (fresh.gated = ["account-waf"]) is CLASSIFIED, so it counts as "known": when it is in the
// registry it must NOT be treated as a newly-registered surface and force-captured — it stays skipped. With
// "account-waf" (gated) AND "workers-for-platforms" (truly new, in NO partition) both in the registry, only
// the truly-new one is unioned into the present set; the gated one is recognised and left out.
const grownWithGated: CfConfigSurface[] = [...fixtureSurfaces, mkSurface("workers-for-platforms"), mkSurface("account-waf")];
ok(
  "auto + fresh: a GATED surface is known (not force-captured) — only the truly-new surface is unioned into present",
  eq(effectiveCfConfigSelector(src("auto"), fresh, 10_000 + 1000, DISCOVERY_MAX_AGE_MS, grownWithGated), { include: ["dns", "rulesets", "workers-for-platforms"], exclude: ["filters"], notAttempted: ["magic"] }),
);

console.log("\n-- G234 END TO END: probe -> auto selector -> the REAL crawl, both directions --");
// This is the whole defect driven through the real path, with no network: the discovery probe classifies
// three stub surfaces, the auto-mode selector narrows on that cache, and the REAL CloudflareConfigSource
// crawls with the selector auto mode actually computes. Against a real engine, the refused
// surface produced no record, no marker and no run-level count; the two assertions below that name it are
// the ones that fail there. The empty surface's assertion is the other direction: it must STILL produce
// nothing, so the fix does not restate "you do not use this product" as "we could not read this".
const e2eSurfaces: CfConfigSurface[] = [
  { id: "in-use", scope: "account", restoreTier: "idempotent", read: async () => [{ name: "a" }] },
  { id: "not-used", scope: "account", restoreTier: "idempotent", read: async () => [] },
  { id: "refused", scope: "account", restoreTier: "idempotent", read: async () => { throw new CfApiError("Cloudflare API GET /zones/z/pagerules: Page Rules endpoint does not support account owned tokens", 400, [1011], false); } },
];
const e2eFetch = (async () => new Response("{}")) as typeof fetch;
const e2eDiscovery = await probeCfConfig("tok", "acct", undefined, 50_000, { surfaces: e2eSurfaces, fetchImpl: e2eFetch });
ok("probe: the readable surface is present", eq(e2eDiscovery.present, ["in-use"]));
ok("probe: the definitively-empty surface is empty", eq(e2eDiscovery.empty, ["not-used"]));
ok("probe: the refused read is unavailable, not gated (CF code 1011 is not an entitlement gate)", eq(e2eDiscovery.unavailable, ["refused"]) && eq(e2eDiscovery.gated, []));

const e2eSelector = effectiveCfConfigSelector({ cfConfigMode: "auto", include: [], exclude: [] }, e2eDiscovery, 50_000 + 1000, DISCOVERY_MAX_AGE_MS, e2eSurfaces);
resetSourceFaultLedger();
const e2eRecords: SourceRecord[] = [];
for await (const ev of new CloudflareConfigSource("tok", "acct", undefined, e2eSurfaces, e2eFetch).crawlFrom(e2eSelector, null)) {
  if (ev.kind === "record" && ev.record.name !== CF_CONFIG_IDENTITY_ID) e2eRecords.push(ev.record);
}
const byName = new Map(e2eRecords.map((r) => [r.name, r]));
const decode = (r: SourceRecord | undefined) => (r === undefined ? undefined : (JSON.parse(new TextDecoder().decode(r.value!)) as Record<string, unknown>));

ok("the surface in use is captured for real", eq(decode(byName.get("in-use")), [{ name: "a" }]) && byName.get("in-use")?.markerKind === undefined);
// THE FIX, archive half. Against origin/main byName has no "refused" entry at all.
ok("the REFUSED surface produces a record in the archive (it did not just vanish)", byName.has("refused"));
ok("that record is an _unavailable marker the restore path already refuses to diff", byName.get("refused")?.markerKind === "_unavailable" && "_unavailable" in (decode(byName.get("refused")) ?? {}));
ok("the marker says it was NOT ATTEMPTED, so a reader years later can tell it from a refused read", decode(byName.get("refused"))?.notAttempted === true);
ok("its reason is the closed 'not-attempted' class, not a status this run never measured", byName.get("refused")?.markerReason === "not-attempted");
// THE OTHER DIRECTION. An empty surface must still be silent: no record, no marker, nothing to alarm about.
ok("the genuinely EMPTY surface still produces NO record (unchanged behaviour)", !byName.has("not-used"));
ok("exactly two surface records: the captured one and the marker", e2eRecords.length === 2);

// THE FIX, run half. The seal folds markerKind into recordsIncomplete/incompleteByMarker/incompleteIds, and
// the adapter files the reason + the surface id in the fault ledger the support pack carries.
const e2eLedger = readSourceFaultLedger();
ok("the run's fault ledger counts the shortfall under _unavailable/not-attempted", e2eLedger.incompleteReasons._unavailable?.["not-attempted"] === 1);
ok("and NAMES the surface (a closed-registry product token, carried raw)", eq(e2eLedger.incompleteIds._unavailable, ["refused"]));
ok("the empty surface is nowhere in the ledger", !JSON.stringify(e2eLedger).includes("not-used"));

// A RESUME must not lose the marker or re-read anything: resuming from the captured surface's watermark
// still emits the marker, because the marker sits in the same stable registry order as a read surface.
const resumed: string[] = [];
for await (const ev of new CloudflareConfigSource("tok", "acct", undefined, e2eSurfaces, e2eFetch).crawlFrom(e2eSelector, JSON.stringify({ after: "in-use" }))) {
  if (ev.kind === "record") resumed.push(ev.record.name);
}
ok("a resume past the captured surface still emits the marker (the watermark order holds)", eq(resumed, ["refused"]));

// The cost projection has to match what the run reports, or a marker would read as an unexplained extra record.
const est = await new CloudflareConfigSource("tok", "acct", undefined, e2eSurfaces, e2eFetch).estimate(e2eSelector);
ok("estimate counts the marker record, so the projection still matches the run", est.records === e2eRecords.length + 1);

// CONTROL: the ALL-SURFACES path is untouched. Same registry, include [] = all, so "refused" is actually
// READ and refused. It must still marker with the CF message and the classified reason, and "not-used" must
// still produce a real empty record. If this drifts, the fix has changed the mode it was not meant to touch.
resetSourceFaultLedger();
const allRecords: SourceRecord[] = [];
for await (const ev of new CloudflareConfigSource("tok", "acct", undefined, e2eSurfaces, e2eFetch).crawlFrom({ include: [], exclude: [] }, null)) {
  if (ev.kind === "record" && ev.record.name !== CF_CONFIG_IDENTITY_ID) allRecords.push(ev.record);
}
const allByName = new Map(allRecords.map((r) => [r.name, r]));
ok("all-surfaces control: the empty surface still seals a real empty record", eq(decode(allByName.get("not-used")), []) && allByName.get("not-used")?.markerKind === undefined);
ok("all-surfaces control: the refused surface still markers with the CF message, not the not-attempted text", /account owned tokens/.test(String(decode(allByName.get("refused"))?._unavailable)));
ok("all-surfaces control: its reason is still the CLASSIFIED fault, not 'not-attempted'", allByName.get("refused")?.markerReason !== "not-attempted");

// RESTORE VISIBILITY: the marker has to reach a human. decodeConfigSnapshot refuses to diff it (so a
// not-attempted surface can never be written against live config), and coarseCfReason is the exact text the
// restore preview lists beside the surface name. The two markers must not read the same, because the remedy
// differs: one wants a retry, the other wants a discovery token that can read the surface.
const reasonFor = (rec: SourceRecord | undefined): string => {
  try {
    decodeConfigSnapshot(rec!.value!);
    return "DID NOT THROW";
  } catch (e) {
    return coarseCfReason(e);
  }
};
const notAttemptedReason = reasonFor(byName.get("refused"));
// byName.has() is part of the condition on purpose: without it this assertion passes vacuously wherever the
// marker does not exist at all (the very defect), because reasonFor would throw on the absent record instead.
ok("restore refuses to diff a not-attempted marker (it is never written against live config)", byName.has("refused") && notAttemptedReason !== "DID NOT THROW");
ok("the restore preview says the surface was NEVER CAPTURED and names the remedy (the discovery token)", /never captured this surface/.test(notAttemptedReason) && /discovery token/.test(notAttemptedReason));
ok("an attempted-and-refused marker keeps its own, different reason", reasonFor(allByName.get("refused")) !== notAttemptedReason);
ok("a real captured surface still decodes normally", eq(decodeConfigSnapshot(byName.get("in-use")!.value!), [{ name: "a" }]));

console.log("\n-- G015-b: a plan-entitlement gate stamps its own marker; a token-scope 403 does not --");
// Both a token-scope 403 and a plan-entitlement gate land as {_unavailable} on the DIRECT-ATTEMPT path (no
// cached discovery to skip them silently, e.g. a first run before discovery has ever classified the account).
// The two need to read differently from the marker's OWN value, not just from the out-of-band markerReason,
// because a discovery-less run (or a stale-fallback run) attempts both for real and this is the only place a
// reader of the archive itself -- the downpipe reader, a restore, a support engineer -- can tell "the plan does
// not carry this" from "the token cannot read this, check its scope" without the run row beside it.
const planGateSurfaces: CfConfigSurface[] = [
  // A healthy surface, so the all-failed guard (every surface read this run failed -> throw loudly) does
  // not fire and mask the two markers below; the guard's own behaviour is exercised elsewhere.
  { id: "healthy", scope: "account", restoreTier: "idempotent", read: async () => [{ ok: true }] },
  // A planted 403 with NO entitlement verdict: an ordinary token-scope gap.
  { id: "scope-gap", scope: "account", restoreTier: "idempotent", read: async () => { throw new CfApiError("Cloudflare API GET /accounts/a/access/groups: Unauthorized to access requested resource", 403, [9109], false); } },
  // A planted 403 whose verdict IS a definitive plan-entitlement gate (computed by isCfPlanEntitlementError
  // at the real throw site in production; planted directly here since this test drives no network).
  { id: "plan-gap", scope: "account", restoreTier: "idempotent", read: async () => { throw new CfApiError("Cloudflare API GET /accounts/a/rulesets/phases/x/entrypoint: not entitled to use the phase http_request_firewall_custom", 400, [50002], true); } },
];
resetSourceFaultLedger();
const planGateRecords: SourceRecord[] = [];
for await (const ev of new CloudflareConfigSource("tok", "acct", undefined, planGateSurfaces, e2eFetch).crawlFrom({ include: [], exclude: [] }, null)) {
  if (ev.kind === "record" && ev.record.name !== CF_CONFIG_IDENTITY_ID) planGateRecords.push(ev.record);
}
const byPlanGateName = new Map(planGateRecords.map((r) => [r.name, r]));
const scopeGapValue = decode(byPlanGateName.get("scope-gap"));
const planGapValue = decode(byPlanGateName.get("plan-gap"));
ok("both attempted surfaces still marker _unavailable (the shape is unchanged)", "_unavailable" in (scopeGapValue ?? {}) && "_unavailable" in (planGapValue ?? {}));
ok("the token-scope 403 carries NO planGated flag", !("planGated" in (scopeGapValue ?? {})));
ok("the plan-entitlement gate carries planGated: true, on the record's own value", planGapValue?.planGated === true);
ok("markerReason still separates them too (auth vs entitlement)", byPlanGateName.get("scope-gap")?.markerReason === "auth" && byPlanGateName.get("plan-gap")?.markerReason === "entitlement");

// The two remedies read differently from decodeConfigSnapshot + coarseCfReason, the exact text a restore
// preview shows beside the surface name -- a plan gate is not a token to re-scope or a run to retry.
const scopeGapReason = reasonFor(byPlanGateName.get("scope-gap"));
const planGapReason = reasonFor(byPlanGateName.get("plan-gap"));
ok("restore refuses to diff either marker", byPlanGateName.has("scope-gap") && scopeGapReason !== "DID NOT THROW" && byPlanGateName.has("plan-gap") && planGapReason !== "DID NOT THROW");
ok("the plan-gated remedy names the ACCOUNT'S PLAN, not the token", /account's Cloudflare plan/.test(planGapReason) && !/token/.test(planGapReason));
ok("the token-scope remedy is the generic 'incomplete, re-run' text, not the plan-gate text", /re-run a backup/.test(scopeGapReason) && !/account's Cloudflare plan/.test(scopeGapReason));
ok("the two remedies are not the same sentence", scopeGapReason !== planGapReason);

console.log("\n-- discoveryIsStale: the daily cron pass predicate --");
ok("never discovered -> stale", discoveryIsStale(undefined, 0));
ok("fresh -> not stale", !discoveryIsStale(fresh, 10_000 + 1000));
ok("older than max age -> stale", discoveryIsStale(fresh, 10_000 + DISCOVERY_MAX_AGE_MS + 1));

console.log(failures === 0 ? "\nCF-CONFIG DISCOVERY PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
