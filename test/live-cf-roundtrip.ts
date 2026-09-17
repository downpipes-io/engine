// LIVE Cloudflare round-trip proof: create, capture, damage, restore, verify.
//
// This is the GATE for adding a write() to a surface. Triage criteria based on reading Cloudflare's
// documentation are not evidence that a writer works: shipped writers can fail criteria derived that
// way once checked against a real account. Destroying a real object and getting it back is evidence
// that a writer works.
//
// PER SURFACE the loop is:
//   1. CAPTURE  read the surface through its own read(), exactly as a backup would
//   2. DAMAGE   mutate the live object away from that snapshot, through the raw API
//   3. VERIFY   confirm the damage actually took, so a no-op cannot masquerade as a pass
//   4. DRY RUN  call write() with dryRun, assert it reports the change and applies NOTHING
//   5. RESTORE  call write() for real
//   6. PROVE    re-read and assert byte equality with the snapshot
//   7. RERUN    call write() again and assert it converges to zero changes (idempotence)
//
// Step 3 is the one most easily skipped and the one that makes the rest meaningful. Without it, a
// surface whose damage silently failed would sail through steps 5 and 6 and be recorded as PASS.
//
// NOT PART OF CI. It needs a real Cloudflare account and it MUTATES it. It is skipped unless
// DOWNPIPE_LIVE_CF=1 and the credential files are present, and it refuses to run against an account
// that looks like production. Run:
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-roundtrip.ts
//
// CREDENTIALS are read from files by path and never echoed. The path is deliberately outside every
// repository. This mirrors the custody posture the product sells: we do not paste tokens into things.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { kitDir } from "./cf-kit.ts";
import { makeCfApi, surfaceById } from "../src/sources/cf-config-surfaces.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const KEYS = kitDir();
const read = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();

let failures = 0;
// Surfaces the account cannot exercise. Reported separately from failures, because conflating
// "we could not test this" with "this is broken" is how a report stops being read.
const unproven: string[] = [];
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A single-setting case: the surface id, the raw endpoint, and two values to toggle between. `probe` is
// chosen so that whichever value is live, the other is a real change.
interface SettingCase {
  surface: string;
  path: (zoneId: string) => string;
  a: unknown;
  b: unknown;
}

const SETTING_CASES: SettingCase[] = [
  { surface: "zone-setting-speed-brain", path: (z) => `/zones/${z}/settings/speed_brain`, a: "on", b: "off" },
  { surface: "zone-setting-ssl-automatic-mode", path: (z) => `/zones/${z}/settings/ssl_automatic_mode`, a: "auto", b: "custom" },
  { surface: "zone-setting-origin-max-http-version", path: (z) => `/zones/${z}/settings/origin_max_http_version`, a: "2", b: "1" },
  { surface: "zone-setting-origin-h2-max-streams", path: (z) => `/zones/${z}/settings/origin_h2_max_streams`, a: 100, b: 50 },
  { surface: "zone-setting-fonts", path: (z) => `/zones/${z}/settings/fonts`, a: "on", b: "off" },
  { surface: "zone-setting-auto-origin-tls-kex", path: (z) => `/zones/${z}/settings/auto_origin_tls_kex`, a: "on", b: "off" },
];

// A list case: create a real item, capture, DELETE it, restore, prove it came back. Deletion is the
// harshest damage available and the one a customer actually fears, so it is what the loop uses.
interface ListCase {
  surface: string;
  scope: "zone" | "account";
  collection: (ids: { accountId: string; zoneId: string }) => string;
  item: (ids: { accountId: string; zoneId: string }, id: string) => string;
  // make builds a create body unique to this run, so a leftover from a previous run cannot be mistaken
  // for a successful restore.
  make: (tag: string) => Record<string, unknown>;
  // identify finds the created item in the captured snapshot.
  matches: (o: Record<string, unknown>, tag: string) => boolean;
}

const LIST_CASES: ListCase[] = [
  {
    // DNS records already ship a writer. Running it FIRST validates the harness against known-good code:
    // if this case fails, the harness is wrong, not the writer under test.
    surface: "dns",
    scope: "zone",
    collection: (i) => `/zones/${i.zoneId}/dns_records`,
    item: (i, id) => `/zones/${i.zoneId}/dns_records/${id}`,
    make: (tag) => ({ type: "TXT", name: `rt-${tag}`, content: `downpipes round trip ${tag}`, ttl: 60 }),
    matches: (o, tag) => typeof o.name === "string" && o.name.includes(`rt-${tag}`),
  },
  {
    surface: "account-rule-lists",
    scope: "account",
    collection: (i) => `/accounts/${i.accountId}/rules/lists`,
    item: (i, id) => `/accounts/${i.accountId}/rules/lists/${id}`,
    make: (tag) => ({ name: `rt_${tag}`, kind: "ip", description: "downpipes round trip" }),
    matches: (o, tag) => typeof o.name === "string" && o.name.includes(tag),
  },
];

async function runListCases(api: ReturnType<typeof makeCfApi>, ids: { accountId: string; zoneId: string }, tag: string): Promise<void> {
  for (const c of LIST_CASES) {
    const surface = surfaceById(c.surface);
    console.log(`-- ${c.surface} (list) --`);
    if (surface === undefined || typeof surface.write !== "function") {
      console.log("  UNPROVEN  no write() on this surface yet");
      unproven.push(c.surface);
      continue;
    }
    let createdId = "";
    try {
      // 1. CREATE a real object.
      const created = (await api.send("POST", c.collection(ids), c.make(tag))) as Record<string, unknown>;
      createdId = String(created?.id ?? "");
      if (createdId === "") {
        console.log("  UNPROVEN  create returned no id on this account");
        unproven.push(c.surface);
        continue;
      }
      // 2. CAPTURE through the surface's own read().
      const snapshot = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      const inSnap = Array.isArray(snapshot) && snapshot.some((o) => c.matches(o, tag));
      ok("the created item appears in the captured snapshot", inSnap);

      // 3. DAMAGE by DELETING it, the harshest damage available.
      await api.send("DELETE", c.item(ids, createdId), undefined);
      const afterDelete = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      ok("the delete took, so the restore below is a real test", !afterDelete.some((o) => c.matches(o, tag)));

      // 4. DRY RUN reports the re-add and writes nothing.
      const dry = await surface.write(api, ids, snapshot, { dryRun: true });
      ok("dry run reports at least one add", dry.changes.some((x) => x.action === "add"));
      ok("dry run applies nothing", dry.applied === 0);
      const stillGone = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      ok("dry run really did not recreate it", !stillGone.some((o) => c.matches(o, tag)));

      // 5. RESTORE.
      const res = await surface.write(api, ids, snapshot, { dryRun: false });
      ok(`restore applied at least one item (skipped: ${res.skipped.map((x) => x.cls).join(",") || "none"})`, res.applied >= 1);

      // 6. PROVE it came back.
      const after = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      const back = after.find((o) => c.matches(o, tag));
      ok("the deleted item is back in the live account", back !== undefined);

      // 7. RERUN converges. This is where a bad natural key shows itself: if the restored item does not
      // match its snapshot counterpart, the second run DUPLICATES it instead of skipping.
      const again = await surface.write(api, ids, snapshot, { dryRun: false });
      ok("re-running the restore applies nothing (no duplicate)", again.applied === 0);
      const finalList = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      ok("exactly one copy exists after the re-run (the natural key matched)", finalList.filter((o) => c.matches(o, tag)).length === 1);

      // CLEANUP: leave the account as we found it.
      const leftover = finalList.filter((o) => c.matches(o, tag));
      for (const o of leftover) {
        try {
          await api.send("DELETE", c.item(ids, String(o.id ?? "")), undefined);
        } catch { /* reported below by the sweep */ }
      }
    } catch (e) {
      const m = (e as Error).message;
      if (/not available for your plan|1135|not entitled|not_entitled|10004|feature gate/i.test(m)) {
        console.log("  UNPROVEN  plan or feature gate on this account");
        unproven.push(c.surface);
      } else {
        ok(`${c.surface} list round trip threw: ${m.slice(0, 110)}`, false);
      }
      if (createdId !== "") {
        try { await api.send("DELETE", c.item(ids, createdId), undefined); } catch { /* best effort */ }
      }
    }
    console.log("");
  }
}

async function main(): Promise<void> {
  if (process.env.DOWNPIPE_LIVE_CF !== "1") {
    console.log("SKIP live-cf-roundtrip: set DOWNPIPE_LIVE_CF=1 to run (this test MUTATES a live account)");
    verdictSkipped("SKIP live-cf-roundtrip: set DOWNPIPE_LIVE_CF=1 to run (this test MUTATES a live account)");
    return;
  }
  if (!existsSync(join(KEYS, "cf-api-token.txt"))) {
    console.log(`SKIP live-cf-roundtrip: no credentials at ${KEYS}`);
    verdictSkipped(`SKIP live-cf-roundtrip: no credentials at ${KEYS}`);
    return;
  }
  const token = read("cf-api-token.txt");
  const accountId = read("account-id.txt");
  const zoneId = read("zone-id.txt");
  const api = makeCfApi(token);

  // SAFETY. This test damages live configuration, so it refuses to run against an account that holds
  // anything recognisably production. The check is cheap and the failure mode it prevents is not.
  const zones = (await api.get("/zones")) as Array<{ name?: string }>;
  const names = zones.map((z) => String(z.name ?? ""));
  const PROD = /(downpipes\.io|maelstrom\.au)$/;
  if (names.some((n) => PROD.test(n))) {
    console.log(`REFUSED: this account holds a production zone (${names.filter((n) => PROD.test(n)).join(", ")}). Never run the round trip here.`);
    process.exit(1);
  }
  // A per-run tag makes every created object identifiable and makes a leftover from a previous run
  // impossible to mistake for a successful restore. Date.now is fine here: this is a live script, never
  // a replayed workflow.
  const tag = `dp${Date.now().toString(36)}`;
  console.log(`live account ${accountId.slice(0, 8)}..., zone ${zoneId.slice(0, 8)}..., zones: ${names.join(", ")}, tag ${tag}\n`);

  for (const c of SETTING_CASES) {
    const surface = surfaceById(c.surface);
    console.log(`-- ${c.surface} --`);
    if (surface === undefined || typeof surface.write !== "function") {
      ok(`${c.surface} exists and has a write()`, false);
      continue;
    }
    const ids = { accountId, zoneId };
    let original: unknown;
    try {
      // 1. CAPTURE, through the surface's own read(), exactly as a backup does.
      const snapshot = (await surface.read(api, ids)) as { value?: unknown; editable?: unknown };
      original = snapshot?.value;
      if (snapshot?.editable === false) {
        console.log("  UNPROVEN  Cloudflare reports this setting as not editable on this zone");
        unproven.push(c.surface);
        continue;
      }
      if (original === undefined) {
        console.log("  UNPROVEN  the live zone returned no value for this setting");
        unproven.push(c.surface);
        continue;
      }
      // 2. DAMAGE: move the live value away from the snapshot.
      //
      // A refusal HERE is not a writer defect and must never be scored as one. On a Free plan a large
      // share of settings are plan-gated, and Cloudflare says so precisely (code 1135, "not available
      // for your plan type"). Scoring that as FAIL would flood the report with false failures and, worse,
      // would train whoever reads it to ignore real ones. It is UNPROVEN: the writer may well be correct,
      // this account simply cannot demonstrate it. Nothing was written, so nothing needs repairing.
      const damaged = JSON.stringify(original) === JSON.stringify(c.a) ? c.b : c.a;
      try {
        await api.send("PATCH", c.path(zoneId), { value: damaged });
      } catch (e) {
        const m = (e as Error).message;
        if (/not available for your plan|1135|not entitled|not_entitled/i.test(m)) {
          console.log("  UNPROVEN  plan-gated on this account, so the round trip cannot run here");
          unproven.push(c.surface);
          continue;
        }
        throw e;
      }

      // 3. VERIFY THE DAMAGE TOOK. Without this a silent no-op passes the whole test.
      const afterDamage = (await surface.read(api, ids)) as { value?: unknown };
      if (JSON.stringify(afterDamage?.value) === JSON.stringify(original)) {
        console.log(`  skip  Cloudflare did not accept the damage value, so this case proves nothing`);
        continue;
      }
      ok("the damage took, so the restore below is a real test", true);

      // 4. DRY RUN reports the change and writes nothing.
      const dry = await surface.write(api, ids, snapshot, { dryRun: true });
      ok("dry run reports the change", dry.changes.length === 1);
      ok("dry run applies nothing", dry.applied === 0);
      const stillDamaged = (await surface.read(api, ids)) as { value?: unknown };
      ok("dry run really did not touch the live value", JSON.stringify(stillDamaged?.value) === JSON.stringify(afterDamage?.value));

      // 5. RESTORE for real.
      const res = await surface.write(api, ids, snapshot, { dryRun: false });
      ok(`restore applied exactly one change (skipped: ${res.skipped.map((s) => s.cls).join(",") || "none"})`, res.applied === 1);

      // 6. PROVE the value came back.
      const after = (await surface.read(api, ids)) as { value?: unknown };
      ok("the live value now equals the snapshot", JSON.stringify(after?.value) === JSON.stringify(original));

      // 7. RERUN converges: a second restore is a no-op.
      const again = await surface.write(api, ids, snapshot, { dryRun: false });
      ok("re-running the restore converges to zero changes", again.changes.length === 0 && again.applied === 0);
    } catch (e) {
      ok(`${c.surface} round trip threw: ${(e as Error).message.slice(0, 100)}`, false);
      // Best effort: put the original back even when the case failed, so the zone is left as found.
      if (original !== undefined) {
        try {
          await api.send("PATCH", c.path(zoneId), { value: original });
        } catch {
          console.log("  WARNING: could not restore the original value; the zone may be left damaged");
        }
      }
    }
    console.log("");
  }

  if (unproven.length > 0) {
    console.log(`UNPROVEN on this account (${unproven.length}): ${unproven.join(", ")}`);
    console.log("These are plan or entitlement gates, not defects. A writer stays only if it PASSES here");
    console.log("or is proven on an account that has the product; an unproven writer is a claim, not a fact.\n");
  }
  await runListCases(api, { accountId, zoneId }, tag);

  console.log(failures === 0 ? "LIVE CF ROUND TRIP PASS" : `\n${failures} LIVE ROUND-TRIP FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
