// LIVE round trip for SINGLETON surfaces: damage the live config, restore it from the snapshot, converge.
//
// WHY THIS EXISTS
// ---------------
// live-cf-autoprove.ts proves COLLECTIONS. Its whole loop is create an item, capture, delete it, restore
// it, compare. A surface whose config is one object has nothing to create and nothing to delete, so it
// falls straight through and is never proven by anything.
//
// Fourteen singletons were nevertheless proven during this work, by a prober written inline, run once, and
// never committed. That is the same hole the suite entry point was built to close: a claim resting on a
// script that no longer exists cannot be re-checked, and when the next singleton writer lands there is
// nothing to run it against. Thirteen unproven surfaces are singletons, and this is what they need.
//
// THE LOOP, AND WHY EACH STEP IS THERE
// ------------------------------------
//   1. snapshot = read()          what a backup would hold
//   2. write(damaged)             a DIFFERENT config, through the surface's own writer
//   3. re-read, CONFIRM IT TOOK   the step that makes the rest mean anything
//   4. write(snapshot)            the restore under test
//   5. re-read, compare           did the original config come back
//
// Step 3 is not a formality. Three times in this work a writer was blamed for a surface that had never
// changed at all: the endpoint answered 200, echoed the request, and ignored it. Without step 3 that reads
// as a clean pass, because step 5 compares the original against an object that never left the original.
// A surface whose damage does not take is reported NOT-EXERCISABLE, never proven.
//
// It writes twice through write() rather than damaging by raw API call, so the UPDATE path is exercised
// in both directions rather than only on the way back.
//
// CHOOSING THE DAMAGE
// -------------------
// Harder than it sounds, and the reason two Cloudflare 500s were misattributed as Cloudflare bugs during
// this work when both were bad damage choices of mine. The rules, each from a specific failure:
//
//   - Walk the WHOLE object, not the top level. managed-headers keeps its booleans inside an array and
//     gateway-configuration keeps its two levels down under `settings`, so a top-level scan finds nothing
//     to change on either and reports a false NOT-EXERCISABLE.
//   - Never touch a naming field. Perturbing `name` or `title` on a collection made one item look like two;
//     the singleton equivalent is renaming the thing rather than reconfiguring it.
//   - Booleans only. A boolean has exactly one other legal value, so flipping one cannot stray outside what
//     the endpoint accepts. Changing a string means guessing at an enum, which is where the 500s came from.
//   - Try candidates in order and keep going when one is refused. A single candidate makes the run's
//     verdict depend on which field happens to come first in Cloudflare's JSON.
//
// SAFETY
// ------
// This DAMAGES A REAL ACCOUNT, briefly and deliberately. Every run restores the original snapshot in a
// finally, including when an assertion fails partway, and reports loudly if the restore itself fails so a
// damaged surface is never left quiet. Gated on DOWNPIPE_LIVE_CF=1 and deliberately not in `validate`.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-singleton-prove.ts
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-singleton-prove.ts --only zone-hold,smart-shield

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { announceKit, kitDir, requireDamagePermission } from "./cf-kit.ts";
import { classifyRefusal } from "./cf-refusal.ts";
import { HAND_DAMAGE } from "./cf-hand-damage.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { jsonEqual, SERVER_STAMPED } from "../src/sources/cf-config-shared.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";

// The kit is selectable (DOWNPIPE_CF_KIT); see test/cf-kit.ts for which harnesses are safe against
// a real account and which are not.
const KEYS = kitDir();
const read = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();


// Fields that NAME the thing rather than configure it. Changing one is a rename, not a reconfiguration,
// and on a collection that mistake made one item look like two.
const NAMING = new Set(["name", "title", "id", "hostname", "type", "target", "pattern", "expression"]);

// Server-reported metadata ABOUT the setting rather than the setting itself. `editable` is the one that
// matters: every zone-settings response carries it, it is the first boolean in the object, and the endpoint
// correctly ignores any attempt to write it. The first run of this harness flipped it on ten surfaces and
// called them all NOT EXERCISABLE.
//
// That was caught rather than believed because one of the ten, zone-setting-origin-tls-compliance, is in
// PROVEN_WRITE_SURFACES with a live round trip behind it. A harness that reports a proven surface as
// unexercisable is wrong about the harness, not the surface. Re-running the already-proven set is worth the
// requests for exactly this reason: it is the only thing in the loop that can catch the prober itself.
const READ_ONLY_META = new Set(["editable", "read_only", "readonly", "locked", "modifiable"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// A field this harness can safely change, and what to change it to.
//
// TWO-VALUED FIELDS ONLY, which is the rule that keeps the damage safe. A boolean has exactly one other
// legal value. So does a zone setting carrying "on"/"off": that pair is Cloudflare's own vocabulary for
// those endpoints, not a guess at an enum, and guessing at enums is where two misattributed 500s came from
// earlier in this work. Anything with more than two legal values is left alone.
//
// The "on"/"off" case is not a nicety. Ten zone settings carry their value as that string rather than a
// boolean, including the cache family, so a boolean-only prober reports the whole group unexercisable.
// "enabled"/"disabled" is the same situation one vocabulary along, and content-scanning-settings is the
// surface it unlocks.
//
// WHAT IS DELIBERATELY NOT IN HERE. Anything with more than two legal values needs those values to come
// from somewhere, and the only two sources are a guess or the vendor. Guessing produced the 500s. So
// flipOf stays two-valued, and multi-valued fields are handled by HAND_DAMAGE below, which reads the legal
// values out of Cloudflare's published schema. schema-validation-settings and its API Shield twin moved
// there once their enum could be quoted rather than supposed.
//
// cache-origin-pq-encryption keeps its "supported" case here rather than in that table because the value
// came from a refusal message rather than the schema.
//
// zone-setting-origin-h2-max-streams is not a prober limit at all. The ask-probe below got 1135 back, this
// zone setting is not available for your plan type, so it is an entitlement and no better prober reaches it.
interface Damage { path: Array<string | number>; to: unknown }

function flipOf(v: unknown): unknown | undefined {
  if (typeof v === "boolean") return !v;
  if (v === "on") return "off";
  if (v === "off") return "on";
  if (v === "enabled") return "disabled";
  if (v === "disabled") return "enabled";
  // Cloudflare's own words for origin post-quantum encryption: "The value must either be `off`,
  // `supported`". Taken from the refusal the ask-probe below elicited, not from documentation and not from
  // a guess. One direction only: a value of "off" is already claimed by the on/off pair above, and the
  // prober would try "on" first, which this endpoint refuses. That refusal is reported rather than hidden.
  if (v === "supported") return "off";
  return undefined;
}

function damagePaths(node: unknown, path: Array<string | number> = []): Damage[] {
  const found: Damage[] = [];
  if (Array.isArray(node)) {
    node.forEach((v, i) => found.push(...damagePaths(v, [...path, i])));
  } else if (isPlainObject(node)) {
    for (const [k, v] of Object.entries(node)) {
      if (SERVER_STAMPED.has(k) || NAMING.has(k) || READ_ONLY_META.has(k)) continue;
      const to = flipOf(v);
      if (to !== undefined) found.push({ path: [...path, k], to });
      else found.push(...damagePaths(v, [...path, k]));
    }
  }
  return found;
}

function cloneWithDamage(root: unknown, d: Damage): unknown {
  const copy = structuredClone(root) as Record<string, unknown>;
  let node: Record<string, unknown> | unknown[] = copy;
  for (const step of d.path.slice(0, -1)) node = (node as Record<string, unknown>)[step as string] as Record<string, unknown>;
  (node as Record<string, unknown>)[d.path[d.path.length - 1] as string] = d.to;
  return copy;
}

function valueAt(root: unknown, path: Array<string | number>): unknown {
  let node: unknown = root;
  for (const step of path) {
    if (node === null || node === undefined) return undefined;
    node = (node as Record<string, unknown>)[step as string];
  }
  return node;
}

// One shared classifier, so the same Cloudflare message cannot mean different things in different
// harnesses. This file and live-cf-idempotence.ts used to carry character-identical copies of one pattern
// and live-cf-autoprove.ts a different, narrower one.
const isAccountRefusal = (m: string): boolean => classifyRefusal(m) === "account";

async function main(): Promise<void> {
  if (process.env.DOWNPIPE_LIVE_CF !== "1" || !existsSync(join(KEYS, "cf-api-token.txt"))) {
    console.log("SKIP live-cf-singleton-prove: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    return;
  }
  announceKit("live-cf-singleton-prove");
  // THIS HARNESS CHANGES CONFIGURATION THAT WAS ALREADY THERE. Permission to test against an account and
  // delete what you create does not cover flipping settings the owner already had, so against any kit but
  // the throwaway one it refuses unless told explicitly.
  const denied = requireDamagePermission();
  if (denied !== "") { console.log(`SKIP live-cf-singleton-prove: ${denied}`); return; }

  const rawApi = makeCfApi(read("cf-api-token.txt"));
  // lastGetPath records the endpoint the surface's own read() just used. It is the only way this harness
  // can address a surface directly: read() and write() are both closures over their paths, and nothing
  // exposes them. It exists solely for the last-resort restore below, never for the proof itself, which
  // always goes through the writer under test.
  let lastGetPath = "";
  const api = {
    get: async (path: string) => { lastGetPath = path; return rawApi.get(path); },
    getPage: async (path: string) => { lastGetPath = path; return rawApi.getPage(path); },
    send: rawApi.send.bind(rawApi),
  } as typeof rawApi;
  const ids = { accountId: read("account-id.txt"), zoneId: read("zone-id.txt") };

  const onlyArg = process.argv.indexOf("--only");
  const only = onlyArg >= 0 ? new Set((process.argv[onlyArg + 1] ?? "").split(",").filter(Boolean)) : null;

  const proven: string[] = [];
  // Kept apart from notExercisable on purpose. "I could not find a field I am willing to change" is a
  // limit of THIS HARNESS; "I changed a field and the endpoint threw the change away" is a fact about the
  // account. Reporting both as one number is the kind of blur this whole sweep exists to remove: it lets a
  // gap in the prober read as a property of the surface, and there is then no way to tell how much of the
  // unproven set is waiting on a better prober rather than on an entitlement.
  const ignoredByEndpoint: string[] = [];
  const notExercisable: string[] = [];
  const accountLimited: string[] = [];
  const failures: string[] = [];
  const restoreFailed: string[] = [];
  // A surface the WRITER could not put back but a direct call could. Reported separately and loudly: the
  // account is safe, and the writer is broken in a way that only shows up when it has to undo itself.
  const restoreFallback: string[] = [];

  for (const s of CF_CONFIG_SURFACES) {
    if (typeof s.write !== "function") continue;
    if (only !== null && !only.has(s.id)) continue;

    let snapshot: unknown;
    try {
      snapshot = await s.read(api, ids, undefined);
    } catch (e) {
      const m = (e as Error).message;
      if (isAccountRefusal(m)) accountLimited.push(`${s.id}: read refused by the account`);
      else failures.push(`${s.id}: READ THREW ${m.replace(/\s+/g, " ").slice(0, 100)}`);
      continue;
    }
    // Collections are autoprove's business; this harness is only about the one-object surfaces.
    if (Array.isArray(snapshot) || !isPlainObject(snapshot)) continue;
    if ("_unavailable" in snapshot) {
      accountLimited.push(`${s.id}: read returned an unavailable marker`);
      continue;
    }

    // Cloudflare saying the setting may not be changed, which the zone-settings writer already honours by
    // skipping. Worth naming separately: without this the write is issued, correctly does nothing, and the
    // run reports "the endpoint accepted a change and did not apply it", which reads like a writer defect
    // when it is the plan speaking.
    if (snapshot["editable"] === false) {
      accountLimited.push(`${s.id}: the account reports this setting as not editable`);
      continue;
    }

    // Never damage a field the WRITER will not send. A surface may declare per-surface field rules, and a
    // candidate the rules strip is unreachable by construction: the prober changes it, the writer drops it,
    // the read-back shows no change, and the run reports "the endpoint accepted a change and did not apply
    // it". That verdict blames Cloudflare for a field we chose not to send. fraud-detection-settings
    // produced exactly that on user_profiles, the field it strips because the endpoint refuses it.
    const rules = (s.write as unknown as { cfApplyFieldRules?: (src: Record<string, unknown> | null) => Record<string, unknown> } | undefined)?.cfApplyFieldRules;
    const sendable = rules === undefined || snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)
      ? null
      : new Set(Object.keys(rules(snapshot as Record<string, unknown>)));
    // Hand-written candidates FIRST, then the generic walk. Order matters for account-dns-settings, where
    // the walk does find a flippable boolean but finds it nested under zone_defaults, which drags a
    // plan-gated sibling into the writer's diff. Both lists then pass through the same field-rules filter
    // below: a hand-written candidate the writer would strip is no more reachable than a walked one.
    const hand: Damage[] = [];
    for (const h of HAND_DAMAGE.get(s.id) ?? []) {
      const now = valueAt(snapshot, h.path);
      // The account does not have this field. Not a defect: the table is written against the schema, and a
      // response may legitimately omit an optional field. Fall through to the generic walk.
      if (now === undefined) continue;
      const to = h.values.find((v) => !jsonEqual(v, now));
      if (to !== undefined) hand.push({ path: h.path, to });
    }
    const candidates = [...hand, ...damagePaths(snapshot)].filter((c) => sendable === null || c.path.length === 0 || sendable.has(String(c.path[0])));
    if (candidates.length === 0) {
      // Nothing this harness will flip. Rather than give up and record a bare "prober limit", ASK: send an
      // obviously invalid value and read what comes back. The write is REJECTED, so nothing changes, and
      // Cloudflare frequently answers with the reason or with the legal values themselves. Done by hand
      // first, which is how origin_h2_max_streams turned out to be "not available for your plan type", an
      // ENTITLEMENT that this harness had been recording against its own inability to find a field.
      //
      // Anything that is not clearly an account refusal stays a prober limit: the failure mode to avoid is
      // a vague error being read as an entitlement, which is how three verdicts in this work were wrong.
      const scalar = Object.keys(snapshot).find((k) => !SERVER_STAMPED.has(k) && !READ_ONLY_META.has(k) && (typeof snapshot[k] === "string" || typeof snapshot[k] === "number"));
      if (scalar !== undefined) {
        try {
          const probe = await s.write?.(api, ids, { ...snapshot, [scalar]: "dp-not-a-legal-value" }, { dryRun: false }, undefined);
          // A WRITER DOES NOT THROW ON A PER-ITEM REFUSAL. It records the reason in `skipped` and resolves
          // normally, so "it did not throw" is not "the endpoint accepted it". Reading it that way made the
          // first run of this probe report that every one of these surfaces swallowed an obviously invalid
          // value, including one I had already watched refuse it by hand.
          const refusal = probe?.skipped?.map((k) => k.reason ?? k.cls).join("; ") ?? "";
          if (refusal !== "") {
            if (isAccountRefusal(refusal) || /not available for your plan/i.test(refusal)) {
              accountLimited.push(`${s.id}: ${refusal.replace(/\s+/g, " ").slice(0, 110)}`);
            } else {
              // Not truncated to a stub: this message often NAMES the legal values, which is the single most
              // useful thing for whoever widens the prober next, and cutting it off loses exactly that.
              notExercisable.push(`${s.id}: no two-valued field; the endpoint says: ${refusal.replace(/\s+/g, " ").slice(0, 220)}`);
            }
            continue;
          }
          // Genuinely applied. Put the original back and say so: an endpoint taking a junk value is a
          // finding in its own right, not a pass.
          await s.write?.(api, ids, snapshot, { dryRun: false }, undefined).catch(() => undefined);
          notExercisable.push(`${s.id}: ACCEPTED an obviously invalid value for ${scalar}, which is its own finding`);
          continue;
        } catch (e) {
          const m = (e as Error).message.replace(/\s+/g, " ");
          if (isAccountRefusal(m) || /not available for your plan/i.test(m)) {
            accountLimited.push(`${s.id}: ${m.slice(0, 110)}`);
            continue;
          }
          // Cloudflare named something useful but not an entitlement (often the legal values). Carry the
          // message so the next person does not have to re-run the probe to see it.
          notExercisable.push(`${s.id}: no two-valued field; the endpoint says: ${m.slice(0, 120)}`);
          continue;
        }
      }
      // Nothing two-valued anywhere. Not a defect and not a pass: there is nothing this harness can safely
      // change, so the writer's update path stays unexercised and says so.
      notExercisable.push(`${s.id}: no two-valued field this harness is willing to change`);
      continue;
    }

    let verdict = "";
    let damaged = false;
    let damagedPath: Array<string | number> | null = null;
    // An ACCOUNT refusal on ONE FIELD is not the surface's verdict. It is remembered and only becomes the
    // verdict if no candidate succeeds. See the two `continue`s below for why this is not a `break`.
    let accountVerdict = "";
    try {
      for (const cand of candidates.slice(0, 4)) {
        const path = cand.path;
        const label = path.join(".");
        const want = cloneWithDamage(snapshot, cand);
        let wrote: Awaited<ReturnType<NonNullable<typeof s.write>>> | undefined;
        try {
          wrote = await s.write?.(api, ids, want, { dryRun: false }, undefined);
        } catch (e) {
          const m = (e as Error).message;
          // CONTINUE, not break, even for an account refusal. This used to break out of the candidate loop
          // entirely, which contradicted the rule stated on the next line and cost a real proof: once the
          // refusal classifier learnt "not available to this account or zone", dns-settings started
          // reporting account-limited on `foundation_dns` and STOPPED being re-proved, though it had been
          // proven by flipping `multi_provider` two fields later. The count stayed 57 and the harness
          // stayed green, because an account-limited surface is reported rather than failed.
          //
          // A per-field entitlement says nothing about the fields after it. Only an exhausted candidate
          // list makes it the surface's answer.
          if (isAccountRefusal(m)) {
            if (accountVerdict === "") accountVerdict = `account: ${m.replace(/\s+/g, " ").slice(0, 80)}`;
            continue;
          }
          verdict = `write refused on ${label}: ${m.replace(/\s+/g, " ").slice(0, 80)}`;
          continue; // another field may be writable; one refusal is not the surface's verdict
        }
        // A REFUSAL DOES NOT ALWAYS THROW. writeSingleObject catches the API error and RETURNS it as a
        // skip with applied: 0, so the catch above never runs, and this loop used to fall straight through
        // to the read-back, find nothing changed, and report "the endpoint accepted a change and did not
        // apply it". That verdict was wrong in the most expensive direction available: it blames the
        // endpoint for silently discarding, when the endpoint refused loudly and said why, and we did not
        // read the answer.
        //
        // It produced three wrong entries in UNPROVEN_WRITE_CAUSES before this was noticed. Reading the
        // returned result is the whole fix: `applied` and `skipped` are the writer's own report, and the
        // prover was throwing them away while asking the same question a slower way.
        const reported = (wrote?.skipped ?? []).map((sk) => `${sk.reason} [${sk.cls}]`).join("; ");
        if ((wrote?.applied ?? 0) === 0 && reported !== "") {
          // Same reasoning as the thrown case above: remember it, keep looking.
          if (isAccountRefusal(reported)) {
            if (accountVerdict === "") accountVerdict = `account: ${reported.replace(/\s+/g, " ").slice(0, 90)}`;
            continue;
          }
          verdict = `write refused on ${label}: ${reported.replace(/\s+/g, " ").slice(0, 90)}`;
          continue;
        }
        // THE STEP THAT MAKES THE REST MEAN ANYTHING. An endpoint that answers 200 and ignores the body
        // leaves live identical to the snapshot, and every later comparison then passes vacuously. It only
        // means "discarded" once the writer has reported that it actually sent something and got a success.
        const after = await s.read(api, ids, undefined);
        if (jsonEqual(valueAt(after, path), valueAt(snapshot, path))) {
          verdict = `the endpoint accepted a change to ${label} and did not apply it`;
          continue;
        }
        damaged = true;
        damagedPath = path;
        // The restore under test.
        await s.write?.(api, ids, snapshot, { dryRun: false }, undefined);
        const back = await s.read(api, ids, undefined);
        if (jsonEqual(valueAt(back, path), valueAt(snapshot, path))) {
          damaged = false;
          proven.push(`${s.id} (flipped ${label})`);
          verdict = "";
        } else {
          failures.push(`${s.id}: restored ${label} did not come back to the snapshot value`);
          verdict = "";
        }
        break;
      }
      // Nothing proved, and an account refusal was seen along the way: THAT is the surface's answer, now
      // that every candidate has actually been tried rather than only the ones before it.
      if (verdict === "" && !damaged && proven.every((pv) => !pv.startsWith(`${s.id} `)) && accountVerdict !== "") verdict = accountVerdict;
    } catch (e) {
      failures.push(`${s.id}: THREW mid-loop ${(e as Error).message.replace(/\s+/g, " ").slice(0, 90)}`);
    } finally {
      // Never leave a real account damaged, including when an assertion above failed.
      if (damaged) {
        let recovered = false;
        try {
          await s.write?.(api, ids, snapshot, { dryRun: false }, undefined);
          const back = await s.read(api, ids, undefined);
          recovered = jsonEqual(back, snapshot);
        } catch {
          recovered = false;
        }
        // LAST RESORT, and the reason it exists: the restore above goes through the WRITER, which is the
        // thing under test, so a broken writer breaks its own cleanup. zone-rum left Web Analytics ENABLED
        // on a real zone exactly that way. Its writer's diff carried `site_tag`, a server-assigned field
        // the endpoint refuses (10004 malformedParams), so every restore attempt failed the same way and
        // the finally block retried the identical broken call.
        //
        // This bypasses the writer entirely and PATCHes the single field that was changed, at the path the
        // surface's own read() used. Deliberately narrow: only a top-level scalar flip, because a nested
        // or array path cannot be addressed this way without guessing at the endpoint's merge semantics,
        // and guessing during cleanup is how a rescue becomes a second incident.
        if (!recovered && damagedPath !== null && damagedPath.length === 1 && lastGetPath !== "") {
          const field = String(damagedPath[0]);
          try {
            await api.send("PATCH", lastGetPath, { [field]: valueAt(snapshot, damagedPath) });
            const back2 = await s.read(api, ids, undefined);
            recovered = jsonEqual(valueAt(back2, damagedPath), valueAt(snapshot, damagedPath));
            if (recovered) restoreFallback.push(`${s.id}: the writer could not restore it; a direct PATCH of ${field} did`);
          } catch (e) {
            restoreFailed.push(`${s.id}: LEFT DAMAGED, direct restore also failed: ${(e as Error).message.replace(/\s+/g, " ").slice(0, 80)}`);
          }
        }
        if (!recovered && restoreFailed.every((r) => !r.startsWith(`${s.id}:`))) {
          restoreFailed.push(`${s.id}: LEFT DAMAGED, restore did not converge`);
        }
      }
    }
    if (verdict.startsWith("account:")) accountLimited.push(`${s.id}: ${verdict.slice(9)}`);
    else if (verdict.startsWith("the endpoint accepted")) ignoredByEndpoint.push(`${s.id}: ${verdict}`);
    else if (verdict !== "") notExercisable.push(`${s.id}: ${verdict}`);
  }

  const already = proven.filter((p) => PROVEN_WRITE_SURFACES.has(p.split(" ")[0] ?? "")).length;
  // MACHINE-READABLE, for the suite's coverage check. A proof that no harness re-runs can regress in
  // silence, so the suite unions these lines across stages and fails when a surface that should have a
  // live route was not exercised. One line, one contract, parsed by exactly one reader.
  console.log(`LIVE-PROVED: ${proven.map((pv) => pv.split(" ")[0]).sort().join(",")}`);
  console.log(`-- singleton surfaces with a writer --`);
  console.log(`  PROVEN round trip    ${proven.length} (${already} already recorded, ${proven.length - already} new)`);
  for (const p of proven.sort()) console.log(`     ${p}`);
  // A prober limit on an ALREADY-PROVEN surface is not a coverage gap: the proof exists, this particular
  // harness just cannot reproduce it (zone-setting-origin-tls-compliance was proven with a string LIST,
  // origin-max-http-version with a "1"/"2" pair Cloudflare names in its own validation message). Only a
  // prober limit on an UNPROVEN surface is work owed, and saying so takes the number that reads as a debt
  // from 6 to 3 on this account.
  const limitProven = notExercisable.filter((n) => PROVEN_WRITE_SURFACES.has(n.split(":")[0] ?? ""));
  const limitUnproven = notExercisable.filter((n) => !PROVEN_WRITE_SURFACES.has(n.split(":")[0] ?? ""));
  console.log(`  PROBER LIMIT         ${notExercisable.length} (nothing here this harness will change)`);
  console.log(`     ${limitUnproven.length} on UNPROVEN surfaces: work owed, this harness is the gap`);
  for (const n of limitUnproven.sort()) console.log(`        ${n}`);
  console.log(`     ${limitProven.length} on already-proven surfaces: no gap, the proof exists by another route`);
  for (const n of limitProven.sort()) console.log(`        ${n}`);
  console.log(`  ENDPOINT IGNORED IT  ${ignoredByEndpoint.length} (the change was accepted and discarded; a fact about the account, NOT a pass)`);
  for (const n of ignoredByEndpoint.sort()) console.log(`     ${n}`);
  console.log(`  account-limited      ${accountLimited.length} (reported, not failed)`);
  for (const a of accountLimited.sort()) console.log(`     ${a}`);
  console.log(`  DEFECTS              ${failures.length}`);
  for (const f of failures.sort()) console.log(`     ${f}`);
  if (restoreFallback.length > 0) {
    console.log(`\n  RESTORED BY A DIRECT CALL, NOT BY THE WRITER (${restoreFallback.length}) -- the account is safe and the writer is not:`);
    for (const r of restoreFallback) console.log(`     ${r}`);
  }

  if (restoreFailed.length > 0) {
    console.log(`\n  *** ${restoreFailed.length} SURFACE(S) LEFT DAMAGED ON A REAL ACCOUNT ***`);
    for (const r of restoreFailed) console.log(`     ${r}`);
  }

  const bad = failures.length + restoreFailed.length;
  console.log(bad === 0 ? "\nCF-CONFIG SINGLETON ROUND TRIP PASS" : `\n${bad} FAILURE(S)`);
  if (bad > 0) process.exit(1);
}

await main();
