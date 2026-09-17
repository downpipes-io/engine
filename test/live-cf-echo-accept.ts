// Does a one-object surface ACCEPT ITS OWN READ OUTPUT?
//
// WHY THIS EXISTS
// ---------------
// writeSingleObject sends the top-level fields that DIFFER between live and the snapshot. In the good
// case only one or two differ, and that is what every proof so far has exercised. In a real restore,
// after a real incident, many fields differ at once. If any of them is a field the endpoint will not
// accept, Cloudflare rejects the WHOLE request and none of the others are applied either.
//
// That is not hypothetical. zone-rum was recorded as PROVEN on the strength of a round trip that flipped
// one field. Its endpoint accepts `{value}` and refuses any body carrying a second field, including
// fields it reports itself: {value, host}, {value, lite} and {value, site_tag} are each 10004
// malformedParams. The proof was real and the conclusion drawn from it was too broad. It has since been
// moved to writeSingleSetting, which sends exactly one field by construction.
//
// The dry-run idempotence sweep structurally cannot find this. When live already matches the snapshot the
// writer correctly sends nothing, so the surface looks clean precisely because nothing is being asked of
// it. This asks the question the sweep cannot: send the surface everything it just told us, and see
// whether it will take its own words back.
//
// WHAT A REFUSAL MEANS, AND WHAT IT DOES NOT
// ------------------------------------------
// A 4xx naming an ENTITLEMENT is a fact about the account, not about the writer, and is reported
// separately. A refusal of the BODY is a latent restore failure: the surface restores today only while
// the fields that differ happen to be the acceptable ones.
//
// This is NOT proof of the opposite either. A surface that accepts its own output has been shown to
// tolerate the widest body it will ever be sent, which is a stronger statement than any single-field
// proof, but it is still one account and one moment.
//
// SAFETY
// ------
// Every value sent is the value already live, so each call is a no-op by construction. It is still a
// WRITE, so it is gated behind DOWNPIPE_LIVE_CF=1 like the other live harnesses, and it refuses a
// non-default kit without DOWNPIPE_CF_ALLOW_DAMAGE for the same reason the prober does: "no-op" is a
// claim about our intent, and an endpoint is free to disagree.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-echo-accept.ts

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { announceKit, kitDir, requireDamagePermission } from "./cf-kit.ts";
import { classifyRefusal } from "./cf-refusal.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { stripStamped } from "../src/sources/cf-config-shared.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

if (process.env.DOWNPIPE_LIVE_CF !== "1") {
  console.log("LIVE CF ECHO CHECK SKIPPED: set DOWNPIPE_LIVE_CF=1 to run it against a real account");
  verdictSkipped("LIVE CF ECHO CHECK SKIPPED: set DOWNPIPE_LIVE_CF=1 to run it against a real account");
  process.exit(0);
}
const refusal = requireDamagePermission();
if (refusal !== "") {
  console.error(`REFUSING: ${refusal}`);
  process.exit(1);
}

const KEYS = kitDir();
const kit = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();
announceKit("live-cf-echo-accept");

const api = makeCfApi(kit("cf-api-token.txt"));
const ids = { accountId: kit("account-id.txt"), zoneId: kit("zone-id.txt") };

interface Tagged {
  cfWriteKind?: string;
  cfWriteMethod?: "PATCH" | "PUT";
  cfWritePath?: (i: { accountId: string; zoneId?: string }) => string;
  // The writer's OWN field rules. Applying the global strip here instead re-derives what the writer
  // already decided, and gets it wrong the moment a surface corrects the global set: three surfaces kept
  // reporting as refusing after their per-surface fixes had landed, because this harness was still
  // building a body the writer would never send.
  cfApplyFieldRules?: (src: Record<string, unknown> | null) => Record<string, unknown>;
  // The list writers publish the same facts about their UPDATE call.
  cfListItemPath?: (i: { accountId: string; zoneId?: string }, id: string) => string;
  cfListUpdateMethod?: "PUT" | "PATCH";
  cfListBody?: (it: Record<string, unknown>) => Record<string, unknown>;
  cfListServerId?: (it: Record<string, unknown>) => string;
}

// LIST SURFACES, asked the same question about a REAL item.
//
// autoprove already exercises every list writer's update path, but only against items IT created from the
// vector: a name, sometimes a description, and little else. The account's own items are far richer, and
// the fields that break an update are exactly the ones a synthetic item does not have. A surface can pass
// the whole round trip on a two-field item it made, and refuse the customer's real one.
//
// So this takes the FIRST live item of each collection, builds the update body the writer would build,
// and sends it back to that item's own path. Every value is the value already there.
const listAccepts: string[] = [];
const listBodyRefused: string[] = [];
const listAccountRefused: string[] = [];
let listEmpty = 0;
let listUnreadable = 0;
let listNoId = 0;

const accepts: string[] = [];
const bodyRefused: string[] = [];
const accountRefused: string[] = [];
const unreadable: string[] = [];
// Fields the writer withholds that the endpoint would nonetheless accept. Candidates for `keep`.
const strippedButAccepted: string[] = [];
let skipped = 0;

for (const s of CF_CONFIG_SURFACES) {
  const w = s.write as unknown as Tagged | undefined;
  if (w?.cfWriteKind === "list" && w.cfListItemPath !== undefined && w.cfListBody !== undefined && w.cfListServerId !== undefined && w.cfListUpdateMethod !== undefined) {
    let items: unknown;
    try {
      items = await s.read(api, ids, undefined);
    } catch {
      listUnreadable++;
      continue;
    }
    const first = Array.isArray(items) ? items[0] : undefined;
    if (first === undefined || first === null || typeof first !== "object") {
      // An empty collection proves nothing, exactly as the idempotence sweep says of a vacuous no-op.
      listEmpty++;
      continue;
    }
    const item = first as Record<string, unknown>;
    const sid = w.cfListServerId(item);
    if (sid === "") {
      listNoId++;
      continue;
    }
    try {
      await api.send(w.cfListUpdateMethod, w.cfListItemPath(ids, sid), w.cfListBody(item));
      listAccepts.push(s.id);
    } catch (e) {
      const m = (e as Error).message.replace(/\s+/g, " ");
      const line = `${s.id}${PROVEN_WRITE_SURFACES.has(s.id) ? " [PROVEN]" : ""}: ${m.slice(0, 110)}`;
      if (classifyRefusal(m) === "account") listAccountRefused.push(line);
      else listBodyRefused.push(line);
    }
    continue;
  }
  // Only the whole-object writers. writeSingleSetting sends one field by construction and cannot hit this
  // failure; list writers send an item at a time and are a different question again.
  if (w?.cfWriteKind !== "object" || w.cfWriteMethod === undefined || w.cfWritePath === undefined) {
    skipped++;
    continue;
  }
  let live: unknown;
  try {
    live = await s.read(api, ids, undefined);
  } catch (e) {
    unreadable.push(`${s.id}: ${(e as Error).message.replace(/\s+/g, " ").slice(0, 80)}`);
    continue;
  }
  if (live === null || typeof live !== "object" || Array.isArray(live)) {
    skipped++;
    continue;
  }
  const body = (w.cfApplyFieldRules ?? stripStamped)(live as Record<string, unknown>);
  if (Object.keys(body).length === 0) {
    skipped++;
    continue;
  }
  const path = w.cfWritePath(ids);

  // SECOND QUESTION, and the one that finds the OPPOSITE defect. The check above asks whether we send a
  // field the endpoint refuses. This asks whether we WITHHOLD a field the endpoint would accept.
  //
  // A withheld field is never restored, and the run still reports success, so it is the worse of the two:
  // the operator is told the restore worked. `scope` was in the global strip set and is one of only two
  // settings on url-normalization, so its writer sent `{type}` alone and a changed scope would silently
  // never have come back.
  //
  // Each probe re-sends the field's CURRENT value alongside the accepted body, so it is a no-op like the
  // rest of this harness. Acceptance is a signal to review, not proof of configuration: an endpoint may
  // accept and ignore a field it does not own. It is reported, never failed on.
  const liveObj = live as Record<string, unknown>;
  for (const field of Object.keys(liveObj)) {
    if (field in body) continue;
    try {
      await api.send(w.cfWriteMethod, path, { ...body, [field]: liveObj[field] });
      strippedButAccepted.push(`${s.id}.${field}`);
    } catch {
      // Refused, so stripping it is right. This is the expected outcome and needs no report.
    }
  }

  try {
    await api.send(w.cfWriteMethod, path, body);
    accepts.push(s.id);
  } catch (e) {
    const m = (e as Error).message.replace(/\s+/g, " ");
    const cls = classifyRefusal(m);
    const line = `${s.id}${PROVEN_WRITE_SURFACES.has(s.id) ? " [PROVEN]" : ""}: ${m.slice(0, 110)}`;
    if (cls === "account") accountRefused.push(line);
    else bodyRefused.push(line);
  }
}

console.log("-- one-object writers echoed their own read output --");
console.log(`  ACCEPTS ITS OWN OUTPUT   ${accepts.length}`);
console.log(`  REFUSES ITS OWN BODY     ${bodyRefused.length} (a restore differing in the wrong field fails ENTIRELY)`);
for (const l of bodyRefused.sort()) console.log(`     ${l}`);
console.log(`  account/entitlement      ${accountRefused.length} (a fact about the account, not the writer)`);
for (const l of accountRefused.sort()) console.log(`     ${l}`);
if (unreadable.length > 0) {
  console.log(`  unreadable               ${unreadable.length}`);
  for (const l of unreadable.sort()) console.log(`     ${l}`);
}
console.log(`  skipped                  ${skipped} (not a whole-object writer, or nothing to send)`);
console.log(`  WITHHELD BUT ACCEPTED    ${strippedButAccepted.length} (the writer strips these and the endpoint takes them: review for \`keep\`)`);
for (const l of strippedButAccepted.sort()) console.log(`     ${l}`);

console.log("\n-- list writers: a REAL live item sent back to its own path --");
console.log(`  ACCEPTS ITS OWN ITEM     ${listAccepts.length}`);
console.log(`  REFUSES ITS OWN ITEM     ${listBodyRefused.length} (autoprove passes on a synthetic item and the customer's real one is refused)`);
for (const l of listBodyRefused.sort()) console.log(`     ${l}`);
console.log(`  account/entitlement      ${listAccountRefused.length}`);
for (const l of listAccountRefused.sort()) console.log(`     ${l}`);
// THE VACUITY IS THE HEADLINE HERE, not a footnote. On an account whose collections are empty this
// section checks almost nothing, and "0 refused" then means "0 asked". The idempotence sweep learnt the
// same lesson and reports VACUOUS as its own line rather than folding it into a pass.
console.log(`  NOT ASKED                ${listEmpty + listUnreadable + listNoId}: ${listEmpty} empty collection, ${listUnreadable} unreadable, ${listNoId} no addressable id`);
if (listAccepts.length + listBodyRefused.length + listAccountRefused.length === 0) {
  console.log("  ^ NOTHING WAS ASKED of any list writer on this account. This section proved nothing.");
}

// A PROVEN surface that refuses its own body is the finding worth failing on: the published claim is
// that downpipes re-applies it, and that claim is narrower than it reads. Everything else is reported.
const provenAndRefusing = [...bodyRefused, ...listBodyRefused].filter((l) => l.includes("[PROVEN]"));
console.log(
  provenAndRefusing.length === 0
    ? "\nCF-CONFIG ECHO CHECK PASS: no PROVEN one-object surface refuses its own read output"
    : `\n${provenAndRefusing.length} PROVEN SURFACE(S) REFUSE THEIR OWN READ OUTPUT`,
);
verdictReached(provenAndRefusing.length);
process.exit(provenAndRefusing.length === 0 ? 0 : 1);
