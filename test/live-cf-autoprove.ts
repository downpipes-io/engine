// LIVE auto-prove: run the FULL round trip against every generated writer, using create bodies
// synthesised from Cloudflare's own OpenAPI schema.
//
// This exists because the earlier claim that each surface needs a HAND-WRITTEN create body was wrong.
// Cloudflare's schema carries `required` plus the type and enum of each property for most collection
// POSTs, which is enough to build a body the API will accept. Where it is not enough the create simply
// fails and the surface is recorded as still unvalidated, which is an honest outcome rather than a
// silent skip.
//
// PER SURFACE: create from the synthesised body, capture through the surface's own read(), DELETE,
// restore through write(), prove the object came back, then re-run and prove exactly one copy exists.
// That last step is the natural-key proof and it is the reason this is worth doing at all.
//
// The account is left as found: every object created here is deleted, including on the failure paths.
//
// THE BODIES FILE IS A COMMITTED VECTOR: test/vectors/cf-config/autoprove-bodies.json, used by default.
// It started as schema-synthesised bodies and now carries the corrections learned by running it, which are
// the expensive part and were previously living only in a scratch directory. Each correction is a fact
// about Cloudflare that cost a live run to discover: magic-bgp-filter-profiles needs a CIDR in `targets`
// and was recorded as "Magic Transit is an enterprise product" until one was supplied; custom page assets
// reject hyphens in a name; device-ip-profiles needs `precedence` and a `match` before it will even tell
// you it also needs a real WARP subnet.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-autoprove.ts [bodies.json]

import { existsSync, readFileSync } from "node:fs";
import { classifyRefusal } from "./cf-refusal.ts";
import { GENERATED_KEY_FIELDS, PROVEN_WRITE_SURFACES, resolveServerIdField } from "../src/sources/cf-config-write-generated.ts";
import { itemKey } from "./cf-item-key.ts";
import { SKIP_IN_DIFF, stripStamped } from "../src/sources/cf-config-shared.ts";
import { join } from "node:path";
import { announceKit, kitDir } from "./cf-kit.ts";
import { makeCfApi, surfaceById } from "../src/sources/cf-config-surfaces.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

// The kit is selectable (DOWNPIPE_CF_KIT); see test/cf-kit.ts for which harnesses are safe against
// a real account and which are not.
const KEYS = kitDir();
const read = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();

// BAD-BODY and PRECONDITION are split out of what used to be one CREATE-REFUSED bucket. A malformed body is
// OURS and, worse, it MASKS the real answer: two DLP surfaces were carried as entitlement-blocked when the
// request never reached the entitlement check. A precondition is neither a defect nor an entitlement, it is
// a fact about account STATE and may be satisfiable, so it is worth separating from both.
type Outcome = "PROVEN" | "CREATE-REFUSED" | "BAD-BODY" | "PRECONDITION" | "RESTORE-FAILED" | "DUPLICATED" | "GATED";

function isPlainObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const out: Array<{ id: string; outcome: Outcome; detail: string }> = [];
// Surfaces that were handed back the item they had just returned. See the echo block below for why this
// is asked here rather than only in the standalone harness.
const echoAccepted: string[] = [];
const echoRefused: Array<{ id: string; why: string }> = [];

async function main(): Promise<void> {
  if (process.env.DOWNPIPE_LIVE_CF !== "1" || !existsSync(join(KEYS, "cf-api-token.txt"))) {
    console.log("SKIP live-cf-autoprove: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    verdictSkipped("SKIP live-cf-autoprove: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    return;
  }
  announceKit("live-cf-autoprove");
  const bodiesPath = process.argv[2] ?? new URL("./vectors/cf-config/autoprove-bodies.json", import.meta.url).pathname;
  // `prereq` is optional per surface: something that must EXIST before the surface's own create is legal.
  // It is not a workaround for a broken writer. mnm-rules refuses with "rule can not be added without
  // initial account configuration", which the refusal classifier calls a PRECONDITION precisely because it
  // is a fact about account state rather than about the plan, and is therefore satisfiable. Without a way
  // to express that, such a surface sits unproven forever behind a reason that was never a blocker.
  // `resolve` fills a body field from something the ACCOUNT already has, looked up at run time.
  //
  // device-ip-profiles needs a WARP subnet id. The vector held one, which meant the surface could only ever
  // prove on the single account that subnet belonged to; anywhere else it refused with "subnet_id must be
  // valid uuid" and that refusal read like a defect. An account-specific identifier in a shared vector is
  // not a body, it is a note about one machine.
  const bodies = JSON.parse(readFileSync(bodiesPath, "utf8")) as Record<string, { path: string; body: Record<string, unknown> | null; prereq?: { path: string; body: Record<string, unknown> }; resolve?: Record<string, { path: string; field: string }> }>;
  const api = makeCfApi(read("cf-api-token.txt"));
  const accountId = read("account-id.txt");
  const zoneId = read("zone-id.txt");
  const ids = { accountId, zoneId };
  const resolve = (t: string): string => t.replace("/accounts/{}", `/accounts/${accountId}`).replace("/zones/{}", `/zones/${zoneId}`);

  for (const [id, entry] of Object.entries(bodies)) {
    if (entry.body === null) continue;
    const spec = { path: entry.path, body: entry.body };
    const surface = surfaceById(id);
    if (surface === undefined || typeof surface.write !== "function") continue;
    const coll = resolve(spec.path);
    if (coll.includes("{}")) continue;
    // Stand the precondition up before the loop and TEAR IT DOWN afterwards, whatever happens. This account
    // already carries two persistent changes made by earlier probes; it does not need a third left behind
    // because a run failed halfway.
    let prereqPath = "";
    if (entry.prereq !== undefined) {
      prereqPath = resolve(entry.prereq.path);
      try {
        await api.send("POST", prereqPath, entry.prereq.body);
      } catch (e) {
        const m = (e as Error).message;
        // A precondition we cannot stand up is reported as whatever it actually is, not as the surface's
        // own verdict: blaming the writer for a setup step that the account refused would be exactly the
        // misattribution the refusal classifier exists to stop.
        out.push({ id, outcome: classifyRefusal(m) === "account" ? "GATED" : "PRECONDITION", detail: `prerequisite ${entry.prereq.path} could not be created: ${m.replace(/\s+/g, " ").slice(0, 150)}` });
        continue;
      }
    }
    // Fill any run-time-resolved fields before the create. A lookup that finds nothing is reported as a
    // PRECONDITION, not as the surface's own verdict: the account simply does not have the thing this body
    // needs to point at, which is a fact about the account rather than about the writer.
    if (entry.resolve !== undefined) {
      let unmet = "";
      for (const [field, look] of Object.entries(entry.resolve)) {
        const found = await api.get(resolve(look.path)).catch(() => null);
        const first = Array.isArray(found) ? (found[0] as Record<string, unknown> | undefined) : undefined;
        const val = first?.[look.field];
        if (typeof val !== "string" || val === "") { unmet = `${field} needs a ${look.field} from ${look.path}, and the account has none`; break; }
        spec.body[field] = val;
      }
      if (unmet !== "") {
        out.push({ id, outcome: "PRECONDITION", detail: unmet });
        if (prereqPath !== "") await api.send("DELETE", prereqPath, undefined).catch(() => undefined);
        continue;
      }
    }
    let createdId = "";
    try {
      // SWEEP FIRST. A leftover from an earlier failed run makes the create fail with
      // "resource_already_exists" and the surface reads as broken when it is not. That happened to
      // access-tags: an orphan from a run that mis-detected its own success blocked the next three
      // attempts. Delete anything carrying our marker before creating.
      const preexisting = (await surface.read(api, ids).catch(() => [])) as Array<Record<string, unknown>>;
      if (Array.isArray(preexisting)) {
        for (const o of preexisting.filter((x) => JSON.stringify(x).includes("dp-roundtrip"))) {
          try { await api.send("DELETE", `${coll}/${itemKey(o)}`, undefined); } catch { /* best effort */ }
        }
      }
      // Some collection POSTs return an ARRAY rather than the created object. `filters` is one, and
      // reading `.id` off the array yielded "" and a CREATE-REFUSED verdict while the object had in
      // fact been created and was then left behind. Unwrap a single-element array before reading the id.
      const raw = (await api.send("POST", coll, spec.body)) as unknown;
      const created = (Array.isArray(raw) ? raw[0] : raw) as Record<string, unknown> | null;
      // Some collections have NO id: the NAME is the key (Access tags are one, returning only
      // name/app_count/created_at). Requiring an id reported CREATE-REFUSED on a create that had
      // succeeded, and left the object behind. Fall back to the name, and record which key is in use so
      // the delete path below targets the right thing.
      createdId = created === null ? "" : itemKey(created);
      if (createdId === "") { out.push({ id, outcome: "CREATE-REFUSED", detail: "create returned neither an id nor a name" }); continue; }

      // CAN THE WRITER ADDRESS WHAT IT JUST CREATED? The idempotence sweep asks this too, but only for
      // collections that already hold something, which on both test accounts is about nine writers out of
      // sixty-nine. Here there is a freshly created object for every surface carrying a body, so the same
      // question covers roughly six times as many.
      //
      // It matters because the failure is silent in the other direction: a writer that cannot resolve an
      // address skips every changed item with "no id to update in place", so it CREATES on a restore after
      // a delete and does nothing at all on a restore over live data. Two surfaces shipped in that state.
      if (created !== null && resolveServerIdField(created) === "" && !GENERATED_KEY_FIELDS.has(id)) {
        out.push({ id, outcome: "RESTORE-FAILED", detail: `NOT ADDRESSABLE: the created item carries no id and no keyField is declared, so the writer can create but never update (keys: ${Object.keys(created).slice(0, 6).join(",")})` });
        await api.send("DELETE", `${coll}/${createdId}`, undefined).catch(() => undefined);
        continue;
      }

      const snapshot = (await surface.read(api, ids)) as Array<Record<string, unknown>>;

      // WILL THIS SURFACE TAKE BACK THE ITEM IT JUST HANDED US?
      //
      // The standalone echo harness asks this of one-object writers and of list writers whose collection
      // already holds something. On this account 25 of 29 collections are EMPTY, so it asks almost
      // nothing. Here there is a freshly created item on every surface carrying a body, and crucially it
      // is the item AS READ BACK: Cloudflare has added its own id, timestamps, computed fields and
      // defaults, none of which were in the body we sent. Those additions are precisely what breaks an
      // update, and a synthetic item never has them.
      //
      // It is a no-op: every value sent is the value just read. A refusal means a restore over live data
      // fails ENTIRELY for this surface, while the create-after-delete path this loop otherwise exercises
      // keeps passing, because a create never sends the server's own additions back.
      const echoItem = Array.isArray(snapshot) ? snapshot.find((o) => itemKey(o) === createdId) : undefined;
      const lw = surface.write as unknown as {
        cfListItemPath?: (i: typeof ids, itemId: string) => string;
        cfListUpdateMethod?: "PUT" | "PATCH";
        cfListBody?: (it: Record<string, unknown>) => Record<string, unknown>;
        cfListServerId?: (it: Record<string, unknown>) => string;
      };
      if (echoItem !== undefined && lw.cfListItemPath !== undefined && lw.cfListBody !== undefined && lw.cfListServerId !== undefined && lw.cfListUpdateMethod !== undefined) {
        const sid = lw.cfListServerId(echoItem);
        if (sid !== "") {
          try {
            await api.send(lw.cfListUpdateMethod, lw.cfListItemPath(ids, sid), lw.cfListBody(echoItem));
            echoAccepted.push(id);
          } catch (e) {
            echoRefused.push({ id, why: (e as Error).message.replace(/\s+/g, " ").slice(0, 120) });
          }
        }
      }

      const present = Array.isArray(snapshot) && snapshot.some((o) => itemKey(o) === createdId);
      // `continue`, not a bare push. Without it a surface whose created object was not found still ran the
      // rest of the loop and could ALSO report PROVEN, so one run emitted both verdicts for the same
      // surface. A harness that contradicts itself in one report is worse than one that is simply wrong.
      if (!present) { out.push({ id, outcome: "CREATE-REFUSED", detail: "created object did not appear in the surface read" }); await api.send("DELETE", `${coll}/${createdId}`, undefined).catch(() => undefined); continue; }

      await api.send("DELETE", `${coll}/${createdId}`, undefined);
      const gone = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      if (gone.some((o) => itemKey(o) === createdId)) { out.push({ id, outcome: "CREATE-REFUSED", detail: "delete did not take, so nothing is proven" }); continue; }

      const res = await surface.write(api, ids, snapshot, { dryRun: false });
      if (res.applied < 1) {
        out.push({ id, outcome: "RESTORE-FAILED", detail: res.skipped[0]?.reason?.slice(0, 70) ?? "restore applied nothing" });
        continue;
      }
      // Finding the restored object CANNOT key on the created id: a restore creates a NEW object with a
      // NEW id, so matching the old one always fails and a working writer reads as broken. It nearly
      // cost two good writers. Match on a stable CONTENT field from the create body instead, preferring
      // a human-named one and falling back to any distinctive string the body carried.
      const marker = String(spec.body.name ?? spec.body.title ?? spec.body.description ?? spec.body.expression ?? spec.body.hostname ?? spec.body.id ?? "dp-roundtrip");
      const after = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      const back = after.filter((o) => JSON.stringify(o).includes(marker));
      if (back.length === 0) { out.push({ id, outcome: "RESTORE-FAILED", detail: "restore reported success but the object is not back" }); continue; }

      const again = await surface.write(api, ids, snapshot, { dryRun: false });
      const finalList = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
      const copies = finalList.filter((o) => JSON.stringify(o).includes(marker)).length;
      if (again.applied !== 0 || copies !== 1) {
        out.push({ id, outcome: "DUPLICATED", detail: `re-run applied ${again.applied}, ${copies} copies exist: the natural key does not match the surface's own output` });
      } else {
        // THE UPDATE LEG. Everything above only ever exercises CREATE: the object is deleted, so the
        // restore recreates it and the writer's updateMethod is never called. A writer whose update is
        // wrong therefore looked PROVEN, because the failing update was caught as a per-item skip and
        // `applied` stayed 0, which the convergence check above reads as "nothing to do". A writer that
        // can never update is indistinguishable from one with nothing to do, and
        // observability-saved-queries shipped a 404-ing PUT past this harness on exactly that.
        //
        // So: change the LIVE object, then restore the snapshot over it. The item now matches by natural
        // key and differs in content, which is the only path that reaches updateMethod.
        const live = finalList.filter((o) => JSON.stringify(o).includes(marker))[0];
        const liveKey = live === undefined ? "" : itemKey(live);
        let updateVerdict = "";
        if (live === undefined || liveKey === "") updateVerdict = "could not find the restored object to modify";
        else {
          // The perturbed field must NOT be one preferredKey builds the natural key from. The first
          // version used name and title, which ARE key fields, so changing one changed the item's identity:
          // the writer then correctly created a second object rather than updating, and five surfaces
          // reported "the update produced 2 copies" as though the WRITER were at fault. It was the test
          // moving the goalposts mid-run. Only free-text fields are safe to perturb here.
          // A surface with NONE of preferredKey's named fields falls back to a natural key built from the
          // whole stripped item, so EVERY field is identifying and no perturbation can leave identity
          // intact. zone-lockdowns is one: changing its description made the writer create rather than
          // update, and Cloudflare refused that with zonelockdown.api.duplicate_of_existing, which read as
          // a writer defect and was the harness again. Detect it and say so rather than manufacture a
          // failure.
          const NAMED_KEY_FIELDS = ["name", "title", "hostname", "expression", "pattern", "url", "host", "domain", "identifier"];
          const hasNamedKey = NAMED_KEY_FIELDS.some((f) => typeof live[f] === "string" && live[f] !== "");
          // Any NON-KEY field, not just free text. The first version looked only for description / comment
          // / notes, which parked five surfaces as unexercisable when they carried a perfectly good
          // non-identifying boolean, number or other string: secondary-dns-acls has ip_range,
          // magic-bgp-filter-profiles has match_action, device-managed-networks has type. Free text is
          // preferred because it is the least likely to be validated, then anything else that is not part
          // of the key and not server-stamped.
          const perturbable = (f: string): boolean =>
            !NAMED_KEY_FIELDS.includes(f) && !SKIP_IN_DIFF.has(f) && !/^(app_count|count|num_items|status|state)$/.test(f);
          const nextValue = (v: unknown): unknown =>
            typeof v === "string" ? `${v}-upd` : typeof v === "boolean" ? !v : typeof v === "number" ? v + 1 : undefined;
          const field = !hasNamedKey
            ? undefined
            : (["description", "comment", "notes"].find((f) => typeof live[f] === "string" && live[f] !== "") ??
               Object.keys(live).find((f) => perturbable(f) && nextValue(live[f]) !== undefined) ??
               // Last resort: a NESTED object holding a perturbable scalar. device-managed-networks keeps
               // its only changeable value at config.tls_sockaddr, so every top-level candidate was either
               // the key or a field the endpoint ignores, and the update path read as unreachable when it
               // was simply one level down.
               Object.keys(live).find((f) => perturbable(f) && isPlainObj(live[f]) && Object.values(live[f] as Record<string, unknown>).some((v) => nextValue(v) !== undefined)));
          if (!hasNamedKey) updateVerdict = "NOT-EXERCISABLE: the natural key is built from the whole item, so every field is identifying and no perturbation preserves identity";
          else if (field === undefined) updateVerdict = "NOT-EXERCISABLE: no non-identifying free-text field to perturb, so this harness cannot reach the update path";
          else {
            // The harness does not know the surface's own updateMethod (it lives in the writer table, not
            // in the bodies vector), and it does not need to: this step only has to CHANGE the live object
            // by any means so the writer has something to update. Try PUT, then PATCH.
            // Try the full body first, then just the changed field: some endpoints refuse a whole object
            // on update (account rule lists answer filters.api.invalid_json), which is a fact about the
            // endpoint and must not read as the writer being unexercisable.
            // A nested object is perturbed by changing its first perturbable member, not by replacing it.
            const changedValue = ((): unknown => {
              const v = live[field];
              if (!isPlainObj(v)) return nextValue(v);
              const inner = { ...(v as Record<string, unknown>) };
              const k = Object.keys(inner).find((j) => nextValue(inner[j]) !== undefined);
              if (k !== undefined) inner[k] = nextValue(inner[k]);
              return inner;
            })();
            const full = { ...stripStamped(live), [field]: changedValue };
            const narrow = { [field]: changedValue };
            let modified = false;
            for (const [m, b] of [["PUT", full], ["PATCH", full], ["PUT", narrow], ["PATCH", narrow]] as Array<["PUT" | "PATCH", Record<string, unknown>]>) {
              try {
                await api.send(m, `${coll}/${liveKey}`, b);
                modified = true;
                break;
              } catch {
                /* next shape */
              }
            }
            if (!modified) updateVerdict = "NOT-EXERCISABLE: no request shape this harness tries could modify the live object, so the update path cannot be reached";
            if (updateVerdict === "") {
              // Confirm the perturbation actually CHANGED the object before judging the writer on it.
              // Several endpoints accept a write and ignore the field, so live still equalled the snapshot
              // and the writer correctly did nothing, which was being reported as "the update did not
              // apply" as though the writer were at fault. An unchanged object means the update path
              // cannot be reached here, which is a limit of this harness and not a verdict.
              const check = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
              const perturbedLive = check.filter((o) => JSON.stringify(o).includes(marker))[0];
              if (perturbedLive === undefined || JSON.stringify(perturbedLive[field]) === JSON.stringify(live[field])) {
                updateVerdict = "NOT-EXERCISABLE: the endpoint accepted the change and did not apply it, so live never differs from the snapshot";
              }
            }
            if (updateVerdict === "") {
              const upd = await surface.write(api, ids, snapshot, { dryRun: false });
              const after = (await surface.read(api, ids)) as Array<Record<string, unknown>>;
              const restored = after.filter((o) => JSON.stringify(o).includes(marker));
              // applied must be >= 1 (the update ran) AND the field must be back AND still one copy.
              if (upd.applied < 1) updateVerdict = `the update did not apply (skipped: ${upd.skipped[0]?.reason?.slice(0, 60) ?? "none"})`;
              else if (restored.length !== 1) updateVerdict = `the update produced ${restored.length} copies`;
              else if (JSON.stringify(restored[0]![field]) !== JSON.stringify(live[field])) updateVerdict = "the update applied but the field did not come back";
            }
          }
        }
        if (updateVerdict === "") out.push({ id, outcome: "PROVEN", detail: "created, captured, deleted, restored, converged, and UPDATED in place" });
        else if (updateVerdict.startsWith("NOT-EXERCISABLE")) {
          // A limit of the harness, not a verdict on the writer, and reported as such. Calling this a
          // failure would park working writers; calling it PROVEN would repeat the false proof this leg
          // exists to stop. The create path IS proven, and the detail says exactly how far that goes.
          out.push({ id, outcome: "PROVEN", detail: `created, captured, deleted, restored, converged; update path not exercised (${updateVerdict.slice("NOT-EXERCISABLE: ".length)})` });
        } else out.push({ id, outcome: "RESTORE-FAILED", detail: `create path proven, UPDATE path not: ${updateVerdict}` });
      }
      for (const o of finalList.filter((x) => JSON.stringify(x).includes(marker))) {
        try { await api.send("DELETE", `${coll}/${itemKey(o)}`, undefined); } catch { /* swept below */ }
      }
    } catch (e) {
      const m = (e as Error).message;
      // classifyRefusal is shared with the idempotence and singleton harnesses, so the same message can no
      // longer mean different things depending on which one saw it. The pattern that used to live here was
      // much narrower and was wrong about most of what it saw: bare "Forbidden", an entitlements code, an
      // enterprise-only notice and a zero quota all fell through to CREATE-REFUSED, which reads as "our
      // writer cannot create" when the account was simply declining.
      const cls = classifyRefusal(m);
      const outcome: Outcome = cls === "account" ? "GATED" : cls === "our-body" ? "BAD-BODY" : cls === "precondition" ? "PRECONDITION" : "CREATE-REFUSED";
      out.push({ id, outcome, detail: m.replace(/\s+/g, " ").slice(0, 220) });
      // 220, not 80. An 80-character slice cut every message at the URL and dropped Cloudflare's error
      // code and reason, which is the only part that says what to do next. Two surfaces were triaged
      // twice over because of it.
      if (createdId !== "") { try { await api.send("DELETE", `${coll}/${createdId}`, undefined); } catch { /* best effort */ } }
    } finally {
      // TEAR THE PRECONDITION DOWN on every path, including the ones that threw. Setup without matching
      // teardown is how this account ended up carrying a Zero Trust organisation and a default Gateway
      // location that cannot now be removed, and neither was meant to outlive its probe.
      if (prereqPath !== "") { try { await api.send("DELETE", prereqPath, undefined); } catch { /* best effort */ } }
    }
  }

  for (const k of ["PROVEN", "DUPLICATED", "RESTORE-FAILED", "BAD-BODY", "PRECONDITION", "CREATE-REFUSED", "GATED"] as Outcome[]) {
    const rs = out.filter((r) => r.outcome === k);
    if (rs.length === 0) continue;
    console.log(`\n${k} (${rs.length}):`);
    for (const r of rs) console.log(`   ${r.id.padEnd(36)} ${r.detail}`);
  }
  // "NEWLY" MEANS NOT ALREADY IN PROVEN_WRITE_SURFACES, and it used to mean nothing of the sort: every
  // surface that passed the loop was listed under that heading, whether or not it had been proven months
  // ago. A run against a second account then reported twelve NEWLY PROVEN surfaces of which zero were new,
  // and the obvious next move on reading that is to raise the published count by twelve.
  //
  // The re-proofs are still worth printing. A surface passing the same loop on a DIFFERENT account is
  // stronger evidence than passing it twice on the same one; it is just not new coverage.
  const proven = out.filter((r) => r.outcome === "PROVEN").map((r) => r.id);
  const fresh = proven.filter((id) => !PROVEN_WRITE_SURFACES.has(id));
  const again = proven.filter((id) => PROVEN_WRITE_SURFACES.has(id));
  console.log(`LIVE-PROVED: ${[...proven].sort().join(",")}`);
  console.log(`\nPROVEN THIS RUN (${proven.length})`);
  console.log(`  NEW, add these to PROVEN_WRITE_SURFACES (${fresh.length}): ${fresh.join(", ") || "(none)"}`);
  console.log(`  re-proved, already recorded (${again.length}): ${again.join(", ") || "(none)"}`);

  // The echo result is reported next to the proof it qualifies, because it says what the proof does NOT
  // cover: this loop restores by CREATING after a delete, which never sends the server's own additions
  // back, so a surface can pass it and still fail a restore over live data.
  console.log(`\nECHO: handed back the item it had just returned (${echoAccepted.length} accepted, ${echoRefused.length} refused)`);
  for (const r of echoRefused) console.log(`   REFUSED ${r.id.padEnd(34)} ${r.why}`);
  const provenAndRefusing = echoRefused.filter((r) => proven.includes(r.id) || PROVEN_WRITE_SURFACES.has(r.id));
  verdictReached(provenAndRefusing.length);
  if (provenAndRefusing.length > 0) {
    console.error(`\n${provenAndRefusing.length} PROVEN surface(s) refuse an item they themselves returned: a restore over live data fails entirely for these`);
    process.exitCode = 1;
  }
}

await main();
