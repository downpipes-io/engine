// Vendor Cloudflare's published OpenAPI schema so test/validate-cf-config-drift.ts (and its
// siblings validate-hand-damage-vs-schema.ts / validate-autoprove-bodies-vs-schema.ts) can
// cross-check the cf-config endpoint registry against Cloudflare's own API surface.
//
// It mirrors scripts/fetch-acvp.mjs, with one deliberate difference forced by a bug this repo
// found in itself: none of those three consumers check the file's AGE, only
// its PRESENCE. A vendored copy from months ago is therefore indistinguishable to them from one
// pulled seconds ago, and every one of them "passes confidently" against whichever it finds.
//
// DELETE-FIRST DISCIPLINE (the fix). Every invocation attempts a fresh fetch, unconditionally --
// there is no "leave any existing copy alone" fast path any more. After this script returns:
//   - exit 0  ->  dest holds a schema that was structurally validated and written THIS RUN.
//   - exit 1  ->  dest does NOT exist. If a copy was vendored before this run and the fetch could
//                 not refresh it, that copy is deleted rather than left in place, specifically so
//                 a stale schema can never survive an invocation to be silently graded as current.
// There is no third outcome where dest is left holding something this run did not just verify.
// That closes both needed routes: "delete before fetch" and "fail when it cannot fetch,
// rather than falling back to the stale copy" -- this does both, in the safer order (fetch first,
// only delete once the fetch is known to have failed, so a crash between the two steps can never
// lose a good copy that a successful fetch would have replaced anyway).
//
// FAIL CLOSED: a script that cannot fetch must not report a pass. Every path that does not end in
// a freshly-written, structurally-valid schema exits 1, including an unexpected error (disk full,
// permissions, a malformed body that parses but is not an OpenAPI document). The only exception is
// deliberate and unrelated to freshness: this script's own network reachability is not assumed, so
// "no network" is reported the same way as any other fetch failure -- exit 1, guidance printed --
// which is what lets `fetch-cf-openapi.mjs && REQUIRE_CF_OPENAPI=1 node test/validate-cf-config-drift.ts`
// (engine CI's own invocation) halt at the fetch step on a real outage rather than limping on to
// fail less clearly one step later.
//
// The write remains ATOMIC (temp file then rename): a fetch that returns a truncated or malformed
// body must never clobber a good vendored schema in place before the replacement is proven good.

import { mkdirSync, writeFileSync, existsSync, renameSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "test", "vectors", "cf-openapi");
const dest = join(outDir, "openapi.json");

// Cloudflare publishes its OpenAPI at the api-schemas repository (openapi.json). The same
// schema is the upstream the cf CLI / SDK / docs are generated from, so it is the right
// authority to diff our hand-maintained endpoint templates against.
const URLS = [
  "https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json",
  "https://raw.githubusercontent.com/cloudflare/api-schemas/master/openapi.json",
];

function guidance() {
  console.log("");
  console.log("No fresh Cloudflare OpenAPI was vendored. To enable the drift guard's Cloudflare");
  console.log("cross-check (Section 2) OFFLINE, obtain Cloudflare's published OpenAPI schema");
  console.log("from the api-schemas repository:");
  console.log("  https://github.com/cloudflare/api-schemas  ->  openapi.json");
  for (const u of URLS) console.log(`     ${u}`);
  console.log("and save it at:");
  console.log(`  ${dest}`);
  console.log("Then run:  node test/validate-cf-config-drift.ts");
  console.log("(Placing a file there by hand is still honest: the three consumers only trust");
  console.log(" what THIS script writes and verifies, and re-running this script will replace");
  console.log(" a hand-placed copy the next time the network is reachable.)");
}

async function fetchFirst(urls) {
  // Returns the first URL body that fetches and looks like an OpenAPI doc, or null.
  if (typeof fetch !== "function") return null;
  for (const u of urls) {
    try {
      const res = await fetch(u, { redirect: "follow" });
      if (res.ok) {
        const text = await res.text();
        // Sanity: must PARSE as an OpenAPI document with a paths object, so we never write a 404 page, a
        // renamed/empty file, or a TRUNCATED response as if it were the schema.
        //
        // Substring checks alone were not enough, and that was measured rather than supposed: the body
        // `{"openapi":"3.1.0","paths":{"/a":{` contains both markers, passed, and overwrote a good vendored
        // schema, leaving 34 bytes behind. On an offline box that copy is the only one there is. A truncated
        // download is the commonest way a fetch "succeeds" badly, so the check has to be structural.
        if (text.includes('"paths"') && text.includes('"openapi"')) {
          try {
            const doc = JSON.parse(text);
            if (doc && typeof doc === "object" && typeof doc.openapi === "string" && doc.paths && typeof doc.paths === "object") return text;
            console.error(`skipping ${u}: parsed, but it is not an OpenAPI document (no string openapi, or no paths object)`);
          } catch {
            console.error(`skipping ${u}: the response looked like OpenAPI but did not parse as JSON (truncated?)`);
          }
        }
      }
    } catch {
      // try the next url
    }
  }
  return null;
}

// --force is accepted and silently ignored: every invocation now behaves the way --force used to
// (always attempts a fresh fetch), so there is no longer a distinct "leave it alone" mode for it
// to opt out of. Kept so any existing caller that passes it does not need to change.

async function main() {
  mkdirSync(outDir, { recursive: true });
  const hadExisting = existsSync(dest);
  const body = await fetchFirst(URLS);
  if (body === null) {
    // DELETE-FIRST DISCIPLINE: this run could not verify a fresh schema, so any copy left over
    // from an earlier run is removed rather than left for the three consumers to grade as current
    // -- none of them check its age, only whether it exists.
    if (hadExisting) {
      try {
        unlinkSync(dest);
        console.error(`fetch failed; removed the previously vendored copy at ${dest} rather than leave it gradable as current`);
      } catch (e) {
        console.error(`fetch failed AND could not remove the stale copy at ${dest}: ${e?.message ? e.message : e}`);
      }
    } else {
      console.log("No network reachable, or Cloudflare's schema could not be fetched.");
    }
    guidance();
    process.exit(1); // FAIL CLOSED: a script that cannot fetch must not report a pass
  }
  // ATOMIC: write beside the target and rename over it, so a truncated or malformed body can never destroy a
  // good vendored schema in place before the replacement is proven good.
  const tmp = `${dest}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, body);
    renameSync(tmp, dest);
  } catch (e) {
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* best effort */ }
    // The write/rename itself failed (disk full, permissions...). dest may still hold whatever
    // was there before this run; remove it too, for the same delete-first reason as above -- this
    // run did not produce a verified-fresh artefact, so nothing stale should survive it.
    try { if (existsSync(dest)) unlinkSync(dest); } catch { /* best effort */ }
    throw e;
  }
  console.log(`vendored: ${dest} (${body.length} bytes)`);
  console.log("Run `node test/validate-cf-config-drift.ts` to run the Cloudflare cross-check.");
  process.exit(0);
}

main().catch((e) => {
  // FAIL CLOSED here too: an unexpected error (not just an ordinary fetch failure) still means
  // this run did not produce a verified-fresh artefact, so it must not report success either.
  console.error("fetch-cf-openapi: unexpected error:", e?.message ? e.message : e);
  guidance();
  process.exit(1);
});
