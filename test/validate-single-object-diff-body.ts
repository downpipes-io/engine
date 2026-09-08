// A one-object PATCH sends only the fields that DIFFER. A PUT still sends the whole object.
//
// WHY THIS MATTERS
// -----------------
// The published contract for an in-band restore is that it "applies only the fields that differ". Every
// list writer does that item by item, and a single-object writer must too, because Cloudflare validates
// the whole PATCH body: ONE field the account cannot set refuses the ENTIRE write, so a plan-gated
// neighbour riding along in a whole-object body can make an otherwise-writable field unwritable. For
// example, PATCH /zones/{id}/dns_settings with the whole object can return HTTP 400 "Custom SOA records
// are not available to this account or zone", while the same change sent as {multi_provider: true} returns
// 200 and takes.
//
// WHAT IT CHECKS
// --------------
//   1. PATCH sends only the changed keys, and does NOT send unchanged ones. The second half is the point:
//      an unchanged plan-gated key is exactly what sank the write.
//   2. PUT still sends the whole object, because PUT means replace and a partial body would delete the
//      keys left out. The method is declared per surface, so the behaviour follows the declaration.
//   3. A nested object that changed is sent whole, not partially. Cloudflare merges a partial nested PATCH
//      on the one endpoint where that was measured, but PATCH semantics for nested objects are not
//      guaranteed across the API, and an endpoint that REPLACES would silently delete the siblings left
//      out. Sending the changed nested object whole is the safe reading, and this pins it so that
//      "recurse one level" is a deliberate decision with evidence rather than a tidy-up.
//   4. Equality ignores volatile churn, so a surface that only ever differs in a field jsonEqual skips
//      does not send a request at all.
//
//   node test/validate-single-object-diff-body.ts

import type { CfApi } from "../src/sources/cf-config-surfaces.ts";
import { writeSingleObject } from "../src/sources/cf-config-write-settings.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail === "" ? "" : ` (${detail})`}`);
  if (!cond) failures++;
}

interface Sent {
  method: string;
  path: string;
  body: unknown;
}

function doubleFor(live: Record<string, unknown>): { api: CfApi; sent: Sent[] } {
  const sent: Sent[] = [];
  const api: CfApi = {
    get: async () => structuredClone(live),
    getPage: async () => ({ result: [structuredClone(live)], result_info: { page: 1, total_pages: 1 } }),
    send: async (method, path, body) => {
      sent.push({ method, path, body });
      return null;
    },
  };
  return { api, sent };
}

const IDS = { accountId: "acct", zoneId: "zone" };
const OPTS = { dryRun: false };

// --- 1. PATCH sends the diff only -------------------------------------------------------------------
{
  const live = { multi_provider: false, flatten_all_cnames: false, foundation_dns: false, ns_ttl: 86400 };
  const snap = { multi_provider: true, flatten_all_cnames: false, foundation_dns: false, ns_ttl: 86400 };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/zones/zone/dns_settings", "PATCH", "dns-settings");
  const res = await w(api, IDS, snap, OPTS, undefined);
  const body = (sent[0]?.body ?? {}) as Record<string, unknown>;
  ok("PATCH: exactly one request is sent", sent.length === 1, `sent ${sent.length}`);
  ok("PATCH: the changed key is in the body", body.multi_provider === true);
  ok("PATCH: an unchanged plan-gated key is NOT in the body", !("flatten_all_cnames" in body), JSON.stringify(body));
  ok("PATCH: no other unchanged key is in the body", Object.keys(body).length === 1, JSON.stringify(body));
  ok("PATCH: the write is reported as applied", res.applied === 1);
}

// --- 2. PUT still sends the whole object -------------------------------------------------------------
{
  const live = { a: 1, b: 2 };
  const snap = { a: 9, b: 2 };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/accounts/acct/workers/account-settings", "PUT", "workers-account-settings");
  await w(api, IDS, snap, OPTS, undefined);
  const body = (sent[0]?.body ?? {}) as Record<string, unknown>;
  ok("PUT: the whole object is sent, not a diff", body.a === 9 && body.b === 2, JSON.stringify(body));
}

// --- 3. a changed nested object is sent WHOLE --------------------------------------------------------
{
  const live = { zone_defaults: { multi_provider: false, flatten_all_cnames: false, ns_ttl: 86400 }, other: "same" };
  const snap = { zone_defaults: { multi_provider: true, flatten_all_cnames: false, ns_ttl: 86400 }, other: "same" };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/accounts/acct/dns_settings", "PATCH", "account-dns-settings");
  await w(api, IDS, snap, OPTS, undefined);
  const body = (sent[0]?.body ?? {}) as Record<string, unknown>;
  const zd = (body.zone_defaults ?? {}) as Record<string, unknown>;
  ok("nested: only the changed top-level key is sent", Object.keys(body).length === 1 && "zone_defaults" in body, JSON.stringify(body));
  ok("nested: WITHOUT nestedDiff the changed nested object is sent WHOLE, siblings included", Object.keys(zd).length === 3, JSON.stringify(zd));
}

// --- 4. no request at all when nothing differs -------------------------------------------------------
{
  const live = { a: 1, b: 2 };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/zones/zone/thing", "PATCH", "thing");
  const res = await w(api, IDS, { a: 1, b: 2 }, OPTS, undefined);
  ok("identical snapshot sends nothing", sent.length === 0, `sent ${sent.length}`);
  ok("identical snapshot reports no change", res.applied === 0 && res.changes.length === 0);
}

// --- 5. nestedDiff: true sends only the changed field INSIDE the nested object -------------------------
//
// account-dns-settings reads an `soa` block it never changes, and a Free account refuses the whole-object
// body with "Custom SOA records are not available to this account or zone", so the surface could not be
// restored at all over a field nobody touched. Cloudflare deep-merges the partial body on this endpoint.
{
  const live = { zone_defaults: { multi_provider: false, soa: { ttl: 3600, mname: null }, ns_ttl: 86400 } };
  const snap = { zone_defaults: { multi_provider: true, soa: { ttl: 3600, mname: null }, ns_ttl: 86400 } };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/accounts/acct/dns_settings", "PATCH", "account-dns-settings", { nestedDiff: true });
  await w(api, IDS, snap, OPTS, undefined);
  const zd = ((sent[0]?.body as Record<string, unknown>)?.zone_defaults ?? {}) as Record<string, unknown>;
  ok("nestedDiff: only the changed nested field is sent", Object.keys(zd).length === 1 && zd.multi_provider === true, JSON.stringify(zd));
  ok("nestedDiff: the untouched soa block is NOT sent", !("soa" in zd), JSON.stringify(zd));
}

// --- 6. nestedDiff edge cases, each one a way a partial body could be WRONG ----------------------------
{
  // An ARRAY is sent whole. A partial array cannot say which elements it replaces, so narrowing one would
  // be a silent truncation rather than a smaller change.
  const live = { cfg: { list: ["a", "b", "c"], flag: false } };
  const snap = { cfg: { list: ["a", "z"], flag: false } };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/x", "PATCH", "x", { nestedDiff: true });
  await w(api, IDS, snap, OPTS, undefined);
  const cfg = ((sent[0]?.body as Record<string, unknown>)?.cfg ?? {}) as Record<string, unknown>;
  ok("nestedDiff: a changed array is sent WHOLE", JSON.stringify(cfg.list) === JSON.stringify(["a", "z"]), JSON.stringify(cfg));
  ok("nestedDiff: the unchanged sibling is omitted", !("flag" in cfg), JSON.stringify(cfg));
}
{
  // A nested object the LIVE side does not have has nothing to merge into, so it goes whole.
  const live = { present: 1 };
  const snap = { present: 1, added: { a: 1, b: 2 } };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/x", "PATCH", "x", { nestedDiff: true });
  await w(api, IDS, snap, OPTS, undefined);
  const body = (sent[0]?.body ?? {}) as Record<string, unknown>;
  ok("nestedDiff: an object absent from live is sent whole", JSON.stringify(body.added) === JSON.stringify({ a: 1, b: 2 }), JSON.stringify(body));
}
{
  // Two levels down, so the recursion is exercised rather than one level of special-casing.
  const live = { a: { b: { c: 1, keep: "same" }, sibling: "same" } };
  const snap = { a: { b: { c: 2, keep: "same" }, sibling: "same" } };
  const { api, sent } = doubleFor(live);
  const w = writeSingleObject(() => "/x", "PATCH", "x", { nestedDiff: true });
  await w(api, IDS, snap, OPTS, undefined);
  ok("nestedDiff: narrows two levels down", JSON.stringify(sent[0]?.body) === JSON.stringify({ a: { b: { c: 2 } } }), JSON.stringify(sent[0]?.body));
}

console.log(failures === 0 ? "\nSINGLE-OBJECT DIFF BODY PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
