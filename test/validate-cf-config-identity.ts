// Validates the self-identifying cf-config record (CF_CONFIG_IDENTITY_ID): every cf-config crawl emits a
// FIRST record naming WHICH account/zone this backup is for ({ v, accountId, zoneId?, zoneName? }), so a
// Cloudflare-config archive identifies its own zone without relying on the downpipe name (which lives only in
// config, not the backup). Covers: content for a zone crawl (accountId+zoneId+zoneName), an account-only crawl
// (accountId only), the fail-open zone-name read, resume-safety (not re-emitted after its watermark), and that
// it is emitted regardless of the surface selector. The CF API is stubbed (no network).
// Run: node test/validate-cf-config-identity.ts

import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { CF_CONFIG_SURFACES, CF_CONFIG_IDENTITY_ID } from "../src/sources/cf-config-surfaces.ts";
import type { Selector, SourceRecord, CrawlEvent } from "../src/sources/types.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const ALL: Selector = { include: [], exclude: [] };

// A stub that returns a real zone object (with a name) for the exact `/zones/<id>` path (the zone-name read),
// and the generic stub envelope for every surface read. `zoneFault` makes the zone-name read fail (fail-open).
function stubFetch(opts: { zoneId?: string; zoneName?: string; zoneFault?: boolean } = {}): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (opts.zoneId !== undefined && url.endsWith(`/zones/${opts.zoneId}`)) {
      if (opts.zoneFault) return new Response("upstream error", { status: 500 });
      return new Response(JSON.stringify({ success: true, result: { id: opts.zoneId, name: opts.zoneName ?? "example.com" } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, result: [{ stub: true }] }), { status: 200 });
  }) as typeof fetch;
}

async function collect(it: AsyncIterable<SourceRecord>): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of it) out.push(r);
  return out;
}
async function collectEvents(it: AsyncIterable<CrawlEvent>): Promise<CrawlEvent[]> {
  const out: CrawlEvent[] = [];
  for await (const e of it) out.push(e);
  return out;
}
function parseIdentity(rec: SourceRecord): { v?: unknown; accountId?: unknown; zoneId?: unknown; zoneName?: unknown } {
  return JSON.parse(new TextDecoder().decode(rec.value));
}

async function main(): Promise<void> {
  console.log("-- a zone crawl emits the identity record FIRST, with accountId+zoneId+zoneName --");
  {
    const src = new CloudflareConfigSource("tok", "acct-1", "zone-1", CF_CONFIG_SURFACES, stubFetch({ zoneId: "zone-1", zoneName: "example.com" }));
    const recs = await collect(src.crawl(ALL));
    ok("the FIRST record is the reserved identity record", recs[0]?.name === CF_CONFIG_IDENTITY_ID && recs[0]?.sourceType === "cf-config");
    ok("exactly one identity record is emitted", recs.filter((r) => r.name === CF_CONFIG_IDENTITY_ID).length === 1);
    const id = parseIdentity(recs[0]!);
    ok("identity records the accountId", id.accountId === "acct-1");
    ok("identity records the zoneId", id.zoneId === "zone-1");
    ok("identity records the human-readable zoneName (fetched from the API)", id.zoneName === "example.com");
    ok("identity carries a version tag", typeof id.v === "number");
    ok("the identity record never leaks a secret-shaped value", !new TextDecoder().decode(recs[0]!.value).includes("tok"));
    ok("the remaining records are all surfaces (one per registry surface)", recs.length === CF_CONFIG_SURFACES.length + 1);
  }

  console.log("-- an account-only crawl (no zone): identity has accountId, no zoneId/zoneName --");
  {
    const src = new CloudflareConfigSource("tok", "acct-2", undefined, CF_CONFIG_SURFACES, stubFetch());
    const recs = await collect(src.crawl(ALL));
    ok("account-only: the first record is still the identity record", recs[0]?.name === CF_CONFIG_IDENTITY_ID);
    const id = parseIdentity(recs[0]!);
    ok("account-only: identity has accountId", id.accountId === "acct-2");
    ok("account-only: identity has NO zoneId (account backup)", id.zoneId === undefined);
    ok("account-only: identity has NO zoneName", id.zoneName === undefined);
  }

  console.log("-- the zone-name read is FAIL-OPEN: a failed read still records accountId+zoneId --");
  {
    const src = new CloudflareConfigSource("tok", "acct-3", "zone-3", CF_CONFIG_SURFACES, stubFetch({ zoneId: "zone-3", zoneFault: true }));
    const recs = await collect(src.crawl(ALL));
    const id = parseIdentity(recs[0]!);
    ok("fail-open: the crawl still completes and emits the identity", recs[0]?.name === CF_CONFIG_IDENTITY_ID && recs.length > 1);
    ok("fail-open: identity still has accountId + zoneId (unambiguous)", id.accountId === "acct-3" && id.zoneId === "zone-3");
    ok("fail-open: zoneName is omitted, never a throw", id.zoneName === undefined);
  }

  console.log("-- the identity is emitted regardless of the surface selector --");
  {
    const src = new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, stubFetch({ zoneId: "z", zoneName: "z.example" }));
    const recs = await collect(src.crawl({ include: ["dns"], exclude: [] }));
    ok("a narrow (dns-only) downpipe still self-identifies (identity + the ticked surface)", recs.some((r) => r.name === CF_CONFIG_IDENTITY_ID) && recs.some((r) => r.name === "dns") && recs.length === 2);
  }

  console.log("-- RESUME-SAFETY: resuming after the identity watermark does not re-emit it --");
  {
    const src = new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, stubFetch({ zoneId: "z", zoneName: "z.example" }));
    // Resume from the mark emitted right after the identity record.
    const events = await collectEvents(src.crawlFrom(ALL, JSON.stringify({ after: CF_CONFIG_IDENTITY_ID })));
    const records = events.filter((e): e is Extract<CrawlEvent, { kind: "record" }> => e.kind === "record").map((e) => e.record);
    ok("resume after the identity watermark yields the surfaces", records.length === CF_CONFIG_SURFACES.length);
    ok("resume after the identity watermark does NOT re-emit the identity record", !records.some((r) => r.name === CF_CONFIG_IDENTITY_ID));
  }

  console.log(failures === 0 ? "\nCF-CONFIG IDENTITY PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
