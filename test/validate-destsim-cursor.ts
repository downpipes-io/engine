// Pins strict audit-feed cursor validation: a PRESENT but malformed afterSeq is a clear
// 400 instead of being silently coerced to 0 (which would replay the whole retained log and hide a client
// bug re-sending a corrupt cursor). An absent/empty cursor still defaults to 0; a valid float floors; the
// validation happens AFTER auth (an unauthenticated caller learns nothing about request shape).
//
// Run: node test/validate-destsim-cursor.ts

import { handleSupportPull, mintIngestCredential, type IngestGrant } from "../src/admin/support-ingest.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

// A scheduler stub that answers the two DO routes handleSupportPull needs for an audit-feed pull: the grant
// lookup and the export. The export honours afterSeq+limit so a valid cursor returns a real window.
function schedulerFor(grant: IngestGrant): DurableObjectStub {
  const rows = Array.from({ length: 30 }, (_v, i) => ({ seq: i + 1 }));
  return {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.pathname === "/ingest-credential") return new Response(JSON.stringify({ grant }), { headers: { "content-type": "application/json" } });
      if (u.pathname === "/ingest-credential/record-pull") return new Response("{}");
      if (u.pathname === "/audit/export") {
        const after = Math.floor(Number(u.searchParams.get("afterSeq") ?? "0")) || 0;
        const lim = Math.min(Math.max(Math.floor(Number(u.searchParams.get("limit") ?? "500")) || 500, 1), 1000);
        const events = rows.filter((r) => r.seq > after).slice(0, lim);
        return new Response(JSON.stringify({ events, headSeq: 30, headHash: "sha384:30", earliestSeq: 1 }), { headers: { "content-type": "application/json" } });
      }
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

const env = {} as Env;

async function main(): Promise<void> {
  const { clientId, secret, grant } = await mintIngestCredential("audit-feed", "owner@acme.example", undefined);
  const scheduler = schedulerFor(grant);
  const bearer = `${clientId}.${secret}`;
  const pull = (qs: string): Promise<Response> =>
    handleSupportPull(new Request(`https://engine.example/support/audit-feed${qs}`, { headers: { Authorization: `Bearer ${bearer}` } }), env, scheduler);

  // Valid / absent / empty cursors are accepted.
  {
    const r = await pull("?afterSeq=10&limit=5");
    const body = (await r.json()) as { afterSeq: number; count: number };
    ok("valid afterSeq=10: 200", r.status === 200);
    ok("valid afterSeq=10: echoes afterSeq and returns a window", body.afterSeq === 10 && body.count === 5);
  }
  ok("absent afterSeq: 200 (defaults to 0)", (await pull("?limit=5")).status === 200);
  ok("empty afterSeq (afterSeq=): 200 (treated as absent)", (await pull("?afterSeq=&limit=5")).status === 200);
  {
    const r = await pull("?afterSeq=3.9&limit=5");
    const body = (await r.json()) as { afterSeq: number };
    ok("float afterSeq=3.9: 200 and floored to 3", r.status === 200 && body.afterSeq === 3);
  }
  // Any value JS Number() parses to a finite non-negative number is accepted and floored -- deliberately
  // consistent with the DO's own parseAuditFilter, so the two boundaries never disagree. Hex and
  // whitespace-padded spellings resolve to a real seq, so they are valid cursors, not malformed.
  ok("hex afterSeq=0x10: 200 (Number parses it to 16, a valid cursor)", (await pull("?afterSeq=0x10&limit=5")).status === 200);
  ok("whitespace afterSeq=' 5 ': 200 (Number trims to 5)", (await pull(`?afterSeq=${encodeURIComponent(" 5 ")}&limit=5`)).status === 200);

  // Truly malformed cursors -- non-numeric or non-finite or negative -- are a clear 400 (never silently coerced
  // to 0). "1e400" overflows to Infinity, which would survive the Worker's clamp then make the DO drop BOTH the
  // cursor and the limit, returning the ENTIRE retained chain unpaginated. A finite check rejects it with a 400.
  for (const bad of ["abc", "NaN", "-1", "1e", "Infinity", "-Infinity", "hello world", "1e400", "9e999"]) {
    const r = await pull(`?afterSeq=${encodeURIComponent(bad)}&limit=5`);
    ok(`malformed afterSeq=${JSON.stringify(bad)}: 400 (never a silent replay-from-0)`, r.status === 400);
  }

  // The 400 is AFTER auth: an unauthenticated caller with a bad cursor still gets 401, not 400 (no request-
  // shape feedback to an anonymous caller).
  {
    const anon = await handleSupportPull(new Request("https://engine.example/support/audit-feed?afterSeq=abc"), env, scheduler);
    ok("unauthenticated + bad cursor: 401 (cursor validation never runs before auth)", anon.status === 401);
  }

  console.log(failures === 0 ? "\nDESTSIM CURSOR-STRICTNESS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
