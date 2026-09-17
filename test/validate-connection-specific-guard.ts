// validate-connection-specific-guard: a request carrying a hop-by-hop header the edge forwarded is refused
// with a fixed 400 before routing (ASVS V4.2.3), the identical request without it is served (the guard
// discriminates), `te: trailers` passes and any other te value is refused, and the edge-injected
// `connection: Keep-Alive` is never refused (refusing it would refuse all traffic).
import worker from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { connectionSpecificHeaderRefusal } from "../src/admin/connection-specific-guard.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
let failures = 0;
function ok(label: string, cond: boolean): void { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`); if (!cond) failures++; }
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const go = (headers: Record<string, string>) => worker.fetch(new Request("https://engine.example/ready", { headers }), {} as Env, ctx);
async function main(): Promise<void> {
  console.log("\nrefused: each forwarded hop-by-hop field, fixed body, value never echoed");
  for (const [name, value] of [["proxy-connection", "keep-alive"], ["transfer-encoding", "chunked"], ["keep-alive", "timeout=5"], ["upgrade", "h2c"], ["te", "gzip"]] as const) {
    const r = await go({ [name]: value }); const body = await r.text();
    ok(`${name}: ${value} -> 400 fixed body`, r.status === 400 && body === "malformed request: connection-specific header\n");
    ok(`${name}: value not echoed`, !body.includes(value));
  }
  console.log("\nserved: the same request clean, te: trailers, and the edge-injected connection: Keep-Alive");
  ok("no hop-by-hop header -> 200 (the guard discriminates)", (await go({})).status === 200);
  ok("te: trailers -> 200", (await go({ te: "trailers" })).status === 200);
  ok("te: Trailers (case) -> 200", (await go({ te: " Trailers " })).status === 200);
  ok("connection: Keep-Alive alone -> 200 (the edge sets this on every origin request)", (await go({ connection: "Keep-Alive" })).status === 200);
  console.log("\nhelper: names the offending field");
  ok("names proxy-connection", connectionSpecificHeaderRefusal(new Headers({ "proxy-connection": "x" })) === "proxy-connection");
  ok("names te for a non-trailers value", connectionSpecificHeaderRefusal(new Headers({ te: "deflate" })) === "te");
  ok("clean headers -> undefined", connectionSpecificHeaderRefusal(new Headers({ accept: "*/*" })) === undefined);
  console.log(failures === 0 ? "\nCONNECTION-SPECIFIC GUARD VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures); if (failures > 0) process.exit(1);
}
void main();
