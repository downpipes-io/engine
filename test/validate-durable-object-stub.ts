// The DurableObjectSource compile-only stub.
//
// This adapter exists so the engine carries a typed "durable_object" source member that lines up with
// the live SourceAdapter/ResumableSource interface, WITHOUT being selectable on a run. Two properties
// keep that promise honest and are pinned here:
//
//   1. Every entry point (crawl, crawlFrom, estimate) THROWS the same clear "not yet wired" error
//      rather than yielding nothing, so a future wiring change that reaches the stub before the
//      in-tenant export shim lands fails loudly instead of producing a silent empty backup.
//   2. validateConfig REJECTS a source.type of "durable_object", so no downpipe config can ever
//      select it (the allow-list and buildAdapter both omit it).
//
// Run: node test/validate-durable-object-stub.ts

import { DurableObjectSource } from "../src/sources/durable-object.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import type { Selector } from "../src/sources/types.ts";
import type { DownpipeConfig } from "../src/sched/scheduler-do.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const NOT_WIRED = /requires an in-tenant export shim.*not yet wired/;
const SELECTOR: Selector = { include: [], exclude: [] };

async function testCrawlThrows(): Promise<void> {
  console.log("\ndurable-object-stub: crawl throws (never a silent empty backup):");
  const src = new DurableObjectSource();
  ok("sourceType is durable_object", src.sourceType === "durable_object");

  // crawl throws on the call itself (it is not a generator), so reaching the stub fails immediately.
  let threw = "";
  try {
    const it = src.crawl(SELECTOR);
    // Should be unreachable; if crawl ever returns an iterator, draining it must still throw and
    // certainly must not yield a record (which would be a silent empty/partial backup).
    for await (const _r of it) {
      ok("crawl must not yield any record", false);
    }
  } catch (e) {
    threw = e instanceof Error ? e.message : String(e);
  }
  ok("crawl throws the not-wired error", NOT_WIRED.test(threw));
}

async function testCrawlFromThrows(): Promise<void> {
  console.log("\ndurable-object-stub: crawlFrom throws:");
  const src = new DurableObjectSource();
  let threw = "";
  try {
    const it = src.crawlFrom(SELECTOR, null);
    for await (const _ev of it) {
      ok("crawlFrom must not yield any event", false);
    }
  } catch (e) {
    threw = e instanceof Error ? e.message : String(e);
  }
  ok("crawlFrom throws the not-wired error", NOT_WIRED.test(threw));
}

async function testEstimateThrows(): Promise<void> {
  console.log("\ndurable-object-stub: estimate throws (no silent zero-record projection):");
  const src = new DurableObjectSource();
  let threw = "";
  try {
    await src.estimate(SELECTOR);
  } catch (e) {
    threw = e instanceof Error ? e.message : String(e);
  }
  ok("estimate throws the not-wired error", NOT_WIRED.test(threw));
}

function testConfigRejects(): void {
  console.log("\ndurable-object-stub: validateConfig rejects a durable_object source (not selectable):");
  // The config source union does not include "durable_object", so a config that names it is cast past
  // the type to prove the RUNTIME allow-list rejects it too (defence beyond the compile-time type).
  const cfg = {
    id: "dp_do",
    name: "durable object attempt",
    cadenceSeconds: 3600,
    enabled: true,
    source: { type: "durable_object", include: [], exclude: [] },
  } as unknown as DownpipeConfig;

  let threw = "";
  try {
    validateConfig(cfg);
  } catch (e) {
    threw = e instanceof Error ? e.message : String(e);
  }
  ok("validateConfig rejects source.type durable_object", threw.length > 0);
  ok("rejection names the permitted source types", /source\.type must be/.test(threw));
  ok("rejection does NOT list durable_object as permitted", !/durable_object/.test(threw));
}

async function main(): Promise<void> {
  await testCrawlThrows();
  await testCrawlFromThrows();
  await testEstimateThrows();
  testConfigRejects();

  console.log(failures === 0 ? "\nDURABLE OBJECT STUB TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
