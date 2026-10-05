// Shared fixtures for the site-fault proofs (test/validate-site-fault-*.ts).
//
// Each proof builds two worlds that differ only by one planted fault at one catch, builds the real support pack
// in each over the real SchedulerDO, and compares them. A pack that shows nothing of the fault is identical to
// its healthy twin once volatile values (times, durations) are masked. The sentinel is planted in the thrown
// error's message, stack, cause and an own property, and must never reach the pack or DO storage.

import { buildSupportBundle } from "../../src/admin/support.ts";
import type { Env } from "../../src/env.d.ts";
import type { SchedulerDO } from "../../src/sched/scheduler-do.ts";
import type { MockStorage } from "../validate-scheduler-shared.ts";

export const SENTINEL = "SENTINEL-u6-7f3a-acme-crown-jewels";

// sentinelError is a thrown value that carries the sentinel everywhere a careless recorder might read.
export function sentinelError(name = "Error"): Error {
  const e = new Error(`storage unavailable for ${SENTINEL}`, { cause: new Error(SENTINEL) });
  e.name = name;
  e.stack = `${name}: ${SENTINEL}\n    at ${SENTINEL} (file:///${SENTINEL}.ts:1:1)`;
  (e as unknown as Record<string, unknown>).detail = SENTINEL;
  return e;
}

// stubOver is a DurableObjectStub over a real DO instance, taking the (url, init) form the engine calls with.
export function stubOver(dobj: { fetch(req: Request): Promise<Response> }): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(input instanceof Request ? input : new Request(String(input), init)),
  } as unknown as DurableObjectStub;
}

export function namespaceOver(stub: DurableObjectStub): DurableObjectNamespace {
  return { idFromName: () => ({}) as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
}

export async function packOver(env: Partial<Env>, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  return buildSupportBundle(env as Env, scheduler);
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const VOLATILE_KEY = /(At|Ms|ms|Time|Seconds|seconds|Age|age|Since|since|generated)$/;

// normalise masks values that differ between two builds of the same world: times, durations and epoch numbers.
export function normalise(v: unknown, key = ""): unknown {
  // A measured duration inside prose ("responded in 3ms") changes between builds of the same world.
  if (typeof v === "string") return ISO.test(v) ? "<time>" : v.replace(/\b\d+(\.\d+)?\s?ms\b/g, "<n>ms");
  if (typeof v === "number") return VOLATILE_KEY.test(key) || v > 1e12 ? "<n>" : v;
  if (Array.isArray(v)) return v.map((x) => normalise(x, key));
  if (typeof v === "object" && v !== null) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) out[k] = normalise((v as Record<string, unknown>)[k], k);
    return out;
  }
  return v;
}

// diffPaths lists the JSON paths where two normalised packs differ.
export function diffPaths(a: unknown, b: unknown, at = "$"): string[] {
  if (JSON.stringify(a) === JSON.stringify(b)) return [];
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null || Array.isArray(a) !== Array.isArray(b)) return [at];
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const out: string[] = [];
  for (const k of [...keys].sort()) out.push(...diffPaths((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${at}.${k}`));
  return out;
}

export function siteFaultRows(pack: Record<string, unknown>): Array<Record<string, unknown>> {
  return Array.isArray(pack.siteFaults) ? (pack.siteFaults as Array<Record<string, unknown>>) : [];
}

// storageText is every value the scheduler DO holds, serialised, for the redaction scan.
export function storageText(storage: MockStorage): string {
  return storage.rawListKeys().map((k) => `${k}=${JSON.stringify(storage.rawGet(k))}`).join("\n");
}

export type Scheduler = SchedulerDO;

let failures = 0;
let checks = 0;
export function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
export function tally(): { failures: number; checks: number } {
  return { failures, checks };
}
