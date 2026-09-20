// support-pack-fault-oracle.ts -- THE SUPPORT PACK SCORED BACKWARDS, AGAINST EVERY DEFECT THIS CAMPAIGN HAS FOUND.
//
//   node tools/support-corpus/support-pack-fault-oracle.ts [--only <substring>] [--self-test] [--diff <n>]
//
// The requirement: the support pack has to have all the answers. So for every defect in the numbered
// boundaries-and-accumulation defect table (2026-08-11) -- if a customer hit it and sent a
// pack, would the pack identify the fault or look clean?
//
// WHAT MAKES THIS DIFFERENT FROM THE FIRST PASS. An earlier pass scored 9 of 22 by READING the generator and
// said so itself ("I PROVED THE INSTRUMENT AND DID NOT USE IT"). Every verdict here comes from a GENERATED
// PACK: the healthy baseline bundle and the faulted bundle are both built by the REAL `buildSupportBundle`
// over the REAL projectors, and the verdict is a function of the DIFFERENCE BETWEEN THEM plus a predicate
// asking whether the pack NAMES the fault.
//
// THE FOUR VERDICTS.
//   DIAGNOSABLE     the faulted pack names the fault, or names enough that an engineer reaches it.
//   PARTIAL         the pack differs from healthy but cannot say WHAT is wrong.
//   SILENT          the faulted pack is materially indistinguishable from the healthy one. The worst outcome.
//   NOT-APPLICABLE  the pack should not be expected to see it, with the reason stated per defect.
//
// SILENT IS DECIDED BY MEASUREMENT, NOT BY OPINION: the two bundles are canonicalised, their volatile stamps
// normalised, and their JSON path sets differenced. An empty difference is the definition.
//
// TWO CONTROLS, BOTH LOAD-BEARING, BOTH RUN BEFORE ANY VERDICT IS TAKEN AND BOTH ABLE TO FAIL THE WHOLE RUN:
//   POSITIVE  a world that IS different (one extra downpipe) must produce a NON-EMPTY diff. Without it a
//             broken normaliser would report every defect SILENT and the run would look like a finding.
//   NEGATIVE  the healthy world, built twice, must produce an EMPTY diff. Without it clock jitter alone would
//             report every defect DIAGNOSABLE and the run would look like a clean bill of health.
//
// AND THE POPULATION IS ASSERTED. "The pack diagnosed everything" is also true of a run that generated no
// faults, so the scorecard prints its denominator, and a run that adjudicates zero probes exits 2.

import { buildSupportBundle } from "../../src/admin/support.ts";
import { projectClientDiagnostics } from "../../src/admin/client-diag-receive.ts";
import { healthyWorld, makeKeys, type HarnessKeys, type NetRule, type Routes, type World } from "./harness.ts";
import type { Env } from "../../src/env.d.ts";

type Dict = Record<string, unknown>;

// ---------------------------------------------------------------------------------------------------------
// The probe contract

export type Where = "engine" | "console" | "docs" | "website" | "control-plane";

export interface Probe {
  /** The ordinal in the defect table. */
  n: number;
  /** Short name, taken from the table's own "what" column. */
  what: string;
  where: Where;
  /**
   * Induce the fault in the world the pack is built from. A console-only render fault induces NOTHING here,
   * deliberately and by construction: the engine's world does not move, which is exactly the measurement.
   */
  mutate: (w: World) => void;
  /** Optional console-asserted evidence the browser would post with the pack (the clientDiagnostics half). */
  clientDiag?: () => unknown;
  /**
   * Does the pack NAME the fault? Return [] when it does, or one string per thing it cannot say. Only
   * consulted when the diff is non-empty (a byte-identical pack names nothing by definition).
   */
  names: (faulted: Dict, healthy: Dict, diff: string[]) => string[];
  /** When set, the defect is scored NOT-APPLICABLE and this is the reason. */
  notApplicable?: string;
  /** Free prose carried into the scorecard. */
  note?: string;
}

export type Verdict = "DIAGNOSABLE" | "PARTIAL" | "SILENT" | "NOT-APPLICABLE";

// ---------------------------------------------------------------------------------------------------------
// Normalisation: everything that moves between two runs of the SAME world, and nothing else.

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
/** Epoch-millisecond range: 2017-07-14 to 2096-10-02. Wide enough for every stamp, narrow enough to miss counts. */
const EPOCH_LO = 1_500_000_000_000;
const EPOCH_HI = 4_000_000_000_000;

function normalise(v: unknown): unknown {
  if (typeof v === "string") return ISO_RE.test(v) ? "<ISO>" : v;
  if (typeof v === "number") return Number.isFinite(v) && v >= EPOCH_LO && v <= EPOCH_HI ? "<EPOCH>" : v;
  if (Array.isArray(v)) return v.map(normalise);
  if (typeof v === "object" && v !== null) {
    const out: Dict = {};
    for (const k of Object.keys(v as Dict).sort()) out[k] = normalise((v as Dict)[k]);
    return out;
  }
  return v;
}

/** Flatten to `path = json` leaves, so a difference is reported as the PATH that moved. */
function leaves(v: unknown, path: string, out: Map<string, string>): void {
  if (Array.isArray(v)) {
    out.set(`${path}.length`, String(v.length));
    v.forEach((e, i) => {
      leaves(e, `${path}[${i}]`, out);
    });
    return;
  }
  if (typeof v === "object" && v !== null) {
    for (const k of Object.keys(v as Dict)) leaves((v as Dict)[k], path === "" ? k : `${path}.${k}`, out);
    return;
  }
  out.set(path, JSON.stringify(v));
}

/** The set of JSON paths on which the two bundles disagree, each rendered `path: healthy -> faulted`. */
export function diffBundles(healthy: Dict, faulted: Dict): string[] {
  const a = new Map<string, string>();
  const b = new Map<string, string>();
  leaves(normalise(healthy), "", a);
  leaves(normalise(faulted), "", b);
  const keys = new Set([...a.keys(), ...b.keys()]);
  const out: string[] = [];
  for (const k of [...keys].sort()) {
    const x = a.get(k);
    const y = b.get(k);
    if (x !== y) out.push(`${k}: ${x ?? "(absent)"} -> ${y ?? "(absent)"}`);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// Building one pack

function stubFromRoutes(routes: Routes): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> } {
  return {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const v = routes[url.pathname];
      if (v === undefined) return new Response(JSON.stringify({}));
      const body = init?.body !== undefined ? (JSON.parse(String(init.body)) as unknown) : undefined;
      const payload = typeof v === "function" ? (v as (u: URL, b: unknown) => unknown)(url, body) : v;
      if (payload instanceof Response) return payload;
      return new Response(JSON.stringify(payload));
    },
  };
}

function installNet(rules: NetRule[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = input instanceof Request ? input.url : String(input);
    for (const r of rules) if (r.re.test(url)) return new Response(r.body ?? "", { status: r.status, headers: r.headers ?? {} });
    throw new Error(`support-pack-fault-oracle: unexpected network egress to ${url}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

/**
 * THE CLOCK IS FROZEN for the whole build. Two builds of the same world must be byte-identical or the
 * negative control cannot hold, and `now` is threaded through the healthy world's own route payloads.
 */
const FROZEN_NOW = 1_786_000_000_000;

export async function buildPack(mutate: (w: World) => void, keys: HarnessKeys, clientDiag?: unknown): Promise<Dict> {
  const w = healthyWorld(FROZEN_NOW, keys);
  mutate(w);
  const restore = installNet(w.net);
  const realNow = Date.now;
  Date.now = (): number => FROZEN_NOW;
  try {
    const ctx = clientDiag === undefined ? {} : { clientDiagnostics: projectClientDiagnostics(clientDiag) };
    return (await buildSupportBundle(w.env as unknown as Env, stubFromRoutes(w.routes) as never, ctx as never)) as Dict;
  } finally {
    Date.now = realNow;
    restore();
  }
}

// ---------------------------------------------------------------------------------------------------------
// Small readers the probes share

export function rows(b: Dict): Dict[] {
  return Array.isArray(b.downpipes) ? (b.downpipes as Dict[]) : [];
}
export function sec(b: Dict, name: string): Dict {
  const v = b[name];
  return (typeof v === "object" && v !== null ? v : {}) as Dict;
}
export function sectionStatus(b: Dict, name: string): string {
  const s = sec(b, "sections");
  return typeof s[name] === "string" ? (s[name] as string) : "(absent)";
}
/** Does any leaf anywhere in the bundle contain this substring? The pack's own bytes, searched. */
export function packSays(b: Dict, needle: string): boolean {
  return JSON.stringify(b).includes(needle);
}
/** Every diff path mentioning a section, for quoting in the report. */
export function diffUnder(diff: string[], prefix: string): string[] {
  return diff.filter((d) => d.startsWith(`${prefix}.`) || d.startsWith(`${prefix}:`) || d.startsWith(`${prefix}[`));
}

export const NOOP = (_w: World): void => {
  // A console-side or published-artefact defect moves NOTHING in the engine's world. Inducing nothing is the
  // measurement, not a shortcut: the pack the customer sends is the pack below.
};

// ---------------------------------------------------------------------------------------------------------
// The run

export interface Scored {
  n: number;
  what: string;
  where: Where;
  verdict: Verdict;
  diff: string[];
  cannotSay: string[];
  reason?: string | undefined;
  note?: string | undefined;
}

export async function score(probes: Probe[]): Promise<{ scored: Scored[]; healthy: Dict }> {
  const keys = await makeKeys();

  // CONTROL 1 (NEGATIVE): the same world twice must be byte-identical, or clock jitter would report every
  // defect DIAGNOSABLE and the run would look like a clean bill of health.
  const healthy = await buildPack(NOOP, keys);
  const healthyAgain = await buildPack(NOOP, keys);
  const drift = diffBundles(healthy, healthyAgain);
  if (drift.length !== 0) {
    console.log(`CONTROL FAILED (negative): the healthy world built twice differs on ${drift.length} path(s):`);
    for (const d of drift.slice(0, 10)) console.log(`  ${d}`);
    process.exit(2);
  }

  // CONTROL 2 (POSITIVE): a world that IS different must produce a non-empty diff, or a broken normaliser
  // would report every defect SILENT and the run would look like a finding.
  const plus = await buildPack((w: World): void => {
    (w.routes["/downpipes"] as unknown[]).push({
      config: { id: "dp-control", name: "control", enabled: true, cadenceSeconds: 3600, source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "ns", include: [], exclude: [] } },
      lastRunId: null,
      inFlight: false,
    });
  }, keys);
  const pos = diffBundles(healthy, plus);
  if (pos.length === 0) {
    console.log("CONTROL FAILED (positive): a world with an extra downpipe produced an EMPTY diff, so the comparator sees nothing and every SILENT verdict below would be manufactured.");
    process.exit(2);
  }
  console.log(`controls: negative 0 differing paths, positive ${pos.length} differing paths. Both hold.\n`);

  const scored: Scored[] = [];
  for (const p of probes) {
    if (p.notApplicable !== undefined) {
      scored.push({ n: p.n, what: p.what, where: p.where, verdict: "NOT-APPLICABLE", diff: [], cannotSay: [], reason: p.notApplicable, note: p.note });
      continue;
    }
    const faulted = await buildPack(p.mutate, keys, p.clientDiag?.());
    // A PROBE THAT DECLARES BROWSER EVIDENCE AND PRODUCES NONE IS VACUOUS, AND IT FAILS SILENTLY IN THE
    // FLATTERING DIRECTION: `projectClientDiagnostics` fails a record CLOSED on any non-member value, so one
    // wrong screen id drops the whole row and the probe then measures a pack with no console evidence in it
    // while reporting on the console half. That is exactly the shape this campaign exists to remove, so it
    // fails the run rather than the probe.
    if (p.clientDiag !== undefined) {
      const cd = (typeof faulted.clientDiagnostics === "object" && faulted.clientDiagnostics !== null ? faulted.clientDiagnostics : {}) as Dict;
      const kept = Array.isArray(cd.records) ? (cd.records as unknown[]).length : 0;
      // THE SECTION'S PRESENCE IS NOT THE TEST, and finding that out is the point: a record dropped on arrival
      // still leaves `{source, receivedAt, records: []}` behind, so a guard on the section would have passed on
      // a probe measuring nothing. The COUNT is the test.
      if (kept === 0) {
        console.log(`REFUSE: probe ${p.n} supplies console evidence and the pack KEPT ZERO records, so the row was failed closed on arrival and this probe measures nothing.`);
        process.exit(2);
      }
    }
    const diff = diffBundles(healthy, faulted);
    const cannotSay = p.names(faulted, healthy, diff);
    const verdict: Verdict = diff.length === 0 ? "SILENT" : cannotSay.length === 0 ? "DIAGNOSABLE" : "PARTIAL";
    scored.push({ n: p.n, what: p.what, where: p.where, verdict, diff, cannotSay, note: p.note });
  }
  return { scored, healthy };
}
