// validate-preflight-bucket-redaction: the preflight destination evidence must not carry the console-set bucket
// name or endpoint host.
//
// Preflight evidence rides in the vendor-bound support bundle (support.ts runs runPreflight). The destination
// probe sanitised only the env DEST_ENDPOINT / DEST_BUCKET values. A console-set destination is stored in the
// scheduler and wins over env, so its values passed through. On a timeout with path-style addressing, s3.ts
// names the request path `/<bucket>/_RECOVERY/RUNLOG`, and the evidence carried the bucket name.
// data-classification.md says the bundle never carries a bucket name.
//
// This validator drives the real probeDestination against a stubbed scheduler that returns a console-set S3
// destination. It proves:
//  - on a timeout (path-style), the evidence names neither the bucket nor the endpoint host, and still says
//    that the request timed out;
//  - on a doubled-bucket refusal (vhost addressing on a per-bucket URL), the evidence names neither the bucket
//    nor the endpoint host;
//  - the probe still reports the failure (status failed), so the redaction hides values, not the fault.
//
// The S3 fetch bound is 120 s (S3_FETCH_TIMEOUT_MS). The validator shortens only that timer, so the real
// abort path runs in milliseconds.
//
// Run: node test/validate-preflight-bucket-redaction.ts

import { probeDestination } from "../src/admin/preflight-probes.ts";
import { S3_FETCH_TIMEOUT_MS } from "../src/dest/s3.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const BUCKET = "acme-payroll-backups";
const HOST = "s3.storage.example.net";

// A scheduler stub that answers GET /dest-config with one console-set destination.
function schedulerWith(stored: Record<string, unknown>): DurableObjectStub {
  return {
    fetch: async (url: string) => {
      const p = new URL(url).pathname;
      if (p === "/dest-config") return new Response(JSON.stringify({ config: stored }));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function destinationItem(stored: Record<string, unknown>): Promise<Record<string, unknown> | undefined> {
  const items: Array<Record<string, unknown>> = [];
  await probeDestination(items as never, {} as Env, schedulerWith(stored));
  return items.find((i) => i.id === "destination");
}

async function main(): Promise<void> {
  const realFetch = globalThis.fetch;
  const realSetTimeout = globalThis.setTimeout;
  // The endpoint black-holes: it never answers and rejects only when aborted. The DoH lookup the endpoint
  // screen makes answers with a public address, so the request is let through to the black hole.
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (u.hostname === "cloudflare-dns.com") {
      return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "8.8.8.8" }] }), { headers: { "content-type": "application/dns-json" } });
    }
    return new Promise<Response>((_, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    });
  }) as typeof fetch;
  // Shorten only the S3 fetch bound.
  globalThis.setTimeout = ((fn: (...a: unknown[]) => void, ms?: number, ...rest: unknown[]) =>
    realSetTimeout(fn, ms === S3_FETCH_TIMEOUT_MS ? 5 : ms, ...rest)) as typeof setTimeout;

  try {
    const timeout = await destinationItem({ id: "d1", endpoint: `https://${HOST}`, bucket: BUCKET, region: "us-east-1", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "plain-legacy-secret", addressing: "path" });
    const tEvidence = String(timeout?.evidence ?? "");
    console.log(`  timeout evidence: ${tEvidence}`);
    ok("timeout: the probe reports the destination as failed", timeout?.status === "failed");
    ok("timeout: the evidence still says the request timed out", tEvidence.includes("timed out"));
    ok("timeout: the evidence does not carry the console-set bucket name", !tEvidence.includes(BUCKET));
    ok("timeout: the evidence does not carry the console-set endpoint host", !tEvidence.includes(HOST));

    const perBucketHost = `${BUCKET}.s3.us-east-1.amazonaws.com`;
    const doubled = await destinationItem({ id: "d2", endpoint: `https://${perBucketHost}`, bucket: BUCKET, region: "us-east-1", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "plain-legacy-secret", addressing: "vhost" });
    const dEvidence = String(doubled?.evidence ?? "");
    console.log(`  doubled-bucket evidence: ${dEvidence}`);
    ok("doubled bucket: the probe reports the destination as failed", doubled?.status === "failed");
    ok("doubled bucket: the evidence does not carry the console-set bucket name", !dEvidence.includes(BUCKET));
  } finally {
    globalThis.fetch = realFetch;
    globalThis.setTimeout = realSetTimeout;
  }

  console.log(failures === 0 ? "\nVALIDATE-PREFLIGHT-BUCKET-REDACTION VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
