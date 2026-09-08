// The Azure Blob destination, driven against an in-memory Azure that speaks the real wire protocol.
//
// WHY A MOCK RATHER THAN A LIVE ACCOUNT. Every assertion here has to be re-runnable by any pass and by
// CI, with no credential and no third party. A destination whose only proof needs an Azure subscription
// is a destination nobody can grade after the person who built it moves on. The mock below implements
// the SHAPES Azure actually returns, taken from the protocol rather than invented to suit the client:
// a 404 for an absent blob, a 412 for a failed precondition, a quoted ETag, and a List Blobs document
// with NextMarker paging.
//
// WHAT THE MOCK DELIBERATELY DOES NOT DO is authenticate. It asserts that an Authorization header of the
// right SHAPE arrived, and the signing itself is graded character for character against Microsoft's own
// published examples in validate-azure-sharedkey.ts. Splitting it that way means neither file passes for
// the other's reasons: a signer that produced a correct-looking wrong signature would pass here and fail
// there, which is the right way round.
//
// Run: node test/validate-azure-blob.ts

import { AzureBlobDestination, AZURE_BLOCK_SIZE, azurePacerStatus } from "../src/dest/azure-blob.ts";
import { looksLikeAzureSasToken } from "../src/dest/azure-sas.ts";
import { AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER } from "../src/dest/azure-worm.ts";
import { DestBuildError } from "../src/dest/build-health.ts";
import { isObjectLockRefusalStamped } from "../src/dest/classify.ts";
import { pendingDestIo, resetPendingDestIo } from "../src/dest/dest-io.ts";
import { DestPacer } from "../src/dest/pace.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

const ACCOUNT = "acct";
const ENDPOINT = `https://${ACCOUNT}.blob.core.windows.net`;
const CONTAINER = "archive";
const KEY_B64 = "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk=";
const FIXED = (): Date => new Date("2026-08-25T00:00:00Z");

interface Blob {
  body: Uint8Array;
  etag: string;
  // The immutability policy the CREATING write carried, or undefined when it carried none. Recorded on the
  // blob rather than only in the request log so a test can assert the policy landed on the object that was
  // committed, which for a block-staged write is not the request that carried the bytes.
  policy?: { until: string; mode: string };
}

/** policyOf reads the immutability policy off ONE request's headers, so the mock can record what the
 *  creating write asked for. Both headers must be present to count as a policy: Azure takes them as a pair,
 *  and a client that sent one of them would be sending something no store would apply. */
function policyOf(headers: Record<string, string>): { policy?: { until: string; mode: string } } {
  const until = headers["x-ms-immutability-policy-until-date"];
  const mode = headers["x-ms-immutability-policy-mode"];
  return until === undefined || mode === undefined ? {} : { policy: { until, mode } };
}

/** An in-memory Azure Blob service. Records every request so a test can assert the WIRE shape, not only
 *  the outcome: an implementation that got the right answer by the wrong request is a real defect. */
class MockAzure {
  blobs = new Map<string, Blob>();
  staged = new Map<string, Uint8Array>();
  requests: { method: string; path: string; query: string; headers: Record<string, string> }[] = [];
  private seq = 0;
  /** When set, the next matching request answers this status instead. */
  fail: { method?: string; status: number; code?: string } | null = null;
  /** What Get Container Properties says about VERSION-LEVEL IMMUTABILITY, which is the fact the WORM
   *  capability probe reads. "absent" omits the header entirely, which is a real answer and not a
   *  malformed one: it is what a container without the feature looks like. "denied" and "server-error"
   *  drive the two could-not-check arms. */
  vlw: "true" | "false" | "absent" | "denied" | "server-error" | "redirect" = "absent";
  /** Set when the mock should accept a SAS-authenticated request (no Authorization header, a signature in
   *  the query) as well as a Shared Key one. Kept OFF by default so every existing section still proves
   *  that its requests were signed. */
  acceptSas = false;

  private nextEtag(): string {
    this.seq += 1;
    return `"0x${this.seq.toString(16).padStart(16, "0")}"`;
  }

  handler = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = String(v);
    this.requests.push({ method, path: decodeURIComponent(url.pathname), query: url.search, headers });

    if (this.fail !== null && (this.fail.method === undefined || this.fail.method === method)) {
      const f = this.fail;
      this.fail = null;
      return new Response("", { status: f.status, headers: f.code === undefined ? {} : { "x-ms-error-code": f.code } });
    }

    // Every credentialed call must be authenticated one way or the other, and the two ways are mutually
    // exclusive on the wire: a Shared Key request carries an Authorization header, a SAS request carries a
    // signature in the query and NO Authorization header at all. Asserted here so a client that forgot to
    // sign one op, or that sent both, fails loudly rather than being caught only by a live account.
    const sasSigned = (url.searchParams.get("sig") ?? "") !== "";
    if (this.acceptSas && sasSigned) {
      if ((headers.authorization ?? "") !== "") return new Response("", { status: 403, headers: { "x-ms-error-code": "AuthenticationFailed" } });
    } else if (!/^SharedKey acct:/.test(headers.authorization ?? "")) {
      return new Response("", { status: 403, headers: { "x-ms-error-code": "AuthenticationFailed" } });
    }

    const parts = url.pathname.replace(/^\//, "").split("/");
    const container = decodeURIComponent(parts[0] ?? "");
    const key = parts.slice(1).map(decodeURIComponent).join("/");
    const comp = url.searchParams.get("comp");

    // Get Container Properties: the WORM capability probe. A container-root GET with restype=container and
    // no comp, answering the version-level immutability header.
    if (url.searchParams.get("restype") === "container" && comp === null) {
      if (this.vlw === "denied") return new Response("", { status: 403, headers: { "x-ms-error-code": "AuthorizationPermissionMismatch" } });
      if (this.vlw === "server-error") return new Response("", { status: 500, headers: { "x-ms-error-code": "InternalError" } });
      if (this.vlw === "redirect") return new Response("", { status: 302, headers: { location: "https://elsewhere.example/" } });
      return new Response(null, { status: 200, headers: this.vlw === "absent" ? {} : { [AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER]: this.vlw } });
    }

    if (comp === "list") {
      const prefix = url.searchParams.get("prefix") ?? "";
      const marker = url.searchParams.get("marker") ?? "";
      const all = [...this.blobs.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = marker === "" ? 0 : all.indexOf(marker);
      const page = all.slice(start, start + 2);
      const rest = all.slice(start + 2);
      const names = page.map((k) => `<Blob><Name>${k.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</Name></Blob>`).join("");
      const next = rest.length > 0 ? `<NextMarker>${rest[0]}</NextMarker>` : "<NextMarker />";
      return new Response(`<?xml version="1.0"?><EnumerationResults><Blobs>${names}</Blobs>${next}</EnumerationResults>`, { status: 200 });
    }

    if (method === "PUT" && comp === "block") {
      const id = url.searchParams.get("blockid") ?? "";
      this.staged.set(`${key}#${id}`, new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer()));
      return new Response("", { status: 201 });
    }

    if (method === "PUT" && comp === "blocklist") {
      const xml = await new Response(init?.body as BodyInit).text();
      const ids = [...xml.matchAll(/<Latest>([^<]*)<\/Latest>/g)].map((m) => m[1] ?? "");
      let total = 0;
      const chunks = ids.map((id) => {
        const c = this.staged.get(`${key}#${id}`);
        if (c === undefined) throw new Error(`mock: block ${id} was committed but never staged`);
        total += c.byteLength;
        return c;
      });
      const body = new Uint8Array(total);
      let at = 0;
      for (const c of chunks) {
        body.set(c, at);
        at += c.byteLength;
      }
      const etag = this.nextEtag();
      this.blobs.set(key, { body, etag, ...policyOf(headers) });
      return new Response("", { status: 201, headers: { etag } });
    }

    if (method === "PUT") {
      if (container !== CONTAINER) return new Response("", { status: 404, headers: { "x-ms-error-code": "ContainerNotFound" } });
      const existing = this.blobs.get(key);
      const ifNone = headers["if-none-match"];
      const ifMatch = headers["if-match"];
      if (ifNone === "*" && existing !== undefined) return new Response("", { status: 409, headers: { "x-ms-error-code": "BlobAlreadyExists" } });
      if (ifMatch !== undefined && (existing === undefined || existing.etag !== ifMatch)) return new Response("", { status: 412, headers: { "x-ms-error-code": "ConditionNotMet" } });
      const body = new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer());
      const etag = this.nextEtag();
      this.blobs.set(key, { body, etag, ...policyOf(headers) });
      return new Response("", { status: 201, headers: { etag } });
    }

    const blob = this.blobs.get(key);
    if (method === "GET") {
      if (blob === undefined) return new Response("", { status: 404, headers: { "x-ms-error-code": "BlobNotFound" } });
      return new Response(blob.body as unknown as BodyInit, { status: 200, headers: { etag: blob.etag } });
    }
    if (method === "HEAD") return new Response("", { status: blob === undefined ? 404 : 200, ...(blob === undefined ? {} : { headers: { etag: blob.etag } }) });
    if (method === "DELETE") {
      if (blob === undefined) return new Response("", { status: 404, headers: { "x-ms-error-code": "BlobNotFound" } });
      this.blobs.delete(key);
      return new Response("", { status: 202 });
    }
    return new Response("", { status: 405 });
  };
}

function install(mock: MockAzure): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = mock.handler as unknown as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

const mk = (): AzureBlobDestination => new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED });

async function construction(): Promise<void> {
  console.log("construction is fail-loud, before any request:");
  let cause = "";
  try {
    new AzureBlobDestination("http://acct.blob.core.windows.net", CONTAINER, ACCOUNT, KEY_B64);
  } catch (e) {
    cause = e instanceof DestBuildError ? e.buildCause : "NOT-A-DestBuildError";
  }
  ok("a non-https Azure endpoint is refused as endpoint-not-https, not as the residual \"other\"", cause === "endpoint-not-https", cause);
  cause = "";
  try {
    new AzureBlobDestination("not a url", CONTAINER, ACCOUNT, KEY_B64);
  } catch (e) {
    cause = e instanceof DestBuildError ? e.buildCause : "NOT-A-DestBuildError";
  }
  ok("an unparseable endpoint is refused as endpoint-unparseable", cause === "endpoint-unparseable", cause);
}

async function roundTrip(): Promise<void> {
  console.log("put / get / exists / delete round trip:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const d = mk();
    const payload = new TextEncoder().encode("downpipes azure round trip");
    await d.put("seg/0001", payload);

    const req = mock.requests.find((r) => r.method === "PUT");
    ok("the write is a block blob, declared with x-ms-blob-type", req?.headers["x-ms-blob-type"] === "BlockBlob", JSON.stringify(req?.headers));
    ok("...and it is signed with Shared Key", /^SharedKey acct:/.test(req?.headers.authorization ?? ""));
    ok("...at the container-scoped path", req?.path === "/archive/seg/0001", req?.path);

    const got = await d.get("seg/0001");
    ok("the object reads back byte-identical", got !== null && new TextDecoder().decode(got.body) === "downpipes azure round trip");
    ok("...and carries the store's ETag", (got?.etag ?? "").startsWith('"0x'), got?.etag);

    ok("exists is true for a written key", (await d.exists("seg/0001")) === true);
    ok("exists is false for an absent key", (await d.exists("seg/absent")) === false);
    ok("headStatus distinguishes absent (404) from present (200)", (await d.headStatus("seg/absent")) === 404 && (await d.headStatus("seg/0001")) === 200);

    ok("a GET of an absent key is null, not a throw", (await d.get("seg/absent")) === null);

    await d.delete("seg/0001");
    ok("the object is gone after delete", (await d.exists("seg/0001")) === false);
    // The interface's own contract, and what makes an interrupted retention prune safe to re-run.
    let threw = false;
    await d.delete("seg/0001").catch(() => {
      threw = true;
    });
    ok("deleting an absent key is a no-op success, so a re-run of a prune is idempotent", !threw);
  } finally {
    restore();
  }
}

async function conditional(): Promise<void> {
  console.log("conditional writes:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const d = mk();
    const first = await d.putConditional("runlog", new TextEncoder().encode("v1"), { ifNoneMatch: "*" });
    ok("an if-none-match:* write succeeds when nothing is there", first.ok && (first.etag ?? "") !== "");

    const second = await d.putConditional("runlog", new TextEncoder().encode("v2"), { ifNoneMatch: "*" });
    ok("a second if-none-match:* write is REFUSED rather than overwriting (a concurrent write won)", !second.ok);
    ok("...and the refusal did not clobber the stored body", new TextDecoder().decode((await d.get("runlog"))?.body ?? new Uint8Array()) === "v1");

    const match = await d.putConditional("runlog", new TextEncoder().encode("v3"), { ifMatch: first.etag ?? "" });
    ok("an if-match write on the CURRENT etag succeeds", match.ok);
    const stale = await d.putConditional("runlog", new TextEncoder().encode("v4"), { ifMatch: first.etag ?? "" });
    ok("an if-match write on a STALE etag is refused (412), not thrown", !stale.ok);
  } finally {
    restore();
  }
}

async function streaming(): Promise<void> {
  console.log("putStream stages blocks and commits a block list:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const d = mk();
    // Two and a bit blocks, so the loop stages twice and the remainder rides in a third.
    const total = AZURE_BLOCK_SIZE * 2 + 1024;
    const chunk = new Uint8Array(64 * 1024).fill(0x61);
    let written = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        if (written >= total) {
          c.close();
          return;
        }
        const n = Math.min(chunk.byteLength, total - written);
        c.enqueue(chunk.subarray(0, n));
        written += n;
      },
    });
    await d.putStream("seg/big", stream, total);

    const stored = mock.blobs.get("seg/big");
    ok("the committed blob is the full byte count, reassembled in order", stored?.body.byteLength === total, String(stored?.body.byteLength));
    ok("...and every byte is the payload, so no block landed out of order or twice", stored?.body.every((b) => b === 0x61) === true);

    const blockPuts = mock.requests.filter((r) => r.query.includes("comp=block&") || r.query.includes("comp=block")).filter((r) => r.query.includes("blockid"));
    ok("it staged three blocks (two full, one remainder)", blockPuts.length === 3, String(blockPuts.length));

    // Fixed-width ids are the thing most likely to be got wrong, and Azure's refusal names neither the
    // block nor the width.
    const ids = blockPuts.map((r) => new URLSearchParams(r.query).get("blockid") ?? "");
    const lens = new Set(ids.map((i) => atob(i).length));
    ok("every block id decodes to the SAME byte length, which Azure requires", lens.size === 1, JSON.stringify(ids));

    const commit = mock.requests.find((r) => r.query.includes("comp=blocklist"));
    ok("the write is committed with a block list", commit !== undefined);
  } finally {
    restore();
  }
}

async function smallStreamIsOnePut(): Promise<void> {
  console.log("a small streamed body costs ONE request, not a staged commit:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const d = mk();
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode("small"));
        c.close();
      },
    });
    await d.putStream("seg/small", stream, 5);
    const puts = mock.requests.filter((r) => r.method === "PUT");
    ok("exactly one PUT was issued", puts.length === 1, JSON.stringify(puts.map((p) => p.query)));
    ok("...and it was a plain block-blob write, with no comp= parameter", puts[0]?.query.includes("comp=") === false, puts[0]?.query);
    ok("the body is correct", new TextDecoder().decode(mock.blobs.get("seg/small")?.body ?? new Uint8Array()) === "small");
  } finally {
    restore();
  }
}

async function listing(): Promise<void> {
  console.log("list pages through NextMarker:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const d = mk();
    for (const k of ["run/a", "run/b", "run/c", "run/d", "run/e", "other/x"]) mock.blobs.set(k, { body: new Uint8Array(0), etag: '"0x1"' });

    const page1 = await d.listPage("run/");
    ok("one page returns the store's page size, not everything", page1.keys.length === 2, JSON.stringify(page1.keys));
    ok("...and a cursor for the next page", page1.cursor !== undefined);

    const all = await d.list("run/");
    ok("list() walks every page and returns the whole prefix", all.length === 5, JSON.stringify(all));
    ok("...in lexicographic order, which the replication merge-walk relies on", JSON.stringify(all) === JSON.stringify(["run/a", "run/b", "run/c", "run/d", "run/e"]));
    ok("...and nothing outside the prefix", !all.includes("other/x"));

    // A key with an ampersand is legal and must round-trip, or the prune cannot address it to delete it.
    mock.blobs.set("run/a&b", { body: new Uint8Array(0), etag: '"0x1"' });
    const withAmp = await d.list("run/");
    ok("an XML-escaped key is decoded back to its real name", withAmp.includes("run/a&b"), JSON.stringify(withAmp));
  } finally {
    restore();
  }
}

// ---- immutability -----------------------------------------------------------------------------------
//
// Until an Azure destination could not carry an immutability policy at all: the field was
// refused for every Azure endpoint, and objectLockStatus hardcoded a not-enabled answer. Both are gone.
// These sections grade what replaced them, and the thing they have to prove is not "immutability works"
// but the finer claim that the mapping is EXACT: a compliance policy must reach the wire as Azure's LOCKED
// mode, because an unlocked one is the weaker guarantee wearing the same word.

const wormed = (worm: { mode: "governance" | "compliance"; retentionDays: number }): AzureBlobDestination => new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED, worm });

async function immutabilityOnTheWire(): Promise<void> {
  console.log("an armed policy reaches the wire as Azure's own per-blob immutability headers:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    await wormed({ mode: "compliance", retentionDays: 30 }).put("seg/locked", new TextEncoder().encode("x"));
    const p = mock.blobs.get("seg/locked")?.policy;

    // THE ASSERTION THE WHOLE REVERSAL RESTS ON. compliance promises that nobody can shorten or remove the
    // retention. Azure spells that "locked"; "unlocked" is the guarantee governance makes, and shipping it
    // for a compliance policy would be the silent downgrade the old refusal was afraid of.
    ok("compliance maps to Azure's LOCKED mode, not the weaker unlocked one", p?.mode === "locked", JSON.stringify(p));

    // RFC 1123, not the RFC 3339 instant the S3 header takes. Sending either store the other spelling is a
    // rejected write, and this is the assertion that keeps the two formatters apart. FIXED is
    // , so 30 days is.
    ok("the retain-until date is the RFC 1123 form Azure requires, at now + retentionDays", p?.until === "Thu, 24 Sep 2026 00:00:00 GMT", JSON.stringify(p));

    // Azure's SECOND primitive, and it must stay absent. A legal hold has no expiry at all and is cleared
    // only by an explicit administrative action, so deriving one from a retention window would make every
    // archive object undeletable for ever, which is not what the customer asked for.
    const put = mock.requests.find((r) => r.method === "PUT");
    ok("no legal hold is set: it has no expiry and no counterpart in the policy the form collects", put?.headers["x-ms-legal-hold"] === undefined, JSON.stringify(put?.headers));

    // ...and it is still signed. The headers go into the SAME record the signer reads, so the canonical
    // string covers them; an x-ms-* header on the wire that the signature did not include is a 403.
    ok("...and the lock-bearing write is still signed with Shared Key", /^SharedKey acct:/.test(put?.headers.authorization ?? ""));
  } finally {
    restore();
  }

  {
    const mock = new MockAzure();
    const restore2 = install(mock);
    try {
      await wormed({ mode: "governance", retentionDays: 7 }).put("seg/gov", new TextEncoder().encode("x"));
      // The other half of the mapping. Without it the compliance assertion above would pass just as
      // happily under a client that sent "locked" for every policy, which would over-promise on the mode
      // the customer chose precisely because they wanted it liftable.
      ok("governance maps to Azure's UNLOCKED mode, which is what governance means", mock.blobs.get("seg/gov")?.policy?.mode === "unlocked", JSON.stringify(mock.blobs.get("seg/gov")?.policy));
    } finally {
      restore2();
    }
  }

  {
    const mock = new MockAzure();
    const restore3 = install(mock);
    try {
      // THE CONTROL, and it is the one that keeps the default-off promise honest: with no policy the write
      // path is byte-identical to the pre-immutability one.
      await mk().put("seg/plain", new TextEncoder().encode("x"));
      const put = mock.requests.find((r) => r.method === "PUT");
      ok("with NO policy configured the write carries no immutability headers at all", mock.blobs.get("seg/plain")?.policy === undefined && put?.headers["x-ms-immutability-policy-mode"] === undefined, JSON.stringify(put?.headers));
    } finally {
      restore3();
    }
  }
}

async function immutabilityOnEveryCreatingWrite(): Promise<void> {
  console.log("every OBJECT-CREATING write carries the policy, and only those:");
  {
    const mock = new MockAzure();
    const restore = install(mock);
    try {
      // A block-staged write. The blob comes into existence at the COMMIT, so that is the request that
      // carries the policy; Put Block stages bytes and creates nothing, and sending policy headers on one
      // would be sending them to an operation that does not take them.
      const total = AZURE_BLOCK_SIZE + 1024;
      const chunk = new Uint8Array(64 * 1024).fill(0x61);
      let written = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(c) {
          if (written >= total) {
            c.close();
            return;
          }
          const n = Math.min(chunk.byteLength, total - written);
          c.enqueue(chunk.subarray(0, n));
          written += n;
        },
      });
      await wormed({ mode: "compliance", retentionDays: 30 }).putStream("seg/big", stream, total);

      ok("a block-staged blob is committed WITH the policy", mock.blobs.get("seg/big")?.policy?.mode === "locked", JSON.stringify(mock.blobs.get("seg/big")?.policy));
      const blockPuts = mock.requests.filter((r) => r.query.includes("blockid"));
      ok("...and the staged blocks carry none, because staging creates no blob", blockPuts.length > 0 && blockPuts.every((r) => r.headers["x-ms-immutability-policy-mode"] === undefined), String(blockPuts.length));
      const commit = mock.requests.find((r) => r.query.includes("comp=blocklist"));
      ok("...so it is the block-list COMMIT that carries them", commit?.headers["x-ms-immutability-policy-mode"] === "locked", JSON.stringify(commit?.headers));
    } finally {
      restore();
    }
  }
  {
    const mock = new MockAzure();
    const restore = install(mock);
    try {
      // The RUNLOG is written ONLY through putConditional. An implementation that armed the two plain
      // writes and forgot this one would leave the run history as the single unprotected object on the
      // destination, which is exactly what a ransomware event rewrites.
      await wormed({ mode: "compliance", retentionDays: 30 }).putConditional("runlog", new TextEncoder().encode("v1"), { ifNoneMatch: "*" });
      ok("a conditional write is object-creating too, so the RUNLOG is locked with everything else", mock.blobs.get("runlog")?.policy?.mode === "locked", JSON.stringify(mock.blobs.get("runlog")?.policy));
    } finally {
      restore();
    }
  }
}

async function lockRefusalIsLegible(): Promise<void> {
  console.log("a refused lock-bearing write names the AZURE setting, not a downpipes fault:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    // Version-level immutability has to be ON before a per-blob policy binds, and a write carrying the
    // headers to a container without it fails. Everything visible about that failure says downpipes: an
    // engine message, on an engine run, about a destination the product itself reported verified. Without
    // the hint the first move is to audit a credential that was never the problem.
    mock.fail = { method: "PUT", status: 409, code: "UnsupportedHeader" };
    let e: Error | undefined;
    await wormed({ mode: "compliance", retentionDays: 30 }).put("seg/x", new TextEncoder().encode("x")).catch((err) => {
      e = err as Error;
    });
    const msg = e?.message ?? "";
    ok("the message still carries the status and Azure's code, so every existing reader still finds them", /status 409/.test(msg) && msg.includes("UnsupportedHeader"), msg);
    ok("...and names version-level immutability, which is the thing that is actually off", /version-level immutability/i.test(msg), msg);
    ok("...and says plainly that it is an Azure setting rather than a downpipes one", /not a downpipes one/i.test(msg), msg);
    ok("...and warns that an existing container needs migrating, which is the part that surprises people", /migrated/i.test(msg), msg);
    // The fault also has to CLASSIFY as a lock refusal, on the same rail an S3 one does, or it lands in the
    // generic permanent bucket and the down-reason says nothing about immutability.
    ok("...and the fault is stamped as an object-lock refusal, as the S3 path stamps its own", isObjectLockRefusalStamped(e));
  } finally {
    restore();
  }

  {
    const mock2 = new MockAzure();
    const restore2 = install(mock2);
    try {
      // The control. A failure on a write that carried NO policy must not grow an immutability hint: it
      // would send an operator to change an Azure setting that has nothing to do with their problem.
      mock2.fail = { method: "PUT", status: 403, code: "AuthenticationFailed" };
      let msg = "";
      await mk().put("seg/x", new TextEncoder().encode("x")).catch((err) => {
        msg = (err as Error).message;
      });
      ok("a failure on an UNARMED write carries no immutability hint at all", !/version-level immutability/i.test(msg), msg);
    } finally {
      restore2();
    }
  }
}

async function wormPosture(): Promise<void> {
  console.log("the WORM posture is read from the store, per container:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    // ENABLED. This is the answer that could not be reached at all before, when the probe
    // hardcoded a not-enabled verdict: a container that really does enforce immutability was reported as
    // one that could not, on exactly the destinations a compliance customer bought it for.
    mock.vlw = "true";
    const on = await mk().objectLockStatus();
    ok("a container with version-level immutability enabled reports enforced", on.enabled === true, JSON.stringify(on));

    // ...and the probe is ONE container-scoped GET, not an account-wide read. That is what lets it work
    // with a container-scoped SAS as well as an account key.
    const probe = mock.requests.filter((r) => r.query.includes("restype=container") && !r.query.includes("comp="));
    ok("...read with one Get Container Properties call, scoped no wider than the container", probe.length === 1 && probe[0]?.path === "/archive", JSON.stringify(probe.map((r) => r.path)));

    // No default rule is claimed. Azure's account and container DEFAULT retention policies live on the
    // management plane, which an account key and a SAS cannot reach, so reporting one would be inventing it.
    ok("...and no default retention rule is claimed, because the data plane cannot read one", on.defaultMode === undefined && on.defaultDays === undefined, JSON.stringify(on));

    // NOT ENABLED, stated by the store. A lock-bearing write here would be refused, so a definite false is
    // what the save-time gate needs in order to refuse at the one moment the operator can act.
    mock.vlw = "false";
    const off = await mk().objectLockStatus();
    ok("a container that answers the header false reports a DEFINITE not-enabled", off.enabled === false, JSON.stringify(off));

    // THE DELIBERATE ONE. An absent header is read as not-enabled rather than as an "unknown", because an
    // "unknown" that is not "not-implemented" is ACCEPTED by wormCannotBeEnforced, and the save-time probe
    // runs with the policy DISARMED. So an accepted unknown yields a destination that reports itself
    // verified and then has every backup write refused for ever. See versionLevelImmutabilityStatus.
    mock.vlw = "absent";
    const absent = await mk().objectLockStatus();
    ok("an ABSENT header is not-enabled too, which is the reading that refuses the save", absent.enabled === false, JSON.stringify(absent));
    ok("...and specifically NOT \"unknown\", which the router would wave through", (absent.enabled as unknown) !== "unknown", JSON.stringify(absent));

    // The could-not-check arms, which must stay could-not-check: refusing a correctly-configured
    // destination because a probe was denied or a packet was lost is the opposite defect.
    mock.vlw = "denied";
    const denied = await mk().objectLockStatus();
    ok("a probe the credential is not allowed to make is unknown/denied, not a verdict about the container", denied.enabled === "unknown" && denied.unknownReason === "denied", JSON.stringify(denied));

    mock.vlw = "server-error";
    const err = await mk().objectLockStatus();
    ok("a 5xx is unknown/server-error: the store, not the customer", err.enabled === "unknown" && err.unknownReason === "server-error", JSON.stringify(err));

    mock.vlw = "redirect";
    const red = await mk().objectLockStatus();
    ok("a redirected credentialed probe is unknown/redirect, and never carries the target", red.enabled === "unknown" && red.unknownReason === "redirect", JSON.stringify(red));
  } finally {
    restore();
  }

  {
    // A probe that never got an answer at all. It must degrade rather than throw: a probe failure NEVER
    // blocks a backup, it only affects reporting.
    const restore = installHang();
    try {
      const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED, fetchTimeoutMs: 5 });
      const status = await d.objectLockStatus();
      ok("a probe that never answered is unknown/network, the self-healing cause", status.enabled === "unknown" && status.unknownReason === "network", JSON.stringify(status));
    } finally {
      restore();
    }
  }
}

// ---- SAS token credentials --------------------------------------------------------------------------
//
// A SAS needs no signing by us: it is a query string somebody else already signed, and the Authorization
// header is omitted entirely. What it DOES need, and what a Shared Key has never needed, is an expiry the
// product can see coming: it is the first credential this engine holds that dies on its own.

// MARKER is planted in every token below so the no-echo assertion has ONE distinctive string to hunt for
// across all three refusals. Its first draft hunted for the SIGNATURE instead, and a mutation caught that:
// the no-sig refusal is precisely the one whose token has no signature in it, so echoing that token whole
// left the assertion green. The marker rides in a parameter every one of them carries.
const MARKER = "Zm9yYmlkZGVuLWNyZWRlbnRpYWwtbWF0ZXJpYWw";
const SAS_SIG = `sig=${MARKER}`;
const sasToken = (se: string | null): string => `sv=2021-12-02&sr=c&sp=racwdl${se === null ? "" : `&se=${se}`}&${SAS_SIG}`;

async function sasOnTheWire(): Promise<void> {
  console.log("a SAS destination authenticates by query string, with no Authorization header:");
  const mock = new MockAzure();
  mock.acceptSas = true;
  const restore = install(mock);
  // EVERY STORE CALL HERE IS CAUGHT rather than allowed to reject, and that is not defensive tidiness: it
  // is what makes these lines assertions at all. The mock REFUSES a request that authenticates wrongly, so
  // a client that signed a SAS request, or dropped the token from the URL, throws out of the call. Left
  // uncaught, that kills the process, and the suite reports a stack trace instead of naming the claim that
  // is false. Measured: with the rejection uncaught, four separate mutations of the SAS path (signing as
  // well, dropping the token, dropping the request's own parameters, ignoring the token entirely) all
  // crashed the run rather than moving the assertion written for them.
  const attempt = async <T>(p: Promise<T>): Promise<T | Error> => p.catch((e) => e as Error);
  try {
    const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { now: FIXED, sasToken: sasToken("2027-01-01T00:00:00Z") });
    const payload = new TextEncoder().encode("sas round trip");
    const wrote = await attempt(d.put("seg/sas", payload));
    ok("a SAS-authenticated write is accepted by the store", !(wrote instanceof Error), wrote instanceof Error ? wrote.message : "");

    const put = mock.requests.find((r) => r.method === "PUT");
    // The mock refuses a request carrying BOTH, because Azure does: a SAS request with an Authorization
    // header is rejected rather than treated as belt and braces.
    ok("the request carries NO Authorization header", (put?.headers.authorization ?? "") === "", JSON.stringify(put?.headers));
    ok("...and carries the signature in the query instead", (put?.query ?? "").includes("sig="), put?.query);
    ok("...and still declares the API version, which is required on every authorised request", put?.headers["x-ms-version"] !== undefined, JSON.stringify(put?.headers));

    const got = await attempt(d.get("seg/sas"));
    ok("the object round-trips through the SAS path", !(got instanceof Error) && got !== null && new TextDecoder().decode(got.body) === "sas round trip", got instanceof Error ? got.message : JSON.stringify(got));

    // The request's OWN parameters have to survive the merge, or a listing loses its prefix and its marker
    // and pages through the wrong keyspace.
    mock.blobs.set("run/a", { body: new Uint8Array(0), etag: '"0x1"' });
    await attempt(d.listPage("run/"));
    const list = mock.requests.find((r) => r.query.includes("comp=list"));
    ok("a request's own query parameters survive alongside the SAS parameters", /restype=container/.test(list?.query ?? "") && /prefix=run/.test(list?.query ?? "") && /sig=/.test(list?.query ?? ""), list?.query);
  } finally {
    restore();
  }
}

async function sasExpiryIsRead(): Promise<void> {
  console.log("a SAS carries its own death, and it is read rather than guessed:");
  const withSe = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { now: FIXED, sasToken: sasToken("2027-01-01T00:00:00Z") });
  ok("the se parameter is parsed into an absolute instant a warning surface can read", withSe.sasExpiry()?.expiresAtMs === Date.parse("2027-01-01T00:00:00Z"), JSON.stringify(withSe.sasExpiry()));

  // A SAS with no `se` is legal: a service SAS can take its expiry from a stored access policy on the
  // container instead. Reporting null says "we cannot see the date". Reporting a far-future instant, or
  // treating it as never expiring, would invent the one fact this is here to avoid inventing.
  const noSe = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { now: FIXED, sasToken: sasToken(null) });
  ok("a token with no se reports an UNKNOWN expiry, not an invented one", noSe.sasExpiry()?.expiresAtMs === null, JSON.stringify(noSe.sasExpiry()));

  // The control: a Shared Key destination has no expiry at all, and must not be confused with a SAS whose
  // expiry we could not read. One needs no warning ever; the other needs a human to go and look.
  ok("a Shared Key destination reports no expiry reading at all, which is a different thing from an unknown one", mk().sasExpiry() === null);
}

function sasRefusals(): void {
  console.log("a SAS that cannot do the job is refused at construction, naming what is wrong:");
  const build = (token: string): string => {
    try {
      new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { now: FIXED, sasToken: token });
      return "";
    } catch (e) {
      return e instanceof DestBuildError ? e.message : `NOT-A-DestBuildError: ${String(e)}`;
    }
  };

  // Refusing at CONSTRUCTION is what turns "the SAS expired on Tuesday" into a standing, attributable fact:
  // buildDestination records a construction failure with the moment the destination started failing. A
  // refusal deferred to the first write arrives as a 403 that names nothing.
  const noSig = build(`sv=2021-12-02&sr=c&sp=racwdl&se=2027-01-01T00:00:00Z&skoid=${MARKER}`);
  ok("a token with no sig is refused, because nothing in it could authenticate anything", /no sig parameter/.test(noSig), noSig);
  ok("...and the message names what to paste instead, rather than saying the credential is bad", /connection string|container URL|account key/.test(noSig), noSig);

  const expired = build(sasToken("2026-08-01T00:00:00Z"));
  ok("an already-expired token is refused", /expired at/.test(expired), expired);
  ok("...and the message carries the DATE, which is what separates last night from last March", /2026-08-01T00:00:00\.000Z/.test(expired), expired);

  // A PRESENT but unreadable se is refused rather than demoted to "no expiry". The absence of se is an
  // honest unknown; a broken se is a malformed token, and quietly treating it as absent would invent the
  // fact on the one input where we can see something is wrong.
  const broken = build(sasToken("not-a-date"));
  ok("an se that is not a date is refused, NOT quietly treated as a token with no expiry", /not a date this engine can read/.test(broken), broken);

  // No token echoes into any message. A SAS IS a credential, in full, and one in an error message reaches
  // the run log, the support pack and whatever the operator pastes into a ticket.
  // Not one of the three may carry ANY of the token back, which is why the marker is hunted rather than the
  // signature: a SAS is a credential in full, and every parameter of it is secret, not just the sig. A
  // refusal that echoes one reaches the run log, the support pack and whatever the operator pastes into a
  // ticket.
  ok("no refusal ever echoes any part of the token back", ![noSig, expired, broken].some((m) => m.includes(MARKER)), JSON.stringify([noSig, expired, broken]));

  // And a token that is fine builds. Without this the refusals above would pass under a client that
  // refused every SAS.
  ok("a well-formed, live token builds", build(sasToken("2027-01-01T00:00:00Z")) === "");
}

function sasDiscrimination(): void {
  console.log("a stored secret is told apart from an account key by SHAPE, not by a substring:");
  ok("a real SAS query string reads as a token", looksLikeAzureSasToken(sasToken("2027-01-01T00:00:00Z")));
  ok("...with or without the leading question mark Azure's portal includes", looksLikeAzureSasToken(`?${sasToken("2027-01-01T00:00:00Z")}`));
  ok("an ordinary base64 account key does NOT", !looksLikeAzureSasToken(KEY_B64));

  // THE ASSERTION THAT MAKES THE RULE STRUCTURAL RATHER THAN A SUBSTRING SEARCH. A base64 account key ends
  // in "=" padding, so a key whose final characters happen to be "sig=" would match a naive test for that
  // substring and be routed down the SAS path, where it would authenticate nothing. Roughly one key in
  // 262,144 ends that way, which is not rare enough to build a credential decision on. Requiring a
  // parameter separator as well is what rules it out.
  // THE STRING BELOW REALLY DOES END IN THE FOUR CHARACTERS s, i, g, "=", which is the whole point: an
  // earlier draft of this line used base64 that DECODED to "...sig" and so contained no literal "sig=" at
  // all, and the substring-test mutation it was written to catch sailed straight past it. An assertion
  // about text has to be made of the text it is about.
  const keyEndingInSig = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzsig=";
  ok("...and neither does a key that happens to END in \"sig=\", which a substring test would have matched", !looksLikeAzureSasToken(keyEndingInSig), keyEndingInSig);
  ok("a value with a separator but no sig is not a token either", !looksLikeAzureSasToken("sv=2021-12-02&sr=c&sp=racwdl"));
}

async function errorsCarryNoBody(): Promise<void> {
  console.log("a store refusal names the status and Azure's own code, and nothing else:");
  const mock = new MockAzure();
  const restore = install(mock);
  try {
    const d = mk();
    mock.fail = { method: "PUT", status: 403, code: "AuthorizationPermissionMismatch" };
    let msg = "";
    await d.put("seg/x", new TextEncoder().encode("x")).catch((e) => {
      msg = (e as Error).message;
    });
    ok("the message carries the status", msg.includes("403"), msg);
    ok("...and Azure's closed error code, which names the remedy", msg.includes("AuthorizationPermissionMismatch"), msg);
    ok("...and the key, so an operator knows which object", msg.includes("seg/x"), msg);
    ok("...and never the account key", !msg.includes(KEY_B64), msg);
  } finally {
    restore();
  }
}

// ---- backpressure: the pacer and the degradation counters ------------------------------------------
//
// These sections are about the thing an Azure destination could NOT do until: back off when the
// store pushes back, and leave a trace when it did. They are graded separately from the wire sections above
// because the failure they guard against is a run that SUCCEEDS and simply takes ten times as long.

/** installStatuses replaces fetch with a stub that answers a scripted sequence of {status, code} responses,
 *  repeating the last one for ever. The MockAzure above is a store; this is a store having a bad day, and
 *  the two are kept apart because a mock that can be told to fail on demand ends up asserting its own
 *  scripting rather than the client's behaviour. */
function installStatuses(script: ReadonlyArray<{ status: number; code?: string }>): () => void {
  const real = globalThis.fetch;
  let at = 0;
  globalThis.fetch = (async () => {
    const step = script[Math.min(at, script.length - 1)] ?? { status: 500 };
    at += 1;
    return new Response("", { status: step.status, headers: step.code === undefined ? {} : { "x-ms-error-code": step.code } });
  }) as unknown as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

/** installHang replaces fetch with one that never answers and only settles when its AbortSignal fires, which
 *  is what a black-holed endpoint looks like from inside the client. */
function installHang(): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = ((_input: unknown, init?: RequestInit) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
    })) as unknown as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

// A fast pacer: a high base rate and a burst to match, so take() never actually sleeps in a test. The rate
// halving is what is being graded, not the wall clock.
const fastPacer = (): DestPacer => new DestPacer({ ratePerSec: 1000, burst: 1000 });
const paced = (pacer: DestPacer): AzureBlobDestination => new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED, pacer });
const swallow = async (p: Promise<unknown>): Promise<void> => {
  await p.catch(() => undefined);
};

function pacerMapping(): void {
  console.log("azurePacerStatus maps AZURE's throttling signals, not Amazon's:");
  // The shared arms. A 503 is backpressure in both vocabularies (Azure's ServerBusy, Amazon's SlowDown),
  // so it passes through untouched and the code is not consulted at all on that arm.
  ok("503 ServerBusy is backpressure and passes through", azurePacerStatus(503, "ServerBusy") === 503);
  ok("a 503 with no code is still backpressure, since the status alone says the store cannot serve it now", azurePacerStatus(503, "") === 503);
  ok("429 passes through unchanged, shared with S3 and not something Azure Blob is documented to send", azurePacerStatus(429, "") === 429);

  // AZURE'S OWN ARM, and the reason the function exists. Read as a raw status this is a server error and
  // the pacer would ignore it; it is in fact the other half of Azure's throttling pair.
  ok("500 OperationTimedOut is TRANSLATED to backpressure, because that is Azure's second throttling answer", azurePacerStatus(500, "OperationTimedOut") === 503);

  // The control that makes the arm above mean something: not every 500 is congestion.
  ok("500 InternalError is NOT translated, because a server fault is not a signal to back off", azurePacerStatus(500, "InternalError") === 500);
  ok("a 500 with no code is not translated either", azurePacerStatus(500, "") === 500);

  // Everything else is untouched, so the recovery arm and the neutral arm behave exactly as on S3.
  ok("a 201 passes through, so a clean write still recovers the rate", azurePacerStatus(201, "") === 201);
  ok("a 403 passes through as neutral: an auth failure is not congestion", azurePacerStatus(403, "AuthenticationFailed") === 403);
}

async function pacerClampsOnAzureSignals(): Promise<void> {
  console.log("the pacer is actually driven by those signals, at the send chokepoint:");
  {
    const restore = installStatuses([{ status: 503, code: "ServerBusy" }]);
    try {
      const pacer = fastPacer();
      const d = paced(pacer);
      await swallow(d.put("seg/x", new TextEncoder().encode("x")));
      ok("a 503 ServerBusy HALVES the effective rate", pacer.effectiveRate() === 500, String(pacer.effectiveRate()));
      ok("...and is counted as store backpressure in the degradation record", d.destIo().throttleObservations === 1, JSON.stringify(d.destIo()));
      ok("...and the worst rate the destination was driven to is recorded", d.destIo().minEffectiveRatePerSec === 500, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
  {
    const restore = installStatuses([{ status: 500, code: "OperationTimedOut" }]);
    try {
      const pacer = fastPacer();
      const d = paced(pacer);
      await swallow(d.put("seg/x", new TextEncoder().encode("x")));
      // THE ASSERTION THIS WHOLE GAP EXISTED FOR. Before the mapping, this response reached the pacer as a
      // bare 500 and neither clamped the rate nor left a trace, so an Azure account being throttled through
      // its timeout arm was driven at full rate into a store already asking for less.
      ok("a 500 OperationTimedOut halves the rate too, through the Azure mapping", pacer.effectiveRate() === 500, String(pacer.effectiveRate()));
      ok("...and is counted, so the support pack can attribute the slowness", d.destIo().throttleObservations === 1, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
  {
    const restore = installStatuses([{ status: 500, code: "InternalError" }]);
    try {
      const pacer = fastPacer();
      const d = paced(pacer);
      await swallow(d.put("seg/x", new TextEncoder().encode("x")));
      // The control. Without it the line above would pass just as happily under a rule that clamped on
      // EVERY 500, which would slow a backup for a fault that backing off cannot help.
      ok("an ordinary 500 InternalError does NOT clamp the rate", pacer.effectiveRate() === 1000, String(pacer.effectiveRate()));
      ok("...and is not counted as backpressure", d.destIo().throttleObservations === 0, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
  {
    const restore = installStatuses([{ status: 503, code: "ServerBusy" }, { status: 201 }]);
    try {
      const pacer = fastPacer();
      const d = paced(pacer);
      await swallow(d.put("seg/x", new TextEncoder().encode("x")));
      await d.put("seg/x", new TextEncoder().encode("x"));
      ok("a clean write afterwards recovers the rate additively, rather than leaving it clamped for the slice", pacer.effectiveRate() === 600, String(pacer.effectiveRate()));
      ok("...and the WORST rate is still the one recorded, not the recovered one", d.destIo().minEffectiveRatePerSec === 500, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
}

async function pacerActuallyPaces(): Promise<void> {
  console.log("the pacer SPACES the requests, rather than only counting them:");
  // The clamp assertions above grade the adaptive RATE. None of them would notice a client that folded
  // every response into the rate and then never waited on it, which is a pacer that reports pacing it is
  // not doing. This is the line that makes take() load-bearing: a burst of one and a low rate means the
  // SECOND request cannot go out until the bucket refills, so the elapsed time is the witness.
  const restore = installStatuses([{ status: 201 }]);
  try {
    const body = new TextEncoder().encode("x");
    const slow = paced(new DestPacer({ ratePerSec: 20, burst: 1 }));
    const startPaced = Date.now();
    await slow.put("seg/a", body);
    await slow.put("seg/b", body);
    const pacedMs = Date.now() - startPaced;

    // The control, and it is the half that matters: a destination with NO pacer must issue both writes back
    // to back, or the delay above would be proving something about the stub rather than about the pacer.
    const unpaced = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED });
    const startFree = Date.now();
    await unpaced.put("seg/a", body);
    await unpaced.put("seg/b", body);
    const freeMs = Date.now() - startFree;

    ok("a paced destination waits for the bucket to refill before the second request", pacedMs >= 25, `${pacedMs}ms`);
    ok("...while an unpaced one issues both back to back", freeMs < 25, `${freeMs}ms`);
  } finally {
    restore();
  }
}

async function degradationIsCounted(): Promise<void> {
  console.log("the branches a SUCCESSFUL run swallows are counted rather than corrected:");
  {
    const restore = installHang();
    try {
      const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED, fetchTimeoutMs: 5 });
      let msg = "";
      await d.put("seg/x", new TextEncoder().encode("x")).catch((e) => {
        msg = (e as Error).message;
      });
      ok("a black-holed endpoint is abandoned at the fetch bound and counted", d.destIo().timeouts === 1, JSON.stringify(d.destIo()));
      ok("...and the throw NAMES the timeout, rather than surfacing a bare AbortError", /timed out/.test(msg), msg);
      ok("...and names the bound it hit, so a support reader knows it was the bound and not the store", msg.includes("5ms"), msg);
    } finally {
      restore();
    }
  }
  {
    const mock = new MockAzure();
    const restore = install(mock);
    try {
      const d = mk();
      await d.putConditional("runlog", new TextEncoder().encode("v1"), { ifNoneMatch: "*" });
      ok("a conditional PUT that WON is not a conflict", d.destIo().conditionalPutConflicts === 0, JSON.stringify(d.destIo()));
      const lost = await d.putConditional("runlog", new TextEncoder().encode("v2"), { ifNoneMatch: "*" });
      ok("a lost if-none-match (Azure answers 409 BlobAlreadyExists) is counted as a conflict", !lost.ok && d.destIo().conditionalPutConflicts === 1, JSON.stringify(d.destIo()));
      const stale = await d.putConditional("runlog", new TextEncoder().encode("v3"), { ifMatch: '"0xdead"' });
      ok("a lost if-match (412) is counted on the SAME counter, since both mean a concurrent writer won", !stale.ok && d.destIo().conditionalPutConflicts === 2, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
  {
    const restore = installStatuses([{ status: 403, code: "AuthenticationFailed" }]);
    try {
      const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, KEY_B64, { now: FIXED });
      const present = await d.exists("seg/x");
      // THE dedup-defeating fault: the credential lost its read, exists() says "absent", and the caller
      // re-uploads the whole archive on a run that reports success.
      ok("a HEAD that answers 403 still collapses to absent, because the callers ride it out", present === false);
      ok("...but the collapse is now COUNTED, so a nightly full re-upload is visible afterwards", d.destIo().headNon200CollapsedToAbsent === 1, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
  {
    const mock = new MockAzure();
    const restore = install(mock);
    try {
      const d = mk();
      // The control for the line above: a genuine absence is the ordinary dedup answer and must not be
      // counted, or the counter reads as an incident on every healthy first backup.
      ok("a HEAD that answers 404 is a genuine absence and is NOT counted", (await d.exists("seg/absent")) === false && d.destIo().headNon200CollapsedToAbsent === 0, JSON.stringify(d.destIo()));
    } finally {
      restore();
    }
  }
}

async function degradationReachesTheIsolateTally(): Promise<void> {
  console.log("an Azure degradation reaches the isolate tally, which is what makes it durable:");
  // The per-instance snapshot is read only by a caller that holds the destination. The isolate-local tally
  // is the half that survives it: buildDestination flushes it to the DO's bounded admin-counter aggregate,
  // so the evidence outlives the run even though the dest layer has no end-of-run hook. An Azure client
  // that bumped only its own snapshot would be invisible in the pack, which is where support looks.
  resetPendingDestIo();
  const restore = installStatuses([{ status: 503, code: "ServerBusy" }]);
  try {
    await swallow(paced(fastPacer()).put("seg/x", new TextEncoder().encode("x")));
    const pending = pendingDestIo();
    ok("the throttle bump is pending for the next flush to the DO", pending["throttleObservations"] === 1, JSON.stringify(pending));
  } finally {
    restore();
    resetPendingDestIo();
  }
}

console.log("azure blob destination\n");
await construction();
await roundTrip();
await conditional();
await streaming();
await smallStreamIsOnePut();
await listing();
await immutabilityOnTheWire();
await immutabilityOnEveryCreatingWrite();
await lockRefusalIsLegible();
await wormPosture();
await sasOnTheWire();
await sasExpiryIsRead();
sasRefusals();
sasDiscrimination();
await errorsCarryNoBody();
pacerMapping();
await pacerClampsOnAzureSignals();
await pacerActuallyPaces();
await degradationIsCounted();
await degradationReachesTheIsolateTally();

console.log(failures === 0 ? "\nall azure blob checks passed" : `\n${failures} check(s) FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
