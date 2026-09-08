// Destination HTTP contract vectors for the S3 destination: the conditional
// 412 -> ok:false / get 404 -> null / exists surface, the https endpoint enforcement at construction
// (V12.3.1), the absent-ETag-no-unconditional-overwrite fix, redirect:"manual" on every fetch
// with a 3xx treated as an error (V15.3.2), and the delete + list retention-prune write side (V14.2.7).
// Behaviour-preserving: same assertions, same order as the original main().

import { S3Destination } from "../src/dest/s3.ts";
import { encodePath } from "../src/dest/sigv4.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import {
  ok,
  ENDPOINT,
  BUCKET,
  CREDS,
  FIXED_NOW,
  eqBytes,
  installFetch,
  res,
} from "./validate-s3dest-shared.ts";

// Part 3: the rest of the Destination HTTP contract (conditional 412 -> ok:false, get 404 ->
// null, exists), mirroring validate-r2dest.ts so the whole surface is exercised over fetch.
async function httpContract(): Promise<void> {
  console.log("Destination HTTP contract:");

  // putConditional: create with If-None-Match: * -> on success returns ok + etag; on 412 the
  // precondition failed and it maps to ok:false (the RUNLOG retry signal).
  {
    const { captures, restore } = installFetch((c) => (c.headers["if-none-match"] === "*" ? res(200, { etag: '"rl-1"' }) : res(500)));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const r = await dest.putConditional("_RECOVERY/RUNLOG", utf8("v1"), { ifNoneMatch: "*" });
      ok("conditional create (ifNoneMatch:*) succeeds and returns an etag", r.ok && r.etag === '"rl-1"');
      ok("conditional create sent If-None-Match: *", captures[0]!.headers["if-none-match"] === "*");
      ok("conditional create body is buffered (length-delimited)", !captures[0]!.bodyWasStream);
      const auth = captures[0]!.headers["authorization"];
      ok("conditional create carries a SigV4 Authorization header", !!auth && auth.startsWith("AWS4-HMAC-SHA256 Credential="));
    } finally {
      restore();
    }
  }
  {
    const { restore } = installFetch(() => res(412));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const r = await dest.putConditional("_RECOVERY/RUNLOG", utf8("v2"), { ifMatch: '"rl-1"' });
      ok("conditional replace returns ok:false on a 412 precondition failure", !r.ok);
    } finally {
      restore();
    }
  }

  // get: 200 returns the bytes + etag; 404 returns null.
  {
    const payload = utf8("restored bytes");
    const { restore } = installFetch(() => new Response(payload, { status: 200, headers: { etag: '"g-1"' } }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const got = await dest.get("seg/0001");
      ok("get returns the body and etag on 200", !!got && eqBytes(got.body, payload) && got.etag === '"g-1"');
    } finally {
      restore();
    }
  }
  {
    const { restore } = installFetch(() => res(404));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      ok("get maps a 404 to null", (await dest.get("seg/missing")) === null);
    } finally {
      restore();
    }
  }

  // exists: 200 -> true (HEAD), 404 -> false.
  {
    const { captures, restore } = installFetch(() => res(200));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      ok("exists is true on a 200 HEAD", await dest.exists("seg/0001"));
      ok("exists used a HEAD request", captures[0]!.method === "HEAD");
    } finally {
      restore();
    }
  }
  {
    const { restore } = installFetch(() => res(404));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      ok("exists is false on a 404 HEAD", !(await dest.exists("seg/missing")));
    } finally {
      restore();
    }
  }
}

// Part 4: a non-https DEST_ENDPOINT is rejected at construction, before any signing or fetch
// (V12.3.1). https and the http://localhost test loopback are accepted; everything else throws.
function httpsEnforcement(): void {
  console.log("https endpoint enforcement (V12.3.1):");
  const make = (endpoint: string) => () => new S3Destination(endpoint, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

  function threw(fn: () => unknown): boolean {
    try {
      fn();
      return false;
    } catch {
      return true;
    }
  }

  ok("rejects a plain http:// endpoint", threw(make("http://s3.example.com")));
  ok("rejects an http:// endpoint with a port", threw(make("http://s3.example.com:9000")));
  ok("rejects a non-http(s) scheme (ftp)", threw(make("ftp://s3.example.com")));
  ok("rejects a scheme-less endpoint", threw(make("s3.example.com")));
  ok("accepts an https:// endpoint", !threw(make("https://s3.example.com")));
  ok("accepts the http://localhost test loopback", !threw(make("http://localhost:9000")));
  ok("accepts the http://127.0.0.1 test loopback", !threw(make("http://127.0.0.1:9000")));

  // Belt and braces: the rejection happens with NO request issued, so a credential is never
  // signed onto a cleartext endpoint even momentarily.
  const { captures, restore } = installFetch(() => res(200));
  try {
    try {
      const bad = new S3Destination("http://s3.example.com", BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      void bad;
    } catch {
      /* expected */
    }
    ok("constructing on an http endpoint issued no request", captures.length === 0);
  } finally {
    restore();
  }
}

// Part 5: empty or absent ETag from GET never degrades the RUNLOG conditional write
// to an unconditional overwrite.
//
// Two defects closed by the fix:
//   (a) get() used to return etag:"" when the response had no ETag header. The RUNLOG
//       read-modify-write loop in seal/pipeline.ts then called putConditional with
//       { ifMatch: "" }, and the old truthiness guard (if (opts.ifMatch)) dropped the
//       If-Match header entirely, turning a conditional PUT into an unconditional one that
//       always succeeded and never triggered a 412/retry.
//   (b) putConditional used a truthiness guard, so any caller that somehow passed "" as
//       ifMatch would silently omit If-Match and defeat the single-writer guard.
//
// The fix:
//   (a) get() now throws when the 200 response carries no ETag - fail loud at the read so
//       no caller can even construct a subsequent conditional write with a fabricated token.
//   (b) putConditional now guards with !== undefined (matching R2Destination), so an
//       explicit empty-string ifMatch IS forwarded as If-Match: "" in both the signed
//       headers and the request, which every conformant store returns as 412 (ok:false,
//       retry), rather than being silently dropped.
async function etagMissingNoUnconditionalOverwrite(): Promise<void> {
  console.log("Absent ETag does not produce an unconditional overwrite:");

  // TC-M14-1: get() on a 200 with no ETag header throws rather than returning etag:"".
  // The throw is the earliest possible signal that this store cannot support the conditional-
  // write contract; it prevents a fabricated "" token from ever reaching putConditional.
  {
    const payload = utf8("runlog body");
    // The store returns a valid 200 body but omits the ETag header entirely.
    const { captures, restore } = installFetch(() => new Response(payload, { status: 200 }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      let threw = false;
      let threwMessage = "";
      try {
        await dest.get("_RECOVERY/RUNLOG");
      } catch (e) {
        threw = true;
        threwMessage = e instanceof Error ? e.message : String(e);
      }
      ok("get() throws when the 200 response carries no ETag header", threw);
      ok("get() error message mentions ETag", threwMessage.includes("ETag") || threwMessage.includes("etag"));
      ok("get() with absent ETag issued exactly one request (the GET)", captures.length === 1);
    } finally {
      restore();
    }
  }

  // TC-M14-2: get() on a 200 with an empty-string ETag header also throws. An empty ETag is
  // not a valid strong or weak validator and cannot be used as an If-Match condition.
  {
    const payload = utf8("runlog body");
    const { restore } = installFetch(() => new Response(payload, { status: 200, headers: { etag: "" } }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      let threw = false;
      try {
        await dest.get("_RECOVERY/RUNLOG");
      } catch {
        threw = true;
      }
      ok("get() throws when the 200 response has an empty ETag header", threw);
    } finally {
      restore();
    }
  }

  // TC-M14-3: putConditional with an explicit ifMatch:"" sends If-Match:"" in the request
  // (it is NOT dropped). A store that returns 412 causes putConditional to return ok:false
  // (the retry signal), not ok:true. This is the key change: an empty-string ifMatch can no
  // longer silently degrade to an unconditional overwrite that returns ok:true.
  {
    // The store responds 412 when it receives If-Match:"" (the correct behaviour for an
    // empty/unmatched ETag condition).
    const { captures, restore } = installFetch(() => res(412));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const r = await dest.putConditional("_RECOVERY/RUNLOG", utf8("v2"), { ifMatch: "" });
      ok("putConditional with ifMatch:\"\" returns ok:false (not ok:true) on 412", !r.ok);
      ok("putConditional with ifMatch:\"\" sent one request", captures.length === 1);
      // The critical assertion: If-Match MUST be present in the request headers. The old
      // truthiness guard dropped it entirely (empty string is falsy), turning this into an
      // unconditional PUT. The new !== undefined guard forwards it, so the store sees the
      // condition and can respond with 412.
      ok("putConditional with ifMatch:\"\" forwarded If-Match to the request (not dropped)", "if-match" in captures[0]!.headers);
      ok("putConditional with ifMatch:\"\" forwarded the empty string, not a different value", captures[0]!.headers["if-match"] === "");
    } finally {
      restore();
    }
  }

  // TC-M14-4: belt-and-braces - a non-empty ifMatch is still forwarded correctly (regression
  // guard: the !== undefined change must not break the normal If-Match path).
  {
    // The store responds 200 when If-Match matches.
    const { captures, restore } = installFetch(() => res(200, { etag: '"rl-2"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const r = await dest.putConditional("_RECOVERY/RUNLOG", utf8("v2"), { ifMatch: '"rl-1"' });
      ok("putConditional with a real etag ifMatch still returns ok:true on 200", r.ok);
      ok("putConditional with a real etag still forwards If-Match", captures[0]!.headers["if-match"] === '"rl-1"');
    } finally {
      restore();
    }
  }
}

// Part 6: redirect:"manual" on every S3 fetch and rejection of unexpected 3xx (V15.3.2).
//
// A destination endpoint could legitimately return a 3xx (e.g. a temporary redirect during a
// bucket migration, or a misconfigured load balancer). Without redirect:"manual" the runtime
// follows the redirect silently and re-sends the full SigV4 Authorization header and the
// archive body to whatever Location the response names. That is an SSRF-adjacent exfiltration
// path: a malicious or misconfigured endpoint can redirect a credentialed PUT to an attacker's
// server. redirect:"manual" stops the follow at the edge; the engine then treats the 3xx as
// an error rather than retrying against the redirect target.
//
// This suite asserts:
//   (a) every S3 fetch is issued with redirect:"manual" in the RequestInit, and
//   (b) each method throws on an unexpected 3xx rather than silently succeeding.
async function redirectManual(): Promise<void> {
  console.log("V15.3.2 - redirect:manual on all S3 fetches + 3xx treated as error:");

  const makeDestination = () => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

  // (a) redirect option is "manual" on all four request types.
  for (const [label, script, run] of [
    [
      "PUT",
      () => res(200),
      async (d: S3Destination) => { await d.put("seg/redir-check", utf8("x")); },
    ],
    [
      "conditional PUT",
      () => res(200, { etag: '"e"' }),
      async (d: S3Destination) => { await d.putConditional("seg/redir-check", utf8("x"), { ifNoneMatch: "*" }); },
    ],
    [
      "GET",
      () => new Response(utf8("x"), { status: 200, headers: { etag: '"e"' } }),
      async (d: S3Destination) => { await d.get("seg/redir-check"); },
    ],
    [
      "HEAD/exists",
      () => res(200),
      async (d: S3Destination) => { await d.exists("seg/redir-check"); },
    ],
  ] as Array<[string, () => Response, (d: S3Destination) => Promise<void>]>) {
    const { captures, restore } = installFetch(script);
    try {
      await run(makeDestination());
      ok(`${label}: request was issued with redirect:"manual"`, captures.length === 1 && captures[0]!.redirect === "manual");
    } finally {
      restore();
    }
  }

  // (b) each method throws on an unexpected 3xx (301/302) rather than following or returning ok.
  for (const [label, status, run] of [
    [
      "PUT on 301",
      301,
      async (d: S3Destination) => { await d.put("seg/redir", utf8("x")); },
    ],
    [
      "conditional PUT on 302",
      302,
      async (d: S3Destination) => { await d.putConditional("seg/redir", utf8("x"), { ifNoneMatch: "*" }); },
    ],
    [
      "GET on 307",
      307,
      async (d: S3Destination) => { await d.get("seg/redir"); },
    ],
    [
      "HEAD/exists on 308",
      308,
      async (d: S3Destination) => { await d.exists("seg/redir"); },
    ],
  ] as Array<[string, number, (d: S3Destination) => Promise<void>]>) {
    const { restore } = installFetch(() => res(status, { location: "https://attacker.example.com/steal" }));
    try {
      let threw = false;
      let threwMessage = "";
      try {
        await run(makeDestination());
      } catch (e) {
        threw = true;
        threwMessage = e instanceof Error ? e.message : String(e);
      }
      ok(`${label}: throws rather than following the redirect`, threw);
      ok(`${label}: error message mentions the redirect status`, threwMessage.includes(String(status)) || threwMessage.includes("redirect"));
    } finally {
      restore();
    }
  }
}

// Part 7: delete + list, the WRITE side of the retention prune (ASVS V14.2.7). delete is a
// signed DELETE that treats 204 and 404 as success (idempotent, so a re-run of an interrupted
// prune never fails on an already-gone object); list is a signed ListObjectsV2 bucket-root GET
// (list-type=2) that follows the continuation token across pages and parses the object keys out
// of the XML. Both keep the same SigV4 + redirect:"manual" discipline as every other call.
async function deleteAndList(): Promise<void> {
  console.log("delete + list (retention prune write side, V14.2.7):");

  // delete: a 204 is success; the request is a signed DELETE with redirect:"manual".
  {
    const { captures, restore } = installFetch(() => res(204));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      await dest.delete("seg/aa/aaaa.seg");
      ok("delete issued exactly one request", captures.length === 1);
      ok("delete used method DELETE", captures[0]!.method === "DELETE");
      ok("delete targets endpoint/bucket/encoded-key", captures[0]!.url === `${ENDPOINT}/${BUCKET}/${encodePath("seg/aa/aaaa.seg")}`);
      ok("delete carries a SigV4 Authorization header", (captures[0]!.headers["authorization"] ?? "").startsWith("AWS4-HMAC-SHA256 Credential="));
      ok("delete was issued with redirect:\"manual\"", captures[0]!.redirect === "manual");
    } finally {
      restore();
    }
  }
  // delete: a 404 is treated as success (idempotent), not an error.
  {
    const { restore } = installFetch(() => res(404));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      let threw = false;
      try {
        await dest.delete("seg/aa/already-gone.seg");
      } catch {
        threw = true;
      }
      ok("delete maps a 404 to success (idempotent)", !threw);
    } finally {
      restore();
    }
  }
  // delete: a 500 is a hard error.
  {
    const { restore } = installFetch(() => res(500));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      let threw = false;
      try {
        await dest.delete("seg/aa/x.seg");
      } catch {
        threw = true;
      }
      ok("delete throws on a 500", threw);
    } finally {
      restore();
    }
  }

  // list: a single un-truncated page returns every <Key> in the XML, via a signed ListObjectsV2
  // bucket-root GET with list-type=2 and the prefix in the query.
  {
    const page = `<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated>` +
      `<Contents><Key>run/RUN1/root.manifest.json</Key></Contents>` +
      `<Contents><Key>run/RUN1/root.manifest.json.sig</Key></Contents>` +
      `<Contents><Key>run/RUN1/manifest/00000.dpe</Key></Contents></ListBucketResult>`;
    const { captures, restore } = installFetch(() => new Response(page, { status: 200 }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const keys = await dest.list("run/RUN1/");
      ok("list returns every Key in the page", keys.length === 3 && keys[0] === "run/RUN1/root.manifest.json" && keys[2] === "run/RUN1/manifest/00000.dpe");
      ok("list issued one request for a single page", captures.length === 1);
      ok("list used method GET", captures[0]!.method === "GET");
      ok("list is a bucket-root request (endpoint/bucket/)", captures[0]!.url.startsWith(`${ENDPOINT}/${BUCKET}/?`));
      ok("list query carries list-type=2", captures[0]!.url.includes("list-type=2"));
      ok("list query carries the prefix", captures[0]!.url.includes("prefix=run%2FRUN1%2F"));
      ok("list carries a SigV4 Authorization header", (captures[0]!.headers["authorization"] ?? "").startsWith("AWS4-HMAC-SHA256 Credential="));
      ok("list was issued with redirect:\"manual\"", captures[0]!.redirect === "manual");
    } finally {
      restore();
    }
  }
  // list: a truncated first page is followed by the continuation token to a second page; the
  // union of both pages' keys is returned and the second request carries the token.
  {
    let call = 0;
    const page1 = `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>TOKEN-2</NextContinuationToken>` +
      `<Contents><Key>run/RUN1/a</Key></Contents></ListBucketResult>`;
    const page2 = `<ListBucketResult><IsTruncated>false</IsTruncated>` +
      `<Contents><Key>run/RUN1/b</Key></Contents></ListBucketResult>`;
    const { captures, restore } = installFetch(() => new Response(call++ === 0 ? page1 : page2, { status: 200 }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const keys = await dest.list("run/RUN1/");
      ok("list follows the continuation token across pages", keys.length === 2 && keys[0] === "run/RUN1/a" && keys[1] === "run/RUN1/b");
      ok("list issued two requests (paged)", captures.length === 2);
      ok("the second list request carried the continuation token", captures[1]!.url.includes("continuation-token=TOKEN-2"));
    } finally {
      restore();
    }
  }
  // list: a 500 is a hard error.
  {
    const { restore } = installFetch(() => res(500));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      let threw = false;
      try {
        await dest.list("run/RUN1/");
      } catch {
        threw = true;
      }
      ok("list throws on a 500", threw);
    } finally {
      restore();
    }
  }
}

export async function run(): Promise<void> {
  await httpContract();
  httpsEnforcement();
  await etagMissingNoUnconditionalOverwrite();
  await redirectManual();
  await deleteAndList();
}
