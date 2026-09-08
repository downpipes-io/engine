import { ab, base64Encode, concat, hexDecode, sha256Hex } from "../crypto/bytes.ts";
import { sealedSegmentLength } from "../crypto/streamseal.ts";
import type { CfOp, Meter } from "../meter.ts";
import { isObjectLockRefusalStamped } from "./classify.ts";
import { DestIo, type DestIoSnapshot } from "./dest-io.ts";
import { DestFaultLog, type DestFaultSnapshot, type DestOp } from "./fault-log.ts";
import type { DestPacer } from "./pace.ts";
import { type Addressing, requireHttpsEndpoint, resolveAddressing } from "./s3-addressing.ts";
import { MULTIPART_MAX_BACKOFF_MS, MULTIPART_RETRY_ATTEMPTS, MULTIPART_THRESHOLD, PART_SIZE, retryAfterMsOf } from "./s3-multipart.ts";
import { abortMultipart, completeMultipart, initiateMultipart, type MultipartIO, uploadPart } from "./s3-multipart-ops.ts";
import { del, exists, get, headStatus, list, listPage, objectLockStatus, type ReadIO } from "./s3-read-ops.ts";
import { drainBounded, drainResponseBounded } from "./s3-stream.ts";
import { retainUntilISO, S3_OBJECT_LOCK_MODE, s3WriteFailure } from "./s3-worm.ts";
import { encodePath, type SigV4Creds, signV4 } from "./sigv4.ts";
import type { Destination, GetResult, ListPage, PutConditionalResult, WormPolicy, WormStatus } from "./types.ts";
import { MAX_DEST_TEXT_BYTES, MAX_STREAM_SEGMENT_BYTES } from "./types.ts";

// Re-export the addressing style so existing importers (e.g. sched/scheduler-do.ts) keep their
// "../dest/s3.ts" import path unchanged after the helper extraction.
export type { Addressing } from "./s3-addressing.ts";

/**
 * S3_FETCH_TIMEOUT_MS bounds EVERY outbound S3 fetch (GET/HEAD/DELETE/LIST, a small buffered PUT, and every
 * multipart part) so a black-holed S3-compatible endpoint can never hang a pass indefinitely. It is GENEROUS:
 * a large backup segment shares this exact primitive (a multipart
 * part up to PART_SIZE, or a small buffered object up to MULTIPART_THRESHOLD), so the bound must survive a
 * real-world slow-but-progressing upload, not just the fast common case -- 120s is well beyond a typical
 * multi-megabyte part's expected wall time even on a throttled destination, while still being FINITE: no
 * destination, however slow, may hang a slice forever. Overridable per destination instance (the
 * constructor's opts.fetchTimeoutMs) so a validator can drive the abort path in milliseconds instead of
 * waiting out the real bound; production callers never set it, so every real destination gets this full
 * generous default.
 *
 * It bounds ONE request, not a whole upload: a 33-part multipart may legitimately run far longer, since
 * each part gets its own fresh budget. An abort under this bound is counted as a timeout degradation and
 * surfaces to the retry as a transient fault.
 */
export const S3_FETCH_TIMEOUT_MS = 120_000;

/**
 * A minimal Destination over any S3-compatible bucket (AWS S3, R2's S3 endpoint, Google Cloud Storage's
 * S3-interoperable endpoint, B2, Wasabi, MinIO; Azure Blob has its own client) using fetch
 * with SigV4. Writes go to the customer's own bucket, so no data leaves their control. Content-addressed
 * seg/ writes are idempotent, so a re-run or a resumed run overwrites identically. It refuses a
 * non-https endpoint at construction, refuses redirects on every credentialed call, streams large
 * segments as a multipart upload, and arms opt-in, default-off WORM Object-Lock headers when a
 * policy is configured.
 */
export class S3Destination implements Destination {
  private endpoint: string;
  private bucket: string;
  private creds: SigV4Creds;
  private now: () => Date;
  private meter: Meter | undefined;
  // worm is the OPT-IN, DEFAULT-OFF Object-Lock policy. When undefined (the default) every write is
  // byte-identical to the pre-WORM path (no object-lock headers). When set, the object-creating
  // requests (PUT, conditional PUT, and multipart initiate) carry the S3 Object-Lock mode +
  // retain-until-date headers, signed into the SigV4 signature, so the store enforces immutability
  // for the window. It NEVER changes get/exists/list/delete (delete is left to the store's own
  // retention enforcement: a locked object's delete is simply refused by S3).
  private worm: WormPolicy | undefined;
  // pacer is the OPTIONAL adaptive destination throttle (T1-A). When set, every outbound request takes a
  // token before it is sent and reports its response status back, so the writer paces itself BELOW a
  // destination that is pushing back (503/429) instead of hammering it. Absent (the default for the
  // in-memory test doubles and any caller that omits it) means no pacing, byte-identical to before.
  private pacer: DestPacer | undefined;
  // sessionToken is the OPTIONAL AWS STS session token (x-amz-security-token) for TEMPORARY credentials:
  // when the accessKeyID/secretKey are short-lived STS credentials (from AssumeRole, or a customer's own
  // rotation), the session token MUST ride every signed request as the x-amz-security-token header, in
  // BOTH the signed header set (so it is covered by the signature) and on the wire. Absent (the default,
  // for long-lived keys) means no such header, byte-identical to before. It is credential-class: held only
  // in memory for this destination's life, never logged, never surfaced in a status view.
  private sessionToken: string | undefined;
  // useVhost selects virtual-hosted-style addressing (https://<bucket>.<host>/<key>) over the default
  // path-style (https://<host>/<bucket>/<key>). AWS S3 prefers virtual-hosted and path-style to its global
  // endpoint 301-redirects (which the redirect:"manual" guard turns into a hard error); some S3-compatible
  // stores ONLY accept one form. vhostBase is the precomputed "https://<bucket>.<host>" prefix (empty for
  // path-style). The signed host header and canonical path are always derived from the URL these produce,
  // so signing follows addressing automatically.
  private readonly useVhost: boolean;
  private readonly vhostBase: string;
  // storageClass is the OPTIONAL S3 storage class (x-amz-storage-class) set on object CREATION (PUT and
  // CreateMultipartUpload), so cold backup data can land in a cheaper tier. Only IMMEDIATELY-READABLE
  // classes are ever passed here: the factory rejects GLACIER/DEEP_ARCHIVE, which cannot be read without an
  // async thaw and would break verify-at-seal (the engine reads the archive back at seal time) and restore.
  // Absent = the bucket default (byte-unchanged).
  private storageClass: string | undefined;

  // fetchTimeoutMs is the bound metered() applies to every outbound fetch (item 7). Defaults to the
  // generous S3_FETCH_TIMEOUT_MS; only a validator overrides it (opts.fetchTimeoutMs) to drive the abort
  // path without waiting out the real bound.
  private readonly fetchTimeoutMs: number;

  // multipartAbortFailedCount tallies how many times a FAILED multipart upload's best-effort abort ALSO
  // failed during this destination instance's lifetime, leaving invisible stranded part-storage the bucket's
  // own lifecycle/abort policy must reap (multipart-abort-stranded-parts). It is a DIAGNOSTIC counter only
  // (an integer, never a key/id/value); putMultipart increments it in the abort-failed branch it otherwise
  // swallows, and the seal driver reads it via multipartAbortFailures() to surface the signal on the run row.
  private multipartAbortFailedCount = 0;

  // faults is the bounded, closed-vocabulary destination-fault ring (G135): every failing op notes its
  // IDENTITY here (op, HTTP status, closed S3 <Code>, fault class, classifier arm, request-id presence,
  // Object-Lock-checksum complaint), so a fault past the single-shot PUT path is no longer a bare
  // "status 403". Diagnostic only: it never changes control flow, and the seal driver reads it via
  // destFaults() to stamp the run row, exactly as it already does for multipartAbortFailures().
  private readonly faults = new DestFaultLog();

  // io is the bounded DEGRADATION counter set (G186): the swallowed-by-design branches that make a run that
  // SUCCEEDED take ten times as long, or cost ten times as much -- store backpressure (503/429) driving the
  // pacer down, multipart retries, aborted requests against a black-holed endpoint, conditional-PUT conflicts
  // (two engines fighting over one RUNLOG), and the dedup-defeating HEAD that collapses a 403/5xx to "absent"
  // and re-uploads the whole archive. Diagnostic only: noting never changes control flow. It is read back via
  // destIo() for the run row, and every bump also lands in the isolate-local tally that flushes to the DO.
  private readonly io = new DestIo();

  // opts groups EVERY optional capability (the run clock, the meter, the WORM policy, the pacer, the STS
  // session token, the addressing style, the storage class) under one named argument, so the public
  // surface is the 5 required identity fields + opts (GUARDRAILS §6 max-4-params: the 3 required identity
  // fields beyond the bucket/key pair justify the residual one-over). An omitted opts (and any omitted
  // field) is byte-identical to before; a future destination knob has a named home, not a positional tail.
  constructor(endpoint: string, bucket: string, region: string, accessKeyID: string, secretKey: string, opts?: { now?: () => Date; meter?: Meter; worm?: WormPolicy; pacer?: DestPacer; sessionToken?: string; addressing?: Addressing; storageClass?: string; fetchTimeoutMs?: number }) {
    // Refuse a non-https endpoint at the boundary, before any credential or byte is signed
    // or sent: the SigV4 Authorization header and the archive bytes must never ride cleartext.
    requireHttpsEndpoint(endpoint);
    this.endpoint = endpoint.replace(/\/+$/, "");
    this.bucket = bucket;
    this.creds = { accessKeyID, secretKey, region, service: "s3" };
    this.now = opts?.now ?? (() => new Date());
    this.meter = opts?.meter;
    this.worm = opts?.worm;
    this.pacer = opts?.pacer;
    this.sessionToken = opts?.sessionToken;
    this.storageClass = opts?.storageClass;
    this.fetchTimeoutMs = opts?.fetchTimeoutMs ?? S3_FETCH_TIMEOUT_MS;
    // Resolve the addressing style ONCE from the (already-https-validated) endpoint host, the bucket and
    // the policy. The vhost prefix inherits the endpoint's scheme (https) and never downgrades.
    const u = new URL(this.endpoint);
    this.useVhost = resolveAddressing(u.host, bucket, opts?.addressing);
    this.vhostBase = this.useVhost ? `${u.protocol}//${bucket}.${u.host}` : "";
  }

  // securityTokenHeader returns the x-amz-security-token header for temporary (STS) credentials, or an
  // empty object when none is set (long-lived keys, the default). It is spread into BOTH every signed
  // header map (so the signature covers it) AND the wire headers (in metered(), the single fetch
  // chokepoint), keeping the two in lockstep, exactly the pattern objectLockHeaders uses for WORM.
  private securityTokenHeader(): Record<string, string> {
    return this.sessionToken !== undefined && this.sessionToken !== "" ? { "x-amz-security-token": this.sessionToken } : {};
  }

  // objectLockHeaders returns the S3 Object-Lock headers for a write made NOW, or an empty object
  // when no WORM policy is configured (the default, so a non-WORM write is byte-unchanged). The two
  // headers are x-amz-object-lock-mode (GOVERNANCE|COMPLIANCE) and x-amz-object-lock-retain-until-date
  // (an absolute RFC-3339 instant derived from the policy's retention window). They are returned as a
  // plain record so the caller can MERGE them into BOTH the signed-headers set (so the signature
  // covers them) AND the fetch headers (so they actually go on the wire), keeping the two in lockstep
  // is what makes the signature valid.
  private objectLockHeaders(): Record<string, string> {
    if (this.worm === undefined) return {};
    return {
      "x-amz-object-lock-mode": S3_OBJECT_LOCK_MODE[this.worm.mode],
      "x-amz-object-lock-retain-until-date": retainUntilISO(this.now(), this.worm.retentionDays),
    };
  }

  // storageClassHeader returns the x-amz-storage-class header when a storage class is set, or an empty
  // object otherwise (the bucket default, byte-unchanged). Like the Object-Lock headers it is set only on
  // object CREATION (PUT, conditional PUT, CreateMultipartUpload) and is spread into BOTH the signed and the
  // wire headers in lockstep, so the signature covers it.
  private storageClassHeader(): Record<string, string> {
    return this.storageClass !== undefined && this.storageClass !== "" ? { "x-amz-storage-class": this.storageClass } : {};
  }

  // wormChecksumHeader returns the x-amz-checksum-sha256 header REQUIRED by AWS S3 on any PutObject that
  // carries Object-Lock parameters (without a Content-MD5 or x-amz-checksum-* header AWS rejects the write
  // with InvalidRequest, so every WORM seal to S3 failed before this). It is emitted ONLY when a WORM policy
  // is configured: a non-WORM write (and every write to R2, which has no such rule) stays byte-identical to
  // before. The value is the STANDARD-base64 SHA-256 of the body; we reuse the digest already computed for
  // the SigV4 x-amz-content-sha256 (hex), decoding it back to bytes rather than hashing the body twice. Like
  // the lock headers it is merged into BOTH the signed and wire header sets, so it is covered by the
  // signature; AWS then validates the stored bytes against it end to end.
  private wormChecksumHeader(payloadHashHex: string): Record<string, string> {
    return this.worm === undefined ? {} : { "x-amz-checksum-sha256": base64Encode(hexDecode(payloadHashHex)) };
  }

  // metered wraps every outbound fetch so a slice budget sees the destination's true
  // subrequest spend (each multipart part is a real subrequest, not just each putStream).
  //
  // destOp names the closed destination operation this request belongs to. It is used ONLY to attribute a
  // TRANSPORT fault (a black-holed endpoint, a DNS/TLS failure, this method's own abort bound) to the op
  // that suffered it in the fault ring -- a fault that never reaches a call site's status check, and so was
  // previously attributable to nothing at all. A response-carried fault is noted at the call site instead
  // (only the call site knows whether a given non-2xx is a fault: a 404 on exists(), a 412 on
  // putConditional and a 404 on the object-lock probe are all NORMAL answers). It is distinct from the
  // COST op below, which classes the subrequest for the meter, not the fault ring.
  private async metered(input: URL, init: RequestInit, destOp: DestOp): Promise<Response> {
    // Tag by HTTP method so the cost ledger separates R2 read class (GET/HEAD) from write class
    // (PUT/POST multipart parts, DELETE). Cost Phase 3; an untagged spend would still count the total.
    const method = (init.method ?? "GET").toUpperCase();
    const costOp: CfOp = method === "GET" || method === "HEAD" ? "r2ClassB" : "r2ClassA";
    this.meter?.spend(1, costOp);
    // Pace BELOW the destination's tolerance (T1-A): take a token before the request, then fold the
    // response status back into the adaptive rate, so a store that pushes back (503/429) is queried more
    // slowly on the next requests instead of being hammered. Absent pacer = no pacing (unchanged). Every
    // request method and every multipart part routes through here, so the whole write path is paced.
    if (this.pacer) await this.pacer.take();
    // Add the STS session token (x-amz-security-token) to the WIRE headers HERE, the single fetch
    // chokepoint, so every credentialed request carries it; it is added to each SIGNED header map at the
    // signing site too (so the signature covers it), keeping signed and wire in lockstep. Empty (and so a
    // byte-identical request) unless temporary credentials are configured.
    const tokenHeader = this.securityTokenHeader();
    const sendInit = Object.keys(tokenHeader).length > 0 ? { ...init, headers: { ...(init.headers as Record<string, string>), ...tokenHeader } } : init;
    // Bound the request with a finite, generous AbortController timeout (item 7): a black-holed
    // S3-compatible endpoint must never hang the pass indefinitely. Scoped to THIS call only (never shared
    // across requests, so pacing/backoff between retries is unaffected); a timed-out call throws a plain,
    // key-inclusive-but-secret-free Error (mirroring the redirect/write-failure errors this method's callers
    // already throw), which multipartStep's transient-fault regex already retries on (it matches "timed?
    // ?out"), and any other caller surfaces exactly like today's network-failure throw.
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.fetchTimeoutMs);
    try {
      const resp = await fetch(input, { ...sendInit, signal: controller.signal });
      this.pacer?.observe(resp.status);
      // Note the DEGRADATION this response represents (G186), at the one chokepoint every request passes
      // through: a 503/429 is the store's own backpressure signal (the same statuses the pacer just halved
      // on), and the pacer's resulting effective rate is the WORST-CASE pace this destination was driven
      // down to. A count and a rate; the status itself is never retained, and no other status leaves a trace.
      this.io.noteStatus(resp.status);
      if (this.pacer) this.io.noteEffectiveRate(this.pacer.effectiveRate());
      return resp;
    } catch (e) {
      // Note the TRANSPORT fault before rethrowing (G135). The recorded record carries the op, the closed
      // classifier arm and status 0 (no response was ever received); the error's message, the URL and the
      // key never enter it.
      if (timedOut) {
        const err = new Error(`s3 request timed out after ${this.fetchTimeoutMs}ms (${method} ${input.pathname})`);
        this.faults.noteThrown(destOp, err);
        // A BLACK-HOLED endpoint (aborted at the fetch bound) is a different fault from a refused one, and a
        // multipart step RETRIES it away, so a run can succeed having eaten several of these. Count it (G186).
        this.io.note("timeouts");
        throw err;
      }
      this.faults.noteThrown(destOp, e);
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  private url(key: string): string {
    // Virtual-hosted: the bucket is a subdomain and the path is just the key (so url("") is the bucket
    // root https://<bucket>.<host>/ with canonical path "/"). Path-style: the bucket is the first path
    // segment (url("") is https://<host>/<bucket>/). Either way the host header and signed canonical path
    // are taken from this URL at every call site, so the signature matches.
    // G207: encodePath REFUSES a key with a "." or ".." path segment (the traversal guard). The refusal is a
    // hard error the run row coarsens away, so support could not tell that a specific dot-segmented key --
    // rather than the destination -- stopped the run. Record the closed class (never the key) and rethrow
    // unchanged: the guard's behaviour is untouched, only its invisibility is.
    try {
      if (this.useVhost) return `${this.vhostBase}/${encodePath(key)}`;
      return `${this.endpoint}/${this.bucket}/${encodePath(key)}`;
    } catch (e) {
      this.faults.noteGuardRefusal("key-shape-refused");
      throw e;
    }
  }

  private amzDate(): string {
    // ISO basic form YYYYMMDDTHHMMSSZ.
    return this.now().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  }

  // put writes an object. The body hash is bound into the signature via
  // x-amz-content-sha256, so a proxy cannot alter the body undetected.
  //
  // redirect:"manual" prevents the runtime from silently following a 3xx response and
  // re-sending the credentialed SigV4 request to a third-party endpoint (V15.3.2). Any
  // redirect returned by the destination is treated as an error rather than followed.
  // multipartAbortFailures reports how many FAILED multipart uploads' best-effort aborts ALSO failed over
  // this destination instance's lifetime (multipart-abort-stranded-parts), so the seal driver can stamp
  // `multipartAbortFailed` on the run row and the invisible stranded-part-storage fault becomes visible. An
  // integer only, never a key/id/value. Implements the optional Destination.multipartAbortFailures accessor.
  multipartAbortFailures(): number {
    return this.multipartAbortFailedCount;
  }

  // destFaults is the bounded, closed-vocabulary snapshot of every destination op that FAILED over this
  // instance's lifetime (G135). Implements the optional Destination.destFaults accessor; the seal driver
  // reads it after finalising a run and stamps it on the run row, so a multipart/GET/DELETE/LIST fault
  // carries its real identity (expired STS session vs bucket-policy denial vs WORM refusal vs a fault the
  // classifier could not read at all) instead of dying as a bare "status 403".
  destFaults(): DestFaultSnapshot {
    return this.faults.snapshot();
  }

  // destIo is the bounded DEGRADATION snapshot of this instance (G186): the counters for the branches a
  // SUCCESSFUL run swallows (store backpressure, multipart retries, aborted requests, conditional-PUT
  // conflicts, dedup-defeating HEAD collapses, unparseable Retry-Afters) plus the worst effective rate the
  // pacer was driven down to. Implements the optional Destination.destIo accessor, on the exact model of
  // destFaults(): clamped integers only, so a run row can carry it and a green-but-slow run stops being
  // indistinguishable from a healthy one.
  destIo(): DestIoSnapshot {
    return this.io.snapshot();
  }

  // errorBodyOf reads a FAILED write's error body once, bounded (V12.3.1) regardless of whether the
  // store's response carries a Content-Length, so a hostile/misconfigured destination cannot exhaust
  // isolate memory via its error response. Swallowed to "" on any hiccup (a bound-exceeded read included),
  // exactly as the unbounded resp.text().catch(() => "") this replaces already did on a network fault.
  private async errorBodyOf(resp: Response): Promise<string> {
    try {
      return new TextDecoder().decode(await drainResponseBounded(resp, MAX_DEST_TEXT_BYTES, "s3 error body"));
    } catch {
      return "";
    }
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    const u = new URL(this.url(key));
    const amzDate = this.amzDate();
    const payloadHash = await sha256Hex(body);
    // Object-Lock headers (empty unless a WORM policy is configured) go in BOTH the signed set and
    // the request headers; signV4 lower-cases and sorts, so adding them here covers them in the
    // SignedHeaders/Signature, and merging the SAME map below puts them on the wire in lockstep.
    // lockHeaders is kept separately from the merged set because the FAILURE path needs to know whether
    // this write carried Object-Lock headers: R2 refuses a lock-bearing PUT to a bucket that is not
    // Object-Lock enabled with a bare NotImplemented, which names the lock policy only in that context.
    const lockHeaders = this.objectLockHeaders();
    const lockArmed = Object.keys(lockHeaders).length > 0;
    const lock = { ...lockHeaders, ...this.storageClassHeader(), ...this.wormChecksumHeader(payloadHash) };
    const headers: Record<string, string> = { host: u.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...lock, ...this.securityTokenHeader() };
    const auth = await signV4("PUT", u.pathname, "", headers, payloadHash, amzDate, this.creds);
    const resp = await this.metered(
      u,
      {
        method: "PUT",
        headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...lock, Authorization: auth },
        body: ab(body),
        redirect: "manual",
      },
      "put",
    );
    if (resp.status >= 300 && resp.status < 400) {
      this.faults.noteResponse("put", resp, "");
      this.faults.noteRedirect(resp); // G119: the region hint / unrecognised-target class (never the Location URL)
      throw new Error(`PUT ${key}: unexpected redirect (status ${resp.status}); a destination endpoint must not redirect a credentialed request`);
    }
    if (!resp.ok) {
      // Read the (bounded) error body ONCE and use it for BOTH the fault record (the closed S3 <Code> and
      // the Object-Lock-checksum boolean) and the operator-facing message. The body itself is never retained.
      const errBody = await this.errorBodyOf(resp);
      this.faults.noteResponse("put", resp, errBody);
      throw s3WriteFailure("PUT", key, resp.status, errBody, lockArmed);
    }
  }

  // putConditional writes only if the precondition holds: If-None-Match: * to create when
  // absent, or If-Match: <etag> to replace a specific version. A 412 returns ok:false so
  // the caller can re-read and retry (the RUNLOG accumulation path).
  //
  // Guard note: unlike a truthiness check, !== undefined here means an explicit empty string
  // ifMatch is never silently dropped from the signed headers and the request (ENG-M14). An
  // empty ifMatch would degrade a conditional write to an unconditional PUT, defeating the
  // RUNLOG single-writer guard. Instead, an empty-string ifMatch IS sent as If-Match: "" (which
  // every conformant S3-compatible store rejects with a 412, so the caller retries, which is the
  // correct outcome). This mirrors R2Destination.putConditional's === undefined guard.
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const u = new URL(this.url(key));
    const amzDate = this.amzDate();
    const payloadHash = await sha256Hex(body);
    // Object-Lock headers (empty unless a WORM policy is configured) are added to the signed set and
    // the wire headers in lockstep, so a conditional write (e.g. the RUNLOG) is locked too when WORM is on.
    const lockHeaders = this.objectLockHeaders();
    const lockArmed = Object.keys(lockHeaders).length > 0;
    const lock = { ...lockHeaders, ...this.storageClassHeader(), ...this.wormChecksumHeader(payloadHash) };
    const headers: Record<string, string> = { host: u.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...lock, ...this.securityTokenHeader() };
    if (opts.ifMatch !== undefined) headers["if-match"] = opts.ifMatch;
    if (opts.ifNoneMatch !== undefined) headers["if-none-match"] = opts.ifNoneMatch;
    const auth = await signV4("PUT", u.pathname, "", headers, payloadHash, amzDate, this.creds);
    // The host header is signed but set by the runtime, not by us, so it is omitted here.
    const fetchHeaders: Record<string, string> = { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...lock, Authorization: auth };
    if (opts.ifMatch !== undefined) fetchHeaders["if-match"] = opts.ifMatch;
    if (opts.ifNoneMatch !== undefined) fetchHeaders["if-none-match"] = opts.ifNoneMatch;
    // redirect:"manual" prevents the runtime from silently following a 3xx and re-sending
    // the credentialed SigV4 request to a third-party endpoint (V15.3.2).
    const resp = await this.metered(u, { method: "PUT", headers: fetchHeaders, body: ab(body), redirect: "manual" }, "put-conditional");
    if (resp.status >= 300 && resp.status < 400) {
      this.faults.noteResponse("put-conditional", resp, "");
      this.faults.noteRedirect(resp); // G119
      throw new Error(`conditional PUT ${key}: unexpected redirect (status ${resp.status}); a destination endpoint must not redirect a credentialed request`);
    }
    // A 412 is the NORMAL lost-precondition answer the RUNLOG retry loop expects, not a fault: it is not noted
    // in the FAULT ring. It IS counted as a degradation (G186): one conflict is routine, but a rising count on
    // the RUNLOG is two engines fighting over one log, which is invisible on the (successful) run today.
    if (resp.status === 412) {
      this.io.note("conditionalPutConflicts");
      return { ok: false };
    }
    if (!resp.ok) {
      const errBody = await this.errorBodyOf(resp);
      this.faults.noteResponse("put-conditional", resp, errBody);
      throw s3WriteFailure("conditional PUT", key, resp.status, errBody, lockArmed);
    }
    const etag = resp.headers.get("etag");
    // G206: a conforming store returns an ETag on a successful conditional PUT. A store that does NOT is
    // SILENTLY TOLERATED here (the caller falls back to a body compare), so the RUNLOG's single-writer
    // concurrency guard quietly degrades and nothing anywhere says so. The tolerance is unchanged; the
    // non-conformance is now recorded as a closed class (no header, no body, no key).
    if (!etag) this.faults.noteAnomaly("no-etag-on-conditional-put");
    return etag ? { ok: true, etag } : { ok: true };
  }

  // putStream writes a streamed body (a large sealed segment, plaintext <=1 GiB per SPEC
  // 14.5). A streaming request body emits chunked Transfer-Encoding with no
  // Content-Length, which real S3/R2 endpoints reject (S3 returns 411/501 on an unframed
  // chunked PUT; R2's S3 API requires Content-Length), so a stream is never handed to
  // fetch directly. A small body (sealed bytes within MULTIPART_THRESHOLD) drains to one
  // length-known PUT with its real hash signed; a large one uploads as a SigV4 multipart
  // (initiate, 32 MiB parts each with its own signed hash, complete), holding one part in
  // memory at a time, so a maximal sealed segment never approaches the isolate memory
  // limit. size is the PLAINTEXT byte count (the writer's contract); the sealed stream is
  // bounded at sealedSegmentLength of the cap, which is slightly MORE than 1 GiB (the
  // STREAM framing and per-chunk tags), so a maximal legal segment is not refused.
  async putStream(key: string, body: ReadableStream<Uint8Array>, size?: number): Promise<void> {
    if (size !== undefined && size > MAX_STREAM_SEGMENT_BYTES) {
      // G207: the engine's OWN ceiling refused the write. The run row coarsens the message away, so support
      // could not tell an off-by-framing overrun from a wildly wrong size. Record the closed class plus the
      // CLAMPED magnitude (a size is a non-secret int); the key never rides.
      this.faults.noteGuardRefusal("segment-over-limit", size);
      throw new Error(`segment ${key} exceeds the ${MAX_STREAM_SEGMENT_BYTES}-byte single-segment limit`);
    }
    const sealedBound = sealedSegmentLength(size ?? MAX_STREAM_SEGMENT_BYTES);
    if (size !== undefined && sealedBound <= MULTIPART_THRESHOLD) {
      const buffered = await drainBounded(body, sealedBound, key);
      await this.put(key, buffered);
      return;
    }
    await this.putMultipart(key, body, sealedBound);
  }

  // putMultipart streams the body as an S3 multipart upload: initiate, PART_SIZE parts
  // (each length-known, its real SHA-256 bound into its own SigV4 signature), then
  // complete with the collected part ETags. Each step retries transient faults a bounded
  // number of times; on a terminal failure the upload is aborted best-effort so the
  // destination is not left accumulating invisible part storage. The whole-object
  // integrity remains end-to-end: the archive's per-record hashes and the segment AEAD
  // are what a reader verifies, not the transport ETags.
  private async putMultipart(key: string, body: ReadableStream<Uint8Array>, bound: number): Promise<void> {
    const io = this.multipartIO;
    const uploadId = await this.multipartStep(`initiate multipart ${key}`, () => initiateMultipart(io, key));
    try {
      const etags = await this.uploadAllParts(key, body, bound, uploadId);
      if (etags.length === 0) {
        // An empty stream cannot complete a multipart upload (S3 requires at least one
        // part); abort it and write the empty object directly.
        await abortMultipart(io, key, uploadId);
        await this.put(key, new Uint8Array(0));
        return;
      }
      await this.multipartStep(`complete multipart ${key}`, () => completeMultipart(io, key, uploadId, etags));
    } catch (e) {
      // Best-effort abort so a failed upload does not strand invisible part storage; the
      // original error is what the caller needs to see.
      try {
        await abortMultipart(io, key, uploadId);
      } catch {
        // The abort itself failing leaves parts the bucket's lifecycle/abort policy
        // reaps; the seal error below is still the actionable failure. TALLY the failed abort (an integer
        // only, no key/id) so the seal driver can surface `multipartAbortFailed` on the run row -- otherwise
        // stranded part-storage (a real cost + clutter fault) is completely invisible to the operator.
        this.multipartAbortFailedCount++;
      }
      throw e;
    }
  }

  // uploadAllParts reads the body and uploads it as PART_SIZE multipart parts, returning the
  // collected ETags in part order (so completeMultipart can name them). Each emitted chunk is
  // accumulated until at least PART_SIZE is buffered, then exactly PART_SIZE is carved off and
  // uploaded so every part but the last is uniform (S3 requires every non-final part to be at
  // least 5 MiB); the trailing remainder (the final, possibly-short part) is flushed at the end.
  // The running total is bounded so a stream that overruns its sealed bound fails loud rather than
  // uploading unbounded parts. Behaviour is identical to the inline loop putMultipart used to run.
  private async uploadAllParts(key: string, body: ReadableStream<Uint8Array>, bound: number, uploadId: string): Promise<string[]> {
    const io = this.multipartIO;
    const etags: string[] = [];
    let partNumber = 1;
    const reader = body.getReader();
    let pending: Uint8Array[] = [];
    let pendingBytes = 0;
    let total = 0;
    const flushPart = async (): Promise<void> => {
      if (pendingBytes === 0) return;
      const part = concat(...pending);
      pending = [];
      pendingBytes = 0;
      const n = partNumber++;
      const etag = await this.multipartStep(`part ${n} of ${key}`, () => uploadPart(io, key, uploadId, n, part));
      etags.push(etag);
    };
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined || value.length === 0) continue;
      total += value.length;
      if (total > bound) {
        // G207: a sealed stream overran its declared bound -- an engine-side invariant, so the MAGNITUDE is
        // what tells an off-by-framing from a wildly wrong bound. Closed class + a clamped int.
        this.faults.noteGuardRefusal("sealed-bound-exceeded", total);
        throw new Error(`segment ${key} stream exceeds its ${bound}-byte sealed bound`);
      }
      pending.push(value);
      pendingBytes += value.length;
      while (pendingBytes >= PART_SIZE) {
        // Carve exactly PART_SIZE so every part but the last is uniform (S3 requires
        // every non-final part to be at least 5 MiB; uniform 32 MiB parts satisfy that).
        const whole = concat(...pending);
        const head = whole.subarray(0, PART_SIZE);
        const rest = whole.subarray(PART_SIZE);
        pending = rest.length > 0 ? [rest] : [];
        pendingBytes = rest.length;
        const n = partNumber++;
        const etag = await this.multipartStep(`part ${n} of ${key}`, () => uploadPart(io, key, uploadId, n, head));
        etags.push(etag);
      }
    }
    await flushPart();
    return etags;
  }

  // multipartStep retries one multipart step on transient faults (5xx/429/network) with
  // jittered backoff, locally to the destination so a single flaky part never forces the
  // caller to re-send the whole object.
  private async multipartStep<T>(label: string, fn: () => Promise<T>): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < MULTIPART_RETRY_ATTEMPTS; attempt++) {
      if (attempt > 0) {
        // Jittered exponential backoff, BUT honour a server Retry-After when the last error carried one
        // (a 503 SlowDown / 429 from the store): wait AT LEAST the requested time, never less, so a
        // throttling destination is not re-hit on a blind 150ms backoff (T1-4: stop spamming a
        // destination that is pushing back). Capped at MULTIPART_MAX_BACKOFF_MS so a large Retry-After
        // cannot stall the slice wall budget; a throttle needing longer is carried by the run's resume.
        const expo = Math.floor(Math.random() * 150 * 2 ** (attempt - 1));
        const ra = retryAfterMsOf(lastErr);
        // Count the RE-ISSUE (G186). A retry that eventually succeeds leaves no trace anywhere today, yet a
        // run that quietly re-sent a third of its parts is the slow, expensive night the customer is ringing
        // about. Counted at the moment the step is about to be re-issued, so it counts RETRIES, not attempts.
        this.io.note("retryAttemptsTotal");
        await new Promise((r) => setTimeout(r, Math.min(MULTIPART_MAX_BACKOFF_MS, ra !== null ? Math.max(ra, expo) : expo)));
      }
      try {
        return await fn();
      } catch (e) {
        lastErr = e;
        // A STAMPED Object-Lock refusal is thrown on immediately, above the message regex. R2 refuses a
        // lock-bearing CreateMultipartUpload to a bucket that is not Object-Lock enabled with 501, and
        // /status (5\d\d|429)/ matches it, so every large segment spent three attempts waiting for a bucket
        // to acquire a property it can only be created with. Rethrowing HERE also keeps the stamp: the
        // exhaustion wrapper below builds a NEW Error and would drop it, taking the worm-refused down-reason
        // with it. Read as a strict boolean the initiate stamped from the store's own body, never as text.
        if (isObjectLockRefusalStamped(e)) throw e;
        const m = e instanceof Error ? e.message : String(e);
        if (!/status (5\d\d|429)/.test(m) && !/fetch failed|network|timed? ?out|connection/i.test(m)) throw e;
      }
    }
    throw new Error(`${label}: ${(lastErr as Error)?.message ?? String(lastErr)}`);
  }

  // signedRequest signs and sends one S3 request with an optional canonical query string,
  // refusing redirects the same way every other credentialed call here does. extra carries any
  // additional headers that must be BOTH signed and sent (e.g. the Object-Lock headers on a
  // multipart initiate); it defaults to none, so every existing caller is byte-unchanged.
  //
  // req.op is the closed destination op this request belongs to (G135), so a transport fault or a refused
  // redirect is attributed to the op that suffered it in the fault ring; req.label is the operator-facing
  // text the redirect error carries, unchanged. They ride in one named argument so the parameter count
  // stays inside the guardrail.
  private async signedRequest(method: string, key: string, query: string, body: Uint8Array | null, req: { label: string; op: DestOp }, extra?: Record<string, string>): Promise<Response> {
    const { label, op } = req;
    const u = new URL(this.url(key) + (query ? `?${query}` : ""));
    const amzDate = this.amzDate();
    const payloadHash = body === null ? await sha256Hex(new Uint8Array(0)) : await sha256Hex(body);
    const extraHeaders = extra ?? {};
    const headers: Record<string, string> = { host: u.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...extraHeaders, ...this.securityTokenHeader() };
    const auth = await signV4(method, u.pathname, query, headers, payloadHash, amzDate, this.creds);
    const resp = await this.metered(
      u,
      {
        method,
        headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, ...extraHeaders, Authorization: auth },
        ...(body !== null ? { body: ab(body) } : {}),
        redirect: "manual",
      },
      op,
    );
    if (resp.status >= 300 && resp.status < 400) {
      this.faults.noteResponse(op, resp, "");
      throw new Error(`${label}: unexpected redirect (status ${resp.status}); a destination endpoint must not redirect a credentialed request`);
    }
    return resp;
  }

  // multipartIO exposes the seam the s3-multipart-ops free functions need (signedRequest plus the two
  // creation-only header builders) without widening any of these to public. The arrows bind to this
  // instance, so the extracted ops sign, send and classify exactly as the former methods did.
  private get multipartIO(): MultipartIO {
    return {
      signedRequest: (method, key, query, body, req, extra) => this.signedRequest(method, key, query, body, req, extra),
      objectLockHeaders: () => this.objectLockHeaders(),
      storageClassHeader: () => this.storageClassHeader(),
      faults: this.faults,
      io: this.io,
    };
  }

  // readIO exposes the seam the s3-read-ops free functions need without widening any of these to public.
  // The arrows bind to this instance, so the extracted ops build, sign and send exactly as before.
  private get readIO(): ReadIO {
    return {
      url: (key) => this.url(key),
      amzDate: () => this.amzDate(),
      sha256Hex: (b) => sha256Hex(b),
      metered: (input, init, op) => this.metered(input, init, op),
      securityTokenHeader: () => this.securityTokenHeader(),
      signedRequest: (method, key, query, body, req, extra) => this.signedRequest(method, key, query, body, req, extra),
      creds: this.creds,
      faults: this.faults,
      io: this.io,
    };
  }

  // get fetches an object's bytes and ETag, or null if absent.
  //
  // A missing or empty ETag on a 200 response is treated as a hard error rather than a silent
  // default of "" (ENG-M14). The conditional-write guard in putConditional uses !== undefined,
  // so a caller that passes the empty string back as ifMatch would still send If-Match: "" to
  // the store (which returns a 412, triggering a retry). Throwing here instead is the cleaner
  // path: it surfaces a non-conformant store immediately on the read, before the caller constructs
  // the next write, so the RUNLOG retry loop never runs on a fabricated token and the problem is
  // visible rather than silently degraded into an unconditional overwrite. Any S3-compatible store
  // that serves a 200 GET without an ETag cannot satisfy the conditional-write contract and should
  // fail loudly at the earliest opportunity.
  // The read/probe ops (get/exists/delete/list/objectLockStatus) live in s3-read-ops.ts as free
  // functions over the readIO seam (this destination's URL/date/hash primitives, the metered fetch,
  // the STS header builder, signedRequest and the creds); these thin delegates keep the public method
  // surface identical. Behaviour is unchanged: every request is built, signed and classified as before.
  get(key: string): Promise<GetResult | null> {
    return get(this.readIO, key);
  }

  exists(key: string): Promise<boolean> {
    return exists(this.readIO, key);
  }

  // headStatus surfaces the raw HEAD status so the destination preflight can tell "absent" (404) from
  // "unauthorised" (403) / "unavailable" (5xx/429), instead of exists() collapsing all of them to a
  // false-green "verified". Read-only.
  headStatus(key: string): Promise<number> {
    return headStatus(this.readIO, key);
  }

  delete(key: string): Promise<void> {
    return del(this.readIO, key);
  }

  list(prefix: string): Promise<string[]> {
    return list(this.readIO, prefix);
  }

  // listPage streams the keyspace one native page at a time (the bounded-memory primitive the
  // off-site replication seg/ sync uses, M6); list() above accumulates the whole result and is for
  // small bounded scans only.
  listPage(prefix: string, cursor?: string): Promise<ListPage> {
    return listPage(this.readIO, prefix, cursor);
  }

  objectLockStatus(): Promise<WormStatus> {
    return objectLockStatus(this.readIO);
  }
}
