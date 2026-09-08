// The Azure Blob Storage destination.
//
// AZURE IS NOT AN S3-COMPATIBLE STORE, and that is the whole reason this file exists rather than a
// twenty-line configuration of the S3 client the way Google Cloud Storage needed. R2 and GCS are both
// reached over the S3 XML API with SigV4, so they share s3.ts verbatim. Azure Blob has its own wire
// protocol, its own authentication scheme, its own object model and its own listing document: pointing
// the S3-compatible destination at a real Azure endpoint answers 403 AuthenticationFailed on the first
// call, and no configuration makes that work.
//
// WHAT MAPS CLEANLY, and it is most of it. Azure's block blob is a close enough analogue of an S3 object
// that every method on the Destination interface has an honest implementation:
//
//   get              GET the blob
//   put              PUT Blob with x-ms-blob-type: BlockBlob, single shot
//   putStream        Put Block per chunk, then Put Block List, for a body too large to buffer
//   putConditional   If-Match / If-None-Match, which Azure implements with the same semantics
//   exists           HEAD the blob
//   delete           DELETE the blob, and a 404 is a no-op success, as the interface requires
//   list / listPage  List Blobs, paged by NextMarker rather than a continuation token
//
// WHAT DOES NOT MAP, and is refused rather than approximated:
//
//   IMMUTABILITY is not refused as unmappable: governance is an UNLOCKED policy and compliance is a
//   LOCKED one, and the mode is a header we choose per write rather than something we have to infer. See
//   dest/azure-worm.ts for the correspondence.
//
//   STORAGE CLASS. Azure's access tiers (Hot, Cool, Cold, Archive) are not Amazon's class names, and this
//   codebase does no translation between the two vocabularies. Refused, for the same reason GCS's are.
//
//   ASSUMEROLE. An AWS mechanism with no Azure equivalent.
//
// BACKPRESSURE IS SHARED MACHINERY OVER AN AZURE-SPECIFIC SIGNAL. This client holds the same DestPacer and
// the same DestIo the S3 client holds, because the adaptive-rate behaviour and the degradation vocabulary
// are not provider-specific. What IS provider-specific is what counts as the store pushing back, and that
// is the one place a blind copy of the S3 table would have been wrong: Azure answers 503 ServerBusy where
// S3 answers 503 SlowDown, but it ALSO answers 500 OperationTimedOut for the same congestion, and it does
// not use 429 for Blob at all. azurePacerStatus below is the whole of that mapping, and it says of each arm
// whether it is Azure's own or shared.
//
// THE CREDENTIAL. Azure offers three kinds and they are not interchangeable. A Shared Key is the whole
// storage account with no expiry, and is signed here (azure-sharedkey.ts). A SAS token is scoped and
// time-limited and needs no signing by us at all: it is a query string appended to the request URL with
// the Authorization header omitted entirely (azure-sas.ts). An Entra service principal is scoped by an
// Azure RBAC role assignment and refreshable, signs nothing, and carries a bearer token instead, which
// lets the storage account have its keys disabled altogether (azure-entra.ts).
//
// THE CREDENTIAL IS APPLIED IN EXACTLY ONE PLACE, the private authorise() below, which send() calls for
// every outbound request. That is the whole of the difference between the three schemes as far as this
// file is concerned: everything else here (the block staging, the paging, the pacer mapping, the
// degradation counters, the immutability headers) is credential-agnostic and must stay that way, or a
// fourth credential kind becomes a fourth copy of the client.

import type { Meter } from "../meter.ts";
import { DestBuildError } from "./build-health.ts";
import type { AzureEntraTokenSource } from "./azure-entra.ts";
import { type AzureSasCreds, mergeSasQuery, parseAzureSasToken } from "./azure-sas.ts";
import { AZURE_API_VERSION, type AzureSharedKeyCreds, signAzureSharedKey } from "./azure-sharedkey.ts";
import { AZURE_IMMUTABILITY_UNSUPPORTED_HINT, AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER, azureImmutabilityHeaders, stampAzureImmutabilityRefusal, versionLevelImmutabilityStatus } from "./azure-worm.ts";
import { DestIo } from "./dest-io.ts";
import type { DestPacer } from "./pace.ts";
import type { Destination, DestIoSnapshot, GetResult, ListPage, PutConditionalResult, WormPolicy, WormStatus } from "./types.ts";

/** The largest body this destination will PUT in one request. Azure's own single-shot Put Blob limit is
 *  larger, but a block-staged write above this size keeps one request's memory bounded and matches the
 *  shape the S3 destination already uses for the same reason. */
export const AZURE_BLOCK_SIZE = 8 * 1024 * 1024;

/** How long one request may take before it is abandoned. Matches the S3 destination's own generous
 *  production bound rather than a short fuse. */
export const AZURE_FETCH_TIMEOUT_MS = 120_000;

/** azureBlobError builds the operator-facing failure for a store request that ANSWERED with a status we
 *  cannot use. The key rides (an operator needs to know which object), the body does NOT: an Azure error
 *  document can echo request metadata, and this message reaches logs and the support pack.
 *
 *  lockArmed says whether the failed request carried the immutability headers. It does two things and both
 *  exist because a lock refusal is otherwise undiagnosable: it appends the fixed hint naming the AZURE
 *  account setting that has to be on (a failure whose whole cause is outside downpipes reads as a downpipes
 *  defect without it), and it stamps the shared Object-Lock-refusal boolean so the fault classifies on the
 *  same rail an S3 lock refusal does rather than as a generic permanent error. The message SHAPE is
 *  unchanged up to the hint, so every existing "status NNN" reader still finds what it reads. */
function azureBlobError(verb: string, key: string, status: number, code: string, lockArmed = false): Error {
  const base = `${verb} ${key}: status ${status}${code === "" ? "" : ` (${code})`}`;
  return stampAzureImmutabilityRefusal(new Error(lockArmed ? `${base}.${AZURE_IMMUTABILITY_UNSUPPORTED_HINT}` : base), code, lockArmed);
}

/** azureErrorCode pulls Azure's own closed error code out of a response header, which is where Azure puts
 *  it. Reading the header rather than parsing the XML body means no byte of the body is ever carried. */
function azureErrorCode(resp: Response): string {
  return resp.headers.get("x-ms-error-code") ?? "";
}

/**
 * azurePacerStatus maps ONE Azure response onto the status the shared backpressure machinery reads, and it
 * exists because AZURE DOES NOT SIGNAL THROTTLING THE WAY S3 DOES. DestPacer.observe and DestIo.noteStatus
 * both treat 503 and 429 as the congestion signal, which is the S3 vocabulary; the mapping below is what
 * makes that honest for Azure rather than merely reused.
 *
 *   503 with ANY code       SHARED with S3, and correct for Azure on its own terms. Azure Blob answers 503
 *                           ServerBusy when the account's request rate, ingress or egress target is
 *                           exceeded, which is exactly the backpressure the pacer exists to back off from.
 *                           It is passed through unchanged, so the code is not read on this arm: a 503 for
 *                           any other reason is still the store saying it cannot serve this request now.
 *
 *   500 OperationTimedOut   AZURE'S OWN, and the reason this function exists at all. Azure pairs
 *                           OperationTimedOut with ServerBusy as its two throttling-shaped answers: the
 *                           operation could not be completed within the permitted time, which on a hot
 *                           partition is congestion wearing a 500. It is TRANSLATED to 503 so the pacer
 *                           halves and the degradation is counted. Without the translation an account
 *                           being throttled through this arm would be driven at full rate.
 *
 *   500 anything else       NOT translated. InternalError and its siblings are a server fault, not a
 *                           congestion signal, and clamping the rate on them would slow a backup for a
 *                           reason backing off cannot help. The code is what separates the two, so the
 *                           gate is on the code and not on the status.
 *
 *   429                     SHARED with S3, and INERT here as far as anything has been measured. Azure
 *                           Blob's documented throttling answer is 503, not 429. It is left in the shared
 *                           path rather than stripped out, because a 429 arriving from a proxy or a future
 *                           Azure surface means the same thing and backing off is the right response.
 *
 * Everything else passes through untouched, so a 2xx still recovers the rate additively and a 403 is still
 * neutral, exactly as on the S3 arm.
 *
 * @param status - the observed HTTP status.
 * @param code - the x-ms-error-code header, or "" when the response carried none.
 * @returns the status the pacer and the degradation counters should read.
 */
export function azurePacerStatus(status: number, code: string): number {
  if (status === 500 && code === "OperationTimedOut") return 503;
  return status;
}

/** Azure returns ETags quoted, the way HTTP specifies. The rest of this engine compares ETags as opaque
 *  strings, so they are passed through unchanged rather than unquoted here: unquoting in one destination
 *  and not another is how two stores stop agreeing about whether an object changed. */
function etagOf(resp: Response): string {
  return resp.headers.get("etag") ?? "";
}

/**
 * AzureBlobDestination writes sealed archive objects to one Azure Blob Storage container.
 *
 * Construction is fail-loud, the same discipline requireHttpsEndpoint applies to an S3 endpoint: an
 * endpoint that is not https, or that is not an Azure Blob host, throws a typed DestBuildError at
 * construction rather than producing a destination that fails on its first write.
 */
export class AzureBlobDestination implements Destination {
  private readonly origin: string;
  private readonly container: string;
  // creds is EXACTLY ONE of the three kinds, resolved ONCE at construction so no request path has to
  // re-decide it and no two of them can be armed at once. A Shared Key is signed here, a SAS is appended
  // to the URL with no Authorization header at all, and Entra carries a bearer token and signs nothing.
  private readonly creds: { kind: "shared-key"; sharedKey: AzureSharedKeyCreds } | { kind: "sas"; sas: AzureSasCreds } | { kind: "entra"; entra: AzureEntraTokenSource };
  // worm is the OPT-IN, DEFAULT-OFF immutability policy, held on the same terms S3Destination holds one.
  // When undefined (the default) every write is byte-identical to the pre-immutability path. When set,
  // every OBJECT-CREATING write carries Azure's two per-blob policy headers; see dest/azure-worm.ts for
  // the mode mapping and for which Azure operations accept them.
  private readonly worm: WormPolicy | undefined;
  private readonly now: () => Date;
  private readonly fetchTimeoutMs: number;
  private readonly meter: Meter | undefined;
  // pacer is the OPTIONAL adaptive destination throttle (T1-A), on the same terms the S3 client holds one:
  // when set, every outbound request takes a token before it is sent and reports its status back, so the
  // writer paces itself BELOW a store that is pushing back instead of hammering it. Absent (every in-memory
  // test double, and any caller that omits it) means no pacing at all, byte-identical to before. What is
  // Azure-specific is not the pacer, it is what counts as pushback: see azurePacerStatus above.
  private readonly pacer: DestPacer | undefined;
  // io is the bounded DEGRADATION counter set (G186), the same one S3Destination and R2Destination hold. It
  // records the branches a SUCCESSFUL run swallows, so a backup that finished green but took ten times as
  // long can be attributed afterwards. FOUR of the six closed counters can be reached from this client:
  // throttleObservations and timeouts at the send() chokepoint, conditionalPutConflicts at putConditional,
  // and headNon200CollapsedToAbsent at exists(). The other two cannot, and their absence is a fact about
  // this client rather than an omission: retryAttemptsTotal belongs to the S3 multipart step's own retry
  // loop, which has no Azure counterpart because a failed Put Block is re-issued by the caller's withRetry
  // and not here, and retryAfterUnparseable belongs to code that READS Retry-After, which this client does
  // not. Diagnostic only: noting never changes control flow.
  private readonly io = new DestIo();

  /**
   * @param endpoint - the account's blob endpoint, which must be https.
   * @param container - the container the archive lives in.
   * @param account - the storage account name, used by the Shared Key signature.
   * @param accountKeyBase64 - one of the account's access keys, as the portal shows it. Ignored, and
   *   allowed to be empty, when opts.sasToken is supplied.
   * @param opts.sasToken - a shared access signature the operator supplied, INSTEAD of the account key. It
   *   is validated and its expiry read at construction, so a token that is malformed or already dead fails
   *   loud here rather than as a 403 on the first backup.
   * @param opts.worm - the opt-in immutability policy. Absent means no immutability and a byte-unchanged
   *   write path.
   * @param opts.entra - a Microsoft Entra token source, INSTEAD of an account key or a SAS. Present means
   *   nothing is signed and every request carries a bearer token.
   */
  constructor(endpoint: string, container: string, account: string, accountKeyBase64: string, opts?: { now?: () => Date; fetchTimeoutMs?: number; meter?: Meter; pacer?: DestPacer; sasToken?: string; worm?: WormPolicy; entra?: AzureEntraTokenSource }) {
    let u: URL;
    try {
      u = new URL(endpoint);
    } catch {
      throw new DestBuildError("endpoint-unparseable", `the Azure endpoint is not a valid URL: ${JSON.stringify(endpoint)}`);
    }
    if (u.protocol !== "https:") {
      throw new DestBuildError("endpoint-not-https", `the Azure endpoint must use https (got ${JSON.stringify(u.protocol)}); a non-https endpoint would transmit the account key and the archive bytes in cleartext`);
    }
    this.origin = u.origin;
    this.container = container;
    this.now = opts?.now ?? (() => new Date());
    // The SAS is parsed with THIS destination's clock rather than the wall clock, so a caller that pins the
    // time (every test double, and the drill) gets a deterministic expiry verdict instead of one that turns
    // over at midnight.
    const sasToken = opts?.sasToken;
    // ONE ordered expression, so no two credential kinds can be armed at once and the precedence is
    // readable in one place: an Entra principal, else a SAS token, else the account key.
    this.creds =
      opts?.entra !== undefined
        ? { kind: "entra" as const, entra: opts.entra }
        : sasToken === undefined || sasToken.trim() === ""
          ? { kind: "shared-key" as const, sharedKey: { account, accountKeyBase64 } }
          : { kind: "sas" as const, sas: parseAzureSasToken(sasToken, this.now()) };
    // A destination with NO credential at all is refused here rather than on its first request. An Entra
    // destination genuinely has no account key and passes "", so without this guard a dropped token source
    // would fall through to the signer, which would HMAC with a zero-length key and answer 403
    // AuthenticationFailed on every call: a permission-shaped symptom for a wiring fault.
    if (this.creds.kind === "shared-key" && accountKeyBase64 === "") {
      throw new DestBuildError("config-incomplete", "the Azure destination has neither a storage account key, a SAS token, nor an Entra service principal");
    }

    this.worm = opts?.worm;
    this.fetchTimeoutMs = opts?.fetchTimeoutMs ?? AZURE_FETCH_TIMEOUT_MS;
    this.meter = opts?.meter;
    this.pacer = opts?.pacer;
  }

  /**
   * sasExpiry reports when this destination's credential dies of its own accord, for a surface that warns
   * before the day comes, or null when the credential is a Shared Key (which has no expiry: it is valid
   * until somebody rotates it).
   *
   * A SAS destination with `expiresAtMs: null` is one whose token carries no `se` parameter, which is
   * legal and means the expiry is not visible to us, NOT that the token never expires. A caller must not
   * collapse those two into "no warning needed".
   *
   * @returns the expiry reading, or null when this destination is not SAS-authenticated.
   */
  sasExpiry(): { expiresAtMs: number | null } | null {
    return this.creds.kind === "sas" ? { expiresAtMs: this.creds.sas.expiresAtMs } : null;
  }

  /**
   * immutabilityHeaders returns the per-blob policy headers for a write made NOW, or an empty object when
   * no policy is configured. Derived at each write rather than once at construction, because the
   * retain-until date is relative to the write instant: a destination built at midnight and still writing
   * at dawn must not stamp every object with midnight's window.
   */
  private immutabilityHeaders(): Record<string, string> {
    return azureImmutabilityHeaders(this.worm, this.now());
  }

  /**
   * authorise turns one request into the headers and query string to put on the wire, and it is the ONE
   * place the two credential kinds differ.
   *
   * SHARED KEY signs: the canonical string is built over the method, the standard fields, every x-ms-*
   * header and the canonicalised resource including its query, so the query the signature covers and the
   * query on the URL have to be the same one. Both come from `query` here.
   *
   * A SAS DOES NOT SIGN, AND MUST NOT SEND AN AUTHORIZATION HEADER. The signature is already inside the
   * token; a request carrying both a SAS and an Authorization header is refused by Azure rather than
   * treated as belt and braces. x-ms-version is still sent, because it is required on every authorised
   * request and governs the response shape this client parses. x-ms-date is NOT sent: it exists so a Shared
   * Key signature can be bound to an instant, and nothing signs it here.
   */
  private async authorise(method: string, path: string, query: Record<string, string> | undefined, headers: Record<string, string>, contentLength?: number): Promise<{ headers: Record<string, string>; qs: string }> {
    const qs = query === undefined ? "" : `?${new URLSearchParams(query).toString()}`;
    if (this.creds.kind === "sas") {
      return { headers: { ...headers, "x-ms-version": AZURE_API_VERSION }, qs: mergeSasQuery(query, this.creds.sas.query) };
    }
    if (this.creds.kind === "entra") {
      // ENTRA SIGNS NOTHING. It adds a bearer token plus the two x-ms-* headers the signer would otherwise
      // have added. x-ms-version is REQUIRED on the bearer path too, and its absence is a 400 naming the
      // version rather than the credential. x-ms-date is not required for a bearer request; it is sent
      // anyway so a request differs between the schemes in the Authorization header and nowhere else,
      // which is what makes a wire capture of an Entra request comparable to a Shared Key one.
      //
      // A token failure PROPAGATES rather than being folded into a store error: it is a fault of the
      // identity plane, and dressing it as a storage status would send the operator to audit the container.
      return { headers: { ...headers, "x-ms-version": AZURE_API_VERSION, "x-ms-date": this.now().toUTCString(), Authorization: `Bearer ${await this.creds.entra.bearer()}` }, qs };
    }
    const signed = await signAzureSharedKey({ method, path, ...(query === undefined ? {} : { query }), headers, ...(contentLength === undefined ? {} : { contentLength }) }, this.creds.sharedKey, this.now);
    return { headers: signed.headers, qs };
  }

  /** The resource path Azure signs and receives. Kept in ONE place because the signer and the request must
   *  agree exactly: a path that is encoded for the URL but signed raw authenticates nothing. */
  private blobPath(key: string): string {
    return `/${this.container}/${key}`;
  }


  // send is the ONE outbound chokepoint, so it is also where the slice budget is charged. Every caller
  // that hands buildDestination a Meter is a caller that must yield before the platform subrequest cap:
  // the sliced seal (seal/runstate-helpers.ts) and the 3-2-1 replication pass (seal/replicate.ts, which
  // walks a whole content-addressed keyspace a page at a time). An unmetered destination in that pass
  // spends the invocation's subrequests without ever moving the budget, so the pass does not yield and the
  // platform kills it, which is the repl-dest-unmetered fault the S3 client's own metered() exists to
  // prevent. The spend is UNTAGGED on purpose: CfOp names Cloudflare resource classes, and an Azure request
  // is not an R2 class-A or class-B operation. An untagged spend still counts toward the subrequest total
  // shouldYield() reads, which is the whole of what the budget needs, and it keeps the cost ledger's
  // per-resource split from claiming R2 operations that were never made.
  private async send(method: string, path: string, query: Record<string, string> | undefined, headers: Record<string, string>, body?: BodyInit, contentLength?: number): Promise<Response> {
    this.meter?.spend(1);
    const wire = await this.authorise(method, path, query, headers, contentLength);
    // The path is encoded for the wire here and signed raw in authorise, which is what Azure's own
    // canonicalised resource specifies: it is built from the DECODED path.
    const url = `${this.origin}${path.split("/").map(encodeURIComponent).join("/")}${wire.qs}`;
    // Pace BELOW the store's tolerance (T1-A), at the same point in the sequence the S3 client does it: the
    // token is taken AFTER the budget is charged and BEFORE the request goes out, so a clamped pacer widens
    // the spacing between requests without the meter losing count of them. Every method routes through
    // here, so the whole write path and the whole list path are paced.
    if (this.pacer) await this.pacer.take();
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, this.fetchTimeoutMs);
    try {
      const resp = await fetch(url, { method, headers: wire.headers, ...(body === undefined ? {} : { body }), redirect: "manual", signal: ctrl.signal });
      // Fold the response into the adaptive rate and the degradation record, through the Azure mapping
      // rather than through the raw status: a 500 OperationTimedOut IS this store's throttling signal and
      // would otherwise be read as neutral. Both readers are given the SAME mapped status, so the pacer
      // cannot clamp on a response the counter does not count, or the other way about.
      const paced = azurePacerStatus(resp.status, azureErrorCode(resp));
      this.pacer?.observe(paced);
      this.io.noteStatus(paced);
      if (this.pacer) this.io.noteEffectiveRate(this.pacer.effectiveRate());
      return resp;
    } catch (e) {
      // A BLACK-HOLED endpoint (aborted at the finite fetch bound) is a different fault from a refused one,
      // and the caller's retry can ride several of them out on a run that still reports success. Count it,
      // and rethrow a NAMED error: the bare AbortError this used to surface named neither the bound nor the
      // request, so a timed-out Azure write and a cancelled one read identically in a log.
      if (timedOut) {
        this.io.note("timeouts");
        throw new Error(`azure request timed out after ${this.fetchTimeoutMs}ms (${method} ${path})`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  async get(key: string): Promise<GetResult | null> {
    const resp = await this.send("GET", this.blobPath(key), undefined, {});
    if (resp.status === 404) return null;
    if (!resp.ok) throw azureBlobError("GET", key, resp.status, azureErrorCode(resp));
    return { body: new Uint8Array(await resp.arrayBuffer()), etag: etagOf(resp) };
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    // Put Blob is an object-creating write, so it carries the immutability headers when a policy is armed.
    // They are added to the SAME header record the signer reads, so a Shared Key signature covers them:
    // an x-ms-* header on the wire that the canonical string did not include is a 403 naming nothing.
    const lock = this.immutabilityHeaders();
    const armed = Object.keys(lock).length > 0;
    const resp = await this.send(
      "PUT",
      this.blobPath(key),
      undefined,
      { "x-ms-blob-type": "BlockBlob", "content-type": "application/octet-stream", ...lock },
      body as unknown as BodyInit,
      body.byteLength,
    );
    if (!resp.ok) throw azureBlobError("PUT", key, resp.status, azureErrorCode(resp), armed);
  }

  /**
   * putStream writes a body without buffering it whole, by staging it as blocks and then committing the
   * block list. A body that fits in one block is written as a single Put Blob instead, so the common small
   * object costs one request rather than two.
   *
   * BLOCK IDS ARE FIXED WIDTH AND BASE64, and both matter. Azure requires every block id in one blob to
   * decode to the same byte length, so a zero-padded counter is used rather than the counter itself: block
   * "10" and block "9" are different lengths and Azure rejects the commit with an error that names neither.
   *
   * THE IMMUTABILITY HEADERS GO ON THE COMMIT, NOT ON THE BLOCKS, and that is Azure's own division rather
   * than a choice. Put Block stages bytes and creates no blob; Put Block List is the operation that brings
   * the blob into existence, and it is the one that accepts a policy. Staging a block is not an
   * object-creating write, and sending policy headers on one would be sending them to an operation that
   * does not take them.
   */
  async putStream(key: string, body: ReadableStream<Uint8Array>, size?: number): Promise<void> {
    const reader = body.getReader();
    const blockIds: string[] = [];
    let buf = new Uint8Array(0);
    let index = 0;

    const stage = async (chunk: Uint8Array): Promise<void> => {
      const id = btoa(String(index).padStart(8, "0"));
      index += 1;
      const resp = await this.send(
        "PUT",
        this.blobPath(key),
        { comp: "block", blockid: id },
        { "content-type": "application/octet-stream" },
        chunk as unknown as BodyInit,
        chunk.byteLength,
      );
      if (!resp.ok) throw azureBlobError("PUT block", key, resp.status, azureErrorCode(resp));
      blockIds.push(id);
    };

    for (;;) {
      const { done, value } = await reader.read();
      if (value !== undefined && value.byteLength > 0) {
        const next = new Uint8Array(buf.byteLength + value.byteLength);
        next.set(buf, 0);
        next.set(value, buf.byteLength);
        buf = next;
        while (buf.byteLength >= AZURE_BLOCK_SIZE) {
          await stage(buf.subarray(0, AZURE_BLOCK_SIZE));
          buf = buf.subarray(AZURE_BLOCK_SIZE);
        }
      }
      if (done) break;
    }

    // A body that never filled one block, and staged nothing, is a single-shot Put Blob. This is the
    // common case for a small sealed segment and it must not cost a block-list commit.
    if (blockIds.length === 0) {
      await this.put(key, buf);
      return;
    }
    if (buf.byteLength > 0) await stage(buf);

    const xml = `<?xml version="1.0" encoding="utf-8"?><BlockList>${blockIds.map((b) => `<Latest>${b}</Latest>`).join("")}</BlockList>`;
    const bytes = new TextEncoder().encode(xml);
    const lock = this.immutabilityHeaders();
    const armed = Object.keys(lock).length > 0;
    const resp = await this.send(
      "PUT",
      this.blobPath(key),
      { comp: "blocklist" },
      { "content-type": "application/xml", ...lock },
      bytes as unknown as BodyInit,
      bytes.byteLength,
    );
    if (!resp.ok) throw azureBlobError("PUT blocklist", key, resp.status, azureErrorCode(resp), armed);
    void size;
  }

  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    // Object-creating, so it is locked too when a policy is armed: without this the RUNLOG, which is
    // written only through this path, would be the one archive object on the destination with no
    // immutability at all, and the run history is exactly what a ransomware event would rewrite.
    const lock = this.immutabilityHeaders();
    const armed = Object.keys(lock).length > 0;
    const headers: Record<string, string> = { "x-ms-blob-type": "BlockBlob", "content-type": "application/octet-stream", ...lock };
    if (opts.ifMatch !== undefined) headers["if-match"] = opts.ifMatch;
    if (opts.ifNoneMatch !== undefined) headers["if-none-match"] = opts.ifNoneMatch;
    const resp = await this.send("PUT", this.blobPath(key), undefined, headers, body as unknown as BodyInit, body.byteLength);
    // 412 is the precondition failing, which is a NORMAL answer meaning a concurrent write won, not an
    // error. 409 is Azure's BlobAlreadyExists, which an If-None-Match:* can also produce and means the
    // same thing to the caller. Neither is a fault, and BOTH are counted as a degradation (G186): one
    // conflict is routine, but a rising count on the RUNLOG is two engines fighting over one log, which is
    // invisible on the run that succeeded. Azure reaching this counter by TWO statuses where S3 reaches it
    // by one is the store's own difference, not a second meaning.
    if (resp.status === 412 || resp.status === 409) {
      this.io.note("conditionalPutConflicts");
      return { ok: false };
    }
    if (!resp.ok) throw azureBlobError("conditional PUT", key, resp.status, azureErrorCode(resp), armed);
    return { ok: true, etag: etagOf(resp) };
  }

  async exists(key: string): Promise<boolean> {
    const status = await this.headStatus(key);
    // THE dedup-defeating fault (G186), and it reaches Azure by the same route it reaches S3: a 403 (the
    // account key was rotated out from under the destination) or a 5xx (the store is wobbling) is collapsed
    // to "absent" here, so the caller RE-UPLOADS a blob the container already holds, every segment, every
    // night, on a run that still reports success. A 404 is a genuine absence and is not a degradation. The
    // collapse itself is deliberately unchanged: it is counted, not corrected.
    if (status !== 200 && status !== 404) this.io.note("headNon200CollapsedToAbsent");
    return status === 200;
  }

  async headStatus(key: string): Promise<number> {
    const resp = await this.send("HEAD", this.blobPath(key), undefined, {});
    return resp.status;
  }

  async delete(key: string): Promise<void> {
    const resp = await this.send("DELETE", this.blobPath(key), undefined, {});
    // A delete of an absent blob is a no-op success, so an interrupted retention prune is idempotent on
    // re-run. This is the interface's own contract, not an Azure quirk.
    if (resp.status === 404 || resp.ok) return;
    throw azureBlobError("DELETE", key, resp.status, azureErrorCode(resp));
  }

  async list(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.listPage(prefix, cursor);
      keys.push(...page.keys);
      cursor = page.cursor;
    } while (cursor !== undefined);
    return keys;
  }

  async listPage(prefix: string, cursor?: string): Promise<ListPage> {
    const query: Record<string, string> = { restype: "container", comp: "list", prefix };
    if (cursor !== undefined && cursor !== "") query.marker = cursor;
    const resp = await this.send("GET", `/${this.container}`, query, {});
    if (!resp.ok) throw azureBlobError("LIST", prefix, resp.status, azureErrorCode(resp));
    const xml = await resp.text();
    // Regex rather than an XML parser, matching the object-lock probe's own approach in s3-worm.ts: the
    // List Blobs document is a fixed shape and this reads two elements out of it. A <Name> that carries
    // XML entities is decoded, because a key with an ampersand in it is legal and would otherwise be
    // returned in a form no later request could address.
    const keys = [...xml.matchAll(/<Name>([\s\S]*?)<\/Name>/g)].map((m) => decodeXmlText(m[1] ?? ""));
    const next = /<NextMarker>([\s\S]*?)<\/NextMarker>/.exec(xml)?.[1] ?? "";
    return next === "" ? { keys } : { keys, cursor: next };
  }

  /**
   * objectLockStatus is the WORM capability probe: it ASKS THE STORE whether this container can enforce a
   * per-blob immutability policy, and reports the answer.
   *
   * THE ANSWER MUST REFLECT WHAT THE WRITE PATH ACTUALLY ARMS. The question WormStatus asks is whether
   * this container enforces the policies we write, so a stale or hardcoded answer here would report "no
   * immutability here" about a container that is in fact enforcing it, on the very destinations a
   * compliance customer bought it for.
   *
   * THE PROBE IS ONE CREDENTIALED GET. Get Container Properties (a container-root GET with
   * restype=container) answers with x-ms-immutable-storage-with-versioning-enabled, which is exactly this
   * question for exactly this container. It is scoped no wider than the container, so it works with a
   * container-scoped SAS as well as with an account key, and it costs one request in the same place the S3
   * arm spends one on GetObjectLockConfiguration.
   *
   * WHAT EACH ANSWER MEANS, and in particular why an ABSENT header is a definite `false` rather than an
   * "unknown" the router would wave through, is argued in full at versionLevelImmutabilityStatus
   * (dest/azure-worm.ts). The short of it: an accepted "unknown" here yields a destination that reports
   * itself verified and then has every backup write refused, because the save-time probe deliberately runs
   * with the policy disarmed.
   *
   * It never throws. A transport fault degrades to the cannot-confirm reading, exactly as the S3 probe
   * does, because a probe failure must never block a backup.
   */
  async objectLockStatus(): Promise<WormStatus> {
    try {
      const resp = await this.send("GET", `/${this.container}`, { restype: "container" }, {});
      return versionLevelImmutabilityStatus(resp.status, resp.headers.get(AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER));
    } catch {
      // The probe never got an answer (DNS, TLS, a reset, or the fetch bound). That is the SELF-HEALING
      // cause and it must not read like a permanent one, or a compliance customer chases a configuration
      // change for a passing blip.
      return { enabled: "unknown", unknownReason: "network" };
    }
  }

  // destIo is the bounded DEGRADATION snapshot of this instance (G186), implementing the optional
  // Destination.destIo accessor exactly as S3Destination and R2Destination do, so the seal driver's
  // run-fault report reads an Azure destination through the same call and an Azure backup that was
  // throttled, black-holed or driven into re-uploading its whole archive stops being indistinguishable
  // from a healthy one in the support pack. Clamped integers only; no key, status string or endpoint.
  destIo(): DestIoSnapshot {
    return this.io.snapshot();
  }
}

/** decodeXmlText undoes the five XML entities Azure escapes a blob name with. Named and complete rather
 *  than a two-case approximation: a key that round-trips wrong is a key the prune cannot delete. */
function decodeXmlText(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}
