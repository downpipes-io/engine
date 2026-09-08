// Microsoft Entra ID (service principal) authentication for the Azure Blob destination.
//
// WHAT IT REPLACES. A Shared Key signature (dest/azure-sharedkey.ts) proves possession of the storage
// account's own key, which is the whole account with no expiry and no scope. An Entra service principal
// proves possession of an application's client secret to Microsoft's identity platform, gets back a
// short-lived bearer token, and is authorised on the data plane by an Azure RBAC ROLE ASSIGNMENT rather
// than by holding the account key. So the two schemes are not two spellings of one credential: under
// Entra there is no account key anywhere in the configuration, no request is signed, and the storage
// account can have its keys disabled entirely.
//
// THE FLOW is OAuth2 client credentials, and it is two hops rather than one:
//
//   POST https://<authority>/<tenant>/oauth2/v2.0/token
//     grant_type=client_credentials & client_id & client_secret & scope=<storage scope>
//   -> { access_token, expires_in }
//
//   then every storage request carries `Authorization: Bearer <access_token>` and `x-ms-version`,
//   and NOTHING is signed.
//
// SO THE TOKEN IS CACHED, and that is the point of this module rather than an incidental optimisation.
// A backup writes thousands of blobs. Minting one token per blob would put a login round trip in front
// of every write, and Microsoft rate-limits the token endpoint, so a large run would eventually be
// throttled at the identity plane where the destination pacer cannot see it. One token serves its whole
// lifetime, and the refresh happens on a MARGIN rather than on the exact second: a token fetched with
// 3599 seconds to live that is used at second 3599 is a token the storage account may already consider
// expired, because the two clocks are not the same clock. See AZURE_ENTRA_REFRESH_MARGIN_MS.
//
// THE CLIENT SECRET NEVER APPEARS IN A MESSAGE. Every error this module raises is assembled from a
// closed set of parts, none of which is the secret: the authority host, the tenant id, the application
// (client) id, the HTTP status, the OAuth2 `error` code, and the AADSTS number lifted out of the
// description by a digits-only pattern. The response BODY is never carried and never logged, on the same
// reasoning dest/azure-blob.ts refuses to carry an Azure error document: a message assembled from parts
// that cannot be a secret is provably safe, and one that merely tries not to include the secret is not.
//
// THE US GOVERNMENT AND CHINA CLOUDS ARE REFUSED RATHER THAN GUESSED. dest/provider.ts routes three Azure clouds to the
// Azure client, and each cloud has its OWN Entra login authority and its own storage OAuth scope. Only
// the commercial cloud's pair has been driven against a real account here. The other two are refused by
// name, with the reason, rather than filled in from memory: see AZURE_ENTRA_CLOUDS.

import { AZURE_STORAGE_SUFFIXES } from "./provider.ts";

/** The three values a service principal is: the directory it lives in, the application it is, and the
 *  secret that proves it. tenantId and clientId are NOT secret (they are identifiers, and they ride in
 *  error messages so a failure is diagnosable); clientSecret is credential-class and is handled exactly
 *  as a destination's secretAccessKey is, because on an Entra destination it IS the secretAccessKey. */
export interface AzureEntraCreds {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

/** One Azure cloud's Entra facts: where a token is asked for, and what to ask it for. */
export interface AzureEntraCloud {
  /** The Entra login authority host, without a scheme. */
  authorityHost: string;
  /** The OAuth2 scope that yields a token Azure Storage's data plane accepts. */
  scope: string;
}

/**
 * AZURE_ENTRA_CLOUDS maps an Azure Storage endpoint suffix to that cloud's Entra facts, and it is
 * DELIBERATELY INCOMPLETE.
 *
 * dest/provider.ts admits three storage suffixes. Only one of them has an entry here:
 *
 *   core.windows.net        the commercial cloud. Both values below were driven against a real storage
 *                           account and a real service principal: the token endpoint
 *                           returned a bearer token for the storage scope, and the storage account
 *                           accepted that token on put, get, head, delete, block staging, block-list
 *                           commit, list and a conditional write.
 *
 *   core.usgovcloudapi.net  Azure US Government. NO ENTRY, on purpose.
 *   core.chinacloudapi.cn   Azure China (21Vianet). NO ENTRY, on purpose.
 *
 * WHY THE US GOVERNMENT AND CHINA CLOUDS ARE ABSENT RATHER THAN FILLED IN. Their login authority hosts differ from
 * the commercial one, and so, as far as anything can be established here, does the audience a storage
 * account in those clouds will accept. Nobody here holds a subscription in either cloud, so neither the
 * authority nor the scope could be confirmed against a real account. A WRONG SCOPE IS THE DANGEROUS ONE:
 * an authority that does not exist fails at DNS, which is legible, but a token minted for the wrong
 * AUDIENCE is a perfectly valid token that the storage account rejects with a bare 401 naming nothing,
 * and the operator is then sent to audit a service principal that was correct all along. Writing down a
 * remembered value would convert "downpipes does not support this yet" into "downpipes supports this and
 * it does not work". The cost of the absence is a named refusal at save time, which is a strictly better
 * failure, and a Shared Key on the same account still works in every cloud.
 *
 * Adding a cloud here is one line, and the thing that must come with it is a live round trip against an
 * account in that cloud, not a citation.
 */
export const AZURE_ENTRA_CLOUDS: Readonly<Record<string, AzureEntraCloud>> = {
  "core.windows.net": { authorityHost: "login.microsoftonline.com", scope: "https://storage.azure.com/.default" },
};

/** What azureEntraCloudFor decided: the cloud's facts, or an operator-facing reason it will not serve
 *  this endpoint. Two arms rather than a nullable, so a caller cannot lose the reason. */
export type AzureEntraCloudResolution = { ok: true; cloud: AzureEntraCloud } | { ok: false; reason: string };

/** azureStorageSuffixOf finds which Azure cloud an endpoint host belongs to, by matching the closed
 *  suffix list dest/provider.ts routes on. Returns "" for a host in no Azure cloud. The match is on a
 *  DOT-PREFIXED suffix, so "notcore.windows.net" cannot pass as the commercial cloud. */
function azureStorageSuffixOf(host: string): string {
  const h = host.trim().toLowerCase();
  return AZURE_STORAGE_SUFFIXES.find((s) => h.endsWith(`.${s}`)) ?? "";
}

/**
 * azureEntraCloudFor derives the Entra authority and storage scope from the ENDPOINT HOST, which is the
 * only place in a destination configuration that names the cloud. Deriving them rather than storing them
 * is what stops a US Government endpoint being pointed at the commercial login authority: there is no
 * field an operator could set inconsistently, because there is no field.
 *
 * @param endpointOrHost - the destination endpoint, as a full URL or a bare host.
 * @returns the cloud's Entra facts, or the reason this endpoint will not be served.
 */
export function azureEntraCloudFor(endpointOrHost: string): AzureEntraCloudResolution {
  const host = endpointOrHost
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
  const suffix = azureStorageSuffixOf(host);
  if (suffix === "") {
    return { ok: false, reason: "Microsoft Entra authentication is only offered on an Azure Blob Storage endpoint, and that endpoint is not one." };
  }
  const cloud = AZURE_ENTRA_CLOUDS[suffix];
  if (cloud === undefined) {
    return {
      ok: false,
      // Written to survive classifyProbeError's 200-character clip whole, the same constraint the
      // account-mismatch refusal in dest/factory.ts is written to.
      reason: `Microsoft Entra authentication is not offered on ${suffix} yet: the storage OAuth scope that cloud accepts has not been confirmed against a real account there, and guessing it would mint a token the account rejects without saying why. Use a storage account key on this destination instead.`,
    };
  }
  return { ok: true, cloud };
}

/**
 * AZURE_ENTRA_REFRESH_MARGIN_MS is how long BEFORE its stated expiry a cached token stops being used.
 *
 * Five minutes, which is what Microsoft's own client libraries use, and the reason is clock skew rather
 * than caution: `expires_in` is measured by Entra's clock and enforced by the storage account's, and a
 * request issued in the last seconds of a token's life can arrive after that other clock has passed it.
 * The failure is a 401 in the middle of a run that was working, which retry does not fix because the
 * cached token is still there. Refreshing early costs one extra token request per hour.
 */
export const AZURE_ENTRA_REFRESH_MARGIN_MS = 300_000;

/** How long a token request may take before it is abandoned. Shorter than the storage request bound
 *  (dest/azure-blob.ts, 120s) on purpose: the identity plane is a small JSON round trip, and a token
 *  request that has hung for half a minute is not going to answer. */
export const AZURE_ENTRA_TOKEN_TIMEOUT_MS = 30_000;

/** The closed vocabulary for WHY a token could not be acquired, so a caller can classify the failure
 *  without parsing the message. */
export type AzureEntraFailure = "http" | "malformed" | "timeout" | "network";

/** AzureEntraTokenError is the operator-facing token failure. Its message is assembled from parts that
 *  cannot be the client secret (see this module's header), and it carries the closed cause separately. */
export class AzureEntraTokenError extends Error {
  readonly entraFailure: AzureEntraFailure;
  constructor(failure: AzureEntraFailure, message: string) {
    super(message);
    this.name = "AzureEntraTokenError";
    this.entraFailure = failure;
  }
}

/** REMEDIES maps the OAuth2 `error` code Entra returns to the thing an operator can actually do about
 *  it. The codes are RFC 6749's closed set; anything outside it falls through to the general remedy, so
 *  a code this map has never seen still produces a sentence rather than a dangling colon. */
const REMEDIES: Readonly<Record<string, string>> = {
  invalid_client: "the application id or the client secret is wrong, or the secret has expired; re-enter the client secret from the app registration",
  unauthorized_client: "that application is not permitted the client-credentials grant in this directory",
  invalid_scope: "the storage scope was refused for this application",
  invalid_request: "the token request was rejected as malformed, which usually means the tenant id is not a tenant in this cloud",
};
const GENERAL_REMEDY = "check the tenant id, the application id and the client secret";

/** aadstsCodeOf lifts the AADSTS number out of an error description. Digits only, and the whole rest of
 *  the description is discarded: the number is the diagnosable part, and a bounded token drawn from a
 *  fixed pattern cannot smuggle a credential into a log the way a free-text field could. */
function aadstsCodeOf(body: string): string {
  return /AADSTS\d{4,7}/.exec(body)?.[0] ?? "";
}

/**
 * AzureEntraTokenSource acquires and CACHES one service principal's storage access token.
 *
 * One instance serves one destination for the life of the isolate that built it. It is deliberately not
 * a module-level cache: two destinations may hold two different service principals, and a shared cache
 * keyed on nothing would hand one account's token to the other.
 *
 * CONCURRENT CALLERS SHARE ONE REQUEST. A sliced seal issues many writes at once, and the first slice
 * after a refresh would otherwise fire one token request per in-flight write. The in-flight promise is
 * held so the second caller waits on the first request instead of starting another.
 */
export class AzureEntraTokenSource {
  private readonly creds: AzureEntraCreds;
  private readonly cloud: AzureEntraCloud;
  private readonly now: () => Date;
  private readonly fetchTimeoutMs: number;
  private cached: { token: string; refreshAtMs: number } | undefined;
  private inflight: Promise<string> | null = null;

  constructor(creds: AzureEntraCreds, cloud: AzureEntraCloud, opts?: { now?: () => Date; fetchTimeoutMs?: number }) {
    this.creds = creds;
    this.cloud = cloud;
    this.now = opts?.now ?? (() => new Date());
    this.fetchTimeoutMs = opts?.fetchTimeoutMs ?? AZURE_ENTRA_TOKEN_TIMEOUT_MS;
  }

  /**
   * bearer returns a token that is good NOW, minting one only when the cached token is absent or inside
   * its refresh margin.
   *
   * @returns the access token to put in an Authorization: Bearer header.
   * @throws AzureEntraTokenError when the token could not be acquired. The message never carries the
   *   client secret, and never carries the response body.
   */
  async bearer(): Promise<string> {
    const c = this.cached;
    if (c !== undefined && this.now().getTime() < c.refreshAtMs) return c.token;
    if (this.inflight !== null) return this.inflight;
    // The in-flight promise is cleared in a finally, so a FAILED request does not leave every later
    // caller awaiting a rejected promise for the life of the isolate.
    const p = this.acquire();
    this.inflight = p;
    try {
      return await p;
    } finally {
      this.inflight = null;
    }
  }

  /** acquire performs the client-credentials round trip and installs the result in the cache. */
  private async acquire(): Promise<string> {
    const url = `https://${this.cloud.authorityHost}/${encodeURIComponent(this.creds.tenantId)}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.creds.clientId,
      client_secret: this.creds.clientSecret,
      scope: this.cloud.scope,
    });
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, this.fetchTimeoutMs);
    let resp: Response;
    try {
      resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        redirect: "manual",
        signal: ctrl.signal,
      });
    } catch {
      // A hung identity plane and a refused one are different faults with different remedies, and the
      // bare AbortError names neither. The caught error is deliberately NOT bound and NOT echoed: it is
      // the one value in this function whose text this module did not compose.
      if (timedOut) throw new AzureEntraTokenError("timeout", `${this.who()}: the token endpoint did not answer within ${this.fetchTimeoutMs}ms`);
      throw new AzureEntraTokenError("network", `${this.who()}: the token endpoint could not be reached`);
    } finally {
      clearTimeout(timer);
    }
    // The body is read as TEXT and only two bounded things are ever taken out of it: the OAuth2 error
    // code on the failure arm, and the AADSTS number. Neither can be the client secret.
    const text = await resp.text();
    if (!resp.ok) {
      let code = "";
      try {
        const j = JSON.parse(text) as { error?: unknown };
        if (typeof j.error === "string" && /^[a-z_]{1,40}$/.test(j.error)) code = j.error;
      } catch {
        /* a non-JSON error body (a proxy's HTML, an empty 502) still produces a legible message below */
      }
      const aadsts = aadstsCodeOf(text);
      const remedy = REMEDIES[code] ?? GENERAL_REMEDY;
      throw new AzureEntraTokenError(
        "http",
        `${this.who()}: the token endpoint answered ${resp.status}${code === "" ? "" : ` ${code}`}${aadsts === "" ? "" : ` ${aadsts}`}; ${remedy}`,
      );
    }
    let token = "";
    let lifetimeSec = 0;
    try {
      const j = JSON.parse(text) as { access_token?: unknown; expires_in?: unknown };
      if (typeof j.access_token === "string") token = j.access_token;
      if (typeof j.expires_in === "number" && Number.isFinite(j.expires_in)) lifetimeSec = j.expires_in;
      else if (typeof j.expires_in === "string" && /^\d+$/.test(j.expires_in)) lifetimeSec = Number(j.expires_in);
    } catch {
      throw new AzureEntraTokenError("malformed", `${this.who()}: the token endpoint answered ${resp.status} with a body that is not JSON`);
    }
    if (token === "") throw new AzureEntraTokenError("malformed", `${this.who()}: the token endpoint answered ${resp.status} with no access_token`);
    if (lifetimeSec <= 0) throw new AzureEntraTokenError("malformed", `${this.who()}: the token endpoint answered ${resp.status} with no usable expires_in`);
    const lifetimeMs = lifetimeSec * 1000;
    // The margin is never more than HALF the lifetime. A five-minute margin on a token that lives four
    // minutes would put every token past its refresh point the instant it arrived, and this source would
    // then mint a fresh token per request, which is the exact behaviour the cache exists to prevent.
    const margin = Math.min(AZURE_ENTRA_REFRESH_MARGIN_MS, Math.floor(lifetimeMs / 2));
    this.cached = { token, refreshAtMs: this.now().getTime() + lifetimeMs - margin };
    return token;
  }

  /** who names the principal and the authority a failure belongs to. Every part is an identifier the
   *  operator typed or the endpoint implied; none of them is the secret. */
  private who(): string {
    return `Microsoft Entra token request for application ${this.creds.clientId} in tenant ${this.creds.tenantId} at ${this.cloud.authorityHost}`;
  }
}
