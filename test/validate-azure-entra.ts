// Microsoft Entra ID (service principal) authentication for the Azure Blob destination, driven against an
// in-memory identity plane AND an in-memory Azure.
//
// WHY BOTH DOUBLES. Entra authentication is TWO round trips to two different services, and the interesting
// behaviour is in the seam between them: a token is fetched from one and spent at the other, and the whole
// point of the module under test is that the first call happens far less often than the second. A test with
// only a storage double could not see the token endpoint at all, and a test with only a token double could
// not see the header the token ends up in. Both are here, told apart by host inside one fetch stand-in, and
// EVERY request to either is recorded, so an assertion can grade the wire rather than the outcome.
//
// This file exists so that the client's behaviour stays re-runnable by anyone with no credential, no
// subscription and no third party.
//
// Run: node test/validate-azure-entra.ts

import { AzureBlobDestination } from "../src/dest/azure-blob.ts";
import { AZURE_ENTRA_REFRESH_MARGIN_MS, azureEntraCloudFor, AzureEntraTokenError, AzureEntraTokenSource } from "../src/dest/azure-entra.ts";
import { AZURE_API_VERSION } from "../src/dest/azure-sharedkey.ts";
import { DestBuildError } from "../src/dest/build-health.ts";
import { azureEntraDirectoryRejection, buildDestination, fetchDestConfig, validateAzureEntraDirectory } from "../src/dest/factory.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

const ACCOUNT = "acct";
const ENDPOINT = `https://${ACCOUNT}.blob.core.windows.net`;
const CONTAINER = "archive";
const TENANT = "98d21390-5d4f-488d-8fef-cb5b4defe180";
const CLIENT = "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57";
// The one value in this file that must never turn up anywhere else. It is a distinctive literal so a
// substring search over an error message is a real check and not a check that happens to pass.
const SECRET = "CANARY~entra~client~secret~DO~NOT~LEAK~9f3d";
const CREDS = { tenantId: TENANT, clientId: CLIENT, clientSecret: SECRET };
const COMMERCIAL = { authorityHost: "login.microsoftonline.com", scope: "https://storage.azure.com/.default" };

/** An in-memory Microsoft identity platform and an in-memory Azure Blob service behind ONE fetch, told
 *  apart by host. Every request to either is recorded whole, INCLUDING the token request's form body, so a
 *  test can assert what the client sent and not only what it did with the answer. */
class MockCloud {
  tokenRequests: { tenantPath: string; form: Record<string, string> }[] = [];
  storageRequests: { method: string; path: string; headers: Record<string, string> }[] = [];
  blobs = new Map<string, { body: Uint8Array; etag: string }>();
  /** Each entry is one token the endpoint will issue, in order. A number is a lifetime in seconds with a
   *  generated token value; an object is an explicit failure to answer with. */
  script: ({ lifetimeSec: number } | { status: number; body: string } | { hang: true })[] = [];
  private issued = 0;
  private seq = 0;

  handler = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = String(v);

    if (url.hostname.endsWith("microsoftonline.com") || url.hostname.endsWith("microsoftonline.us") || url.hostname.endsWith("chinacloudapi.cn")) {
      const form: Record<string, string> = {};
      for (const [k, v] of new URLSearchParams(String(init?.body ?? ""))) form[k] = v;
      this.tokenRequests.push({ tenantPath: url.pathname, form });
      const next = this.script.shift() ?? { lifetimeSec: 3600 };
      if ("hang" in next) {
        // Never answers, but honours the abort so the client's own bound is what ends it.
        return new Promise<Response>((_resolve, reject) => {
          (init?.signal as AbortSignal | undefined)?.addEventListener("abort", () => reject(new Error("aborted")));
        });
      }
      if ("status" in next) return new Response(next.body, { status: next.status });
      this.issued += 1;
      return new Response(JSON.stringify({ token_type: "Bearer", access_token: `token-${this.issued}`, expires_in: next.lifetimeSec }), { status: 200 });
    }

    this.storageRequests.push({ method, path: decodeURIComponent(url.pathname), headers });
    // The storage double authenticates only in the sense that matters here: it insists on a bearer token
    // this identity plane actually issued. A client that sent a stale token, no token, or a Shared Key
    // signature gets the same 403 a real account would give it.
    if (!/^Bearer token-\d+$/.test(headers.authorization ?? "")) {
      return new Response("", { status: 403, headers: { "x-ms-error-code": "AuthenticationFailed" } });
    }
    const key = url.pathname.replace(/^\//, "").split("/").slice(1).map(decodeURIComponent).join("/");
    if (method === "PUT") {
      this.seq += 1;
      const etag = `"0x${this.seq.toString(16)}"`;
      this.blobs.set(key, { body: new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer()), etag });
      return new Response("", { status: 201, headers: { etag } });
    }
    const blob = this.blobs.get(key);
    if (method === "GET") {
      if (blob === undefined) return new Response("", { status: 404, headers: { "x-ms-error-code": "BlobNotFound" } });
      return new Response(blob.body as unknown as BodyInit, { status: 200, headers: { etag: blob.etag } });
    }
    if (method === "HEAD") return new Response("", { status: blob === undefined ? 404 : 200 });
    if (method === "DELETE") {
      this.blobs.delete(key);
      return new Response("", { status: 202 });
    }
    return new Response("", { status: 405 });
  };
}

function install(mock: MockCloud): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = mock.handler as unknown as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

/** A clock a test can advance. The token source reads it on every bearer() call, which is what makes the
 *  refresh margin observable without waiting an hour. */
function clock(startMs: number): { now: () => Date; advance: (ms: number) => void } {
  let t = startMs;
  return {
    now: () => new Date(t),
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** message returns the message of whatever an async call threw, or "" when it did not throw, so a missing
 *  throw is a visible failure rather than a silently skipped assertion. */
async function message(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "";
  } catch (e) {
    return (e as Error).message;
  }
}

// ---- the cloud table: derived from the host, and refused rather than guessed --------------------------

function cloudDerivation(): void {
  console.log("the login authority and the storage scope are derived from the endpoint host:");
  const commercial = azureEntraCloudFor(ENDPOINT);
  ok("a commercial Azure Blob host resolves to the commercial login authority", commercial.ok && commercial.cloud.authorityHost === "login.microsoftonline.com", JSON.stringify(commercial));
  ok("...and to the storage scope, which is what makes the token spendable at the data plane", commercial.ok && commercial.cloud.scope === "https://storage.azure.com/.default", JSON.stringify(commercial));
  ok("the host may arrive as a bare host rather than a URL", azureEntraCloudFor(`${ACCOUNT}.blob.core.windows.net`).ok);

  // THE SOVEREIGN CLOUDS. dest/provider.ts routes all three Azure clouds to the Azure client, so an
  // endpoint in either sovereign cloud reaches this resolution. The property being graded is NOT that
  // they are supported: it is that they resolve DIFFERENTLY from the commercial cloud, and that the
  // commercial authority is nowhere in the answer. A table that silently fell through to the commercial
  // entry would mint a token at the wrong identity plane, in the wrong sovereignty, for a tenant that does
  // not exist there, and the operator would be told their service principal was wrong.
  for (const [cloud, suffix] of [
    ["Azure US Government", "core.usgovcloudapi.net"],
    ["Azure China", "core.chinacloudapi.cn"],
  ] as const) {
    const r = azureEntraCloudFor(`https://${ACCOUNT}.blob.${suffix}`);
    ok(`${cloud} does NOT resolve to the commercial authority`, !(r.ok && r.cloud.authorityHost === "login.microsoftonline.com"), JSON.stringify(r));
    ok(`${cloud} is refused BY NAME, so the operator is told which cloud is not served`, !r.ok && r.reason.includes(suffix), JSON.stringify(r));
    ok(`${cloud}'s refusal never names the commercial authority`, !r.ok && !r.reason.includes("login.microsoftonline.com"), JSON.stringify(r));
    ok(`${cloud}'s refusal offers the remedy that does work there, a storage account key`, !r.ok && r.reason.includes("account key"), JSON.stringify(r));
  }

  const notAzure = azureEntraCloudFor("https://s3.ap-southeast-2.amazonaws.com");
  ok("a host that is in no Azure cloud is refused rather than given the commercial authority", !notAzure.ok);
  const lookalike = azureEntraCloudFor("https://acct.blob.core.windows.net.evil.example");
  ok("a look-alike host that merely CONTAINS an Azure suffix is refused", !lookalike.ok, JSON.stringify(lookalike));
}

// ---- the cache: one token, reused, refreshed on a margin ---------------------------------------------

async function tokenIsAcquiredOnceAndReused(): Promise<void> {
  console.log("a token is acquired once and REUSED, which is the whole reason this module caches:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    const c = clock(Date.parse("2026-08-25T00:00:00Z"));
    const source = new AzureEntraTokenSource(CREDS, COMMERCIAL, { now: c.now });
    const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { entra: source, now: c.now });
    for (let i = 0; i < 12; i++) await d.put(`seg/${i}`, new TextEncoder().encode("x"));
    ok("twelve writes cost ONE token request", mock.tokenRequests.length === 1, `tokenRequests=${mock.tokenRequests.length}`);
    ok("...and twelve storage requests, so nothing was skipped to get that number", mock.storageRequests.length === 12, `storageRequests=${mock.storageRequests.length}`);
    ok("the token request is a client-credentials grant", mock.tokenRequests[0]?.form.grant_type === "client_credentials", JSON.stringify(mock.tokenRequests[0]?.form.grant_type));
    ok("...for the storage scope", mock.tokenRequests[0]?.form.scope === "https://storage.azure.com/.default");
    ok("...at the TENANT's own token endpoint, not a multi-tenant one", mock.tokenRequests[0]?.tenantPath === `/${TENANT}/oauth2/v2.0/token`, mock.tokenRequests[0]?.tenantPath);
  } finally {
    restore();
  }
}

async function concurrentCallersShareOneRequest(): Promise<void> {
  console.log("concurrent first callers share ONE token request:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    const source = new AzureEntraTokenSource(CREDS, COMMERCIAL);
    const tokens = await Promise.all([source.bearer(), source.bearer(), source.bearer(), source.bearer()]);
    ok("four simultaneous first calls made ONE token request", mock.tokenRequests.length === 1, `tokenRequests=${mock.tokenRequests.length}`);
    ok("...and every caller got the same token", new Set(tokens).size === 1, JSON.stringify(tokens));
  } finally {
    restore();
  }
}

async function refreshHappensBeforeExpiry(): Promise<void> {
  console.log("the token refreshes BEFORE it expires, on a margin rather than on the second:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    const c = clock(Date.parse("2026-08-25T00:00:00Z"));
    const lifetimeMs = 3600_000;
    const source = new AzureEntraTokenSource(CREDS, COMMERCIAL, { now: c.now });
    const first = await source.bearer();
    ok("the first call mints a token", first === "token-1", first);

    // One millisecond BEFORE the refresh point: still the cached token. This is the control for the line
    // below, and without it "refreshes early" would also pass for a source that refreshed on every call.
    c.advance(lifetimeMs - AZURE_ENTRA_REFRESH_MARGIN_MS - 1);
    ok("inside the margin the cached token is reused", (await source.bearer()) === "token-1" && mock.tokenRequests.length === 1, `requests=${mock.tokenRequests.length}`);

    // Two milliseconds later, and still a FULL MARGIN short of the stated expiry: refreshed.
    c.advance(2);
    const second = await source.bearer();
    ok("crossing the refresh point mints a new token", second === "token-2" && mock.tokenRequests.length === 2, `${second} requests=${mock.tokenRequests.length}`);
    ok("...and that happened with the stated expiry still ahead, which is the point of the margin", c.now().getTime() < Date.parse("2026-08-25T00:00:00Z") + lifetimeMs);
  } finally {
    restore();
  }
}

async function marginNeverExceedsHalfTheLifetime(): Promise<void> {
  console.log("the margin is clamped to half the lifetime, so a short-lived token still caches:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    const c = clock(Date.parse("2026-08-25T00:00:00Z"));
    // A 60-second token against a 300-second margin. Unclamped, its refresh point would be 240 seconds in
    // the PAST at the instant it was issued, so every single request would mint a fresh token: the cache
    // would be inert and a run would be throttled at the identity plane.
    mock.script = [{ lifetimeSec: 60 }, { lifetimeSec: 60 }];
    const source = new AzureEntraTokenSource(CREDS, COMMERCIAL, { now: c.now });
    await source.bearer();
    c.advance(1000);
    ok("a 60-second token is still reused a second later", (await source.bearer()) === "token-1" && mock.tokenRequests.length === 1, `requests=${mock.tokenRequests.length}`);
    c.advance(29_500);
    ok("...and is refreshed once past half its life", (await source.bearer()) === "token-2", `requests=${mock.tokenRequests.length}`);
  } finally {
    restore();
  }
}

// ---- failure is legible, and never carries the secret ------------------------------------------------

async function failureIsLegible(): Promise<void> {
  console.log("a failed token request names what failed:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    // The body is the shape Entra actually returns for a wrong client secret, confirmed live on
    // against the real identity plane.
    mock.script = [{ status: 401, body: JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value." }) }];
    const source = new AzureEntraTokenSource(CREDS, COMMERCIAL);
    const msg = await message(() => source.bearer());
    ok("the message names the HTTP status", msg.includes("401"), msg);
    ok("...the OAuth2 error code", msg.includes("invalid_client"), msg);
    ok("...the AADSTS number, which is what a support search is done on", msg.includes("AADSTS7000215"), msg);
    ok("...the application id, so the operator knows WHICH principal failed", msg.includes(CLIENT), msg);
    ok("...the tenant, so a right secret in the wrong directory is diagnosable", msg.includes(TENANT), msg);
    ok("...and the remedy for THIS code, which is to re-enter the client secret", msg.includes("re-enter the client secret"), msg);
    ok("the free text of Entra's own description is NOT carried through", !msg.includes("Ensure the secret being sent"), msg);
  } finally {
    restore();
  }

  {
    const mock = new MockCloud();
    const r = install(mock);
    try {
      mock.script = [{ status: 502, body: "<html>gateway</html>" }];
      const msg = await message(() => new AzureEntraTokenSource(CREDS, COMMERCIAL).bearer());
      ok("a non-JSON error body still produces a legible message rather than a parse crash", msg.includes("502") && msg.includes("check the tenant id"), msg);
      ok("...and no byte of that body rides in it", !msg.includes("gateway"), msg);
    } finally {
      r();
    }
  }

  {
    const mock = new MockCloud();
    const r = install(mock);
    try {
      mock.script = [{ status: 200, body: JSON.stringify({ token_type: "Bearer", expires_in: 3600 }) }];
      const msg = await message(() => new AzureEntraTokenSource(CREDS, COMMERCIAL).bearer());
      ok("a 200 with no access_token is named as such, not treated as a token", msg.includes("no access_token"), msg);
    } finally {
      r();
    }
  }

  {
    const mock = new MockCloud();
    const r = install(mock);
    try {
      mock.script = [{ hang: true }];
      const source = new AzureEntraTokenSource(CREDS, COMMERCIAL, { fetchTimeoutMs: 25 });
      const msg = await message(() => source.bearer());
      ok("a token endpoint that never answers is abandoned at the bound, named", msg.includes("did not answer within 25ms"), msg);
    } finally {
      r();
    }
  }
}

async function failureCarriesAClosedCause(): Promise<void> {
  console.log("every failure carries the closed cause, so a caller can classify without parsing prose:");
  const cases: { script: MockCloud["script"]; cause: string; label: string }[] = [
    { script: [{ status: 401, body: '{"error":"invalid_client"}' }], cause: "http", label: "a refused credential is http" },
    { script: [{ status: 200, body: "not json at all" }], cause: "malformed", label: "an unparseable 200 is malformed" },
    { script: [{ hang: true }], cause: "timeout", label: "a hung endpoint is timeout" },
  ];
  for (const c of cases) {
    const mock = new MockCloud();
    const restore = install(mock);
    try {
      mock.script = c.script;
      const source = new AzureEntraTokenSource(CREDS, COMMERCIAL, { fetchTimeoutMs: 25 });
      let cause = "NOT-AN-AzureEntraTokenError";
      try {
        await source.bearer();
      } catch (e) {
        if (e instanceof AzureEntraTokenError) cause = e.entraFailure;
      }
      ok(c.label, cause === c.cause, cause);
    } finally {
      restore();
    }
  }
}

async function theSecretNeverAppears(): Promise<void> {
  console.log("the client secret never appears in an error, on ANY arm:");
  const arms: { script: MockCloud["script"]; label: string }[] = [
    // The dangerous one: an identity provider that echoes the submitted credential back in its own error
    // description. Nothing stops a provider (or a proxy in front of one) from doing this, so the module
    // must not carry the body even when the body is where the diagnosis would otherwise be.
    { script: [{ status: 401, body: JSON.stringify({ error: "invalid_client", error_description: `AADSTS7000215: the secret ${SECRET} is not valid` }) }], label: "an error description that ECHOES the secret back" },
    { script: [{ status: 400, body: `error=invalid_request&client_secret=${SECRET}` }], label: "a non-JSON error body carrying the secret" },
    { script: [{ status: 200, body: `{"junk":"${SECRET}"}` }], label: "a malformed success body carrying the secret" },
    { script: [{ hang: true }], label: "a timeout" },
  ];
  for (const arm of arms) {
    const mock = new MockCloud();
    const restore = install(mock);
    try {
      mock.script = arm.script;
      const source = new AzureEntraTokenSource(CREDS, COMMERCIAL, { fetchTimeoutMs: 25 });
      const msg = await message(() => source.bearer());
      ok(`${arm.label}: the message is non-empty`, msg !== "");
      ok(`${arm.label}: the secret is NOT in it`, !msg.includes(SECRET), msg);
    } finally {
      restore();
    }
  }

  // And the secret must not reach the STORE either, on any header of any request. It is spent at the
  // identity plane and nowhere else; what reaches Azure is the token it was exchanged for.
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { entra: new AzureEntraTokenSource(CREDS, COMMERCIAL) });
    await d.put("seg/0001", new TextEncoder().encode("x"));
    await d.get("seg/0001");
    await d.delete("seg/0001");
    const everyHeader = JSON.stringify(mock.storageRequests);
    ok("no storage request carries the client secret in any header", !everyHeader.includes(SECRET));
    ok("...and the token request is the ONLY place it was ever sent", mock.tokenRequests.every((r) => r.form.client_secret === SECRET) && mock.tokenRequests.length === 1);
  } finally {
    restore();
  }
}

// ---- the wire: bearer, not Shared Key ---------------------------------------------------------------

async function theWireIsBearerAndNothingIsSigned(): Promise<void> {
  console.log("under Entra every request carries a bearer token and NOTHING is signed:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { entra: new AzureEntraTokenSource(CREDS, COMMERCIAL) });
    await d.put("seg/0001", new TextEncoder().encode("downpipes entra"));
    const got = await d.get("seg/0001");
    ok("the round trip works: the object reads back byte-identical", got !== null && new TextDecoder().decode(got.body) === "downpipes entra");
    ok("exists is true for a written key", (await d.exists("seg/0001")) === true);
    for (const r of mock.storageRequests) {
      ok(`${r.method} ${r.path} carries Authorization: Bearer`, /^Bearer token-\d+$/.test(r.headers.authorization ?? ""), r.headers.authorization);
      ok(`${r.method} ${r.path} carries no SharedKey signature`, !(r.headers.authorization ?? "").includes("SharedKey"), r.headers.authorization);
      ok(`${r.method} ${r.path} carries x-ms-version, which a bearer request REQUIRES`, r.headers["x-ms-version"] === AZURE_API_VERSION, r.headers["x-ms-version"]);
    }
  } finally {
    restore();
  }
}

async function aTokenFailureIsNotDressedAsAStoreFailure(): Promise<void> {
  console.log("a token failure propagates out of the storage call rather than becoming a store status:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    mock.script = [{ status: 401, body: '{"error":"invalid_client","error_description":"AADSTS7000215: bad secret"}' }];
    const d = new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "", { entra: new AzureEntraTokenSource(CREDS, COMMERCIAL) });
    const msg = await message(() => d.put("seg/0001", new TextEncoder().encode("x")));
    ok("put rejects with the TOKEN failure, naming the identity plane", msg.includes("AADSTS7000215") && msg.includes("login.microsoftonline.com"), msg);
    ok("...not as a storage status, which would send the operator to audit the container", !msg.startsWith("PUT seg/0001:"), msg);
    ok("...and no storage request was made at all", mock.storageRequests.length === 0, String(mock.storageRequests.length));
  } finally {
    restore();
  }
}

function neitherCredentialIsRefusedAtConstruction(): void {
  console.log("a destination with neither credential is refused at construction:");
  let cause = "";
  try {
    new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "");
  } catch (e) {
    cause = e instanceof DestBuildError ? e.buildCause : "NOT-A-DestBuildError";
  }
  ok("no account key and no service principal is config-incomplete, not a 403 on the first write", cause === "config-incomplete", cause);
  // The control: a Shared Key destination is untouched by that guard.
  let built = false;
  try {
    new AzureBlobDestination(ENDPOINT, CONTAINER, ACCOUNT, "ZmFrZS1rZXk=");
    built = true;
  } catch {
    built = false;
  }
  ok("a Shared Key destination still builds, so the guard did not widen into the existing path", built);
}

// ---- the stored configuration ------------------------------------------------------------------------

function directoryValidation(): void {
  console.log("the stored service principal is bounded before it is used:");
  ok("a GUID tenant and a GUID application are accepted", validateAzureEntraDirectory({ tenantId: TENANT, clientId: CLIENT }) !== null);
  ok("a verified-domain tenant is accepted", validateAzureEntraDirectory({ tenantId: "contoso.onmicrosoft.com", clientId: CLIENT }) !== null);
  ok("both values are trimmed", validateAzureEntraDirectory({ tenantId: ` ${TENANT} `, clientId: ` ${CLIENT} ` })?.tenantId === TENANT);
  ok("a non-GUID application id is refused", validateAzureEntraDirectory({ tenantId: TENANT, clientId: "my-app" }) === null);
  ok("a missing application id is refused", validateAzureEntraDirectory({ tenantId: TENANT }) === null);
  ok("a missing tenant is refused", validateAzureEntraDirectory({ clientId: CLIENT }) === null);
  // The tenant is placed in the PATH of the token request URL, so a value that could carry a path segment
  // is refused rather than encoded and hoped for.
  ok("a tenant carrying a path segment is refused", validateAzureEntraDirectory({ tenantId: "contoso.com/evil", clientId: CLIENT }) === null);
  ok("a tenant carrying a dot-segment is refused", validateAzureEntraDirectory({ tenantId: "..", clientId: CLIENT }) === null);
  // THE MULTI-TENANT ALIASES. Measured by mutation: removing the alias check from
  // validateAzureEntraDirectory leaves these four assertions GREEN, because a bare "common" is also not a
  // GUID and not a dotted domain, so the tenant pattern already refuses it. The alias set is therefore
  // DEFENCE IN DEPTH in the validator and load-bearing only in the REJECTION message, which is graded
  // separately below (removing the alias sentence does turn that assertion red). Said here rather than
  // left as a quiet redundancy: an assertion that reads as though it grades one rule and actually grades
  // another is how a rule gets deleted years later with every test still green.
  for (const alias of ["common", "organizations", "consumers", "COMMON"]) {
    ok(`the multi-tenant alias "${alias}" is refused: a destination has to name one directory`, validateAzureEntraDirectory({ tenantId: alias, clientId: CLIENT }) === null);
  }

  ok("an absent value is not a rejection: no service principal was asked for", azureEntraDirectoryRejection(undefined) === null && azureEntraDirectoryRejection(null) === null);
  ok("a usable value is not a rejection", azureEntraDirectoryRejection({ tenantId: TENANT, clientId: CLIENT }) === null);
  const aliasReason = azureEntraDirectoryRejection({ tenantId: "common", clientId: CLIENT });
  ok('the "common" tenant gets its OWN sentence, because it is the wrong value that looks deliberate', (aliasReason ?? "").includes("ONE directory"), String(aliasReason));
  const generalReason = azureEntraDirectoryRejection({ tenantId: TENANT, clientId: "not-a-guid" });
  ok("a malformed principal is refused with the reason and where to find the right values", (generalReason ?? "").includes("app registration"), String(generalReason));
}

/** A scheduler-DO stand-in that answers /dest-config with one stored row. fetchDestConfig only ever
 *  fetches, so this is the whole of the surface it needs, and it lets the READ path be graded without a
 *  Durable Object. */
function storedDestStub(config: unknown): DurableObjectStub {
  return {
    fetch: async () => new Response(JSON.stringify({ config }), { status: 200, headers: { "content-type": "application/json" } }),
  } as unknown as DurableObjectStub;
}

async function theStoredPrincipalIsBoundedOnTheWayOut(): Promise<void> {
  console.log("the READ-for-use path bounds the stored service principal:");
  const base = { endpoint: ENDPOINT, bucket: CONTAINER, region: "auto", accessKeyId: ACCOUNT, secretAccessKey: SECRET };
  const good = await fetchDestConfig(storedDestStub({ ...base, azureEntra: { tenantId: TENANT, clientId: CLIENT } }));
  ok("a valid stored principal is read back", good?.azureEntra?.tenantId === TENANT && good.azureEntra.clientId === CLIENT, JSON.stringify(good?.azureEntra));
  // Fail-safe, exactly like a malformed worm or assumeRole policy: DROPPED, not passed through. A stored
  // principal that reached the token endpoint with a tenant of "common" or a path segment in it would put
  // a caller-shaped value into the URL of a credentialed request.
  for (const bad of [{ tenantId: "common", clientId: CLIENT }, { tenantId: TENANT, clientId: "not-a-guid" }, { tenantId: "contoso.com/evil", clientId: CLIENT }, "a string", 7, null]) {
    const r = await fetchDestConfig(storedDestStub({ ...base, azureEntra: bad }));
    ok(`a malformed stored principal (${JSON.stringify(bad)}) is DROPPED rather than trusted`, r?.azureEntra === undefined, JSON.stringify(r?.azureEntra));
  }
  const none = await fetchDestConfig(storedDestStub(base));
  ok("a destination with no principal reads back with none, so Shared Key is unchanged", none !== null && none.azureEntra === undefined);
}

// ---- the factory wiring ------------------------------------------------------------------------------

function env(partial: Record<string, unknown>): Env {
  return partial as unknown as Env;
}

async function theFactoryDispatchesToTheBearerPath(): Promise<void> {
  console.log("a stored destination carrying a service principal is BUILT onto the bearer path:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    // The stored shape: the storage account in accessKeyId, the CLIENT SECRET in secretAccessKey, and the
    // two non-secret ids in azureEntra. This is the whole of the configuration change.
    const dest = await buildDestination(env({}), undefined, {
      endpoint: ENDPOINT,
      bucket: CONTAINER,
      region: "auto",
      accessKeyId: ACCOUNT,
      secretAccessKey: SECRET,
      azureEntra: { tenantId: TENANT, clientId: CLIENT },
    });
    ok("the built destination is the Azure client", dest instanceof AzureBlobDestination);
    await dest.put("seg/0001", new TextEncoder().encode("x"));
    ok("it authenticated with a bearer token, so the factory passed the principal through", /^Bearer token-\d+$/.test(mock.storageRequests[0]?.headers.authorization ?? ""), mock.storageRequests[0]?.headers.authorization);
    ok("the stored secretAccessKey was spent as the CLIENT SECRET at the identity plane", mock.tokenRequests[0]?.form.client_secret === SECRET);
    ok("...and never as a storage account key, so nothing was signed", !JSON.stringify(mock.storageRequests).includes("SharedKey"));
  } finally {
    restore();
  }

  // The control: the same stored destination WITHOUT azureEntra still takes the Shared Key path.
  const mock2 = new MockCloud();
  const restore2 = install(mock2);
  try {
    const dest = await buildDestination(env({}), undefined, {
      endpoint: ENDPOINT,
      bucket: CONTAINER,
      region: "auto",
      accessKeyId: ACCOUNT,
      secretAccessKey: "ZmFrZS1rZXk=",
    });
    await dest.put("seg/0001", new TextEncoder().encode("x")).catch(() => undefined);
    ok("without a service principal the same config still signs with Shared Key", (mock2.storageRequests[0]?.headers.authorization ?? "").startsWith("SharedKey "), mock2.storageRequests[0]?.headers.authorization);
    ok("...and no token was ever requested", mock2.tokenRequests.length === 0, String(mock2.tokenRequests.length));
  } finally {
    restore2();
  }
}

async function theFactoryRefusesASovereignCloud(): Promise<void> {
  console.log("a service principal on a sovereign-cloud endpoint is refused at BUILD, loudly:");
  const mock = new MockCloud();
  const restore = install(mock);
  try {
    let cause = "";
    let msg = "";
    try {
      await buildDestination(env({}), undefined, {
        endpoint: "https://acct.blob.core.usgovcloudapi.net",
        bucket: CONTAINER,
        region: "auto",
        accessKeyId: ACCOUNT,
        secretAccessKey: SECRET,
        azureEntra: { tenantId: TENANT, clientId: CLIENT },
      });
    } catch (e) {
      cause = e instanceof DestBuildError ? e.buildCause : "NOT-A-DestBuildError";
      msg = (e as Error).message;
    }
    ok("the build fails as a typed config fault, so the standing health names it", cause === "config-incomplete", cause);
    ok("...naming the cloud that is not served", msg.includes("core.usgovcloudapi.net"), msg);
    ok("...and no token was requested at the commercial authority", mock.tokenRequests.length === 0, String(mock.tokenRequests.length));
    ok("the refusal never carries the client secret", !msg.includes(SECRET), msg);
    // The control: the SAME sovereign endpoint with a Shared Key still builds. Refusing Entra there must
    // not have refused the cloud.
    const sharedKey = await buildDestination(env({}), undefined, {
      endpoint: "https://acct.blob.core.usgovcloudapi.net",
      bucket: CONTAINER,
      region: "auto",
      accessKeyId: ACCOUNT,
      secretAccessKey: "ZmFrZS1rZXk=",
    });
    ok("a Shared Key destination in the same sovereign cloud still builds", sharedKey instanceof AzureBlobDestination);
  } finally {
    restore();
  }
}

console.log("azure entra (service principal) authentication\n");
cloudDerivation();
await tokenIsAcquiredOnceAndReused();
await concurrentCallersShareOneRequest();
await refreshHappensBeforeExpiry();
await marginNeverExceedsHalfTheLifetime();
await failureIsLegible();
await failureCarriesAClosedCause();
await theSecretNeverAppears();
await theWireIsBearerAndNothingIsSigned();
await aTokenFailureIsNotDressedAsAStoreFailure();
neitherCredentialIsRefusedAtConstruction();
directoryValidation();
await theStoredPrincipalIsBoundedOnTheWayOut();
await theFactoryDispatchesToTheBearerPath();
await theFactoryRefusesASovereignCloud();

console.log(failures === 0 ? "\nall azure entra checks passed" : `\n${failures} check(s) FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
