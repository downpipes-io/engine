// A read-only Cloudflare GraphQL Analytics client for COST SIZING: it answers "how big is this KV
// namespace / R2 bucket" from the account's storage analytics, so the cost estimate can size a source
// BEFORE the first backup runs, without reading a single value (analytics-first, by design). It runs in
// the customer's own account (no-custody is inherent) and reads only sizes and counts, never content.
//
// BEST-EFFORT BY CONTRACT: sizing is advisory, so every method returns null on any failure (a network
// fault, a missing analytics scope on the token, a GraphQL error, or an unexpected shape) rather than
// throwing. The caller (the sizing probe) degrades to "unavailable" and the estimate stays honest.
//
// VERIFY BEFORE RELYING: the GraphQL dataset and field names below are from Cloudflare's Analytics API
// and MUST be checked against the current schema; they are isolated as constants here and parsed
// defensively so a schema drift degrades to null rather than a wrong number.
//
// House rules: Australian English; precise claims; no vendor URLs in user copy (this is engine code, the
// API endpoint is a technical constant). noUncheckedIndexedAccess is satisfied by guarding indexed reads.

const CF_GRAPHQL = "https://api.cloudflare.com/client/v4/graphql";

// WINDOW_DAYS is how far back the storage sample looks: storage analytics report a daily figure, so the
// most recent day is the current size. One day back covers the boundary while analytics settle.
const WINDOW_DAYS = 1;

// CfSize is a source's measured size: stored bytes and the item count (KV keys, R2 objects).
export interface CfSize {
  bytes: number;
  count: number;
}

// CfAnalyticsFault is WHY a size could not be measured (G296). A bare null collapsed four different
// answers into one -- and the difference is the whole remediation: an auth/scope fault is a token the
// operator must widen (permanent, actionable), a schema drift is a Cloudflare-side dataset change the
// vendor must ship a fix for (permanent, and NOT the customer's fault), and a network fault is a blip that
// heals itself. Worse, an analytics response the engine could not read used to be indistinguishable from a
// source that genuinely holds nothing. A closed enum; the GraphQL error body is never retained.
export type CfAnalyticsFault = "auth-or-scope" | "schema-drift" | "network";

export interface CfAnalytics {
  // kvNamespaceSize returns a KV namespace's stored bytes and key count, or the closed fault class.
  kvNamespaceSize(accountId: string, namespaceId: string): Promise<CfSize | CfAnalyticsFault>;
  // r2BucketSize returns an R2 bucket's stored bytes (payload + metadata) and object count, or the fault class.
  r2BucketSize(accountId: string, bucketName: string): Promise<CfSize | CfAnalyticsFault>;
}

// isCfSize narrows a sizing answer to a MEASURED one. A fault class is a bare string, a size is an object,
// so the discriminator needs no tag field on the wire.
export function isCfSize(v: CfSize | CfAnalyticsFault): v is CfSize {
  return typeof v === "object";
}

// The queries. Compact, parameterised, and isolated so a schema change is a one-line edit. VERIFY the
// dataset and field names against the current Cloudflare Analytics GraphQL schema.
const KV_QUERY =
  "query KvSize($a:String!,$n:String!,$s:Date!,$u:Date!){viewer{accounts(filter:{accountTag:$a}){kvStorageAdaptiveGroups(limit:1,filter:{namespaceId:$n,date_geq:$s,date_leq:$u},orderBy:[date_DESC]){max{byteCount keyCount}}}}}";
const R2_QUERY =
  "query R2Size($a:String!,$b:String!,$s:Date!,$u:Date!){viewer{accounts(filter:{accountTag:$a}){r2StorageAdaptiveGroups(limit:1,filter:{bucketName:$b,date_geq:$s,date_leq:$u},orderBy:[date_DESC]){max{payloadSize metadataSize objectCount}}}}}";

// dateWindow returns the [since, until] ISO-date range (UTC) covering the last WINDOW_DAYS. The engine
// runtime allows the wall clock (unlike the pure browser cost-model); tests inject fetch, so the exact
// dates do not affect the fixtures.
function dateWindow(): { s: string; u: string } {
  const dayMs = 86_400_000;
  const now = Date.now();
  const u = new Date(now).toISOString().slice(0, 10);
  const s = new Date(now - WINDOW_DAYS * dayMs).toISOString().slice(0, 10);
  return { s, u };
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
}

// firstGroupMax pulls the single group's `max` object out of a GraphQL storage response, defensively:
// data.viewer.accounts[0].<dataset>[0].max. Returns null on any missing or wrong-shaped level.
function firstGroupMax(data: unknown, dataset: string): Record<string, unknown> | null {
  const accounts = (data as { viewer?: { accounts?: unknown } } | null)?.viewer?.accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) return null;
  const acct = accounts[0];
  if (acct === null || typeof acct !== "object") return null;
  const groups = (acct as Record<string, unknown>)[dataset];
  if (!Array.isArray(groups) || groups.length === 0) return null;
  const group = groups[0];
  if (group === null || typeof group !== "object") return null;
  const max = (group as Record<string, unknown>).max;
  return max !== null && typeof max === "object" ? (max as Record<string, unknown>) : null;
}

export function makeCfAnalytics(token: string, fetchImpl: typeof fetch = fetch): CfAnalytics {
  // query POSTs a GraphQL request and returns the `data` payload, or null on any failure (HTTP error,
  // GraphQL errors array, unparseable body). Single attempt: sizing is best-effort, not load-bearing.
  // query POSTs a GraphQL request and returns the `data` payload, or the CLOSED fault class (G296). It reads
  // the HTTP status and the GraphQL errors array ONLY to SELECT an enum member and RETURNS that member: the
  // error body -- which can quote an account tag, a namespace id or a bucket name -- is never retained, and
  // never leaves this function. Single attempt: sizing is best-effort, not load-bearing.
  async function query(q: string, variables: Record<string, unknown>): Promise<unknown | CfAnalyticsFault> {
    try {
      const resp = await fetchImpl(CF_GRAPHQL, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ query: q, variables }),
      });
      // A 401/403 is a token the operator must widen: permanent, actionable, and the commonest cause of an
      // estate that sizes to nothing. Any other non-2xx is treated as a transient Cloudflare-side fault.
      if (resp.status === 401 || resp.status === 403) return "auth-or-scope";
      if (!resp.ok) return "network";
      const b = (await resp.json().catch(() => null)) as { data?: unknown; errors?: unknown } | null;
      // An unparseable body, or a GraphQL errors array, means the DATASET the engine asks for no longer
      // answers as it did: a schema drift on Cloudflare's side, which no customer action can fix and which
      // must never be reported to them as "your source is empty".
      if (b === null || (Array.isArray(b.errors) && b.errors.length > 0)) return "schema-drift";
      return b.data ?? "schema-drift";
    } catch {
      return "network";
    }
  }

  // sized narrows the query result: a fault class rides straight out; a data payload whose expected group is
  // missing or wrong-shaped is itself a SCHEMA DRIFT, not an empty source -- the distinction G296 exists for.
  function sized(data: unknown, dataset: string): Record<string, unknown> | CfAnalyticsFault {
    if (data === "auth-or-scope" || data === "network" || data === "schema-drift") return data;
    const max = firstGroupMax(data, dataset);
    return max === null ? "schema-drift" : max;
  }

  return {
    async kvNamespaceSize(accountId, namespaceId) {
      const { s, u } = dateWindow();
      const max = sized(await query(KV_QUERY, { a: accountId, n: namespaceId, s, u }), "kvStorageAdaptiveGroups");
      if (typeof max === "string") return max;
      return { bytes: num(max.byteCount), count: num(max.keyCount) };
    },
    async r2BucketSize(accountId, bucketName) {
      const { s, u } = dateWindow();
      const max = sized(await query(R2_QUERY, { a: accountId, b: bucketName, s, u }), "r2StorageAdaptiveGroups");
      if (typeof max === "string") return max;
      return { bytes: num(max.payloadSize) + num(max.metadataSize), count: num(max.objectCount) };
    },
  };
}
