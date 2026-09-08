// SOURCE-DISCOVERY HEALTH: the closed vocabularies, the pure
// classifier, and the pure applier that is the single redaction chokepoint for the discovery aggregate.
//
// THE GAP. GET /sources/discover is the engine's answer to "what can this account back up?", and the console
// renders the whole Add-a-source form from it. It is FAIL-OPEN PER PRODUCT (router-sources-discovery.ts): a
// token missing the R2 scope degrades the R2 listing to a coarse error string and the route still answers 200
// with an EMPTY r2 array. The operator sees a form with no buckets in it. Nothing is recorded anywhere, so
// remotely there is no way to tell those three states apart:
//
//   - the account genuinely HAS no R2 buckets              (nothing to back up: correct, benign)
//   - the token cannot SEE them (a 403 scope gap)           (the customer never backs up their buckets)
//   - the listing was TRUNCATED at the page cap             (the buckets exist, past bucket 500 is invisible)
//
// The second and third are DATA LOSS by omission: the customer configures backups for the sources they were
// shown, believes the estate is covered, and the un-shown ones are never protected. "The setup form is empty"
// and "the account is empty" have to stop being the same observation.
//
// THIS IS A LEAF (it imports NOTHING), for the same reason diag-records.ts is: it is written by the Worker
// edge (admin/router-discovery.ts), folded by the DO (sched/scheduler-do-support-diag.ts) and projected into
// the pack (admin/support-sections-config.ts), so any non-leaf home would close an import cycle through the
// DO base.
//
// NO-CUSTODY (binding): every field here is a CLOSED ENUM, a COUNT, a CLAMPED INT or a BOOLEAN. The
// classifier READS a Cloudflare error string ONLY to SELECT an enum member and RETURNS that enum (the
// classifyCoarseError idiom): the text never passes through. No account id, no account name, no bucket, no
// namespace, no database, no secret name, no zone, no token and no endpoint can reach a record -- the router
// hands this module the classified OUTCOME, never the listing.

// ---------------------------------------------------------------------------------------------------------
// The closed vocabularies.
// ---------------------------------------------------------------------------------------------------------

// DISCOVERY_PRODUCTS are the listings one discover request performs. "accounts" is the account RESOLUTION
// itself (which precedes the per-account listings and, when it fails, empties the form completely); the rest
// are the per-account product listings the source picker is built from.
export const DISCOVERY_PRODUCTS = ["accounts", "kv", "r2", "d1", "secrets", "zones"] as const;
export type DiscoveryProduct = (typeof DISCOVERY_PRODUCTS)[number];
const DISCOVERY_PRODUCT_SET: ReadonlySet<string> = new Set(DISCOVERY_PRODUCTS);

// DISCOVERY_OUTCOMES is the closed per-product verdict of ONE listing. They are mutually exclusive, and the
// whole point of the gap is the distance between the first two:
//   ok           the listing succeeded and returned at least one resource
//   empty        the listing succeeded and the account genuinely holds none of this product (HONEST absence)
//   truncated    the listing succeeded and hit the page cap: resources exist that the form NEVER SHOWED
//   denied       401/403: the token lacks the scope. The form is empty and the customer is told nothing
//   rate-limited 429: Cloudflare throttled the discovery; the form is empty for a transient reason
//   not-found    404: the product surface answered "no such thing" for this account
//   unavailable  5xx: Cloudflare's own fault
//   http-other   any other non-2xx (including the refused redirect on a credentialed call)
//   transport    the fetch threw (DNS, TLS, abort): no status was ever seen
export const DISCOVERY_OUTCOMES = ["ok", "empty", "truncated", "denied", "rate-limited", "not-found", "unavailable", "http-other", "transport"] as const;
export type DiscoveryOutcome = (typeof DISCOVERY_OUTCOMES)[number];
const DISCOVERY_OUTCOME_SET: ReadonlySet<string> = new Set(DISCOVERY_OUTCOMES);

// DEGRADED_OUTCOMES are the verdicts that mean "the form you are looking at is NOT the account". "empty" is
// deliberately NOT one of them (an honestly empty account is not a fault), and "truncated" deliberately IS.
const DEGRADED_OUTCOMES: ReadonlySet<DiscoveryOutcome> = new Set(["truncated", "denied", "rate-limited", "not-found", "unavailable", "http-other", "transport"]);

// SEVERITY orders the outcomes so several accounts' verdicts for ONE product fold to the WORST one in the
// last-observation snapshot: a token that can read account A's buckets and not account B's is degraded, and
// the snapshot must say so rather than being overwritten by whichever account was listed last.
const SEVERITY: Readonly<Record<DiscoveryOutcome, number>> = {
  ok: 0,
  empty: 1,
  truncated: 2,
  "not-found": 3,
  "rate-limited": 4,
  unavailable: 5,
  "http-other": 6,
  transport: 7,
  denied: 8,
};

/**
 * worstDiscoveryOutcome folds two verdicts for the same product into the one a diagnosis must act on. Pure.
 *
 * @param a - one verdict.
 * @param b - the other.
 * @returns the more severe of the two.
 */
export function worstDiscoveryOutcome(a: DiscoveryOutcome, b: DiscoveryOutcome): DiscoveryOutcome {
  return SEVERITY[b] > SEVERITY[a] ? b : a;
}

// ---------------------------------------------------------------------------------------------------------
// The CLASSIFIER: text selects an enum member, and only the enum member is returned.
// ---------------------------------------------------------------------------------------------------------

// The engine's OWN literals. cfApi throws `HTTP <status>` (router-sources-discovery.ts) and each product
// helper prefixes its error with its own product token; resolveDiscoveryAccounts pushes ONE engine-authored
// sentence when a valid token can see no account at all. The classifier matches on THESE ONLY. Everything
// else -- a Cloudflare message body, a TypeError's text, a hostname -- is read, discarded, and coarsened to
// "transport": it never leaves this function.
const HTTP_MARK = /HTTP (\d{3})/;
const NO_ACCOUNTS_MARK = "cannot list any account";
// The product token each list helper prefixes its error with, mapped to the closed product enum. "secrets-store"
// is the helper's token; "secrets" is the vocabulary member.
const ERROR_PREFIX_TO_PRODUCT: Readonly<Record<string, DiscoveryProduct>> = {
  accounts: "accounts",
  kv: "kv",
  r2: "r2",
  d1: "d1",
  "secrets-store": "secrets",
  zones: "zones",
};

/**
 * classifyDiscoveryError coarsens ONE fail-open discovery error string into a closed { product, outcome }.
 * It reads the string ONLY to match the engine's own prefixes and the `HTTP <status>` literal, and RETURNS
 * the enums: no Cloudflare message, hostname, account id or token can pass through it.
 *
 * @param err - the error string the fail-open lister pushed (never recorded, only read).
 * @returns the closed product (null when the prefix is not one the engine writes) and the closed outcome.
 */
export function classifyDiscoveryError(err: unknown): { product: DiscoveryProduct | null; outcome: DiscoveryOutcome } {
  const s = typeof err === "string" ? err : "";
  const colon = s.indexOf(":");
  const prefix = colon > 0 ? s.slice(0, colon) : "";
  const product = ERROR_PREFIX_TO_PRODUCT[prefix] ?? null;
  if (s.includes(NO_ACCOUNTS_MARK)) return { product, outcome: "empty" };
  const m = HTTP_MARK.exec(s);
  if (m === null) return { product, outcome: "transport" };
  const status = Number(m[1]);
  if (status === 401 || status === 403) return { product, outcome: "denied" };
  if (status === 429) return { product, outcome: "rate-limited" };
  if (status === 404) return { product, outcome: "not-found" };
  if (status >= 500 && status <= 599) return { product, outcome: "unavailable" };
  return { product, outcome: "http-other" };
}

// ---------------------------------------------------------------------------------------------------------
// THE TOKEN-SET VERDICT (the most common onboarding failure, and the one the pack could not answer)
//
// "Verify and save always fails" is the single commonest onboarding ticket, and FIVE different faults wear
// that one sentence. The console cannot tell them apart: POST /sources/discovery-token answers a flat 400 for
// every one of them, so the browser's own row collapsed to {discovery-connect, sources, refused} and a typo'd
// token, a scope-less token, an expired token, a Cloudflare outage and a verify that never got an answer all
// COALESCED into it on the ring's tuple key. The gap's ticketScenario names the pair that matters verbatim:
// "support cannot remotely distinguish a scope gap from token-invalid".
//
// THE ENGINE OWNS THIS CLASS AND THE CONSOLE CANNOT. The engine is the side that made the Cloudflare call and
// SAW THE STATUS. The console sees a 400 and a sentence. So the class is decided here, where it is a FACT, and
// the console's row stays what it honestly is: the ATTEMPT half (and the only evidence of a verify request the
// engine never received at all).
//
// NO-CUSTODY: this classifier is the classifyDiscoveryError idiom exactly. It READS the engine's own
// `HTTP <status>` literal and its own no-accounts sentence to SELECT a member, and RETURNS the member. The
// Cloudflare message body, the token, the account ids and the endpoint are read, discarded, and cannot leave.
// ---------------------------------------------------------------------------------------------------------

// DISCOVERY_TOKEN_SET_FAIL_CLASSES is WHY a pasted discovery token was refused. The first two are the pair the
// whole gap turns on, and they have OPPOSITE remedies:
//
//   token-invalid       the token is not a usable credential: it failed the shape check before any call was
//                       made (a paste of the token NAME, or of an id), or Cloudflare answered 401. The remedy
//                       is "paste the token value itself" / "mint a new token".
//   scope-insufficient  the token AUTHENTICATED and Cloudflare refused the read (403), or it authenticated,
//                       listed cleanly and could see NO ACCOUNT AT ALL (a 200 with an empty result: the token
//                       is valid and its Account Settings read scope admits nothing). The token is fine and its
//                       PERMISSIONS are not. The remedy is "re-mint with Account Settings read", and telling
//                       this customer their token is invalid sends them round the same loop again.
//   cf-api-error        Cloudflare itself failed the verify (429, 5xx, or any other non-2xx). Nothing is wrong
//                       with the token or the operator. The remedy is "try again".
//   verify-timeout      the verify call never got an answer at all (DNS, TLS, an abort): no status was ever
//                       seen, so nothing can be concluded about the token. Distinct from cf-api-error, which is
//                       Cloudflare ANSWERING with a failure.
export const DISCOVERY_TOKEN_SET_FAIL_CLASSES = ["token-invalid", "scope-insufficient", "cf-api-error", "verify-timeout"] as const;
export type DiscoveryTokenSetFailClass = (typeof DISCOVERY_TOKEN_SET_FAIL_CLASSES)[number];
const DISCOVERY_TOKEN_SET_FAIL_CLASS_SET: ReadonlySet<string> = new Set(DISCOVERY_TOKEN_SET_FAIL_CLASSES);

export const DISCOVERY_TOKEN_SET_OUTCOMES = ["ok", "refused"] as const;
export type DiscoveryTokenSetOutcome = (typeof DISCOVERY_TOKEN_SET_OUTCOMES)[number];
const DISCOVERY_TOKEN_SET_OUTCOME_SET: ReadonlySet<string> = new Set(DISCOVERY_TOKEN_SET_OUTCOMES);

/** The last discovery-token SET attempt. Closed enums, a clamped count and a clamped instant. */
export interface DiscoveryTokenSet {
  readonly outcome: DiscoveryTokenSetOutcome;
  readonly failClass?: DiscoveryTokenSetFailClass; // absent on `ok`
  readonly accountsSeen: number; // how many accounts the token could list (0 on every refusal)
  readonly at: number; // epoch ms
}

export const DISCOVERY_TOKEN_SET_KEY = "diag:discoverytokenset";

/**
 * classifyTokenSetFailure coarsens the account-resolution errors of ONE refused token-set into a closed fail
 * class. PURE, total, and the single redaction chokepoint for the class: it reads the engine's own literals to
 * SELECT a member and returns it.
 *
 * The 401/403 split is the point of the whole function and it is why classifyDiscoveryError (which folds both
 * into `denied`) could not be reused: 401 is "this is not a valid credential" and 403 is "this credential is
 * valid and may not do that". They are the gap's headline pair, and their remedies are opposites.
 *
 * @param errors - the sentences resolveDiscoveryAccounts pushed (read, never recorded).
 * @param shapeRejected - the token failed validateDeployToken before any call was made.
 * @returns the closed fail class.
 */
export function classifyTokenSetFailure(errors: readonly unknown[], shapeRejected: boolean): DiscoveryTokenSetFailClass {
  // A shape rejection happens BEFORE any Cloudflare call, so there is no status to read and nothing to weigh.
  if (shapeRejected) return "token-invalid";
  const s = errors.map((e) => (typeof e === "string" ? e : "")).join("; ");
  // A token that AUTHENTICATED, listed cleanly and saw no account is a SCOPE gap, not a bad token. This is the
  // exact state the gap's "it said verified and then nothing showed" ticket is about, and the engine refuses it
  // with the same flat 400 as a typo.
  if (s.includes(NO_ACCOUNTS_MARK)) return "scope-insufficient";
  const m = HTTP_MARK.exec(s);
  // No status was ever seen: the fetch threw (DNS, TLS, an abort). Nothing can be concluded about the token.
  if (m === null) return "verify-timeout";
  const status = Number(m[1]);
  if (status === 403) return "scope-insufficient";
  if (status === 401) return "token-invalid";
  return "cf-api-error";
}

/**
 * applyDiscoveryTokenSet is the PURE, DO-side applier and the single redaction chokepoint for the token-set
 * record: it re-checks the outcome and the fail class against their frozen sets (an out-of-vocabulary value is
 * dropped, and a record whose outcome does not admit is not written at all), re-clamps the count, and reads
 * NOTHING else off the posted body. So a token, an account id or a Cloudflare sentence cannot enter the record
 * even if a future call site were to post one.
 *
 * @param obs - the posted observation (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record, or null when the posted outcome is not a vocabulary member.
 */
export function applyDiscoveryTokenSet(obs: unknown, now: number): DiscoveryTokenSet | null {
  const o = (obs ?? {}) as { outcome?: unknown; failClass?: unknown; accountsSeen?: unknown };
  if (typeof o.outcome !== "string" || !DISCOVERY_TOKEN_SET_OUTCOME_SET.has(o.outcome)) return null;
  const outcome = o.outcome as DiscoveryTokenSetOutcome;
  // A fail class rides ONLY on a refusal, and only when it is a frozen member. An `ok` carrying one is a
  // drifted call site, and the class is dropped rather than trusted.
  const failClass = outcome === "refused" && typeof o.failClass === "string" && DISCOVERY_TOKEN_SET_FAIL_CLASS_SET.has(o.failClass) ? (o.failClass as DiscoveryTokenSetFailClass) : undefined;
  return {
    outcome,
    ...(failClass !== undefined ? { failClass } : {}),
    accountsSeen: intClamp(o.accountsSeen, DISCOVERY_ACCOUNTS_CAP),
    at: intClamp(now, Number.MAX_SAFE_INTEGER),
  };
}

/**
 * classifyDiscoveryListing verdicts ONE successful product listing from its SHAPE alone (a count and the cap
 * it was bounded by), never its contents. This is the half that separates "the account holds no buckets"
 * from "the account holds more buckets than the form was allowed to show".
 *
 * @param count - how many resources the listing returned.
 * @param cap - the page cap the lister was bounded by.
 * @returns "empty", "truncated" or "ok".
 */
export function classifyDiscoveryListing(count: number, cap: number): DiscoveryOutcome {
  if (!Number.isFinite(count) || count <= 0) return "empty";
  return count >= cap ? "truncated" : "ok";
}

// ---------------------------------------------------------------------------------------------------------
// The OBSERVATION + the bounded DO record.
// ---------------------------------------------------------------------------------------------------------

/**
 * One discover request's outcome, built by the Worker edge (router-discovery.ts) AFTER it has classified every
 * listing. Every field is already a closed enum, a count or a boolean at the point it is constructed, so a
 * resource name structurally cannot be passed in.
 */
export interface DiscoveryObservation {
  // The per-product verdict, already folded to the WORST across the scanned accounts. A product the request
  // never attempted (there was no token, so no listing ran) is simply absent.
  readonly products: Partial<Record<DiscoveryProduct, DiscoveryOutcome>>;
  readonly tokenPresent: boolean; // a discovery token (console-set or the env fallback) was resolved at all
  readonly engineAccountKnown: boolean; // the engine could name its OWN account: false means no source can ever be ATTACHED
  readonly accountsScanned: number; // how many accounts this request listed
  readonly accountsCapped: boolean; // the scan hit MAX_DISCOVERY_ACCOUNTS: accounts exist that were NOT listed
  readonly boundSources: number; // how many backup-able bindings the engine itself holds (the env-binding tier)
  // THE PER-ACCOUNT DIMENSION. `products` above is folded to the WORST across every account, which means
  // "all ten accounts 403 on D1" and "one of ten accounts 403s on D1, the other nine list it fine" produce a
  // BYTE-IDENTICAL record: products.d1 = "denied", accountsScanned = 10, degradedObservations + 1. A total D1
  // blackout and a single membership-scoped account are opposite tickets ("my D1 databases never show up" versus
  // "half our accounts show no resources", which is the gap's own second clause) and the fold destroyed the
  // difference. These are COUNTS OF ACCOUNTS by verdict class, per product, computed BEFORE the fold. No account
  // id and no account name is here or can be: the router hands this module numbers.
  readonly accountsByProduct?: Partial<Record<DiscoveryProduct, DiscoveryAccountTally>>;
  // How many of the scanned accounts had AT LEAST ONE degraded product. The gap names this accountsWithErrors.
  readonly accountsDegraded?: number;
}

/**
 * DiscoveryAccountTally counts the scanned ACCOUNTS by what one product's listing did in each of them. The three
 * classes are exhaustive over the accounts that attempted the listing, and they are the three the diagnosis turns
 * on: `withData` proves the token CAN read that product somewhere (so an empty peer is not a blackout), `empty`
 * is the honest nothing-here, and `degraded` is the account the customer is not seeing.
 */
export interface DiscoveryAccountTally {
  readonly withData: number;
  readonly empty: number;
  readonly degraded: number;
}

/**
 * The standing discovery-health record. The SNAPSHOT half says what the setup form looks like right now; the
 * CUMULATIVE half says how long it has looked that way.
 */
export interface DiscoveryHealth {
  // ---- the last observation ----
  readonly lastOutcome: Record<string, DiscoveryOutcome>; // closed product -> its worst verdict on the last discover
  readonly tokenPresent: boolean;
  readonly engineAccountKnown: boolean;
  readonly accountsScanned: number;
  readonly accountsCapped: boolean;
  readonly boundSources: number;
  readonly accountsByProduct?: Partial<Record<DiscoveryProduct, DiscoveryAccountTally>>; // G286: see DiscoveryObservation
  readonly accountsDegraded?: number; // G286: accounts with at least one degraded product on the last scan
  // ---- the cumulative counters ----
  readonly totals: Record<string, Record<string, number>>; // closed product -> closed outcome -> count
  readonly observations: number; // discover requests recorded
  readonly degradedObservations: number; // requests in which AT LEAST ONE product was degraded (not ok/empty)
  readonly emptyObservations: number; // requests in which every attempted listing was cleanly EMPTY: the "the account is empty" claim, and the one this record exists to qualify
  readonly noTokenObservations: number; // requests that could resolve no discovery token at all: the account-wide tier was never even attempted
  readonly lastAt: number; // epoch ms of the most recent observation
  readonly lastDegradedAt?: number; // epoch ms of the most recent DEGRADED observation (absent while clean)
}

export const DISCOVERY_HEALTH_KEY = "diag:discoveryhealth";
const DISCOVERY_COUNT_CAP = 1_000_000;
// A single discover request is bounded to MAX_DISCOVERY_ACCOUNTS (8) accounts; the clamp is deliberately
// generous so a future widening cannot silently truncate the record, and tight enough to bound it.
const DISCOVERY_ACCOUNTS_CAP = 1_000;

// intClamp is the numeric gate: a NaN, an Infinity, a negative or a non-number is DROPPED to 0.
function intClamp(n: unknown, cap: number): number {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return 0;
  return Math.min(cap, Math.floor(n));
}

/**
 * applyDiscoveryHealth folds ONE observation into the standing record. PURE, and the SINGLE REDACTION
 * CHOKEPOINT for this aggregate: every product key is re-checked against DISCOVERY_PRODUCTS and every verdict
 * against DISCOVERY_OUTCOMES (an out-of-vocabulary key or value is DROPPED, so the key space is exactly the
 * two closed sets), every count is re-clamped DO-side, and everything else is coerced to a boolean. NOTHING
 * else on the posted body is read -- so a bucket, a namespace id, an account name, a zone, a token or a
 * Cloudflare message structurally cannot enter the record even if a future call site were to post one.
 *
 * @param prior - the stored record, if any.
 * @param obs - the posted observation (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record.
 */
export function applyDiscoveryHealth(prior: DiscoveryHealth | undefined, obs: unknown, now: number): DiscoveryHealth {
  const base: DiscoveryHealth = prior ?? {
    lastOutcome: {},
    tokenPresent: false,
    engineAccountKnown: false,
    accountsScanned: 0,
    accountsCapped: false,
    boundSources: 0,
    totals: {},
    observations: 0,
    degradedObservations: 0,
    emptyObservations: 0,
    noTokenObservations: 0,
    lastAt: 0,
  };
  const o = (typeof obs === "object" && obs !== null ? obs : {}) as Partial<DiscoveryObservation> & { products?: unknown };

  // The per-product verdicts, re-gated against BOTH closed sets. Anything else is dropped whole.
  const lastOutcome: Record<string, DiscoveryOutcome> = {};
  const posted = (typeof o.products === "object" && o.products !== null ? o.products : {}) as Record<string, unknown>;
  for (const [product, outcome] of Object.entries(posted)) {
    if (!DISCOVERY_PRODUCT_SET.has(product)) continue;
    if (typeof outcome !== "string" || !DISCOVERY_OUTCOME_SET.has(outcome)) continue;
    lastOutcome[product] = outcome as DiscoveryOutcome;
  }

  // The cumulative per-product/outcome tally (bounded: 6 products x 9 outcomes of integers, so a decade of
  // discovery cannot grow it).
  const totals: Record<string, Record<string, number>> = {};
  for (const [product, byOutcome] of Object.entries(base.totals ?? {})) {
    if (!DISCOVERY_PRODUCT_SET.has(product) || typeof byOutcome !== "object" || byOutcome === null) continue;
    const row: Record<string, number> = {};
    for (const [outcome, n] of Object.entries(byOutcome)) {
      if (!DISCOVERY_OUTCOME_SET.has(outcome)) continue;
      row[outcome] = intClamp(n, DISCOVERY_COUNT_CAP);
    }
    totals[product] = row;
  }
  for (const [product, outcome] of Object.entries(lastOutcome)) {
    const row = totals[product] ?? {};
    row[outcome] = Math.min(DISCOVERY_COUNT_CAP, (row[outcome] ?? 0) + 1);
    totals[product] = row;
  }

  // G286: the per-account tallies, through the SAME chokepoint discipline as everything above -- the product key
  // is re-checked against the closed set and each of the three counts is re-clamped DO-side, so a future call
  // site cannot post an account id, a name or an unbounded number into this record even by accident.
  const accountsByProduct: Record<string, DiscoveryAccountTally> = {};
  const postedTallies = (typeof o.accountsByProduct === "object" && o.accountsByProduct !== null ? o.accountsByProduct : {}) as Record<string, unknown>;
  for (const [product, tally] of Object.entries(postedTallies)) {
    if (!DISCOVERY_PRODUCT_SET.has(product)) continue;
    if (typeof tally !== "object" || tally === null) continue;
    const t = tally as Record<string, unknown>;
    accountsByProduct[product] = {
      withData: intClamp(t.withData, DISCOVERY_ACCOUNTS_CAP),
      empty: intClamp(t.empty, DISCOVERY_ACCOUNTS_CAP),
      degraded: intClamp(t.degraded, DISCOVERY_ACCOUNTS_CAP),
    };
  }

  const verdicts = Object.values(lastOutcome);
  const degraded = verdicts.some((v) => DEGRADED_OUTCOMES.has(v));
  // A cleanly EMPTY observation: every listing this request actually ran answered "nothing here", with no
  // fault anywhere. This is the exact claim the console renders as "your account has no sources", and the
  // counter beside it (degradedObservations) is what says whether that claim can be trusted.
  const cleanEmpty = verdicts.length > 0 && verdicts.every((v) => v === "empty");
  const tokenPresent = o.tokenPresent === true;

  return {
    lastOutcome,
    tokenPresent,
    engineAccountKnown: o.engineAccountKnown === true,
    accountsScanned: intClamp(o.accountsScanned, DISCOVERY_ACCOUNTS_CAP),
    accountsCapped: o.accountsCapped === true,
    boundSources: intClamp(o.boundSources, DISCOVERY_ACCOUNTS_CAP),
    ...(Object.keys(accountsByProduct).length > 0 ? { accountsByProduct } : {}),
    ...(o.accountsDegraded !== undefined ? { accountsDegraded: intClamp(o.accountsDegraded, DISCOVERY_ACCOUNTS_CAP) } : {}),
    totals,
    observations: Math.min(DISCOVERY_COUNT_CAP, intClamp(base.observations, DISCOVERY_COUNT_CAP) + 1),
    degradedObservations: Math.min(DISCOVERY_COUNT_CAP, intClamp(base.degradedObservations, DISCOVERY_COUNT_CAP) + (degraded ? 1 : 0)),
    emptyObservations: Math.min(DISCOVERY_COUNT_CAP, intClamp(base.emptyObservations, DISCOVERY_COUNT_CAP) + (cleanEmpty ? 1 : 0)),
    noTokenObservations: Math.min(DISCOVERY_COUNT_CAP, intClamp(base.noTokenObservations, DISCOVERY_COUNT_CAP) + (tokenPresent ? 0 : 1)),
    lastAt: intClamp(now, Number.MAX_SAFE_INTEGER),
    ...(degraded
      ? { lastDegradedAt: intClamp(now, Number.MAX_SAFE_INTEGER) }
      : base.lastDegradedAt !== undefined
        ? { lastDegradedAt: intClamp(base.lastDegradedAt, Number.MAX_SAFE_INTEGER) }
        : {}),
  };
}

// ---------------------------------------------------------------------------------------------------------
// ATTACH / RE-ATTACH HEALTH: a deploy silently dropping every console-attached source, with no record of it failing.
//
// THE GAP. POST /sources/attach and POST /sources/reattach-missing are the two writes that put a source
// binding onto the engine, and reattach-missing is the HEAL for the worst-case failure -- a bare
// `wrangler deploy` resetting the worker's bindings and silently dropping every console-attached source.
// Both routes end in `catch (e) { ...; return jsonError(e.message.slice(0, 300), 400) }`: the refusal is a
// RESPONSE, and the response dies with the browser tab. recordBindingAlarmFrom persists a row ONLY for a
// TAGGED post-write safety alarm -- which is deliberately narrow, and means an ORDINARY failure (a
// bad token, a 403, a Cloudflare 5xx, an unresolvable account, a conflicting plan) records NOTHING AT ALL.
// So "attach failed halfway during the self-binding rewrite" and "reattach-missing keeps failing after the
// deploy wiped bindings" both arrive at support with an empty pack: no attempt, no cause, no timestamp.
//
// The record is per-OP (attach vs reattach are different remedies) x per-CLASS, plus the PLAN SHAPE the last
// re-attach saw -- because the second half of the gap is the plan's own SILENCE: a downpipe whose source has
// no binding name is presented in NONE of the plan's four lists (see roster-reattach.ts MalformedSource),
// and a CONFLICTING claim blocks a binding out of the heal entirely. Both leave the heal reporting success
// while a downpipe stays broken.
//
// NO-CUSTODY: a closed op, a closed class, counts and clamped ints. The deploy token, the account id, the
// script name, the Cloudflare message and the binding names never enter this record (the binding names are
// already carried, separately and deliberately, by sourcesDetached).
// ---------------------------------------------------------------------------------------------------------

// ATTACH_OPS is the closed op vocabulary. They are NOT interchangeable: `attach` ADDS a new source the operator
// chose (its failure means a source was never protected); `reattach` REBUILDS the already-approved roster after
// a deploy dropped it (its failure means protected sources STAY dropped, and backups are failing right now).
// `detach` is the third, and it was hiding inside `attach`: an attach and a detach are the SAME POST to
// the same route, told apart only by which of the two typed argument lists the console filled in, so a Detach the
// engine refused was recorded as an Attach the engine refused, and two of those three were one row. Their failures are not
// interchangeable either: a refused attach means a source was never protected; a refused DETACH means a source
// the operator believes they have removed is STILL BOUND and still being read.
export const ATTACH_OPS = ["attach", "detach", "reattach"] as const;
export type AttachOp = (typeof ATTACH_OPS)[number];
const ATTACH_OP_SET: ReadonlySet<string> = new Set(ATTACH_OPS);

// ---- G180: which PHASE of the binding change refused, decided where it is KNOWN --------------------------
//
// "Attach now / Detach / Re-attach all refuses with an error" is the owner's number-one fear domain, and support
// could not tell the three answers apart:
//
//   the SAFETY HARNESS refused        prove-before-write did its job. NOTHING was written, nothing is at risk, and
//                                     the engine behaved exactly as designed. The customer must be told that this
//                                     is protection, not breakage.
//   the TOKEN lacked what it needed   the pasted deploy token cannot do this change (a capability it does not
//                                     carry, or a token outside its validity window). NOTHING was written.
//   the WRITE genuinely failed        the settings PATCH did not land at Cloudflare. Nothing was CHANGED (settings
//                                     updates are atomic), and the remedy is Cloudflare's, not the customer's.
//
// All three answered the console with an identical 400, and classifyAttachError below had only the MESSAGE to go
// on: a harness refusal ("safety check failed: existing binding X would be dropped; refusing to write") carries no
// status and no network word, so it landed in `other` -- the same bucket as a Cloudflare write failure whose body
// was prose. The one refusal that means THE PRODUCT WORKED and the one that means CLOUDFLARE BROKE were one row.
// The token pre-flight was worse than merely coarse: its message contains the word "permission", so the classifier
// matched it and filed the engine's OWN "this token cannot use Workers KV" as a Cloudflare `auth` rejection.
//
// A CLASSIFIER OVER A MESSAGE IS A GUESS, AND THESE PHASES DO NOT NEED TO GUESS: each one knows what it refused.
// The vocabulary lives HERE, in the leaf, because attach.ts (which throws it) can import a leaf while this module
// cannot import attach.ts: it is folded by the Durable Object, and an import back into the attach path would close
// a cycle through the DO base. AttachRefusalError is thrown at the phase boundary in attach.ts, the message is
// passed through UNCHANGED (so every operator-facing string and HTTP response is byte-identical), and only the TAG
// is ever recorded. The token, the account id, the script name, the binding names and Cloudflare's own prose stay
// in the message, which never leaves the browser tab it is rendered in.
export const ATTACH_REFUSAL_CLASSES = [
  "safety-prove-failed", // the PROVE-BEFORE-WRITE harness refused: the identity guard, the superset proof, a validation or a collision. NOTHING was written, and this is the engine protecting itself
  "token-scope", // the token capability pre-flight PROVED the refusal: Cloudflare answered 401/403 on a capability this change needs, so the pasted deploy token cannot do it. NOTHING was written
  "token-window", // the token is expired or not yet active: every Cloudflare call would otherwise fail as a generic auth error. NOTHING was written
  "cf-write-failed", // Cloudflare ANSWERED the settings PATCH and refused it. Settings updates are atomic, so nothing was changed. This is a PROVEN fact and it is why the class may say "nothing was changed": Cloudflare told us
  "write-unconfirmed", // the settings PATCH got NO ANSWER (the call threw before a status was seen: a socket reset, a timeout, a response lost after the request went out). ATOMICITY DOES NOT HELP HERE. Atomicity says the write either fully applied or did not apply; it does NOT say which, and Cloudflare may well have applied it and lost the reply. So the bindings MAY NOW BE REWRITTEN, and the post-write verify never ran to find out. This is the highest-impact failure mode domain with the safety harness blind, and it must NEVER be filed as cf-write-failed, whose meaning asserts the write did not land. Remedy: re-read the live bindings before retrying, because a blind retry is a second write on top of an unknown state
  "verify-unread", // the settings PATCH LANDED (Cloudflare said so) and the POST-WRITE verify re-read could not run, so the bindings were written and never confirmed. NOT the same as a pre-write read failure (nothing written), NOT the same as write-unconfirmed (we never learned whether the write landed at all) and NOT the same as binding-alarm (the verify ran and disagreed): here the safety harness's post-check is BLIND over a write we know happened
] as const;
export type AttachRefusalClass = (typeof ATTACH_REFUSAL_CLASSES)[number];

// ATTACH_TAGGABLE_CLASSES is every class a PHASE is allowed to tag onto its own throw: the phase classes above,
// plus the four a phase can establish for itself when Cloudflare did not answer it at all (G180).
//
// The capability pre-flight is why the second group exists. It used to report each probe as a BOOLEAN (`ok`), and
// a boolean cannot tell "Cloudflare said 403 on this capability" (a PROVEN fact: the token lacks it) from "the
// probe did not answer" (a Cloudflare 5xx, a 429, a socket reset: NOTHING about the token was established). Both
// came out false, both threw token-scope, and the pack then told the support engineer the engine had PROVED the
// token lacks Workers KV, so they went off to re-mint a perfectly good deploy token while the customer's
// Cloudflare 5xx and 429s sat in their own logs. A member whose NAME asserts a fact must only be written by code
// that established that fact.
//
// `binding-alarm` is deliberately NOT taggable: it is decided by the route from a tagged post-write safety alarm
// and outranks every phase class, so no phase may claim it.
export const ATTACH_TAGGABLE_CLASSES = [
  ...ATTACH_REFUSAL_CLASSES,
  "rate-limited", // Cloudflare throttled the probe: the token was never assessed
  "unavailable", // Cloudflare answered the probe with a 5xx: the token was never assessed
  "transport", // the probe never reached Cloudflare: the token was never assessed
  "other", // the probe answered, but with neither a success nor a refusal nor a transient status: the token was never assessed
] as const;
export type AttachTaggableClass = (typeof ATTACH_TAGGABLE_CLASSES)[number];
const ATTACH_TAGGABLE_SET: ReadonlySet<string> = new Set(ATTACH_TAGGABLE_CLASSES);

/**
 * AttachRefusalError tags a binding-change refusal with TWO independent closed facts, and it carries both because
 * they answer two different questions and neither can be derived from the other:
 *
 *   - `attachRefusalClass`: the COARSE class of the phase that refused, which is what the fault counters
 *     and the streak logic aggregate on, and what classifyAttachError returns.
 *   - `refusal`: the FINE {stage, cause, missingCaps} the refusals ring records, which is what tells a
 *     token whose Start Date is in the future from a token missing the D1 permission -- both of which coarsen to
 *     a refusal at the token pre-flight and are two different sentences to the customer.
 *
 * The message is the operator's, unchanged, and only the tags are ever recorded.
 */
export class AttachRefusalError extends Error {
  readonly attachRefusalClass: AttachTaggableClass;
  readonly refusal?: { stage: AttachRefusalStage; cause: AttachRefusalCause; missingCaps?: readonly AttachCapabilityKey[] };
  constructor(attachRefusalClass: AttachTaggableClass, message: string, refusal?: { stage: AttachRefusalStage; cause: AttachRefusalCause; missingCaps?: readonly AttachCapabilityKey[] }) {
    super(message);
    this.name = "AttachRefusalError";
    this.attachRefusalClass = attachRefusalClass;
    if (refusal !== undefined) this.refusal = refusal;
  }
}

/**
 * attachRefusalClassOf reads the COARSE class off a thrown binding-change refusal. An UNTAGGED error yields null:
 * it is one no phase claimed, so the classifier falls back to its status-derived classes rather than inventing one
 * from prose.
 *
 * @param e - the thrown value.
 * @returns the closed class, or null when untagged.
 */
export function attachRefusalClassOf(e: unknown): AttachTaggableClass | null {
  const c = (e as { attachRefusalClass?: unknown } | null)?.attachRefusalClass;
  if (typeof c !== "string" || !ATTACH_TAGGABLE_SET.has(c)) return null;
  return c as AttachTaggableClass;
}

// ATTACH_FAULT_CLASSES is the closed cause of ONE failed attach/detach/re-attach. The first four are the PHASE
// classes above: TAGGED at the phase that refused, never guessed from the message. They are SPREAD in rather than
// re-typed, so the vocabulary has exactly one definition and a phase class added at the throw site is a phase
// class the pack admits. The rest are the status-derived and structural classes, decided where a Cloudflare status
// is in hand.
export const ATTACH_FAULT_CLASSES = [
  ...ATTACH_REFUSAL_CLASSES, // safety-prove-failed | token-scope | token-window | cf-write-failed | verify-unread (G180)
  "token-invalid", // the pasted deploy token is not token-shaped: the write never left the engine
  "account-unknown", // the engine cannot name its OWN Cloudflare account, so it cannot address the script-settings write
  "auth", // 401/403 FROM CLOUDFLARE on the read: the deploy token is wrong or was revoked. NOT the same as token-scope, which is the engine's own pre-flight catching Cloudflare refusing a NAMED capability this change needs
  "not-found", // 404: the script or the named resource does not exist at Cloudflare
  "rate-limited", // 429: Cloudflare throttled the script-settings write, or the capability probe (in which case the token was never assessed)
  "unavailable", // 5xx on a PRE-WRITE call (the settings read, or the capability probe): Cloudflare's own fault, and nothing was written. A 5xx on the POST-WRITE verify re-read is verify-unread, not this
  "http-other", // any other non-2xx from the script-settings API
  "transport", // the call threw before a status was seen
  "binding-alarm", // the POST-WRITE safety harness raised: the write landed and the verify says the bindings are not what was intended. The single most serious member (it is the highest-impact failure mode ACTUALLY HAPPENING, mid-heal)
  "plan-refused", // the ROSTER heal computed a plan it can never run (a conflicting claim it will never auto-pick). Not a write refusal: no write was ever attempted
  "unclassified", // a FAILURE whose class this recorder does not know: a route running AHEAD of the Durable Object posted a class the fold has never heard of. It is a failure, and it is recorded as one; the remedy is a version-skew bug report, not a customer action
  "other", // classified as none of the above
] as const;
export type AttachFaultClass = (typeof ATTACH_FAULT_CLASSES)[number];
const ATTACH_FAULT_CLASS_SET: ReadonlySet<string> = new Set(ATTACH_FAULT_CLASSES);

/**
 * classifyAttachError coarsens ONE attach/detach/re-attach throw into a closed AttachFaultClass.
 *
 * THE ORDER OF PRECEDENCE IS THE POINT (G180). A TAG beats the text, every time, because a tag was written by the
 * phase that established the fact and the text is a sentence someone wrote for a human. Before the tags existed
 * this function had only the sentence, and the two most important refusals on this route both fell into `other`:
 * the safety harness saying "existing binding X would be dropped; refusing to write" (the product working, nothing
 * written, nothing at risk) and Cloudflare failing the settings PATCH with a prose body (the product not working).
 * One row, opposite answers. It also read the word "permission" out of the engine's OWN token pre-flight message
 * and filed a token-scope refusal as a Cloudflare auth failure.
 *
 * The message is still read for the UNTAGGED remainder, and there it does what it has always done: it SELECTS a
 * member and returns it. Nothing from it is ever carried -- not the deploy token, not the account id, not the
 * script name, not a binding name, not Cloudflare's body.
 *
 * @param e - the thrown fault (never recorded, only read).
 * @param bindingAlarm - true when the caller has already recognised a TAGGED post-write safety alarm (G099),
 *   which outranks every other class: the write LANDED and the verify disagrees with it.
 * @returns the closed class.
 */
export function classifyAttachError(e: unknown, bindingAlarm = false): AttachFaultClass {
  if (bindingAlarm) return "binding-alarm";
  const tagged = attachRefusalClassOf(e);
  if (tagged !== null) return tagged;
  // THE CLOUDFLARE STATUS, READ OFF THE TAG THE CALL SITE ALREADY WROTE (CfApiFault.cfFault, cf-api.ts). It is
  // read STRUCTURALLY, by duck-typing a single clamped NUMBER, because this module is a leaf and must stay one
  // (the DO folds it, so an import into the Cloudflare-API path would close a cycle through the DO base).
  //
  // It goes before the message regex because it is the truth and the regex is a guess. The read leg's own
  // diagnoseRead() builds a precise, human sentence about which of the token, the account or the script name is
  // wrong, and that sentence carries no "HTTP 500" token, so a Cloudflare 5xx ON THE READ fell past the regex into
  // `other`. The number was in hand the whole time, on the throw. A number is also the one thing that cannot leak:
  // it is not the body, not the error prose, not the account id.
  const cfStatus = cfStatusOf(e);
  if (cfStatus !== null) return classFromStatus(cfStatus);
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  const status = /\b(?:status |HTTP )(\d{3})\b/.exec(m);
  if (status !== null) return classFromStatus(Number(status[1]));
  // WORD-BOUNDARY anchored, for the ECONNREFUSED reason: an unanchored permission match inside a transport
  // message would send the operator to re-mint a perfectly good deploy token.
  if (/\bnetwork\b|\bfetch failed\b|\bECONNRE|\bENOTFOUND\b|\bTLS\b|\bsocket\b|\btimed? ?out\b/i.test(m)) return "transport";
  if (/\bforbidden\b|\bunauthorised\b|\bunauthorized\b|\bAuthentication\b|\bpermission\b/i.test(m)) return "auth";
  return "other";
}

/**
 * cfStatusOf duck-types the Cloudflare HTTP status off a CfApiFault tag (cf-api.ts writes it at the call that made
 * the request). It reads ONE clamped integer and nothing else: not the body, not the error codes, not the prose.
 * Null when the throw carries no tag, or its status is the 0 sentinel that means "no status was ever seen".
 *
 * @param e - the thrown value.
 * @returns the HTTP status, or null.
 */
function cfStatusOf(e: unknown): number | null {
  const tag = (e as { cfFault?: { httpStatus?: unknown } } | null)?.cfFault;
  const n = tag?.httpStatus;
  return typeof n === "number" && Number.isInteger(n) && n >= 100 && n <= 599 ? n : null;
}

/**
 * classFromStatus is the one status-to-class map, shared by the tag and the message-derived paths so they cannot
 * disagree about what a 429 means.
 *
 * @param n - an HTTP status.
 * @returns the closed class.
 */
function classFromStatus(n: number): AttachFaultClass {
  if (n === 401 || n === 403) return "auth";
  if (n === 404) return "not-found";
  if (n === 429) return "rate-limited";
  if (n >= 500 && n <= 599) return "unavailable";
  return "http-other";
}

/**
 * The PLAN SHAPE one re-attach computed: what it could heal, and what it could NOT EVEN CONSIDER. Counts only.
 */
export interface AttachPlanShape {
  readonly toAttach: number; // bindings the heal would rebuild
  readonly alreadyAttached: number; // bindings the deploy did not drop
  readonly unreconstructable: number; // bindings whose native id the roster never recorded (operator must re-save)
  readonly conflictingClaims: number; // binding names two downpipes claim as DIFFERENT resources: blocked out of the heal
  readonly malformedSources: number; // downpipes whose binding-backed source has NO binding name: presented in NO list at all
}


// ---------------------------------------------------------------------------------------------------------
// G244: THE ATTACH REFUSAL HISTORY (the richest diagnostics in the product, thrown away with the browser tab)
//
// The attach path computes, and then DISCARDS, the most precise evidence the engine produces anywhere: a
// per-capability checklist ("your token can use Workers Scripts and KV; it cannot use D1"), and a token-window
// verdict that separates a future Start Date from an expiry from a token Cloudflare will not confirm. All of it
// reaches ONE operator's browser as a 400 and dies there. AttachFaultClass -- the coarse class the pack already
// carries -- collapses every one of them into `auth` or `other`.
//
// So "attaching a D1 source fails but KV works" and "attach says my token doesn't work" arrive at support with
// a counter that says an attach failed, and nothing that says WHY. The operator spends an hour failing at step
// 2 and support cannot see any of it.
//
// The ring below is the fix: a bounded, append-only history of {at, stage, cause, missingCaps}. It does NOT
// coalesce (a ring, not a counter map) because the SEQUENCE is the diagnosis: "capability, capability,
// capability" is a token that needs a permission added, while "window, capability, plan" is an operator
// flailing through three different problems.
//
// NO-CUSTODY: closed stage + closed cause + the fixed CF-PERMISSION vocabulary (workers | kv | r2 | d1 |
// secrets, the engine's own capability keys). Never the token, never its value, never the account id, never
// the script name, never Cloudflare's prose. The public tokenId already rides, separately, on the credential
// lifecycle registry for a SUCCESSFUL attach; a REFUSED token's id is not carried here at all.
// ---------------------------------------------------------------------------------------------------------

// The STAGE of changeBindings the refusal happened at. The order is the pipeline's order, and it matters: a
// refusal at token-window means the engine never even asked what the token can do, and a refusal at
// identity-guard means the token WORKED and the thing it was pointed at is not this engine.
export const ATTACH_REFUSAL_STAGES = [
  "token-window", // step 0a: Cloudflare says the token is not usable right now (a future Start Date, an expiry, a non-active status)
  "window-check-unavailable", // step 0a could not be COMPLETED (the verify call threw or answered unusably), so the attach proceeded BLIND to the token's window: a later generic auth failure may be a window problem nobody checked
  "token-capability", // step 0b: the per-capability checklist refused. missingCaps names exactly which permission is absent
  "identity-guard", // step 2: the bindings read back do not look like THIS engine (its scheduler/seal DOs are not both present), so the write was refused rather than risk rewriting a stranger's worker
  "plan-validate", // steps 3-5: the planner refused before any write (a name conflict, a binding that would be dropped, a removal that did not take, nothing to change)
] as const;
export type AttachRefusalStage = (typeof ATTACH_REFUSAL_STAGES)[number];
const ATTACH_REFUSAL_STAGE_SET: ReadonlySet<string> = new Set(ATTACH_REFUSAL_STAGES);

// The closed CAUSE within the stage. Each is a different sentence to the customer.
export const ATTACH_REFUSAL_CAUSES = [
  "token-not-yet-active", // a future Start Date: every call authenticates as a generic "Authentication error" until then
  "token-expired", // the token has expired
  "token-status-inactive", // Cloudflare reports a status other than "active" (revoked, disabled)
  "window-unreadable", // the verify endpoint could not be reached or would not answer: the window is UNKNOWN, not proven good
  "missing-capability", // the token cannot use one or more permissions THIS change needs (see missingCaps): Cloudflare ANSWERED 401/403 on a capability by name, so this is a PROVEN fact about the token
  "token-invalid", // Cloudflare rejected the TOKEN ITSELF on the capability probe, by its own error code on a 400: it is not a valid API token (mistyped, revoked, expired). This is the ONE cause whose remedy is to re-mint the token, which is why it is not folded into the residual below (whose sentence tells the operator to leave the token alone)
  "capability-unprovable", // the capability probe never ANSWERED (a Cloudflare 5xx, a 429, a dead socket), so NOTHING was established about the token. The coarse class beside it (unavailable | rate-limited | transport) says which. Recorded separately from missing-capability because a member whose name asserts a fact must only be written by code that established that fact: this one asserts the opposite

  "not-this-engine", // the identity guard: the script's live bindings do not carry both of this engine's Durable Objects
  "binding-name-conflict", // an addition names a binding that already exists as something else
  "would-drop-binding", // the superset proof refused: an existing binding would be lost by the write
  "removal-not-applied", // a removal target survived into the write set
  "nothing-to-change", // the request added nothing and removed nothing
  "other", // residual within a named stage (never a message)
] as const;
export type AttachRefusalCause = (typeof ATTACH_REFUSAL_CAUSES)[number];
const ATTACH_REFUSAL_CAUSE_SET: ReadonlySet<string> = new Set(ATTACH_REFUSAL_CAUSES);

// The fixed CF-permission vocabulary the capability checklist is built from (cf-api.ts neededCapabilities).
// These are the engine's OWN capability keys, not customer data.
export const ATTACH_CAPABILITY_KEYS = ["workers", "kv", "r2", "d1", "secrets"] as const;
export type AttachCapabilityKey = (typeof ATTACH_CAPABILITY_KEYS)[number];
const ATTACH_CAPABILITY_KEY_SET: ReadonlySet<string> = new Set(ATTACH_CAPABILITY_KEYS);

/** ONE refused attach, as the pack carries it. */
export interface AttachRefusalEntry {
  readonly at: number;
  readonly op: AttachOp;
  readonly stage: AttachRefusalStage;
  readonly cause: AttachRefusalCause;
  readonly missingCaps?: readonly AttachCapabilityKey[]; // present only on a token-capability refusal
}
export const ATTACH_REFUSALS_CAP = 20;

// STAGE_CLASS is the ONE place a fine stage is coarsened to the class the fault counters aggregate on, so the two
// vocabularies cannot drift apart at a call site. It exists because a phase that knows the fine cause also knows
// the coarse class by construction: a plan-validate refusal IS the prove-before-write harness refusing, and a
// token-capability refusal IS a proven token-scope refusal. Deriving it here means a throw site cannot record one
// and forget the other, which is precisely how a refusal ends up in the ring and missing from the counters.
const STAGE_CLASS: Record<AttachRefusalStage, AttachTaggableClass> = {
  "token-window": "token-window",
  "window-check-unavailable": "token-window",
  "token-capability": "token-scope",
  "identity-guard": "safety-prove-failed",
  "plan-validate": "safety-prove-failed",
};

/**
 * AttachRefusal is the bounded, redaction-safe evidence TAGGED onto the throw at the site that knows it, in
 * exactly the CfApiFault idiom: the operator-facing message is UNCHANGED (it is still an Error with the same
 * .message, so every existing response, test and console string is byte-identical), and a caller that wants the
 * evidence reads the tag with attachRefusalOf.
 *
 * It IS an AttachRefusalError, carrying the coarse class STAGE_CLASS derives from its stage. That is not tidiness:
 * asAttachRefusal re-tags an untagged phase throw by building a NEW error from its message, so a refusal that
 * carried only the fine tag would have had that tag rebuilt away, and every plan-validate cause would have been
 * lost between the throw and the ring while the coarse counter still ticked. One class, both tags, no such gap.
 */
export class AttachRefusal extends AttachRefusalError {
  constructor(message: string, refusal: { stage: AttachRefusalStage; cause: AttachRefusalCause; missingCaps?: readonly AttachCapabilityKey[] }) {
    super(STAGE_CLASS[refusal.stage], message, refusal);
    this.name = "AttachRefusal";
  }
}

/**
 * attachRefusalOf reads the bounded refusal off a thrown value, or null when it carries none. It NEVER
 * inspects an untagged error's message (guessing from text is the free-text leak the tag exists to prevent),
 * and it RE-VALIDATES every field against its closed set, so even a forged tag cannot widen what is recorded.
 *
 * @param e - the thrown value.
 * @returns the bounded refusal, or null.
 */
export function attachRefusalOf(e: unknown): { stage: AttachRefusalStage; cause: AttachRefusalCause; missingCaps?: readonly AttachCapabilityKey[] } | null {
  const r = (e as { refusal?: unknown } | null)?.refusal as Partial<AttachRefusalEntry> | undefined;
  if (r === undefined || r === null || typeof r !== "object") return null;
  if (typeof r.stage !== "string" || !ATTACH_REFUSAL_STAGE_SET.has(r.stage)) return null;
  if (typeof r.cause !== "string" || !ATTACH_REFUSAL_CAUSE_SET.has(r.cause)) return null;
  const caps = Array.isArray(r.missingCaps)
    ? r.missingCaps.filter((c): c is AttachCapabilityKey => typeof c === "string" && ATTACH_CAPABILITY_KEY_SET.has(c)).slice(0, ATTACH_CAPABILITY_KEYS.length)
    : [];
  return { stage: r.stage as AttachRefusalStage, cause: r.cause as AttachRefusalCause, ...(caps.length > 0 ? { missingCaps: caps } : {}) };
}

/**
 * One attach/re-attach attempt's outcome, built at the route AFTER it has classified the fault (or landed).
 */
export interface AttachObservation {
  readonly op: AttachOp;
  readonly fault?: AttachFaultClass; // absent on a SUCCESSFUL attach (a success is recorded too: it is what clears a failing streak)
  readonly attached?: number; // how many bindings the write actually added
  readonly plan?: AttachPlanShape; // the re-attach plan's shape (absent on the plain attach path, which has no roster plan)
  // G244: the RICH refusal evidence, when the throw carried a tag. Absent on a success and on an untagged
  // throw (a Cloudflare fault, a transport error), which the coarse `fault` class above already names.
  readonly refusal?: { stage: AttachRefusalStage; cause: AttachRefusalCause; missingCaps?: readonly AttachCapabilityKey[] };
}

/**
 * The standing attach/re-attach record.
 */
export interface AttachHealth {
  readonly faults: Record<string, Record<string, number>>; // closed op -> closed class -> count
  readonly attempts: Record<string, number>; // closed op -> attempts (so a fault RATE is readable, not just a count)
  readonly successes: Record<string, number>; // closed op -> successful writes
  readonly lastFault?: { op: string; cls: string; at: number }; // the most recent failure, whichever op
  readonly lastAt: number;
  readonly lastPlan?: AttachPlanShape & { at: number }; // the shape of the last re-attach plan computed
  // G244: the bounded, APPEND-ONLY refusal history (newest last). It deliberately does not coalesce: the
  // sequence of refusals IS the diagnosis, and a counter keyed on stage|cause would erase it.
  readonly refusals?: readonly AttachRefusalEntry[];
}

export const ATTACH_HEALTH_KEY = "diag:attachhealth";
const ATTACH_COUNT_CAP = 1_000_000;
const ATTACH_PLAN_CAP = 100_000;

/**
 * applyAttachHealth folds ONE observation into the standing record. PURE, and the SINGLE REDACTION CHOKEPOINT
 * for this aggregate: the op is re-checked against ATTACH_OPS (an out-of-vocabulary op records NOTHING: there is
 * nowhere safe to put it), the class against ATTACH_FAULT_CLASSES, and every number is re-clamped DO-side. The
 * key space is exactly the two closed sets, so a token, an account id, a script name or a binding name
 * structurally cannot enter the record even if a future call site were to post one.
 *
 * An out-of-vocabulary CLASS is not dropped, because dropping it silently recorded a FAILED attach as a SUCCESS
 * (see the branch below). Its VALUE is dropped, and the attempt is recorded as a failure of class `unclassified`.
 *
 * @param prior - the stored record, if any.
 * @param obs - the posted observation (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record.
 */
export function applyAttachHealth(prior: AttachHealth | undefined, obs: unknown, now: number): AttachHealth {
  const base: AttachHealth = prior ?? { faults: {}, attempts: {}, successes: {}, lastAt: 0 };
  const o = (typeof obs === "object" && obs !== null ? obs : {}) as Partial<AttachObservation> & { plan?: unknown };
  const op = typeof o.op === "string" && ATTACH_OP_SET.has(o.op) ? (o.op as AttachOp) : null;
  if (op === null) return base; // an out-of-vocabulary op is not recorded at all (there is nowhere safe to put it)

  const faults: Record<string, Record<string, number>> = {};
  for (const [k, row] of Object.entries(base.faults ?? {})) {
    if (!ATTACH_OP_SET.has(k) || typeof row !== "object" || row === null) continue;
    const clean: Record<string, number> = {};
    for (const [cls, n] of Object.entries(row)) {
      if (!ATTACH_FAULT_CLASS_SET.has(cls)) continue;
      clean[cls] = intClamp(n, ATTACH_COUNT_CAP);
    }
    faults[k] = clean;
  }
  const attempts: Record<string, number> = {};
  const successes: Record<string, number> = {};
  for (const k of ATTACH_OPS) {
    const a = intClamp(base.attempts?.[k], ATTACH_COUNT_CAP);
    const s = intClamp(base.successes?.[k], ATTACH_COUNT_CAP);
    if (a > 0) attempts[k] = a;
    if (s > 0) successes[k] = s;
  }
  attempts[op] = Math.min(ATTACH_COUNT_CAP, (attempts[op] ?? 0) + 1);

  // A FAILURE IS DECIDED BY THE PRESENCE OF THE FIELD, NOT BY THE RECOGNISABILITY OF ITS VALUE (G180).
  //
  // This branch used to read "if the class is in the vocabulary, count a fault; otherwise count a SUCCESS", and
  // an out-of-vocabulary class therefore fell through to successes[op]. A FAILED attach carrying a class this
  // fold did not recognise came out BYTE-IDENTICAL to a genuinely successful one, so the chokepoint's own stated
  // invariant ("an out-of-vocabulary class is dropped whole") was false at exactly the untrusted-input boundary
  // it exists to guard, and it INFLATED the success count of the heal that repairs the highest-impact failure mode.
  //
  // The two facts are separate. That a fault field was POSTED is the caller saying "this attempt FAILED", and it
  // is trustworthy in the only direction that matters (no success path posts one; the route omits the key). That
  // the VALUE is a member of the vocabulary is a separate question, and when the answer is no the honest record
  // is a failure of unknown class, never a success. `unclassified` says exactly that and nothing more, and it is
  // its own cell, so it can never be mistaken for `other` (which means the classifier RAN and matched nothing).
  const posted = (o as { fault?: unknown }).fault;
  const cls: AttachFaultClass | null =
    typeof posted === "string" && ATTACH_FAULT_CLASS_SET.has(posted)
      ? (posted as AttachFaultClass)
      : posted === undefined
        ? null // no fault field at all: this is a SUCCESS, which is what clears a failing streak
        : "unclassified"; // a fault WAS posted and its value is not one of ours: a failure, recorded as one
  if (cls !== null) {
    const row = faults[op] ?? {};
    row[cls] = Math.min(ATTACH_COUNT_CAP, (row[cls] ?? 0) + 1);
    faults[op] = row;
  } else {
    successes[op] = Math.min(ATTACH_COUNT_CAP, (successes[op] ?? 0) + 1);
  }

  const at = intClamp(now, Number.MAX_SAFE_INTEGER);
  const p = (typeof o.plan === "object" && o.plan !== null ? o.plan : null) as Partial<AttachPlanShape> | null;
  const lastPlan = p !== null
    ? {
        toAttach: intClamp(p.toAttach, ATTACH_PLAN_CAP),
        alreadyAttached: intClamp(p.alreadyAttached, ATTACH_PLAN_CAP),
        unreconstructable: intClamp(p.unreconstructable, ATTACH_PLAN_CAP),
        conflictingClaims: intClamp(p.conflictingClaims, ATTACH_PLAN_CAP),
        malformedSources: intClamp(p.malformedSources, ATTACH_PLAN_CAP),
        at,
      }
    : base.lastPlan;

  // G244: append the RICH refusal, when the observation carried one. Every field is re-gated against its
  // closed set HERE (the applier is the single redaction chokepoint for this record, exactly as it is for the
  // op and the fault class), so no message, token, account id or binding name can enter the ring even from a
  // drifted writer. The ring is bounded and append-only; the oldest entries fall off the front.
  const priorRefusals: readonly unknown[] = Array.isArray(base.refusals) ? base.refusals : [];
  const carried: AttachRefusalEntry[] = [];
  for (const raw of priorRefusals) {
    const r = (typeof raw === "object" && raw !== null ? raw : {}) as Partial<AttachRefusalEntry>;
    const rop = typeof r.op === "string" && ATTACH_OP_SET.has(r.op) ? (r.op as AttachOp) : null;
    const kept = attachRefusalOf({ refusal: r });
    if (rop === null || kept === null) continue;
    carried.push({ at: intClamp(r.at, Number.MAX_SAFE_INTEGER), op: rop, stage: kept.stage, cause: kept.cause, ...(kept.missingCaps !== undefined ? { missingCaps: kept.missingCaps } : {}) });
  }
  const fresh = attachRefusalOf({ refusal: (o as { refusal?: unknown }).refusal });
  if (fresh !== null) carried.push({ at, op, stage: fresh.stage, cause: fresh.cause, ...(fresh.missingCaps !== undefined ? { missingCaps: fresh.missingCaps } : {}) });
  const refusals = carried.length > ATTACH_REFUSALS_CAP ? carried.slice(carried.length - ATTACH_REFUSALS_CAP) : carried;

  return {
    faults,
    attempts,
    successes,
    ...(cls !== null
      ? { lastFault: { op, cls, at } }
      : base.lastFault !== undefined
        ? { lastFault: { op: base.lastFault.op, cls: base.lastFault.cls, at: intClamp(base.lastFault.at, Number.MAX_SAFE_INTEGER) } }
        : {}),
    lastAt: at,
    ...(lastPlan !== undefined ? { lastPlan } : {}),
    ...(refusals.length > 0 ? { refusals } : {}),
  };
}
