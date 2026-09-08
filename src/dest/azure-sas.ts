// Azure shared access signature (SAS) credentials, for the Azure Blob destination.
//
// A SAS IS THE CHEAPEST CREDENTIAL THIS ENGINE HOLDS, and that is not a figure of speech: it needs no
// signing by us at all. Where a Shared Key request is authenticated by building Azure's canonical string
// and HMAC-ing it (azure-sharedkey.ts, and every positional trap documented in it), a SAS is a query string
// somebody else already signed. The request carries it as query parameters and OMITS the Authorization
// header entirely. So the SAS path is strictly less code than the Shared Key path that came first, not
// more, and the reason Shared Key was built first was that it matched the credential pair the destination
// form already collected, not that it was simpler.
//
// WHAT WE ACCEPT AND WHAT WE REFUSE TO DO. We accept a token an operator supplies. We do NOT mint one, and
// that is a standing decision rather than an unfinished piece: minting a SAS requires the account key, so a
// product that mints SAS tokens is a product that holds account keys in order to hand out scoped ones,
// which is the opposite of the custody posture. An operator who wants a narrower credential mints it in
// Azure, where the key already lives, and pastes it here.
//
// WHY THE EXPIRY IS PARSED RATHER THAN LEFT OPAQUE. Every Shared Key credential this engine has ever held
// is valid until somebody rotates it. A SAS is the first credential that dies ON ITS OWN, at an instant
// already written into the token, and a backup destination whose credential expires quietly at 3am is a
// backup that stops with no alert and no cause. The `se` parameter is right there in the token, so it is
// read and exposed for a surface that can warn before the day comes. A token with no `se` at all is
// reported as an unknown expiry, never as "never expires": a service SAS can take its expiry from a stored
// access policy on the container instead, so the absence means we cannot see the date, not that there
// isn't one.

import { DestBuildError } from "./build-health.ts";

/**
 * A parsed SAS credential: the token normalised for appending to a request URL, and what it says about its
 * own death.
 *
 * expiresAtMs is null when the token carries no `se` parameter. That is the honest reading of the absence
 * and not a default: see this module's header for why "no `se`" does not mean "never expires".
 */
export interface AzureSasCreds {
  /** The token as query parameters, with no leading "?" and nothing re-encoded. */
  query: string;
  /** The `se` expiry as epoch milliseconds, or null when the token carries no `se` parameter. */
  expiresAtMs: number | null;
}

/**
 * looksLikeAzureSasToken decides whether a stored credential value is a SAS token rather than a storage
 * account key, so one stored field can carry either.
 *
 * THE TEST IS STRUCTURAL, NOT A SUBSTRING SEARCH, and the difference matters. An account key is standard
 * base64 of 64 random bytes: 88 characters over the base64 alphabet, with "=" appearing only as trailing
 * padding and "&" and "?" never appearing at all. A SAS is a query string, so it always carries several
 * parameters joined by "&" and always carries `sig`. Requiring BOTH a parameter separator and a `sig`
 * parameter is what keeps a key from ever reading as a token: a bare substring test for "sig=" would match
 * an account key whose base64 happened to end "...sig=", which is not a rare enough accident to build a
 * credential decision on.
 *
 * It answers only "which KIND of credential is this". Whether the token is USABLE is decided by
 * parseAzureSasToken, which refuses the broken ones by name.
 *
 * @param raw - the stored credential value.
 * @returns true when the value is shaped like a SAS query string.
 */
export function looksLikeAzureSasToken(raw: string): boolean {
  const t = raw.trim().replace(/^\?/, "");
  if (!t.includes("&")) return false;
  return new URLSearchParams(t).has("sig");
}

/**
 * parseAzureSasToken validates an operator-supplied SAS token and reads its expiry.
 *
 * IT REFUSES AT CONSTRUCTION, which is deliberate. A destination built on a dead credential is one whose
 * every backup fails at its first request, and buildDestination records a construction failure with a
 * closed cause and the moment the destination STARTED failing, so "the SAS expired on Tuesday" becomes a
 * standing, attributable fact rather than a nightly run error nobody reads. A refusal deferred to the first
 * write would arrive as a 403 that names nothing.
 *
 * THE THREE REFUSALS, and each names what is wrong rather than reporting a generic bad credential:
 *   no `sig`             not a signature at all, so nothing in it could ever authenticate a request. This
 *                        is the paste-the-wrong-thing case: a connection string, a container URL, a key.
 *   `se` in the past     a token that has already died. Accepting it would build a destination that
 *                        verifies nothing and writes nothing.
 *   `se` unparseable     REFUSED rather than treated as absent, and the distinction is the point. "No `se`"
 *                        is a legal SAS shape with an honest unknown expiry. A PRESENT `se` that is not a
 *                        date is a malformed token, and silently demoting it to "no expiry" would invent
 *                        exactly the fact this module refuses to invent, on the one input where we can see
 *                        that something is wrong.
 *
 * WHAT IT DOES NOT REFUSE, on purpose. It does not check `sp` (the permission letters), `sr`/`srt` (the
 * resource scope) or `ss` (the service). Those spell differently across account, service and user
 * delegation SAS tokens, and a rule written from one shape would reject working tokens of another. What a
 * token is allowed to do is answered by the live save-time probe, which tries the actual operations, and a
 * refusal there is reported. Guessing here would trade a real check for a brittle one.
 *
 * @param raw - the token as the operator supplied it, with or without a leading "?".
 * @param now - the current instant, for the expiry comparison.
 * @returns the normalised token and its expiry.
 * @throws DestBuildError when the token cannot serve as this destination's credential.
 */
export function parseAzureSasToken(raw: string, now: Date): AzureSasCreds {
  const query = raw.trim().replace(/^\?/, "");
  const params = new URLSearchParams(query);
  // The message never quotes the token. A SAS IS a credential, in full, and one echoed into an error
  // message reaches the run log, the support pack and whatever the operator pastes into a ticket.
  if ((params.get("sig") ?? "") === "") {
    throw new DestBuildError("config-incomplete", "the Azure SAS token has no sig parameter, so it carries no signature and cannot authenticate any request. Paste the shared access signature itself (the query string Azure gives you, beginning sv=), not a connection string, a container URL or an account key.");
  }
  const se = params.get("se");
  if (se === null || se === "") return { query, expiresAtMs: null };
  const at = Date.parse(se);
  if (!Number.isFinite(at)) {
    throw new DestBuildError("config-incomplete", "the Azure SAS token's se parameter is not a date this engine can read, so its expiry cannot be established. Azure writes it as an ISO 8601 UTC instant, for example 2026-12-31T23:59:59Z. Mint the token again in Azure rather than editing it by hand.");
  }
  if (at <= now.getTime()) {
    // The DATE rides in the message and the token does not. The date is the operator's own configuration
    // and is the one fact that makes this refusal actionable: it separates "expired last night" from
    // "expired in March and nobody noticed".
    throw new DestBuildError("config-incomplete", `the Azure SAS token expired at ${new Date(at).toISOString()}, so every request made with it would be refused. Mint a new shared access signature in Azure and update this destination.`);
  }
  return { query, expiresAtMs: at };
}

/**
 * mergeSasQuery joins a request's own query parameters to the SAS token's, producing the query string for
 * the wire.
 *
 * The request parameters go FIRST and the SAS parameters after, which is cosmetic (a SAS signature is
 * computed over named fields, not over the URL's parameter order) but keeps a logged URL readable, with
 * the operation up front and the credential trailing where a reader expects it.
 *
 * @param query - the request's own parameters, or undefined when it has none.
 * @param sasQuery - the SAS token's query string, without a leading "?".
 * @returns the full query string including its leading "?".
 */
export function mergeSasQuery(query: Record<string, string> | undefined, sasQuery: string): string {
  const own = query === undefined ? "" : new URLSearchParams(query).toString();
  return `?${own === "" ? sasQuery : `${own}&${sasQuery}`}`;
}
