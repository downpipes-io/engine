// Leaf module of notify symbols shared between notify.ts (the routing hub) and the
// per-kind channel adapters (notify/channels/*). This leaf imports NOTHING from notify.ts;
// both sides import from here, which keeps notify.ts and the channel adapters from importing
// each other directly.
//
// It carries the channel-facing types (ChannelKind, NotifyChannel, NotifyEmission,
// Severity), the cosmetic severityEmoji helper, and the self-contained webhook-POST /
// SSRF-screen machinery the url/routingKey adapters use (deliverPayload and its
// dependencies). notify.ts re-exports each symbol so callers can import from either module.
//
// This module also carries a type-only import of WrappedSecret (src/admin/config-secret.ts)
// for NotifyChannel.apiKey's at-rest-sealed shape (the jsm/servicenow bearer credential). It is
// type-only (erased at build time) and config-secret.ts depends only on the crypto leaves, so this
// does not introduce a cycle or any runtime coupling to the admin domain.
import type { WrappedSecret } from "../admin/config-secret.ts";
import { DOH_ENDPOINT, isFixedEgressHostExact } from "../lib/outbound.ts";

// ChannelKind is the closed set of delivery providers. "email" and "teams"(via toAddresses) route
// through src/email.ts; "webhook" | "slack" | "teams"(connector) POST a url; "pagerduty" POSTs the
// Events API v2 with a routing key. "jsm" is Jira Service Management / Opsgenie (one alias-keyed
// Alert API client covers both, see src/notify/channels/jsm.ts); "servicenow" is ServiceNow Event
// Management's em_event table API (src/notify/channels/servicenow.ts). Both carry a customer url
// (SSRF-screened like webhook/slack) plus a sealed bearer/basic credential (apiKey), unlike
// pagerduty's fixed endpoint + unsealed routingKey.
export type ChannelKind = "email" | "webhook" | "slack" | "pagerduty" | "teams" | "jsm" | "servicenow";

// DeliveryFailCode is the CLOSED reason vocabulary for a FAILED per-channel delivery. Without it a channel
// delivery collapses to a bare `delivered:false`, so "an alert never reached me" cannot be diagnosed: was it a
// 4xx (bad url/auth on the customer's sink), a 5xx (their sink is down), a redirect, an SSRF default-deny (an
// internal target), a timeout, an email onboarding gap? This is that WHY, as a closed enum -- never the raw
// HTTP body / a provider error message / a customer url. It rides on the NotifyHistoryEntry so the pack can
// reason over it.
export type DeliveryFailCode =
  | "internal-sink-blocked" // SSRF default-deny screened the target at send time (an internal/private/loopback sink)
  // The literal spelling was public but the name RESOLVED to internal space, which is the DNS-rebinding
  // case. Kept distinct from internal-sink-blocked so a reviewer can tell a sink that was always internal
  // from one that was repointed after it was stored: the second is an attack, the first is a misconfiguration.
  | "internal-sink-resolved"
  | "url-invalid" // the stored channel url did not parse at send time
  | "http-redirect" // a 3xx (redirect:"manual" opaque redirect) treated as non-ok
  // 401/403. USUALLY the customer's own credential or permission (fix the credential, not the network), but
  // the two statuses do NOT always mean the same thing and this code deliberately does not claim they do.
  // Splunk's HEC listener answers 403 code 4 "Invalid token" for the customer's own credential, but answers
  // 401 code 3 "Invalid authorization" when the Authorization header's SCHEME is wrong (Bearer, or a bare
  // token, where HEC requires the literal "Splunk ") -- an engine-side bug that no customer credential change
  // can fix. Other sinks differ again: ServiceNow answers 401 for bad Basic credentials, which IS the
  // customer's. So the per-status meaning is vendor-specific and the httpStatus recorded beside this code is
  // what separates them; do not fold that status away on the assumption this code implies it.
  | "http-auth"
  | "http-rate-limited" // 429: the sink is throttling this account/token -- back off, this is not a broken credential
  | "http-bad-request" // 400: the sink rejected the request shape outright (a malformed field/body)
  | "http-gone" // 410: the sink was DEPROVISIONED (the endpoint existed and has been permanently removed) --
  // a different fix from a 404 (a wrong path on a live sink): recreate/repoint the integration, do not
  // re-check the path
  | "http-4xx" // any OTHER 4xx (not-found/method-not-allowed/... on the customer's endpoint)
  | "http-5xx" // the sink returned a 5xx (the customer's endpoint is erroring)
  | "http-other" // some other non-2xx status
  | "timeout" // the POST was aborted at the send timeout (a hanging sink)
  // The fetch threw (no HTTP response at all). The SUB-CAUSE is split out because "flapping
  // network-error" is three different customer-side fixes: a name that no longer resolves (fix DNS / the
  // hostname), a TLS trust/handshake failure (fix the sink's certificate chain), a mid-connection reset
  // (a firewall/proxy/load-balancer dropping us). classifyNetworkFailure derives these from the exception
  // TEXT and returns a CLOSED code; the text itself is never recorded.
  | "network-dns" // the sink hostname did not resolve
  | "network-tls" // the TLS handshake / certificate validation failed
  | "network-reset" // the connection was refused or reset mid-flight
  | "network-error" // an unclassified transport failure (the residual bucket)
  | "email-not-configured" // no send_email binding bound (email unconfigured)
  | "email-from-invalid" // EMAIL_FROM unset/invalid (a misconfigured sender)
  | "email-recipients-invalid" // the channel's recipient list was rejected
  // Email failures split by OWNER: a formatting bug the ENGINE owns (a subject/body that failed the send
  // primitive's own bounds) is distinct from the email PLATFORM refusing the send (an un-onboarded sending
  // domain, an unverified sender) -- opposite owners, opposite fixes, so each is named rather than collapsed
  // into one generic email-rejected code.
  | "email-subject-invalid" // the SUBJECT failed sendEmail's bounds (empty / past the RFC 5322 header ceiling): an ENGINE-side formatting fault, never the customer's platform
  | "email-body-invalid" // the BODY (text/html) failed sendEmail's bounds (empty / past the 256 KiB ceiling): likewise an engine-side formatting fault
  | "email-platform-rejected" // the Email Service itself REFUSED the send (env.EMAIL.send threw): the platform's own code rides in platformCode (E_SENDER_DOMAIN_NOT_AVAILABLE, ...), or E_OTHER when it did not conform to the documented shape
  | "email-rejected" // residual: an email non-delivery outside the named arms (kept so a future reason can never fall out of the vocabulary)
  // The channel's SEALED credential (jsm's GenieKey, servicenow's Basic password) would not decrypt at send
  // time: CONFIG_WRAP_KEY is absent, or it was ROTATED since the credential was sealed. Distinct
  // from no-transport (a channel with no url/key configured at all) because the FIX is different: restore the
  // wrap key or re-enter the sealed credential, NOT "re-enter the channel's fields".
  | "credential-undecryptable"
  // EMAIL_FROM was NEVER SET, as opposed to set-but-invalid. Kept distinct from email-from-invalid: one is
  // "you have not finished setup"; the other is "the value you typed is wrong".
  | "email-from-not-configured"
  // The channel ADAPTER itself threw. Kept distinct from network-error: an adapter exception is an engine
  // bug, not an intermittent transport fault, and the pack must say so.
  | "adapter-exception"
  // no-transport by itself names a FAMILY, not a FIELD. For JSM / ServiceNow / PagerDuty / Teams / email one
  // shared code cannot say whether the url, the username, the credential or the recipient list is the missing
  // one. Each of the codes below names the absent field CLASS; never the field's value.
  | "no-url" // the channel has no endpoint url / instance host at all
  | "no-credential" // the channel has a url but no routing key / api key / password
  | "no-recipients" // the channel has a transport but an empty recipient / address list
  | "no-username" // ServiceNow only: the url is present and the USERNAME is not. Kept distinct from no-url so the missing field is named precisely rather than pointing at an endpoint that is actually fine.
  | "no-transport" // residual: a channel missing its transport in a way none of the three above names
  // egress-not-allowlisted: the account has configured an outbound egress allowlist and this
  // channel's host is not on it (and is not one of the exact fixed vendor hosts isFixedEgressHostExact
  // always permits).
  // Distinct from internal-sink-blocked: that code is the SSRF default-deny over private/loopback address
  // space; this one is the OPERATOR's own positive list of external hosts the account has chosen to reach,
  // and it can refuse a perfectly public host the operator never added. The host itself never rides; only
  // the fact that the configured list did not admit it.
  | "egress-not-allowlisted";

// DELIVERY_FAIL_CODES is the runtime allow-list of the closed vocabulary (defence in depth: only a member
// reaches the history / the pack; anything else is dropped).
export const DELIVERY_FAIL_CODES: ReadonlySet<string> = new Set<DeliveryFailCode>([
  "internal-sink-blocked",
  "internal-sink-resolved", "url-invalid", "http-redirect", "http-auth", "http-rate-limited", "http-bad-request", "http-gone", "http-4xx", "http-5xx", "http-other", "timeout",
  "network-dns", "network-tls", "network-reset", "network-error",
  "email-not-configured", "email-from-invalid", "email-from-not-configured", "email-recipients-invalid", "email-subject-invalid", "email-body-invalid", "email-platform-rejected", "email-rejected",
  "adapter-exception", "credential-undecryptable", "no-url", "no-credential", "no-recipients", "no-username", "no-transport",
  "egress-not-allowlisted",
]);

// WEBHOOK_REJECT_CODES is the CLOSED reason vocabulary behind an isAllowedWebhookUrl refusal. The verdict
// already carries an operator-facing SENTENCE, which is exactly what the pack can never record: it quotes
// the submitted URL's shape and is free text. The code is the same decision, closed.
//
// "I can't save my SIEM/webhook channel" is a COMMON ticket and the customer is stuck in a validation loop the
// pack was completely blind to (every rejection is a 400 to the browser and nothing else). A count per code
// answers it in one line: they keep pasting an http:// URL, or their sink is on a private address and they
// have not ticked the internal-sink override.
export const WEBHOOK_REJECT_CODES = ["non-https", "userinfo", "workers-dev", "internal-no-optin", "too-long", "unparseable", "not-allowlisted"] as const;
export type WebhookRejectCode = (typeof WEBHOOK_REJECT_CODES)[number];

// AckOutcome is the CLOSED verdict of an ASYNC-ACCEPTED delivery's confirmation step. Without it a
// JSM/Opsgenie 202 whose status poll came back data.success:FALSE (the provider POSITIVELY told us the alert
// was never created) is recorded identically to a poll that timed out or answered ambiguously: both read as
// delivered:true + unconfirmed:true. The first is a REAL, actionable non-delivery ("a critical page never
// appeared in JSM"); the second is only a missing confirmation. This names which:
//   - confirmed: the poll POSITIVELY confirmed the async create/close succeeded (no caveat).
//   - async-create-failed: the poll POSITIVELY reported failure (data.success:false). The alert does NOT exist.
//   - confirmation-unavailable: no requestId, or the poll refused / timed out / was unparseable.
// It rides ALONGSIDE unconfirmed (which stays exactly as it is: any non-confirmed outcome), so delivery
// behaviour is unchanged (an idempotent-by-alias async create is never retry-stormed by a flipped ok).
export type AckOutcome = "confirmed" | "async-create-failed" | "confirmation-unavailable";

// ACK_OUTCOMES is the runtime allow-list of the closed AckOutcome vocabulary (defence in depth: only a member
// may reach the history / the pack).
export const ACK_OUTCOMES: ReadonlySet<string> = new Set<AckOutcome>(["confirmed", "async-create-failed", "confirmation-unavailable"]);

// TRANSPORT_FAULT_TEXT_DEPTH bounds how far down an exception's cause chain the classifier reads. A wrapped
// fetch failure nests two deep in practice (TypeError -> the underlying transport Error); four is slack
// without letting a cyclic or absurdly deep chain turn classification into work.
const TRANSPORT_FAULT_TEXT_DEPTH = 4;

// transportFaultText flattens an exception into the lower-cased text the substring matchers read: the name,
// the message AND the `code` property at EVERY level of the cause chain (plus an AggregateError's members).
//
// Reading only the top level was the whole defect. Under undici (Node's fetch, which every `node test/*.ts`
// validator and the destsim harness run on) a certificate refusal arrives as `TypeError: fetch failed` and
// NOTHING else: the cause carries the real fault, verified live against a Splunk Cloud stack whose HEC port
// serves Splunk's stock self-signed certificate, where the thrown object is
//   TypeError: fetch failed
//     cause: Error: self-signed certificate in certificate chain  (code SELF_SIGNED_CERT_IN_CHAIN)
// so the old `${err.name} ${err.message}` read "TypeError fetch failed", matched nothing, and reported the
// residual network-error. The operator was told a certificate problem was a generic network problem, which is
// the one thing that gives them no route to the cause.
//
// The `code` property is read as well as the message because it is the STABLE half of that shape: undici's
// wording can be reworded between releases, whereas SELF_SIGNED_CERT_IN_CHAIN / CERT_HAS_EXPIRED /
// ERR_TLS_CERT_ALTNAME_INVALID come from OpenSSL and do not move.
//
// Only the flattened text is used, and only to pick an ENUM MEMBER. It never leaves this module: no message,
// host, certificate subject, code or stack can reach the history ring or the pack.
function transportFaultText(err: unknown): string {
  const parts: string[] = [];
  const seen = new Set<unknown>();
  const walk = (e: unknown, depth: number): void => {
    if (depth > TRANSPORT_FAULT_TEXT_DEPTH || e === null || e === undefined || seen.has(e)) return;
    seen.add(e);
    if (typeof e === "string") {
      parts.push(e);
      return;
    }
    if (typeof e !== "object") return;
    const o = e as { name?: unknown; message?: unknown; code?: unknown; cause?: unknown; errors?: unknown };
    if (typeof o.name === "string") parts.push(o.name);
    if (typeof o.message === "string") parts.push(o.message);
    if (typeof o.code === "string") parts.push(o.code);
    if (typeof o.code === "number") parts.push(String(o.code));
    if (Array.isArray(o.errors)) for (const m of o.errors) walk(m, depth + 1);
    walk(o.cause, depth + 1);
  };
  walk(err, 0);
  // Both spellings are searched: the raw lower-cased text, and a copy with underscores opened out to spaces.
  // An OpenSSL code is SCREAMING_SNAKE and a message is prose, so a single form always misses half of them --
  // "cert_" finds CERT_HAS_EXPIRED but not DEPTH_ZERO_SELF_SIGNED_CERT, and "self signed" finds the prose but
  // not SELF_SIGNED_CERT_IN_CHAIN. Both of those were live misses this suite caught.
  const raw = parts.join(" ").toLowerCase();
  return `${raw} ${raw.replace(/_/g, " ")}`;
}

// classifyNetworkFailure coarsens a THROWN fetch exception into the closed network sub-cause. It
// reads the exception's flattened name/message/code text ONLY to match well-known transport-fault substrings
// and returns an ENUM MEMBER; the message, the host, the certificate subject and the stack NEVER leave this
// function, so no raw error text can reach the history ring or the pack. An unrecognised fault falls to the
// residual network-error, so this can only ever ADD precision, never lose a failure.
//
// TLS IS TESTED BEFORE DNS, deliberately. A hostname-mismatch refusal reads "Hostname/IP does not match
// certificate's altnames: ... is not in the cert's altnames: DNS:*.example.com", which contains "dns" and
// would otherwise be reported as an unresolvable name: the operator would go and check their DNS while the
// certificate sat there wrong. The DNS matchers below are all name-resolution specific, so nothing that is
// genuinely a DNS fault is lost to the earlier test.
//
// WHAT THIS CANNOT REACH. On the Workers runtime the substring matchers are largely powerless, because
// workerd does not hand the transport cause to JavaScript at all: a certificate refusal arrives as
// `Error: internal error; reference = <id>` with the real text (kj/compat/tls.c++: "TLS peer's certificate is
// not trusted") going only to the runtime log, and an unresolvable name arrives in that same opaque shape.
// That is why a certificate fault is ALSO determined structurally, by observation rather than by text, in
// transport-probe.ts. This function stays the fast, pure, always-available first pass.
export function classifyNetworkFailure(err: unknown): Extract<DeliveryFailCode, "network-dns" | "network-tls" | "network-reset" | "network-error"> {
  const m = transportFaultText(err);
  // "unable to verify" covers both UNABLE_TO_VERIFY_LEAF_SIGNATURE (a chain missing its intermediate, the
  // second most common cause after a self-signed leaf) and the prose "unable to verify the first certificate".
  // Neither named a certificate or a TLS layer anywhere in its text, so both were reported as generic.
  if (m.includes("certificate") || m.includes("cert_") || m.includes("ssl") || m.includes("tls") || m.includes("handshake") || m.includes("self-signed") || m.includes("self signed") || m.includes("unable to verify")) return "network-tls";
  if (m.includes("enotfound") || m.includes("eai_again") || m.includes("getaddrinfo") || m.includes("dns") || m.includes("name not resolved") || m.includes("could not resolve")) return "network-dns";
  // "network connection lost" is workerd's own wording for a connection that was refused or dropped: measured
  // against a closed port on a real host, the Workers runtime throws exactly `Error: Network connection lost.`
  // It matched none of the errno spellings below, so a refused connection on the runtime we actually ship on
  // was reported as the residual.
  if (m.includes("econnreset") || m.includes("econnrefused") || m.includes("connection reset") || m.includes("connection refused") || m.includes("connection lost") || m.includes("socket hang up") || m.includes("epipe")) return "network-reset";
  return "network-error";
}

// SinkScreenVerdict is the CLOSED verdict of the SEND-TIME sink screen for a url-bearing channel. It is the
// DIAGNOSTIC OBSERVATION of what the internal-sink screen concluded about the target host BY ITS LITERAL
// SPELLING, independent of whether delivery then succeeded:
//   - internal-literal: the host is a literal internal/private/loopback/link-local IP or an internal name
//     (localhost / *.localhost). This is the class the default-deny BLOCKS (surfaced as internal-sink-blocked).
//   - public-literal: the host is a literal PUBLIC IP (v4 dotted-quad or a v6 literal). A literal IP cannot
//     be rebound by DNS, so the screen fully covers it: this sink is screened AND safe.
//   - hostname: the host is a DNS NAME (not an IP literal). The literal-spelling screen PASSES it, but a name
//     can RESOLVE to an internal IP that only true resolve-then-pin would catch. This verdict is the RESIDUAL
//     dns-rebinding exposure made observable: a `hostname` sink is the one a rebind could still slip through.
//   - url-invalid: the stored url did not parse at send time.
//   - not-allowlisted: the account has configured an outbound egress allowlist and the host,
//     whatever its literal-spelling class would otherwise have been, is not on it. Checked independently of
//     the three literal-spelling verdicts above (a public, well-formed hostname can still be refused this
//     way), so it is reported instead of them, never alongside one.
// It is redaction-safe by construction (a fixed 5-member enum; never the host, never the url). It rides on the
// delivery result / history entry so a diagnoser can see "this channel points at an un-pinnable hostname sink"
// WITHOUT the engine adding true IP-pinning behaviour (which would be a deeper, behaviour-changing follow-up).
export type SinkScreenVerdict = "internal-literal" | "public-literal" | "hostname" | "url-invalid" | "not-allowlisted";

// SINK_SCREEN_VERDICTS is the runtime allow-list (defence in depth: only a member reaches the history / pack).
export const SINK_SCREEN_VERDICTS: ReadonlySet<string> = new Set<SinkScreenVerdict>([
  "internal-literal", "public-literal", "hostname", "url-invalid", "not-allowlisted",
]);

// isIpLiteralHost reports whether a url hostname is an IP LITERAL (an IPv4 dotted-quad or an IPv6 literal),
// as opposed to a DNS name. The URL parser has already collapsed obfuscated IPv4 spellings to the canonical
// dotted-quad and brackets an IPv6 literal, so a bracket / a colon / a dotted-quad match covers the literals;
// anything else is a name. Used only by screenSinkHost to split a public LITERAL (un-rebindable) from a NAME.
function isIpLiteralHost(hostname: string): boolean {
  let h = canonicalWebhookHost(hostname);
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.includes(":")) return true; // IPv6 literal (bracketed by the parser; brackets stripped above)
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h); // IPv4 dotted-quad literal
}

// screenSinkHost is the pure SEND-TIME sink classifier behind the SinkScreenVerdict observation. It parses
// the url and reports the closed verdict WITHOUT any network resolution (no DNS, no IP-pinning): a literal
// internal address/name is internal-literal, a literal public IP is public-literal, a DNS name is hostname
// (the residual rebind-exposed class), an unparseable url is url-invalid. It is the OBSERVE side of the
// dns-rebinding gap: it names what the literal screen can and cannot see, so the gap is diagnosable.
export function screenSinkHost(url: string): SinkScreenVerdict {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return "url-invalid";
  }
  if (isInternalSinkHost(host)) return "internal-literal";
  if (isIpLiteralHost(host)) return "public-literal";
  return "hostname";
}

// ChannelDeliveryResult is what a per-kind adapter returns: the best-effort delivery boolean plus, on a
// FAILURE, the closed DeliveryFailCode and (for email) a SHAPE-GATED platform error code, and (for a
// url-bearing channel) the SinkScreenVerdict of the send-time sink screen. All redaction-safe.
export interface ChannelDeliveryResult {
  ok: boolean;
  code?: DeliveryFailCode;
  platformCode?: string; // email only: the platform error code (E_UPPER_SNAKE), shape-gated + bounded, never raw text
  sinkScreen?: SinkScreenVerdict; // url channels only: the closed verdict of the send-time internal-sink screen
  // url channels only: the closed verdict of the send-time RESOLVE screen. Carried so a resolver outage
  // (resolve-unavailable, the deliberate fail-open) is distinguishable in the history from a clean resolve.
  resolvedScreen?: ResolvedSinkVerdict;
  // unconfirmed: true when the sink ACCEPTED the request for async
  // processing (JSM/Opsgenie's Alert API 202) but the outcome was not positively confirmed (no poll
  // attempted, the poll timed out/errored, or its response was ambiguous). ok stays true -- the sink DID
  // accept it, and a create/close that only ever 202s is idempotent-by-alias, so treating it as a hard
  // failure would retry-storm every tick against an inherently-async provider -- but this flag keeps the
  // record honest: "accepted" is a weaker claim than "confirmed delivered", and a bare 202 must never be
  // silently reported as a plain, no-caveat "delivered".
  unconfirmed?: boolean;
  // ackOutcome is the CLOSED verdict of the async confirmation step on an async-accepted (202)
  // delivery. It SPLITS the single `unconfirmed:true` flag into "the provider positively told us the create
  // FAILED" (async-create-failed: the alert does not exist, a real non-delivery hiding inside a delivered:true
  // row) and "we could not confirm" (confirmation-unavailable). Set by the jsm adapter only; absent for every
  // synchronous channel.
  ackOutcome?: AckOutcome;
  // On an email-recipients-invalid failure, the POSITION of the offending address in the channel's list.
  // One typo'd address kills delivery to EVERY recipient of that channel (the send is a single call), and the
  // pack could not name the bad entry. An index is an integer, never an address; it never identifies a person.
  recipientIndex?: number;
}

// sanitiseEmailPlatformCode is the redaction-safe gate for the Cloudflare Email Service error code the
// email path exposes (EmailResult.code, e.g. E_SENDER_DOMAIN_NOT_AVAILABLE). It is the one diagnostic an
// operator needs to fix send onboarding, but it must not become a channel for free text: only a bounded
// E_UPPER_SNAKE token passes (the platform's documented code shape); anything else is DROPPED. It is not a
// secret or PII (it names the onboarding gap), and the pack is an authenticated surface.
export function sanitiseEmailPlatformCode(code: unknown): string | undefined {
  return typeof code === "string" && /^E_[A-Z][A-Z0-9_]{1,46}$/.test(code) ? code : undefined;
}

// EMAIL_PLATFORM_CODE_OTHER is the ENGINE-OWNED placeholder recorded when the email platform rejected a send
// with a code that did NOT conform to the documented E_UPPER_SNAKE shape. The shape gate above is
// the redaction chokepoint and must stay strict -- a platform message is free text and could carry a
// recipient address or an internal hostname -- but DROPPING the non-conforming code entirely also erased the
// FACT that the platform sent one, so "the Email Service refused us and said something we could not verify"
// was indistinguishable from "the Email Service refused us silently". This records the fact without the text.
//
// It is deliberately spelled to CONFORM to the shape gate itself, so it survives every re-gate on the way to
// the pack (the DO's record path and the pack projection both re-run sanitiseEmailPlatformCode) with no
// change needed in either layer. It is a fixed engine constant, never a customer value.
export const EMAIL_PLATFORM_CODE_OTHER = "E_OTHER";

// emailPlatformCodeOf is the classifier the email adapter records through. It reads the platform's raw code
// ONLY to decide which CLOSED token to return -- the documented code when it passes the shape gate, the
// engine-owned E_OTHER placeholder when a code was present but non-conforming, and undefined when the
// platform sent none at all. The raw string NEVER leaves this function, so a free-text platform message
// cannot reach the delivery result, the notify history or the pack.
export function emailPlatformCodeOf(code: unknown): string | undefined {
  const gated = sanitiseEmailPlatformCode(code);
  if (gated !== undefined) return gated;
  return typeof code === "string" && code.length > 0 ? EMAIL_PLATFORM_CODE_OTHER : undefined;
}

// classifyHttpDeliveryStatus maps a non-ok HTTP status to the closed DeliveryFailCode. A redirect:"manual"
// opaque redirect surfaces as status 0, and a 3xx as 300-399; both read as http-redirect (the alert POST
// deliberately does not follow redirects). 400/401/403/429 are split out by name rather than left in a
// blanket http-4xx bucket, so "an alert never reached me" can distinguish "fix your credential" (401/403)
// from "you're throttled" (429) from "you sent a malformed request" (400) -- three operator-actionable
// classes; every remaining 4xx (not-found, method-not-allowed, ...) keeps the plain http-4xx code. The 52x
// band is decided by name below.
export function classifyHttpDeliveryStatus(status: number): DeliveryFailCode {
  if (status === 0 || (status >= 300 && status < 400)) return "http-redirect";
  if (status === 401 || status === 403) return "http-auth";
  if (status === 429) return "http-rate-limited";
  if (status === 400) return "http-bad-request";
  // 410 Gone: the sink was DEPROVISIONED. Slack/Teams/JSM answer 410 for a webhook or integration
  // that has been permanently removed, which needs a NEW integration, not a path re-check -- the residual
  // http-4xx bucket (which still carries 404 "wrong path on a live sink") could not tell the two apart.
  if (status === 410) return "http-gone";
  if (status >= 400 && status < 500) return "http-4xx";
  // THE CLASS (525/526/530 are named individually rather than left in the 5xx bucket). These statuses are
  // not the destination ANSWERING: the delivering runtime decided the fault itself and handed back a
  // synthesised status, so `fetch` RESOLVES and the throw path that classifies transport faults
  // (classifyTransportFault) never runs. Left in the 5xx bucket each one tells an operator their SIEM
  // returned a server error and sends them to the wrong team. All three sit outside the IANA range, so no
  // conforming intake answers one.
  //   525/526 -> network-tls. Against a TLS-terminating proxy this fires on a certificate fault
  //     (self-signed, expired, or a hostname mismatch); a valid chain answers its own real status instead.
  //   530 -> network-dns. This fires for an unresolvable host (RFC 6761 reserves .invalid as
  //     never-resolvable, for example), which is usually the operator's own typo rather than a genuine
  //     5xx from the vendor.
  // 520-524 and 527 deliberately STAY http-5xx: this runtime THROWS on a refused connection rather than
  // synthesising one (measured, classifyNetworkFailure's "connection lost" matcher), and each of those
  // presupposes a proxy that answered for something behind it, so "the vendor's end" stands unrefuted.
  if (status === 525 || status === 526) return "network-tls";
  if (status === 530) return "network-dns";
  if (status >= 500) return "http-5xx";
  return "http-other";
}

// Severity is the closed three-level scale routing filters on (deliver at or above a rule's
// minSeverity).
export type Severity = "info" | "warning" | "critical";

// NotifyChannel is one configured delivery destination, stored under `notify-channel:${id}`. EXACTLY
// ONE transport field is set per kind (validated by validateChannel): url for webhook/slack/teams/jsm/
// servicenow; routingKey for pagerduty; toAddresses for email (and teams-via-email). It carries no
// secret beyond what the customer's own destination needs (a Slack/Teams webhook url or a PagerDuty
// routing key is the customer's own credential to their own sink; the engine stores it as their
// config, never logs it). name is an operator label; enabled toggles delivery without deleting;
// createdAt is RFC-3339.
export interface NotifyChannel {
  id: string; // ULID; storage key `notify-channel:${id}`
  kind: ChannelKind;
  name: string; // operator label
  url?: string; // webhook | slack | teams (https, no userinfo, not workers.dev); jsm (alert-create endpoint); servicenow (em_event table endpoint)
  routingKey?: string; // pagerduty (Events API v2 routing key)
  toAddresses?: string[]; // email | teams-via-email (validated custom-domain addresses)
  // apiKey is the jsm (GenieKey token) or servicenow (HTTP Basic password) bearer credential, SEALED at
  // rest under a kind-specific domain-separated AAD (JSM_SECRET_AAD / SERVICENOW_SECRET_AAD in
  // src/admin/config-secret.ts) the same way the SIEM push destination's auth header secret is sealed:
  // the router wraps it before the DO ever sees it (the DO holds no env/wrap key), and a channel
  // adapter's deliver() unwraps it for the instant of the send. A plain string means the
  // CONFIG_WRAP_KEY-absent back-compat floor (unwrapped, matching every other secret's lazy-migration
  // behaviour); an absent apiKey on an edit is the KEEP-SECRET signal (addNotifyChannel splices in the
  // prior stored value). Unlike pagerduty's routingKey this is NEVER stored in the request body at
  // delivery time -- only in the Authorization header.
  apiKey?: string | WrappedSecret;
  // username is servicenow's HTTP Basic auth username. It is NOT a secret (an integration account
  // name), so it is never sealed and is always resupplied on every submit (like url), unlike apiKey's
  // KEEP-SECRET treatment.
  username?: string;
  // allowInternalSink opts THIS channel out of the SSRF default-deny on internal/private/loopback/
  // link-local webhook targets. Default absent/false: a url pointed at an internal IP is
  // refused at config AND send time. Set true ONLY for the rare on-prem SIEM-on-a-private-IP case; it
  // is the operator's explicit, auditable decision. It applies only to url-bearing kinds (webhook /
  // slack / teams-connector); it is meaningless for pagerduty (fixed endpoint) and email.
  allowInternalSink?: boolean;
  enabled: boolean;
  createdAt: string; // RFC-3339
}

// NotifyEmission is the internal, redaction-safe event the routing layer and the channel formatters
// consume. It is built by the emit call site from the SAME safe surface the webhook alert uses: the
// event + severity enums, the downpipe id/name (or null for an account-level event like role-change),
// a one-line redaction-safe detail, the emit time (RFC-3339), and an OPTIONAL `recovered` flag for
// the PagerDuty resolve action (a recovered backup may send resolve). It
// carries NO secret, key, value, selector or fingerprint.
export interface NotifyEmission {
  event: NotifyEvent;
  severity: Severity;
  downpipeId: string | null;
  downpipeName: string | null;
  detail: string; // redaction-safe one-liner (downpipe name + state)
  at: string; // RFC-3339 UTC millis
  recovered?: boolean; // pagerduty resolve hint (a recovered failure/stale condition)
  // AUTO-HEAL hint (replication events only): the most-behind replica's LAST replication attempt SUCCEEDED
  // (lastOk:true), so the keyless replicate pass is actively catching it up on its backlog of ALREADY-SIGNED
  // runs (a safe, self-healing catch-up, never a promotion of an unverified copy). true => "degraded/at-risk
  // but recovering on its own"; false/absent => the lagging copy is not reachable, so a human should look. It
  // is descriptive only: it never changes the proven-copy accounting or which destination a restore reads.
  catchingUp?: boolean;
}

// NOTIFY_EVENT_NAMES is the SINGLE SOURCE OF TRUTH for the closed set of notifiable engine events. The
// NotifyEvent type is derived from it (below), and the routing guards that must stay in lockstep with it
// (the DO's isNotifyEventLocal admit-guard, the NOTIFY_EVENTS rule vocabulary and severityOf) are each
// asserted against it by a structural test (validate-notify-routing.ts), so a new event added here that
// forgets one of those wirings fails CI rather than having its alert SILENTLY DROPPED at parseEmission.
// This is the AUDIT_ACTIONS -> AuditAction discipline (a const array the union is derived from and the
// runtime guard iterates, so the two can never disagree). The success-class (backup-success, restore-test-
// pass, restore-applied, role-change, canary-recovered) is info severity and digestible; the rest map to
// warning/critical (see severityOf). Defined here (a leaf) because NotifyEmission.event references it and
// the channel adapters consume NotifyEmission; notify.ts re-exports it for its callers.
export const NOTIFY_EVENT_NAMES = [
  "backup-success",
  "backup-failure",
  "backup-stale",
  // Retention's volume guard HELD a downpipe's volume high-water run: the newest runs inside the
  // keepRuns/keepDays window carry FEWER records than an older run the
  // cap would otherwise have superseded, so retention refused to evict the last FULL backup for smaller or
  // empty ones. Fired EDGE-TRIGGERED by the retention pass (once per regression episode, re-arms when the
  // volume recovers), so a persistently-emptied source pages once. Warn: no data was lost (the larger run
  // is HELD, not deleted), but a source that suddenly emptied is worth a human's eye. Redaction-safe detail
  // only (the downpipe name + the held-vs-retained record counts); never a value.
  "backup-volume-regression",
  // A configured source's binding is NO LONGER present on the engine (a deploy dropped it, or the resource
  // was deleted), so the downpipes it backs will fail their NEXT run. Fired PROACTIVELY by the scheduled
  // source-drift pass (not waiting for a run to fail), EDGE-TRIGGERED in the DO (once per detach episode,
  // re-arms when the binding returns), so a persistently-missing source pages once, not every tick. Warn:
  // backups already taken are safe (history is anchored to the downpipe, not the binding), but new data is
  // not being captured until it is re-attached, so a human should act. Redaction-safe detail only (the
  // binding name + how many downpipes it breaks + the re-attach pointer); never an id or value.
  "source-detached",
  "restore-test-pass",
  "restore-test-fail",
  "restore-applied",
  "credential-expiry",
  "posture-regression",
  "role-change",
  // A user's AUTHENTICATION credentials changed (a passkey credential was revoked, or recovery codes were
  // regenerated) - the "your sign-in details changed" signal that lets a human spot an unexpected or takeover
  // change. Warn: not necessarily an attack, but security-relevant. Redaction-safe detail only.
  "auth-credential-change",
  // A backup DESTINATION was added, repointed, removed or made default - the surface a compromised or coerced
  // owner would use to exfiltrate every future backup (repoint to an attacker bucket) or destroy proven copies
  // (force-remove). The change is already audited and dual-controllable; this is the REAL-TIME signal a human
  // needs to spot an unexpected destination change promptly. Warn. Redaction-safe detail only (who + what class
  // of change, never the endpoint, bucket or credential).
  "dest-change",
  // A successful sign-in came from a COARSE network context (IPv4 /24 or IPv6 /48 prefix) not in the account's
  // recent per-operator baseline. OFF BY DEFAULT (opt-in notifyNewSignInContext); when on, the
  // "did you just sign in from a new place?" signal that helps a human spot a takeover. Warn: not necessarily
  // an attack. Runs in the customer's OWN account against a bounded, coarse seen-set (no raw IP, no custody).
  // Redaction-safe detail ONLY (a generic one-liner); NEVER an IP, prefix, email, subject or location.
  "sign-in-new-context",
  // recovery-code break-glass (admin sign-in). recovery-code-used fires on a SUCCESSFUL recovery-code
  // sign-in (a warning: a break-glass admin sign-in just happened, so a human should know); recovery-code-
  // abuse fires on repeated/rate-limited recovery FAILURES (critical: someone is guessing a high-value
  // credential). Both carry only a redaction-safe detail (the email + a one-liner), never a code.
  "recovery-code-used",
  "recovery-code-abuse",
  // Canary backup (the on-by-default known-answer integrity flight). canary-dead fires the moment the
  // bird falls dead: a byte strayed from the exact known data, so the destination/path must not be
  // trusted for real backups until investigated (critical: evacuate the coalmine, page now). canary-
  // recovered fires when a dead bird flies clean again (info: the mine is safe to work in once more).
  // Both carry only a redaction-safe detail (which aspect drifted and by how many bytes), never a value.
  "canary-dead",
  "canary-recovered",
  // Dual control DISARMED: the second-owner-approval gate over high-blast-radius config + owner operations
  // was turned OFF (requireConfigApproval true -> false). A human must know promptly that the guarantee was
  // dropped (whether by a legitimate owner, an approved second-owner disarm, or the break-glass escape), so a
  // disarm is ALERTED, not just audited (warning: not necessarily an attack, but it weakens a control).
  // Redaction-safe detail only (who disarmed it + the path); never a secret.
  "dual-control-disabled",
  // A NEWER signed engine version is available on the configured update channel. Fired ONCE per new
  // recommended version (deduped in the DO by the last-alerted version), pull-only + signature-pinned (the
  // vendor never pushes), fail-open (a check/notify fault never blocks a backup). Carries a redaction-safe
  // detail only (the version + risk + a one-line summary + "review in the console"); NEVER a token, url or
  // hash. A new version is informational-but-actionable, so it is a warning (and never digested, it is a
  // one-shot per version, not a batchable success stream).
  "update-available",
  // An engine update was PROMOTED LIVE but its canary verification was never finished (the console was
  // closed between promote and settle), and the hourly canary has since found the now-live new version
  // UNHEALTHY. The engine cannot auto-roll-back unattended (it deliberately holds NO deploy credential,
  // no-custody), so this pages the owner that a ONE-CLICK rollback is needed now (critical: the live engine
  // version is failing its canary and only a human-supplied deploy token can revert it). Redaction-safe
  // detail only (the version + "open the console and roll back"); never a token, url or hash.
  "update-rollback-needed",
  // The proven, contiguous off-site replica count for a downpipe fell BELOW the configured copy count
  // (the 3-2-1 guarantee weakened). A copy is only counted when its segment bytes are present and verify,
  // so this fires on a genuinely-degraded copy set, not a copy still in flight (warning: the data is still
  // held by at least one copy, but the configured redundancy is not currently met). Redaction-safe detail
  // only (the downpipe name + configured/proven copy counts); never a destination secret, key or value.
  "replication-degraded",
  // A run is about to age OUT of the fixed 50-run history ring while a replica still lacks its segment
  // bytes: once evicted, that run can no longer be reconciled to the lagging copy, so the window to
  // restore the configured redundancy for that run is closing (warning by default; the DO may RAISE it to
  // critical when eviction would leave only a single proven copy, see severityOf). Redaction-safe detail
  // only (the downpipe name + which run is at risk + the copy count); never a destination secret or value.
  "run-at-risk-eviction",
] as const;

// NotifyEvent is the closed set of notifiable engine events, DERIVED from NOTIFY_EVENT_NAMES so the
// compile-time union and the runtime list can never drift apart.
export type NotifyEvent = (typeof NOTIFY_EVENT_NAMES)[number];

// EVENT_EMOJI is a small, fixed, redaction-safe glyph per severity for the Slack/Teams text. It is
// cosmetic only and carries no data; kept here so Slack and Teams agree.
export function severityEmoji(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "\u{1F534}"; // red circle
    case "warning":
      return "\u{1F7E0}"; // orange circle
    case "info":
      return "\u{1F7E2}"; // green circle
  }
}

// classifyReplication is the PURE detector behind the "replication-degraded" event. Given a
// downpipe's configured copy count (the 3-2-1 target) and the number of copies whose segment bytes are
// PROVEN present (verified, contiguous), it reports whether redundancy is currently degraded. It is
// degraded when fewer copies are proven than configured. It carries no storage and no I/O so it is
// unit-testable; the emit wiring supplies the counts and the DO decides whether to fire. A
// non-positive or non-integer configured count is treated as "not degraded" (a misconfiguration must
// not cry wolf). provenCopies is clamped at zero.
// The non-positive / non-integer arm below must not SILENTLY SWITCH THE WHOLE DETECTOR OFF: a corrupt copy
// count that simply returned degraded:false would report healthy with no event, log or posture check ever
// firing, losing a lost replica entirely. Not crying wolf is right; doing it INVISIBLY would be the bug.
// copyCountInvalid is the flag the DO turns into the closed `replication-copy-count-invalid` counter. The
// raw configured value never rides (only the fact it was bad).
export function classifyReplication(input: { configuredCopies: number; provenCopies: number }): { degraded: boolean; copyCountInvalid: boolean } {
  const configured = input.configuredCopies;
  if (!Number.isInteger(configured) || configured <= 0) return { degraded: false, copyCountInvalid: true };
  const proven = Number.isInteger(input.provenCopies) && input.provenCopies > 0 ? input.provenCopies : 0;
  return { degraded: proven < configured, copyCountInvalid: false };
}

// isRunEvictionRisk is the PURE detector behind the "run-at-risk-eviction" event. The run history is a
// fixed-size ring (50 runs); once the ring is at capacity the OLDEST run (the lowest live index, headIndex)
// is the next to be evicted. A run is at risk when the ring is at capacity AND a replica still lacks the
// run that is at (or before) the head, i.e. the lagging copy's holdsIndex is below the head that is about
// to roll off. When the ring is NOT at capacity nothing is being evicted yet, so there is no risk. The DO
// supplies headIndex (the oldest live run index) and holdsIndex (the oldest run a lagging replica still
// holds); both are leaf inputs, no storage or I/O. ringAtCap is the DO's own at-capacity verdict.
export function isRunEvictionRisk(input: { ringAtCap: boolean; headIndex: number; holdsIndex: number }): { atRisk: boolean } {
  if (!input.ringAtCap) return { atRisk: false };
  return { atRisk: input.holdsIndex < input.headIndex };
}

// canonicalWebhookHost normalises a URL hostname for the name-based screens: it lowercases (the URL
// parser already does, but be explicit) and strips a single trailing dot, so a fully-qualified
// "localhost." (which resolves to 127.0.0.1) is screened the same as "localhost", and an IPv6 literal
// keeps its brackets removed by the caller. This mirrors oidc-verify.ts's canonicalHost so the two
// SSRF screens normalise identically.
function canonicalWebhookHost(hostname: string): string {
  const h = hostname.toLowerCase();
  return h.endsWith(".") ? h.slice(0, -1) : h;
}

// isInternalSinkHost is the SSRF default-deny classifier. It returns true when a webhook
// host resolves, by its LITERAL spelling, to an address that must not be reached from the Cloudflare
// edge without an explicit operator opt-in: loopback, RFC1918 private space, link-local (including the
// 169.254.169.254 cloud-metadata IP), IPv6 unique-local / link-local, or an obviously-internal
// hostname (localhost / *.localhost). The URL parser has already collapsed obfuscated IPv4 spellings
// (decimal 2130706433, hex 0x7f000001, octal, IPv4-mapped IPv6) to their canonical dotted-quad before
// this runs, so a single dotted-quad / bracketed-IPv6 check covers those bypasses (the same technique
// oidc-verify.ts relies on).
//
// LIMITATION (DNS rebinding, follow-up): a hostname that DNS-RESOLVES to an internal IP is NOT caught
// here, that needs resolve-then-pin at send time, which is a deeper change. This blocks the literal
// internal IPs and the obvious internal names now; the rebind gap is documented as a follow-up.
// canonicaliseBareHost satisfies isInternalSinkHost's stated precondition for a host that never went
// through a URL parser. Every caller above it takes its host from `new URL(...).hostname`, which has
// already collapsed the obfuscated IPv4 spellings. The syslog sink does not: its host is a bare
// hostname an operator types into a form, so it reaches the classifier exactly as typed.
//
// Canonicalising first matters because numeric IPv4 spellings resolve to a real address by ordinary
// getaddrinfo behaviour, not an exotic trick: decimal 2852039166, hex 0x7f000001, dotted-decimal 127.1
// and octal 017700000001 all resolve the way `dns.lookup` resolves them (2852039166 IS 169.254.169.254,
// the cloud-metadata address; the other three are all 127.0.0.1). Screening a bare host without
// canonicalising first is therefore a screen with a hole in it, which is worse than no screen because it
// reads as covered.
//
// Parsing is the canonicaliser rather than a hand-rolled table: the URL parser is the thing that defines
// what an address spelling means, and a table would drift from it.
export function canonicaliseBareHost(host: string): string {
  const bare = host.startsWith("[") || !host.includes(":") ? host : host.split(":")[0]!;
  try {
    return new URL(`https://${bare}`).hostname;
  } catch {
    // An unparseable host cannot be canonicalised, so it is returned unchanged and the classifier judges
    // the literal. A caller must still refuse anything it cannot make sense of.
    return bare;
  }
}

export function isInternalSinkHost(hostname: string): boolean {
  let h = canonicalWebhookHost(hostname);
  // Obvious internal hostnames (no IP at all).
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  // IPv6 literal: the URL parser brackets it. Strip the brackets to inspect the address.
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.includes(":")) {
    // IPv6. Loopback ::1; unspecified ::; link-local fe80::/10; unique-local fc00::/7. Lowercased.
    if (h === "::1" || h === "::") return true;
    // IPv4-mapped (::ffff:a.b.c.d) must re-check the embedded v4 so an internal v4 cannot ride in
    // mapped. The URL parser COLLAPSES the dotted-quad to the canonical hex form (::ffff:a00:1), so
    // accept BOTH spellings: the literal dotted-quad and the two trailing hextets that encode it.
    const mappedDotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(h);
    if (mappedDotted) return isInternalIpv4(mappedDotted[1]!);
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1]!, 16);
      const lo = parseInt(mappedHex[2]!, 16);
      const quad = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isInternalIpv4(quad);
    }
    if (h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) return true; // fe80::/10
    if (h.startsWith("fc") || h.startsWith("fd")) return true; // fc00::/7 unique-local
    return false;
  }
  // IPv4 dotted-quad. A bare host that is not an IP falls through to false (it is a domain name).
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return isInternalIpv4(h);
  return false;
}

// isInternalIpv4 returns true for a dotted-quad in a loopback / private / link-local / carrier-NAT range:
// 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (incl. 169.254.169.254 the
// cloud-metadata IP), 100.64.0.0/10 (RFC 6598 carrier-grade-NAT shared space, which some clouds also use
// for internal metadata/service endpoints), 0.0.0.0/8 (this-host). Each octet must be 0..255 or the value
// is not a real IPv4 literal and is treated as not-internal (it will fail elsewhere as a malformed host).
function isInternalIpv4(quad: string): boolean {
  const parts = quad.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts as [number, number, number, number];
  if (a === 127) return true; // loopback
  if (a === 10) return true; // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 cloud metadata
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 carrier-grade NAT (RFC 6598 shared space)
  if (a === 0) return true; // 0.0.0.0/8 this-host
  return false;
}

// WEBHOOK_TIMEOUT_MS bounds the outbound POST so a slow or hanging customer endpoint cannot stall the
// reconciliation tick. On timeout the POST is abandoned (fail-open); the alert is simply not
// delivered this tick and the next transition or cooldown window will try again.
// ResolvedSinkVerdict is the CLOSED vocabulary of the send-time RESOLVE screen, the half that sees what a
// hostname actually points at. screenSinkHost classifies the literal spelling and returns "hostname" when
// the target is a name, which is precisely the case its own comment records as the DNS-rebinding residual:
// a name that resolves to 169.254.169.254 is spelled like any other name. This screen resolves the name and
// judges the ADDRESSES.
//
// WHAT THIS CLOSES AND WHAT IT DOES NOT. It closes the case that matters in practice: a webhook stored
// while its name resolved somewhere public, later repointed at private space, is now refused at send time
// rather than delivered to. It does NOT make the target un-rebindable, because Workers offers no way to pin
// a resolved address for the fetch that follows: fetch resolves the name again itself. So an attacker who
// can flip a record between our lookup and the runtime's, against Cloudflare's own resolver cache, still has
// a race. The exposure goes from "store a name, repoint it, wait" to "win that race", which is a different
// class of attack, and the residual is disclosed rather than described as closed.
export type ResolvedSinkVerdict =
  | "resolved-public" // every address the name returned is public
  | "resolved-internal" // at least one address is internal: the delivery is refused
  | "resolve-unavailable"; // no answer was obtained, so this screen has nothing to say

export const RESOLVED_SINK_VERDICTS: ReadonlySet<string> = new Set<ResolvedSinkVerdict>([
  "resolved-public", "resolved-internal", "resolve-unavailable",
]);

// The resolver this screen asks. A fixed public DoH endpoint, never customer-supplied, so this lookup can
// never itself become the SSRF it exists to prevent.
// The base URL lives in src/lib/outbound.ts (the one place vendor hosts are enumerated).
// The resolve screen is a guard in front of a 5s delivery, not the delivery, so it gets its own smaller
// budget and can never double the time a send takes.
export const SINK_RESOLVE_TIMEOUT_MS = 2000;

// screenResolvedIfHostname is the resolve screen as the bespoke senders call it (SIEM HTTP push, OTLP push,
// JSM): the same decision deliverPayload makes inline, exposed so those three cannot drift from it. A
// "hostname" literal verdict is the only case worth a lookup; a literal was already judged and the
// per-channel internal opt-in has already answered the question. Refuses on a resolved-internal answer,
// and hands back the verdict so the caller can carry it the way it carries sinkScreen.
export async function screenResolvedIfHostname(
  url: string,
  sinkScreen: SinkScreenVerdict,
  allowInternal: boolean,
  fetchImpl: typeof fetch = fetch,
): Promise<{ refused: boolean; resolvedScreen?: ResolvedSinkVerdict }> {
  if (allowInternal || sinkScreen !== "hostname") return { refused: false };
  const r = await screenResolvedSinkHost(new URL(url).hostname, fetchImpl);
  return { refused: r.verdict === "resolved-internal", resolvedScreen: r.verdict };
}

// screenResolvedSinkHost resolves `hostname` over DoH and classifies every A/AAAA answer.
//
// FAIL-OPEN ON NO ANSWER, FAIL-CLOSED ON A BAD ANSWER, and the asymmetry is deliberate. A resolver that is
// unreachable or answers nothing tells us nothing, and refusing every webhook in that window would turn a
// resolver blip into an outage of the customer's own alerting, which is a denial of service we would have
// built ourselves. An answer that CONTAINS an internal address is information, and it refuses. The
// "resolve-unavailable" verdict is recorded rather than swallowed, so a reviewer can see when this screen
// abstained instead of assuming it passed.
export async function screenResolvedSinkHost(
  hostname: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ verdict: ResolvedSinkVerdict; addresses: string[] }> {
  const name = canonicaliseBareHost(hostname);
  // An IP literal has nothing to resolve; the literal screen has already judged it.
  if (isIpLiteralHost(name)) {
    return { verdict: isInternalSinkHost(name) ? "resolved-internal" : "resolved-public", addresses: [name] };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SINK_RESOLVE_TIMEOUT_MS);
  try {
    const addresses: string[] = [];
    // A and AAAA are asked separately because the json API takes one type per query. Both are needed: a
    // name that answers a public A and an internal AAAA is internal.
    for (const type of ["A", "AAAA"]) {
      const resp = await fetchImpl(`${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`, {
        redirect: "manual",
        headers: { accept: "application/dns-json" },
        signal: controller.signal,
      });
      if (!resp.ok) continue;
      const body = (await resp.json()) as { Answer?: { type?: number; data?: string }[] };
      for (const ans of body.Answer ?? []) {
        // 1 = A, 28 = AAAA. Every other record in the chain (CNAME, and the rest) is not an address.
        if ((ans.type === 1 || ans.type === 28) && typeof ans.data === "string") addresses.push(ans.data);
      }
    }
    if (addresses.length === 0) return { verdict: "resolve-unavailable", addresses: [] };
    // isInternalSinkHost takes a url hostname, so an IPv6 answer is bracketed the way the URL parser
    // would have bracketed it.
    const internal = addresses.some((a) => isInternalSinkHost(a.includes(":") ? `[${a}]` : a));
    return { verdict: internal ? "resolved-internal" : "resolved-public", addresses };
  } catch {
    // A timeout or a transport failure is an abstention, not a pass and not a refusal.
    return { verdict: "resolve-unavailable", addresses: [] };
  } finally {
    clearTimeout(timer);
  }
}

// screenEgressAllowlist is the shared operator-allowlist decision: given a host and the
// account's configured egressAllowlist, it reports whether the engine is permitted to reach it.
//
//   - a FIXED vendor host by EXACT match (isFixedEgressHostExact: api.cloudflare.com, cloudflare-dns.com,
//     update.downpipes.io, login.microsoftonline.com) is ALWAYS permitted. These are hosts the engine
//     reaches on its own initiative, never a customer-chosen destination, so the operator's list -- which
//     governs what THEY configured the engine to talk to -- does not gate them. This deliberately checks
//     the EXACT set only, never isFixedEgressHost's wildcard suffixes (.amazonaws.com, .cloudflareaccess.com,
//     .cloudflarestream.com): those suffixes carry a customer- or attacker-namespaced left-most label, and
//     the host screened here is the customer's own typed notify-channel url, so treating the whole suffix as
//     always-permitted would let a channel pointed at another tenant's subdomain of one of these suffixes
//     bypass an operator-configured egressAllowlist entirely.
//   - an UNSET or EMPTY allowlist permits every host: an account that has not configured one reaches any
//     public https host from its notify channels.
//   - a SET, non-empty allowlist permits only an EXACT match on one of its entries, or a match against a
//     single-label wildcard entry ("*.suffix") on a DOTTED SUFFIX boundary: "*.pagerduty.com" matches
//     "events.pagerduty.com" but never "notpagerduty.com" or "pagerduty.com.evil" (a plain substring test
//     would pass both of those; this never uses one).
//
// It is independent of the internal-sink SSRF deny screen (isInternalSinkHost) and of allowInternal: a
// private host still needs BOTH the allowlist match and the per-channel internal-sink opt-in, and an
// allowlisted PUBLIC host is still subject to the internal-sink screen (which it will simply pass, being
// public). The two controls answer different questions -- "is this host safe to reach at all" versus "did
// the operator say this application may talk to it" -- and neither substitutes for the other.
export function screenEgressAllowlist(host: string, allowlist: readonly string[] | undefined): boolean {
  const h = canonicalWebhookHost(host);
  if (isFixedEgressHostExact(h)) return true;
  if (allowlist === undefined || allowlist.length === 0) return true;
  for (const entry of allowlist) {
    if (entry.startsWith("*.")) {
      const suffix = entry.slice(1); // ".suffix"
      if (h.length > suffix.length && h.endsWith(suffix)) return true;
    } else if (h === entry) {
      return true;
    }
  }
  return false;
}

// EGRESS_ALLOWLIST_MAX_ENTRIES / EGRESS_ALLOWLIST_ENTRY_MAX_CHARS bound the operator-configured egress
// allowlist at the authority boundary (setEgressAllowlist), well above any realistic
// configuration, so a malformed or adversarial submission cannot store an unbounded array or field.
export const EGRESS_ALLOWLIST_MAX_ENTRIES = 64;
export const EGRESS_ALLOWLIST_ENTRY_MAX_CHARS = 253; // the DNS name length ceiling (RFC 1035)

// HOSTNAME_LABEL_RE is one dot-separated DNS label: a letter or digit, optionally followed by more
// letters/digits/hyphens ending in a letter or digit (RFC 1035, the same shape a real hostname label takes).
const HOSTNAME_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

// normaliseEgressAllowlistEntry validates and lowercases ONE allowlist entry: a canonical hostname, or a
// single-label wildcard prefix "*.suffix" whose suffix is itself a canonical hostname. Refuses a scheme, a
// port, userinfo, an IP literal (an allowlist entry names a NAME the operator chose, not an address; a
// literal IP is validated the same way the internal-sink screen already validates one, at send time,
// against the resolved address), or a value outside the length/shape bounds. The offending value rides in
// the reason (bounded to 40 chars) so a rejection is actionable; it is the operator's own typed host, never
// a secret.
export function normaliseEgressAllowlistEntry(raw: string): { ok: true; entry: string } | { ok: false; reason: string } {
  const trimmed = raw.trim().toLowerCase();
  const shown = trimmed.slice(0, 40);
  if (trimmed.length === 0) return { ok: false, reason: "an allowlist entry must not be empty" };
  if (trimmed.length > EGRESS_ALLOWLIST_ENTRY_MAX_CHARS) {
    return { ok: false, reason: `an allowlist entry must be at most ${EGRESS_ALLOWLIST_ENTRY_MAX_CHARS} characters: ${shown}` };
  }
  const isWildcard = trimmed.startsWith("*.");
  const hostPart = isWildcard ? trimmed.slice(2) : trimmed;
  if (hostPart.length === 0 || hostPart.includes("://") || hostPart.includes("@") || hostPart.includes(":") || hostPart.includes("/") || hostPart.includes("*")) {
    return { ok: false, reason: `an allowlist entry must be a plain hostname or a "*.suffix" wildcard, with no scheme, port or userinfo: ${shown}` };
  }
  if (isIpLiteralHost(hostPart)) return { ok: false, reason: `an allowlist entry must not be an IP literal: ${shown}` };
  const labels = hostPart.split(".");
  if (!labels.every((l) => HOSTNAME_LABEL_RE.test(l))) return { ok: false, reason: `an allowlist entry must be a valid hostname: ${shown}` };
  return { ok: true, entry: trimmed };
}

// validateEgressAllowlist validates a full submitted allowlist at the authority boundary (setEgressAllowlist):
// a list of at most EGRESS_ALLOWLIST_MAX_ENTRIES strings, each a valid entry per normaliseEgressAllowlistEntry.
// Duplicates are silently de-duplicated (not refused: a repeated entry is not a shape error), preserving first
// occurrence order.
export function validateEgressAllowlist(raw: unknown): { ok: true; hosts: string[] } | { ok: false; reason: string } {
  if (!Array.isArray(raw)) return { ok: false, reason: "egressAllowlist must be a list of hostnames" };
  if (raw.length > EGRESS_ALLOWLIST_MAX_ENTRIES) return { ok: false, reason: `egressAllowlist must have at most ${EGRESS_ALLOWLIST_MAX_ENTRIES} entries` };
  const hosts: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (typeof item !== "string") return { ok: false, reason: "each allowlist entry must be a string" };
    const v = normaliseEgressAllowlistEntry(item);
    if (!v.ok) return v;
    if (seen.has(v.entry)) continue;
    seen.add(v.entry);
    hosts.push(v.entry);
  }
  return { ok: true, hosts };
}

export const WEBHOOK_TIMEOUT_MS = 5000;

// deliverPayload is the generalised fail-open POST the url/routingKey channel adapters use, so a
// channel can POST a PROVIDER-SPECIFIC body (Slack blocks, a PagerDuty
// Events API v2 envelope, the generic webhook v1 body) with one hygiene discipline:
// a 5s AbortController timeout, redirect:"manual", and ALL errors swallowed into a
// returned { ok:false }. It NEVER throws. The url is the channel's own validated destination (already
// passed isAllowedWebhookUrl at store time); a routing-key channel POSTs to a FIXED provider endpoint
// the adapter supplies, not a customer url.
//
// SSRF defence in depth: a customer url is RE-CHECKED here against the internal-address
// deny-list at SEND time, not only at config time, so an internal target can never be POSTed to even
// if a channel were persisted by a path that bypassed isAllowedWebhookUrl (a future route, a migration,
// a hand-edited storage value). allowInternal defaults FALSE; a channel that explicitly opted in passes
// true, and a FIXED provider endpoint (PagerDuty) passes true because the adapter, not the customer,
// chose that host. A blocked send is a fail-open non-delivery (ok:false), consistent with every other
// best-effort webhook failure, and never throws.
//
// extraHeaders lets a channel that authenticates via a header (jsm's `Authorization: GenieKey <token>`,
// servicenow's `Authorization: Basic <user:pass>`) ride the SAME hardened POST (timeout, redirect:
// "manual", the send-time SSRF re-screen, the closed failure classification) without the credential
// ever touching the JSON body: it is merged into the request headers alongside content-type, never
// serialised into `payload`. Every existing call site (webhook/slack/teams/pagerduty, none of which
// need a custom header) is unaffected by the optional 4th parameter.
//
// egressAllowlist is the account's configured operator allowlist, threaded in by the caller
// (a channel adapter passes the customer's OWN account setting; PagerDuty's fixed provider endpoint passes
// nothing, so its call is never subject to an allowlist the operator never configured it against). It is
// checked independently of allowInternal: see screenEgressAllowlist for why an allowlisted private host
// still needs the internal-sink opt-in too.
export async function deliverPayload(
  url: string,
  payload: unknown,
  allowInternal = false,
  extraHeaders?: Record<string, string>,
  fetchImpl: typeof fetch = fetch,
  egressAllowlist?: readonly string[],
): Promise<{ ok: boolean; status?: number; code?: DeliveryFailCode; sinkScreen?: SinkScreenVerdict; resolvedScreen?: ResolvedSinkVerdict | undefined }> {
  // OBSERVE the send-time sink screen verdict FIRST, independent of whether the
  // POST then succeeds, so the delivery result always carries what the literal screen concluded about the
  // host (internal-literal / public-literal / hostname / url-invalid). A `hostname` verdict is the residual
  // rebind exposure the literal screen cannot see through; the caller surfaces it on the history entry.
  const sinkScreen = screenSinkHost(url);
  // The egress allowlist gate, checked BEFORE and INDEPENDENTLY of the internal-sink deny below:
  // a private host opted into via allowInternalSink still needs to be on the list too, and a public host
  // needs to be on the list regardless of allowInternal. Skipped only when the url itself did not parse
  // (screenSinkHost already reports that as url-invalid, handled below).
  if (sinkScreen !== "url-invalid" && !screenEgressAllowlist(new URL(url).hostname, egressAllowlist)) {
    return { ok: false, code: "egress-not-allowlisted", sinkScreen: "not-allowlisted" };
  }
  // Re-screen the host. A malformed url (should be impossible post-validation) or an internal target
  // without the opt-in is a non-delivery, mirroring the fail-open contract of a network failure. The
  // CLOSED code names WHICH so the pack can tell an SSRF default-deny (an internal sink) from a bad url.
  let resolvedScreen: ResolvedSinkVerdict | undefined;
  if (!allowInternal) {
    if (sinkScreen === "url-invalid") return { ok: false, code: "url-invalid", sinkScreen };
    if (sinkScreen === "internal-literal") return { ok: false, code: "internal-sink-blocked", sinkScreen };
    // A "hostname" verdict is the one the literal screen cannot see through, so it is the only case worth
    // paying a resolve for. A public IP literal is un-rebindable and already settled.
    if (sinkScreen === "hostname") {
      const resolved = await screenResolvedSinkHost(new URL(url).hostname, fetchImpl);
      resolvedScreen = resolved.verdict;
      if (resolved.verdict === "resolved-internal") {
        return { ok: false, code: "internal-sink-resolved", sinkScreen, resolvedScreen };
      }
    }
  }
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, WEBHOOK_TIMEOUT_MS);
  try {
    const resp = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...extraHeaders },
      body: JSON.stringify(payload),
      signal: controller.signal,
      redirect: "manual",
    });
    const ok = resp.ok;
    const status = resp.status;
    // Release the underlying connection. An unconsumed response body holds the TCP connection open in
    // the Worker/DO runtime until exit, so cancel it once we have read ok/status.
    void resp.body?.cancel();
    // On a non-2xx, classify the status into the closed vocabulary (a redirect / 4xx / 5xx) so the pack can
    // tell "the customer's sink returned an error" from "we never reached it". The RAW body is never read.
    if (ok) return { ok, status, sinkScreen, resolvedScreen };
    return { ok, status, code: classifyHttpDeliveryStatus(status), sinkScreen, resolvedScreen };
  } catch (e) {
    // A thrown fetch is a timeout (we aborted at the send timeout) or a transport failure. The transport
    // fault is coarsened to its CLOSED sub-cause (dns / tls / reset / other) at this site, so the
    // exception text is classified and DISCARDED here and can never ride onwards.
    return { ok: false, code: timedOut ? "timeout" : classifyNetworkFailure(e), sinkScreen, resolvedScreen };
  } finally {
    clearTimeout(timer);
  }
}

// isAllowedWebhookUrl validates a customer-supplied webhook url at the authority boundary, the same
// discipline validateConfig applies to a downpipe id. It enforces:
//  - it parses as a URL;
//  - the scheme is https (so the alert, which carries the customer's own downpipe ids/names, is not
//    sent in cleartext; http is rejected);
//  - the url carries no userinfo (username or password component). A userinfo-bearing webhook sink is
//    never legitimate: RFC 3986 allows user@host syntax but modern browsers and proxies treat it as a
//    phishing or host-spoof vector, and no real PagerDuty/Slack/SIEM ingest URL carries credentials
//    in the authority (they use path tokens or body fields). Rejecting userinfo closes a class of
//    confusion attacks without any cost to a legitimate customer;
//  - the host is NOT a *.workers.dev address (house rule: never a workers.dev endpoint; customers
//    point alerts at a real custom-domain sink, and rejecting workers.dev also blocks an accidental
//    loopback to a Worker preview);
//  - the host is NOT an internal/private/loopback/link-local target (SSRF default-deny),
//    UNLESS opts.allowInternalSink is set. By default a webhook pointed at 127.x / 10.x / 172.16-31.x /
//    192.168.x / 169.254.x (incl. the 169.254.169.254 cloud-metadata IP) / ::1 / fc00::/7 / fe80::/10 /
//    localhost is REFUSED, so a misconfigured or hostile channel cannot turn the engine into a confused
//    deputy that POSTs to a metadata endpoint or an internal service. The override is the rare on-prem
//    SIEM-on-a-private-IP case: an operator who genuinely runs their sink on a private address opts in
//    per channel (allowInternalSink:true), making the decision explicit and auditable.
// It returns a typed verdict so the route can map a rejection to a 400 with a precise reason. The
// destination is the CUSTOMER's own endpoint and the payload is already their own redaction-safe data,
// but default-deny on internal targets removes the SSRF foot-gun while keeping the explicit-opt-in
// escape hatch for legitimate private-network deployments.
//
// Every rejection carries a CLOSED code (WEBHOOK_REJECT_CODES) beside the operator-facing sentence. The
// sentence goes to the browser; the CODE is what the engine records, so the pack can say WHICH validator is
// refusing a customer who is stuck saving their channel. The submitted URL never rides anywhere.
//
// opts.egressAllowlist is the account's CURRENT configured allowlist, when the caller has one
// to check against (validateChannel is a pure function called from a config-mutation authority that DOES hold
// the account's stored value; a caller with none omits it, and screenEgressAllowlist then permits every
// host). Checked AFTER every other screen: a url that is malformed, carries
// userinfo, or names workers.dev/an unopted-in internal host is refused for that reason first, so the
// allowlist rejection is reported only for a url that would otherwise have been accepted.
export function isAllowedWebhookUrl(
  raw: unknown,
  opts?: { allowInternalSink?: boolean; egressAllowlist?: readonly string[] },
): { ok: true; url: string } | { ok: false; reason: string; code: WebhookRejectCode } {
  if (typeof raw !== "string" || raw.trim().length === 0) return { ok: false, reason: "url is required", code: "unparseable" };
  const trimmed = raw.trim();
  if (trimmed.length > 2048) return { ok: false, reason: "url is too long", code: "too-long" };
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return { ok: false, reason: "url must be a valid absolute URL", code: "unparseable" };
  }
  if (u.protocol !== "https:") return { ok: false, reason: "url must be https", code: "non-https" };
  // Reject userinfo (username or password in the authority component). The URL parser populates
  // u.username / u.password; an empty string means absent. A credentials-bearing URL enables
  // host-spoof confusion attacks and is never a legitimate alert sink.
  if (u.username !== "" || u.password !== "") {
    return { ok: false, reason: "url must not carry userinfo (username or password); use a path token on your endpoint instead", code: "userinfo" };
  }
  // Reject workers.dev (and any subdomain of it). hostname is already lowercased by the URL parser.
  const host = u.hostname;
  if (host === "workers.dev" || host.endsWith(".workers.dev")) {
    return { ok: false, reason: "workers.dev endpoints are not allowed; use a custom domain", code: "workers-dev" };
  }
  // SSRF default-deny: refuse an internal/private/loopback/link-local target unless the channel
  // explicitly opted in. This is the config-time half of the defence; deliverPayload re-checks at
  // send time (defence in depth), so a stored channel can never POST to an internal IP on a code path
  // that bypassed this boundary.
  if (opts?.allowInternalSink !== true && isInternalSinkHost(host)) {
    return {
      ok: false,
      reason:
        "url points at a private/loopback/link-local address (incl. cloud metadata); these are refused by default. If your sink really is on a private network, enable the per-channel internal-sink override.",
      code: "internal-no-optin",
    };
  }
  // The operator egress allowlist, checked last: a url that would otherwise be accepted is
  // refused when the account has configured a list and this host is not on it (and is not a fixed vendor
  // host, which screenEgressAllowlist always permits).
  if (!screenEgressAllowlist(host, opts?.egressAllowlist)) {
    return {
      ok: false,
      reason: "url's host is not on the account's configured outbound egress allowlist",
      code: "not-allowlisted",
    };
  }
  return { ok: true, url: trimmed };
}


// DigestPeriod is the non-off batching cadence of a digest rule (the values that actually defer a
// success-class event; "off" is not a digest). Kept distinct from NotifyRule["digest"] so the flush
// path (which only ever sees deferred entries) cannot carry "off". It lives in this leaf so both the
// routing module (which records the period on a deferral) and the digest-flush module (which applies
// the per-period window) import it without depending on each other.
export type DigestPeriod = "daily" | "weekly";
