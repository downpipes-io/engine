// The ServiceNow Event Management channel adapter (contract section 2.2). ServiceNow's Event
// Management module ingests a POST to the em_event table API; its correlation engine (Event Rules)
// groups events sharing a message_key into ONE Alert, and a later event on the same message_key with a
// LOWER severity updates (at severity 0, CLEARS) that Alert. Unlike PagerDuty/JSM there is no separate
// close endpoint: "closing" IS posting another em_event with severity 0 and the same message_key, so
// create and recover share this same POST shape, varying only severity/description.
//
// HONEST SCOPE (do not overclaim): reaching severity 0 clears the ALERT. Whether that Alert's associated
// INCIDENT (if any) auto-closes is governed by the customer's own ITOM/Event Management business rules
// (their "auto-close incident on alert-clear" property) -- a customer-side ServiceNow configuration
// choice, not something this engine controls or guarantees. Operator-facing copy must say so too.
//
// AUTH: HTTP Basic (username + password); the password rides ONLY in the Authorization header, NEVER
// the body. The password is sealed at rest under SERVICENOW_SECRET_AAD (src/admin/config-secret.ts),
// domain-separated from every other secret class the engine seals (including jsm's own token), and is
// decrypted here, in the Worker, only for the instant of the POST.
//
// SEVERITY: ServiceNow Event Management's scale is 0=Clear, 1=Critical, 2=Major, 3=Minor, 4=Warning,
// 5=Info (0 is the BEST outcome, the reverse of our scale where higher is worse -- ServiceNow's own
// documented scale, not a choice made here). A recovered emission always sends 0 (Clear); otherwise
// critical -> 1, warning -> 4, info -> 5 (2/Major and 3/Minor are headroom ServiceNow itself reserves
// for a human to hand-adjust).
//
// REDACTION: the event body carries only the emission's safe surface (event/severity enums, the
// downpipe name + state one-liner, the message_key); never a secret, key, value or fingerprint.
// FAIL-OPEN: deliver never throws (deliverPayload swallows all send-time failures; the secret-resolve
// step below is wrapped in its own try/catch so an undecryptable/rotated wrap key degrades to a clean
// non-delivery rather than an unhandled rejection).

import { loadConfigWrapKey, resolveConfigSecret, SERVICENOW_SECRET_AAD } from "../../admin/config-secret.ts";
import type { Env } from "../../env.d.ts";
import type { ChannelDeliveryResult, NotifyChannel, NotifyEmission } from "../types.ts";
import { deliverPayload } from "../types.ts";

// ServiceNowSeverity is ServiceNow Event Management's closed 0..5 scale (see the module comment above
// for the full mapping).
export type ServiceNowSeverity = 0 | 1 | 2 | 3 | 4 | 5;

// servicenowSeverity maps our three-level severity (plus the recovered hint) to ServiceNow's 0..5 scale.
// A recovered emission ALWAYS maps to 0 (Clear) regardless of its nominal severity, auto-clearing the
// Alert; otherwise critical -> 1, warning -> 4, info -> 5.
export function servicenowSeverity(emission: NotifyEmission): ServiceNowSeverity {
  if (emission.recovered === true) return 0;
  switch (emission.severity) {
    case "critical":
      return 1;
    case "warning":
      return 4;
    case "info":
      return 5;
  }
}

// servicenowMessageKey derives the STABLE dedup key ServiceNow's correlation engine groups events on,
// mirroring pagerdutyDedupKey/jsmAlias exactly (the same downpipe id + event scoping), so an operator
// running multiple incident channels sees an identical correlation shape across all three.
export function servicenowMessageKey(emission: NotifyEmission): string {
  return emission.downpipeId !== null ? `downpipe:${emission.downpipeId}:${emission.event}` : `account:${emission.event}`;
}

const SERVICENOW_SOURCE = "downpipes";

// ServiceNowEventPayload is the em_event table API body (the fields Event Management's default field
// mapping reads). node is the redaction-safe source label (the downpipe name, or "downpipe"); resource
// is the event enum; metric_name distinguishes our events from another integration's on the same
// instance.
export interface ServiceNowEventPayload {
  source: string;
  node: string;
  resource: string;
  metric_name: string;
  severity: ServiceNowSeverity;
  description: string;
  message_key: string;
}

// format renders the em_event body from the emission's safe surface.
export function format(emission: NotifyEmission): ServiceNowEventPayload {
  return {
    source: SERVICENOW_SOURCE,
    node: emission.downpipeName ?? "downpipe",
    resource: emission.event,
    metric_name: `downpipe.${emission.event}`,
    severity: servicenowSeverity(emission),
    description: emission.detail,
    message_key: servicenowMessageKey(emission),
  };
}

// EM_JSONV2_PATH_MARKER identifies ServiceNow's OTHER documented Event Management intake,
// /api/global/em/jsonv2 (ServiceNow's own tutorials teach this path), which wants the event wrapped in a
// {records:[...]} envelope -- distinct from the Table API's flat em_event body (/api/now/table/em_event)
// this adapter otherwise targets (item 11, HARDENING.md).
const EM_JSONV2_PATH_MARKER = "em/jsonv2";

// EmJsonV2Envelope is the jsonv2 intake's wrapper: the SAME event shape as the Table API, just wrapped in
// a single-element records array.
export interface EmJsonV2Envelope {
  records: ServiceNowEventPayload[];
}

// buildServiceNowBody wraps the event for the em/jsonv2 intake when the configured url's PATH contains
// EM_JSONV2_PATH_MARKER, or returns the flat em_event Table API body otherwise (the default, and the
// documented shape for /api/now/table/em_event). The url has already been SSRF/https-validated at config
// time (isAllowedWebhookUrl), so it always parses; a defensive substring fallback covers the
// should-be-impossible case where it somehow does not.
export function buildServiceNowBody(url: string, event: ServiceNowEventPayload): ServiceNowEventPayload | EmJsonV2Envelope {
  let path: string;
  try {
    path = new URL(url).pathname;
  } catch {
    path = url;
  }
  return path.toLowerCase().includes(EM_JSONV2_PATH_MARKER) ? { records: [event] } : event;
}

// deliver POSTs the event to the channel's own Event Management endpoint (the customer's ServiceNow
// instance url -- either the Table API's /api/now/table/em_event, or their jsonv2 intake
// /api/global/em/jsonv2, item 11 -- always a customer url, so it is SSRF-screened like any other). HTTP
// Basic auth rides in the Authorization header, resolved from its sealed envelope for the instant of the
// call; the body never carries it. A channel missing its url, username or apiKey (should be impossible
// after validateChannel) is a non-delivery.
export async function deliver(env: Env, channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  // G280: a ServiceNow channel needs an instance URL, a username AND a password, and the one code covered
  // all three. The url/username pair is the ENDPOINT class; the password is the CREDENTIAL class.
  // G280: the url and the username are DIFFERENT missing fields with different fixes. Reporting a blank
  // username as "no-url" sent support to check a perfectly good endpoint while the empty field sat one line
  // below it in the same form.
  if (!channel.url) return { ok: false, code: "no-url" };
  if (!channel.username) return { ok: false, code: "no-username" };
  if (channel.apiKey === undefined) return { ok: false, code: "no-credential" };
  let password: string;
  try {
    password = await resolveConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), channel.apiKey, SERVICENOW_SECRET_AAD);
  } catch {
    // The stored envelope will not open (CONFIG_WRAP_KEY absent or ROTATED since the password was sealed) or
    // the key is malformed: there is no usable credential. This is its OWN closed code (gap G004), NOT
    // no-transport, so a rotated wrap key is diagnosable separately from a genuinely misconfigured channel.
    // The fix here is the wrap key / re-sealing the credential. Fail-open.
    return { ok: false, code: "credential-undecryptable" };
  }
  // HTTP Basic: base64("user:pass") in the Authorization header, mirroring the SAME btoa idiom
  // src/admin/oauth2.ts and src/admin/oidc.ts already use for their own Basic-auth token exchange, so
  // credential encoding stays consistent across the codebase.
  const headers = { Authorization: `Basic ${btoa(`${channel.username}:${password}`)}` };
  const body = buildServiceNowBody(channel.url, format(emission));
  const r = await deliverPayload(channel.url, body, channel.allowInternalSink === true, headers);
  return { ok: r.ok, ...(r.code !== undefined ? { code: r.code } : {}), ...(r.sinkScreen !== undefined ? { sinkScreen: r.sinkScreen } : {}) };
}
