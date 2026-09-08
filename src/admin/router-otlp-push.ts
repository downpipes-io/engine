// router-otlp-push.ts -- the outbound OTLP/HTTP metrics push destination admin routes: GET /otlp-push
// (the redacted view), POST /otlp-push (set/replace, owner +
// dual-control) and POST /otlp-push/delete (owner, no dual control). Mirrors router-push.ts EXACTLY, minus
// the SIEM push's format/sink/s3/syslog/url-token machinery (OTLP push is ONE shape, ONE http transport, ONE
// bearer/API-key secret): the router validates the endpoint + WRAPS the secret under OTLP_PUSH_SECRET_AAD
// BEFORE forwarding to the DO (the dual-control + storage authority), so an invalid submission never gets
// queued as a pending approval, and the DO NEVER sees the plaintext secret when a wrap key is configured.

import { isAllowedWebhookUrl } from "../notify.ts";
import { isForbiddenPushHeaderName, isValidPushHeaderValue } from "../sched/scheduler-do-limits.ts";
import { loadConfigWrapKey, maybeWrapConfigSecret, OTLP_PUSH_SECRET_AAD, type WrappedSecret } from "./config-secret.ts";
import { recordAdminRefusal } from "./diag-admin.ts";
import { callerHeaders, gate, jsonError, rateLimited } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";

// fireInBackground: see router-identity.ts's identical helper.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// OTLP_PUSH_HEADER_NAME_RE mirrors the DO's own re-check (scheduler-do-otlp-push.ts): the RFC 7230 token
// character set, 1..100 chars.
const OTLP_PUSH_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$/;

// ValidatedOtlpPushShape is the router's normalised, UNWRAPPED submission. authHeaderValue is carried only
// when the operator supplied a non-empty one, so the route wraps exactly that before forwarding, and an
// absent one means keep-secret at the DO.
interface ValidatedOtlpPushShape {
  ok: true;
  enabled: boolean;
  endpoint: string;
  authHeaderName: string;
  authHeaderValue?: string; // present only when supplied (to wrap under OTLP_PUSH_SECRET_AAD)
}

// validateOtlpPushSetShape validates + normalises a POST /otlp-push submission at the router (the SAME
// discipline validatePushSetShape applies for the SIEM push), so a malformed submission is refused 400 BEFORE
// it can be queued as a pending dual-control approval. KEEP-SECRET: authHeaderValue is OPTIONAL here -- an
// absent/empty value is ALLOWED (not a 400) and means "keep the currently sealed secret unchanged", so the
// console can toggle `enabled` or edit the endpoint without resupplying a write-only secret; it is present in
// the result ONLY when the operator supplied a non-empty one, and the DO enforces that a FIRST-ever create
// still carries the secret.
function validateOtlpPushSetShape(body: {
  endpoint?: unknown;
  authHeaderName?: unknown;
  authHeaderValue?: unknown;
  enabled?: unknown;
}): ValidatedOtlpPushShape | { ok: false; response: Response } {
  if (typeof body.enabled !== "boolean") return { ok: false, response: jsonError("enabled must be a boolean", 400) };
  const v = isAllowedWebhookUrl(typeof body.endpoint === "string" ? body.endpoint.trim() : "");
  if (!v.ok) return { ok: false, response: jsonError(`OTLP push destination endpoint invalid: ${v.reason}`, 400) };
  const authHeaderNameRaw = typeof body.authHeaderName === "string" ? body.authHeaderName.trim() : "";
  const authHeaderName = authHeaderNameRaw === "" ? "Authorization" : authHeaderNameRaw;
  if (!OTLP_PUSH_HEADER_NAME_RE.test(authHeaderName)) {
    return { ok: false, response: jsonError("OTLP push destination auth header name must be a valid HTTP header name", 400) };
  }
  // OTLP push always sends the auth header (no url-token option), so the forbidden-name check is unconditional:
  // content-type would collide with the application/json the sender sets, and a runtime-controlled header
  // (host/content-length/connection) is never a legitimate collector auth header.
  if (isForbiddenPushHeaderName(authHeaderName)) {
    return { ok: false, response: jsonError("OTLP push destination auth header name must not be content-type or a runtime-controlled header (e.g. host, content-length, connection)", 400) };
  }
  const authHeaderValue = typeof body.authHeaderValue === "string" ? body.authHeaderValue : "";
  // Screen the auth header VALUE at config time (finding F3), matching router-push.ts: a supplied value with a
  // control char (CR/LF injection) or over the length cap is a clear 400 here, before sealing, not an opaque
  // send-time failure. An absent/empty value is the keep-secret signal (unchanged).
  if (authHeaderValue !== "" && !isValidPushHeaderValue(authHeaderValue)) {
    return { ok: false, response: jsonError("OTLP push destination auth header value must be within the length cap and free of control characters (no CR/LF)", 400) };
  }
  return { ok: true, enabled: body.enabled, endpoint: v.url, authHeaderName, ...(authHeaderValue !== "" ? { authHeaderValue } : {}) };
}

// handleOtlpPush dispatches the OTLP metrics push destination group. Returns the route's Response, or null
// when no case here matched (the hub falls to the next spoke).
export async function handleOtlpPush(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // GET /otlp-push is the redacted admin view (any authenticated role, the same reconnaissance class as
    // GET /push): the endpoint, header NAME, enabled flag, who/when and the bounded delivery trail. The secret
    // and its ciphertext NEVER appear (the DO's getOtlpPushView never reads them into the response); a
    // byte-for-byte forward of the DO's own reply.
    // The twin of GET /push and gated the same way for the same reasons: no
    // callerHeaders are forwarded so getOtlpPushView() has no principal to check, and
    // support-sections-push.ts fetches doURL("/otlp-push") into the posture.read-gated support pack.
    // posture.read is a viewer-floor capability, so this refuses nobody.
    case "GET /otlp-push": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/otlp-push"), { method: "GET" });
    }

    // POST /otlp-push sets or replaces the OTLP push destination. Owner-exclusive (keys.ceremony) +
    // rate-limited, then forwarded to the DO's dual-control gate (otlp-push-dest-set): with a second owner
    // present (or the opt-in gate on), this queues a pending approval (202) instead of repointing the egress
    // inline. The endpoint is SSRF/shape-validated and the secret is WRAPPED under OTLP_PUSH_SECRET_AAD HERE,
    // BEFORE the DO ever sees it, so an invalid submission never reaches the approval queue and the DO holds
    // only ciphertext.
    case "POST /otlp-push": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown };
      const validated = validateOtlpPushSetShape(body);
      if (!validated.ok) {
        // G245: as for SIEM push -- the attempt itself was invisible.
        fireInBackground(runtime, recordAdminRefusal(scheduler, "otlp-config", "validation"));
        return validated.response;
      }
      // KEEP-SECRET: wrap + forward the secret ONLY when the operator supplied a non-empty one, under
      // OTLP_PUSH_SECRET_AAD. When absent, the record is forwarded WITHOUT it so the DO keeps the existing
      // sealed one (a first-ever create with no secret is rejected by the DO's buildOtlpPushRecord, not here).
      // The DO never sees plaintext.
      let wrappedHeader: string | WrappedSecret | undefined;
      try {
        const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
        if (validated.authHeaderValue !== undefined) {
          wrappedHeader = await maybeWrapConfigSecret(wrapKey, validated.authHeaderValue, OTLP_PUSH_SECRET_AAD);
        }
      } catch (e) {
        return jsonError(`the engine's CONFIG_WRAP_KEY is misconfigured (${(e as Error).message}); fix it in the Secrets Store before setting an OTLP push destination (the auth secret is encrypted at rest under this key)`, 400);
      }
      return scheduler.fetch(doURL("/otlp-push"), {
        method: "POST",
        body: JSON.stringify({
          enabled: validated.enabled,
          endpoint: validated.endpoint,
          authHeaderName: validated.authHeaderName,
          ...(wrappedHeader !== undefined ? { authHeaderValue: wrappedHeader } : {}),
        }),
        headers: callerHeaders(caller),
      });
    }

    // POST /otlp-push/delete clears the OTLP push destination. Owner-exclusive; NOT dual-control gated
    // (closing an egress is the safe direction, mirroring POST /push/delete). It IS change-controlled: the DO
    // route enforces the change-number policy on the forwarded reference (kind "otlp-clear") before clearing.
    case "POST /otlp-push/delete": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/otlp-push/delete"), { method: "POST", headers: callerHeaders(caller) });
    }
    default:
      return null;
  }
}
