// CONFIG-FAULT EVIDENCE (gap G142, support-pack mode run-config-fault-unnamed). Every run of a downpipe can
// start failing after a wrangler deploy, a token rotation or a discovery-scope change (a deploy that wipes
// source bindings is the best-known cause). Today the failed run row carries only a COARSE class --
// "source binding error", "engine not fully configured", "run failed" -- and the one fact support needs, WHICH
// binding / secret / token / env var is missing, exists only in the customer's own Workers Logs. The engine
// KNOWS the answer at the throw site (it read the name straight out of the stored config), then throws it away
// into a message string that the redaction layer correctly refuses to carry.
//
// This leaf fixes that at the SOURCE rather than by parsing the message back out: the config-fault throw sites
// raise a TYPED ConfigFaultError carrying a CLOSED code and, where one exists, the offending binding / env-var
// NAME taken DIRECTLY from the config or the env-var vocabulary (never sliced out of an error message, never a
// value). The run path classifies the caught error by TYPE (configFaultOf), never by text, and records the pair
// on the seal-fault OBSERVE ring, so a failed run is finally attributable to the knob that broke it.
//
// NO-CUSTODY / REDACTION:
//   - code is a member of the CLOSED CONFIG_FAULT_CODES vocabulary. Nothing else is ever recorded as a code.
//   - name is an OPERATOR LABEL (a Workers binding identifier or one of the engine's own env vars), the same
//     redaction class the pack's sourcesDetached already carries. It is gated by isConfigFaultName to the
//     identifier charset [A-Za-z0-9_] and 64 chars, so a value, a URL, a token, a record name or free text
//     structurally cannot ride in this field.
//   - a VALUE is never carried: not the token, not the secret, not the accountId (the scope-excluded and
//     account-id codes deliberately carry NO name, because the only "name" available there would be a
//     customer account id).
// PURE: no I/O, no state. The throw sites, the run-path classifier and the validator all share this one leaf,
// so the redaction cannot drift from the thing it describes.

// CONFIG_FAULT_CODES is the CLOSED vocabulary for "the run could not even be CONSTRUCTED, and this is the
// prerequisite that was missing". Each member names a distinct operator remedy:
//   - reserved-binding        : the configured source binding is one of the engine's OWN reserved bindings
//                               (the confused-deputy guard refused it). Security-significant: never a typo.
//   - source-binding-missing  : a kv/r2/d1 source's Workers binding is not present in the environment -- the
//                               classic "wrangler deploy overwrote the bindings" failure.
//   - secret-binding-missing  : a secrets source names a binding that is not present in the environment.
//   - discovery-token-missing : an API-discovery source (cf-config / workers / stream / images / artifacts)
//                               ran with no read-only discovery token (never set, or rotated away).
//   - account-id-missing      : an API-discovery source carries no accountId in its stored config.
//   - account-scope-excluded  : the source's accountId is no longer one of the discovery-SELECTED accounts
//                               (the owner narrowed the scope after the downpipe was created).
//   - signer-missing          : SIGNER_PRIVATE is absent from the environment (a redeploy dropped the secret).
//   - signer-format           : SIGNER_PRIVATE is present but is not the 64-byte seed form (a bad paste).
//   - env-missing             : another REQUIRED engine env var (the fixed DEST_*/BREAK_GLASS_PUBLIC vocabulary
//                               requireEnv guards) is absent. The var NAME rides; its value never does.
//   - unsupported-source-type : the stored source type is not one this engine build can adapt (a downgrade, or
//                               a hand-edited config).
//   - secret-binding-wrong-type (G041): a secrets source names a binding that IS present but is NEITHER a
//                               Secrets Store binding (which exposes get()) NOR a plaintext string secret --
//                               a KV namespace, an R2 bucket, a service binding, a D1 database bound under the
//                               secret's name. Coercing it with String(store) would seal "[object Object]" as
//                               the secret's value while reporting a clean ok. The build REFUSES the record
//                               (this typed fault) rather than sealing the coercion, so the run fails
//                               loudly and names the binding. The binding NAME rides (an operator label); the
//                               value never does.
export const CONFIG_FAULT_CODES = [
  "reserved-binding",
  "source-binding-missing",
  "secret-binding-missing",
  "secret-binding-wrong-type",
  "discovery-token-missing",
  "account-id-missing",
  "account-scope-excluded",
  "signer-missing",
  "signer-format",
  "env-missing",
  "unsupported-source-type",
] as const;
export type ConfigFaultCode = (typeof CONFIG_FAULT_CODES)[number];
const CONFIG_FAULT_CODE_SET: ReadonlySet<string> = new Set(CONFIG_FAULT_CODES);

// isConfigFaultCode gates a code against the CLOSED vocabulary. Exported so the seal-fault sanitiser (the one
// redaction chokepoint on the ring) re-gates a posted code without importing the whole seal graph.
export function isConfigFaultCode(v: unknown): v is ConfigFaultCode {
  return typeof v === "string" && CONFIG_FAULT_CODE_SET.has(v);
}

// CONFIG_FAULT_NAME_MAX bounds a carried operator label. A Workers binding identifier and every engine env var
// are far shorter; this is the abuse ceiling, not a real limit.
const CONFIG_FAULT_NAME_MAX = 64;
// CONFIG_FAULT_NAME_RE is the REDACTION GATE on the one free-ish field this record has. A Workers binding /
// env-var name is a JavaScript-identifier-shaped operator label: letters, digits and underscores. A customer
// VALUE, a URL, an endpoint, a token, a record key or an error sentence structurally cannot pass it (they carry
// spaces, punctuation, slashes, colons or quotes), so even a future call site that wrongly passed a value would
// have it DROPPED here rather than persisted.
const CONFIG_FAULT_NAME_RE = /^[A-Za-z0-9_]{1,64}$/;

// isConfigFaultName reports whether a candidate label is a bare operator identifier (the ONLY shape this
// evidence may carry). PURE; shared by the throw sites, the sanitiser and the validator.
export function isConfigFaultName(v: unknown): v is string {
  return typeof v === "string" && v.length <= CONFIG_FAULT_NAME_MAX && CONFIG_FAULT_NAME_RE.test(v);
}

/**
 * ConfigFaultError is the TYPED form of a run-blocking configuration fault. It extends Error and keeps the
 * EXISTING message verbatim, so every downstream behaviour is unchanged (coarseRunError's text classification,
 * the strike ladder, the log line, the /complete row all see exactly what they saw before). The `code` and
 * `name` fields are the ADDITIVE evidence: they are set from the config / env-var vocabulary at the throw site,
 * never parsed back out of the message.
 *
 * `name` is OPTIONAL by design: the codes whose only candidate name would be a customer value (account-scope-
 * excluded, account-id-missing) deliberately carry none.
 */
export class ConfigFaultError extends Error {
  readonly code: ConfigFaultCode;
  readonly bindingName?: string;
  constructor(code: ConfigFaultCode, message: string, bindingName?: string) {
    super(message);
    this.name = "ConfigFaultError";
    this.code = code;
    // The gate is applied AT CONSTRUCTION as well as at the sanitiser, so a non-identifier label never even
    // exists on the error object that the run path later reads.
    if (isConfigFaultName(bindingName)) this.bindingName = bindingName;
  }
}

// ConfigFault is the bounded, redaction-safe evidence one config fault yields: a closed code plus (sometimes)
// an operator label. It is exactly what rides the seal-fault ring's "config-fault" record.
export interface ConfigFault {
  readonly code: ConfigFaultCode;
  readonly bindingName?: string;
}

/**
 * configFaultOf classifies a CAUGHT error into its config-fault evidence, or null when the error is not a
 * config fault at all. It matches on the TYPE (a ConfigFaultError raised by the throw site), never on the
 * message text: the message may embed a record name or a customer label, and this classifier must never be
 * the thing that reads it. PURE.
 */
export function configFaultOf(e: unknown): ConfigFault | null {
  if (!(e instanceof ConfigFaultError)) return null;
  if (!isConfigFaultCode(e.code)) return null; // defence in depth: an internal drift is dropped, never coerced
  return e.bindingName !== undefined && isConfigFaultName(e.bindingName) ? { code: e.code, bindingName: e.bindingName } : { code: e.code };
}
