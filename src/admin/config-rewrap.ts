// config-rewrap.ts -- the key-install re-wrap. When the console key install sets CONFIG_WRAP_KEY, every
// credential the scheduler Durable Object already holds as plaintext is sealed under that key, so the first run
// no longer leaves the discovery token and the destination secret on the plaintext floor until someone saves
// them again.
//
// WHERE IT RUNS. POST /keys/install and POST /keys/add-config-recovery (router-keys.ts) call
// rewrapAfterKeyInstall after their secret PUTs and their own audit row. The key comes from the request when the
// route installed it, and from env when /keys/install kept the key the engine already held. It is never read
// back from Cloudflare and never logged.
//
// THE ORDER FOR EACH CREDENTIAL. Seal it here, open the envelope again with the same key and label and compare it
// with the plaintext, and only then ask the DO to swap. The DO swaps only while the stored value is still that
// plaintext (sched/config-secret-sweep.ts). So an envelope reaches storage only after it has been proved to open,
// and a credential saved again after the census is left as the save wrote it.
//
// IT NEVER FAILS THE INSTALL. The keys are already installed when this runs. A census that cannot be read, a key
// that does not load, or a swap that fails is reported in the result and in one audit row; the credential it
// could not seal stays plaintext and keeps working, and its next save seals it.
//
// THE ROLLOUT WINDOW. Each secret PUT rolls a new worker version and resets this Worker's Durable Objects, so every
// DO call here takes a fresh stub and rides out that reset (retryOnSelfDeployReset). An isolate of the OLD
// version that reads a credential in the seconds after the swap has no CONFIG_WRAP_KEY in its env and fails that
// read with the key-missing fault; the next read, on the new version, opens it.

import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { CONFIG_SECRET_CLASSES, type ConfigSecretCensus, type ConfigSecretClass, isConfigSecretClass, type PlaintextConfigSecret, type SwapOutcome } from "../sched/config-secret-sweep.ts";
import type { AuditTarget } from "./audit-types.ts";
import {
  CONFIG_SECRET_AAD,
  DISCOVERY_SECRET_AAD,
  IDP_SECRET_AAD,
  JSM_SECRET_AAD,
  loadConfigWrapKey,
  maybeWrapConfigSecret,
  OTLP_PUSH_SECRET_AAD,
  PUSH_S3_SECRET_AAD,
  PUSH_SECRET_AAD,
  resolveConfigSecret,
  SERVICENOW_SECRET_AAD,
} from "./config-secret.ts";
import type { Caller } from "./identity.ts";
import { recordAuditCheckedAfterSelfDeploy, retryOnSelfDeployReset } from "./router-audit.ts";
import { doURL, schedulerStub } from "./router-helpers.ts";

// CLASS_AAD maps each credential class to the label its own save seals it under. A Record over the closed class
// type, so a class added to the census without a label here fails the typecheck rather than being sealed under
// the wrong label, which would make it unreadable.
const CLASS_AAD: Record<ConfigSecretClass, Uint8Array> = {
  destination: CONFIG_SECRET_AAD,
  "discovery-token": DISCOVERY_SECRET_AAD,
  "siem-push-header": PUSH_SECRET_AAD,
  "siem-push-s3": PUSH_S3_SECRET_AAD,
  "otlp-push-header": OTLP_PUSH_SECRET_AAD,
  "notify-jsm": JSM_SECRET_AAD,
  "notify-servicenow": SERVICENOW_SECRET_AAD,
  "idp-client-secret": IDP_SECRET_AAD,
};

// RewrapFault names why a re-wrap could not run at all: the census could not be read (the DO did not answer), or
// there were plaintext credentials and the key did not load.
export type RewrapFault = "census-failed" | "key-unusable";

// RewrapReport is what the install returns and what the audit row records. Counts and closed class names only:
// no value, no envelope, no key.
//   ok              true when no credential is left on the plaintext floor
//   wrapped         credentials this pass sealed
//   alreadyWrapped  credentials that were envelopes already
//   leftPlaintext   plaintext credentials this pass did not seal (they still work, and their next save seals them)
//   failedClasses   the classes of those credentials, in CONFIG_SECRET_CLASSES order
export interface RewrapReport {
  ok: boolean;
  wrapped: number;
  alreadyWrapped: number;
  leftPlaintext: number;
  failedClasses: ConfigSecretClass[];
  fault?: RewrapFault;
}

// parseCensus reads the DO's census defensively. A row that is not a well-formed credential is not sealed,
// because a class or slot the swap cannot name is one it cannot write back. It is COUNTED (malformed), so the
// report never reads cleaner than the store: that row is a credential the pass saw and left plaintext.
function parseCensus(body: unknown): ConfigSecretCensus & { malformed: number } {
  const o = (body ?? {}) as { plaintext?: unknown; wrapped?: unknown };
  const rows = Array.isArray(o.plaintext) ? o.plaintext : [];
  const plaintext: PlaintextConfigSecret[] = [];
  let malformed = 0;
  for (const r of rows) {
    const x = (r ?? {}) as Record<string, unknown>;
    if (!isConfigSecretClass(x.cls) || typeof x.slot !== "string" || typeof x.ref !== "string" || typeof x.value !== "string" || x.value === "") {
      malformed++;
      continue;
    }
    plaintext.push({ cls: x.cls, slot: x.slot, ref: x.ref, value: x.value });
  }
  const wrapped = typeof o.wrapped === "number" && Number.isInteger(o.wrapped) && o.wrapped >= 0 ? o.wrapped : 0;
  return { plaintext, wrapped, malformed };
}

function orderedClasses(classes: ReadonlySet<ConfigSecretClass>): ConfigSecretClass[] {
  return CONFIG_SECRET_CLASSES.filter((c) => classes.has(c));
}

// sealAndSwap seals one credential, proves the envelope opens to the same value, and asks the DO to swap it in.
// Returns the DO's outcome, or "not-sealed" when the proof failed and nothing was sent.
async function sealAndSwap(stubFor: () => DurableObjectStub, key: Uint8Array, item: PlaintextConfigSecret): Promise<SwapOutcome | "not-sealed"> {
  const aad = CLASS_AAD[item.cls];
  // The write ingress every save uses, and the read every reader uses: nothing here reaches past them to the
  // raw enveloper (test/validate-secret-and-signature-guard-completeness.ts holds that line).
  const envelope = await maybeWrapConfigSecret(key, item.value, aad);
  if (typeof envelope === "string" || (await resolveConfigSecret(key, envelope, aad)) !== item.value) return "not-sealed";
  return retryOnSelfDeployReset(async () => {
    const resp = await stubFor().fetch(doURL("/config-secrets/swap"), {
      method: "POST",
      body: JSON.stringify({ cls: item.cls, slot: item.slot, ref: item.ref, wrapped: envelope }),
      headers: { "content-type": "application/json" },
    });
    if (!resp.ok) throw new Error(`the swap answered ${resp.status}`);
    const outcome = ((await resp.json()) as { outcome?: unknown }).outcome;
    return outcome === "swapped" || outcome === "already-wrapped" || outcome === "changed" || outcome === "absent" || outcome === "refused" ? outcome : "refused";
  });
}

// rewrapStoredConfigSecrets runs one pass: census, then seal and swap each plaintext credential in turn. Each
// credential is independent, so a failure on one is counted and the pass moves to the next. It does not throw.
// stubFor returns a FRESH scheduler stub on each call (the rollout reset invalidates a held one). keyRaw is the
// CONFIG_WRAP_KEY value (base64url of 32 bytes).
export async function rewrapStoredConfigSecrets(stubFor: () => DurableObjectStub, keyRaw: string | undefined): Promise<RewrapReport> {
  let census: ConfigSecretCensus & { malformed: number };
  try {
    census = await retryOnSelfDeployReset(async () => {
      const resp = await stubFor().fetch(doURL("/config-secrets/census"), { method: "GET" });
      if (!resp.ok) throw new Error(`the census answered ${resp.status}`);
      return parseCensus(await resp.json());
    });
  } catch {
    return { ok: false, wrapped: 0, alreadyWrapped: 0, leftPlaintext: 0, failedClasses: [], fault: "census-failed" };
  }
  if (census.plaintext.length === 0) return { ok: census.malformed === 0, wrapped: 0, alreadyWrapped: census.wrapped, leftPlaintext: census.malformed, failedClasses: [] };

  let key: Uint8Array | undefined;
  try {
    key = loadConfigWrapKey(keyRaw);
  } catch {
    key = undefined;
  }
  if (key === undefined) {
    return {
      ok: false,
      wrapped: 0,
      alreadyWrapped: census.wrapped,
      leftPlaintext: census.plaintext.length + census.malformed,
      failedClasses: orderedClasses(new Set(census.plaintext.map((p) => p.cls))),
      fault: "key-unusable",
    };
  }

  let wrapped = 0;
  let alreadyWrapped = census.wrapped;
  let leftPlaintext = census.malformed;
  const failed = new Set<ConfigSecretClass>();
  for (const item of census.plaintext) {
    let outcome: SwapOutcome | "not-sealed" | "error";
    try {
      outcome = await sealAndSwap(stubFor, key, item);
    } catch {
      outcome = "error";
    }
    if (outcome === "swapped") wrapped++;
    else if (outcome === "already-wrapped") alreadyWrapped++;
    else if (outcome !== "absent") {
      // changed, refused, not-sealed or error: the credential is still plaintext (or was replaced by a newer
      // plaintext save), so it is still on the floor.
      leftPlaintext++;
      failed.add(item.cls);
    }
  }
  return { ok: leftPlaintext === 0, wrapped, alreadyWrapped, leftPlaintext, failedClasses: orderedClasses(failed) };
}

// rewrapAuditTarget is the audit row's target: the key-ceremony kind carrying the counts. No value.
export function rewrapAuditTarget(r: RewrapReport): AuditTarget {
  return {
    kind: "key-ceremony",
    wrapped: r.wrapped,
    alreadyWrapped: r.alreadyWrapped,
    leftPlaintext: r.leftPlaintext,
    ...(r.failedClasses.length > 0 ? { failedClasses: [...r.failedClasses] } : {}),
    ...(r.fault !== undefined ? { rewrapFault: r.fault } : {}),
  };
}

// rewrapAfterKeyInstall is the call the key-install routes make once their keys are in. It runs the pass, logs
// the counts, and appends ONE config-secrets-rewrapped audit row when there was anything to report: a credential
// seen, or a pass that could not complete. An engine that holds no credential yet gets no row. The append rides
// the same rollout ladder as the keys-installed row. It never throws.
export async function rewrapAfterKeyInstall(env: Env, caller: Caller, sourceIp: string | null, keyRaw: string | undefined): Promise<RewrapReport> {
  let report: RewrapReport;
  try {
    report = await rewrapStoredConfigSecrets(() => schedulerStub(env), keyRaw);
  } catch {
    report = { ok: false, wrapped: 0, alreadyWrapped: 0, leftPlaintext: 0, failedClasses: [], fault: "census-failed" };
  }
  const classes = report.failedClasses.length > 0 ? ` (${report.failedClasses.join(", ")})` : "";
  const fault = report.fault !== undefined ? `; fault ${report.fault}` : "";
  const line = `config-secrets-rewrapped: wrapped ${report.wrapped}, already wrapped ${report.alreadyWrapped}, left on the plaintext floor ${report.leftPlaintext}${classes}${fault} (values never logged)`;
  if (report.ok) log("info", line);
  else log("warn", line);
  if (!report.ok || report.wrapped + report.alreadyWrapped + report.leftPlaintext > 0) {
    try {
      await recordAuditCheckedAfterSelfDeploy(env, caller, sourceIp, "config-secrets-rewrapped", report.ok ? "success" : "failed", rewrapAuditTarget(report), "key-ceremony-audit");
    } catch (e) {
      log("warn", `config-secrets-rewrapped audit append failed: ${(e as Error).message.slice(0, 140)}`);
    }
  }
  return report;
}
