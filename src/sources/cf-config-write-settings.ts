// Write-back for SINGLE-SETTING surfaces: the zone settings Cloudflare exposes only at their own
// endpoint and omits from the aggregate /zones/{id}/settings response.
//
// WHY THIS IS A SEPARATE SHAPE FROM zone-settings
// -----------------------------------------------
// The shipped `zone-settings` writer reads an ARRAY of {id, value, editable} and PATCHes each changed
// member at /settings/{id}. These surfaces are the same product concept at a different granularity: one
// endpoint returns ONE setting object, so there is no array to walk and no member id to append. The
// zone-settings pattern does not generalise by copying, because its per-key isolation exists precisely
// because that endpoint returns an array. This module keeps the parts that carry over and drops the part
// that does not.
//
// WHAT CARRIES OVER, and is deliberately preserved:
//   * The `editable === false` guard. Cloudflare marks plan-gated and ACM-gated settings non-editable,
//     and attempting them produces noise at best and a confusing partial restore at worst.
//   * Compare-then-write. An unchanged value is NEVER touched, so a restore that is already converged
//     writes nothing at all and re-running is free.
//   * Fail-soft per surface. A refusal is classified and reported, never fatal.
//   * dryRun returns the diff and applies nothing.
//
// WHAT DOES NOT CARRY OVER: there is no per-member loop, so a single refusal fails the whole surface
// rather than one member of it. That is honest for a one-value surface and it is why each of these is
// registered as its own surface rather than being folded into one multi-setting writer: a customer sees
// exactly which setting did not come back.
//
// SCOPE. Only settings whose endpoint documents PATCH get a writer. `zaraz/default` is GET-only in
// Cloudflare's schema and therefore has NO writer, by the standing rule that a surface with no writer is
// honest while a surface with a wrong writer is a liability.

import type { Meter } from "../meter.ts";
import type { CfApi, CfConfigSurface, ConfigWriteResult } from "./cf-config-core.ts";
import { classifyCfWriteSkip } from "./cf-config-fault.ts";
import { asJson, type ConfigChange, jsonEqual, stripStamped } from "./cf-config-shared.ts";

// SingleSettingValue is the shape Cloudflare returns for a one-setting endpoint. `editable` is absent on
// some settings, which is treated as editable: the guard only refuses an EXPLICIT false, so a schema that
// omits the field does not silently make a restorable setting unrestorable.
interface SingleSettingValue {
  id?: unknown;
  value?: unknown;
  // Some settings carry their value under `enabled` instead. auto_origin_tls_kex is one: it reads back as
  // {id, enabled, modified_on} and its PATCH REFUSES {value: ...} with 1003 "Malformed JSON in request
  // body", accepting only {enabled: bool}. Assuming `value` everywhere made that surface skip on every
  // restore with "the snapshot carries no value for this setting", including when live and snapshot were
  // identical, which is the signature that found it.
  enabled?: unknown;
  editable?: unknown;
}

// valueFieldOf names which field carries this setting's value, so the write PATCHes back the same shape it
// read. Preferring `value` keeps every existing setting on its current path; `enabled` is consulted only
// when `value` is absent, so a setting that carried both would be unaffected.
function valueFieldOf(v: SingleSettingValue | null): "value" | "enabled" | null {
  if (v === null || typeof v !== "object") return null;
  if (v.value !== undefined) return "value";
  if (v.enabled !== undefined) return "enabled";
  return null;
}

// writeSingleSetting builds the diff-driven write() for one settings endpoint. `path` is the full
// endpoint (the same one the surface reads), so the read and the write can never drift apart.
export function writeSingleSetting(pathFor: (ids: { accountId: string; zoneId?: string }) => string, label: string): NonNullable<CfConfigSurface["write"]> {
  const fn: NonNullable<CfConfigSurface["write"]> = async (api: CfApi, ids, data, opts, meter?: Meter): Promise<ConfigWriteResult> => {
    const path = pathFor(ids);
    meter?.spend(1, "cfApiRead");
    const live = (await api.get(path)) as SingleSettingValue | null;
    const snap = (data ?? null) as SingleSettingValue | null;

    // A snapshot with no value is nothing to restore. This is the `_unavailable` / `_truncated` case the
    // decode layer already refuses, plus the ordinary "the surface was empty at backup time" case.
    const field = valueFieldOf(snap);
    if (snap === null || typeof snap !== "object" || field === null) {
      // `cls` takes the residual: CF_WRITE_SKIP_CLASSES is a CLOSED vocabulary, and this is not a
      // Cloudflare refusal at all, so widening a closed set and its consumers for one local case would
      // be the wrong trade.
      return { changes: [], applied: 0, skipped: [{ path: label, reason: "the snapshot carries no value for this setting", cls: "other" }] };
    }
    // Cloudflare marks plan-gated and ACM-gated settings non-editable. Refuse only an EXPLICIT false.
    if (snap.editable === false || (live !== null && typeof live === "object" && live.editable === false)) {
      return { changes: [], applied: 0, skipped: [{ path: label, reason: "Cloudflare reports this setting as not editable on this zone", cls: "entitlement" }] };
    }

    // Compare and send on the SAME field the snapshot used, so a setting whose value lives under `enabled`
    // is diffed against live's `enabled` rather than against an absent `value` (which would read as "add"
    // on every run and PATCH a shape the endpoint refuses).
    const to = JSON.stringify(snap[field]);
    const from = live !== null && typeof live === "object" && live[field] !== undefined ? JSON.stringify(live[field]) : undefined;
    if (from === to) return { changes: [], applied: 0, skipped: [] }; // converged: never touched

    const changes: ConfigChange[] = [{ path: label, action: from === undefined ? "add" : "change", from: from ?? "", to }];
    if (opts.dryRun) return { changes, applied: 0, skipped: [] };

    try {
      meter?.spend(1);
      await api.send("PATCH", path, { [field]: snap[field] });
      return { changes, applied: 1, skipped: [] };
    } catch (e) {
      return {
        changes,
        applied: 0,
        skipped: [{ path: label, reason: (e as Error).message.replace(/^Cloudflare API [A-Z]+ [^:]+:\s*/, "").slice(0, 120), cls: classifyCfWriteSkip(e) }],
      };
    }
  };
  // DECLARED for the same reason writeSingleObject declares: a fact the code already holds should never be
  // re-derived by a reader guessing at it. Seven proven surfaces are served by this factory, and publishing
  // its verb, its path and its label lets a reader ask instead of parsing this file.
  return Object.assign(fn, {
    cfWriteKind: "setting" as const,
    cfWriteMethod: "PATCH" as const,
    cfWritePath: pathFor,
    cfWriteSpec: { label },
  });
}

// writeSingleObject is the diff-driven write for a SINGLETON CONFIG OBJECT: a surface whose whole body is
// the configuration, rather than one wrapped in a {value} or {enabled} field.
//
// writeSingleSetting covers the zone-settings shape, where Cloudflare wraps a scalar. It does not fit
// Gateway configuration, Gateway logging, DLP settings, Page Shield settings or the Email Routing catch-all
// rule, each of which returns the config itself. Those five were among 131 idempotent surfaces carrying no
// writer at all, so they were captured and previewed but never re-applied, and each is something a customer
// configures by hand and would have to re-enter from the snapshot.
//
// It is deliberately NOT a list writer: there is one object, so there is no natural key to match on, no
// create path, and nothing to delete. That also makes it inherently additive at the object level. The
// FIELD level is a different question and the reason this sends the snapshot's own stripped body: a PUT
// replaces the object, so a field live has and the snapshot does not is dropped. That is the same shape as
// the ruleset problem, but here it cannot be guarded the same way, because a singleton has no per-item
// identity to report a live-only entry against. What it does instead is report the WHOLE before and after
// in the diff, so the operator sees the object being replaced rather than a count.
// bodyToSend decides what actually goes on the wire for a one-object surface.
//
// PATCH sends ONLY the top-level keys whose value differs from live. It used to send the whole snapshot,
// and that is both a contract breach and a live defect:
//
//   The contract. The product's published promise for an in-band restore is that it "applies only the
//   fields that differ". Every list writer does that item by item. This one did not, and the difference
//   was invisible because the result is the same whenever every field is writable.
//
//   The defect. One field the account cannot set sinks the ENTIRE write. Cloudflare validates the whole
//   body, so a snapshot carrying a plan-gated field is refused outright and none of the fields that WOULD
//   have applied are applied. Measured on a Free zone: PATCH /zones/{id}/dns_settings with the whole
//   object returns HTTP 400 "Custom SOA records are not available to this account or zone", while the
//   same change sent as `{multi_provider: true}` returns 200 and takes. The surface reads as unwritable
//   and is not; the plan-gated neighbour is what refused.
//
// PUT keeps sending the whole object, because PUT means replace and a partial body would DELETE the keys
// left out. The method is declared per surface, so this switches on the declaration rather than guessing.
//
// Comparison is by jsonEqual for the same reason the equality check above uses it: it honours SKIP_IN_DIFF
// and so does not treat volatile churn as a difference worth sending.
// narrowNested reduces a changed value to the smallest thing that still expresses the change.
//
// Objects only, and only when BOTH sides are objects. An array is sent whole: a partial array says nothing
// about which elements it replaces, and an endpoint cannot merge it sensibly. A value the live side does
// not have at all is sent whole, because there is nothing to merge it into.
//
// If two objects differ but every leaf comparison says otherwise (a key present on one side only, say), the
// result would be an empty object, which asks the endpoint to change nothing. Send the whole value instead,
// for the same reason bodyToSend falls back to the whole object on an empty top-level diff: a wrong-but-
// complete body fails loudly, an empty one silently means nothing.
function narrowNested(snapValue: unknown, liveValue: unknown): unknown {
  if (!isPlainRecord(snapValue) || !isPlainRecord(liveValue)) return snapValue;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(snapValue)) {
    if (jsonEqual(v, liveValue[k])) continue;
    out[k] = narrowNested(v, liveValue[k]);
  }
  return Object.keys(out).length > 0 ? out : snapValue;
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function bodyToSend(
  method: "PATCH" | "PUT" | "POST",
  live: Record<string, unknown> | null,
  snap: Record<string, unknown>,
  applyFieldRules: (src: Record<string, unknown> | null) => Record<string, unknown>,
  nestedDiff: boolean,
): Record<string, unknown> {
  const stripped = applyFieldRules(snap);
  // POST is treated as PUT here, whole-object. Several Cloudflare SETTINGS endpoints expose only GET and
  // POST, where POST is documented as the setter ("Enable or Disable Total TLS") rather than a create, and
  // they declare REQUIRED fields. A diff can legitimately omit a required field, so sending the diff would
  // turn "one setting changed" into a 400 about a field that did not change.
  if (method !== "PATCH" || live === null || typeof live !== "object") return stripped;
  const strippedLive = applyFieldRules(live);
  const diff: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(stripped)) {
    if (jsonEqual(v, strippedLive[k])) continue;
    diff[k] = nestedDiff ? narrowNested(v, strippedLive[k]) : v;
  }
  // A snapshot that differs only in fields stripStamped or jsonEqual ignore reaches here with an empty
  // diff. Sending {} would be a pointless request that some endpoints reject, so fall back to the whole
  // object: the caller has already established the two are not equal, and a wrong-but-whole body fails
  // loudly rather than sending a request that means nothing.
  return Object.keys(diff).length > 0 ? diff : stripped;
}

// A surface may CORRECT the global strip in either direction. The global SERVER_STAMPED set is a single
// vocabulary applied to every surface, and no single vocabulary is right everywhere:
//
//   `keep` restores a field the global set removes but which is CONFIGURATION here. `scope` is stripped
//   globally, and on url-normalization it is one of the surface's only two settings, so the writer sent
//   `{type}` alone. Cloudflare answers "erroneous scope" to that, and where it did not, a changed scope
//   would simply never have been restored while the run reported success. A field silently dropped from a
//   restore is the worst shape available: the operator is told it worked.
//
//   `alsoStrip` removes a field the global set keeps but which this endpoint REFUSES. bot-management
//   reports `using_latest_model`, a server-computed status, and rejects any PUT carrying it; removing
//   just that field makes the same request succeed. fraud-detection-settings does the same with
//   `user_profiles`. Both were found by sending each surface its own read output back and then dropping
//   one field at a time until it was accepted.
//
// Both lists are per surface and carry their reason at the declaration, which is the difference between
// this and growing the global list further: a global entry is a claim about every surface at once.
export interface SingleObjectFieldRules {
  keep?: readonly string[];
  alsoStrip?: readonly string[];
  // nestedDiff descends the PATCH diff INTO nested objects, so a change to one field inside a nested object
  // sends only that field rather than the whole object.
  //
  // WHY IT IS OPT-IN, AND WHY IT IS NOT THE DEFAULT
  // ----------------------------------------------
  // Sending a partial nested object is only correct if the endpoint DEEP-MERGES it. If it replaces the
  // nested object wholesale instead, every field we omitted is dropped, which turns a restore into data
  // loss on exactly the surface a customer asked to have put back. That is not a risk worth taking on a
  // guess, and the two behaviours are indistinguishable from the schema.
  //
  // So it is enabled per surface, only where the merge semantics have been PROVEN against the live API:
  // send a partial nested body, read back, and confirm the sibling fields are untouched.
  //
  // account-dns-settings is the first. Its whole-object body is REFUSED on a Free account with "Custom SOA
  // records are not available to this account or zone", because the read carries an `soa` block that rides
  // along on every write regardless of what changed. The partial body is accepted, and a read-back confirms
  // only the changed field moved. Without this, restoring account DNS settings fails outright on any
  // account without custom SOA entitlement, over a field the customer never touched.
  nestedDiff?: boolean;
}

export function writeSingleObject(
  pathFor: (ids: { accountId: string; zoneId?: string }) => string,
  // POST is accepted for the settings endpoints that expose only GET and POST, where Cloudflare documents
  // POST as the setter. It is safe there because the path addresses ONE object, so a POST cannot create a
  // second: /zones/{id}/acm/total_tls is the Total TLS setting, not a collection of them. Do not use it
  // for a collection endpoint, which is what writeList is for.
  method: "PATCH" | "PUT" | "POST",
  label: string,
  fields: SingleObjectFieldRules = {},
): NonNullable<CfConfigSurface["write"]> {
  const applyFieldRules = (src: Record<string, unknown> | null): Record<string, unknown> => {
    if (src === null || typeof src !== "object") return {};
    const out = stripStamped(src);
    for (const k of fields.keep ?? []) if (k in src) out[k] = src[k];
    for (const k of fields.alsoStrip ?? []) delete out[k];
    return out;
  };
  const fn: NonNullable<CfConfigSurface["write"]> = async (api: CfApi, ids, data, opts, meter?: Meter): Promise<ConfigWriteResult> => {
    const path = pathFor(ids);
    meter?.spend(1, "cfApiRead");
    const live = (await api.get(path)) as Record<string, unknown> | null;
    const snap = data as Record<string, unknown> | null;
    if (snap === null || typeof snap !== "object" || Array.isArray(snap)) {
      return { changes: [], applied: 0, skipped: [{ path: label, reason: "the snapshot carries no object for this surface", cls: "other" }] };
    }
    const from = live === null || typeof live !== "object" ? "" : asJson(applyFieldRules(live));
    const to = asJson(applyFieldRules(snap));
    // EQUALITY IS DECIDED BY jsonEqual, NOT BY THE STRINGS ABOVE. The strings remain what the operator is
    // shown in the diff, but comparing them was a SECOND rule for "did this change", and it disagreed with
    // the one every list writer uses: stripStamped drops SERVER_STAMPED only, while jsonEqual consults
    // SKIP_IN_DIFF, which also covers volatile churn.
    //
    // The cost of that divergence was a live defect. Zaraz mints a fresh `debugKey` on every read, so a
    // singleton writer comparing strings saw a difference on every run and would have rewritten the whole
    // Zaraz configuration forever, on any account that has Zaraz. Adding the field to VOLATILE_KEYS fixed
    // nothing here until this comparison started honouring the same set as everything else.
    if (jsonEqual(live, snap)) return { changes: [], applied: 0, skipped: [] };
    if (from === to) return { changes: [], applied: 0, skipped: [] };
    const changes: ConfigChange[] = [{ path: label, action: from === "" ? "add" : "change", from, to }];
    if (opts.dryRun) return { changes, applied: 0, skipped: [] };
    try {
      meter?.spend(1);
      await api.send(method, path, bodyToSend(method, live, snap, applyFieldRules, fields.nestedDiff === true));
      return { changes, applied: 1, skipped: [] };
    } catch (e) {
      return {
        changes,
        applied: 0,
        skipped: [{ path: label, reason: (e as Error).message.replace(/^Cloudflare API [A-Z]+ [^:]+:\s*/, "").slice(0, 120), cls: classifyCfWriteSkip(e) }],
      };
    }
  };
  // The writer DECLARES how it writes, so a reader can ask instead of parsing this file: the verb and
  // whether this is the whole-object shape. A fact the code already holds should never be re-derived by a
  // reader guessing at it.
  return Object.assign(fn, {
    cfWriteKind: "object" as const,
    cfWriteMethod: method,
    cfWritePath: pathFor,
    // The field rules go out with the rest, so a reader deriving a body from the function alone would not
    // silently test one this writer never sends.
    cfApplyFieldRules: applyFieldRules,
    // The field RULES themselves, as data, which cfApplyFieldRules cannot supply: it is a closure, and its
    // source is identical for all twenty-seven surfaces this factory serves. `keep: ["scope"]` on
    // url-normalization decides what a restore sends and is invisible to any reader that only has the
    // function.
    cfWriteSpec: { label, fields },
  });
}
