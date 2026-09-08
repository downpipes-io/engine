import { BINDING_ALARM_KINDS, type BindingAlarmKind } from "./diag-records.ts";
// The G180 phase-refusal vocabulary lives in discovery-health.ts, the leaf that owns every attach fault class.
// The dependency runs THIS WAY ONLY: discovery-health is folded by the Durable Object, so an import from it back
// into the attach path would close a cycle through the DO base.
import { AttachRefusal, type AttachRefusalClass, AttachRefusalError, attachRefusalClassOf } from "./discovery-health.ts";
// The PURE planner + proof half of the in-product source attach (see attach.ts for the full
// safety-harness narrative). Nothing here performs IO: every guard runs in memory, so the
// validator drives each one directly. attach.ts re-exports these symbols, so importers are
// unchanged.
//
// The contract: this code must NEVER drop or alter the engine's OWN bindings (its scheduler/seal
// Durable Objects, the R2 archive, its secrets). The two proofs (planChange + verifyAfter) make an
// unintended change impossible, and refuse on any doubt so the caller falls back to the wrangler
// deploy path.

import { RESERVED_BINDINGS } from "../sched/scheduler-do.ts";

// AttachSource mirrors the console's SourceInput wire shape (lib/add-source.ts).
export interface AttachSource {
  type: "kv" | "r2" | "d1" | "secrets";
  binding: string;
  namespaceId?: string;
  bucketName?: string;
  databaseId?: string;
  databaseName?: string;
  storeId?: string;
  secretName?: string;
}

// A live binding as the script-settings read returns it. Re-sent VERBATIM on the write
// (same endpoint, same shape), so its every field is preserved; only name and type are
// inspected here.
export interface LiveBinding extends Record<string, unknown> {
  name?: string;
  type?: string;
}

// REDACTED_TYPES carry a value Cloudflare does not return on read, so they cannot be
// re-sent; keep_bindings preserves them in place instead.
const REDACTED_TYPES = new Set(["secret_text", "secret_key"]);

// The engine's REQUIRED infrastructure bindings: their presence proves the read is THIS
// engine's, and the harness refuses if the write would lose either.
const REQUIRED_DO = ["SCHEDULER", "RUNSEAL"];

const BINDING_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

// nameKey identifies a binding for the superset proof: name + type. A binding is
// "the same" across read and write when both match.
function _nameKey(b: LiveBinding): string {
  return `${typeof b.name === "string" ? b.name : ""}|${typeof b.type === "string" ? b.type : ""}`;
}

// bindingFromSource validates one requested source and returns the settings binding
// object the API expects. Fail-loud: nothing is written until every requested binding
// has passed.
export function bindingFromSource(s: AttachSource): LiveBinding {
  if (typeof s.binding !== "string" || !BINDING_NAME.test(s.binding)) {
    throw new Error(`binding name ${JSON.stringify(s.binding ?? "")} is not a valid Worker binding name`);
  }
  if (RESERVED_BINDINGS.has(s.binding)) {
    throw new Error(`binding ${s.binding} is reserved by the engine and cannot be a source`);
  }
  switch (s.type) {
    case "kv":
      if (!s.namespaceId) throw new Error(`${s.binding}: a KV source needs its namespace id`);
      return { type: "kv_namespace", name: s.binding, namespace_id: s.namespaceId };
    case "r2":
      if (!s.bucketName) throw new Error(`${s.binding}: an R2 source needs its bucket name`);
      return { type: "r2_bucket", name: s.binding, bucket_name: s.bucketName };
    case "d1":
      if (!s.databaseId) throw new Error(`${s.binding}: a D1 source needs its database id`);
      return { type: "d1", name: s.binding, id: s.databaseId };
    case "secrets":
      if (!s.storeId || !s.secretName) throw new Error(`${s.binding}: a Secrets Store source needs the store id and the secret name`);
      return { type: "secrets_store_secret", name: s.binding, store_id: s.storeId, secret_name: s.secretName };
    default:
      throw new Error(`unsupported source type ${JSON.stringify((s as { type?: unknown }).type)}`);
  }
}

// looksLikeThisEngine asserts the read is genuinely this engine: both required Durable
// Object bindings are present. A read missing either is refused (not this engine, or a
// partial/anomalous read we must not act on).
export function looksLikeThisEngine(bindings: LiveBinding[]): boolean {
  return REQUIRED_DO.every((doName) => bindings.some((b) => b.type === "durable_object_namespace" && b.name === doName));
}

// planChange computes the write set for an attach (additions) AND/OR a detach (removals)
// and PROVES it changes EXACTLY the intended bindings and nothing else, or throws. It is
// pure (no IO), so the validator drives every guard directly. Returns the bindings to
// send, the keep_bindings types, and the added/removed names.
//
// The two proofs are symmetric and together make an unintended change impossible:
//   ADD, every existing binding survives; the additions are the only new ones.
//   REMOVE, every removal target is a NON-RESERVED, non-Durable-Object, non-secret source
//            binding that EXISTS; it is gone from the new set; every OTHER existing binding
//            survives. The engine's own bindings (RESERVED_BINDINGS, the Durable Objects,
//            the secrets) can never be a removal target, so a detach can never brick it.
// validateRemovals checks every detach target: it must name an EXISTING, NON-RESERVED,
// non-Durable-Object, non-secret source binding. Returns the validated removal set.
function validateRemovals(byName: Map<string, LiveBinding>, removals: string[]): Set<string> {
  const removeSet = new Set<string>();
  for (const name of removals) {
    if (typeof name !== "string" || name === "") throw new Error("a removal target was not a binding name");
    const b = byName.get(name);
    if (b === undefined) throw new Error(`cannot detach ${name}: it is not bound to the engine`);
    if (RESERVED_BINDINGS.has(name) || REQUIRED_DO.includes(name)) throw new Error(`refusing to detach ${name}: it is one of the engine's own bindings, not a source`);
    if (b.type === "durable_object_namespace") throw new Error(`refusing to detach ${name}: it is a Durable Object the engine owns`);
    if (typeof b.type === "string" && REDACTED_TYPES.has(b.type)) throw new Error(`refusing to detach ${name}: it is one of the engine's secrets`);
    removeSet.add(name);
  }
  return removeSet;
}

// validateAdditions builds the fresh binding objects, refusing a name collision with a
// surviving binding (a name being removed in the same change is free to be re-added).
function validateAdditions(byName: Map<string, LiveBinding>, additions: AttachSource[], removeSet: Set<string>): { fresh: LiveBinding[]; added: string[] } {
  const taken = new Set(byName.keys());
  const fresh: LiveBinding[] = [];
  const added: string[] = [];
  for (const s of additions) {
    const b = bindingFromSource(s);
    const name = b.name as string;
    // A NAME COLLISION with a binding that is staying. The operator's fix is to pick another binding
    // name (or detach the existing one first). Message unchanged.
    if (taken.has(name) && !removeSet.has(name)) throw new AttachRefusal(`binding ${name} already exists on the engine`, { stage: "plan-validate", cause: "binding-name-conflict" });
    taken.add(name);
    fresh.push(b);
    added.push(name);
  }
  return { fresh, added };
}

// buildWriteSet assembles the write set: every existing NON-redacted binding EXCEPT the
// removals, re-sent verbatim, plus the additions. Redacted (secret) types are preserved by
// keep_bindings, not re-sent (Cloudflare does not return their value on read).
function buildWriteSet(existing: LiveBinding[], removeSet: Set<string>, fresh: LiveBinding[]): { bindings: LiveBinding[]; keepBindings: string[] } {
  const resend = existing.filter((b) => typeof b.type === "string" && !REDACTED_TYPES.has(b.type) && !(typeof b.name === "string" && removeSet.has(b.name)));
  const keepBindings = [...new Set(existing.map((b) => b.type).filter((t): t is string => typeof t === "string" && REDACTED_TYPES.has(t)))];
  return { bindings: [...resend, ...fresh], keepBindings };
}

// assertSupersetProof runs the two symmetric proofs that make an unintended change impossible:
// PROOF 1 (no unintended drop): every existing binding that is NOT an intended removal survives
// (a non-redacted one in `bindings`, a redacted one via keep_bindings); PROOF 2 (precise removal):
// every removal target is gone from the new set, and nothing re-added it (unless it was a replace).
function assertSupersetProof(existing: LiveBinding[], bindings: LiveBinding[], keepBindings: string[], removeSet: Set<string>, added: string[]): void {
  const sentNames = new Set(bindings.map((b) => (typeof b.name === "string" ? b.name : "")));
  for (const b of existing) {
    const name = typeof b.name === "string" ? b.name : "";
    const t = typeof b.type === "string" ? b.type : "";
    if (removeSet.has(name)) continue; // intended removal, proved gone below
    if (REDACTED_TYPES.has(t)) {
      if (!keepBindings.includes(t)) throw new Error(`safety check failed: the redacted binding ${name} (${t}) is not preserved by keep_bindings`);
      continue;
    }
    if (!sentNames.has(name)) throw new AttachRefusal(`safety check failed: existing binding ${name} (${t}) would be dropped; refusing to write`, { stage: "plan-validate", cause: "would-drop-binding" });
  }
  const addedNames = new Set(added);
  for (const name of removeSet) {
    if (sentNames.has(name) && !addedNames.has(name)) throw new AttachRefusal(`safety check failed: ${name} was meant to be removed but is still in the write set`, { stage: "plan-validate", cause: "removal-not-applied" });
  }
}

export function planChange(
  existing: LiveBinding[],
  additions: AttachSource[],
  removals: string[],
): { bindings: LiveBinding[]; keepBindings: string[]; added: string[]; removed: string[] } {
  // THE IDENTITY GUARD. The token WORKED and what it is pointed at is not this engine, so the write is
  // refused rather than risk rewriting a stranger's worker. Message unchanged; tag added.
  if (!looksLikeThisEngine(existing)) {
    throw new AttachRefusal("the engine's current bindings could not be confirmed (its scheduler/seal Durable Objects are not both present); refusing to modify it", { stage: "identity-guard", cause: "not-this-engine" });
  }
  if (additions.length === 0 && removals.length === 0) throw new AttachRefusal("nothing to change", { stage: "plan-validate", cause: "nothing-to-change" });

  const byName = new Map<string, LiveBinding>();
  for (const b of existing) if (typeof b.name === "string") byName.set(b.name, b);

  const removeSet = validateRemovals(byName, removals);
  const { fresh, added } = validateAdditions(byName, additions, removeSet);
  const { bindings, keepBindings } = buildWriteSet(existing, removeSet, fresh);
  assertSupersetProof(existing, bindings, keepBindings, removeSet, added);
  return { bindings, keepBindings, added, removed: [...removeSet] };
}

// planAttach is the attach-only convenience wrapper (kept for the add path + the validator).
export function planAttach(existing: LiveBinding[], additions: AttachSource[]): { bindings: LiveBinding[]; keepBindings: string[]; added: string[] } {
  const { bindings, keepBindings, added } = planChange(existing, additions, []);
  return { bindings, keepBindings, added };
}

// verifyAfter is the POST-WRITE proof: after the PATCH, re-read the bindings and confirm
// the change was EXACTLY what was intended. Every original binding survives EXCEPT the
// intended removals; the required Durable Objects survive; every addition landed; every
// removal is gone. Any mismatch is a loud, named alarm with the redeploy recovery, never
// a silent gap.
//
// LOST-UPDATE GUARD (TOCTOU): the write set is computed from the
// pre-read, so a concurrent attach/detach landing BETWEEN our read and our PATCH is a
// classic read-modify-write race. Two outcomes both have to be caught here, because the
// happy-path proofs above (which only check our OWN intended before/added/removed set)
// would otherwise report success on a silent clobber:
//   - a concurrent writer's binding our PATCH overwrote (it was added after our read, so
//     it is not in beforeExisting and is not one of our additions; it is now ABSENT or, if
//     it survived, it is an after-read binding the change did not intend); and
//   - our own write being clobbered by a concurrent writer whose PATCH won the race (our
//     addition is absent, already caught below; a binding we removed reappears, also caught;
//     or an after-read binding we never sent appears, caught by the unexpected-binding guard).
// The detection is exact: the after-read must contain ONLY bindings the change accounted
// for, every named before-binding that was not an intended removal, plus every intended
// addition. Any other NAMED binding in the after-read is a writer we did not coordinate
// with (its write or ours is a lost update), so we alarm rather than report success.
export function verifyAfter(beforeExisting: LiveBinding[], added: string[], removed: string[], after: LiveBinding[]): void {
  const afterNames = new Set(after.map((b) => (typeof b.name === "string" ? b.name : "")).filter((x) => x !== ""));
  const removeSet = new Set(removed);
  // Every original binding that was NOT an intended removal must still be present.
  for (const b of beforeExisting) {
    const name = typeof b.name === "string" ? b.name : "";
    if (name === "" || removeSet.has(name)) continue;
    if (!afterNames.has(name)) {
      throw new BindingAlarmError("postwrite-binding-missing", [name], `POST-WRITE SAFETY ALARM: the engine binding "${name}" is missing after the change. The settings update did not preserve it. Redeploy the engine with wrangler to restore its bindings; do not rely on this engine until you do.`);
    }
  }
  // The required Durable Objects must still be present and correctly typed.
  if (!looksLikeThisEngine(after)) {
    throw new BindingAlarmError("postwrite-do-missing", [], "POST-WRITE SAFETY ALARM: the engine's Durable Object bindings are missing after the change. Redeploy the engine with wrangler immediately to restore them.");
  }
  // Every addition must have landed.
  for (const name of added) {
    if (!afterNames.has(name)) {
      throw new BindingAlarmError("postwrite-addition-absent", [name], `the change reported success but the new binding "${name}" is not present afterwards; nothing else was harmed. Use the wrangler deploy path instead.`);
    }
  }
  // Every intended removal must be gone (precision: it did not silently survive).
  for (const name of removed) {
    if (afterNames.has(name)) {
      throw new BindingAlarmError("postwrite-removal-survived", [name], `the change reported success but "${name}" is still bound afterwards; nothing else was harmed. Use the wrangler deploy path instead.`);
    }
  }
  // LOST-UPDATE GUARD: the after-read must hold ONLY the bindings the change accounts for.
  // Anything else NAMED is a concurrent writer's binding that landed since our pre-read (our
  // PATCH would have clobbered it had it lost the race, or it clobbered ours had it won), so
  // the run is a lost update even though our own before/added/removed proofs all held.
  const accountedFor = new Set<string>();
  for (const b of beforeExisting) {
    const name = typeof b.name === "string" ? b.name : "";
    if (name !== "" && !removeSet.has(name)) accountedFor.add(name);
  }
  for (const name of added) accountedFor.add(name);
  for (const name of afterNames) {
    if (!accountedFor.has(name)) {
      throw new BindingAlarmError("lost-update-race", [name], `POST-WRITE SAFETY ALARM: the binding "${name}" is present after the change but the change did not add it and it was not bound before. A concurrent attach or detach modified the engine between this operation's read and its write, so one of the two writes was a silent lost update. Re-read the engine's bindings and re-apply the intended change; do not rely on this result.`);
    }
  }
}

// ---- The post-write binding-safety alarms, as RECORDABLE evidence ----------------------------------
//
// verifyAfter's alarms catch the worst-case failure in the act: a settings PATCH that did NOT preserve a
// binding, the engine's own Durable Objects gone, or a concurrent writer's PATCH proving one of the two writes
// was a silent lost update. Every one of them was thrown into an HTTP response, read by one operator in one
// browser tab, once -- while the pack kept showing two healthy-looking sources-attached audit rows and a source
// that had quietly stopped backing up.
//
// BindingAlarmError TAGS the throw at the site that knows, with the closed kind and the operator's own binding
// labels (the sourcesDetached redaction class the pack already ships). The MESSAGE is unchanged, so every
// operator-facing string, test and HTTP response is byte-identical: only the tag is new, and only the tag and
// the names are ever recorded. Never a resource id, an account id, a script name or a token.
export class BindingAlarmError extends Error {
  readonly bindingAlarmKind: BindingAlarmKind;
  readonly bindingAlarmNames: string[];
  constructor(bindingAlarmKind: BindingAlarmKind, bindingAlarmNames: string[], message: string) {
    super(message);
    this.name = "BindingAlarmError";
    this.bindingAlarmKind = bindingAlarmKind;
    this.bindingAlarmNames = bindingAlarmNames;
  }
}

/**
 * bindingAlarmOf reads the tag off a thrown binding-safety alarm. An UNTAGGED error yields null (it is one no
 * guard classified, and guessing from its text is exactly the free-text leak the vocabulary prevents).
 *
 * @param e - the thrown value.
 * @returns the closed kind + the binding labels, or null when untagged.
 */
export function bindingAlarmOf(e: unknown): { kind: BindingAlarmKind; names: string[] } | null {
  const k = (e as { bindingAlarmKind?: unknown } | null)?.bindingAlarmKind;
  if (typeof k !== "string" || !BINDING_ALARM_KINDS.includes(k as BindingAlarmKind)) return null;
  const raw = (e as { bindingAlarmNames?: unknown }).bindingAlarmNames;
  const names = Array.isArray(raw) ? raw.filter((n): n is string => typeof n === "string") : [];
  return { kind: k as BindingAlarmKind, names };
}

// ---- The PHASE tag, applied where the phase's own throw passes through -------------------------------
//
// The closed vocabulary, the error class and the reader all live in discovery-health.ts (the leaf that owns every
// attach fault class); this is the one piece that cannot, because it must recognise a BindingAlarmError, which is
// defined here.
//
// asAttachRefusal re-throws a phase's throw with its closed class attached, preserving the message VERBATIM, so
// the operator's sentence, the HTTP response and every test string are byte-identical and only the tag is new.
export function asAttachRefusal(cls: AttachRefusalClass, e: unknown): unknown {
  // A post-write alarm passes through UNTAGGED and unchanged. It means the write LANDED and the verify disagrees
  // with it, which outranks every phase class there is: burying a binding actually being dropped under a
  // "the plan was refused" label would be the worst mislabel this route could produce.
  if (bindingAlarmOf(e) !== null) return e;
  // Already tagged by an inner phase: the innermost class is the true one, so it wins. This return is also what
  // keeps the FINE {stage, cause} tag alive: an AttachRefusal carries both tags, and rebuilding the error from its
  // message here would silently strip the cause while leaving the coarse counter ticking.
  if (attachRefusalClassOf(e) !== null) return e;
  return new AttachRefusalError(cls, e instanceof Error ? e.message : String(e));
}
