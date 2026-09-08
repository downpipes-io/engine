// router-sources.ts -- source discovery + in-product attach support + restore-destination fallback +
// the role-invite email + the dynamic-route matchers: the bound-source enumerator, the engine-account
// resolvers, the signed-artefact fetcher, the run-destination fallback wrapper, the Cloudflare-API
// account/product listers, the best-effort role-grant invite email, and the config-change / owner-action
// path matchers + the denied-role guard.

import { makeCfAnalytics } from "../cost/cf-analytics.ts";
import { drainSizingOutcomes, estimateEstateSize, type SizingSource } from "../cost/sizing-probe.ts";
import { fetchDestConfig, type RuntimeDestConfig } from "../dest/factory.ts";
import { renderEngineEmailHtml } from "../email-theme.ts";
import { isCustomDomainAddress } from "../email.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { isReplicaFallbackReason, REASON_ORIGIN_REMOVED } from "../restore-reasons.ts";
import type { RestoreDestFallback, RestoreDestRefusal } from "./restore-types.ts";
import { type DownpipeState, RESERVED_BINDINGS } from "../sched/scheduler-do.ts";
import { recordCostSizing } from "./diag-cost.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import { classifyChannelFetchCause, type UpdateCauseClass } from "./diag-records.ts";
import type { Role } from "./identity.ts";
import { doURL, resolveDiscoveryToken } from "./router-helpers.ts";



// enumerateBoundSources classifies the engine's OWN env bindings by duck-typing (KV namespace /
// R2 bucket / D1 database / Secrets Store), excluding the engine's reserved bindings and plain
// vars. BINDING NAMES ONLY, no values, no keys, no data. Shared by GET /sources/discover (the
// picker's bound tier) and GET /setup-state (the boundSourceCount fact) so the two never drift.
//
// A binding that matches more than one of the five mutually exclusive capability groups below (R2/KV/D1/
// DO-like/email-like) is treated as a generic capability stub rather than any single kind: only the Secrets
// Store binding exhibits this shape (it answers "yes" to every probed method with an empty own property
// list), so a stub that also answers "get" is routed to secrets, before the DO/email/service exclusions
// get a chance to misfire on it. A binding matching exactly one group is unaffected and reaches the same
// exclude-or-classify ladder as before.
export function enumerateBoundSources(env: Env): { kv: string[]; r2: string[]; d1: string[]; secrets: string[] } {
  const bound: { kv: string[]; r2: string[]; d1: string[]; secrets: string[] } = { kv: [], r2: [], d1: [], secrets: [] };
  const bag = env as unknown as Record<string, unknown>;
  const fns = (o: object, names: string[]): boolean => names.every((n) => typeof (o as Record<string, unknown>)[n] === "function");
  for (const name of Object.getOwnPropertyNames(bag)) {
    if (RESERVED_BINDINGS.has(name)) continue;
    const value = bag[name];
    // vars/secrets (strings) and other primitives, plus null, are never auto-offered.
    if (value === null || typeof value !== "object") continue;
    const o = value as object;
    const isR2 = fns(o, ["get", "put", "list", "head", "createMultipartUpload"]);
    const isKv = fns(o, ["get", "put", "list", "getWithMetadata"]);
    const isD1 = fns(o, ["prepare", "batch", "exec"]);
    const isDoLike = fns(o, ["idFromName"]);
    const isEmailLike = fns(o, ["send"]);
    // The generic-capability-stub shape: a real binding on this
    // estate never matches more than one of these five groups. Three or more is a wide, deliberately
    // conservative margin above the two actually needed to reproduce the defect, so a binding that
    // legitimately overlaps two groups by coincidence is not swept in by this check alone.
    //
    // WHAT WOULD BREAK THIS. The margin holds only because every binding kind this engine deploys today
    // is a native object with a small, FIXED method set -- it is structurally incapable of matching more
    // than one group. A Workers RPC stub (a service binding targeting a WorkerEntrypoint/RpcTarget, or a
    // dispatch-namespace binding) is a JS Proxy with a wildcard trap and would match all five plus .get,
    // exactly like the binding this fix was built for. test/validate-rpc-binding-tripwire.ts fails the
    // build the moment such a binding is declared in wrangler.toml, so that assumption cannot go stale
    // silently; see that file for why, and src/admin/rpc-proxy-bindings-reverified.ts for how to clear it.
    const matchesMultipleGroups = [isR2, isKv, isD1, isDoLike, isEmailLike].filter(Boolean).length >= 3;
    if (matchesMultipleGroups && fns(o, ["get"])) {
      bound.secrets.push(name);
      continue;
    }
    if (isDoLike || isEmailLike || (fns(o, ["fetch"]) && !fns(o, ["get"]))) continue; // DO / email / service bindings
    if (isR2) bound.r2.push(name);
    else if (isKv) bound.kv.push(name);
    else if (isD1) bound.d1.push(name);
    else if (fns(o, ["get"]) && !fns(o, ["put"]) && !fns(o, ["prepare"])) bound.secrets.push(name);
  }
  bound.kv.sort();
  bound.r2.sort();
  bound.d1.sort();
  bound.secrets.sort();
  return bound;
}


// doURL is imported from the leaf ./router-helpers.ts (where it lives to break the router.ts<->spoke import
// cycles) for internal use here, e.g. building the SchedulerDO request paths in resolveEngineAccount.

// resolveEngineAccount finds the Cloudflare account the engine is deployed in (where a self-update must
// deploy), mirroring the attach flow: the discovery config's marked engineAccountId, else the CF_ACCOUNT_ID
// deploy var. Null when neither is known (the route then refuses with guidance). Never throws.
export async function resolveEngineAccount(env: Env, scheduler: DurableObjectStub): Promise<string | null> {
  try {
    const cfgResp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
    const cfg = ((await cfgResp.json()) as { config?: { engineAccountId?: string | null } | null }).config ?? null;
    if (cfg?.engineAccountId) return cfg.engineAccountId;
  } catch {
    // G051: a DO fault here silently demotes the engine's own account id to the env var -- or to null, which
    // makes a self-update refuse with "we cannot tell which account the engine is in" on an account that has
    // told us exactly that. Counted, so the refusal has a cause in the pack.
    void bumpAdminCounter(scheduler, "degraded-read-engine-account");
  }
  return typeof env.CF_ACCOUNT_ID === "string" && env.CF_ACCOUNT_ID.trim() !== "" ? env.CF_ACCOUNT_ID.trim() : null;
}


// The read-only discovery-token resolution (discovery config first, then the DISCOVERY_API_TOKEN env
// fallback) is the shared resolveDiscoveryToken in ./router-helpers.ts -- the SAME resolver the run path
// uses, so cost sizing and an env-only backup never disagree about whether a token is present.

// handleEstateSize answers GET /admin/cost/estate-size: an ANALYTICS-FIRST onboarding size estimate of the
// account's backup-relevant data, so the cost screen can show a real figure BEFORE the first backup runs.
// Read-only and best-effort: it reads Cloudflare storage analytics (no value reads, design Phase 2) for
// each configured downpipe's KV namespace / R2 bucket, and reports zero/"unavailable" for what it cannot
// size (no token, no account, D1) rather than guessing. Never throws; on any failure it returns an honest
// empty estate (available:false) so the caller degrades to manual entry, never blocks.
export async function handleEstateSize(env: Env, scheduler: DurableObjectStub): Promise<Response> {
  const json = (body: unknown): Response => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  try {
    const accountId = await resolveEngineAccount(env, scheduler);
    const token = await resolveDiscoveryToken(scheduler, env);
    if (accountId === null || token === null) {
      // G237: THE SETUP-TIME TICKET. "The cost projection shows 0 records for our account with thousands of
      // images/videos/scripts." The probe never ran at all here -- there is no account id, or no discovery
      // token -- so not a single sizing outcome is drained and NOTHING anywhere records that the estimate was
      // impossible. The console renders the honest-empty estate as an empty account, at the exact moment a
      // dead or under-scoped token is cheapest to catch (before any run has been attempted). The response is
      // byte-unchanged; the counter is the evidence that it is a MISSING TOKEN, not an empty account.
      await bumpAdminCounter(scheduler, "cost-estate-token-missing");
      return json({ totalBytes: 0, totalCount: 0, sizedSources: 0, sourceCount: 0, available: false, perSource: [] });
    }
    let downpipes: DownpipeState[] = [];
    try {
      downpipes = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as DownpipeState[];
    } catch {
      downpipes = [];
    }
    const sources: SizingSource[] = downpipes.map((d) => {
      const s = d.config.source;
      const out: SizingSource = { type: s.type };
      if (s.namespaceId !== undefined) out.namespaceId = s.namespaceId;
      if (s.bucketName !== undefined) out.bucketName = s.bucketName;
      return out;
    });
    const estate = await estimateEstateSize(sources, { analytics: makeCfAnalytics(token), accountId });
    // G296: drain the probe's closed outcome classes and file them. Until now the sizing probe's failures
    // were completely invisible: an unavailable size and a MEASURED zero both rendered as a 0, so a broken
    // discovery token (or a Cloudflare analytics schema drift, which no customer action can fix) showed the
    // customer an EMPTY ACCOUNT and invited them to conclude they had nothing worth backing up. The response
    // to the console is byte-unchanged; this only records what the probe already computed.
    await recordCostSizing(scheduler, drainSizingOutcomes());
    return json({ totalBytes: estate.totalBytes, totalCount: estate.totalCount, sizedSources: estate.sizedSources, sourceCount: sources.length, available: true, perSource: estate.perSource });
  } catch {
    // The honest-empty estate the console renders on ANY failure is exactly the state G296 exists to explain:
    // record whatever the probe managed to classify before it threw, so an available:false is not the end of
    // the trail. Best-effort, and deliberately AFTER the response shape is decided, so observing the fault can
    // never change what the operator sees.
    await recordCostSizing(scheduler, drainSizingOutcomes());
    // G237: the probe THREW, so the per-source classes may be empty (it may not have reached a single source)
    // and the whole projection collapses to the same mute zero the empty-account case renders. The counter says
    // the estimate FAILED rather than measured nothing.
    await bumpAdminCounter(scheduler, "cost-estate-probe-failed");
    return json({ totalBytes: 0, totalCount: 0, sizedSources: 0, sourceCount: 0, available: false, perSource: [] });
  }
}


// fetchArtefactBytes downloads the update bundle from the signature-verified channel's artefact url. It is
// https-only and redirect:"manual" (a redirected signed-artefact fetch cannot be steered to another host,
// V15.3.2), and bounds the size so a hostile url cannot exhaust memory. The BYTES are still verified
// against the channel's pinned sha384 by the state machine before any deploy, this only fetches. Returns
// null on any problem (bad url, non-https, non-2xx/redirect, empty, or over the cap).
export async function fetchArtefactBytes(url: string): Promise<Uint8Array | null> {
  const r = await fetchArtefactBytesDetailed(url);
  return r.ok ? r.bytes : null;
}

/**
 * fetchArtefactBytesDetailed (G159) is fetchArtefactBytes's SIX-WAY split. The bare null collapsed a CDN 404
 * (the signed channel names an artefact that does not exist), a 5xx (wait), a refused redirect (a signed update
 * being steered elsewhere -- a security signal, V15.3.2), an empty body, an over-cap bundle and a network fault
 * into ONE fixed audit detail, "artefact-download-failed". Those are five different tickets and one incident.
 *
 * The closed cause + the numeric HTTP status are the only things that ever leave this function: the artefact
 * URL, the redirect target and the response body never do.
 *
 * @param url - the signature-verified channel's artefact url.
 * @returns the bytes, or the closed cause + the observed status (0 when no HTTP exchange happened).
 */
export async function fetchArtefactBytesDetailed(url: string): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; cause: UpdateCauseClass; httpStatus: number }> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, cause: "url-config", httpStatus: 0 };
  }
  if (u.protocol !== "https:") return { ok: false, cause: "url-config", httpStatus: 0 };
  try {
    const r = await fetch(url, { redirect: "manual" });
    if (!r.ok) {
      // redirect:"manual" surfaces a 3xx as an opaque non-ok response, so a REFUSED redirect is distinguished
      // here rather than folded into a generic "the CDN said no".
      return { ok: false, cause: classifyChannelFetchCause(r.status), httpStatus: r.status };
    }
    const buf = new Uint8Array(await r.arrayBuffer());
    if (buf.length === 0) return { ok: false, cause: "empty-body", httpStatus: r.status };
    if (buf.length > 30 * 1024 * 1024) return { ok: false, cause: "oversize", httpStatus: r.status }; // sane Worker-bundle cap (30 MiB)
    return { ok: true, bytes: buf };
  } catch {
    return { ok: false, cause: "network", httpStatus: 0 }; // DNS / TLS / reset: there IS no status
  }
}


// resolveRunDestCandidates resolves the ORDERED destinations a restore/drill/verify may read a run from:
// the caller's explicit override alone if given, else the run's downpipe destinations (PRIMARY first,
// then replicas) looked up from the runId via the DO history, else [undefined] = the default. The list
// is what lets a restore FALL BACK to a replica when the primary bucket is lost (the 3-2-1 DR case). A
// lookup fault degrades to [the default], never throwing.
export async function resolveRunDestCandidates(scheduler: DurableObjectStub, runId: string, explicit?: string): Promise<Array<string | undefined>> {
  if (explicit) return [explicit];
  if (!runId) return [undefined];
  try {
    const resp = await scheduler.fetch(doURL(`/downpipes/dests-for-run?runId=${encodeURIComponent(runId)}`), { method: "GET" });
    if (resp.ok) {
      const { destinationIds } = (await resp.json()) as { destinationIds?: string[] };
      if (Array.isArray(destinationIds) && destinationIds.length > 0) return destinationIds;
    }
  } catch {
    /* fall through to the default */
  }
  return [undefined];
}


// fallbackContext builds the RestoreDestFallback describing an attempt that is about to run, or undefined
// when nothing has refused yet. Returning undefined for the first attempt is the whole discipline: a
// first-choice restore carries no field, so "was this a fallback?" is answered by the field's PRESENCE and
// there is no boolean that a consumer can forget to read. servedAt is 1-based over the walk, so the first
// attempt that can ever produce one is the second, and it is never 1.
function fallbackContext(refused: readonly RestoreDestRefusal[], servedDestinationId: string | undefined): RestoreDestFallback | undefined {
  if (refused.length === 0) return undefined;
  return {
    servedAt: refused.length + 1,
    ...(servedDestinationId !== undefined ? { servedDestinationId } : {}),
    refused: refused.map((r) => ({ ...r })),
  };
}

// stampDestFallback attaches the walk to a result the walk did not get from its first choice, and returns
// the result UNTOUCHED otherwise -- so the common path allocates nothing and no existing result shape
// changes. It stamps a REFUSAL as readily as a success: an operator told only that the whole restore failed,
// on a run whose three copies failed for three different reasons, has been told the least useful version of
// what happened.
function stampDestFallback<T>(r: T, fallback: RestoreDestFallback | undefined): T {
  if (fallback === undefined || r === null || typeof r !== "object") return r;
  return { ...r, destFallback: fallback };
}

// withRunDestFallback runs a restore-class operation against the run's destinations in order (primary,
// then replicas), returning the FIRST result that either succeeds or fails for a reason a replica could NOT
// remedy. When the primary read fails for an AVAILABILITY reason (the object is missing here, the primary
// refused/faulted with an HTTP status -- 403 revoked creds / 5xx outage / redirect / 429 -- or a
// network/transport fault reading the primary), it transparently retries the next destination, the 3-2-1 DR
// payoff. Each restore-class op OPENS the run before any write, so a fallback never half-applies.
//
// INTEGRITY is NOT availability: a TAMPER / verification failure (bad signature, hash mismatch, Merkle-root
// or key-commitment failure) returns IMMEDIATELY and never falls through to a replica, because that is a real
// corruption signal the operator must see, not a missing object. isReplicaFallbackReason (in
// restore-reasons.ts, shared with every reason producer) is the single source of truth for which reasons
// fall back; see its contract for the full availability-vs-integrity split.
//
// EVERY CANDIDATE IS VERIFIED IN FULL, and nothing is inherited from a refused attempt. The walk re-runs the
// caller's whole op against the next destination, and each restore-class op opens the run from that
// destination's own bytes: its own root manifest, its own signature, its own shards and record hashes, and
// (where the op asks for it) its own `_RECOVERY/RUNLOG`. The only thing that crosses from one attempt to the
// next is the refusal record below, which is evidence and never an input to a verdict. So a result served by
// a replica is a result the replica proved on its own, not one the primary's failure was waved past.
//
// A SERVED FALLBACK IS NOT SILENT. Until now it was: the refused attempt was dropped on the floor, no result
// shape carried a destination identity, and the fault ring projects only from a FAILED outcome, so a restore
// served by the third copy after two refusals was indistinguishable from one served by the first. The walk
// now records each refusal and stamps a RestoreDestFallback onto any result it did not get from the first
// choice. The op also RECEIVES the refusals so far, which is how the apply path carries the same fact into
// the signed receipt core (a receipt is what a customer keeps to prove what they recovered and from where).
export async function withRunDestFallback<T extends { ok: boolean }>(
  scheduler: DurableObjectStub,
  runId: string,
  explicit: string | undefined,
  op: (destCfg: RuntimeDestConfig | null, fallback?: RestoreDestFallback) => Promise<T>,
  wrapKey?: Uint8Array,
): Promise<T> {
  const candidates = await resolveRunDestCandidates(scheduler, runId, explicit);
  let last: T | undefined;
  // DEST-2 detection: did the run carry RECORDED destination id(s) (a string candidate, not the [undefined]
  // default fallback), and did ANY of them still resolve to a configured destination? When the run recorded
  // destinations but NONE are configured any more, every read fell through to the env default and the only
  // honest cause is "the destination(s) holding this run were removed", not a generic missing object.
  let recordedId = false;
  let anyConfigured = false;
  // The destinations this walk has already tried and been refused by, in walk order. Empty until the first
  // refusal, so the overwhelmingly common first-choice restore builds and stamps nothing at all.
  const refused: RestoreDestRefusal[] = [];
  // The context of the MOST RECENT attempt, so the exhausted tail below stamps the walk it actually made
  // rather than losing it. Without this, the one outcome where every copy failed -- the outcome an operator
  // most needs the per-destination breakdown for -- would be the only one that reported no walk at all.
  let lastContext: RestoreDestFallback | undefined;
  for (const id of candidates) {
    if (typeof id === "string") recordedId = true;
    // wrapKey opens an at-rest-encrypted credential (CONFIG_WRAP_KEY set) before the restore-class op
    // builds a Destination from it; undefined is a no-op decrypt (back-compat plaintext floor).
    const cfg = await fetchDestConfig(scheduler, id, wrapKey);
    if (cfg) anyConfigured = true;
    // The fallback context handed to the op describes the walk SO FAR: which destination is about to serve
    // and which ones already refused. It is undefined on the first attempt, so an op that threads it into a
    // receipt writes nothing extra on a first-choice restore and its receipt hashes exactly as it always did.
    const context = fallbackContext(refused, id);
    lastContext = context;
    const r = await op(cfg, context);
    last = r;
    // Return immediately on success, or on a failure a replica could NOT fix (integrity/freshness/config).
    // Only an AVAILABILITY failure on this destination falls through to the next candidate.
    if (r.ok || !isReplicaFallbackReason((r as { reason?: string }).reason)) return stampDestFallback(r, context);
    refused.push({ ...(typeof id === "string" ? { destinationId: id } : {}), reason: (r as { reason?: string }).reason ?? "" });
  }
  // DEST-2: every recorded candidate exhausted on an AVAILABILITY reason AND none of the recorded ids still
  // resolves to a configured destination -> the run's copy lived on a removed destination. Re-label the
  // generic availability reason (e.g. "object missing") with the actionable removed-origin cause so the
  // operator is told to re-add the destination or re-point the restore (the `explicit` override seam), not
  // left chasing a missing object that is structurally unaddressable. This never masks an integrity failure
  // (those already returned above, are excluded from isReplicaFallbackReason, and can never reach here).
  if (last !== undefined && recordedId && !anyConfigured && isReplicaFallbackReason((last as { reason?: string }).reason)) {
    return stampDestFallback({ ...last, reason: REASON_ORIGIN_REMOVED } as T, lastContext);
  }
  return stampDestFallback(last as T, lastContext);
}


// RoleInvite is the redaction-safe slice of the persisted RoleEntry the invite send needs: the
// granted person's email (the recipient), the built-in role, and the OPTIONAL custom-role name. It is
// the customer's own people data, never a secret; no key, value or credential is involved.
export interface RoleInvite {
  email: string;
  role: Role;
  customRole?: string;
  // inviteToken, when present, is the single-use, email-bound passkey REGISTRATION invite the DO minted
  // because the grant was to an email with no passkey credential yet. The invite email embeds it in a
  // register link so the granted person can enrol their first key; without it the email still sends (it
  // just points at the bare console). It is a one-shot capability the DO re-validates and consumes on
  // register/finish, not a secret to protect at rest, but it is still only ever sent to the bound email.
  inviteToken?: string;
}


// parseRoleEntry narrows the DO's 200 /roles body (the persisted RoleEntry) to the slice the invite
// needs. It returns null on anything unexpected (a non-object, a missing/blank email, a non-string
// role) so a shape surprise degrades to "no invite", never a throw on the grant path. A custom-role
// grant pins the stored role to the viewer floor and carries the custom-role NAME, so customRole is
// read when present (it is the human-facing label the invite names).
export function parseRoleEntry(bodyText: string): RoleInvite | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const o = parsed as Record<string, unknown>;
  if (typeof o.email !== "string" || o.email.length === 0) return null;
  if (!isRoleString(o.role)) return null;
  const role = o.role;
  const customRole = typeof o.customRole === "string" && o.customRole.length > 0 ? o.customRole : undefined;
  // inviteToken is present on the DO's 200 body only when the grant minted a passkey-registration invite
  // (the granted email had no credential yet). It is read here so the invite email can carry the register
  // link; absent otherwise (the person already has a key, or invites are not in play).
  const inviteToken = typeof o.inviteToken === "string" && o.inviteToken.length > 0 ? o.inviteToken : undefined;
  return { email: o.email, role, ...(customRole !== undefined ? { customRole } : {}), ...(inviteToken !== undefined ? { inviteToken } : {}) };
}


// INVITE_SUBJECT is the fixed, redaction-safe subject line for the role-invite notification. It names
// no person and no role (the role is in the body), so it carries nothing sensitive and is stable.
export const INVITE_SUBJECT = "You have been granted a role on this organisation's Downpipes backups";


// sendRoleInvite best-effort emails a newly granted person that they now hold a role, with a sign-in
// pointer to the in-account console. It is the email counterpart of stampRestoreProven: strictly
// best-effort, fully fail-open, and it NEVER throws (so a caller may await it without risking the
// grant). The send is OFF unless BOTH env.EMAIL is bound AND env.INVITE_EMAIL_FROM is set (a separate,
// opt-in sender from EMAIL_FROM, so an account can run alerts/expiry email without emailing on every
// role grant). The sender and the recipient are each validated as custom-domain addresses at this
// boundary (the house rule, the same check sendEmail applies). The body is the redaction-safe line the
// contract specifies, naming the human-facing role (the custom-role NAME when assigned, else the
// built-in role) and the console origin. Any failure (unconfigured, an invalid address, or a thrown
// send) returns a short reason and is swallowed; the grant has already committed regardless.
// inviteSenderConfigured is the ONE definition of "this deployment has an invite path at all": the email binding
// is bound AND a dedicated invite sender address is set. sendRoleInvite gates on exactly this (below), the pack's
// status.inviteSenderConfigured REPORTS exactly this, and the role-grant-invite-undeliverable counter is gated on
// exactly this (router-rbac.ts). All three read the SAME function, so the boolean in the pack and the predicate
// behind the counter cannot drift apart, which is the whole basis on which support joins them.
//
// A MALFORMED sender address still reads as configured here: the operator intended an invite path and the send
// refused it, which is the state the counter is for. "Configured" is an intent, not a proof of delivery.
export function inviteSenderConfigured(env: Env): boolean {
  const binding = env.EMAIL;
  if (!binding || typeof binding.send !== "function") return false;
  const fromRaw = env.INVITE_EMAIL_FROM;
  return typeof fromRaw === "string" && fromRaw.trim().length > 0;
}

export async function sendRoleInvite(env: Env, invite: RoleInvite): Promise<{ sent: boolean; reason?: string }> {
  const binding = env.EMAIL;
  // OFF unless the binding is bound AND a dedicated invite sender is configured. Either absent is the
  // honest "invites not configured" state: a silent no-op, never an error on the grant path.
  if (!binding || typeof binding.send !== "function") return { sent: false, reason: "invite-not-configured" };
  const fromRaw = env.INVITE_EMAIL_FROM;
  if (typeof fromRaw !== "string" || fromRaw.trim().length === 0) return { sent: false, reason: "invite-from-not-configured" };
  const fromV = isCustomDomainAddress(fromRaw);
  if (!fromV.ok) return { sent: false, reason: "invite-from-invalid" };
  // The recipient is the granted person's email. The DO already normalised/bounded it, but re-validate
  // it as a custom-domain address here at the send boundary (a non-custom-domain grantee is a no-op).
  const toV = isCustomDomainAddress(invite.email);
  if (!toV.ok) return { sent: false, reason: "invite-recipient-invalid" };
  // The human-facing role label: the custom-role NAME when the grant referenced one (the stored built-in
  // role is then the viewer floor and would mislead), else the built-in role. Both are the customer's
  // own role catalogue, never a secret.
  const roleLabel = invite.customRole !== undefined ? invite.customRole : invite.role;
  // The console origin the invite points the new member at. When CONSOLE_ORIGIN is unset, fall back to a
  // generic phrase so the sentence still reads cleanly (no broken "Sign in at ." with an empty origin).
  const originSet = typeof env.CONSOLE_ORIGIN === "string" && env.CONSOLE_ORIGIN.trim().length > 0;
  const origin = originSet ? env.CONSOLE_ORIGIN!.trim() : "your Downpipes console";
  // REGISTRATION LINK (the proven INVITE path): when the grant minted a single-use, email-bound passkey
  // registration invite (the person has no key yet), include a register link carrying that token so the
  // bound email can enrol its first credential. The DO takes the bound email FROM the invite, so the link
  // proves THIS email was authorised by the granting Owner. The link is built only when both the origin is
  // known and a token was minted; otherwise the invite is a plain "sign in" pointer (an already-enrolled
  // member adds further keys via the self-add path). The token is URL-encoded into the fragment so it is
  // not logged in server access logs the way a query string can be, and the SPA reads it client-side.
  const registerLink = originSet && invite.inviteToken !== undefined
    ? `${origin}/#/register?invite=${encodeURIComponent(invite.inviteToken)}`
    : null;
  const text = registerLink !== null
    ? `You have been granted the ${roleLabel} role on this organisation's Downpipes backups. Set up your passkey to sign in: ${registerLink}`
    : `You have been granted the ${roleLabel} role on this organisation's Downpipes backups. Sign in at ${origin}.`;
  // The html twin carries the same role sentence and the same sign-in URL, shown as a button; the URL
  // stays in the text part too. The register link is used when one was minted, else a plain sign-in
  // pointer, and no button at all when origin is the generic fallback phrase (not a real URL). roleLabel
  // is the customer's own role name, escaped by the renderer; no vendor sign-off (engine mail).
  const roleSentence = `You have been granted the ${roleLabel} role on this organisation's Downpipes backups.`;
  const html = registerLink !== null
    ? renderEngineEmailHtml({ subject: INVITE_SUBJECT, heading: "You have a new role", paragraphs: [roleSentence, "Set up your passkey to sign in."], cta: { label: "Set up your passkey", url: registerLink } })
    : renderEngineEmailHtml({ subject: INVITE_SUBJECT, heading: "You have a new role", paragraphs: [roleSentence], ...(originSet ? { cta: { label: "Sign in", url: origin } } : {}) });
  try {
    // Only the validated sender, the single validated recipient, and the redaction-safe subject/body
    // (the text and its branded HTML twin) cross to the binding; no header, attachment or raw field besides.
    await binding.send({ to: toV.address, from: fromV.address, subject: INVITE_SUBJECT, text, html });
    return { sent: true };
  } catch (e) {
    // Fail-open: a rejected send, an edge restriction, or a binding that threw is swallowed. Log a
    // coarse reason only, NEVER the recipient, subject or body. The grant has already committed.
    log("error", `role-invite send skipped (non-critical, grant still committed): ${(e as Error).message}`);
    return { sent: false, reason: "invite-send-failed" };
  }
}


export type { AccountListing, DiscoveryConfigView } from "./router-sources-discovery.ts";
// ---- account-wide source discovery (console-set token; multi-account) -------------------------
// The discovery slice (the Cloudflare-API caller, the account resolvers, the paginating lister, and
// the per-account product lister) MOVED VERBATIM to the leaf ./router-sources-discovery.ts to keep
// this spoke under the structural budget (engine-struct-miss-routersources). Re-exported here so
// callers importing them by name from router-sources.ts (or via router.ts) are unchanged.
export {
  cfApi,
  DISCOVERY_LIST_CAP,
  listAccountProducts,
  MAX_DISCOVERY_ACCOUNTS,
  resolveDiscoveryAccounts,
  resolveEngineAccountId,
} from "./router-sources-discovery.ts";


// matchActionPath parses a dynamic-segment POST /<prefix>/<id>/(approve|reject) route a literal switch case
// cannot express, returning the decoded id + the action, or null when the method/path is not a match (so the
// caller falls through to the literal switch and a 404 falls out of it). The <id> is taken from the path
// segment (the trusted route, not a client body field) and percent-decoded. The action segment must be
// exactly "approve" or "reject" and the id must be non-empty; anything else returns null. It does NOT
// validate the id shape beyond non-empty: the DO looks the id up and returns "no such ..." for an unknown
// one, so a malformed id is a clean 400 from the DO, not a router concern. `prefix` is the literal route
// stem without the surrounding slashes, e.g. "config/changes" or "owner-actions".
function matchActionPath(method: string, sub: string, prefix: string): { id: string; action: "approve" | "reject" } | null {
  if (method !== "POST") return null;
  const m = new RegExp(`^/${prefix}/([^/]+)/(approve|reject)$`).exec(sub);
  if (m === null) return null;
  const idRaw = m[1]!;
  const action = m[2] as "approve" | "reject";
  let id: string;
  try {
    id = decodeURIComponent(idRaw);
  } catch {
    return null;
  }
  if (id.length === 0) return null;
  return { id, action };
}


// matchConfigChangeAction parses the change-control routes POST /admin/config/changes/<id>/(approve|reject).
// The <id> is a ULID the DO minted; see matchActionPath for the full parse and security contract.
export function matchConfigChangeAction(method: string, sub: string): { id: string; action: "approve" | "reject" } | null {
  return matchActionPath(method, sub, "config/changes");
}


// matchOwnerActionAction is the owner-action analogue of matchConfigChangeAction: it parses the dynamic
// POST /admin/owner-actions/<id>/(approve|reject) path. The id is the trusted path segment forwarded to the
// DO in the body; see matchActionPath for the full parse and security contract.
export function matchOwnerActionAction(method: string, sub: string): { id: string; action: "approve" | "reject" } | null {
  return matchActionPath(method, sub, "owner-actions");
}


// isRoleString is the router-side guard for the role string on a DENIED role write (where the DO
// guard never runs because the router refused first), so the denied audit target is always a valid
// closed-union role. It mirrors identity.ts isRole (kept as a local copy, not a value import at the
// use site) and so must list ALL six roles, including the two narrow roles, or a denied write naming
// one of them would fall back to "viewer" in the audit target.
export function isRoleString(v: unknown): v is Role {
  return (
    v === "viewer" ||
    v === "operator" ||
    v === "restore-operator" ||
    v === "approver" ||
    v === "access-admin" ||
    v === "owner"
  );
}
