// OPT-IN dual-control for the HIGH-BLAST-RADIUS OWNER OPERATIONS a single compromised or coerced owner
// account could use to STEAL data or BREAK the system. It REUSES the SAME org toggle the config-change gate
// reads (requireConfigApproval): one switch arms BOTH the config-change gate (change-control.ts) AND these
// owner ops, so an operator turns dual control on once. When the toggle is OFF (the default) this module is
// never reached and every owner op runs inline EXACTLY as before. When it is ON, an owner op does not
// execute on the first call: a PENDING OWNER-ACTION APPROVAL is recorded, bound to a canonical hash over the
// action's DECISION-RELEVANT params, and a SECOND owner (maker != checker on the stable subject axis) must
// approve before the SAME action runs with the proposer's authority re-resolved LIVE.
//
// WHY A SEPARATE MECHANISM FROM change-control.ts. The config-change gate keys a pending change to the
// config-history HEAD and replays a config-MUTATING DO method through a dry-run/diff model. These owner ops
// do NOT fit that model: they are not config-history mutations (a destination repoint, an IdP connection
// change, an engine self-deploy, a discovery-token set), several EXECUTE IN THE ROUTER with a one-shot
// client deploy token (update/apply, sources/attach), and several have no clean dry-run. So this is a
// PARALLEL approval store, deliberately mirroring approvals.ts (restore) and change-control.ts (config) in
// shape and discipline: the pure binding-hash + maker != checker + state-machine + lazy-expiry logic lives
// here; the scheduler Durable Object is the single storage authority and drives this pure logic, so the
// propose, the approve and the execute can never compute the binding or the state two different ways.
//
// THE BINDING (maker != checker, re-arm-on-change, no stale apply). A pending owner action is keyed by a
// FRESH id and carries an actionHash over its DECISION-RELEVANT inputs: the OPERATION KIND, its canonical
// PARAMS (the destination id + verified fields, the IdP connId + change, the update target version + the
// artefact sha, the discovery token's account fingerprint, etc.), and the PROPOSER IDENTITY (email + stable
// subject + propose-time groups) the execute re-resolves authority from. The approve path re-derives the
// SAME hash from the stored record alone: if the params OR the proposer identity were tampered, the hash no
// longer matches and the approve is refused. A re-submission that changes any decision field yields a
// DIFFERENT hash that simply has no matching pending record (the server-side teeth behind re-arm-on-change).
// For MOST kinds the params are NAMES, ids, fingerprints and verified non-secret fields only. For the
// secret-bearing kinds (discovery-token-set, dest-set/dest-put, idp-conn create/delete/enabled) the params
// carry the LIVE SECRET the proposer supplied verbatim at rest, so the actionHash is SHA-384 over that full
// content INCLUDING the secret. It is therefore NOT safe to treat the hash as secret-free: it is computed
// over potentially-secret material stored at rest in DO storage (the listing projection strips the secret on
// read, but the verbatim params and the hash do not). It uses the SAME primitives the rest of the codebase
// uses for fingerprints (canonical JSON + SHA-384, "sha384:" prefix).
//
// THE ROUTER-EXECUTED OPS (the subtle ones). update/apply, update/settle and sources/attach do the
// privileged work IN THE ROUTER with a one-shot client deploy token, NOT in the DO. For these the flow is:
//   1. the maker calls the route with NO approval -> the ROUTER asks the DO to RECORD a pending approval and
//      returns 202 WITHOUT consuming the token and WITHOUT running the privileged op (the token is not even
//      required on this first call);
//   2. a SECOND owner approves at the DO (maker != checker), which marks the record APPROVED-AND-ARMED;
//   3. the maker RE-SUBMITS the route WITH the one-shot token; the router asks the DO to CONSUME the armed
//      approval for the SAME action hash (single-use, the consume is atomic in the DO) and proceeds ONLY if
//      the DO confirms a usable armed approval existed, so the token is used exactly once on the approved
//      execution. With dual control ON, no op THAT REACHES THIS GATE can run on one owner.
//
// WHICH OPS REACH IT IS NOT "ALL OF THEM", and the sentence above used to say it was. The fourteen DO-side
// kinds reach it unconditionally. Of the four router-executed kinds, update-apply and update-settle consult
// the gate ONLY when the release's risk class is "migration" or "breaking" (updateNeedsDualControl in
// router-core.ts, called at router-updates.ts, router-updates-ramp.ts and router-updates-components.ts). A
// "routine" release therefore applies on one owner with dual control armed. That narrowing is deliberate
// (only gate dangerous activities) and is argued at the router, but it belongs here too, because the
// property an auditor quotes is this one. Note what decides it: riskClass comes from the SIGNED channel
// manifest, so the release's publisher, not the customer, picks whether the customer's armed dual control
// applies to a given release. normaliseRiskClass makes an absent or unknown class default to migration, so
// the failure direction is toward gating.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries a value.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { GovernanceDecision } from "./approvals.ts";

// OwnerActionKind is the CLOSED set of high-blast-radius owner operations the gate covers. Each is an act a
// single compromised/coerced owner could use to STEAL data (repoint/exfiltrate, hand out an account-read CF
// credential, egress a sealed support bundle) or BREAK the system (destroy backup copies, ship arbitrary
// engine code, take over who can sign in, remove the way back in, change the auth posture). It is a closed
// union so a crafted kind cannot reach the execute path (the DO's dispatch is exhaustive over this set and
// fails closed on any other value). The DELIBERATELY-EXCLUDED owner ops (session-terminate, licence pin,
// canary-config, passkey-credential-delete, config snapshot) are NOT here: they are legitimate-response or
// low-blast actions that dual control would only hamper.
export type OwnerActionKind =
  // Destinations: where every backup lands. A repoint/add exfiltrates all future backups to an
  // attacker-controlled bucket; a remove/force destroys proven copies; default repoints the seal target.
  | "dest-set" // POST /destination (the legacy single destination set/repoint)
  | "dest-put" // POST /destinations (add a new destination OR edit one)
  | "dest-remove" // POST /destinations/remove (incl. force, which drops the only proven copies)
  | "dest-default" // POST /destinations/default (repoint which destination is the seal target)
  // SIEM push destination (SIEM-PUSH-DESIGN.md): where the hash-chained audit trail is forwarded
  // to. Architecturally a sibling of the destinations above (the engine reconstructs a live secret on every
  // delivery); a repoint/replace could redirect identity-bearing audit data to an attacker-controlled
  // endpoint, the same blast class as repointing a backup destination. Clearing it is NOT DUAL-CONTROL gated
  // (the safe direction; see push-dest-set's HIGH_BLAST_ALWAYS_GATED membership below and POST
  // /admin/push/delete). It IS change-controlled: the two are different axes, and the clear enforces the
  // change-number policy at its own DO route (scheduler-do-routing.ts, kind "push-clear") rather than here,
  // because this union is the DUAL-CONTROL set and an entry in it would queue the clear for a second owner.
  | "push-dest-set" // POST /push (set/replace the SIEM push destination)
  // OTLP/HTTP metrics push destination: where the backup-health metric
  // snapshot is pushed to. The SNAPSHOT sibling of push-dest-set and the same blast class: a repoint/replace
  // could redirect the engine's operational telemetry (which downpipe/destination is healthy, when each last
  // succeeded) to an attacker-controlled collector, and it carries a live bearer/API-key secret the approved
  // execution replays. Clearing it is NOT DUAL-CONTROL gated (the safe direction; see POST /otlp-push/delete)
  // but IS change-controlled at its own DO route, kind "otlp-clear", exactly like the SIEM clear above.
  | "otlp-push-dest-set" // POST /otlp-push (set/replace the OTLP metrics push destination)
  // Update: ship arbitrary engine code. apply promotes a new version live; settle finalises it as keep or
  // rollback. ROUTER-EXECUTED (a one-shot deploy token runs the privileged op in the router, not the DO).
  // update-settle gates the KEEP direction ONLY (trusting the new code); ROLLBACK to the known-good version
  // is the SAFE recovery direction and is NEVER gated, the router decides keep-vs-rollback by flying the
  // canary (no token) and only invokes this gate when the decision is KEEP (see POST /update/settle).
  | "update-apply"
  | "update-settle"
  // IdP connections: account takeover / who can sign in. Adding a hostile connection, editing one, or
  // enabling/disabling one changes which external identities can authenticate to the engine.
  | "idp-conn-create"
  | "idp-conn-delete"
  | "idp-conn-enabled"
  // Roll over a SAML signing cert in place: a zero-downtime trust-root edit. A signing cert is the SAML
  // trust anchor, so appending/replacing one changes which assertions verify - the same account-takeover surface
  // as adding a connection - but as ONE approval rather than the two a delete+recreate rollover would queue.
  | "idp-conn-cert"
  // Remove the way back in: retire the ADMIN_TOKEN bearer (the in-app way back in). (NOTE: the "require-access
  // posture flip" the task also names is NOT a gated kind because the engine has no setter for it, the
  // ADMIN_TOKEN_DISABLED posture is an ENV var the console cannot write; POST /policy/require-access is a
  // read-only ECHO that stores nothing, so there is no state change to gate. See the router route.)
  | "break-glass-retire"
  // Sources: hand out an account-read CF credential / change the backup scope. discovery-token sets the
  // customer's read-only API token; discovery-accounts changes which accounts are browsed; attach (ROUTER-
  // EXECUTED) rewrites the engine's own bindings with a one-shot deploy token.
  | "discovery-token-set"
  | "discovery-accounts-set"
  | "sources-attach"
  // Support credentials: egress of a sealed support bundle. mint opens a (read-only, scoped, expiring) pull
  // surface a vendor/SIEM reads; the gate stops a lone owner opening that surface. ROUTER-EXECUTED: the
  // router GENERATES the one-time secret on the APPROVED execution (a fresh non-deterministic secret cannot
  // be pre-recorded), so the decision (open scope X) is what is approved and the mint runs once on consume.
  | "support-credential-mint"
  // Disarm the dual-control OFF SWITCH ITSELF (turn requireConfigApproval true -> false). This is the gate
  // covering its OWN off switch, ASYMMETRICALLY (exactly like break-glass-retire gates only retire:true):
  // ARMING (false -> true) and any no-op are immediate, but DISARMING when the gate is ON is the one
  // dangerous direction (a single compromised owner could otherwise flip the gate OFF, run every gated op
  // inline, and flip it back, a one-owner bypass of the whole guarantee), so it takes a SECOND owner's
  // approval. It is DO-EXECUTED: the approve runs setRequireConfigApproval(false) as the proposer. The
  // BARE-TOKEN break-glass owner is NEVER routed through this kind, it disarms IMMEDIATELY at the route
  // (the break-glass owner cannot propose/approve owner actions by design, so it must keep a direct way to
  // disarm or the account could be locked out of its own off switch; arm-immediate + break-glass-disarm-
  // immediate together prove no deadlock). The params are empty (the decision is simply "disarm"); the
  // summary is redaction-safe; no secret is involved.
  | "dual-control-disable";

// OWNER_ACTION_KINDS is the value-level companion to the type-only union (the union cannot be iterated at
// runtime), used by isOwnerActionKind and by the validator's "the dispatch covers every kind" check. Kept in
// lockstep with OwnerActionKind (the validator asserts the two agree so they cannot drift).
export const OWNER_ACTION_KINDS: readonly OwnerActionKind[] = [
  "dest-set",
  "dest-put",
  "dest-remove",
  "dest-default",
  "push-dest-set",
  "otlp-push-dest-set",
  "update-apply",
  "update-settle",
  "idp-conn-create",
  "idp-conn-delete",
  "idp-conn-enabled",
  "idp-conn-cert",
  "break-glass-retire",
  "discovery-token-set",
  "discovery-accounts-set",
  "sources-attach",
  "support-credential-mint",
  "dual-control-disable",
];

// ROUTER_EXECUTED_OWNER_ACTIONS are the kinds whose privileged op runs IN THE ROUTER with a one-shot deploy
// token, NOT in the DO. They use the propose -> approve -> RE-SUBMIT-with-token -> consume flow (the DO never
// runs them; it only records, approves and consumes the approval). The other kinds are DO-EXECUTED: the DO
// runs the real method on a clean approve. Kept here so the DO and the validator agree on which flow a kind
// uses without re-deriving it. (The set is small and fixed; membership is a linear test.)
export const ROUTER_EXECUTED_OWNER_ACTIONS: ReadonlySet<OwnerActionKind> = new Set<OwnerActionKind>([
  "update-apply",
  "update-settle",
  "sources-attach",
  // support-credential-mint is router-executed too: the router GENERATES the one-time secret on the approved
  // execution (a fresh non-deterministic secret cannot be recorded at propose time and re-shown), so the mint
  // runs in the router on consume, exactly like the token-flow ops, but the "token" here is the secret the
  // router itself generates rather than a client-supplied deploy token.
  "support-credential-mint",
]);

// isRouterExecutedOwnerAction reports whether a kind is router-executed (the token-flow) vs DO-executed.
export function isRouterExecutedOwnerAction(kind: OwnerActionKind): boolean {
  return ROUTER_EXECUTED_OWNER_ACTIONS.has(kind);
}

// HIGH_BLAST_ALWAYS_GATED is the SUBSET of owner-action kinds whose blast radius is high enough that dual
// control is AUTO-APPLIED (not opt-in) once a SECOND owner exists, regardless of the requireConfigApproval
// toggle: repointing/removing a destination (where every backup lands, so a lone compromised owner could
// exfiltrate all future backups or destroy proven copies) and changing the external IdP connections (who
// can sign in). When there is only ONE owner the toggle still governs these (forcing dual control with no
// second owner would deadlock the single-owner self-hosted bootstrap, with no one able to approve); the
// fresh-auth step-up is then the sole control. This is DELIBERATELY narrower than the full opt-in set: it
// does not auto-gate the low-blast or recovery-direction kinds, only the two data/sign-in surfaces a lone
// owner could most damagingly misuse. dest-default is OMITTED on purpose (repointing the default among
// already-proven destinations is lower blast than adding/removing one). The global default-on for ALL
// gated ops remains opt-in.
export const HIGH_BLAST_ALWAYS_GATED: ReadonlySet<OwnerActionKind> = new Set<OwnerActionKind>([
  "dest-set",
  "dest-put",
  "dest-remove",
  "idp-conn-create",
  "idp-conn-delete",
  "idp-conn-enabled",
  "idp-conn-cert",
  // Opening or repointing the SIEM push destination is the same blast class as dest-put: it chooses where
  // an egress of identity-bearing audit data lands, so it auto-gates once a second owner exists.
  "push-dest-set",
  // Opening or repointing the OTLP metrics push destination is the same blast class (mon-otlp): it chooses
  // where an egress of operational backup-health telemetry lands, so it auto-gates once a second owner exists.
  "otlp-push-dest-set",
]);

// isHighBlastAlwaysGated reports whether a kind is auto-gated once a second owner exists (see the set above).
export function isHighBlastAlwaysGated(kind: OwnerActionKind): boolean {
  return HIGH_BLAST_ALWAYS_GATED.has(kind);
}

// CHANGE_CONTROL_EXEMPT_OWNER_ACTIONS are the owner-action kinds the OWNER-OPT-IN change-number policy does
// NOT apply to, for two distinct reasons:
//   - dual-control-disable is the asymmetric OFF SWITCH of dual control itself: it is the emergency escape (a
//     lone owner, or the bare-token break-glass, must keep a direct way to disarm), so blocking it on a change
//     number could lock an account out of disarming. It already carries its own config-policy-change audit
//     event and a real-time disarm ALERT, so it is recorded without a change reference.
//   - sources-attach is ADDITIVE / low-blast: it adds backup-source bindings (it expands what is backed up),
//     it does not repoint where backups land, exfiltrate, or destroy. It is an engine-binding rewrite, but its
//     OUTCOME is benign (more coverage), so it is not a CAB-worthy "dangerous change" the way a destination
//     repoint, an IdP change, a support-credential mint or a break-glass retire is.
//   - update-apply / update-settle are the engine self-deploy, which is a CAB-worthy change BUT is already
//     heavily gated on its own terms (a vendor-SIGNED manifest, a live canary verdict, and dual control on a
//     migration/breaking release) AND runs as a TWO-PHASE router-executed flow (promote then settle, each its
//     own owner action with a one-shot token resubmit) that a single change reference does not cleanly span.
//     Recording a change number across that flow is a scoped, tracked follow-up (one CR for the whole
//     apply+settle), so it is exempt here for now rather than gated awkwardly or half-wired. (Move it out of
//     this set to gate it.) Not yet built.
const CHANGE_CONTROL_EXEMPT_OWNER_ACTIONS: ReadonlySet<OwnerActionKind> = new Set<OwnerActionKind>(["dual-control-disable", "sources-attach", "update-apply", "update-settle"]);

// isChangeControlledOwnerAction reports whether an owner action is subject to the OWNER-OPT-IN change-number
// policy (change-ref.ts): every owner action EXCEPT the exempt set above. Every change-controlled op (a
// destination repoint/remove, an IdP change, a discovery-token/accounts change, a support-credential mint, a
// break-glass retire) is recorded with the operator's change reference when the policy is on; the exempt ops
// are recorded without one (or not at all).
export function isChangeControlledOwnerAction(kind: OwnerActionKind): boolean {
  return !CHANGE_CONTROL_EXEMPT_OWNER_ACTIONS.has(kind);
}

// isOwnerActionKind guards a stored/forwarded kind against the closed set, mirroring isConfigChangeKind /
// isRole. It is defensive: the kind is set by the router/DO from their own dispatch (never a free client
// field), but a tampered stored record carrying an unknown kind must not reach the execute, so the approve
// and consume paths re-check it and the dispatch fails closed on a non-member.
export function isOwnerActionKind(v: unknown): v is OwnerActionKind {
  return typeof v === "string" && (OWNER_ACTION_KINDS as readonly string[]).includes(v);
}

// OWNER_ACTION_PREFIX is the DO storage key prefix; the key is `owneraction:${id}`. The id is a ULID so a
// storage prefix list returns records in chronological (oldest-first) order without a separate counter, the
// same idiom as the pending-change records.
export const OWNER_ACTION_PREFIX = "owneraction:";

// ownerActionKey is the storage key for a pending owner-action record.
export function ownerActionKey(id: string): string {
  return OWNER_ACTION_PREFIX + id;
}

// OWNER_ACTION_TTL_MS bounds a stale pending owner action (and a stale armed approval): 24 hours, matching
// the restore approval TTL. A short TTL means an armed approval cannot be banked indefinitely against a
// future execution; past it the record reads as expired (lazily) and an execute/consume is refused, forcing
// a fresh proposal + approval. This is the bank-the-approval defence the restore approval has and the
// config-change gate substitutes a base-moved check for; an owner action has no config-history base to bind,
// so it uses the clock (like the restore approval) PLUS the actionHash re-arm-on-change.
export const OWNER_ACTION_TTL_MS = 24 * 60 * 60 * 1000;

// OwnerActionStatus is the closed lifecycle. pending: the maker proposed it; it awaits a SECOND owner.
// approved: a DISTINCT owner approved (maker != checker); the action is ARMED to execute. For a DO-executed
// kind the DO runs the method AS PART of the approve and the record goes straight to executed (approved is a
// transient internal step the DO never persists for those). For a ROUTER-EXECUTED kind the record SITS in
// approved until the maker re-submits with the token and the router consumes it. executed: the action ran
// (single use; terminal). rejected: an owner discarded it (terminal). expired: the TTL lapsed (computed
// lazily from expiresAt, the restore approval's pattern).
export type OwnerActionStatus = "pending" | "approved" | "executed" | "rejected" | "expired";

// PendingOwnerAction is one queued owner action, held in the scheduler DO under `owneraction:${id}`. It
// carries the binding (kind + params), the proposer identity (email + stable subject + propose-time groups)
// the execute re-resolves authority from, the actionHash that binds all of it, a redaction-safe human
// SUMMARY for the approver to review, the status, and (once approved) the checker. proposedBy is the verified
// maker email; approvedBy MUST differ (maker != checker on subject), enforced server-side in the DO (the
// type cannot encode the inequality, so it is a runtime invariant the validator proves). params is stored
// VERBATIM so the approved execution replays the IDENTICAL action, and for a few kinds that verbatim store
// includes a LIVE SECRET the proposer supplied (the destination secret access key, the IdP client secret, the
// discovery token), exactly as the config-change gate stores a webhook url. That at-rest secret is read ONLY
// by id on the approve/consume replay; the INBOX LISTING projection (viewOwnerAction) STRIPS it, so a
// proposer's credential is never surfaced to other owners. Every value is escaped on display like every
// server value.
export interface PendingOwnerAction {
  id: string; // the record id (a ULID, also the storage key suffix `owneraction:${id}`)
  kind: OwnerActionKind; // which owner operation this is
  // The action's DECISION-RELEVANT params, stored verbatim for replay/consume. For dest/idp/discovery kinds
  // this AT-REST value can carry a live secret (secretAccessKey / secret / token); the listing redacts it
  // (viewOwnerAction → redactOwnerActionParamsForListing), so the secret never leaves on a read.
  params: unknown;
  // routerExecuted is whether this kind runs in the router (the token-flow). It is DERIVED from the kind at
  // propose time (isRouterExecutedOwnerAction) and stored so the consume path knows the record is for a
  // re-submit flow without re-deriving; it is part of the integrity binding for the same reason the kind is.
  routerExecuted: boolean;
  proposedBy: string; // the proposer's verified email (the MAKER); a bare-token proposer is refused upstream
  // proposedBySubject is the proposer's STABLE principal AT PROPOSE TIME (ASVS V10.3.3 / V10.5.2). The
  // execute re-resolves the proposer's authority from THIS subject against the LIVE role table, so a proposer
  // demoted/revoked between propose and approve/consume is caught and a recycled email never inherits the
  // departed proposer's authority. It is BOUND INTO actionHash (alongside proposedBy and proposedByGroups) so
  // a stored-record tamper of the actor identity is caught by the approve/consume-time recompute. It is null
  // only for the bare-token break-glass, which cannot propose (refused upstream), so a queued record always
  // carries a real subject.
  proposedBySubject: string | null;
  // proposedByGroups is the proposer's verified IdP groups AT PROPOSE TIME, bound into actionHash for the
  // same reason: the execute re-resolves the proposer's authority from their subject + these groups, so a
  // group-derived proposer keeps exactly the authority they presented and a stored-groups tamper is caught.
  proposedByGroups: string[];
  // proposedBySourceIp is the EDGE ADDRESS THE PROPOSE REQUEST ARRIVED FROM, the owner-action twin of
  // PendingConfigChange.proposedBySourceIp. The approve-time execute runs AS THE PROPOSER (proposerReplayCaller),
  // so without it the replayed mutation's audit row is human-attributed with a null sourceIp: the exact shape the
  // audit-human-event-missing-source-ip counter names as a capture fault, raised on an approval that worked. The
  // engine captured the address at propose time and this is where it keeps it. Not bound into actionHash (no
  // authority is re-resolved from it), and it never enters the support pack.
  proposedBySourceIp?: string | null;
  proposedAt: string; // RFC-3339 UTC millis
  summary: string; // a redaction-safe human description of the action (ids/names/fingerprints only), for the inbox
  actionHash: string; // "sha384:" over { kind, params, routerExecuted, proposedBy, proposedBySubject, proposedByGroups }
  status: OwnerActionStatus;
  approverSubject?: string; // the CHECKER's STABLE subject; MUST differ from proposedBySubject (maker != checker)
  approvedBy?: string; // the CHECKER's verified email (DISPLAY/AUDIT only); present once approved
  approvedAt?: string;
  executedAt?: string; // set when the action ran (single use)
  expiresAt: string; // RFC-3339 UTC millis; status reads as "expired" past this (lazily)
  // The LAST FAILED APPROVE/EXECUTE ATTEMPT on this record. See PendingConfigChange.lastAttempt: the
  // owner-action machine had the same hole (a record that will not execute just sits there "approved", with
  // every refusal reaching one browser and nothing else), and the CONSUME half has the worse one -- a replayed
  // one-shot approval was detected and refused with no durable trace at all. Closed outcome class + a time;
  // never the guard's prose, the params or an identity.
  lastAttempt?: { at: string; outcomeClass: string };
  // paramsScrubbedAt is when the AT-REST params were stripped of their live secret because this action can
  // never run again (scrubOwnerActionParams / ownerActionParamsSpent). It is set ONLY when the strip actually
  // removed something, so a secret-free record never carries it and keeps its full actionHash teeth. Its
  // presence means the binding is NO LONGER RECOMPUTABLE by construction, which is why every integrity
  // recompute must consult it FIRST: without that, a duplicate approve or a replayed consume of a spent
  // action would be filed as a TAMPER, and integrity-failed is the one governance class that must never
  // cry wolf. A record carrying it whose effective status is still pending or approved IS a tamper (only a
  // spent record is ever scrubbed), and the DO reports it as one.
  paramsScrubbedAt?: string;
}

// ActionBinding is the canonical object the actionHash is computed over: the operation kind, its params, the
// router-executed flag, and the PROPOSER IDENTITY (email + stable subject + propose-time groups) the execute
// re-resolves authority from. Binding the params is the re-arm-on-change + no-tamper teeth: an approve/
// consume recomputes this over the SAME stored inputs, so a params tamper (or a swapped-in more-privileged
// proposer) yields a different hash and is refused; a re-submission that changes a decision field hashes to a
// record that does not exist. The params are folded as-is (the customer's own non-secret ids/names/
// fingerprints, OR for the secret-bearing kinds the live secret the proposer supplied); canonicalJSON sorts
// object keys so a key-order difference cannot change the hash, matching the config-history / restore-plan /
// config-change content-hash discipline. For secret-bearing kinds the hash is therefore over secret material.
interface ActionBinding {
  kind: OwnerActionKind;
  params: unknown;
  routerExecuted: boolean;
  proposedBy: string;
  proposedBySubject: string | null;
  proposedByGroups: string[];
}

// ownerActionHash computes the binding hash: "sha384:" + hex(SHA-384(canonicalJSON(binding))), the SAME
// primitives the restore plan hash and the config-change content hash use. It is recomputable from the
// stored record alone (kind/params/routerExecuted/proposedBy/proposedBySubject/proposedByGroups), so the
// approve and consume paths re-derive it without re-running anything, and it folds NO key and NO secret. It
// is async (sha384 is async) and pure.
export async function ownerActionHash(
  kind: OwnerActionKind,
  params: unknown,
  routerExecuted: boolean,
  proposedBy: string,
  proposedBySubject: string | null,
  proposedByGroups: string[],
): Promise<string> {
  const binding: ActionBinding = { kind, params, routerExecuted, proposedBy, proposedBySubject, proposedByGroups };
  return `sha384:${hexEncode(await sha384(canonicalJSON(binding)))}`;
}

// effectiveOwnerActionStatus applies lazy expiry: a record whose expiresAt is in the past reads as "expired"
// unless it is already in a terminal-by-action state (rejected or executed, which an expiry should not
// overwrite). A pending or approved record past its TTL reads as expired, mirroring the restore approval's
// lazy self-revoke, so a stale armed approval cannot authorise an execution without a sweep. The stored
// record is left as-is; only the reported value changes.
// The owner-action queue's twin of approvalTimestampUnparseable. The same lazy-expiry idiom, the same
// Number.isFinite guard, the same consequence: a queued owner action whose expiresAt does not parse never
// reads as expired, so an armed second-owner approval outlives its TTL with nothing anywhere saying so.
export function ownerActionTimestampUnparseable(record: PendingOwnerAction): boolean {
  return !Number.isFinite(Date.parse(record.expiresAt));
}

export function effectiveOwnerActionStatus(record: PendingOwnerAction, now: number): OwnerActionStatus {
  if (record.status === "rejected" || record.status === "executed") return record.status;
  const exp = Date.parse(record.expiresAt);
  if (Number.isFinite(exp) && exp <= now) return "expired";
  return record.status;
}

// canApproveOwnerAction decides whether a caller may APPROVE a pending owner action, returning a precise
// refusal reason or null to allow. It encodes the dual-control-specific rules; the OWNER re-check (the
// approver must be an owner, since every gated op is owner-class) is the DO's own re-resolution and is passed
// in as approverIsOwner (so this stays pure over the record + the two facts). The rules, in order:
//   - the action must still be PENDING (an approved/executed/rejected/expired record cannot be approved);
//   - the approver must be attributable (an email): the bare-token break-glass cannot approve (no stable
//     identity), exactly as it cannot approve a config change or a restore;
//   - maker != checker on the STABLE SUBJECT axis (the authority axis, ASVS V10.3.3 / V10.5.2), the SAME
//     axis restore + config dual control compare: the approver's subject must differ from proposedBySubject.
//     The display-email comparison is kept as a belt-and-suspenders floor (a same-email self-approval is also
//     refused), so a legacy record with a null proposedBySubject still cannot be self-approved by email;
//   - the approver must be an owner (every gated op is owner-class).
// The actionHash recompute (tamper check) and the TTL/expiry are checked around this call by the DO (the hash
// recompute is async; the DO has the clock), exactly as approveChange does the base-moved check around
// canApproveChange. canApproveOwnerAction is the synchronous identity/state/authority gate; both run inside
// the DO's read-modify-write so the decision is atomic with the write.
export function canApproveOwnerAction(
  record: PendingOwnerAction,
  approverEmail: string | null,
  approverSubject: string | null,
  approverIsOwner: boolean,
  now: number,
): GovernanceDecision {
  const status = effectiveOwnerActionStatus(record, now);
  if (status === "approved") return { ok: false, reason: "the action is already approved", reasonCode: "terminal-state" };
  if (status === "executed") return { ok: false, reason: "the action was already carried out", reasonCode: "consumed" };
  if (status === "rejected") return { ok: false, reason: "the action was rejected", reasonCode: "terminal-state" };
  if (status === "expired") return { ok: false, reason: "the request has expired; raise it again", reasonCode: "expired" };
  if (approverEmail === null) {
    return { ok: false, reason: "dual control requires an attributable identity; the bare-token fallback cannot approve an owner action", reasonCode: "bare-token" };
  }
  // Maker != checker on the subject axis (primary): a self-approval is refused even across an email change,
  // exactly as restore + config dual control compare subjects. proposedBySubject is non-null for any action
  // proposed after the subject re-key; a null (legacy) value falls through to the email floor below.
  if (record.proposedBySubject !== null && approverSubject === record.proposedBySubject) {
    return { ok: false, reason: "cannot approve your own action", reasonCode: "self-approval" };
  }
  // Email floor (belt-and-suspenders): also refuse a same-display-email self-approval.
  if (approverEmail === record.proposedBy) {
    return { ok: false, reason: "cannot approve your own action", reasonCode: "self-approval" };
  }
  if (!approverIsOwner) {
    return { ok: false, reason: "cannot approve: only an Owner may approve a high-blast-radius owner action", reasonCode: "not-owner" };
  }
  return { ok: true };
}

// canRejectOwnerAction mirrors canApproveOwnerAction for a rejection: only a still-pending OR still-armed
// (effective "pending"/"approved") record can be rejected. A reject does NOT require maker != checker (the
// proposer may withdraw their own action, and any owner may veto an armed one before it executes), but it
// must not overwrite a terminal state (executed/rejected/expired). The owner re-check is the DO's.
export function canRejectOwnerAction(record: PendingOwnerAction, now: number): GovernanceDecision {
  const status = effectiveOwnerActionStatus(record, now);
  if (status === "executed") return { ok: false, reason: "the action was already carried out", reasonCode: "consumed" };
  if (status === "rejected") return { ok: false, reason: "the action was already rejected", reasonCode: "terminal-state" };
  if (status === "expired") return { ok: false, reason: "the request has expired", reasonCode: "expired" };
  // pending or approved (armed) -> a reject is allowed (an owner can veto an armed action before it runs).
  return { ok: true };
}

// isArmedOwnerAction is the EXECUTE/CONSUME-time gate over a found record: it is a valid armed approval for
// this action iff its EFFECTIVE status is "approved" (not pending, not expired, not rejected, not already
// executed) AND a checker SUBJECT is recorded AND the checker subject differs from the proposer subject
// (maker != checker, on the STABLE principals). The maker != checker is enforced at approve time too (the DO
// refuses a self-approval), so this is defence in depth: even a record that somehow carried
// approverSubject == proposedBySubject would be rejected here. A null record (no approval at all) is never
// armed. This is the owner-action analogue of isUsableApproval (restore).
export function isArmedOwnerAction(record: PendingOwnerAction | null, now: number): boolean {
  if (record === null) return false;
  if (effectiveOwnerActionStatus(record, now) !== "approved") return false;
  if (!record.approverSubject) return false;
  if (record.approverSubject === record.proposedBySubject) return false; // maker != checker (by subject)
  return true;
}

// OWNER_ACTION_SECRET_TOPLEVEL_KEYS are the TOP-LEVEL params fields that can carry a LIVE SECRET the proposer
// supplied: the IdP client secret ("secret"), the account-discovery read-only API token ("token"), and the
// SIEM push destination's auth header value ("authHeaderValue", flat on the push-dest-set params, not nested
// under a config object). The OTLP metrics push destination (otlp-push-dest-set, mon-otlp) carries its
// bearer/API-key secret under the SAME flat "authHeaderValue" key, so this one entry redacts both push kinds. The nested secrets handled separately below are the archive destination secret
// access key (config.secretAccessKey, the dest-set/-put kinds), the AssumeRole externalId
// (config.assumeRole.externalId), and the SIEM push S3-drop sink secret access key (s3Target.secretAccessKey,
// the same push-dest-set kind). These are folded into the at-rest record (so the approved execution replays
// the IDENTICAL action) but MUST NOT appear in the read-time inbox listing: the approver decides from the
// redaction-safe summary (which already names the host/bucket/scope/format), never the credential. (A repeated
// read of the inbox must never surface a proposer's live secret to other owners; the IdP client secret, the
// push auth header value and the push S3 key are all WRITE-ONLY by contract.)
const OWNER_ACTION_SECRET_TOPLEVEL_KEYS: readonly string[] = ["secret", "token", "authHeaderValue"];

// hasNestedSecretAccessKey reports whether params[field] is an object carrying a live secretAccessKey the
// listing must strip. Used for BOTH the archive destination (params.config.secretAccessKey, the dest-set/-put
// kinds) AND the SIEM push S3-drop sink (params.s3Target.secretAccessKey, the push-dest-set kind): the s3 sink
// rides the SAME push-dest-set owner action, and its s3 secret is nested under s3Target (NOT under config), so
// without this branch a proposer's live S3 key would leak in the GET /admin/owner-actions pending listing.
function hasNestedSecretAccessKey(src: Record<string, unknown>, field: string): boolean {
  const v = src[field];
  return v !== null && typeof v === "object" && !Array.isArray(v) && "secretAccessKey" in (v as Record<string, unknown>);
}

// redactOwnerActionParamsForListing returns a SHALLOW-ENOUGH redacted COPY of an action's params for the
// inbox listing: the known secret-bearing fields (config.secretAccessKey, config.assumeRole.externalId,
// s3Target.secretAccessKey, top-level secret/token/authHeaderValue) are stripped. It NEVER mutates the input
// (the at-rest record the approve/consume paths replay from is read by id and is untouched), so byte-faithful
// replay is preserved; only the LISTING projection loses the secret. A non-object params value (or one with no
// secret fields) round-trips unchanged. It is deliberately conservative: it strips the EXACT known keys rather
// than guessing, so a new secret-bearing kind must be added here deliberately (the validator asserts the
// listing carries no secret for the secret-bearing kinds).
function redactOwnerActionParamsForListing(params: unknown): unknown {
  if (params === null || typeof params !== "object" || Array.isArray(params)) return params;
  const src = params as Record<string, unknown>;
  // Only clone + strip when a known secret field is actually present, so a secret-free action's params are
  // returned untouched (no needless copy, and the inbox shows the exact non-secret fields).
  const hasTopLevelSecret = OWNER_ACTION_SECRET_TOPLEVEL_KEYS.some((k) => k in src);
  const hasConfigSecret = hasNestedSecretAccessKey(src, "config");
  const hasS3Secret = hasNestedSecretAccessKey(src, "s3Target");
  // config.assumeRole.externalId is the STS cross-account confused-deputy guard: destStatusOf already strips
  // it from every status/list view ("NEVER the externalId or the principal secret"), so this listing must
  // treat it the same way, one level deeper than secretAccessKey.
  const cfg = src.config;
  const cfgIsObj = cfg !== null && typeof cfg === "object" && !Array.isArray(cfg);
  const assumeRole = cfgIsObj ? (cfg as Record<string, unknown>).assumeRole : undefined;
  const assumeRoleIsObj = assumeRole !== null && typeof assumeRole === "object" && !Array.isArray(assumeRole);
  const hasExternalId = assumeRoleIsObj && "externalId" in (assumeRole as Record<string, unknown>);
  if (!hasTopLevelSecret && !hasConfigSecret && !hasS3Secret && !hasExternalId) return params;
  const out: Record<string, unknown> = { ...src };
  for (const k of OWNER_ACTION_SECRET_TOPLEVEL_KEYS) delete out[k];
  // Strip the nested secretAccessKey from each secret-bearing container that carries one, cloning ONLY that
  // container so the rest of the (redaction-safe) params round-trip unchanged.
  if (hasConfigSecret || hasExternalId) {
    const cfgOut: Record<string, unknown> = { ...(src.config as Record<string, unknown>) };
    delete cfgOut.secretAccessKey;
    if (hasExternalId) {
      // Destructure-omit rather than delete-in-place: cfgOut is only a SHALLOW clone of cfg, so cfgOut.assumeRole
      // is still the SAME nested object the at-rest record holds. Deleting externalId off it in place would
      // mutate that shared object (corrupting the record this projection is supposed to leave untouched); a
      // fresh object one level deeper keeps this a pure projection, exactly like cfgOut itself above.
      const { externalId: _externalId, ...assumeRoleRest } = assumeRole as Record<string, unknown>;
      cfgOut.assumeRole = assumeRoleRest;
    }
    out.config = cfgOut;
  }
  if (hasS3Secret) {
    const s3Out: Record<string, unknown> = { ...(src.s3Target as Record<string, unknown>) };
    delete s3Out.secretAccessKey;
    out.s3Target = s3Out;
  }
  return out;
}

// viewOwnerAction is the read-time projection for any CALLER-FACING echo of a record: the inbox LISTING, and
// the approve/reject RESPONSE BODY -- the record with its EFFECTIVE status substituted (so a
// lapsed record reads "expired" without the DO mutating storage on a read) AND its params REDACTED of any
// live secret (config.secretAccessKey / config.assumeRole.externalId / top-level secret / top-level token).
// The approver decides from the redaction-safe summary; no caller-facing echo carries a proposer's credential,
// whether they are listing the inbox, vetoing a proposal (reject needs no maker != checker), or arming/
// executing one (approve). It is a pure copy; the STORED record is untouched, so the INTERNAL replay/execute
// paths (executeOwnerActionDO, consumeOwnerAction; these read the record by id, NOT through this projection)
// still run against the byte-identical, unredacted action. (Mirrors the restore approval's viewStatus, plus
// the params redaction.)
export function viewOwnerAction(record: PendingOwnerAction, now: number): PendingOwnerAction {
  const status = effectiveOwnerActionStatus(record, now);
  const params = redactOwnerActionParamsForListing(record.params);
  // Build the projection only when something changed (status or params), so a redaction-free, non-expired
  // record round-trips as-is.
  if (status === record.status && params === record.params) return record;
  return { ...record, status, params };
}

// ---- The AT-REST scrub: the params of an action that can never run again ------------------------------------
//
// THE EXPOSURE THIS CLOSES. viewOwnerAction above strips the live secret from every caller-facing READ, and
// that is a read-path control only: the STORED record keeps the proposer's credential verbatim (the archive
// destination secret access key, the IdP client secret, the account-discovery API token, a push destination's
// auth header value) and NOTHING has ever deleted an owner-action record. So a secret submitted once sat in
// the Durable Object's storage indefinitely, long after the action it belonged to had run, been vetoed or
// lapsed undecided. It is the one residue in this subsystem whose exposure GROWS with time rather than merely
// persisting: a credential the customer rotated a year ago is still readable to anything that reaches the
// store, and the customer has no way to know it is there. Every other armed-authority residue here is bounded
// by the 24h TTL, which bounds what the record can DO and does nothing at all about what it HOLDS.
//
// WHY A SCRUB RATHER THAN A DELETE. The record is also the forensic account of what a second owner approved,
// and ownerActionQueueStats reads the whole prefix for the support pack's governance-stall counts. Deleting it
// would erase both. Stripping exactly the known secret fields leaves the decision-relevant params (the host,
// the bucket, the connection id, the scope) intact, which is what a later "who approved that repoint" question
// actually needs, and it reuses the SAME field list the listing redaction uses, so there is one definition of
// what counts as a secret and a new secret-bearing kind has one place to be declared.

// ownerActionParamsSpent reports whether a record's params can never be needed again: its EFFECTIVE status is
// executed, rejected or expired. Those are exactly the three states from which no approve and no consume can
// proceed (canApproveOwnerAction refuses all three; isArmedOwnerAction admits only "approved"), so the params
// have no remaining reader. The ARMED router-executed state is deliberately NOT here: that record is waiting
// for the maker's token re-submit, and consumeOwnerAction re-derives the actionHash FROM THE STORED PARAMS to
// pin the consume to the exact approved action, so scrubbing an armed record would break the very binding that
// stops a consume being redirected to a different action.
export function ownerActionParamsSpent(record: PendingOwnerAction, now: number): boolean {
  const status = effectiveOwnerActionStatus(record, now);
  return status === "executed" || status === "rejected" || status === "expired";
}

// scrubOwnerActionParams returns the params with every known secret-bearing field removed, for the AT-REST
// record of a spent action. It is the SAME projection the inbox listing applies, deliberately: the listing has
// been the single declared answer to "which fields carry a live secret" since ML-04, and a second answer here
// would be a second thing to keep in step. It returns the input BY REFERENCE when there was no secret to
// strip, which is what lets the caller stamp paramsScrubbedAt only when something actually went.
export function scrubOwnerActionParams(params: unknown): unknown {
  return redactOwnerActionParamsForListing(params);
}

// ownerActionParamsScrubbed reports whether a record's at-rest params were stripped, and therefore whether its
// actionHash can still be recomputed from them. See PendingOwnerAction.paramsScrubbedAt.
export function ownerActionParamsScrubbed(record: PendingOwnerAction): boolean {
  return typeof record.paramsScrubbedAt === "string" && record.paramsScrubbedAt.length > 0;
}

// canRequesterSeeOwnerAction decides whether a given caller may see a given pending owner action in the inbox
// listing. Every gated op is owner-class, so the natural reviewers are owners; but the proposer should also
// see THEIR OWN proposal even if (defensively) they are mid-demotion, so this encodes "owners see all, the
// proposer also sees their own", keyed on the STABLE subject (the maker != checker axis). The DO passes
// whether the caller is an owner. A caller with no subject (the token break-glass) sees only the owner view
// (callerIsOwner); it never matches a proposer subject. (Mirrors canRequesterSee for restore.)
export function canRequesterSeeOwnerAction(record: PendingOwnerAction, callerSubject: string | null, callerIsOwner: boolean): boolean {
  if (callerIsOwner) return true;
  return callerSubject !== null && record.proposedBySubject === callerSubject;
}
