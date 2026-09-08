// The closed-union type vocabulary for the tamper-evident audit log. These types are the
// redaction-by-construction boundary in type form: there is no open string/object field a caller
// could stuff a secret into, so the safe path is the ONLY path the types allow. The runtime logic
// (hash chain, verify, export, status snapshot) lives in audit.ts and its siblings; this module
// holds only the declarations they share, so the record shape has a single home and the append and
// the verify can never disagree on what an entry is. audit.ts re-exports every symbol here, so
// importers see one public surface.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries
// a value.

import type { AdvisoryAuthContext } from "./auth-context.ts";
import type { AuthMethod, Role } from "./identity.ts";

// SHA384_HEX_LEN is the hex width of a SHA-384 digest (48 bytes = 96 hex characters), and the ONE
// place that number is written for the audit chain's `prevHash`/`hash` fields. It lives in this leaf
// so the producer and the checker derive from the same constant instead of each typing 96:
// GENESIS_PREV_HASH (audit.ts) builds the zero placeholder from it, and destsim's strict parser
// (test/destsim/parsers.ts) builds its accepting regex from it.
//
// It exists because the two disagreed. The push test-send's synthetic event carried a placeholder of
// 94 zeros, not 96 (siem-push-shape.ts buildSyntheticPushEvent). Real Splunk HEC does not check the
// digest, so it answered 200 and the wiring test read as clean; destsim's parser did check, so it
// answered 400. Every run of that path had one of the two lying, and neither could say which. With
// both sides derived from here, a width change is one edit and a mismatch cannot be typed.
export const SHA384_HEX_LEN = 96;

// AuditAction is the closed set of first-class privileged actions the engine records. The first
// group is recorded as a by-product of the action's route (success AND denied attempts); the
// intent group is recorded by the console-driven marker route (the only audit WRITE the console
// performs, and it writes an intent event only, never a result or a value); the engine-observed
// group is detected by the engine out of band (see the engine-observed events below).
// AUDIT_ACTIONS is the single source of truth for the closed action set. The AuditAction type is
// derived from it (below) and the runtime guard isAuditAction iterates it, so the type and the guard
// can never drift apart: adding a member here is the ONLY place a new action is declared, and both the
// compile-time union and the query-filter guard follow automatically.
export const AUDIT_ACTIONS = [
  "restore-apply",
  // restore-verified anchors a RESTORE RECEIPT (auditable proof-of-correct-restore) into the tamper-
  // evident chain: after an applied restore the engine produces a receipt proving each restored record's
  // LANDED bytes hash to the signed manifest hash, and the router appends this entry carrying the receipt's
  // SHA-384 (+ runId, recordsRestored, allVerified) so the receipt is bound to the chain even when no
  // signer key was reachable to sign it. The target is the closed `restore-receipt` kind (hash + counts
  // only, never a value). Recorded once per applied restore that reached the write phase.
  "restore-verified",
  "restore-request",
  "restore-approve",
  "restore-reject",
  // Dual control: a retention-prune APPLY deletes archive bytes outright (a less reversible act than
  // a restore apply, which overwrites live data but leaves the archive itself untouched), so it needs the
  // same maker != checker second-authority pattern restore-request/approve/reject already give restore
  // applies, bound to a planHash computed from the downpipe's CURRENT retained/superseded split (never a
  // client claim). These three mirror the restore trio exactly; see admin/prune-approvals.ts.
  "retention-prune-request",
  "retention-prune-approve",
  "retention-prune-reject",
  "downpipe-create",
  "downpipe-delete",
  // the roster-hygiene heal (POST /downpipes/reconcile-roster, keys.ceremony): structural ghost rows
  // (key-id mismatch / malformed) were repaired back to the "storage key = config.id" invariant. A
  // heal-to-invariant like the sources-attached re-attach, recorded so a roster repair is never a
  // silent mutation. The target is the loose access-policy kind (the repair is roster-wide).
  "downpipe-roster-reconcile",
  // a manual run-now (POST /trigger) gated on run.trigger: it allocates a run, sets the in-flight lease and
  // appends a history row, so the privileged actor who initiated an off-schedule run is recorded in the
  // tamper-evident chain (the run itself is in the history ring, but WHO triggered it would otherwise be
  // lost, unlike every other privileged mutation). The target is the closed `run` kind (runId only).
  "run-trigger",
  "role-change",
  "group-role-change", // an identity-provider group->role mapping was upserted or removed (Owner)
  "custom-role-change", // a composable custom role was created/updated or deleted (access.policy)
  "idp-connection-change", // a native external-IdP connection (OIDC/OAuth2/SAML) was created, updated, enabled/disabled or deleted (Owner-only, gated on keys.ceremony)
  "idp-sign-in", // a principal completed a native external-IdP sign-in; the actor is the signed-in subject, the target the connection it came through
  "authn-failure", // a FAILED authentication attempt (e.g. a failed passkey login assertion). Recorded so a brute-force/credential-stuffing sweep is visible in the tamper-evident chain. No identity is verified on a failure, so the actor fields are null (V16.3.1).
  "key-ceremony-intent",
  // in-product KEY INSTALL (the no-customer-CLI ceremony): the owner installed the in-browser key
  // ceremony's output as the engine's OWN worker secrets via a ONE-SHOT scoped "Edit Cloudflare
  // Workers" token (used once, never stored, never logged), so no `wrangler secret put` is needed.
  // Records who installed and when (key-ceremony target, field-less); the secret NAMES set ride the
  // structured engine log only, and NO private value and NO token ever reaches the trail.
  "keys-installed",
  // break-glass key ROTATION (no-customer-CLI): the owner generated a new break-glass pair in the
  // browser and applied only the new BREAK_GLASS_PUBLIC to the engine via a one-shot scoped token
  // (signer + operational untouched; not a re-key). Field-less key-ceremony target (who + when); the
  // public is the recovery-sheet pin, no private value and no token ever reaches the trail.
  "break-glass-rotated",
  // targeted operational-key ADD (the minimal upgrade path for a break-glass-only engine, the inverse of
  // operational-removed below): the owner installed ONLY OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE via a
  // one-shot scoped token. SIGNER_PRIVATE and BREAK_GLASS_PUBLIC are never touched, so this is not a re-key:
  // every existing run stays signed by the same signer and console-verifiable exactly as before. Field-less
  // key-ceremony target (who + when); the engine refuses the whole call when an operational key is already
  // present, so this row is never recorded over a silent overwrite.
  "operational-added",
  // posture tightening to strict break-glass-only: the owner removed BOTH operational worker secrets
  // via a one-shot scoped token, so the engine can no longer self-decrypt archives (recovery still
  // works via the offline identity.key). Field-less key-ceremony target (who + when); irreversible
  // without a re-key, so the row is the durable evidence of the change.
  "operational-removed",
  // The key ceremony's FAILURES. Until now the trail carried keys-installed / break-glass-rotated /
  // operational-removed on SUCCESS only, so an install that died at PUT #2 (leaving the engine HALF-KEYED) and a
  // key-paste that would not parse both recorded nothing at all: remotely, "we installed the keys and backups
  // still do not run" was indistinguishable from "we never got past the key screen". These name the STEP the
  // ceremony died on and the closed CAUSE (parse / missing / cf-put / cf-delete), plus the bounded Cloudflare
  // evidence (status class + Cloudflare's own numeric codes). Never a key, a paste, its length, or the token.
  "key-install-failed",
  "key-removal-failed",
  // key-posture acknowledgement (the liability record for the onboarding fork + Keys-screen posture
  // actions): the customer confirmed a versioned acceptance statement that RESTATES the specific
  // residual of the posture they chose. The target carries the posture, the statement VERSION and the
  // SHA-384 of the exact words shown (posture-ack-statements.ts is the single source of those words),
  // plus the channel (onboarding vs a later Keys re-key) and the resolved principal type (owner-passkey
  // / named-operator / bootstrap-admin-token) so a bootstrap-token acknowledgement never reads as a
  // named one. The verbatim text NEVER enters the chain (only its hash); the version + hash fully
  // determine the words, which are a frozen repo constant. Recorded on a successful acknowledge and on
  // a denied attempt (who tried, when).
  "posture-acknowledged",
  // custody share email: the customer chose to email ONE Shamir share of their split break-glass key to
  // a custodian (the alternative is a download). The engine emails one share per request over the
  // customer's own outbound email; the share value is NEVER logged and NEVER stored, and the ciphertext
  // (the envelope over identity.key) never reaches the engine, so an attacker who captured every emailed
  // share still could not decrypt. Recorded as counts only (the total shares and the threshold), never a
  // share, never the custodian address.
  "custody-share-emailed",
  "access-policy-change-intent",
  // Security-centre overrides (owner-only, posture.riskaccept): an owner set or withdrew a per-check
  // override (risk-accepted / attested-pass / compensating-control / not-applicable). The target names the
  // check id + the override kind; the owner's REASON text deliberately never enters the tamper-evident
  // log (it lives on the stored record and flows into the posture/evidence reports instead).
  "posture-override-set",
  "posture-override-withdrawn",
  // dual-control change control (OPT-IN config approval gate; opt-in, default off). When the org setting
  // requireConfigApproval is ON, a config mutation is queued as a pending change a SECOND identity must
  // approve (maker != checker) before the validated mutation replays. These record the lifecycle with
  // BOTH actors: propose attributes the maker (the proposer), approve attributes the checker (and the
  // applied mutation's own audit event records the maker again as its actor), reject the rejecter, and
  // supersede that an approve found the base config had moved. config-policy-change records the
  // owner-only toggle of the gate itself.
  "config-change-propose",
  "config-change-approve",
  "config-change-reject",
  "config-change-supersede",
  "config-policy-change",
  // dual-control for the high-blast-radius OWNER OPERATIONS (the same requireConfigApproval toggle arms it).
  // When the toggle is ON, a gated owner op (a destination repoint/remove, an engine self-deploy, an IdP
  // connection change, a discovery-token set, a support-credential mint, etc.) is recorded as a pending
  // owner action a SECOND owner must approve (maker != checker) before it runs. These record the lifecycle
  // with BOTH actors: propose attributes the maker, approve attributes the checker, execute records that the
  // approved action ran (the actor is the maker re-resolved at execute), and reject the rejecter/veto. The
  // target is the closed `owneraction` kind: the action kind + opaque id, never the params (no secret, no
  // destination credential, no deploy token ever reaches the log).
  "owner-action-propose",
  "owner-action-approve",
  "owner-action-execute",
  "owner-action-reject",
  // change management (OWNER OPT-IN "Require Change Number", default OFF). When requireChangeNumber is ON, a
  // CAB-worthy change (every owner action + a restore apply) is recorded with the operator's CHANGE REFERENCE
  // the moment it is initiated: a change-recorded event carrying the action kind, whether it was an EMERGENCY
  // change (a deliberate bypass of the number requirement, flagged loudly), the change number and the reason.
  // It is the CR ledger entry the change-requests report reads; the action's OWN event (e.g. dest-config-set,
  // restore-apply, owner-action-propose) records the action/result separately. The change number + reason are
  // operator-attested free text (bounded, redaction class of the restore reason), never a secret. When the
  // policy is OFF this event is never written and the trail is byte-identical to before.
  "change-recorded",
  // break-glass admin token lifecycle (single-use bootstrap + in-app disposal). bootstrap-consumed records
  // the ONE legitimate use of the break-glass token (or the first Access/passkey Owner claim): the moment
  // the FIRST Owner row is created, latched so no later bootstrap can mint a second Owner. break-glass-token-
  // retired records the OWNER-ONLY in-app retire that makes the engine stop honouring the ADMIN_TOKEN bearer
  // (no redeploy). Both reuse the field-less access-policy target (who + when, never a value).
  "bootstrap-consumed",
  "break-glass-token-retired",
  // account-discovery lifecycle (the customer's own READ-ONLY API token, set from the console;
  // DO-stored, never logged). set/cleared record who flipped account browsing and when;
  // accounts-set records a change to WHICH accounts are browsed (ids ride in the field-less
  // access-policy target's absence, who + when only, never the token, never an account list).
  "discovery-token-set",
  "discovery-token-cleared",
  "discovery-accounts-set",
  // sources-set records a change to WHICH token-authenticated source types (cf-config / workers /
  // stream / images / artifacts) are ADDED as available to protect (who + when only).
  "discovery-sources-set",
  // engine-account-verified: the engine proved its own
  // Cloudflare account id for the FIRST time, from a successful attach or update-apply's own read of
  // /accounts/{a}/workers/scripts/{name} against the engine's script. Recorded once (never overwritten,
  // see recordVerifiedEngineAccount); who + when only, the field-less access-policy target, never the
  // account id itself.
  "engine-account-verified",
  // archive-destination lifecycle (the console-set destination credentials; DO-stored, never
  // logged). set/cleared record who changed WHERE BACKUPS GO and when, the most consequential
  // pointer in the product, and never an endpoint credential (field-less access-policy target).
  "dest-config-set",
  "dest-config-cleared",
  // assurance-licence lifecycle (the customer's signed LICENCE_TOKEN, activated from the console; the
  // router verifies it live against the pinned signer before the DO stores it). activated/cleared record
  // who pinned or removed the token and when, never the token bytes and never the tier claims (the
  // field-less access-policy target). Fail-open holds: the licence never gates the data or recovery path.
  "licence-activated",
  "licence-cleared",
  // safe-apply engine update lifecycle (update-apply.ts): the owner applied a vendor-signed new engine
  // version from the console. promoted = phase 1 made the new version live (pending canary verification);
  // applied = the canary proved it healthy and it was kept; rolled-back = it did not sing and was reverted;
  // refused = aborted before going live (bad/corrupt artefact, migration required, upload/promote failed).
  // The target is engine-state (the version transition); the deploy token is never logged.
  "update-promoted",
  "update-applied",
  "update-rolled-back",
  "update-refused",
  // Canary backup: the owner toggled the on-by-default integrity canary, repointed its
  // destination, or changed its cadence. Records who changed the canary and when, never a value
  // (field-less access-policy target). The hourly flight results are NOT audited (they live in the
  // canary's own bounded history ring); only the operator config change is.
  "canary-config",
  // In-product source attach: the engine added source bindings to itself with a
  // ONE-SHOT deploy token (used once, never stored, never logged). Records who
  // attached and when; the binding names ride the structured log only.
  "sources-attached",
  "sources-detached",
  // Credential lifecycle registry: the operator ATTESTED they deleted a spent ephemeral credential
  // (e.g. a one-shot Cloudflare attach token) in Cloudflare. The engine holds no CF token and cannot
  // verify Cloudflare-side state, so this records an operator ATTESTATION (who + when), never a value.
  "expiry-cleanup-attested",
  // recovery-code lifecycle (the ongoing admin-sign-in break-glass). recovery-codes-generated records that a
  // fresh single-use set was minted for an email (enrolment OR regenerate), invalidating any prior set;
  // recovery-code-used records a recovery ATTEMPT (success = a code signed a session; failed = a wrong/absent
  // code; denied = a rate-limited attempt). Both reuse the field-less access-policy target: the trail records
  // who + when + the outcome, and NEVER a code, a hash, or which code (no plaintext ever touches the log).
  "recovery-codes-generated",
  // recovery-codes-staged: a fresh set was MINTED for an
  // email that already had a live set, but held back -- the live set the trail already knows about still
  // verifies. It is not yet a rotation and never appears alone as "the codes changed"; recovery-codes-
  // generated below is the row that says the old set actually died, and it fires only once the operator
  // confirms (or a bootstrap/invite enrolment mints straight to live, having nothing to protect).
  "recovery-codes-staged",
  "recovery-code-used",
  // support ingest credential lifecycle (the owner-minted, scoped, expiring pull credentials for
  // vendor diagnostics / the SIEM audit feed). grant records a mint (which replaces any prior
  // credential for the scope); revoke records a clear. Opening or closing a vendor-readable pull
  // surface carries the same custody weight as a role change, so it is first-class in the trail.
  // The target carries only the scope and the PUBLIC clientId (+ expiry); the secret exists once
  // in the mint response and neither it nor its hash ever reaches the log.
  "support-credential-grant",
  "support-credential-revoke",
  // passkey credential lifecycle: revoke records that a WebAuthn credential was removed (the
  // theft/loss revocation, ASVS V6.5.6), self-service or by an access-admin/owner. Field-less
  // access-policy target: who + when, never the credential id or any key material.
  "passkey-credential-revoke",
  // signin-factor-revoke: an operator removed EVERY way one person can
  // authenticate, across all three sign-in stores at once -- their WebAuthn credentials, their banked recovery
  // codes and their outstanding registration invites. It is deliberately NOT three audit rows, because the
  // operator performed ONE act ("this person can no longer sign in") and a trail that splits it into three
  // makes the important question ("was the offboarding complete?") a join the reader has to perform.
  //
  // WHY IT IS FIRST-CLASS IN THE CHAIN rather than a closed counter. Two of the three stores hold BEARER
  // secrets, so this is the event that closes a way in that needed no device. Recording it only as a support-
  // pack counter would put the evidence somewhere support can read and the account's own administrator cannot,
  // which is the same asymmetry this codebase has already had to correct elsewhere.
  //
  // Target: the existing field-less-secret `role` kind, naming the member and the role they held AT the
  // revocation. The role is unchanged by this action (revoking factors is not a demotion, and deliberately so
  // -- see revokeSignInFactors), so the field records what they were, not a transition. Counts of what was
  // removed ride the structured log; NEVER a code, a code hash, an invite token or a credential's key.
  "signin-factor-revoke",
  // session termination (ASVS V7.4.5 / V7.5.2): a user terminated their OTHER sessions (access-policy
  // target), or an admin terminated a member's sessions (role target naming the member). Records the
  // act of revoking sessions; the session tokens themselves never touch the log.
  "session-terminate",
  // retention prune (ASVS V14.2.7): an ENFORCED per-downpipe retention prune ran and deleted
  // superseded runs' trees + their now-orphaned segments (the RUNLOG entries are retained marked
  // superseded, never removed, SPEC 10.1). Recorded only on an APPLIED prune, with the downpipe
  // target and the counts in the structured log; a DRY-RUN or an ABSTAIN writes nothing and is not
  // audited as an action (it is reported in the engine log + the bounded seal-fault ring only).
  // Two producers share this ONE action, distinguished by actorMethod: the cron applies it on the
  // configured schedule with no human actor (actorMethod "engine", success outcome only; a cron-side
  // half-applied prune is caught by its own per-downpipe fail-open wrapper and lands on the pass
  // evidence record, cron/retention-record.ts, never on this audit action). The batched-capsule
  // admin route (POST /admin/retention-prune/apply, router-retention-prune.ts) applies the SAME
  // downpipe policy from browser-recovered per-run masters on a break-glass-only estate that has no
  // held key for the cron to use, so actorMethod there is the caller's own real auth method, and it
  // is the one producer of this action's "failed" outcome (a half-applied PruneApplyError; the
  // committed-so-far counts still ride the response, never the audit target).
  "retention-prune",
  // control-plane recovery: the SchedulerDO config slice is exported, signed, to the destination
  // bucket so a DO storage loss is recoverable. control-plane-exported records that a signed export was
  // written (engine-driven, the cron pass; field-less access-policy target -- who/value never logged, only
  // that an export ran). control-plane-empty records the health pass detecting an EMPTY control plane while
  // the bucket still has runs (the amnesia signal; engine-driven, outcome failed). control-plane-reconciled
  // is the BRIDGE event written when a break-glass operator rebuilds the DO from a verified export: the old
  // hash chain is gone, so this is the first event of the NEW chain and its presence marks the seam. All
  // reuse the field-less access-policy target; no secret, no config value, ever reaches the trail.
  "control-plane-exported",
  "control-plane-empty",
  "control-plane-reconciled",
  // control-plane-recovery-acknowledged:
  // an authenticated owner cleared the recovery-required latch WITHOUT a reconcile, because the plane had
  // organically un-emptied under the latch (break-glass activity kept creating downpipes/roles while the
  // latch stayed set) and the two reconcile routes above refuse forever once the plane is non-empty. Distinct
  // from control-plane-reconciled so the trail can tell an acknowledge-only clear apart from a genuine
  // rebuild carrying bridgedFrom; no downpipe/destination/role state changes, so the field-less access-policy
  // target is all it ever needs.
  "control-plane-recovery-acknowledged",
  // control-plane-resumed: the cron auto-heal re-applied the NO-AUTHORITY resume
  // slice (downpipes/schedules/dest-config) from a verified signed export, so backups RESUME without a
  // human. Engine-driven (the cron, no human actor); it grants no authority (the silence-killer latch
  // stays set + the role table stays empty until a break-glass confirm), so it is a success, not a failure.
  "control-plane-resumed",
  // engine-observed (out-of-band result detection; actorMethod "engine", no human actor):
  "engine-secret-present", // a GET /admin/status presence transition false -> true
  // The presence transition true -> FALSE. The engine recorded a secret appearing but never one VANISHING,
  // so "backups stopped three weeks ago" (a deploy that dropped SIGNER_PRIVATE, the highest-impact failure mode) showed
  // signerConfigured:false today with nothing saying WHEN. Outcome "failed": a tracked secret disappearing is
  // never healthy. The detail is the presence-boolean NAME from the fixed vocabulary, never a value.
  "engine-secret-absent",
  "engine-version-change", // engineVersion changed between two status observations
  // SIEM audit-log push destination: the outbound egress of the
  // hash-chained audit trail to a customer SIEM. set/cleared record who repointed or removed WHERE the
  // audit trail is forwarded and when (never the auth header value), the same custody weight as
  // dest-config-set/-cleared. push-delivery-failure is engine-driven (actorMethod "engine", the cron drain
  // recorded a failed delivery attempt, never a value or the endpoint), so a persistently-failing push
  // destination is visible in the tamper-evident trail, not only the bounded delivery-trail ring.
  "push-destination-set",
  "push-destination-cleared",
  "push-delivery-failure",
  // OTLP/HTTP metrics push destination: the snapshot sibling of the SIEM
  // audit-log push above. set/cleared record who repointed or removed WHERE the canonical backup-health
  // metric snapshot is pushed and when (never the auth header value), the same custody weight as
  // push-destination-set/-cleared. otlp-push-delivery-failure is engine-driven (actorMethod "engine", the
  // cron drain recorded a failed delivery attempt, never a value or the endpoint), so a persistently-failing
  // collector is visible in the tamper-evident trail, not only the bounded delivery-trail ring. These are
  // DISTINCT action names (not push-destination-set/-cleared reused) so an operator's audit trail can tell
  // the two egress features apart; both share the SAME closed push-destination target shape (op/id/
  // rejectReason/failureCount), which is generic enough to describe either.
  "otlp-push-destination-set",
  "otlp-push-destination-cleared",
  "otlp-push-delivery-failure",
  // attended verification (key-posture attend): an offline-key-only customer proves their backups restorable
  // by supplying, through their browser, only the per-run master keys (never the break-glass private). The
  // session lifecycle is recorded so a compliance reviewer can see WHO ran an attended verification, WHEN, and
  // over how many runs. attest-session-started records a create (the challenge was issued + the runs pinned);
  // attest-session-proven records the operator proving live possession of the break-glass private (or a denied
  // attempt with a bad proof); attest-run-verified records a batch of runs sampled-and-verified (COUNTS ONLY,
  // never a master or a value); attest-session-aborted records the operator ending the session. All carry the
  // closed `attest-session` target: an opaque session id + counts, never a key, a master, a seed or a proof.
  "attest-session-started",
  "attest-session-proven",
  "attest-run-verified",
  "attest-session-aborted",
  // THE TEST-FAULT HOOK, made auditable. The hook can force an engine-internal
  // failure on a fault-carrying estate, and it wrote NOTHING to the chain: 5,407 audit events on one such
  // estate carried zero fault-shaped actions, so "was a fault armed when this verdict was banked" was
  // UNANSWERABLE retrospectively, for every verdict the estate ever produced. That is not a missing log line,
  // it is a hole in the provenance of a whole class of evidence, and it is the cheapest possible thing to
  // close.
  //
  // Three actions, because they answer three different questions and an operator reading the trail must be
  // able to tell them apart. test-fault-armed says a fault was LOADED and by whom. test-fault-disarmed says
  // it was cleared BEFORE firing, which is what makes a verdict banked after it trustworthy. test-fault-fired
  // is the load-bearing one: it is the moment the hook actually changed engine behaviour, it carries no human
  // actor (actorMethod "engine", like the other engine-observed events), and it carries the instant the fault
  // was armed, so the window in which any verdict is suspect has both ends.
  //
  // A disarm that cleared NOTHING is deliberately not recorded: silence there means the fault had already
  // fired, and the fired event says so. Recording a no-op disarm would put a reassuring row in the chain at
  // exactly the moment the estate was least clean.
  //
  // These only ever appear on an estate running with fault injection enabled, since a production engine never
  // routes to the hook at all. That is precisely why they belong in the CLOSED set rather than in a
  // harness-side ledger: their absence from a production chain is then a checkable fact, not an artefact of
  // where somebody chose to write them.
  "test-fault-armed",
  "test-fault-disarmed",
  "test-fault-fired",
  // A FOURTH action, added for the control-plane-recovery-required fault: that fault, once fired,
  // LATCHES the real recovery-required flag (setControlPlaneRecoveryRequired, the same method a genuine wipe
  // uses), so releasing it needs a real clear, not just a disarm of the fault record. The real production
  // clears (acknowledge, the break-glass reconcile) both refuse over an empty role table -- exactly the state
  // this fault-hook's own throwaway recovery estate carries -- so POST /test-fault/control-plane-clear is a
  // dedicated harness-only release, and it needs its own action so the trail can tell it apart from a genuine
  // acknowledge/reconcile rather than folding it into either.
  "test-fault-control-plane-cleared",
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

// AuditOutcome distinguishes a completed action, a refused one (a Viewer denied an apply, a
// non-Owner denied a role write), and one that ran but failed in-flow. Reviews care about denied
// attempts as much as successes, so denied is first-class.
export type AuditOutcome = "success" | "denied" | "failed";

// AuditActorMethod is the auth method of the actor, widened with "engine" for the observed
// events that have no attributable human actor (a presence transition is not a person's action).
export type AuditActorMethod = AuthMethod | "engine";

// AuditTarget is the small, closed, redaction-safe description of WHAT an event acted on. Each
// variant carries only fields that are already public or non-sensitive in-account. There is
// deliberately no open string/object field, so a secret cannot be written even by a buggy caller.
// The engine-state variant's `detail` is a boolean NAME (e.g. "signerConfigured") or a version
// string, never a value.
export type AuditTarget =
  | { kind: "downpipe"; id: string; name?: string }
  | { kind: "run"; runId: string }
  // prune-approval: the retention-prune dual-control record, the counterpart of the "restore" kind's
  // planHash carriage below but for a prune approval. downpipeId + counts only (never a run id list, which
  // would be an operator-facing detail this closed shape deliberately keeps off the chain); the planHash is
  // opaque and recomputable from the downpipe's own live RUNLOG, never a secret. reason is the requester's
  // free text (not a secret); reasonClass is the checker's closed rejection reason, present only on a reject.
  | { kind: "prune-approval"; downpipeId: string; planHash: string; retainedRuns: number; supersededRuns: number; reason?: string; approverEmail?: string; approverSubject?: string; reasonClass?: string }
  | {
      kind: "restore";
      runId: string;
      redirectBinding: string | null; // the target binding NAME on a redirect, else null
      planHash: string; // "sha384:..." over names/counts/selectors only (redaction-safe)
      isLatest: boolean;
      reason?: string; // operator free-text justification; not a secret
      approverEmail?: string; // the checker's DISPLAY email (maker != checker); present once dual control supplies it
      approverSubject?: string; // the checker's STABLE subject (the maker != checker axis); the maker's subject is actorSubject
      destinationId?: string; // HI-15: WHICH archive destination the reviewed/applied cues came from; an opaque id, never a credential
    }
  // restore-receipt anchors a proof-of-correct-restore RECEIPT to the chain: the run it covers, the
  // canonical SHA-384 of the receipt (so the chain commits to the receipt's exact content; any later edit
  // to the receipt is detectable), the count of records restored, and whether every restored record's
  // LANDED bytes verified. All redaction-safe: a run id, a hash, an integer, a boolean -- never a value or
  // a key. This is the tamper-evidence for the receipt even when no signer key was reachable to sign it.
  // The apply SUMMARY (all optional, so a legacy anchor without them still typechecks and an older reader
  // ignores them): the redaction-safe shape of HOW the apply landed, for the support pack. complete is the
  // windowed-restore complete flag (false => a windowed apply left records unrestored); recordsVerified /
  // failures / outOfWindow are integer counts; readbackVerified / readbackMismatched summarise the post-write
  // READBACK proof (how many landed records re-hashed to their signed hash vs did not); d1Total / d1Verified
  // are the per-DB(D1) apply outcome (D1 records attempted vs proven -- a D1 restore writes over several
  // non-atomic batches, so a partial load must be visible). Counts + booleans only; never a record name/value/key.
  | {
      kind: "restore-receipt";
      runId: string;
      receiptSha384: string;
      recordsRestored: number;
      allVerified: boolean;
      complete?: boolean;
      recordsVerified?: number;
      failures?: number;
      // recordsSkipped is the count the apply deliberately did not write. Omitted when zero, so an audit
      // entry for a restore that skipped nothing is unchanged. It matters here more than anywhere: this
      // entry says "restore-verified / success" and an auditor reading recordsRestored and allVerified
      // alone would conclude the recovery is finished when records from the archive are still missing.
      recordsSkipped?: number;
      outOfWindow?: number;
      readbackVerified?: number;
      readbackMismatched?: number;
      d1Total?: number;
      d1Verified?: number;
      // configSkipReasons: the cf-config restore's per-item SKIP classes, as a CLOSED {class -> count}
      // map. `skipped: 20` on a DNS restore of 200 records was an integer with no cause: the reason existed
      // only as a RAW Cloudflare API message, sliced to 120 chars, on an HTTP response the operator may not
      // have kept -- and being a raw provider message it could never enter a pack. The classes route to
      // OPPOSITE remediations (an `entitlement` skip is a benign plan gate the customer cannot fix by
      // rotating a perfectly good token; a `quota` skip is a full plan, not an invalid DNS record), so the
      // class IS the answer. Counts against a closed engine vocabulary only; the 120-char text never rides.
      configSkipReasons?: Record<string, number>;
      // Media apply: the per-CLASS media failure counts (closed MEDIA_FAULT_CLASSES keys -> int) and the
      // conflict DIGEST PAIRS. "Some videos restored, some failed" was one anonymous failures count, so an
      // over-the-cap video (recover it out of band), a transient blip (retry) and an id occupied by DIFFERENT
      // live bytes (choose: overwrite or remap) all read the same. The digests are SHA-384 hashes of the
      // customer's own bytes, the SAME irreversible join-key idiom receiptSha384 already carries, so a conflict
      // dispute can be adjudicated. Never a media byte, an asset id or a Cloudflare error body.
      mediaFaults?: Record<string, number>;
      mediaConflictDigests?: Array<{ archivedSha384: string; liveSha384: string }>;
      // D1 partial apply: a D1 restore replays over several NON-ATOMIC batches, so a mid-apply fault
      // leaves a PARTIALLY-LOADED database -- the worst silent corruption the engine can leave behind -- and
      // the receipt said only "partial restore". d1Fault LOCALISES it: the closed D1 error class (selected
      // from D1's own error tokens; the SQLite message, which embeds table names, column names and row values,
      // is never carried), the batch the apply stopped at and the batch total (batch 3 of 900 is a schema/type
      // problem; 899 of 900 is a size/constraint problem), and -- on the "target not empty" refusal, where
      // NOTHING was written -- how many tables are standing in the way. d1SchemaObjectsFiltered counts the
      // indexes/triggers/views a table-SUBSET restore silently dropped (the "the app broke after a successful
      // restore" ticket). Integers and one closed enum.
      d1Fault?: { d1ErrorClass: string; failedBatchIndex?: number; batchTotal?: number; residualTableCount?: number };
      d1SchemaObjectsFiltered?: number;
      // The restore descriptor fields a sink SHED by design (a KV expiration that was not a usable
      // number, an R2 cacheExpiry that did not parse), as a {closed field kind: count} map. The record is
      // restored, the field is not, and the receipt used to claim full fidelity either way. Never the value.
      metadataFieldsDropped?: Record<string, number>;
    }
  | { kind: "role"; email: string; role: Role }
  // grouprole carries only the customer's own IdP group NAME and the mapped role; never a secret.
  // A group name is the customer's own directory data, redaction-safe like a downpipe id or a
  // member email (the actor key itself). role is the closed Role union.
  | { kind: "grouprole"; group: string; role: Role }
  // customrole carries only the role NAME and the count of capabilities it bundles; never a secret and
  // never the capability list itself (the name + count are the reviewable facts, and they keep the
  // target a small closed shape). action "deleted" is signalled by a 0 capability count on a removal.
  // affectedGrantCount (DELETE only): how many member + group grants still named this role when it was
  // deleted, i.e. how many people the deletion floors to viewer at their next request. A COUNT, never a holder.
  | { kind: "customrole"; name: string; capabilityCount: number; affectedGrantCount?: number }
  // configchange carries the pending change's id + the mutation KIND it queues, and (on approve) the
  // checker email, all redaction-safe: the id is an opaque ULID, the changeKind is a closed enum naming
  // WHICH mutation (e.g. "role-set"), never the params, and approverEmail is the checker (the maker !=
  // checker counterpart of the restore approval's approverEmail). The params a change carries are the
  // customer's own non-secret config and are deliberately NOT in the target (the closed shape cannot hold
  // them), so a queued change never writes its body to the tamper-evident log; the plain-English diff
  // lives only on the pending record the console reads behind auth, exactly like the webhook url.
  | { kind: "configchange"; id: string; changeKind: string; approverEmail?: string }
  // owneraction carries the pending owner action's opaque id + the OPERATION KIND it gates (e.g.
  // "dest-remove", "update-apply"), and (on approve/execute) the checker email, all redaction-safe: the id
  // is an opaque ULID, actionKind is a closed enum naming WHICH owner op, never the params, and approverEmail
  // is the checker (the maker != checker counterpart of the restore/config approverEmail). The params an
  // owner action carries (destination ids, IdP connIds, an artefact sha, an account fingerprint) are the
  // reviewable facts and are deliberately NOT in the target (the closed shape cannot hold them), so a queued
  // owner action never writes its body to the tamper-evident log; the redaction-safe summary lives only on
  // the pending record the console reads behind auth, exactly like the config-change diff and the webhook url.
  | { kind: "owneraction"; id: string; actionKind: string; approverEmail?: string }
  // change carries the change-controlled action's KIND (a closed engine-set action kind, e.g. "dest-remove",
  // "restore-apply", never a free client value), whether it was an EMERGENCY change, and the operator's CHANGE
  // NUMBER + emergency REASON. changeNumber and reason are the ONLY operator free-text fields on any target;
  // they are deliberately allowed here (a change reference is the whole point of the event), bounded and
  // control-char-stripped at the parse boundary (change-ref.ts), and are the SAME redaction class as the
  // restore target's `reason` (operator justification, not a secret). They are null when absent (an emergency
  // raised without a number; a normal change has no reason). actionKind is engine-set, so it cannot carry a value.
  | { kind: "change"; actionKind: string; emergency: boolean; changeNumber: string | null; reason: string | null }
  // key-ceremony is FIELD-LESS on the success rows (who + when is the whole evidence). The failure evidence widens it with the
  // OPTIONAL failure evidence, so a legacy row without them still typechecks and an older reader ignores them:
  //   step   - which secret the ceremony died on (a fixed env-var NAME, never a value): the half-keyed engine
  //   cause  - the closed cause: parse | missing | cf-put | cf-delete | other
  //   cfStatusClass / cfCodes - the bounded Cloudflare evidence when the cause was cf-put/cf-delete, so support
  //            can tell a CF EDGE OUTAGE (5xx) from a TOKEN SCOPE problem (4xx + Cloudflare's own numeric code)
  //            without ever carrying the response body (which can embed account and script names).
  | { kind: "key-ceremony"; step?: string; cause?: string; cfStatusClass?: string; cfCodes?: number[] }
  // access-policy was FIELD-LESS by design, and that design lost the decisive field on every governance event
  // that uses it: an incident timeline cannot prove WHEN dual control was disarmed (a config-approval
  // toggle and a change-number toggle write byte-identical events), that the break-glass token was UN-retired
  // (both directions write the same event), or that the canary was disabled before an incident (enable and
  // disable are one "canary-config"). Every field below is a CLOSED ENUM or a BOOLEAN -- the policy NAME, not
  // its value; the DIRECTION, not any operator text -- so the redaction class of the target is unchanged.
  //   policyName  - WHICH account policy the event moved
  //   newValue    - the direction it moved in (true = armed/retired/enabled)
  //   canaryOp    - which canary control was used (enable/disable are opposite facts, not one event)
  //   gateBypass  - the gated action was executed via the BARE BREAK-GLASS TOKEN, which is exempt from the
  //                 high-blast dual-control auto-apply. How often the token exercises that bypass is a
  //                 first-class posture fact and was recorded nowhere at all
  | {
      kind: "access-policy";
      policyName?: "config-approval" | "restore-approval" | "change-number" | "notify-signin-context" | "break-glass-retired" | "attended-cadence";
      newValue?: boolean;
      // newDays carries the new value of a policy measured in DAYS rather than a boolean (the attended
      // verification cadence). Unlike the boolean policies, whose value is deliberately NOT written to the
      // immutable log, an interval is recorded: lengthening a proof interval is exactly the change a reviewer
      // needs to see, and an integer number of days is redaction-safe. 0 records "cadence cleared".
      newDays?: number;
      canaryOp?: "enable" | "disable" | "pin" | "cadence";
      gateBypass?: "break-glass";
    }
  // custody-share is the redaction-safe record of emailing a Shamir share to a custodian: the total
  // shares (n) and the threshold (m), counts only. It NEVER carries a share value, a custodian address,
  // the wrapping key or the ciphertext; the actor and time come from the event itself.
  | { kind: "custody-share"; n: number; m: number }
  // posture-ack is the key-posture acknowledgement target: the posture chosen, the acceptance
  // statement VERSION and the "sha384:"-prefixed hash of the exact words shown, the capture channel
  // and the resolved principal type. Every field is a closed enum / opaque id / hash, so no secret and
  // no free-form text can ride here. The statementSha384 binds the tamper-evident chain to WHICH words
  // were acknowledged (the words themselves are a frozen repo constant, never in the log); principalType
  // records the evidentiary weight (a bootstrap-token ack is marked, not disguised as a named one).
  | {
      kind: "posture-ack";
      posture: "operational" | "break-glass-only";
      statementVersion: string;
      statementSha384: string;
      channel: "onboarding" | "keys-rekey";
      principalType: "owner-passkey" | "named-operator" | "bootstrap-admin-token";
    }
  // posture-check is the security-centre override target: WHICH check was overridden and the override
  // KIND (a closed enum string; "risk-accepted" | "attested-pass" | "compensating-control" |
  // "not-applicable", or null on a withdraw of a record whose kind was unreadable). checkId is an
  // engine-minted stable id (POSTURE_ID_PATTERN-bounded at the write), never operator free text; the
  // owner's reason deliberately does NOT ride here (same discipline as the risk-accept comment above).
  | { kind: "posture-check"; checkId: string; overrideKind: string | null }
  // dest-change is the REDACTION-SAFE detail on an archive-destination mutation (dest-config-set/-cleared),
  // added so the support pack can diagnose the config-change modes the bare action name could not: the op
  // (set|clear|default|remove); the destination id acted on (an operator label, redaction-safe like a
  // downpipe id, NEVER a credential); the default-pointer BEFORE/AFTER (a clear/remove of the current default
  // silently PROMOTES the next remaining destination, redirecting where unassigned downpipes write); whether
  // a removal was FORCED past the orphan guard and how many origin runs had no other proven copy at that
  // moment (the data-loss magnitude of a forced drop); and, on a rejected set, a CLOSED reject-reason class
  // (never the submitted endpoint/bucket/credential). Every field is a closed enum / operator label / bool /
  // int, so no secret can ride here, exactly like every other target.
  | {
      kind: "dest-change";
      op: "set" | "clear" | "default" | "remove";
      id?: string;
      fromDefaultId?: string;
      toDefaultId?: string;
      force?: boolean;
      uncoveredOriginRunCount?: number;
      rejectReason?: "endpoint-not-https" | "missing-fields" | "invalid-config";
      // WHICH downpipes lost their only proven copy on a FORCED removal. uncoveredOriginRunCount is the
      // magnitude and answers "how bad"; this answers "who", which is the question an incident timeline
      // actually has. The names are the customer's OWN downpipe labels (the redaction class downpipes[]
      // already carries), capped at 5 -- exactly the cap the refusal message already shows the operator.
      affectedDownpipeNames?: string[];
    }
  // supportcredential carries the closed scope plus the PUBLIC clientId and expiry of the grant a
  // mint created (a revoke records the scope + the clientId it removed when one existed). The
  // secret and its hash are deliberately unrepresentable here, like every other target. "metrics" is
  // the Prometheus-scrape bearer scope (admin/metrics.ts), the third IngestScope alongside the
  // original vendor-support/SIEM-audit-feed pair.
  | { kind: "supportcredential"; scope: "diagnostics" | "audit-feed" | "metrics"; clientId?: string; expiresAt?: string }
  // idpconnection carries the connection's opaque id, its protocol KIND and the lifecycle op (or "signin"
  // for a completed sign-in through it, or "test" for a read-only pre-save connection probe). It NEVER
  // carries a client secret, private key, signing cert, discovery secret, assertion bytes or token: those are
  // unrepresentable here, exactly like every other target. connId is an operator-chosen [a-z0-9-] slug
  // (redaction-safe like a downpipe id); connKind and op are closed unions. A sign-in's / test's actor (the
  // WHO) is the AuditEvent's own actorSubject/actorEmail.
  | { kind: "idpconnection"; connId: string; connKind: "oidc" | "oauth2" | "saml"; op: "create" | "update" | "delete" | "enable" | "disable" | "signin" | "test" }
  // credential-cleanup carries the registry item's id and (when the engine captured it at attach time)
  // the PUBLIC Cloudflare token id descriptor the operator is asked to delete. NEVER the token value;
  // the secret is unrepresentable here, exactly like every other target.
  | { kind: "credential-cleanup"; itemId: string; tokenRef?: string }
  // push-destination is the REDACTION-SAFE detail on a SIEM push destination mutation or delivery outcome,
  // mirroring dest-change: the op (set|clear|test|delivery-failure); an optional operator-label id (reserved
  // for a future multi-destination push, unused by the single current destination); on a rejected set, a
  // CLOSED reject-reason class (never the submitted endpoint/header name/secret); and on a delivery-failure,
  // the CONSECUTIVE failure count. There is deliberately NO free-form field, so neither the auth header
  // value NOR the endpoint URL NOR any fragment of a shaped push payload can ever enter the chain.
  | {
      kind: "push-destination";
      op: "set" | "clear" | "test" | "delivery-failure";
      id?: string;
      rejectReason?: "endpoint-invalid" | "format-invalid" | "missing-fields";
      failureCount?: number;
    }
  // attest-session is the attended-verification target: an OPAQUE session id plus redaction-safe COUNTS (how
  // many runs the event covered, the per-cent sample rate). It deliberately has NO field that could hold a
  // per-run master, the sampling seed, the challenge proof or a record value: the id is a ULID and runs /
  // sampleRate are integers, so a secret is unrepresentable here, exactly like every other target.
  | { kind: "attest-session"; sessionId: string; runs?: number; sampleRate?: number }
  // "secret-absent" is the true -> false twin of "secret-present": same closed shape, same detail
  // vocabulary (a presence-boolean NAME from TRACKED_PRESENCE_FIELDS), never a value.
  | { kind: "engine-state"; field: "secret-present" | "secret-absent" | "engineVersion"; detail: string }
  // test-fault is the fault-hook target: the CLOSED armable kind (validated against ARMABLE_FAULT_KINDS
  // before the event is built, so an arbitrary string cannot arrive here), the operator's own binding LABEL
  // for the one kind that names one, and on a fire, the RFC-3339 instant the fault was armed. armedAt is what
  // turns a fired event into a bounded window rather than a point: every verdict banked between armedAt and
  // the event's own ts on this estate is the set a reviewer has to doubt. No free-form field, so nothing a
  // fault provoked can be described here in a customer's own words.
  //
  // "control-plane-clear" is a FIFTH op, distinct from "disarm": disarm clears an ARMED-but-not-
  // yet-fired fault record; control-plane-clear releases the REAL recovery-required latch a fired
  // control-plane-recovery-required fault set, which the fault record itself can no longer describe (it was
  // already consumed). faultKind is always "control-plane-recovery-required" here (the only kind this op
  // applies to); it stays required rather than optional, matching the other three ops.
  | { kind: "test-fault"; op: "arm" | "disarm" | "fire" | "control-plane-clear"; faultKind: string; binding?: string; armedAt?: string };

// AuditEvent is one entry of the chain. seq is the monotonic sequence (the storage key is
// `audit:${padSeq(seq)}`); prevHash links the prior entry (genesis = GENESIS_PREV_HASH); hash is
// SHA-384 over the canonical JSON of every field EXCEPT hash itself. actorEmail is the verified
// Access email (null for the token fallback or an engine-observed event). sourceIp is from the
// CF-Connecting-IP header the engine sees (null if absent); it is a coarse provenance field, not
// a secret.
export interface AuditEvent {
  seq: number;
  ts: string; // RFC-3339 UTC millis
  // actorSubject is the STABLE principal that performed the action (iss+"|"+sub for Access,
  // passkeySubject(email) for passkey): the immutable identity the engine authorises on. It is null for
  // the bare-token break-glass and for engine-observed events (no attributable human). It is an OPAQUE
  // id, redaction-safe (never a secret/value/private fingerprint), so it is safe to record alongside the
  // display email. It is OPTIONAL on the wire/in storage for BACKWARD COMPATIBILITY: an entry recorded
  // before subject-keying has no actorSubject, and auditHash includes the field ONLY when present, so a
  // legacy entry's hash is unchanged and the chain still verifies across the upgrade.
  actorSubject?: string | null;
  actorEmail: string | null; // the verified DISPLAY email (null for the token fallback / engine events)
  actorMethod: AuditActorMethod;
  sourceIp: string | null;
  action: AuditAction;
  outcome: AuditOutcome;
  target: AuditTarget;
  // advisory (V6.8.4): the IdP's ADVISORY, NON-GATING acr/amr/auth_time (OIDC) or AuthnContextClassRef/
  // AuthnInstant (SAML), bounded + redaction-safe (auth-context.ts). Present ONLY on an idp-sign-in event
  // whose IdP asserted at least one of them; absent for every other action and for a basic IdP. Like
  // actorSubject it is OPTIONAL for BACKWARD COMPATIBILITY: auditHash folds it in ONLY when present, so every
  // pre-upgrade entry (and every non-sign-in entry) hashes byte-for-byte as before and the chain still
  // verifies. It NEVER influenced authorization (the RP resolved identity/role without it); it is recorded
  // purely so an operator can see how the IdP said the session authenticated.
  advisory?: AdvisoryAuthContext;
  prevHash: string; // "sha384:..."
  hash: string; // "sha384:..."
}

// AuditDraft is the recorder's input: everything in an AuditEvent EXCEPT the chain-managed
// fields (seq, ts, prevHash, hash) and the IP, which the DO/router supply. The recorder cannot be
// handed a hash or a prevHash, so it cannot forge a chain link, and it cannot be handed a
// free-form target, so it cannot write plaintext. ts is set by the DO at append time; sourceIp is
// threaded from the request by the router. This is the redaction-by-construction boundary in type
// form: the only way to add an entry is to provide a closed-union target plus the safe scalars.
export interface AuditDraft {
  // actorSubject is the stable principal of the actor (OPTIONAL: an engine-observed draft, or a caller
  // with no stable identity, omits it). buildEvent stamps it onto the event (defaulting to null when the
  // draft omits it), and auditHash folds it in only when it is a string, so an omitted subject leaves
  // the hash byte-for-byte as it was before subject-keying. It is redaction-safe (an opaque id).
  actorSubject?: string | null;
  actorEmail: string | null;
  actorMethod: AuditActorMethod;
  sourceIp: string | null;
  action: AuditAction;
  outcome: AuditOutcome;
  target: AuditTarget;
  // advisory (V6.8.4): OPTIONAL, non-gating IdP acr/amr/auth_time carried onto an idp-sign-in event only.
  // Omitted for every other draft. See AuditEvent.advisory. buildEvent stamps it only when present.
  advisory?: AdvisoryAuthContext;
}

// ChainVerdict is the GET /admin/audit/verify result: intact through checkedThrough (the head
// seq), or the first seq at which the chain breaks. A break is a RESULT, not an error: the route
// still returns 200 and the console shows "break detected at entry N". earliestSeq is the lowest
// seq actually verified (the baseline), so after a retention rollover the console can show that the
// retained chain legitimately begins above seq 1 rather than at genesis; it is -1 for an empty log.
export interface ChainVerdict {
  intact: boolean;
  checkedThrough: number; // the highest seq checked (the head seq), or -1 for an empty log
  earliestSeq: number; // the lowest seq checked (the baseline), or -1 for an empty log
  brokenAt?: number; // the first seq whose stored hash or prevHash does not recompute/link
  // causeClass names WHICH of the four checks failed. "Broken at version 41" cannot distinguish an
  // EDITED snapshot (recompute-mismatch: someone changed a stored entry) from a FORGED digest
  // (prev-hash-mismatch: an entry was inserted or reordered) from a DELETED entry (seq-gap) from a chain that
  // no longer links to genesis (genesis-link). Those are four different investigations, and the verdict used
  // to give the same answer to all four. A closed enum, derived from the branch that fired; never a value.
  causeClass?: ChainBreakCause;
}

// The closed cause of ONE chain break. Shared by the audit chain and the config-history chain.
//
// "recompute-mismatch" was answering for TWO INDEPENDENT CHECKS on the config-history chain, and they are
// different incidents with different blast radii. The contentHash covers the SNAPSHOT BYTES. The HMAC digest
// covers the ENVELOPE around them (id/at/author/summary/contentHash/parentHash), NOT the snapshot.
//
// The split itself was asserting a fact the code had never established. configContentHash takes NO KEY,
// so the only actor who can rewrite a stored version -- the only actor who can produce EITHER state -- can also
// refresh the unkeyed contentHash. That version passes the recompute and fails the digest, and the pack told
// support "the body is INTACT and verifies cleanly" about a body that was the attacker's. What actually vouches
// for a body is the SUCCESSOR's parentHash, which commits to it and rides inside the successor's KEYED digest.
// So the digest family is now three honest causes, and each says only what was proven:
//
//   recompute-mismatch        the body at version 41 no longer hashes to its own stored contentHash: it was
//                             rewritten in place by someone who did not bother to refresh the hash.
//   content-swapped           the body was rewritten AND re-hashed. The successor's VALID keyed envelope commits
//                             to a DIFFERENT contentHash for version 41, so the successor's own key-bound word is
//                             that this is not the body that was there.
//   envelope-digest-mismatch  the successor's VALID keyed envelope commits to EXACTLY this body, so the body is
//                             keyed-vouched. What was rewritten is the record's ATTRIBUTION (who changed it, and
//                             when), or the record was minted without the DO's HMAC key.
//   digest-unvouched          the digest failed on the HEAD version (no successor exists), or on a version whose
//                             successor's digest is broken too. NOTHING vouches for the body, so the code cannot
//                             separate a swapped body from a forged attribution. It says that, rather than
//                             picking one.
//   head-truncated            the retained chain's HEAD sits BELOW the head this DO itself committed to (the
//                             persisted head anchor: auditHead's seq+hash, config-history's id+contentHash), or
//                             sits AT it with a different hash. The newest entries -- the ones that record what
//                             was just done -- were REMOVED or REWRITTEN. Retention rolls the OLDEST entries off
//                             and never lowers the anchor, so a rollover cannot produce this. It needs NO key:
//                             the anchor is an unkeyed witness already in storage, and the recompute passes
//                             cannot see the deletion at all (a truncated tail leaves the survivors perfectly
//                             linked, which is why "delete the newest rows" read INTACT before this check existed).
//   signing-key-rotated       the in-DO HMAC key was regenerated or lost, so EVERY digest in the chain fails and
//                             the KEYED check proves nothing either way. The engine models this as recoverable
//                             context (configHistorySigningKeyRotated), and a latch that reported forgery for it
//                             was pointing support at an attacker who does not exist.
//
//                             WHAT THE KEY-FREE PASS PROVES, AND WHAT IT CANNOT. unkeyedIntact=true means
//                             exactly this: NO LAZY TAMPER. No stale content hash, no broken parent link, no id
//                             gap. It does NOT mean "not tamper". Once the key is gone, nothing unkeyed vouches
//                             for the HEAD version's body (no successor commits to it), for a rewritten body
//                             whose successor's parentHash was RE-LINKED to match, or for ANY version's
//                             attribution (the author and the timestamp live only inside the keyed envelope).
//                             Every one of those is recomputable for free by the only actor who can reach this
//                             state: they already hold DO-storage write, and they have just destroyed the one
//                             thing they could not forge. So this cause means "the rotation explains every KEYED
//                             failure, and the unkeyed checks find no careless edit" -- never "this is not
//                             tamper". A key-free pass cannot exclude a re-linked body, the head body, or a
//                             forged author, and the pack must not read as an all-clear.
//
//                             IT DOES NOT SAY "NOTHING WAS TAMPERED" ON ITS OWN. verifyConfigChain
//                             returns at the FIRST break, so with the key gone it dies on version 1's digest and
//                             never examines 2..N -- and the key can be destroyed by an OWNER BUTTON (terminate
//                             all sessions deletes the passkey session key), so any actor with the DO-storage
//                             write access a tamper already requires could press it and convert every
//                             config-history tamper into the row that says nothing happened. A one-button mask.
//                             The recorder therefore runs the UNKEYED pass -- body recompute, parentHash link, id
//                             contiguity, none of which a key can fake or break -- over the WHOLE chain, and
//                             latches this cause only when that pass is CLEAN. When it is not, the unkeyed cause
//                             is latched AT ITS OWN SEQ beside this one, so a rotated key and a rewritten version
//                             are two rows, not one.
//
// The audit chain has no HMAC envelope, so its four causes are unaffected.
//
// seq-gap on config-history is reachable only if a deleter ALSO re-links the survivor's
// parentHash. A plain deletion breaks the LINK first and reports prev-hash-mismatch at the survivor, because the
// parent-hash check runs before the contiguity check.
export const CHAIN_BREAK_CAUSES = ["genesis-link", "prev-hash-mismatch", "seq-gap", "recompute-mismatch", "envelope-digest-mismatch", "content-swapped", "digest-unvouched", "signing-key-rotated", "missing-version", "head-truncated"] as const;
export type ChainBreakCause = (typeof CHAIN_BREAK_CAUSES)[number];

// VerifyChainOptions tunes the genesis-linkage check. By default verifyChain expects the first
// entry to be the TRUE genesis (seq 1 linking to GENESIS_PREV_HASH), so deleting the genesis from a
// chain that never rolled over is still detected as a break at the new first entry. After a
// documented retention rollover the chain legitimately begins above seq 1 with a first entry whose
// prevHash links to a now-pruned predecessor, so the caller (the DO, which knows a rollover
// happened) passes expectGenesis:false to take the baseline from the first RETAINED entry instead of
// failing because genesis is gone. This does NOT weaken tamper-evidence within the retained set:
// every retained entry's hash must still recompute, every link from the second retained entry
// onward must match its predecessor's stored hash, and the seqs must stay contiguous; only the "the
// first entry must be genesis" assertion is relaxed, and only when the DO has recorded a rollover.
export interface VerifyChainOptions {
  expectGenesis?: boolean; // default true; false after a documented retention rollover
}

// AuditFilter is the server-side filter for GET /admin/audit. All fields are optional; an omitted
// field does not constrain. before+limit page a long log (return entries with seq < before,
// newest-first, up to limit). The filter is applied over the stored, ordered list in the DO.
export interface AuditFilter {
  actor?: string; // exact verified email match (lowercased compare)
  action?: AuditAction;
  downpipe?: string; // a downpipe id (matches a downpipe or restore/run target carrying that id)
  outcome?: AuditOutcome;
  from?: string; // RFC-3339 inclusive lower bound on ts
  to?: string; // RFC-3339 inclusive upper bound on ts
  before?: number; // page cursor: only entries with seq strictly less than this
  afterSeq?: number; // tail cursor: only entries with seq strictly greater than this (the audit-feed collector cursor)
  limit?: number; // page size; defaulted and capped by the DO
}

// ExportFormat is the GET /admin/audit/export shape selector. JSON is the default; CSV is offered
// for a spreadsheet/SIEM import. The CSV rendering (and its formula-injection guard) lives in
// audit.ts alongside the chain logic so the export head hash and the chain stay in one module.
export type ExportFormat = "json" | "csv";
