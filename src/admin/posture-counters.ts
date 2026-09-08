// The POSTURE half of the admin diagnostic counters.
//
// WHY A SEPARATE LEAF. These are members of ADMIN_COUNTER_NAMES (admin/diag-records.ts spreads them into it,
// so they share its one bounded {closed name -> count, lastAt} aggregate, its applier, its redaction
// chokepoint and its pack section). They live here because diag-records.ts is already at its module-size
// ceiling and because they are one coherent family: every name below is a control the customer BELIEVES is in
// force and which the engine has quietly stopped applying, or a refusal support cannot otherwise prove
// happened. A data-loss counter says "you lost bytes"; these say "you are not protected the way you think you
// are", which is the harm a posture gap does.
//
// DISCRIMINATION IS THE POINT. Every name here is a DISCRIMINATOR, not a generic fault: the pair of states a
// ticket cannot tell apart gets one name EACH. A settle that was refused by the high-water guard and one
// refused because no pending record existed are two different tickets with two different fixes, so they are
// two different counters -- collapsing them into "update-refused" is the failure mode this whole campaign
// exists to remove.
//
// NO-CUSTODY: the only thing that ever crosses the wire is a {closed name: int count} tally. There is no
// payload, no message, no id, no value. A classifier upstream may READ text to SELECT one of these names; it
// returns the name and discards the text.

// ---- G271: the claim/group BOUNDING DROPS at every parse boundary ---------------------------------------
//
// "The user is in the right AD group but gets viewer." Three separate normalisers (access.ts boundGroups,
// identity.ts boundCallerGroups, oidc.ts boundGroups) drop an over-long, control-char-bearing or past-the-cap
// group SILENTLY, and auth-context.ts drops an over-length acr / amr / auth_time the same way. The drop is
// CORRECT (a truncated group name would be a different group, and a truncate-not-drop policy is how a
// customer's group silently becomes someone else's), and it is also why "present but dropped" reads exactly
// like "the IdP sent nothing at all". These name the BOUNDARY and the CLAIM KIND, so support can say "your
// group list exceeds the cap" or "that group carries a control character" without ever seeing a group name.
//
// The dropped VALUE never rides. It is customer IdP data and, at the Access boundary, attacker-influenceable:
// the whole reason drop-not-truncate is the rule.
export const CLAIM_DROP_COUNTER_NAMES = [
  // the Cloudflare Access JWT boundary (access.ts): the signed groups claim + the optional idp hint
  "claim-drop-access-jwt-group-overlength", // a group name exceeded GROUP_NAME_MAX and was dropped whole: the mapped group can never match
  "claim-drop-access-jwt-group-control-char", // a group name carried an ASCII control character and was dropped (it could never be a safe storage key)
  "claim-drop-access-jwt-groups-list-capped", // the token asserted MORE groups than GROUPS_MAX: the groups past the cap were never considered, so a user with 200+ groups can lose the one that matters. THE "right AD group, viewer role" ticket
  "claim-drop-access-jwt-idp-hint", // the identityProvider hint was present but unusable, so the console cannot show the role's BASIS honestly
  // THE CALLER-HEADER BOUNDARY HAS NO MEMBERS, AND CANNOT HAVE ONE. decodeCaller re-bounds the groups the
  // router reconstructs for the DO, and it is the SECOND bound: EVERY producer of a Caller has already applied
  // the IDENTICAL limits (access.ts boundGroups, oidc.ts boundGroups, oauth2.ts addGroup and the DO's own
  // boundGroupList all use GROUPS_MAX 200 / GROUP_NAME_MAX 256), so decodeCaller has nothing left to drop. Three
  // members lived here whose only input was a hand-built header no production producer can emit -- coverage-shaped
  // nothing that a support engineer could never see -- and the doc block claimed SAML group drops were tallied
  // here, which was false in both directions. They are deleted, and the SAML front door now tallies its own.
  // the native OIDC/OAuth2 id_token (oidc.ts + auth-context.ts): the groups/roles claim and the advisory context
  "claim-drop-oidc-token-group-overlength",
  "claim-drop-oidc-token-group-control-char",
  "claim-drop-oidc-token-groups-list-capped",
  "claim-drop-oidc-token-acr", // an acr was asserted but exceeded ACR_MAX_LEN and was dropped: the sign-in record cannot show the assurance level the IdP claimed
  "claim-drop-oidc-token-amr", // an amr entry was asserted but unusable (over-long, or past the list cap): "prove this session was MFA'd" is unanswerable
  "claim-drop-oidc-token-auth-time", // an auth_time was asserted but not a usable epoch: the session's original authentication instant is unknown
  // the OAUTH2 front door (oauth2.ts): GitHub/GitLab/generic providers, a LIVE interactive sign-in kind that
  // tallied NOTHING. resolveGroups builds membership from the provider's org/team endpoints and addGroup drops
  // an over-long name, a control-char name and every group past GROUPS_MAX -- and completeOauth2Login returned
  // a principal with no claimDrops at all, so the DO's shared recorder could never fire on this path. A GitHub
  // org with 260 teams whose mapped team falls past the cap is verbatim this gap's ticket ("the user is in the
  // right group and gets viewer"), and it produced the SAME empty row as a provider that asserted no groups.
  // The caller-header re-bound is no safety net: it re-applies IDENTICAL limits to an already-truncated list,
  // so it drops nothing and tallies nothing.
  "claim-drop-oauth2-group-overlength",
  "claim-drop-oauth2-group-control-char",
  "claim-drop-oauth2-groups-list-capped", // the provider asserted MORE groups than GROUPS_MAX: resolveGroups stops at the cap and the mapped team can fall past it
  // the SAML assertion (saml/assertion.ts): the advisory context. buildAuthContext was called with NO tally,
  // so an over-length AuthnContextClassRef or an unusable AuthnInstant was dropped in silence and read
  // exactly like an IdP asserting neither. The auth-time drop is recorded in assertion.ts, at the raw
  // attribute, because parseSamlInstantMs folds an unreadable instant to null and null reached the shared
  // constructor as `undefined` -- the same input as an IdP that asserted no AuthnInstant at all.
  "claim-drop-saml-acr", // an AuthnContextClassRef was asserted and was over the length cap: the assurance level the IdP claimed cannot be shown
  "claim-drop-saml-auth-time", // an AuthnInstant was ASSERTED and could not be used (unreadable, empty, or outside the usable range): the session's original authentication instant is unknown
  // the SAML GROUPS attribute. R5: this is the front door the gap's own ticket walks through, and it was the one
  // that named nothing. SAML groups ride VERBATIM out of the assertion (collectIdentity returns every value of the
  // configured groups attribute, unbounded) and are first bounded by the DO's boundGroupList inside the native
  // session mint -- which tallied only the coarse group-name-dropped signal, a count that names neither the KIND
  // nor the boundary. An Entra or Okta SAML user in three hundred groups whose ONE mapped group falls past the cap
  // is "the user is in the right AD group and gets viewer", and the pack could not say which of the three bounds
  // threw it away. Produced at the session mint, where the SAML principal's groups are actually bounded.
  "claim-drop-saml-group-overlength", // a SAML group name exceeded GROUP_NAME_MAX and was dropped whole: the mapped group can never match
  "claim-drop-saml-group-control-char", // a SAML group name carried an ASCII control character and was dropped (it could never be a safe storage key)
  "claim-drop-saml-groups-list-capped", // the assertion carried MORE groups than GROUPS_MAX: the groups past the cap were never considered
] as const;

// The closed PARSE BOUNDARY a claim was bounded at.
//
// G271: "oauth2" and "saml" are two front doors that were bounding claims and tallying nothing. Note that the
// boundary is a fact about WHERE the drop happened, so it must be passed in rather than assumed: buildAuthContext
// is shared by the OIDC and SAML paths and used to hard-code "oidc-token", which would have filed a SAML drop
// under a boundary the assertion never crossed.
export const CLAIM_BOUNDARIES = ["access-jwt", "oidc-token", "oauth2", "saml"] as const;
export type ClaimBoundary = (typeof CLAIM_BOUNDARIES)[number];

/** The closed CLAIM KIND that was dropped. */
export const CLAIM_DROP_KINDS = ["group-overlength", "group-control-char", "groups-list-capped", "idp-hint", "acr", "amr", "auth-time"] as const;
export type ClaimDropKind = (typeof CLAIM_DROP_KINDS)[number];

/**
 * claimDropCounter composes the closed counter name for ONE bounding drop. Both halves are closed-set
 * members, so the produced name is always a member of CLAIM_DROP_COUNTER_NAMES (the validate suite pins the
 * product of the two sets that are actually reachable against that list, so a boundary that grows a claim kind
 * cannot silently start emitting a name the aggregate would drop).
 *
 * @param boundary - the closed parse boundary.
 * @param kind - the closed claim kind that was dropped.
 * @returns the closed counter name.
 */
export function claimDropCounter(boundary: ClaimBoundary, kind: ClaimDropKind): string {
  return `claim-drop-${boundary}-${kind}`;
}

/**
 * A ClaimDropTally is the bounded, redaction-safe out-parameter the three group normalisers and the advisory
 * auth-context bounder fill in as they drop. It is a SET of closed counter names: no value, no count per
 * value, and nothing derived from the dropped string. The caller (which holds the scheduler stub the pure
 * normaliser does not) bumps each name once per sign-in, so a token asserting 300 over-long groups is ONE
 * observation of "this token's groups are over-length", not 300.
 */
export type ClaimDropTally = Set<string>;

// ---- G274: the FIRE-AND-FORGET security alert that silently never fired ----------------------------------
//
// "Dual control was disarmed / an attacker added an owner / recovery codes were regenerated and nobody was
// alerted." Every one of these alerts is emitted best-effort through routeEmission, whose resolve phase can
// throw, whose channel set can be EMPTY, whose delivery can fail on every channel, and whose post-delivery
// history record is a void-ed promise. In each case the alert never reached a human AND the pack's notify
// history has no row -- so the pack is emptiest for exactly the alert that mattered most.
//
// The key is CLASS x STAGE, not class alone: "nobody was told the dual control was disarmed because no channel
// matched" (the operator never wired alerting for that event) and "...because the delivery failed" (the webhook
// is dead) are opposite fixes. Folding the stage into the KEY is what makes them two rows rather than one.
//
// NOISE. no-channel is recorded ONLY for these SECURITY alert classes, where a zero-channel resolution means a
// takeover/disarm notification was silently dropped. It is not a fault of the notify pipeline; it is the
// posture fact the customer needs to know, and it is the single most common cause of "nobody was alerted".
// THE CLASS IS THE ALERT'S MEANING, NOT THE NOTIFY EVENT. The class axis used to be derived from the
// coarse notify EVENT, and three of the events are shared by unrelated alerts, so the counters COALESCED on
// exactly the distinctions the gap exists to make. "An attacker added an owner" (role-change) and "recovery
// codes were regenerated" (auth-credential-change) and "the backup destination was repointed" (dest-change) all
// composed alert-emit-auth-change-*, and bumpAdminCounter sums by closed name, so they were ONE count in ONE
// row. A support engineer holding the pack could not tell which alert had never reached a human, which is the
// whole question. "auth-change" swallowed 13 of the 21 call sites.
//
// Each class below is now passed DOWN from the call site that knows what it is alerting about, so the name says
// what happened. The events are unchanged (the customer's notify rules still key on them); only the evidence
// improves.
export const ALERT_EMISSION_COUNTER_NAMES = [
  // owner-role-grant: a role was granted or changed (the "an attacker added an owner" alert)
  "alert-emit-owner-role-grant-resolve", // the channel RESOLVE round trip threw / answered unusably: the alert died before any channel was chosen
  "alert-emit-owner-role-grant-no-channel", // resolve answered with ZERO channels: the alert was dropped and nothing anywhere said so
  "alert-emit-owner-role-grant-deliver", // every resolved channel FAILED delivery: the alert was addressed and never arrived
  "alert-emit-owner-role-grant-record", // the post-delivery history write failed: the alert may have been delivered, and the pack's notify history has no row to prove it
  // offboard: a member was DEPROVISIONED (a removal in the console, or a SCIM leaver removal)
  "alert-emit-offboard-resolve",
  "alert-emit-offboard-no-channel",
  "alert-emit-offboard-deliver",
  "alert-emit-offboard-record",
  // credential-change: an admin credential was revoked (a passkey removed)
  "alert-emit-credential-change-resolve",
  "alert-emit-credential-change-no-channel",
  "alert-emit-credential-change-deliver",
  "alert-emit-credential-change-record",
  // idp-change: an IdP connection was added, removed, enabled/disabled, or had its signing cert rolled (this
  // changes WHO CAN SIGN IN, and it is the quietest way to take an account over)
  "alert-emit-idp-change-resolve",
  "alert-emit-idp-change-no-channel",
  "alert-emit-idp-change-deliver",
  "alert-emit-idp-change-record",
  // dest-change: a backup destination was set, repointed, removed or made default (a repoint is exfiltration,
  // a removal is destruction), which is a different incident from anyone's role changing
  "alert-emit-dest-change-resolve",
  "alert-emit-dest-change-no-channel",
  "alert-emit-dest-change-deliver",
  "alert-emit-dest-change-record",
  // recovery-regenerate: the recovery codes were REGENERATED (the old ones are void, the new ones are somebody's)
  "alert-emit-recovery-regenerate-resolve",
  "alert-emit-recovery-regenerate-no-channel",
  "alert-emit-recovery-regenerate-deliver",
  "alert-emit-recovery-regenerate-record",
  // dual-control-disarm: the second-owner-approval guarantee was switched OFF
  "alert-emit-dual-control-disarm-resolve",
  "alert-emit-dual-control-disarm-no-channel",
  "alert-emit-dual-control-disarm-deliver",
  "alert-emit-dual-control-disarm-record",
  // sign-in-context: a sign-in from an unrecognised context (the takeover signal)
  "alert-emit-sign-in-context-resolve",
  "alert-emit-sign-in-context-no-channel",
  "alert-emit-sign-in-context-deliver",
  "alert-emit-sign-in-context-record",
  // recovery-code-used: a recovery code SUCCEEDED and someone is now signed in as an admin (router-auth-flow.ts,
  // the break-glass path). recovery-code-abuse: attempts were rate-limited or repeatedly rejected and NOBODY got
  // in. These were ONE class called "recovery-abuse", and the coalescence was the very defect the round
  // claimed to have removed from auth-change. They are opposite facts -- someone is IN versus someone is being
  // KEPT OUT -- the customer's notify rules key on the two different EVENTS, so the no-channel remedy differs,
  // and the single name asserted a fact the code never established: a lawful owner break-glass with no channel
  // wired was filed as "abuse".
  "alert-emit-recovery-code-used-resolve",
  "alert-emit-recovery-code-used-no-channel",
  "alert-emit-recovery-code-used-deliver",
  "alert-emit-recovery-code-used-record",
  "alert-emit-recovery-code-abuse-resolve",
  "alert-emit-recovery-code-abuse-no-channel",
  "alert-emit-recovery-code-abuse-deliver",
  "alert-emit-recovery-code-abuse-record",
  // posture-regression: a security posture check that was passing and now fails
  "alert-emit-posture-regression-resolve",
  "alert-emit-posture-regression-no-channel",
  "alert-emit-posture-regression-deliver",
  "alert-emit-posture-regression-record",
  // ---- the REJECTED stage (R4), and it is enumerated for TWO classes ONLY, because two classes are all that
  // can produce it. A "rejected" row means the DO's parseEmission REFUSED the emission at the input boundary, so
  // it was never matched against a single rule: no channel was consulted, and NO rule change can ever fix it.
  // That is the opposite remedy from no-channel ("wire a rule"), and it used to be filed AS no-channel, which
  // sent support to a rule the customer already had.
  //
  // THE PRODUCERS, NAMED. parseEmission bounds `detail` at 512 chars (scheduler-do-notify.ts). Only two call
  // sites compose a detail that can exceed it, and both do so out of TWO e-mail addresses, each admitted up to
  // 320 chars by the engine's own validators (scim.ts, session.ts SESSION_EMAIL_MAX):
  //   router-rbac.ts  `Role changed for ${entry.email} to ${entry.role} by ${caller.email}.`   -> owner-role-grant
  //   router-rbac.ts  `Member removed (offboarded): ${body.email} by ${caller.email}.`         -> offboard
  // Every other alert's detail is engine-authored or carries at most ONE e-mail, so it cannot reach the bound and
  // a "rejected" member for it would be coverage-shaped nothing. routeEmission composes the name and falls back
  // to the `resolve` stage -- which is still true of a rejection, the alert died before any channel was chosen --
  // when the vocabulary does not admit it, so a future over-long detail is never silently dropped either.
  "alert-emit-owner-role-grant-rejected",
  "alert-emit-offboard-rejected",
] as const;

// The closed ALERT CLASS and STAGE vocabularies the key above is the product of. Kept as sets so the recorder
// composes the name from two enum members rather than from a caller string (the redaction boundary is that a
// name is COMPOSED, never passed in).
export const ALERT_CLASSES = ["owner-role-grant", "offboard", "credential-change", "idp-change", "dest-change", "recovery-regenerate", "dual-control-disarm", "sign-in-context", "recovery-code-used", "recovery-code-abuse", "posture-regression"] as const;
export type AlertClass = (typeof ALERT_CLASSES)[number];
// "rejected" (R4) is NOT the product of every class: see the note in ALERT_EMISSION_COUNTER_NAMES. The composed
// name is admitted against that list, so a stage a class cannot produce can never enter the aggregate.
export const ALERT_EMISSION_STAGES = ["resolve", "no-channel", "deliver", "record", "rejected"] as const;
export type AlertEmissionStage = (typeof ALERT_EMISSION_STAGES)[number];
const ALERT_EMISSION_COUNTER_NAME_SET: ReadonlySet<string> = new Set(ALERT_EMISSION_COUNTER_NAMES);

/**
 * alertEmissionCounterAdmitted answers whether the composed class x stage name is one the aggregate stores.
 *
 * routeEmission uses it so a stage with no enumerated name for a class is never SILENTLY DROPPED by the DO's
 * out-of-vocabulary guard: it falls back to a stage that is still true of the same fault.
 *
 * @param cls - the closed alert class.
 * @param stage - the closed stage the emission died at.
 * @returns true when the composed name is a member of ALERT_EMISSION_COUNTER_NAMES.
 */
export function alertEmissionCounterAdmitted(cls: AlertClass, stage: AlertEmissionStage): boolean {
  return ALERT_EMISSION_COUNTER_NAME_SET.has(alertEmissionCounter(cls, stage));
}

/**
 * alertEmissionCounter composes the closed counter name for ONE failed security-alert emission. Both halves
 * are closed-set members, so the produced name is always a member of ALERT_EMISSION_COUNTER_NAMES.
 *
 * @param cls - the closed alert class.
 * @param stage - the closed stage the emission died at.
 * @returns the closed counter name.
 */
export function alertEmissionCounter(cls: AlertClass, stage: AlertEmissionStage): string {
  return `alert-emit-${cls}-${stage}`;
}

// THE EVENT->CLASS MAP IS GONE, AND ITS ABSENCE IS THE FIX (G274).
//
// securityAlertClass(event) used to derive the class from the notify EVENT. That is a lossy read: the events
// are a NOTIFICATION-ROUTING vocabulary (what a customer subscribes a channel to), not a taxonomy of what
// happened, and three of them are shared by unrelated alerts. Deriving the class from the event therefore made
// the counters coalesce on the exact pairs the gap says must be told apart.
//
// The class is now an ARGUMENT, passed from the call site that knows the meaning of the alert it is firing
// (routeAuthChangeAlert and its siblings in router-notify.ts). A call site cannot pass a string: AlertClass is
// a closed union, so a drifted caller is a compile error rather than a new counter name.
//
// NOISE is preserved structurally, and better than before: only the routeXxxAlert wrappers -- which fire ONLY
// on security events -- reach the counter at all. An OPERATIONAL notification (backup-success, canary-recovered,
// update-available) goes through routeNotification, never touches this, and a customer who has deliberately
// wired no channel for one can never trip a fault counter.
//
// "source-detached" was REMOVED with the map, and it is worth recording why it never worked. It was bound to
// the "offboard" class, but a detached SOURCE BINDING is not a member being deprovisioned, and the event is
// emitted only from the cron alert pass, through routeNotification -- a DIFFERENT transport that never calls
// noteEmissionFailure. So all four alert-emit-offboard-* names were unwritable by any code path, while the REAL
// offboard events (a member removed in the console, a SCIM leaver removal) were counted as auth-change and
// collided with the owner-added grant. The class now names what it says, and both real events produce it.

// ---- G275: the REFUSED / INCONCLUSIVE update, settle, ramp and rollback attempts -------------------------
//
// "We tried to roll back at 02:00 and it refused" / "we kept trying to settle the ramp overnight". The apply
// and ramp-start guards already emit an `update-refused` audit event; the settle, ramp-settle, rollback and
// freshness guards return a BARE 400 and record nothing. Worse, the audit EXCERPT the pack carries does not
// forward the audit target's `detail` field (by design: it is operator prose), so even the guards that DO
// audit contribute no pack-visible cause. So the pack shows an armed-or-expired pending record and zero
// evidence that any attempt happened, let alone which guard tripped or how many times.
//
// The freshness/replay refusal is the one that matters most: it is a possible ATTACK signal (a replayed or
// back-dated update artefact) and it uniquely emits no audit at all.
export const UPDATE_REFUSAL_COUNTER_NAMES = [
  // WHICH GUARD refused (the closed guardClass). One name each: a rollback refused for want of a deploy token
  // and one refused because the target version is below the high-water mark are different tickets.
  "update-refused-no-pending", // the action needs an armed pending record and there is none (or it has expired): "we tried to settle and it just 400'd"
  "update-refused-ramp-shaped", // the pending record is not the shape this action needs (a ramp action against a plain pending, or the reverse)
  "update-refused-deploy-token", // no usable deploy token was supplied for an action that must redeploy
  "update-refused-account-unmarked", // the engine cannot name its own Cloudflare account, so no apply/settle/rollback can address the script
  "update-refused-high-water", // the target version is at or below the recorded high-water mark: a DOWNGRADE was refused
  "update-refused-freshness-replay", // THE ATTACK SIGNAL: the artefact's issuedAt / sequence is not fresh (a replayed or back-dated update). The only guard whose refusal emitted nothing at all
  "update-refused-no-target", // the action named no resolvable target version / artefact
  // THE APPLY LEG'S OWN GUARDS, which audited and were still invisible. The four names below sat behind a
  // recordUpdateRefusal audit event and NOTHING ELSE, and the pack's configEvents excerpt deliberately drops the
  // audit target's `detail` -- so every one of them reached a support engineer as the same unclassed
  // "update-refused / denied" row. "We clicked Update now three times last night and it just errored" then had
  // four different causes with four different remedies (settle the open verification / mark the engine's own
  // Cloudflare account / the signed channel would not resolve an artefact / configure a destination) and one row.
  "update-refused-pending-open", // a prior apply/ramp is still awaiting verification, so a NEW apply/ramp was refused: settle or roll back the open one first
  "update-refused-artefact-resolve", // the signed channel resolved NO usable artefact for the requested component (engine or console): the release is not one this engine can apply
  "update-refused-artefact-download", // the artefact URL the signed channel names would not download (the bundle never arrived), so nothing was deployed
  "update-refused-no-destination", // the LIVE apply was refused because no backup destination is configured: the canary flight that verifies an update would have nowhere to fly
  // NO MEMBER for an unrecognised component split (R6). parseComponentsRequest refuses a `components` array
  // naming anything outside the closed set, but the ONLY client that posts that field is the console, whose
  // own UpdateComponentId type is "engine" | "console" and whose every call site builds the array from those
  // two literals. No request a real client can send reaches that guard, so a counter on it would be a name no
  // pack can ever carry. Re-add it in the same change set as the release that gives the console a third
  // component id. (The RELEASE naming an unplannable component is a different, reachable state: it is
  // update-degraded-components-unplannable, where nothing is refused and the component just never updates.)
  // HOW MANY attempts, and how they ended. The pending record keeps only the LAST outcome, so a night of
  // repeated settle attempts collapses to one row and "how many settle attempts were inconclusive?" (the
  // question that decides whether the ramp is stuck or the verification is genuinely slow) is unanswerable.
  "update-settle-inconclusive", // a settle attempt RAN and could not decide (the verification is still pending): the ramp stays armed, and this is the count that says how hard the operator has been trying
  "update-settle-refused", // a settle attempt was refused by a guard before it could run
  "update-rollback-refused", // a rollback attempt was refused by a guard: "we tried to roll back at 02:00 and it refused"
] as const;

/** The closed guard that refused an update-family action. Selected by the guard site; never a message. */
export const UPDATE_GUARD_CLASSES = [
  "no-pending",
  "ramp-shaped",
  "deploy-token",
  "account-unmarked",
  "high-water",
  "freshness-replay",
  "no-target",
  "pending-open",
  "artefact-resolve",
  "artefact-download",
  "no-destination",
] as const;
export type UpdateGuardClass = (typeof UPDATE_GUARD_CLASSES)[number];

/**
 * updateRefusalCounter composes the closed counter name for ONE refused update-family action.
 *
 * @param guard - the closed guard class that refused it.
 * @returns the closed counter name (a member of UPDATE_REFUSAL_COUNTER_NAMES).
 */
export function updateRefusalCounter(guard: UpdateGuardClass): string {
  return `update-refused-${guard}`;
}

// ---- G332: the SILENT DEGRADATION of the update safety machinery -----------------------------------------
//
// The update path is the one place where the engine rewrites ITSELF, so every safety control on it (replay
// protection, the canary regression guard, the component map, the destination gate) is load-bearing. Each of
// the branches below quietly WEAKENS one of those controls and reports success, and the weakening is visible
// only in Workers Logs, which remote support structurally cannot read.
//
// "Was replay protection active when that update applied?" is the question these answer, and today the honest
// answer is "we cannot tell" -- which is the same posture as "no, it was not".
export const UPDATE_DEGRADATION_COUNTER_NAMES = [
  // R6 SPLIT: PRESENT-BUT-UNUSABLE versus HONESTLY-ABSENT. These were one pair of names over two states with
  // opposite remediations, and the recorder sat PAST the point where the product erased the difference.
  // loadVerifiedChannel sanitises the signed claim to well-typed-or-absent, so a TYPE-malformed claim (a
  // sequence shipped as the string "12", an issuedAt shipped as an epoch number) was already undefined by the
  // time checkChannelFreshness ran: it could only ever see ABSENT, and it filed that absence under the
  // MALFORMED name. So the malformed names had no producer for their own meaning, and the far worse state --
  // no watermark yet (the whole fleet today), a type-malformed issuedAt, the opt-in max-age guard ON, and
  // therefore running on nothing while a stale descriptor applies -- recorded NOTHING AT ALL and read exactly
  // like a fully-protected apply. The -malformed/-unparseable pair is now bumped AT THE ERASURE (the
  // sanitiser), unconditionally, so it fires with or without a watermark; the -absent pair is bumped by the
  // check, and only for a claim the descriptor genuinely never made.
  "update-degraded-freshness-issuedat-unparseable", // the artefact DECLARED an issuedAt and it was unusable (the wrong type, or a string no date parser accepts), so it was dropped: the anti-rollback floor and the opt-in max-age staleness guard both ran on NOTHING for that apply. This is the publisher shipping a broken claim, and it is the row that says replay protection was not in force
  "update-degraded-freshness-sequence-malformed", // the artefact DECLARED a monotonic sequence and it was not a finite number, so it was dropped: the sequence half of the replay guard was skipped. Our release bug, not the customer's
  "update-degraded-freshness-issuedat-absent", // the artefact declared NO issuedAt though this engine has accepted one before: an ordinary legacy (freshness-less) descriptor, timestamp-replay protection weaker for it, and nothing to fix at the customer's end
  "update-degraded-freshness-sequence-absent", // the artefact declared NO sequence though this engine has accepted one before: the legacy twin of the row above
  "update-degraded-riskclass-coerced", // the artefact's declared risk class was unusable and was coerced to a default: an update that should have demanded dual control may not have
  "update-degraded-components-map-malformed", // the channel's components map would not parse: the engine falls back to the legacy single-artefact path and the CONSOLE half of the update never ships ("the console update never shows up")
  "update-degraded-component-entry-dropped", // ONE component entry in an otherwise-valid map was dropped (an unknown component kind, or a malformed entry): that component silently never updates
  "update-degraded-components-unplannable", // the signed RELEASE names a component id this build cannot plan (a well-formed entry, kept and displayed, that no apply/settle/rollback here can act on): that component silently never updates while the release claims to carry it
  "update-degraded-provenance-dropped", // the artefact's provenance block was unusable and was dropped: the update applied WITHOUT the provenance the operator believes is being checked
  "update-degraded-legacy-artefact-fallback", // the engine deployed from the legacy artefacts[] mirror rather than the v2 components entry: it may have shipped a DIFFERENT artefact than the one the channel advertises
  "update-degraded-baseline-read-failed", // the canary BASELINE read failed and was coerced to "pending", which silently DISARMS the ramp's stricter regression guard: "why did the ramp keep a regressed build?"
  "update-degraded-canary-unmeasured", // the settle's canary flight resolved NO destination, so it attempted no probe and MEASURED NOTHING -- and reported "pending", which is what a legitimately slow post-swap flight reports. The update was gated on a flight that never happened
  "update-degraded-dest-fallback-env", // the update gate probed the ENV destination because the customer's console-set default could not be resolved: the gate passed against a destination the customer is not using
  // R5: the FLEET-WIDE key fault, which is not a fact about any stored row. CONFIG_WRAP_KEY is present and is not
  // 32 bytes (an operator pasted the wrong secret), so loadConfigWrapKey throws BEFORE the config plane is read.
  // No destination credential in the ACCOUNT can be opened, and the gate has learnt nothing about whether a
  // console-set default even exists. It used to be filed as "the stored credential would not open" plus
  // "the console-set default could not be resolved" -- two claims about a row nobody had fetched, on the poll path.
  "update-degraded-destgate-wrapkey-malformed",
  // selfCheckOk was ONE boolean over two OPPOSITE diagnoses: the wrong build is live (roll back) versus the
  // engine could not PROVE what is live (do not touch it). Splitting the cause is the whole point.
  //
  // A third member, "update-degraded-selfcheck-throw" ("the DO plane is down"), was DELETED (R4). It had NO
  // REACHABLE PRODUCER -- its only writer was a catch around runPreflight, which cannot throw by construction --
  // and it asserted a fact the code never established: with every scheduler fetch rejecting, the real gate emits
  // -preflight, because a preflight that proved nothing is exactly what that member says. See update-gate.ts.
  "update-degraded-selfcheck-version-mismatch", // the self-check ran and the LIVE version is not the one just applied: the wrong build is serving
  "update-degraded-selfcheck-preflight", // the self-check's preflight could not complete (including a DO plane that will not answer): the engine could not prove what is live, which is NOT the same as proving the wrong thing is
  // The destination gate's read failure was ONE counter called "decrypt-failed" over three causes with three
  // OPPOSITE remedies -- and it asserted a decrypt failure in two cases where no decryption had been attempted.
  // The discriminator was already on the thrown error (a closed, tagged cause) and was being discarded.
  "update-degraded-destgate-decrypt-failed", // the stored destination credential would not OPEN: an absent, rotated or malformed CONFIG_WRAP_KEY. Re-wrap the credential or restore the key. This, and only this, is a decrypt failure
  "update-degraded-destgate-config-plane-unreadable", // the scheduler DO would not answer the destination-config read: the destination may be perfectly healthy and the CONFIG PLANE is what is down. Wait; change nothing
  "update-degraded-destgate-config-incomplete", // the STORED destination config is missing a required field: the customer re-enters it. Neither the key nor the DO is at fault
  "update-degraded-destgate-unclassified-error", // the destination gate failed for a cause it could not classify: the residual, kept so an unclassified gate failure is still a visible fact
] as const;

/** The closed self-check cause: the two states one boolean used to erase. Both have a real producer in makeHealthGate.selfCheck. */
export const SELF_CHECK_CAUSES = ["version-mismatch", "preflight"] as const;
export type SelfCheckCause = (typeof SELF_CHECK_CAUSES)[number];

/**
 * selfCheckDegradationCounter composes the closed counter name for ONE failed update self-check.
 *
 * @param cause - the closed cause the self-check failed for.
 * @returns the closed counter name.
 */
export function selfCheckDegradationCounter(cause: SelfCheckCause): string {
  return `update-degraded-selfcheck-${cause}`;
}

// ---- THE CONTROLS SUPPORT COULD NOT PROVE WERE IN FORCE -------------------------------------
//
// Two counters, two tickets that were unanswerable from the pack, and both are POSTURE in the exact sense this
// group is about: the customer believes something is happening (a new member is being emailed their set-up
// link; every human action is attributed to a source IP) and it is not, and nothing anywhere said so.
export const GRANT_POSTURE_COUNTER_NAMES = [
  // G340: a role grant MINTED a registration invite (so the granted person has no passkey and CANNOT sign in
  // without the link), THE ENGINE HAS AN INVITE SENDER CONFIGURED, and the send still did not land. The grant
  // COMMITTED: they have authority they cannot use, and the only remaining path is the Owner copying the link
  // out of the modal by hand.
  //
  // BOTH conditions are required, and the second one is why this counter is readable at all. It
  // used to bump whenever a minted invite was not sent, which is TRUE OF EVERY GRANT in an org that deliberately
  // configures no invite sender and hands links over out of band -- a legitimate posture the gap itself names. A
  // fault-named counter climbed for ever on a healthy engine, in the one section whose contract is that any
  // non-zero value means something silently went wrong.
  //
  // Pair it with status.inviteSenderConfigured (the same predicate, one definition, router-sources.ts) to read
  // the posture off the pack: FALSE with a zero counter is an org that never set an invite sender up and is not
  // broken; TRUE with a non-zero counter is a sender that is configured and refusing, and the closed auth signal
  // (role-invite-email-from-invalid / -recipient-invalid / -send-rejected) names which refusal it was.
  "role-grant-invite-undeliverable",
  // G346: an audit entry was appended for an ATTRIBUTED HUMAN actor (the engine identified a subject or an
  // email) with NO source IP captured, AT THE MOMENT THE ROW IS WRITTEN. The console labels such rows honestly
  // ("not recorded") and the pack's audit excerpt strips sourceIp from every event by design, so the customer's
  // "why do some of our audit rows have no source IP?" could not be answered from the pack at all: a capture path
  // that is STILL failing (a proxy stripping the header, a path that never threaded it) and one that was fixed
  // long ago are the same silence. It counts only what this engine appends from here on -- it does not count, and
  // cannot count, the rows already on the chain -- so a NON-ZERO count is a capture failure that is happening
  // now, and lastAt says when it last did. The historical population is read off the audit rows themselves. The
  // IP itself still never rides: this counter exists precisely so that it never has to.
  //
  // THE GOVERNED REPLAY IS NOT A CAPTURE FAULT. Approving a change or an owner action REPLAYS
  // the proposer's mutation as the proposer, and the replay caller carried no source IP, so the replayed row was
  // attributed + human + sourceIp null: this counter's exact shape. Every approved change under dual control
  // climbed a fault counter on a healthy engine, and it did so only at the customers who had turned the gate ON.
  // The engine HAD the address (the propose request carried it, and its own propose row records it), so the fix
  // is to carry it: PendingConfigChange.proposedBySourceIp / PendingOwnerAction.proposedBySourceIp, threaded onto
  // the replay caller. A deliberate drop of a captured address must never be read as a failure to capture it.
  //
  // ATTRIBUTED is load-bearing. Gated on the actor METHOD alone, this counted every FAILED
  // PASSKEY LOGIN: that audit draft carries actorMethod "passkey" with a null subject, a null email and a
  // hard-coded null sourceIp, because "passkey" there names the MECHANISM and there is no person and no session
  // to take an IP from. So a healthy engine with three fumbled logins this week produced {count:3, lastAt:now},
  // BYTE-IDENTICAL to the ongoing-capture-failure row this counter exists to tell apart, and every cancelled
  // WebAuthn prompt kept lastAt recent for ever. The question is asked about rows that NAME A PERSON, and that
  // is now the only population counted.
  "audit-human-event-missing-source-ip",
] as const;

// ---- the whole posture family, in the order it is spread into ADMIN_COUNTER_NAMES ------------------------
//
// G312's six names are NOT here: they already exist in ADMIN_COUNTER_NAMES (the vocabulary landed in an
// earlier wave with no caller at all, which is the "dead evidence" this campaign keeps finding). This pass
// wires their recorders; the names stay where they are.
export const POSTURE_COUNTER_NAMES = [...CLAIM_DROP_COUNTER_NAMES, ...ALERT_EMISSION_COUNTER_NAMES, ...UPDATE_REFUSAL_COUNTER_NAMES, ...UPDATE_DEGRADATION_COUNTER_NAMES, ...GRANT_POSTURE_COUNTER_NAMES] as const;
