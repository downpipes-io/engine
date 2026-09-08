// client-diag-vocab.ts -- the FROZEN closed vocabulary for the console-diagnostics support-pack section
// (Wave C, plan CONSOLE-DIAGNOSTICS-IN-PACK-PLAN.md §3a, review §5). This is the CANONICAL source of the
// closed unions; the console and the diagnosis bot MIRROR these exact lists in their own repos and a
// conformance/drift test asserts they match (the AUTO_HEAL_REFUSAL_CODES pattern), because console/engine
// are separate repos.
//
// INVARIANT I2 (STRUCTURALLY VALUE-FREE): the client-diagnostics record has ZERO free-string fields. Every
// string field is a member of one of the closed unions below, checked by SET MEMBERSHIP against the frozen
// allowlist; every numeric goes through a clamp. A smuggled customer value cannot be a set member and is
// therefore structurally dropped by the receiver (client-diag-receive.ts). Every member here is a PRODUCT
// CONSTANT, provably value-free: none is derived from a URL, path, header, error message/name/code/stack,
// field name, email, label or any customer/server text.

// kind -- what fired (14). A closed product classifier, never error text.
export const CLIENT_DIAG_KINDS = [
  "engine-call", // a fetch to the engine API failed
  "contract-drift", // a 2xx body did not match the expected shape
  "bulk-outcome", // a bulk action reported partial/failed results
  "boot-fault", // app-root error boundary / failed initial render
  "unhandled", // window unhandledrejection / onerror (non-Abort)
  "deep-link-lost", // a deep link resolved to no screen
  // apply-outcome -- how a LIVE RESTORE APPLY ended, recorded by the console on every ending. Its own
  // kind so it cannot coalesce with the restore screen's other traffic; applyClass is the discriminator and
  // count is how many applies ended that way, which lines the client's attempts up against this engine's own
  // restore-apply audit events (an attempt with no matching audit event never arrived).
  "apply-outcome",
  // fanout-degraded -- a console bulk protect went ahead against the DEFAULT destination only, because
  // the destination list could not be read, so the operator's intended replicas were never created. The row's
  // existence is the discriminator: a deliberate choice of the default produces no row.
  "fanout-degraded",
  // capability-fault -- a BROWSER CAPABILITY the console asked for and did not get, at a named point in
  // the key or recovery ceremony. Its own kind, never `unhandled`: `unhandled` means a console DEFECT that
  // reached no catch site, and a browser that declines a download is not a defect, so folding one into the
  // other both inflates the defect counter and destroys the evidence (a row reading unhandled/other on the
  // keys screen cannot say a download was refused, and cannot say which file). The discriminators are
  // `capability` (what the browser would not do) and `surface` (which ceremony asked), and `capabilityOutcome`
  // separates a capability that is ABSENT in this host, which is a legitimate configuration, from one that is
  // present and REFUSED.
  "capability-fault",
  // console-build-check -- WHAT BUILD THE BROWSER IS ACTUALLY BEING SERVED. This engine cannot probe a
  // console behind Cloudflare Access, so its own update record says the console component applied and nothing in
  // the pack can contradict it: a CDN still serving the old assets, an asset deploy that never landed, or an
  // Access page in front of /__build.json all leave the applied verdict standing with no evidence the new build ever
  // reached anyone. The operator's browser is the only witness, and buildCheckClass is what it saw.
  "console-build-check",
  // console-rollback -- the operator pressed the post-apply console rollback. Its existence IS the fact
  // that a rollback was attempted; rollbackClass is how it ended, in THIS engine's own outcome vocabulary. The
  // member that earns it its own kind is `not-sent`: a rollback POST that never arrived leaves no engine-side
  // rollback record at all, so a rollback that double-failed after a failed apply is otherwise invisible.
  "console-rollback",
  // identity-unresolved -- the console's caller-identity read did not resolve, so every client-side
  // capability gate fell back to the least-privileged `viewer`. Its own kind because an engine-call row cannot
  // answer the ticket (an actual Owner reports every control greyed out): the screens that go grey make many
  // other calls, so a 5xx row on the security screen does not say WHICH call failed. This row says the identity
  // report was ABSENT rather than LOW. A 401 is never recorded (a lapsed session is the ordinary state).
  "identity-unresolved",
  // restore-gate-blocked -- the console did not offer Apply on a restore plan, and gateBlockClass is why.
  // The four preconditions of the client apply gate were indistinguishable, so the report that an approver signed
  // and Apply stayed greyed out was unfalsifiable. The legitimate state, a plan genuinely awaiting its approver,
  // is deliberately NOT a member and is never recorded.
  "restore-gate-blocked",
  // wire-anomaly -- a value THIS ENGINE served that the console could not use: it did not parse, it was
  // not finite, it was negative where only a count is meaningful, or it was absent where the screen needs it.
  // Every such site in the console silently coerces (a timestamp to 0, a count to 0) or dies mid-render, and the
  // pack's own copy of the same row is clamped by the pack builder, so the pack can read CLEAN while the
  // console-visible copy was corrupt. fieldClass and anomaly are the discriminators; the value never travels.
  "wire-anomaly",
  // transport-fault -- how the console's transport to THIS ENGINE failed, in the console's own
  // already-computed classification. The engine cannot see any of it: for access-redirect (an Access login page
  // interposed), html-not-engine (the browser is pointed at some other address entirely) and origin-rejected (a
  // CORS block, where the engine's response WAS made and the browser then discarded it), the request either
  // never arrived or the answer never got back, so no engine-side record of these exists or could exist. This
  // is the one kind whose whole value is that it is client-asserted.
  "transport-fault",
  // read-degraded -- a fire-and-forget console read that failed and was swallowed into a degraded
  // chip or a fail-open gate. callClass names WHICH read went quiet. It lets the pack line the browser's view
  // up against the engine's: a browser that saw the control-plane status 404 a dozen times is a different
  // incident from an engine that logged no inbound request at all, and only the pair says which.
  //
  // (No quoted phrases in this block, deliberately: the console's conformance test parses the members out of
  // this array by matching double-quoted strings, so a quotation inside a comment here would be read as a
  // twentieth kind and fail the drift guard. It did, on the first pass.)
  "read-degraded",
  // onboarding-step -- how one step of the setup wizard ended. The wizard is the flow with the least
  // engine-side evidence: a connect-time transport failure never reaches this engine, the readiness poll is a
  // client-side timer this engine knows nothing about, and a completion acknowledgement that did not land is,
  // from here, indistinguishable from a wizard nobody ever ran.
  "onboarding-step",
  // discovery-connect -- what the account-discovery token actually SAW in the browser. The console half
  // of the gap: it separates a token that was accepted and then saw zero accounts, an account whose product
  // listings were refused for want of scope, and an account that is genuinely empty. The refusal FAIL CLASS is
  // deliberately not a client-asserted field: it belongs to this engine's own discovery state, which knows it.
  "discovery-connect",
  // claim-exchange -- the licence claim-code exchange with the VENDOR control plane. It does not touch
  // this engine at all (it is a direct browser POST to the control-plane host), so this engine has no view of
  // it whatsoever, and until now neither did the pack.
  "claim-exchange",
  // admin-write -- a PRIVILEGED CONSOLE WRITE and how it ended. This engine AUDITS THE
  // WRITES IT ACCEPTS, so a write it REFUSED leaves it no audit event, no config event and no trace of any kind:
  // the refusal was a toast the operator dismissed. The pack then shows dual control off, the departed employee
  // still holding a role, the binding unattached and the known-bad version still live, with nothing anywhere
  // saying anyone ever tried to change any of it. adminOp says WHICH privileged write (no screen id can: one
  // route serves both an attach and a detach) and writeOutcome how it ended. `unreachable` is the member this
  // engine can never hold itself: it means the request never arrived.
  "admin-write",
  // recovery-refusal -- a manual disaster-recovery refusal: a control-plane reconcile, an estate
  // import or a signed-export download that did not go through. These run when this engine is FRESH OR WIPED
  // and its audit ring is empty, and several of the codes (an export that would not parse, a field left blank)
  // are decided in the browser and never reach it at all. recoveryCode is the frozen DP-R token the console
  // already shows the operator, so the code quoted down the phone and the code in the pack are one token.
  "recovery-refusal",
  // identity-stale-gate -- a capability-gated screen RENDERED WHILE THE CALLER IDENTITY WAS UNRESOLVED, so
  // every gate on that render was computed from the `viewer` default rather than from the identity report. The
  // console's whoami read SUCCEEDED; it simply had not returned yet, and nothing re-renders the screen when it
  // lands. An actual Owner deep-linking to /security therefore sees every control greyed "owner only" and the pack
  // was byte-identical to a genuine viewer's. The row says the gates were computed blind and says NOTHING about
  // the role that came back: a role is a customer value and has no field here.
  "identity-stale-gate",
  // update-channel-unverified -- this engine consulted the update channel and answered the console
  // verified:false. status.updateChannelConfigured is Boolean(env.UPDATE_CHANNEL_URL && env.UPDATE_SIGNER_PUBLIC),
  // an env-var presence check that stays true while the signature has been failing for a month, so it is not a
  // verdict. channelReasonClass is, and the console SELECTS it from the reason text and never carries it.
  "update-channel-unverified",
  // intent-dropped -- the console BUILT A REQUEST that silently DISCARDED something the operator typed.
  // The restore request builder drops a half-filled option on the floor: a Max records that did not parse, a
  // cf-config or media edit token with no account id beside it, a D1 database with no tables, a redirect target
  // with an empty binding. The engine NEVER SEES the dropped intent, so no engine-side record of it exists or
  // could exist: the plan it answers is the plan for the request it was actually sent, and it is correct about
  // it. `intentClass` says WHICH option was discarded, and it is the whole row: the typed value is a Cloudflare
  // edit token or an account id and there is no field on the record for one.
  "intent-dropped",
  // probe-outcome -- an OPERATOR-INITIATED TEST and how it ended. These are the richest per-surface
  // diagnostics in the product (a destination verify, an IdP connection test, a notify or SIEM test send, an
  // email test), and they are computed, rendered once and stored NOWHERE, so an intermittent failure and a
  // vendor that has since been fixed are both unreconstructable. probeSurface says which test and probeOutcome
  // how it ended, and BOTH are needed: a red cert check on an IdP test and a 403 from a SIEM endpoint are not
  // the same ticket. `ok` is a member, deliberately: it fails every morning and works on retry is a claim
  // about the RATIO of good runs to bad, and a ring that recorded only the failures could not answer it.
  "probe-outcome",
  // form-rejected -- the console's OWN client-side validator turned an operator away, or quietly
  // replaced what they typed. No request is made, so the engine sees NOTHING: a customer blocked at setup for a
  // week, or one whose contracted rate was silently swapped for the vendor preset, produces zero remote
  // evidence, and a console validator that has drifted TIGHTER than the field catalogue is undetectable in the
  // field. formField is the catalogue control id (a closed product vocabulary, never the typed value: these
  // fields hold endpoints, ARNs, account ids and rates) and rejectOutcome separates a REFUSAL the operator can
  // see from a COERCION they cannot.
  "form-rejected",
  // catalogue-degraded -- the console did not OFFER Cloudflare configuration, or offered it against a
  // catalogue it could not trust, and catalogueClass is why. The console's own hint text is the only place any
  // of this is said today and it dies with the render. The classes separate the four states the ticket the
  // wizard stopped offering Cloudflare configuration confuses: an under-scoped discovery token, an engine that
  // predates the feature, a source that was never added, and an account the token can read nothing in. Joined
  // to the engine's own discoveryHealth (which knows whether the zone listing was DENIED) the pair resolves the
  // first two, which neither half can do alone.
  "catalogue-degraded",
  // feature-probe -- WHICH DIAGNOSIS THE CONSOLE REACHED about a route it could not read. The console
  // systematically conflates a live 5xx with a route that was never built (the pending-the-engine tile), maps
  // every failure of the config-approvals read to feature-absent, and presents a whoami 500 as a benign
  // degrade, so support cannot tell BROKEN from UNBUILT. featureClass names the route family and featureOutcome
  // the verdict, and the verdict is the point: `origin-rejected` is the console's CONSOLE_ORIGIN diagnosis (the
  // fetch threw with no response AND the unauthenticated health probe answered in the same breath), which the
  // console computes today and then throws away, and `engine-url-unparseable` is a setup wizard that never
  // built a client at all, so every other row in this ring is silent by construction.
  "feature-probe",
  // gov-gate -- a GOVERNANCE GATE the CONSOLE applied, which by construction leaves no engine-side trace.
  // A role-gate refusal greys a control out and makes NO request, so there is no 403 and no audit row anywhere.
  // A change-number prompt SKIPPED because the policy read failed proceeds without a reference, and the engine's
  // own 400 count (configIntegrity.changeControlRefusals) shows the refusal without ever saying the console
  // never asked. govGate is which gate, and adminOp (the same closed op vocabulary the admin-write rows use, so
  // the two join) is which action it fell on.
  "gov-gate",
  // console-skew -- WHICH CONSOLE BUILD IS ACTUALLY RUNNING, expressed as its RELATION to the engine that
  // is answering it. The pack carries engine.version and has never carried anything at all about the browser's
  // build, so a skewed pair (a dead Approve button, a feature that is silently off, an origin still serving the
  // old assets) is indistinguishable from a defect. The row is a CLASS, not a version string, and that is not a
  // redaction compromise but the better evidence: the version alone would still need the engine's to be read
  // against, and this row IS that comparison, made in the one place that can see both.
  "console-skew",
  // material-rejected -- operator KEY or CEREMONY material the console REFUSED. Every one of these
  // refusals is decided in the BROWSER and no request is made, so this engine holds no record of it and could
  // not: a pasted recovery share that will not decode, and a stored ceremony result the console read back and
  // threw away (so it asks the operator to run the whole key ceremony again), never reach this engine at all.
  // materialClass is why it refused. Nothing about the material rides: not the text, not the offending
  // character, not its position, and deliberately not a length (a length is a fingerprint of the secret).
  "material-rejected",
  // contract-skew -- the console was handed data it could not interpret and rendered something
  // plausible anyway: an unknown IdP preset became a generic globe, a `roles` field that was not an array was
  // counted as 0 role grants in a signed snapshot, a missing `connections` array turned three live IdP
  // connections into three empty add-a-provider tiles, an unknown change kind rendered an Approve button this engine will
  // always refuse. THIS ENGINE IS THE OTHER HALF OF EVERY ONE OF THOSE ROWS: joined to engine.version in
  // section 3, a contract-skew row pins the drift to a deploy, which neither half can do alone.
  "contract-skew",
  // fleet-drill -- one fleet-drill SESSION, as the console assembled it. This engine records every drill
  // it HANDLED (per downpipe, §4.3), so the per-pipe outcomes are already here. What it cannot see is the shape
  // of the session: how many pipes the console targeted, how many it silently could not target at all (a latest
  // history row with no runId is dropped from the target list without a word), whether the loop finished or a
  // 401 cut it short at pipe 9, and whether it exhausted its capped 429 retries. An aborted sweep and a
  // deliberate partial drill leave this engine the IDENTICAL evidence.
  "fleet-drill",
  // The POSTURE round, group 3 (the console's G300/G301/G304/G308/G310/G328 rows). Each is a browser-side fact the
  // engine cannot hold: a dual-control refusal the console decided (or that the engine refused and only the
  // console can attribute), the grants a custom-role delete silently downgraded, a resource the browser's own CSP
  // blocked, part of a paste the console dropped before any request was made, a wizard hand-off that lost the
  // operator's pick between steps, and a key-ceremony step that ran entirely in the browser. Admitted here or the
  // rows are DROPPED on arrival and the browser evidence silently vanishes from the pack.
  "owner-action-refusal",
  "role-delete-impact",
  "csp-violation",
  "input-dropped",
  "handoff-dropped",
  "ceremony-step",
  // The POSTURE round, group 4. Both are BROWSER-ENVIRONMENT facts that no engine can ever
  // observe: a store the browser refused to keep anything in, and which renderer the topology map actually got.
  // Admitted here or the rows are DROPPED on arrival and the browser evidence silently vanishes from the pack.
  // storage-blocked -- the BROWSER REFUSED to keep something the console asked it to keep. On a
  // locked-down enterprise profile localStorage and sessionStorage throw on access, and every call site in the
  // console swallows that throw by design (a preference that will not persist must never break a flow). The
  // result is a console that loses half-filled wizards, forgets which engine it is pointed at, and re-enables
  // auto-refresh over a motion-sensitivity pause, with NOTHING anywhere admitting the browser is the cause. It
  // is a kind of its own because it is not an engine call, not a console defect and not a capability the
  // customer pressed a button for: it is an environment fact, and the fix is a browser-policy fix.
  //
  // The discriminators are `storageArea` (which store), `storageClass` (WHY: denied by policy, out of quota, or
  // absent from the host) and `storageSurface` (WHAT the customer lost), and all three are in the coalescing
  // tuple. Without them a blocked localStorage and a full sessionStorage would be one row, and a lost draft and
  // a forgotten engine URL would be one row: three tickets with three different answers, told apart by nothing.
  // The stored VALUE is never read: the key is not recorded either (a draft id can carry a run id).
  "storage-blocked",
  // renderer-degraded -- WHICH RENDERER WAS ACTUALLY LIVE on the topology map, and why it was not the
  // full one. The map is frozen / is a static diagram for one user is a browser-policy ticket (a blocked
  // canvas, an extension freezing requestAnimationFrame) whose only evidence today is a Copy-view-diagnostics
  // block that reaches support ONLY if the customer manually pastes it.
  //
  // It is a STATE row, not a fault row, and `none` is a member on purpose: the pack must be able to say the
  // renderer WAS live, or the map is frozen and the customer never opened the map are the same evidence.
  // For the same reason `reduced-motion` is a member and is not counted as a browser fault: a static frame the
  // operator ASKED for is a legitimate state, and telling it apart from a canvas the browser refused is the
  // whole point (one is an accessibility preference, the other is a policy the customer must change).
  //
  // WebGL is deliberately NOT a cause. The console's live view is canvas2d; it never asks for a WebGL context,
  // so a browser without WebGL renders the full live map, and a webgl-blocked row would fire on a perfectly
  // healthy session. That is exactly the wolf-cry this vocabulary refuses.
  "renderer-degraded",
  // focus-landing -- WHERE KEYBOARD FOCUS ACTUALLY LANDED after a navigation whose activating control
  // was itself the navigation. This is the FIRST member of this vocabulary that can see the accessibility
  // surface at all, and it exists because two passes measured the same zero: a search of every member of every
  // union here for keyboard / a11y / accessib / tablist / roving / focus returned NOTHING, so a keyboard user
  // who could not arrow past the first tab produced a pack byte-identical to a healthy one.
  //
  // The shell moves focus to <main> after every real navigation, which is right for an ordinary route change
  // and wrong for a tablist whose sections each own a route (the Keys sections, the Notifications areas):
  // there the arrow key IS the navigation, so the shell's move takes focus off the tab the operator just
  // selected and every further arrow does nothing. A screen therefore DECLARES where focus belongs and the
  // shell honours it, and the declaration is ignored unless the named element is connected when the shell
  // reads it, so a stale intent can never park focus on a detached node.
  //
  // THE CONSOLE ALREADY COMPUTED THAT DISCRIMINATION AND THREW IT AWAY: its reader collapsed no intent was
  // declared and the declared element was not mounted into one null, and the second of those two IS the
  // defect. focusOutcome is that fact, kept. It is a STATE row on the tablist population rather than a fault
  // row, for the same reason `none` is a member of degradeCause: without an honoured row the pack cannot say
  // the mechanism was working, and a tablist that is broken and a tablist the customer never touched carry
  // identical evidence.
  //
  // VALUE-FREE like every kind above: the row is three product constants (the kind, the closed
  // focusOutcome, and the compile-time `screen` literal) and two clamped integers. No element, id, label,
  // accessible name, selector or key is recorded, so the row cannot carry anything the operator typed.
  "focus-landing",
] as const;
export type ClientDiagKind = (typeof CLIENT_DIAG_KINDS)[number];

// screen -- the route TEMPLATE id, sourced from console src/screens/** (I3: a compile-time literal attached
// at the emit site, NEVER read from location/history/router-params at runtime). `boot` is the pre-router
// crash sentinel; `unknown-route` is the total-mapper fallback that never echoes location/pathname/search.
export const CLIENT_DIAG_SCREENS = [
  "overview",
  "destinations",
  "sources",
  "downpipes",
  "restore",
  "access",
  "idp",
  "notifications",
  "integrations",
  "keys",
  "security",
  // config-changes / owner-actions -- the two APPROVAL INBOXES, prised out of the `security` bucket the
  // console's route table used to drop them both into. A render throw inside a .then with no .catch is nearly
  // always a TypeError, so the config-approvals screen frozen on skeleton rows and the owner-approvals screen
  // frozen on skeleton rows produced the byte-identical tuple and coalesced into ONE row. Splitting the two names both
  // screens and lets support tell them apart.
  "config-changes",
  "owner-actions",
  "updates",
  "support",
  "settings",
  "boot", // pre-router crash sentinel
  "unknown-route", // total-function fallback; never echoes location
] as const;
export type ClientDiagScreen = (typeof CLIENT_DIAG_SCREENS)[number];

// httpClass -- engine-call only (5). `aborted` is recorded but EXCLUDED from the console-engine-calls-failing
// signal (a navigation-cancelled/unmount fetch is not a Downpipes fault).
export const CLIENT_DIAG_HTTP_CLASSES = ["4xx", "5xx", "network", "timeout", "aborted"] as const;
export type ClientDiagHttpClass = (typeof CLIENT_DIAG_HTTP_CLASSES)[number];

// faultClass -- a total pure mapper's output (7). The single `other` bucket NEVER touches error text (it is a
// mapped fallback, not a stringified message/name/code/stack).
export const CLIENT_DIAG_FAULT_CLASSES = ["auth", "not-found", "conflict", "rate-limited", "server", "transport", "other"] as const;
export type ClientDiagFaultClass = (typeof CLIENT_DIAG_FAULT_CLASSES)[number];

// driftClass -- class ONLY, never the offending value or the field name (4). `unknown-enum`/`missing-field`
// carry the CLASS the value/field-name stood in for, never the value/field-name itself.
export const CLIENT_DIAG_DRIFT_CLASSES = ["unknown-enum", "malformed-body", "missing-field", "version-skew"] as const;
export type ClientDiagDriftClass = (typeof CLIENT_DIAG_DRIFT_CLASSES)[number];

// reasonClass -- bulk-outcome only (5).
// selection-dropped is not a failure of the batch, it is a failure of its INPUT: rows the operator had
// selected VANISHED from under them on a background refresh, and the loop ran over the survivors. Every count
// the console then reports is self-consistent (17 attempted, 17 done) and this engine sees 17 perfectly good
// requests. I selected 20 downpipes and only 17 were acted on cannot be answered from this side at all.
export const CLIENT_DIAG_REASON_CLASSES = ["partial", "all-failed", "validation", "auth", "server", "selection-dropped"] as const;
export type ClientDiagReasonClass = (typeof CLIENT_DIAG_REASON_CLASSES)[number];

// applyClass -- apply-outcome only (6). How much a live restore apply actually WROTE, which is the question
// the customer's ticket asks. `wrote-none` is the one that matters most: the engine answered an apply result,
// reported NO failures, and wrote NO records, so success was reported and nothing moved. It was previously
// indistinguishable from a clean full apply and from an apply that never ran, because all three recorded
// nothing at all. `not-sent` is an apply POST that never came back, so the count of client attempts can be
// reconciled with the restore-apply audit events this engine wrote. A class, never a record count and never a
// record name: the counts belong to the signed audit event and the names are customer data.
export const CLIENT_DIAG_APPLY_CLASSES = ["wrote-all", "wrote-some", "wrote-none", "wrote-none-all-failed", "unknown-shape", "not-sent"] as const;
export type ClientDiagApplyClass = (typeof CLIENT_DIAG_APPLY_CLASSES)[number];

// capability -- capability-fault only (4). WHAT the browser would not do. A closed product classifier, chosen
// by the CALL SITE, never parsed out of an error: the console's reporter takes no error argument at all.
//
//   blob-download    a Blob + object URL + <a download> click the browser refused. The delivery path for
//                    identity.key, the recipient/signer files, the recovery sheet, the custody shares and the
//                    recovery codes: everything the customer must keep.
//   tab-open         a blob-URL tab the browser refused (the printable recovery sheet opens this way).
//   clipboard        navigator.clipboard.writeText refused, or the API is not there at all.
//   webcrypto-keygen the in-browser key ceremony itself could not generate a key pair. A locked-down browser
//                    with no usable WebCrypto produces NO key material, so there is nothing to save and no
//                    backup can ever be recovered.
export const CLIENT_DIAG_CAPABILITIES = ["blob-download", "tab-open", "clipboard", "webcrypto-keygen"] as const;
export type ClientDiagCapability = (typeof CLIENT_DIAG_CAPABILITIES)[number];

// surface -- capability-fault only (5). WHICH CEREMONY asked for the capability, and therefore WHAT the
// customer has lost. This is the field that makes the row actionable: a refused blob-download on the keys
// screen is a different ticket depending on whether it was the first key ceremony (there is no identity.key
// anywhere and the operator can re-run the ceremony), a break-glass rotation (the old key still works), or the
// one-time recovery codes (they are gone, and the operator is one lost passkey from being locked out). A
// route id cannot answer that, because several surfaces share one route. It is a compile-time literal at the
// call site, never a file name, a label or any customer text.
export const CLIENT_DIAG_SURFACES = ["key-ceremony", "break-glass-rotation", "add-operational-key", "recovery-codes", "recovery-sheet", "integrations-copy", "map-diagnostics", "restore-receipt"] as const;
export type ClientDiagSurface = (typeof CLIENT_DIAG_SURFACES)[number];

// capabilityOutcome -- capability-fault only (2). WHY the console did not get the capability.
//
//   refused     the capability is present in this host and the browser DECLINED the use of it (a download
//               policy, a permissions policy, a lost user gesture, a keygen that threw). A fault.
//   unavailable the capability is NOT PRESENT in this host at all: navigator.clipboard is absent on a
//               plain-http self-host, and WebCrypto is absent outside a secure context. That is a LEGITIMATE
//               configuration, not a defect, and the customer's fix is a different one (serve the console over
//               HTTPS, or use the control that does not need the capability). It is recorded because the
//               operator still did not get what they pressed for, and it is kept SEPARATE because counting it
//               as a refusal would report a working browser as a broken one.
export const CLIENT_DIAG_CAPABILITY_OUTCOMES = ["refused", "unavailable"] as const;
export type ClientDiagCapabilityOutcome = (typeof CLIENT_DIAG_CAPABILITY_OUTCOMES)[number];

// bootClass -- boot-fault only (2). WHICH bring-up step failed, for the two failures that are otherwise
// totally silent: a lazy-chunk preload the console's update flow swallows by design (so the asset swap then
// renames chunks under a running session and it breaks mid-update), and a navigation bridge that was never
// installed (its defaults are no-ops, so every click is swallowed whole and nothing is thrown to catch).
export const CLIENT_DIAG_BOOT_CLASSES = ["chunk-preload-failed", "nav-bridge-uninstalled"] as const;
export type ClientDiagBootClass = (typeof CLIENT_DIAG_BOOT_CLASSES)[number];

// buildCheckClass -- console-build-check only (5). What the ORIGIN was serving when the console asked it
// what build it serves. `confirmed` is recorded too, so its ABSENCE after an applied console update means
// something; `wrong-version` is an origin still serving the old assets; `non-json` is something else answering
// on the console's own origin (an Access page reads exactly like this); `unstamped` is a bundle carrying no
// version at all, which blinds the console's update verdict so it can read up to date releases behind.
// `unstamped` is THE ORIGIN answering valid JSON with no usable version; `running-unstamped` is THE RUNNING
// BUNDLE in the operator's tab carrying no baked version define. Two facts about two different artefacts, which
// used to be one member and therefore one coalesced row: support could not tell the update verdict was computed
// blind and no apply ever happened from an apply landed assets with no stamp. Different remedies.
export const CLIENT_DIAG_BUILD_CHECK_CLASSES = ["confirmed", "wrong-version", "unreachable", "non-json", "unstamped", "running-unstamped"] as const;
export type ClientDiagBuildCheckClass = (typeof CLIENT_DIAG_BUILD_CHECK_CLASSES)[number];

// rollbackClass -- console-rollback only (6). The first five ARE this engine's own
// StandaloneRollbackResult.outcome vocabulary, so the client row and the engine's rollback record speak one
// language and line up. `not-sent` is the sixth, and the only one the engine cannot have a record of.
export const CLIENT_DIAG_ROLLBACK_CLASSES = ["reverted", "reverted-unverified", "already", "no-target", "failed", "dry-run", "not-sent"] as const;
export type ClientDiagRollbackClass = (typeof CLIENT_DIAG_ROLLBACK_CLASSES)[number];

// gateBlockClass -- restore-gate-blocked only (4). WHY the console kept Apply disabled on a plan whose
// approval the operator believes is in place. `plan-hash-mismatch` is the one that answers the ticket: an
// approval for this run EXISTS and is approved, and its planHash is not the one the console computed, so the
// console passes over a record the operator can see in their own approvals inbox. The approvals themselves ride
// in the pack, so support can now join the two: the approval is there, and this says why it was not used.
export const CLIENT_DIAG_GATE_BLOCK_CLASSES = ["plan-hash-failed", "no-caller-identity", "plan-hash-mismatch", "self-approval"] as const;
export type ClientDiagGateBlockClass = (typeof CLIENT_DIAG_GATE_BLOCK_CLASSES)[number];

// fieldClass -- wire-anomaly only (6). WHICH CLASS of engine-supplied field was unusable. A class, never
// the field's name and never its value: a malformed URL or id can embed customer data, and the whole point of
// the row is that the value is not to be trusted.
// G298 adds the four families the console COARSENS rather than crashes on, each of which rendered a
// plausible-looking verdict from a value it could not read: an unrecognised whoami method was presented as the
// break-glass TOKEN FALLBACK posture (a false claim that the customer's security posture is degraded), an
// unknown downpipe status became unknown on the map, an unparseable last-run instant skipped the staleness
// test entirely (a month-old pipe read FRESH), and a non-finite byte figure became a 0.
export const CLIENT_DIAG_FIELD_CLASSES = [
  "timestamp",
  "count",
  "seal-at",
  "stored-url",
  "b64url-id",
  "run-id-missing",
  "auth-method",
  "status-enum",
  "source-kind",
  "bytes",
  "duration",
  // cadence: the downpipe config's cadenceSeconds, read by the ONE console seam (map.ts cadenceSecondsOf)
  // that the map, the downpipes table and the Overview fleet roll-up share. A cadence the console cannot read is
  // nulled, and a null cadence DISABLES THE STALENESS TEST, so the downpipe renders green however old its last
  // good run is. It is the false-SAFETY twin of `timestamp`: one is the stamp that cannot be dated, the other is
  // the yardstick it would have been dated against. `missing` (an engine that does not send the field) and
  // `non-finite` (a field that arrived in a shape the console cannot read) are the two anomalies it takes.
  "cadence",
  // The POSTURE round, group 3. The three protection-statement recency stamps, the licence/estate/artefact
  // malformations and the drill-evidence stamp. Each names a DIFFERENT customer-visible assurance
  // that a corrupt value silently disarms, so each is its own member: as one generic `timestamp` row they coalesce
  // and support cannot say which assurance the customer lost.
  "restore-test-at",
  "integrity-verified-at",
  "restore-proven-at",
  // blackout-minute: the stored blackout WINDOW bound. The console CLAMPS an out-of-range value into
  // 0..1440, so a corrupt bound renders as a plausible end-of-day time and the next save writes the clamped
  // value back, rewriting the customer's own schedule. The field whose coercion EDITS the configuration.
  "blackout-minute",
  "licence-not-after",
  "licence-band",
  "estate-figure",
  "artefact-sha",
  "drill-recorded-at",
] as const;
export type ClientDiagFieldClass = (typeof CLIENT_DIAG_FIELD_CLASSES)[number];

// anomaly -- wire-anomaly only (4). HOW the value was wrong.
// unknown-enum is the fifth: the value arrived, it PARSED, and it is simply not a member of the closed
// set that console build knows. Distinct from `unparseable` (corruption) and `missing` (absence), and the
// distinction is the ticket: an unknown enum member after an engine update is VERSION SKEW against THIS engine,
// and the remedy is to update the console. The unrecognised member itself never rides.
// out-of-range: parsed, finite, not negative, and still outside the range the field is defined over, so
// the console coerced it to the nearest legal value. No other member fits a blackout minute of 3000.
export const CLIENT_DIAG_ANOMALIES = ["unparseable", "non-finite", "negative", "missing", "unknown-enum", "out-of-range"] as const;
export type ClientDiagAnomaly = (typeof CLIENT_DIAG_ANOMALIES)[number];

// errorClass -- unhandled / boot-fault (10). The JS ERROR CLASS of a fault nobody caught, selected by SET
// MEMBERSHIP over this frozen list of platform error constructors: the console compares the thrown value's name
// against the list and sends a member or `other`, so no error text can ride. Without it every uncaught defect in
// the console reduced to one bucket per screen, and a screen frozen on skeleton rows (nearly always a TypeError
// inside a .then with no .catch) could not be told from any other fault on the same screen.
export const CLIENT_DIAG_ERROR_CLASSES = [
  "Error",
  "TypeError",
  "RangeError",
  "ReferenceError",
  "SyntaxError",
  "EvalError",
  "URIError",
  "AggregateError",
  "DOMException",
  "other",
] as const;
export type ClientDiagErrorClass = (typeof CLIENT_DIAG_ERROR_CLASSES)[number];

// faultSource -- unhandled only (2). WHICH CHANNEL the uncaught fault arrived on, which is what tells the
// two customer-visible symptoms apart: an unhandled rejection is the screen that never finishes loading (the
// promise chain ended and the skeleton rows stayed up), a window error is a painted screen whose control died.
export const CLIENT_DIAG_FAULT_SOURCES = ["unhandled-rejection", "window-error"] as const;
export type ClientDiagFaultSource = (typeof CLIENT_DIAG_FAULT_SOURCES)[number];

// transportClass -- transport-fault only (9). The console's own resolved transport
// classification. `origin-rejected` is the load-bearing one: it means the console's fetch threw with no
// response AND the unauthenticated health probe was reachable in the same breath, which is the CORS
// fingerprint and separates set CONSOLE_ORIGIN on the engine from the engine is down. `stored-url-invalid`
// means no engine client was ever constructed, so no call was ever attempted and every other diagnostic in the
// ring is silent by construction. Never the engine URL, the host, a body or a header: closed members only.
//
// engine-binding-absent is the one member that says nothing about THIS ENGINE, and it is the reason it
// matters. On the default single-hostname topology the console worker proxies /admin, /support and /metrics to
// this engine over a service binding. A console redeploy that DROPS that binding used to let those paths fall
// through to the console's static assets, which answered the SPA's index.html at HTTP 200: the console read its
// own shell as engine data, a /metrics scraper read HTML as a healthy scrape, and this engine -- which never
// received one of those requests -- reported itself perfectly healthy in the pack, because it was. A pack showing
// a healthy engine and a customer reporting a dead console are the same pack in this state, and the fault is in
// the console's deploy, not here. The console worker now answers its own 503 with a frozen code and the browser
// records this class.
//
// AND HERE IS THE BOUND ON IT, WHICH IS STATED RATHER THAN PAPERED OVER. A clientDiagnostics
// section rides ONLY on the customer's deliberate Generate action, which POSTs to /admin/support/bundle -- an
// ENGINE surface, reached over the very service binding that is missing. So the console CANNOT BUILD A PACK AT
// ALL while this fault is live: the row is recorded if and only if the pack that would carry it is refused. The
// class is therefore reachable in a pack in exactly one shape, and it is a POST-MORTEM: a browser session that
// OBSERVED the 503s and generated the pack after the binding was restored, in the same tab (the ring is
// in-memory, so a reload ends the observation). Every pack that carries this class was necessarily generated
// with the binding PRESENT, which is why the bot renders it in the past tense and must never send a support
// engineer off to restore a binding whose absence would have stopped the pack existing. This class remains OPEN for
// the live fault: a console that cannot reach this engine cannot report to it either, and the engine-side
// counter the gap originally proposed would be a background beacon, which was ruled out and which
// this topology cannot carry regardless (the engine is reachable only over the service binding and has no public
// hostname). What the live fault DOES get is the console's own 503 on /metrics, which alarms the customer's
// monitoring instead of feeding it HTML at 200.
export const CLIENT_DIAG_TRANSPORT_CLASSES = [
  "access-redirect",
  "html-not-engine",
  "origin-rejected",
  "engine-unreachable",
  "rate-limited",
  "server-error",
  "forbidden",
  "stored-url-invalid",
  "engine-binding-absent",
  // console-origin-fault: the CONSOLE'S OWN worker manufactured a 500, admitted by a frozen header it sets
  // on its own responses. Its dispatch threw, or the BOUND ENGINE service binding's fetch REJECTED (this engine's
  // worker deleted, throwing on boot, or over its resource limits). THIS ENGINE RECEIVED NOTHING, so it is not
  // `server-error` (which asserts this engine saw the call and refused it, and sends support to refusal logs that
  // hold no trace of it), not `engine-unreachable` (something answered: the console) and not
  // `engine-binding-absent` (the binding is present).
  "console-origin-fault",
] as const;
export type ClientDiagTransportClass = (typeof CLIENT_DIAG_TRANSPORT_CLASSES)[number];

// callClass -- read-degraded only (5). WHICH swallowed console read went quiet. The console's screen
// cannot stand in for this: these reads fire from wherever the operator happens to be, so without the class a
// failing control-plane-status read and a failing credentials-count read are one row.
// dest-bucket-list / dest-downpipes-list are the destination form's two ADVISORY reads. Neither
// blocks the form, and that is the problem: a failed account/bucket listing leaves the operator TYPING a
// bucket name into a form that would have offered it, and a failed downpipes read silently disables the
// circular-backup safety check (an archive written into its own source grows without bound). A safety check
// that could not run is not a safety check that passed, and nothing said so.
export const CLIENT_DIAG_CALL_CLASSES = ["status", "setup-state", "control-plane-status", "update-chip", "passkey-logout", "dest-bucket-list", "dest-downpipes-list"] as const;
export type ClientDiagCallClass = (typeof CLIENT_DIAG_CALL_CLASSES)[number];

// obStep / obOutcome -- onboarding-step only (6 and 12). WHICH wizard step and HOW it ended. The steps
// share one route, so the screen cannot say which. `health-ok-status-failing` is the Access signature (the
// unauthenticated probe got through and the authenticated read did not); `poll-exhausted` is a purely
// client-side timer this engine has no view of.
//
// keys-precheck is the configure card's ONE-SHOT "does this engine already hold its keys?" read, taken when the
// wizard is resumed with no in-tab key material. It is NOT an install (nothing is posted, and no key material
// exists), and it had to become its own step: its catch wrote {install, transport-error} unconditionally, with no
// status check at all, so an engine that ANSWERED the probe wrote the row that promises this engine never saw the
// request -- and it coalesced with the genuine install-POST row. When that read fails the wizard tells an operator
// whose engine already holds working keys to go back and generate them again, so the step earns its own evidence.
export const CLIENT_DIAG_ONBOARDING_STEPS = ["connect", "generate", "install", "keys-precheck", "readiness-poll", "finish"] as const;
export type ClientDiagOnboardingStep = (typeof CLIENT_DIAG_ONBOARDING_STEPS)[number];
export const CLIENT_DIAG_ONBOARDING_OUTCOMES = [
  "ok",
  "engine-not-ok",
  "transport-error",
  "health-ok-status-failing",
  "unauthorised",
  "access-verdict-unresolved",
  "poll-exhausted",
  // THE FOUR FAILED-POLL MEMBERS BELOW ARE THE PRODUCT OF TWO QUESTIONS: did the poll EVER read this engine, and
  // did its FINAL tick fail because this engine REFUSED the read or because it could not be REACHED? The second
  // question is the one the console never used to ask, and the omission put a FALSE CLAIM in the pack rather than
  // a vague one: `readiness-unread` and `poll-went-quiet` both assert, in their own definitions and in the bot's
  // rendering of them ("fix the engine's reachability first"), that this engine did not answer. An engine that
  // answered a 500 forty times is reachable and holds forty refusals in its own logs, and the pack was sending
  // support away from them. A member whose meaning asserts a fact may only be written where the code established
  // that fact, so the console now classifies the poll's every failed tick through the same total mapper the rest
  // of the wizard uses and splits answered-refusal from unreachable on both legs.
  //
  // readiness-unread -- the poll ran to its bound, NEVER ONCE READ THIS ENGINE, and its final tick could
  // not REACH it. This engine was already gone when the readiness card mounted. Before the split above, the
  // console's poll loop also fell through from its catch leg into the same exhaustion branch as a tick that
  // succeeded and reported the keys absent, so "the engine told us forty times the break-glass secret is not
  // there" and "we never got an answer at all" were the same row and coalesced into it.
  "readiness-unread",
  // readiness-refused -- the poll ran to its bound, NEVER ONCE READ THIS ENGINE, and THIS ENGINE WAS
  // ANSWERING: its final tick came back as a refusal (a 500, a 403, an unusable body). It is REACHABLE and it saw
  // every one of those forty reads, so the remedy is its own logs, and the customer's keys may well be installed.
  // Filed as readiness-unread until this member existed, which is the single most misleading row the console could
  // produce: the support bot reads that member out as an unreachable engine.
  "readiness-refused",
  // poll-went-quiet -- THIS ENGINE ANSWERED, AND THEN COULD NOT BE REACHED. The poll read a status at least
  // once and its FINAL tick failed in transport. It is the ordinary shape of an engine that goes away mid-wizard
  // (installing the key secrets sets Worker secrets, which is itself a redeploy), and it had no member:
  // readiness-unread demands that EVERY tick failed, which happens only if the engine was already dead before the
  // readiness card mounted. So the console fell through to poll-exhausted carrying a lastRead taken minutes
  // earlier, and the pack asserted this engine had gone on answering and gone on reporting the keys absent when it
  // had in fact stopped answering. Support then sent the customer to re-run the key ceremony; the remedy was an
  // unreachable engine. It carries no obSecret, because a stale read is not evidence of what this engine held when
  // it died.
  "poll-went-quiet",
  // poll-refused -- THIS ENGINE ANSWERED, AND THEN STARTED REFUSING. The poll read a status at least once
  // and its FINAL tick was a refusal, not a transport failure. This engine is UP and turning the status read away,
  // which is a different ticket and a different remedy from one that vanished. It used to write poll-went-quiet,
  // whose definition says in as many words that the engine is not reachable now. No obSecret, for the same reason:
  // the last successful read is stale and is not evidence of what this engine holds now.
  "poll-refused",
  // engine-binding-absent -- THE CONSOLE'S OWN DEPLOY HAS NO ENGINE SERVICE BINDING, so the wizard's
  // call never left the console: its worker answered the engine surface itself, with a 503 carrying a frozen code.
  // THIS ENGINE RECEIVED NOTHING AND IS NOT AT FAULT, and the remedy is the console's wrangler configuration and a
  // console redeploy. It is a member because the console's classifier keyed on a trailing numeric status and the
  // throw for this state carries a marker instead, so it fell through to `transport-error` and to the poll's
  // unreachable legs, every one of which asserts that THIS ENGINE did not answer. The wizard was telling support to
  // go and revive an engine that was up, healthy and idle, which is the same misdirection the transportClass member
  // of this name exists to stop, arriving one level down inside the wizard.
  //
  // A row carrying it reaches a pack only where the console's engine base later moves off its own bindingless
  // origin, or the binding is restored while the tab lives: the pack POST is an engine-surface call on that same
  // base, so it meets the same 503. That bound is stated rather than papered over (this stays open). The
  // member is still admitted here, because the console's alternative is not silence, it is a false claim about this
  // engine's reachability.
  "engine-binding-absent",
  // console-origin-fault: every tick of the readiness poll was answered by the CONSOLE'S OWN worker with a
  // 500 it manufactured, so THIS ENGINE received none of them. Admitted for the same reason as the row above: the
  // console's alternative is not silence, it is a false claim about this engine (the refused legs assert this
  // engine answered and turned the read away, the unreachable legs assert it could not be reached). Both send
  // support to an engine that is not the fault. Unlike the bindingless 503, it can ride a pack generated live: the
  // fault is per-request, so a Generate can succeed while the poll's ticks were answered by the console.
  "console-origin-fault",
  "ack-failed",
] as const;
export type ClientDiagOnboardingOutcome = (typeof CLIENT_DIAG_ONBOARDING_OUTCOMES)[number];

// obSecret -- onboarding-step / poll-exhausted only (3). WHICH KEY this engine kept reporting absent when
// the readiness poll ran out. The console emits one row per secret still absent at exhaustion, so a HALF-KEYED
// engine (router-keys.ts documents it: "nothing, or only the secrets named before the failure, was set") writes
// one row and an install that never took writes two or three. The three members are this engine's own key-ceremony
// slot NAMES, which are product constants; no key material and no secret VALUE can reach this field.
export const CLIENT_DIAG_ONBOARDING_SECRETS = ["signer", "break-glass", "operational"] as const;
export type ClientDiagOnboardingSecret = (typeof CLIENT_DIAG_ONBOARDING_SECRETS)[number];

// channelReasonClass -- update-channel-unverified only (6). WHY this engine's update-channel verdict came
// back unverified. This engine now hands the console the CLOSED cause on UpdateStatus.channelFault (updates.ts,
// UPDATE_CHANNEL_FAULTS) and the console maps it here; the free-text `reason` -- which can embed the channel URL,
// the signer key id and the platform's error prose -- is only the FALLBACK classifier's input, read to SELECT a
// member and never carried. A clamp of that reason into the pack would be a leak with a length bound on it, which
// is not a redaction. `none` is the honest fallback: unverified, cause unstated.
//
// bad-url and bad-signer-key are the MISCONFIGURED channel, and they are why this row was refuted once. The
// console gated its emit on this engine's `configured` flag, which is a VERDICT and not the operator's INTENT:
// checkUpdates answers configured:false for an unparseable UPDATE_CHANNEL_URL, a non-https one, and an
// UPDATE_SIGNER_PUBLIC that will not parse -- three states in which both env vars are set. So a truncated paste of
// the pinned signer key recorded NOTHING and produced a pack byte-identical to a healthy channel. UpdateStatus now
// carries channelIntended (env presence) and the emit keys off that.
export const CLIENT_DIAG_CHANNEL_REASON_CLASSES = ["signature", "unreachable", "malformed", "bad-url", "bad-signer-key", "none"] as const;
export type ClientDiagChannelReasonClass = (typeof CLIENT_DIAG_CHANNEL_REASON_CLASSES)[number];

// discoveryOutcome -- discovery-connect only (5). What the discovery token SAW in the browser. It
// separates the three faults the most common onboarding ticket confuses: a token accepted that then saw zero
// accounts, product listings refused for want of scope, and an account that is genuinely empty. No account id,
// no resource name, no Cloudflare API error text: their EXISTENCE is the discriminator, not their content.
export const CLIENT_DIAG_DISCOVERY_OUTCOMES = ["verified-accounts-seen", "verified-zero-accounts", "refused", "listing-errors", "listing-empty"] as const;
export type ClientDiagDiscoveryOutcome = (typeof CLIENT_DIAG_DISCOVERY_OUTCOMES)[number];

// claimResult -- claim-exchange only (9). How the licence claim-code exchange with the VENDOR control
// plane ended. This engine is not on that path at all. `http-5xx` (a vendor outage, which the console used to
// report to the customer as check your connection) and `empty-token-200` (a control-plane deploy that changed
// the response shape) are the two that were most expensively invisible. Never the claim code or a response body.
export const CLIENT_DIAG_CLAIM_RESULTS = [
  "success",
  "shape-rejected",
  "not-recognised",
  "band-full",
  "http-4xx",
  "http-5xx",
  "empty-token-200",
  "timeout",
  "network-or-cors",
  "parse-failure",
] as const;
export type ClientDiagClaimResult = (typeof CLIENT_DIAG_CLAIM_RESULTS)[number];

// The record shape (review §5). Every string field is one of the closed unions above; every numeric is a
// clamped integer. NO other string fields exist. `count` is a coalesce-repeat count (D7: never a sequence,
// index or id). firstMs/lastMs are performance.now() offsets (monotonic), so a rate is computable despite
// the untrusted client clock.
// adminOp -- admin-write only (35). WHICH privileged write the console attempted. Every
// member is a product constant naming an operation, chosen by the console call site that makes it. It is never
// a route, and never a target: no email, no credential id, no binding name, no channel URL, no role name.
export const CLIENT_DIAG_ADMIN_OPS = [
  "update-apply",
  "update-ramp",
  "update-rollback",
  "update-settle",
  "role-set",
  "role-delete",
  "group-role-set",
  "group-role-delete",
  "custom-role-create",
  "custom-role-delete",
  "passkey-revoke",
  "terminate-user-sessions",
  "terminate-other-sessions",
  "terminate-all-sessions",
  "recovery-codes-regenerate",
  // STAGED-RECOVERY-CODES-CONFIRM-GATE: the save-confirm panel's own POST, fired after a self-add
  // enrolment staged a fresh set over an existing live one, most often the forced re-enrolment after a
  // recovery-code sign-in. See POST /admin/auth/recovery-codes/confirm (router-auth-flow.ts).
  "recovery-codes-confirm",
  "break-glass-retire",
  "approval-policy-set",
  "change-number-policy-set",
  "signin-context-set",
  "posture-accept",
  "posture-unaccept",
  "notify-channel-upsert",
  "notify-channel-delete",
  "notify-rule-upsert",
  "notify-rule-delete",
  "expiry-item-set",
  "expiry-item-delete",
  "idp-connection-upsert",
  "idp-connection-delete",
  "idp-connection-toggle",
  // The zero-downtime SAML signing-certificate rollover (owner action `idp-conn-cert`, POST
  // /admin/idp/connections/cert). It is its own op rather than a shade of the upsert because the two are
  // refused for different reasons and fixed by different edits: an operator blocked at the rollover needs the
  // row to name the rollover, not the connection edit they never attempted. Admitted HERE first, because this
  // list is the RECEIVER: projectClientDiagnostics checks adminOp by set membership and fails the whole record
  // closed on a member this set does not hold (client-diag-receive.ts:220), so the console half of the pair can
  // only land once this one has.
  "idp-connection-cert-rollover",
  "credential-mint",
  "credential-delete",
  "source-attach",
  "source-detach",
  "source-reattach",
  // The DOWNPIPE and DESTINATION ops. They were absent because no console call site named them, and the
  // gap is why they are needed: these are the controls a role gate most often greys out (the Delete button is
  // greyed out for our admin and we do not know why), and a gov-gate row cannot say WHICH control was refused
  // without an op to name it. They are privileged writes in their own right, so they belong in this vocabulary
  // whether or not a gate ever fires on them.
  "downpipe-run",
  "downpipe-edit",
  "downpipe-toggle",
  "downpipe-delete",
  "destination-verify",
  "destination-set-default",
  "destination-upsert",
  "destination-delete",
  // The PUSH / OTLP / RESTORE-APPLY / DISCOVERY ops. Every one of them is change-controlled (each is a
  // requireChange call site), so each is an action a skipped change-number prompt can fall on, and a gov-gate row
  // that cannot name which one is a row that says a governance control misfired somewhere.
  "push-upsert",
  "push-toggle",
  "push-clear",
  "otlp-upsert",
  "otlp-toggle",
  "otlp-clear",
  "restore-apply",
  "discovery-token-set",
  "discovery-token-clear",
  "discovery-accounts-set",
  // The dual-control inbox ops and the offboarding IdP-cleanup attestation.
  "owner-action-approve",
  "owner-action-reject",
  "idp-cleanup-attest",
] as const;
export type ClientDiagAdminOp = (typeof CLIENT_DIAG_ADMIN_OPS)[number];

// writeOutcome -- admin-write only (7). HOW the privileged write ended, derived by the console from the numeric
// HTTP status alone, never from this engine's refusal prose. It is deliberately NOT a guard identity: the
// last-Owner, last-passkey and owner-escalation guards all answer 400, and only the refusal SENTENCE separates
// them, so a client-side classifier over it would silently mislabel the moment this engine rewords itself. That
// subdivision belongs HERE, beside the guard that fired. `applied` rides only for the ops whose success is
// itself the question (a terminate-all-sessions, a recovery-code regeneration, a rollback); `unreachable` is
// the one this engine can never record, because the write never arrived.
export const CLIENT_DIAG_WRITE_OUTCOMES = [
  "applied",
  "refused-validation",
  "denied-role",
  "conflict",
  "rate-limited",
  "server-error",
  "unreachable",
] as const;
export type ClientDiagWriteOutcome = (typeof CLIENT_DIAG_WRITE_OUTCOMES)[number];

// recoveryOp -- recovery-refusal only (4). WHICH manual disaster-recovery flow was refused. The
// four share one code vocabulary and are four different tickets.
//
// estate-import-sealed is the browser-unseal counterpart of estate-import: the console verifies the
// SEALED wrapper's signature and unseals its body ENTIRELY IN THE BROWSER (identity.key never leaves it),
// then hands the recovered plaintext to POST /control-plane/import-sealed. Most of its refusals (a wrong key,
// a corrupt capsule or body) can only ever be decided in the browser and never reach this engine at all --
// exactly the DP-R01..R06 shape below, one flow later.
// cp-acknowledge (defect 23) is the ACKNOWLEDGE-ONLY latch clear, its own op rather than a re-use of
// cp-restore: cp-restore is a break-glass holder over a WIPED plane, cp-acknowledge an authenticated owner
// whose configuration is already back and whose banner will not go down. One coalesced row for the two would
// send support to opposite places.
export const CLIENT_DIAG_RECOVERY_OPS = ["cp-restore", "cp-restore-sealed", "cp-acknowledge", "estate-import", "estate-import-sealed", "export-download"] as const;
export type ClientDiagRecoveryOp = (typeof CLIENT_DIAG_RECOVERY_OPS)[number];

// recoveryCode -- recovery-refusal only (28). The console's frozen DP-R refusal codes, already
// stamped into the message the operator reads. DP-R01..R06 are decided in the browser and never reach this
// engine; DP-R10..R14 are this engine's own refusals keyed to the status it answered with.
export const CLIENT_DIAG_RECOVERY_CODES = [
  "DP-R01",
  "DP-R02",
  "DP-R03",
  "DP-R04",
  "DP-R05",
  "DP-R06",
  "DP-R10",
  "DP-R11",
  "DP-R12",
  "DP-R13",
  "DP-R14",
  // DP-R15/R16/R17 SPLIT DP-R12. DP-R12 was EVERY 400 this engine answered, so signature, shape-check and
  // no-custody -- three of the five states the ticket enumerates -- were one row that coalesced on the tuple key.
  // This engine now returns a CLOSED `refusalClass` member in its 400 body and the console admits it by SET
  // MEMBERSHIP, mapping it to a code; a body carrying no recognised member still lands on DP-R12, so the mapper
  // stays total and an older engine keeps working.
  "DP-R15", // the signed export's SIGNATURE did not verify
  "DP-R16", // the artefact FAILED THE SHAPE CHECK (it parsed; it is not an estate export)
  "DP-R17", // the NO-CUSTODY GATE refused it: it carries a plaintext secret, and this engine will not take one
  // DP-R18/R19 SPLIT DP-R15, because the remedies are OPPOSITE. Both halves of the hybrid signature cover
  // the same bytes, so a failure that leaves EITHER half verifying PROVES the export intact and puts the damage
  // in the customer's own key file. Reading that out as DP-R15 told them their recovery artefact had been
  // tampered with when the answer was "take another copy of your kit".
  "DP-R18", // the CLASSICAL half failed and the post-quantum half verified these exact export bytes: the export is INTACT and the Ed25519 half of the kit is damaged. NOT tamper
  "DP-R19", // the .sig blob would not decode: the SIGNATURE file is damaged and the export was never checked. NOT tamper
  "DP-R20", // the KEY would not import: the export was never checked. NOT tamper
  "DP-R21", // the POST-QUANTUM half failed and the classical half verified these exact export bytes: the export is INTACT (a partial signer rotation, or a rotted ML-DSA key half). NOT tamper
  // the browser-unseal-only codes. DP-R15/18/19/20/21 above are now ALSO reachable straight from the
  // browser (the console verifies the SEALED wrapper's signature locally, byte-identical to this engine's own
  // check, before ever decrypting) -- same meaning, just caught one round-trip earlier. These seven are new
  // STATES that have no plaintext-import equivalent, because only a browser holding the private identity can
  // ever observe them (this engine holds no key that opens a sealed artefact it did not seal itself).
  "DP-R22", // the sealed artefact's version is one this browser's unseal does not understand
  "DP-R23", // the sealed artefact predates bodyHash: it cannot be cross-checked, so it is refused rather than trusted unverified
  "DP-R24", // no capsule wrap matches the held identity: the WRONG break-glass key (or quorum) for this estate
  "DP-R25", // the capsule addressed to the held identity did not decrypt cleanly: a corrupt or truncated sealed artefact
  "DP-R26", // the sealed BODY did not decrypt cleanly, after a good capsule open: a corrupt or truncated sealed artefact
  "DP-R27", // the body decrypted, but is not a valid control-plane export
  "DP-R28", // the recovered plaintext's hash does not match the SIGNED bodyHash (should never occur once the signature and both AEAD opens already succeeded; refused rather than silently trusted)
  // the ENGINE-SIDE twins of DP-R23 and DP-R28, reachable only on POST /control-plane/restore-sealed, where
  // THIS engine opens the sealed artefact itself and can answer sealed-unhashed or sealed-body-mismatch by name
  // (router-identity.ts, the `reconcile-sealed` surface). Kept distinct from the client-side pair rather than
  // fused: those assert the BROWSER opened the artefact and found the fault locally, which a wire refusal does
  // not prove, and the diagnostics ring keys on the code.
  "DP-R29", // the engine refused a sealed artefact that predates bodyHash, so it cannot be cross-checked (the wire twin of DP-R23)
  "DP-R30", // the engine recovered the plaintext and its hash does not match the SIGNED bodyHash (the wire twin of DP-R28)
  // Defect 23: the acknowledge-only latch clear's three refusals, each its own branch under the
  // one-branch-one-code rule (DP-R11 says "not an Owner", which is wrong in both directions on this route).
  "DP-R31", // 400 (class ack-role-table-empty): the role table is empty, so clearing the latch would remove the only explanation for every caller resolving to viewer
  "DP-R32", // 400 (class ack-no-latch): no recovery was in effect by the time the acknowledge arrived. Benign
  "DP-R33", // 403: the caller does not hold access.policy, or is the bare break-glass token, refused on this route by design
] as const;
export type ClientDiagRecoveryCode = (typeof CLIENT_DIAG_RECOVERY_CODES)[number];

// intentClass -- intent-dropped only (5). WHICH half-filled restore option the request builder threw
// away. Every one of them is a silent downgrade of the operator's intent into a WIDER or DIFFERENT run than
// they asked for: a Max records that did not parse plans the WHOLE run, a cf-config or media token with no
// account beside it drops that whole section out of the restore, a D1 database with no tables plans every
// record instead of the chosen subset, and an empty redirect binding lets an approved apply write back over
// the LIVE original bindings. The typed values are Cloudflare edit tokens and account ids; only the class rides.
export const CLIENT_DIAG_INTENT_CLASSES = [
  "max-records-invalid",
  "cf-pair-partial",
  "media-pair-partial",
  "d1-subset-partial",
  "redirect-binding-empty",
] as const;
export type ClientDiagIntentClass = (typeof CLIENT_DIAG_INTENT_CLASSES)[number];

// probeSurface -- probe-outcome only (5). WHICH operator-initiated test ran. The screen cannot stand in
// for it (the notify and SIEM tests share one screen, and a destination verify fires from two), and the remedy
// is different for every one of them.
export const CLIENT_DIAG_PROBE_SURFACES = ["dest-verify", "idp-test", "notify-test", "push-test", "email-test"] as const;
export type ClientDiagProbeSurface = (typeof CLIENT_DIAG_PROBE_SURFACES)[number];

// probeOutcome -- probe-outcome only (17). HOW the test ended, in ONE union whose members are surface-
// prefixed so a class can never be read against the wrong surface. The members are selected from the RESPONSE
// SHAPE wherever the shape carries the answer (push-test returns a numeric httpStatus; a destination verify
// returns a deleteProbe verdict; an IdP test returns per-check pass/fail lines with the engine's own check
// names), and otherwise by a classifier that READS the engine's reason ONLY to SELECT a member and RETURNS the
// member. No vendor response body, no endpoint, no certificate and no platform message can ride: there is no
// field for one.
//
//   ok                      the test passed. A MEMBER ON PURPOSE. Verify fails every morning and works on
//                           retry is a claim about a RATIO, and a ring holding only failures cannot answer it.
//   probe-refused           the ENGINE turned the test down (a role gate, a step-up, a rate limit). The test
//                           never ran, so nothing was learnt about the vendor: a wholly different ticket from a
//                           test that ran and failed, and the two were previously one red toast.
//   probe-unreachable       the test call itself never came back. Same distinction, other cause.
export const CLIENT_DIAG_PROBE_OUTCOMES = [
  "ok",
  "probe-refused",
  "probe-unreachable",
  "dest-unreachable",
  "dest-auth",
  "dest-write-probe-failed",
  // dest-delete-denied is the WORM/RETENTION POSTURE CASE: the bucket accepts writes and REFUSES deletes, so the
  // destination works and its retention cannot be managed. The engine reports it on the ok:TRUE arm of the verify
  // union (a refused cleanup delete does not fail the probe), which is why destProbeOutcome tests deleteProbe
  // BEFORE ok. Read the other way round, this member has no producer and the state coalesces with a clean verify.
  "dest-delete-denied",
  // dest-region-mismatch: S3 answers a request signed for the wrong region with a 301 PermanentRedirect and the
  // dest layer refuses to follow it. Its own member because it is common and its remedy (set the region to the
  // bucket's) is unlike every other dest member's; in dest-other it was invisible among the unclassified.
  "dest-region-mismatch",
  "dest-other",
  "idp-discovery-failed",
  "idp-jwks-failed",
  "idp-cert-failed",
  "idp-metadata-failed",
  "idp-other",
  "notify-delivery-failed",
  "push-endpoint-4xx",
  "push-endpoint-5xx",
  "push-egress-blocked",
  "push-timeout",
  "push-other",
  "email-platform-refused",
  "email-other",
] as const;
export type ClientDiagProbeOutcome = (typeof CLIENT_DIAG_PROBE_OUTCOMES)[number];

// formField -- form-rejected only (21). The FIELD CATALOGUE control id the console's own validator acted
// on. It is a product vocabulary (the catalogue's own ids), chosen by the call site, and it is emphatically NOT
// the typed value: these fields hold endpoints, bucket names, access keys, role ARNs, account ids and
// contracted rates, every one of which is customer data. The id is what makes the row feed the catalogue's
// divergence detector: a console validator that has drifted TIGHTER than the catalogue shows up as a field that
// is refused in the field and accepted on paper.
// REMOVED: dest-r2-bucket, dest-account-id, dest-s3-bucket, dest-region,
// dest-access-key and dest-secret. This vocabulary is the RECEIVING TWIN of the console's, so it may only admit
// what the console can actually emit. A form-rejected row means the CONSOLE'S OWN validator refused the operator
// in the browser, and those six controls carry no client-side validator: a bucket name, a region, an account id
// and an access key/secret pair are not decidable in a browser. THIS ENGINE verifies them, live, and its refusal
// is already carried as an engine-call row, which is what it is. Admitting a member the console cannot send is a
// promise this pack cannot keep.
export const CLIENT_DIAG_FORM_FIELDS = [
  "binding",
  "namespaceId",
  "bucketName",
  "databaseName",
  "databaseId",
  "storeId",
  "secretName",
  "dest-endpoint",
  // These SEVEN ids are the CATALOGUE'S OWN ids, and they were wrong before. The members
  // emitted were dest-secret-key, dest-worm-retention-days, dest-sts-role-arn and dest-pricing-{storage,class-a,
  // class-b,egress}: NOT ONE of them is the id of any control in the console, and not one appears in any
  // catalogue row. The whole stated purpose of carrying a field id rather than a screen name is that the row
  // JOINS to the field catalogue and feeds its divergence detector, and an id present in no catalogue row joins
  // to nothing. dest-secret-key was additionally DEAD: the control's id is dest-secret, so formFieldFor -- which
  // admits by SET MEMBERSHIP and drops anything else -- could never have selected it.
  "dest-worm-days",
  "dest-role-arn",
  "dest-sts-duration",
  "dest-price-storage",
  "dest-price-classa",
  "dest-price-classb",
  "dest-price-egress",
  // The CONSOLE-WIDE funnel. Every control built by components/field.ts runs its validator through ONE
  // function, and a refusal there has never left the browser: the form will not accept my cron / bucket name /
  // endpoint, and the split button stays disabled, are the two commonest console tickets there is no evidence
  // for at all. These are the catalogued control ids of every field that HAS a validator to refuse with, so the
  // row can say WHICH control refused. The id is a product constant from the field catalogue; the typed VALUE is
  // never read, and on this family that matters more than most: these fields hold licence tokens, deploy tokens,
  // recovery codes, IdP client ids, SAML certificates and email addresses.
  //
  // A field id NOT in this list is DROPPED at the funnel rather than coerced (formFieldFor), so a control added
  // without a catalogue row produces no evidence rather than the wrong evidence.
  //
  // R2: the first cut of this list was SHORT, and short in the places the ticket names. Seventeen
  // controls that have a validator to refuse with were absent, so their refusal was dropped at the console funnel
  // and support read no row -- which reads as no refusal happened, the one reading worse than a blank. dp-bucket
  // is the sharpest: the bucket name was answerable from the add-source and destination forms and silently
  // unanswerable from the downpipe editor, which is where a downpipe's bucket override is edited. dp-sched-cron
  // and dp-sched-tz were not on the funnel at all until the console put them there.
  // DELIBERATELY ABSENT, and this is the G246 lesson applied to our own list: idp-var (the IdP preset's dynamic
  // required-variable controls), saml-idp-entity and saml-sp-entity. Every one of them is `required: true` with a
  // validator that only rejects the EMPTY string, so field()'s validate() hits the required-and-empty branch
  // first and returns before the validator ever runs. Their sole possible refusal is therefore the one refusal
  // the funnel deliberately does not record (an operator part-way through a form is not a fault), which means a
  // member for them could never be produced by any code path. A vocabulary member with no producer reads like
  // coverage and is not: it tells a support engineer the evidence was looked for and not found.
  //
  // REMOVED (dead vocabulary,, R3), in lockstep with the console: channel-name, channel-routing-key,
  // demo-reset-token, group-role-group, idp-client-id, idp-label, licence-token, saml-label,
  // update-component-token, update-deploy-token, update-ramp-token, update-rollback-token,
  // update-rollback-token-urgent and update-settle-token. Fourteen members with exactly the pathology the
  // paragraph above describes. Each control HAS a validator, which is why the list looked right, and each of
  // those validators is an emptiness test and nothing more, so any non-empty string passes it. Their one
  // reachable refusal is the empty one, and the console funnel does not record that (an operator part-way
  // through a form is not a fault), so no console build could ever send them. This twin is the RECEIVER: a
  // member admitted here that the console can never send is the same dead promise read from the other end.
  "channel-addresses",
  "channel-url",
  "cost-cadence-custom",
  "cost-churn",
  "cost-dedup",
  "cost-drills",
  // The four contracted-rate controls on the COSTS screen. Not the dest-price-* four: those are the destination
  // form's rates. A customer on a negotiated rate card types into these.
  "cost-price-storage",
  "cost-price-classa",
  "cost-price-classb",
  "cost-price-egress",
  "cost-restores",
  "cost-retention-days",
  "cost-retention-runs",
  "cost-source",
  // The Shamir split pickers (G335, custody-step-panels.ts). Two ids, not one, and that IS the discrimination:
  // the split button stays disabled is answered by WHICH picker the ceremony refused, because the share count
  // and the threshold are refused for different reasons and fixed by different edits. N and the threshold
  // themselves never ride: they are the customer's own custody design and a fingerprint of it.
  "custody-split-n",
  "custody-split-threshold",
  "dp-binding",
  "dp-bucket",
  "dp-dbid",
  "dp-name",
  "dp-ns",
  "dp-sched-cron",
  "dp-sched-tz",
  "expiry-date",
  "expiry-label",
  "idp-id",
  "ob-invite-email",
  "otlp-push-endpoint",
  "pk-email",
  "pk-recovery-email",
  "posture-override-reason",
  "push-endpoint",
  "push-s3-endpoint",
  "push-syslog-host",
  "push-syslog-port",
  "role-email",
  "saml-certs",
  "saml-id",
  "saml-idp-sso",
  // The rollover paste box (cert-rollover.ts, control id saml-rollover-certs). It is NOT saml-certs: that is
  // the connection form's certificate field, and a refusal on one is a different ticket from a refusal on the
  // other. It clears the bar the paragraph above sets for a member with no reachable producer: its validator
  // refuses a NON-EMPTY paste that carries no BEGIN CERTIFICATE header, so its refusal is not the
  // required-and-empty one the funnel deliberately drops, and a paste in the wrong format is the ordinary way
  // a rollover fails.
  "saml-rollover-certs",
  "update-ramp-pct",
] as const;
export type ClientDiagFormField = (typeof CLIENT_DIAG_FORM_FIELDS)[number];

// rejectOutcome -- form-rejected only (2). The two are NOT the same ticket and must never be one row.
//
//   rejected          the operator SAW the refusal: an error under the field, a blocked save. They know they
//                     are stuck, they are on the phone about it, and the question is whether the console is
//                     right to refuse (a validator tighter than the catalogue refuses a value the engine would
//                     have taken).
//   silently-coerced  the operator saw NOTHING. What they typed was quietly replaced with a default, the save
//                     succeeded, and the estate is now running on a value they did not choose. This is the
//                     member that answers "cost estimates ignore the contracted rate I entered", and it can
//                     never be inferred from an engine-side record, because the engine was sent the DEFAULT and
//                     stored it faithfully.
export const CLIENT_DIAG_REJECT_OUTCOMES = ["rejected", "silently-coerced"] as const;
export type ClientDiagRejectOutcome = (typeof CLIENT_DIAG_REJECT_OUTCOMES)[number];

// catalogueClass -- catalogue-degraded only (6). WHY the Cloudflare-configuration offer was withheld or
// untrustworthy. It records a WITHHELD AFFORDANCE, not a fault: the operator opened the wizard and did not get
// the option, which is the ticket, and the row says which of the four confusable reasons applied.
//
//   cf-catalogue-empty        the engine returned NO surface catalogue. On its own this is ambiguous: the
//                             discovery token can no longer read the account, or the engine predates the
//                             feature. It is disambiguated by joining it to the engine's OWN discoveryHealth,
//                             which knows whether the zone listing came back denied. Neither half can say alone.
//   cf-not-added              cf-config was never added as a source on the Sources screen.
//   cf-no-accounts            the catalogue is there and the token could read no account to scope a downpipe to.
//   cf-surface-list-unreadable the editor's re-read of the surface list failed, so the operator is re-picking
//                             surfaces against a list that did not load.
//   cf-never-discovered       a cf-config downpipe whose discovery has NEVER run, so it is capturing EVERY
//                             surface rather than the ones in use. The operator picked auto and believes it is
//                             narrowing; it is not.
//   cf-rediscover-failed      the operator pressed Rediscover and it did not complete, so the stale surface
//                             set stands.
export const CLIENT_DIAG_CATALOGUE_CLASSES = [
  "cf-catalogue-empty",
  "cf-not-added",
  "cf-no-accounts",
  "cf-zones-empty",
  // The CATALOGUE READ (GET /sources/discover: the wizard's source step, the editor's re-read on every cf-config
  // open) throws, and until now every throw wrote the one residual below. Seven states shared it, and two of them
  // were not faults at all: a lapsed Cloudflare Access session (the ordinary overnight tab, on an Access-fenced
  // console) and a 401 now record NOTHING. The five members here are five different remedies, and they are the
  // twins of the cf-rediscover-* members: the ADDRESS (a web page answered), the ROLE (the engine's own 403), an
  // EDGE RULE or the address (a 403 that did not speak the engine's refusal vocabulary), a retry (429), and a
  // dropped call. The console's own 500 and its missing ENGINE binding stay on the residual: no request reached
  // any engine, and the console-side rows in the same ring name them.
  "cf-surface-list-unreadable",
  "cf-surface-list-not-an-engine",
  "cf-surface-list-denied",
  "cf-surface-list-refused-at-edge",
  "cf-surface-list-rate-limited",
  "cf-surface-list-transport",
  "cf-never-discovered",
  "cf-discovery-all-unavailable",
  "cf-rediscover-no-token",
  "cf-rediscover-out-of-scope",
  // cf-rediscover-denied is now the ENGINE'S OWN 403 (the refusal body is one of its shapes: engine-capability,
  // engine-authz, engine-csrf), so it means what its note says: the engine answered, this caller's role may not
  // rediscover, and the address is not in doubt. A 403 that did NOT speak the engine's refusal vocabulary is
  // cf-rediscover-refused-at-edge: the customer's WAF in front of a healthy engine, or a foreign host at an
  // address where no engine is deployed. They used to be one row, whose remedy sent support to fix a role on an
  // engine that may not exist.
  "cf-rediscover-denied",
  "cf-rediscover-refused-at-edge",
  "cf-rediscover-rate-limited",
  // cf-rediscover-not-an-engine: a WEB PAGE answered the rediscover where engine JSON was expected, so a proxy, a
  // static host or an SPA shell sits at the engine's address. It got an answer, from the wrong system, and the
  // remedy is the ADDRESS. It used to file as cf-rediscover-transport, whose note says the call got no answer at
  // all. A lapsed Cloudflare Access session, the other statusless throw, deliberately has NO member: it records
  // nothing (the ordinary overnight tab), and a member with no producer reads like coverage.
  "cf-rediscover-not-an-engine",
  "cf-rediscover-transport",
  "cf-rediscover-failed",
] as const;
export type ClientDiagCatalogueClass = (typeof CLIENT_DIAG_CATALOGUE_CLASSES)[number];

// featureClass -- feature-probe only (7). WHICH route family the console could not read and then made a
// judgement about. The screen cannot stand in for it: the security screen makes seven of these reads, so a
// server-5xx row on that screen names none of them, and the whole complaint is that ONE table never loads.
export const CLIENT_DIAG_FEATURE_CLASSES = [
  "roles-table",
  "group-roles",
  "config-approvals",
  "restore-approvals",
  "audit-events",
  "whoami",
  // engine-url is not a ROUTE: it is the address the console would have called one on. It earns a member because
  // a stored engine address that will not parse means NO client was ever constructed and NO call was ever made,
  // so every other row in this ring is silent BY CONSTRUCTION rather than because nothing went wrong. Without it,
  // the most broken console possible produces the emptiest pack.
  "engine-url",
] as const;
export type ClientDiagFeatureClass = (typeof CLIENT_DIAG_FEATURE_CLASSES)[number];

// featureOutcome -- feature-probe only (9). THE VERDICT THE CONSOLE REACHED, which is the field the whole
// kind exists for. Today all of these collapse into one tile that says the feature is pending the engine.
//
//   route-absent            a 404: the engine genuinely does not serve this route. The pending-the-engine tile
//                           is CORRECT here, and only here.
//   not-implemented         a 501: the route exists and declines to do the work.
//   server-error            a 5xx: the engine is BROKEN, and the console told the customer the feature was not
//                           built yet. This is the conflation the gap is about, and it is the common case.
//   forbidden               a 403: the route is there, the engine works, and this caller may not read it. The
//                           table is empty because of a role, not a defect.
//   rate-limited            a 429.
//   network                 the fetch threw and the health probe did NOT answer: the engine is unreachable.
//   origin-rejected         the fetch threw and the health probe DID answer in the same breath. That pair is the
//                           CORS fingerprint, and it means CONSOLE_ORIGIN is not set on the engine. The console
//                           computes exactly this diagnosis today, shows it, and discards it.
//   engine-url-unparseable  the stored engine address would not parse, so NO client was ever constructed and no
//                           call was ever made. Every other diagnostic in this ring is silent by construction
//                           when this row is present, which is precisely what makes an empty ring readable.
//   other                   a non-2xx in none of the classes above.
export const CLIENT_DIAG_FEATURE_OUTCOMES = [
  "route-absent",
  "not-implemented",
  "server-error",
  // forbidden is now a 403 THE ENGINE ITSELF REFUSED, decided by the SHAPE of the refusal body (engine-capability,
  // engine-authz, engine-csrf): the engine is deployed at that address, it saw the call, and the remedy is a role
  // or an origin check.
  "forbidden",
  // refused-not-by-engine: a 403 whose body is not a refusal this engine emits (an HTML block page, a proxy's
  // plain text). SOMETHING refused the call and it did not speak the engine's refusal language, which is all the
  // console established. Either the customer's own edge refused the browser in front of a healthy engine, or
  // nothing is deployed at that address and a foreign host refused. Both used to file as `forbidden`, whose note
  // told support the remedy was never the engine's address, in the one case where the address IS the fault.
  "refused-not-by-engine",
  "rate-limited",
  "network",
  "not-an-engine",
  // engine-binding-absent: no request reached any engine, because the console's OWN worker has no ENGINE service
  // binding and answered the call itself. It is a console deploy fault and is NOT `network`, whose note
  // asserts the engine is unreachable: nothing here establishes anything about the engine at all, and support
  // sent to the engine's logs for a request that was never sent finds nothing there.
  "engine-binding-absent",
  // console-origin-fault: a 500 the CONSOLE'S OWN worker manufactured (a frozen header on its own response
  // admits it), because its proxied dispatch threw or the bound ENGINE binding's fetch rejected. NO REQUEST
  // REACHED ANY ENGINE. On the bare status this landed on `server-error`, whose note says this engine is broken
  // and saw the call, so the pack sent support to read refusals that cannot exist: the inversion of the state,
  // which is an engine that is absent or down reported as up and refusing.
  // IT HAS A SECOND PRODUCER, added with the round that found the first one incomplete: a 5xx with an HTML body,
  // in the PROXIED topology. The header gate only catches a 500 the console worker LIVED to answer; when the
  // worker never runs (over its limits, script gone, an edge fault) Cloudflare answers with its own HTML error
  // page and no header of ours. In the proxied topology the engine is a SERVICE BINDING and cannot answer HTML,
  // so that page did not come from the engine either. In the SPLIT topology it usually IS a broken engine behind
  // Cloudflare's 1101, and the console does not make the claim there.
  "console-origin-fault",
  "origin-rejected",
  "engine-url-unparseable",
  "other",
] as const;
export type ClientDiagFeatureOutcome = (typeof CLIENT_DIAG_FEATURE_OUTCOMES)[number];

// govGate -- gov-gate only (2). WHICH client-side governance gate fired. Both are invisible to the engine
// by construction, and they fail in OPPOSITE directions, which is why they are two members and not one:
//
//   role-gate-refusal-shown             the console GREYED A CONTROL OUT. No request was made, so there is no
//                                       403 and no audit event: an Owner reporting that Delete is disabled has
//                                       nothing anywhere to point at. The row plus adminOp says which control.
//   change-prompt-skipped-policy-read-failed
//                                       the console did NOT ASK for a change number because the policy read
//                                       faulted, and proceeded without one. The engine then refuses the action
//                                       with a 400 and counts it (configIntegrity.changeControlRefusals), so the
//                                       pack today shows a refusal with no explanation. This row is the missing
//                                       half, and the two JOIN: a change-control refusal with one of these
//                                       beside it is a console that never prompted, not an operator who ignored
//                                       the prompt.
export const CLIENT_DIAG_GOV_GATES = ["role-gate-refusal-shown", "change-prompt-skipped-policy-read-failed"] as const;
export type ClientDiagGovGate = (typeof CLIENT_DIAG_GOV_GATES)[number];

// skewClass -- console-skew only (5). THE CONSOLE'S BUILD, EXPRESSED AS ITS RELATION TO THE ENGINE. A raw
// version string is a product constant and would be redaction-safe, but it is also not the evidence: support
// would still have to compare it to the engine's, and only the browser can see both at once. So the comparison
// is made where it is possible and the RESULT is what rides.
//
//   matched              the running console build is the one the engine's own update record names. A member on
//                        purpose: its ABSENCE from a pack whose engine reports a console component is itself the
//                        finding.
//   console-behind       the browser is running an OLDER build than the engine expects. The dead Approve button,
//                        the feature that is silently off, the expiry warning that never appears: all of them.
//   console-ahead        the browser is running a NEWER build than the engine expects, so the console is calling
//                        routes the engine does not serve, and every one of them answers 404.
//   engine-version-unknown the engine did not report a console component version at all, so no comparison is
//                        possible. Recorded rather than assumed matched.
//   console-unstamped    this console bundle carries no version at all, which blinds the console's own update
//                        verdict: it can read up to date while it is releases behind.
export const CLIENT_DIAG_SKEW_CLASSES = [
  "served-matches-running",
  "served-newer-than-running",
  "served-older-than-running",
  "served-version-differs",
  "origin-unreachable",
  "origin-not-json",
  "origin-unstamped",
  "running-unstamped",
] as const;
export type ClientDiagSkewClass = (typeof CLIENT_DIAG_SKEW_CLASSES)[number];

// bulkAction -- bulk-outcome only (7). WHICH bulk operation the row is about. Without it EVERY bulk loop
// in the console coalesced into one row: a bulk delete that half-failed and a bulk run that half-failed are the
// same tuple and the first written wins. Chosen by the console's call site, never parsed from a rendered verb.
export const CLIENT_DIAG_BULK_ACTIONS = ["create", "run", "disable", "delete", "protect", "drill", "restore-apply"] as const;
export type ClientDiagBulkAction = (typeof CLIENT_DIAG_BULK_ACTIONS)[number];

// materialClass -- material-rejected only (5). WHY the console refused a piece of key or ceremony
// material, decided at the reject branch. padding-present and non-ascii are the two that are invisible to the
// operator and trivially fixable: a share pasted from a standard-base64 tool, and a share an email client
// smart-quoted on its way to them. A length NEVER rides: it fingerprints the secret.
export const CLIENT_DIAG_MATERIAL_CLASSES = ["bad-length", "non-alphabet", "padding-present", "non-ascii", "ceremony-shape"] as const;
export type ClientDiagMaterialClass = (typeof CLIENT_DIAG_MATERIAL_CLASSES)[number];

// contractClass -- contract-skew only (6). HOW this engine's payload broke the contract the console
// was compiled against. Decided by the console's own guard (an Array.isArray that failed, a set lookup that
// missed, an `?? []` that fired), never read out of any engine text.
export const CLIENT_DIAG_CONTRACT_CLASSES = [
  "unknown-enum-member",
  "missing-field",
  "wrong-shape",
  "empty-payload",
  "legacy-path-taken",
  "watch-timeout-drift",
] as const;
export type ClientDiagContractClass = (typeof CLIENT_DIAG_CONTRACT_CLASSES)[number];

// fieldFamily -- contract-skew only (16). WHICH family of data broke. A closed PRODUCT vocabulary,
// never a field name (a wire detail that would drift) and never the unrecognised VALUE (an id can be
// operator-named). role-grants has its own family because it is the one the ticket names: a signed, hash-chained
// snapshot that reports 0 role grants when there were 12 is evidence an auditor will read as "nobody held a role".
export const CLIENT_DIAG_FIELD_FAMILIES = [
  "idp-preset", // the IdP provider key behind a tile (unknown key renders the neutral globe)
  "idp-connections", // the connections array on the IdP screen (absent renders every tile as an empty add-a-provider tile)
  // `vendor-mark` WAS A MEMBER HERE AND IS DELETED: its only producer in the console was guarded on a
  // CONSOLE-SIDE CONSTANT (every caller passes a mark key off the console's own integrations catalogue, and every
  // key in it resolves), so no engine of any version could satisfy it. The engine never names a vendor, so a
  // contract-drift family for one was coverage-shaped nothing.
  "notify-event", // a notification event id the label table does not know
  "source-type", // a source-type id the cost table's label map does not know
  "surface-screen", // a landing-screen id the roles builder does not know
  "status-fields", // the security status payload (a dropped field silently removes a control)
  "policy-fields", // the approval-policy payload (a dropped field silently removes an option)
  "posture-checks", // the posture report's checks array, well-formed and empty
  "role-grants", // the config snapshot's role-grant list, counted as 0 when it was not an array
  "snapshot-counts", // any other config-snapshot count field that was not an array and was counted as 0
  "change-kind", // a config-change kind the approve-capability mirror does not know
  "change-description", // a config change with no description for the approver to read
  "action-summary", // an owner action with no summary for the operator to read
  "flight-watch", // the canary flight watch: the client ceiling expired with the run still in flight
  "added-sources", // the added-sources roster, absent on an older engine (the compatibility branch)
  // downpipe-config: ONE ROW inside a perfectly good downpipe list whose config the console cannot
  // read (no config object, no source, or a source with no type word). It is a family of its own and NOT
  // `downpipe-list`, because the two are different faults with different remedies: `downpipe-list` is the whole
  // read settling ok with no array, healed by a retry or a version match, and this is a single malformed roster
  // record inside a healthy response, which THIS engine's own roster-hygiene names ("MALFORMED: dp:X holds a
  // value with no readable string config.id at all") and heals, and which no retry will ever fix.
  //
  // ADMITTED HERE BECAUSE THE ALTERNATIVE IS SILENCE, not a downgraded row: a field family the console emits and
  // this list does not hold makes projectRecord() return null, which drops THE WHOLE RECORD on arrival. Between
  // the console landing the family and this line landing, every browser record of a malformed roster row
  // vanished on its way into the support pack and the pack read clean.
  "downpipe-config",
  // The CONSOLE/ENGINE VOCABULARY SKEW families. Each is a place the console SILENTLY NORMALISES a value
  // an engine of a different version handed it, and each normalisation is a DIFFERENT symptom the customer
  // reports: a capability the console does not know is STRIPPED from a custom role's resolved set, so a
  // custom-role holder loses buttons (and a tampered role record trying to smuggle a capability looks exactly the
  // same, which is why the fact is worth recording at all); an unknown landing id falls back to Overview, so an
  // executive lands on the wrong screen; an unknown owner-action kind renders its RAW id in the inbox; and an
  // engine that advertises no token-source capability at all makes those source types vanish from Add a source.
  // `surface-screen` already covers the surface-map half (an unknown screen id in a custom role's surface, which
  // renders read-only rather than hidden).
  //
  // The unrecognised STRING never rides, and on this family that is not a formality: a corrupt or tampered custom
  // role could carry anything at all in its capability list, and it is the one input here an attacker chooses.
  "role-capability", // a capability id the console's closed set does not know, stripped from a custom role
  "landing-screen", // a landing-screen id the router does not know, defaulted to Overview
  "owner-action-kind", // an owner-action kind the inbox has no label for, rendered as its raw id
  // The TOKEN-SOURCE CAPABILITY families, one per capability, in lockstep with the console.
  // They replace the single `token-source-flags`, which fired only when the engine advertised NOT ONE
  // capability. The four flags landed on four different dates, so every build in between advertises a strict
  // SUBSET, and a subset is not zero: an engine offering cf-config but not Workers recorded nothing and read
  // like a healthy one, which is exactly the build a rollback lands on. fieldFamily is in the ring's tuple key,
  // so the SET of rows is the evidence and the families do not coalesce.
  "token-source-tier", // the response carried NO tokenPresent field: an engine older than the account tier itself
  "token-source-cf-config", // a discovery token is present and the engine advertised no cf-config surface catalogue
  "token-source-workers", // ... and no Workers capability, so the Workers source vanishes from Add a source
  "token-source-stream", // ... and no Stream capability
  "token-source-images", // ... and no Images capability
  // The OVERVIEW CONTRACT-BREAK families. A partial engine payload that settles ok:true is masked by a
  // defensive default at every one of these sites, and the mask is indistinguishable from an ordinary absence:
  // a paying customer's licence tile reads Community / Fail-open off a payload that never carried a tier, the
  // cost card never projects because the run rows carried no byte fields, and the coverage grid reads all-unknown
  // off a downpipe list that was not an array. Every one of those is an ENGINE-CONSOLE CONTRACT BREAK, which is a
  // defect signal, and today it looks exactly like a quiet estate.
  "licence-payload", // the licence status settled ok with no tier/valid on it, defaulted to community/fail-open
  "downpipe-list", // the downpipe list settled ok and was absent or not an array, read as an honest unknown
  "run-cost-fields", // run rows carried no finite archiveBytesWritten/segmentsWritten, so no cost is projected
  // The INVITE-CAPABILITY family. A committed role grant that came back with no invite token AND no
  // inviteState is an engine that predates the registration-invite mint: the new member is authorised, has no
  // way to enrol a passkey, and the console silently fell back to the they are emailed if invites are
  // configured toast. An engine that DOES carry inviteState says already-enrolled for an existing member,
  // which is the legitimate no-link case and records nothing. Without this family the two are one silence.
  "invite-state",
  // The AUDIT FORWARD-COMPAT families. The audit table renders unrecognised target (newer engine?),
  // unknown method and raw internal field names when the engine has moved ahead of the console, and today
  // those fallbacks exist only on the operator's screen. Three families, not one: an unknown target kind, an
  // unknown auth method and an unlabelled target field are three different pieces of engine vocabulary the
  // console has not caught up with, and the fix (which console version to deploy) is proved by joining any of
  // them to the pack's consoleBuild and engine.version. The unrecognised STRING never rides.
  "audit-target",
  "audit-method",
  "audit-field-name",
] as const;
export type ClientDiagFieldFamily = (typeof CLIENT_DIAG_FIELD_FAMILIES)[number];

// drillAbort -- fleet-drill only (3). HOW the session ended. `none` is a member on purpose: a session that
// ran to completion must be TELLABLE from one that was cut short, and a ring that recorded only the bad endings
// would leave a clean partial drill and an aborted one carrying identical evidence, which is the gap.
export const CLIENT_DIAG_DRILL_ABORTS = ["none", "signed-out", "fleet-read-failed"] as const;
export type ClientDiagDrillAbort = (typeof CLIENT_DIAG_DRILL_ABORTS)[number];

// drillFact -- fleet-drill only (6, G287; op-key-canary-drill). WHICH of the session's counts the row carries;
// `count` carries it. skipped-no-run-id is the quiet one: a downpipe whose latest history row has no runId is
// dropped from the target list silently, so it is never drilled, and its absence from the drill evidence is
// identical to the absence of a pipe that has never been drilled at all. deferred is the break-glass-only
// posture refusal (missingBinding "operational-private", drill.ts): a downpipe the engine honestly declined to
// drill because it structurally cannot, recorded distinct from failed so a correctly-functioning break-glass-
// only fleet is never miscategorised as a fleet with failing drills.
export const CLIENT_DIAG_DRILL_FACTS = ["targeted", "passed", "failed", "deferred", "skipped-no-run-id", "rate-limit-exhausted"] as const;
export type ClientDiagDrillFact = (typeof CLIENT_DIAG_DRILL_FACTS)[number];

// The POSTURE round, group 3 vocabularies, mirroring the console's (src/lib/client-diag/vocab.ts). Every member
// here is one the CONSOLE emits: a member missing from this file is a row the receiver DROPS on arrival, so the
// browser recorded the fault, the customer sent the pack, and support sees nothing.

// ownerActionCode -- owner-action-refusal only (7). WHY a dual-control approve/reject did not go through.
// Every member is decided by the CONSOLE, from state it holds: this engine collapses every refusal it makes on
// the owner-action routes into ONE status (a plain thrown Error in the DO becomes a 400; only an AuthError
// becomes a 403), so the status can separate none of them and the console does not read the refusal prose.
//
// expired / already-decided REPLACE the old `terminal-state`, which was keyed on a 409/404/410 THESE ROUTES NEVER
// RETURN: it had zero producers while the gap's headline ticket (a proposal that expired and "just vanished")
// coalesced into engine-refused with the already-decided one. The console now re-reads its own inbox after a
// refusal: the listing drops terminal records, so an action that is GONE reached a terminal state, and the
// record's expiresAt says which. The two have opposite remedies (propose it again, versus read who decided it).
//
// identity-unresolved: the refusal landed while whoami had not resolved, so the console held NO identity to judge
// the caller by. Without it an unresolved caller was recorded as "not-owner", which asserts a fact nothing
// established. unreachable: the call got no answer from an engine at all, so no engine-side record can exist.
// R4: TWO MORE MEMBERS, both of them states the console used to file as something else.
// bare-token: the caller is on the ADMIN_TOKEN break-glass, which canApproveOwnerAction refuses by design (dual
// control needs an attributable approver). The console holds that fact before it calls, and it was landing in the
// generic engine-refused. answer-unreadable: the engine answered 2xx and the body would not parse, which on an
// approve means the action WAS taken; the console was recording it as `unreachable` ("no engine saw it, no
// engine-side record of it can exist"), which sends support away from an action that has already run.
// The console also stopped inferring not-owner from its own role mirror: it now records it only off the engine's
// own 403, and reads the action's fate only for a caller whose listing is complete (an owner), because the
// listing is caller-scoped and absence from it was otherwise true by construction for everybody else.
//
// AND A BARE 403 IS NOT ONE FACT: THIS ENGINE ANSWERS 403 FOUR WAYS ON THE SAME CALL, and the
// console now splits them by the SHAPE of the body this engine sends. not-owner is the route capability gate
// (router-core gate(): { error:"forbidden", required, have } -- the only 403 that names the caller as the one
// refused). engine-authz-refused is THIS DO's AuthError funnel (scheduler-do.ts: a bare { error:"forbidden" },
// anti-enumeration by design), whose live producer on an approve is a PROPOSER who lost owner between propose and
// approve, so the caller being told no is a perfectly good second owner and a not-owner row there is a lie.
// engine-csrf is the CSRF-origin check (router.ts), which pre-empts the route dispatch for EVERY cookie-borne
// non-GET request, so an engine deployed with CONSOLE_ORIGIN unset 403s every save in the console (the same fault
// this engine's own csrf-origin-unset auth-signal names). edge-blocked is a 403 carrying no refusal shape this
// engine emits (a Cloudflare WAF block page): the engine may never have seen the request.
export const CLIENT_DIAG_OWNER_ACTION_CODES = ["self-approval", "not-owner", "expired", "already-decided", "identity-unresolved", "bare-token", "engine-authz-refused", "engine-csrf", "edge-blocked", "engine-refused", "answer-unreadable", "unreachable"] as const;
export type ClientDiagOwnerActionCode = (typeof CLIENT_DIAG_OWNER_ACTION_CODES)[number];

// cspDirective / cspBlocked -- csp-violation only (8 + 5). The browser blocked a resource under the
// console's own CSP. Both are needed: the console's OWN asset blocked by its own policy (the stale-hashed-chunk
// incident) is {script-src, self} and a third-party injection attempt is {script-src, external}, and they are a
// broken deploy and a security incident told apart by nothing else.
// REMOVED: `frame-src`. The console's own policy (worker.ts buildCsp) states no
// frame-src and the console embeds no frames, so the browser can never name that directive to it and the console
// can never send this member. An injected off-origin frame is still carried, as `other`.
export const CLIENT_DIAG_CSP_DIRECTIVES = ["script-src", "style-src", "connect-src", "img-src", "font-src", "form-action", "other"] as const;
export type ClientDiagCspDirective = (typeof CLIENT_DIAG_CSP_DIRECTIVES)[number];
export const CLIENT_DIAG_CSP_BLOCKED = ["self", "inline", "eval", "external", "other"] as const;
export type ClientDiagCspBlocked = (typeof CLIENT_DIAG_CSP_BLOCKED)[number];

// cspInlineOrigin -- csp-violation only, and only on an inline block (2). Twin of the console's. It splits
// the two states that actually occur under the console's policy and that BOTH report blockedURI "inline": a
// stale pre-paint hash after a deploy (a broken deploy) and an injected inline script (an attack). The console
// reads its OWN pre-paint execution marker to decide, never anything from the violation report.
export const CLIENT_DIAG_CSP_INLINE_ORIGINS = ["sanctioned-prepaint", "unsanctioned"] as const;
export type ClientDiagCspInlineOrigin = (typeof CLIENT_DIAG_CSP_INLINE_ORIGINS)[number];

// deleteFate -- role-delete-impact only (2). Twin of the console's. WHETHER the custom-role delete the
// grant count belongs to was APPLIED or merely QUEUED by change control (HTTP 202, nothing written, nobody
// floored). Without it a queued proposal and an applied deletion are one row asserting a downgrade that may
// never happen.
export const CLIENT_DIAG_DELETE_FATES = ["applied", "queued-for-approval"] as const;
export type ClientDiagDeleteFate = (typeof CLIENT_DIAG_DELETE_FATES)[number];

// dropSurface / dropFact -- input-dropped only (2 + 2). The console silently discarded part of a paste
// before any request was made, so the engine never saw the dropped block. Both counts ride as separate rows:
// one of two certificates was dropped and one of nine are the same droppedCount and different tickets.
export const CLIENT_DIAG_DROP_SURFACES = ["idp-cert-paste", "coverage-inventory-paste"] as const;
export type ClientDiagDropSurface = (typeof CLIENT_DIAG_DROP_SURFACES)[number];
export const CLIENT_DIAG_DROP_FACTS = ["accepted", "dropped"] as const;
export type ClientDiagDropFact = (typeof CLIENT_DIAG_DROP_FACTS)[number];

// handoffClass -- handoff-dropped only (2). WHERE a wizard or deep-link hand-off lost the operator's pick.
// Twin of the console's CLIENT_DIAG_HANDOFF_CLASSES (3). It held five: prefill-zone-unmatched and
// prefill-account-unmatched were removed because no console screen emits a zone- or account-named deep link, so
// nothing could ever produce them, and the recorders that carried those names were firing on the ordinary
// Add-a-source click instead. Dead vocabulary reads like coverage; it is not.
// R3: `wizard-binding-lost` removed in lockstep with the console, for the same reason as the two
// before it. Its console recorder existed and typechecked, and it was unreachable twice over: the guard needed a
// chosenType of kv/r2/d1 and the wizard's radio rows write only workers/stream/images/artifacts, and the
// binding-backed kinds never reach that path at all (they are the checkbox selection, keyed BY the binding name,
// so the binding cannot go missing -- it is the map key). No console build could send it, so this receiver stops
// admitting it.
// R4: `wizard-account-lost` removed and replaced by TWO members. It asserted a loss between the
// wizard's steps, and the wizard cannot lose an account (every discovered-row apply() writes the account id in the
// same block as the binding, and Continue stays disabled until a row is picked); and it coalesced two opposite
// tickets into one row -- the wizard SENDS an accountless spec (there is an engine 400 to go and find) while the
// advanced editor refuses the save locally and makes NO REQUEST AT ALL. Same kind, same screen, same class, so
// they merged on the tuple key and the commoner buried the rarer. The classes now say which, so a support engineer
// knows whether the engine ever heard about it.
export const CLIENT_DIAG_HANDOFF_CLASSES = [
  "prefill-type-invalid",
  "wizard-spec-account-absent",
  "editor-refused-account-absent",
] as const;
export type ClientDiagHandoffClass = (typeof CLIENT_DIAG_HANDOFF_CLASSES)[number];

// ceremonyStep / ceremonyOutcome / ceremonyFault -- ceremony-step only (4 + 2 + 5). A browser-side key or
// enrolment ceremony step and how it ended, the product's deliberate no-custody blind spot. `ok` is a member
// because "the recovery codes were never saved" is answered by which row exists. NO KEY MATERIAL, share bytes,
// payload fragment, decode offset, N or threshold rides: the step, the outcome and a coarse fault class only.
export const CLIENT_DIAG_CEREMONY_STEPS = ["paper-roundtrip-check", "tier12-encrypt", "shamir-split", "recovery-codes-copy"] as const;
export type ClientDiagCeremonyStep = (typeof CLIENT_DIAG_CEREMONY_STEPS)[number];
export const CLIENT_DIAG_CEREMONY_OUTCOMES = ["ok", "failed"] as const;
export type ClientDiagCeremonyOutcome = (typeof CLIENT_DIAG_CEREMONY_OUTCOMES)[number];
// ---- the BLOCKED BROWSER STORE ----------------------------------------------------------------------
//
// storageArea -- storage-blocked only (2). WHICH store the browser refused. They are not interchangeable: a
// blocked localStorage loses the operator's PREFERENCES and the engine URL (every refresh re-points the
// console); a blocked sessionStorage loses their in-progress WORK (the wizard draft). One ticket says it keeps
// forgetting my engine, the other says it keeps losing my half-filled form, and the browser policies that
// cause them are set independently.
export const CLIENT_DIAG_STORAGE_AREAS = ["local", "session"] as const;
export type ClientDiagStorageArea = (typeof CLIENT_DIAG_STORAGE_AREAS)[number];

// storageOp -- storage-blocked only (3). WHICH operation the store refused. A store that READS but will not
// WRITE (a quota wall, a write-blocking policy) behaves completely differently from one that refuses even to be
// touched, and only the write half loses the operator's work.
export const CLIENT_DIAG_STORAGE_OPS = ["read", "write", "remove"] as const;
export type ClientDiagStorageOp = (typeof CLIENT_DIAG_STORAGE_OPS)[number];

// storageClass -- storage-blocked only (4). WHY the store refused, and the four are four different remedies:
//
//   denied          the host THREW on access: a third-party-cookie/storage policy, a locked-down enterprise
//                   profile, a private window with storage partitioned off. The remedy is a browser policy
//                   change, and it is the state the whole gap is about.
//   quota-exceeded  the store is writable and FULL. The remedy is to clear site data, and nothing about the
//                   customer's browser policy is wrong. Folding this into `denied` would send support chasing
//                   a group policy that does not exist.
//   unavailable     the API is not present in this host at all (an old embedded browser, a hardened runtime).
//   other           a throw the classifier could not place. It exists so the classifier is TOTAL and never has
//                   to guess: a fault it cannot name is named as unnamed, not as the nearest member.
//
// The classifier READS the exception only to SELECT one of these members, and returns the member. The message,
// the name and the stack are discarded at that boundary and enter no field.
export const CLIENT_DIAG_STORAGE_CLASSES = ["denied", "quota-exceeded", "unavailable", "other"] as const;
export type ClientDiagStorageClass = (typeof CLIENT_DIAG_STORAGE_CLASSES)[number];

// storageSurface -- storage-blocked only (7). WHAT THE CUSTOMER LOST, which is the half of the ticket the area
// and the class cannot answer. The gap's own scenario names three symptoms in one breath (lost wizards, an
// engine URL that will not stick, an auto-refresh that re-enables itself against a motion pause) and they are
// three surfaces, so they are three rows. The draft ID is never recorded: a draft id can carry a run id.
export const CLIENT_DIAG_STORAGE_SURFACES = [
  "draft", // an in-progress wizard/selection draft (sessionStorage): the operator's WORK
  "engine-url", // the connected engine URL (localStorage): the console re-asks for it on every refresh
  "theme", // the theme preference
  "motion-pref", // the rain/motion preference: an accessibility setting that will not stick is not cosmetic
  "refresh-pref", // the auto-refresh pause: it re-enables itself against a motion-sensitivity pause
  "view-mode", // the list/grid view mode
  "setup-state", // the onboarding wizard's progress: the operator is walked back to step one
] as const;
export type ClientDiagStorageSurface = (typeof CLIENT_DIAG_STORAGE_SURFACES)[number];

// ---- the TOPOLOGY MAP's RENDERER --------------------------------------------------------------------
//
// rendererMode -- renderer-degraded only (2). WHICH renderer was live. The console picks canvas2d when the
// browser gives it a 2d context and falls back to a static SVG topology when it does not; the fallback is the
// "the map is just a static diagram" ticket.
export const CLIENT_DIAG_RENDERER_MODES = ["canvas2d", "svg-fallback"] as const;
export type ClientDiagRendererMode = (typeof CLIENT_DIAG_RENDERER_MODES)[number];

// degradeCause -- renderer-degraded only (5). WHY the live view was not what it should be. Every member is a
// different answer down the phone, and `none` is the member that makes the others mean anything:
//
//   canvas-blocked   the browser refused a 2d context (graphics acceleration off, an extension blocking
//                    canvas). The map is the SVG fallback. The remedy is a browser setting.
//   raf-frozen       requestAnimationFrame never ticked within the freeze guard: an extension (or a throttled
//                    background tab policy) has frozen the animation loop. The map is canvas2d and DEAD, which
//                    reads to the customer exactly like a hung console.
//   css-anim-frozen  the page's CSS animations do not advance: the same class of extension, one layer up.
//   reduced-motion   a SINGLE STATIC FRAME because the operator asked for reduced motion (or the OS did). A
//                    LEGITIMATE state, recorded so support can say this is your accessibility setting, not a
//                    fault, and never counted as a browser fault.
//   none             the live view was running. Recorded so the pack can say the renderer WAS healthy: without
//                    it, a frozen map and a map the customer never opened carry identical evidence.
// unobserved: the map mounted in a document that was NOT VISIBLE, so the animation-loop reading
// was not taken. A hidden document suspends requestAnimationFrame while setTimeout keeps running, so the freeze
// guard fires and a healthy browser reads as raf-frozen; an ordinary backgrounded tab therefore manufactured the
// gap's own headline fault and coalesced with the real one. Telling it apart is what makes raf-frozen believable.
export const CLIENT_DIAG_DEGRADE_CAUSES = ["canvas-blocked", "raf-frozen", "css-anim-frozen", "reduced-motion", "unobserved", "none"] as const;
export type ClientDiagDegradeCause = (typeof CLIENT_DIAG_DEGRADE_CAUSES)[number];

export const CLIENT_DIAG_CEREMONY_FAULTS = ["webcrypto", "oom", "decode", "clipboard-denied", "other"] as const;
export type ClientDiagCeremonyFault = (typeof CLIENT_DIAG_CEREMONY_FAULTS)[number];

// ---- WHERE KEYBOARD FOCUS LANDED ---------------------------------------------------------------------
//
// focusOutcome -- focus-landing only (3). The population is navigations for which a screen DECLARED where
// focus belongs, which is exactly the tablist-owns-a-route population and nothing else; an ordinary route
// change declares nothing and records nothing, so this union never fires on the healthy common path.
//
//   honoured          the declared control was mounted and took focus. THE HEALTHY MEMBER, and the one that
//                     makes the others mean something: without it a tablist that is broken and a tablist the
//                     customer never touched are the same evidence (absence), which is the whole reason this
//                     surface was invisible.
//   dropped-detached  a screen declared where focus belongs and the named element was NOT CONNECTED when the
//                     shell read it, so focus fell back to <main>. THIS IS THE DEFECT, in the pack's own
//                     words: the tab moved, focus did not follow, and every further arrow key does nothing
//                     until the operator re-focuses the tablist by hand. It is the regression sentinel for a
//                     repair whose failure mode is a RACE (the shell's swap-and-focus runs in a later task
//                     than the render that scheduled the declaration, under a view transition), so it can
//                     come back from a change to the transition and never from a change to the tablist.
//   consumed-quiet    a quiet same-screen re-render consumed the declaration without moving focus at all.
//                     The intent is deliberately consumed there so it cannot leak forward onto the NEXT
//                     navigation, and the customer symptom is the same one: the tab did not take focus. Its
//                     own member because the remedy is different (an in-place re-render arriving on top of a
//                     tab activation), and folding it into dropped-detached would send support hunting a
//                     mount race that did not happen.
//
// Value-free by construction: three product constants, none derived from any DOM node, label, accessible name,
// selector, key or customer text.
export const CLIENT_DIAG_FOCUS_OUTCOMES = ["honoured", "dropped-detached", "consumed-quiet"] as const;
export type ClientDiagFocusOutcome = (typeof CLIENT_DIAG_FOCUS_OUTCOMES)[number];

export interface ClientDiagnosticRecord {
  kind: ClientDiagKind;
  screen: ClientDiagScreen;
  httpClass?: ClientDiagHttpClass; // engine-call only
  faultClass?: ClientDiagFaultClass; // engine-call / unhandled / boot-fault
  driftClass?: ClientDiagDriftClass; // contract-drift only
  reasonClass?: ClientDiagReasonClass; // bulk-outcome only
  applyClass?: ClientDiagApplyClass; // apply-outcome only
  capability?: ClientDiagCapability; // capability-fault only
  surface?: ClientDiagSurface; // capability-fault only
  capabilityOutcome?: ClientDiagCapabilityOutcome; // capability-fault only
  bootClass?: ClientDiagBootClass; // boot-fault only
  buildCheckClass?: ClientDiagBuildCheckClass; // console-build-check only
  rollbackClass?: ClientDiagRollbackClass; // console-rollback only
  gateBlockClass?: ClientDiagGateBlockClass; // restore-gate-blocked only
  fieldClass?: ClientDiagFieldClass; // wire-anomaly only
  anomaly?: ClientDiagAnomaly; // wire-anomaly only
  errorClass?: ClientDiagErrorClass; // unhandled / boot-fault
  faultSource?: ClientDiagFaultSource; // unhandled only
  transportClass?: ClientDiagTransportClass; // transport-fault only
  callClass?: ClientDiagCallClass; // read-degraded only
  obStep?: ClientDiagOnboardingStep; // onboarding-step only
  obOutcome?: ClientDiagOnboardingOutcome; // onboarding-step only
  obSecret?: ClientDiagOnboardingSecret; // onboarding-step / poll-exhausted only
  channelReasonClass?: ClientDiagChannelReasonClass; // update-channel-unverified only
  discoveryOutcome?: ClientDiagDiscoveryOutcome; // discovery-connect only
  claimResult?: ClientDiagClaimResult; // claim-exchange only
  adminOp?: ClientDiagAdminOp; // admin-write only
  writeOutcome?: ClientDiagWriteOutcome; // admin-write only
  recoveryOp?: ClientDiagRecoveryOp; // recovery-refusal only
  recoveryCode?: ClientDiagRecoveryCode; // recovery-refusal only
  intentClass?: ClientDiagIntentClass; // intent-dropped only
  probeSurface?: ClientDiagProbeSurface; // probe-outcome only
  probeOutcome?: ClientDiagProbeOutcome; // probe-outcome only
  formField?: ClientDiagFormField; // form-rejected only
  rejectOutcome?: ClientDiagRejectOutcome; // form-rejected only
  catalogueClass?: ClientDiagCatalogueClass; // catalogue-degraded only
  featureClass?: ClientDiagFeatureClass; // feature-probe only
  featureOutcome?: ClientDiagFeatureOutcome; // feature-probe only
  govGate?: ClientDiagGovGate; // gov-gate only
  skewClass?: ClientDiagSkewClass; // console-skew only
  bulkAction?: ClientDiagBulkAction; // bulk-outcome only
  materialClass?: ClientDiagMaterialClass; // material-rejected only
  contractClass?: ClientDiagContractClass; // contract-skew only
  fieldFamily?: ClientDiagFieldFamily; // contract-skew only
  drillAbort?: ClientDiagDrillAbort; // fleet-drill only
  drillFact?: ClientDiagDrillFact; // fleet-drill only
  ownerActionCode?: ClientDiagOwnerActionCode; // owner-action-refusal only
  cspDirective?: ClientDiagCspDirective; // csp-violation only
  cspBlocked?: ClientDiagCspBlocked; // csp-violation only
  cspInlineOrigin?: ClientDiagCspInlineOrigin; // csp-violation only, inline blocks only
  deleteFate?: ClientDiagDeleteFate; // role-delete-impact only
  dropSurface?: ClientDiagDropSurface; // input-dropped only
  dropFact?: ClientDiagDropFact; // input-dropped only
  handoffClass?: ClientDiagHandoffClass; // handoff-dropped only
  ceremonyStep?: ClientDiagCeremonyStep; // ceremony-step only
  ceremonyOutcome?: ClientDiagCeremonyOutcome; // ceremony-step only
  storageArea?: ClientDiagStorageArea; // storage-blocked only
  storageOp?: ClientDiagStorageOp; // storage-blocked only
  storageClass?: ClientDiagStorageClass; // storage-blocked only
  storageSurface?: ClientDiagStorageSurface; // storage-blocked only
  rendererMode?: ClientDiagRendererMode; // renderer-degraded only
  degradeCause?: ClientDiagDegradeCause; // renderer-degraded only
  focusOutcome?: ClientDiagFocusOutcome; // focus-landing only
  ceremonyFault?: ClientDiagCeremonyFault; // ceremony-step only
  count: number; // coalesce-repeat only; clamped non-negative int, cap COUNT_MAX
  firstMs: number; // performance.now offset (monotonic), clamped int
  lastMs: number; // performance.now offset (monotonic), clamped int
}

// The engine-side wrapper (I4 CLIENT-ASSERTED PROVENANCE): source/receivedAt/engineAttempts are stamped by
// the engine, never by the client. `source: 'client-asserted'` makes the signature attest the engine
// received this client blob at receivedAt, NEVER these events occurred. engineAttempts is a value-free
// denominator for the failure-RATIO signal. rollupByKind is the per-kind UNCAPPED true-count of valid
// records seen before the per-kind row cap, so tuples dropped by the cap still register as a number.
export interface ClientDiagnosticsSection {
  source: "client-asserted";
  receivedAt: string;
  engineAttempts?: number;
  records: ClientDiagnosticRecord[];
  rollupByKind?: Partial<Record<ClientDiagKind, number>>;
  // consoleBuild: WHICH CONSOLE BUILD the browser was running. The pack has always carried engine.version
  // and nothing at all about the console, so an audit row rendering unrecognised target (newer engine?) could
  // never be answered with deploy console X: the console's own version was not in the pack at any point.
  //
  // It is CLIENT-ASSERTED like every other field in this section (source says so), and it is admitted by a SHAPE
  // GATE, not a clamp: CONSOLE_BUILD_RE below admits a bare semantic version and nothing else, so a message, a
  // URL, an account id or a bucket name cannot enter this field at any length. A value that fails the gate is
  // dropped whole; it is never truncated in.
  consoleBuild?: string;
}

// CONSOLE_BUILD_RE is that shape gate, and it is the engine's OWN authority: the console applies the same regex
// before sending, and the engine does not take its word for it. A bare semver with an optional short
// pre-release tag, anchored at both ends.
export const CONSOLE_BUILD_RE = /^\d{1,4}\.\d{1,4}\.\d{1,4}(-[a-z0-9.]{1,16})?$/;

// Caps. PER_KIND_ROW_CAP newest-wins per kind; GLOBAL_ROW_CAP across all kinds; COUNT_MAX bounds each
// coalesce count; MS_MAX bounds a performance.now offset (~24.8 days, so ordering survives a long session);
// MAX_BODY_BYTES bounds the POST body BEFORE parse. The worst-case section at these caps is ~128 rows x
// ~100 bytes ~= 13 KB, in line with existing sections.
export const CLIENT_DIAG_PER_KIND_ROW_CAP = 32;
export const CLIENT_DIAG_GLOBAL_ROW_CAP = 128;
export const CLIENT_DIAG_COUNT_MAX = 1_000_000;
export const CLIENT_DIAG_MS_MAX = 2_147_483_647;
export const CLIENT_DIAG_MAX_BODY_BYTES = 32_768;
