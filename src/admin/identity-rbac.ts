// The capability + composable-custom-role layer of the engine governance backbone, split out of
// identity.ts so each module stays a coherent unit under 500 lines. This holds the Capability unit of
// authority, the ROLE_CAPABILITIES source-of-truth table, the can() primitive, the closed ALL_CAPABILITIES
// list + isCapability guard, the owner-reserved bar, the console presentation/surface hints, the custom-role
// record + proposal + the pure validateCustomRole guardrail + capabilitiesOfCustomRole. It imports only the
// role PRIMITIVES (identity-roles.ts) so there is no import cycle with identity.ts (which re-exports this
// surface and layers Caller/callerCan/WhoAmI on top). Behaviour is byte-identical to the original
// identity.ts: this code was MOVED verbatim, not changed.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit field declarations only.
// Mirrored read-only in the console (api.ts) so the two sides cannot drift.

import type { Role } from "./identity-roles.ts";
import { isRole } from "./identity-roles.ts";

// Capability is the explicit unit of authority a route gates on (contract section 1). Replacing the
// linear rank check with a capability map is what lets the two narrow roles hold a precise subset of
// powers (recovery-only, people-only) without sitting on the cumulative ladder. The router gates a
// route on a Capability via gate(caller, cap) -> can(caller.role, cap); the console mirrors the same
// map so client gating matches the engine exactly.
// restore.verify (restorability assurance) is a read-SAFE recoverability-proof capability: it gates the
// BLIND restore test and the KEYLESS integrity attestation, both of which prove a sealed archive can be
// recovered WITHOUT writing a byte back and WITHOUT ever surfacing plaintext. It is deliberately its OWN
// capability, granted to viewer and up, and it does NOT imply downpipe.read or restore.apply: proving an
// archive restores is a strictly weaker, side-effect-free act than reading downpipe config or applying a
// restore over live data. A role holding restore.verify alone can prove recoverability but cannot read
// content or write anything back (the blind test decrypts only to a discard sink; the keyless attest
// decrypts nothing at all). It sits alongside restore.dryrun (the existing read-safe preview).
export type Capability =
  | "downpipe.read" | "downpipe.write" | "downpipe.delete"
  | "run.trigger" | "drill.run"
  | "restore.dryrun" | "restore.verify" | "restore.request" | "restore.apply" | "restore.approve"
  | "roles.read" | "roles.write" | "access.policy"
  | "keys.ceremony"
  | "audit.read"
  | "notify.config" | "expiry.config" | "scheduledtest.config"
  | "reports.read"
  | "posture.read" | "posture.riskaccept";

// ROLE_CAPABILITIES is the SINGLE source of truth for authorisation (can() reads it; nothing else
// decides a per-route allow). It is the contract section-1 table verbatim. ReadonlySet so a consumer
// cannot mutate a role's grant at runtime. The four cumulative roles hold exactly their prior powers
// (so the existing route gates and validate-rbac outcomes are unchanged), plus the read-safe
// restore.verify granted from the viewer floor up: viewer = reads + dryrun + verify;
// operator = data ops + config (no apply, no people, no keys); approver = operator + apply + approve;
// owner = everything. The two narrow roles: restore-operator = recovery only; access-admin = people
// only. Owner-exclusive: keys.ceremony and posture.riskaccept.
export const ROLE_CAPABILITIES: Record<Role, ReadonlySet<Capability>> = {
  // Reads + restore dry-run + the read-safe restore.verify (blind test / keyless attest). The
  // least-privilege resting role; restore.verify is granted from viewer up because proving an
  // archive restores writes nothing and surfaces no plaintext, so it is as safe as a read.
  viewer: new Set<Capability>([
    "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
  ]),
  // Data operations and the operational config, plus raising a restore request; NO apply/approve,
  // NO people, NO keys. (Identical power to the pre-capability "operator" role, plus the read-safe
  // restore.verify it inherits from the viewer floor.)
  operator: new Set<Capability>([
    "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
    "downpipe.write", "downpipe.delete", "run.trigger", "drill.run",
    "notify.config", "expiry.config", "scheduledtest.config",
    "restore.request",
  ]),
  // Recovery only: the reads, drill, restore.verify, and the full restore lifecycle (request/apply/
  // approve), but it canNOT create/edit/delete or trigger downpipes, configure notify/expiry, manage
  // people or keys.
  "restore-operator": new Set<Capability>([
    "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
    "drill.run",
    "restore.request", "restore.apply", "restore.approve",
  ]),
  // Operator + the restore apply/approve. (Identical power to the pre-capability "approver" role, plus
  // the read-safe restore.verify it inherits from the viewer floor.)
  approver: new Set<Capability>([
    "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
    "downpipe.write", "downpipe.delete", "run.trigger", "drill.run",
    "notify.config", "expiry.config", "scheduledtest.config",
    "restore.request", "restore.apply", "restore.approve",
  ]),
  // People only: read everything the others read (including the read-safe restore.verify), plus manage
  // roles and the access policy; NO data write, NO restore apply, NO keys.
  "access-admin": new Set<Capability>([
    "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
    "roles.write", "access.policy",
  ]),
  // Everything. The break-glass holder; the only role with keys.ceremony and posture.riskaccept.
  owner: new Set<Capability>([
    "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
    "downpipe.write", "downpipe.delete", "run.trigger", "drill.run",
    "notify.config", "expiry.config", "scheduledtest.config",
    "restore.request", "restore.apply", "restore.approve",
    "roles.write", "access.policy",
    "keys.ceremony",
    "posture.riskaccept",
  ]),
};

// can is the authorisation primitive: does this role hold this capability? It is a single map+set
// lookup over ROLE_CAPABILITIES (the only source of truth). The router's gate() is can() plus the
// 403 shaping; the console mirrors can() so a client affordance is shown only when the server would
// allow it. A role absent from the table (impossible for the closed Role union, but defensive)
// confers nothing.
export function can(role: Role, capability: Capability): boolean {
  const caps = ROLE_CAPABILITIES[role];
  return caps?.has(capability);
}

// ---- Composable custom roles (additive on top of the six built-ins) ----------------------------
// A custom role is an account-defined, NAMED bundle of capabilities a creator composes for their own
// org (e.g. "kv-restorer", "compliance-reader"). It sits ALONGSIDE the six built-ins, never replacing
// them: the built-in ROLE_CAPABILITIES table above is the floor and is untouched, and a custom role is
// only ever REACHED by an explicit per-email grant or an IdP-group mapping that references its NAME.
// The authority a custom role confers is its own capability set folded EXACTLY like a built-in's set
// (callerCan() reads the resolved set, whatever its source). The hard guardrails (no privilege
// escalation, owner-reserved caps barred, owner is never a custom role, edit-needs-write) live in
// validateCustomRole below and are enforced at the DO write boundary, mirroring how setGroupRole bounds
// the group mapping at its boundary.

// ALL_CAPABILITIES is the closed list of every Capability, the value-level companion to the Capability
// union (the union is type-only and cannot be iterated at runtime). It is the universe a custom role's
// capability list is validated against (isCapability), and the set the no-escalation guard intersects
// the creator's holdings with. Kept in lockstep with the Capability union above; a new capability added
// there must be added here too (the validator asserts the two agree so they cannot drift).
export const ALL_CAPABILITIES: readonly Capability[] = [
  "downpipe.read", "downpipe.write", "downpipe.delete",
  "run.trigger", "drill.run",
  "restore.dryrun", "restore.verify", "restore.request", "restore.apply", "restore.approve",
  "roles.read", "roles.write", "access.policy",
  "keys.ceremony",
  "audit.read",
  "notify.config", "expiry.config", "scheduledtest.config",
  "reports.read",
  "posture.read", "posture.riskaccept",
];

// isCapability is the authority-boundary guard for a client-supplied capability string in a custom-role
// proposal, mirroring isRole: it rejects anything that is not one of the closed Capability values, so a
// crafted capability name cannot land in a stored custom role. It is a linear membership test over
// ALL_CAPABILITIES (the closed universe), which is small and fixed.
export function isCapability(v: unknown): v is Capability {
  return typeof v === "string" && (ALL_CAPABILITIES as readonly string[]).includes(v);
}

// OWNER_RESERVED_CAPABILITIES are the capabilities that may NEVER be placed into a custom role: the
// key ceremony (the highest-consequence cryptographic action) and accepting a posture risk (the
// owner's deliberate sign-off that a security check may legitimately fail). They are the owner's alone
// (only the owner built-in holds them, see ROLE_CAPABILITIES). Barring them from custom roles keeps the
// break-glass owner the single named holder of these two powers: a creator cannot carve a custom role
// that quietly grants them, even if the creator is themselves an owner (owner is never a custom role).
export const OWNER_RESERVED_CAPABILITIES: ReadonlySet<Capability> = new Set<Capability>([
  "keys.ceremony",
  "posture.riskaccept",
]);

// Presentation is the cosmetic mode the console renders a custom-role holder's UI in: "technical" is
// the full operator console; "shiny" is the simplified, reassurance-first surface. It is a presentation
// hint ONLY and carries NO authority (the capability set is the sole authority); the console reads it to
// pick a skin, the engine never gates on it.
export type Presentation = "technical" | "shiny";

// SurfaceMode is the per-screen visibility a custom role declares: "hidden" (the screen is not shown),
// "read" (shown read-only), or "edit" (shown with its write affordances). It is a CONSOLE hint, not the
// authority boundary: the engine still gates every write on the capability set, so a surface saying
// "edit" without the matching write capability is incoherent and is rejected at create time (see
// validateCustomRole / SCREEN_WRITE_CAPABILITY), and a surface that is more restrictive than the
// capabilities (e.g. "read" while the role holds the write cap) is allowed (the console simply hides an
// affordance the engine would have permitted, which is safe).
export type SurfaceMode = "hidden" | "read" | "edit";

// SCREEN_WRITE_CAPABILITY maps each console SCREEN a surface can address to the write Capability that an
// "edit" mode on that screen implies. It is the consistency contract behind the edit-requires-write-cap
// guardrail: declaring a screen editable in a custom role's surface is a promise the role can actually
// perform that screen's writes, so the validator requires the matching capability to be in the role's
// own set. A screen with no write side (a pure read/report screen) maps to null: "edit" is meaningless
// there and is rejected outright (there is nothing to edit). The screen names are the console's own
// route segments; they are the contract the console and the engine share, kept here as the single source
// of truth so the two cannot drift.
export const SCREEN_WRITE_CAPABILITY: Record<string, Capability | null> = {
  downpipes: "downpipe.write",
  restore: "restore.apply",
  approvals: "restore.approve",
  people: "roles.write",
  access: "access.policy",
  notify: "notify.config",
  expiry: "expiry.config",
  audit: null, // the audit trail is append-only by the engine; there is no console write side
  reports: null, // reports are read-only projections
  posture: null, // posture risk-accept is an owner-reserved cap and cannot be in a custom role
};

// isScreen guards a client-supplied screen name in a surface map against the known SCREEN_WRITE_CAPABILITY
// keys, so an unknown screen cannot be persisted in a custom role's surface (the console would not know
// how to render it, and an "edit" on an unknown screen could not be consistency-checked).
export function isScreen(v: unknown): v is keyof typeof SCREEN_WRITE_CAPABILITY {
  return typeof v === "string" && Object.hasOwn(SCREEN_WRITE_CAPABILITY, v);
}

// CUSTOM_ROLE_NAME_PATTERN bounds a custom-role NAME so it is a safe storage-key fragment (the record is
// stored under `customrole:<name>`) and is visually distinct from a built-in role (lowercase, no
// at-sign). It deliberately does not overlap the built-in role spellings: a name equal to a built-in is
// rejected separately (a custom role may never shadow or be confused with a built-in). 1 to 64 chars of
// lowercase letters, digits and hyphen, not starting or ending with a hyphen.
export const CUSTOM_ROLE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

// CustomRole is the stored record (DO key `customrole:<name>`). name is the canonical lowercased key;
// label is the human display name; capabilities is the role's authority set (a subset of the creator's
// own holdings, never containing an owner-reserved capability); surface is the per-screen console
// visibility; presentation is the cosmetic skin; landing is the screen the console opens on; createdBy
// is the verified email of the creator (null for the bare-token break-glass); createdAt is RFC-3339
// millis. It carries NO secret and NO key material, so it is redaction-safe like the role/group tables.
export interface CustomRole {
  name: string;
  label: string;
  capabilities: Capability[];
  surface: Record<string, SurfaceMode>;
  presentation: Presentation;
  landing: string;
  createdBy: string | null;
  createdAt: string;
}

// A custom-role proposal as it arrives from the console (every field client-supplied and untrusted).
// validateCustomRole turns a proposal into a stored CustomRole or a precise rejection reason.
export interface CustomRoleProposal {
  name?: unknown;
  label?: unknown;
  capabilities?: unknown;
  surface?: unknown;
  presentation?: unknown;
  landing?: unknown;
}

// validateCustomRole is the PURE guardrail the DO and the validators share, so the create path and any
// re-check can never compute the rules two different ways. Given a proposal and the CREATOR's own
// effective capability set, it returns either a fully-formed, redaction-safe CustomRole (the createdBy/
// createdAt are stamped by the caller, since this pure function has no identity or clock) or a precise
// reason string. The guardrails, in order:
//   1. name: a valid lowercased key that does NOT collide with a built-in role (no shadowing);
//   2. label: a bounded display string;
//   3. capabilities: a non-empty list of KNOWN capabilities, deduped;
//   4. OWNER-RESERVED bar: none of keys.ceremony / posture.riskaccept may appear (owner-only);
//   5. NO PRIVILEGE ESCALATION: every capability MUST be one the creator themselves holds (a creator
//      cannot mint a role more powerful than themselves);
//   6. surface: known screens mapped to known modes; and the EDIT-REQUIRES-WRITE-CAP consistency check:
//      a screen set to "edit" requires the screen's write capability (SCREEN_WRITE_CAPABILITY) to be in
//      the role's OWN capability set (and the screen must have a write side at all);
//   7. presentation: technical|shiny; landing: a screen the surface does not HIDE (you cannot land a
//      user on a screen you hid from them).
// It NEVER throws; the DO maps a non-CustomRole result to a 400, exactly as validateConfig's discipline.
// validateCustomRoleName checks the name (pattern + no built-in collision) and the label, returning the
// normalised pair or a reason.
function validateCustomRoleName(proposal: CustomRoleProposal): { ok: true; name: string; label: string } | { ok: false; reason: string } {
  if (typeof proposal.name !== "string") return { ok: false, reason: "name must be a string" };
  const name = proposal.name.trim().toLowerCase();
  if (!CUSTOM_ROLE_NAME_PATTERN.test(name)) {
    return { ok: false, reason: "name must be 1 to 64 chars of lowercase letters, digits and hyphen (not leading/trailing hyphen)" };
  }
  if (isRole(name)) {
    return { ok: false, reason: "name must not collide with a built-in role (viewer/operator/restore-operator/approver/access-admin/owner)" };
  }
  if (typeof proposal.label !== "string" || proposal.label.trim().length < 1 || proposal.label.length > 128) {
    return { ok: false, reason: "label must be 1 to 128 characters" };
  }
  return { ok: true, name, label: proposal.label.trim() };
}

// validateCustomRoleCapabilities enforces the TWO security invariants alongside membership/dedup: the
// OWNER-RESERVED BAR (an owner-reserved capability can never enter a custom role) and the NO-ESCALATION
// rule (the creator must hold every capability they grant). It returns the deduped capability list and the
// seen-set the surface check needs, or a reason.
function validateCustomRoleCapabilities(
  proposal: CustomRoleProposal,
  creatorCapabilities: ReadonlySet<Capability>,
): { ok: true; caps: Capability[]; seen: Set<Capability> } | { ok: false; reason: string; escalation?: "escalation-refused" | "owner-reserved" } {
  if (!Array.isArray(proposal.capabilities) || proposal.capabilities.length === 0) {
    return { ok: false, reason: "capabilities must be a non-empty array" };
  }
  const caps: Capability[] = [];
  const seen = new Set<Capability>();
  for (const c of proposal.capabilities) {
    if (!isCapability(c)) return { ok: false, reason: `unknown capability: ${typeof c === "string" ? c : "<non-string>"}` };
    // SECURITY: owner-reserved bar.
    // `escalation` tags the TWO refusals that are SECURITY events rather than validation ones. An
    // attempted privilege escalation through a custom role -- an access-admin composing a role that grants a
    // capability they do not themselves hold -- left NO evidence either way: the DO threw prose, the router
    // 400'd, and the pack could not say whether anyone had ever tried. "Someone attempted to escalate" and
    // "nobody has ever attempted to escalate" were the same empty pack.
    if (OWNER_RESERVED_CAPABILITIES.has(c)) {
      return { ok: false, reason: `${c} is owner-reserved and cannot be placed in a custom role`, escalation: "owner-reserved" };
    }
    // SECURITY: no privilege escalation: the creator must hold every capability they grant.
    if (!creatorCapabilities.has(c)) {
      return { ok: false, reason: `cannot grant ${c}: the creator does not hold it`, escalation: "escalation-refused" };
    }
    if (!seen.has(c)) {
      seen.add(c);
      caps.push(c);
    }
  }
  return { ok: true, caps, seen };
}

// validateCustomRoleSurface validates the optional surface map and the EDIT-REQUIRES-WRITE-CAP consistency
// check (an editable screen must be backed by the role holding that screen's write capability, and the
// screen must have a write side at all). It returns the screen->mode map or a reason.
function validateCustomRoleSurface(
  proposal: CustomRoleProposal,
  seen: ReadonlySet<Capability>,
): { ok: true; surface: Record<string, SurfaceMode> } | { ok: false; reason: string } {
  const surface: Record<string, SurfaceMode> = {};
  if (proposal.surface === undefined) return { ok: true, surface };
  if (typeof proposal.surface !== "object" || proposal.surface === null || Array.isArray(proposal.surface)) {
    return { ok: false, reason: "surface must be an object mapping screen to hidden/read/edit" };
  }
  for (const [screen, modeRaw] of Object.entries(proposal.surface as Record<string, unknown>)) {
    if (!isScreen(screen)) return { ok: false, reason: `unknown surface screen: ${screen}` };
    if (modeRaw !== "hidden" && modeRaw !== "read" && modeRaw !== "edit") {
      return { ok: false, reason: `surface mode for ${screen} must be hidden/read/edit` };
    }
    if (modeRaw === "edit") {
      // isScreen guarantees the key exists, so the lookup is null (no write side) or a Capability;
      // the undefined arm is defensive (it can only arise if the table and isScreen ever drift) and
      // is treated as "no write side" so it fails closed rather than skipping the consistency check.
      const writeCap = SCREEN_WRITE_CAPABILITY[screen];
      if (writeCap === null || writeCap === undefined) {
        return { ok: false, reason: `screen ${screen} has no write surface and cannot be set to edit` };
      }
      if (!seen.has(writeCap)) {
        return { ok: false, reason: `screen ${screen} is set to edit but the role lacks ${writeCap}` };
      }
    }
    surface[screen] = modeRaw;
  }
  return { ok: true, surface };
}

export function validateCustomRole(
  proposal: CustomRoleProposal,
  creatorCapabilities: ReadonlySet<Capability>,
): { ok: true; role: Omit<CustomRole, "createdBy" | "createdAt"> } | { ok: false; reason: string; escalation?: "escalation-refused" | "owner-reserved" } {
  const named = validateCustomRoleName(proposal);
  if (!named.ok) return named;
  const capsResult = validateCustomRoleCapabilities(proposal, creatorCapabilities);
  if (!capsResult.ok) return capsResult;
  const surfaceResult = validateCustomRoleSurface(proposal, capsResult.seen);
  if (!surfaceResult.ok) return surfaceResult;
  const { surface } = surfaceResult;
  // presentation + landing
  const presentation = proposal.presentation ?? "technical";
  if (presentation !== "technical" && presentation !== "shiny") {
    return { ok: false, reason: "presentation must be technical or shiny" };
  }
  if (typeof proposal.landing !== "string" || !isScreen(proposal.landing)) {
    return { ok: false, reason: "landing must be a known screen" };
  }
  const landing = proposal.landing;
  // You cannot land a user on a screen you hid from them (a hidden landing would render nothing).
  if (surface[landing] === "hidden") {
    return { ok: false, reason: `landing screen ${landing} is hidden in the surface` };
  }
  return { ok: true, role: { name: named.name, label: named.label, capabilities: capsResult.caps, surface, presentation, landing } };
}

// capabilitiesOfCustomRole materialises a stored custom role's capability list into a ReadonlySet for
// the same has()-based authorisation the built-in ROLE_CAPABILITIES sets use, so a custom-role caller is
// gated EXACTLY like a built-in (callerCan reads whichever set applies). It re-applies the owner-reserved
// bar defensively at READ time: even a tampered stored record that somehow held an owner-reserved
// capability could never confer it, mirroring capGroupRole's resolution-time re-application of the group
// owner cap.
// THE TAMPER SIGNAL THE CLAMP ERASED. capabilitiesOfCustomRole re-applies the owner-reserved bar at
// READ time, so a stored custom role that somehow HOLDS an owner-reserved capability can never confer it. The
// clamp is right. But a stored role can only hold an owner-reserved capability if something wrote one there,
// and the write path refuses to -- so a drop here means the RECORD WAS TAMPERED WITH, and dropping it silently
// destroys the only evidence of that. This counts the drop (never the capability, the role name or the label).
export function customRoleReservedCapabilityDrops(role: CustomRole): number {
  let dropped = 0;
  for (const c of role.capabilities) if (isCapability(c) && OWNER_RESERVED_CAPABILITIES.has(c)) dropped++;
  return dropped;
}

export function capabilitiesOfCustomRole(role: CustomRole): ReadonlySet<Capability> {
  const out = new Set<Capability>();
  for (const c of role.capabilities) {
    if (isCapability(c) && !OWNER_RESERVED_CAPABILITIES.has(c)) out.add(c);
  }
  return out;
}
