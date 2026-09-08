// Prove the COMPOSABLE CUSTOM ROLES feature, end to end and SERVER-SIDE, with in-memory doubles
// only. No network, no deploy, no cost. Run:
//   node test/validate-custom-roles.ts
//
// A custom role is an account-defined NAMED capability bundle that sits ON TOP of the six built-in
// roles (the built-ins are untouched). It is reachable only by an explicit per-email grant or an
// IdP-group mapping that references its NAME, and its authority is its own capability set, folded at
// resolution EXACTLY like a built-in's set. What this proves (the guardrail claims the task pins):
//  - NO PRIVILEGE ESCALATION: a creator cannot put a capability into a custom role they do not
//    themselves hold (the access-admin who holds neither downpipe.write nor restore.apply is refused
//    a role that bundles them); an owner CAN compose those, because the owner holds them;
//  - OWNER-RESERVED bar: keys.ceremony and posture.riskaccept can NEVER go into a custom role, even
//    for the owner (they stay the owner's named, non-delegable powers);
//  - EDIT-REQUIRES-WRITE-CAP: a surface that marks a screen "edit" is rejected unless the role holds
//    that screen's write capability; "read"/"hidden" on the same screen is fine without it;
//  - OWNER IS NEVER A CUSTOM ROLE: a name colliding with a built-in (incl. owner) is rejected;
//  - RESOLUTION FOLDS THE CAPS: a per-email grant referencing a custom role lifts the holder to
//    EXACTLY that role's capabilities (the actual route gate honours it, not just whoami), and an
//    IdP-group mapping referencing a custom role does the same; deleting the role drops the holder
//    back to the viewer floor (never fails open);
//  - ADDITIVE: an account with no custom role behaves exactly as before; a built-in caller carries
//    no capability set and is gated by can(role, cap) unchanged;
//  - AUDIT: every custom-role create/delete/assign is recorded as a redaction-safe custom-role-change
//    in the tamper-evident chain (name + capability count only, never the capability list);
//  - DEFENCE IN DEPTH: the DO re-resolves the creator's OWN capability set (never a forwarded set) and
//    re-applies the guardrails, so a router-bypassing caller cannot escalate.
//
// The Access path is driven with a forged-but-correctly-signed RS256 JWT verified against a
// controlled JWKS served by a stubbed global fetch, so authorise() runs its REAL verification and
// resolves a REAL verified identity at the chosen role, exercising the production router + DO code
// path rather than a shim (the same technique as validate-group-roles.ts / validate-rbac.ts).

import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { validateCustomRole, ROLE_CAPABILITIES, type Capability, type Caller } from "../src/admin/identity.ts";
import { gate } from "../src/admin/router-core.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";
// MockStorage: the shared DO storage double (test/mock-storage.ts), not a local copy. It implements both
// storage.get() overloads (the single-key form and the array-of-keys batch form findRunRing uses), which
// destinationsForRun's DR/replica-fallback lookup needs.
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, stub };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ------------------------
const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "custom-roles-test-aud";
const KID = "custom-roles-kid-1";

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

const OWNER = "owner@acme.example";
const PEOPLE = "people@acme.example"; // an access-admin: holds roles.write + access.policy, NOT downpipe.write / restore.apply
const ALICE = "alice@acme.example"; // a plain caller we will grant a custom role
const BOB = "bob@acme.example"; // a caller we will lift via a group->custom-role mapping
const CAROL = "carol@acme.example"; // a stable identity reused across several proofs
const G_KVTEAM = "kv-restore-team"; // an IdP group we will map to a custom role
const ONE_HOUR_S = 3600;
const ONE_DAY_S = 24 * 3600;
const ONE_WEEK_S = 7 * 24 * 3600;

type Who = {
  method: string;
  email: string | null;
  role: string;
  roleSource: string;
  groups: string[];
  isOnlyOwner: boolean;
  customRole?: { name: string; label: string; capabilities: string[]; presentation: string; landing: string };
  capabilities?: string[];
};

// The shared end-to-end harness threaded through the PROOF helpers: the in-memory scheduler/DO, an
// authenticated `call`, and a `whoami` read. The PROOF blocks mutate DO state in order, so each helper
// is awaited in sequence from main().
interface CustomRolesCtx {
  sched: ReturnType<typeof makeScheduler>;
  accessEnv: () => Env;
  call: (email: string, method: "GET" | "POST", path: string, body?: unknown, jwtOpts?: { groups?: unknown }) => Promise<Response>;
  whoami: (email: string, jwtOpts?: { groups?: unknown }) => Promise<Who>;
}

async function buildCustomRolesCtx(): Promise<CustomRolesCtx> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  const tokenFor = async (email: string, opts?: { groups?: unknown }): Promise<string> => {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    // Authorisation keys on the stable subject (iss+"|"+sub), so every token carries a sub (a stable
    // per-email value so each distinct email is a distinct subject).
    const claims: Record<string, unknown> = { iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` };
    if (opts && "groups" in opts) claims["groups"] = opts.groups;
    const body = jwtPart(claims);
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  };

  // The restore-approval gate is OWNER-OPT-IN and OFF by default; this file exercises it, so it arms it.
  const sched = makeScheduler();
  await sched.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
  const accessEnv = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;

  const call: CustomRolesCtx["call"] = async (email, method, path, body, jwtOpts) => {
    const assertion = await tokenFor(email, jwtOpts);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  };

  const whoami: CustomRolesCtx["whoami"] = async (email, jwtOpts) => (await (await call(email, "GET", "/admin/whoami", undefined, jwtOpts)).json()) as Who;

  return { sched, accessEnv, call, whoami };
}

// Bootstrap OWNER as the first Access caller (-> Owner) and make PEOPLE an access-admin.
async function bootstrapPrincipals(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    const who = await whoami(OWNER);
    ok("bootstrap: first Access caller is Owner", who.role === "owner");
  }
  // Make PEOPLE an access-admin (holds access.policy so it may compose custom roles, but holds NEITHER
  // downpipe.write NOR restore.apply, so the no-escalation guard has real teeth against it).
  {
    const r = await call(OWNER, "POST", "/admin/roles", { email: PEOPLE, role: "access-admin" });
    ok("Owner grants PEOPLE the access-admin role (200)", r.status === 200);
    const who = await whoami(PEOPLE);
    ok("PEOPLE resolves to access-admin", who.role === "access-admin");
  }
}

// ---- PROOF 0: ADDITIVE / built-in unchanged --------------------------------------------
async function proveAdditive(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    // With no custom role defined or assigned, ALICE is a plain viewer carrying NO capability set: the
    // built-in path (can(role, cap)) is unchanged.
    const who = await whoami(ALICE);
    ok("a caller with no custom role is the viewer default (additive: built-ins unchanged)", who.role === "viewer" && who.roleSource === "default");
    ok("a built-in caller carries no resolved capability set", who.capabilities === undefined && who.customRole === undefined);
    // The empty catalogue is readable and empty.
    const list = (await (await call(OWNER, "GET", "/admin/custom-roles")).json()) as unknown[];
    ok("the custom-role catalogue starts empty", Array.isArray(list) && list.length === 0);
  }
}

// ---- PROOF 1: NO PRIVILEGE ESCALATION ---------------------------------------------------
async function proveNoEscalation(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  {
    // PEOPLE (access-admin) holds access.policy so MAY compose custom roles, but does NOT hold
    // downpipe.write. A custom role bundling downpipe.write is a privilege escalation and is refused.
    const escalate = await call(PEOPLE, "POST", "/admin/custom-roles", {
      name: "kv-restorer",
      label: "KV restorer",
      capabilities: ["downpipe.read", "downpipe.write"],
      landing: "downpipes",
    });
    const eb = (await escalate.json()) as { error?: string };
    ok("a creator cannot put a capability they do not hold into a custom role (400)", escalate.status === 400);
    ok("the rejection names the escalation (does not hold downpipe.write)", typeof eb.error === "string" && /downpipe\.write/.test(eb.error) && /does not hold/.test(eb.error));
    // Nothing was stored.
    const list = (await (await call(OWNER, "GET", "/admin/custom-roles")).json()) as Array<{ name: string }>;
    ok("the escalating role was not stored", !list.some((r) => r.name === "kv-restorer"));

    // The OWNER holds downpipe.write + restore.apply, so the SAME role IS allowed for the owner: the
    // guard is about the CREATOR's holdings, not a blanket ban.
    const allowed = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "kv-restorer",
      label: "KV restorer",
      capabilities: ["downpipe.read", "downpipe.write", "restore.apply", "restore.request", "restore.approve"],
      landing: "restore",
      presentation: "shiny",
      surface: { restore: "edit", downpipes: "read" },
    });
    ok("the owner (who holds the caps) CAN compose the same role (200)", allowed.status === 200);
  }
}

// ---- PROOF 2: OWNER-RESERVED capabilities barred ---------------------------------------
async function proveOwnerReservedBarred(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  {
    // keys.ceremony and posture.riskaccept can never go into a custom role, even for the OWNER.
    for (const cap of ["keys.ceremony", "posture.riskaccept"] as const) {
      const r = await call(OWNER, "POST", "/admin/custom-roles", {
        name: "danger",
        label: "danger",
        capabilities: ["downpipe.read", cap],
        landing: "downpipes",
      });
      const b = (await r.json()) as { error?: string };
      ok(`owner-reserved ${cap} cannot go into a custom role (400)`, r.status === 400);
      ok(`the rejection names ${cap} as owner-reserved`, typeof b.error === "string" && new RegExp(cap.replace(".", "\\.")).test(b.error) && /owner-reserved/.test(b.error));
    }
    const list = (await (await call(OWNER, "GET", "/admin/custom-roles")).json()) as Array<{ name: string }>;
    ok("the owner-reserved role was not stored", !list.some((r) => r.name === "danger"));
  }
}

// ---- PROOF 3: EDIT-REQUIRES-WRITE-CAP ---------------------------------------------------
async function proveEditRequiresWriteCap(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  {
    // A surface marking "people" editable requires roles.write; a role without it is rejected. The
    // OWNER holds roles.write, so the role's capability list deciding this is the ROLE's own set.
    const noWrite = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "auditor-edit",
      label: "Auditor (edit)",
      capabilities: ["audit.read", "reports.read"], // no roles.write
      surface: { people: "edit" }, // claims to edit people without the write cap
      landing: "audit",
    });
    const nb = (await noWrite.json()) as { error?: string };
    ok("a surface 'edit' without the matching write capability is rejected (400)", noWrite.status === 400);
    ok("the rejection names the missing write cap (roles.write)", typeof nb.error === "string" && /roles\.write/.test(nb.error));

    // The SAME role with the screen set to "read" (not edit) is fine without the write cap.
    const readOK = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "auditor-read",
      label: "Auditor (read)",
      capabilities: ["audit.read", "reports.read"],
      surface: { people: "read", audit: "read" },
      landing: "audit",
      presentation: "technical",
    });
    ok("the same screen set to 'read' is allowed without the write cap (200)", readOK.status === 200);

    // A pure no-write screen (reports) cannot be 'edit' at all.
    const reportsEdit = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "report-edit",
      label: "report edit",
      capabilities: ["reports.read"],
      surface: { reports: "edit" },
      landing: "reports",
    });
    const re = (await reportsEdit.json()) as { error?: string };
    ok("a screen with no write side cannot be set to edit (400)", reportsEdit.status === 400 && typeof re.error === "string" && /no write surface/.test(re.error));

    // The PURE validateCustomRole drives the same outcome directly (the guardrail is a shared pure fn).
    const pure = validateCustomRole(
      { name: "x", label: "x", capabilities: ["audit.read"], surface: { people: "edit" }, landing: "audit" },
      new Set<Capability>(["audit.read"]),
    );
    ok("the pure validateCustomRole rejects edit-without-write directly", pure.ok === false && /roles\.write/.test((pure as { reason: string }).reason));
  }
}

// ---- PROOF 4: OWNER IS NEVER A CUSTOM ROLE (no shadowing a built-in name) ---------------
async function proveNoBuiltinShadowing(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  {
    for (const name of ["owner", "viewer", "access-admin"] as const) {
      const r = await call(OWNER, "POST", "/admin/custom-roles", {
        name,
        label: name,
        capabilities: ["downpipe.read"],
        landing: "downpipes",
      });
      const b = (await r.json()) as { error?: string };
      ok(`a custom role cannot shadow the built-in name '${name}' (400)`, r.status === 400 && typeof b.error === "string" && /built-in role/.test(b.error));
    }
  }
}

// ---- PROOF 5: RESOLUTION FOLDS THE CAPS (per-email grant) -------------------------------
async function provePerEmailResolution(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    // Assign the kv-restorer custom role (created in PROOF 1) to ALICE via a per-email grant.
    const assign = await call(OWNER, "POST", "/admin/roles", { email: ALICE, customRole: "kv-restorer" });
    ok("Owner assigns a custom role to a member by name (200)", assign.status === 200);

    // ALICE now resolves to the custom role: roleSource 'custom', role floored at viewer, and the
    // resolved capability set is EXACTLY the role's (folded like a built-in).
    const who = await whoami(ALICE);
    ok("the custom-role holder reports roleSource 'custom'", who.roleSource === "custom");
    ok("the custom-role holder's built-in role is the viewer floor", who.role === "viewer");
    ok("whoami surfaces the custom-role record", who.customRole?.name === "kv-restorer");
    ok("the resolved capability set includes the role's caps (restore.apply)", Array.isArray(who.capabilities) && who.capabilities.includes("restore.apply"));
    // The viewer floor's read caps are folded in too (additive over the floor), but NOT downpipe.delete
    // (the role did not include it), proving the set is the role's bundle, not a built-in role's.
    ok("the set does NOT include a capability the role did not bundle (downpipe.delete)", !(who.capabilities ?? []).includes("downpipe.delete"));

    // The lift is REAL server-side: ALICE may now APPLY a restore (restore.apply), which a plain viewer
    // cannot. We drive the actual route gate, not just whoami. (The apply then needs an approval, so a
    // 403 'restore not approved' is the GATE PAST the capability check; a capability denial would be a
    // 403 forbidden naming restore.apply, which is what we assert is NOT returned.)
    // runId must be a canonical ULID (rejected before any object-key template), so the
    // capability/dual-control proof below needs a validly-shaped placeholder.
    const apply = await call(ALICE, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    const ab = (await apply.json()) as { error?: string; required?: string };
    ok("the custom-role holder passes the restore.apply CAPABILITY gate (not a capability 403)", !(apply.status === 403 && ab.required === "restore.apply"));
    ok("the custom-role holder is stopped only by dual control (awaiting approval), proving the cap held", apply.status === 403 && ab.error === "restore not approved");

    // A capability the role does NOT hold is still refused: ALICE cannot delete a downpipe (the role
    // bundles downpipe.write was NOT granted to kv-restorer; it has restore caps + downpipe.read only).
    const del = await call(ALICE, "POST", "/admin/downpipes/delete", { id: "dp-x" });
    const db = (await del.json()) as { required?: string };
    ok("a capability the custom role lacks is refused (downpipe.delete)", del.status === 403 && db.required === "downpipe.delete");
  }
}

// ---- PROOF 6: RESOLUTION FOLDS THE CAPS (IdP-group mapping) -----------------------------
async function proveGroupResolution(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    // Map an IdP group to the same custom role; BOB presenting that group resolves to the role.
    const map = await call(OWNER, "POST", "/admin/group-roles", { group: G_KVTEAM, customRole: "kv-restorer" });
    ok("Owner maps an IdP group to a custom role by name (200)", map.status === 200);
    const who = await whoami(BOB, { groups: [G_KVTEAM] });
    ok("a caller in the mapped group resolves to the custom role", who.roleSource === "custom" && who.customRole?.name === "kv-restorer");
    ok("the group-conferred custom role folds the same capability set (restore.apply)", (who.capabilities ?? []).includes("restore.apply"));
    // Without the group claim, BOB is back to the viewer default (additive per token).
    const without = await whoami(BOB);
    ok("the same caller WITHOUT the group claim is the viewer default (mapping is additive)", without.role === "viewer" && without.roleSource === "default" && without.capabilities === undefined);
  }
}

// ---- PROOF 7: DELETING THE ROLE DROPS HOLDERS TO THE VIEWER FLOOR (never fails open) ----
async function proveDeleteDropsToFloor(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    // Delete the kv-restorer role; ALICE still has the dangling grant, but resolution ignores a deleted
    // role and drops her to the viewer floor (least privilege), never failing open to the old caps.
    const del = await call(OWNER, "POST", "/admin/custom-roles/delete", { name: "kv-restorer" });
    ok("Owner deletes a custom role (200, deleted:true)", del.status === 200 && (await del.json() as { deleted: boolean }).deleted === true);
    const who = await whoami(ALICE);
    ok("a holder of a DELETED custom role drops to the viewer floor (never fails open)", who.role === "viewer" && who.roleSource === "default" && who.capabilities === undefined);
    // The capability really is gone: the apply is now a capability 403 naming restore.apply.
    // a validly-shaped runId so this hits the capability gate, not the earlier shape check.
    const apply = await call(ALICE, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    const ab = (await apply.json()) as { required?: string };
    ok("the dropped holder is refused restore.apply at the capability gate", apply.status === 403 && ab.required === "restore.apply");
  }
}

// ---- PROOF 8: DEFENCE IN DEPTH (DO re-resolves the creator's own caps) ------------------
async function proveDefenceInDepth(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  {
    // A non-access-policy caller (ALICE, viewer) is refused the custom-role write at the router (403).
    const r = await call(ALICE, "POST", "/admin/custom-roles", { name: "sneaky", label: "sneaky", capabilities: ["downpipe.read"], landing: "downpipes" });
    const b = (await r.json()) as { error?: string; required?: string };
    ok("a non-access-policy caller is refused the custom-role write (403)", r.status === 403);
    ok("the 403 is the forbidden capability gate naming access.policy", b.error === "forbidden" && b.required === "access.policy");

    // PEOPLE (access-admin) MAY write a custom role, but the DO re-resolves PEOPLE's OWN capability set
    // (which lacks downpipe.write), so PEOPLE still cannot escalate even though they passed the gate.
    const escalate = await call(PEOPLE, "POST", "/admin/custom-roles", {
      name: "people-escalate",
      label: "x",
      capabilities: ["downpipe.write"],
      landing: "downpipes",
    });
    ok("an access-admin still cannot escalate via a custom role (DO re-resolves their own caps)", escalate.status === 400);
  }
}

// ---- PROOF 8b: a custom-role caller with people powers is NOT an escalation ladder ------
async function provePeoplePowersNotLadder(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    // Compose a custom role that bundles roles.write + access.policy (the owner holds both, so it is a
    // legal composition) and assign it to a fresh caller. That caller can MANAGE people, but because
    // their resolved built-in role is the viewer FLOOR (never owner), the owner-escalation guard must
    // still stop them granting the owner built-in role or composing a role above their own caps.
    const compose = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "people-manager",
      label: "People manager",
      capabilities: ["roles.read", "roles.write", "access.policy"],
      surface: { people: "edit", access: "edit" },
      landing: "people",
    });
    ok("the owner composes a people-manager custom role bundling roles.write + access.policy (200)", compose.status === 200);
    const assign = await call(OWNER, "POST", "/admin/roles", { email: CAROL, customRole: "people-manager" });
    ok("the owner assigns people-manager to CAROL (200)", assign.status === 200);
    // CAROL holds roles.write via the custom role, so she passes the roles.write GATE...
    const who = await whoami(CAROL);
    ok("CAROL resolves to the people-manager custom role with roles.write", (who.capabilities ?? []).includes("roles.write"));
    // ...but she is the viewer FLOOR, so she CANNOT grant the owner built-in role (anti-escalation).
    const grantOwner = await call(CAROL, "POST", "/admin/roles", { email: "victim@acme.example", role: "owner" });
    const gb = (await grantOwner.json()) as { error?: string };
    ok("a custom-role holder with roles.write cannot grant the owner role (403 anti-escalation)", grantOwner.status === 403 && gb.error === "forbidden" && !/only an Owner/.test(JSON.stringify(gb)));
    // And she cannot compose a NEW custom role that bundles a capability she does not hold (downpipe.write).
    const composeEscalate = await call(CAROL, "POST", "/admin/custom-roles", {
      name: "carol-escalate",
      label: "x",
      capabilities: ["downpipe.write"],
      landing: "downpipes",
    });
    ok("a custom-role holder cannot compose a role bundling a capability they lack (no escalation)", composeEscalate.status === 400);
    // ...and ASSIGNMENT is the second door the within-authority guard closes: granting a built-in role
    // whose caps she does NOT hold is refused too. CAROL (people-manager: roles.read/roles.write/
    // access.policy) lacks downpipe.write, so granting operator is refused 400 NAMING the missing cap,
    // even though she passes the roles.write gate. This is the assign-side mirror of the compose-side guard.
    const grantOperator = await call(CAROL, "POST", "/admin/roles", { email: "newhire@acme.example", role: "operator" });
    const goBody = (await grantOperator.json()) as { error?: string };
    ok("a custom-role holder with roles.write CANNOT grant a role conferring caps it lacks (operator, 403)", grantOperator.status === 403 && goBody.error === "forbidden" && !/downpipe\.write/.test(JSON.stringify(goBody)) && !/do not hold/.test(JSON.stringify(goBody)));
    ok("the refused operator grant did not persist (newhire was not created)", !((await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string }>).some((e) => e.email === "newhire@acme.example"));
    // But she CAN perform a WITHIN-AUTHORITY people write. No built-in role is a subset of her people-only
    // bundle (even viewer carries downpipe.read etc.), so the within-authority grant is a CUSTOM role whose
    // caps ARE a subset of hers: the owner composes "policy-reader" = {roles.read, access.policy}, and CAROL
    // assigns it (200), proving the guard blocks only escalation, not legitimate delegation she can back.
    const composeWithin = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "policy-reader",
      label: "Policy reader",
      capabilities: ["roles.read", "access.policy"],
      landing: "access",
    });
    ok("the owner composes a policy-reader role whose caps are a subset of CAROL's (200)", composeWithin.status === 200);
    const grantWithin = await call(CAROL, "POST", "/admin/roles", { email: "newhire@acme.example", customRole: "policy-reader" });
    ok("the custom-role holder CAN grant a custom role whose caps are a subset of its own (within authority, 200)", grantWithin.status === 200);
  }
}

// ---- PROOF 9: AUDIT recorded for create / assign / delete ------------------------------
async function proveAuditRecorded(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  {
    const auditResp = await call(OWNER, "GET", "/admin/audit?action=custom-role-change&limit=100");
    const { events } = (await auditResp.json()) as { events: AuditEvent[] };
    ok("the audit chain holds custom-role-change events", events.length > 0 && events.every((e) => e.action === "custom-role-change"));
    const kvr = events.filter((e) => e.target.kind === "customrole" && e.target.name === "kv-restorer");
    // kv-restorer was created (PROOF 1) with 5 capabilities; the create + the two ASSIGNS (the per-email
    // grant and the group mapping) each record that real count, never the cap list (the assign paths audit
    // the role's actual capability count, not a misleading 0).
    const KV_RESTORER_CAPS = 5;
    const kvrCount5Success = kvr.filter((e) => e.outcome === "success" && e.target.kind === "customrole" && e.target.capabilityCount === KV_RESTORER_CAPS);
    ok("the create + both assigns (per-email + group) are audited with the role's real capability count (>=3 count-5 successes)", kvrCount5Success.length >= 3);
    const created = kvrCount5Success[0];
    ok("a create/assign is audited with the role name + capability count (never the cap list)", created !== undefined);
    ok("the audited target carries NO capability list (only name + count)", created !== undefined && !("capabilities" in (created.target as object)));
    // The DELETE records the name with a 0 count (a removed role bundles nothing): exactly one count-0
    // success for kv-restorer, which proves the delete path audits AND that the assigns are NO LONGER 0.
    const kvrZeroSuccess = kvr.filter((e) => e.outcome === "success" && e.target.kind === "customrole" && e.target.capabilityCount === 0);
    ok("the delete is audited with a 0 count and the assigns are not (exactly 1 count-0 success)", kvrZeroSuccess.length === 1);
    // Every custom-role-change is attributed to a VERIFIED actor (a non-null email, method access);
    // the denied entries are correctly attributed to the caller that was refused (e.g. ALICE), not the
    // Owner, so we assert "a verified actor", not "the Owner specifically", for the whole set.
    ok("every custom-role-change is attributed to a verified actor", events.every((e) => typeof e.actorEmail === "string" && e.actorMethod === "access"));
    // The SUCCESSFUL custom-role changes are the Owner's, EXCEPT the one within-authority assign CAROL
    // (the people-manager) legitimately performed in PROOF 8b (assigning policy-reader, a role whose caps
    // are a subset of her own). So every successful custom-role-change is attributed to a people-powers
    // holder (OWNER or CAROL), never an escalating actor.
    ok("every SUCCESSFUL custom-role-change is a people-powers holder's (owner or the within-authority delegator)", events.filter((e) => e.outcome === "success").every((e) => e.actorEmail === OWNER || e.actorEmail === CAROL));
    // The router-side DENIED entry (ALICE refused at the gate) is present and attributed to ALICE.
    ok("a router-denied custom-role write is audited and attributed to the refused caller", events.some((e) => e.outcome === "denied" && e.actorEmail === ALICE));
    // The chain is intact across all these writes.
    const verify = await (await call(OWNER, "GET", "/admin/audit/verify")).json() as { intact: boolean };
    ok("the audit chain remains intact across the custom-role writes", verify.intact === true);
  }
}

// ---- PROOF 10: a pure no-escalation negative control over the shared validator ----------
function provePureNegativeControl(): void {
  {
    // Cross-check the no-escalation guard at the pure layer with the access-admin's REAL built-in
    // capability set: access-admin holds roles.write but NOT downpipe.write, so the pure validator
    // rejects a role bundling downpipe.write and accepts one bundling only roles.write.
    const adminCaps = ROLE_CAPABILITIES["access-admin"];
    const reject = validateCustomRole({ name: "x", label: "x", capabilities: ["downpipe.write"], landing: "downpipes" }, adminCaps);
    ok("pure: access-admin cannot compose downpipe.write (no escalation)", reject.ok === false);
    const accept = validateCustomRole({ name: "x", label: "x", capabilities: ["roles.write"], surface: { people: "edit" }, landing: "people" }, adminCaps);
    ok("pure: access-admin CAN compose roles.write it holds (with a consistent people=edit surface)", accept.ok === true);
  }
}

// ---- PROOF 11: ASSIGN-SIDE no-escalation regression matrix (requireGrantWithinAuthority) ----------
// The create-time guard (validateCustomRole) stops composing a role above your authority; ASSIGNMENT is
// the second door. Once any strong role exists, a roles.write/access.policy holder must not be able to
// hand it out (or self-grant it) and confer capabilities beyond its own. These four cases pin that:
//  (a) a non-owner with a roles.write CUSTOM role cannot SELF-ASSIGN a stronger custom role (one with
//      restore.apply it lacks) -> refused naming the cap;
//  (b) access-admin cannot grant approver or restore-operator (both confer caps it lacks) -> refused
//      naming the cap;
//  (c) owner (holds every capability) CAN grant ANY non-owner built-in role;
//  (d) an assigner CAN grant a role whose caps are a SUBSET of its own.
// (a) CAROL (people-manager from PROOF 8b: roles.read/roles.write/access.policy) cannot self-assign a
// STRONGER custom role. The owner composes "blind-recoverer" bundling restore.apply (owner holds it).
// The role lists CAROL's own caps FIRST so the within-authority guard's first-unheld capability is
// restore.apply. CAROL passes the roles.write gate but the guard refuses, naming the cap she lacks.
async function proveAssignSelfStrongerRefused(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  const composeStrong = await call(OWNER, "POST", "/admin/custom-roles", {
    name: "blind-recoverer",
    label: "Blind recoverer",
    capabilities: ["roles.read", "roles.write", "access.policy", "restore.apply"],
    landing: "people",
  });
  ok("(a) the owner composes a stronger custom role bundling restore.apply (200)", composeStrong.status === 200);
  const selfAssignStronger = await call(CAROL, "POST", "/admin/roles", { email: CAROL, customRole: "blind-recoverer" });
  const saBody = (await selfAssignStronger.json()) as { error?: string };
  ok("(a) a roles.write custom-role holder CANNOT self-assign a stronger custom role (refused 403)", selfAssignStronger.status === 403);
  ok("(a) the refusal is the generic forbidden body, leaking no capability name", saBody.error === "forbidden" && !/restore\.apply/.test(JSON.stringify(saBody)) && !/do not hold/.test(JSON.stringify(saBody)));
  // CAROL did not escalate: she still resolves to the people-manager set (no restore.apply).
  const carolStill = await whoami(CAROL);
  ok("(a) the refused self-assign did not escalate (CAROL still lacks restore.apply)", !(carolStill.capabilities ?? []).includes("restore.apply"));
}

// (b) PEOPLE (access-admin: roles.write + access.policy, NO downpipe.write / drill.run / restore.apply)
// cannot grant approver (confers downpipe.write) NOR restore-operator (confers drill.run + restore.apply
// among others). Each is refused, even though access-admin passes the roles.write gate.
async function proveAssignBuiltinAboveAuthorityRefused(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  const grantApprover = await call(PEOPLE, "POST", "/admin/roles", { email: "would-be-approver@acme.example", role: "approver" });
  const gaBody = (await grantApprover.json()) as { error?: string };
  ok("(b) access-admin CANNOT grant approver (refused 403)", grantApprover.status === 403);
  ok("(b) the approver refusal is the generic forbidden body, leaking no capability name", gaBody.error === "forbidden" && !/downpipe\.write/.test(JSON.stringify(gaBody)) && !/do not hold/.test(JSON.stringify(gaBody)));
  const grantRestoreOp = await call(PEOPLE, "POST", "/admin/roles", { email: "would-be-restoreop@acme.example", role: "restore-operator" });
  const grBody = (await grantRestoreOp.json()) as { error?: string };
  ok("(b) access-admin CANNOT grant restore-operator (refused 403)", grantRestoreOp.status === 403);
  ok("(b) the restore-operator refusal is the generic forbidden body, leaking no capability name", grBody.error === "forbidden" && !/drill\.run/.test(JSON.stringify(grBody)) && !/do not hold/.test(JSON.stringify(grBody)));
}

// (c) OWNER holds every capability, so it CAN grant ANY non-owner built-in role.
async function proveOwnerCanGrantAnyBuiltin(ctx: CustomRolesCtx): Promise<void> {
  const { call } = ctx;
  const ESCALATOR = "escalator@acme.example"; // a fresh target for the (c) grants
  for (const role of ["viewer", "operator", "restore-operator", "approver", "access-admin"] as const) {
    const g = await call(OWNER, "POST", "/admin/roles", { email: `${ESCALATOR.replace("@", `+${role}@`)}`, role });
    ok(`(c) owner CAN grant the non-owner built-in role ${role} (200)`, g.status === 200);
  }
}

async function proveAssignWithinAuthorityHonoured(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    const DAVE = "dave-grantor@acme.example"; // gets a custom role that is a SUPERSET of a built-in role (case d)

    // (d) An assigner CAN grant a role whose caps are a SUBSET of its own. The owner composes
    // "super-grantor" whose set is a SUPERSET of restore-operator (it adds roles.write + access.policy on
    // top of every restore-operator capability) and assigns it to DAVE. DAVE then grants the restore-operator
    // built-in role to a fresh member: restore-operator's caps are a subset of DAVE's, so it is HONOURED (200).
    const composeSuper = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "super-grantor",
      label: "Super grantor",
      capabilities: [
        "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
        "drill.run", "restore.request", "restore.apply", "restore.approve",
        "roles.write", "access.policy",
      ],
      surface: { people: "edit", restore: "edit" },
      landing: "people",
    });
    ok("(d) the owner composes super-grantor (a superset of restore-operator + people powers) (200)", composeSuper.status === 200);
    const assignSuper = await call(OWNER, "POST", "/admin/roles", { email: DAVE, customRole: "super-grantor" });
    ok("(d) the owner assigns super-grantor to DAVE (200)", assignSuper.status === 200);
    const daveGrantsSubset = await call(DAVE, "POST", "/admin/roles", { email: "dave-grantee@acme.example", role: "restore-operator" });
    ok("(d) an assigner CAN grant a built-in role whose caps are a subset of its own (restore-operator, 200)", daveGrantsSubset.status === 200);
    const granteeWho = await whoami("dave-grantee@acme.example");
    ok("(d) the within-authority grant took effect (the grantee resolves to restore-operator)", granteeWho.role === "restore-operator");
    // And DAVE granting a role conferring a capability it LACKS (operator confers downpipe.write/.delete,
    // which super-grantor does not bundle) is still refused, proving the subset check is exact, not "any role".
    const daveGrantsAbove = await call(DAVE, "POST", "/admin/roles", { email: "dave-grantee@acme.example", role: "operator" });
    ok("(d) the same assigner CANNOT grant a role conferring a capability it lacks (operator, 403)", daveGrantsAbove.status === 403);
  }
}

// ---- PROOF 12: a composable custom role bundling downpipe.write can manage a downpipe -----------
// scheduledtest.config is a composable capability in the custom-role model (a creator may bundle or omit
// it independently of downpipe.write), so this composes a data-ops role with downpipe.write but WITHOUT
// scheduledtest.config and proves the role can CREATE a downpipe (the restore-test cadence defaults to
// weekly on create), toggle it, and round-trip its cadence -- none of which CHANGES the cadence, so none
// of it needs scheduledtest.config. Changing the cadence to a genuinely new value IS gated: the
// same role is refused (403) the moment it tries to weaken the mandatory restore test, while an OWNER
// (who holds scheduledtest.config) can still change it, and the role can still edit every OTHER field on
// the downpipe while round-tripping the cadence unchanged.
async function proveComposableDownpipeWrite(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  {
    const ERIN = "erin@acme.example"; // gets a custom role with downpipe.write but NOT scheduledtest.config
    // Owner composes a data-ops role deliberately OMITTING scheduledtest.config (it keeps the other
    // operator config caps so the composition is exercised with the capability genuinely absent).
    const compose = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "dp-writer-no-schedtest",
      label: "Downpipe writer (no scheduled-test config)",
      capabilities: ["downpipe.read", "downpipe.write", "downpipe.delete", "run.trigger", "notify.config", "expiry.config"],
      surface: { downpipes: "edit" },
      landing: "downpipes",
    });
    ok("(12) owner composes a downpipe.write role WITHOUT scheduledtest.config (200)", compose.status === 200);
    const assign = await call(OWNER, "POST", "/admin/roles", { email: ERIN, customRole: "dp-writer-no-schedtest" });
    ok("(12) owner assigns the role to ERIN (200)", assign.status === 200);
    // Sanity: ERIN holds downpipe.write but not scheduledtest.config (the gate's whole premise).
    const who = await whoami(ERIN);
    ok("(12) ERIN holds downpipe.write", (who.capabilities ?? []).includes("downpipe.write"));
    ok("(12) ERIN does NOT hold scheduledtest.config", !(who.capabilities ?? []).includes("scheduledtest.config"));

    const baseSource = { type: "kv" as const, binding: "KV_erin", include: [] as string[], exclude: [] as string[] };
    // (a) Create OMITTING the cadence: no explicit cadence, so the on-by-default weekly applies and the
    // gate does not fire. ERIN's downpipe.write is sufficient.
    const create = await call(ERIN, "POST", "/admin/downpipes", { id: "dp-erin", name: "Erin pipe", cadenceSeconds: ONE_HOUR_S, enabled: true, source: baseSource });
    ok("(12a) ERIN can CREATE a downpipe omitting the cadence (200, default applies, no gate)", create.status === 200);
    const created = (await create.json()) as { config: { restoreTestCadenceSeconds?: number } };
    ok("(12a) the created downpipe carries the on-by-default weekly cadence", created.config.restoreTestCadenceSeconds === ONE_WEEK_S);

    // (b) Re-upsert ROUND-TRIPPING the same cadence (what the console's enable/disable toggle does: it
    // spreads ...state.config, which carries the stored weekly value). Same value => NOT a change => no gate.
    const toggle = await call(ERIN, "POST", "/admin/downpipes", { id: "dp-erin", name: "Erin pipe", cadenceSeconds: ONE_HOUR_S, enabled: false, source: baseSource, restoreTestCadenceSeconds: ONE_WEEK_S });
    ok("(12b) ERIN can edit/toggle the downpipe while round-tripping the SAME cadence (200, no gate)", toggle.status === 200);

    // (b2) regression: ERIN attempts to CHANGE the cadence to a genuinely NEW value (weekly ->
    // daily) on the same downpipe. ERIN's downpipe.write passes the router's blanket gate, but the DO's
    // own scheduledtest.config re-check must refuse it (403), and the stored cadence must be unchanged.
    const erinChangeAttempt = await call(ERIN, "POST", "/admin/downpipes", { id: "dp-erin", name: "Erin pipe", cadenceSeconds: ONE_HOUR_S, enabled: false, source: baseSource, restoreTestCadenceSeconds: ONE_DAY_S });
    ok("(12b2) ERIN CANNOT change the cadence without scheduledtest.config (403)", erinChangeAttempt.status === 403);
    const afterErinAttempt = (await (await call(OWNER, "GET", "/admin/downpipes")).json()) as Array<{ config: { id: string; restoreTestCadenceSeconds?: number } }>;
    ok("(12b2) the refused attempt left the stored cadence UNCHANGED (still weekly)", afterErinAttempt.find((d) => d.config.id === "dp-erin")?.config.restoreTestCadenceSeconds === ONE_WEEK_S);

    // (c) An OWNER changes the cadence (weekly -> daily): a downpipe.write holder edits the restore-test
    // cadence like any other config field and the change takes effect.
    const ownerChange = await call(OWNER, "POST", "/admin/downpipes", { id: "dp-erin", name: "Erin pipe", cadenceSeconds: ONE_HOUR_S, enabled: true, source: baseSource, restoreTestCadenceSeconds: ONE_DAY_S });
    ok("(12c) an OWNER CAN change the cadence (200)", ownerChange.status === 200);
    const afterOwner = (await (await call(OWNER, "GET", "/admin/downpipes")).json()) as Array<{ config: { id: string; restoreTestCadenceSeconds?: number } }>;
    ok("(12c) the owner's change took effect (cadence now daily)", afterOwner.find((d) => d.config.id === "dp-erin")?.config.restoreTestCadenceSeconds === ONE_DAY_S);

    // (d) ERIN (downpipe.write) can still EDIT other fields, round-tripping the (now daily) cadence unchanged.
    const editOther = await call(ERIN, "POST", "/admin/downpipes", { id: "dp-erin", name: "Erin pipe RENAMED", cadenceSeconds: 2 * ONE_HOUR_S, enabled: true, source: baseSource, restoreTestCadenceSeconds: ONE_DAY_S });
    ok("(12d) ERIN can still edit other fields while round-tripping the (now daily) cadence (200)", editOther.status === 200);
  }
}

// ---- PROOF 13: audit.read, restore.dryrun and roles.read are now real, live gate() checks --
// These three capabilities were declared in the contract, shown in the console's roles-builder (a
// creator could tick or untick each), and granted to every built-in role from the viewer floor up --
// but no gate()/can() call anywhere ever checked them, so the gate below closes that hole (it is now
// a genuine authorisation primitive, not a phantom one).
//
// PRECISE CLAIM, verified two ways: (a) the pure gate()/callerCan() PRIMITIVE genuinely refuses a
// caller whose resolved capability set excludes one of the three, proving the code path is correct
// and live, never dead; (b) the PRODUCT's own custom-role composition cannot actually construct such
// a caller today, because identity-rbac.ts's read floor (downpipe.read/audit.read/restore.dryrun/
// restore.verify/reports.read/posture.read/roles.read) is folded, unconditionally, into every custom
// role's resolved capability set on top of whatever the role's own bundle lists (resolveAuthority,
// scheduler-do-rbac.ts:530-533: "the built-in floor is included so a custom role is purely additive").
// A custom role composed to EXCLUDE all three (thin-reader, below, bundling only downpipe.read) still
// resolves with all three present, so it is refused nowhere: no role, built-in or custom, can lack
// audit.read/restore.dryrun/roles.read under the current RBAC design.
//
// Placed LAST in the proof chain (after every other PROOF) so its extra role/audit writes cannot
// perturb an earlier proof's exact audit-count or role-list assertions.
async function proveVestigialCapabilitiesGated(ctx: CustomRolesCtx): Promise<void> {
  const { call, whoami } = ctx;
  const THREE = ["audit.read", "restore.dryrun", "roles.read"] as const;

  // ---- (a) the pure gate()/callerCan() primitive: a hand-built caller proves the code is live -----
  // No product flow can construct a Caller whose resolved capabilities exclude a universal read-floor
  // member (see below), so this constructs one directly to prove gate() itself is correct: IF such a
  // caller ever existed (a future narrower actor, a resolution-formula change), it would genuinely be
  // refused today, not silently admitted the way audit.read/restore.dryrun/roles.read were before B9.
  const baseSynthetic: Caller = {
    method: "access",
    email: "synthetic@acme.example",
    subject: "https://synthetic.cloudflareaccess.com|sub-of-synthetic",
    role: "viewer",
    groups: [],
  };
  for (const cap of THREE) {
    const narrow: Caller = { ...baseSynthetic, capabilities: new Set<Capability>(["downpipe.read"]) };
    const denied = gate(narrow, cap);
    ok(`(13a) gate() refuses a hand-built caller whose explicit capability set excludes ${cap}`, denied !== null && denied.status === 403);
    const full: Caller = { ...baseSynthetic, capabilities: new Set<Capability>(["downpipe.read", cap]) };
    ok(`(13a) gate() admits the same shape of caller when ${cap} is explicitly held`, gate(full, cap) === null);
  }

  // ---- (b) the product's real custom-role flow: the additive floor makes exclusion unreachable -----
  const FAY = "fay@acme.example"; // composed to hold ONLY downpipe.read; resolves with all three anyway
  const GUS = "gus@acme.example"; // composed to hold all three explicitly, alongside downpipe.read
  // A validly-shaped ULID; no real run need exist to reach the capability gate (it runs before the run
  // is ever opened), and the existing file convention reuses this placeholder.
  const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

  // thin-reader deliberately excludes all three from its OWN declared bundle: it holds only
  // downpipe.read (which the owner holds, so no escalation issue).
  const composeThin = await call(OWNER, "POST", "/admin/custom-roles", {
    name: "thin-reader",
    label: "Thin reader",
    capabilities: ["downpipe.read"],
    landing: "downpipes",
  });
  ok("(13b) the owner composes thin-reader holding only downpipe.read (200)", composeThin.status === 200);
  const assignThin = await call(OWNER, "POST", "/admin/roles", { email: FAY, customRole: "thin-reader" });
  ok("(13b) the owner assigns thin-reader to FAY (200)", assignThin.status === 200);
  const fayWho = await whoami(FAY);
  ok(
    "(13b) FAY's RESOLVED set holds all three anyway (the additive read floor, not the role's own bundle)",
    THREE.every((cap) => (fayWho.capabilities ?? []).includes(cap)),
  );

  // full-reader holds all three explicitly (plus downpipe.read), assigned to a second fresh caller, so
  // the "an entitled role still passes" half is also proven by a genuine, explicit custom-role grant.
  const composeFull = await call(OWNER, "POST", "/admin/custom-roles", {
    name: "full-reader",
    label: "Full reader",
    capabilities: ["downpipe.read", ...THREE],
    landing: "downpipes",
  });
  ok("(13b) the owner composes full-reader holding all three explicitly (200)", composeFull.status === 200);
  const assignFull = await call(OWNER, "POST", "/admin/roles", { email: GUS, customRole: "full-reader" });
  ok("(13b) the owner assigns full-reader to GUS (200)", assignFull.status === 200);

  // audit.read: GET /audit, GET /audit/verify, GET /audit/export all gate on it, and FAY, GUS and the
  // owner all reach every one (200) -- FAY's case documents the additive floor, not a denial.
  for (const path of ["/admin/audit", "/admin/audit/verify", "/admin/audit/export"]) {
    ok(`(13b) FAY (thin-reader) still reaches ${path} via the additive floor (200)`, (await call(FAY, "GET", path)).status === 200);
    ok(`(13b) the owner reaches ${path} (200)`, (await call(OWNER, "GET", path)).status === 200);
    ok(`(13b) GUS (full-reader, explicit audit.read) reaches ${path} (200)`, (await call(GUS, "GET", path)).status === 200);
  }

  // restore.dryrun: POST /restore with confirm omitted gates on it; same three-way check.
  {
    ok("(13b) FAY (thin-reader) still reaches the dry-run via the additive floor (200)", (await call(FAY, "POST", "/admin/restore", { runId: RUN_ID })).status === 200);
    ok("(13b) the owner reaches the dry-run (200)", (await call(OWNER, "POST", "/admin/restore", { runId: RUN_ID })).status === 200);
    ok("(13b) GUS (full-reader, explicit restore.dryrun) reaches the dry-run (200)", (await call(GUS, "POST", "/admin/restore", { runId: RUN_ID })).status === 200);
  }

  // roles.read: GET /roles gates on it; same three-way check.
  {
    ok("(13b) FAY (thin-reader) still reaches GET /roles via the additive floor (200)", (await call(FAY, "GET", "/admin/roles")).status === 200);
    ok("(13b) the owner reaches GET /roles (200)", (await call(OWNER, "GET", "/admin/roles")).status === 200);
    ok("(13b) GUS (full-reader, explicit roles.read) reaches GET /roles (200)", (await call(GUS, "GET", "/admin/roles")).status === 200);
  }
}

async function main(): Promise<void> {
  const ctx = await buildCustomRolesCtx();
  await bootstrapPrincipals(ctx);
  await proveAdditive(ctx);
  await proveNoEscalation(ctx);
  await proveOwnerReservedBarred(ctx);
  await proveEditRequiresWriteCap(ctx);
  await proveNoBuiltinShadowing(ctx);
  await provePerEmailResolution(ctx);
  await proveGroupResolution(ctx);
  await proveDeleteDropsToFloor(ctx);
  await proveDefenceInDepth(ctx);
  await provePeoplePowersNotLadder(ctx);
  await proveAuditRecorded(ctx);
  provePureNegativeControl();
  // PROOF 11: ASSIGN-SIDE no-escalation regression matrix (cases a-d).
  await proveAssignSelfStrongerRefused(ctx);
  await proveAssignBuiltinAboveAuthorityRefused(ctx);
  await proveOwnerCanGrantAnyBuiltin(ctx);
  await proveAssignWithinAuthorityHonoured(ctx);
  await proveComposableDownpipeWrite(ctx);
  await proveVestigialCapabilitiesGated(ctx);

  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`CUSTOM ROLE VECTORS: ${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("COMPOSABLE CUSTOM ROLE VECTORS PASS");
}

void main();
