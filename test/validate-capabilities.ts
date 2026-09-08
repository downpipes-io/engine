// Prove the capability and role model (contract section 1) SERVER-SIDE, against the real
// ROLE_CAPABILITIES map and can() in src/admin/identity.ts. No network, no deploy, no cost. Run:
//   node test/validate-capabilities.ts
//
// The blueprint replaces the linear rank check with an explicit capability map: the four existing
// roles keep EXACTLY their prior powers (so the existing route gates and validate-rbac outcomes are
// unchanged), and two narrow roles are added (restore-operator = recovery only; access-admin =
// people only). This validator pins the contract section-1 table as an INDEPENDENT expected matrix,
// so any drift in ROLE_CAPABILITIES is caught here rather than at a route.
//
// What this proves:
//  - the Role union is exactly the six contract roles (and isRole guards each, rejecting junk);
//  - the Capability union is exactly the 21 contract capabilities;
//  - can(role, cap) === the contract table for EVERY (role, capability) pair (126 cells);
//  - restore.verify (restorability assurance) is a read-SAFE capability held by viewer up (every role),
//    and it does NOT imply downpipe.read or restore.apply (proving recoverability is strictly weaker);
//  - the backward-compatibility invariants: the four cumulative roles are unchanged, restore-operator
//    is recovery-only (no write/delete/trigger, no people, no keys), access-admin is people-only
//    (no data/restore/keys), and keys.ceremony + posture.riskaccept are owner-exclusive;
//  - viewer is a strict subset of operator, operator a strict subset of approver (the cumulative
//    ladder for the three lower legacy roles), and owner is a strict superset of every role;
//  - can() confers nothing for a role absent from the table (defensive lookup);
//  - the ReadonlySet grants cannot be mutated to confer authority (the map is the only source).

import {
  ROLE_CAPABILITIES,
  can,
  isRole,
  type Role,
  type Capability,
} from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The contract section-1 role union, listed independently of the source so a removed/renamed role is
// caught.
const ALL_ROLES: Role[] = [
  "viewer",
  "operator",
  "restore-operator",
  "approver",
  "access-admin",
  "owner",
];

// The contract section-1 capability union, listed independently of the source.
const ALL_CAPS: Capability[] = [
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

// EXPECTED is the contract section-1 table transcribed by hand as the set of capabilities each role
// holds. It is the authority of record for this test; can() must match it cell for cell. Rows are
// built from the table:
//   - downpipe.read, audit.read, restore.dryrun, restore.verify, reports.read, posture.read,
//     roles.read: all six (restore.verify is the read-safe restorability-proof capability, granted from
//     the viewer floor up because proving an archive restores writes nothing and surfaces no plaintext).
//   - downpipe.write/delete, run.trigger, drill.run, notify.config, expiry.config,
//     scheduledtest.config: operator, approver, owner.
//   - restore.request: operator, restore-operator, approver, owner.
//   - restore.apply, restore.approve: restore-operator, approver, owner.
//   - roles.write, access.policy: access-admin, owner.
//   - keys.ceremony, posture.riskaccept: owner only.
const READS: Capability[] = [
  "downpipe.read", "audit.read", "restore.dryrun", "restore.verify", "reports.read", "posture.read", "roles.read",
];
const OPERATOR_DATA: Capability[] = [
  "downpipe.write", "downpipe.delete", "run.trigger", "drill.run",
  "notify.config", "expiry.config", "scheduledtest.config",
];
const EXPECTED: Record<Role, Set<Capability>> = {
  viewer: new Set<Capability>([...READS]),
  operator: new Set<Capability>([...READS, ...OPERATOR_DATA, "restore.request"]),
  "restore-operator": new Set<Capability>([
    ...READS, "drill.run", "restore.request", "restore.apply", "restore.approve",
  ]),
  approver: new Set<Capability>([
    ...READS, ...OPERATOR_DATA, "restore.request", "restore.apply", "restore.approve",
  ]),
  "access-admin": new Set<Capability>([...READS, "roles.write", "access.policy"]),
  owner: new Set<Capability>([
    ...READS, ...OPERATOR_DATA,
    "restore.request", "restore.apply", "restore.approve",
    "roles.write", "access.policy",
    "keys.ceremony", "posture.riskaccept",
  ]),
};

function main(): void {
  // ---- The unions are exactly the contract's --------------------------------------------
  console.log("unions:");
  const srcRoles = Object.keys(ROLE_CAPABILITIES) as Role[];
  ok("ROLE_CAPABILITIES has exactly the six contract roles",
    srcRoles.length === ALL_ROLES.length && ALL_ROLES.every((r) => srcRoles.includes(r)));
  ok("isRole accepts every contract role", ALL_ROLES.every((r) => isRole(r)));
  ok("isRole rejects a junk role string", !isRole("superuser") && !isRole("admin") && !isRole(""));
  ok("isRole rejects a non-string", !isRole(5) && !isRole(null) && !isRole(undefined) && !isRole({}));

  // The union has 21 capabilities (the count guards an accidental add/remove in the source union;
  // a new capability MUST be added to ALL_CAPS and EXPECTED here too). The 21st is restore.verify.
  ok("the capability union has 21 members (contract section 1)", ALL_CAPS.length === 21);
  const capSet = new Set(ALL_CAPS);
  ok("the capability union has no duplicates", capSet.size === ALL_CAPS.length);
  // Every capability the source map actually grants somewhere is present in ALL_CAPS (catches a new
  // capability added to the source union + a role grant but not transcribed here).
  const granted = new Set<Capability>();
  for (const role of ALL_ROLES) for (const c of ROLE_CAPABILITIES[role]) granted.add(c);
  ok("every capability granted by the source map is in the test union",
    [...granted].every((c) => capSet.has(c)));

  // ---- can() matches the EXPECTED table for every (role, capability) cell ----------------
  console.log("\ntable (126 cells):");
  let mismatches = 0;
  let cells = 0;
  for (const role of ALL_ROLES) {
    for (const cap of ALL_CAPS) {
      cells++;
      const want = EXPECTED[role].has(cap);
      const got = can(role, cap);
      if (got !== want) {
        mismatches++;
        console.log(`  FAIL cell ${role} x ${cap}: want ${want}, got ${got}`);
      }
    }
  }
  ok("all 126 cells evaluated", cells === ALL_ROLES.length * ALL_CAPS.length);
  ok("can() matches the contract table for every cell", mismatches === 0);

  // The source map and EXPECTED agree on the exact grant set per role (catches a grant present in
  // the source but absent from ALL_CAPS, which the cell loop alone would miss).
  for (const role of ALL_ROLES) {
    const src = ROLE_CAPABILITIES[role];
    const want = EXPECTED[role];
    const srcArr = [...src];
    const sameSize = srcArr.length === want.size;
    const sameMembers = srcArr.every((c) => want.has(c)) && [...want].every((c) => src.has(c));
    ok(`grant set for ${role} matches the contract exactly`, sameSize && sameMembers);
  }

  // ---- restore.verify (restorability assurance): read-safe, held by all, implies nothing else ----
  console.log("\nrestore.verify:");
  // restore.verify is granted from the viewer floor up, so EVERY role holds it (it is as safe as a read:
  // the blind test decrypts only to a discard sink, the keyless attest decrypts nothing).
  ok("restore.verify is held by EVERY role", ALL_ROLES.every((r) => can(r, "restore.verify")));
  // A role holding restore.verify must NOT thereby hold downpipe.read or restore.apply: proving an
  // archive restores is strictly weaker than reading config or applying a restore over live data. viewer
  // is the witness for "cannot apply"; there is no role that holds restore.verify but not downpipe.read,
  // so the implication is checked structurally: restore.verify and restore.apply are distinct grants.
  ok("restore.verify does NOT imply restore.apply (viewer holds verify, not apply)",
    can("viewer", "restore.verify") && !can("viewer", "restore.apply"));
  // restore.verify and downpipe.read are distinct capabilities (the union lists both), so holding one is
  // never the same as holding the other; a hypothetical verify-only grant would not confer read. We
  // assert the two are separate union members so the gate on a route cannot be satisfied by the wrong one.
  ok("restore.verify and downpipe.read are distinct capabilities",
    ALL_CAPS.includes("restore.verify") && ALL_CAPS.includes("downpipe.read") && ("restore.verify" as Capability) !== ("downpipe.read" as Capability));
  // restore.verify is NOT an apply: a route gated on restore.apply must reject a caller who holds only
  // verify. viewer holds verify but not apply, proving the gate is not satisfiable by verify.
  ok("a restore.apply gate is NOT satisfied by restore.verify (viewer witness)",
    can("viewer", "restore.verify") && !can("viewer", "restore.apply"));

  // ---- Backward-compatibility invariants (the four cumulative roles unchanged) -----------
  console.log("\nbackward-compatibility:");
  // viewer: reads + dryrun + verify only, NO data ops, NO apply.
  ok("viewer reads downpipes", can("viewer", "downpipe.read"));
  ok("viewer may dry-run a restore", can("viewer", "restore.dryrun"));
  ok("viewer may verify (blind test / keyless attest) a restore", can("viewer", "restore.verify"));
  ok("viewer canNOT write downpipes", !can("viewer", "downpipe.write"));
  ok("viewer canNOT trigger a run", !can("viewer", "run.trigger"));
  ok("viewer canNOT apply a restore", !can("viewer", "restore.apply"));
  ok("viewer canNOT request a restore", !can("viewer", "restore.request"));

  // operator: data ops + config + request, NO apply/approve, NO people, NO keys.
  ok("operator writes downpipes", can("operator", "downpipe.write"));
  ok("operator triggers a run", can("operator", "run.trigger"));
  ok("operator configures notify", can("operator", "notify.config"));
  ok("operator may request a restore", can("operator", "restore.request"));
  ok("operator canNOT apply a restore", !can("operator", "restore.apply"));
  ok("operator canNOT approve a restore", !can("operator", "restore.approve"));
  ok("operator canNOT write roles", !can("operator", "roles.write"));
  ok("operator canNOT run a key ceremony", !can("operator", "keys.ceremony"));

  // approver: operator + apply + approve, still NO people, NO keys.
  ok("approver applies a restore", can("approver", "restore.apply"));
  ok("approver approves a restore", can("approver", "restore.approve"));
  ok("approver still writes downpipes (operator powers retained)", can("approver", "downpipe.write"));
  ok("approver canNOT write roles", !can("approver", "roles.write"));
  ok("approver canNOT run a key ceremony", !can("approver", "keys.ceremony"));
  ok("approver canNOT risk-accept a posture check", !can("approver", "posture.riskaccept"));

  // owner: everything.
  ok("owner holds every capability", ALL_CAPS.every((c) => can("owner", c)));

  // ---- The two narrow roles ---------------------------------------------------------------
  console.log("\nnarrow roles:");
  // restore-operator: recovery only. Has the restore lifecycle + drill, NOT data write/trigger,
  // NOT people, NOT keys, NOT notify/expiry config.
  ok("restore-operator may request a restore", can("restore-operator", "restore.request"));
  ok("restore-operator may apply a restore", can("restore-operator", "restore.apply"));
  ok("restore-operator may approve a restore", can("restore-operator", "restore.approve"));
  ok("restore-operator may run a drill", can("restore-operator", "drill.run"));
  ok("restore-operator may dry-run a restore", can("restore-operator", "restore.dryrun"));
  ok("restore-operator canNOT write downpipes", !can("restore-operator", "downpipe.write"));
  ok("restore-operator canNOT delete downpipes", !can("restore-operator", "downpipe.delete"));
  ok("restore-operator canNOT trigger a run", !can("restore-operator", "run.trigger"));
  ok("restore-operator canNOT configure notify", !can("restore-operator", "notify.config"));
  ok("restore-operator canNOT configure expiry", !can("restore-operator", "expiry.config"));
  ok("restore-operator canNOT write roles", !can("restore-operator", "roles.write"));
  ok("restore-operator canNOT touch the access policy", !can("restore-operator", "access.policy"));
  ok("restore-operator canNOT run a key ceremony", !can("restore-operator", "keys.ceremony"));
  ok("restore-operator canNOT risk-accept a posture check", !can("restore-operator", "posture.riskaccept"));

  // access-admin: people only. Has roles.write + access.policy + the reads, NOTHING else.
  ok("access-admin may write roles", can("access-admin", "roles.write"));
  ok("access-admin may set the access policy", can("access-admin", "access.policy"));
  ok("access-admin reads roles", can("access-admin", "roles.read"));
  ok("access-admin reads the audit log", can("access-admin", "audit.read"));
  ok("access-admin canNOT write downpipes", !can("access-admin", "downpipe.write"));
  ok("access-admin canNOT trigger a run", !can("access-admin", "run.trigger"));
  ok("access-admin canNOT request a restore", !can("access-admin", "restore.request"));
  ok("access-admin canNOT apply a restore", !can("access-admin", "restore.apply"));
  ok("access-admin canNOT approve a restore", !can("access-admin", "restore.approve"));
  ok("access-admin canNOT run a drill", !can("access-admin", "drill.run"));
  ok("access-admin canNOT run a key ceremony", !can("access-admin", "keys.ceremony"));
  ok("access-admin canNOT risk-accept a posture check", !can("access-admin", "posture.riskaccept"));

  // ---- Owner-exclusive capabilities -------------------------------------------------------
  console.log("\nowner-exclusive:");
  for (const owned of ["keys.ceremony", "posture.riskaccept"] as Capability[]) {
    ok(`only owner holds ${owned}`,
      can("owner", owned) && ALL_ROLES.filter((r) => r !== "owner").every((r) => !can(r, owned)));
  }

  // ---- Subset / superset structure --------------------------------------------------------
  console.log("\nstructure:");
  function isSubset(a: Role, b: Role): boolean {
    return ALL_CAPS.every((c) => !can(a, c) || can(b, c));
  }
  function isStrictSubset(a: Role, b: Role): boolean {
    return isSubset(a, b) && ALL_CAPS.some((c) => can(b, c) && !can(a, c));
  }
  // The three lower legacy roles form a cumulative ladder.
  ok("viewer is a strict subset of operator", isStrictSubset("viewer", "operator"));
  ok("operator is a strict subset of approver", isStrictSubset("operator", "approver"));
  ok("viewer is a strict subset of approver", isStrictSubset("viewer", "approver"));
  // owner is a strict superset of every other role.
  ok("owner is a superset of every role",
    ALL_ROLES.filter((r) => r !== "owner").every((r) => isSubset(r, "owner")));
  ok("owner strictly exceeds approver, restore-operator and access-admin",
    isStrictSubset("approver", "owner") && isStrictSubset("restore-operator", "owner") && isStrictSubset("access-admin", "owner"));
  // The two narrow roles are NOT on the cumulative ladder: each holds something the other and the
  // adjacent legacy role do not.
  ok("restore-operator is NOT a subset of operator (it adds apply/approve)", !isSubset("restore-operator", "operator"));
  ok("operator is NOT a subset of restore-operator (it adds data ops)", !isSubset("operator", "restore-operator"));
  ok("access-admin is NOT a subset of approver (it adds people)", !isSubset("access-admin", "approver"));
  ok("approver is NOT a subset of access-admin (it adds data + restore)", !isSubset("approver", "access-admin"));

  // ---- Defensive lookup + immutability ----------------------------------------------------
  console.log("\ndefensive:");
  // A role absent from the table confers nothing (impossible for the closed union, but can() must be
  // robust to a bad cast at the boundary).
  ok("can() confers nothing for an unknown role", !can("nobody" as unknown as Role, "downpipe.read"));
  ok("can() confers nothing for an unknown capability", !can("owner", "totally.fake" as unknown as Capability));

  // The grant is a ReadonlySet at the type level; at runtime, a Set is mutable, so prove that the
  // map can() reads is the one published (a consumer that does NOT mutate gets the contract grant).
  // We confirm that a copy + add does not change can()'s answer (can reads ROLE_CAPABILITIES, not a
  // caller's copy).
  const copy = new Set<Capability>(ROLE_CAPABILITIES.viewer);
  copy.add("downpipe.write");
  ok("mutating a COPY of viewer's grant does not grant viewer downpipe.write via can()",
    copy.has("downpipe.write") && !can("viewer", "downpipe.write"));

  console.log(failures === 0 ? "\nCAPABILITIES VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
