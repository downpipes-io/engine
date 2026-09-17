// Prove the field-level access matrix documented at docs/security/field-level-access-matrix.md
// (OWASP ASVS 5.0 V8.1.2: "Authorization documentation defines field-level access restrictions
// (read and write) based on consumer permissions and resource attributes") against the REAL
// capability constants in src/admin, so the document cannot silently drift from the code it
// describes. No network, no deploy, no cost. Run:
//   node test/validate-field-access-matrix.ts
//
// WHAT THIS PROVES, mirroring validate-capabilities.ts's transcribe-and-compare method (that
// validator pins the ROLE x CAPABILITY cell matrix; this one pins the FIELD/RESOURCE-GROUP x
// CAPABILITY matrix the doc presents to a reader, plus the two caller-class families the
// capability model does not cover on its own):
//
//  1. Every one of the 21 capabilities in ALL_CAPABILITIES is assigned to EXACTLY ONE field row
//     below (as its read capability or its write capability), so the doc's field groups are a
//     complete partition of the authority surface, not a curated subset.
//  2. For every row, the roles the doc claims can read/write that field are recomputed from
//     ROLE_CAPABILITIES via can() and must match exactly -- a role added to or removed from a
//     capability's grant set fails here until the doc (and this file, its single source of
//     truth) is updated.
//  3. The two owner-reserved fields (keys.ceremony, posture.riskaccept) are asserted to still be
//     members of OWNER_RESERVED_CAPABILITIES, so a custom role could never be composed to reach
//     them (identity-rbac.ts's validateCustomRole enforces this at write time).
//  4. Every file:line citation backing a row resolves in the CURRENT tree and the cited line
//     still contains the substring the doc quotes it for (a citation that has drifted to name
//     the wrong line, or the wrong capability string, fails loudly rather than reading as true).
//  5. The STEP-UP overlay: the 43 STEPUP_SUBS entries (router-core.ts) are transcribed
//     independently here and compared by SET EQUALITY, so a sensitive route added to or removed
//     from that Set is caught the moment it drifts from the doc's step-up column, in either
//     direction.
//  6. The two MACHINE-BEARER surfaces that sit outside the Capability model entirely (SCIM
//     deprovision and the support/metrics ingest-credential pulls) are checked against their own
//     source of truth: the closed IngestScope set (support-ingest.ts's INGEST_TTL_CAPS_SECONDS)
//     and the SCIM synthetic-caller predicate (identity.ts's isScimOffboardCaller), so the doc's
//     claim about what those bearers can and cannot reach is grounded in a running check, not
//     prose alone.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ALL_CAPABILITIES,
  type Capability,
  can,
  isCapability,
  isScimOffboardCaller,
  OWNER_RESERVED_CAPABILITIES,
  type Role,
  SCIM_OFFBOARD_EMAIL,
  SCIM_OFFBOARD_SUBJECT,
} from "../src/admin/identity.ts";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import { INGEST_TTL_CAPS_SECONDS } from "../src/admin/support-ingest.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The six built-in roles, transcribed independently (as validate-capabilities.ts does), so a
// role added to or removed from the Role union is caught by the completeness check below rather
// than silently narrowing which roles this file ever asks can() about.
const ALL_ROLES: Role[] = ["viewer", "operator", "restore-operator", "approver", "access-admin", "owner"];

function sortedRoles(roles: Role[]): Role[] {
  return [...roles].sort();
}

function rolesHolding(cap: Capability): Role[] {
  return sortedRoles(ALL_ROLES.filter((r) => can(r, cap)));
}

interface Evidence {
  file: string;
  line: number;
  mustContain: string;
}

interface FieldRow {
  /** the field/resource group name as it appears in the doc's table. */
  field: string;
  readCap: Capability | null;
  writeCap: Capability | null;
  ownerReserved: boolean;
  expectRead: Role[];
  expectWrite: Role[];
  evidence: Evidence[];
}

const READ_ALL: Role[] = sortedRoles(ALL_ROLES);
const OPERATOR_UP: Role[] = sortedRoles(["operator", "approver", "owner"]);
const OPERATOR_UP_PLUS_RESTORE_OP: Role[] = sortedRoles(["operator", "restore-operator", "approver", "owner"]);
const RESTORE_OP_UP: Role[] = sortedRoles(["restore-operator", "approver", "owner"]);
const ACCESS_ADMIN_UP: Role[] = sortedRoles(["access-admin", "owner"]);
const OWNER_ONLY: Role[] = ["owner"];

// FIELD_ROWS is the field-level access matrix, ONE row per capability (a complete partition of
// ALL_CAPABILITIES, asserted below), transcribed by hand from src/admin/identity-rbac.ts's
// ROLE_CAPABILITIES table and the router gate() call sites. This IS the documented matrix: the
// prose table in docs/security/field-level-access-matrix.md is a rendering of exactly these rows,
// and this array (not the prose) is what the gate below holds to the capability constants.
const FIELD_ROWS: FieldRow[] = [
  {
    field: "Downpipe configuration (read)",
    readCap: "downpipe.read",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [{ file: "src/admin/router.ts", line: 591, mustContain: "downpipe.read" }],
  },
  {
    field: "Downpipe configuration (create/edit)",
    readCap: null,
    writeCap: "downpipe.write",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP,
    evidence: [
      { file: "src/admin/router-pipelines.ts", line: 41, mustContain: "downpipe.write" },
      { file: "src/admin/router-discovery.ts", line: 277, mustContain: "downpipe.write" },
    ],
  },
  {
    field: "Downpipe deletion",
    readCap: null,
    writeCap: "downpipe.delete",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP,
    evidence: [{ file: "src/admin/router-pipelines.ts", line: 89, mustContain: "downpipe.delete" }],
  },
  {
    field: "Manual run trigger",
    readCap: null,
    writeCap: "run.trigger",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP,
    evidence: [{ file: "src/admin/router-pipelines.ts", line: 136, mustContain: "run.trigger" }],
  },
  {
    field: "Restore drill (recovery test)",
    readCap: null,
    writeCap: "drill.run",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP_PLUS_RESTORE_OP,
    evidence: [{ file: "src/admin/router-ops.ts", line: 70, mustContain: "drill.run" }],
  },
  {
    field: "Restore dry-run preview",
    readCap: "restore.dryrun",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [{ file: "src/admin/router-restore.ts", line: 575, mustContain: "restore.dryrun" }],
  },
  {
    field: "Restorability proof (blind restore test / keyless attest)",
    readCap: "restore.verify",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [
      { file: "src/admin/router-restore.ts", line: 621, mustContain: "restore.verify" },
      { file: "src/admin/router-restore.ts", line: 867, mustContain: "restore.verify" },
    ],
  },
  {
    field: "Restore request (raise a recovery)",
    readCap: null,
    writeCap: "restore.request",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP_PLUS_RESTORE_OP,
    evidence: [{ file: "src/admin/router-restore.ts", line: 701, mustContain: "restore.request" }],
  },
  {
    field: "Restore apply (overwrite live data)",
    readCap: null,
    writeCap: "restore.apply",
    ownerReserved: false,
    expectRead: [],
    expectWrite: RESTORE_OP_UP,
    evidence: [{ file: "src/admin/router-restore.ts", line: 240, mustContain: "restore.apply" }],
  },
  {
    field: "Restore approve (dual-control sign-off)",
    readCap: null,
    writeCap: "restore.approve",
    ownerReserved: false,
    expectRead: [],
    expectWrite: RESTORE_OP_UP,
    evidence: [{ file: "src/admin/router-restore.ts", line: 794, mustContain: "restore.approve" }],
  },
  {
    field: "Member/role table (read)",
    readCap: "roles.read",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [{ file: "src/admin/router-rbac.ts", line: 171, mustContain: "roles.read" }],
  },
  {
    field: "Member/role table (grant/revoke)",
    readCap: null,
    writeCap: "roles.write",
    ownerReserved: false,
    expectRead: [],
    expectWrite: ACCESS_ADMIN_UP,
    evidence: [{ file: "src/admin/router-rbac.ts", line: 43, mustContain: "roles.write" }],
  },
  {
    field: "Account governance policy (break-glass retire, session termination, custom-role admin, control-plane export/import)",
    readCap: null,
    writeCap: "access.policy",
    ownerReserved: false,
    expectRead: [],
    expectWrite: ACCESS_ADMIN_UP,
    evidence: [
      { file: "src/admin/router-rbac.ts", line: 177, mustContain: "access.policy" },
      { file: "src/admin/router-identity.ts", line: 390, mustContain: "access.policy" },
    ],
  },
  {
    field: "Audit log (read)",
    readCap: "audit.read",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [{ file: "src/admin/router-rbac.ts", line: 291, mustContain: "audit.read" }],
  },
  {
    field: "Trust roots and egress targets (key ceremony, destinations, IdP connections, SIEM/OTLP push)",
    readCap: null,
    writeCap: "keys.ceremony",
    ownerReserved: true,
    expectRead: [],
    expectWrite: OWNER_ONLY,
    evidence: [
      { file: "src/admin/router-keys.ts", line: 300, mustContain: "keys.ceremony" },
      { file: "src/admin/router-destinations.ts", line: 328, mustContain: "keys.ceremony" },
      { file: "src/admin/router-identity.ts", line: 834, mustContain: "keys.ceremony" },
      { file: "src/admin/router-push.ts", line: 232, mustContain: "keys.ceremony" },
    ],
  },
  {
    field: "Notification rules and channels",
    readCap: null,
    writeCap: "notify.config",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP,
    evidence: [{ file: "src/admin/router-ops.ts", line: 93, mustContain: "notify.config" }],
  },
  {
    field: "Expiry / licence-lapse policy",
    readCap: null,
    writeCap: "expiry.config",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP,
    evidence: [{ file: "src/admin/router-ops.ts", line: 297, mustContain: "expiry.config" }],
  },
  {
    field: "Scheduled restore-test policy",
    readCap: null,
    writeCap: "scheduledtest.config",
    ownerReserved: false,
    expectRead: [],
    expectWrite: OPERATOR_UP,
    // scheduledtest.config is the ONE capability with no direct router gate() call site: it is
    // re-checked inside the DO's addDownpipe against its own resolved caller (router-pipelines.ts's
    // comment block explains why: downpipe.write implies it for every built-in role, so the only
    // caller who can hold one without the other is a composable custom role). The capability's
    // grant is still pinned in ROLE_CAPABILITIES (identity-rbac.ts), which is what row 6 above
    // checks cell-by-cell; here the citation is the DO re-check comment itself.
    evidence: [{ file: "src/admin/router-pipelines.ts", line: 39, mustContain: "scheduledtest.config" }],
  },
  {
    field: "Reports (SLA / compliance projections)",
    readCap: "reports.read",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [{ file: "src/admin/router.ts", line: 582, mustContain: "reports.read" }],
  },
  {
    field: "Security posture (checks and scores)",
    readCap: "posture.read",
    writeCap: null,
    ownerReserved: false,
    expectRead: READ_ALL,
    expectWrite: [],
    evidence: [{ file: "src/admin/router-status.ts", line: 244, mustContain: "posture.read" }],
  },
  {
    field: "Security posture (risk-accept a failing check)",
    readCap: null,
    writeCap: "posture.riskaccept",
    ownerReserved: true,
    expectRead: [],
    expectWrite: OWNER_ONLY,
    evidence: [{ file: "src/admin/router-config-version.ts", line: 36, mustContain: "posture.riskaccept" }],
  },
];

// The 43 STEPUP_SUBS entries (router-core.ts), transcribed independently (not read from the
// source and echoed back) so an entry added to or removed from that Set is caught by a SET
// EQUALITY comparison rather than a one-directional subset check either direction could pass
// vacuously. Grouped here by which field row above it overlays; the grouping is documentation
// only, the check is unordered set equality.
const EXPECTED_STEPUP_SUBS: string[] = [
  // keys.ceremony (trust roots / egress targets)
  "/keys/install", "/keys/rotate", "/keys/add-operational", "/keys/break-glass-only",
  "/destination", "/destinations", "/destinations/remove", "/destinations/default",
  "/push", "/push/delete", "/push/test", "/otlp-push", "/otlp-push/delete",
  "/idp/connections", "/idp/connections/delete", "/idp/connections/enabled", "/idp/connections/cert",
  // roles.write (member/role table)
  "/roles", "/roles/delete", "/group-roles", "/group-roles/delete", "/custom-roles", "/custom-roles/delete",
  // posture.riskaccept
  "/posture/accept", "/posture/unaccept",
  // access.policy (account governance)
  "/policy/retire-break-glass-token", "/passkey/credentials/delete", "/signin-factors/revoke",
  "/sessions/terminate", "/sessions/terminate-others", "/sessions/terminate-user", "/sessions/terminate-all",
  "/custody/send-share", "/support/credentials",
  // notify.config
  "/notify/rules", "/notify/rules/delete", "/config/signin-context-policy", "/notify/channels", "/notify/channels/delete",
  // restore.apply / restore.approve
  "/restore/approve", "/retention-prune/apply", "/retention-prune/approve",
  // drill.run (attended verification)
  "/attest/session/create",
];

// The three IngestScope values (support-ingest.ts), transcribed independently for the same
// set-equality reason as STEPUP_SUBS above: the machine-bearer surfaces the doc describes
// (metrics scrape, support diagnostics pull, SIEM audit-feed pull) are exactly these three.
const EXPECTED_INGEST_SCOPES: string[] = ["audit-feed", "diagnostics", "metrics"];

function citationHolds(ev: Evidence): boolean {
  const abs = resolve(ROOT, ev.file);
  if (!existsSync(abs)) return false;
  const lines = readFileSync(abs, "utf8").split("\n");
  if (ev.line < 1 || ev.line > lines.length) return false;
  const line = lines[ev.line - 1];
  return line !== undefined && line.includes(ev.mustContain);
}

function main(): void {
  console.log("field partition (every capability in exactly one row):");
  const seen = new Set<Capability>();
  for (const row of FIELD_ROWS) {
    for (const cap of [row.readCap, row.writeCap]) {
      if (cap === null) continue;
      ok(`${row.field}: ${cap} is a real capability`, isCapability(cap));
      ok(`${row.field}: ${cap} is not claimed by another row`, !seen.has(cap));
      seen.add(cap);
    }
  }
  ok(
    `every one of the ${ALL_CAPABILITIES.length} capabilities is covered by a row`,
    ALL_CAPABILITIES.every((c) => seen.has(c)) && seen.size === ALL_CAPABILITIES.length,
  );

  console.log("\nper-row caller classes (recomputed from ROLE_CAPABILITIES via can()):");
  for (const row of FIELD_ROWS) {
    if (row.readCap !== null) {
      ok(`${row.field}: read holders match ROLE_CAPABILITIES`, JSON.stringify(rolesHolding(row.readCap)) === JSON.stringify(row.expectRead));
    }
    if (row.writeCap !== null) {
      ok(`${row.field}: write holders match ROLE_CAPABILITIES`, JSON.stringify(rolesHolding(row.writeCap)) === JSON.stringify(row.expectWrite));
      if (row.ownerReserved) {
        ok(`${row.field}: ${row.writeCap} is still owner-reserved`, OWNER_RESERVED_CAPABILITIES.has(row.writeCap));
      }
    }
  }

  console.log("\nevidence citations resolve in the current tree:");
  for (const row of FIELD_ROWS) {
    for (const ev of row.evidence) {
      ok(`${row.field}: ${ev.file}:${ev.line} contains "${ev.mustContain}"`, citationHolds(ev));
    }
  }

  console.log("\nstep-up overlay (STEPUP_SUBS, router-core.ts):");
  ok(`STEPUP_SUBS has exactly ${EXPECTED_STEPUP_SUBS.length} members`, STEPUP_SUBS.size === EXPECTED_STEPUP_SUBS.length);
  const stepupSorted = [...STEPUP_SUBS].sort();
  const expectedStepupSorted = [...EXPECTED_STEPUP_SUBS].sort();
  ok("STEPUP_SUBS matches the documented set exactly", JSON.stringify(stepupSorted) === JSON.stringify(expectedStepupSorted));

  console.log("\nmachine-bearer surfaces:");
  const ingestScopes = Object.keys(INGEST_TTL_CAPS_SECONDS).sort();
  ok("IngestScope matches the documented set exactly (metrics, diagnostics, audit-feed)", JSON.stringify(ingestScopes) === JSON.stringify([...EXPECTED_INGEST_SCOPES].sort()));
  ok(
    "the SCIM offboard synthetic caller is recognised only by its exact email+subject pair",
    isScimOffboardCaller({ method: "token", email: SCIM_OFFBOARD_EMAIL, subject: SCIM_OFFBOARD_SUBJECT }) === true,
  );
  ok(
    "a caller merely presenting the SCIM offboard email (wrong subject) is NOT the synthetic caller",
    isScimOffboardCaller({ method: "token", email: SCIM_OFFBOARD_EMAIL, subject: "someone-elses-subject" }) === false,
  );
  ok(
    "an access/passkey caller can never BE the SCIM offboard synthetic caller",
    isScimOffboardCaller({ method: "access", email: SCIM_OFFBOARD_EMAIL, subject: SCIM_OFFBOARD_SUBJECT }) === false,
  );
  ok(
    "SCIM's own auth comment names its dedicated bearer, separate from ADMIN_TOKEN",
    citationHolds({ file: "src/admin/scim.ts", line: 14, mustContain: "SCIM_BEARER_TOKEN" }),
  );
  ok(
    "metrics' own auth comment names the read-only ingest-credential bearer",
    citationHolds({ file: "src/admin/metrics.ts", line: 6, mustContain: "READ-ONLY bearer" }),
  );
  ok(
    "support-credential minting is a bare owner-role check, not a Capability (so no custom role can ever inherit it)",
    citationHolds({ file: "src/admin/router-status.ts", line: 370, mustContain: 'caller.role !== "owner"' }),
  );
  ok(
    "the ADMIN_TOKEN break-glass resolves unconditionally to the owner role",
    citationHolds({ file: "src/sched/scheduler-do-rbac-authority.ts", line: 110, mustContain: 'role: "owner"' }),
  );

  console.log(failures === 0 ? "\nFIELD-ACCESS-MATRIX PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main();
