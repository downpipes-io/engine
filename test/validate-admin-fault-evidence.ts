// validate-admin-fault-evidence: the ADMIN subsystem's support-pack fault evidence.
//
//   The runtime wrap-key UNWRAP fault timeline (a rotated key vs a damaged record vs an unbound env var
//         vs a malformed key -- four different remediations that would otherwise read as ONE lazily-failing
//         destination error, days after the change, with no first-failure timestamp anywhere).
//   The DRILL's discriminating detail: how many records failed, WHICH one first, WHICH archive object
//         the destination could not produce, WHICH engine binding was absent, and the break-glass-only posture
//         as an HONEST REFUSAL rather than a failure.
//   The DEGRADED READS a Durable Object fault renders as honest-looking ABSENT CONFIGURATION.
//   The POST-WRITE BINDING-SAFETY alarms that would otherwise live only in one operator's browser tab.
//   The self-update pipeline's fault ring: the step that failed, the channel three-way collapse (a truncated
//         CDN object reported as "signature did not verify"), the six-way artefact-download collapse, the
//         lifecycle records that could fail to persist AFTER a live deploy, and the NAMES of the source
//         bindings an update dropped (the owner's #1 fear: the count is audited and the names ride the HTTP
//         response).
//   The router-local SSO legs + the IdP's OWN error code, neither of which can ever reach the DO's
//         classifier -- so the pack would otherwise show ZERO SSO failures through an outage full of them.
//   The vendor / SIEM pull surface's own failure counters.
//   The admin REFUSAL trail, including the gate-unavailable split ("our approved restore said
//         not-approved" is either a missing approval or a DO fault, and the two are otherwise indistinguishable).
//
// THE BINDING PROPERTY (no-custody): every recorded field is a closed enum member, a count, a clamped int, a
// boolean, a clamped timestamp, Cloudflare's own integer error codes, the sha384 of a PUBLIC release artefact,
// or the operator's OWN binding / archive-object label (the class the pack already ships). To PROVE it, each
// case plants a customer SENTINEL (an email, a bucket, an object key, a secret, an access key id, a raw
// provider message) at the fault site and asserts the sentinel appears in NO BYTE of the resulting record.

import {
  ADMIN_COUNTER_NAMES,
  ADMIN_REFUSAL_REASONS,
  ADMIN_REFUSAL_SURFACES,
  applyAdminRefusal,
  applyBindingAlarm,
  applyRestoreFault,
  applyUnwrapFault,
  applyUpdateFault,
  BINDING_ALARM_KINDS,
  classifyChannelFetchCause,
  classifyRestoreFaultClass,
  classifyUpdateFailStep,
  cfCauseFromStatus,
  UNWRAP_FAULT_CAUSES,
  unwrapFaultCauseOf,
  UPDATE_CAUSE_CLASSES,
  UPDATE_FAIL_STEPS,
  UnwrapFaultError,
  type AdminRefusals,
  type BindingAlarmRow,
  type RestoreFaultRow,
  type UnwrapFaults,
  type UpdateFaultRow,
} from "../src/admin/diag-records.ts";
import { bindingAlarmOf, verifyAfter, type LiveBinding } from "../src/admin/attach-plan.ts";
import { drillFaultRows } from "../src/admin/restore-faults.ts";
import { loadConfigWrapKey, resolveConfigSecret, wrapConfigSecret } from "../src/admin/config-secret.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { idpErrorSignalName, ssoEdgeSignalName, IDP_ERROR_CODES } from "../src/admin/sso-failure-class.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(name: string, cond: boolean, detail?: string): void {
  if (cond) {
    console.log(`  ok  ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ""}`);
  }
}

// SENTINELS: the customer values planted at each fault site. Not one of them may appear in any recorded byte.
const SENTINELS = [
  "alice@customer-hospital.example", // an operator email
  "acme-prod-backups-eu-west-1", // a destination bucket
  "AKIAIOSFODNN7EXAMPLE", // an access key id
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // a secret access key
  "https://a1b2c3.r2.cloudflarestorage.com", // a destination endpoint
  "patients/2026/ward-7-admissions.json", // a customer record name
  "The AWS Access Key Id you provided does not exist in our records.", // a raw provider message
];

/**
 * assertNoSentinels serialises a record and asserts that NO planted customer value survives into it. This is
 * the redaction proof: it is applied to the JSON the DO would actually persist, so it covers every field, not
 * only the ones the test happened to read.
 *
 * @param name - the case name.
 * @param record - the record as the DO would store it.
 */
function assertNoSentinels(name: string, record: unknown): void {
  const bytes = JSON.stringify(record);
  const leaked = SENTINELS.filter((s) => bytes.includes(s));
  ok(`${name}: redaction-safe (no customer sentinel in any recorded byte)`, leaked.length === 0, leaked.length > 0 ? `LEAKED: ${leaked.join(", ")}` : undefined);
}

console.log("validate-admin-fault-evidence");

// ---------------------------------------------------------------------------------------------------------
// The wrap-key unwrap fault timeline
// ---------------------------------------------------------------------------------------------------------
console.log("\nwrap-key unwrap faults (admin/config-secret.ts -> dest/factory.ts)");
{
  const keyA = new Uint8Array(32).fill(7);
  const keyB = new Uint8Array(32).fill(9); // the ROTATED key

  // (a) a ROTATED key: the envelope is well-formed and the configured key does not open it.
  const env1 = await wrapConfigSecret(keyA, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
  let rotatedCause: string | null = null;
  try {
    await resolveConfigSecret(keyB, env1);
  } catch (e) {
    rotatedCause = unwrapFaultCauseOf(e);
  }
  ok("a rotated CONFIG_WRAP_KEY tags aead-tag (the key is wrong; restore the prior key)", rotatedCause === "aead-tag", `got ${rotatedCause}`);

  // (b) a DAMAGED stored record: undecodable base64url. This must be distinguished from (a): merging the two
  //     would tell the operator to restore a previous key that could never have opened it.
  let corruptCause: string | null = null;
  try {
    await resolveConfigSecret(keyA, { v: 1, iv: "!!!not-base64url!!!", ct: "@@@" });
  } catch (e) {
    corruptCause = unwrapFaultCauseOf(e);
  }
  ok("a damaged envelope tags envelope-corrupt, NOT aead-tag (an opposite remediation)", corruptCause === "envelope-corrupt", `got ${corruptCause}`);

  // (c) the env var was dropped by a deploy: the credential is encrypted and there is no key at all.
  let missingCause: string | null = null;
  try {
    await resolveConfigSecret(undefined, env1);
  } catch (e) {
    missingCause = unwrapFaultCauseOf(e);
  }
  ok("an unbound CONFIG_WRAP_KEY tags key-missing", missingCause === "key-missing", `got ${missingCause}`);

  // (d) a malformed key stops the WHOLE fleet, not one downpipe.
  let malformedCause: string | null = null;
  try {
    loadConfigWrapKey("c2hvcnQ"); // decodes to fewer than 32 bytes
  } catch (e) {
    malformedCause = unwrapFaultCauseOf(e);
  }
  ok("a malformed CONFIG_WRAP_KEY tags key-malformed", malformedCause === "key-malformed", `got ${malformedCause}`);

  // (e) a corrupt STORED SHAPE (neither plaintext nor envelope).
  let shapeCause: string | null = null;
  try {
    await resolveConfigSecret(keyA, { v: 2, nope: true } as unknown as { v: 1; iv: string; ct: string });
  } catch (e) {
    shapeCause = unwrapFaultCauseOf(e);
  }
  ok("a corrupt stored record tags envelope-shape", shapeCause === "envelope-shape", `got ${shapeCause}`);

  // An UNTAGGED throw must never be guessed at (that is precisely the free-text leak the tag prevents).
  ok("an untagged error yields null (never a guess from its message)", unwrapFaultCauseOf(new Error("The AWS Access Key Id you provided does not exist in our records.")) === null);

  // The RECORD: first-failure timestamp is never overwritten (the "when did this start?" fact).
  let rec: UnwrapFaults | undefined;
  rec = applyUnwrapFault(rec, "aead-tag", 1_000);
  rec = applyUnwrapFault(rec, "aead-tag", 5_000);
  rec = applyUnwrapFault(rec, "aead-tag", 9_000);
  ok("the record counts every fault", rec["aead-tag"]?.count === 3);
  ok("firstAt is the FIRST failure and is never overwritten", rec["aead-tag"]?.firstAt === 1_000);
  ok("lastAt advances", rec["aead-tag"]?.lastAt === 9_000);

  // Defence in depth: an out-of-vocabulary cause is DROPPED, so no caller can inject a key into the record.
  const before = JSON.stringify(rec);
  rec = applyUnwrapFault(rec, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 10_000);
  ok("an out-of-vocabulary cause is DROPPED (never a caller-injected key)", JSON.stringify(rec) === before);
  ok("the cause vocabulary is closed and complete", UNWRAP_FAULT_CAUSES.length === 5);
  assertNoSentinels("unwrapFaults", rec);
}

// ---------------------------------------------------------------------------------------------------------
// The drill's discriminating detail
// ---------------------------------------------------------------------------------------------------------
console.log("\nthe restore drill's discriminating detail (admin/drill.ts)");
{
  // (a) the BREAK-GLASS-ONLY posture: an honest refusal, no longer filed as a failure.
  const posture = drillFaultRows({
    ok: false,
    reason: "break-glass-only posture: no in-account read-back key. Exercise recovery offline with the break-glass key and the downpipe CLI.",
    missingBinding: "operational-private",
  });
  ok("a break-glass-only drill classifies posture-unexercisable, NOT a failure class", posture[0]?.cls === "posture-unexercisable", `got ${posture[0]?.cls}`);
  ok("...and names the absent binding", posture[0]?.binding === "operational-private");

  // (b) a WIPED SIGNER_PRIVATE reads as a bad archive today. It must name the binding instead.
  ok("a wiped SIGNER_PRIVATE is a not-configured class (not an integrity fault)", classifyRestoreFaultClass("missing required configuration: SIGNER_PRIVATE") === "not-configured");

  // (c) a corrupt record deep in the archive: the blast radius + the FIRST failing index + the missing object.
  const corrupt = drillFaultRows({
    ok: false,
    reason: "integrity check failed",
    failedRecordCount: 3,
    firstFailedIndex: 401,
    missingObjectKey: "downpipes/dp_7f3a/runs/2026-07-10T02-00-00Z/chunk-000401.dpk",
  });
  ok("a corrupt archive is an integrity fault in the VERIFY phase (nothing was written)", corrupt[0]?.cls === "integrity" && corrupt[0]?.phase === "verify");
  ok("the blast radius rides (3 records failed, not 1 and not 500)", corrupt[0]?.count === 3);
  ok("the FIRST failing index rides (records 0-400 verify; 401 does not)", corrupt[0]?.index === 401);
  ok("the ENGINE-WRITTEN archive object key rides", corrupt[0]?.recordName?.includes("chunk-000401") === true);

  // (d) a PASSING drill records nothing at all (the healthy steady state costs nothing).
  ok("a passing drill projects no row", drillFaultRows({ ok: true }).length === 0);

  // The DO-side chokepoint re-validates every field: an out-of-vocabulary binding and a negative index are
  // dropped, and the archive key is control-stripped + clamped.
  let ring: RestoreFaultRow[] | undefined;
  ring = applyRestoreFault(ring, { ...corrupt[0], binding: "alice@customer-hospital.example", index: -5 }, 42);
  ok("an out-of-vocabulary binding is DROPPED by the DO-side applier", ring[0]?.binding === undefined);
  ok("a negative index is DROPPED", ring[0]?.index === undefined);
  ring = applyRestoreFault(ring, { op: "drill", phase: "open", cls: "object-missing", recordName: `x\n${"A".repeat(400)}` }, 43);
  ok("a record label is control-stripped and clamped to 128", (ring[1]?.recordName?.length ?? 0) === 128 && ring[1]?.recordName?.includes("\n") === false);
  assertNoSentinels("restoreFaults ring", ring);

  // The raw provider message the drill saw must NEVER become the record.
  const fromProviderMessage = classifyRestoreFaultClass("The AWS Access Key Id you provided does not exist in our records.");
  ok("a raw provider message coarsens to a closed class and returns the ENUM, never the text", fromProviderMessage === "other");
}

// ---------------------------------------------------------------------------------------------------------
// The degraded reads
// ---------------------------------------------------------------------------------------------------------
console.log("\ndegraded reads rendered as absent configuration");
{
  const sites = ADMIN_COUNTER_NAMES.filter((n) => n.startsWith("degraded-read-"));
  ok("all nine degraded-read sites have a closed counter name", sites.length === 9, `got ${sites.length}: ${sites.join(", ")}`);
  for (const s of ["degraded-read-preflight-roster", "degraded-read-dest-status", "degraded-read-setup-state", "degraded-read-discovery-config", "degraded-read-providers-list", "degraded-read-lockout-preflight", "degraded-read-whoami", "degraded-read-engine-account", "degraded-read-status-presence"]) {
    ok(`  ${s} is in the closed vocabulary`, (ADMIN_COUNTER_NAMES as readonly string[]).includes(s));
  }
  // The residual is ACKNOWLEDGED and itself counted: a bump lost to a total DO outage lands in droppedWrites
  // under kind "admin-counter" (proved by validate-admin-diag / the diag-writer's own validator).
}

// ---------------------------------------------------------------------------------------------------------
// The post-write binding-safety alarms
// ---------------------------------------------------------------------------------------------------------
console.log("\npost-write binding-safety alarms (admin/attach-plan.ts verifyAfter)");
{
  const engineBindings: LiveBinding[] = [
    { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" } as unknown as LiveBinding,
    { type: "durable_object_namespace", name: "RUNSEAL", class_name: "RunSealDO" } as unknown as LiveBinding,
  ];
  // A binding that existed before, was not an intended removal, and is GONE afterwards: the settings PATCH
  // dropped it, and its source will fail on its next run. The customer's binding label rides; nothing else.
  const before: LiveBinding[] = [...engineBindings, { type: "kv_namespace", name: "PATIENTS_KV" } as unknown as LiveBinding];
  let tagged: { kind: string; names: string[] } | null = null;
  try {
    verifyAfter(before, [], [], engineBindings);
  } catch (e) {
    tagged = bindingAlarmOf(e);
  }
  ok("a dropped binding raises a TAGGED postwrite-binding-missing alarm", tagged?.kind === "postwrite-binding-missing", `got ${tagged?.kind}`);
  ok("...and names the binding (the operator's own label, the sourcesDetached class)", tagged?.names[0] === "PATIENTS_KV");

  // A concurrent writer's binding in the after-read PROVES one of the two writes was a lost update.
  let race: { kind: string; names: string[] } | null = null;
  try {
    verifyAfter(engineBindings, [], [], [...engineBindings, { type: "kv_namespace", name: "SOMEONE_ELSES_KV" } as unknown as LiveBinding]);
  } catch (e) {
    race = bindingAlarmOf(e);
  }
  ok("a concurrent writer's binding raises a TAGGED lost-update-race alarm", race?.kind === "lost-update-race", `got ${race?.kind}`);

  // An ordinary (untagged) refusal records nothing: only genuine post-write alarms ride.
  ok("an untagged error yields null (an ordinary refusal records no alarm)", bindingAlarmOf(new Error("acme-prod-backups-eu-west-1 refused")) === null);

  // The DO-side chokepoint: out-of-vocabulary kinds dropped, names control-stripped/clamped/capped.
  let ring: BindingAlarmRow[] | undefined;
  ring = applyBindingAlarm(ring, { kind: tagged?.kind, bindingNames: tagged?.names }, 100);
  ok("the alarm lands in the bounded ring", ring.length === 1 && ring[0]?.kind === "postwrite-binding-missing");
  const beforeJson = JSON.stringify(ring);
  ring = applyBindingAlarm(ring, { kind: "The AWS Access Key Id you provided does not exist in our records.", bindingNames: ["X"] }, 101);
  ok("an out-of-vocabulary kind is DROPPED", JSON.stringify(ring) === beforeJson);
  ring = applyBindingAlarm(ring, { kind: "postwrite-do-missing", bindingNames: Array.from({ length: 40 }, (_, i) => `B${i}\n`) }, 102);
  ok("the name list is capped at 16 and control-stripped", (ring[1]?.bindingNames.length ?? 0) === 16 && ring[1]?.bindingNames.every((n) => !n.includes("\n")) === true);
  ok("the alarm-kind vocabulary is closed", BINDING_ALARM_KINDS.length === 6);
  assertNoSentinels("bindingAlarms ring", ring);
}

// ---------------------------------------------------------------------------------------------------------
// The self-update pipeline's fault ring
// ---------------------------------------------------------------------------------------------------------
console.log("\nthe self-update pipeline's fault ring");
{
  // The channel three-way collapse. A TRUNCATED CDN object reads as "signature did not verify" if the three
  // causes are not split, sending support on a key-pinning chase. The three causes are three different tickets.
  ok("channel: a refused redirect is its own cause (a signed update must never be steered elsewhere)", classifyChannelFetchCause(302) === "redirect-refused");
  ok("channel: a CDN 404 is fetch-status-4xx (the signed channel names an artefact that is not there)", classifyChannelFetchCause(404) === "fetch-status-4xx");
  ok("channel: a CDN 5xx is fetch-status-5xx (wait, do not re-pin the key)", classifyChannelFetchCause(503) === "fetch-status-5xx");
  ok("channel: a fetch that THREW has no status and is a network fault", classifyChannelFetchCause(0) === "network");
  ok("channel: a 200 with no bytes is empty-body", classifyChannelFetchCause(200, { empty: true }) === "empty-body");

  // The step identity. The refusal reason is a 200-char sentence already coarsened by msg(); every step
  // has a DIFFERENT remediation. The classifier reads the engine's own literals and returns the enum only.
  const cases: Array<[string, string, string]> = [
    ["could not read the engine's current settings to preserve its bindings before uploading the new version (Cloudflare: HTTP 403)", "read-settings", "other"],
    ["Cloudflare returned no deployments for \"downpipe-engine\", so there is no current live version to roll back to", "read-deployments", "no-rollback-target"],
    ["refusing to upload a new version: the engine has binding type(s) the safe-apply pipeline cannot guarantee to preserve", "binding-guard", "binding-uncarryable"],
    ["the console bundle is not valid JSON; refusing it (nothing was changed)", "parse-bundle", "bundle-invalid"],
    ["the console asset manifest was not accepted (Cloudflare: HTTP 500)", "asset-session", "asset-token-absent"],
    ["Cloudflare requested an asset hash that is not in the verified console bundle", "asset-upload", "asset-hash-unknown"],
    ["the new version could not be uploaded (Cloudflare: HTTP 413); your engine is unchanged", "version-post", "other"],
    ["could not make version abc the live deployment (Cloudflare: HTTP 500)", "promote", "promote-failed"],
    ["the version read-back response shape was not recognised (keep the raw response as the OA-3 experiment fixture)", "readback", "readback-unknown-shape"],
  ];
  for (const [msg, step, cause] of cases) {
    const got = classifyUpdateFailStep(new Error(msg));
    ok(`  step: ${step} / ${cause}`, got.step === step && got.cause === cause, `got ${got.step}/${got.cause}`);
  }
  // The HTTP status refines an unclassified upload cause into the token-scope vs CF-incident split.
  ok("an upload 4xx refines to upload-4xx (a token scope: the operator fixes it)", cfCauseFromStatus("version-post", "other", 403) === "upload-4xx");
  ok("an upload 5xx refines to upload-5xx (a Cloudflare incident: they wait)", cfCauseFromStatus("version-post", "other", 502) === "upload-5xx");
  ok("a 429 refines to quota", cfCauseFromStatus("version-post", "other", 429) === "quota");

  // The RING: every field is re-validated DO-side.
  let ring: UpdateFaultRow[] | undefined;
  // The NAMES of the source bindings an update dropped (the owner's #1 fear).
  ring = applyUpdateFault(ring, { component: "engine", step: "binding-guard", cause: "sources-dropped", droppedSources: ["PATIENTS_KV", "PATIENTS_KV", "LEDGER_D1"] }, 1);
  ok("the dropped source-binding NAMES ride (deduped)", JSON.stringify(ring[0]?.droppedSources) === JSON.stringify(["PATIENTS_KV", "LEDGER_D1"]));
  // The lifecycle record that can fail to persist AFTER a live deploy.
  ring = applyUpdateFault(ring, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "pending" }, 2);
  ok("a lost lifecycle record is a durable marker (the engine is LIVE and nothing recorded it)", ring[1]?.recordPhase === "pending" && ring[1]?.cause === "record-write-failed");
  // The auto-rollback that ITSELF failed, and Cloudflare's own integer codes.
  ring = applyUpdateFault(ring, { component: "engine", step: "rollback", cause: "rollback-failed", rollbackFailed: true, httpStatus: 500, cfCodes: [10021, 10000] }, 3);
  ok("the rollback-failed latch rides (the engine is limping on a BAD version)", ring[2]?.rollbackFailed === true);
  ok("Cloudflare's OWN integer error codes ride (a fixed vendor vocabulary)", JSON.stringify(ring[2]?.cfCodes) === JSON.stringify([10021, 10000]));

  // Defence in depth: out-of-vocabulary rows dropped; every carried field clamped or shape-gated.
  const beforeJson = JSON.stringify(ring);
  ring = applyUpdateFault(ring, { component: "engine", step: "promote", cause: "The AWS Access Key Id you provided does not exist in our records." }, 4);
  ok("an out-of-vocabulary cause is DROPPED (never a caller-injected message)", JSON.stringify(ring) === beforeJson);
  ring = applyUpdateFault(
    ring,
    {
      component: "engine",
      step: "digest-check",
      cause: "digest-mismatch",
      httpStatus: 99999,
      cfCodes: ["alice@customer-hospital.example", 7],
      observedSha384: "The AWS Access Key Id you provided does not exist in our records.",
      droppedSources: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "ok\nname", ...Array.from({ length: 200 }, (_, i) => `B${i}`)],
      readbackShape: { topLevelKeys: 9999, hasSuccess: true, hasResult: "yes", hasErrors: 1 },
    },
    5,
  );
  const row = ring[ring.length - 1]!;
  ok("httpStatus is clamped to 0..599", row.httpStatus === 599);
  ok("a non-integer cfCode is dropped", JSON.stringify(row.cfCodes) === JSON.stringify([7]));
  ok("observedSha384 is accepted ONLY as 96 hex digits (so no message can ride in it)", row.observedSha384 === undefined);
  ok("droppedSources are SHAPE-GATED to binding names, control-stripped and capped at 64", (row.droppedSources?.length ?? 0) === 64 && row.droppedSources?.[0] === "okname" && row.droppedSources?.every((n) => /^[A-Za-z0-9_-]{1,64}$/.test(n)) === true);
  ok("the read-back descriptor is clamped ints + strict booleans (no CF key names, no body)", row.readbackShape?.topLevelKeys === 64 && row.readbackShape?.hasResult === false && row.readbackShape?.hasErrors === false);
  ok("the step vocabulary is closed", UPDATE_FAIL_STEPS.length === 15);
  ok("the cause vocabulary is closed", UPDATE_CAUSE_CLASSES.length === 26);
  assertNoSentinels("updateFaults ring", ring);
}

// ---------------------------------------------------------------------------------------------------------
// The router-local SSO legs and the IdP's own error code
// ---------------------------------------------------------------------------------------------------------
console.log("\nrouter-local SSO failures + the IdP's OWN error code");
{
  for (const c of IDP_ERROR_CODES) {
    ok(`  ${idpErrorSignalName(c)} is in the closed auth-signal vocabulary`, (AUTH_SIGNAL_NAMES as readonly string[]).includes(idpErrorSignalName(c)));
  }
  for (const e of ["edge-parse", "edge-transport", "edge-metadata-unavailable", "edge-providers-unavailable"] as const) {
    ok(`  ${ssoEdgeSignalName(e)} is in the closed auth-signal vocabulary`, (AUTH_SIGNAL_NAMES as readonly string[]).includes(ssoEdgeSignalName(e)));
  }
  // The IdP's `?error=` is an ATTACKER-INFLUENCEABLE query string. It is mapped through a CLOSED set, so a
  // hostile (or merely vendor-specific) value can never inject a key into the bounded aggregate.
  ok("a registry error code maps to its own signal (kebab-folded, a bare identifier)", idpErrorSignalName("invalid_client") === "sso-idp-error-invalid-client");
  ok("an UNKNOWN error code coarsens to `other` (never the raw value)", idpErrorSignalName("alice@customer-hospital.example") === "sso-idp-error-other");
  ok("a hostile 5,000-char error coarsens to `other`", idpErrorSignalName("A".repeat(5000)) === "sso-idp-error-other");
  ok("a non-string error coarsens to `other`", idpErrorSignalName({ evil: true }) === "sso-idp-error-other");
  assertNoSentinels("idp error signal", [idpErrorSignalName("alice@customer-hospital.example"), idpErrorSignalName("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")]);
}

// ---------------------------------------------------------------------------------------------------------
// The vendor / SIEM pull surface
// ---------------------------------------------------------------------------------------------------------
console.log("\nthe vendor / SIEM pull surface's own failure counters");
{
  for (const n of ["ingest-pull-auth-failed", "ingest-pull-grant-unreadable", "ingest-pull-bad-cursor", "ingest-pull-seal-failed", "ingest-pull-audit-export-failed", "ingest-pull-gap-served"]) {
    ok(`  ${n} is in the closed vocabulary`, (ADMIN_COUNTER_NAMES as readonly string[]).includes(n));
  }
  // The outward 401 stays FLAT (anti-enumeration): these are recorded pack-side only, never oracled back.
}

// ---------------------------------------------------------------------------------------------------------
// The admin refusal trail (and the gate-unavailable split)
// ---------------------------------------------------------------------------------------------------------
console.log("\nthe admin refusal trail");
{
  let agg: AdminRefusals | undefined;
  // THE MARQUEE SPLIT: "our approved restore said not-approved" is either a missing approval or a DO fault
  // that refused FAIL-CLOSED while a perfectly valid approval sat in storage. The RESPONSE is byte-identical
  // in both cases (deliberately), and the pack could not tell them apart.
  agg = applyAdminRefusal(agg, "restore-apply", "not-approved", "2026-07-10T00:00:00.000Z");
  agg = applyAdminRefusal(agg, "restore-apply", "gate-unavailable", "2026-07-10T00:01:00.000Z");
  ok("a genuinely missing approval and a DO-faulted GATE are DIFFERENT rows", agg["restore-apply:not-approved"]?.count === 1 && agg["restore-apply:gate-unavailable"]?.count === 1);

  agg = applyAdminRefusal(agg, "dest-add", "validation", "2026-07-10T00:02:00.000Z");
  agg = applyAdminRefusal(agg, "dest-add", "validation", "2026-07-10T00:03:00.000Z");
  ok("repeated attempts re-bump ONE bounded counter (never a new storage row)", agg["dest-add:validation"]?.count === 2);

  // Defence in depth: BOTH axes are closed, so the key space is bounded by their product.
  const beforeJson = JSON.stringify(agg);
  agg = applyAdminRefusal(agg, "acme-prod-backups-eu-west-1", "validation", "2026-07-10T00:04:00.000Z");
  agg = applyAdminRefusal(agg, "dest-add", "The AWS Access Key Id you provided does not exist in our records.", "2026-07-10T00:05:00.000Z");
  ok("an out-of-vocabulary surface is DROPPED", JSON.stringify(agg) === beforeJson);
  ok("an out-of-vocabulary reason is DROPPED", JSON.stringify(agg) === beforeJson);
  // The SURFACE axis covers the governance / people / notify writes (the dual-control switch, the change-number
  // policy, the sign-in-context policy, the notify channels and rules, the expiry items, the custom roles, the
  // posture overrides, the recovery-code regeneration and the break-glass retire), so a refusal on any of them
  // is evidence rather than "I turned dual control on last week and it is off" reading as no evidence anywhere.
  // The op rides IN the surface name wherever the remedy differs (a failed channel CREATE and a failed channel
  // DELETE are different tickets), which keeps the key a bounded 2-D product rather than growing a third axis.
  //
  // The REASON axis is deliberately kept small. A `change-control` member would be dead evidence: the
  // change-number gate lives inside the DO and refuses by throwing a plain Error, so the hub recorder -- which
  // classifies from the STATUS -- cannot tell it from a shape refusal and could only ever guess. A member nothing
  // can honestly write is dead evidence wearing a discriminator's clothes. The fork is already carried by
  // configIntegrity.changeControlRefusals and the governanceRefusals ring, in the same pack.
  ok("both axes are closed vocabularies", ADMIN_REFUSAL_SURFACES.length === 27 && ADMIN_REFUSAL_REASONS.length === 11);
  // `restore-proof` is its own surface. A restorability PROOF (a blind verify or a keyless attest) refused
  // BEFORE it runs, runs no restore, writes no evidence and stamps no downpipe, so a week of refused proofs and
  // a week in which nobody drilled leave the pack IDENTICAL (the same stale lastRestoreProvenAt), and they are
  // opposite tickets. It is deliberately its own surface rather than folded into `drill` or `restore-apply`,
  // which are different refusals with different remedies.
  ok("a refused restorability PROOF has a surface of its own", (ADMIN_REFUSAL_SURFACES as readonly string[]).includes("restore-proof"));
  assertNoSentinels("adminRefusals", agg);
}

// ---------------------------------------------------------------------------------------------------------
// The tagged errors themselves must never widen the operator-facing contract.
// ---------------------------------------------------------------------------------------------------------
console.log("\nthe tags never change the operator-facing message");
{
  const e = new UnwrapFaultError("aead-tag", "the configured CONFIG_WRAP_KEY does not decrypt this destination credential");
  ok("UnwrapFaultError is an Error and keeps its message byte-identical", e instanceof Error && e.message.startsWith("the configured CONFIG_WRAP_KEY"));
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-admin-fault-evidence (${failures} failure(s))`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
