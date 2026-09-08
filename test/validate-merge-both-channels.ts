// Proves BOTH evidence channels ride on the one support bundle: the D5 section context (SupportBundleContext,
// which carries accessPerimeter) and the browser diagnostics ring (clientDiagnostics). buildSupportBundle /
// signedSupportBundle / sealedSupportBundle take a single SupportBundleContext with clientDiagnostics folded
// in, so there is one object and no positional collision between the two channels: a change that silently
// drops one of them (never a type error) would leave the pack missing a whole evidence section that nobody
// was looking for.
//
// It also pins that accessPerimeter must ride alongside clientDiagnostics on the one path a customer actually
// uses to generate a pack (POST /support/bundle).
import { buildSupportBundle } from "../src/admin/support.ts";
import { projectClientDiagnostics } from "../src/admin/client-diag-receive.ts";
import { CLIENT_DIAG_KINDS } from "../src/admin/client-diag-vocab.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// A scheduler double that answers every DO read with an empty value of the right SHAPE: this test is about
// PLUMBING, not content. List routes must answer with an array or the gatherers throw before we reach the point.
const ARRAY_ROUTES = /\/(downpipes|history|runs|config-events|notify\/history|audit)/;
const scheduler = {
  fetch: async (url: string) =>
    new Response(ARRAY_ROUTES.test(String(url)) ? "[]" : "{}", { headers: { "content-type": "application/json" } }),
} as unknown as DurableObjectStub;

const env = {} as Env;

// An already-projected console ring, shaped EXACTLY as ClientDiagnosticsSection (client-diag-vocab.ts):
// `records`, not `rows`. The shape matters, and getting it wrong here would make the dumped fixture a lie: the
// bot would reject the section as unknown and this whole pairing proof would be measuring a bundle no engine
// emits.
//
// ONE RECORD OF EVERY KIND, with its DISCRIMINATING FIELDS populated with real closed-vocabulary members. That
// is the whole point of this ring, and it did not used to be: the ring carried a single `engine-call` row, so
// the fixture the bot proves itself against exercised ONE of the twenty-one kinds and NONE of the fields the
// later waves added. The bot was six kinds behind for exactly that reason -- it silently dropped fifteen kinds
// of browser evidence and forbade auto-post on every customer-generated pack, with a green suite on both sides.
// A pairing proof is only worth what its payload covers, so this payload covers the vocabulary.
//
// Keep this in step with CLIENT_DIAG_KINDS: a new kind here means a new row, and the bot's engine-contract test
// asserts every kind in the engine's vocabulary survives into its facts.
const ring = {
  source: "client-asserted",
  receivedAt: "2026-07-12T00:00:00.000Z",
  engineAttempts: 40,
  // consoleBuild: the browser's own build stamp. The console sets it on EVERY session, so a fixture without it is
  // not the bundle a customer sends.
  consoleBuild: "0.1.10",
  records: [
    { kind: "engine-call", screen: "settings", httpClass: "4xx", faultClass: "auth", count: 1, firstMs: 100, lastMs: 900 },
    { kind: "contract-drift", screen: "restore", driftClass: "version-skew", count: 1, firstMs: 1000, lastMs: 1100 },
    { kind: "bulk-outcome", screen: "sources", reasonClass: "partial", count: 2, firstMs: 1200, lastMs: 1300 },
    { kind: "boot-fault", screen: "boot", faultClass: "other", bootClass: "chunk-preload-failed", errorClass: "TypeError", count: 1, firstMs: 10, lastMs: 20 },
    { kind: "unhandled", screen: "overview", faultClass: "other", errorClass: "TypeError", faultSource: "unhandled-rejection", count: 3, firstMs: 1400, lastMs: 1500 },
    { kind: "deep-link-lost", screen: "unknown-route", count: 1, firstMs: 1600, lastMs: 1600 },
    { kind: "apply-outcome", screen: "restore", applyClass: "wrote-none", count: 1, firstMs: 1700, lastMs: 1800 },
    { kind: "fanout-degraded", screen: "downpipes", count: 1, firstMs: 1900, lastMs: 1900 },
    { kind: "capability-fault", screen: "keys", capability: "blob-download", surface: "recovery-codes", capabilityOutcome: "refused", count: 1, firstMs: 2000, lastMs: 2000 },
    { kind: "console-build-check", screen: "updates", buildCheckClass: "wrong-version", count: 1, firstMs: 2100, lastMs: 2100 },
    { kind: "console-rollback", screen: "updates", rollbackClass: "not-sent", count: 1, firstMs: 2200, lastMs: 2200 },
    { kind: "identity-unresolved", screen: "security", count: 2, firstMs: 2300, lastMs: 2400 },
    { kind: "restore-gate-blocked", screen: "restore", gateBlockClass: "plan-hash-mismatch", count: 1, firstMs: 2500, lastMs: 2500 },
    { kind: "wire-anomaly", screen: "overview", fieldClass: "timestamp", anomaly: "unparseable", count: 4, firstMs: 2600, lastMs: 2700 },
    { kind: "transport-fault", screen: "overview", transportClass: "origin-rejected", count: 5, firstMs: 2800, lastMs: 2900 },
    { kind: "read-degraded", screen: "overview", callClass: "control-plane-status", count: 6, firstMs: 3000, lastMs: 3100 },
    { kind: "onboarding-step", screen: "sources", obStep: "readiness-poll", obOutcome: "poll-exhausted", count: 1, firstMs: 3200, lastMs: 3200 },
    { kind: "discovery-connect", screen: "sources", discoveryOutcome: "verified-zero-accounts", count: 1, firstMs: 3300, lastMs: 3300 },
    { kind: "claim-exchange", screen: "settings", claimResult: "empty-token-200", count: 1, firstMs: 3400, lastMs: 3400 },
    { kind: "admin-write", screen: "access", adminOp: "role-delete", writeOutcome: "unreachable", count: 1, firstMs: 3500, lastMs: 3500 },
    { kind: "recovery-refusal", screen: "settings", recoveryOp: "estate-import", recoveryCode: "DP-R12", count: 1, firstMs: 3600, lastMs: 3600 },
    // A capability-gated screen that rendered BEFORE the identity report landed, so every gate on it was
    // computed from the `viewer` default. Carries NO httpClass: nothing failed, the read simply had not returned.
    { kind: "identity-stale-gate", screen: "security", count: 1, firstMs: 3700, lastMs: 3700 },
    // The engine consulted the update channel and answered verified:false. channelReasonClass is the
    // discriminator between a silent signature failure and a channel host that is merely down.
    { kind: "update-channel-unverified", screen: "updates", channelReasonClass: "signature", count: 1, firstMs: 3800, lastMs: 3800 },
    // Each of these was a live kind in the console's vocabulary with no row in this fixture, so the bundle a
    // contract check reads never exercised it.
    { kind: "intent-dropped", screen: "restore", intentClass: "max-records-invalid", count: 1, firstMs: 4900, lastMs: 4900 },
    { kind: "probe-outcome", screen: "destinations", probeSurface: "dest-verify", probeOutcome: "dest-delete-denied", count: 1, firstMs: 5000, lastMs: 5000 },
    // dest-worm-days, not dest-s3-bucket: the bucket control carries no client-side validator (the ENGINE verifies
    // it, live), so the console can never emit that member and it is not in the vocabulary. dest-worm-days has a
    // real producer -- an explicit recordFormRejected at the destination submit -- so this row is one the product
    // can actually put in the ring, which is the only kind of row a contract fixture may assert.
    { kind: "form-rejected", screen: "destinations", formField: "dest-worm-days", rejectOutcome: "silently-coerced", count: 1, firstMs: 5100, lastMs: 5100 },
    { kind: "catalogue-degraded", screen: "sources", catalogueClass: "cf-no-accounts", count: 1, firstMs: 5200, lastMs: 5200 },
    { kind: "feature-probe", screen: "access", featureClass: "config-approvals", featureOutcome: "server-error", count: 1, firstMs: 5300, lastMs: 5300 },
    { kind: "gov-gate", screen: "access", govGate: "role-gate-refusal-shown", adminOp: "role-delete", count: 1, firstMs: 5400, lastMs: 5400 },
    // served-older-than-running, not console-behind: `console-behind` is not a member of CLIENT_DIAG_SKEW_CLASSES
    // and never was, so THIS ENGINE dropped the row on arrival and the fixture was asserting a record its own
    // receiver discards. The vocabulary names the two artefacts it compares (what the ORIGIN serves against what
    // is RUNNING in the tab), because that pair is the diagnosis and a single "behind" cannot express it.
    { kind: "console-skew", screen: "overview", skewClass: "served-older-than-running", count: 1, firstMs: 5500, lastMs: 5500 },
    // A further group of posture-related kinds.
    { kind: "material-rejected", screen: "keys", materialClass: "padding-present", count: 1, firstMs: 5600, lastMs: 5600 },
    { kind: "contract-skew", screen: "idp", contractClass: "missing-field", fieldFamily: "idp-connections", count: 1, firstMs: 5700, lastMs: 5700 },
    { kind: "fleet-drill", screen: "overview", drillAbort: "signed-out", drillFact: "targeted", count: 30, firstMs: 5800, lastMs: 5800 },
    // A further group of browser-side facts. Every one of these is a browser-side fact this
    // engine cannot hold: a dual-control refusal the console decided (no request was made), the grants a
    // custom-role delete silently downgraded, a resource the browser's own CSP blocked, part of a paste the
    // console dropped before submitting, a wizard pick lost between browser steps, and a key ceremony that runs
    // entirely in the browser.
    { kind: "owner-action-refusal", screen: "security", adminOp: "owner-action-approve", ownerActionCode: "expired", count: 1, firstMs: 5900, lastMs: 5900 },
    { kind: "role-delete-impact", screen: "access", count: 4, firstMs: 6000, lastMs: 6000 },
    { kind: "csp-violation", screen: "overview", cspDirective: "script-src", cspBlocked: "self", count: 1, firstMs: 6100, lastMs: 6100 },
    { kind: "input-dropped", screen: "idp", dropSurface: "idp-cert-paste", dropFact: "dropped", count: 1, firstMs: 6200, lastMs: 6200 },
    { kind: "handoff-dropped", screen: "sources", handoffClass: "wizard-spec-account-absent", count: 1, firstMs: 6300, lastMs: 6300 },
    { kind: "ceremony-step", screen: "keys", ceremonyStep: "shamir-split", ceremonyOutcome: "failed", ceremonyFault: "webcrypto", count: 1, firstMs: 6400, lastMs: 6400 },
    { kind: "storage-blocked", screen: "sources", storageArea: "session", storageOp: "write", storageClass: "denied", storageSurface: "draft", count: 1, firstMs: 6500, lastMs: 6500 },
    { kind: "renderer-degraded", screen: "overview", rendererMode: "svg-fallback", degradeCause: "canvas-blocked", count: 1, firstMs: 6600, lastMs: 6600 },
    { kind: "focus-landing", screen: "keys", focusOutcome: "dropped-detached", count: 1, firstMs: 6700, lastMs: 6700 },
  ],
  rollupByKind: { "engine-call": 1, "read-degraded": 40 },
} as never;

async function main(): Promise<void> {
  console.log("the merged bundle carries BOTH evidence channels:");

  // Guard the PAYLOAD before guarding the plumbing. A kind added to the vocabulary and not added to the ring
  // above leaves the dumped fixture silently under-covering it, and the bot's pairing proof then passes on a
  // payload that never exercised the new evidence -- which is the exact way the last drift went unseen.
  const rows = (ring as unknown as { records: Array<{ kind: string }> }).records;
  const covered = new Set(rows.map((r) => r.kind));
  const uncovered = CLIENT_DIAG_KINDS.filter((k) => !covered.has(k));
  ok(`the ring carries one record of EVERY kind (${CLIENT_DIAG_KINDS.length} kinds${uncovered.length > 0 ? `; MISSING: ${uncovered.join(", ")}` : ""})`, uncovered.length === 0);

  // DRIVE THE REAL RECEIVER, DO NOT HAND THE LITERAL STRAIGHT TO THE BUILDER. `ring` above is cast `as never`, so
  // TypeScript checks nothing about it: a member that no console can send, or one deleted from the vocabulary,
  // could otherwise ride into a fixture unchallenged and be validated against a shape the product cannot produce.
  //
  // projectClientDiagnostics IS the receiver the POST /support/bundle route runs. Putting the ring through it means
  // the fixture is one THIS ENGINE actually validated and would actually sign, and a dead or misspelled member now
  // fails HERE, loudly, instead of becoming a green test over dead evidence.
  const projected = projectClientDiagnostics(ring);
  ok("the engine's OWN receiver accepts the ring (a hand-built fixture is not evidence)", projected !== null);
  // Set<string>, not Set<ClientDiagKind>: `covered` is read off the `as never` ring and is therefore untyped
  // strings, and the whole point of the comparison below is to catch a kind the vocabulary does NOT contain.
  const kept = new Set<string>((projected?.records ?? []).map((r) => r.kind));
  const dropped = [...covered].filter((k) => !kept.has(k));
  ok(
    `the receiver KEEPS every row (a dropped row = a member no console can send${dropped.length > 0 ? `; DROPPED: ${dropped.join(", ")}` : ""})`,
    dropped.length === 0,
  );
  ok("the receiver carries consoleBuild through its shape gate", projected?.consoleBuild === "0.1.10");

  // `projected` rides as-is: SupportBundleContext.clientDiagnostics is declared `ClientDiagnosticsSection | null`,
  // so a rejected ring is passed through as the null the receiver produced rather than laundered to undefined.
  // The builder treats both the same (`clientDiagnostics ? {...} : {}`), so the bundle is byte-identical either way.
  const both = await buildSupportBundle(env, scheduler, { accessPerimeter: true, clientDiagnostics: projected });
  ok("the BROWSER evidence rides (clientDiagnostics), top-level", both["clientDiagnostics"] !== undefined);
  ok("the ACCESS PERIMETER boolean rides alongside it (the bug the merge surfaced)", both["accessPerimeter"] === true);

  // The two structural omissions must survive the merge as well: a bundle built off-request must not FABRICATE
  // either channel. An empty clientDiagnostics section would read as "the browser saw no errors", which is a
  // different and much worse claim than "no browser evidence was supplied".
  const neither = await buildSupportBundle(env, scheduler, {});
  ok("a bundle built with NO console ring omits clientDiagnostics STRUCTURALLY (never an empty section)", neither["clientDiagnostics"] === undefined);
  ok("a bundle built off-request omits accessPerimeter rather than asserting a false 'no perimeter'", neither["accessPerimeter"] === undefined);

  // And the D5 section context still composes: the sections roster must not have been lost.
  // --dump <path> writes the BOTH-CHANNELS bundle, so it can be checked against the one shape a
  // customer actually produces (the console-generate POST, which is the only path that carries the ring).
  const dumpAt = process.argv.indexOf("--dump");
  if (dumpAt !== -1 && process.argv[dumpAt + 1] !== undefined) {
    const { writeFileSync } = await import("node:fs");
    writeFileSync(process.argv[dumpAt + 1] as string, `${JSON.stringify(both, null, 2)}\n`);
    console.log(`dumped the both-channels bundle to ${process.argv[dumpAt + 1]}`);
  }

  ok("the D5 sections roster survives the merge (idpCertHealth is still gathered)", (neither["sections"] as Record<string, unknown>)["idpCertHealth"] !== undefined);

  console.log(failures === 0 ? "\nMERGE BOTH-CHANNELS: ALL PASS" : `\nMERGE BOTH-CHANNELS: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
