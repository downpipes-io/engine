// Prove restorePlanHash (src/admin/approvals.ts) is REPRODUCIBLE for the same input and
// parity-safe, so the request route, the approve flow, the apply lookup and the console mirror all
// compute the SAME binding key. No network, no deploy, no cost. Run:
//   node test/validate-restoreplanhash.ts
//
// The plan hash is the dual-control teeth: an approval is keyed by it, so the apply route can find
// the approval from the apply request ALONE (no re-run of the dry-run, no race), approving "this
// exact restore" cannot be reused for a different one, and any change to a decision-relevant field
// yields a DIFFERENT hash with no matching approval (the visible re-arm-on-change UX). All of that
// rests on the hash being a pure, stable function of the request's decision fields. This validator
// pins those properties:
//
//  REPRODUCIBLE: the same RestoreRequest hashes identically across repeated calls, across freshly
//    constructed equal objects, and (the parity property) equals an INDEPENDENT recomputation that
//    builds the same canonical PlanBinding and runs canonicalJSON + SHA-384 + hex with the "sha384:"
//    prefix. A console mirror that builds the identical canonical form gets the identical answer.
//
//  PRESENCE-EQUIVALENT (exactOptionalPropertyTypes): an absent optional field and an
//    explicit-undefined optional field hash identically (target subfields, maxRecords); and a missing
//    include/exclude hashes the same as an explicit empty array (the default is []).
//
//  ORDER-INDEPENDENT where canonical JSON sorts (the target object's key order does not matter),
//    but ORDER-SENSITIVE where order is semantic (include/exclude are arrays: a different element
//    order is a different selector and MUST hash differently).
//
//  RE-ARM-ON-CHANGE: changing the runId, the target binding/namespace/bucket, the include/exclude
//    selectors, maxRecords, recordName, destinationId, the cfConfig account/zone, or the mediaRestore
//    account each yields a distinct hash; while changing a NON-decision field (confirm: the dry-run/apply
//    toggle, or the EXCLUDED cfConfig/mediaRestore token secret) does NOT change the hash, because the
//    binding is over the non-secret decision fields only and an apply for the same plan must match the
//    request's hash. The granular-record / cf-config / media targets each carry their OWN approval, and so
//    does destinationId: an apply against a DIFFERENT destination than the one the approver's cues
//    were computed from can never reuse that approval.
//
//  REDACTION-SAFE shape: the hash is "sha384:" + 96 hex chars; it folds in only names/counts/
//    selectors, never a value (this is a shape proof, the no-secret guarantee is structural).
//
// In-memory / pure only; this exercises the real production restorePlanHash and the real crypto +
// canonical-JSON primitives, with an independent recomputation as the parity oracle.

import { restorePlanHash } from "../src/admin/approvals.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode } from "../src/crypto/bytes.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import type { RestoreRequest } from "../src/admin/restore-types.ts";
// Registry DATA, not the production resolver. The oracle must resolve the in-band surface set on
// its own so a divergence between the two resolutions is caught here rather than widening an approval.
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const RUN_A = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RUN_B = "01BX5ZZKBKACTAV9WEVGEMMVRZ";

// independentHash is the PARITY ORACLE: a SEPARATE implementation of the binding-hash, built to the
// contract's stated shape (canonical PlanBinding -> canonicalJSON -> SHA-384 -> hex, "sha384:"
// prefix), NOT importing the production helper. A console mirror that builds the same canonical
// PlanBinding and runs the same primitives must land here, so if this matches restorePlanHash the
// shapes have not drifted. It deliberately reconstructs the optional-key inclusion rule (a key is
// present only when it carries a value) so the presence-equivalence proofs are meaningful.
async function independentHash(req: RestoreRequest): Promise<string> {
  const target = req.target
    ? {
        ...(req.target.binding !== undefined ? { binding: req.target.binding } : {}),
        ...(req.target.namespaceId !== undefined ? { namespaceId: req.target.namespaceId } : {}),
        ...(req.target.bucketName !== undefined ? { bucketName: req.target.bucketName } : {}),
      }
    : null;
  const binding = {
    runId: req.runId,
    target,
    include: req.include ?? [],
    exclude: req.exclude ?? [],
    ...(req.maxRecords !== undefined ? { maxRecords: req.maxRecords } : {}),
    ...(req.recordName !== undefined ? { recordName: req.recordName } : {}),
    // destinationId binds WHICH archive copy the plan was reviewed against.
    ...(req.destinationId !== undefined ? { destinationId: req.destinationId } : {}),
    // The cf-config apply target (account/zone) AND the resolved surface allow-list are bound; the token
    // is NEVER hashed (it is a secret). The surface set is resolved here INDEPENDENTLY of the
    // production helper (the point of the oracle), from the registry data, so a drift between the two
    // resolutions fails this parity check rather than silently widening an approval.
    ...(req.cfConfig
      ? {
          cfConfig: {
            accountId: req.cfConfig.accountId,
            ...(req.cfConfig.zoneId !== undefined ? { zoneId: req.cfConfig.zoneId } : {}),
            surfaces: [
              ...new Set(
                CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function")
                  .map((s) => s.id)
                  // Mirrors the production default: an OMITTED list resolves to the PROVEN set, not to
                  // every surface carrying a write(). Most writers are generated from Cloudflare's schema
                  // and are off by default, so a restore that names no scope cannot reach one.
                  .filter((id) => (req.cfConfig?.surfaces === undefined ? PROVEN_WRITE_SURFACES.has(id) : req.cfConfig.surfaces.includes(id))),
              ),
            ].sort(),
          },
        }
      : {}),
    // The media re-upload target (account) is bound; the token is NEVER hashed (it is a secret).
    ...(req.mediaRestore ? { mediaRestore: { accountId: req.mediaRestore.accountId } } : {}),
  };
  return "sha384:" + hexEncode(await sha384(canonicalJSON(binding)));
}

async function main(): Promise<void> {
  // ---- Reproducible: identical input -> identical hash ------------------------------------
  console.log("reproducible:");
  const base: RestoreRequest = {
    runId: RUN_A,
    target: { binding: "KV_MAIN", namespaceId: "ns_1" },
    include: ["users/", "config/"],
    exclude: ["users/tmp/"],
    maxRecords: 100,
  };
  const h1 = await restorePlanHash(base);
  const h2 = await restorePlanHash(base);
  ok("the same object hashes identically on repeat calls", h1 === h2);

  // A freshly constructed, structurally equal request hashes the same (no hidden dependence on
  // object identity or insertion order of the top-level request).
  const baseEqual: RestoreRequest = {
    maxRecords: 100,
    exclude: ["users/tmp/"],
    include: ["users/", "config/"],
    target: { namespaceId: "ns_1", binding: "KV_MAIN" }, // target keys in a DIFFERENT order
    runId: RUN_A,
  };
  ok("a structurally equal request (top-level + target keys reordered) hashes identically",
    (await restorePlanHash(baseEqual)) === h1);

  // ---- Parity: independent recomputation matches -----------------------------------------
  console.log("\nparity:");
  ok("an independent canonical recomputation matches (mirror parity)",
    (await independentHash(base)) === h1);
  // Parity holds across a spread of shapes (minimal, target-only, selectors-only, full).
  const shapes: RestoreRequest[] = [
    { runId: RUN_A },
    { runId: RUN_A, target: { binding: "R2_BUCKET", bucketName: "vault" } },
    { runId: RUN_B, include: ["a/", "b/"], exclude: [] },
    { runId: RUN_B, target: { binding: "D1_DB" }, include: ["t1"], maxRecords: 5 },
    { runId: RUN_A, target: { binding: "KV", namespaceId: "n", bucketName: "b" }, include: ["x"], exclude: ["y"], maxRecords: 1 },
    // Each of the granular-record / cf-config / media binding fields exercised individually, so the
    // parity oracle is proven to fold each into the canonical PlanBinding the same way production does.
    { runId: RUN_A, recordName: "user:42" },
    { runId: RUN_A, destinationId: "replica-s3" },
    { runId: RUN_A, cfConfig: { token: "tok-never-hashed", accountId: "acc_1" } },
    { runId: RUN_A, cfConfig: { token: "tok-never-hashed", accountId: "acc_1", zoneId: "zone_1" } },
    { runId: RUN_A, mediaRestore: { token: "tok-never-hashed", accountId: "acc_1" } },
  ];
  let parityMismatch = 0;
  for (const s of shapes) {
    if ((await restorePlanHash(s)) !== (await independentHash(s))) parityMismatch++;
  }
  ok("independent recomputation matches across minimal/target/selector/full shapes", parityMismatch === 0);

  // ---- Presence equivalence (exactOptionalPropertyTypes) ---------------------------------
  console.log("\npresence-equivalence:");
  // Absent optional vs explicit-undefined optional hash identically.
  const noMax: RestoreRequest = { runId: RUN_A, include: ["x/"] };
  // This block exists to assert that an explicit-undefined optional hashes the same as an ABSENT one, so the
  // explicit `undefined` is precisely the value under test. exactOptionalPropertyTypes forbids it in a typed
  // literal AND in a direct cast (no overlap), so the deliberate explicit-undefined input goes through unknown.
  // This is negative/edge testing of the hashing function, not a real request shape.
  const undefMax = { runId: RUN_A, include: ["x/"], maxRecords: undefined } as unknown as RestoreRequest;
  ok("absent maxRecords == explicit-undefined maxRecords", (await restorePlanHash(noMax)) === (await restorePlanHash(undefMax)));

  const noTargetSub: RestoreRequest = { runId: RUN_A, target: { binding: "KV" } };
  // Same deliberate explicit-undefined-subfields input (the property under test); via unknown for the same reason.
  const undefTargetSub = { runId: RUN_A, target: { binding: "KV", namespaceId: undefined, bucketName: undefined } } as unknown as RestoreRequest;
  ok("explicit-undefined target subfields == absent target subfields",
    (await restorePlanHash(noTargetSub)) === (await restorePlanHash(undefTargetSub)));

  // destinationId: absent == explicit-undefined, the same presence-equivalence every other
  // optional decision field gets.
  const noDest: RestoreRequest = { runId: RUN_A, include: ["x/"] };
  const undefDest = { runId: RUN_A, include: ["x/"], destinationId: undefined } as unknown as RestoreRequest;
  ok("absent destinationId == explicit-undefined destinationId", (await restorePlanHash(noDest)) === (await restorePlanHash(undefDest)));

  // Missing include/exclude == explicit empty array (the documented default of []).
  const noSelectors: RestoreRequest = { runId: RUN_A };
  const emptySelectors: RestoreRequest = { runId: RUN_A, include: [], exclude: [] };
  ok("missing include/exclude == explicit empty arrays", (await restorePlanHash(noSelectors)) === (await restorePlanHash(emptySelectors)));

  // A null target is distinct from a target with no usable subfields? The contract maps an absent
  // target to null; a present target with all-undefined subfields canonicalises to {} (an empty
  // object), which is NOT the same as null. Prove that distinction holds (so "no override" and "an
  // override object that happens to be empty" do not collide).
  const targetNull: RestoreRequest = { runId: RUN_A };
  const targetEmptyObj: RestoreRequest = { runId: RUN_A, target: {} };
  ok("absent target (null) differs from an empty target object ({})",
    (await restorePlanHash(targetNull)) !== (await restorePlanHash(targetEmptyObj)));

  // ---- Order sensitivity (arrays are semantic) -------------------------------------------
  console.log("\norder-sensitivity:");
  const incOrderA: RestoreRequest = { runId: RUN_A, include: ["a/", "b/"] };
  const incOrderB: RestoreRequest = { runId: RUN_A, include: ["b/", "a/"] };
  ok("a different include ELEMENT order yields a different hash (selectors are ordered)",
    (await restorePlanHash(incOrderA)) !== (await restorePlanHash(incOrderB)));
  const excOrderA: RestoreRequest = { runId: RUN_A, exclude: ["x/", "y/"] };
  const excOrderB: RestoreRequest = { runId: RUN_A, exclude: ["y/", "x/"] };
  ok("a different exclude ELEMENT order yields a different hash",
    (await restorePlanHash(excOrderA)) !== (await restorePlanHash(excOrderB)));

  // ---- Re-arm-on-change: any decision field changes the hash ------------------------------
  console.log("\nre-arm-on-change:");
  const ref = await restorePlanHash(base);
  ok("changing runId changes the hash", (await restorePlanHash({ ...base, runId: RUN_B })) !== ref);
  ok("changing target.binding changes the hash",
    (await restorePlanHash({ ...base, target: { binding: "KV_OTHER", namespaceId: "ns_1" } })) !== ref);
  ok("changing target.namespaceId changes the hash",
    (await restorePlanHash({ ...base, target: { binding: "KV_MAIN", namespaceId: "ns_2" } })) !== ref);
  ok("adding target.bucketName changes the hash",
    (await restorePlanHash({ ...base, target: { binding: "KV_MAIN", namespaceId: "ns_1", bucketName: "b" } })) !== ref);
  ok("changing include changes the hash",
    (await restorePlanHash({ ...base, include: ["users/", "config/", "extra/"] })) !== ref);
  ok("changing exclude changes the hash",
    (await restorePlanHash({ ...base, exclude: ["users/tmp/", "more/"] })) !== ref);
  ok("changing maxRecords changes the hash", (await restorePlanHash({ ...base, maxRecords: 101 })) !== ref);
  // Drop maxRecords by omitting it from a spread of base (rather than re-listing base's optional fields, which
  // would set target/include/exclude to their possibly-undefined values and trip exactOptionalPropertyTypes).
  const { maxRecords: _droppedMax, ...baseNoMax } = base;
  ok("dropping maxRecords changes the hash", (await restorePlanHash(baseNoMax)) !== ref);

  // The granular-record / cf-config / media binding fields each re-arm the approval: adding one to a
  // plain run plan changes the hash (a whole-run approval cannot authorise a single-record / cf-config /
  // media apply), and changing the bound identity (recordName, cfConfig.accountId/zoneId,
  // mediaRestore.accountId) changes it again. The EXCLUDED token must NEVER perturb the hash.
  ok("adding recordName changes the hash", (await restorePlanHash({ ...base, recordName: "user:42" })) !== ref);
  ok("changing recordName changes the hash",
    (await restorePlanHash({ ...base, recordName: "user:42" })) !== (await restorePlanHash({ ...base, recordName: "user:43" })));
  // destinationId: a caller who reviews a plan against one destination and applies against a
  // DIFFERENT one (or drops it back to the default) must get a DIFFERENT hash, so gateRestore/
  // isUsableApproval can never find a usable approval for the mismatched apply -- the exploit this fix
  // closes (a destination-relative isLatest cue reviewed against one copy, applied against another).
  ok("adding destinationId changes the hash", (await restorePlanHash({ ...base, destinationId: "replica-s3" })) !== ref);
  ok("changing destinationId changes the hash",
    (await restorePlanHash({ ...base, destinationId: "replica-s3" })) !== (await restorePlanHash({ ...base, destinationId: "replica-r2" })));
  ok("dropping destinationId back to the default changes the hash",
    (await restorePlanHash({ ...base, destinationId: "replica-s3" })) !== (await restorePlanHash(base)));
  ok("adding cfConfig changes the hash",
    (await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1" } })) !== ref);
  ok("changing cfConfig.accountId changes the hash",
    (await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1" } })) !== (await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_2" } })));
  ok("changing cfConfig.zoneId changes the hash",
    (await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", zoneId: "z_1" } })) !== (await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", zoneId: "z_2" } })));
  // The surface allow-list is a decision field and re-arms like every other one. Without this the
  // hash bound only the account and zone, so an approver who signed "re-apply Cloudflare config into this
  // account" authorised whatever the in-band set happened to be, and widening it silently widened an
  // already-granted approval under an identical hash.
  {
    const inBand = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function").map((s) => s.id).sort();
    ok("the in-band set is non-trivial, so the assertions below are meaningful", inBand.length >= 2);
    const all = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1" } });
    const narrowed = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: [inBand[0]!] } });
    ok("narrowing the surface allow-list changes the hash (re-arms the approval)", all !== narrowed);
    const sameNarrow = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: [inBand[0]!] } });
    ok("the same allow-list hashes identically (reproducible)", narrowed === sameNarrow);
    const reordered = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: [inBand[1]!, inBand[0]!] } });
    const ordered = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: [inBand[0]!, inBand[1]!] } });
    ok("caller ORDER of the allow-list does not change the hash (it is resolved sorted)", reordered === ordered);
    const dupes = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: [inBand[0]!, inBand[0]!] } });
    ok("a duplicated entry does not change the hash (it is resolved deduped)", dupes === narrowed);
    const bogus = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: [inBand[0]!, "account-members"] } });
    ok("naming a non-in-band surface does not widen the set (allow-list only narrows)", bogus === narrowed);
    // The omitted default is the PROVEN subset, so naming every in-band surface is a genuinely WIDER
    // request and MUST hash differently. If these ever collide, an approval granted for the safe default
    // would silently authorise every generated, unproven writer as well.
    const everyOne = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: inBand } });
    ok("naming every in-band surface is WIDER than the default and hashes differently", everyOne !== all);
    const proven = inBand.filter((id) => PROVEN_WRITE_SURFACES.has(id));
    const provenOnly = await restorePlanHash({ ...base, cfConfig: { token: "t", accountId: "acc_1", surfaces: proven } });
    ok("explicitly listing exactly the proven set equals the omitted default", provenOnly === all);
    ok("the proven set is a strict subset of in-band, so the default really does narrow", proven.length < inBand.length && proven.length > 0);
  }

  ok("changing the cfConfig token does NOT change the hash (the secret is never bound)",
    (await restorePlanHash({ ...base, cfConfig: { token: "t1", accountId: "acc_1" } })) === (await restorePlanHash({ ...base, cfConfig: { token: "t2", accountId: "acc_1" } })));
  ok("adding mediaRestore changes the hash",
    (await restorePlanHash({ ...base, mediaRestore: { token: "t", accountId: "acc_1" } })) !== ref);
  ok("changing mediaRestore.accountId changes the hash",
    (await restorePlanHash({ ...base, mediaRestore: { token: "t", accountId: "acc_1" } })) !== (await restorePlanHash({ ...base, mediaRestore: { token: "t", accountId: "acc_2" } })));
  ok("changing the mediaRestore token does NOT change the hash (the secret is never bound)",
    (await restorePlanHash({ ...base, mediaRestore: { token: "t1", accountId: "acc_1" } })) === (await restorePlanHash({ ...base, mediaRestore: { token: "t2", accountId: "acc_1" } })));

  // A NON-decision field does NOT change the hash: confirm (dry-run vs apply) is not part of the
  // binding, so the request's hash matches the apply's hash for the same plan. This is the property
  // that lets the apply route find the approval the request raised.
  ok("changing confirm (dry-run vs apply) does NOT change the hash",
    (await restorePlanHash({ ...base, confirm: false })) === ref &&
    (await restorePlanHash({ ...base, confirm: true })) === ref);

  // ---- Shape: redaction-safe scheme + length ---------------------------------------------
  console.log("\nshape:");
  ok("the hash is 'sha384:' prefixed", ref.startsWith("sha384:"));
  const hex = ref.slice("sha384:".length);
  ok("the hash body is 96 lowercase hex chars (SHA-384)", /^[0-9a-f]{96}$/.test(hex));
  // The binding folds names/counts/selectors only: a distinctive secret-looking VALUE placed in a
  // field that is NOT a decision field (confirm) cannot perturb the hash, and the hash never embeds a
  // raw value (it is a digest). This is a structural redaction proof: the hash is a fixed-length
  // digest, so no input substring survives into it.
  ok("the hash never embeds an input substring (it is a digest)", !ref.includes("KV_MAIN") && !ref.includes(RUN_A));

  console.log(failures === 0 ? "\nRESTORE PLAN HASH VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
