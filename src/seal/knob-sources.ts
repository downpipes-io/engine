// ENGINE KNOB SOURCES (gap G169, support-pack mode scale-knobs-invisible). The pack has long carried the
// RESOLVED value of the seal knobs -- but a resolved value alone cannot answer the commonest tuning question:
// whether a knob such as SCALE_SEGMENT_TARGET_BYTES / DEST_THROTTLE_ATTEMPTS / SEAL_VERIFY_SAMPLE /
// REPL_VERIFY_SEGMENTS / SCALE_FANOUT_RANGES that an operator set was actually applied.
//
// Every knob resolver in the engine is deliberately FAIL-SOFT: a typo'd value is IGNORED and the built-in
// default runs, because a bad knob must never stop a backup. The cost is diagnostic: the pack reports the
// default (or an honest absence) with no hint that a value WAS set and REJECTED. Set-but-invalid and never-set
// are indistinguishable, and support tells the operator to "check the value is set" when it is.
//
// The two SCALE_SLICE_* knobs already reported {resolved, source} via budget.ts resolveKnob. This module
// extends that same closed four-member vocabulary (KNOB_SOURCES: default | env | clamped | invalid) to EVERY
// remaining knob family the seal subsystem resolves, by asking each OWNING module -- the one that holds the
// defaults and the clamps -- to classify its own knobs. Classification therefore cannot drift from resolution:
// there is no second copy of a default or a ceiling anywhere in here.
//
// NO-CUSTODY: the raw operator string is NEVER read out, forwarded, logged or recorded. An invalid value is
// reported ONLY as the closed enum member "invalid" plus the (integer) default that is actually running -- the
// rejected string could be anything at all, including a pasted secret. PURE: env in, enums + bounded ints out.
// It records nothing, reads no destination, and touches no seal / verify / replicate path.

import type { Env } from "../env.d.ts";
import { type KnobResolution, resolveSliceScaleKnobs, scaleKnobSources } from "./budget.ts";
import { replVerifyKnobSources } from "./replicate.ts";
import { throttleRetryKnobSources } from "./retry.ts";
import { sealLadderKnobSources } from "./runstate-helpers.ts";
import { sealVerifyKnobSources } from "./verify-at-seal.ts";

/**
 * sealKnobSources resolves EVERY seal-subsystem env knob to {source, resolved, ceiling} for the support pack.
 * The keys are a stable, closed set (one per knob); the values are redaction-safe by construction. Grouped by
 * the module that owns each knob's defaults + clamps:
 *   - slice budget      : sliceSubrequests, sliceWallMs                      (budget.ts, already reported)
 *   - seal shaping      : shardMaxRecords, segmentTargetBytes, slicedRunsDisabled           (budget.ts)
 *   - destination retry : destThrottleAttempts, destThrottleBaseMs                           (retry.ts)
 *   - fault ladder      : destThrottleMaxYields                                    (runstate-helpers.ts)
 *   - fan-out           : fanoutRanges, fanoutMinRecords, fanoutSampleCap         (runstate-helpers.ts)
 *   - verify at seal    : verifyAtSeal, sealVerify{Sample,MaxBytes,FullBytes,Attempts,FullShards,ShardSample}
 *   - replication       : replVerifySegments                                              (replicate.ts)
 * A diagnoser reads a `source: "invalid"` as "the operator DID set this and the engine rejected it", a
 * `"clamped"` as "the value was over the platform-survivable ceiling and was pulled down to it", and a
 * `"default"` as an honest never-set.
 */
export function sealKnobSources(env: Env): Record<string, KnobResolution> {
  const slice = resolveSliceScaleKnobs(env as unknown as { SCALE_SLICE_SUBREQUESTS?: unknown; SCALE_SLICE_WALL_MS?: unknown });
  return {
    sliceSubrequests: slice.sliceSubrequests,
    sliceWallMs: slice.sliceWallMs,
    ...scaleKnobSources(env as unknown as { SCALE_SHARD_MAX_RECORDS?: unknown; SCALE_SEGMENT_TARGET_BYTES?: unknown; SLICED_RUNS_DISABLED?: unknown }),
    ...throttleRetryKnobSources(env as unknown as { DEST_THROTTLE_ATTEMPTS?: unknown; DEST_THROTTLE_BASE_MS?: unknown }),
    ...sealLadderKnobSources(env),
    ...sealVerifyKnobSources(env),
    ...replVerifyKnobSources(env),
  };
}
