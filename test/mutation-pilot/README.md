# Mutation pilot: RUNLOG and crypto envelope

StrykerJS configurations that mutate the RUNLOG append and verify code and the crypto envelope. The test
oracle is a set of plain validator scripts that exit non-zero on failure (the Stryker command runner).

| Config | Mutated code | Oracle |
| --- | --- | --- |
| `stryker.runlog.json` | `src/seal/pipeline.ts` lines 449-780: signature resolve, `readFloor`, `verifyRunlogForWrite`, `appendRunlog`, the index-held refusal, supersede | 16 RUNLOG validators |
| `stryker.crypto.json` | `src/crypto/sign.ts`, `capsule.ts`, `kem.ts`, `combiner.ts` | 12 crypto validators |
| `stryker.crypto-wide.json` | the survivor regions of the crypto run | 11 wider validators (fault evidence, control plane, restore, key flows) |

Run from the engine root:

    npx stryker run test/mutation-pilot/stryker.runlog.json
    npx stryker run test/mutation-pilot/stryker.crypto.json
    npx stryker run test/mutation-pilot/stryker.crypto-wide.json
    node test/mutation-pilot/survivors.mjs test/mutation-pilot/reports/runlog.json

Stryker mutates a copy of the tree in `.stryker-tmp-*`, so `src/` is never modified. Each config sets
`thresholds.break` to null, so a run reports a score and never fails the build. JSON reports go to
`test/mutation-pilot/reports/` (ignored by git). `survivors.mjs` lists each surviving mutant as
`file:line`, mutator, replacement and source line.

The RUNLOG run takes about 95 minutes on a loaded workstation (313 mutants, four workers). The crypto
runs take about 10 minutes each. Each run's initial dry run executes the whole oracle once, about 35 seconds.
