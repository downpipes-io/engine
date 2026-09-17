# Writer to reader demo

This demo proves the platform's moat on real bytes: the engine's TypeScript writer seals a
genuine `downpipe/0.1.0` archive, and the independent open-core Go reader (the offline recovery
CLI, a separate repository) then verifies the full signed chain and restores every record, with
neither Cloudflare nor the vendor in the loop. A divergence here is a critical failure of the
recover-forever promise, so the same steps run in CI on every push (the `e2e-writer-reader` job).

The demo is non-destructive. It writes only into a fresh temporary directory and removes it on exit.

## What it shows

- The engine writer and the Go reader agree on the frozen `downpipe/0.1.0` wire format byte for byte.
- Recovery works fully offline, given only the archive, the break-glass identity and the pinned
  signer public key. No Cloudflare token, no vendor call.
- A tampered archive is REJECTED rather than silently restored: the negative check flips a byte in
  a sealed data segment and asserts the reader's restore fails closed on the record integrity check.

## Prerequisites

- Node 22 or newer (the writer runs `.ts` directly via the runtime's type stripping).
- Go 1.26 or newer (to build the reader from the sibling `downpipe` checkout).
- A local checkout of the Go `downpipe` repository. By default the demo looks for it at `../downpipe`
  (a sibling of this repository). Override with the `DOWNPIPE_REPO` environment variable.
- `npm ci` already run in this repository (the writer imports the engine's crypto and format modules).

## Run it

From the repository root:

```sh
make demo
# or, equivalently:
npm run demo
# point at a downpipe checkout elsewhere:
DOWNPIPE_REPO=/path/to/downpipe make demo
```

## Numbered steps (what the demo does)

1. Builds the Go reader from `$DOWNPIPE_REPO/cmd/downpipe` into a temporary directory.
2. Runs the engine's TypeScript writer (`test/write-archive.ts`), which seals a multi-record,
   multi-chunk archive plus the break-glass identity and the signer public key in the Go CLI's
   labelled format.
3. Runs `downpipe verify` against the engine-written archive (full signed chain plus freshness).
4. Runs `downpipe restore --apply`, recovering every in-scope record to a restore directory, and
   asserts the restore actually produced output.
5. Runs `downpipe inspect` against the same archive and asserts its output names the self-identifying
   `database` (D1's native UUID) and `account` (the Cloudflare account a backup is OF) coordinates the
   engine writer stamped onto the manifest line -- proof that the independent reader, not just the
   engine's own tests, sees the fields that let an archive identify what it is a backup of.
6. Runs the NEGATIVE path: copies the verified archive, flips a byte in the largest sealed data
   segment, and asserts `downpipe restore --apply` now FAILS on the per-record integrity check,
   proving tamper-evidence rather than a silent bad restore. (The signed root and chain that
   `verify` checks are over the manifest, so a corrupted segment surfaces on restore.)

## Expected output

The run prints a line per step and ends with:

```
e2e: PASS - the engine wrote it and the independent Go reader verified + restored it.
e2e: PASS - inspect output shows database= and account= (the engine wrote them, the independent Go reader read them).
e2e: PASS - a tampered archive was correctly REJECTED by the reader.
```

The process exits `0` on success and non-zero on any divergence (a verify failure, an empty restore,
or a tampered archive that was NOT rejected).

## Where this runs in CI

The `e2e-writer-reader` job in `.github/workflows/ci.yml` checks out both this repository and the
`downpipes-io/downpipe` reader, then runs `scripts/e2e-writer-reader.sh` against the sibling checkout.
It is part of the `ci-success` gate, so a writer/reader divergence blocks merge.
