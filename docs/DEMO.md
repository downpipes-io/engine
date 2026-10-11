# Writer to reader demo

This demo proves the platform's moat on real bytes: the engine's TypeScript writer seals a
genuine `downpipe/0.1.0` archive, and the independent open-core Go reader (the offline recovery
CLI, a separate repository) then verifies the full signed chain and restores every record, with
neither Cloudflare nor the vendor in the loop. A divergence here is a critical failure of the
recover-forever promise, so the same steps run in CI on every push to `main` and every pull request
against `main` (the `e2e-writer-reader` job).

The demo is non-destructive. It writes only into a fresh temporary directory and removes it on exit.

## What it shows

- The engine writer and the Go reader agree on the frozen `downpipe/0.1.0` wire format byte for byte.
- Recovery works fully offline, given only the archive, the break-glass identity and the pinned
  signer public key. No Cloudflare token, no vendor call.
- A tampered archive is REJECTED rather than silently restored: the negative checks flip a byte in
  a sealed data segment and in each of the two signature files, and assert that the reader exits
  non-zero each time.

## Prerequisites

- Node 22.18 or newer, or 23.6 or newer on the 23 line (the writer runs `.ts` directly via the
  runtime's type stripping, which is on by default from those releases).
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
5. Runs every command that the archive's bundled `RECOVER.md` prints, read out of the archive
   (`test/bundle-recover-commands.ts`).
6. Runs `downpipe inspect` against the same archive and asserts its output names the self-identifying
   `database` (D1's native UUID) and `account` (the Cloudflare account a backup is OF) coordinates the
   engine writer stamped onto the manifest line -- proof that the independent reader, not just the
   engine's own tests, sees the fields that let an archive identify what it is a backup of.
7. Flips the first byte of a copy's root signature (`root.manifest.json.sig`) and asserts that
   `downpipe verify` exits `2` and reports `invalid`, `absent` or `wrong-signer`, never `valid`.
8. Runs the NEGATIVE segment path: copies the verified archive, flips the middle byte of the largest
   sealed data segment, and asserts `downpipe restore --apply` now FAILS, proving tamper-evidence
   rather than a silent bad restore. The flipped byte is in the sealed ciphertext, past the 5-byte
   container header, so the reader refuses the segment on the per-record AEAD check. The step also
   asserts that the reader reports a chunk authentication failure and not a container magic refusal.
   (The signed root and chain that `verify` checks are over the manifest, so a corrupted segment
   surfaces on restore.)
9. Flips the first byte of a copy's `_RECOVERY/RUNLOG.sig` and asserts that `downpipe verify` exits `5`.
10. Runs `downpipe verify --min-runlog-index` twice: a pin one above the archive's real RUNLOG index
    must exit `5`, and a pin at the real index must exit `0`.

## Expected output

The run prints a line per step. Its `PASS` lines are these. The fixture's real values replace
`<uuid>`, `<account>` and `<n>`, the reader's reported signature result replaces `<value>`, and the
reader's non-zero restore exit code replaces `<exit>`:

```
e2e: PASS - the engine wrote it and the independent Go reader verified + restored it.
e2e: PASS - inspect output shows database="<uuid>" and account="<account>": the exact expected VALUES, not merely present labels
e2e: PASS - corrupted root signature: exit 2 AND signatureResult=<value> (never 'valid'), both independently confirmed
e2e: PASS - a tampered data segment was REJECTED by the reader: exit <exit> AND a chunk authentication failure, both independently confirmed.
e2e: PASS - corrupted RUNLOG signature: exit 5 (ExitStale), the freshness path independently detected it
e2e: PASS - the pin refuses one above the real index <n> (exit 5) and passes at the real index (exit 0)
```

The process exits `0` on success and non-zero on any divergence (a verify failure, an empty restore,
or a tampered archive that was NOT rejected). It exits `2` before any work when it cannot find the
reader checkout.
