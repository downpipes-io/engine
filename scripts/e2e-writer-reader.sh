#!/usr/bin/env bash
# End-to-end writer->reader gate (assessment XC-1): prove the moat's two halves agree on REAL
# bytes. The engine's TypeScript WRITER seals a downpipe/0.1.0 archive; the independent open-core
# Go READER (the offline recovery CLI) then verifies and restores it with neither Cloudflare nor
# the vendor in the loop. A divergence here is a critical failure of the recover-forever promise,
# so this runs both toolchains and asserts the Go tool recovers every record the engine wrote.
#
# MOAT.7 (2026-08) attacked this file with five real, reverted source divergences in the Go reader,
# one per required class, and it caught ZERO of five -- most seriously, a reader with root-signature
# verification entirely disabled still printed `signature=valid` and exited 0, because every assertion
# here checked for a LABEL's presence, never a VALUE. MOAT.8 filed the five assertions that close that;
# they are built below. Every negative assertion in this file now requires BOTH the reader's exit code
# AND an independently-derived value to agree with the expected outcome -- never a label-presence grep
# alone -- because a label a bypassed check still prints is exactly what MOAT.7 proved worthless.
#
# What this file proves and does not prove (state this honestly; do not let it imply more). It is ONE
# fixed, non-adversarial archive shape (9 records: 2 kv, 1 small r2, 1 streamed multi-chunk r2, 1 d1
# with identity, 1 secrets, and the 3 records of a D1 table the engine's D1Source crawled, whose BLOBs hold
# every byte value; 1 shard, 1 run) exercised by four tamper primitives (a data-segment ciphertext
# byte flip, a root-signature byte flip, a RUNLOG-signature byte flip, and the --min-runlog-index
# pin), plus one label/value cross-check. It does not exercise multi-shard runs, cross-run dedup, gzip, or most of
# the negative-vector taxonomy (non-canonical JSON, out-of-range counts, capsule forgery, and more) --
# that is the shared conformance corpus's job (downpipe/internal/format/testdata/vectors/, replayed via
# `npm run validate`/`test/validate-reader.ts` and `go test ./internal/format -run TestConformance`),
# which does most of the real cross-implementation checking. This script's distinct, narrower job is a
# live two-binary production-direction round trip the corpus's fixture replay cannot exercise: a real
# TypeScript writer process and a real Go reader binary agreeing on real bytes, not a replayed fixture.
#
# Usage:  scripts/e2e-writer-reader.sh
# Env:    DOWNPIPE_REPO  path to the Go downpipe repo (default: ../downpipe, the sibling checkout)
#         NODE           node binary (default: node; must run .ts via strip-types, Node 22+)
# Exit:   0 = engine-written archive verified + restored by the Go reader, and every negative
#         assertion below independently confirmed the reader detects the tamper it targets;
#         non-zero otherwise. This script has no corpus of its own to run dry against, but its one
#         completeness check (below) explicitly FAILs a zero-record write rather than passing an
#         empty result, and the missing-repo / build-failure guards below FAIL rather than skip.
set -euo pipefail

ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNPIPE_REPO="${DOWNPIPE_REPO:-$ENGINE_DIR/../downpipe}"
NODE="${NODE:-node}"
RUN_ID="01ARZ3NDEKTSV4RRFFQ69G5FAV" # the fixed run id test/write-archive.ts seals

if [ ! -d "$DOWNPIPE_REPO/cmd/downpipe" ]; then
  echo "e2e: cannot find the Go downpipe repo at '$DOWNPIPE_REPO' (set DOWNPIPE_REPO)" >&2
  exit 2
fi

# WHICH GO READER, said out loud, every run. GRADE AND SAY SO rather than refuse, and the choice is argued
# rather than inherited: this is a DEMONSTRATION, not a comparison. It really does seal an archive, restore it
# with a different codebase and reject a tampered one, so a pass against an older reader is a fact about that
# reader rather than a guess about the current one. It is also the most expensive thing in this repo to run
# and the one an operator invokes by hand as `make demo` against whatever downpipe checkout they have, so
# refusing would block a run whose result stays meaningful. What it owed its reader was the VERSION it proved,
# which is the one thing it never printed: the line below said only the path, and a path is not a version.
#
# In CI the reader is checked out at downpipes-io/downpipe's default branch and nothing rewrites its origin/main,
# so this line reads 0 because the tree really is at main. See scripts/lib/sibling-lag.mjs for why the sha is
# printed beside the number rather than the number alone.
#
# This never changes the exit code (--report, not --require). The exit 2 above, for an ABSENT reader, is
# unchanged and stays the loud case.
"${NODE:-node}" "$ENGINE_DIR/scripts/lib/sibling-lag.mjs" --report --gate e2e-writer-reader "downpipe=$DOWNPIPE_REPO" >&2

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/downpipe"

echo "e2e: building the Go reader ($DOWNPIPE_REPO)"
( cd "$DOWNPIPE_REPO" && go build -o "$BIN" ./cmd/downpipe )

echo "e2e: the engine TypeScript writer seals an archive -> $WORK"
( cd "$ENGINE_DIR" && "$NODE" test/write-archive.ts "$WORK" )

ARCHIVE="$WORK/archive"
ID="$WORK/identity.key"
SIGNER="$WORK/signer.pub"

# flip_first_byte mutates the first byte of $1 in place (XOR 1) and prints "old -> new". Shared by
# every negative assertion below: each targets a different file, but the primitive is identical, so a
# reader either detects a one-bit change on its own code path or it does not.
flip_first_byte() {
  flip_byte_at "$1" 0
}

# flip_byte_at mutates the byte at offset $2 of $1 in place (XOR 1) and prints "old -> new". The segment
# case needs an offset past the container header: byte 0 of a .seg is its magic, so a flip there is
# refused by the framing check and never reaches the per-record AEAD the assertion is about.
flip_byte_at() {
  local target="$1" offset="$2" old new
  old="$(od -An -tu1 -j "$offset" -N1 "$target" | tr -d ' ')"
  new=$(( old ^ 1 ))
  printf "$(printf '\\%03o' "$new")" | dd of="$target" bs=1 seek="$offset" count=1 conv=notrunc status=none
  echo "$old -> $new"
}

echo "e2e: the Go reader VERIFIES the engine-written archive (full chain + freshness)"
"$BIN" verify --archive "$ARCHIVE" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER"

echo "e2e: the Go reader RESTORES every record (offline, no vendor)"
# restore is dry-run by default; --apply actually writes the recovered records to --out.
"$BIN" restore --archive "$ARCHIVE" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER" --out "$WORK/restored" --apply

# Assert the restore actually produced output (every in-scope record recovered to a file). This is the
# closest thing this script has to a "nothing to check" guard, and it FAILs rather than passing silently
# on a zero-record write.
if [ -z "$(ls -A "$WORK/restored" 2>/dev/null)" ]; then
  echo "e2e: FAIL - restore produced no output" >&2
  exit 1
fi

echo "e2e: PASS - the engine wrote it and the independent Go reader verified + restored it."

# ---- A D1 BLOB may hold any byte. test/write-archive.ts crawls a real SQLite table through the engine's own
# D1Source: row 1 is one BLOB of the 256 byte values 0x00 to 0xFF in order, row 2 is the 32 bytes 0x80 to
# 0x9F. Until 0.3.7 the engine's BLOB encoder built btoa's input with TextDecoder("latin1"), which is
# windows-1252 under the WHATWG Encoding standard, so any byte from 0x80 to 0x9F failed the whole D1 backup
# (customer-path test finding F1) and no archive was written. The expected bytes are built here, in the shell,
# independently of both codebases, and compared by VALUE: first the SQL literal the reader wrote, then, where
# sqlite3 is installed, the bytes SQLite holds after the restored SQL is applied to a fresh database.
ALL_HEX=""
i=0
while [ "$i" -lt 256 ]; do
  ALL_HEX="$ALL_HEX$(printf '%02x' "$i")"
  i=$((i + 1))
done
HIGH_HEX="${ALL_HEX:256:64}" # bytes 0x80 to 0x9F
BLOB_ROWS="$WORK/restored/blobdb/10-rows/000000-blobs/000000.sql"
if [ ! -f "$BLOB_ROWS" ]; then
  echo "e2e: FAIL - the every-byte D1 table was not restored (no $BLOB_ROWS)" >&2
  exit 1
fi
if ! grep -qF "(1, x'$ALL_HEX')" "$BLOB_ROWS" || ! grep -qF "(2, x'$HIGH_HEX')" "$BLOB_ROWS"; then
  echo "e2e: FAIL - the restored D1 BLOBs are not the bytes 0x00-0xFF and 0x80-0x9F the engine sealed" >&2
  exit 1
fi
if command -v sqlite3 >/dev/null 2>&1; then
  BLOB_DB="$WORK/blobdb.sqlite"
  cat "$WORK/restored/blobdb/00-header.sql" "$BLOB_ROWS" "$WORK/restored/blobdb/20-schema.sql" | sqlite3 "$BLOB_DB"
  GOT="$(sqlite3 "$BLOB_DB" 'SELECT id || ":" || lower(hex(b)) FROM "blobs" ORDER BY id;' | tr '\n' ' ')"
  WANT="1:$ALL_HEX 2:$HIGH_HEX "
  if [ "$GOT" != "$WANT" ]; then
    echo "e2e: FAIL - SQLite holds different BLOB bytes after applying the restored SQL" >&2
    exit 1
  fi
  echo "e2e: PASS - every byte value 0x00-0xFF in a D1 BLOB was sealed by the engine and restored byte-identical by the Go reader (SQL literal and SQLite bytes)"
else
  echo "e2e: PASS - every byte value 0x00-0xFF in a D1 BLOB was sealed by the engine and restored by the Go reader as the exact SQL literal (sqlite3 not installed: the apply step was not run)"
fi

# ---- The commands the SIGNED, IN-ARCHIVE RECOVER.md prints are DRIVEN, from the archive's own bytes.
# This is the only place in the repo where both halves needed to drive them exist at once: a real
# engine-written archive is on disk and a real Go reader is built. Nothing had ever run them,
# and the document shipped a custody line that exits 6 (ExitUsage) against a 3-of-N split and a
# headline line with no --apply, so the only instruction a customer had mid-disaster exited 0 and
# restored nothing. Reading the string literal is what missed both; the gate runs the lines instead.
CUSTODY_DIR="$DOWNPIPE_REPO/cmd/downpipe/testdata/custody"
if [ ! -d "$CUSTODY_DIR" ]; then
  echo "e2e: FAIL - the Go reader's custody fixture is missing at '$CUSTODY_DIR', so the bundled RECOVER.md custody line cannot be driven" >&2
  exit 1
fi
echo "e2e: driving every command the bundled RECOVER.md prints, read out of the archive"
( cd "$ENGINE_DIR" && ARCHIVE="$ARCHIVE" READER_BIN="$BIN" RUN_ID="$RUN_ID" IDENTITY="$ID" SIGNER="$SIGNER" CUSTODY_DIR="$CUSTODY_DIR" "$NODE" test/bundle-recover-commands.ts )

# ---- IDENTITY path, value comparison (closes MOAT.7 divergence 1). The self-identifying `database`
# (D1 native UUID) and `account` (Cloudflare account) annotations test/write-archive.ts's d1 record
# carries must reach the INDEPENDENT Go reader with the CORRECT values, not just as present labels.
# `inspect` is a diagnostic viewer (not `verify`/`restore`): with --identity/--signer it opens the
# encrypted preamble and prints a "records (identity + restore descriptors):" line per record via
# describeIdentity() (cmd/downpipe/inspect.go), which renders `database="..."`/`account="..."` (Go %q)
# when present. MOAT.7 found this exact function with `database`/`account` SWAPPED: the archive's real
# account value printed under the `database=` label, and `grep -q 'database='` still passed, because a
# label-presence check cannot tell a swap from a correct value. The expected values below are DERIVED
# from test/write-archive.ts at run time (the one place that sets them), not re-typed as a second,
# driftable copy: a future change to the fixture's identity values updates this assertion automatically.
echo "e2e: the Go reader INSPECTS the archive and prints its self-identifying record coordinates"
INSPECT_OUT="$("$BIN" inspect --archive "$ARCHIVE" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER")"
echo "$INSPECT_OUT"

DB_EXPECT="$(grep -oE 'database: *"[^"]+"' "$ENGINE_DIR/test/write-archive.ts" | head -n1 | sed -E 's/.*"([^"]+)"/\1/')"
ACCT_EXPECT="$(grep -oE 'account: *"[^"]+"' "$ENGINE_DIR/test/write-archive.ts" | head -n1 | sed -E 's/.*"([^"]+)"/\1/')"
if [ -z "$DB_EXPECT" ] || [ -z "$ACCT_EXPECT" ]; then
  echo "e2e: FAIL - could not derive the expected database/account identity values from test/write-archive.ts (fixture shape changed?)" >&2
  exit 1
fi
DB_TOKEN="database=\"$DB_EXPECT\""
ACCT_TOKEN="account=\"$ACCT_EXPECT\""
if ! grep -qF "$DB_TOKEN" <<<"$INSPECT_OUT"; then
  echo "e2e: FAIL - inspect output does not contain $DB_TOKEN (the label is absent, or a different value prints under it -- MOAT.7 divergence 1)" >&2
  exit 1
fi
if ! grep -qF "$ACCT_TOKEN" <<<"$INSPECT_OUT"; then
  echo "e2e: FAIL - inspect output does not contain $ACCT_TOKEN (the label is absent, or a different value prints under it -- MOAT.7 divergence 1)" >&2
  exit 1
fi
echo "e2e: PASS - inspect output shows $DB_TOKEN and $ACCT_TOKEN: the exact expected VALUES, not merely present labels"

# ---- NEGATIVE, headline (closes MOAT.7 divergence 3, the most serious of the five). Before this
# assertion the script's only signature-adjacent check was `grep -q 'signature=valid'` against the
# POSITIVE run's own output above -- exactly the string a reader whose root-signature verification is
# short-circuited to always-succeed also prints. MOAT.7 proved this live: disabling
# verifyRootSignatureGate's real check (internal/format/reader.go) left every assertion in this file
# passing, including that grep, against a genuinely forged signature. The fix compares the VALUE the
# reader independently derives, not a label's presence: flip one byte of the stored root signature, run
# `verify` at its DEFAULT posture (no --allow-unverified), and require BOTH (a) the exit code is exactly
# 2 (ExitUnverified, SPEC.md 8.5) and (b) the printed "verify root signature: <value>" line names one of
# the reader's own closed bad-signature outcomes (invalid, absent or wrong-signer --
# internal/format/reader.go verifyRootSignatureGate) and specifically NOT "valid". A bypassed check
# fails (a): it exits 0 and never reaches this error path at all, so (b) also has nothing to match. Both
# signals must independently hold, which is the "value comparison against the exit code and the label's
# value together" the fix calls for.
echo "e2e: NEGATIVE - corrupt the root signature and require verify to independently detect and report it (the signature-bypass case)"
SIGTAMPERED="$WORK/archive-sig-tampered"
cp -R "$ARCHIVE" "$SIGTAMPERED"
ROOT_SIG="$SIGTAMPERED/run/$RUN_ID/root.manifest.json.sig"
if [ ! -f "$ROOT_SIG" ]; then
  echo "e2e: FAIL - could not locate root.manifest.json.sig to tamper" >&2
  exit 1
fi
echo "e2e: tampered $ROOT_SIG (byte 0: $(flip_first_byte "$ROOT_SIG"))"

SIG_VERIFY_EXIT=0
SIG_VERIFY_OUT="$("$BIN" verify --archive "$SIGTAMPERED" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER" 2>&1)" || SIG_VERIFY_EXIT=$?
echo "$SIG_VERIFY_OUT"

if [ "$SIG_VERIFY_EXIT" -ne 2 ]; then
  echo "e2e: FAIL - verify against a corrupted root signature exited $SIG_VERIFY_EXIT, not 2 (ExitUnverified); a bypassed signature check exits 0" >&2
  exit 1
fi
SIG_VALUE="$(grep -oE 'verify root signature: [a-z-]+' <<<"$SIG_VERIFY_OUT" | sed 's/.*: //')"
case "$SIG_VALUE" in
  invalid|absent|wrong-signer) ;;
  *)
    echo "e2e: FAIL - verify exited 2 but did not report one of the reader's own bad-signature values (invalid|absent|wrong-signer); got '${SIG_VALUE:-<none>}'" >&2
    exit 1
    ;;
esac
echo "e2e: PASS - corrupted root signature: exit 2 AND signatureResult=$SIG_VALUE (never 'valid'), both independently confirmed"

# ---- NEGATIVE: a tampered data segment MUST be rejected (tamper-evidence, not a silent bad restore).
# Copy the verified archive, flip a single byte in the sealed ciphertext of the LARGEST data segment, and
# assert the Go reader REJECTS it. A reader that silently restored mutated bytes would break the
# recover-forever integrity guarantee, so this is a hard gate, not a warning.
#
# A corrupted segment surfaces on the per-record AEAD/plaintext-hash check during RESTORE (the signed
# root and chain that `verify` checks are over the manifest, not the raw segment files), so the
# negative assertion runs `restore --apply` and requires it to FAIL.
#
# THE OFFSET IS THE ASSERTION. This used to flip byte 0, which is the first byte of the 5-byte container
# header (the DPS1 magic, SPEC 7.1). The reader refused that as "bad container magic" before it read any
# ciphertext, so the AEAD path this block names was never exercised: a reader with chunk authentication
# disabled still passed. The flip now lands in the middle of the segment, deep in the sealed chunks, and
# the block requires the reader to name the chunk authentication failure (internal/crypto/stream.go) and
# not the framing refusal, beside the non-zero exit.
echo "e2e: NEGATIVE - flip one byte in a sealed data segment's ciphertext and confirm the reader REJECTS it on the AEAD check"
TAMPERED="$WORK/archive-tampered"
cp -R "$ARCHIVE" "$TAMPERED"
# Pick the largest .seg file under the tampered archive (a data segment) to mutate.
VICTIM="$(find "$TAMPERED" -type f -name '*.seg' -exec ls -S {} + | head -n 1)"
if [ -z "$VICTIM" ] || [ ! -f "$VICTIM" ]; then
  echo "e2e: FAIL - could not locate a data segment to tamper" >&2
  exit 1
fi
SEG_SIZE="$(wc -c <"$VICTIM" | tr -d ' ')"
SEG_OFFSET=$(( SEG_SIZE / 2 ))
if [ "$SEG_OFFSET" -le 5 ]; then
  echo "e2e: FAIL - the data segment is $SEG_SIZE bytes, too short to flip a byte past its 5-byte container header" >&2
  exit 1
fi
echo "e2e: tampered $VICTIM (byte $SEG_OFFSET of $SEG_SIZE: $(flip_byte_at "$VICTIM" "$SEG_OFFSET"))"

# The reader MUST now fail to restore the tampered archive, and it must fail on the AEAD. Invert the exit
# status: a zero exit (restore silently accepted the mutated bytes) is the failure we are guarding against.
SEG_RESTORE_EXIT=0
SEG_RESTORE_OUT="$("$BIN" restore --archive "$TAMPERED" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER" --out "$WORK/restored-tampered" --apply 2>&1)" || SEG_RESTORE_EXIT=$?
if [ "$SEG_RESTORE_EXIT" -eq 0 ]; then
  echo "e2e: FAIL - the reader RESTORED a tampered archive (tamper-evidence broken)" >&2
  exit 1
fi
if grep -qF "bad container magic" <<<"$SEG_RESTORE_OUT"; then
  echo "e2e: FAIL - the reader refused the tampered segment on its container magic, so the flip did not reach the sealed ciphertext" >&2
  exit 1
fi
if ! grep -qF "authentication failed" <<<"$SEG_RESTORE_OUT"; then
  echo "e2e: FAIL - restore exited $SEG_RESTORE_EXIT but did not report a chunk authentication failure; the per-record AEAD path was not the one that refused" >&2
  echo "$SEG_RESTORE_OUT" >&2
  exit 1
fi
echo "e2e: PASS - a tampered data segment was REJECTED by the reader: exit $SEG_RESTORE_EXIT AND a chunk authentication failure, both independently confirmed."

# ---- NEGATIVE (closes MOAT.7 divergence 5): the RUNLOG's OWN whole-document signature is a distinct
# code path from both the root-signature gate above and the data-segment check above (SPEC.md 8.7 item
# 1, section 10) -- MOAT.7 disabled checkFreshness entirely (internal/format/verify.go, short-circuited
# to an unconditional "this run is latest") with zero effect on any assertion this file ran, because
# nothing here ever corrupted a RUNLOG-specific byte; every existing negative case is caught elsewhere
# (data-segment AEAD, root-signature gate) and neither exercises the RUNLOG signature at all. Flip one
# byte of `_RECOVERY/RUNLOG.sig` and require verify to refuse. The expected exit code is taken from
# SPEC.md 8.7 item 1, not guessed: "An absent or truncated RUNLOG, or a RUNLOG signature that is
# invalid, single-half, or by a different signer, fails with exit 5 unless --allow-stale is given."
echo "e2e: NEGATIVE - corrupt the RUNLOG's own signature and require verify to REJECT it (the freshness-signature path, distinct from the root-signature and data-segment paths)"
RUNLOG_TAMPERED="$WORK/archive-runlog-sig-tampered"
cp -R "$ARCHIVE" "$RUNLOG_TAMPERED"
RUNLOG_SIG="$RUNLOG_TAMPERED/_RECOVERY/RUNLOG.sig"
if [ ! -f "$RUNLOG_SIG" ]; then
  echo "e2e: FAIL - could not locate _RECOVERY/RUNLOG.sig to tamper" >&2
  exit 1
fi
echo "e2e: tampered $RUNLOG_SIG (byte 0: $(flip_first_byte "$RUNLOG_SIG"))"

RUNLOG_VERIFY_EXIT=0
RUNLOG_VERIFY_OUT="$("$BIN" verify --archive "$RUNLOG_TAMPERED" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER" 2>&1)" || RUNLOG_VERIFY_EXIT=$?
echo "$RUNLOG_VERIFY_OUT"

if [ "$RUNLOG_VERIFY_EXIT" -ne 5 ]; then
  echo "e2e: FAIL - verify against a corrupted RUNLOG signature exited $RUNLOG_VERIFY_EXIT, not 5 (ExitStale, SPEC.md 8.7 item 1); the freshness/RUNLOG-signature path was not exercised or did not fail closed" >&2
  exit 1
fi
echo "e2e: PASS - corrupted RUNLOG signature: exit 5 (ExitStale), the freshness path independently detected it"

# ---- The anti-rollback pin path, both ways (closes MOAT.7 divergence 2). --min-runlog-index is never
# passed anywhere else in this file (the reader itself WARNS "--min-runlog-index was not set" on every
# run above), so CheckFreshness's `runlogMax < minIndex` comparison -- including an off-by-one MOAT.7
# injected there (`minIndex-1`) -- was dead code as far as this gate is concerned, correctness or not.
# Exercise it both ways on the archive's real runlogIndex, derived from test/write-archive.ts rather
# than re-typed: pin one above the actual latest MUST refuse (exit 5), and pin AT the actual latest MUST
# pass (exit 0). Both are required: a reader that always refused any pin would pass the first case and
# silently fail the second; the off-by-one specifically passes the second case wrongly too permissively
# (accepts a pin one above where it should refuse), so only running both closes the boundary.
echo "e2e: the anti-rollback --min-runlog-index pin, exercised both ways (never otherwise passed in this file)"
RUNLOG_INDEX="$(grep -oE 'runlogIndex: *[0-9]+' "$ENGINE_DIR/test/write-archive.ts" | head -n1 | grep -oE '[0-9]+')"
if [ -z "$RUNLOG_INDEX" ]; then
  echo "e2e: FAIL - could not derive the archive's runlogIndex from test/write-archive.ts (fixture shape changed?)" >&2
  exit 1
fi
PIN_ABOVE=$(( RUNLOG_INDEX + 1 ))

PIN_ABOVE_EXIT=0
PIN_ABOVE_OUT="$("$BIN" verify --archive "$ARCHIVE" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER" --min-runlog-index "$PIN_ABOVE" --acknowledge-no-rollback-pin 2>&1)" || PIN_ABOVE_EXIT=$?
echo "$PIN_ABOVE_OUT"
if [ "$PIN_ABOVE_EXIT" -ne 5 ]; then
  echo "e2e: FAIL - --min-runlog-index $PIN_ABOVE (one above the real latest index $RUNLOG_INDEX) exited $PIN_ABOVE_EXIT, not 5 (ExitStale); the pin comparison did not fire" >&2
  exit 1
fi

PIN_EXACT_EXIT=0
PIN_EXACT_OUT="$("$BIN" verify --archive "$ARCHIVE" --run "$RUN_ID" --identity "$ID" --signer "$SIGNER" --min-runlog-index "$RUNLOG_INDEX" --acknowledge-no-rollback-pin 2>&1)" || PIN_EXACT_EXIT=$?
echo "$PIN_EXACT_OUT"
if [ "$PIN_EXACT_EXIT" -ne 0 ]; then
  echo "e2e: FAIL - --min-runlog-index $RUNLOG_INDEX (the real latest index) exited $PIN_EXACT_EXIT, not 0; the pin comparison over-refused a satisfied pin" >&2
  exit 1
fi
echo "e2e: PASS - the pin refuses one above the real index $RUNLOG_INDEX (exit 5) and passes at the real index (exit 0)"
