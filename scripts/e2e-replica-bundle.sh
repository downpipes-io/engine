#!/usr/bin/env bash
# End-to-end replica-bundle gate: a destination reached only through replication, never sealed to
# directly, is still a self-sufficient, verifiable archive. test/write-replica-bundle.ts seals a real
# archive with the engine's TypeScript writer, replicates it to a SECOND, empty destination with the real
# replication cores (mirrorRunToReplica, replicateRecoveryBundle), and flushes that replica to disk. The
# independent Go reader then runs `verify --check-bundle` and `restore --signer-fingerprint` against it,
# with neither Cloudflare nor the vendor in the loop, mirroring scripts/e2e-writer-reader.sh's shape.
#
# NEGATIVE CONTROL. The same driver also writes a replica with the bundle step skipped (a replica that
# holds the run copies and not the bundle), so this gate cannot pass vacuously -- it must show the reader
# actually fails against the bundle-less replica (exit 2 on verify, exit 6 on restore) before it can show
# the replica with the bundle succeeding (exit 0 on both).
#
# Usage:  bash scripts/e2e-replica-bundle.sh
# Env:    DOWNPIPE_REPO  path to the Go downpipe repo (default: ../downpipe, the sibling checkout)
#         NODE           node binary (default: node; must run .ts via strip-types, Node 22+)
# Exit:   0 = the replica with the bundle verifies and restores (exit 0 on both commands) AND the negative
#         control independently confirms the bundle-less replica fails closed (exit 2 on verify, exit 6 on
#         restore); non-zero otherwise.
set -euo pipefail

ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNPIPE_REPO="${DOWNPIPE_REPO:-$ENGINE_DIR/../downpipe}"
NODE="${NODE:-node}"
RUN_ID="01ARZ3NDEKTSV4RRFFQ69G5FAV"

if [ ! -d "$DOWNPIPE_REPO/cmd/downpipe" ]; then
  echo "e2e-replica-bundle: cannot find the Go downpipe repo at '$DOWNPIPE_REPO' (set DOWNPIPE_REPO)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/downpipe"

echo "e2e-replica-bundle: building the Go reader ($DOWNPIPE_REPO) into a temp dir"
( cd "$DOWNPIPE_REPO" && go build -o "$BIN" ./cmd/downpipe )

POS="$WORK/positive"
NEG="$WORK/negative"

echo "e2e-replica-bundle: the engine seals an archive and replicates it, WITH the bundle, to an empty destination -> $POS"
( cd "$ENGINE_DIR" && "$NODE" test/write-replica-bundle.ts "$POS" with-bundle )

echo "e2e-replica-bundle: the same replication, bundle step SKIPPED (a bundle-less replica) -> $NEG"
( cd "$ENGINE_DIR" && "$NODE" test/write-replica-bundle.ts "$NEG" no-bundle )

FP="$("$BIN" keys --fingerprint --signer "$POS/signer.pub" | awk '/^signer /{print $2}')"
if [ -z "$FP" ]; then
  echo "e2e-replica-bundle: FAIL - could not read the signer fingerprint from 'downpipe keys --fingerprint'" >&2
  exit 1
fi
echo "e2e-replica-bundle: signer fingerprint $FP"

# ---- POSITIVE: the replica with the bundle verifies and restores, both exit 0 -----------------------------
echo "e2e-replica-bundle: POSITIVE - verify --check-bundle against the replica with the bundle"
POS_VERIFY_EXIT=0
"$BIN" verify --archive "$POS/archive" --run "$RUN_ID" --identity "$POS/identity.key" --signer "$POS/signer.pub" --check-bundle || POS_VERIFY_EXIT=$?
echo "e2e-replica-bundle: positive verify exit=$POS_VERIFY_EXIT"
if [ "$POS_VERIFY_EXIT" -ne 0 ]; then
  echo "e2e-replica-bundle: FAIL - verify --check-bundle against the replica WITH the bundle exited $POS_VERIFY_EXIT, want 0" >&2
  exit 1
fi

echo "e2e-replica-bundle: POSITIVE - restore --signer-fingerprint against the replica with the bundle"
POS_RESTORE_EXIT=0
"$BIN" restore --archive "$POS/archive" --run "$RUN_ID" --identity "$POS/identity.key" --signer-fingerprint "$FP" --out "$POS/restored" --apply || POS_RESTORE_EXIT=$?
echo "e2e-replica-bundle: positive restore exit=$POS_RESTORE_EXIT"
if [ "$POS_RESTORE_EXIT" -ne 0 ]; then
  echo "e2e-replica-bundle: FAIL - restore --signer-fingerprint against the replica WITH the bundle exited $POS_RESTORE_EXIT, want 0" >&2
  exit 1
fi
if [ -z "$(ls -A "$POS/restored" 2>/dev/null)" ]; then
  echo "e2e-replica-bundle: FAIL - the positive restore produced no output" >&2
  exit 1
fi

# ---- NEGATIVE CONTROL: the bundle-less replica fails closed, exit 2 then exit 6 ----------------------------
echo "e2e-replica-bundle: NEGATIVE - verify --check-bundle against the bundle-less replica (bundle step skipped)"
NEG_VERIFY_EXIT=0
"$BIN" verify --archive "$NEG/archive" --run "$RUN_ID" --identity "$NEG/identity.key" --signer "$NEG/signer.pub" --check-bundle || NEG_VERIFY_EXIT=$?
echo "e2e-replica-bundle: negative verify exit=$NEG_VERIFY_EXIT"
if [ "$NEG_VERIFY_EXIT" -ne 2 ]; then
  echo "e2e-replica-bundle: FAIL - verify --check-bundle against the bundle-less replica exited $NEG_VERIFY_EXIT, want 2 (ExitUnverified): the negative control did not reproduce the gap this gate checks for" >&2
  exit 1
fi

echo "e2e-replica-bundle: NEGATIVE - restore --signer-fingerprint against the bundle-less replica (bundle step skipped)"
NEG_RESTORE_EXIT=0
"$BIN" restore --archive "$NEG/archive" --run "$RUN_ID" --identity "$NEG/identity.key" --signer-fingerprint "$FP" --out "$NEG/restored" --apply || NEG_RESTORE_EXIT=$?
echo "e2e-replica-bundle: negative restore exit=$NEG_RESTORE_EXIT"
if [ "$NEG_RESTORE_EXIT" -ne 6 ]; then
  echo "e2e-replica-bundle: FAIL - restore --signer-fingerprint against the bundle-less replica exited $NEG_RESTORE_EXIT, want 6 (ExitUsage): the negative control did not reproduce the gap this gate checks for" >&2
  exit 1
fi

echo "e2e-replica-bundle: PASS - the replica with the bundle verifies and restores (exit 0, exit 0); the bundle-less replica fails closed the same way (exit 2, exit 6)"
