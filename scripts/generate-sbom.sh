#!/usr/bin/env bash
# Generate a CycloneDX 1.6 SBOM for the engine repo (runtime deps only).
#
# Output: sbom.cdx.json in the repo root.
#
# Requires:
#   node >= 20
#   @cyclonedx/cyclonedx-npm (installed as a dev dependency or globally)
#
# Install if missing:
#   npm install --save-dev @cyclonedx/cyclonedx-npm@4.2.1
#
# The generator is pinned to an exact version, and --output-reproducible
# drops the random serial number and the wall-clock timestamp. Two builds of
# one commit then give the same SBOM bytes. SHA256SUMS.txt names those bytes.
# test/validate-build-tool-pins.ts holds both properties.
#
# This script only generates the SBOM; it does not run npm install or
# modify any files other than sbom.cdx.json.
#
# See engine/docs/security/sbom.md for the dependency inventory and the
# @noble/* pinning strategy (exact-pinned in package.json).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if ! command -v npx >/dev/null 2>&1; then
  echo "error: npx not found; install Node.js >= 20 and re-run" >&2
  exit 1
fi

npx --yes @cyclonedx/cyclonedx-npm@4.2.1 \
  --omit dev \
  --output-format JSON \
  --spec-version 1.6 \
  --output-file sbom.cdx.json \
  --output-reproducible \
  --package-lock-only

echo "SBOM written to ${REPO_ROOT}/sbom.cdx.json"
