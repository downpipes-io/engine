# Dependency inventory and SBOM approach

**Scope:** All three Downpipes repositories -- `engine`, `console`, `downpipe`
**Standard:** CycloneDX 1.6 (JSON)
**ASVS control:** V15.1.2 (L2, PARTIAL -- P-34 in the assessment)
**Source files read:** `engine/package.json`, `console/package.json`, `downpipe/go.mod`, `downpipe/go.sum`

---

## 1. Purpose

ASVS 5.0 V15.1.2 requires a maintained component inventory. For Downpipes the relevant surface is the runtime cryptographic dependency surface: the libraries that touch key material, ciphertext, and signatures on live requests. This document records that surface, explains how the inventory is pinned, and describes the toolchain used to generate a machine-readable SBOM artefact.

---

## 2. Runtime dependency surface

### 2.1 TypeScript repos (engine and console)

Both repos share the same two runtime dependencies, declared in `engine/package.json:38-41` and `console/package.json:20-23`:

| Package | Declared range | Resolved version (lockfile) | Role |
|---|---|---|---|
| `@noble/curves` | `^2.2.0` | see `package-lock.json` | Ed25519 signing, X25519 key agreement (classical half of the PQ-hybrid) |
| `@noble/post-quantum` | `^0.6.1` | see `package-lock.json` | ML-KEM-1024 key encapsulation, ML-DSA-87 signatures (post-quantum half of the PQ-hybrid) |

All other `dependencies` and `devDependencies` entries (`@cloudflare/workers-types`, `typescript`, `vitest`, `wrangler`) are build-time or type-checking tools that are not bundled into the deployed Worker artefact.

There are no transitive runtime dependencies beyond the `@noble` libraries. The `@noble` libraries are zero-dependency by design.

### 2.2 Go repo (downpipe)

Declared in `downpipe/go.mod` and hash-pinned in `downpipe/go.sum`:

| Module | Version | go.sum hash (h1:) | Role |
|---|---|---|---|
| `golang.org/x/crypto` | `v0.52.0` | `RMs7fP2rXdep0CftQlK8Uf+kibLm7qkCcradZWYz988=` | Go `mlkem`, `ecdh`, `ed25519`, `sha512`, `hkdf` -- stdlib-adjacent extensions |
| `filippo.io/mldsa` | `v0.0.0-20260215214346-43d0283efc3e` | `VsUbObBMxXlc23Eb9VeeJYE4jvTs87qa5RqSN2U5FJU=` | ML-DSA-87 signatures (post-quantum signing half) |

The Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha512`) is used directly for AES-256-GCM, SHA-384, and secure random, and carries no external version -- it is governed by the `go 1.26` toolchain directive in `go.mod:3`.

---

## 3. Pinning strategy and known concern

### 3.1 Go (downpipe) -- exactly pinned

`go.mod` pins exact versions; `go.sum` records the expected SHA-256 tree hashes for both the module zip and the `go.mod` file. `go mod download` will refuse to proceed if either hash does not match. This is the strongest pinning available in the Go toolchain.

### 3.2 TypeScript (engine, console) -- caret-range concern

**`package.json` uses caret ranges (`^2.2.0`, `^0.6.1`) for both `@noble` libraries.** A caret range permits any minor or patch update within the declared major version. In practice, the installed version is pinned by `package-lock.json` (lockfileVersion 3), which records the exact resolved version and its SHA-512 integrity hash. `npm ci` (used in CI) enforces the lockfile and will error if it is absent or inconsistent.

The risk is not in CI or in `npm ci` installs. It arises in two scenarios:

1. A developer runs `npm install` (not `npm ci`) locally, which can silently update the resolved version inside the lockfile and introduce a dependency change that is then committed without review.
2. The lockfile is regenerated (for example after a Dependabot PR merges) and the PR diff for `package-lock.json` is not reviewed with the same care as source changes. Because both `@noble` libraries are cryptographic primitives that directly handle key material and signatures, an unreviewed version bump is a higher-risk event than it would be for a non-cryptographic dependency.

**Recommended resolution:** Pin the `@noble` dependencies to an exact version in `package.json` (remove the `^` prefix):

```json
"dependencies": {
  "@noble/curves": "2.2.0",
  "@noble/post-quantum": "0.6.1"
}
```

After updating, run `npm install` to regenerate the lockfile, commit both files together, and tag the review as a security-sensitive change. Exact pinning ensures that no tooling path can silently introduce a new version, and makes the lockfile and `package.json` consistently express the same version. Dependabot will still raise PRs for new releases; the difference is that those PRs become an explicit, reviewable gate.

---

## 4. SBOM generation toolchain

### 4.1 TypeScript repos (engine and console)

Tool: `@cyclonedx/cyclonedx-npm` (CycloneDX schema 1.6, JSON output)

Installation:

```sh
npm install --save-dev @cyclonedx/cyclonedx-npm
```

Each repo has a `scripts/generate-sbom.sh` that invokes the tool. See `engine/scripts/generate-sbom.sh` and `console/scripts/generate-sbom.sh`.

The tool reads `package.json` and `package-lock.json` and produces a CycloneDX BOM. Running with `--omit dev` limits the inventory to runtime dependencies only (the two `@noble` libraries), which is the appropriate scope for an SBOM representing the deployed artefact.

### 4.2 Go repo (downpipe)

Tool: `cyclonedx-gomod` (CycloneDX schema 1.6, JSON output)

Installation:

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
```

The `downpipe/scripts/generate-sbom.sh` script invokes the tool. The tool reads `go.mod` and `go.sum` and records the exact pinned version and hash for each module.

---

## 5. CI integration (recommended)

Add a `generate-sbom` step to each repo's CI workflow after the build step:

```yaml
- name: Generate SBOM
  run: bash scripts/generate-sbom.sh
- name: Upload SBOM artefact
  uses: actions/upload-artifact@v4
  with:
    name: sbom-${{ github.sha }}
    path: sbom.cdx.json
```

Attaching the SBOM as a signed workflow artefact (using `actions/attest-build-provenance` alongside the existing SLSA attestation) closes the V15.1.2 maintained-inventory requirement and aligns with the transparency workstream goal of proving that the deployed Worker runs audited source.

---

## 6. Relationship to existing CI scanning

`engine/.github/workflows/ci.yml` already runs `npm audit --omit=dev --audit-level=high`. The Go CI runs `govulncheck`. Dependabot is configured across the organisation with a weekly cadence. These controls provide automated vulnerability detection against the currently-resolved lockfile. The SBOM generated by the scripts in this document provides the point-in-time inventory artefact that V15.1.2 requires and that GAP-02 (V15.1.1) references as the measurement baseline for a remediation-SLA policy.

---

*Source paths cited: `engine/package.json`, `console/package.json`, `downpipe/go.mod`, `downpipe/go.sum`.*
*ASVS finding cross-references: P-34 (V15.1.2, PARTIAL), GAP-02 (V15.1.1, GAP).*
