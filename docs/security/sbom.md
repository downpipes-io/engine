# Dependency inventory and SBOM approach

**Scope:** All three Downpipes repositories -- `engine`, `console`, `downpipe`
**Standard:** CycloneDX 1.6 (JSON)
**ASVS control:** V15.1.2 (L2, PARTIAL, per the 2026-06-08 assessment)
**Source files read:** `engine/package.json`, `console/package.json`, `downpipe/go.mod`, `downpipe/go.sum`

---

## 1. Purpose

ASVS 5.0 V15.1.2 requires a maintained component inventory. For Downpipes the relevant surface is the runtime cryptographic dependency surface: the libraries that touch key material, ciphertext, and signatures on live requests. This document records that surface, explains how the inventory is pinned, and describes the toolchain used to generate a machine-readable SBOM artefact.

---

## 2. Runtime dependency surface

### 2.1 TypeScript repos (engine and console)

Both repos share the same two runtime dependencies, declared in `engine/package.json:339-340` and `console/package.json:232,234`:

| Package | Declared range | Resolved version (lockfile) | Role |
|---|---|---|---|
| `@noble/curves` | `2.4.0` | see `package-lock.json` | Ed25519 signing, X25519 key agreement (classical half of the PQ-hybrid) |
| `@noble/post-quantum` | `0.6.1` | see `package-lock.json` | ML-KEM-1024 key encapsulation, ML-DSA-87 signatures (post-quantum half of the PQ-hybrid) |

All other `dependencies` and `devDependencies` entries (`@cloudflare/workers-types`, `typescript`, `typescript-7`, `vitest`, `wrangler`) are build-time or type-checking tools that are not bundled into the deployed Worker artefact. `typescript-7` is an `npm:` alias for a second, newer `typescript` release (`engine/package.json`): the compiler-API gates under `test/` and `scripts/` import the "typescript" package by name and stay on the 6.x line, while every `tsc` CLI invocation is pointed at the 7.x binary by explicit path, because both packages declare a `tsc` bin and only one name can occupy `node_modules/.bin/tsc`.

There are no transitive runtime dependencies beyond the `@noble` libraries. The `@noble` libraries are zero-dependency by design.

### 2.2 Go repo (downpipe)

Declared in `downpipe/go.mod` and hash-pinned in `downpipe/go.sum`:

| Module | Version | go.sum hash (h1:) | Role |
|---|---|---|---|
| `golang.org/x/crypto` | `v0.52.0` | `RMs7fP2rXdep0CftQlK8Uf+kibLm7qkCcradZWYz988=` | Go `mlkem`, `ecdh`, `ed25519`, `sha512`, `hkdf` -- stdlib-adjacent extensions |
| `filippo.io/mldsa` | `v0.0.0-20260215214346-43d0283efc3e` | `VsUbObBMxXlc23Eb9VeeJYE4jvTs87qa5RqSN2U5FJU=` | ML-DSA-87 signatures (post-quantum signing half) |

The Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha512`) is used directly for AES-256-GCM, SHA-384, and secure random, and carries no external version -- it is governed by the `go 1.26` toolchain directive in `go.mod:3`.

---

## 3. Pinning strategy

### 3.1 Go (downpipe) -- exactly pinned

`go.mod` pins exact versions; `go.sum` records the expected SHA-256 tree hashes for both the module zip and the `go.mod` file. `go mod download` will refuse to proceed if either hash does not match. This is the strongest pinning available in the Go toolchain.

### 3.2 TypeScript (engine, console) -- exact-pinned

`package.json` exact-pins both `@noble` libraries in both repos (`engine/package.json:339-340`, `console/package.json:232,234`): `"@noble/curves": "2.4.0"` and `"@noble/post-quantum": "0.6.1"`, no `^` or `~` prefix. `package-lock.json` (lockfileVersion 3) resolves to the same versions and records their SHA-512 integrity hashes. `npm ci` (used in CI) enforces the lockfile and will error if it is absent or inconsistent.

Because the range is already exact, a plain `npm install` cannot move the resolved version on its own: with no caret or tilde in `package.json`, `npm` has nothing to resolve up to, and the lockfile stays put. Moving to a new `@noble` release requires an explicit edit to `package.json` (a `npm install @noble/curves@<new-version>` or a hand edit), which shows as a `package.json` diff in the PR and is reviewable like any other source change, not only as a `package-lock.json` diff. Dependabot still raises PRs for new `@noble` releases on its normal cadence; each one lands as a `package.json` version-string change plus the matching lockfile update, both visible in the same review.

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

## 5. CI integration (current)

The SBOM generation step already runs, tag-triggered, in each repo's release workflow -- not on every push, only when a version tag cuts a release:

- `engine/.github/workflows/release.yml:107-108`, in the `build` job: `Generate CycloneDX SBOM (runtime deps)` runs `bash scripts/generate-sbom.sh`, then `sbom.cdx.json` is one of the files hashed into `SHA256SUMS.txt` (`release.yml:116`) and uploaded with the release tree (`release.yml:121-129`).
- `console/.github/workflows/release.yml:84-85` runs the same step for the console repo, with `sbom.cdx.json` hashed into its own `SHA256SUMS.txt`.
- `downpipe/.github/workflows/release.yml:56-58` installs `cyclonedx-gomod` ahead of the GoReleaser run that produces the Go repo's SBOM.

`SHA256SUMS.txt` (which covers `sbom.cdx.json`) is the file the SLSA Build L3 provenance step attests, and the GitHub release carries the SBOM alongside the artefact, sums, cosign bundles and `.intoto.jsonl`. The SBOM is generated from the exact commit each release ships, attested under the same provenance as the artefact, and published where a customer verifying a release can retrieve it -- it does not need to run on every push to do that job.

---

## 6. Relationship to existing CI scanning

`engine/.github/workflows/ci.yml` already runs `npm audit --omit=dev --audit-level=high`. The Go CI runs `govulncheck`. Dependabot is configured across the organisation with a weekly cadence. These controls provide automated vulnerability detection against the currently-resolved lockfile. The SBOM generated by the scripts in this document provides the point-in-time inventory artefact that V15.1.2 requires and that the V15.1.1 finding references as the measurement baseline for a remediation-SLA policy.

---

*Source paths cited: `engine/package.json`, `console/package.json`, `downpipe/go.mod`, `downpipe/go.sum`.*
*ASVS findings referenced: V15.1.2 (PARTIAL), V15.1.1 (GAP).*
