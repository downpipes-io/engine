# Dependency inventory and SBOM approach

**Scope:** All three Downpipes repositories: `engine`, `console` and `downpipe`
**Standard:** CycloneDX 1.6 (JSON)
**ASVS requirement:** V15.1.2
**Source files read:** `engine/package.json`, `console/package.json`, `downpipe/go.mod`, `downpipe/go.sum`

---

## 1. Purpose

ASVS 5.0 V15.1.2 requires a maintained component inventory. For Downpipes the relevant surface is the runtime cryptographic dependency surface: the libraries that touch key material, ciphertext, and signatures on live requests. This document records that surface, explains how the inventory is pinned, and describes the toolchain used to generate a machine-readable SBOM artefact.

---

## 2. Runtime dependency surface

### 2.1 TypeScript repos (engine and console)

Both repos share the same three runtime dependencies, declared in `engine/package.json:370-372` and `console/package.json:244-246`:

| Package | Declared range | Resolved version (lockfile) | Role |
|---|---|---|---|
| `@noble/curves` | `2.4.0` | see `package-lock.json` | Ed25519 public-key derivation and verification, X25519 key agreement (classical half of the PQ-hybrid) |
| `@noble/hashes` | `2.4.0` | see `package-lock.json` | SHA-2, HMAC and BLAKE3 in the engine; SHA-2 and HKDF in the console |
| `@noble/post-quantum` | `0.7.1` | see `package-lock.json` | ML-KEM-1024 key encapsulation, ML-DSA-87 signatures (post-quantum half of the PQ-hybrid) |

Every `devDependencies` entry (for example `typescript`, `@typescript/typescript6`, `vitest` and `wrangler`) is a build, test or type-check tool. None is bundled into the deployed Worker artefact. `typescript` is the 7.x release and supplies every `tsc` CLI invocation. The 7.x line ships no JavaScript compiler API, so the compiler-API gates under `test/` and `scripts/` import `@typescript/typescript6` (the 6.x API, published by the TypeScript team for that purpose) by name.

The one transitive runtime dependency is `@noble/ciphers` `2.4.0`, which `@noble/post-quantum` requires. The `@noble` packages depend only on each other.

### 2.2 Go repo (downpipe)

Declared in `downpipe/go.mod` and hash-pinned in `downpipe/go.sum`:

| Module | Version | go.sum hash (h1:) | Role |
|---|---|---|---|
| `golang.org/x/crypto` | `v0.57.0` | `3ZVCjf8Ggz7zneR/EHRVx68Ctf+2pmIMP2UFhh9cC6M=` | HKDF (`golang.org/x/crypto/hkdf`) |
| `filippo.io/mldsa` | `v1.0.0` | `DSyjDhIEKrGEO/RZfI60iuXI83Yzy8jDcbqMuPySK5U=` | ML-DSA-87 signatures (post-quantum signing half) |

The Go standard library supplies the other primitives directly. `crypto/mlkem`, `crypto/ecdh` and `crypto/ed25519` supply ML-KEM-1024, X25519 and Ed25519. `crypto/aes`, `crypto/cipher`, `crypto/sha512` and `crypto/rand` supply AES-256-GCM, SHA-384 and secure random. The standard library carries no external version. The `go 1.26.0` directive (`go.mod:3`) sets the minimum Go version, and the `toolchain go1.26.6` line (`go.mod:14`) selects the build toolchain.

---

## 3. Pinning strategy

### 3.1 Go (downpipe): exactly pinned

`go.mod` pins exact versions; `go.sum` records the expected SHA-256 tree hashes for both the module zip and the `go.mod` file. `go mod download` will refuse to proceed if either hash does not match. This is the strongest pinning available in the Go toolchain.

### 3.2 TypeScript (engine, console): exact-pinned

`package.json` exact-pins the three `@noble` libraries in both repos (`engine/package.json:370-372`, `console/package.json:244-246`): `"@noble/curves": "2.4.0"`, `"@noble/hashes": "2.4.0"` and `"@noble/post-quantum": "0.7.1"`, with no `^` or `~` prefix. `package-lock.json` (lockfileVersion 3) resolves to the same versions and records their SHA-512 integrity hashes. `npm ci` (used in CI) enforces the lockfile and will error if it is absent or inconsistent.

Because the range is already exact, a plain `npm install` cannot move the resolved version on its own: with no caret or tilde in `package.json`, `npm` has nothing to resolve up to, and the lockfile stays put. Moving to a new `@noble` release requires an explicit edit to `package.json` (a `npm install @noble/curves@<new-version>` or a hand edit), which shows as a `package.json` diff in the PR and is reviewable like any other source change, not only as a `package-lock.json` diff. Dependabot still raises PRs for new `@noble` releases on its normal cadence; each one lands as a `package.json` version-string change plus the matching lockfile update, both visible in the same review.

---

## 4. SBOM generation toolchain

### 4.1 TypeScript repos (engine and console)

Tool: `@cyclonedx/cyclonedx-npm`, major version 4 (CycloneDX schema 1.6, JSON output)

Each repo has a `scripts/generate-sbom.sh` that runs the tool as `npx --yes @cyclonedx/cyclonedx-npm@4`, so no install step is needed. See `engine/scripts/generate-sbom.sh` and `console/scripts/generate-sbom.sh`.

The script passes `--package-lock-only`, so the tool reads `package-lock.json` and produces a CycloneDX BOM. The script also passes `--omit dev`, which limits the inventory to the runtime dependencies (the three `@noble` libraries and `@noble/ciphers`). That is the appropriate scope for an SBOM representing the deployed artefact.

### 4.2 Go repo (downpipe)

Tool: `cyclonedx-gomod` (CycloneDX schema 1.6, JSON output)

Installation:

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
```

The `downpipe/scripts/generate-sbom.sh` script invokes the tool. The release workflow pins the tool at `v1.10.0` (`CYCLONEDX_GOMOD_VERSION`, `downpipe/.github/workflows/release.yml:28`). The tool reads `go.mod` and `go.sum` and records the exact pinned version and hash for each module.

---

## 5. CI integration (current)

The SBOM generation step runs in each repo's release workflow. A `v*` tag push triggers it, and an ordinary push does not:

- `engine/.github/workflows/release.yml:107-108`, in the `build` job: `Generate CycloneDX SBOM (runtime deps)` runs `bash scripts/generate-sbom.sh`, then `sbom.cdx.json` is one of the files hashed into `SHA256SUMS.txt` (`release.yml:116`) and uploaded with the release tree (`release.yml:121-129`).
- `console/.github/workflows/release.yml:84-85` runs the same step for the console repo, with `sbom.cdx.json` hashed into its own `SHA256SUMS.txt`.
- `downpipe/.github/workflows/release.yml:92-94` installs `cyclonedx-gomod` ahead of the GoReleaser run. GoReleaser then writes one CycloneDX SBOM per archive (`downpipe/.goreleaser.yaml:51-57`).

In engine and console, the SLSA Build L3 provenance step attests every file that `SHA256SUMS.txt` lists, and that list includes `sbom.cdx.json`. cosign also signs the SBOM. The GitHub release carries the SBOM with the artefact, the sums, the cosign bundles and the `.intoto.jsonl`. The SBOM comes from the exact commit each release ships, so it does not need to run on every push.

---

## 6. Relationship to existing CI scanning

`engine/.github/workflows/ci.yml` runs `npm audit --omit=dev --audit-level=high`. The Go CI runs `govulncheck`. Dependabot runs weekly in all three repos. These controls provide automated vulnerability detection against the currently-resolved lockfile. The SBOM generated by the scripts in this document provides the point-in-time inventory artefact that V15.1.2 requires and that the V15.1.1 finding references as the measurement baseline for a remediation-SLA policy.

---

*Source paths cited: `engine/package.json`, `console/package.json`, `downpipe/go.mod`, `downpipe/go.sum`.*
*ASVS requirements referenced: V15.1.2, V15.1.1.*
