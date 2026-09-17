# Verify that a release is what it claims to be

You do not have to trust us. This document lets you confirm, yourself, that a downpipes engine
release was built by CI from the tagged source in this repository, published byte-exactly on the
update channel, and (from your own account's records) applied byte-exactly where you run it.

## What this proves, and what it does not

- It PROVES the artefact on the update channel is byte-for-byte the artefact you get by building
  the tagged commit yourself, and that CI attested exactly those bytes: nothing was swapped at
  any point between the tagged source and what your account applied.
- It does NOT prove the source is benign. A defect written into the source reproduces perfectly.
  Reading the source and the published assessments is the separate assurance that covers that;
  reproducibility and source review are different guarantees and we keep them distinct.
- It does NOT prove real-time runtime execution. Cloudflare Workers, like every serverless
  platform, exposes no hardware attestation of the running isolate. Your engine verifies the
  bytes at apply time, records the verdict in your own hash-chained audit log, and continuously
  compares the running deployment's version identity against the last verified apply. Between
  those checks you trust the Cloudflare control plane and whoever can access your own account,
  the same trust every Worker you run already carries. Established reproducible-build projects
  such as Tor state this same boundary; we state it plainly rather than imply more.

## Release integrity

This repository's own source-control and build gates sit upstream of everything above: every
change reaches `main` through a pull request and a green CI check, `main` and release tags
require signatures, and the release workflow checks a tag's signature against this repository's
allowed-signers file before it builds. See [What protects the release
path](https://docs.downpipes.io/operations/verify-a-release/#what-protects-the-release-path) for
the full picture, including reproducible builds and the update-channel's own signing.

## Step 1: rebuild the artefact from the tagged source

```bash
git checkout vX.Y.Z
npm ci
node scripts/build-release.mjs
# prints { version, sha384, sha256, ... }; writes dist/engine-X.Y.Z.mjs
```

The build is a deterministic function of the committed source (lockfile-pinned toolchain, no
timestamps, unstamped bundle; the script refuses a dirty tree). The reproducibility-check
workflow re-proves byte-stability on every release by building twice on two runner images from
two working paths; this document's claim stands only while that workflow is green.

## Step 2: compare against the signed channel

```bash
curl -fsSL https://update.downpipes.io/stable.json
# components.engine.sha384 must equal your rebuilt sha384
```

The channel is signed with the offline post-quantum hybrid release key (Ed25519 + ML-DSA-87,
both halves required); deployed engines verify it against the pinned public key and refuse
anything else. The provenance block inside the same signed body names the commit, tag, CI run
and Rekor log index, so the offline key vouches for those pointers too.

## Step 3: verify the CI attestations (no repository access needed)

Every attestation file is republished on the channel host under `provenance/X.Y.Z/`:

```bash
BASE=https://update.downpipes.io/provenance/X.Y.Z
curl -fsSLO "$BASE/engine.intoto.jsonl"
curl -fsSLO "$BASE/engine-X.Y.Z.mjs.cosign-bundle"
curl -fsSLO "$BASE/engine.SHA256SUMS.txt"

cosign verify-blob --bundle engine-X.Y.Z.mjs.cosign-bundle \
  --certificate-identity-regexp '^https://github.com/downpipes-io/engine/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dist/engine-X.Y.Z.mjs

slsa-verifier verify-artifact dist/engine-X.Y.Z.mjs \
  --provenance-path engine.intoto.jsonl \
  --source-uri github.com/downpipes-io/engine
```

The keyless signature and its certificate are logged in the public Sigstore Rekor transparency
log (the log index is in the signed channel), so a signature served to you and hidden from
everyone else is detectable.

## Step 4: read the account's own record

The half no vendor can fake after the fact: the console's Licence and updates screen, Provenance
section, shows the digest the engine enforced at apply time, the platform read-back verdict
(whether Cloudflare's own API returned byte-exactly those bytes before promotion), and offers an
on-demand cross-check against the published release record. The Security Centre's
`update-apply-provenance` and `update-version-drift` checks keep both facts graded between
applies, and everything above is persisted in the account's hash-chained audit log.

## If any step fails

Confirm you compared the same version first (the channel moves; the account record names the
version it applied). A same-version digest mismatch is exactly what this process exists to
surface: email security@maelstrom.au and keep the artefacts you fetched.
