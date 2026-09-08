# Upgrading the downpipe engine

This file records the migration-guide policy for the engine. The engine is the
in-account Cloudflare Worker that seals Workers KV, R2, Secrets Store and D1 to
the `downpipe/0.1.0` archive format. It is self-hosted in the customer's own
Cloudflare account; there is no managed rollout.

## Policy

While the engine is pre-1.0 (the `0.x.y` series), minor and patch releases may
carry behaviour changes. Each release that needs operator action will be called
out here under a version heading, with the exact steps, before the version is
tagged. Releases with no operator action are noted as such.

When the engine reaches a major version increment, every breaking change in that
release gets a numbered migration step in this file, written before the tag is
cut. A migration guide is a release blocker for any breaking change.

The on-disk archive format carries its own frozen version (`downpipe/0.1.0`) that
is independent of the engine version. A change to a byte-level rule of the
archive format is a new format MINOR version (an incompatible format identity
while the format major stays 0), specified normatively in the
sibling `downpipe` repository at `docs/format/SPEC.md`, and is never an engine
upgrade note. The engine must keep producing archives the offline reader
recovers byte-for-byte where the spec says writer-authoritative.

## How to upgrade

Deployments are manual. Pull the release, run `npm run validate` and
`npm run typecheck`, follow any version-specific steps below, then
`npm run deploy`. There is no automatic rollout, so the operator controls the
timing and can roll back by redeploying the prior tag.

Use `npm run deploy` for the engine, not a bare `wrangler deploy`: it runs
`scripts/sync-bindings.mjs` first, which deploys a superset `wrangler.deploy.toml`
that preserves every console-attached source binding and fails closed if it
cannot prove those sources survive. A bare `wrangler deploy` would silently drop
every source attached from the console (they live on the worker, not in git).

## Migrations

No operator-action migrations are recorded yet. The first will be added here
before its release is tagged.
