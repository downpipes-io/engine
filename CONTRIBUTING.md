# Contributing to downpipes-io/engine

The engine is the in-account Cloudflare Worker that reads Workers KV, R2, Secrets Store
and D1 and seals them to the `downpipe/0.1.0` archive format. It is byte-compatible with
the Go reference at the sibling `downpipe` repository and is checked against that
reference's conformance vectors.

## Contributor Licence Agreement

Pull requests are accepted only from contributors who have signed the
[Contributor Licence Agreement](CLA.md). State that you accept it in the description of your first
pull request; the maintainer records the acceptance and you only do it once.

## Non-negotiables

- No custody. The engine runs only in the customer's own account. It never sends
  customer data or a Cloudflare token to the vendor. It holds the signer private key
  (which it needs to sign roots and the RUNLOG) and public recipient keys. It also holds
  two keys that protect only its own configuration. In the two-recipient posture it also
  holds the operational private key, which opens archives.
- Break-glass. The engine can wrap the run master to the offline break-glass public key
  but can never unwrap it. It decapsulates only with the operational key or with the
  config-recipient key, which opens only its own configuration export.
- Recover without the vendor and without Cloudflare. The format and the offline
  `downpipe` reader are the contract; the engine must produce archives that reader
  recovers byte-for-byte where the spec says writer-authoritative.
- The engine has no `*.workers.dev` route. The shipped console uses a custom domain; a `workers.dev` console is a supported first run.

## Crypto

CNSA 2.0 hybrid post-quantum, matching the Go reference byte-for-byte:

- AES-256-GCM in the downpipe STREAM, SHA-384 / HKDF-SHA-384 / HMAC-SHA-384 and Ed25519
  come from Web Crypto (`crypto.subtle`). X25519 comes from the pinned `@noble/curves`.
  The streaming SHA-384 and HMAC-SHA-384 come from the pinned `@noble/hashes`.
- ML-KEM-1024 and ML-DSA-87 come from the pinned `@noble/post-quantum`. The three
  `@noble` packages are the only third-party cryptographic dependencies.
  `@noble/post-quantum` is not constant-time-guaranteed. The engine decapsulates with
  long-lived keys: the config-recipient key in both postures, and the operational key
  in the two-recipient posture. A constant-time Rust/WASM escalation is the documented
  fallback.
- Do not invent a primitive or a wire rule. The frozen constants live in
  `src/format/version.ts`, ported verbatim from the reference `internal/spec`.

Every crypto change must keep `npm run validate:crypto` green: it reproduces the Go
`crypto-kat` and `kem-combiner-kat` vectors byte-for-byte.

## Style

Errors are values, not thrown control flow where a result is
expected. Secrets plaintext lives only
in isolate memory and is never logged, never written to an object, a manifest, Durable
Object storage or any orchestration state.

## CI

The CI and release workflows live in `.github/workflows/`. Run `npm run lint` and
`npm run validate` locally before you open a pull request.
