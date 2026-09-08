# Contributing to downpipes-io/engine

The engine is the in-account Cloudflare Worker that reads Workers KV, R2, Secrets Store
and D1 and seals them to the `downpipe/0.1.0` archive format. It is byte-compatible with
the Go reference at the sibling `downpipe` repository and is proven against that
reference's conformance vectors.

## Contributor Licence Agreement

Pull requests are accepted only from contributors who have signed the
[Contributor Licence Agreement](CLA.md). The CLA Assistant bot checks this automatically on your
first pull request and posts a comment with a sign-off link if you have not signed yet; signing
takes one comment and you only do it once.

## Non-negotiables

- No custody. The engine runs only in the customer's own account. It never sends
  customer data or a Cloudflare token off-account. It holds only public recipient keys
  plus the signer private key (which it needs to sign roots and the RUNLOG).
- Break-glass. The engine can wrap the run master to the offline break-glass public key
  but can never unwrap it. It never decapsulates a recipient.
- Recover without the vendor and without Cloudflare. The format and the offline
  `downpipe` reader are the contract; the engine must produce archives that reader
  recovers byte-for-byte where the spec says writer-authoritative.
- Custom domains only. No `*.workers.dev` route, ever.

## Crypto

CNSA 2.0 hybrid post-quantum, matching the Go reference byte-for-byte:

- AES-256-GCM in the downpipe STREAM, SHA-384 / HKDF-SHA-384 / HMAC-SHA-384, Ed25519,
  and X25519 come from Web Crypto (`crypto.subtle`).
- ML-KEM-1024 (encapsulate only) and ML-DSA-87 (sign only) come from the pinned
  `@noble/post-quantum`. That is the only third-party cryptographic dependency. It is
  not constant-time-guaranteed; the mitigation is that the engine never decapsulates a
  long-lived key in-account and the signer is the only live secret. A constant-time
  Rust/WASM escalation is the documented fallback.
- Do not invent a primitive or a wire rule. The frozen constants live in
  `src/format/version.ts`, ported verbatim from the reference `internal/spec`.

Every crypto change must keep `npm run validate:crypto` green: it reproduces the Go
`crypto-kat` and `kem-combiner-kat` vectors byte-for-byte with Web Crypto.

## Style

Australian English. Errors are values, not thrown control flow where a result is
expected. Secrets plaintext lives only
in isolate memory and is never logged, never written to an object, a manifest, Durable
Object storage or any orchestration state.

## What is out of scope here

CI/CD and supply-chain hardening are added at the very end of the whole platform, not
now. Do not add workflow files.
