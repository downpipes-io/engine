# Dangerous functionality

The parts of the engine that do something inherently risky, what makes each one risky, and the
protection that contains it. ASVS 5.0 V15.1.5 asks that the documentation highlight where dangerous
functionality is used; V15.2.5 asks that those parts carry additional protection beyond the ordinary,
of the encapsulation, sandboxing or isolation kind. This document is both halves in one place, because
a list of hazards with no matching defences is not useful to a reviewer and a set of defences nobody
can find is not documentation.

**What qualifies.** A surface is on this list if it parses something an attacker can shape, holds key
material, reaches the network on a caller's instruction, or depends on a third-party library doing
something subtle correctly. Ordinary validated input handling is covered in
`input-validation-and-limits.md` and is not repeated here.

**The architectural property that bounds all of it.** The engine runs in the customer's own Cloudflare
account as a Worker. There is no vendor-operated instance, no inbound path from the vendor, and no
shared multi-tenant process: one customer's engine cannot pivot into another's because there is no
"elsewhere" to pivot to. Each numbered surface below adds its own containment on top of that.

---

## 1. The SAML response parser

**Why it is dangerous.** It parses XML supplied by an unauthenticated caller, at the point where an
identity is about to be established. This is the XML signature-wrapping (XSW), XXE and entity-expansion
class, and it is the highest-value surface in the engine: a defect here forges an operator identity.

**Containment.** The parser is hand-rolled and fail-closed rather than a general-purpose XML library,
because the dangerous features are ones a general parser is expected to support.

- No DTD, no entity expansion, no second root element, no processing-instruction content, and no
  last-value-wins attribute dedupe: a duplicate qualified attribute name is a refusal, not a
  resolution (`src/admin/saml/parser.ts:6,82,183-184,260`).
- A single-decode "verify equals read" discipline, so the bytes whose signature was checked are the
  bytes that are acted on. This is what defeats the wrapping class, where a verifier and a reader are
  induced to look at different elements.
- The root must be a `samlp:Response` in the SAML protocol namespace, matched namespace-exactly, with
  exactly one assertion. An `EncryptedAssertion` is out of scope and refused with a stated reason.
- The IdP signing certificates are **pinned** from the connection record. The assertion's own
  `ds:KeyInfo` is never read, so an attacker cannot nominate the key that validates their own
  assertion.
- Order matters and is structural: the base64 decode and its size ceiling run first, then the parser's
  raw-byte gates, then the namespace and cardinality checks, then signature verification.

**Proof it holds.** `test/validate-saml-xsw.ts` and `test/validate-saml-response.ts` carry the attack
vectors, including the wrapping variants, and run in `validate:chain`.

---

## 2. The archive container reader

**Why it is dangerous.** It parses bytes fetched back from a destination bucket during restore,
replication read-back and verification. Those bytes are attacker-influenceable: whoever can write to
the bucket can put anything there, including a truncated, substituted or hostile container.

**Containment.**

- The magic-byte and version gate is evaluated **as the argument to the decrypt**, so a bad `DPS1`
  magic or an unsupported version byte throws before the stream is ever opened
  (`src/format/container.ts:61,73`, called at `src/crypto/segment.ts:26,46`,
  `src/format/reader.ts:276,608`, `src/seal/fanout.ts:405`, `src/seal/replicate.ts:753`). This is a
  structural property rather than a convention: there is no call path that opens a stream first and
  validates afterwards.
- Everything is AEAD-sealed, so a substituted or edited body fails authentication rather than being
  parsed. Integrity is not a separate check that could be skipped.
- Sizes are bounded by construction: `CHUNK_SIZE` is 65,536 bytes and `MAX_SEGMENT_CHUNKS` is 16,384
  (`src/format/version.ts:33,50`), so a hostile container cannot ask the runtime for unbounded memory.
- Replication read-back deliberately re-unframes a bounded sample of what it just wrote
  (`src/seal/replicate.ts:738,724`), so a truncated, empty or wrong-object copy is caught at write
  time rather than at restore time. The check reads the framing only. It does not detect a changed
  byte inside a well-framed segment; the keyed restore drill checks that.

---

## 3. Outbound network egress

**Why it is dangerous.** Several features take a destination from a caller and then connect to it:
webhook notifications, the SIEM push sinks (HTTP and syslog-TLS), the OTLP push, and the archive
destination endpoint. This is the SSRF class, and the engine runs at the Cloudflare edge where
link-local cloud-metadata addresses are reachable.

**Containment.**

- Default-deny internal-host screening, at **both** the configuration boundary and the wire boundary,
  so a record stored by a path that bypassed the first is still refused at the second. The classifier
  covers loopback, RFC1918, link-local (including `169.254.169.254`), IPv6 unique-local and
  link-local, IPv4-mapped IPv6, and the obviously-internal names.
- Obfuscated address spellings are canonicalised through the URL parser before classification, so
  `2130706433`, `0x7f000001`, `127.1` and `017700000001` are screened rather than passing as opaque
  names (`canonicaliseBareHost`). A bare host typed into a form, which never went through a URL
  parser, is canonicalised explicitly at the syslog sink.
- Send-time **resolve** screening for hostnames, which is the DNS-rebinding half the literal screen
  cannot see through: the name is resolved and every A and AAAA answer is classified. It fails closed
  on an answer containing an internal address and open on no answer at all, and records which
  happened. It runs on the notify channels, the SIEM HTTP push, the SIEM syslog-TLS push, the OTLP
  push, the archive destination endpoint (`S3Destination`, at its request chokepoint, once per
  hostname per instance), the OIDC discovery, JWKS and token endpoints (`guardedOidcFetch`) and
  `BEACON_URL`. The residual is stated rather than hidden: Workers cannot pin a resolved address for
  the fetch or socket that follows, so a racing attacker is not stopped.
- Reaching a private network is refused by design rather than by omission. The engine runs at the edge
  with no tunnel into a customer network, so an on-prem sink on a private address was never a working
  configuration; the refusal is a named non-delivery the push trail shows. A notify channel has an
  explicit per-channel opt-in for an operator who really has a reachable private sink.
- Redirects are not followed (`redirect: "manual"`), so a redirect cannot walk a screened request to
  an unscreened target, and response bodies are never read into the audit trail.
- A notify channel (webhook, Slack, Teams, JSM, ServiceNow) is additionally bounded by an
  **operator-configured allowlist** of the external hosts the account has permitted: an exact hostname
  or a single-label `*.suffix` wildcard, checked at both the configuration boundary
  (`isAllowedWebhookUrl` / `validateChannel`) and the wire boundary (`deliverPayload`, and JSM's own
  create/close/poll sender), independently of the deny screening above. Absent or empty, the allowlist
  is unrestricted (every public host passes, subject only to the deny screens); once the account sets
  one, a host it does not name is refused there, on either boundary, with no request issued. A fixed
  vendor host the engine reaches on its own initiative, matched exactly (`isFixedEgressHostExact`,
  `src/lib/outbound.ts`), is always permitted and never needs an entry. The list is a positive statement of what the account
  permits, not a substitute for the deny screening: a host on the list still passes the internal-host
  and resolve screens above, and a private host still needs the per-channel opt-in even when it is
  listed. The SIEM push sinks, the OTLP push and the archive destination endpoint are bounded by the
  deny screening above only; the allowlist covers the notify-channel surface.

**Proof it holds.** `test/validate-egress-host-screen.ts`, `test/validate-ssrf-resolve-screen.ts` and
`test/validate-egress-allowlist.ts`, all in `validate:chain`.

---

## 4. Key material and the secrets source

**Why it is dangerous.** The engine reads the customer's own Secrets Store values in order to back
them up, and it holds the signing key it must use on every run.

**Containment.**

- **No read-all of values.** The Worker must be explicitly bound to each secret it backs up, so it
  only ever reads the values it was granted (`src/sources/secrets.ts:7-14`). There is no binding that
  enumerates the store.
- **Wiring metadata.** With the discovery token, a secrets run also reads metadata
  (`src/sources/secrets-wiring.ts:343`). It lists the names, scopes and comments of every secret in
  the store. It reads the settings of every Worker script in the account, and those settings hold
  each script's bindings, plain-text values included, in isolate memory for the read. The reader
  keeps only the entries that match a configured secret and reads no secret value. It reads only
  accounts in the Owner's discovery scope.
- A secret value lives in isolate memory only for the duration of the yield, is sealed into the
  archive, and is never written to a descriptor field and never logged.
- `RESERVED_BINDINGS` prevents the engine's own namespaces being nominated as a backup source, so it
  cannot be pointed at itself.
- The break-glass private identity is **never in the engine**. It is generated in the operator's
  browser and held by the customer offline, which is why a compromise of the running engine does not
  yield archive plaintext.
- The signer private is the one secret the engine necessarily holds, and it is held as a 64-byte seed
  with the Ed25519 half imported non-extractable. Custody, rotation cadence and the consequences of
  rotating are in `cryptography-and-keys.md`.
- The signer never re-signs a destination RUNLOG it has not verified: every RUNLOG writer checks the
  stored signature, the chain it rewrites and the destination's floor first
  (`src/seal/pipeline.ts` `verifyRunlogForWrite`). An Owner can sign a destination RUNLOG that does
  not verify under the signer through `POST /admin/runlog/resign` (`src/admin/router-runlog.ts`). That route is Owner-only (`keys.ceremony`) and needs step-up. It signs only the exact bytes whose
  SHA-384 the Owner confirmed, and it refuses a RUNLOG with a chain anomaly or one below the last
  good index. Each re-sign writes a `runlog-resigned` audit row and raises the `runlog-resigned`
  alert. Nothing in the engine calls it on its own. `POST /admin/runlog/floor/reset`, under the same
  gate, moves a destination's anti-rollback floor down to the RUNLOG it holds now when the writers
  refuse it on the floor alone (an env destination repointed by redeploy). It signs nothing.
  `POST /admin/runlog/relink`, under the same gate, relinks one downpipe's anomalous chain, once, in
  a RUNLOG that verifies, when the append refuses to. It never signs bytes that do not verify.

---

## 5. Third-party cryptography

**Why it is dangerous.** Post-quantum primitives are new, and a subtle implementation defect is not
visible from the calling code.

**Containment, and the one residual.** The engine pins its runtime dependencies to exact
versions, and the Go reader vendors its own. `crypto-call-sites.json` records, for each engine
source file, the crypto imports, calls and algorithms it uses. Both halves of each hybrid are
mandatory, with no downgrade path: a classical-only or PQ-only archive is not a shape the format can
express. Against published NIST ACVP subsets, the engine's implementations are tested in CI. The engine and
the Go reader both check the shared known-answer and conformance vectors, so a defect would have to
be present identically in two implementations to pass unnoticed.

The residual, recorded rather than mitigated: `@noble/post-quantum` states that it offers no protection
against side-channel attacks, and no constant-time ML-DSA is available to a Workers runtime today. The
exposure is largest where the engine decapsulates with the long-lived operational key, which it does in
the two-recipient posture. The header of `src/crypto/pq.ts` and `cryptography-and-keys.md` state the bounds.

---

## 6. The scheduler Durable Object

**Why it is dangerous.** It is the single authority for configuration, the audit chain, push records
and retention state. Everything that matters is behind one object, so a defect in its request handling
is a defect in all of it.

**Containment.**

- It is not addressable from outside. There is no public route to the DO. Only the engine Worker
  reaches it, through internal calls from its routes and its cron handler.
- Authentication is three methods in strict precedence, and a present-but-invalid stronger method is
  refused outright rather than falling through to a weaker one (`src/admin/auth.ts:7-14`). That
  anti-downgrade rule is the property that makes the precedence meaningful.
- Authorisation is re-resolved per request inside the DO rather than trusted from the caller, so a
  role change takes effect immediately and a stale capability cannot be replayed.
- The audit chain is append-only through one internal path: no external caller can inject an entry,
  and every entry is hash-chained to its predecessor. The chain is tamper-**evident** rather than
  tamper-proof, as `logging-inventory.md` and the accepted-risk register state.
- Security-sensitive changes require step-up re-authentication, and the admin retention-prune apply
  route additionally requires a dual-control approval bound to that exact plan. The scheduled prune
  deletes only when a downpipe's `retention.enforce` is on, and arming that, or widening an armed
  policy, needs `restore.apply` (`src/sched/scheduler-do.ts:424`). While someone other than the editor
  holds `restore.approve`, that edit is queued as a pending change (202) and applies only when a
  different holder of `restore.approve` approves it (`src/sched/scheduler-do-change-control.ts:488`,
  `:640`). The cron reads only the stored config, so a queued arm prunes nothing. The break-glass
  token, or an editor whom nobody else could approve, applies it at once; that writes a
  `retention-armed-alone` audit row and raises the `retention-armed-alone` alert (warning).
- A restore, retention-prune, owner-action or config-change approval is refused with a 429 and a
  Retry-After header when it arrives less than five seconds after the request was raised
  (`src/admin/approvals.ts:164`), so a
  scripted maker-and-checker pair cannot drive a dual-control ceremony faster than a person could read
  and act on it.

---

## 7. Generated documents and exports

**Why it is dangerous.** Audit CSV exports carry IdP-claim and edge-header-derived text, which an
attacker can choose, into a file a human opens in a spreadsheet.

**Containment.** `csvCell` neutralises a leading formula trigger (`=`, `+`, `-`, `@`, tab, CR, NUL)
with a single quote before the RFC-4180 quote-wrap, applied uniformly to every column rather than to
the ones someone remembered (`src/admin/audit.ts:517-521`). The export carries the flattened target
description and safe scalars only, never a raw target object, so no unreviewed value can ride out.

---

## What is deliberately NOT on this list

`eval`, `Function`, dynamic `import()` of caller-supplied paths, shell execution and native modules do
not appear because the engine uses none of them. The Workers runtime offers no shell and no filesystem,
so an entire family of dangerous functionality is absent by platform rather than by discipline. Saying
so is the point: a reviewer should be able to tell "we avoid this" from "we do this carefully".
