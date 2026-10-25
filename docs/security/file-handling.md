# File handling

**Standard:** OWASP ASVS 5.0 - V5.1.1 (file handling documentation).
**Scope:** the Downpipes console (TypeScript, a Cloudflare Worker serving a browser app), the engine (TypeScript, Cloudflare Workers), the control plane (TypeScript, Cloudflare Workers) and the offline `downpipe` CLI (Go).


This document answers V5.1.1 for each feature that accepts a file: the permitted file types and expected extensions (section 2), the maximum size including the unpacked size (section 3), how a file is made safe to download and process (section 4), and what each surface does with a malformed, oversized or malicious file (section 5). Every claim carries a `repo/path:line` citation into the tree that enforces it.

---

## 1. Where files enter and leave

The product is a content-addressed backup system. It has no general upload pipeline: no route stores an operator-submitted file, no service scans one, and no surface serves a file another user uploaded. It does accept files at a small number of places, and each of them is bounded.

| Surface | What it accepts | Where the bytes go |
|---|---|---|
| Console file pickers (section 2.1 to 2.3) | The operator's own `identity.key`, custody share files and the encrypted key file `identity.key.enc` | Read in the browser with `FileReader`; parsed in the browser; never sent to any server |
| Console estate-import form (section 2.4) | A pasted control-plane export, its detached signature and the recovery kit's `signer.pub` | Sent to the operator's own engine as JSON, verified against the operator-supplied public key |
| Engine restore (section 2.6) | Sealed archive objects read back from the operator's own destination bucket | Verified and decrypted inside the Worker, then written to in-account bindings |
| CLI (section 2.5) | The same key and custody files as the console, the sealed export, and archive objects | Read on the operator's machine; restored to a directory or a dotenv target |

The engine and the control plane emit downloads (an audit export, a PDF report) but take no upload. The console produces key artefacts as local downloads and takes only the pickers above.

---

## 2. Features that accept a file

### 2.1 The identity.key pickers

Seven console controls take the operator's break-glass private key as a file. Each declares the same accept filter, `.key,text/plain`, and each hands the file to one bounded read (`console/src/lib/file-size-guard.ts:37`) followed by one parser (`console/src/lib/keydecap.ts:202`).

| Control | Declared at | Read through |
|---|---|---|
| Attended verification, start a session | `console/src/screens/restore-flow/attend.ts:435` | `readIdentityFile`, `console/src/screens/restore-flow/attend.ts:76` |
| Attended verification, resume a session | `console/src/screens/restore-flow/attend.ts:691` | `readIdentityFile`, `console/src/screens/restore-flow/attend.ts:76` |
| In-console break-glass restore | `console/src/screens/restore-flow/break-glass.ts:254` | `readIdentityFile`, `console/src/screens/restore-flow/attend.ts:76` |
| Break-glass retention prune | `console/src/screens/restore-flow/break-glass-prune.ts:464` | `readIdentityFile`, `console/src/screens/restore-flow/attend.ts:76` |
| Estate import and scheduler recovery (the shared key panel) | `console/src/components/break-glass-key-panel.ts:93` | `readIdentityFileLocal`, `console/src/components/break-glass-key-panel.ts:44` |
| Split custody on the Keys screen | `console/src/screens/keys/custody.ts:118` | `readTextFileBounded`, `console/src/screens/keys/custody.ts:129` |
| Setup's Keys step, checking the saved key file | `console/src/screens/setup/b/q-keys.ts:294` | `readTextFileBounded`, `console/src/screens/setup/b/q-keys.ts:305` |

Permitted type: a text file whose whole content is one line, `downpipe-identity-v1 <base64url>`. Expected extension: `.key`. The accept filter also admits `text/plain`, because the file is plain text and an operator's system may not map `.key` to a type.

Parse rule: the text is trimmed and split on whitespace; there must be exactly two tokens and the first must be the label (`console/src/lib/keydecap.ts:204`); the second must decode to exactly 96 bytes, an X25519 scalar of 32 bytes followed by an ML-KEM seed of 64 bytes (`console/src/lib/keydecap.ts:206`). Anything else is refused.

Where the file goes: nowhere. The parsed private is held in the screen's own closure and is zeroed when the screen ends (`console/src/screens/restore-flow/attend.ts:145-150`). Setup's check keeps it only for one comparison: it compares the key's fingerprint with the keys made in the tab and zeroes both halves before it returns (`console/src/lib/setup-flow/actions.ts:459-460`). What reaches the operator's own engine is material recovered with it in the browser, a per-run master or the plaintext of a sealed export, never the private itself.

### 2.2 Custody share files

The reassembly card takes one or more Shamir share files at `console/src/screens/restore-flow/reassembly.ts:357`, with the accept filter `.txt,text/plain` (`console/src/screens/restore-flow/reassembly.ts:361`). The same card is mounted by the attended-verification screen, the break-glass restore and prune panels, the shared key panel, the Keys screen and the standalone `/restore/recover-key` screen.

Permitted type: a `downpipe-shamir-share-v1` text file. Expected extension: `.txt`. Parse rule: the first meaningful line must equal the label (`console/src/lib/custody-files.ts:228`); the file must carry the labelled lines `index`, `n`, `threshold`, `checksum` and `share` (`console/src/lib/custody-files.ts:162`); the checksum must decode to the module's checksum length (`console/src/lib/custody-files.ts:170`); a repeated label is refused (`console/src/lib/custody-files.ts:240`). Where the file goes: the share bytes stay in the card's closure, are combined in the browser, and are zeroed on reset and on navigation away (`console/src/screens/restore-flow/reassembly.ts:599-606`).

### 2.3 The encrypted key file

The same card takes exactly one `identity.key.enc` at `console/src/screens/restore-flow/reassembly.ts:441`, with the accept filter `.enc,.txt,text/plain` (`console/src/screens/restore-flow/reassembly.ts:444`). Permitted type: a `downpipe-wrapped-identity-v1` text file. Expected extension: `.enc`. Parse rule: the label line, then the `iv` and `ciphertext` lines, with an optional public `credential-id` line (`console/src/lib/custody-files.ts:87`). Where the file goes: the ciphertext and IV stay in the card's closure and are decrypted in the browser once a share quorum verifies.

### 2.4 The pasted estate export

The estate-import modal takes no file picker. It takes pasted text in three textareas: the signed control-plane export (`console/src/components/estate-import-modal.ts:46`), its detached signature (`console/src/components/estate-import-modal.ts:55`) and the recovery kit's `signer.pub` (`console/src/components/estate-import-modal.ts:63`). Permitted type: the JSON artefact the engine's own control-plane pass wrote to the destination bucket, in its plaintext form (`<version>-<time>.json`) or its sealed form (`.sealed.json`), with the signature file beside it. A sealed export is opened in the browser with the break-glass key from the panel in section 2.1, and the recovered plaintext is sent with the still-sealed original (`console/src/components/estate-import-modal.ts:215`).

Where the pasted text goes: the operator's own engine, at `POST /control-plane/import` (`engine/src/admin/router-identity.ts:291`) or `POST /control-plane/import-sealed` (`engine/src/admin/router-identity.ts:390`). Both routes read the body through `parseJsonBody` (`engine/src/admin/router-core.ts:78`), then apply shape checks in a fixed order: the export must be a control-plane export artefact (`engine/src/admin/router-identity.ts:301`), a signature string must be present (`engine/src/admin/router-identity.ts:306`), a `signer.pub` must be present (`engine/src/admin/router-identity.ts:310`), the artefact must carry no plaintext secret (`engine/src/admin/router-identity.ts:315`), the public key must parse (`engine/src/admin/router-identity.ts:326`), and the signature must verify against it (`engine/src/admin/router-identity.ts:346`). The sealed route adds a hash cross-check between the recovered plaintext and the signed `bodyHash` commitment (`engine/src/admin/router-identity.ts:461`).

### 2.5 The CLI inputs

The `downpipe` CLI reads key and custody files named on the command line. Key material is never accepted as an argument value, only as a path.

| Flag | Registered at | Permitted type | Parse rule |
|---|---|---|---|
| `--identity <file>` | `downpipe/cmd/downpipe/identity_source.go:50` | A `downpipe-identity-v1` file, `.key` | Two whitespace-separated tokens, the first the label (`downpipe/cmd/downpipe/recombine.go:167`); the second decodes to exactly 96 bytes (`downpipe/internal/crypto/keys.go:37`) |
| `--share <file>` (repeatable) | `downpipe/cmd/downpipe/identity_source.go:51` | A `downpipe-shamir-share-v1` file, or a file holding the bare emailed share body | Read under the artefact cap (`downpipe/cmd/downpipe/recombine.go:134`), then parsed by the custody package |
| `--wrapping-key <file>` | `downpipe/cmd/downpipe/identity_source.go:52` | A `downpipe-wrapping-key-v1` file | The same cap and parser family |
| `--envelope <file>` | `downpipe/cmd/downpipe/identity_source.go:53` | A `downpipe-wrapped-identity-v1` file, `.enc` | The same cap; an envelope carrying a `credential-id` is refused offline (`downpipe/cmd/downpipe/recombine.go:192`) |
| `--signer <file>` | `downpipe/cmd/downpipe/signer_source.go:40` | A `downpipe-signer-public-v1` file, `.pub` | The label rule at `downpipe/cmd/downpipe/recombine.go:167` |
| `--in`, `--sig` (unseal-export) | `downpipe/cmd/downpipe/unseal_export.go:59` | The sealed export JSON and its detached signature | Read whole (`downpipe/cmd/downpipe/unseal_export.go:77`); the signature must be base64url (`downpipe/cmd/downpipe/unseal_export.go:85`); verify precedes decrypt |

### 2.6 Archive objects

The engine's restore path and the CLI both read sealed archive objects (segments, manifests, the RUNLOG) that the engine wrote. Object keys are content-addressed identifiers derived from cryptographic material, never operator-supplied names. On the engine the objects come from the operator's own destination binding; on the CLI from `--archive <dir>`, an S3-compatible endpoint or an Azure endpoint. Every object is authenticated before any of its plaintext is used (section 6).

---

## 3. Maximum sizes, including the unpacked size

### 3.1 Ceilings

Each row's cited line holds the named constant, and the literal on that line evaluates to the value in the second column.

| Ceiling | Value | Constant | Where |
|---|---|---|---|
| Any file a console picker reads (identity.key, a share, identity.key.enc) | 64 KiB | `CONSOLE_FILE_MAX_BYTES` | `console/src/lib/file-size-guard.ts:20` |
| Any custody artefact file the CLI reads (a share, a wrapping key, an envelope) | 1 MiB | `maxArtefactBytes` | `downpipe/cmd/downpipe/recombine.go:27` |
| An Images file re-uploaded in-account on restore | 25 MiB | `MEDIA_UPLOAD_MAX` | `engine/src/admin/media-restore.ts:34` |
| A Stream video re-uploaded in-account on restore | 200 MB | `STREAM_DIRECT_MAX` | `engine/src/admin/media-restore.ts:40` |
| An R2 restore record held whole in Worker memory | 32 MiB | `BUFFERED_RESTORE_MAX_BYTES_CEILING` | `engine/src/admin/restore-sinks.ts:54` |
| The plaintext of one sealed segment | 1 GiB | `MAX_STREAM_SEGMENT_BYTES` | `engine/src/dest/types.ts:142` |
| Chunks in one segment on the CLI | 16384 | `maxSegmentChunks` | `downpipe/internal/format/restore.go:371` |
| One chunk on the CLI | 64 KiB | `ChunkSize` | `downpipe/internal/spec/spec.go:22` |
| A record's decompressed plaintext on the CLI (the product of the two rows above) | 1 GiB | `maxDecompressedBytes` | `downpipe/internal/format/restore.go:342` |
| One archive object read by the CLI | 2 GiB | `maxObjectBytes` | `downpipe/internal/source/dir.go:40` |

### 3.2 What each ceiling bounds

**Console pickers.** `File.size` is compared with `CONSOLE_FILE_MAX_BYTES` before a `FileReader` is constructed (`console/src/lib/file-size-guard.ts:38`); the reader exists only after the check passes (`console/src/lib/file-size-guard.ts:41`). A real key file is under four kilobytes, so the ceiling is a wrong-file guard. The parsers then bound the content further: an identity must decode to 96 bytes and a share's checksum must be the fixed length (section 2). There is no unpacked size: none of these files is compressed.

**Pasted estate export.** The engine applies no byte cap of its own on the two import routes; `parseJsonBody` reads the whole body (`engine/src/admin/router-core.ts:78`). The size is bounded by the Cloudflare Workers request-body limit for the account's plan, and the shape checks in section 2.4 refuse anything that is not a signed export artefact before it is stored. The export is JSON and is not compressed, so there is no unpacked size.

**Media re-upload.** A restore of an Images or Stream record re-uploads the captured bytes in-account. A record whose plaintext is above `MEDIA_UPLOAD_MAX` is surfaced for manual re-upload rather than restored (`engine/src/admin/restore-plan.ts:183`); a video above `STREAM_DIRECT_MAX` stays out of band (`engine/src/admin/media-restore.ts:383`).

**Buffered restore.** An R2 record above the buffered ceiling streams and is read back; every other record is materialised whole (`engine/src/admin/restore-sinks.ts:90`). The operator knob `RESTORE_BUFFERED_MAX_BYTES` can lower the figure and never raise it past the ceiling (`engine/src/admin/restore-sinks.ts:66`).

**Segments and unpacked size on the engine.** A value is sealed in segments of at most `MAX_STREAM_SEGMENT_BYTES` of plaintext; the R2, S3 and Azure Blob destinations assert the same ceiling on the put (`engine/src/dest/r2.ts:133`, `engine/src/dest/s3.ts:570`, `engine/src/dest/azure-blob.ts:407`). The Azure Blob destination asserts it from engine 0.3.7. A record's gzip member is inflated under a cap equal to the record's declared plaintext size: the buffered path passes it to `gunzip` (`engine/src/format/reader.ts:169`), the streaming path to `capStream` (`engine/src/format/reader.ts:320`), and the cap errors the stream the moment more bytes than declared have flowed (`engine/src/format/record-codec.ts:128`). A gzip bomb is therefore stopped mid-inflate, never buffered.

**Unpacked size on the CLI.** `maxDecompressedBytes` is the product of the chunk count and the chunk size (`downpipe/internal/format/restore.go:342`). A record whose declared plaintext size is above it is refused before any inflate starts (`downpipe/internal/format/restore.go:348`), and an inflate that produces more than the declared size is refused (`downpipe/internal/format/restore.go:360`). Every object read is bounded by `maxObjectBytes`: a content length above it is refused (`downpipe/internal/source/stream.go:139`) and the body reader is capped at the same figure (`downpipe/internal/source/stream.go:149`).

---

## 4. Downloads and processing

**No content sniffing.** Every response from the engine carries `x-content-type-options: nosniff`, on the `/admin` set (`engine/src/index.ts:118`) and on the base set applied to every other path (`engine/src/index.ts:134`). The console Worker sets it on every asset and page response (`console/src/worker.ts:239`) and passes a proxied engine response through with the engine's own headers. The control plane sets it in its base header set. A browser therefore renders a download as the declared type only. Every engine response also carries `content-security-policy: default-src 'none'; frame-ancestors 'none'`, `x-frame-options: DENY`, `strict-transport-security` and `cache-control: no-store` unless the route set its own, including the public `/`, `/ready` and `/scim` answers and the early refusals (`engine/src/index.ts:189` (`ENGINE_RESPONSE_FLOOR`), `engine/src/index.ts:530` (`ENGINE_RESPONSE_FLOOR`)).

**Attachment disposition with fixed filenames.** The audit export is delivered as an attachment under a name the engine chooses, never one taken from a request: `downpipe-audit.json` (`engine/src/sched/scheduler-do-audit.ts:595`, `engine/src/sched/scheduler-do-audit.ts:650`) and `downpipe-audit.csv` (`engine/src/sched/scheduler-do-audit.ts:645`).

**Inline PDF.** A posture report or evidence pack is delivered as `application/pdf` with an inline disposition so the console can preview it (`engine/src/admin/router-posture.ts:607`). The filename is built from a closed report kind and the framework name (`engine/src/admin/router-posture.ts:603`).

**Key artefacts never touch a server.** Every file the console produces for the operator (identity.key, the signer files, the recovery sheet, custody shares, recovery codes) is built as an in-memory `Blob`, minted as an object URL and clicked through a transient anchor (`console/src/lib/file-delivery.ts:44`); the object URL is revoked afterwards (`console/src/lib/file-delivery.ts:68`). There is no server URL for a key artefact, so nothing can be fetched twice or by another party.

**Processing a file the operator selected.** A selected file is processed in the browser only, by the parsers in section 2. No selected file is echoed back to the page, written to storage or sent over the network.

---

## 5. Behaviour on a malformed, oversized or malicious file

**Console, oversized.** The size guard rejects with a message naming the byte count and the ceiling (`console/src/lib/file-size-guard.ts:29`) and no `FileReader` is created (`console/src/lib/file-size-guard.ts:38`). The picker then clears any key it held and states "No key left this device" (`console/src/screens/restore-flow/attend.ts:443`, `console/src/screens/restore-flow/break-glass.ts:266`, `console/src/screens/restore-flow/break-glass-prune.ts:476`, `console/src/components/break-glass-key-panel.ts:113`). On the Keys screen the split step is unmounted (`console/src/screens/keys/custody.ts:160`). In the reassembly card the message lands in the shares error (`console/src/screens/restore-flow/reassembly.ts:380`) or the ciphertext error (`console/src/screens/restore-flow/reassembly.ts:462`). A refused encrypted key file also invalidates any prior reconstruction.

**Console, malformed.** An identity file without the label, or not 96 decoded bytes, throws from the parser (`console/src/lib/keydecap.ts:204`, `console/src/lib/keydecap.ts:206`) and the same clear-and-report path runs. The Keys screen refuses a file without the label (`console/src/screens/keys/custody.ts:132`) and a labelled file that fails the strict parse (`console/src/screens/keys/custody.ts:149`), zeroing the probe copy it parsed. A share or envelope of the wrong kind is refused at the label (`console/src/lib/custody-files.ts:228`). Refusal messages name the kind of file expected and the kind of fault, and never a line, offset or byte from the file, so a wrong file that is itself a secret cannot leak through a screenshot of the error.

**Console, malicious.** A crafted share that combines to a wrong key is caught by the wrapping-key checksum and the authenticated decrypt, and named by index rather than used (`console/src/screens/restore-flow/reassembly.ts:508`, `console/src/screens/restore-flow/reassembly.ts:544`). A crafted identity cannot do more than fail a decapsulation in the browser, because it is never sent anywhere.

**Engine, malformed or oversized archive content.** An inflate that runs past the declared plaintext size files a `decompress-overflow` locator carrying the declared and observed byte counts (`engine/src/format/record-codec.ts:132`, the kind at `engine/src/format/integrity-fault-ledger.ts:194`) and errors the stream (`engine/src/format/record-codec.ts:133`), so the record fails and nothing partial is written. On a confirmed restore every in-scope record is verified before any write (`engine/src/admin/restore-apply.ts:123`) and writes begin only once all have passed (`engine/src/admin/restore-apply.ts:140`). A segment above the ceiling is refused at the destination with a closed fault class (`engine/src/dest/r2.ts:135`).

**Engine, malformed import.** Each refusal on the estate-import routes records a recovery refusal with a closed class and answers with that class: `shape` (`engine/src/admin/router-identity.ts:302`), `malformed` (`engine/src/admin/router-identity.ts:306`), `no-custody` (`engine/src/admin/router-identity.ts:317`), `verifier-invalid` (`engine/src/admin/router-identity.ts:332`), the signature verdict's own class (`engine/src/admin/router-identity.ts:351`) and `reconcile-refused` (`engine/src/admin/router-identity.ts:369`), except that a 403 from the scheduler answers without a class. The sealed route adds `sealed-unhashed` (`engine/src/admin/router-identity.ts:453`) and `sealed-body-mismatch` (`engine/src/admin/router-identity.ts:461`). A malformed JSON body is a plain 400 (`engine/src/admin/router-identity.ts:297`). Nothing is imported until every check has passed.

**CLI.** A declared plaintext size above the decompression ceiling is refused before inflating (`downpipe/internal/format/restore.go:349`); an inflate past the declared size is refused (`downpipe/internal/format/restore.go:361`); an object whose content length is over the read bound is refused (`downpipe/internal/source/stream.go:142`); a custody artefact that is not a regular file, such as a FIFO or a device, is refused before it is read (`downpipe/cmd/downpipe/recombine.go:131`); a custody artefact file over the artefact cap is refused without being read (`downpipe/cmd/downpipe/recombine.go:135`); a key file with the wrong label is refused (`downpipe/cmd/downpipe/recombine.go:168`); an identity of the wrong length is refused (`downpipe/internal/crypto/keys.go:38`). The key and custody-file refusals exit with the usage code, 6. The archive refusals fail the command with a non-zero exit. The error text never echoes key or share bytes.

---

## 6. Archive write and restore paths

**Engine write.** Segments are written content-addressed through the destination drivers. The R2, S3 and Azure Blob drivers assert the single-segment ceiling on the put (`engine/src/dest/r2.ts:133`, `engine/src/dest/s3.ts:570`, `engine/src/dest/azure-blob.ts:407`). The Azure Blob driver asserts it from engine 0.3.7.

**Engine restore.** A target binding is checked against the engine's reserved bindings before any sink is constructed; a reserved binding refuses the whole restore (`engine/src/admin/restore-sinks.ts:343`). A D1 replay binds column values as parameters and never interpolates them into SQL (`engine/src/dest/restore-sink.ts:616`). A secrets sink with no runtime write path throws rather than skipping silently (`engine/src/dest/restore-sink.ts:385`). An R2 object too large for a single in-account put is refused with a pointer to the offline CLI (`engine/src/dest/restore-sink.ts:267`).

**CLI restore to a directory.** A record name is mapped to a contained relative path before it is written: `DirTarget.Key` (`downpipe/internal/restore/target_dir.go:45`) delegates to `safeKey`, which splits on both `/` and `\` and drops every empty, `.` and `..` element (`downpipe/internal/restore/target_dir.go:252`). `Write` opens the output directory as an `os.Root` (`downpipe/internal/restore/target_dir.go:133`) and creates the file through it with `O_WRONLY|O_CREATE|O_EXCL` at mode `0o600` (`downpipe/internal/restore/target_dir.go:108`), so an existing path is never overwritten, and a symlink already in the output directory that points outside it is refused rather than followed. The planner reads the paths already in the output directory (`downpipe/internal/restore/target_dir.go:57`), and a record whose path exists is a conflict that is not written.

**CLI restore to a dotenv target.** The record name must match `[A-Za-z_][A-Za-z0-9_]*` (`downpipe/internal/restore/target_env.go:79`, the predicate at `downpipe/internal/restore/target_env.go:104`), a value holding a NUL byte or a line break is refused (`downpipe/internal/restore/target_env.go:85`), and values are single-quoted with embedded quotes escaped (`downpipe/internal/restore/target_env.go:88`).

---

## 7. ASVS mapping

| V5.1.1 clause | Section | How it is addressed |
|---|---|---|
| The documentation defines the permitted file types and expected file extensions for each upload feature | 2 | every file-accepting feature is enumerated with its type, extension, accept filter and parse rule. |
| The documentation defines the maximum size, including unpacked size, for each upload feature | 3 | the ceilings table names each constant at its line, and the unpacked ceilings on the engine and the CLI are stated. |
| The documentation specifies how files are made safe for end-users to download and process | 4 | nosniff on every response, fixed attachment names, inline PDF, and Blob-only delivery of key artefacts. |
| The documentation specifies how the application behaves when a malicious file is detected | 5 | refusal, zeroing and classed recording on each surface. |
