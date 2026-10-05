# Operating the downpipe engine

This is the runbook for standing the engine up in your own Cloudflare account and taking it from a
fresh deploy to a working, scheduled backup. The engine runs entirely in your account; the vendor
never holds your data or a Cloudflare token, and your offline break-glass private key is never sent to
the engine. Recovery works offline from the destination bytes and that key alone, with neither
Cloudflare nor the vendor in the loop.

Most of this is guided by the console (the key ceremony, the exact wrangler commands, and a live
readiness check). This document is the written reference behind that flow.

## What "ready" means

`GET /admin/status` reports `ready: true` once three things are configured:

- `SIGNER_PRIVATE` (the signer secret) is present,
- `BREAK_GLASS_PUBLIC` (the recipient public key) is present,
- a destination resolves (an R2 binding, or the S3-compatible settings).

The licence and the update channel are optional and never gate a backup or a recovery. Until
`ready: true`, the engine accepts admin calls but will not run a backup.

## Coverage (what is and is not backed up)

downpipes covers the Cloudflare data and configuration layer and Workers code, not every part of
the compute layer. Know the scope before you depend on it for recovery.

- **Covered.** Workers KV, R2, Secrets Store, D1, and Cloudflare configuration across 313 zone and
  account surfaces, including DNS records, WAF and rulesets, page and firewall rules, Access /
  Zero-Trust, load balancers, Email Routing, Logpush, Turnstile, and account members and roles.
  The configuration surfaces also hold the settings of Queues, Vectorize indexes, Hyperdrive and
  Pages projects. Workers scripts (code, settings with bindings, cron triggers and a versions inventory) and
  Stream and Images (the inventory and metadata, with the media bytes as an option) are sources
  too, including the downpipes Workers themselves. The engine does not re-deploy a Worker from a
  backup: restore gives you the verified code and settings, and you re-deploy.
- **Not covered.** Durable Object storage, queue messages, Vectorize vectors and Pages deployment
  files. Do not assume them. Keep your Worker source in version control and your deploy
  reproducible.
- **Limits.** D1 is backed up as a resumable sequence of page records read from one D1 Sessions
  snapshot, and each page holds at most 96 MiB in memory. Restore replays the records into a
  fresh, empty target (a partial restore says so and asks you to drop and retry). A default
  cf-config *restore* writes back only the 60 surfaces whose writers passed a live round trip. The
  other surfaces are backed up and listed out of band with guidance for an operator to re-apply
  them. The engine never blind-writes them to production.

## Prerequisites

- A Cloudflare account with Workers PAID, Durable Objects, and R2 enabled. Activate
  Workers Paid BEFORE deploying: the deploy itself fails without it (the engine sets
  `[limits] cpu_ms`), and the free plan's 50-subrequest cap would break runs regardless.
- A custom domain for the engine (and one for the console). The engine is custom-domain only; the
  `workers.dev` route is disabled by policy.
- `wrangler` authenticated against the account (`npx wrangler whoami`).
- The console deployed (it serves the key ceremony and the readiness check).

Validate all of this before deploying rather than hoping: `downpipe preflight
--account <id> --domain <your-engine-fqdn>` lists the account's available domains,
verifies the chosen one is on an active zone, and reports Secrets Store headroom, the
Workers plan, Logpush and R2 (read-only, operator token). After deploying,
`GET /admin/preflight` (the console onboarding reads it) PROBES the runtime
prerequisites live, including that the cron genuinely ticks. The full entitlement
matrix, the large-environment (sliced runs) guide, SIEM log delivery and the support
model are in docs/SCALE-AND-ENTERPRISE.md.

## Step 1: deploy the engine

```
cd engine
# Always deploy with `npm run deploy`. It reconciles console-attached sources so a later
# deploy cannot silently drop them (see "How sources survive a deploy" below). On a FIRST
# deploy the Worker does not exist yet, so the reconcile deploys wrangler.toml as it is:
npm run deploy
```

This creates the `downpipe-engine` Worker, the `SCHEDULER` Durable Object (the schedule, run lock and
RUNLOG index authority), and the `*/15` reconciliation cron. The cron tick is the dispatch
driver for new runs (the scheduler alarm prunes expired records, re-arms, and runs the cron's alert
sweep when the cron goes silent; it does not dispatch runs), and an already-started large run continues on the seal DO's own alarm chain between ticks.

`npm run deploy` typechecks and validates the tree before it deploys. On an engine with no keys, it
then generates the keys on your machine and installs them as secrets. It writes the break-glass
private key (`identity.key`) and the recovery sheet to `./recovery-kit/`: move that folder offline.
If no first-Owner path is set, it then asks how you will claim the first Owner (Step 2).

Set the console origin so CORS is scoped to your console (already in `wrangler.toml` as a var; change
it to your console's custom domain):

```toml
[vars]
CONSOLE_ORIGIN = "https://<your-console-domain>"
```

## Step 2: the admin token (ONE-TIME bootstrap, then dispose of it)

Set an admin token. This is the lower-assurance break-glass path: anyone with the engine URL and the
token can administer the engine, and the token caller is not attributable in the audit log.

```
npx wrangler secret put ADMIN_TOKEN
```

Use a long random value and store it in your secrets manager.

`npm run deploy` offers this step when neither `ADMIN_TOKEN` nor `BOOTSTRAP_OWNER_EMAIL` is set. It
either generates the token and prints it once, or sets `BOOTSTRAP_OWNER_EMAIL`. From the console sign-in
page, the engine then emails a first-Owner set-up link to that address.

The admin token is for a ONE-TIME bootstrap of the FIRST Owner. Use it once to sign in and either register
your Owner passkey in the console or claim the first Owner via Cloudflare Access (Step 6). The first Owner is
claimed once and once only: the engine latches a `bootstrapConsumed` flag the moment the first Owner exists,
so the token can never mint a second Owner afterwards, even if the role table is later emptied.

When you complete your Owner passkey enrolment, the console shows you a set of RECOVERY CODES, ONCE. SAVE THEM
OFFLINE (a password manager, or printed and locked away). These are your ongoing admin break-glass, exactly
like the recovery codes any app gives you: if you ever lose your passkey, you use one to get back in. They are
shown only once and the engine stores only salted hashes of them, never the codes themselves, so there is no
way to see them again later (you regenerate a fresh set instead, which invalidates the old one).

Once your passkey works AND your recovery codes are saved, DISPOSE OF THE BOOTSTRAP TOKEN. Leaving it live
means anyone who ever sees the string can take admin. You have two equivalent ways to dispose of it:

- RETIRE it in-app: Security Centre > Retire break-glass token. This is immediate and needs NO redeploy: the
  engine stops honouring the `ADMIN_TOKEN` bearer the instant you retire it (it cannot delete its own Worker
  secret, because by design it holds no Cloudflare token that can change its own secrets, so the retire flag is how it stops
  honouring the string). With dual control on, the retire waits for a second Owner's approval. A retired
  token can never un-retire itself, and the engine has no route that re-enables it.
- Or delete the secret: `npx wrangler secret delete ADMIN_TOKEN` (equivalent; also removes the bearer).

The engine REFUSES to retire the token until a way back in is in place: you must have generated recovery codes
for an Owner OR have a SECOND Owner. This is so disposing of the token can never strand you with no path back
in. The Security Centre raises a high-severity `dispose-bootstrap-token` finding once a way back in exists and
the token is still live (it clears the moment you retire or delete it), and a `recovery-codes-low` finding when
your remaining codes run low. Setting `ADMIN_TOKEN_DISABLED` (see [ACCESS.md](ACCESS.md)) also refuses the
bearer.

The recovery path: if you lose your passkey, go to the sign-in screen and enter one of your recovery codes
(instead of using your passkey). That signs you back in with your normal role for a single use of that code;
then enrol a NEW passkey and regenerate your recovery codes (Security Centre > Regenerate recovery codes),
saving the fresh set offline. Recovery-code sign-ins are hard rate-limited and every attempt is audited, and a
successful use or repeated failures raise an alert, so misuse is loud.

Your BACKUPS remain offline-recoverable via the break-glass KEY regardless (Step 3), which is a DIFFERENT thing
from these recovery codes: the break-glass key opens your archived DATA offline, while recovery codes are only
for admin SIGN-IN. Disposing of the admin token never risks your backups.

Prefer Cloudflare Access (Step 6) or your Owner passkey for day-to-day administration.

## Step 3: the key ceremony (in the browser, nothing is sent)

The console key ceremony is the in-browser path to the same keys: use it on an engine that has no keys,
or to rotate keys. It generates, entirely in your browser:

- the break-glass key pair (X25519 + ML-KEM-1024). The PRIVATE half is the offline recovery key. It is
  downloaded to your machine and is NEVER transmitted to the engine or the vendor. Store it offline;
  consider an M-of-N split across custodians (the console explains the pattern).
- the signer key pair (Ed25519 + ML-DSA-87). The engine signs runs with the private half.
- optionally an operational recipient key pair, whose private half lets the engine do the UNATTENDED
  work on its own: scheduled restore tests, the automated drill, and in-account retention pruning.
  Omitting it is a deliberate higher-assurance posture, and the cost is narrower than it sounds.
  Verification at seal and the hourly canary still run in-account, because the seal path holds the run's
  own per-run key while it finalises. An in-console restore still works too, with the break-glass private
  supplied to the browser for that restore and wiped afterwards; the engine never receives it. What you
  give up is the work that needs a key at a moment when nobody is present to supply one, and retention
  then moves offline to the reader's prune command.
- the configuration recovery key pair and the configuration wrap key, in both postures. The recovery
  private opens only this engine's own sealed configuration export, so the engine can rebuild its
  settings after a Durable Object wipe; it cannot read an archive. The wrap key encrypts the credentials
  the console stores. An engine that already holds either key keeps it.

The console installs these to the engine with a one-shot Cloudflare token, with no terminal. It also
shows the exact `wrangler secret put` commands with the generated values, for an operator who prefers
to apply them out of band:

```
npx wrangler secret put SIGNER_PRIVATE            # base64url ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes
npx wrangler secret put BREAK_GLASS_PUBLIC         # base64url x25519(32) || ML-KEM-1024 ek(1568)
npx wrangler secret put OPERATIONAL_PUBLIC         # optional
npx wrangler secret put OPERATIONAL_PRIVATE        # optional, enables in-account drill and restore
npx wrangler secret put CONFIG_RECIPIENT_PRIVATE   # base64url x25519 scalar(32) || ML-KEM seed(64)
npx wrangler secret put CONFIG_RECIPIENT_PUBLIC    # base64url x25519(32) || ML-KEM-1024 ek(1568)
npx wrangler secret put CONFIG_WRAP_KEY            # base64url of 32 random bytes (AES-256)
```

The break-glass PRIVATE never goes to the engine; there is no engine binding and no console field for
it. An engine keyed before the ceremony made the configuration keys gains them from the Keys screen
("Add configuration keys"), which never touches the signer, the break-glass key or the operational key.

## Step 4: the destination (where archives land)

Choose one. The engine refuses an ambiguous configuration (both with no `DEST_KIND`, or neither) and
reports `destConfigured: false` rather than guessing.

R2 in your account (no credentials on the wire), in `wrangler.toml`:

```toml
[[r2_buckets]]
binding = "DEST_R2"
bucket_name = "<your-archive-bucket>"
```

Or an endpoint-addressed destination, via vars + secrets:

```toml
[vars]
DEST_KIND = "s3"
DEST_ENDPOINT = "https://<endpoint>"
DEST_BUCKET = "<bucket>"
DEST_REGION = "<region>"
```
```
npx wrangler secret put DEST_ACCESS_KEY_ID
npx wrangler secret put DEST_SECRET_ACCESS_KEY
```

`DEST_KIND` is a two-member wire selector (`r2` for the binding, `s3` for everything reached over
HTTP); it has no `gcs` or `azure` member. The engine picks the client from the endpoint host. It does
this for a destination set from the console (Destinations screen) and, from engine 0.3.7, for the
`DEST_*` vars:

| Endpoint | Client | Credential pair |
| --- | --- | --- |
| `https://s3.<region>.amazonaws.com` and other S3-compatible stores | S3 (SigV4) | access key id + secret |
| `https://storage.googleapis.com` (Google Cloud Storage) | S3 (SigV4), over its S3-interoperable API | HMAC key pair for the service account |
| `https://<account>.blob.core.windows.net` (Azure Blob) | Azure Blob, with its own Shared Key signer | storage account name + account key, or a shared access signature |

For an Azure Blob endpoint in the `DEST_*` vars, `DEST_ACCESS_KEY_ID` is the storage account name
and `DEST_SECRET_ACCESS_KEY` is an account key or a shared access signature. If `DEST_ACCESS_KEY_ID`
is empty, the engine uses the account in the endpoint host. `DEST_REGION` is not necessary. The engine
ignores `DEST_ADDRESSING` and `DEST_STORAGE_CLASS` for Azure Blob. A Microsoft Entra service principal
is available only for a destination set from the console.

The engine refuses an Azure Data Lake Storage Gen2 `dfs` endpoint by name: it is a different wire
protocol from Azure Blob. The console refuses it when you save the destination. From engine 0.3.7 the
engine also refuses it in `DEST_ENDPOINT`, when it builds the destination, with the build cause
`endpoint-unusable`. Point the destination at the same storage account's `blob` endpoint instead.

Redeploy after editing `wrangler.toml` with `npm run deploy` (it preserves console-attached
source bindings; see "How sources survive a deploy" below, since a bare `wrangler deploy` would drop them).

### Encrypting console-set destination credentials at rest (recommended)

A destination you set from the console (rather than via the `DEST_*` secrets above) is stored in the
scheduler Durable Object. Without `CONFIG_WRAP_KEY`, its secret access key sits there as a plaintext
field, protected only by Cloudflare's own at-rest encryption (the "plaintext floor"). `npm run deploy`
and the console key ceremony both install `CONFIG_WRAP_KEY`. It envelope-encrypts that credential with
AES-256-GCM under a key held as a Worker secret, so a read of Durable Object storage alone does not
disclose it and its confidentiality roots in the same store as the signer key. To set it by hand,
generate a 32-byte key:

```
node -e "console.log(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'))"
npx wrangler secret put CONFIG_WRAP_KEY
```

It is optional: without it, the credential stays a plaintext field and the Security Centre raises a
recommendation. When the console installs the key (the key ceremony, or the Keys screen's "Add
configuration keys" card on an engine keyed without it), the engine seals every console-set credential
it already holds as plaintext in the same step: the discovery token, destination credentials, SIEM and
OTLP push secrets, JSM and ServiceNow channel keys and IdP client secrets. The install reports the
counts, and when it found any credential it writes one `config-secrets-rewrapped` audit entry. A key set
by hand with `wrangler secret put` does not run that step, so re-save each console-set credential once to
seal it. A plaintext credential keeps working until it is sealed. The Security Centre's "Destination
credentials encrypted at rest" check turns green when the key is set and no plaintext destination
credential remains.

## Step 5: source bindings and the first downpipe

A binding **source** is a Workers binding (KV namespace, R2 bucket, D1 database, or Secrets Store
secret). The account-wide sources (Cloudflare configuration, Workers scripts, Stream and Images) read
the Cloudflare API with the read-only discovery token and need no binding. **Attach sources from
the console** (Sources screen), no terminal needed: the engine adds the binding to its own live worker via the Cloudflare API and proves the change drops nothing
(`src/admin/attach.ts`). Then create a downpipe (source binding, schedule, enabled). The first
scheduled run (or a manual trigger) seals the source to the destination. Confirm `ready: true`, then
watch the run land in the run history.

### How sources survive a deploy (important)

`wrangler deploy` is destructive to bindings: it REPLACES the worker's binding set with **exactly**
what `wrangler.toml` lists. Console-attached sources live on the worker, **not** in `wrangler.toml`,
so a plain deploy from a tree that lacks them would silently drop them, and each dropped source's
next run fails with `source binding error`. To prevent that:

- **Always deploy with `npm run deploy`.** It runs `scripts/sync-bindings.mjs` first, which reads the
  live worker's bindings and writes `wrangler.deploy.toml = wrangler.toml + the live sources`, then
  deploys that superset. A code deploy cannot drop a source. The reconcile **refuses** (and
  stops the deploy) if it cannot read the live bindings, rather than ship a binding-dropping config.
- It reads the live bindings with `CLOUDFLARE_API_TOKEN` (the "Edit Cloudflare Workers" template) and
  `CLOUDFLARE_ACCOUNT_ID` when both are set, and through your `wrangler login` session when they are
  not. A **first deploy** needs no override: the Worker does not exist yet, so there is nothing to
  preserve. `DOWNPIPE_ALLOW_BINDING_RESET=1 npm run deploy` acts only when the live bindings cannot
  be read: it then deploys `wrangler.toml` as it is, and any attached source not in it is dropped.
- You can run the check on its own at any time: `npm run sync-bindings`.
- **Do not** run a bare `wrangler deploy` from a working tree unless you have run the reconcile and
  pass `-c wrangler.deploy.toml`; a bare deploy ships only the sources hand-listed in `wrangler.toml`.

Advanced / IaC: you may still declare sources directly in `wrangler.toml`; the reconcile keeps them
and simply adds any console-attached ones on top.

### If a source goes missing

The Sources screen shows any configured source whose binding is no longer present as **"not
attached"** (a red badge, under "Needs attention"), and the preflight **"Source bindings"** check
fails and names it. The cause is a deploy that dropped the binding, or a deleted resource. Recover by
**Re-attach** on the Sources screen (the engine re-adds the binding to itself with a scoped token and
verifies it survives), then redeploy with `npm run deploy` so the next deploy preserves it too.

## Step 6: Cloudflare Access (the green verified verdict and per-email roles)

See [ACCESS.md](ACCESS.md) for the full identity-and-access guide: provider setup (EntraID, Okta, GitHub), group-to-role mapping, and the optional `ADMIN_TOKEN_DISABLED` hardening.

Wire a Cloudflare Access application in front of the engine and the console domains, then tell the
engine which Access policy to trust:

```toml
[vars]
CF_ACCESS_TEAM_DOMAIN = "<your-team>.cloudflareaccess.com"
CF_ACCESS_AUD = "<the Access application AUD tag>"
```

With Access wired, the engine verifies each caller's identity and the console shows the green
"Access verified as <email>" verdict instead of the amber shared-token verdict. Roles are then keyed
by the verified email and enforced server-side: the first authenticated caller bootstraps as Owner;
thereafter roles are administered from the console. Without Access, roles key on the identity the
engine verifies at a passkey or identity-provider sign-in. Only a caller that presents the
`ADMIN_TOKEN` bearer runs as the unattributed token-fallback Owner (the amber verdict).

## Optional: the update channel and the assurance licence

Neither gates the data or recovery path. The shipped `wrangler.toml` turns the in-account update
check on. It sets both vars to the vendor channel:

```toml
[vars]
UPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"
UPDATE_SIGNER_PUBLIC = "<the pinned vendor release-signer public key>"
```

The engine refuses a channel URL on any host other than `update.downpipes.io`. Remove both vars to
turn the check off.

Activate the assurance licence from the console (Licence and updates > Activate licence). The
engine verifies the token against the vendor licence-signer key built into the engine and stores
it. A `LICENCE_TOKEN` var also works as a deploy-time fallback, and a console-activated token wins
over it. Absent or unverifiable, the engine fails open to the community tier.

What lapses when the licence does, exactly:

| Surface | Licensed (Enterprise) | Lapsed or never licensed |
| --- | --- | --- |
| Backups, schedules, sliced runs | run | run, unchanged |
| Restores, drills, the offline CLI | work | work, unchanged, forever |
| The console and every screen | full | full, unchanged |
| Governance (RBAC, dual control, audit, SIEM feed) | on | on, unchanged |
| Engine status / reports | report tier Enterprise | report tier community |
| Vendor support entitlement | per your agreement | community channels |
| The signed update channel | recommended versions | unchanged (it is pinned to the vendor key, not the licence) |

A backup and DR product must never hold recovery hostage to a subscription: the licence is
an assurance and support entitlement, not a key. Nothing above is marketing; the engine
enforces none of its data paths against the licence, and the offline CLI never reads one.

## Optional: release provenance for the console provenance card (DEF-04)

`GET /admin/status` can surface two public, non-secret build descriptors so the console
can display the running artefact hash and the declared release-signer pin:

- `ARTEFACT_SHA384`: the SHA-384 digest of the deployed artefact (e.g. `sha384:...`),
  set out of band at deploy time from the published release checksum.
- `RELEASE_SIGNER_PIN`: the `edmldsa1:` fingerprint you expect the update signer to have,
  set from the published release metadata. It is a declared value. The engine does not
  verify updates with it.

Set them as plain vars (they are not secrets):

```toml
[vars]
ARTEFACT_SHA384 = "sha384:<hex>"
RELEASE_SIGNER_PIN = "edmldsa1:<hex>"
```

`releaseSignerPin` is absent from `GET /admin/status` when `RELEASE_SIGNER_PIN` is unset.

The engine verifies update-channel signatures with `UPDATE_SIGNER_PUBLIC`. `GET /admin/status`
reports the fingerprint of that key as `updateSignerFingerprint`: `edmldsa1:` followed by the
SHA-384 (hex) of the Ed25519 and ML-DSA-87 public key bytes, the same form as the signer
fingerprint on a recovery sheet. It is absent when `UPDATE_SIGNER_PUBLIC` is unset or does not
parse. The same response compares your declared pin with it:

- `releaseSignerPinDeclared`: `true` when `RELEASE_SIGNER_PIN` is set.
- `releaseSignerPinMatches`: present only when a pin is declared. It is `true` when the pin,
  trimmed and compared without regard to case, equals `updateSignerFingerprint`. A short label,
  a partial fingerprint or a pin with no valid `UPDATE_SIGNER_PUBLIC` reads `false`.
- `releaseSignerPinWarning`: present when the pin does not match. It reads "RELEASE_SIGNER_PIN
  is only a label. The engine verifies updates with key `<fingerprint>`. Set RELEASE_SIGNER_PIN
  to that value, or clear it." With no valid `UPDATE_SIGNER_PUBLIC`, it says so and asks you to
  set that key or clear the pin.

When a pin is declared, the Security Centre also grades the `release-signer-pin` check
(medium). It passes when the pin matches and fails with the same sentence when it does not.
With no pin declared, the check is not raised. The support pack carries the same status
fields, and `keys.updateSigner` gives `configured`, `signerFingerprint` and `malformed`.
`artefactSha384Source` says where `artefactSha384` came from, in this order:

- `operator`: your `ARTEFACT_SHA384` value, reported as you set it.
- `deployed`: the SHA-384 of the main module bytes the last upload sent. `npm run deploy`
  builds the bundle once into `.wrangler/deploy-bundle/`, hashes `index.js`, uploads that
  same file with `wrangler deploy --no-bundle`, and records the hash as the plain-text
  binding `DEPLOYED_ARTEFACT_SHA384`. An update-channel apply records the hash of the bytes
  it uploads the same way. To check it after `npm run deploy`, run
  `shasum -a 384 .wrangler/deploy-bundle/index.js` and compare.
- `build-stamp`: a digest written into `src/format/build-stamp.ts` by
  `scripts/stamp-build-id.mjs`. It is the hash of the bundle built with the committed
  placeholder, not of the stamped bytes that build serves. `npm run deploy` does not stamp.

Both fields are absent when no source gives a value. The engine does not verify them; they
are documentation the operator cross-checks against the published release. An empty value
after trimming is treated as unset.

## Verifying and operating

- `GET /admin/health` is open and returns `200` when the Worker is up.
- `GET /admin/status` (admin-authenticated) reports the presence booleans and `ready`. It never
  returns a secret, a secret-key fingerprint, a destination detail, or a downpipe name. It returns
  `updateSignerFingerprint`, the public fingerprint of the pinned update signer. When
  `RELEASE_SIGNER_PIN` is set, and when an artefact hash is known (see above), they appear in
  the response so the console can show the running artefact hash and the declared pin with its
  match verdict.
- `GET /admin/whoami` reports the verified identity and resolved role.
- The console drives downpipe management, the restore flow (dry run, dual-control request and approve,
  apply), drills, the audit log, and the cost calculator.

## Recovery (offline, no engine and no vendor)

If the engine or the account is gone, recover directly from the destination bytes with the open-source
`downpipe` CLI and your break-glass private key. The console Keys screen shows the exact commands
(`downpipe inspect` / `verify` / `restore --check-bundle`). The recovery bundle written alongside each
run carries the current signer's public key (`signer.pub`), the recovery instructions and a pointer to
the versioned format documentation.

## Upgrades and rollback

You perform every upgrade yourself, in your account, with your own credentials; the vendor
cannot deploy, modify or read your deployment. The update channel (above) only tells the
engine a newer version exists; nothing applies itself.

The runbook for a normal upgrade:

1. Read the release notes for every version between yours and the target. A release
   marked as a REQUIRED stop cannot be skipped; step through it.
2. Preflight first: `GET /admin/preflight` must be green (the console Readiness card
   shows the same facts), and `downpipe preflight --account <id>` covers the account
   side. Do not upgrade over a red preflight; you will not be able to tell whether the
   upgrade caused the breakage.
3. Export your evidence before any major upgrade: the support bundle, the audit log
   (JSON, with the head hash) and the config history. These are small, redaction-safe,
   and make "restore the pre-upgrade state" a real remediation.
4. Apply: pull the release into your deployment pipeline (verify the artefact digests
   against the published checksums first) and `npm run deploy` (engine, then console).
   `npm run deploy` runs the source-binding reconcile so an upgrade cannot drop a
   console-attached source; a bare `wrangler deploy` would. For a cautious rollout,
   `npx wrangler versions upload -c wrangler.deploy.toml` (after `npm run sync-bindings`,
   so the preview carries the live sources) gives a zero-traffic preview to smoke first;
   note that a release containing a Durable Object migration cannot use the gradual path
   (the platform applies migrations atomically via a full deploy).
5. Verify after (five minutes, then an hour): `/admin/health` is 200, `/admin/status`
   reports the new engineVersion and ready, the audit log carries the
   engine-version-change event (the upgrade is in the tamper-evident trail), the next
   cron tick lands (`lastTickAt` advances; the preflight cron item stays verified), and
   the next scheduled restore test passes.

Rolling back: redeploying the previous release (or `wrangler rollback`) is safe between
releases that share a schema epoch (the release notes say when an epoch changes; epoch
bumps are rare and always land on a required stop). Know the platform's real limits
before you rely on it: a rollback never touches STATE (Durable Object storage, KV, R2,
D1 keep whatever the newer release wrote), it is refused across a Durable Object
migration, and it reaches at most the recent versions Cloudflare retains. Across an
epoch, the path is the pre-upgrade evidence from step 3 plus the release notes, not a
blind redeploy. Secrets survive deploys and rollbacks; plain-text vars in wrangler.toml
are overwritten by whatever the deployed config says, so keep secrets in secrets.

The archives on the destination are never part of an engine upgrade or rollback: they
are an open, versioned format the offline CLI reads regardless of what the engine is
running, and the engine never starts writing a newer format version implicitly.

## Offboarding and exit (decommission cleanly, keep your archives)

Leaving is deliberately boring; this is the no-custody exit working as designed. The
order matters:

1. Run a final backup of anything you still want captured, and wait for it to complete
   (the Runs screen shows it ok).
2. Prove recoverability one last time: run a drill, or `downpipe verify` against the
   destination from a clean machine with your break-glass key.
3. Export the evidence you may need later: the audit log (JSON, head hash included),
   the config history, and a support bundle (versions + provenance snapshot).
4. Revoke the vendor-facing surfaces: revoke any support ingest credentials (Settings >
   Support), and let the licence lapse or remove LICENCE_TOKEN (nothing operational
   changes; see the licensing table in the docs).
5. Disable the schedules (pause every downpipe) so nothing writes after your final run.
6. Delete the two Workers (engine and console) and their secrets from your account.
   This removes all compute; nothing the vendor holds needs cancelling beyond the
   licence subscription itself.
7. KEEP: the destination bucket (your archives), the `downpipe` CLI binary, the printed
   recovery sheet, the break-glass private key, and `signer.pub` from your recovery kit.
   Keep every `signer.pub` you have had, including the old one after a re-key. A re-key
   first verifies each destination's `_RECOVERY/RUNLOG` under the old signer. If one does
   not verify, the re-key stops before any key changes and names that destination.
   Otherwise the engine signs the same RUNLOG bytes under the new signer. Runs sealed
   before the re-key keep their old root signatures, so verify them with the old
   `signer.pub`. From
   engine 0.3.7 the recovery bundle in the bucket also carries the current signer's
   `signer.pub`, and reader 0.3.4 pins it with the signer fingerprint on the sheet. Every
   run overwrites that copy, so it covers a run only while the signer that sealed it is
   still current. Those things are a complete, vendor-independent recovery capability
   for as long as you retain them. The bucket holds a versioned format pointer and the
   recovery instructions next to the data (`_RECOVERY/`), and the CLI verifies and
   restores offline with no engine, no licence and no vendor.

If the exit is a migration (new provider, org consolidation), copy the bucket like any
object store data; the archives are portable bytes and the CLI reads them wherever they
sit. If the exit must prove deletion instead, empty and delete the bucket AFTER step 3's
exports, and record the final audit export (with its head hash) as the closing evidence.

## Design rules for operators

- Custom domains only, never `workers.dev`.
- The break-glass private key is yours alone: store it offline, never paste it anywhere, and retain old
  keys after a rotation (archives sealed before a rotation need the old key).
- Treat `ADMIN_TOKEN` as a ONE-TIME bootstrap credential: once your Owner passkey or Cloudflare Access
  works AND you have saved your recovery codes offline, retire it in-app (Security Centre > Retire break-glass
  token, immediate, no redeploy) or delete the secret. The engine refuses to retire it until a way back in
  exists (recovery codes for an Owner, or a second Owner). Leaving it live lets anyone with the string take
  admin. Prefer Cloudflare Access or a passkey for attributable administration.
- Save your RECOVERY CODES offline when you enrol your passkey (shown once). They are your ongoing admin
  break-glass: if you lose your passkey, enter a code at the sign-in screen to get back in, then enrol a new
  passkey and regenerate your codes. They are distinct from the break-glass KEY, which is for offline DATA
  recovery, not admin sign-in.
