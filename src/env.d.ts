// The typed environment bindings the engine expects. The customer fills these in at
// onboarding (wrangler.toml + the account Secrets Store). Source/destination bindings
// are added per downpipe; only public recipient keys and the signer are read from the
// Secrets Store, never customer data off-account.

export interface Env {
  // The scheduler Durable Object (the authority plane).
  SCHEDULER: DurableObjectNamespace;

  // The per-downpipe seal Durable Object (design F11): a run too large for one
  // invocation's subrequest/CPU budget continues here as alarm-chained slices, each on a
  // fresh per-invocation budget, until it finalises. Small runs complete inline in the
  // cron invocation and never touch it.
  RUNSEAL: DurableObjectNamespace;

  // RATELIMIT_DO is the OPTIONAL account-global CF API rate-limit Durable Object (the shared token bucket
  // DistributedPacer fronts). When bound, accountPacer (src/cf-pace.ts) routes every CF account-API crawl
  // through one shared bucket so concurrent crawls are paced in aggregate, not just per-isolate; when
  // absent it falls back to the per-isolate CfPacer (CF_API_RATE_PER_SEC), so the binding is purely
  // additive. The platform currently uses the per-isolate fallback; the binding is drafted in
  // wrangler.toml/wrangler.demo.toml (migration v3). See src/sched/ratelimit-do.ts.
  RATELIMIT_DO?: DurableObjectNamespace;

  // Sliced-run knobs (all optional; the defaults suit the platform limits). Subrequests
  // per slice (default 700 of the 1000 cap, leaving headroom for the scheduler
  // round-trips and finalisation), wall-clock per slice in ms (default 20000), records
  // per manifest shard (default 5000), and the per-segment plaintext target in bytes
  // (default and maximum the SPEC 14.5 ceiling, 1 GiB; lower it only for testing).
  SCALE_SLICE_SUBREQUESTS?: string;
  SCALE_SLICE_WALL_MS?: string;
  SCALE_SHARD_MAX_RECORDS?: string;
  SCALE_SEGMENT_TARGET_BYTES?: string;
  // CPU_MS is an OPTIONAL operator mirror of the deployed `[limits] cpu_ms` from wrangler.toml (the Worker
  // cannot read its own platform CPU limit at runtime). It is surfaced verbatim in the support pack's infra
  // block ONLY to let a diagnoser cross-check the resolved slice WALL budget against it (INFRA
  // cpu-ms-misconfigured-low): a slice wall budget set at or near cpu_ms leaves no headroom and an
  // uncatchable CPU kill wedges the slice. Absent = not mirrored (the pack omits it); a non-numeric value
  // is dropped. Never a secret, just an integer millisecond bound.
  CPU_MS?: string;
  // Fan-out (Fix 2b) knobs, all optional and FAIL-SAFE OFF. SCALE_FANOUT_RANGES is the maximum number of
  // parallel WORKER ranges a high-cardinality KV run splits into; it DEFAULTS TO 1 (no fan-out, the serial
  // path), so fan-out is opt-in and a typo can only fall back to serial, never break a backup. Set it to e.g.
  // 16 (max 256) to turn fan-out on. SCALE_FANOUT_MIN_RECORDS is the estimated-record threshold below which a
  // run stays serial (small runs do not pay the merge overhead); it defaults high. Only KV is fanned out
  // today (R2 is a documented stretch); D1/secrets/API sources always stay serial.
  SCALE_FANOUT_RANGES?: string;
  SCALE_FANOUT_MIN_RECORDS?: string;
  // SCALE_FANOUT_SAMPLE_CAP (Fix 2b H2) is the DIRECT-PLAN threshold: a run whose whole keyspace fits this
  // cheap front sample is planned inline; a larger run is handed to the coordinator's SLICED, keys-only
  // count-then-stride scan, which sizes BALANCED ranges over the real keyspace (so the parallelism is
  // actually delivered, not skewed to the sampled front). Defaults to FANOUT_SAMPLE_CAP (10000).
  SCALE_FANOUT_SAMPLE_CAP?: string;
  // CF_API_RATE_PER_SEC paces calls to the Cloudflare ACCOUNT API (cf-config, workers, discovery) below
  // the global ~1200 req/5min account limit (see src/cf-pace.ts). A positive number of requests/second;
  // absent/invalid falls back to a conservative default. Lower it if the account is shared with other
  // heavy tooling (Terraform, CI); it never needs raising above the account ceiling.
  CF_API_RATE_PER_SEC?: string;
  // RESTORE_TEST_MAX_PER_TICK caps how many scheduled restore-test drills the cron runs in ONE tick, so a
  // large fleet does not dispatch every due drill at once (a thundering herd competing with backups for the
  // shared subrequest budget). A positive integer; absent/invalid falls back to a small default. Tests not
  // run this tick stay due and are picked up next tick (a passed test drops out of "due", so the cap rotates
  // fairly).
  RESTORE_TEST_MAX_PER_TICK?: string;

  // ORPHAN_RECONCILE gates the orphan-reconcile DRY-RUN INVENTORY cron pass (scale-rearch P2e,
  // cron/reconcile-pass.ts). DEFAULT OFF: the pass is a no-op unless this is set to an affirmative
  // value ("1"/"true"/"on"/"yes", case-insensitive), so deploying the code changes nothing - no extra
  // reads, no log lines - until an operator opts in. When on, it EMITS a per-class inventory of the
  // run-trees physically present but absent from each bucket's signed RUNLOG (orphaned-but-recoverable
  // bytes); it DELETES NOTHING and SALVAGES NOTHING (enforced GC + salvage ride the sharded-RUNLOG
  // keystone). Rollback = unset this flag.
  ORPHAN_RECONCILE?: string;
  // ORPHAN_RECONCILE_GRACE_HOURS is the grace window: an orphan younger than this (by its own ULID /
  // signed createdAt time) is "within-grace" and left alone - it may be a finalise still in flight. A
  // positive number; absent/invalid falls back to the 48h default (which exceeds the max park horizon).
  ORPHAN_RECONCILE_GRACE_HOURS?: string;
  // ORPHAN_RECONCILE_MAX_FRACTION is the mass-orphan CIRCUIT-BREAKER threshold: above this fraction of
  // physical trees being orphans, the pass ABSTAINS (an implausible fraction signals a wrong-source read
  // of the committed set, where live committed runs would masquerade as orphans). Default 0.5.
  ORPHAN_RECONCILE_MAX_FRACTION?: string;
  // ORPHAN_RECONCILE_MAX_CLASSIFY bounds the per-pass attest READ load: at most this many orphans are
  // classified per tick, the rest deferred to the next tick. A positive integer; default 32.
  ORPHAN_RECONCILE_MAX_CLASSIFY?: string;

  // DRILL_EVIDENCE_CAP is the retention cap on the (non-chained) drill-evidence log the scheduler DO
  // holds (ENG-SCALE-06): once the row count exceeds it, the DO rolls over the oldest rows first, the
  // same bounding AUDIT_CAP gives the audit chain. It is enforced INSIDE the DO, which today holds no
  // env reference, so the live value is the module constant DRILL_EVIDENCE_CAP in scheduler-do.ts
  // (the same arrangement as AUDIT_CAP / RING_CAP); this declaration documents the intended override
  // knob for the day the DO is constructed with an env. The default (500) suits years of drills.
  DRILL_EVIDENCE_CAP?: string;

  // Verify-at-seal (finding ENG-RST-01). After a run seals successfully, the engine reads the
  // just-written archive BACK from the destination and verifies it (keyless Tier-0 chain
  // attestation always; a keyed decrypt sample additionally whenever the run's master can be reached,
  // by the in-account operational read-back key OR by the per-run master the seal path hands in),
  // so a corrupt/partial backup is caught at seal time rather than at the next periodic
  // drill. It is FAIL-OPEN (a failure flags the run suspect + alerts, but never deletes, blocks or
  // fails the run) and it READS from the customer's metered destination, so it is bounded:
  //  - VERIFY_AT_SEAL gates the whole feature and DEFAULTS ON (only an explicit falsey value,
  //    "0"/"false"/"no"/"off", disables it; absence => enabled), mirroring the SLICED_RUNS_DISABLED
  //    / DEMO_MODE truthy-string idiom in reverse.
  //  - SEAL_VERIFY_SAMPLE is how many records the decrypt sample reads + hash-checks (default 3,
  //    bounded). 0 turns the decrypt sample off (Tier-0 only). The sample needs a way to reach the run
  //    master, and EITHER source will do: the in-account OPERATIONAL_PRIVATE read-back key, or the
  //    per-run master handed in by the seal path that just finalised this run. A BREAK-GLASS-ONLY
  //    downpipe therefore does reach the keyed decrypt tier, which it never could before; only a run
  //    with neither source falls back to an honest Tier-0 verdict (tier0Cause "break-glass"). See the
  //    `canDecrypt` gate in src/seal/verify-at-seal.ts. When the operational key IS present the run is
  //    still opened through the CAPSULE, so the recipient-wrap decapsulation stays exercised on every
  //    run; the per-run master is the fallback, never the preferred path.
  //  - SEAL_VERIFY_MAX_BYTES is the run plaintext-size threshold above which only Tier-0 runs (the
  //    decrypt sample is skipped) so a very large run cannot become an unbounded re-read (default 5 GiB).
  //  - SEAL_VERIFY_FULL_BYTES is the run plaintext-size threshold AT OR BELOW which the decrypt step
  //    covers EVERY record (full coverage, tier "full") rather than a strided sample, so a flipped byte
  //    in any record of a small run is caught at seal time (default 64 MiB; 0 disables full coverage).
  //    The max-bytes Tier-0 cutoff is applied first, so SEAL_VERIFY_FULL_BYTES only matters below it.
  //  - SEAL_VERIFY_ATTEMPTS is the total number of whole read-back verification attempts (default 3,
  //    clamped to 8). The R2 S3-compat endpoint is read-after-write inconsistent under load, so a verify
  //    run milliseconds after the write can briefly read a just-written object as a 404 / stale and flag
  //    a recoverable archive "suspect". A bounded jittered re-read clears a consistency LAG while a real
  //    CORRUPTION still surfaces as a suspect after the final attempt (never weakens tamper detection).
  //    0 or 1 = today's single-read, no-retry behaviour (the exact rollback).
  //  - SEAL_VERIFY_FULL_SHARDS is the shard-count threshold AT OR BELOW which the Tier-0 keyless
  //    completeness re-read reads back EVERY shard (full, today's exact verdict); ABOVE it only a strided
  //    SEAL_VERIFY_SHARD_SAMPLE of shards is re-read (default 900, clamped 5000), so a very large run's
  //    at-seal verify cannot trip the subrequest cap. The root signature still authenticates the whole
  //    shard listing; the offline CLI and the periodic drill always re-read every shard (Fix-A).
  //  - SEAL_VERIFY_SHARD_SAMPLE is how many shards the bounded re-read samples above that threshold
  //    (default 64, clamped 256); 0 reads none (signature-only completeness above the threshold).
  // See src/seal/verify-at-seal.ts.
  VERIFY_AT_SEAL?: string;
  SEAL_VERIFY_SAMPLE?: string;
  SEAL_VERIFY_MAX_BYTES?: string;
  SEAL_VERIFY_FULL_BYTES?: string;
  SEAL_VERIFY_ATTEMPTS?: string;
  SEAL_VERIFY_FULL_SHARDS?: string;
  SEAL_VERIFY_SHARD_SAMPLE?: string;
  // SEAL_VERIFY_DECRYPT_MAX_SHARDS caps the shard count at which the KEYED decrypt tier runs at all. Tier-0
  // walks the shard list and the decrypt tier's openRun walks it again with no sampling of its own, so both
  // running costs roughly twice the shard count in subrequests before a record is read. Above this ceiling
  // the verdict is honestly Tier-0 (tier0Cause "too-many-shards") rather than a cap trip reported as a
  // SUSPECT archive. Absent/invalid falls back to a conservative default well under the platform cap.
  SEAL_VERIFY_DECRYPT_MAX_SHARDS?: string;

  // REPL_VERIFY_SEGMENTS gates the 3-2-1 replication pass's KEYLESS, STRUCTURAL check of the just-copied
  // seg/ bytes on each replica (Finding 6): after a run's data segments are mirrored, a bounded sample of
  // the newly-copied objects is read BACK from the replica and unframed (container.ts), so a truncated,
  // empty or wrong-object copy fails the mirror (the run is never recorded held) instead of sitting as a
  // silently non-restorable copy. It DEFAULTS ON: only an explicit falsey value ("0"/"false"/"no"/"off")
  // disables it (the deliberate cost opt-out), so a deployment that sets nothing verifies every replica's
  // segment bytes rather than copying them blind (M5(a)), mirroring the VERIFY_AT_SEAL idiom. It catches
  // container framing only, NOT cryptographic plaintext integrity (the content-address is a keyed HMAC over
  // the plaintext and replication holds no operational key); per-segment cryptographic verification stays
  // the keyed restore drill's job. See src/seal/replicate.ts.
  REPL_VERIFY_SEGMENTS?: string;

  // RESTORE_BUFFERED_MAX_BYTES is the largest plaintext an in-account R2 restore may BUFFER (the
  // strongest path: the verified in-memory bytes are the bytes written by an atomic put). An R2 record
  // larger than this STREAMS (constant memory) and is proven by a post-write readback re-hash instead,
  // so capability is unchanged either way; this knob only chooses WHICH path runs. It DEFAULTS to 32 MiB.
  // A supplied value must be a POSITIVE INTEGER and is honoured up to a 32 MiB CEILING: the override
  // exists to LOWER the ceiling (e.g. to exercise the streaming + readback path on a small object under
  // test), never to raise it past 32 MiB (the buffered path concats per-segment plaintext, a ~2x
  // transient peak, so a higher ceiling risks OOMing the 128 MB isolate). An absent, non-integer,
  // non-positive, or over-ceiling value falls back to the 32 MiB default. See src/admin/restore.ts.
  RESTORE_BUFFERED_MAX_BYTES?: string;

  // SLICED_RUNS_DISABLED ("1"/"true"/"yes"/"on") reverts to the v1 whole-run buffered
  // seal. That keeps the hard per-invocation size ceiling (a namespace past roughly a
  // thousand records cannot complete) but never persists a wrapped run master in Durable
  // Object storage: the documented trade-off for break-glass-only postures that prefer
  // the ceiling over the at-rest (encrypted) master during long runs. See
  // docs/OPERATIONS.md "Large environments".
  SLICED_RUNS_DISABLED?: string;

  // CHAOS_SOURCE_FAULT (chaos builds ONLY, via wrangler.chaos.toml --var) arms an in-engine source-fault
  // injector (sources/chaos-fault.ts): a JSON spec {source,fault,at,path?} that wraps the matching source's
  // Cloudflare-API fetch / KV binding to inject a read-boundary fault. UNSET => fail-safe no-op, byte-identical
  // to production (the injector returns the real fetch/binding untouched). Never set on a production config.
  CHAOS_SOURCE_FAULT?: string;

  // BEACON_URL + BEACON_INGEST_KEY opt the engine into the no-custody vendor beacon (cron/beacon-emit.ts).
  // OFF by default: with EITHER unset the engine never phones home. When BOTH are set, the engine POSTs a
  // content-free aggregate beacon (downpipe-beacon-v1: counts + engine version + CF deploy id; nothing
  // per-downpipe) to `${BEACON_URL}/beacon` with the bearer, so the control-plane per-account deploy ledger
  // can record a deploy on a cfVersionId change. Advisory + fail-open; never on a backup/restore path.
  BEACON_URL?: string;
  BEACON_INGEST_KEY?: string;

  // VENDOR_SUPPORT_PUBLIC is the vendor support team's hybrid public key (the same
  // b64url x25519(32) || ML-KEM-1024 ek(1568) layout as a recipient key). When set, the
  // support bundle (GET /admin/support/bundle and the credentialed pull) is SEALED to
  // this key so diagnostics stay confidential through whatever ticket system carries
  // them; absent, the bundle is signed-plain (it is redaction-safe either way). It is a
  // PUBLIC key: setting it grants no access to anything in the account.
  VENDOR_SUPPORT_PUBLIC?: string;

  // Admin auth: Cloudflare Access (verified) is the documented default; set the team
  // domain and the Access application AUD tag to enable it. ADMIN_TOKEN is the
  // lower-assurance fallback bearer token (design F3).
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  ADMIN_TOKEN?: string;

  // ADMIN_TOKEN_DISABLED, when set to a truthy string ("1"/"true"/"yes"/"on"), hardens the gate so
  // ONLY a verified Cloudflare Access JWT is accepted and the ADMIN_TOKEN bearer fallback is refused
  // even if ADMIN_TOKEN is configured (P9). An Enterprise tenant that has stood up Access can set this
  // to remove the shared-token path entirely. Absent or falsey leaves the current behaviour: Access
  // when configured, otherwise the token fallback. See src/admin/auth.ts. Status reflects it as
  // tokenFallbackDisabled so the console can show the hardened posture.
  ADMIN_TOKEN_DISABLED?: string;

  // SCIM_BEARER_TOKEN is the DEDICATED bearer secret that authenticates the minimal SCIM 2.0
  // deprovision surface (/scim/v2/Users, src/admin/scim.ts). It is SEPARATE from ADMIN_TOKEN on
  // purpose: an identity provider's SCIM connector holds only a leaver-offboarding credential, never
  // the owner break-glass. When it is UNSET the SCIM surface is OFF and every /scim/v2 request returns
  // 503 (fail closed, no functionality without an explicit secret); when set, the presented bearer is
  // compared against it in constant time over the SHA-384 of each side (no length leak). The surface is
  // deprovision-only: it drives the existing audited offboarding (role removal + session termination),
  // never provisioning or any other write. See src/admin/scim.ts.
  SCIM_BEARER_TOKEN?: string;

  // DEMO_MODE, when set to a truthy string ("1"/"true"/"yes"/"on"), enables the demo-only reset
  // surface (POST /admin/demo/reset), which wipes the scheduler Durable Object back to first-run so
  // a throwaway demo deployment can be reset and re-walked repeatedly. It is a destructive
  // capability, so it is hard-gated: when DEMO_MODE is absent/falsey the route 404s before any auth,
  // so a production deployment has no reset surface at all. When set, only the ADMIN_TOKEN
  // break-glass bearer may invoke it. See src/admin/router.ts.
  DEMO_MODE?: string;

  // Optional release provenance the console's provenance card surfaces (DEF-04). These are public,
  // non-secret descriptors of the running build, set out of band at deploy time when known: the
  // artefact's SHA-384 digest and a short pin/identifier for the release signer. They are presence-
  // optional (honestly absent when unset, never fabricated) and are NOT verified here; they are
  // documentation the operator can cross-check against the published release. Reported verbatim by
  // GET /admin/status; they carry no key material (a public digest and a signer pin, not a private).
  //
  // ARTEFACT_SHA384 is now a manual OVERRIDE/fallback only: the engine self-reports a BUILD-STAMPED
  // digest by default (src/format/build-id.ts, written by scripts/stamp-build-id.mjs), which is the
  // real hash of the deployable bundle. This env var, when set, takes precedence as a deliberate
  // out-of-band override (e.g. to pin a publisher-attested value); when unset the self-stamped hash
  // is reported, and only when BOTH are absent is the field honestly omitted. See status.ts.
  ARTEFACT_SHA384?: string; // e.g. "sha384:..." over the deployed artefact (manual override)
  RELEASE_SIGNER_PIN?: string; // a short public identifier/pin of the release signer

  // CF_VERSION_METADATA is the Cloudflare version_metadata binding (wrangler [version_metadata]
  // binding = "CF_VERSION_METADATA"). At runtime it exposes the IMMUTABLE identity of the deployed
  // Worker version serving the request, { id, tag, timestamp }, so the engine can self-report which
  // Cloudflare version it actually is (provenance) and the safe-apply self-check can confirm the live
  // version id matches the just-promoted one (an independent confirmation beyond the ENGINE_VERSION
  // string). It is OPTIONAL because the binding is absent in local/dry-run/test contexts (where there
  // is no deployed version); GET /admin/status surfaces id/tag presence-safely (honestly absent when
  // unbound, never fabricated). It is a PUBLIC build identifier, not a secret. It is already in
  // cf-deploy.ts's RESENDABLE_TYPES, so adding it does not trip the brick-safety binding-preservation
  // guard on a self-deploy.
  CF_VERSION_METADATA?: WorkerVersionMetadata;

  // The in-account console's origin, allowlisted for CORS so the SPA can call the admin
  // API cross-origin (e.g. https://console.example.com). Only this exact origin is
  // allowed; no wildcard.
  CONSOLE_ORIGIN?: string;

  // PASSKEY_RP_ID is the WebAuthn Relying Party ID the engine's own passkey provider scopes credentials
  // to (the free, self-contained sign-in front door, independent of Cloudflare Access). WebAuthn binds a
  // credential to an rp.id that MUST be a registrable-domain suffix of the ORIGIN the ceremony runs in,
  // which is the CONSOLE (CONSOLE_ORIGIN), not the engine. So this is OPTIONAL and DEFAULTS to the host
  // of CONSOLE_ORIGIN (the WebAuthn-correct default: a credential created on the console page is valid
  // for that exact host). Set it explicitly to the shared registrable parent (e.g. "downpipes.io") ONLY
  // when the console and another first-party surface live on sibling subdomains and a parent-scoped
  // credential is wanted; the browser still enforces that the value is a suffix of the console origin's
  // domain, so a mis-set value simply fails the ceremony in the browser rather than weakening anything.
  // The passkey routes are refused (501) when neither this nor CONSOLE_ORIGIN yields a usable rp.id and
  // origin, so the engine never runs a passkey ceremony without a known origin to bind and check against.
  PASSKEY_RP_ID?: string;

  // Destination selection. DEST_KIND forces the writer: "r2" uses the in-account R2 binding
  // DEST_R2 (no credentials on the wire); "s3" (or absent with no R2 binding) uses the
  // S3-compatible HTTP path below. When DEST_KIND is absent and DEST_R2 is bound, R2 is the
  // default. See dest/factory.ts.
  //
  // PRECEDENCE: everything here is the deploy-time/IaC path. A destination set FROM THE
  // CONSOLE (the Destinations screen; stored in the scheduler DO, verified live before
  // storage, owner-gated, audited) WINS over all of it, including DEST_KIND, exactly as
  // the console-set discovery token wins over DISCOVERY_API_TOKEN. See dest/factory.ts
  // (RuntimeDestConfig / fetchDestConfig).

  // WORKER_NAME: the engine's own script name for the in-product source attach
  // (the self-targeted settings PATCH). Optional; defaults to "downpipe-engine"
  // (the wrangler.toml name). Set it only on a renamed deployment.
  WORKER_NAME?: string;

  // CONSOLE_WORKER_NAME: the CONSOLE's script name, the twin of WORKER_NAME for the multi-component
  // update path (a console component in the signed channel deploys onto THIS script and no other --
  // the deploy-target guarantee; the one-shot token itself cannot be script-scoped). Optional; defaults
  // to "downpipe-console" (the console's wrangler.toml name). Set it on a renamed console deployment
  // (the demo sets "downpipe-console-demo" so a demo update can never touch the prod console).
  CONSOLE_WORKER_NAME?: string;

  DEST_KIND?: "r2" | "s3";
  DEST_R2?: R2Bucket; // the in-account archive bucket binding (R2 destination)

  // Destination (the customer's own S3-compatible bucket).
  DEST_ENDPOINT?: string;
  DEST_BUCKET?: string;
  DEST_REGION?: string;
  DEST_ACCESS_KEY_ID?: string; // from the Secrets Store
  DEST_SECRET_ACCESS_KEY?: string; // from the Secrets Store

  // CONFIG_WRAP_KEY is an OPTIONAL base64url AES-256 key (32 bytes) held in the account Secrets Store.
  // When set, a console-set destination's secretAccessKey is AES-256-GCM envelope-encrypted at rest in
  // the scheduler Durable Object instead of stored as a plaintext field (the DO holds only ciphertext;
  // the key never enters the DO, which has no env, so encryption/decryption happen in the engine Worker
  // context: the router wraps on write, fetchDestConfig unwraps on read). It upgrades the "Durable
  // Object plaintext floor" to an encrypted floor whose
  // confidentiality roots in the same Secrets Store the signer key does. Absent => the prior plaintext
  // behaviour is unchanged (back-compat), and the posture surfaces a recommendation to set it; existing
  // plaintext destinations are migrated lazily (wrapped the next time the destination is saved). A
  // present-but-malformed value fails loud (see src/admin/config-secret.ts). Generate one with:
  //   node -e "console.log(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'))"
  CONFIG_WRAP_KEY?: string;

  // WORM / Object-Lock (OPT-IN, DEFAULT-OFF). When set, every archive object the engine writes to the
  // S3 destination carries S3 Object-Lock retention metadata, so the STORE refuses to delete or
  // overwrite it until the retention window passes (real, store-enforced immutability / ransomware
  // resilience). Unset = OFF = the writes are byte-identical to the pre-WORM path (UNCHANGED behaviour).
  //
  //   DEST_WORM_MODE: "governance" or "compliance".
  //     - governance: a privileged principal (s3:BypassGovernanceRetention) can still lift/shorten the
  //       lock, protects against ordinary/accidental deletion.
  //     - compliance: the retain-until date CANNOT be shortened or the object deleted by ANYONE for the
  //       window, NOT EVEN THE ROOT ACCOUNT. This is the strong ransomware-resilience property; choose it
  //       deliberately, because a wrong retention window cannot be undone.
  //   DEST_WORM_RETENTION_DAYS: the retain-until window in whole days from each write (a positive integer).
  //
  // Both must be set together to arm WORM; a half-configured policy (one set, the other missing/invalid)
  // FAILS SAFE, the destination is built WITHOUT WORM and the immutability posture reports the policy as
  // unconfigured/misconfigured, never silently writing unprotected while claiming protection.
  //
  // CRITICAL: the destination BUCKET MUST have been created with Object-Lock ENABLED for any of this to
  // bind, Object-Lock cannot be turned on for an existing bucket. If the policy is set but the bucket does
  // not enforce Object-Lock, the store REFUSES every write that carries the retention headers, so NOTHING
  // REACHES THAT DESTINATION AT ALL. It is not a weaker backup, it is no backup. R2 answers such a write
  // with 501 NotImplemented and AWS S3 with ObjectLockConfigurationNotFoundError. The capability probe
  // (GetObjectLockConfiguration) reads the bucket's configuration, and the immutability posture check FAILS
  // at medium severity with a detail naming the refusal.
  //
  // R2 CANNOT ENFORCE S3 OBJECT-LOCK, ON ANY BUCKET. It lists GetObjectLockConfiguration and
  // PutObjectLockConfiguration as unimplemented and CreateBucket rejects x-amz-bucket-object-lock-enabled,
  // so Object-Lock can be turned on neither at create time nor after (live probe: a lock-configuration GET
  // on an R2 bucket answers 404 ObjectLockConfigurationNotFoundError). R2's own bucket-lock retention
  // feature (wrangler r2 bucket lock / PutBucketLockConfiguration) is a SEPARATE mechanism this probe does
  // not read. So setting these two vars against an R2 bucket over the S3 endpoint refuses every write.
  //
  // THE ADD-TIME REFUSAL DOES NOT COVER THIS PATH. validateAndProbeDestConfig (admin/router-destinations.ts)
  // refuses a WORM policy on a bucket that cannot enforce Object-Lock, but it only runs for a CONSOLE-SET
  // destination. buildEnvS3Destination (dest/factory.ts) arms these vars from parseWormPolicy with no probe
  // at all, so a deploy carrying them against a non-Object-Lock bucket sits in exactly the refused state and
  // nothing rejects it up front. The posture check is the only warning. See dest/factory.ts
  // (parseWormPolicy) and dest/s3.ts. A console-set destination may carry its own per-destination WORM
  // policy, which wins over these env vars exactly as the rest of the console-set destination config does.
  DEST_WORM_MODE?: "governance" | "compliance";
  DEST_WORM_RETENTION_DAYS?: string; // positive integer days

  // Destination backpressure pacing (T1-A, dest/pace.ts). DEST_RATE_PER_SEC is the steady request rate
  // the adaptive pacer holds to a healthy S3 destination (default 50, deliberately generous: the pacer
  // CLAMPS under observed 503/429 pushback rather than throttling a healthy store). DEST_BURST is the
  // token-bucket capacity (default one second of tokens). Both optional, fail-soft: an invalid value
  // falls back to the default, never stops a backup. R2 (native binding) is not paced.
  DEST_RATE_PER_SEC?: string; // positive number, requests/second (default 50)
  DEST_BURST?: string; // positive number, burst capacity (default = ceil(rate))
  // DEST_ADDRESSING forces the S3 request-addressing style: "path" (https://host/bucket/key), "vhost"
  // (https://bucket.host/key), or "auto" (default: vhost for AWS S3, path-style elsewhere). Some
  // S3-compatible stores only accept one form. A console-set destination's own addressing wins over this.
  DEST_ADDRESSING?: "auto" | "path" | "vhost";
  // DEST_STORAGE_CLASS sets the S3 storage class on every write (a cost lever for cold backups). Only the
  // immediately-readable tiers are accepted (STANDARD, STANDARD_IA, INTELLIGENT_TIERING, ONEZONE_IA);
  // GLACIER/DEEP_ARCHIVE are rejected (they need an async thaw that would break verify-at-seal and restore).
  // A console-set destination's own storage class wins over this.
  DEST_STORAGE_CLASS?: "STANDARD" | "STANDARD_IA" | "INTELLIGENT_TIERING" | "ONEZONE_IA";
  // DEST_THROTTLE_MAX_YIELDS bounds the park-and-resume window (T1-C, seal/runstate.ts): how many
  // consecutive throttle (503/429) waits a sliced run rides out, checkpoint preserved, before it is given
  // up with "destination unavailable". Default 60 (~several hours at the 5min backoff cap). Fail-soft.
  DEST_THROTTLE_MAX_YIELDS?: string; // positive integer (default 60)
  // The deeper in-slice retry budget for the destination THROTTLE/transient class (Layer 1b,
  // seal/retry.ts DEST_THROTTLE_RETRY). DEST_THROTTLE_ATTEMPTS / DEST_THROTTLE_BASE_MS let a store with a
  // known-longer throttle window ride deeper than the 6-attempt / 500 ms default without a code change.
  // Both optional, fail-soft (an invalid value falls back to the default); they only change how patiently
  // a 503 is retried before the run park-and-resumes, never the integrity verdict.
  DEST_THROTTLE_ATTEMPTS?: string; // positive integer (default 6)
  DEST_THROTTLE_BASE_MS?: string; // positive number, ms (default 500)

  // The signer private key and the recipient public keys (from the Secrets Store).
  SIGNER_PRIVATE?: string; // base64url ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes
  BREAK_GLASS_PUBLIC?: string; // base64url x25519(32) || ML-KEM-1024 ek(1568)
  OPERATIONAL_PUBLIC?: string; // optional operational recipient public
  // CONTROL_PLANE_EXPORT_SEALING_DISABLED (S5): sealing is ON BY DEFAULT -- the cron writes the SEALED
  // control-plane export (body encrypted to the break-glass + operational recipients), so a destination-bucket
  // reader sees no roster/topology. Set this to 1 to OPT OUT and fall back to the signed-plaintext export: the
  // one reason to is the break-glass-only posture where you want the engine to AUTO-heal (with no operational
  // key it cannot unseal, so a sealed export recovers only offline via the reader's `unseal-export`). The
  // console never unseals (it verifies the signature only).
  CONTROL_PLANE_EXPORT_SEALING_DISABLED?: string;
  OPERATIONAL_PRIVATE?: string; // optional in-account read-back key for the restore drill
  // The CONFIG RECIPIENT: a recipient key pair whose only job is opening this engine's own sealed
  // configuration export (the control-plane recovery artefact), so auto-heal after a Durable Object wipe
  // does not require a key that can also read customer archives.
  //
  // The sealed export has always been sealed to the ARCHIVE recipient set, which coupled config recovery
  // to the operational key by accident rather than by design: a break-glass-only engine could not open its
  // own configuration and had to be rebuilt offline with the reader's unseal-export. Sealing it to a
  // dedicated recipient removes that coupling.
  //
  // Be precise about what this key opens, because it is not nothing: the estate roster, the topology, the
  // destination endpoint and access key id, and the RBAC email addresses. That is a strictly smaller blast
  // radius than an archive-decryption key and it is a different disclosure class, not an absent one.
  // Break-glass remains a recipient of the export in every posture, so the offline reader's unseal-export
  // keeps working unchanged.
  CONFIG_RECIPIENT_PUBLIC?: string; // base64url x25519(32) || ML-KEM-1024 ek(1568)
  CONFIG_RECIPIENT_PRIVATE?: string; // base64url x25519 scalar(32) || ML-KEM seed(64)

  // The vendor-signed update channel (pulled in-account; never a push). UPDATE_SIGNER_PUBLIC
  // is the pinned release-signer public key the channel signature is verified against.
  UPDATE_CHANNEL_URL?: string;
  UPDATE_SIGNER_PUBLIC?: string; // base64url ed25519(32) || ML-DSA-87 public(2592)
  // UPDATE_READBACK_MODE (DP-D) selects the post-upload read-back gate: "warn" (default when absent)
  // reads the uploaded version back from Cloudflare's API, hashes it against the signed digest and
  // records the verdict but proceeds; "enforce" refuses promotion unless the read-back VERIFIED
  // (fail-closed; enable only after a sandbox experiment); "off" skips the read-back.
  UPDATE_READBACK_MODE?: string;
  // UPDATE_CHANNEL_MAX_AGE_DAYS (R9, OPT-IN, default OFF) is the freshness backstop: when set to a positive
  // number, the safe-apply path REFUSES a signed channel descriptor whose issuedAt is older than this many
  // days (a stale/replayed descriptor). OFF by default so it can never false-positive on a legitimately
  // dormant-but-current channel; the monotonic sequence/issuedAt replay checks always apply regardless.
  UPDATE_CHANNEL_MAX_AGE_DAYS?: string;

  // The out-of-band assurance licence. LICENCE_TOKEN is a compact dot-joined signed token
  // (<body_b64url>.<sig_b64url>); LICENCE_SIGNER_PUBLIC is the PINNED vendor public key its
  // hybrid signature is verified against (same 2624-byte layout as UPDATE_SIGNER_PUBLIC).
  // Both are optional: their absence degrades to tier 'community' (fail-open). They are
  // verify-only here; the vendor mints tokens out of the repo with the matching private key.
  //
  // LICENCE_SIGNER_PUBLIC is now an OVERRIDE over a compile-time baked vendor pin
  // (DEFAULT_LICENCE_SIGNER_PUBLIC in src/licence-pins.ts): a release with the constant filled
  // verifies a licence with NO env pin set, since the vendor's public signer is the same for every
  // customer and never changes. A non-empty value here still WINS (a self-host pinning their own
  // signer, or the demo). When BOTH the override and the baked default are empty, behaviour is
  // unchanged, community fail-open with "pinned vendor key not configured". See effectiveSignerPin
  // in src/admin/licence.ts.
  LICENCE_TOKEN?: string;
  LICENCE_SIGNER_PUBLIC?: string; // base64url ed25519(32) || ML-DSA-87 public(2592); env override over the baked vendor pin

  // SRE alerting (the on-call persona) is configured at RUNTIME by the customer through the admin
  // API (the notify channels/rules under the scheduler Durable Object), NOT through an env binding:
  // a webhook/Slack/Teams url or a PagerDuty routing key lives in the DO as a NotifyChannel. There is
  // deliberately no WEBHOOK_URL binding here; the customer owns and changes the destination from their
  // own console, and the engine never holds an alerting secret (any token the customer needs is
  // embedded in their own url, on their side). See src/notify.ts and the scheduler DO.

  // Outbound email (contract section 3), consumed by the email notification channel (section 2), the
  // expiry alerts (section 4), and the role-invite notification (the people path). EMAIL is the native
  // Cloudflare Email Sending binding (declared in wrangler.toml as [[send_email]] named EMAIL); it is
  // OPTIONAL because live sending needs Workers Paid plus destination-address/domain onboarding, which
  // is separately gated. When the binding is absent, sendEmail (src/email.ts) is honestly fail-open
  // ({ ok:false, reason:"email-not-configured" }) and the role-invite is silently skipped. The binding
  // is CfEmailSend-shaped (the same single send() the control plane uses), so the engine does not couple
  // to a specific email-message library. EMAIL_FROM is the sender address for the notification/expiry
  // channels, validated as a custom-domain address at send time (never a workers.dev or bare hostname).
  // Neither is a secret: the binding is a capability, the from is a public address.
  EMAIL?: CfEmailSend;
  EMAIL_FROM?: string;

  // INVITE_EMAIL_FROM is the sender address for the OPTIONAL role-invite notification: when a role
  // (built-in or custom) is granted to a person via POST /admin/roles, the engine best-effort sends
  // that person an invite/notification email. The invite is OFF unless BOTH the EMAIL binding is bound
  // AND INVITE_EMAIL_FROM is set (a separate, opt-in sender so an account can run alerts/expiry email
  // without also emailing on every role grant, or vice versa). It is validated as a custom-domain
  // address at send time (never a workers.dev or bare hostname) and is a public address, not a secret.
  // A send failure is swallowed and never blocks or fails the grant (email is observability, never a
  // control). CONSOLE_ORIGIN (above) supplies the sign-in link the invite points at when set.
  INVITE_EMAIL_FROM?: string;

  // BOOTSTRAP_OWNER_EMAIL is the deploy-time-pinned FIRST-OWNER address for the email-link bootstrap
  // (blueprint 2.2): on a brand-new engine (empty role table, bootstrap latch unset), POST
  // /admin/auth/bootstrap/send mints a single-active, 24h, single-use first-Owner invite and emails its
  // register link to THIS address ONLY (never a client-supplied one). The trust chain is: control of the
  // Cloudflare account (whoever deploys sets this) -> control of this inbox -> first Owner. Setting it is
  // what makes the no-token first-run possible; the ADMIN_TOKEN bearer bootstrap continues to work
  // independently. Validated as a custom-domain address at send time; a public address, not a secret.
  // Sending requires the EMAIL binding plus a sender (INVITE_EMAIL_FROM, else EMAIL_FROM).
  BOOTSTRAP_OWNER_EMAIL?: string;

  // DISCOVERY_API_TOKEN (opt-in, IaC FALLBACK) enables ACCOUNT-WIDE source discovery: a READ-ONLY
  // Cloudflare API token the CUSTOMER creates in their own account. The PRIMARY path is the console
  // (Choose sources > See everything in your account): the token is verified live, stored by the
  // scheduler DO at runtime (no CLI, no redeploy), owner-gated and audited. This env secret remains
  // for teams that prefer deploy-time configuration; the DO-stored token wins when both exist.
  // Custody is unchanged either way (the vendor never sees it; same class as the S3 destination
  // credentials); the trade is least-privilege blast radius, so scope it read-only to exactly the
  // four products. Never returned by any route; RESERVED so no source can read it into an archive.
  DISCOVERY_API_TOKEN?: string;
  // CF_ACCOUNT_ID pins which account the discovery token lists when the token can see more than one
  // account; with exactly one visible account it is resolved automatically and this stays unset.
  CF_ACCOUNT_ID?: string;

  // Source bindings are added per downpipe, for example:
  // KV_<id>: KVNamespace; R2_<id>: R2Bucket; D1_<id>: D1Database; SECRET_<name>: ...
  [binding: string]: unknown;
}

// CfEmailSend is the native Cloudflare Email Sending binding shape (send_email): a single send()
// taking a small, redaction-safe message and resolving when the platform accepts it. It mirrors the
// control plane's CfEmailSend so the two profiles agree on the binding, but is declared locally
// because this newer Email Sending service is not in @cloudflare/workers-types. `to` accepts a single
// address (the role-invite path, one recipient) OR an address list (the notification/expiry path in
// src/email.ts), so one binding type serves both senders; `text`/`html`/`messageId` are optional so a
// recording double in the validators (which resolves without a message id) still satisfies the shape.
export interface CfEmailSend {
  send(message: { to: string | string[]; from: string; subject: string; text?: string; html?: string }): Promise<{ messageId?: string } | undefined>;
}
