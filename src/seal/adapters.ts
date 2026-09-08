import { accountPacer } from "../cf-pace.ts";
import type { Env } from "../env.d.ts";
import { type DownpipeState, RESERVED_BINDINGS } from "../sched/scheduler-do.ts";
import { ArtifactsSource } from "../sources/artifacts.ts";
import { type MediaContentOpts, makeByteFetcher } from "../sources/byte-fetch.ts";
import { makeCfApi } from "../sources/cf-config-surfaces.ts";
import { CloudflareConfigSource } from "../sources/cloudflare-config.ts";
import { D1Source } from "../sources/d1.ts";
import { ImagesSource } from "../sources/images.ts";
import { KVSource } from "../sources/kv.ts";
import { R2Source } from "../sources/r2.ts";
import { type BoundSecret, SecretsSource } from "../sources/secrets.ts";
import { StreamSource } from "../sources/stream.ts";
import type { SourceAdapter } from "../sources/types.ts";
import { makeWorkersCfApi, WorkersSource } from "../sources/workers.ts";
import { ConfigFaultError } from "./config-fault.ts";

// slicedRunsDisabled reads the SLICED_RUNS_DISABLED knob (the v1 whole-run buffered path, no mid-record
// resume). It gates the resumability the large-value sources (media + R2) hold a large object to: a
// non-resumable run caps it at the one-slice ceiling, a resumable one at the higher cross-slice ceiling.
// The knob test mirrors runstate-helpers.ts truthyKnob, inlined to avoid a seal-builder import dependency.
function slicedRunsDisabled(env: Env): boolean {
  return typeof env.SLICED_RUNS_DISABLED === "string" && /^(1|true|yes|on)$/i.test(env.SLICED_RUNS_DISABLED.trim());
}

// mediaContentOpts builds the byte-capture options for a media adapter: the fetcher is the SAME discovery
// token + pacer the metadata reads use, constructed only when content capture is on so a metadata-only
// downpipe builds no fetcher. Returns undefined when off, so the adapter's default (metadata only) holds.
// resumable mirrors the run's slicing posture (slicedRunsDisabled): the deployed default captures a large
// etag-pinned value across slices up to the higher ceiling; SLICED_RUNS_DISABLED holds it to the one-slice
// ceiling.
function mediaContentOpts(env: Env, token: string, includeContent: boolean | undefined): MediaContentOpts | undefined {
  if (includeContent !== true) return undefined;
  return { includeContent: true, bytes: makeByteFetcher(token, fetch, accountPacer(env)), resumable: !slicedRunsDisabled(env) };
}

// mediaMetadataApi builds the read client for a media source's metadata crawl (Stream/Images/Artifacts).
// It passes ALL THREE positional args to makeCfApi(token, fetch, pacer) so the pacer lands in the pacer
// slot, not the fetchImpl slot, throttling each crawl below the account-API limit the same way
// cf-config/workers/byte-fetch do. The pacer is accountPacer(env): account-global (shared bucket) when the
// RATELIMIT_DO binding is present, otherwise the per-isolate CfPacer fallback (byte-identical to before).
function mediaMetadataApi(env: Env, token: string, _sourceType: string): ReturnType<typeof makeCfApi> {
  return makeCfApi(token, fetch, accountPacer(env));
}

// API_DISCOVERY_SOURCE_TYPES is the single source of truth for the source types whose adapters below read
// the Cloudflare REST API with the engine's read-only discovery token (every branch for these THROWS when
// the token is absent): cf-config, workers, and the three media sources (stream/images/artifacts). It is
// DEFINED in the sources/types.ts leaf and re-exported here so the run-path resolver (cfConfigToken) and
// the coverage reporter share ONE set without importing the seal/scheduler graph; importers that read it
// from this module are unchanged (the drift that left stream/images/artifacts unable to run despite a token).
export { API_DISCOVERY_SOURCE_TYPES } from "../sources/types.ts";

// SELF-IDENTITY (gap G282). A backup only self-identifies -- and a roster rebuild after a deploy wipe only
// works -- when the downpipe's config carries the source's NATIVE id alongside the Workers binding: kv's
// namespaceId, r2's bucketName, d1's databaseId, and (for secrets) each secret's Secrets Store storeId. Those
// fields are OPTIONAL for back-compat, so a LEGACY config saved before they existed falls back to the binding
// name in buildAdapter below (kv/r2) or simply omits the store from the archive record (secrets). Such a
// downpipe still BACKS UP fine, but it cannot be roster-rebuilt or re-attached after the binding is gone, and
// today nothing anywhere says so: sourcesDetached carries only binding names, and support has to ask the
// customer to read their own stored config to find out why one downpipe will not come back.
//
// SELF_IDENTITY_CLASSES is the CLOSED vocabulary for that posture, derived at pack-build time from the stored
// config. No new state is recorded: the config IS the record; this is the classifier that makes it legible.
//   - "ok": the source carries its native identity (or is an API source that needs none).
//   - "native-id-absent": a kv/r2/d1 downpipe whose namespaceId/bucketName/databaseId is missing (the archive
//     falls back to the binding name, so a re-attach cannot resolve the real resource).
//   - "secrets-store-absent": a secrets downpipe with at least one secret whose Secrets Store id is missing (the
//     archive record omits the store, so the secrets_store_secret binding cannot be rebuilt).
export const SELF_IDENTITY_CLASSES = ["ok", "native-id-absent", "secrets-store-absent"] as const;
export type SelfIdentityClass = (typeof SELF_IDENTITY_CLASSES)[number];

/**
 * selfIdentityClass classifies ONE downpipe's archive self-identity from its stored config (gap G282). PURE (no
 * I/O, no state): it reads only the fields buildAdapter itself falls back on, so the classifier can never drift
 * from the behaviour it describes. Redaction-safe by construction: it returns a CLOSED class, never an id.
 */
export function selfIdentityClass(source: DownpipeState["config"]["source"]): SelfIdentityClass {
  if (source.type === "secrets") {
    const list = source.secrets ?? [];
    // A secret with no storeId cannot rebuild its secrets_store_secret binding on re-attach (the crawl leaves
    // `store` off the record entirely, mirroring buildAdapter's `...(sec.storeId !== undefined ...)` below).
    return list.some((sec) => typeof sec.storeId !== "string" || sec.storeId.length === 0) ? "secrets-store-absent" : "ok";
  }
  if (source.type === "kv") return typeof source.namespaceId === "string" && source.namespaceId.length > 0 ? "ok" : "native-id-absent";
  if (source.type === "r2") return typeof source.bucketName === "string" && source.bucketName.length > 0 ? "ok" : "native-id-absent";
  if (source.type === "d1") return typeof source.databaseId === "string" && source.databaseId.length > 0 ? "ok" : "native-id-absent";
  // The API-discovery sources (cf-config / workers / stream / images / artifacts) are identified by the account
  // (and zone) they read, not by a binding, so they carry no native-id degradation.
  return "ok";
}

/** selfIdentityDegraded is the boolean the roster carries (gap G282): true when this downpipe cannot be
 * reconstructed from its archive + config after a binding is lost. Derived, never stored. */
export function selfIdentityDegraded(source: DownpipeState["config"]["source"]): boolean {
  return selfIdentityClass(source) !== "ok";
}

// buildAdapter constructs the source adapter for a downpipe from its configured
// bindings. It lives here (not index.ts) so both the worker entry and the per-run seal
// Durable Object construct sources without an import cycle; index.ts re-exports it as
// the unchanged test seam.
export function buildAdapter(env: Env, state: DownpipeState, cfConfigToken?: string): SourceAdapter {
  const s = state.config.source;
  const guard = (b: string) => {
    // Defence in depth: never read one of the engine's own bindings as a backup source.
    // G142: the refusal is unchanged (same message, same throw); it is now TYPED, so the run path can record
    // WHICH binding was refused as closed evidence instead of the pack seeing only "source binding error".
    if (RESERVED_BINDINGS.has(b)) throw new ConfigFaultError("reserved-binding", `binding ${b} is reserved and cannot be a source`, b);
    return b;
  };
  if (s.type === "secrets") {
    const list = s.secrets ?? [];
    const bound: BoundSecret[] = list.map((sec) => {
      const store = env[guard(sec.binding)];
      if (!store) throw new ConfigFaultError("secret-binding-missing", `secret binding ${sec.binding} is not present in the environment`, sec.binding);
      // A Secrets Store binding exposes get(); a plaintext env secret is the string itself. G041: ANYTHING
      // ELSE (a KV namespace, an R2 bucket, a D1 database, a service binding accidentally bound under the
      // secret's name) is REFUSED rather than coerced with String(store), which would otherwise seal
      // "[object Object]" as the secret's value while every run reports a clean ok. A typed config fault
      // names the binding (an operator label, never the value) and the run fails loudly, so the pack carries
      // a config-fault seal-fault record with the closed code secret-binding-wrong-type rather than silently
      // corrupt backups.
      const hasGet = typeof (store as { get?: unknown }).get === "function";
      if (!hasGet && typeof store !== "string") {
        throw new ConfigFaultError("secret-binding-wrong-type", `secret binding ${sec.binding} is neither a Secrets Store binding nor a string secret; refusing to seal a coerced value`, sec.binding);
      }
      const get = hasGet ? () => (store as { get(): Promise<string> }).get() : () => Promise.resolve(store as unknown as string);
      // Carry the Secrets Store store id into the archive (via the crawl's descriptor.secretsStore) so the
      // backup self-identifies WHICH store each secret came from and a re-attach can rebuild the
      // secrets_store_secret binding (attach needs store_id + secret_name). Omitted when absent (a config
      // saved before storeId existed): the crawl's `if (s.store !== undefined)` then leaves it off the record.
      return { name: sec.name, get, bindingVar: sec.binding, ...(sec.storeId !== undefined ? { store: sec.storeId } : {}) };
    });
    return new SecretsSource(bound);
  }
  if (s.type === "cf-config") {
    // The cf-config source reads the Cloudflare REST API with the engine's read-only discovery
    // token (fetched from the DO by the run path and passed in), NOT a Workers binding.
    if (!cfConfigToken) {
      throw new ConfigFaultError("discovery-token-missing", "the Cloudflare config source needs the account read-only token; set the discovery token (Read all resources) first");
    }
    if (!s.accountId) throw new ConfigFaultError("account-id-missing", "the Cloudflare config source needs an accountId");
    // A token-bucket pacer (env CF_API_RATE_PER_SEC) throttles this crawl below the Cloudflare account-API
    // limit; the validator-only constructor params keep their defaults (undefined).
    return new CloudflareConfigSource(cfConfigToken, s.accountId, s.zoneId, undefined, fetch, undefined, accountPacer(env));
  }
  if (s.type === "workers") {
    // The Workers scripts source reads the Cloudflare REST API with the SAME read-only discovery
    // token as cf-config (account-API based, NOT a Workers binding), so the run path fetches and
    // passes it in exactly as for cf-config (cfConfigToken covers both API sources).
    if (!cfConfigToken) {
      throw new ConfigFaultError("discovery-token-missing", "the Workers scripts source needs the account read-only token; set the discovery token (Read all resources) first");
    }
    if (!s.accountId) throw new ConfigFaultError("account-id-missing", "the Workers scripts source needs an accountId");
    return new WorkersSource(s.accountId, makeWorkersCfApi(cfConfigToken, fetch, accountPacer(env)));
  }
  if (s.type === "stream") {
    // The Stream source reads the Cloudflare REST API with the SAME read-only discovery token as
    // cf-config/workers (account-scoped, NOT a binding), so the run path fetches and passes it in.
    if (!cfConfigToken) {
      throw new ConfigFaultError("discovery-token-missing", "the Stream source needs the account read-only token; set the discovery token (Read all resources) first");
    }
    if (!s.accountId) throw new ConfigFaultError("account-id-missing", "the Stream source needs an accountId");
    return new StreamSource(s.accountId, mediaMetadataApi(env, cfConfigToken, "stream"), mediaContentOpts(env, cfConfigToken, s.includeContent));
  }
  if (s.type === "images") {
    // The Images source reads the Cloudflare REST API with the SAME read-only discovery token as
    // cf-config/workers/stream (account-scoped, NOT a binding), so the run path passes it in.
    if (!cfConfigToken) {
      throw new ConfigFaultError("discovery-token-missing", "the Images source needs the account read-only token; set the discovery token (Read all resources) first");
    }
    if (!s.accountId) throw new ConfigFaultError("account-id-missing", "the Images source needs an accountId");
    return new ImagesSource(s.accountId, mediaMetadataApi(env, cfConfigToken, "images"), mediaContentOpts(env, cfConfigToken, s.includeContent));
  }
  if (s.type === "artifacts") {
    // The Artifact Registry source reads the Cloudflare REST API with the SAME read-only discovery
    // token as cf-config/workers/stream/images (account-scoped, NOT a binding).
    if (!cfConfigToken) {
      throw new ConfigFaultError("discovery-token-missing", "the Artifact Registry source needs the account read-only token; set the discovery token (Read all resources) first");
    }
    if (!s.accountId) throw new ConfigFaultError("account-id-missing", "the Artifact Registry source needs an accountId");
    return new ArtifactsSource(s.accountId, mediaMetadataApi(env, cfConfigToken, "artifacts"), mediaContentOpts(env, cfConfigToken, s.includeContent));
  }
  const binding = s.binding ? env[guard(s.binding)] : undefined;
  // G142: a wrangler deploy that wipes source bindings lands HERE. The TYPE carries the binding NAME so the
  // failed run names it.
  if (!binding) throw new ConfigFaultError("source-binding-missing", `source binding ${s.binding ?? "(none)"} is not present in the environment`, s.binding);
  switch (s.type) {
    case "kv":
      return new KVSource(binding as KVNamespace, s.namespaceId ?? s.binding!);
    case "r2":
      // resumable mirrors the run's slicing posture (as for the media sources): a large R2 object seals
      // across slices when sliced runs are on (the higher in-band ceiling), else it is held to the
      // one-slice ceiling. Either way an object past the ceiling is skipped with a loud marker, not a
      // terminal-fail of the run.
      return new R2Source(binding as R2Bucket, s.bucketName ?? s.binding!, { resumable: !slicedRunsDisabled(env) });
    case "d1":
      return new D1Source(binding as D1Database, s.binding!, undefined, undefined, s.databaseId);
    default:
      throw new ConfigFaultError("unsupported-source-type", `unsupported source type`);
  }
}
