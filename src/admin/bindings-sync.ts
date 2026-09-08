// Pre-deploy binding reconcile, the PURE core. Keeps `wrangler deploy` from silently dropping
// console-attached backup sources.
//
// THE PROBLEM. A backup source is a Workers binding on the engine (a KV namespace, R2 bucket, D1
// database, or Secrets Store secret). There are two ways a binding gets onto the engine and they
// disagree:
//   * The CONSOLE attach path (src/admin/attach.ts changeBindings) adds source bindings to the
//     LIVE worker through the Cloudflare API and PROVES it drops nothing (a superset proof + a
//     post-write re-read). It writes to the worker, never to wrangler.toml, the no-CLI path.
//   * `wrangler deploy` sets the worker's bindings to EXACTLY what wrangler.toml lists. Anything
//     not in the file is removed from the deployed worker. It is the exact inverse of the attach
//     path: a blind overwrite.
// wrangler.toml lists NO source bindings (by design, pinning one would make it survive a deploy
// while every other source is dropped), so a routine code deploy SILENTLY WIPES every console-
// attached source. The source's next run then fails with "source binding error" (src/seal/
// adapters.ts buildAdapter), and it disappears from the Sources listing (discovery sees only LIVE
// bindings).
//
// THE FIX. Before a deploy, READ the live worker's current bindings (the SAME script-settings
// endpoint attach.ts uses) and regenerate the deploy config as the committed wrangler.toml PLUS
// every live SOURCE binding it does not already declare. The deployed config is then a strict
// SUPERSET of the live source bindings, so the deploy cannot drop one. The live worker is the
// source of truth for what is attached; this reconcile carries it forward verbatim.
//
// This module is the pure, IO-free core (classify + parse + render + merge) so a validator can
// drive every guard directly. scripts/sync-bindings.mjs is the IO shell that reads the live
// bindings and writes the generated config, and REFUSES to produce one (stopping the deploy)
// rather than deploy a config it could not prove preserves the sources.

import { RESERVED_BINDINGS } from "../sched/scheduler-do.ts";

// The Cloudflare binding TYPES that are backup sources. Every other type is the engine's own
// infrastructure (Durable Objects, secrets, plain vars, the send_email binding) or the archive
// DESTINATION, none of which this reconcile ever carries as a source.
export const SOURCE_BINDING_TYPES = new Set(["kv_namespace", "r2_bucket", "d1", "secrets_store_secret"]);

// deployConfigPath derives the generated-superset path for a committed config: swap the trailing `.toml` for
// `.deploy.toml` (wrangler.toml -> wrangler.deploy.toml; wrangler.dev.toml -> wrangler.dev.deploy.toml), so each
// env's superset (sync-bindings.mjs --config <env toml>) is a DISTINCT file beside its committed config and can
// never overwrite it in place. Throws if the path does not end in `.toml` -- refusing rather than risk clobber.
export function deployConfigPath(configPath: string): string {
  if (!configPath.endsWith(".toml")) {
    throw new Error(`config path must end in ".toml" (got "${configPath}") so the generated superset is a distinct .deploy.toml file`);
  }
  return configPath.replace(/\.toml$/, ".deploy.toml");
}

// A live binding exactly as the script-settings read returns it (re-sent verbatim by attach.ts;
// here we only read name/type and the per-type resource id fields).
export type LiveBinding = Record<string, unknown> & { name?: string; type?: string };

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

// isSourceBinding: a live binding is a source to PRESERVE iff it is one of the source types AND
// its name is not one of the engine's own reserved bindings. DEST_R2 is an r2_bucket but it is the
// destination (RESERVED_BINDINGS holds it), so it is excluded; Durable Objects, secrets and vars
// are not source types and so are excluded by type. Defensive on shape.
export function isSourceBinding(b: LiveBinding): boolean {
  return typeof b.type === "string"
    && SOURCE_BINDING_TYPES.has(b.type)
    && typeof b.name === "string"
    && b.name !== ""
    && !RESERVED_BINDINGS.has(b.name);
}

// existingBindingNames extracts every binding NAME a wrangler.toml already declares. Source and
// destination stanzas (kv/r2/d1/secrets) use `binding = "NAME"`; Durable Objects and send_email
// use `name = "..."`, so they are not matched (correctly, they are not sources). Tolerant of
// surrounding whitespace and single or double quotes.
export function existingBindingNames(toml: string): Set<string> {
  const names = new Set<string>();
  const re = /^[ \t]*binding[ \t]*=[ \t]*["']([^"']+)["']/gm;
  let m: RegExpExecArray | null = re.exec(toml);
  while (m !== null) {
    names.add(m[1]!);
    m = re.exec(toml);
  }
  return names;
}

// renderStanza renders one live source binding as its wrangler.toml array-of-tables stanza. The
// settings-read field names differ from the toml keys (KV namespace_id -> id; D1 id -> database_id),
// so each type maps explicitly. It THROWS if a required id is absent: a source we cannot render
// faithfully must STOP the deploy, never be dropped silently (the whole point of the reconcile).
export function renderStanza(b: LiveBinding): string {
  const name = str(b.name);
  if (name === undefined) throw new Error("a live source binding has no name");
  switch (b.type) {
    case "kv_namespace": {
      const id = str(b.namespace_id) ?? str(b.id);
      if (id === undefined) throw new Error(`live KV source ${name} has no namespace id in the settings read; cannot render it for deploy`);
      return `[[kv_namespaces]]\nbinding = "${name}"\nid = "${id}"\n`;
    }
    case "r2_bucket": {
      const bucket = str(b.bucket_name);
      if (bucket === undefined) throw new Error(`live R2 source ${name} has no bucket name in the settings read; cannot render it for deploy`);
      const jurisdiction = str(b.jurisdiction);
      return `[[r2_buckets]]\nbinding = "${name}"\nbucket_name = "${bucket}"\n${jurisdiction !== undefined ? `jurisdiction = "${jurisdiction}"\n` : ""}`;
    }
    case "d1": {
      const id = str(b.id) ?? str(b.database_id);
      if (id === undefined) throw new Error(`live D1 source ${name} has no database id in the settings read; cannot render it for deploy`);
      const dbName = str(b.database_name);
      return `[[d1_databases]]\nbinding = "${name}"\ndatabase_id = "${id}"\n${dbName !== undefined ? `database_name = "${dbName}"\n` : ""}`;
    }
    case "secrets_store_secret": {
      const storeId = str(b.store_id);
      const secretName = str(b.secret_name);
      if (storeId === undefined || secretName === undefined) throw new Error(`live Secrets Store source ${name} is missing its store id or secret name; cannot render it for deploy`);
      return `[[secrets_store_secrets]]\nbinding = "${name}"\nstore_id = "${storeId}"\nsecret_name = "${secretName}"\n`;
    }
    default:
      throw new Error(`binding ${name} has unsupported source type ${String(b.type)}`);
  }
}

export interface ReconcilePlan {
  // The deploy config: the committed wrangler.toml + appended stanzas for every live source it did
  // not already declare. A strict superset of the live source bindings.
  generatedToml: string;
  // Live source bindings appended because the committed toml lacked them, i.e. the ones a plain
  // `wrangler deploy` WOULD HAVE DROPPED. The headline of the reconcile.
  preserved: string[];
  // Live source bindings the committed toml already declares (left alone, no duplicate).
  alreadyPresent: string[];
  liveSourceCount: number; // total live source bindings seen
  nonSourceCount: number; // live non-source bindings (engine infra/destination), informational
}

// planReconcile is the PURE merge: given the committed wrangler.toml text and the live binding set,
// produce the deploy config that is a SUPERSET of the live source bindings. Idempotent: a live
// source already named in the toml is left untouched, and feeding the generated output back in is a
// no-op (its appended stanzas are now "already present"). Deterministic order so the file is stable.
export function planReconcile(committedToml: string, live: LiveBinding[]): ReconcilePlan {
  const already = existingBindingNames(committedToml);
  const liveSources = live.filter(isSourceBinding);
  const preserved: string[] = [];
  const alreadyPresent: string[] = [];
  const stanzas: string[] = [];
  for (const b of [...liveSources].sort((a, z) => String(a.name).localeCompare(String(z.name)))) {
    const name = b.name as string;
    if (already.has(name)) {
      alreadyPresent.push(name);
      continue;
    }
    stanzas.push(renderStanza(b));
    preserved.push(name);
  }
  const header =
    "# GENERATED at deploy time by scripts/sync-bindings.mjs, DO NOT EDIT, DO NOT COMMIT.\n" +
    "# This file = wrangler.toml + every source binding the LIVE worker currently has, so that\n" +
    "# `wrangler deploy` cannot drop a source attached from the console. It is regenerated on every\n" +
    "# deploy from the live worker (the source of truth for attached sources); edit wrangler.toml.\n\n";
  const appended =
    stanzas.length > 0
      ? `\n# ---- source bindings carried forward from the LIVE worker (console-attached) ----\n${stanzas.join("\n")}`
      : "";
  return {
    generatedToml: header + committedToml + appended,
    preserved,
    alreadyPresent,
    liveSourceCount: liveSources.length,
    nonSourceCount: live.length - liveSources.length,
  };
}
