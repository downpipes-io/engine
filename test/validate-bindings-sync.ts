// Validates the pre-deploy binding reconcile pure core (src/admin/bindings-sync.ts): the source
// classification, the wrangler.toml binding-name parse, the per-type stanza render, and the merge
// that makes the generated deploy config a strict SUPERSET of the live source bindings. The core
// guarantee under test: a deploy built from the generated config can never DROP a live source, EVERY
// source is treated identically (wrangler.toml pins none of them), and the merge is idempotent and
// never carries the engine's own (reserved/infra) bindings as sources.
// Run: node test/validate-bindings-sync.ts.

import {
  planReconcile,
  isSourceBinding,
  existingBindingNames,
  renderStanza,
  deployConfigPath,
  SOURCE_BINDING_TYPES,
  type LiveBinding,
} from "../src/admin/bindings-sync.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}
function threw(name: string, fn: () => unknown): void {
  let did = false;
  try {
    fn();
  } catch {
    did = true;
  }
  ok(name, did);
}

// The committed wrangler.toml the repo ships: pure INFRASTRUCTURE, ZERO source bindings. Sources are
// never pinned here (pinning one would make it survive a deploy while every other source is dropped).
const COMMITTED = `name = "downpipe-engine"
main = "src/index.ts"

[[durable_objects.bindings]]
name = "SCHEDULER"
class_name = "SchedulerDO"

[[durable_objects.bindings]]
name = "RUNSEAL"
class_name = "RunSealDO"
`;

// A realistic settings-read binding set: two DOs, a secret, a plain var, the R2 DESTINATION
// (reserved), and FOUR console-attached sources, including the KV that used to be hand-pinned in
// wrangler.toml, now treated like any other source. A bare `wrangler deploy` would drop ALL four.
const LIVE: LiveBinding[] = [
  { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" },
  { type: "durable_object_namespace", name: "RUNSEAL", class_name: "RunSealDO" },
  { type: "secret_text", name: "SIGNER_PRIVATE" },
  { type: "plain_text", name: "CONSOLE_ORIGIN", text: "https://console.downpipes.io" },
  { type: "r2_bucket", name: "DEST_R2", bucket_name: "downpipe-archive" },
  { type: "kv_namespace", name: "SRC_KV_ADMIN_RATE_LIMIT_KV", namespace_id: "kv00000000000000000000000000000002" },
  { type: "kv_namespace", name: "SRC_KV_uploads", namespace_id: "kv00000000000000000000000000000001" },
  { type: "r2_bucket", name: "SRC_R2_media", bucket_name: "media" },
  { type: "d1", name: "SRC_D1_app", id: "db-1111-2222", database_name: "app" },
];
const LIVE_SOURCE_NAMES = ["SRC_D1_app", "SRC_KV_ADMIN_RATE_LIMIT_KV", "SRC_KV_uploads", "SRC_R2_media"];

// ---- existingBindingNames -------------------------------------------------------------------
{
  const infra = existingBindingNames(COMMITTED);
  ok("existingBindingNames: the committed infra toml declares NO source bindings", infra.size === 0);
  ok("existingBindingNames: does NOT treat a Durable Object `name =` as a binding", !infra.has("SCHEDULER"));
  ok(
    "existingBindingNames: parses a `binding =` line (double quotes)",
    existingBindingNames('[[kv_namespaces]]\nbinding = "SRC_KV_x"\nid = "n"').has("SRC_KV_x"),
  );
  ok(
    "existingBindingNames: tolerant of single quotes + extra whitespace",
    (() => {
      const s = existingBindingNames(`  binding   =   'SRC_KV_x' `);
      return s.has("SRC_KV_x") && s.size === 1;
    })(),
  );
}

// ---- isSourceBinding ------------------------------------------------------------------------
{
  ok("isSourceBinding: a KV source is a source", isSourceBinding({ type: "kv_namespace", name: "SRC_KV_uploads" }));
  ok("isSourceBinding: an R2 source is a source", isSourceBinding({ type: "r2_bucket", name: "SRC_R2_media" }));
  ok("isSourceBinding: a D1 source is a source", isSourceBinding({ type: "d1", name: "SRC_D1_app" }));
  ok("isSourceBinding: a Secrets Store secret is a source", isSourceBinding({ type: "secrets_store_secret", name: "SRC_SECRET_x" }));
  ok("isSourceBinding: DEST_R2 (reserved) is NOT a source", !isSourceBinding({ type: "r2_bucket", name: "DEST_R2" }));
  ok("isSourceBinding: a Durable Object is NOT a source", !isSourceBinding({ type: "durable_object_namespace", name: "SCHEDULER" }));
  ok("isSourceBinding: a secret_text is NOT a source", !isSourceBinding({ type: "secret_text", name: "SIGNER_PRIVATE" }));
  ok("isSourceBinding: a plain var is NOT a source", !isSourceBinding({ type: "plain_text", name: "CONSOLE_ORIGIN" }));
  ok("isSourceBinding: an unknown type is NOT a source", !isSourceBinding({ type: "analytics_engine", name: "X" }));
  ok("isSourceBinding: a nameless binding is NOT a source", !isSourceBinding({ type: "kv_namespace" }));
  ok("SOURCE_BINDING_TYPES is the four backup-able types", SOURCE_BINDING_TYPES.size === 4);
}

// ---- renderStanza (field-name mapping + fail-safe) ------------------------------------------
{
  ok(
    "renderStanza KV maps namespace_id -> id",
    renderStanza({ type: "kv_namespace", name: "SRC_KV_uploads", namespace_id: "ns-1" }) === '[[kv_namespaces]]\nbinding = "SRC_KV_uploads"\nid = "ns-1"\n',
  );
  ok(
    "renderStanza R2 emits bucket_name (+ jurisdiction when set)",
    renderStanza({ type: "r2_bucket", name: "SRC_R2_media", bucket_name: "media", jurisdiction: "eu" }) ===
      '[[r2_buckets]]\nbinding = "SRC_R2_media"\nbucket_name = "media"\njurisdiction = "eu"\n',
  );
  ok(
    "renderStanza D1 maps id -> database_id (+ database_name)",
    renderStanza({ type: "d1", name: "SRC_D1_app", id: "db-1", database_name: "app" }) ===
      '[[d1_databases]]\nbinding = "SRC_D1_app"\ndatabase_id = "db-1"\ndatabase_name = "app"\n',
  );
  ok(
    "renderStanza Secrets Store emits store_id + secret_name",
    renderStanza({ type: "secrets_store_secret", name: "SRC_SECRET_x", store_id: "st-1", secret_name: "api" }) ===
      '[[secrets_store_secrets]]\nbinding = "SRC_SECRET_x"\nstore_id = "st-1"\nsecret_name = "api"\n',
  );
  threw("renderStanza THROWS when a KV source has no namespace id (fail-safe, never dropped)", () => renderStanza({ type: "kv_namespace", name: "SRC_KV_x" }));
  threw("renderStanza THROWS when a D1 source has no id", () => renderStanza({ type: "d1", name: "SRC_D1_x" }));
  threw("renderStanza THROWS on an unsupported type", () => renderStanza({ type: "weird", name: "X" }));
}

// ---- planReconcile: every source carried, identically ---------------------------------------
{
  const plan = planReconcile(COMMITTED, LIVE);
  ok("planReconcile: carries forward ALL FOUR live sources (none pinned in the toml)", plan.preserved.sort().join(",") === LIVE_SOURCE_NAMES.join(","));
  ok("planReconcile: nothing is 'already present' (the toml pins no source)", plan.alreadyPresent.length === 0);
  ok("planReconcile: counts 4 live sources", plan.liveSourceCount === 4);
  ok("planReconcile: counts 5 non-source live bindings (2 DO + secret + var + DEST_R2)", plan.nonSourceCount === 5);
  ok("planReconcile: the DESTINATION (DEST_R2) is NOT appended as a source", !plan.generatedToml.includes('binding = "DEST_R2"'));
  ok("planReconcile: generated config still contains the committed infra body", plan.generatedToml.includes('class_name = "SchedulerDO"'));
  ok("planReconcile: generated config contains the formerly-pinned KV as a carried source", plan.generatedToml.includes('binding = "SRC_KV_ADMIN_RATE_LIMIT_KV"'));
  ok("planReconcile: generated config contains the new R2 source stanza", plan.generatedToml.includes('[[r2_buckets]]\nbinding = "SRC_R2_media"\nbucket_name = "media"'));

  // THE CORE SAFETY PROPERTY: every live source binding name appears in the generated config, so a
  // deploy built from it cannot drop one.
  const generatedNames = existingBindingNames(plan.generatedToml);
  ok("planReconcile: generated config is a SUPERSET of every live source binding (cannot drop one)", LIVE_SOURCE_NAMES.every((n) => generatedNames.has(n)));
  ok("planReconcile: generated config never adds DEST_R2", !generatedNames.has("DEST_R2"));

  // IDEMPOTENT: feeding the generated config back in carries nothing new (they are now all present).
  const again = planReconcile(plan.generatedToml, LIVE);
  ok("planReconcile: idempotent (re-running over the generated config carries nothing new)", again.preserved.length === 0 && again.alreadyPresent.length === 4);
}

// ---- planReconcile: the dedup path still holds for an IaC-declared source --------------------
// The default toml pins no source, but if an operator DOES declare one via IaC, the reconcile must
// not duplicate it; it is 'already present', and the rest are still carried.
{
  const iac = COMMITTED + '\n[[kv_namespaces]]\nbinding = "SRC_KV_uploads"\nid = "kv00000000000000000000000000000001"\n';
  const plan = planReconcile(iac, LIVE);
  ok("planReconcile (IaC): an in-toml source is 'already present', not duplicated", plan.alreadyPresent.join(",") === "SRC_KV_uploads");
  ok("planReconcile (IaC): the other three sources are still carried", plan.preserved.sort().join(",") === "SRC_D1_app,SRC_KV_ADMIN_RATE_LIMIT_KV,SRC_R2_media");
  const names = existingBindingNames(plan.generatedToml);
  ok("planReconcile (IaC): SRC_KV_uploads appears exactly once in the generated config", (plan.generatedToml.match(/binding = "SRC_KV_uploads"/g) ?? []).length === 1 && names.has("SRC_KV_uploads"));
}

// ---- planReconcile: empty + fail-safe shapes ------------------------------------------------
{
  const empty = planReconcile(COMMITTED, []);
  ok("planReconcile: no live bindings -> nothing carried", empty.preserved.length === 0 && empty.liveSourceCount === 0);
  ok("planReconcile: no live bindings -> generated still contains the committed infra body", empty.generatedToml.includes('class_name = "SchedulerDO"'));

  // A live KV source with no id must STOP the plan (it cannot be rendered faithfully).
  threw("planReconcile: a live source that cannot be rendered THROWS (deploy stops, never silent drop)", () =>
    planReconcile(COMMITTED, [{ type: "kv_namespace", name: "SRC_KV_broken" }]),
  );
}

// ---- deployConfigPath: the env-superset naming contract (sync-bindings.mjs --config) --------
{
  // The default config and every per-env config each derive a DISTINCT .deploy.toml beside it, so an env
  // deploy (--config wrangler.dev.toml) never reads the wrong worker's superset or clobbers the committed file.
  ok("deployConfigPath: the default wrangler.toml -> wrangler.deploy.toml", deployConfigPath("wrangler.toml") === "wrangler.deploy.toml");
  ok("deployConfigPath: an env config wrangler.dev.toml -> wrangler.dev.deploy.toml", deployConfigPath("wrangler.dev.toml") === "wrangler.dev.deploy.toml");
  ok("deployConfigPath: wrangler.uat.toml -> wrangler.uat.deploy.toml", deployConfigPath("wrangler.uat.toml") === "wrangler.uat.deploy.toml");
  ok("deployConfigPath: an absolute path keeps its directory", deployConfigPath("/x/y/wrangler.internal.toml") === "/x/y/wrangler.internal.deploy.toml");
  ok("deployConfigPath: the output is ALWAYS distinct from the input (never overwrites the committed config in place)", deployConfigPath("wrangler.dev.toml") !== "wrangler.dev.toml");
  // A non-.toml path must be refused, not silently mangled -- the guard against writing over a committed config.
  threw("deployConfigPath: a path not ending in .toml THROWS (never risk clobbering)", () => deployConfigPath("wrangler.dev"));
  threw("deployConfigPath: an empty path THROWS", () => deployConfigPath(""));
}

console.log(`\nvalidate-bindings-sync: ${failures === 0 ? "ALL PASS" : `${failures} FAILED`}`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
