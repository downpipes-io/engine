// Pre-deploy binding reconcile — the IO shell. Reads the engine's LIVE bindings from the
// Cloudflare script-settings API and writes a deploy config (wrangler.deploy.toml) that is the
// committed wrangler.toml PLUS every live source binding, so `wrangler deploy -c wrangler.deploy.toml`
// cannot drop a source attached from the console. The pure core and the full rationale are in
// src/admin/bindings-sync.ts.
//
// FAIL-SAFE. If it cannot PROVE what the live sources are, it refuses to write a config and exits
// non-zero, so deploy.sh (set -e) STOPS rather than deploy a binding-dropping config. The honest
// exceptions are handled explicitly:
//   * the worker does not exist yet (HTTP 404) -> a first deploy, nothing to preserve -> proceed
//     with wrangler.toml unchanged;
//   * the operator GENUINELY intends a reset / has no sources -> DOWNPIPE_ALLOW_BINDING_RESET=1.
//
// Run directly:  node scripts/sync-bindings.mjs    (wired into scripts/deploy.sh before deploy)

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { planReconcile, deployConfigPath } from "../src/admin/bindings-sync.ts";

const execFileAsync = promisify(execFile);

const CF_API = "https://api.cloudflare.com/client/v4";
const engineRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// --config <path> (default wrangler.toml) selects which committed toml to reconcile, so a deploy against a
// non-default config (a second worker name) preserves that worker's own live sources. The generated
// superset is <config>.deploy.toml; the prove-or-refuse guard is identical for every config.
const argv = process.argv.slice(2);
const configArg =
  (() => {
    const i = argv.indexOf("--config");
    if (i >= 0 && argv[i + 1]) return argv[i + 1];
    const eq = argv.find((a) => a.startsWith("--config="));
    return eq ? eq.slice("--config=".length) : "wrangler.toml";
  })();
const COMMITTED = configArg.includes("/") ? configArg : join(engineRoot, configArg);
let GENERATED;
try {
  GENERATED = deployConfigPath(COMMITTED);
} catch (e) {
  console.error(`\n[sync-bindings] REFUSING: --config "${configArg}" ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
}

function die(msg) {
  console.error(`\n[sync-bindings] REFUSING TO DEPLOY: ${msg}\n`);
  process.exit(1);
}
function note(msg) {
  console.log(`[sync-bindings] ${msg}`);
}

const allowReset = process.env.DOWNPIPE_ALLOW_BINDING_RESET === "1";
const token = (process.env.CLOUDFLARE_API_TOKEN ?? process.env.CF_API_TOKEN ?? "").trim();
const accountId = (process.env.CLOUDFLARE_ACCOUNT_ID ?? process.env.CF_ACCOUNT_ID ?? "").trim();

const committed = await readFile(COMMITTED, "utf8").catch(() => die(`could not read ${COMMITTED}`));
const scriptName = committed.match(/^[ \t]*name[ \t]*=[ \t]*["']([^"']+)["']/m)?.[1] ?? "downpipe-engine";

// cannotProve is the ONE escape when we cannot read the live bindings: with DOWNPIPE_ALLOW_BINDING_RESET=1 the
// operator has explicitly accepted a reset (a first deploy / no sources), so deploy the committed config as-is;
// otherwise REFUSE (fail-safe -- never ship a config that might silently drop an attached source). Note this
// only fires on a genuine read FAILURE: a successful read (with a token OR via wrangler) always builds the
// superset and preserves sources, so setting allowReset can never drop a source the read could have preserved.
async function cannotProve(reason) {
  if (allowReset) {
    note(`${reason}\n  DOWNPIPE_ALLOW_BINDING_RESET=1: deploying ${configArg} AS-IS. Any console-attached source not in it WILL be dropped.`);
    await writeFile(GENERATED, committed, "utf8");
    process.exit(0);
  }
  die(`${reason}\n  Refusing to deploy a config that might drop your attached sources. Override (first deploy /\n  a deliberate reset with no sources to preserve): DOWNPIPE_ALLOW_BINDING_RESET=1.`);
}

// Read the LIVE bindings so the deploy can PROVE it preserves every console-attached source. Two ways in, same
// prove-or-refuse guard: an explicit token (CLOUDFLARE_API_TOKEN -> the Cloudflare settings API), or the
// operator's `wrangler` session (OAuth -> `wrangler versions view`) when no token is set. The latter is what
// makes an ENV deploy authenticated only by `wrangler login` (no separate token) still binding-safe. Either
// path returns an array of live bindings, or the sentinel NO_WORKER (a not-yet-deployed worker: first deploy).
const NO_WORKER = Symbol("no-worker");

async function readViaSettingsApi() {
  const url = `${CF_API}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`;
  let resp;
  try {
    resp = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  } catch (e) {
    die(`could not reach the Cloudflare API to read "${scriptName}"'s live bindings (${e instanceof Error ? e.message : String(e)}). Nothing was deployed.`);
  }
  if (resp.status === 404) return NO_WORKER;
  const body = await resp.json().catch(() => null);
  if (!resp.ok || body?.success !== true) {
    const why = body?.errors?.map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${resp.status}`;
    await cannotProve(
      `could not read "${scriptName}"'s live bindings (Cloudflare: ${why}).\n` +
        `  The token needs Workers Scripts:Edit on account ${accountId} (the "Edit Cloudflare Workers" template),\n` +
        "  scoped to the account that holds the worker.",
    );
  }
  const b = body.result?.bindings;
  if (!Array.isArray(b)) die(`Cloudflare returned settings without a readable bindings list for "${scriptName}"; refusing to deploy blind.`);
  return b;
}

async function readViaWrangler() {
  // Uses the operator's `wrangler login` session (no separate token). `wrangler versions view --json` returns
  // the SAME {name,type,namespace_id,...} binding shape planReconcile reads. First find the ACTIVE version.
  const wr = async (args) => {
    try {
      const { stdout } = await execFileAsync("npx", ["--prefix", engineRoot, "wrangler", ...args], { cwd: engineRoot, maxBuffer: 16 * 1024 * 1024 });
      return { ok: true, stdout };
    } catch (e) {
      return { ok: false, err: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message ?? ""}` };
    }
  };
  const status = await wr(["deployments", "status", "--config", COMMITTED]);
  if (!status.ok) {
    if (/not found|does not exist|script_not_found|\b10007\b/i.test(status.err)) return NO_WORKER;
    await cannotProve(`could not read the active deployment of "${scriptName}" via wrangler (are you \`wrangler login\`'d, on the right account?).\n  ${status.err.trim().slice(0, 300)}`);
  }
  const versionId = status.stdout.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/)?.[0];
  if (!versionId) await cannotProve(`could not find the active version id of "${scriptName}" in wrangler output.`);
  const view = await wr(["versions", "view", versionId, "--config", COMMITTED, "--json"]);
  if (!view.ok) await cannotProve(`could not read version ${versionId} of "${scriptName}" via wrangler.\n  ${view.err.trim().slice(0, 300)}`);
  let parsed;
  try {
    parsed = JSON.parse(view.stdout.slice(view.stdout.indexOf("{")));
  } catch {
    die(`wrangler versions view did not return parseable JSON for "${scriptName}"; refusing to deploy blind.`);
  }
  const b = (parsed.resources && parsed.resources.bindings) || parsed.bindings;
  if (!Array.isArray(b)) die(`wrangler returned no readable bindings list for "${scriptName}"; refusing to deploy blind.`);
  return b;
}

const authed = Boolean(token && accountId);
if (!authed) note(`no CLOUDFLARE_API_TOKEN set; reading "${scriptName}"'s live bindings via your \`wrangler\` session.`);
const liveBindings = authed ? await readViaSettingsApi() : await readViaWrangler();
if (liveBindings === NO_WORKER) {
  note(`worker "${scriptName}" does not exist yet: first deploy, nothing to preserve. Using ${configArg} as-is.`);
  await writeFile(GENERATED, committed, "utf8");
  process.exit(0);
}
const bindings = liveBindings;

let plan;
try {
  plan = planReconcile(committed, bindings);
} catch (e) {
  die(`a live source binding could not be rendered for deploy (${e instanceof Error ? e.message : String(e)}). Refusing to drop it silently.`);
}

await writeFile(GENERATED, plan.generatedToml, "utf8");
note(`live bindings read: ${plan.liveSourceCount} source(s), ${plan.nonSourceCount} engine/infra binding(s).`);
if (plan.preserved.length > 0) note(`carried forward (a bare \`wrangler deploy\` WOULD HAVE DROPPED these): ${plan.preserved.join(", ")}`);
if (plan.alreadyPresent.length > 0) note(`already in ${configArg} (left as-is): ${plan.alreadyPresent.join(", ")}`);
if (plan.liveSourceCount === 0) note("no source bindings on the live worker yet.");
note(`wrote ${GENERATED}. Deploy with: npx wrangler deploy -c ${GENERATED.replace(engineRoot + "/", "")}`);
