// The console floor holds on the engine that has to enforce it (a cross-repository compatibility rule 9,
// playbook COMPATIBILITY.md 3.4 "floors tested").
//
// THE CASE. Console 0.2.7 is signed into the channel with components.console.minEngineVersion "0.3.7"
// (tools/publish-channel.mjs --console-min-engine-version), because it speaks key-posture-ack/v3 and engine
// 0.3.5 refuses that. The refusal has to happen on the OLD engine: an engine at 0.3.5, offered that channel,
// must refuse the console component cleanly and deploy nothing.
//
// HOW. The channel is built by tools/publish-channel.mjs itself, run as the CLI it is (its module body runs
// main(), so it cannot be imported), with a throwaway signer seed, an engine 0.3.7 artefact and a strictly
// parseable console bundle at 0.2.7. The tool self-verifies what it signs with the engine's own verifyChannel.
// test/console-floor-scenario.ts then runs the real admin router against that channel, once per running engine
// version, each in its own process (ENGINE_VERSION is a module constant, so one process is one version). It
// records every Cloudflare API call the router makes.
//
// WHAT IS GRADED at a running engine of 0.3.5:
//   1. GET /admin/updates shows the console row carrying the 0.3.7 floor from the signed channel.
//   2. The plan (a console-only dry run) refuses at the compat-guard step with the documented reason. The plan
//      for both components shows the engine dry-run and the console applying after the engine reaches 0.3.7,
//      because that apply installs engine 0.3.7 first and holds the console until it settles.
//   3. The live console apply refuses the same way, and the Cloudflare API sees ZERO write calls.
//   4. Nothing is recorded as applied: lastConsole stays empty, floors.console stays unset, no console entry
//      reaches the update history, no update-applied audit is written. One update-refused audit event, outcome
//      denied, names the floor and the running version. That is the documented posture: a refusal is audited
//      and never clobbers the last-outcome records ("Refused, nothing changed").
// THE CONTROL, so the test can fail: the SAME channel against a running engine of 0.3.7 plans the console
// update, applies it, and the Cloudflare API sees the upload and promote writes. If the write counter or the
// version override were broken, the control would not see them.
//
// The override itself is checked: each result reports the ENGINE_VERSION the router imported, and a result
// whose version is not the one requested is a failure, never a pass.
//
// Run: node test/validate-console-floor-refusal.ts

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const TOOL = join(HERE, "..", "tools", "publish-channel.mjs");
const SCENARIO = join(HERE, "console-floor-scenario.ts");
const FLOOR = "0.3.7";
const CONSOLE_VERSION = "0.2.7";
const BELOW = "0.3.5";
const COMPAT_REASON = new RegExp(`requires engine version ${FLOOR.replace(/\./g, "\\.")} or newer, but this engine is ${BELOW.replace(/\./g, "\\.")}; update the engine first`);

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A console bundle the engine's strict parser accepts: format, version, shell worker, config, and each asset
// with its sha256.
function consoleBundle(version: string): string {
  const shell = Buffer.from("export default { fetch() { return new Response('shell'); } };");
  const asset = Buffer.from("<!doctype html><h1>console</h1>");
  return JSON.stringify({
    format: "downpipe-console-bundle/1",
    version,
    worker: { mainModule: "worker.js", sourceB64: shell.toString("base64") },
    config: { compatibilityDate: "2026-06-01", runWorkerFirst: true },
    assets: [{ path: "/index.html", contentType: "text/html; charset=utf-8", sha256: createHash("sha256").update(asset).digest("hex"), b64: asset.toString("base64") }],
  });
}

interface Scenario {
  override: string;
  rewrote: boolean;
  engineVersion: string;
  updates: { components?: { console?: { recommendedVersion?: string; minEngineVersion?: string } } };
  planConsole: { status: number; body: { outcome?: string; component?: string; reason?: string; steps?: { step: string; ok: boolean }[] } };
  planBoth: { status: number; body: { outcome?: string; componentResults?: { component?: string; outcome?: string; reason?: string }[] } };
  writesBeforeLive: number;
  live: { status: number; body: { outcome?: string; component?: string; reason?: string; toVersion?: string; steps?: { step: string; ok: boolean }[] } };
  writesAfterLive: number;
  cfCalls: { method: string; path: string }[];
  status: { lastConsole?: { outcome?: string } | null; floors?: { console?: string }; history?: { component?: string }[] };
  refusedAudit: { events?: { outcome?: string; target?: { detail?: string } }[] };
  appliedAudit: { events?: { target?: { detail?: string } }[] };
  unexpected: string[];
}

function runScenario(fixture: string, version: string): Scenario {
  const out = execFileSync(process.execPath, [SCENARIO, fixture, version], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const last = out.trim().split("\n").pop() ?? "";
  return JSON.parse(last) as Scenario;
}

async function main(): Promise<void> {
  const fixture = mkdtempSync(join(tmpdir(), "console-floor-"));
  try {
    // ---- the channel, built and signed by the publisher itself ----
    writeFileSync(join(fixture, "engine.mjs"), `export default { fetch() { return new Response("engine ${FLOOR}"); } };\n`);
    writeFileSync(join(fixture, "console.json"), consoleBundle(CONSOLE_VERSION));
    const seed = Buffer.concat([createHash("sha256").update("throwaway-edseed").digest(), createHash("sha256").update("throwaway-mldsaseed").digest()]).toString("base64url");
    const published = JSON.parse(
      execFileSync(process.execPath, [
        TOOL,
        "--key", seed,
        "--version", FLOOR,
        "--bundle", join(fixture, "engine.mjs"),
        "--url", `https://update.downpipes.io/engine-${FLOOR}.mjs`,
        "--risk-class", "routine",
        "--console-bundle", join(fixture, "console.json"),
        "--console-url", `https://update.downpipes.io/console-${CONSOLE_VERSION}.json`,
        "--console-risk-class", "routine",
        "--console-min-engine-version", FLOOR,
        "--sequence", "1",
        "--issued-at", "2026-09-27T00:00:00.000Z",
        "--out", join(fixture, "channel.json"),
        "--out-sig", join(fixture, "channel.json.sig"),
      ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }),
    ) as { channel: string; updateSignerPublic: string };
    writeFileSync(join(fixture, "update-signer-public.txt"), `${published.updateSignerPublic}\n`);
    const doc = JSON.parse(published.channel) as { artefacts: { version: string }[]; components: { console?: { version?: string; minEngineVersion?: string } } };
    console.log("\nthe channel, from tools/publish-channel.mjs:");
    ok(`the signed channel carries console ${CONSOLE_VERSION} with minEngineVersion ${FLOOR}`, doc.components.console?.version === CONSOLE_VERSION && doc.components.console?.minEngineVersion === FLOOR);
    ok("the console artefact is in components only, never in artefacts[]", doc.artefacts.every((a) => a.version === FLOOR));

    // ---- engine 0.3.5: the floor refuses, nothing is deployed ----
    console.log(`\na running engine of ${BELOW} offered that channel:`);
    const low = runScenario(fixture, BELOW);
    ok(`the scenario ran as engine ${BELOW} (ENGINE_VERSION imported ${low.engineVersion}, source rewritten ${low.rewrote})`, low.rewrote && low.engineVersion === BELOW);
    ok("no fetch left the stubbed channel host and Cloudflare API", low.unexpected.length === 0);
    ok(`GET /admin/updates shows the console row with its ${FLOOR} floor`, low.updates.components?.console?.recommendedVersion === CONSOLE_VERSION && low.updates.components?.console?.minEngineVersion === FLOOR);
    const pc = low.planConsole.body;
    ok(`the console plan refuses at the compat guard: ${pc.reason ?? "(no reason)"}`, low.planConsole.status === 200 && pc.component === "console" && pc.outcome === "refused" && COMPAT_REASON.test(pc.reason ?? "") && (pc.steps ?? []).some((s) => s.step === "compat-guard" && !s.ok));
    const pb = low.planBoth.body.componentResults ?? [];
    ok(`the plan for both components: the engine would move, and the console applies after the engine reaches ${FLOOR}`, low.planBoth.status === 200 && low.planBoth.body.outcome === "dry-run" && pb[0]?.component === "engine" && pb[0]?.outcome === "dry-run" && pb[1]?.component === "console" && pb[1]?.outcome === "dry-run" && pb[1]?.reason === `the console component applies after the engine reaches ${FLOOR}`);
    const lv = low.live.body;
    ok("the live console apply refuses with the same reason", low.live.status === 200 && lv.component === "console" && lv.outcome === "refused" && COMPAT_REASON.test(lv.reason ?? "") && lv.toVersion === undefined);
    ok(`the Cloudflare API saw ZERO write calls (${low.writesAfterLive}; every call: ${low.cfCalls.map((c) => `${c.method} ${c.path}`).join(", ") || "none"})`, low.writesBeforeLive === 0 && low.writesAfterLive === 0);
    ok("lastConsole stays empty and floors.console stays unset", (low.status.lastConsole ?? null) === null && low.status.floors?.console === undefined);
    ok("no console entry reaches the update history", !(low.status.history ?? []).some((h) => h.component === "console"));
    ok("no update-applied audit event was written", (low.appliedAudit.events ?? []).length === 0);
    const refused = (low.refusedAudit.events ?? []).filter((e) => /^console: /.test(e.target?.detail ?? ""));
    ok(`one update-refused audit event, outcome denied, names the floor and the running version: ${refused[0]?.target?.detail ?? "(none)"}`, refused.length === 1 && refused[0]?.outcome === "denied" && /requires engine version 0\.3\.7 or newer, but this engine is 0\.3\.5/.test(refused[0]?.target?.detail ?? ""));

    // ---- CONTROL, engine 0.3.7: the same channel plans and applies the console ----
    console.log(`\nCONTROL: the same channel against a running engine of ${FLOOR}:`);
    const high = runScenario(fixture, FLOOR);
    ok(`the scenario ran as engine ${FLOOR} (ENGINE_VERSION imported ${high.engineVersion})`, high.rewrote && high.engineVersion === FLOOR);
    ok("the console plan is a dry run with the compat guard passed", high.planConsole.body.outcome === "dry-run" && !(high.planConsole.body.steps ?? []).some((s) => s.step === "compat-guard"));
    ok("the live console apply lands", high.live.body.outcome === "applied" && String(high.live.body.toVersion ?? "").startsWith("cv-new-"));
    ok(`the Cloudflare API saw the upload and promote writes (${high.writesAfterLive}), so the counter can count`, high.writesBeforeLive === 0 && high.writesAfterLive >= 2 && high.cfCalls.some((c) => c.method === "POST" && c.path.endsWith("/deployments")));
    ok(`floors.console advanced to ${CONSOLE_VERSION} and lastConsole records the apply`, high.status.floors?.console === CONSOLE_VERSION && high.status.lastConsole?.outcome === "applied");
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }

  console.log(failures === 0 ? `\nPASS console-floor-refusal: ${checks} checks` : `\nFAIL console-floor-refusal: ${failures} of ${checks} checks failed`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
