// validate-selector-empty-prefix: an empty-string prefix in include or exclude is refused at every
// authority boundary that accepts one, and the reason it must be is demonstrated, not merely asserted.
//
// THE DEFECT. src/sources/selector.ts inScope is a literal prefix test, `!sel.exclude.some((p) =>
// name.startsWith(p))`, and every string starts with the empty string. So `exclude: [""]` puts every
// record out of scope. A downpipe saved that way backs up NOTHING and every run reports success; a
// restore scoped that way plans zero writes and reports success; a blind restore test scoped that way
// verifies nothing and reports a PASS. The honest signal a customer would act on never appears.
//
// WHY IT WAS REACHABLE. The only validation these fields had (config-validate.ts) checked that they were
// ARRAYS, and an array of empty strings is an array. The console filters empties on its way in
// (splitPrefixes) and its import path hardcodes exclude: [], so the screen could never produce this. The
// strictest party in the system was the one an API caller bypasses, and the engine, which is the last
// line and the only one an API caller must pass, was the permissive one. A validation that exists only in
// the client is not a validation.
//
// WHAT THIS FILE PROVES, IN ORDER: that the empty prefix really does empty the scope (so the refusal is
// aimed at a real effect, not a style preference); that the config authority boundary refuses it; that
// the refusal survives the REAL API round trip through handleAdmin and the durable object rather than
// only holding in a direct call to the validator; and that an ordinary selector still saves.
//
// Run: node test/validate-selector-empty-prefix.ts

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";
import { inScope, selectorPrefixFault } from "../src/sources/selector.ts";
import { AUD, makeScheduler, makeSigner, TEAM } from "./validate-rbac-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function threw(fn: () => void): string | null {
  try {
    fn();
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

function configWith(sel: { include: unknown[]; exclude: unknown[] }): DownpipeConfig {
  return {
    id: "empty-prefix-probe",
    name: "empty prefix probe",
    cadenceSeconds: 3600,
    enabled: true,
    source: { type: "kv", binding: "KV_probe", include: sel.include, exclude: sel.exclude },
  } as unknown as DownpipeConfig;
}

async function main(): Promise<void> {
  console.log("-- the effect the refusal is aimed at: an empty exclude prefix empties the scope --");
  // This is the assertion that makes the rest of the file worth running. If inScope did not behave this
  // way the refusal would be pedantry; it does, so the refusal is a safety property.
  ok('inScope: exclude [""] puts an ordinary record OUT of scope', inScope("kv/site-config", { include: [], exclude: [""] }) === false);
  ok('inScope: exclude [""] puts EVERY record out of scope, including the empty name', ["a", "zzz", "kv/x/y", ""].every((n) => inScope(n, { include: [], exclude: [""] }) === false));
  ok("inScope: the same selector without the empty prefix keeps the record in scope", inScope("kv/site-config", { include: [], exclude: [] }) === true);
  ok('inScope: a real prefix still excludes only what it names', inScope("kv/site-config", { include: [], exclude: ["kv/other"] }) === true && inScope("kv/other/x", { include: [], exclude: ["kv/other"] }) === false);

  console.log("\n-- selectorPrefixFault: the rule itself --");
  ok('exclude [""] is a fault', selectorPrefixFault([], [""]) !== null);
  ok("the exclude message says the whole source would go out of scope, not merely that it is invalid", /out of scope/.test(selectorPrefixFault([], [""]) ?? ""));
  ok('include [""] is a fault too (one rule, not two)', selectorPrefixFault([""], []) !== null);
  ok("a non-string entry is a fault (an array bounds the container, not the contents)", selectorPrefixFault([], [7]) !== null);
  ok("an ordinary selector is not a fault", selectorPrefixFault(["kv/keep"], ["kv/drop"]) === null);
  ok("empty lists are not a fault (the documented default)", selectorPrefixFault([], []) === null);
  ok('the empty prefix is caught wherever it sits in the list, not only first', selectorPrefixFault([], ["kv/drop", ""]) !== null);

  console.log("\n-- the config authority boundary refuses it --");
  const excMsg = threw(() => validateConfig(configWith({ include: [], exclude: [""] })));
  ok('validateConfig refuses a source whose exclude contains ""', excMsg !== null);
  ok("the refusal names the field and what the empty prefix would have meant", /source\.exclude/.test(excMsg ?? "") && /out of scope/.test(excMsg ?? ""));
  ok('validateConfig refuses a source whose include contains ""', threw(() => validateConfig(configWith({ include: [""], exclude: [] }))) !== null);
  ok("validateConfig still accepts an ordinary selector", threw(() => validateConfig(configWith({ include: ["kv/a"], exclude: ["kv/b"] }))) === null);
  ok("validateConfig still accepts the empty-list default", threw(() => validateConfig(configWith({ include: [], exclude: [] }))) === null);

  console.log("\n-- the REAL API round trip, because a code read is not a round trip --");
  const signer = await makeSigner();
  const sched = makeScheduler();
  const env = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, WORKER_NAME: "downpipe-engine" }) as unknown as Env;
  const call = async (email: string, method: string, path: string, body?: unknown): Promise<Response> =>
    handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { "cf-access-jwt-assertion": await signer.tokenFor(email), "content-type": "application/json", origin: "https://engine.example" },
        ...(method === "GET" ? {} : { body: JSON.stringify(body ?? {}) }),
      }),
      env(),
    );
  const OWNER = "empty-prefix-owner@acme.example";
  await call(OWNER, "GET", "/admin/whoami"); // bootstraps the Owner

  const base = { id: "empty-prefix-e2e", name: "empty prefix e2e", cadenceSeconds: 3600, enabled: true };
  const bad = await call(OWNER, "POST", "/admin/downpipes", { ...base, source: { type: "kv", binding: "KV_probe", include: [], exclude: [""] } });
  const badText = await bad.text();
  ok("POST /downpipes with an empty exclude prefix is refused 400 through the real router and DO", bad.status === 400);
  ok("the API refusal carries the message a customer can act on", /out of scope/.test(badText));

  // And it did not land: the fleet must not be holding a downpipe that backs nothing up.
  const listed = (await (await call(OWNER, "GET", "/admin/downpipes")).json()) as Array<{ config?: { id?: string } }>;
  ok("the refused downpipe was NOT stored", !listed.some((d) => d.config?.id === "empty-prefix-e2e"));

  const good = await call(OWNER, "POST", "/admin/downpipes", { ...base, source: { type: "kv", binding: "KV_probe", include: [], exclude: ["kv/skip"] } });
  await good.text();
  ok("an ordinary selector still saves through the same route (the refusal is narrow)", good.status === 200);

  console.log("\n-- the restore surfaces refuse it too, where a zero-record run reports SUCCESS --");
  const RUN_ID = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
  for (const path of ["/admin/restore", "/admin/restore/request", "/admin/restore/verify"]) {
    const r = await call(OWNER, "POST", path, { runId: RUN_ID, confirm: false, reason: "probe", include: [], exclude: [""] });
    const t = await r.text();
    ok(`POST ${path} with an empty exclude prefix is refused 400`, r.status === 400 && /out of scope/.test(t));
  }

  signer.restoreFetch();

  console.log(failures === 0 ? "\nSELECTOR EMPTY PREFIX PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
