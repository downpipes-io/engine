// validate-sources-enable: the ADDED token-source set (cf-config / workers / stream / images /
// artifacts) the create-downpipe wizard gates on. Covers POST /admin/sources/enable (owner-only,
// SET semantics, deduped, an unknown type REFUSED), its reflection in discovery-status and the discover
// addedSources field, the DO's own owner re-check (defence in depth, router-bypassed), and the
// no-discovery-token refusal.
//
// Run: node test/validate-sources-enable.ts

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { validateConfig, SELECTABLE_TOKEN_SOURCE_TYPES } from "../src/sched/config-validate.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const sorted = (xs: string[] | undefined): string => JSON.stringify((xs ?? []).slice().sort());

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor, subjectOf } = signer;
  const s = makeScheduler();
  const accEnv = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-token-se" } as unknown as Env;
  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accEnv);
  };

  const OWNER = "owner-se@acme.example";
  const VIEWER = "viewer-se@acme.example";

  // Bootstrap the first Access caller as Owner.
  const who = (await (await call(OWNER, "GET", "/admin/whoami")).json()) as { role: string };
  ok("bootstrap: the first Access caller is Owner", who.role === "owner");

  // Seed a console-set discovery config directly (bypassing the live token verify), one browsed account.
  await s.storage.put(DISCOVERY_KEY, {
    token: "cfat_seeded_discovery_token_value_123456",
    setAt: 1,
    setBy: OWNER,
    accountsSeen: [{ id: "acct-1", name: "Acct One" }],
    selected: ["acct-1"],
    engineAccountId: "acct-1",
  });

  // (1a) A type outside the closed set is REFUSED (POSTCONDITION), not filtered out with a 200: silently
  // dropping it would read to the customer as "I added it and it never appeared". Nothing legitimate sits
  // outside the set.
  const enBad = await call(OWNER, "POST", "/admin/sources/enable", { sources: ["workers", "stream", "bogus", "workers"] });
  ok("an unknown source type is refused 400, not dropped with a success", enBad.status === 400);
  // The EXACT message, not the status: a mutant keeping the 400 and gutting only the wording survives a
  // contains-the-value check, because the template around the gutted phrase still carries the value.
  ok(
    "the refusal carries the exact message, naming the value and the choices",
    String(((await enBad.json()) as { error?: unknown }).error ?? "") === `not a source type this engine can add: bogus. Choose from ${SELECTABLE_TOKEN_SOURCE_TYPES.join(", ")}`,
  );
  // (1) Owner adds workers + stream (+ a duplicate): SET semantics, deduped.
  const en1 = await call(OWNER, "POST", "/admin/sources/enable", { sources: ["workers", "stream", "workers"] });
  ok("owner POST /sources/enable returns 200", en1.status === 200);
  const en1b = (await en1.json()) as { enabledSources?: string[] };
  ok("the response reflects the deduped set", sorted(en1b.enabledSources) === sorted(["stream", "workers"]));

  // (2) discovery-status reflects it (presence-only read, no live fetch).
  const st = (await (await call(OWNER, "GET", "/admin/sources/discovery-status")).json()) as { enabledSources?: string[] };
  ok("discovery-status carries enabledSources", sorted(st.enabledSources) === sorted(["stream", "workers"]));

  // (3) the discover route echoes addedSources when a console config is present (account listing fails
  //     open against the test fetch stub, so the route still answers).
  const disc = await call(OWNER, "GET", "/admin/sources/discover");
  ok("discover returns 200 with a console config present", disc.status === 200);
  const discb = (await disc.json()) as { addedSources?: string[]; tokenPresent?: boolean };
  ok("discover echoes addedSources (the wizard's gate input)", sorted(discb.addedSources) === sorted(["stream", "workers"]));

  // (4) a non-owner is refused at the router gate (keys.ceremony).
  const vp = await call(VIEWER, "POST", "/admin/sources/enable", { sources: ["images"] });
  ok("a non-owner is refused at the router gate (403)", vp.status === 403);

  // (5) the DO's OWN owner re-check (defence in depth, router-bypassed direct DO call).
  const viewerCaller: Caller = { method: "access", email: VIEWER, subject: subjectOf(VIEWER), role: "viewer", groups: [] };
  const doDirect = await s.stub.fetch("https://scheduler.internal/sources/enable", {
    method: "POST",
    headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(viewerCaller) },
    body: JSON.stringify({ sources: ["images"] }),
  });
  ok("the DO refuses a non-owner directly (403, defence in depth)", doDirect.status === 403);

  // (6) an empty set clears it (the Remove-all path).
  const en0 = await call(OWNER, "POST", "/admin/sources/enable", { sources: [] });
  ok("owner can clear the set (200)", en0.status === 200);
  const st0 = (await (await call(OWNER, "GET", "/admin/sources/discovery-status")).json()) as { enabledSources?: string[] };
  ok("the cleared set reads empty", (st0.enabledSources ?? []).length === 0);

  // (7a) The ADD gate and the SELECT gate must agree, type for type.
  //
  // An operator can only usefully add a source type a downpipe config may then select. A type this route
  // KEEPS but config-validate REFUSES is a control that appears to work and protects nothing; a type the
  // route drops but the validator accepts is a source nobody can reach. Both derive from one exported list.
  //
  // This asks each authority BEHAVIOURALLY rather than reading either file, so a source-text scanner cannot
  // be fooled by a comment that merely names an excluded value. Calling the route and calling the validator
  // is the only way to be sure they still agree.
  //
  // typeAccepted discriminates on the TYPE refusal specifically, because validateSource runs LAST: a probe
  // config that trips validateIdentity first throws a message that is not the type refusal, which would read
  // as "the type was accepted" for every type alike. So the config below is otherwise VALID (the identity,
  // cadence and enabled fields the earlier validators want) and differs only in source.type.
  const accountId = "0123456789abcdef0123456789abcdef";
  const typeAccepted = (t: string): boolean => {
    try {
      validateConfig({ id: "dp-gate-probe", name: "gate probe", cadenceSeconds: 3600, enabled: true, source: { type: t, accountId, include: [], exclude: [] } } as unknown as DownpipeConfig);
      return true;
    } catch (e) {
      return !/^source\.type must be/.test(e instanceof Error ? e.message : String(e));
    }
  };
  // Positive control for the discriminator itself: a type that IS accepted must read as accepted, and the
  // one refusal we can name unconditionally (a type no build has ever accepted) must read as refused.
  ok("typeAccepted discriminates: an accepted type reads accepted", typeAccepted("workers") === true);
  ok("typeAccepted discriminates: an unknown type reads refused", typeAccepted("no-such-source-type") === false);
  await s.storage.put(DISCOVERY_KEY, {
    token: "cfat_seeded_discovery_token_value_123456",
    setAt: 1,
    setBy: OWNER,
    accountsSeen: [{ id: "acct-1", name: "Acct One" }],
    selected: ["acct-1"],
    engineAccountId: "acct-1",
  });
  const TOKEN_TYPES = ["cf-config", "workers", "stream", "images", "artifacts"] as const;
  let checked = 0;
  for (const t of TOKEN_TYPES) {
    const r = (await (await call(OWNER, "POST", "/admin/sources/enable", { sources: [t] })).json()) as { enabledSources?: string[] };
    const addable = (r.enabledSources ?? []).includes(t);
    ok(`the add gate and the select gate agree on "${t}" (add=${addable})`, addable === typeAccepted(t));
    checked++;
  }
  // Guard against the check going vacuous: a loop over an empty list asserts nothing and still prints a pass.
  ok("every token source type was put to both gates", checked === TOKEN_TYPES.length && checked === 5);

  // (7) with no discovery config, enabling is a clean 400 (a token source is read with the token).
  await s.storage.delete(DISCOVERY_KEY);
  const noTok = await call(OWNER, "POST", "/admin/sources/enable", { sources: ["workers"] });
  ok("with no discovery token, enable is a clean 400", noTok.status === 400);

  signer.restoreFetch();
  console.log(failures === 0 ? "\nVALIDATE-SOURCES-ENABLE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
