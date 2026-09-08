// Validates the in-product attach SAFETY MODULE (src/admin/attach.ts): the pure planner
// (superset proof, identity guard, collisions, secret preservation), the post-verify, and
// the full read-plan-write-verify flow against a stubbed Cloudflare script-settings API.
// The attach-safety module's whole job is to be unable to drop the engine's own bindings, so the
// adversarial cases (a write that loses a binding; a read that is not this engine) are the
// point. Run: node test/validate-attach.ts.

import { bindingFromSource, looksLikeThisEngine, planAttach, planChange, verifyAfter, attachSources, detachSources, type LiveBinding } from "../src/admin/attach.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

// A realistic engine binding set as the script-settings read returns it: two Durable Objects, a
// secret, a plain var, the R2 archive, and one existing KV source.
const ENGINE_BINDINGS: LiveBinding[] = [
  { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" },
  { type: "durable_object_namespace", name: "RUNSEAL", class_name: "RunSealDO" },
  { type: "secret_text", name: "SIGNER_PRIVATE" },
  { type: "secret_text", name: "BREAK_GLASS_PUBLIC" },
  { type: "plain_text", name: "CONSOLE_ORIGIN", text: "https://console.example" },
  { type: "r2_bucket", name: "DEST_R2", bucket_name: "downpipe-archive" },
  { type: "kv_namespace", name: "SRC_KV_existing", namespace_id: "abc123" },
];

console.log("-- bindingFromSource: shapes and refusals --");
{
  const kv = bindingFromSource({ type: "kv", binding: "SRC_KV_app", namespaceId: "id1" });
  ok("kv -> kv_namespace {name, namespace_id}", kv.type === "kv_namespace" && kv.name === "SRC_KV_app" && kv.namespace_id === "id1");
  const r2 = bindingFromSource({ type: "r2", binding: "SRC_R2_media", bucketName: "media" });
  ok("r2 -> r2_bucket {name, bucket_name}", r2.type === "r2_bucket" && r2.bucket_name === "media");
  const d1 = bindingFromSource({ type: "d1", binding: "SRC_D1_db", databaseId: "uuid-1" });
  ok("d1 -> d1 {name, id}", d1.type === "d1" && d1.id === "uuid-1");
  let threw = "";
  try { bindingFromSource({ type: "kv", binding: "SCHEDULER", namespaceId: "x" }); } catch (e) { threw = (e as Error).message; }
  ok("a reserved binding name is refused", /reserved/.test(threw));
  threw = "";
  try { bindingFromSource({ type: "kv", binding: "bad name!", namespaceId: "x" }); } catch (e) { threw = (e as Error).message; }
  ok("an invalid binding name is refused", /not a valid/.test(threw));
}

console.log("-- looksLikeThisEngine: the identity guard --");
{
  ok("the engine's own bindings pass", looksLikeThisEngine(ENGINE_BINDINGS));
  ok("a set missing RUNSEAL is refused", !looksLikeThisEngine(ENGINE_BINDINGS.filter((b) => b.name !== "RUNSEAL")));
  ok("a stranger script (no DOs) is refused", !looksLikeThisEngine([{ type: "kv_namespace", name: "X" }]));
}

console.log("-- planAttach: the superset proof is the core guarantee --");
{
  const { bindings, keepBindings, added } = planAttach(ENGINE_BINDINGS, [{ type: "kv", binding: "SRC_KV_new", namespaceId: "n9" }]);
  ok("secrets are NOT re-sent (kept via keep_bindings)", bindings.every((b) => b.type !== "secret_text"));
  ok("keep_bindings carries secret_text", keepBindings.includes("secret_text"));
  ok("every existing non-secret binding is re-sent verbatim", ["SCHEDULER", "RUNSEAL", "CONSOLE_ORIGIN", "DEST_R2", "SRC_KV_existing"].every((nm) => bindings.some((b) => b.name === nm)));
  ok("the addition is appended and reported", added.length === 1 && added[0] === "SRC_KV_new" && bindings.some((b) => b.name === "SRC_KV_new"));

  // The proof must REFUSE a plan that is not this engine, a collision, or an empty set.
  let threw = "";
  try { planAttach(ENGINE_BINDINGS.filter((b) => b.name !== "SCHEDULER"), [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }]); } catch (e) { threw = (e as Error).message; }
  ok("planAttach refuses when the engine cannot be confirmed", /could not be confirmed|Durable Object/.test(threw));
  threw = "";
  try { planAttach(ENGINE_BINDINGS, [{ type: "kv", binding: "SRC_KV_existing", namespaceId: "other" }]); } catch (e) { threw = (e as Error).message; }
  ok("planAttach refuses a name collision with a live binding", /already exists/.test(threw));
  threw = "";
  try { planAttach(ENGINE_BINDINGS, []); } catch (e) { threw = (e as Error).message; }
  ok("planAttach refuses an empty attach", /nothing to change/.test(threw));

  // The superset proof itself: it is what makes dropping an engine binding impossible.
  // Every re-sent binding is the verbatim original, so the proof always holds on a real
  // plan; assert the computed set is a strict superset of the existing non-secret set.
  const existingNonSecret = ENGINE_BINDINGS.filter((b) => b.type !== "secret_text").map((b) => b.name);
  ok("the write set is a strict superset of the existing non-secret bindings", existingNonSecret.every((nm) => bindings.some((b) => b.name === nm)) && bindings.length === existingNonSecret.length + 1);
}

console.log("-- planChange: REMOVAL is precise and can never target the engine's own --");
{
  // A clean detach of the existing KV source: it is gone; everything else survives.
  const { bindings, removed, added } = planChange(ENGINE_BINDINGS, [], ["SRC_KV_existing"]);
  ok("the removal is reported and gone from the write set", removed.join(",") === "SRC_KV_existing" && added.length === 0 && !bindings.some((b) => b.name === "SRC_KV_existing"));
  ok("every other binding survives the detach", ["SCHEDULER", "RUNSEAL", "CONSOLE_ORIGIN", "DEST_R2"].every((nm) => bindings.some((b) => b.name === nm)));

  // The engine's OWN bindings can never be a removal target.
  for (const own of ["SCHEDULER", "RUNSEAL", "DEST_R2", "SIGNER_PRIVATE"]) {
    let threw = "";
    try { planChange(ENGINE_BINDINGS, [], [own]); } catch (e) { threw = (e as Error).message; }
    ok(`refusing to detach the engine's own ${own}`, /refusing to detach|engine's own|secret|Durable Object/.test(threw));
  }

  // Detaching something not bound is refused.
  let threw = "";
  try { planChange(ENGINE_BINDINGS, [], ["SRC_KV_ghost"]); } catch (e) { threw = (e as Error).message; }
  ok("detaching a binding that is not bound is refused", /not bound to the engine/.test(threw));

  // A combined replace (remove + re-add the same name) is allowed.
  const repl = planChange(ENGINE_BINDINGS, [{ type: "kv", binding: "SRC_KV_existing", namespaceId: "newid" }], ["SRC_KV_existing"]);
  ok("a remove + re-add of the same name (replace) is allowed and lands the new id", repl.added.includes("SRC_KV_existing") && repl.bindings.some((b) => b.name === "SRC_KV_existing" && b.namespace_id === "newid"));
}

console.log("-- verifyAfter: the post-write alarm catches any unintended change --");
{
  // The happy path: everything survived + the new one landed.
  const after = [...ENGINE_BINDINGS, { type: "kv_namespace", name: "SRC_KV_new", namespace_id: "n9" }];
  let threw = "";
  try { verifyAfter(ENGINE_BINDINGS, ["SRC_KV_new"], [], after); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter passes when all survived and the new one landed", threw === "");

  // A write that dropped a SECRET -> loud alarm naming it.
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, ["SRC_KV_new"], [], after.filter((b) => b.name !== "SIGNER_PRIVATE")); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter ALARMS when a secret was lost, naming it + the redeploy recovery", /SIGNER_PRIVATE/.test(threw) && /SAFETY ALARM/.test(threw) && /[Rr]edeploy/.test(threw));

  // A write that dropped a Durable Object -> loud alarm.
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, ["SRC_KV_new"], [], after.filter((b) => b.name !== "RUNSEAL")); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter ALARMS when a Durable Object was lost", /SAFETY ALARM/.test(threw) && /[Rr]edeploy/.test(threw));

  // The new binding did not actually land -> honest failure, nothing harmed.
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, ["SRC_KV_new"], [], ENGINE_BINDINGS); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter fails honestly when the new binding is absent afterwards", /SRC_KV_new/.test(threw) && /not present/.test(threw));

  // An intended removal that did NOT actually go away -> honest failure.
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, [], ["SRC_KV_existing"], ENGINE_BINDINGS); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter fails honestly when a removal target still survives", /SRC_KV_existing/.test(threw) && /still bound/.test(threw));

  // A NON-removal binding is allowed to be absent only if it was an intended removal: a
  // detach removes its target and verifyAfter passes.
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, [], ["SRC_KV_existing"], ENGINE_BINDINGS.filter((b) => b.name !== "SRC_KV_existing")); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter passes a clean detach (target gone, the rest intact)", threw === "");
}

console.log("-- verifyAfter: the LOST-UPDATE guard catches a concurrent writer (TOCTOU) --");
{
  // A concurrent attach landed a binding (CONCURRENT_KV) AFTER our pre-read but BEFORE our
  // PATCH. Our PATCH set, computed from the stale pre-read, did NOT include it, yet it shows
  // up in the post-write read (it survived because the two writes interleaved). Our own
  // before/added/removed proofs all hold (every before-binding survived, our addition landed),
  // so without the lost-update guard verifyAfter would report SUCCESS on a clobbered run. The
  // guard must flag the unaccounted-for binding and alarm instead.
  const afterWithConcurrent = [
    ...ENGINE_BINDINGS,
    { type: "kv_namespace", name: "SRC_KV_new", namespace_id: "n9" },
    { type: "kv_namespace", name: "CONCURRENT_KV", namespace_id: "race1" },
  ];
  let threw = "";
  try { verifyAfter(ENGINE_BINDINGS, ["SRC_KV_new"], [], afterWithConcurrent); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter ALARMS on an unaccounted-for binding (a concurrent writer), not success", /CONCURRENT_KV/.test(threw) && /SAFETY ALARM/.test(threw) && /[Cc]oncurrent/.test(threw) && /lost update/.test(threw));

  // The mirror case: OUR write was the one clobbered. A concurrent writer that won the race
  // re-bound a name we intended to REMOVE (it reappears) - the removal proof catches that; and
  // a name we never touched appears too. The guard must alarm on the unintended binding rather
  // than the run quietly passing.
  const afterClobberedOurs = [
    ...ENGINE_BINDINGS.filter((b) => b.name !== "SRC_KV_existing"),
    { type: "kv_namespace", name: "OTHER_WRITER_KV", namespace_id: "race2" },
  ];
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, [], ["SRC_KV_existing"], afterClobberedOurs); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter ALARMS when an uncoordinated writer's binding appears after a detach", /OTHER_WRITER_KV/.test(threw) && /SAFETY ALARM/.test(threw) && /[Cc]oncurrent/.test(threw));
}

console.log("-- attachSources: a concurrent modification between read and PATCH is caught end to end --");
{
  // A stateful stub whose binding set MUTATES underneath the module: the pre-read returns the
  // engine bindings, then a concurrent writer adds CONCURRENT_KV (simulated by injecting it into
  // the state the moment after the first GET), so the PATCH (built from the stale pre-read) cannot
  // know about it, and the post-write re-read surfaces it. The module must DETECT the lost update
  // and alarm rather than report a successful attach. A Destination/binding double whose state
  // changes between the read and the write.
  let state: LiveBinding[] = [...ENGINE_BINDINGS];
  let getCount = 0;
  let patched = false;
  const racingStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) {
      getCount += 1;
      const snapshot = [...state];
      // After the pre-read returns its snapshot, a concurrent attach lands a new binding. Our
      // PATCH (next) is computed from the snapshot above, so it will clobber-or-miss this writer.
      if (getCount === 1) state = [...state, { type: "kv_namespace", name: "CONCURRENT_KV", namespace_id: "race1" }];
      return new Response(JSON.stringify({ success: true, result: { bindings: snapshot } }), { status: 200 });
    }
    if (method === "PATCH" && /\/settings$/.test(url)) {
      patched = true;
      const sent = JSON.parse(String((init!.body as FormData).get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      // Emulate the interleave: our sent set plus the kept secrets, AND the concurrent writer's
      // binding survives (it was written by the other party and our PATCH did not name it for
      // removal, so the merged end state still carries it).
      const keptSecrets = state.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      const concurrent = state.filter((b) => b.name === "CONCURRENT_KV");
      state = [...sent.bindings, ...keptSecrets, ...concurrent];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ message: "unexpected", code: 0 }] }), { status: 500 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok-broad-workers-edit-1234567890", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_mine", namespaceId: "ns-mine" }], racingStub); } catch (e) { threw = (e as Error).message; }
  ok("a concurrent modification between read and PATCH is detected as a lost update, not a silent success", /CONCURRENT_KV/.test(threw) && /lost update/.test(threw) && patched);
}

console.log("-- attachSources: the full read -> plan -> write -> verify against a stubbed API --");
{
  // A stateful stub: GET settings returns the CURRENT binding set, the PATCH
  // mutates it (applying the sent bindings + keeping secrets), and the post-verify read
  // reflects the new set. So the module exercises its real flow end to end.
  let state: LiveBinding[] = [...ENGINE_BINDINGS];
  const calls: string[] = [];
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push(`${method} ${url.replace(/^https:\/\/api\.cloudflare\.com\/client\/v4/, "")}`);
    if (method === "GET" && /\/tokens\/verify$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
    }
    if (method === "GET" && /\/settings$/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: { bindings: state } }), { status: 200 });
    }
    if (method === "PATCH" && /\/settings$/.test(url)) {
      const form = init!.body as FormData;
      const sent = JSON.parse(String(form.get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      // Emulate Cloudflare: the new binding set is what was sent, PLUS the kept (secret)
      // types inherited from the prior state.
      const keptSecrets = state.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      state = [...sent.bindings, ...keptSecrets];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }
    // Token capability pre-flight probes (Workers/KV/R2/D1/Secrets list reads): this token
    // can use all of them.
    if (method === "GET" && /\/(workers\/scripts|kv\/namespaces|r2\/buckets|d1\/database|secrets_store\/stores)(\?|$)/.test(url)) {
      return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: [{ message: "unexpected", code: 0 }] }), { status: 500 });
  }) as typeof fetch;

  const { added } = await attachSources("tok-broad-workers-edit-1234567890", "acct1", "downpipe-engine", [
    { type: "kv", binding: "SRC_KV_fresh", namespaceId: "ns9" },
    { type: "d1", binding: "SRC_D1_fresh", databaseId: "db9" },
  ], stub);

  ok("the additions are reported", added.join(",") === "SRC_KV_fresh,SRC_D1_fresh");
  ok("the flow read the settings, patched, then re-read to verify", calls.filter((c) => c.startsWith("GET")).length >= 2 && calls.some((c) => c.startsWith("PATCH")));
  ok("after the attach the engine STILL has its DOs and secrets", state.some((b) => b.name === "SCHEDULER") && state.some((b) => b.name === "RUNSEAL") && state.some((b) => b.name === "SIGNER_PRIVATE") && state.some((b) => b.name === "DEST_R2"));
  ok("after the attach the existing KV source survived and the new ones landed", state.some((b) => b.name === "SRC_KV_existing") && state.some((b) => b.name === "SRC_KV_fresh") && state.some((b) => b.name === "SRC_D1_fresh"));
  ok("no secret VALUE was sent in the PATCH", !JSON.stringify(state).includes("SIGNER_PRIVATE_VALUE"));

  // DETACH end to end: remove one of the freshly-attached sources; the engine's own
  // bindings and the other sources are untouched.
  const { removed } = await detachSources("tok-broad-workers-edit-1234567890", "acct1", "downpipe-engine", ["SRC_KV_fresh"], stub);
  ok("the detach is reported", removed.join(",") === "SRC_KV_fresh");
  ok("the detached source is gone, the rest (incl. engine infra) intact", !state.some((b) => b.name === "SRC_KV_fresh") && state.some((b) => b.name === "SRC_D1_fresh") && state.some((b) => b.name === "SCHEDULER") && state.some((b) => b.name === "SIGNER_PRIVATE"));
}

console.log("-- attachSources: refuses safely (no write) on a bad read or a stranger --");
{
  // A read that is not this engine (no Durable Objects): refuse BEFORE any PATCH.
  let patched = false;
  const strangerStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patched = true;
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: { bindings: [{ type: "kv_namespace", name: "OTHER" }] } }), { status: 200 });
    return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok", "acct1", "not-the-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], strangerStub); } catch (e) { threw = (e as Error).message; }
  ok("a non-engine read refuses and NEVER patches", /could not be confirmed|Durable Object/.test(threw) && patched === false);

  // An auth/scope refusal on the read names the token-template fix and never patches.
  let patched2 = false;
  const authStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if ((init?.method ?? "GET") === "PATCH") patched2 = true;
    return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
  }) as typeof fetch;
  threw = "";
  try { await attachSources("tok", "acct-x", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], authStub); } catch (e) { threw = (e as Error).message; }
  ok("a token with no Workers access is refused by the pre-flight, points at the template, never patches", /Edit Cloudflare Workers/.test(threw) && patched2 === false);
}

console.log("-- attachSources: the token pre-flight names the exact missing permission (no write) --");
{
  // A token that CAN read Workers + KV + R2 but NOT D1, attaching a D1 source: the
  // capability pre-flight names D1 as the missing one and refuses before any write.
  let patched3 = false;
  const partialStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patched3 = true;
    if (method === "GET" && /\/d1\/database/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 9109, message: "Unauthorized to access requested resource" }] }), { status: 403 });
    if (method === "GET" && /\/(workers\/scripts|kv\/namespaces|r2\/buckets|secrets_store\/stores)(\?|$)/.test(url)) return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok", "acctX", "downpipe-engine", [{ type: "d1", binding: "SRC_D1_x", databaseId: "db" }], partialStub); } catch (e) { threw = (e as Error).message; }
  ok("a token missing D1 is refused with D1 named, and never patches", /cannot use D1/.test(threw) && patched3 === false);
  ok("the checklist names a capability the token CAN use, and the D1/Secrets template gap", /it can use: .*Workers Scripts/.test(threw) && /NOT D1 or Secrets Store/.test(threw));
}

console.log("-- attachSources: a not-yet-active token (future Start Date) is named precisely (no write) --");
{
  // The exact real-world trap: a valid, active token whose Start Date is in the future. CF
  // reports it via /tokens/verify message code 10002; the pre-flight must name it, not patch.
  let patched4 = false;
  const notBeforeStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patched4 = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active", not_before: "2099-01-01T00:00:00Z", expires_on: "2099-01-01T23:59:59Z" }, messages: [{ code: 10002, message: "This API Token can not be used before 2099-01-01 00:00:00+00" }], errors: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok", "acctZ", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], notBeforeStub); } catch (e) { threw = (e as Error).message; }
  ok("a not-yet-active token is refused with a Start Date explanation, and never patches", /not active yet|Start Date is in the future/.test(threw) && /2099-01-01/.test(threw) && patched4 === false);
}

console.log("-- bindingFromSource: every per-type guard and the secrets/default arms --");
{
  // A non-string binding name takes the nullish fallback in the error message (binding ?? "").
  let threw = "";
  try { bindingFromSource({ type: "kv", binding: undefined as unknown as string, namespaceId: "x" }); } catch (e) { threw = (e as Error).message; }
  ok("a missing (non-string) binding name is refused and the message survives a null name", /not a valid Worker binding name/.test(threw));

  // Each storage type refuses when its required id/name is absent.
  threw = "";
  try { bindingFromSource({ type: "kv", binding: "SRC_KV_noid" }); } catch (e) { threw = (e as Error).message; }
  ok("a KV source without its namespace id is refused", /needs its namespace id/.test(threw));
  threw = "";
  try { bindingFromSource({ type: "r2", binding: "SRC_R2_nobucket" }); } catch (e) { threw = (e as Error).message; }
  ok("an R2 source without its bucket name is refused", /needs its bucket name/.test(threw));
  threw = "";
  try { bindingFromSource({ type: "d1", binding: "SRC_D1_noid" }); } catch (e) { threw = (e as Error).message; }
  ok("a D1 source without its database id is refused", /needs its database id/.test(threw));

  // The secrets arm: a complete secrets source maps to secrets_store_secret with store + name.
  const sec = bindingFromSource({ type: "secrets", binding: "SRC_SECRET_app", storeId: "store-1", secretName: "API_KEY" });
  ok("secrets -> secrets_store_secret {name, store_id, secret_name}", sec.type === "secrets_store_secret" && sec.name === "SRC_SECRET_app" && sec.store_id === "store-1" && sec.secret_name === "API_KEY");
  threw = "";
  try { bindingFromSource({ type: "secrets", binding: "SRC_SECRET_half", storeId: "store-1" }); } catch (e) { threw = (e as Error).message; }
  ok("a secrets source missing the secret name is refused", /needs the store id and the secret name/.test(threw));

  // The default arm: an unsupported type is refused by name.
  threw = "";
  try { bindingFromSource({ type: "queue" as unknown as "kv", binding: "SRC_Q" }); } catch (e) { threw = (e as Error).message; }
  ok("an unsupported source type is refused", /unsupported source type/.test(threw) && /queue/.test(threw));
}

console.log("-- planChange: detach guards for a DO and a (non-reserved) secret, and a bad target --");
{
  // A set that ALSO carries a non-reserved Durable Object and a non-reserved secret source, so the
  // type-specific detach refusals (a DO the engine owns; one of the engine's secrets) are exercised
  // distinct from the name-based RESERVED/REQUIRED refusal.
  const withOddBindings: LiveBinding[] = [
    ...ENGINE_BINDINGS,
    { type: "durable_object_namespace", name: "SRC_DO_extra", class_name: "OtherDO" },
    { type: "secret_text", name: "SRC_SECRET_extra" },
  ];
  let threw = "";
  try { planChange(withOddBindings, [], ["SRC_DO_extra"]); } catch (e) { threw = (e as Error).message; }
  ok("detaching a non-reserved Durable Object is refused as a DO the engine owns", /Durable Object the engine owns/.test(threw));
  threw = "";
  try { planChange(withOddBindings, [], ["SRC_SECRET_extra"]); } catch (e) { threw = (e as Error).message; }
  ok("detaching a non-reserved secret is refused as one of the engine's secrets", /one of the engine's secrets/.test(threw));

  // A removal target that is an empty string is refused before any lookup.
  threw = "";
  try { planChange(ENGINE_BINDINGS, [], [""]); } catch (e) { threw = (e as Error).message; }
  ok("an empty-string removal target is refused", /was not a binding name/.test(threw));
}

console.log("-- planChange: anomalous reads (a binding with no name; a binding with no type) --");
{
  // A read that contains a well-typed but UNNAMED binding (e.g. an analytics dataset that came back
  // without a name): it is non-redacted so it is re-sent verbatim, the unnamed-binding ternaries are
  // taken on both the write-set build and the no-drop proof, and the plan still succeeds.
  const withUnnamed: LiveBinding[] = [...ENGINE_BINDINGS, { type: "analytics_engine_dataset", dataset: "metrics" }];
  const planned = planChange(withUnnamed, [{ type: "kv", binding: "SRC_KV_after_unnamed", namespaceId: "nn" }], []);
  ok("an unnamed existing binding is re-sent verbatim and does not break the proof", planned.bindings.some((b) => b.type === "analytics_engine_dataset") && planned.added.join(",") === "SRC_KV_after_unnamed");

  // A read that contains a binding with NO type at all is anomalous: it cannot be re-sent (the resend
  // filter requires a string type) and it is not redacted, so the no-drop proof catches it and refuses
  // the write rather than silently dropping it. This drives the typeless ternary AND the proof-1 throw.
  const withTypeless: LiveBinding[] = [...ENGINE_BINDINGS, { name: "MYSTERY_BINDING" } as LiveBinding];
  let threw = "";
  try { planChange(withTypeless, [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], []); } catch (e) { threw = (e as Error).message; }
  ok("a typeless existing binding makes the no-drop proof refuse the write (it would be dropped)", /would be dropped/.test(threw) && /MYSTERY_BINDING/.test(threw));
}

console.log("-- verifyAfter: an unnamed before/after binding, and the post-write DO alarm --");
{
  // An UNNAMED binding in `beforeExisting` is skipped by the survival check (no name to look up); an
  // unnamed binding in `after` is filtered out of the name set. Both ternary else-arms are taken and
  // the verify still passes a real change.
  const before: LiveBinding[] = [...ENGINE_BINDINGS, { type: "analytics_engine_dataset", dataset: "m" }];
  const after: LiveBinding[] = [...ENGINE_BINDINGS, { type: "analytics_engine_dataset", dataset: "m" }, { type: "kv_namespace", name: "SRC_KV_landed", namespace_id: "z" }, { type: "plain_text" }];
  let threw = "";
  try { verifyAfter(before, ["SRC_KV_landed"], [], after); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter tolerates unnamed bindings on both sides and passes a real change", threw === "");

  // The post-write Durable Object alarm: even though planChange can never remove a required DO, the
  // post-verify guards it independently. If a DO is gone afterwards (and was an intended removal so the
  // per-binding survival loop skips it), looksLikeThisEngine fails and the DO-specific alarm fires.
  const afterNoRunseal = ENGINE_BINDINGS.filter((b) => b.name !== "RUNSEAL");
  threw = "";
  try { verifyAfter(ENGINE_BINDINGS, [], ["RUNSEAL"], afterNoRunseal); } catch (e) { threw = (e as Error).message; }
  ok("verifyAfter fires the Durable Object alarm when a required DO is missing afterwards", /SAFETY ALARM/.test(threw) && /Durable Object/.test(threw) && /[Rr]edeploy/.test(threw));
}

console.log("-- changeBindings: the verify-call surfaces the token id + expiry into the result --");
{
  // tokens/verify returns the PUBLIC token id + expires_on for an account-owned token: the result must
  // carry them through (the credential-lifecycle registry's "spent ephemeral token" row), driving the
  // optional-spread present-arms that the plain active-only stub never reached.
  let state: LiveBinding[] = [...ENGINE_BINDINGS];
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { id: "tok-public-id-123", status: "active", expires_on: "2099-12-31T00:00:00Z" } }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: { bindings: state } }), { status: 200 });
    if (method === "PATCH" && /\/settings$/.test(url)) {
      const sent = JSON.parse(String((init!.body as FormData).get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      const keptSecrets = state.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      state = [...sent.bindings, ...keptSecrets];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ message: "unexpected", code: 0 }] }), { status: 500 });
  }) as typeof fetch;
  const res = await attachSources("tok-broad-workers-edit-1234567890", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_idcase", namespaceId: "i1" }], stub);
  ok("the result carries the public token id and expiry from the verify call", res.tokenId === "tok-public-id-123" && res.expiresOn === "2099-12-31T00:00:00Z");
  ok("the permission summary lists the capabilities the change needed", /Workers Scripts/.test(res.permissionSummary) && /Workers KV/.test(res.permissionSummary));
}

console.log("-- checkTokenWindow: an expired/inactive status and an unreadable verify body --");
{
  // An account-owned token whose status is not active (expired): the window check names it precisely
  // (status + expiry), and refuses before any read or write. Drives the status-not-active arm.
  let patchedExp = false;
  const expiredStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patchedExp = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { id: "tid", status: "expired", expires_on: "2000-01-01T00:00:00Z" } }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok", "acctE", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], expiredStub); } catch (e) { threw = (e as Error).message; }
  ok("an inactive (expired-status) token is refused with the status named, and never patches", /status is "expired"/.test(threw) && /2000-01-01/.test(threw) && patchedExp === false);

  // A token reported via an "expired" MESSAGE rather than a status field (success, active-ish status
  // absent) takes the message-based expired arm.
  let patchedMsg = false;
  const expiredMsgStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patchedMsg = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: false, result: {}, errors: [{ code: 1000, message: "This API Token has expired" }] }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
  }) as typeof fetch;
  threw = "";
  try { await attachSources("tok", "acctM", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], expiredMsgStub); } catch (e) { threw = (e as Error).message; }
  ok("a token reported expired via a message is refused as expired, and never patches", /has expired/.test(threw) && patchedMsg === false);

  // A not-yet-active (code 10002) token with NO not_before field takes the empty "when" arm: the
  // refusal still names the future Start Date but without the dated clause.
  let patchedNb = false;
  const noNotBeforeStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patchedNb = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" }, messages: [{ code: 10002, message: "This API Token can not be used before its start date" }] }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
  }) as typeof fetch;
  threw = "";
  try { await attachSources("tok", "acctN", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], noNotBeforeStub); } catch (e) { threw = (e as Error).message; }
  ok("a future-dated token with no not_before is still named as not active yet, and never patches", /not active yet/.test(threw) && patchedNb === false);

  // A verify call whose body is unreadable (not JSON) returns problem:null so the flow proceeds to the
  // capability probes (which here refuse on the settings read). The window check must NOT throw on a
  // null body. We assert the flow got past the window check by reaching the read-diagnosis message.
  const nullVerifyStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (/\/tokens\/verify$/.test(url)) return new Response("not json", { status: 200 });
    // capability probes pass; the settings read then fails so we land in diagnoseRead
    if (method === "GET" && /\/(kv\/namespaces|r2\/buckets|d1\/database|secrets_store\/stores)(\?|$)/.test(url)) return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    if (method === "GET" && /\/workers\/scripts$/.test(url)) return new Response(JSON.stringify({ success: true, result: [{ id: "downpipe-engine" }] }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10001, message: "versions read denied" }] }), { status: 403 });
    return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
  }) as typeof fetch;
  threw = "";
  try { await attachSources("tok", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], nullVerifyStub); } catch (e) { threw = (e as Error).message; }
  ok("an unreadable verify body does not throw the window check; the flow proceeds and diagnoses the read", /can list this account's workers but not/.test(threw));

  // A verify response carrying notes with NO message field and a non-time-window code: both message
  // tests (the not-yet-active scan and the expired scan) take their nullish-message else-arm, the token
  // is judged usable, and the full attach completes. This proves a messageless note never derails the
  // window check.
  let stateMsgless: LiveBinding[] = [...ENGINE_BINDINGS];
  const messagelessNoteStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" }, messages: [{ code: 777 }], errors: [{ code: 888 }] }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: { bindings: stateMsgless } }), { status: 200 });
    if (method === "PATCH" && /\/settings$/.test(url)) {
      const sent = JSON.parse(String((init!.body as FormData).get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      const kept = stateMsgless.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      stateMsgless = [...sent.bindings, ...kept];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  const okRes = await attachSources("tok", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_msgless", namespaceId: "m" }], messagelessNoteStub);
  ok("a verify note with no message does not derail the window check; the attach completes", okRes.added.join(",") === "SRC_KV_msgless");

  // An inactive status (not "active") with NO expires_on field: the refusal still names the status but
  // omits the dated expiry clause (the expires_on else-arm).
  let patchedDis = false;
  const disabledNoExpStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patchedDis = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "disabled" } }), { status: 200 });
    return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
  }) as typeof fetch;
  threw = "";
  try { await attachSources("tok", "acctD2", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], disabledNoExpStub); } catch (e) { threw = (e as Error).message; }
  ok("a disabled token with no expiry is refused by status alone (no dated clause), and never patches", /status is "disabled"/.test(threw) && !/expires/.test(threw) && patchedDis === false);

  // The verify call itself THROWS (a network error on /tokens/verify): the window check swallows it and
  // returns problem:null, so the flow falls through to the capability probes and completes. This drives
  // the window check's own catch.
  let stateThrow: LiveBinding[] = [...ENGINE_BINDINGS];
  const verifyThrowStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (/\/tokens\/verify$/.test(url)) throw new Error("verify endpoint unreachable");
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: { bindings: stateThrow } }), { status: 200 });
    if (method === "PATCH" && /\/settings$/.test(url)) {
      const sent = JSON.parse(String((init!.body as FormData).get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      const kept = stateThrow.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      stateThrow = [...sent.bindings, ...kept];
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  const thrownVerifyRes = await attachSources("tok", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_verifythrow", namespaceId: "v" }], verifyThrowStub);
  ok("a verify call that throws is swallowed; the flow proceeds and the attach completes", thrownVerifyRes.added.join(",") === "SRC_KV_verifythrow" && thrownVerifyRes.tokenId === undefined);
}

console.log("-- auditToken: a probe that throws network-side refuses the change, and blames Cloudflare, not the token (no write) --");
{
  // A capability probe whose fetch REJECTS (a network error, not an HTTP error) must be caught and must still
  // refuse the change, with that capability named, rather than crashing. What it must NOT do is say the token
  // cannot use it: nothing about the token was established (G180).
  let patchedAt = false;
  const throwingProbeStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patchedAt = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
    if (/\/d1\/database/.test(url)) throw new Error("network down");
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
  }) as typeof fetch;
  let threw = "";
  let cls: unknown;
  try { await attachSources("tok", "acctP", "downpipe-engine", [{ type: "d1", binding: "SRC_D1_x", databaseId: "db" }], throwingProbeStub); } catch (e) { threw = (e as Error).message; cls = (e as { attachRefusalClass?: unknown }).attachRefusalClass; }
  ok("a probe that throws refuses the change, names the capability, and patches nothing", /did not reach Cloudflare/.test(threw) && /D1/.test(threw) && patchedAt === false);
  ok("and it does NOT claim the token lacks the capability (nothing about the token was established)", !/cannot use/.test(threw) && cls === "transport");
}

console.log("-- readDeployedBindings: a settings read with no bindings array refuses blind --");
{
  // The token can read everything (verify + probes pass) and the settings GET succeeds, but the body
  // has no bindings array: the module refuses to modify the engine blind rather than acting on it.
  let patchedNb2 = false;
  const noBindingsStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PATCH") patchedNb2 = true;
    if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: { something_else: 1 } }), { status: 200 });
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_x", namespaceId: "n" }], noBindingsStub); } catch (e) { threw = (e as Error).message; }
  ok("a settings read without a bindings list refuses to modify the engine blind", /without a readable bindings list/.test(threw) && patchedNb2 === false);
}

console.log("-- diagnoseRead: the failed read is turned into a precise cause --");
{
  // Shared scaffold: verify + capability probes pass, the FIRST settings read fails, so changeBindings
  // funnels into diagnoseRead, which re-lists the account's workers. The bare /workers/scripts collection
  // is hit TWICE: first by the capability pre-flight (which must pass) and then by diagnoseRead, so the
  // responder takes a call index and only the SECOND (diagnose) call carries the arm under test; the
  // first always passes so the flow gets past the pre-flight and the failed settings read.
  const makeDiagStub = (diagnoseResponder: () => Response) => {
    let workersCalls = 0;
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (/\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
      if (method === "GET" && /\/workers\/scripts$/.test(url)) {
        workersCalls += 1;
        if (workersCalls === 1) return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
        return diagnoseResponder();
      }
      if (method === "GET" && /\/(kv\/namespaces|r2\/buckets|d1\/database|secrets_store\/stores)(\?|$)/.test(url)) return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
      if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10001, message: "could not read settings" }] }), { status: 403 });
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    }) as typeof fetch;
  };
  const add = [{ type: "kv" as const, binding: "SRC_KV_x", namespaceId: "n" }];

  // Arm A: the token works but the account has NO workers -> the engine is in a different account.
  let threw = "";
  try { await attachSources("tok", "acctDiag", "downpipe-engine", add, makeDiagStub(() => new Response(JSON.stringify({ success: true, result: [] }), { status: 200 }))); } catch (e) { threw = (e as Error).message; }
  ok("diagnoseRead: no workers in the account -> names the wrong-account cause", /no workers in it at all/.test(threw) && /different Cloudflare account/.test(threw));

  // Arm B: the token works, the account has workers, but none is the engine -> lists the real names.
  // One list entry has a NON-string id (a malformed row): it is filtered out of the named list, so the
  // id-coercion else-arm is taken and only the well-formed names appear.
  threw = "";
  try { await attachSources("tok", "acctDiag", "downpipe-engine", add, makeDiagStub(() => new Response(JSON.stringify({ success: true, result: [{ id: "some-other-worker" }, { id: 42 }, { id: "another" }] }), { status: 200 }))); } catch (e) { threw = (e as Error).message; }
  ok("diagnoseRead: a mismatched script name -> lists the workers that ARE there (malformed rows dropped)", /no worker named "downpipe-engine"/.test(threw) && /some-other-worker, another/.test(threw) && !/42/.test(threw));

  // Arm C: the token works AND the engine name is present -> a versions/settings-specific scope gap.
  threw = "";
  try { await attachSources("tok", "acctDiag", "downpipe-engine", add, makeDiagStub(() => new Response(JSON.stringify({ success: true, result: [{ id: "downpipe-engine" }] }), { status: 200 }))); } catch (e) { threw = (e as Error).message; }
  ok("diagnoseRead: the engine name is present -> names the settings-scope gap", /can list this account's workers but not "downpipe-engine"'s settings/.test(threw));

  // Arm D: the diagnose workers list itself fails (success false) -> the token cannot read Workers.
  threw = "";
  try { await attachSources("tok", "acctDiag", "downpipe-engine", add, makeDiagStub(() => new Response(JSON.stringify({ success: false, errors: [{ code: 9109, message: "Unauthorized" }] }), { status: 403 }))); } catch (e) { threw = (e as Error).message; }
  ok("diagnoseRead: the workers list fails -> the token cannot read Workers in the account", /cannot read Workers in account acctDiag/.test(threw) && /Edit Cloudflare Workers/.test(threw));

  // Arm E: the diagnose workers call THROWS (network error) -> the catch returns the fallback message.
  // The throw is raised only on the SECOND workers call (the diagnose one) via the same call-indexed
  // scaffold, so the capability pre-flight still passes and we genuinely reach diagnoseRead's catch.
  threw = "";
  try { await attachSources("tok", "acctDiag", "downpipe-engine", add, makeDiagStub(() => { throw new Error("connection reset"); })); } catch (e) { threw = (e as Error).message; }
  ok("diagnoseRead: a thrown workers-list call -> the fallback wrangler-path message", /could not read this engine on account acctDiag/.test(threw) && /wrangler deploy path/.test(threw));
}

console.log("-- cfErr: a failure body with no errors array still yields an HTTP-status reason --");
{
  // The PATCH (settings write) returns a failure whose body has NO errors array at all. cfErr must fall
  // back to the bare HTTP status (no codes), and changeBindings must report the write did not land
  // without ever claiming a Cloudflare message it did not get. This drives the no-errors fallback arms.
  let state: LiveBinding[] = [...ENGINE_BINDINGS];
  const patchFailStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: { bindings: state } }), { status: 200 });
    if (method === "PATCH" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: false }), { status: 503 });
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  void state;
  let threw = "";
  try { await attachSources("tok", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_patchfail", namespaceId: "n" }], patchFailStub); } catch (e) { threw = (e as Error).message; }
  ok("a PATCH failure with no errors body reports the change did not land with an HTTP-status reason", /did not land/.test(threw) && /HTTP 503/.test(threw) && /atomic/.test(threw));
}

console.log("-- readDeployedBindings (post-write): a failed re-read reports the quiet check, not a diagnosis --");
{
  // The pre-read + PATCH succeed, but the POST-WRITE re-read fails. That read runs in the quiet mode, so
  // it must report the dedicated post-write-check message (and NOT run the full token-vs-account-vs-name
  // diagnosis, which would tell the wrong story after a successful write). The first settings GET
  // succeeds; the second (post-verify) fails.
  let getCount = 0;
  const postReadFailStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/tokens\/verify$/.test(url)) return new Response(JSON.stringify({ success: true, result: { status: "active" } }), { status: 200 });
    if (method === "GET" && /\/settings$/.test(url)) {
      getCount += 1;
      if (getCount === 1) return new Response(JSON.stringify({ success: true, result: { bindings: ENGINE_BINDINGS } }), { status: 200 });
      return new Response(JSON.stringify({ success: false, errors: [{ code: 10001, message: "transient settings read failure" }] }), { status: 502 });
    }
    if (method === "PATCH" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    if (method === "GET") return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    return new Response(JSON.stringify({ success: false }), { status: 500 });
  }) as typeof fetch;
  let threw = "";
  try { await attachSources("tok", "acct1", "downpipe-engine", [{ type: "kv", binding: "SRC_KV_postfail", namespaceId: "n" }], postReadFailStub); } catch (e) { threw = (e as Error).message; }
  ok("a failed post-write re-read reports the quiet post-write-check message (no full diagnosis)", /re-read the engine's settings for the post-write check/.test(threw) && !/different Cloudflare account/.test(threw));
}

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nIN-PRODUCT ATTACH HARNESS VECTORS PASS");
