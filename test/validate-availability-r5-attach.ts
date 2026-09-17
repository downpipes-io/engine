// Validates the redaction chokepoint for a deploy wiping the source bindings (and the heal that repairs it) --
// the owner's #1 fear domain -- against three misclassifications:
//
//   1. applyAttachHealth must never record a FAILED attach carrying an out-of-vocabulary class as a SUCCESSFUL
//      one. A `cls === null` branch that increments successes[op] breaks the chokepoint's own invariant ("an
//      out-of-vocabulary class is DROPPED WHOLE") at exactly the untrusted-input boundary it exists to guard,
//      inflating the success count of the heal for the owner's worst fear.
//   2. `token-scope` means "the engine PROVED the pasted token cannot do this change". Reporting each capability
//      probe as a plain BOOLEAN would make a Cloudflare 500, a 429 and a socket reset all read as false and all
//      throw token-scope -- telling support the token lacks Workers KV while the customer's Cloudflare 5xx and
//      429s sit in their own logs, which is worse than a plain `auth` class that at least points at Cloudflare.
//   3. the POST-WRITE verify re-read throwing an untagged CfApiFault must not land on the same `unavailable`
//      cell as a PRE-WRITE read 5xx: the two mean opposite things. A pre-write read failing means nothing was
//      written; a post-write re-read failing means THE PATCH LANDED and the safety harness's post-check could
//      not run. `binding-alarm` covers "the write landed and the verify DISAGREED"; a distinct class is needed
//      for "the write landed and the verify was BLIND".
//
// Every state below is produced by driving the REAL changeBindings against a STATEFUL Cloudflare stub, through
// the real phases and the real throws, classified by the real classifyAttachError and folded through the real
// applyAttachHealth. Nothing is hand-written: a classifier proved only against a hand-made error string proves
// nothing about the real code path.
//
// Run with `npx tsx test/validate-availability-r5-attach.ts`.

import { changeBindings, type AttachSource, type LiveBinding } from "../src/admin/attach.ts";
import { bindingAlarmOf } from "../src/admin/attach-plan.ts";
import { ATTACH_FAULT_CLASSES, applyAttachHealth, attachRefusalClassOf, classifyAttachError, type AttachFaultClass, type AttachHealth } from "../src/admin/discovery-health.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function eq(label: string, actual: unknown, expected: unknown): void {
  ok(`${label} (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`, actual === expected);
}
function section(title: string): void {
  console.log(`\n-- ${title} --`);
}

const ENGINE_BINDINGS: LiveBinding[] = [
  { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" },
  { type: "durable_object_namespace", name: "RUNSEAL", class_name: "RunSealDO" },
  { type: "secret_text", name: "SIGNER_PRIVATE" },
  { type: "r2_bucket", name: "DEST_R2", bucket_name: "downpipe-archive" },
  { type: "kv_namespace", name: "SRC_KV_existing", namespace_id: "abc123" },
];

const okJson = (body: unknown): Response => new Response(JSON.stringify(body), { status: 200 });
const cfStatus = (status: number): Response => new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: CF_PROSE }] }), { status });

// The customer's own values, in every message the operator reads. NONE of them may reach the record.
const CF_PROSE = "workers.api.error.script_too_large";
const ACCOUNT = "acme-prod-account-9f3";
const SENTINELS = /acme|SRC_KV_|script_too_large|downpipe-archive|abc123|tok-secret/;

// The capability probe's answer, and the leg it answers on. `throw` is a socket reset (no status ever seen);
// `no-success` is a 200 whose body says neither success nor a refusal.
type Probe = "allowed" | 403 | 500 | 429 | "throw" | "no-success";
// The post-write verify leg: answer it, fail it with a status, or answer it with a binding set that DISAGREES
// with what was written (the write landed and the additions are not there: the alarm).
type Verify = "ok" | { status: number } | "disagrees";

interface Legs {
  tokenWindow?: "active" | "not-yet-active";
  kvProbe?: Probe;
  read?: LiveBinding[] | { status: number };
  patch?: "ok" | "cf-rejects";
  verify?: Verify;
}

// A STATEFUL Cloudflare, like the real thing: the PATCH mutates the binding set and the post-verify read sees the
// result. A stateless stub would make every happy path raise a post-write alarm, which is the very fault the alarm
// exists to catch, and the suite would be asserting against a fiction.
function cloudflare(legs: Legs): typeof fetch {
  const { tokenWindow = "active", kvProbe = "allowed", read = ENGINE_BINDINGS, patch = "ok", verify = "ok" } = legs;
  let live: LiveBinding[] = Array.isArray(read) ? [...read] : [];
  let settingsGets = 0;
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";

    if (/\/tokens\/verify$/.test(url)) {
      return tokenWindow === "active"
        ? okJson({ success: true, result: { id: "tok-public", status: "active" } })
        : okJson({
            success: true,
            result: { status: "active", not_before: "2099-01-01T00:00:00Z" },
            messages: [{ code: 10002, message: "This API Token can not be used before 2099-01-01 00:00:00+00" }],
            errors: [],
          });
    }

    // The KV capability probe: the one this change needs beyond Workers Scripts.
    if (/\/storage\/kv\/namespaces/.test(url)) {
      if (kvProbe === "throw") throw new TypeError("fetch failed");
      if (kvProbe === "no-success") return okJson({ result: [] });
      if (kvProbe === "allowed") return okJson({ success: true, result: [] });
      return cfStatus(kvProbe);
    }

    if (/\/settings$/.test(url) && method === "GET") {
      settingsGets += 1;
      // The PRE-WRITE read.
      if (settingsGets === 1) {
        if (!Array.isArray(read)) return cfStatus(read.status);
        return okJson({ success: true, result: { bindings: live } });
      }
      // The POST-WRITE verify re-read.
      if (verify === "disagrees") return okJson({ success: true, result: { bindings: ENGINE_BINDINGS } });
      if (verify !== "ok") return cfStatus(verify.status);
      return okJson({ success: true, result: { bindings: live } });
    }

    if (/\/settings$/.test(url) && method === "PATCH") {
      if (patch === "cf-rejects") return new Response(JSON.stringify({ success: false, errors: [{ code: 10021, message: CF_PROSE }] }), { status: 200 });
      const sent = JSON.parse(String((init!.body as FormData).get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      const kept = live.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      live = [...sent.bindings, ...kept];
      return okJson({ success: true, result: {} });
    }

    // The Workers Scripts probe, and diagnoseRead's account listing.
    if (/\/workers\/scripts$/.test(url)) return okJson({ success: true, result: [{ id: "downpipe-engine" }] });
    return okJson({ success: true, result: [] });
  }) as unknown as typeof fetch;
}

const KV_SOURCE = [{ type: "kv" as const, binding: "SRC_KV_new", namespaceId: "abc123" }];

// drive runs the REAL changeBindings and returns the class the REAL route would record, decided the way the route
// decides it (recordBindingAlarmFrom's alarm flag, then classifyAttachError).
async function drive(legs: Legs, add: AttachSource[] = KV_SOURCE, remove: string[] = []): Promise<{ cls: AttachFaultClass | "no-throw"; message: string; tag: string | null }> {
  try {
    await changeBindings("tok-secret", ACCOUNT, "downpipe-engine", add, remove, cloudflare(legs));
    return { cls: "no-throw", message: "", tag: null };
  } catch (e) {
    const alarm = bindingAlarmOf(e) !== null;
    return { cls: classifyAttachError(e, alarm), message: e instanceof Error ? e.message : String(e), tag: attachRefusalClassOf(e) };
  }
}

// row is the PACK CELL: the state folded through the real chokepoint, exactly as the DO stores it. Two states that
// produce the same row are one row in the support engineer's hands, whatever the classifier said.
function row(cls: AttachFaultClass | "no-throw"): string {
  return JSON.stringify(applyAttachHealth(undefined, cls === "no-throw" ? { op: "attach" } : { op: "attach", fault: cls }, 1_000));
}

// ==============================================================================================
section("the chokepoint must not record a FAILED attach as a SUCCESSFUL one");
// ==============================================================================================
{
  // The exact pair that collapses under a naive fold: an out-of-vocabulary CLASS on a FAILED attach, and a
  // genuinely successful attach. They are byte-identical unless the failure is recorded as a failure, which
  // would otherwise inflate the success count of the heal for the owner's worst fear.
  const outOfVocab = JSON.stringify(applyAttachHealth(undefined, { op: "attach", fault: "s3://acme-prod/key?token=abc" }, 1_000));
  const success = JSON.stringify(applyAttachHealth(undefined, { op: "attach", attached: 1 }, 1_000));
  ok("an out-of-vocabulary CLASS on a failed attach and a SUCCESSFUL attach are no longer the same record", outOfVocab !== success);
  eq("the failure is recorded as a failure, under `unclassified`", JSON.parse(outOfVocab).faults.attach.unclassified, 1);
  eq("and it is NOT counted as a success", JSON.parse(outOfVocab).successes.attach, undefined);
  eq("while the genuine success still is", JSON.parse(success).successes.attach, 1);
  ok("the out-of-vocabulary VALUE itself never enters the record", !SENTINELS.test(outOfVocab) && !/s3:|token=/.test(outOfVocab));

  // `unclassified` must not be confused with `other`: `other` means the classifier RAN and matched nothing, and it
  // is a customer-facing fault. `unclassified` means the RECORDER was handed a class it does not know, which is a
  // version-skew bug report. Different reader, different remedy, different cell.
  ok("`unclassified` is its own cell, never coerced into `other`", row("unclassified") !== row("other"));

  // An out-of-vocabulary OP still records nothing at all: there is nowhere safe to put it.
  const badOp = applyAttachHealth(undefined, { op: "acme-prod", fault: "safety-prove-failed" }, 1_000);
  ok("an out-of-vocabulary OP is still dropped whole", Object.keys(badOp.attempts).length === 0 && Object.keys(badOp.faults).length === 0);

  // NOISE: the fold must not invent a failure out of a legitimate success. The route omits the fault key entirely
  // on the success path, and only a POSTED fault field makes a failure.
  eq("a success posting attached-count and no fault key is still a success", applyAttachHealth(undefined, { op: "reattach", attached: 3 }, 1_000).successes.reattach, 1);
  eq("and it records no fault of any class", Object.keys(applyAttachHealth(undefined, { op: "reattach", attached: 3 }, 1_000).faults).length, 0);
}

// ==============================================================================================
section("`token-scope` must not assert a fact the capability probe never established");
// ==============================================================================================
//
// Of these four states, only the first proves anything about the token; treating all four as `token-scope`
// ("the engine PROVED the pasted token cannot do what this change needs") would misdiagnose the other three.
const probe: Record<string, AttachFaultClass | "no-throw"> = {};
{
  const refused = await drive({ kvProbe: 403 });
  probe.refused = refused.cls;
  eq("(B) Cloudflare REFUSES the KV capability (403) -> token-scope: the one state that proves it", refused.cls, "token-scope");
  ok("(B) and the operator's checklist still names the capability", /cannot use Workers KV/.test(refused.message));

  const down = await drive({ kvProbe: 500 });
  probe.down = down.cls;
  eq("(F) Cloudflare 500 on the capability probe -> unavailable, NOT token-scope", down.cls, "unavailable");
  ok("(F) and the operator is told in as many words not to re-mint the token", /do not re-mint the token/.test(down.message));
  ok("(F) the message says nothing was written", /Nothing was written/.test(down.message));

  const throttled = await drive({ kvProbe: 429 });
  probe.throttled = throttled.cls;
  eq("(G) Cloudflare 429 on the capability probe -> rate-limited, NOT token-scope", throttled.cls, "rate-limited");

  const reset = await drive({ kvProbe: "throw" });
  probe.reset = reset.cls;
  eq("(H) a socket reset on the capability probe -> transport, NOT token-scope", reset.cls, "transport");
  ok("(H) driven through the REAL throw path: the probe's fetch rejects, and nothing is hand-written", /did not reach Cloudflare/.test(reset.message));

  const shapeless = await drive({ kvProbe: "no-success" });
  probe.shapeless = shapeless.cls;
  eq("a 200 that says neither success nor refusal -> other, NOT token-scope", shapeless.cls, "other");

  ok(
    "THE FOUR STATES THAT WERE ONE ROW ARE NOW FOUR ROWS",
    new Set([row(probe.refused!), row(probe.down!), row(probe.throttled!), row(probe.reset!)]).size === 4,
  );
  ok("and the shapeless answer is a fifth", !new Set([row(probe.refused!), row(probe.down!), row(probe.throttled!), row(probe.reset!)]).has(row(probe.shapeless!)));
  ok(
    "NOT ONE of the three Cloudflare faults claims the token lacks a capability",
    ![probe.down, probe.throttled, probe.reset, probe.shapeless].includes("token-scope"),
  );

  // The pre-flight still REFUSES in every one of these states: nothing is written, which is the safety property.
  ok("every unanswered probe still refuses the change (nothing is written)", ![probe.down, probe.throttled, probe.reset, probe.shapeless].includes("no-throw"));

  // And a token that Cloudflare refuses is STILL not the same row as a token Cloudflare rejects outright on the
  // settings read (which is `auth`: the whole token is wrong or revoked, not one capability short).
  const readAuth = await drive({ read: { status: 403 } });
  eq("(M) Cloudflare 403 on the settings READ -> auth (the whole token, not one capability)", readAuth.cls, "auth");
  ok("(M) and it is not the same row as token-scope", row(readAuth.cls) !== row(probe.refused!));
}

// ==============================================================================================
section("the post-write verify re-read must not be filed as a benign pre-write read failure");
// ==============================================================================================
{
  const preRead = await drive({ read: { status: 503 } });
  eq("(D) Cloudflare 5xx on the PRE-WRITE settings read -> unavailable (nothing was written)", preRead.cls, "unavailable");

  const postRead = await drive({ verify: { status: 503 } });
  eq("(I) Cloudflare 5xx on the POST-WRITE verify re-read -> verify-unread (the PATCH LANDED, the verify could not run)", postRead.cls, "verify-unread");
  eq("(I) tagged at the phase that knows, never guessed from the status", postRead.tag, "verify-unread");
  ok("(I) and the operator's post-write-check message is unchanged", /re-read the engine's settings for the post-write check/.test(postRead.message));

  ok("THE TWO ARE DIFFERENT ROWS: opposite meanings, opposite remedies", row(preRead.cls) !== row(postRead.cls));

  // The third member of this family, and it must still OUTRANK the other two: the verify RAN and DISAGREED. That
  // is the owner's #1 fear actually happening, mid-heal, and it may never be buried under a phase label.
  const alarm = await drive({ verify: "disagrees" });
  eq("(J) the verify runs and the additions are NOT there -> binding-alarm", alarm.cls, "binding-alarm");
  ok("(J) the alarm is a third row again: blind, disagreeing and not-written are three states", new Set([row(preRead.cls), row(postRead.cls), row(alarm.cls)]).size === 3);
  eq("(J) and the alarm passes through the verify-unread tagger UNTAGGED, so nothing can outrank it", alarm.tag, null);
}

// ==============================================================================================
section("THE WHOLE STATE SPACE: every state a support engineer must tell apart, driven end to end");
// ==============================================================================================
{
  const states: Array<[string, Legs, AttachSource[], string[]]> = [
    ["a clean attach", {}, KV_SOURCE, []],
    ["the safety harness refusing (this is not the engine)", { read: [{ type: "kv_namespace", name: "SOMEONE_ELSE" }] }, KV_SOURCE, []],
    ["the token outside its validity window", { tokenWindow: "not-yet-active" }, KV_SOURCE, []],
    ["Cloudflare refusing the KV capability (403)", { kvProbe: 403 }, KV_SOURCE, []],
    ["Cloudflare 500 on the capability probe", { kvProbe: 500 }, KV_SOURCE, []],
    ["Cloudflare 429 on the capability probe", { kvProbe: 429 }, KV_SOURCE, []],
    ["a socket reset on the capability probe", { kvProbe: "throw" }, KV_SOURCE, []],
    ["Cloudflare 403 on the pre-write settings read", { read: { status: 403 } }, KV_SOURCE, []],
    ["Cloudflare 404 on the pre-write settings read", { read: { status: 404 } }, KV_SOURCE, []],
    ["Cloudflare 5xx on the pre-write settings read", { read: { status: 503 } }, KV_SOURCE, []],
    ["Cloudflare rejecting the settings PATCH", { patch: "cf-rejects" }, KV_SOURCE, []],
    ["Cloudflare 5xx on the POST-WRITE verify re-read", { verify: { status: 503 } }, KV_SOURCE, []],
    ["the post-write verify DISAGREEING with the write", { verify: "disagrees" }, KV_SOURCE, []],
  ];

  const rows = new Map<string, string[]>();
  for (const [name, legs, add, remove] of states) {
    const r = await drive(legs, add, remove);
    const cell = row(r.cls);
    rows.set(cell, [...(rows.get(cell) ?? []), name]);
    ok(`${name} -> ${r.cls}`, r.cls !== "other");
    ok(`  and no customer value rides in its cell`, !SENTINELS.test(cell));
  }

  // The one DECLARED collapse, and it is declared because the remedy is identical: a Cloudflare 5xx on the
  // capability probe and a Cloudflare 5xx on the pre-write settings read are both "a PRE-WRITE Cloudflare call
  // returned a server error, nothing was written, wait and retry, do not touch the token". Naming them apart would
  // be precision the support engineer cannot use. Everything else must be its own row.
  const collapsed = [...rows.values()].filter((names) => names.length > 1);
  ok(
    `every state is its own row apart from the declared pair (${rows.size} rows from ${states.length} states)`,
    collapsed.length === 1 && collapsed[0]!.length === 2 && collapsed[0]!.every((n) => /500 on the capability probe|5xx on the pre-write settings read/.test(n)),
  );
  eq("and the declared pair is exactly the two pre-write Cloudflare 5xx legs, nothing else", rows.size, states.length - 1);
}

// ==============================================================================================
section("NO CUSTODY: closed vocabulary, closed keys, clamped counts. Nothing else.");
// ==============================================================================================
{
  ok(
    "every ATTACH_FAULT_CLASSES member is a lower-case product constant (no customer value could ever BE one)",
    ATTACH_FAULT_CLASSES.every((c) => /^[a-z-]+$/.test(c)),
  );
  // Fold every driven state into ONE record and scan the whole thing. The messages carry the account id, the
  // binding names, the bucket name and Cloudflare's own prose; the record may carry none of it.
  let health: AttachHealth | undefined;
  for (const cls of ATTACH_FAULT_CLASSES) health = applyAttachHealth(health, { op: "attach", fault: cls }, 1_000);
  health = applyAttachHealth(health, { op: "detach", fault: "safety-prove-failed" }, 1_001);
  health = applyAttachHealth(health, { op: "reattach", fault: "verify-unread", plan: { toAttach: "SRC_KV_new", conflictingClaims: 2 } }, 1_002);
  const dumped = JSON.stringify(health);
  ok("no account id, no binding name, no bucket, no token and no Cloudflare prose in the record", !SENTINELS.test(dumped));
  eq("a non-numeric plan count is clamped to 0, never stored as a string", health.lastPlan?.toAttach, 0);
  eq("and the legitimate plan count survives", health.lastPlan?.conflictingClaims, 2);
  ok("the fault keys are exactly the closed vocabulary", Object.keys(health.faults.attach ?? {}).every((k) => (ATTACH_FAULT_CLASSES as readonly string[]).includes(k)));
  eq("a refused DETACH lands under detach, not attach", health.faults.detach?.["safety-prove-failed"], 1);
  eq("and the blind verify on the HEAL lands under reattach", health.faults.reattach?.["verify-unread"], 1);
}

console.log(failures === 0 ? "\nALL PASS (availability: attach)" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
