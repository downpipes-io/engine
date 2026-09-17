// Validate the ENGINE half of the availability of attach/detach/reattach classification.
//
// THIS IS THE OWNER'S #1 FEAR DOMAIN: a deploy wiping the source bindings, and the heal that repairs it. The
// ticket is verbatim "Attach now / Detach / Re-attach all refuses with an error", and holding the pack, support
// could not tell which of three completely different things had happened:
//
//   the SAFETY HARNESS refused       prove-before-write did its job. NOTHING was written and nothing is at risk.
//                                    The engine behaved exactly as designed, and the customer must be told that.
//   the TOKEN lacked what it needed  the pasted deploy token cannot do this change. NOTHING was written.
//   the WRITE genuinely failed       the settings PATCH did not land at Cloudflare. Nothing was changed.
//
// All three answer the console with an identical 400, and engine-side classifyAttachError has only the MESSAGE to
// go on: a harness refusal ("safety check failed: existing binding X would be dropped; refusing to write") carries
// no status and no network word, so a classifier reading only the status/network shape alone would drop it into
// `other` -- the same row as a Cloudflare write failure whose body was prose. The one refusal that means THE
// PRODUCT WORKED and the one that means CLOUDFLARE BROKE would then be one row. And a classifier that keys off the
// word "permission" would read that word out of the engine's OWN token pre-flight message, filing a token-scope
// refusal as a Cloudflare `auth` rejection.
//
// A fourth collapse hides inside the OP: an attach and a detach are the SAME POST to the same route, told apart
// only by which typed argument list the console filled in, so a naive recorder files every refused DETACH as a
// refused ATTACH.
//
// THIS SUITE DRIVES THE REAL changeBindings against a stubbed Cloudflare API -- the real phases, the real throws,
// the real classifier -- then folds each fault through the real recorder and the real pack projection, and asserts
// every state lands in a DIFFERENT cell. A classifier proved only on a hand-written string does not prove the real
// code paths agree with it, so the phases are driven here, not described.
//
// Run with `npx tsx test/validate-availability-r4-engine.ts`.

import { changeBindings, type LiveBinding } from "../src/admin/attach.ts";
import { bindingAlarmOf } from "../src/admin/attach-plan.ts";
import { ATTACH_FAULT_CLASSES, ATTACH_OPS, applyAttachHealth, classifyAttachError, type AttachFaultClass, type AttachHealth } from "../src/admin/discovery-health.ts";
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

// The engine as the script-settings read returns it: its two Durable Objects, its secrets, its archive.
const ENGINE_BINDINGS: LiveBinding[] = [
  { type: "durable_object_namespace", name: "SCHEDULER", class_name: "SchedulerDO" },
  { type: "durable_object_namespace", name: "RUNSEAL", class_name: "RunSealDO" },
  { type: "secret_text", name: "SIGNER_PRIVATE" },
  { type: "r2_bucket", name: "DEST_R2", bucket_name: "downpipe-archive" },
  { type: "kv_namespace", name: "SRC_KV_existing", namespace_id: "abc123" },
];

const okJson = (body: unknown): Response => new Response(JSON.stringify(body), { status: 200 });

// A Cloudflare stub with each leg switchable, so ONE phase can be made to refuse while every other phase behaves.
// The legs are the real ones changeBindings calls, in the real order: the token window check, the token capability
// audit, the settings read, the settings PATCH, and the post-verify read.
interface Legs {
  tokenWindow?: "active" | "not-yet-active";
  caps?: "all" | "missing-kv";
  read?: LiveBinding[] | "http-500";
  patch?: "ok" | "cf-rejects" | "no-answer";
  capsFault?: "cf-token-invalid" | "cf-500";
}
function cloudflare(legs: Legs): typeof fetch {
  const { tokenWindow = "active", caps = "all", read = ENGINE_BINDINGS, patch = "ok", capsFault } = legs;
  // STATEFUL, like the real thing: the PATCH mutates the binding set and the post-verify read sees the result. A
  // stateless stub would make every happy path raise a post-write alarm, which is precisely the fault the alarm
  // exists to catch, and the suite would be asserting against a fiction.
  let live: LiveBinding[] = Array.isArray(read) ? [...read] : [];
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (/\/tokens\/verify$/.test(url)) {
      return tokenWindow === "active"
        ? okJson({ success: true, result: { id: "tok-public", status: "active" } })
        : okJson({
            success: true,
            result: { status: "active", not_before: "2099-01-01T00:00:00Z", expires_on: "2099-01-01T23:59:59Z" },
            messages: [{ code: 10002, message: "This API Token can not be used before 2099-01-01 00:00:00+00" }],
            errors: [],
          });
    }
    // The capability audit: the engine asks Cloudflare whether the token may do each thing this change needs.
    // "missing-kv" is a token minted without Workers KV, which is the commonest scope gap on this route.
    if (/\/user\/tokens\/permission_groups$/.test(url) || /\/accounts\/[^/]+\/tokens\/permission_groups$/.test(url)) return okJson({ success: true, result: [] });
    if (/\/storage\/kv\/namespaces/.test(url)) {
      // Cloudflare's verdict on the TOKEN ITSELF arrives on a 400 with its own error code 1000, NOT a 401/403.
      // A status-only classifier filed it as "inconclusive", whose sentence tells the operator this is a
      // Cloudflare fault and NOT to re-mint the token: the one state where the token IS the fault was the one
      // state the engine told support to leave it alone.
      if (capsFault === "cf-token-invalid") return new Response(JSON.stringify({ success: false, errors: [{ code: 1000, message: "Invalid API Token" }] }), { status: 400 });
      if (capsFault === "cf-500") return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "oops" }] }), { status: 500 });
      return caps === "all" ? okJson({ success: true, result: [] }) : new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    }
    if (method === "GET" && /\/settings$/.test(url)) {
      if (read === "http-500") return new Response(JSON.stringify({ success: false }), { status: 500 });
      return okJson({ success: true, result: { bindings: live } });
    }
    if (method === "PATCH" && /\/settings$/.test(url)) {
      if (patch === "no-answer") {
        // THE LOST RESPONSE. Cloudflare may have APPLIED this write and had the reply die on the way back. This
        // is a real fetch rejection, exactly as undici/workerd throws, not a hand-written Error.
        throw new TypeError("network error: connection reset");
      }
      if (patch === "cf-rejects") {
        // Cloudflare refusing the write with a PROSE body and no status token in the message the engine then
        // builds. Without the classifier this shape would land in `other` beside the safety harness's refusal.
        return new Response(JSON.stringify({ success: false, errors: [{ code: 10021, message: "workers.api.error.script_too_large" }] }), { status: 200 });
      }
      // Apply the write: the sent set, plus the redacted (secret) bindings keep_bindings preserves in place.
      const sent = JSON.parse(String((init!.body as FormData).get("settings"))) as { bindings: LiveBinding[]; keep_bindings: string[] };
      const kept = live.filter((b) => typeof b.type === "string" && sent.keep_bindings.includes(b.type));
      live = [...sent.bindings, ...kept];
      return okJson({ success: true, result: {} });
    }
    // Anything else the capability audit probes: allow it.
    return okJson({ success: true, result: [] });
  }) as unknown as typeof fetch;
}

// drive runs the REAL changeBindings and returns the class the REAL classifier assigns to whatever it threw.
async function drive(legs: Legs, add: Parameters<typeof changeBindings>[3], remove: string[]): Promise<{ cls: AttachFaultClass | "no-throw"; message: string }> {
  try {
    await changeBindings("tok", "acct", "downpipe-engine", add, remove, cloudflare(legs));
    return { cls: "no-throw", message: "" };
  } catch (e) {
    const alarm = bindingAlarmOf(e) !== null;
    return { cls: classifyAttachError(e, alarm), message: e instanceof Error ? e.message : String(e) };
  }
}

const KV_SOURCE = [{ type: "kv" as const, binding: "SRC_KV_new", namespaceId: "ns-1" }];

// ==============================================================================================
section("the three refusals the ticket names, driven through the REAL changeBindings");
// ==============================================================================================

const seen: Record<string, AttachFaultClass> = {};

// (1) THE SAFETY HARNESS REFUSED. The read comes back WITHOUT the engine's own Durable Objects, so the identity
// guard refuses before any write: this is not the engine, or the read is bad, and the harness will not touch it.
// This is the CORRECT, PROTECTIVE refusal, and without the classifier it would fall into `other`.
{
  const r = await drive({ read: [{ type: "kv_namespace", name: "SOMEONE_ELSE" }] }, KV_SOURCE, []);
  seen.harness = r.cls as AttachFaultClass;
  eq("(1) the identity guard refusing -> safety-prove-failed", r.cls, "safety-prove-failed");
  ok("(1) and the operator's message is UNCHANGED (the tag is the only new thing)", /refusing to modify it/.test(r.message));
}

// (1b) the OTHER shape of the same refusal: a name collision the planner will not resolve. Same phase, same class,
// one row: no invented precision.
{
  const r = await drive({}, [{ type: "kv", binding: "SRC_KV_existing", namespaceId: "ns-2" }], []);
  eq("(1b) a binding-name collision -> safety-prove-failed too (same phase, same remedy, one row)", r.cls, "safety-prove-failed");
}

// (2) THE TOKEN LACKED THE SCOPE. The engine's own pre-flight proves the token cannot use Workers KV on this
// account, and refuses before touching the engine. Without the classifier this reads as `auth` -- a CLOUDFLARE
// rejection -- because the engine's own refusal sentence contains the word "permission".
{
  const r = await drive({ caps: "missing-kv" }, KV_SOURCE, []);
  seen.scope = r.cls as AttachFaultClass;
  eq("(2) the token capability pre-flight refusing -> token-scope", r.cls, "token-scope");
  ok("(2) and the operator's checklist is unchanged", /the token cannot use/.test(r.message));
}

// (2b) the token is outside its validity window: a DIFFERENT token fault with a different remedy (wait, or
// re-mint), and it must not be the same row as a missing capability.
{
  const r = await drive({ tokenWindow: "not-yet-active" }, KV_SOURCE, []);
  seen.window = r.cls as AttachFaultClass;
  eq("(2b) a not-yet-active token -> token-window", r.cls, "token-window");
}

// (3) THE WRITE GENUINELY FAILED. Cloudflare turned the settings PATCH down with a prose body. Nothing was
// changed (settings updates are atomic), and the remedy is Cloudflare's. Without the classifier this would be
// `other`: THE SAME ROW AS THE SAFETY HARNESS DOING ITS JOB.
{
  const r = await drive({ patch: "cf-rejects" }, KV_SOURCE, []);
  seen.write = r.cls as AttachFaultClass;
  eq("(3) the settings PATCH failing at Cloudflare -> cf-write-failed", r.cls, "cf-write-failed");
  ok("(3) and the message still says nothing was changed", /nothing was changed/.test(r.message));
}

// (4) the CLOUDFLARE READ failing with a status. Deliberately NOT a phase class: the status is more precise than
// any phase label, and it still classifies as it always did.
{
  const r = await drive({ read: "http-500" }, KV_SOURCE, []);
  seen.readFail = r.cls as AttachFaultClass;
  eq("(4) a Cloudflare 5xx on the settings READ -> unavailable (the status-derived classes are untouched)", r.cls, "unavailable");
}

// (0) the happy path still works: the harness writes, and nothing is recorded as a fault.
{
  const r = await drive({}, KV_SOURCE, []);
  eq("(0) a clean attach throws nothing at all", r.cls, "no-throw");
}

// ==============================================================================================
section("A ROW MUST NOT ASSERT A FACT THE CODE NEVER TESTED (the lost answer, and the rejected token)");
// ==============================================================================================
//
// Two states are easy to mis-file under a class whose MEANING asserts something the code has not established.
// Both are driven here through the REAL changeBindings, with a REAL fetch rejection and a REAL Cloudflare error
// body.

// THE LOST RESPONSE. cf-write-failed's meaning is "the settings PATCH did not land at Cloudflare. Settings
// updates are atomic, so nothing was changed". Atomicity says the write either fully applied or did not; it does
// NOT say WHICH, and a reply that dies on the way back is exactly the case where Cloudflare may have applied it.
// Filing that as cf-write-failed puts "nothing was changed" in the pack, in the owner's #1 fear domain, over a
// write we cannot vouch for, with the post-write verify never reached.
{
  const lost = await drive({ patch: "no-answer" }, KV_SOURCE, []);
  const answered = await drive({ patch: "cf-rejects" }, KV_SOURCE, []);
  eq("a PATCH that got NO ANSWER -> write-unconfirmed (the write MAY have landed)", lost.cls, "write-unconfirmed");
  eq("a PATCH Cloudflare ANSWERED and refused -> cf-write-failed (nothing changed: a PROVEN fact)", answered.cls, "cf-write-failed");
  ok("and the two are DIFFERENT classes: one says retry, the other says re-read the live bindings first", lost.cls !== answered.cls);
  ok("the unconfirmed write does NOT claim nothing was changed", !/nothing was changed/.test(lost.message));
}

// THE REJECTED TOKEN. Cloudflare answers "Invalid API Token" with its own error code 1000 on an HTTP 400, not a
// 401. A status-only classifier would file it as the residual, whose sentence is "this is a Cloudflare fault, not
// a token fault, so do not re-mint the token on account of it" -- told to the one operator whose token IS the fault.
{
  const badToken = await drive({ capsFault: "cf-token-invalid" }, KV_SOURCE, []);
  const cfDown = await drive({ capsFault: "cf-500" }, KV_SOURCE, []);
  eq("Cloudflare rejecting the TOKEN (400, code 1000) -> token-window, and the operator is told to re-mint", badToken.cls, "token-window");
  ok("and the message does NOT tell them to leave the token alone", !/do not re-mint/.test(badToken.message));
  eq("a Cloudflare 5xx on the same probe -> unavailable (Cloudflare's fault; the token was never assessed)", cfDown.cls, "unavailable");
  ok("the two are DIFFERENT classes: one blames the token, the other blames Cloudflare", badToken.cls !== cfDown.cls);
  ok("and the Cloudflare-fault message still says NOT to re-mint the token", /do not re-mint/.test(cfDown.message));
}

section("THE DISCRIMINATION TEST -- the three states are three DIFFERENT classes");
{
  const three = [seen.harness, seen.scope, seen.write];
  ok("harness-refused, token-scope and cf-write-failed are three distinct classes", new Set(three).size === 3);
  ok(
    "and NONE of them is `other` -- the bucket the harness refusal and the Cloudflare write failure would otherwise SHARE",
    !three.includes("other" as AttachFaultClass),
  );
  ok("the token faults are two rows, not one (a missing capability and an expired token are different remedies)", seen.scope !== seen.window);
  ok("and a failed Cloudflare READ is a fourth row again", !three.includes(seen.readFail!));
}

// ==============================================================================================
section("an attach and a DETACH are the same POST, and would otherwise be the same row");
// ==============================================================================================
{
  ok("`detach` is now an op in its own right", (ATTACH_OPS as readonly string[]).includes("detach"));
  // The route's rule, asserted as the console's rule: a pure removal is a detach, anything that ADDS is an attach
  // (the addition is the half that expands the protected set and deploys).
  const opFor = (add: number, remove: number): string => (add === 0 && remove > 0 ? "detach" : "attach");
  eq("a pure removal is a detach", opFor(0, 1), "detach");
  eq("an addition is an attach", opFor(1, 0), "attach");
  eq("a change that does BOTH is an attach", opFor(1, 1), "attach");

  // And the refusal classes flow through the detach path for real: a detach of a binding that is not bound is the
  // safety harness refusing, and it now lands under `detach`.
  const r = await drive({}, [], ["SRC_KV_not_bound"]);
  eq("a detach the harness refuses -> safety-prove-failed", r.cls, "safety-prove-failed");
  ok("and the operator's message is unchanged", /it is not bound to the engine/.test(r.message));
}

// ==============================================================================================
section("the same three states are three DIFFERENT cells in the pack");
// ==============================================================================================
//
// A class that discriminates in the classifier and coalesces in the aggregate discriminates nothing. The record is
// keyed op -> class -> count, so the fold is driven for real and the cells are compared.
{
  let health: AttachHealth | undefined;
  const fold = (op: string, fault?: string): void => {
    health = applyAttachHealth(health, fault !== undefined ? { op, fault } : { op }, 1_000);
  };
  fold("attach", "safety-prove-failed");
  fold("attach", "token-scope");
  fold("attach", "cf-write-failed");
  fold("detach", "safety-prove-failed");
  fold("reattach", "cf-write-failed");
  fold("attach"); // a SUCCESS: it clears a failing streak, and "it worked on the third try" is its own story

  const f = health!.faults;
  eq("attach: the harness refusal has its own cell", f.attach?.["safety-prove-failed"], 1);
  eq("attach: the token-scope refusal has its own cell", f.attach?.["token-scope"], 1);
  eq("attach: the Cloudflare write failure has its own cell", f.attach?.["cf-write-failed"], 1);
  ok("the three do NOT coalesce", Object.keys(f.attach ?? {}).length === 3);
  eq("a refused DETACH lands under `detach`, not under `attach`", f.detach?.["safety-prove-failed"], 1);
  eq("and a refused re-attach under `reattach`", f.reattach?.["cf-write-failed"], 1);
  eq("the successful attach is counted as a success, not a fault", health!.successes.attach, 1);
  eq("and the attempts denominator counts all four attaches", health!.attempts.attach, 4);
}

// ==============================================================================================
section("NO-CUSTODY -- the tag rides, the message does not");
// ==============================================================================================
{
  // Every one of these carries the customer's own binding names, a Cloudflare account id and Cloudflare's own
  // prose in the MESSAGE the operator reads. None of it may reach the record.
  const r = await drive({ caps: "missing-kv" }, [{ type: "kv", binding: "SRC_KV_acme_prod", namespaceId: "acme-prod-secrets" }], []);
  eq("(the refusal under test is the token-scope one)", r.cls, "token-scope");
  ok("the operator's message DOES carry the account id (it is theirs, on their screen)", /acct/.test(r.message));

  let health: AttachHealth | undefined = applyAttachHealth(undefined, { op: "attach", fault: r.cls }, 1_000);
  // And the belt-and-braces: even a call site that tried to post a value cannot get one in. applyAttachHealth is
  // the single redaction chokepoint and it re-gates the op and the class against the closed sets.
  health = applyAttachHealth(health, { op: "attach", fault: "s3://acme-prod-secrets/key?token=abc" }, 1_001);
  health = applyAttachHealth(health, { op: "acme-prod", fault: "safety-prove-failed" }, 1_002);
  const dumped = JSON.stringify(health);
  ok("no bucket, no account id, no binding name and no Cloudflare prose in the record", !/acme|s3:|token=|SRC_KV|script_too_large|acct/.test(dumped));
  ok("an out-of-vocabulary CLASS's VALUE is dropped whole (never coerced to a nearby member)", !dumped.includes("s3"));
  // But the FAILURE it reported is NOT dropped: without this, an unclassified fault would fall through to
  // successes[op], so a failed attach carrying a class the fold does not know would read byte-identical to a
  // successful one.
  eq("and the attempt it reported is recorded as a FAILURE, not a success", health.faults.attach?.unclassified, 1);
  eq("so the success count of the heal is not inflated by it", health.successes.attach, undefined);
  ok("an out-of-vocabulary OP is dropped whole", !dumped.includes("acme-prod"));
  ok("and the legitimate row survives", /token-scope/.test(dumped));

  // The vocabulary itself is closed and every member is a product constant.
  ok(
    "every ATTACH_FAULT_CLASSES member is a lower-case product constant (no value could ever be one)",
    ATTACH_FAULT_CLASSES.every((c) => /^[a-z-]+$/.test(c)),
  );
}

console.log(failures === 0 ? "\nALL PASS (availability: attach/detach/reattach classification)" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
