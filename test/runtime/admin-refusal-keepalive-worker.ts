// RUNTIME PROBE ENTRY for the admin-refusal keep-alive test. NOT part of the production deploy
// (the production entry is src/index.ts); it is loaded only by test/runtime/runtime.admin-refusal-keepalive.test.mjs.
//
// PURPOSE. Settle whether a refusal recorded with a BARE `void recordAdminRefusal(...)` immediately
// before a Response is returned actually LANDS in the scheduler DO, or is abandoned when the request
// context is torn down. In Node (every existing validator) a floating promise always completes, so the
// two shapes are indistinguishable. Under REAL workerd, reached over a REAL socket via Miniflare's
// dispatchFetch, the IoContext is destroyed after the response, and only ctx.waitUntil work is drained.
//
// This entry deliberately mixes:
//   (a) the PRODUCTION admin router (handleAdmin), so the three bare call sites under investigation are
//       driven exactly as a live request drives them, with a real AdminRuntime carrying ctx.waitUntil;
//   (b) three CALIBRATION arms that call the SAME recorder against the SAME DO route and the SAME
//       storage, differing ONLY in how the promise is held: bare void / ctx.waitUntil / await. Any
//       difference between those three is the runtime and nothing else.
//   (c) a read-back route that reads the DO's own GET /admin-refusals pack read.
//
// The calibration surfaces (key-install, key-rotate, update-apply) are in-vocabulary members that the
// product drives below never touch, so the arms cannot contaminate each other or the measurement.

import { recordAdminRefusal } from "../../src/admin/diag-admin.ts";
import { bumpAdminCounter, noteTestOutcome } from "../../src/admin/diag-counters.ts";
import type { AdminRefusalReason, AdminRefusalSurface } from "../../src/admin/diag-records.ts";
import { handleAdmin } from "../../src/admin/router.ts";
import { callerHeaders } from "../../src/admin/router-audit.ts";
import { requireStepUp } from "../../src/admin/router-core.ts";
import { recordAuthSignalEdge } from "../../src/admin/router-helpers.ts";
import { routeAuthChangeAlert, routeDualControlDisarmAlert, routePostureRegressions, routeRecoveryAlert, routeSignInContextAlert } from "../../src/admin/router-notify.ts";
import { handleScim } from "../../src/admin/scim.ts";
import { doURL } from "../../src/do-url.ts";
import { SchedulerDO } from "../../src/sched/scheduler-do.ts";

export { SchedulerDO };

// RefusalSlowDO exists ONLY to hold a subrequest OPEN across the moment the outer response returns, which
// is the shape the real risk has: recordAdminRefusal issues scheduler.fetch(...) and does not await it,
// so the question is what workerd does to a subrequest still in flight when the IoContext is dropped.
// The production recorder's round trip is sub-millisecond in this harness, far too fast to expose that,
// so this DO makes the window explicit and adjustable.
export class RefusalSlowDO {
  private readonly state: DurableObjectState;
  constructor(state: DurableObjectState) {
    this.state = state;
  }
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/read") {
      const bare = (await this.state.storage.get<number>("bare")) ?? 0;
      const kept = (await this.state.storage.get<number>("kept")) ?? 0;
      return new Response(JSON.stringify({ bare, kept }), { headers: { "content-type": "application/json" } });
    }
    const arm = url.pathname === "/kept" ? "kept" : "bare";
    const delay = Number(url.searchParams.get("d") ?? "0");
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    const prior = (await this.state.storage.get<number>(arm)) ?? 0;
    await this.state.storage.put(arm, prior + 1);
    return new Response(JSON.stringify({ ok: true }));
  }
}

interface ProbeEnv {
  SCHEDULER: DurableObjectNamespace;
  REFUSAL_SLOW: DurableObjectNamespace;
  ADMIN_TOKEN?: string;
  CONFIG_WRAP_KEY?: string;
}

function stubOf(env: ProbeEnv): DurableObjectStub {
  // Byte-identical resolution to src/admin/router-helpers.ts's schedulerStub.
  return env.SCHEDULER.get(env.SCHEDULER.idFromName("account-scheduler"));
}

// notifyalertResolveHits counts the `/notify/resolve` subrequests the notify-alert wrappers below observe, and
// it is THE REACHABILITY ARM FOR THIS RECORD CLASS. The destination-change drive's own arm was the webhook
// delivery, counted at the stub sink: that proves the emission ran, but it is issued AFTER the channel resolve
// is awaited, so an emission that is abandoned AT ITS FIRST AWAIT posts nothing and reads as a drive that
// never happened. The posture-regression call site is exactly that shape, so the arm had to move EARLIER than
// the first await.
//
// routeEmission's first statement is `await scheduler.fetch(doURL("/notify/resolve"), ...)`, and a fetch is
// ISSUED synchronously at the moment routeEmission is entered. So a counted /notify/resolve proves the alert
// line executed, and it proves it before anything downstream can be dropped. It is a module-level counter
// rather than a DO write on purpose: a DO write would itself be a subrequest, and therefore droppable, which
// is the very failure it is trying to detect.
let notifyalertResolveHits = 0;

// A calibration arm: SAME recorder, SAME DO route, SAME storage key. Only the hold differs.
const BARE: [AdminRefusalSurface, AdminRefusalReason] = ["key-install", "validation"];
const KEPT: [AdminRefusalSurface, AdminRefusalReason] = ["key-rotate", "validation"];
const AWAITED: [AdminRefusalSurface, AdminRefusalReason] = ["update-apply", "validation"];

export default {
  async fetch(req: Request, env: ProbeEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    // ---- calibration arms -------------------------------------------------------------------------
    if (url.pathname === "/refusal/bare") {
      void recordAdminRefusal(stubOf(env), BARE[0], BARE[1]);
      return new Response(JSON.stringify({ arm: "bare" }), { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/refusal/kept") {
      ctx.waitUntil(recordAdminRefusal(stubOf(env), KEPT[0], KEPT[1]));
      return new Response(JSON.stringify({ arm: "kept" }), { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/refusal/awaited") {
      await recordAdminRefusal(stubOf(env), AWAITED[0], AWAITED[1]);
      return new Response(JSON.stringify({ arm: "awaited" }), { headers: { "content-type": "application/json" } });
    }

    // ---- calibration arms with the write DELAYED behind an await, so the promise is genuinely
    // outstanding at the moment the response returns (the production recorder is too fast to expose it)
    const d = url.searchParams.get("d") ?? "0";
    if (url.pathname === "/refusal/bare-delay") {
      void (async () => {
        await new Promise((r) => setTimeout(r, Number(d)));
        await recordAdminRefusal(stubOf(env), "restore-apply", "validation");
      })();
      return new Response(JSON.stringify({ arm: "bare-delay", d }), { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/refusal/kept-delay") {
      ctx.waitUntil(
        (async () => {
          await new Promise((r) => setTimeout(r, Number(d)));
          await recordAdminRefusal(stubOf(env), "drill", "validation");
        })(),
      );
      return new Response(JSON.stringify({ arm: "kept-delay", d }), { headers: { "content-type": "application/json" } });
    }

    // ---- calibration arms with the SUBREQUEST ITSELF still in flight when the response returns -----
    const slow = (): DurableObjectStub => env.REFUSAL_SLOW.get(env.REFUSAL_SLOW.idFromName("refusal-slow"));
    if (url.pathname === "/refusal/bare-slowdo") {
      void slow().fetch(`https://slow.internal/bare?d=${d}`);
      return new Response(JSON.stringify({ arm: "bare-slowdo", d }), { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/refusal/kept-slowdo") {
      ctx.waitUntil(slow().fetch(`https://slow.internal/kept?d=${d}`));
      return new Response(JSON.stringify({ arm: "kept-slowdo", d }), { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/refusal/slowread") {
      const r = await slow().fetch("https://slow.internal/read");
      return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json" } });
    }

    // ---- read-back: the DO's OWN pack read, not a reconstruction ----------------------------------
    if (url.pathname === "/refusal/read") {
      const resp = await stubOf(env).fetch(doURL("/admin-refusals"));
      return new Response(await resp.text(), { status: resp.status, headers: { "content-type": "application/json" } });
    }

    // ---- the product, with the DIAGNOSTIC DO WRITE MADE TO FAULT ------------------------------------
    // This is the sharp product-path experiment. recordDiagWrite's whole reason for existing is that a DO
    // which is unavailable must not drop the write silently: on a non-2xx it notes the loss in the
    // isolate-local tally and FLUSHES it, so the pack still shows that something was lost. Both of those
    // happen AFTER `await write()`, i.e. in a continuation that only runs if the request context is still
    // alive. So under a faulting DO, the bare sites should lose the refusal AND its drop accounting, while
    // the helper sites keep the accounting. Only the /diag/admin-refusal route is faulted; every other DO
    // call (the rate limiter, the write itself, the dropped-writes flush) goes to the real DO untouched.
    if (url.pathname.startsWith("/refusal-fault/admin")) {
      const faulted = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              const href = typeof input === "string" ? input : (input as Request).url;
              if (new URL(href).pathname === "/diag/admin-refusal") {
                return Promise.resolve(new Response(JSON.stringify({ error: "refusal injected DO fault" }), { status: 503, headers: { "content-type": "application/json" } }));
              }
              return real.fetch(input as Request, init);
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const inner = new Request(req.url.replace("/refusal-fault/admin", "/admin"), req);
      const runtime = {
        sealNow: () => {},
        waitUntil: (task: Promise<unknown>) => {
          ctx.waitUntil(task);
        },
      };
      return handleAdmin(inner, { ...env, SCHEDULER: faulted } as unknown as Parameters<typeof handleAdmin>[1], runtime);
    }

    // ---- the product, with the DO subrequest NOT DISPATCHED IN THE CALLER'S SYNCHRONOUS TURN -------
    // In this local runtime the scheduler DO sits in the same workerd process on a loopback, so
    // scheduler.fetch(...) is dispatched inside the caller's own synchronous turn and the outstanding
    // subrequest then keeps the context alive by itself. That is the FRIENDLIEST possible scheduling, and
    // it is not what a live deployment gives you: a Durable Object is a separate object on separate
    // hardware, and the dispatch can land after the caller's turn has ended. This wrapper models exactly
    // that one condition -- the fetch is performed a tick later -- and CHANGES NOTHING ELSE. The helper
    // call sites run under the identical wrapper, so any difference between the two is the keep-alive.
    if (url.pathname.startsWith("/refusal-defer/admin")) {
      const deferred = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: (input: RequestInfo, init?: RequestInit): Promise<Response> =>
              new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              }),
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const inner = new Request(req.url.replace("/refusal-defer/admin", "/admin"), req);
      const runtime = {
        sealNow: () => {},
        waitUntil: (task: Promise<unknown>) => {
          ctx.waitUntil(task);
        },
      };
      return handleAdmin(inner, { ...env, SCHEDULER: deferred } as unknown as Parameters<typeof handleAdmin>[1], runtime);
    }

    if (url.pathname === "/refusal/dropped") {
      const resp = await stubOf(env).fetch(doURL("/dropped-writes"));
      return new Response(await resp.text(), { status: resp.status, headers: { "content-type": "application/json" } });
    }

    // ---- the SIGNAL SWEEP arms: the same deferred dispatch, plus a DO route made to fail ----------------
    //
    // The three sites the deferred drive above settled all fire on a plain validation refusal, which a bearer
    // caller can produce directly. The remaining ten signals mostly do NOT: an auth-plane edge signal fires
    // precisely when the auth plane's own backing store answered badly or not at all, and a degraded-read
    // counter fires when a read the route depends on came back non-ok. So a drive that cannot make a NAMED DO
    // ROUTE misbehave cannot reach them at all, and would read a clean zero for a site it never executed.
    //
    // THE FAULT IS SCOPED BY PATHNAME (and, for the shared /rate-check route, by the KEY PREFIX in the posted
    // body, which is the only thing that separates the per-caller limiter from the per-IP auth limiter and the
    // bare-token limiter). Every other DO call -- above all the RECORDER routes and the READ-BACK routes --
    // goes to the real DO untouched, so a zero here is a lost record and never a broken reader.
    //
    //   throw      the stub's fetch rejects: the call site's catch arm ("... unavailable")
    //   noverdict  a 200 whose body carries no verdict token: the ANSWERED-BUT-BROKEN arm ("... malformed")
    //   notok      a 503 with a JSON body: the degraded-read arm (scheduler.fetch does not throw on a status)
    //   verified   a 200 {"verdict":"verified"} with nothing else: the rotten-accept arm (session-shape-invalid)
    if (url.pathname.startsWith("/signal-defer/admin")) {
      const faultPath = req.headers.get("x-signal-fault-path");
      const faultMode = req.headers.get("x-signal-fault-mode") ?? "throw";
      const faultKeyPrefix = req.headers.get("x-signal-fault-keyprefix");
      const faulted = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: async (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              const href = typeof input === "string" ? input : (input as Request).url;
              const path = new URL(href).pathname;
              let hit = faultPath !== null && path === faultPath;
              // /rate-check is shared by three different limiters. Separate them on the key namespace the
              // caller posts, so faulting the bare-token limiter cannot also fault the per-caller one.
              if (hit && faultKeyPrefix !== null) {
                let key = "";
                try {
                  const raw = typeof input === "string" ? (init?.body ?? "") : await (input as Request).clone().text();
                  key = String((JSON.parse(String(raw)) as { key?: unknown }).key ?? "");
                } catch {
                  key = "";
                }
                // "-" means "the key must NOT carry either of the two ip: namespaces" (the per-caller limiter).
                hit = faultKeyPrefix === "-" ? !key.startsWith("ip:") && !key.startsWith("admin-token-ip:") : key.startsWith(faultKeyPrefix);
              }
              if (hit) {
                if (faultMode === "throw") throw new Error("signal injected DO fault");
                if (faultMode === "noverdict") return new Response(JSON.stringify({ signal: "answered without a verdict" }), { status: 200, headers: { "content-type": "application/json" } });
                if (faultMode === "deny") return new Response(JSON.stringify({ allowed: false, retryAfterMs: 30000 }), { status: 200, headers: { "content-type": "application/json" } });
                if (faultMode === "verified") return new Response(JSON.stringify({ verdict: "verified" }), { status: 200, headers: { "content-type": "application/json" } });
                return new Response(JSON.stringify({ error: "signal injected DO fault" }), { status: 503, headers: { "content-type": "application/json" } });
              }
              // The dispatch lands a tick AFTER the caller's turn, which is what a Durable Object on separate
              // hardware gives you and what a same-process loopback hides. Identical for every arm.
              //
              // x-signal-defer: 0 turns the deferral OFF and keeps the fault. That arm is the REACHABILITY
              // CONTROL, and it is the one that separates "the record was lost" from "the drive never executed
              // the line": on the native loopback the subrequest is dispatched inside the caller's own turn and
              // keeps the context alive by itself, so a site that was REACHED records under it whatever its
              // keep-alive. A zero on BOTH arms is a drive that missed, not a defect.
              if (req.headers.get("x-signal-defer") === "0") return real.fetch(input as Request, init);
              return new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              });
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const inner = new Request(req.url.replace("/signal-defer/admin", "/admin"), req);
      const runtime = {
        sealNow: () => {},
        waitUntil: (task: Promise<unknown>) => {
          ctx.waitUntil(task);
        },
      };
      return handleAdmin(inner, { ...env, SCHEDULER: faulted } as unknown as Parameters<typeof handleAdmin>[1], runtime);
    }

    // /signal-stepup reproduces the step-up gate's CALL SITE, which a bearer caller structurally cannot reach:
    // requireStepUp returns null immediately for the token and access methods, so the two recorders inside it
    // only run for a cookie-borne caller, and this harness cannot mint a signed session (the signing key never
    // leaves the DO). So the route below is the call site itself, copied verbatim from router.ts:547 and its
    // four twins -- await the gate, return its Response -- with the same deferred dispatch, the same faulted
    // DO route and the same real recorder. It is a LEAF drive, not a drive over the product's own route, and
    // it is labelled that way in the report.
    if (url.pathname === "/signal-stepup") {
      const mode = url.searchParams.get("mode") ?? "throw";
      const deferred = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              const href = typeof input === "string" ? input : (input as Request).url;
              if (new URL(href).pathname === "/stepup/check") {
                if (mode === "throw") return Promise.reject(new Error("signal injected DO fault"));
                return Promise.resolve(new Response(JSON.stringify({ signal: "answered without a verdict" }), { status: 200, headers: { "content-type": "application/json" } }));
              }
              if (url.searchParams.get("defer") === "0") return real.fetch(input as Request, init);
              return new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              });
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const stub = deferred.get(deferred.idFromName("account-scheduler"));
      // The call site passes the runtime exactly as router.ts:547 and its four twins do; ?runtime=0 drops
      // it, which is the arm that shows the loss.
      const keepAlive = url.searchParams.get("runtime") === "0" ? undefined : { waitUntil: (t: Promise<unknown>) => ctx.waitUntil(t) };
      const stepUp = await requireStepUp(req, stub, "passkey", keepAlive);
      if (stepUp) return stepUp;
      return new Response(JSON.stringify({ signal: "the gate admitted, which it must never do here" }), { status: 500, headers: { "content-type": "application/json" } });
    }

    // /signal/awaited is the READER'S OWN KNOWN POSITIVE, one per aggregate this sweep reads. It is AWAITED, so
    // no teardown can take it: if it is not read back, the reader is dead and every zero beside it is worthless.
    if (url.pathname === "/signal/awaited") {
      const s = stubOf(env);
      await recordAuthSignalEdge(s, "recovery-ratelimited");
      await bumpAdminCounter(s, "degraded-read-providers-list");
      await noteTestOutcome(s, "idp", { ok: false, reason: "signal-sweep known positive" });
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    }

    // ---- DEST-CHANGE-ALERT SETUP ARMS: the state the four destination-change ALERT call sites need before
    // they fire ----------------------------------------------------------------------------------------------
    //
    // Three of the four alerts are guarded by `if (resp.ok)` on a DO write that REFUSES unless a destination
    // already exists ("no such destination"), and the fourth needs one to edit. So a drive with an empty
    // collection never executes the alert line at all and would read a clean zero for a site it never reached.
    //
    // THE SEED GOES STRAIGHT TO THE DO, NOT THROUGH THE ADMIN ROUTER, and that is deliberate: the router's own
    // add path FIRES ONE OF THE FOUR ALERTS UNDER TEST, so seeding through it would put the measurement's own
    // setup into the aggregate it then reads. The DO's POST /destinations is the same route the router forwards
    // to, with the same caller header the router builds, so the stored record is the one the product stores.
    // Nothing here touches a recorder, a read-back route or the keep-alive under test.
    if (url.pathname === "/signal/seed-dest") {
      const id = url.searchParams.get("id") ?? "destchange-seed";
      const r = await stubOf(env).fetch(doURL("/destinations"), {
        method: "POST",
        body: JSON.stringify({
          id,
          label: "destchange seed",
          config: { endpoint: "https://s3.destchange-sink.test", bucket: "destchange-bucket", region: "auto", accessKeyId: "DESTCHANGETESTKEYID000000", secretAccessKey: "destchange-test-secret", verifiedAt: Date.now(), deleteProbe: "ok", objectLock: "not-enforced" },
        }),
        headers: callerHeaders({ method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Parameters<typeof callerHeaders>[0]),
      });
      return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json" } });
    }

    // /signal/wire-alert-channel puts the estate into the shape where the alert has somewhere to GO: one webhook
    // channel and one global rule that selects every event. Without it routeEmission takes its SHORTEST path
    // (resolve, no channel, count it and return); with it the path runs delivery and then the notify-history
    // write. The two paths hand the record off at different moments, so both are measured rather than assumed.
    // The sink host is a .test name answered by the driver's outboundService: no packet leaves the machine.
    if (url.pathname === "/signal/wire-alert-channel") {
      const hdr = callerHeaders({ method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Parameters<typeof callerHeaders>[0]);
      const chResp = await stubOf(env).fetch(doURL("/notify/channels"), {
        method: "POST",
        body: JSON.stringify({ kind: "webhook", name: "destchange sink", url: "https://hook.destchange-sink.test/alert", enabled: true }),
        headers: hdr,
      });
      const chText = await chResp.text();
      if (!chResp.ok) return new Response(JSON.stringify({ stage: "channel", status: chResp.status, body: chText }), { status: 500, headers: { "content-type": "application/json" } });
      const chId = (JSON.parse(chText) as { id?: string }).id ?? "";
      const ruleResp = await stubOf(env).fetch(doURL("/notify/rules"), {
        method: "POST",
        body: JSON.stringify({ scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [chId], enabled: true, digest: "off" }),
        headers: hdr,
      });
      const ruleText = await ruleResp.text();
      if (!ruleResp.ok) return new Response(JSON.stringify({ stage: "rule", status: ruleResp.status, body: ruleText }), { status: 500, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ ok: true, channelId: chId, rule: JSON.parse(ruleText) }), { headers: { "content-type": "application/json" } });
    }

    // /signal-alert-probe is the LEAF DRIVE of routeAuthChangeAlert, and it is labelled that way in the report:
    // it is NOT a drive over the product's own route. It exists because the four product routes read the SAME
    // zero on the deferred arm AND on the native-dispatch reachability arm, and a zero on both arms is
    // normally a drive that missed. This route separates the two readings the only way that settles them: the
    // SAME alert, the SAME DO, the SAME reader, the SAME deferred dispatch, with ONLY THE HOLD DIFFERENT.
    //
    //   ?hold=bare        void routeAuthChangeAlert(...)                        drops the promise
    //   ?hold=waituntil   ctx.waitUntil(routeAuthChangeAlert(...))              the production shape
    //   ?hold=await       await routeAuthChangeAlert(...)                       the caller waits for it
    //   ?hold=settle      await routeAuthChangeAlert(...); await a 400ms turn    the caller then keeps working
    //
    // `settle` is the POSITIVE CONTROL of the right kind for this record: if the row lands under it and not
    // under `waituntil`, the reader is alive, the DO route is alive and the counter name is admitted, and the
    // only thing that separates them is how long the context stayed up.
    if (url.pathname === "/signal-alert-probe") {
      const hold = url.searchParams.get("hold") ?? "waituntil";
      const deferred = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              if (url.searchParams.get("defer") === "0") return real.fetch(input as Request, init);
              return new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              });
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const stub = deferred.get(deferred.idFromName("account-scheduler"));
      const detail = url.searchParams.get("detail") ?? "A backup destination was set/repointed.";
      const task = routeAuthChangeAlert(env as unknown as Parameters<typeof routeAuthChangeAlert>[0], stub, "dest-change", "dest-change", detail);
      if (hold === "bare") void task;
      else if (hold === "waituntil") ctx.waitUntil(task);
      else {
        await task;
        if (hold === "settle") await new Promise((r) => setTimeout(r, 400));
      }
      return new Response(JSON.stringify({ hold }), { headers: { "content-type": "application/json" } });
    }

    // /signal/read is the read-back, through the DO's OWN endpoints rather than a reconstruction.
    if (url.pathname === "/signal/read") {
      const s = stubOf(env);
      const one = async (p: string): Promise<unknown> => {
        try {
          const r = await s.fetch(doURL(p));
          if (!r.ok) return { signalReadStatus: r.status };
          return await r.json();
        } catch (e) {
          return { signalReadError: (e as Error).message };
        }
      };
      const diag = (await one("/sched-diag")) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          authSignals: await one("/auth-signals"),
          adminCounters: await one("/admin-counters"),
          attachHealth: await one("/attach-health"),
          discoveryHealth: await one("/discovery-health"),
          notifyHistory: await one("/notify/history"),
          testOutcomes: diag?.testOutcomes ?? null,
          adminRefusals: diag?.adminRefusals ?? null,
          droppedWrites: diag?.droppedWrites ?? null,
          alertingHealth: diag?.alertingHealth ?? null,
        }),
        { headers: { "content-type": "application/json" } },
      );
    }

    // =========================================================================================================
    // NOTIFY-ALERT ARMS. The destination-change drive above covers routeEmission for the four
    // destination-change alerts; every OTHER routeXxxAlert call site uses the same helper but was not yet
    // driven here. These arms drive those other call sites. They add routes; they change nothing the
    // signal-sweep arms above touch.
    //
    // WHY A SEPARATE DEFERRED WRAPPER RATHER THAN REUSING /signal-defer/admin: one site under test
    // (routePostureRegressions, router-posture.ts:340) fires only when the DO REPORTS A REGRESSION, and a
    // regression needs a prior snapshot in which the check passed. The wrapper below can hand the router the
    // DO's own real /posture answer with a regression present, which is exactly the state the router is
    // contracted to route and the only state in which that call site executes at all. The injection is
    // header-gated and inert without it, so this route with no header is byte-equivalent to /signal-defer/admin.
    // =========================================================================================================

    // NOTIFYALERT_REGRESSION_TITLE is the title the injected regression carries, and therefore the exact detail
    // routePostureRegressions composes: `Posture regression: ${title} now failing`. It is a name no real check
    // has, so a row carrying it can only have come from this drive.
    const NOTIFYALERT_REGRESSION_TITLE = "notify-alert probe check";

    if (url.pathname.startsWith("/notifyalert-defer/admin")) {
      const injectRegression = req.headers.get("x-notifyalert-inject-regression") === "1";
      const deferred = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: async (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              const href = typeof input === "string" ? input : (input as Request).url;
              const path = new URL(href).pathname;
              if (path === "/notify/resolve") notifyalertResolveHits++;
              // THE POSTURE INJECTION. The real DO computes the real report; only the `regressions` array it
              // returns is replaced, because detectRegressions needs a PRIOR SNAPSHOT in which the check
              // passed and this harness has no way to author one. The router's contract is "route what the DO
              // reports as a regression", so this is the DO speaking in the state the call site exists for.
              if (injectRegression && path === "/posture") {
                const realResp = await real.fetch(input as Request, init);
                const body = (await realResp.json()) as Record<string, unknown>;
                body.regressions = [{ id: "notifyalert-probe", title: NOTIFYALERT_REGRESSION_TITLE, severity: "critical" }];
                return new Response(JSON.stringify(body), { status: realResp.status, headers: { "content-type": "application/json" } });
              }
              // The dispatch lands a tick AFTER the caller's turn, which is what a Durable Object on separate
              // hardware gives you and what a same-process loopback hides. x-notifyalert-defer: 0 turns it off
              // and is the native-dispatch arm, reported beside the deferred one exactly as the destination-
              // change drive reported it.
              if (req.headers.get("x-notifyalert-defer") === "0") return real.fetch(input as Request, init);
              return new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              });
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const inner = new Request(req.url.replace("/notifyalert-defer/admin", "/admin"), req);
      const runtime = {
        sealNow: () => {},
        waitUntil: (task: Promise<unknown>) => {
          ctx.waitUntil(task);
        },
      };
      return handleAdmin(inner, { ...env, SCHEDULER: deferred } as unknown as Parameters<typeof handleAdmin>[1], runtime);
    }

    // /notifyalert-scim drives the SCIM leaver offboard (admin/scim.ts:268). SCIM sits OUTSIDE the admin router
    // tree -- index.ts dispatches handleScim directly and hands it a raw ctx.waitUntil -- so the only faithful
    // drive of that call site is this one, which mirrors index.ts:206 exactly (the same waitUntil closure) and
    // adds only the same deferred DO dispatch every other arm uses.
    if (url.pathname.startsWith("/notifyalert-scim")) {
      const deferred = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              if (new URL(typeof input === "string" ? input : (input as Request).url).pathname === "/notify/resolve") notifyalertResolveHits++;
              if (req.headers.get("x-notifyalert-defer") === "0") return real.fetch(input as Request, init);
              return new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              });
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const inner = new Request(req.url.replace("/notifyalert-scim", "/scim/v2"), req);
      return handleScim(inner, { ...env, SCHEDULER: deferred } as unknown as Parameters<typeof handleScim>[1], (task: Promise<unknown>) => {
        ctx.waitUntil(task);
      });
    }

    // /notifyalert/seed-role seeds a member row STRAIGHT ON THE DO, never through the admin router, for the same
    // reason the destination seed above does: POST /admin/roles is itself one of the call sites under test, so
    // seeding through it would put the measurement's own setup into the aggregate it then reads.
    if (url.pathname === "/notifyalert/seed-role") {
      const email = url.searchParams.get("email") ?? "notifyalert-seed@example.test";
      const r = await stubOf(env).fetch(doURL("/roles"), {
        method: "POST",
        body: JSON.stringify({ email, role: "viewer" }),
        headers: callerHeaders({ method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Parameters<typeof callerHeaders>[0]),
      });
      return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json" } });
    }

    // /notifyalert/seed-idp-conn seeds an IdP connection straight on the DO, so the delete / enable / cert
    // routes have a connection to act on. Same reasoning as the role seed: their own router routes are three
    // of the call sites under test.
    if (url.pathname === "/notifyalert/seed-idp-conn") {
      const id = url.searchParams.get("id") ?? "notifyalert-conn";
      const r = await stubOf(env).fetch(doURL("/idp/conn/create"), {
        method: "POST",
        body: JSON.stringify({
          proposal: {
            id,
            kind: "oidc",
            label: "notify-alert seed",
            presetId: "generic-oidc",
            issuer: "https://idp.notifyalert-sink.test",
            clientId: "notifyalert-client",
            scopes: ["openid"],
            idTokenSigAlgs: ["RS256"],
            pkce: "required",
            clientAuth: "pkce_public",
            requireNonce: true,
            enabled: false,
          },
        }),
        headers: callerHeaders({ method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Parameters<typeof callerHeaders>[0]),
      });
      return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json" } });
    }

    // /notifyalert/resolve-count reads the reachability arm and RESETS it, so each arm of each case reads only
    // its own drives. It is deliberately NOT a DO read: see notifyalertResolveHits.
    if (url.pathname === "/notifyalert/resolve-count") {
      const n = notifyalertResolveHits;
      if (url.searchParams.get("reset") === "1") notifyalertResolveHits = 0;
      return new Response(JSON.stringify({ resolves: n }), { headers: { "content-type": "application/json" } });
    }

    // /notifyalert/do is a RAW pass-through to one DO route, for setup and for reading a DO answer back. It never
    // touches the admin router and never touches a recorder or a keep-alive under test.
    if (url.pathname === "/notifyalert/do") {
      const p = url.searchParams.get("p") ?? "/sched-diag";
      const method = url.searchParams.get("m") ?? "GET";
      const body = method === "GET" ? undefined : await req.text();
      const r = await stubOf(env).fetch(doURL(p), {
        method,
        ...(body !== undefined ? { body } : {}),
        headers: callerHeaders({ method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Parameters<typeof callerHeaders>[0]),
      });
      return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json" } });
    }

    // ---- /notifyalert-hold-probe: the LEAF drive, and it is labelled that way in the report ------------------
    //
    // It is NOT a drive over the product's own route. It exists for the two things a product-route drive cannot
    // settle here. First, the sign-in-context and recovery-code alerts fire only from a completed SAML/OIDC/
    // passkey ceremony or a verified recovery-code round trip, none of which this harness can mint (the signing
    // key never leaves the DO). Second, and this is the point of the whole pass, the question is whether a
    // CALLER SHAPE loses the record now that the helper returns its writes -- and the only way to answer that
    // without confusing it with reachability is the same alert, the same DO, the same reader, the same deferred
    // dispatch, with ONLY THE HOLD DIFFERENT.
    //
    //   ?hold=bare        void routeXxx(...)                      router-posture.ts:340's shape
    //   ?hold=waituntil   ctx.waitUntil(routeXxx(...))            every fireInBackground site's shape
    //   ?hold=await       await routeXxx(...)                     router-config-version.ts:160 / router.ts:664
    //   ?hold=settle      await routeXxx(...) then keep working   THE POSITIVE CONTROL: if the row lands here
    //                                                             and not under a hold, the reader, the DO route
    //                                                             and the counter name were all alive throughout
    if (url.pathname === "/notifyalert-hold-probe") {
      const hold = url.searchParams.get("hold") ?? "waituntil";
      const which = url.searchParams.get("which") ?? "auth-change";
      const deferred = {
        idFromName: (n: string) => env.SCHEDULER.idFromName(n),
        get: (id: DurableObjectId) => {
          const real = env.SCHEDULER.get(id);
          return {
            id: real.id,
            fetch: (input: RequestInfo, init?: RequestInit): Promise<Response> => {
              if (new URL(typeof input === "string" ? input : (input as Request).url).pathname === "/notify/resolve") notifyalertResolveHits++;
              if (url.searchParams.get("defer") === "0") return real.fetch(input as Request, init);
              return new Promise<Response>((resolve, reject) => {
                setTimeout(() => {
                  real.fetch(input as Request, init).then(resolve, reject);
                }, 0);
              });
            },
          } as unknown as DurableObjectStub;
        },
      } as unknown as DurableObjectNamespace;
      const stub = deferred.get(deferred.idFromName("account-scheduler"));
      const e = env as unknown as Parameters<typeof routeAuthChangeAlert>[0];
      let task: Promise<unknown>;
      if (which === "sign-in-context") task = routeSignInContextAlert(e, stub);
      else if (which === "recovery-used") task = routeRecoveryAlert(e, stub, "recovery-code-used", url.searchParams.get("email"));
      else if (which === "recovery-abuse") task = routeRecoveryAlert(e, stub, "recovery-code-abuse", null);
      else if (which === "dual-control-disarm") task = routeDualControlDisarmAlert(e, stub, url.searchParams.get("email"), url.searchParams.get("via") ?? "a direct owner toggle");
      else if (which === "posture-regression")
        task = routePostureRegressions(e, stub, [{ id: "notifyalert-probe", title: NOTIFYALERT_REGRESSION_TITLE, severity: "critical" }] as unknown as Parameters<typeof routePostureRegressions>[2]);
      else
        task = routeAuthChangeAlert(
          e,
          stub,
          (url.searchParams.get("event") ?? "auth-credential-change") as Parameters<typeof routeAuthChangeAlert>[2],
          (url.searchParams.get("cls") ?? "credential-change") as Parameters<typeof routeAuthChangeAlert>[3],
          url.searchParams.get("detail") ?? "notify-alert leaf detail.",
        );
      if (hold === "bare") void task;
      else if (hold === "waituntil") ctx.waitUntil(task);
      else {
        await task;
        if (hold === "settle") await new Promise((r) => setTimeout(r, 400));
      }
      return new Response(JSON.stringify({ hold, which }), { headers: { "content-type": "application/json" } });
    }

    // ---- the product: the real admin router, with the real keep-alive capability -------------------
    if (url.pathname.startsWith("/admin")) {
      const runtime = {
        sealNow: () => {
          /* not on any refusal path */
        },
        waitUntil: (task: Promise<unknown>) => {
          ctx.waitUntil(task);
        },
      };
      return handleAdmin(req, env as unknown as Parameters<typeof handleAdmin>[1], runtime);
    }

    return new Response("not found", { status: 404 });
  },
};
