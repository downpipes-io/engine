// router-status.ts -- the onboarding-readiness status read, the preflight entitlement probe, and the
// supportability view + support-bundle download + ingest-credential mint/revoke. The per-route
// capability/role gate runs inline per route.

import { reportedArtefactSha384 } from "../format/build-id.ts";
import type { DownpipeConfig } from "../sched/types.ts";
import { envFlagEnabled } from "./auth.ts";
import { projectClientDiagnostics } from "./client-diag-receive.ts";
import { CLIENT_DIAG_MAX_BODY_BYTES } from "./client-diag-vocab.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { runPreflight } from "./preflight.ts";
import { planRosterReattach } from "./roster-reattach.ts";
import { callerHeaders, gate, ownerActionGate, ownerActionQueuedResponse, rateLimited, recordAudit } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { enumerateBoundSources } from "./router-sources.ts";
import { buildStatus, withAuditCapacity } from "./status.ts";
import { sealedSupportBundle } from "./support.ts";
import { type IngestGrant, type IngestScope, mintIngestCredential, redactGrant } from "./support-ingest.ts";

// handleStatus dispatches the status/preflight/support group. Returns the route's Response, or null when
// no case here matched (the hub falls to the next spoke). The hub already ran authorise(); per-route gates
// stay inline below, unmoved relative to the handler they guard.
export async function handleStatus(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, sourceIp } = ctx;
  switch (`${req.method} ${sub}`) {
    case "GET /status": {
      // Onboarding readiness: presence-only booleans. The scheduler DO is the authority for
      // the downpipe count (GET /downpipes returns the DownpipeState[]); buildStatus reads
      // only env presence and never a secret value. This route sits AFTER the auth gate
      // above because the set of configured-or-not facts is account reconnaissance.
      // Presence-safe: a DO hiccup reading the downpipe list (observed in a post-demo-reset window) must NOT
      // 500 the whole status read, which would break the console's auth/sign-in poll. Default to an empty
      // list so the count + restorabilityProven read 0 rather than throwing, mirroring the other reads here.
      let downpipes: Array<{ restoreProven?: unknown; config?: DownpipeConfig }> = [];
      let downpipesRead = false;
      try {
        const dpResp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
        const parsed = await dpResp.json();
        if (Array.isArray(parsed)) {
          downpipes = parsed as Array<{ restoreProven?: unknown; config?: DownpipeConfig }>;
          downpipesRead = true;
        }
      } catch {
        // leave downpipes empty; status still answers with the env-derived presence booleans.
        // G051: an empty roster is indistinguishable from a fleet the DO could not read, so /status reports
        // "0 downpipes, restorability 0" for a healthy fleet mid-blip -- and suppresses sourcesDetached.
        void bumpAdminCounter(scheduler, "degraded-read-status-presence");
      }
      // sourcesDetachedCount (proactive source-drift surface): how many configured source bindings are NOT
      // currently present on the engine, so their downpipes' next runs fail. Computed PURELY from the live
      // env bindings vs the roster already fetched above (reusing the re-attach planner, so the count equals
      // what a one-click re-attach would address), no extra DO round trip. A COUNT only crosses the wire,
      // never a binding name. Computed ONLY when the roster read SUCCEEDED: if it failed, the count stays
      // honestly ABSENT rather than a false "all attached" (a safety signal must never cry all-clear blind).
      let sourcesDetachedCount: number | undefined;
      if (downpipesRead) {
        const bound = enumerateBoundSources(env);
        const liveNames = new Set<string>([...bound.kv, ...bound.r2, ...bound.d1, ...bound.secrets]);
        const configs = downpipes.map((d) => d?.config).filter((c): c is DownpipeConfig => c !== undefined && c !== null);
        const plan = planRosterReattach(configs, liveNames);
        sourcesDetachedCount = plan.toAttach.length + plan.unreconstructable.length;
      }
      // restorabilityProven (restorability assurance): how many configured downpipes have a passed
      // "offline restorability last proven" record. Computed from the DownpipeState[] already fetched
      // above (no extra DO round trip); it is presence-only (a record's mere existence means a proof
      // passed), so the console can badge the proven count. The per-downpipe who+when comes from this
      // same /downpipes payload; only the integer count crosses into the status body.
      const restorabilityProven = downpipes.reduce((n, d) => (d && typeof d === "object" && d.restoreProven ? n + 1 : n), 0);
      // Fetch the expiry warning count (contract section 4) so status surfaces expiryWarnings. The
      // items live in the DO, not in env; this is one read, presence-safe (a DO hiccup degrades to the
      // count being honestly absent, not a fabricated 0, and never fails the status read). It carries
      // only the integer count; no item and no secret crosses the wire.
      let expiryWarnings: number | undefined;
      let cleanupPending: number | undefined;
      try {
        const expResp = await scheduler.fetch(doURL("/expiry/warnings"), { method: "GET" });
        const { expiryWarnings: n, cleanupPending: c } = (await expResp.json()) as { expiryWarnings?: number; cleanupPending?: number };
        if (typeof n === "number" && Number.isFinite(n)) expiryWarnings = n;
        if (typeof c === "number" && Number.isFinite(c)) cleanupPending = c;
      } catch {
        // Presence-safe: leave expiryWarnings/cleanupPending absent so status never fails on the expiry read.
      }
      // Break-glass disposal (the dispose-bootstrap-token finding + the retire control): read the two
      // DO-owned latches (bootstrapConsumed, breakGlassTokenRetired) in ONE round-trip so status surfaces
      // them. Presence-safe: a DO hiccup leaves them honestly ABSENT (not a fabricated false), so the console
      // simply does not render the finding/control rather than failing the status read. Only the two booleans
      // cross; no secret. The dedicated GET /policy/break-glass-disposal returns both latches together.
      let bootstrapConsumed: boolean | undefined;
      let breakGlassTokenRetired: boolean | undefined;
      try {
        const bgResp = await scheduler.fetch(doURL("/policy/break-glass-disposal"), { method: "GET" });
        const disposal = (await bgResp.json()) as { bootstrapConsumed?: boolean; breakGlassTokenRetired?: boolean };
        if (typeof disposal.bootstrapConsumed === "boolean") bootstrapConsumed = disposal.bootstrapConsumed;
        if (typeof disposal.breakGlassTokenRetired === "boolean") breakGlassTokenRetired = disposal.breakGlassTokenRetired;
      } catch {
        // Presence-safe: leave the latches absent so status never fails on the break-glass read.
      }
      // Recovery-code break-glass: the CALLER'S OWN unconsumed count, so the console can show "N codes left"
      // and prompt a regenerate when low. Scoped to the verified caller email (the DO never returns another
      // user's count); the bare-token break-glass has no email and thus no per-user count, so it is skipped
      // and the field stays absent. Presence-safe: a DO hiccup leaves it absent, never failing the status
      // read. Only the integer count crosses; never a code or a hash.
      let recoveryCodesRemaining: number | undefined;
      if (caller.email !== null) {
        try {
          const rcResp = await scheduler.fetch(doURL(`/recovery/remaining?email=${encodeURIComponent(caller.email)}`), { method: "GET" });
          const { remaining } = (await rcResp.json()) as { remaining?: number };
          if (typeof remaining === "number" && Number.isFinite(remaining)) recoveryCodesRemaining = remaining;
        } catch {
          // Presence-safe: leave the count absent so status never fails on the recovery read.
        }
      }
      // The console-set destination (DO-stored) wins over the env mirror, the same precedence the
      // factory applies at run time, so status never disagrees with what a run would do. Presence-
      // safe: a DO hiccup leaves the env mirror answering alone (consoleDestSet stays undefined).
      let consoleDestSet: boolean | undefined;
      let consoleDestHost: string | undefined;
      try {
        const destResp = await scheduler.fetch(doURL("/dest-status"), { method: "GET" });
        const { present, endpointHost, source } = (await destResp.json()) as { present?: boolean; endpointHost?: string; source?: string };
        // DEST-REPLACE-REASSIGN: source:"deploy" is the synthetic record standing in for the
        // deploy-time/env-configured destination (ensureDeployDestSeeded) -- present:true like any other
        // stored destination, but it carries no real credential and no endpoint host to report. Treating
        // it as a console-set destination here would report destKind from providerForEndpoint("") (a
        // wrong, specific guess -- "s3" -- rather than the env's own true kind) and would answer this
        // status read's env-vs-console precedence question backwards. consoleDestSet stays false for it,
        // exactly as it was before this record existed, so an estate with no REAL console destination
        // still reads its status from env facts.
        if (typeof present === "boolean") consoleDestSet = present && source !== "deploy";
        if (typeof endpointHost === "string") consoleDestHost = endpointHost;
      } catch {
        // Presence-safe: leave the fact absent so status never fails on the destination read.
      }
      // Demo reset honour: a demo reset wiped the DO and set a fresh-first-run marker, but it cannot delete
      // the engine's Worker Secrets, so the key-presence env vars persist. Read the marker (ONLY on a demo
      // engine, to avoid a per-request DO round-trip in production) and pass it so buildStatus masks the key
      // booleans, making the onboarding wizard see a genuinely fresh engine. Presence-safe: a DO hiccup leaves
      // the marker unread (undefined), so status reads keys honestly rather than failing the read.
      let demoFreshFirstRun: boolean | undefined;
      if (envFlagEnabled(env.DEMO_MODE)) {
        try {
          const frResp = await scheduler.fetch(doURL("/demo/first-run"), { method: "GET" });
          const { forceFirstRun } = (await frResp.json()) as { forceFirstRun?: boolean };
          if (forceFirstRun === true) demoFreshFirstRun = true;
        } catch {
          // Presence-safe: leave the marker unread so status never fails on the demo first-run read.
        }
      }
      // W1 provenance: resolve the engine's SELF-STAMPED artefact SHA-384 (the real hash of its own
      // deployable bundle) so status reports it instead of the manual-only env echo. reportedArtefactSha384
      // reads the optional generated build-stamp module dynamically; its absence (a test/tsc run, or an
      // unstamped build) is a clean null, so status honestly omits the field rather than fabricating one.
      const selfArtefact = await reportedArtefactSha384();
      // cfAccountId's DO-persisted fallback (LICENCE-BINDING-ON-CLAIM follow-up,): read the
      // engine's own account-id proof, recorded the first time an attach or update-apply succeeded (see
      // scheduler-do-account-config.ts recordVerifiedEngineAccount). env.CF_ACCOUNT_ID still wins inside
      // buildStatus when set; this round trip is presence-only (no Cloudflare API call, no secret), so it
      // is as cheap as the other DO reads on this route. Presence-safe: a DO hiccup leaves the field
      // absent rather than failing the status read.
      let verifiedCfAccountId: string | undefined;
      try {
        const vaResp = await scheduler.fetch(doURL("/sources/engine-account-verified"), { method: "GET" });
        const va = (await vaResp.json()) as { accountId?: string } | null;
        if (va && typeof va.accountId === "string" && va.accountId.trim() !== "") verifiedCfAccountId = va.accountId.trim();
      } catch {
        // Presence-safe: leave the field absent so status never fails on this read.
      }
      const report = buildStatus(env, downpipes.length, { expiryWarnings, restorabilityProven, bootstrapConsumed, breakGlassTokenRetired, recoveryCodesRemaining, consoleDestSet, consoleDestHost, cleanupPending, selfReportedArtefactSha384: selfArtefact, ...(sourcesDetachedCount !== undefined ? { sourcesDetachedCount } : {}), ...(demoFreshFirstRun !== undefined ? { demoFreshFirstRun } : {}), ...(verifiedCfAccountId !== undefined ? { verifiedCfAccountId } : {}) });
      // Engine-observed events (D4, F6 partial closure): hand the DO the presence booleans +
      // version it just computed so the DO can diff against its last-seen snapshot and append an
      // engine-secret-present / engine-version-change event for any change. This records the RESULT
      // of an out-of-band step (a `wrangler secret put`, a redeploy) without the console ever
      // submitting a value. Best-effort and side-channel: it never alters the status body, so a DO
      // hiccup degrades to "no observed event this poll", not a failed status read.
      // G100: CHECKED. This observation is the keystone -- it is what mints the
      // engine-version-change / engine-secret-present / engine-secret-absent audit events that answer "did a
      // deploy drop my source bindings?". A dropped observation means the deploy simply never appears in the
      // pack, which reads as "no redeploy happened" -- the exact wrong conclusion, in the exact window the
      // pack exists to explain. It stays best-effort and side-channel (the status body is unchanged); the
      // loss is now counted, so a post-deploy pack with a missing keystone SAYS SO instead of misleading.
      // AND ITS ANSWER IS NOW READ, WHICH IS THE WHOLE OF THE AUDIT-CAPACITY FIX. The DO's reply carries
      // the retained audit count, the near-cap verdict and the cumulative rolled-over count, and this call
      // site discarded all three from the day the retention cap was introduced. buildStatus derives
      // auditNearCap only from a count a caller supplies, and NO caller anywhere supplied one, so the field
      // was absent from every status body the engine has ever served. The console handles that absence
      // honestly, with "This engine build does not report audit-log capacity, so the console cannot warn
      // you before entries roll over" -- so the one warning whose whole purpose is to prompt an export
      // BEFORE the rollover destroys evidence had never fired on any estate, and could not.
      let capacity: { auditCount?: unknown; auditRolledOverCount?: unknown } = {};
      try {
        await recordDiagWrite(scheduler, "status-observation", async () => {
          const resp = await scheduler.fetch(doURL("/audit-status"), {
            method: "POST",
            body: JSON.stringify({
              signerConfigured: report.signerConfigured,
              breakGlassConfigured: report.breakGlassConfigured,
              destConfigured: report.destConfigured,
              engineVersion: report.engineVersion,
              cfVersionId: report.cfVersionId, // deploy identity, lets the DO record a redeploy, not just a software upgrade
            }),
            headers: { "content-type": "application/json" },
          });
          // Read from a CLONE so recordDiagWrite's own `resp.ok` check is untouched by this body read, and
          // so a malformed body can never turn a successful observation into a counted dropped write.
          if (resp.ok) {
            try {
              capacity = (await resp.clone().json()) as { auditCount?: unknown; auditRolledOverCount?: unknown };
            } catch {
              // A body we cannot parse leaves capacity empty, which is the honest unknown, not a false zero.
            }
          }
          return resp;
        });
      } catch {
        // Best-effort and side-channel: a DO hiccup degrades to "no observed event this poll", never
        // failing the status read. The report body is already computed and is returned unchanged.
      }
      return new Response(JSON.stringify(withAuditCapacity(report, capacity.auditCount, capacity.auditRolledOverCount)), { headers: { "content-type": "application/json" } });
    }
    case "GET /preflight": {
      // Onboarding entitlement verification (any authenticated role): live, read-only
      // probes that PROVE each Cloudflare prerequisite (Durable Objects, the cron
      // genuinely ticking, destination reachability, the Zero Trust team domain when
      // Access is configured, key parsing, the seal DO, the licence tier) rather than
      // assuming it, each with the required product and the remediation. The console
      // onboarding wizard and the support bundle both read this.
      // Rate-limited (ASVS V2.4.1) despite being a GET and despite deliberately having no
      // capability gate above (onboarding/support must work for a caller who legitimately lacks
      // downpipe.read): runPreflight fans out up to 11 live probes whose subrequest count scales
      // with the tenant's own configured downpipe/source count, so an unprivileged caller looping
      // this GET would otherwise run up the same account's Cloudflare bill and compete against the
      // same KV/R2/D1/destination the tenant's real scheduled run depends on.
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return new Response(JSON.stringify(await runPreflight(env, scheduler)), { headers: { "content-type": "application/json" } });
    }
    case "GET /support": {
      // Gate on posture.read (any authenticated role that holds it), matching every other
      // operational/security-posture read in this dispatch tree (GET /posture, GET /coverage in
      // router-config-version.ts): a custom role can legally be composed with NO read capability at
      // all, and without this the account's own least-privilege model was silently bypassed here.
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      // Rate-limited despite being a GET (router.ts's GET-exempt default assumes a cheap, idempotent
      // read): this view and its /bundle sibling below both fan out multiple scheduler DO round-trips
      // per call, so the same per-caller cap the mutating routes use also bounds this one.
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The customer-facing supportability view: whether a vendor sealing key is
      // configured, and the redacted state of each ingest credential (clientId, scope,
      // expiry, grantedBy, and the most recent 50 recorded pulls; never a secret or its hash).
      const [diagResp, feedResp, metricsResp] = await Promise.all([
        scheduler.fetch(doURL("/ingest-credential?scope=diagnostics"), { method: "GET" }),
        scheduler.fetch(doURL("/ingest-credential?scope=audit-feed"), { method: "GET" }),
        scheduler.fetch(doURL("/ingest-credential?scope=metrics"), { method: "GET" }),
      ]);
      const diag = ((await diagResp.json()) as { grant: IngestGrant | null }).grant;
      const feed = ((await feedResp.json()) as { grant: IngestGrant | null }).grant;
      const metrics = ((await metricsResp.json()) as { grant: IngestGrant | null }).grant;
      // signerConfigured is presence-only (the same boolean /status reports): a pre-ceremony
      // engine serves the bundle UNSIGNED, and the console copy must say so rather than claim
      // a signature that does not exist yet (HC-2).
      //
      // accessPerimeter: the edge injects cf-access-jwt-assertion on every request that traversed a
      // Cloudflare Access application, including perimeter-only deployments where CF_ACCESS_* is unset
      // and the header plays no part in auth. Its presence on THIS read means the hostname is
      // Access-fronted, so the out-of-band /support/* pulls (a SIEM collector, vendor support) AND the
      // top-level /metrics scrape (admin/metrics.ts) will be turned away at the edge unless the customer
      // adds an Access service token or a path-scoped exemption. The console warns at mint time from
      // this flag. It is a hint for copy only, never authority (access.ts: trusting mere header presence
      // for auth is a bypass).
      return new Response(
        JSON.stringify({
          vendorSealConfigured: Boolean(env.VENDOR_SUPPORT_PUBLIC),
          signerConfigured: Boolean(env.SIGNER_PRIVATE),
          accessPerimeter: req.headers.get("cf-access-jwt-assertion") !== null,
          diagnostics: redactGrant(diag),
          auditFeed: redactGrant(feed),
          metrics: redactGrant(metrics),
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    case "GET /support/bundle": {
      // Same posture.read gate as GET /support above: this is the FULL aggregated bundle (audit,
      // SSO/auth posture, replication, wrap-key health, licence, run history...), so the capability
      // check matters even more here than on the summary view.
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      // Rate-limited (ASVS V4.2.1): buildSupportBundle fans out on the order of 25 sequential DO
      // round-trips and, when a vendor seal key is configured, a fresh hybrid PQ (X25519+ML-KEM-1024)
      // encapsulation + AES-256-GCM seal on EVERY call -- an authenticated but unprivileged caller
      // looping this GET would otherwise compete uncapped against the same single per-account
      // SchedulerDO every real run depends on.
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The console download path for the support bundle (sealed to the vendor key when
      // configured, signed otherwise): the customer attaches it to a ticket themselves,
      // which is the default support flow needing NO inbound access at all.
      // accessPerimeter (G267) is threaded from THIS request: the edge injects cf-access-jwt-assertion on every
      // request that traversed a Cloudflare Access application, so its presence here means the hostname is
      // Access-fronted and a minted collector credential will be turned away at the edge. GET /support already
      // reported it to the console; the SEALED bundle now carries the same presence boolean (never the JWT).
      return new Response(JSON.stringify(await sealedSupportBundle(env, scheduler, { accessPerimeter: req.headers.get("cf-access-jwt-assertion") !== null })), { headers: { "content-type": "application/json" } });
      // The GET (and the vendor bearer-pull) carries NO console-diagnostics ring: only the POST sibling
      // below folds one in, so a GET STRUCTURALLY omits the clientDiagnostics section.
    }
    case "POST /support/bundle": {
      // The console GENERATE path (Wave C, I1 REQUEST-SCOPED ONLY): identical to the GET download but it also
      // accepts an OPTIONAL `clientDiagnostics` body -- the console's bounded, local, closed-class error ring.
      // The ring is re-validated + clamped here and folded into ONLY this in-request bundle, then discarded:
      // no DO write, no roster entry, no staging (a DO-persisted ring would be the rejected background beacon
      // with one hop). Same posture.read gate + rate-limit as the GET.
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      // D1: treat the POST as the MOST untrusted input in the pack. Cap Content-Length BEFORE parse so an
      // oversized body is refused 400 without ever being read; the ceiling (~13 KB at the caps) sits well
      // under CLIENT_DIAG_MAX_BODY_BYTES. CSRF/origin is already enforced centrally in handleAdmin (the
      // cookie-session Origin check runs before this spoke for every non-GET), so no extra guard is needed here.
      const contentLength = Number(req.headers.get("content-length") ?? "");
      if (Number.isFinite(contentLength) && contentLength > CLIENT_DIAG_MAX_BODY_BYTES) {
        return new Response(JSON.stringify({ error: "client-diagnostics body too large" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // Parse defensively: a malformed body is a plain 400 (never a coerced/echoed value, never a crashed
      // build). An EMPTY body is allowed (the POST then behaves exactly like the GET: no section).
      let clientDiagnostics: ReturnType<typeof projectClientDiagnostics> = null;
      let body: unknown;
      try {
        const text = await req.text();
        if (text.length > CLIENT_DIAG_MAX_BODY_BYTES) {
          return new Response(JSON.stringify({ error: "client-diagnostics body too large" }), { status: 400, headers: { "content-type": "application/json" } });
        }
        body = text.trim() === "" ? {} : JSON.parse(text);
      } catch {
        return new Response(JSON.stringify({ error: "malformed body" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // The body's `clientDiagnostics` field is the console ring; project it (or null when absent, so the
      // section is omitted like the GET path). Validation failures inside never throw -- a hostile record is
      // dropped by set-membership, so the build always proceeds.
      const raw = body !== null && typeof body === "object" ? (body as { clientDiagnostics?: unknown }).clientDiagnostics : undefined;
      clientDiagnostics = projectClientDiagnostics(raw);
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // BOTH channels ride on the one context object: the console's error ring AND the Access-perimeter boolean.
      // The POST is a console-generate, so it is exactly as Access-fronted as the GET sibling; passing only the
      // ring here would have made the perimeter boolean vanish on the ONE path a customer actually uses to
      // produce a pack.
      return new Response(
        JSON.stringify(await sealedSupportBundle(env, scheduler, { accessPerimeter: req.headers.get("cf-access-jwt-assertion") !== null, clientDiagnostics })),
        { headers: { "content-type": "application/json" } },
      );
    }
    case "POST /support/credentials": {
      // Owner-only: minting an ingest credential opens a (read-only, scoped, expiring)
      // pull surface, the same custody weight as granting a role, so it takes the same
      // authority bar as owner-class actions and is rate-limited like every mutation.
      // The check is deliberately the bare owner-role test rather than gate(caller, cap):
      // this authority is owner-exclusive by design and is intentionally NOT mapped to a
      // custom-role capability, so a future custom role must never inherit it.
      // The body is read BEFORE the gate so a refused attempt records its scope (the
      // role-change deny discipline); a malformed scope is a plain 400 with no entry
      // (nothing meaningful was attempted against a real surface).
      const body = (await req.json()) as { scope?: string; ttlSeconds?: number };
      const scope: IngestScope | null = body.scope === "diagnostics" || body.scope === "audit-feed" || body.scope === "metrics" ? body.scope : null;
      if (scope === null) {
        return new Response(JSON.stringify({ error: 'scope must be "diagnostics", "audit-feed" or "metrics"' }), { status: 400, headers: { "content-type": "application/json" } });
      }
      if (caller.role !== "owner") {
        // ENG-SUP-AUDIT-1 / NC-3: a refused mint is recorded like a refused role write. The DO
        // records the SUCCESS case at its commit point; the router records the DENIED case here
        // because it gates before forwarding.
        await recordAudit(scheduler, caller, sourceIp, "support-credential-grant", "denied", { kind: "supportcredential", scope });
        return new Response(JSON.stringify({ error: "forbidden", required: "owner", have: caller.role }), { status: 403, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // OPT-IN DUAL CONTROL (router-executed): minting a support credential opens a vendor/SIEM-readable pull
      // surface (egress of a sealed support bundle), so it takes a second owner's approval. The mint generates
      // a one-time secret that cannot be pre-recorded, so the DECISION (open this scope for this TTL) is what
      // is approved and the mint runs once on the approved execution, exactly like the token-flow ops. The
      // gate binds to { scope, ttlSeconds }, NEVER the secret. First call (gate ON, no armed approval): record
      // a pending approval + 202 WITHOUT minting; a second owner approves; the owner re-submits and the gate
      // consumes the armed approval here, then the mint runs and the secret is shown once.
      {
        const g = await ownerActionGate(
          scheduler,
          caller,
          "support-credential-mint",
          { scope, ttlSeconds: typeof body.ttlSeconds === "number" ? body.ttlSeconds : null },
          `Mint a ${scope} support credential (opens a read-only pull surface)`,
        );
        if (g.kind === "error") return g.response;
        if (g.kind === "queued") return ownerActionQueuedResponse(g.id);
      }
      const minted = await mintIngestCredential(scope, caller.email, typeof body.ttlSeconds === "number" ? body.ttlSeconds : undefined);
      // The caller header rides along so the DO re-checks owner at the commit point and
      // attributes the grant's audit event (ENG-SUP-DO-1, the /roles discipline).
      // G100: CHECKED. The mint SHOWS the operator their bearer exactly once, below. If this persist is
      // dropped, they walk away holding a credential the engine never stored: their SIEM / Prometheus
      // collector 401s forever against a credential they are certain they configured, and nothing anywhere
      // records why. The response is unchanged; the loss is counted so the pack can say it.
      await recordDiagWrite(scheduler, "ingest-credential", () =>
        scheduler.fetch(doURL("/ingest-credential/set"), {
          method: "POST",
          body: JSON.stringify({ scope, grant: minted.grant }),
          headers: callerHeaders(caller),
        }),
      );
      // The SECRET appears exactly once, here. Only its SHA-384 persists; the response
      // also restates the single-bearer presentation so the operator can paste it
      // straight into a collector or hand it to support.
      return new Response(
        JSON.stringify({
          scope,
          clientId: minted.clientId,
          secret: minted.secret,
          bearer: `${minted.clientId}.${minted.secret}`,
          expiresAt: minted.grant.expiresAt,
          note: "the secret is shown once and stored only as a hash; revoke and re-mint to rotate",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    case "POST /support/credentials/delete": {
      // Owner-exclusive by design, like the mint path above: the bare owner-role test is
      // intentional and this authority is NOT mapped to a custom-role capability, so the
      // gate(caller, cap) form is deliberately not used here.
      const body = (await req.json()) as { scope?: string };
      const scope: IngestScope | null = body.scope === "diagnostics" || body.scope === "audit-feed" || body.scope === "metrics" ? body.scope : null;
      if (scope === null) {
        return new Response(JSON.stringify({ error: 'scope must be "diagnostics", "audit-feed" or "metrics"' }), { status: 400, headers: { "content-type": "application/json" } });
      }
      if (caller.role !== "owner") {
        await recordAudit(scheduler, caller, sourceIp, "support-credential-revoke", "denied", { kind: "supportcredential", scope });
        return new Response(JSON.stringify({ error: "forbidden", required: "owner", have: caller.role }), { status: 403, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Caller header forwarded for the DO's owner re-check + the revoke's audit attribution
      // (ENG-SUP-DO-1; the DO records the success at the commit point, only when a grant existed).
      // G100: CHECKED. A dropped REVOKE is the dangerous direction: the operator is told the credential is
      // dead ({ok:true} below) while it is still LIVE and still serving pulls. The response is unchanged (the
      // revoke path stays as it was), but the loss is now recorded so the pack can contradict the belief.
      await recordDiagWrite(scheduler, "ingest-credential", () =>
        scheduler.fetch(doURL("/ingest-credential/clear"), { method: "POST", body: JSON.stringify({ scope }), headers: callerHeaders(caller) }),
      );
      return new Response(JSON.stringify({ ok: true, scope }), { headers: { "content-type": "application/json" } });
    }
    default:
      return null;
  }
}
