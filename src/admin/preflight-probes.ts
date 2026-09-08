import { classifyDestError } from "../dest/classify.ts";
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { loadRecipientPublic, loadRecipients, loadSigner } from "../keys-env.ts";
import { type DownpipeState, RESERVED_BINDINGS } from "../sched/scheduler-do.ts";
import { D1Source } from "../sources/d1.ts";
import { KVSource } from "../sources/kv.ts";
import { R2Source } from "../sources/r2.ts";
import { probeSourceLiveness, type SourceResourceMissingError } from "../sources/source-errors.ts";
import { API_DISCOVERY_SOURCE_TYPES } from "../sources/types.ts";
import { assertCloudflareAccessHost, teamHost } from "./access.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { readLicence } from "./licence.ts";
import { PREFLIGHT_BINDING_CAP, type PreflightErrorClass, type PreflightItem } from "./preflight-types.ts";
import { doURL, resolveDiscoveryTokenDetailed } from "./router-helpers.ts";

// CRON_STALE_MS: the reconciliation cron is */15; a tick older than two intervals plus
// slack means the cron is not firing (not deployed, or the account cannot run it).
const CRON_STALE_MS = 35 * 60 * 1000;

// Evidence strings are folded into a single line in the report and the support bundle, so
// probe error text is truncated. The long cap is for destination and scheduler evidence,
// the short cap for parse-error messages.
const EVIDENCE_TRUNCATE_LONG = 80;
const EVIDENCE_TRUNCATE_SHORT = 60;
// Missing source bindings are listed up to this cap so the evidence stays a short line. The EVIDENCE line
// keeps this small cap (it is a one-line summary an operator reads); the STRUCTURED lists carry the
// whole set up to PREFLIGHT_BINDING_CAP, so the discriminating tail is no longer thrown away.
const BINDING_DETAIL_CAP = 6;

// classifyProbeError (G130) coarsens ONE probe throw into a closed PreflightErrorClass. It reads the message
// ONLY to SELECT an enum member and RETURNS that member (the classifyCoarseError idiom used throughout the
// engine): the Cloudflare message, the endpoint, the bucket, the key and the stack never leave this function.
// It is the SINGLE classifier every probe below uses, so the pack's cause vocabulary cannot drift per probe.
export function classifyProbeError(e: unknown): PreflightErrorClass {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  // The engine's own literals first (they are the most specific and cannot be forged by a platform message).
  if (/did not respond|Durable Object/i.test(m) && /internal error|network|cannot|unreachable|reset/i.test(m)) return "do-unreachable";
  const status = /\b(?:status |HTTP )(\d{3})\b/.exec(m);
  if (status !== null) {
    const n = Number(status[1]);
    if (n === 401 || n === 403) return "auth";
    if (n === 404) return "not-found";
    if (n === 429) return "rate-limited";
    if (n >= 500 && n <= 599) return "unavailable";
    return "http-other";
  }
  // WORD-BOUNDARY anchors are load-bearing: an unanchored /refus/ matches inside ECONNREFUSED, which would
  // file a transport fault as a permission one -- the exact inversion the governance classifier was bitten by.
  if (/\btimed? ?out\b|\btimeout\b|\baborted\b/i.test(m)) return "timeout";
  if (/\bJSON\b|\bunexpected token\b|\bnot valid\b|\bcould not decode\b|\bparse\b/i.test(m)) return "parse";
  if (/\bnetwork\b|\bfetch failed\b|\bECONNRE|\bENOTFOUND\b|\bTLS\b|\bsocket\b|\bconnection\b/i.test(m)) return "transport";
  if (/\bforbidden\b|\bunauthorised\b|\bunauthorized\b|\bpermission\b|\bAccessDenied\b/i.test(m)) return "auth";
  return "other";
}

// 1. Durable Objects: a live round-trip through the scheduler proves the account can
// create and reach DOs at all (and measures the path the whole control plane rides).
// 2. Cron: the tick recency is RECORDED evidence the [triggers] cron genuinely
// fires on this deployment, not an assumption from wrangler.toml.
export async function probeDurableObjectsAndCron(items: PreflightItem[], scheduler: DurableObjectStub): Promise<void> {
  const started = Date.now();
  try {
    const resp = await scheduler.fetch(doURL("/tick-info"), { method: "GET" });
    const { lastTickAt } = (await resp.json()) as { lastTickAt: number | null };
    items.push({
      id: "durable-objects",
      name: "Durable Objects (scheduler authority)",
      requires: "Workers with Durable Objects enabled",
      required: true,
      status: "verified",
      evidence: `scheduler Durable Object responded in ${Date.now() - started}ms`,
    });
    if (lastTickAt === null) {
      items.push({
        id: "cron-tick",
        name: "Reconciliation cron",
        requires: "the deployed [triggers] crons (wrangler.toml)",
        required: true,
        status: "unconfigured",
        evidence: "no cron tick has been observed yet on this deployment",
        remediation: "deploy with the */15 cron trigger and wait one interval; if it never ticks, the Workers plan or the deployment is missing cron triggers",
      });
    } else {
      const age = Date.now() - lastTickAt;
      items.push({
        id: "cron-tick",
        name: "Reconciliation cron",
        requires: "the deployed [triggers] crons (wrangler.toml)",
        required: true,
        status: age <= CRON_STALE_MS ? "verified" : "failed",
        evidence: `last cron tick observed ${Math.round(age / 60000)} minutes ago`,
        ...(age > CRON_STALE_MS ? { remediation: "the cron has stopped firing: check the deployment's triggers and the account's Workers status" } : {}),
      });
    }
  } catch (e) {
    items.push({
      id: "durable-objects",
      name: "Durable Objects (scheduler authority)",
      requires: "Workers with Durable Objects enabled",
      required: true,
      status: "failed",
      // G130: the truncated message is kept for the operator's screen; the CLOSED class beside it is what
      // survives into the pack, so "the DO is unreachable" is no longer a prefix of an 80-character string.
      probeErrorClass: "do-unreachable",
      evidence: `the scheduler Durable Object did not respond (${(e as Error).message.slice(0, EVIDENCE_TRUNCATE_LONG)})`,
      remediation: "enable Durable Objects for the account (Workers Paid on legacy accounts) and redeploy",
    });
  }
}

// 3. The platform plan itself is not introspectable from inside a Worker (the engine
// deliberately holds no Cloudflare API token), so the item is honest about which gate
// covers it: the deploy fails on an account without the paid limits this engine sets
// ([limits] cpu_ms), and the free plan's 50-subrequest cap would surface as failed
// runs, which the probes above and the run history catch.
export function probeWorkersPlan(items: PreflightItem[]): void {
  items.push({
    id: "workers-plan",
    name: "Workers plan limits",
    requires: "Workers Paid (raised CPU limit, 1000 subrequests per invocation)",
    required: true,
    status: "configured",
    evidence: "not directly observable in-Worker (the engine holds no account API token by design); `wrangler deploy` refuses the configured [limits] cpu_ms on an unpaid account, which is the deploy-time gate",
    remediation: "activate Workers Paid on the account BEFORE deploying; the deploy itself then validates it",
  });
}

// 4. Destination: probe reachability and authorisation with a read-only existence
// check on the RUNLOG key (no object is written; absence is a normal first-run state).
// The CONSOLE-SET destination (the DO-stored record) wins over the env configuration,
// exactly as a run resolves it, so preflight proves the destination a run would use.
export async function probeDestination(items: PreflightItem[], env: Env, scheduler: DurableObjectStub): Promise<void> {
  let destOverride: Awaited<ReturnType<typeof fetchDestConfig>> = null;
  let destOverrideError: string | null = null;
  try {
    destOverride = await fetchDestConfig(scheduler, undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
  } catch (e) {
    destOverrideError = (e as Error).message;
  }
  {
    // A failed read of the console-set override does not condemn the whole destination: fall back to
    // probing the env/binding destination (destOverride stays null) so a transient DO read fault does not
    // mask whether the deploy-configured destination is in fact reachable. The override read fault is noted
    // in the evidence so the operator can see the console-set record was not consulted this probe.
    const overrideNote = destOverrideError !== null ? "; the console-set destination could not be read this probe, so the deploy configuration was probed instead" : "";
    try {
      const dest = await buildDestination(env, undefined, destOverride);
      const started = Date.now();
      // Prefer headStatus when the destination exposes it (S3): it tells "absent" (404 -- a fresh bucket,
      // first run pending) APART from "unauthorised" (403) or "unavailable" (5xx/429), so a broken or down
      // credentialed store is no longer reported as a FALSE-GREEN "verified" (DIAGLAB-FINDINGS round 3). A
      // non-{200,404} status is thrown so the catch below classifies it into failureClass. A binding-backed
      // R2 destination has no headStatus (it cannot return an auth error) and keeps the boolean exists().
      let present: boolean;
      if (typeof dest.headStatus === "function") {
        const status = await dest.headStatus("_RECOVERY/RUNLOG");
        if (status !== 200 && status !== 404) throw new Error(`the destination HEAD probe returned status ${status}`);
        present = status === 200;
      } else {
        present = await dest.exists("_RECOVERY/RUNLOG");
      }
      items.push({
        id: "destination",
        name: "Archive destination",
        requires: destOverride !== null ? "the console-set destination bucket or container (Destinations screen)" : env.DEST_R2 !== undefined && env.DEST_KIND !== "s3" ? "an R2 bucket binding (R2 subscription)" : "an S3-compatible bucket and credentials",
        required: true,
        status: "verified",
        evidence: `destination reachable and authorised in ${Date.now() - started}ms (RUNLOG ${present ? "present" : "absent; first run pending"}; ${destOverride !== null ? "set from the console" : "set at deploy"}${overrideNote})`,
        // overrideUnreadable: the CONSOLE-SET destination record could not be read/
        // decrypted this probe (fetchDestConfig threw -- e.g. a rotated CONFIG_WRAP_KEY), so the deploy
        // configuration was probed instead. A closed boolean a diagnosis pairs with wrapKeyHealth to tell
        // "the stored record cannot be DECRYPTED" apart from "no destination is configured" (the wrap-key
        // misroute). Present on BOTH outcome branches so the discriminator survives either way.
        ...(destOverrideError !== null ? { overrideUnreadable: true } : {}),
      });
    } catch (e) {
      const m = (e as Error).message;
      const unconfigured = /missing required configuration|ambiguous destination|DEST_KIND/.test(m);
      // Classify a genuine probe failure (not an unconfigured one) so a diagnosis can tell a
      // credential/permission fault (auth, "check your credentials") apart from a throttled or
      // unreachable destination (transient, "the store was down, it self-heals"). Uses the ONE
      // shared dest-fault classifier so the preflight verdict matches how a run would class the
      // same fault. A 503/429/5xx/network shape ⇒ transient; 401/403 ⇒ auth; a permanent 4xx ⇒ other.
      const fault = unconfigured ? null : classifyDestError(e);
      const failureClass: PreflightItem["failureClass"] =
        fault === null ? undefined : fault === "auth" ? "auth" : fault === "throttle" || fault === "transient" ? "transient" : "other";
      items.push({
        id: "destination",
        name: "Archive destination",
        requires: "a destination set from the console (Destinations screen) or an R2 binding / S3 configuration at deploy",
        required: true,
        status: unconfigured ? "unconfigured" : "failed",
        ...(failureClass ? { failureClass } : {}),
        // G130: the sanitised destination evidence is truncated at 80 chars, which cuts the S3 error code off
        // the END of the line -- the one token that names the cause. probeErrorClass carries the classified
        // status ALONGSIDE the (still sanitised, still truncated) prose, so the code cannot be lost to a clamp.
        probeErrorClass: unconfigured ? "unconfigured" : classifyProbeError(e),
        // overrideUnreadable: see the verified branch above -- on THIS branch it is the
        // wrap-key-misroute keystone: an "unconfigured" verdict with the console record unreadable means the
        // destination IS configured but cannot be decrypted (CONFIG_WRAP_KEY), not that none is set.
        ...(destOverrideError !== null ? { overrideUnreadable: true } : {}),
        // The raw destination error can echo configuration VALUES (s3.ts throws the
        // configured endpoint verbatim on a malformed DEST_ENDPOINT), and preflight
        // evidence flows into the vendor-bound support bundle, so the evidence string is
        // sanitised before it leaves this probe.
        evidence: unconfigured ? "no destination is configured" : `the destination probe failed (${sanitiseDestinationEvidence(m, env).slice(0, EVIDENCE_TRUNCATE_LONG)})`,
        remediation: unconfigured
          ? "set the destination from the console (Destinations screen), or bind DEST_R2 / set the DEST_* S3 configuration at deploy"
          : "check the bucket exists and the credentials/binding are authorised for read and write",
      });
    }
  }
}

// 5. Keys: parse-only verification (no value is logged or returned).
export async function probeKeys(items: PreflightItem[], env: Env): Promise<void> {
  let signerOk = false;
  let signerEvidence = "SIGNER_PRIVATE is not set";
  let signerClass: PreflightErrorClass | undefined = env.SIGNER_PRIVATE ? undefined : "key-absent";
  if (env.SIGNER_PRIVATE) {
    try {
      await loadSigner(env.SIGNER_PRIVATE);
      signerOk = true;
      signerEvidence = "the signer key parses (64-byte seed form)";
    } catch (e) {
      signerEvidence = `SIGNER_PRIVATE is set but does not parse (${(e as Error).message.slice(0, EVIDENCE_TRUNCATE_SHORT)})`;
      signerClass = "key-unparseable";
    }
  }
  items.push({
    id: "signer",
    name: "Run signer key",
    requires: "the key ceremony (console) + wrangler secret put SIGNER_PRIVATE",
    required: true,
    status: signerOk ? "verified" : env.SIGNER_PRIVATE ? "failed" : "unconfigured",
    evidence: signerEvidence,
    ...(signerClass !== undefined ? { probeErrorClass: signerClass } : {}),
    ...(signerOk ? {} : { remediation: "run the key ceremony in the console and store the signer seed via wrangler secret put SIGNER_PRIVATE" }),
  });

  // G130: WHICH recipient key. loadRecipients(BREAK_GLASS_PUBLIC, OPERATIONAL_PUBLIC) parses both and throws
  // ONE error, so a failed parse produced "recipient keys are set but do not parse (...)" -- with the message
  // truncated at 60 chars and no statement of which env var to re-paste. The two have OPPOSITE remedies: a bad
  // BREAK_GLASS_PUBLIC means the key ceremony did not land and NOTHING can be sealed; a bad OPERATIONAL_PUBLIC
  // leaves break-glass sealing perfectly healthy and silently disables the in-account read-back drill. So each
  // slot is now parsed SEPARATELY (loadRecipientPublic, the same parser loadRecipients calls per slot) and the
  // FAILING slot is named as a closed enum. Break-glass is checked first because it is the required one.
  let recipientsOk = false;
  let recipientsEvidence = "BREAK_GLASS_PUBLIC is not set";
  let recipientsClass: PreflightErrorClass | undefined = env.BREAK_GLASS_PUBLIC ? undefined : "key-absent";
  let whichRecipient: PreflightItem["whichRecipient"];
  if (env.BREAK_GLASS_PUBLIC) {
    let breakGlassOk = false;
    try {
      loadRecipientPublic(env.BREAK_GLASS_PUBLIC);
      breakGlassOk = true;
    } catch (e) {
      whichRecipient = "break-glass";
      recipientsClass = "key-unparseable";
      recipientsEvidence = `BREAK_GLASS_PUBLIC is set but does not parse (${(e as Error).message.slice(0, EVIDENCE_TRUNCATE_SHORT)})`;
    }
    if (breakGlassOk) {
      if (env.OPERATIONAL_PUBLIC) {
        try {
          loadRecipientPublic(env.OPERATIONAL_PUBLIC);
        } catch (e) {
          whichRecipient = "operational";
          recipientsClass = "key-unparseable";
          recipientsEvidence = `OPERATIONAL_PUBLIC is set but does not parse (${(e as Error).message.slice(0, EVIDENCE_TRUNCATE_SHORT)}); break-glass sealing is unaffected`;
        }
      }
      if (whichRecipient === undefined) {
        // Both slots parse individually: run the real loader so the reported count is the one the seal path
        // will actually build (and a future cross-slot check in loadRecipients cannot pass here and fail there).
        const r = loadRecipients(env.BREAK_GLASS_PUBLIC, env.OPERATIONAL_PUBLIC);
        recipientsOk = true;
        recipientsEvidence = `${r.length} recipient public key(s) parse (break-glass${r.length > 1 ? " + operational" : " only"})`;
      }
    }
  }
  items.push({
    id: "recipients",
    name: "Recipient public keys",
    requires: "the key ceremony (console)",
    required: true,
    status: recipientsOk ? "verified" : env.BREAK_GLASS_PUBLIC ? "failed" : "unconfigured",
    evidence: recipientsEvidence,
    ...(recipientsClass !== undefined ? { probeErrorClass: recipientsClass } : {}),
    ...(whichRecipient !== undefined ? { whichRecipient } : {}),
    ...(recipientsOk ? {} : { remediation: "run the key ceremony and store BREAK_GLASS_PUBLIC (and optionally OPERATIONAL_PUBLIC) as secrets" }),
  });
}

// 6. Cloudflare Access: when configured, fetch the team's public JWKS. A successful
// fetch PROVES the Zero Trust team domain is live (the licensing question answered by
// observation); a failure means Access is configured here but not enabled there.
export async function probeAccess(items: PreflightItem[], env: Env): Promise<void> {
  if (env.CF_ACCESS_TEAM_DOMAIN && env.CF_ACCESS_AUD) {
    try {
      // Validate the operator-supplied team domain resolves to a single-label *.cloudflareaccess.com host
      // before fetching, so a misconfigured CF_ACCESS_TEAM_DOMAIN cannot redirect this probe at an
      // attacker-controlled host (SSRF). Shares the same guard as the token verifier in access.ts.
      const host = teamHost(env.CF_ACCESS_TEAM_DOMAIN);
      assertCloudflareAccessHost(host);
      const u = `https://${host}/cdn-cgi/access/certs`;
      const resp = await fetch(u, { redirect: "manual" });
      if (!resp.ok) throw new Error(`status ${resp.status}`);
      const jwks = (await resp.json()) as { keys?: unknown[] };
      const n = Array.isArray(jwks.keys) ? jwks.keys.length : 0;
      items.push({
        id: "access-zero-trust",
        name: "Cloudflare Access (Zero Trust)",
        requires: "Zero Trust enabled on the account (free tier covers up to 50 users)",
        required: false,
        status: n > 0 ? "verified" : "failed",
        // A JWKS that answered with ZERO keys is a SHAPE fault (the team domain is live and publishes nothing),
        // not a transport one: the remedy is to create the Access application, not to check the network.
        ...(n > 0 ? {} : { probeErrorClass: "shape" as const }),
        evidence: n > 0 ? `the team domain is live (${n} signing key(s) published)` : "the team domain answered without signing keys",
        ...(n > 0 ? {} : { remediation: "enable Zero Trust and create the Access application, then re-check CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD" }),
      });
    } catch (e) {
      items.push({
        id: "access-zero-trust",
        name: "Cloudflare Access (Zero Trust)",
        requires: "Zero Trust enabled on the account (free tier covers up to 50 users)",
        required: false,
        status: "failed",
        probeErrorClass: classifyProbeError(e),
        evidence: `the team domain JWKS fetch failed (${(e as Error).message.slice(0, EVIDENCE_TRUNCATE_SHORT)})`,
        remediation: "enable Zero Trust for the account and check the team domain spelling; until then the engine refuses Access assertions rather than trusting them",
      });
    }
  } else {
    items.push({
      id: "access-zero-trust",
      name: "Cloudflare Access (Zero Trust)",
      requires: "Zero Trust enabled on the account (free tier covers up to 50 users)",
      required: false,
      status: "unconfigured",
      evidence: "CF_ACCESS_TEAM_DOMAIN / CF_ACCESS_AUD are not set (token or passkey sign-in is in use)",
      remediation: "optional: enable Zero Trust (One-Time PIN needs no identity provider), create an Access application for the console origin, then set both vars",
    });
  }
}

// 7. Email sending: presence is checkable; a real send is not exercised here (it
// would email someone), so a configured binding is honestly configured-unproven with
// the test-send remediation.
export function probeEmail(items: PreflightItem[], env: Env): void {
  const bound = env.EMAIL !== undefined;
  const from = typeof env.EMAIL_FROM === "string" && env.EMAIL_FROM.includes("@");
  items.push({
    id: "email-sending",
    name: "Outbound email (alerts, expiry, invites)",
    requires: "Workers Paid + Email Sending onboarding (verified sender domain)",
    required: false,
    status: bound && from ? "configured" : "unconfigured",
    evidence: bound ? (from ? "the EMAIL binding is bound and EMAIL_FROM is set (send not exercised by preflight)" : "the EMAIL binding is bound but EMAIL_FROM is not set") : "the EMAIL binding is not bound",
    remediation: bound && from
      ? "prove delivery with the test-send in Settings, Support: presence is not proof, and the shipped EMAIL_FROM default is a domain you do not own"
      : "onboard the sender domain in the dashboard under Compute, Email Service, Email Sending; keep the [[send_email]] binding in wrangler.toml; set EMAIL_FROM to an address on that domain, and redeploy",
  });
}

// 8. Sliced runs: the RUNSEAL binding must exist (migration v2) for runs past one
// invocation's budget; its absence silently caps every downpipe.
export async function probeSlicedRuns(items: PreflightItem[], env: Env): Promise<void> {
  const ns = env.RUNSEAL as DurableObjectNamespace | undefined;
  if (ns && typeof ns.idFromName === "function") {
    try {
      const stub = ns.get(ns.idFromName("preflight-probe"));
      const resp = await stub.fetch("https://runseal.internal/status");
      const body = (await resp.json()) as { active?: boolean };
      items.push({
        id: "sliced-runs",
        name: "Sliced runs (large environments)",
        requires: "the RUNSEAL Durable Object binding (migration v2)",
        required: true,
        status: "verified",
        evidence: `the seal Durable Object responds (active run: ${body.active === true ? "yes" : "no"})`,
      });
    } catch (e) {
      items.push({
        id: "sliced-runs",
        name: "Sliced runs (large environments)",
        requires: "the RUNSEAL Durable Object binding (migration v2)",
        required: true,
        status: "failed",
        probeErrorClass: "do-unreachable",
        evidence: `the seal Durable Object did not respond (${(e as Error).message.slice(0, EVIDENCE_TRUNCATE_SHORT)})`,
        remediation: "redeploy with wrangler.toml migration v2 (RunSealDO)",
      });
    }
  } else {
    items.push({
      id: "sliced-runs",
      name: "Sliced runs (large environments)",
      requires: "the RUNSEAL Durable Object binding (migration v2)",
      required: true,
      status: "unconfigured",
      // G130: "large runs die at the invocation budget with nothing linking back to the missing RUNSEAL
      // migration". The binding-absent CLASS is that link: it survives every evidence clamp, and it is the
      // one preflight state in which a run over one invocation's budget can NEVER complete.
      probeErrorClass: "binding-absent",
      evidence: "the RUNSEAL binding is absent: a run larger than one invocation's budget cannot complete",
      remediation: "redeploy with the current wrangler.toml (RUNSEAL binding + migration v2)",
    });
  }
}

// 9. Licence: read the fail-open licence so onboarding sees the assurance tier it is
// actually entitled to (community is fully functional; assurance features gate).
export async function probeLicence(items: PreflightItem[], env: Env, scheduler: DurableObjectStub): Promise<void> {
  const lic = await readLicence(env, scheduler);
  items.push({
    id: "licence",
    name: "Assurance licence",
    requires: "a vendor-issued licence token (Enterprise) or none (community)",
    required: false,
    status: lic.tier === "community" ? "configured" : "verified",
    evidence: `tier ${lic.tier}${"expiresAt" in lic && lic.expiresAt ? `, expires ${lic.expiresAt}` : ""}`,
  });
}

// 10. Source bindings: every configured downpipe reads a Workers binding (KV/R2/D1) or a
// Secrets Store binding BY NAME; the run path resolves it through env[binding] and fails with
// "source binding error" if it is absent (src/seal/adapters.ts buildAdapter). The classic
// cause is a deploy that did not carry a console-attached source: wrangler.toml is authoritative
// on `wrangler deploy` and lists NO source bindings (they are all console-attached, live-only), so
// a deploy that skips the reconcile drops them. Preflight PROBES this ahead of the run, it
// enumerates every configured source binding and confirms it is present in env, so drift is a
// standing, named health signal (and a support-bundle line) instead of a surprise failed run.
export async function probeSourceBindings(items: PreflightItem[], env: Env, downpipes: DownpipeState[] | null): Promise<void> {
  if (downpipes === null) {
    items.push({
      id: "source-bindings",
      name: "Source bindings",
      requires: "the configured downpipes (scheduler) and their Workers/Secrets Store bindings",
      required: true,
      status: "failed",
      probeErrorClass: "do-unreachable",
      evidence: "the configured downpipes could not be read this probe",
      remediation: "retry; if it persists, the scheduler Durable Object is unreachable (see the Durable Objects item above)",
    });
  } else {
    // Collect each configured source binding -> the downpipe(s) that depend on it. A reserved
    // name can never be a source (the run path refuses it), so a configured binding colliding
    // with a reserved one is surfaced as broken too.
    const needed = new Map<string, { downpipes: Set<string>; reserved: boolean }>();
    const add = (binding: unknown, dp: string): void => {
      if (typeof binding !== "string" || binding === "") return;
      const e = needed.get(binding) ?? { downpipes: new Set<string>(), reserved: RESERVED_BINDINGS.has(binding) };
      e.downpipes.add(dp);
      needed.set(binding, e);
    };
    for (const dp of downpipes) {
      const src = dp.config.source;
      const name = dp.config.name || dp.config.id;
      if ((src.type === "kv" || src.type === "r2" || src.type === "d1")) add(src.binding, name);
      for (const sec of src.secrets ?? []) add(sec.binding, name);
    }
    // Safety: dynamic key lookup over Env. We read bindings by operator-supplied name, which
    // TypeScript cannot check statically; the undefined/null check below is the runtime gate.
    const bag = env as unknown as Record<string, unknown>;
    const missing = [...needed.entries()].filter(([b, e]) => e.reserved || bag[b] === undefined || bag[b] === null);
    if (needed.size === 0) {
      items.push({
        id: "source-bindings",
        name: "Source bindings",
        requires: "a configured downpipe with a Workers/Secrets Store source binding",
        required: false,
        status: "unconfigured",
        evidence: "no downpipe with a binding-backed source is configured yet (cf-config sources read an API token, not a binding)",
      });
    } else if (missing.length === 0) {
      items.push({
        id: "source-bindings",
        name: "Source bindings",
        requires: "the source bindings the configured downpipes read (added per source at attach)",
        required: true,
        status: "verified",
        evidence: `all ${needed.size} configured source binding(s) are present on the engine`,
      });
    } else {
      // Name the missing bindings and the downpipes they break, capped so the evidence stays a
      // short line. Binding NAMES are operator-chosen labels, not archive contents, so they may
      // appear in the report and the support bundle (unlike record names).
      const detail = missing
        .slice(0, BINDING_DETAIL_CAP)
        .map(([b, e]) => `${b}${e.reserved ? " (reserved name; cannot be a source)" : ""} -> ${[...e.downpipes].sort().join(", ")}`)
        .join("; ");
      const more = missing.length > BINDING_DETAIL_CAP ? ` (+${missing.length - BINDING_DETAIL_CAP} more)` : "";
      // G130: the STRUCTURED list. The evidence line above still names six (it is a one-line summary), but
      // "a bad deploy dropped 30 bindings and the pack names 6 plus +24 more" is not a diagnosis -- the 24 are
      // exactly the ones support cannot ask about. missingBindings carries every one up to PREFLIGHT_BINDING_CAP
      // (64, the sourcesDetached precedent), sorted, with the RESERVED-name collision flagged per binding
      // (a reserved name is a different fault from a dropped one: re-attaching it can never work).
      const missingSorted = [...missing].sort((a, b) => a[0].localeCompare(b[0]));
      const missingBindings = missingSorted.slice(0, PREFLIGHT_BINDING_CAP).map(([binding, e]) => ({ binding, reserved: e.reserved }));
      items.push({
        id: "source-bindings",
        name: "Source bindings",
        requires: "the source bindings the configured downpipes read (added per source at attach)",
        required: true,
        probeErrorClass: "binding-absent",
        missingBindings,
        missingBindingsTotal: missing.length,
        ...(missing.length > missingBindings.length ? { missingBindingsTruncated: true } : {}),
        status: "failed",
        evidence: `${missing.length} of ${needed.size} configured source binding(s) are missing from the engine: ${detail}${more}`,
        remediation: "a deploy dropped these bindings (wrangler.toml lists no sources; they live on the worker) or their resources were deleted. Re-attach each from the Sources screen (the engine adds the binding to itself and verifies it survives), or redeploy with the binding-reconcile (scripts/sync-bindings.mjs) so the deploy preserves them.",
      });
    }
  }
}

// 11. Source LIVENESS: the source-bindings probe above proves a binding is PRESENT; this proves
// the resource it names still EXISTS. A truthy binding can point at a KV namespace / R2 bucket / D1
// database that was deleted at Cloudflare: presence is green, yet the next backup dies deep in the crawl
// on a raw platform throw that the run path can only report as a generic failure. This probe issues ONE
// cheap, value-free liveness call per distinct binding (KV/R2 list({limit:1}), D1 SELECT 1) so a deleted
// resource is a standing, named health signal AHEAD of the run, telling the operator which source and
// which binding, and distinguishing a resource that is GONE from a binding that cannot be driven (so they
// know whether to re-create the resource or fix the binding). It NEVER reads a value and NEVER auto-creates
// anything. A minimal binding the probe cannot exercise (a stub without list()/prepare()) is reported as
// present-but-unproven, not failed, so the signal is honest rather than a false alarm.
export async function probeSourceResources(items: PreflightItem[], env: Env, downpipes: DownpipeState[] | null): Promise<void> {
  if (downpipes === null) return; // the source-bindings probe already raises the loud DO-unreachable failure

  // Collect one probe target per DISTINCT present, non-reserved binding-backed source, mapped to the
  // downpipe(s) that depend on it, so a shared binding is probed once and named against every dependant.
  const bag = env as unknown as Record<string, unknown>;
  interface Target { type: "kv" | "r2" | "d1"; binding: string; native: string; downpipes: Set<string> }
  const targets = new Map<string, Target>();
  for (const dp of downpipes) {
    const src = dp.config.source;
    if (src.type !== "kv" && src.type !== "r2" && src.type !== "d1") continue;
    const binding = src.binding;
    if (typeof binding !== "string" || binding === "" || RESERVED_BINDINGS.has(binding)) continue;
    if (bag[binding] === undefined || bag[binding] === null) continue; // absence is the source-bindings probe's job
    const name = dp.config.name || dp.config.id;
    const native = src.type === "kv" ? (src.namespaceId ?? binding) : src.type === "r2" ? (src.bucketName ?? binding) : binding;
    const t = targets.get(binding) ?? { type: src.type, binding, native, downpipes: new Set<string>() };
    t.downpipes.add(name);
    targets.set(binding, t);
  }

  if (targets.size === 0) {
    items.push({
      id: "source-liveness",
      name: "Source resources",
      requires: "a configured KV/R2/D1 source whose binding is present",
      required: false,
      status: "unconfigured",
      evidence: "no present binding-backed source to liveness-probe (API/secret sources have no cheap liveness call)",
    });
    return;
  }

  const live: string[] = [];
  const unproven: string[] = [];
  const missing: { binding: string; kind: string; downpipes: Set<string> }[] = [];
  for (const t of targets.values()) {
    const source =
      t.type === "kv" ? new KVSource(bag[t.binding] as KVNamespace, t.native)
      : t.type === "r2" ? new R2Source(bag[t.binding] as R2Bucket, t.native)
      : new D1Source(bag[t.binding] as D1Database, t.native);
    const res = await probeSourceLiveness(source);
    if (res.status === "live") {
      live.push(t.binding);
    } else if (res.status === "unprobeable" || (res.error as SourceResourceMissingError).kind === "misconfigured") {
      // A binding present but not cheaply exercisable here: present-but-unproven, not a failure (the run
      // path's stricter probe still catches a genuinely undrivable binding).
      unproven.push(t.binding);
    } else {
      missing.push({ binding: t.binding, kind: (res.error as SourceResourceMissingError).kind, downpipes: t.downpipes });
    }
  }

  // G130: the UNPROVEN set was folded to a bare count on every branch ("(3 present but unproven)"), so "one of
  // many sources is unprovable but the item is just a count" had no way to name WHICH one -- and an unprovable
  // source is a source whose next backup may die deep in the crawl. Named here (sorted, capped), on every
  // branch, so the set is readable even when the item is otherwise VERIFIED.
  const unprovenSorted = [...unproven].sort();
  const unprovenFields = unproven.length > 0
    ? { unprovenBindings: unprovenSorted.slice(0, PREFLIGHT_BINDING_CAP), unprovenBindingsTotal: unproven.length }
    : {};

  if (missing.length > 0) {
    const detail = missing
      .slice(0, BINDING_DETAIL_CAP)
      .map((m) => `${m.binding} (${m.kind}) -> ${[...m.downpipes].sort().join(", ")}`)
      .join("; ");
    const more = missing.length > BINDING_DETAIL_CAP ? ` (+${missing.length - BINDING_DETAIL_CAP} more)` : "";
    const missingSorted = [...missing].sort((a, b) => a.binding.localeCompare(b.binding));
    items.push({
      id: "source-liveness",
      name: "Source resources",
      requires: "the KV/R2/D1 resources the configured source bindings name",
      required: true,
      status: "failed",
      probeErrorClass: "not-found",
      // The per-binding liveness KIND rides with the name: "deleted" (re-create the resource) and
      // "unavailable" (retry, it is transient) are different tickets, and the capped evidence line dropped both.
      missingResources: missingSorted.slice(0, PREFLIGHT_BINDING_CAP).map((m) => ({ binding: m.binding, kind: m.kind })),
      missingResourcesTotal: missing.length,
      ...unprovenFields,
      evidence: `${missing.length} of ${targets.size} source resource(s) did not answer a liveness probe: ${detail}${more}`,
      remediation: "the binding is present but the resource it names is gone (deleted) or unreachable. Re-create the KV namespace / R2 bucket / D1 database (the engine never auto-creates a resource), or re-point the source at a live resource from the Sources screen, then re-run. If it is transient (unavailable), retry.",
    });
  } else if (unproven.length > 0 && live.length === 0) {
    items.push({
      id: "source-liveness",
      name: "Source resources",
      requires: "the KV/R2/D1 resources the configured source bindings name",
      required: false,
      status: "configured",
      ...unprovenFields,
      evidence: `${unproven.length} source binding(s) present but their resources could not be liveness-probed from here`,
    });
  } else {
    items.push({
      id: "source-liveness",
      name: "Source resources",
      requires: "the KV/R2/D1 resources the configured source bindings name",
      required: true,
      status: "verified",
      ...unprovenFields,
      evidence: `all ${live.length} probed source resource(s) answered a liveness probe${unproven.length > 0 ? ` (${unproven.length} present but unproven)` : ""}`,
    });
  }
}

// 11. API-source discovery token: the API-discovery source types (cf-config / workers / stream / images
// / artifacts) read the Cloudflare REST API with the engine's read-only discovery token, NOT a Workers
// binding; their adapters THROW at construction when the token is absent, so such a downpipe fails every
// run if no token resolves. The token resolves DO-first (the console-set discovery config) then from the
// DISCOVERY_API_TOKEN env/IaC fallback -- the SAME resolveDiscoveryToken the run path uses, so this probe
// agrees with the run by construction. Advisory (not required for core KV/R2/D1 backup): it is a standing,
// named signal that an API source is configured but no discovery token is resolvable, instead of a
// surprise failed run. The token VALUE is never read into evidence, only its presence.
export async function probeApiSourceDiscoveryToken(items: PreflightItem[], env: Env, scheduler: DurableObjectStub, downpipes: DownpipeState[] | null): Promise<void> {
  // A DO outage is already the loud failure on the Durable Objects item; this advisory stays quiet.
  if (downpipes === null) return;
  const apiSources = downpipes.filter((d) => API_DISCOVERY_SOURCE_TYPES.has(d.config.source.type));
  if (apiSources.length === 0) {
    items.push({
      id: "api-source-discovery-token",
      name: "API source discovery token",
      requires: "a configured cf-config/workers/stream/images/artifacts downpipe",
      required: false,
      status: "unconfigured",
      evidence: "no API-based source (cf-config/workers/stream/images/artifacts) is configured yet (these read a read-only API token, not a binding)",
    });
    return;
  }
  // G130: resolveDiscoveryTokenDetailed reports WHY the token is null. A DO fault on the config read and a
  // genuinely-unset token both resolved to null and rendered the SAME failed item -- "DO-fault vs genuinely-
  // unset conflated for the discovery token". They are opposite tickets: one says "paste a token", the other
  // says "your scheduler is down and the token you already pasted is probably fine".
  const { token, doFault } = await resolveDiscoveryTokenDetailed(scheduler, env);
  if (token !== null) {
    items.push({
      id: "api-source-discovery-token",
      name: "API source discovery token",
      requires: "the engine's read-only discovery token (discovery config or DISCOVERY_API_TOKEN)",
      required: false,
      status: "verified",
      // Carried on the VERIFIED branch too: a token that resolved only because the env fallback caught a DO
      // fault is a healthy-looking item over a degraded read, and that is worth knowing before the fallback
      // is removed.
      ...(doFault ? { tokenResolve: "do-fault" as const } : { tokenResolve: "resolved" as const }),
      evidence: `the read-only discovery token resolves for the ${apiSources.length} configured API-based source(s)${doFault ? " (from the DISCOVERY_API_TOKEN fallback; the scheduler's stored discovery config could not be read this probe)" : ""}`,
    });
  } else {
    const names = apiSources
      .slice(0, BINDING_DETAIL_CAP)
      .map((d) => `${d.config.name || d.config.id} (${d.config.source.type})`)
      .join(", ");
    const more = apiSources.length > BINDING_DETAIL_CAP ? ` (+${apiSources.length - BINDING_DETAIL_CAP} more)` : "";
    items.push({
      id: "api-source-discovery-token",
      name: "API source discovery token",
      requires: "the engine's read-only discovery token (discovery config or DISCOVERY_API_TOKEN)",
      required: false,
      status: "failed",
      tokenResolve: doFault ? "do-fault" : "unset",
      probeErrorClass: doFault ? "do-unreachable" : "unconfigured",
      evidence: doFault
        ? `${apiSources.length} API-based source(s) are configured and the discovery token could not be resolved: the scheduler's stored discovery config could not be READ this probe (and no DISCOVERY_API_TOKEN fallback is set), so a token that IS configured would look identical to none: ${names}${more}`
        : `${apiSources.length} API-based source(s) are configured but no read-only discovery token is resolvable, so every run will fail at source construction: ${names}${more}`,
      remediation: doFault
        ? "the scheduler Durable Object could not be read (see the Durable Objects item above); retry, and only re-enter the discovery token if it is still unresolvable once the scheduler answers."
        : "set the read-only discovery token from the Sources/Discovery screen (it is stored in the scheduler), or deploy the DISCOVERY_API_TOKEN env/IaC fallback. The token needs the 'Read all resources' (account read-only) permission.",
    });
  }
}

// sanitiseDestinationEvidence strips configuration VALUES from a destination error
// before it becomes preflight evidence (NC-5): the literal DEST_ENDPOINT / DEST_BUCKET
// values wherever they appear (s3.ts echoes a malformed endpoint verbatim, including
// JSON-quoted), then any URL-shaped remnant. Status codes and the failure shape survive,
// which is what the remediation needs. Only endpoint URLs and bucket names are suppressed,
// as they could reveal a location; non-secret config such as DEST_REGION or DEST_KIND may
// still appear in a destination error.
function sanitiseDestinationEvidence(m: string, env: Env): string {
  let out = m;
  for (const v of [env.DEST_ENDPOINT, env.DEST_BUCKET]) {
    if (typeof v === "string" && v.length > 0) {
      out = out.split(JSON.stringify(v)).join("<configured value>");
      out = out.split(v).join("<configured value>");
    }
  }
  return out.replace(/https?:\/\/[^\s"')]+/gi, "<url>");
}
