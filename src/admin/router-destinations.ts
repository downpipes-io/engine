// router-destinations.ts -- the archive-destination routes: the single console-set destination (view /
// verify-before-store set / re-verify), the multiple-destination collection (list / add+edit / remove /
// default), the guided-setup consolidated read and the email delivery test. The keys.ceremony gate runs on
// each write.

import { addressingRejection, assumeRolePolicyRejection, azureEntraDirectoryRejection, fetchDestConfig, type RuntimeDestConfig, validateAddressing, validateAssumeRolePolicy, validateAzureEntraDirectory, validateStorageClass, validateWormPolicyValue, wormPolicyRejection } from "../dest/factory.ts";
import { AZURE_REFUSED_FIELDS, GCS_REFUSED_FIELDS, providerForEndpoint, UNUSABLE_ENDPOINT_REASON, unusableEndpoint } from "../dest/provider.ts";
import { immutabilityRemedy, immutabilityStoreNoun } from "../dest/worm-remedy.ts";
import { isValidStsRegion } from "../dest/sts.ts";
import { renderEngineEmailHtml } from "../email-theme.ts";
import { sendEmail } from "../email.ts";
import { isInternalSinkHost } from "../notify.ts";
import type { TestDeleteProbe } from "../sched/sched-fault-ledger.ts";
import { envFlagEnabled } from "./auth.ts";
import { loadConfigWrapKey, maybeWrapConfigSecret } from "./config-secret.ts";
import { recordAdminRefusal } from "./diag-admin.ts";
import { bumpAdminCounter, noteTestOutcome } from "./diag-counters.ts";
import { callerHeaders, gate, jsonError, jsonResponse, rateLimited } from "./router-core.ts";
import { doURL, type RouterCtx, recordAuthSignalEdge } from "./router-helpers.ts";
import { routeAuthChangeAlert } from "./router-notify.ts";
import { probeDestination } from "./router-posture.ts";
import { enumerateBoundSources } from "./router-sources.ts";
import { buildStatus } from "./status.ts";

// fireInBackground: see router-identity.ts's identical helper.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// RawDestConfigBody is the untrusted `config` object both write paths receive (every field unknown).
type RawDestConfigBody = { endpoint?: unknown; bucket?: unknown; region?: unknown; accessKeyId?: unknown; secretAccessKey?: unknown; assumeRole?: unknown; addressing?: unknown; storageClass?: unknown; worm?: unknown; pricing?: unknown; azureEntra?: unknown };

// ValidatedDest is what validateAndProbeDestConfig returns on success: the probe-verified runtime
// config, the at-rest-wrapped credential to store (never the plaintext), the optional WORM policy and
// the live probe verdict (deleteProbe + objectLock).
type ProbeOk = Extract<Awaited<ReturnType<typeof probeDestination>>, { ok: true }>;
interface ValidatedDest {
  submitted: RuntimeDestConfig;
  storedSecret: Awaited<ReturnType<typeof maybeWrapConfigSecret>>;
  // worm is the VALIDATED policy or null (no policy asked for). There is no "rejected" case to carry: a
  // submitted-but-rejected policy is now a 400 from validateAndProbeDestConfig, so nothing that reaches here
  // was ever asked to be immutable and left without immutability.
  worm: ReturnType<typeof validateWormPolicyValue>;
  probe: ProbeOk;
  // pricing is the OPTIONAL per-destination cost rates. It is passed through to the DO, which validates
  // it (validateDestPricing) and stores it; it is non-secret and never part of the location config the
  // probe runs under. Carried here because the router previously dropped it, so console-entered rates
  // never reached the store.
  pricing?: unknown;
}

// validateAndProbeDestConfig is the shared validation + live-probe core both POST /destination and POST
// /destinations run (their DO endpoints and body shapes differ legitimately: id/label/null-clear). It
// builds the runtime config from the untrusted body, validates the endpoint shape, the required fields,
// an unsupported storage class and the STS region, then probes the destination LIVE. On any failure it
// returns an { error } Response the caller returns verbatim; on success it returns the verified config
// plus the at-rest-wrapped credential, the optional WORM policy and the live probe verdict. The probe
// runs on the PLAINTEXT submitted config; the caller stores only the wrapped credential.
async function validateAndProbeDestConfig(env: RouterCtx["env"], rawConfig: unknown, scheduler?: DurableObjectStub): Promise<ValidatedDest | Response> {
  const c = (rawConfig ?? {}) as RawDestConfigBody;
  const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
  // assumeRole is the OPTIONAL STS policy: when present the accessKeyId/secretAccessKey are the
  // assume-role PRINCIPAL and the probe (and every run) mints temporary credentials via buildDestination.
  // Read from c (the null-safe (rawConfig ?? {})), so an absent config body is a clean 400, not a throw.
  // A SUBMITTED-but-unusable AssumeRole policy is refused here rather than dropped. Dropping it stored a
  // destination that silently used the principal keys DIRECTLY (not the role), or silently replaced the
  // requested session duration with the 3600-second default, and answered 200 either way. The read path
  // (validateAssumeRolePolicy, and clampDuration at request time) stays fail-safe for a value already in
  // storage; this is the one moment the operator can still fix it.
  const assumeRoleReason = assumeRolePolicyRejection(c.assumeRole);
  if (assumeRoleReason !== null) return jsonError(assumeRoleReason, 400);
  const assumeRole = validateAssumeRolePolicy(c.assumeRole);
  const addressing = validateAddressing(c.addressing);
  const storageClass = validateStorageClass(c.storageClass);
  // azureEntra is the OPTIONAL Microsoft Entra service principal for an Azure Blob destination (the
  // directory and application ids; the client secret is secretAccessKey). A SUBMITTED-but-unusable value
  // is refused here rather than dropped, on the same reasoning as the assumeRole policy above: dropping it
  // would store a destination that answers 200, reports itself verified, and then tries to use the client
  // secret as a storage account key on every write.
  const azureEntraReason = azureEntraDirectoryRejection(c.azureEntra);
  if (azureEntraReason !== null) return jsonError(azureEntraReason, 400);
  const azureEntra = validateAzureEntraDirectory(c.azureEntra);
  const submitted: RuntimeDestConfig = {
    endpoint: str(c.endpoint),
    bucket: str(c.bucket),
    region: str(c.region) || "auto",
    accessKeyId: str(c.accessKeyId),
    secretAccessKey: typeof c.secretAccessKey === "string" ? c.secretAccessKey : "",
    ...(assumeRole ? { assumeRole } : {}),
    ...(addressing ? { addressing } : {}),
    ...(storageClass ? { storageClass } : {}),
    ...(azureEntra ? { azureEntra } : {}),
  };
  if (!/^https:\/\/[^\s]+$/.test(submitted.endpoint)) {
    return jsonError("the destination endpoint must be an https URL (for R2: https://<account-id>.r2.cloudflarestorage.com)", 400);
  }
  // An endpoint that is a real, well-known object store we CANNOT write to is refused here by name, and
  // its ONE member is now the ADLS Gen2 `dfs` endpoint: Azure BLOB is a supported destination
  // and is dispatched to its own client, so it never reaches here. The dfs endpoint was
  // already refused, because it speaks a different wire protocol and answers the probe's very first call
  // 403. What the operator then got was "check the bucket name, the endpoint and that the credentials
  // allow object read and write on that bucket", which sends them to audit a credential that was never
  // the problem, for a protocol no setting would make work. The refusal moves BEFORE the SSRF check only
  // in the sense of being cheap and host-only; it does not weaken it, because an Azure host is a public
  // name and the SSRF guard still runs on every endpoint that gets past here.
  const unusable = unusableEndpoint(submitted.endpoint);
  if (unusable !== null) return jsonError(UNUSABLE_ENDPOINT_REASON[unusable], 400);
  // SSRF defence in depth (the webhook/IdP-test discipline): before probeDestination issues a live
  // GET/PUT against the endpoint, refuse a host that classifies as internal/private/loopback/link-local
  // (incl. cloud metadata at 169.254.169.254). The platform restricts some link-local egress, but the
  // application layer must not depend on that alone.
  let endpointHost: string;
  try {
    endpointHost = new URL(submitted.endpoint).hostname;
  } catch {
    return jsonError("the destination endpoint must be a valid https URL", 400);
  }
  if (isInternalSinkHost(endpointHost)) {
    // G314: the SSRF guard HELD, and nothing anywhere recorded that it had to. "Did anyone aim the destination
    // probe at 169.254.169.254?" is a post-incident question with a real answer, and the pack could not give it.
    // The refused HOST never rides (it is caller-chosen and could be anything); only the closed signal name.
    if (scheduler !== undefined) void recordAuthSignalEdge(scheduler, "ssrf-endpoint-refused");
    return jsonError("the destination endpoint resolves to an internal/private/loopback/link-local address (incl. cloud metadata); these are refused", 400);
  }
  if (submitted.bucket === "" || submitted.accessKeyId === "" || submitted.secretAccessKey === "") {
    return jsonError("the destination needs the bucket name and both credential halves (Access Key ID and Secret Access Key)", 400);
  }
  // A service principal on an endpoint that is not Azure Blob is refused rather than stored. Nothing reads
  // it there (only the Azure client has a bearer path), so storing it would leave a destination that
  // displays an Entra service principal in the console and authenticates with an S3 key pair on the wire.
  // ASSUMEROLE IS ALREADY REFUSED THE OTHER WAY ROUND, by AZURE_REFUSED_FIELDS below; this is the same
  // rule pointing the other direction, so neither cloud's credential can be stored against the other's
  // store.
  if (submitted.azureEntra !== undefined && providerForEndpoint(submitted.endpoint) !== "azure") {
    return jsonError(
      "a Microsoft Entra service principal only authenticates against Azure Blob Storage, and that endpoint is not an Azure Blob endpoint. Leave the tenant and application ids blank and use the credential pair this store accepts.",
      400,
    );
  }
  // An addressing style was submitted but is not one of auto/path/vhost. Refuse it explicitly rather than
  // dropping it: a dropped value stored a destination that answered
  // 200, reported itself verified, and addressed every object the AUTO way while the operator had chosen
  // path or vhost. Nothing downstream could tell that apart from a destination nobody ever set an addressing
  // style on. This is the last member of the four submitted destination fields to get its refusal: assumeRole
  // and worm carry rejection twins above, storageClass is refused immediately below, and this field was
  // already refused on the audit-export surface (router-push.ts) off the SAME predicate, so the two surfaces
  // cannot drift. An absent or blank value is not a rejection; it is the auto default.
  const addressingReason = addressingRejection(c.addressing);
  if (addressingReason !== null) return jsonError(addressingReason, 400);
  // A storage class was submitted but is not one downpipes will write to (e.g. GLACIER/DEEP_ARCHIVE).
  // Reject it explicitly rather than silently dropping it: those tiers are not immediately readable, so
  // they would break verify-at-seal (the read-back at seal time) and any restore.
  if (typeof c.storageClass === "string" && c.storageClass.trim() !== "" && submitted.storageClass === undefined) {
    return jsonError("that storage class is not supported. downpipes only writes to immediately-readable classes (STANDARD, STANDARD_IA, INTELLIGENT_TIERING, ONEZONE_IA); GLACIER and DEEP_ARCHIVE need an async thaw that would break verify-at-seal and restore.", 400);
  }
  // STS region guard (defence in depth on the SSRF surface, plus a clear error): when an AssumeRole
  // policy is set, the region is host-bearing for the STS call, so it must be a real AWS region.
  if (submitted.assumeRole && !isValidStsRegion(submitted.region)) {
    return jsonError(`STS AssumeRole needs a real AWS region (the destination region is "${submitted.region}"); set it to the role's region (Cloudflare R2's "auto" is not a valid STS region).`, 400);
  }
  // Google Cloud Storage and Azure Blob Storage each refuse a set of Amazon-specific fields, and each
  // refusal carries a remedy an operator of THAT store can act on.
  //
  // Google Cloud Storage reaches us through its S3-interoperable XML API, so it shares every wire path
  // with s3.ts and needs no writer of its own. Azure does not: it has its own client and its own signer.
  // What they share is that neither can honour a storage class named in Amazon's vocabulary, nor an STS
  // role. IMMUTABILITY IS NOT ON THAT LIST: BOTH stores can honour a policy,
  // Google Cloud through a bucket created with per-object retention and Azure through version-level
  // immutability on the container, and both were MEASURED doing so. Whether a given bucket enforces it is
  // decided by the live probe, exactly as it is for every other store, rather than by a rule about the
  // provider (see GCS_REFUSED_FIELDS and AZURE_REFUSED_FIELDS in dest/provider.ts for both measurements).
  //
  // This changes no outcome, only the sentence. Every field below already failed, loudly, before the
  // refusal existed: a storage class fails the write probe (GCS answers 400 InvalidStorageClass and the
  // probe carries the class), measured against a real bucket. The old object-lock message
  // told the operator to "create a new bucket with Object Lock enabled", which is Amazon's mechanism and
  // not Google Cloud's or Azure's, and a remedy that cannot be followed is worse than a plain refusal.
  //
  // Refused BEFORE the probe on purpose: the fault is in the submitted config, so there is nothing a live
  // round trip could add, and the operator should not wait on one to be told about their own input.
  // The refusal SET is chosen by provider; the mechanism below is one piece of code for both, so a third
  // provider with its own unsupported fields cannot end up with a second, subtly different implementation.
  const refusedFields = providerForEndpoint(submitted.endpoint) === "gcs" ? GCS_REFUSED_FIELDS : providerForEndpoint(submitted.endpoint) === "azure" ? AZURE_REFUSED_FIELDS : null;
  if (refusedFields !== null) {
    // `worm` is deliberately ABSENT from this map. It was here while both providers refused immutability
    // by rule, and neither does any more, so no refusal set carries a "worm" field for it to match: a
    // per-destination policy is now decided by the live probe below, the same way it is on Amazon S3.
    // Leaving a key here that nothing can look up would read as a rule that still exists.
    const present: Record<string, boolean> = {
      storageClass: submitted.storageClass !== undefined,
      assumeRole: submitted.assumeRole !== undefined,
      // addressing joins the map with AZURE_REFUSED_FIELDS's third entry. It is undefined
      // unless the operator explicitly chose path or vhost, so this can never fire on a default and an
      // Azure destination saved before today is byte-identical.
      addressing: submitted.addressing !== undefined,
    };
    const refused = refusedFields.find((f) => present[f.field] === true);
    if (refused !== undefined) return jsonError(refused.reason, 400);
  }
  const probe = await probeDestination(env, submitted);
  if (!probe.ok) {
    return jsonError(`destination verification failed: ${probe.reason}. Check the bucket name, the endpoint and that the credentials allow object read and write on that bucket.`, 400);
  }
  // Envelope-encrypt the credential at rest when CONFIG_WRAP_KEY is set (the probe above ran on the
  // plaintext; the DO will only ever hold the ciphertext). No key => plaintext floor (unchanged).
  // A MISCONFIGURED CONFIG_WRAP_KEY (e.g. standard base64 instead of the required base64url, or the wrong
  // length) makes loadConfigWrapKey throw; surface that as a clear operator 400 rather than a generic 500,
  // so a fresh-install key-encoding mistake is self-explaining instead of an opaque internal error.
  let storedSecret: Awaited<ReturnType<typeof maybeWrapConfigSecret>>;
  try {
    storedSecret = await maybeWrapConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), submitted.secretAccessKey);
  } catch (e) {
    return jsonError(`the engine's CONFIG_WRAP_KEY is misconfigured (${(e as Error).message}); fix it in the Secrets Store before adding a destination (the credential is encrypted at rest under this key)`, 400);
  }
  // worm is the OPTIONAL per-destination immutability policy (mode + retention days). It is added ONLY to
  // the stored config by the caller, NEVER to the `submitted` config the probe ran under: arming WORM on the
  // probe would lock its own write-probe object and make deleteProbe falsely read "denied" on an ordinary
  // bucket.
  //
  // A SUBMITTED-but-rejected policy is REFUSED here. It
  // used to be silently dropped: the destination stored, answered 200, reported itself verified, and carried
  // no immutability at all. A compliance control that is silently absent is worse than one that fails loudly,
  // and only an admin counter recorded it -- nothing the operator would ever see. An absent c.worm is not a
  // rejection (the operator configured no policy) and neither is an explicit null clear.
  //
  // The counter still fires, because "somebody tried to set an immutability policy and could not" is a
  // support question with a real answer, and the refusal below is now the operator-facing half of it.
  const wormReason = wormPolicyRejection(c.worm);
  if (wormReason !== null) {
    if (scheduler !== undefined) void bumpAdminCounter(scheduler, "dest-config-worm-policy-submitted-dropped");
    return jsonError(wormReason, 400);
  }
  const worm = validateWormPolicyValue(c.worm);
  // A WORM policy on a bucket that CANNOT enforce Object-Lock is refused here, at the one moment the
  // customer can still act on it.
  //
  // `worm` is the single stored field the probe above never runs under (see the comment on its validation:
  // arming WORM on the probe would lock the probe's own write-probe object and make deleteProbe falsely read
  // "denied", and a WORM-armed scratch object is undeletable for the retention window the operator just
  // typed, so probing with it armed would leave a locked object in the customer's bucket that neither party
  // can remove). So the destination passed the probe writing no lock headers and EVERY write afterwards
  // carries them: the store refuses all of them, and the product had already told the customer the
  // destination was verified. Nothing could ever be written to it.
  //
  // This costs NO extra request. probeDestination already read the bucket's Object-Lock configuration, in
  // the same function, before the same store call, and both write paths already persist the verdict.
  //
  // THE REMEDY IS BRANCHED BY PROVIDER: a single Amazon-shaped sentence would tell every operator to
  // "create a new bucket with Object Lock enabled". Azure's mechanism is version-level
  // immutability on the container or account, Google Cloud's is a bucket created with per-object
  // retention, and R2 has none at all by any route (see dest/worm-remedy.ts for the measurement). A
  // remedy an operator of that store cannot follow is worse than a plain refusal.
  if (worm !== null && wormCannotBeEnforced(probe)) {
    const store = immutabilityStoreNoun(providerForEndpoint(submitted.endpoint));
    return jsonError(
      `this ${store} cannot enforce an immutability policy, so every backup written to it would be refused by the store and nothing would be archived there. ${immutabilityRemedy(providerForEndpoint(submitted.endpoint))}`,
      400,
    );
  }
  return { submitted, storedSecret, worm, probe, pricing: c.pricing };
}

// wormCannotBeEnforced is the refusal predicate: does the probe's live verdict ESTABLISH that this bucket
// cannot enforce Object-Lock. Only a verdict the store itself answered counts.
//
// "not-enforced" is the store answering that the bucket has no Object-Lock configuration (a 404 on
// GetObjectLockConfiguration, or a configuration document reading Disabled). "unknown" with the reason
// "not-implemented" is the store answering 501: it has no Object-Lock API at all, so no bucket it holds can
// enforce anything, which is a store FACT and not a gap in our reading of it. Both are checked-and-failed.
//
// EVERY OTHER "unknown" is could-not-check, and is accepted. "denied" is a least-privilege credential that
// may write but not read the lock configuration; "network", "redirect", "server-error", "body-unparseable"
// and "other" are the probe not getting an answer; "r2-binding-unsupported" is a native R2 binding, which
// cannot arm a WORM policy in the first place. Refusing on any of those would turn a diagnostic gap into a
// customer-facing rejection of a correctly-configured destination, which is the opposite defect.
function wormCannotBeEnforced(probe: ProbeOk): boolean {
  if (probe.objectLock === "not-enforced") return true;
  return probe.objectLock === "unknown" && probe.objectLockUnknownReason === "not-implemented";
}

// handleDestinations dispatches the destination / destinations / setup-state / email-test group. Returns
// the route's Response, or null when no case here matched (the hub falls to the next spoke).
export async function handleDestinations(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, url, scheduler, caller, sub, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- archive destination (console-set; owner-exclusive; no CLI, no redeploy) -------------------
    // GET /destination is the redaction-safe view of WHERE BACKUPS GO: the console-set record when
    // present (endpoint host + bucket + region + who/when/verified, never a credential), else the
    // deploy-time env presence (kind only, mirroring /status). Any authenticated role may read it
    // (the same reconnaissance class as /status).
    case "GET /destination": {
      let consoleDest: { present: boolean; endpointHost?: string; bucket?: string; region?: string; setAt?: number; setBy?: string | null; verifiedAt?: number; deleteProbe?: TestDeleteProbe; source?: "deploy" } = { present: false };
      try {
        const resp = await scheduler.fetch(doURL("/dest-status"), { method: "GET" });
        consoleDest = (await resp.json()) as typeof consoleDest;
      } catch {
        // Presence-safe: report the console record honestly absent; the env facts still answer.
        // G051: "honestly absent" is exactly the trap -- the console then tells an account WITH a destination
        // that it has none, and support chases a configuration that is already there.
        fireInBackground(runtime, bumpAdminCounter(scheduler, "degraded-read-dest-status"));
      }
      const envStatus = buildStatus(env, 0);
      // DEST-REPLACE-REASSIGN: the default MAY now resolve to the synthetic source:"deploy"
      // record (ensureDeployDestSeeded), which reports present:true like any other stored destination --
      // without this check that record would be mislabelled "console" here, the one field on this legacy
      // singular view that read the record's OWN source rather than deriving one. It carries no real
      // credential and every value below it (endpointHost/bucket/etc.) is the blank placeholder
      // ensureDeployDestSeeded stored, not the live env fact; a customer wanting those reads envKind above.
      return jsonResponse({
        ...consoleDest,
        source: consoleDest.source === "deploy" ? "deploy" : consoleDest.present ? "console" : envStatus.destConfigured ? "deploy" : null,
        envConfigured: envStatus.destConfigured,
        envKind: envStatus.destKind,
      });
    }
    // POST /destination verifies the SUBMITTED destination LIVE before anything is stored (the
    // discovery-token discipline): an S3 store is built from the submitted values and probed,
    // reachability + read auth via exists() on the RUNLOG key, then a real write probe, then a
    // best-effort delete of the probe object (a refusal is recorded honestly as an immutable-bucket
    // posture, not a failure). Only a destination that PROVED writable is handed to the DO, which
    // re-checks owner, stores and audits (never a credential). config:null clears. Owner-exclusive
    // (keys.ceremony): repointing where every backup lands is break-glass-grade.
    case "POST /destination": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { config?: unknown };
      if (body.config === null) {
        return scheduler.fetch(doURL("/dest-config"), {
          method: "POST",
          body: JSON.stringify({ config: null }),
          headers: callerHeaders(caller),
        });
      }
      const validated = await validateAndProbeDestConfig(env, body.config, scheduler);
      if (validated instanceof Response) {
        // G245: "we tried to add our S3 destination three times last week." EVERY refusal on this path -- a
        // failed live write probe, an unusable endpoint, a misconfigured CONFIG_WRAP_KEY, an unsupported
        // storage class -- was a 400 into a browser and nothing else, so the pack could not show that the
        // customer had even attempted it, let alone which validator refused. A not-configured refusal (the
        // engine's own wrap key is unusable) is kept distinct from a validation refusal (the customer's input),
        // because they are opposite tickets. Never the endpoint, the bucket, the key id or the secret.
        fireInBackground(runtime, recordAdminRefusal(scheduler, "dest-add", validated.status >= 500 ? "not-configured" : "validation"));
        return validated;
      }
      const { submitted, storedSecret, worm, probe, pricing } = validated;
      const setResp = await scheduler.fetch(doURL("/dest-config"), {
        method: "POST",
        body: JSON.stringify({ config: { ...submitted, secretAccessKey: storedSecret, verifiedAt: Date.now(), deleteProbe: probe.deleteProbe, objectLock: probe.objectLock, ...(worm ? { worm } : {}), ...(pricing !== undefined ? { pricing } : {}) } }),
        headers: callerHeaders(caller),
      });
      // G7: real-time alert on the destination surface (repoint = exfil, remove = destroy). Fail-open.
      if (setResp.ok) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "dest-change", "dest-change", `A backup destination was set/repointed${caller.email ? ` by ${caller.email}` : ""}.`));
      return setResp;
    }
    // POST /destination/verify re-probes the EFFECTIVE destination (console-set config winning over
    // env, exactly as a run resolves it) and returns the honest live result. It writes nothing to
    // the DO (the stored verifiedAt marks the pre-store proof; this is the operator's on-demand
    // re-check). Owner-exclusive like the set, since the probe error can echo configuration detail.
    case "POST /destination/verify": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Verify the SPECIFIC destination the operator is looking at (?id=), not always the default.
      // Each destination in the collection holds its OWN credentials, so verifying the default for
      // every card hides which destination actually fails (and makes a broken default look like
      // "all destinations are down"). Absent id = the default, the legacy single-destination path.
      const verifyId = url.searchParams.get("id");
      let override: RuntimeDestConfig | null;
      try {
        override = await fetchDestConfig(scheduler, verifyId, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      } catch (e) {
        // G246: the engine's OWN config could not be read (a rotated wrap key). That is an `internal` test
        // failure, not a broken destination, and the two send support to opposite systems.
        fireInBackground(runtime, noteTestOutcome(scheduler, "dest-verify", { ok: false, reason: (e as Error).message }));
        return jsonResponse({ ok: false, reason: (e as Error).message });
      }
      const probe = await probeDestination(env, override ?? undefined);
      // G246: "verify destination keeps failing", and its quieter, worse sibling -- "verify says OK and our
      // storage bill never stops climbing".
      //
      // The probe's verdict reached one browser and died. Worse, its DELETE-DENIED finding was thrown away
      // even from that: a destination that accepts every write and refuses every delete PASSES this probe (it
      // should: backups genuinely work), and used to record {ok:true} -- byte-identical to a healthy one. The
      // retention policy the customer configured silently does nothing, the archive grows for ever, and no
      // artefact anywhere said so.
      //
      // deleteProbe, objectLock and (R4) the object-lock probe's OWN closed unknown-reason plus a default-retention
      // boolean now ride WITH the pass. The row records WHAT WAS MEASURED and nothing more:
      //   deleteProbe               did the destination let us delete what we had just written?
      //   objectLock                does the bucket report Object-Lock enabled, disabled, or could we not tell?
      //   objectLockUnknownReason   when we could not tell: WHY. "denied" (a least-privilege key that may not read
      //                             the lock config -- and, by the same allow-list, usually may not delete either,
      //                             so this is the one-line IAM fix) versus "not-implemented" (a store with no
      //                             Object-Lock API at all, where a refused delete is the customer's own policy).
      //                             These two used to be the SAME ROW, and they are the two intents this gap exists
      //                             to separate.
      //   defaultRetention          whether the locked bucket actually carries a default retention rule, because
      //                             Object-Lock ENABLED does not mean anything is being retained.
      // The row no longer asserts INTENT ("the customer chose this" / "nobody chose this"): the probe never
      // established intent, and an unversioned DELETE is not refused by Object Lock, so a 403 on a locked bucket is
      // a policy or credential denial and may be the very fault the customer is reporting. See sched-fault-ledger.ts.
      fireInBackground(
        runtime,
        noteTestOutcome(
          scheduler,
          "dest-verify",
          probe.ok
            ? {
                ok: true,
                deleteProbe: probe.deleteProbe,
                ...(probe.deleteStatusClass !== undefined ? { deleteStatusClass: probe.deleteStatusClass } : {}),
                objectLock: probe.objectLock,
                ...(probe.objectLockUnknownReason !== undefined ? { objectLockUnknownReason: probe.objectLockUnknownReason } : {}),
                ...(probe.defaultRetention !== undefined ? { defaultRetention: probe.defaultRetention } : {}),
              }
            : { ok: false, reason: probe.reason },
        ),
      );
      return jsonResponse(
        probe.ok
          ? {
              ok: true,
              deleteProbe: probe.deleteProbe,
              ...(probe.deleteStatusClass !== undefined ? { deleteStatusClass: probe.deleteStatusClass } : {}),
              objectLock: probe.objectLock,
              ...(probe.objectLockUnknownReason !== undefined ? { objectLockUnknownReason: probe.objectLockUnknownReason } : {}),
              ...(probe.defaultRetention !== undefined ? { defaultRetention: probe.defaultRetention } : {}),
              ms: probe.ms,
              source: override ? "console" : "deploy",
            }
          : { ok: false, reason: probe.reason },
      );
    }

    // ---- multiple destinations (the collection; lets an Owner keep more than one archive) -----------
    // GET /destinations lists every console-set destination (redaction-safe: host/bucket/region/label/
    // who-when, never a credential) plus which id is the default. Any authenticated role may read it
    // (same reconnaissance class as GET /destination).
    // Here the ROUTER IS THE ONLY POSSIBLE HOME, which is what separates this
    // from the notify and rbac reads gated in the same pass. This forward carries no callerHeaders at all,
    // so the DO receives no principal and its arm (listDestStatus(), scheduler-do-routing-config.ts) could
    // not enforce anything even if it wanted to. "Any authenticated role may read it" therefore had
    // nothing anywhere holding it up. posture.read is the floor it already sits behind elsewhere:
    // support-sections-config.ts fetches doURL("/destinations") into the posture.read-gated support pack,
    // twice. Viewer-floor capability, so no reachable principal is refused.
    case "GET /destinations": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/destinations"), { method: "GET" });
    }
    // POST /destinations ADDS a new destination (no id) or EDITS one (id present). Exactly like
    // POST /destination it VERIFIES the submitted credentials LIVE (reachability + read + a real write
    // probe) before the DO stores anything, so an unwritable bucket is never added. Owner-exclusive.
    case "POST /destinations": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { id?: unknown; label?: unknown; config?: unknown };
      const validated = await validateAndProbeDestConfig(env, body.config, scheduler);
      if (validated instanceof Response) return validated;
      const { submitted, storedSecret, worm, probe, pricing } = validated;
      // DEST-REPLACE-REASSIGN: envDestConfigured is read HERE (the router is the one place
      // with env binding access; the DO cannot see DEST_R2 or the DEST_* vars itself) and carried into the
      // SAME gated putDest call, never a separate one, so the deploy-time destination's synthetic seed and
      // this add land under one owner decision even when dual control is on. It is the exact fact GET
      // /destination already reports as envConfigured, over the SAME buildStatus(env, 0) read: PURE env,
      // never influenced by whether a console destination already exists.
      const envDestConfigured = buildStatus(env, 0).destConfigured;
      const putResp = await scheduler.fetch(doURL("/destinations"), {
        method: "POST",
        body: JSON.stringify({
          ...(typeof body.id === "string" ? { id: body.id } : {}),
          label: typeof body.label === "string" ? body.label : "",
          config: { ...submitted, secretAccessKey: storedSecret, verifiedAt: Date.now(), deleteProbe: probe.deleteProbe, objectLock: probe.objectLock, ...(worm ? { worm } : {}), ...(pricing !== undefined ? { pricing } : {}) },
          envDestConfigured,
        }),
        headers: callerHeaders(caller),
      });
      if (putResp.ok) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "dest-change", "dest-change", `A backup destination was added or edited${caller.email ? ` by ${caller.email}` : ""}.`));
      return putResp;
    }
    // POST /destinations/remove deletes a destination by id; POST /destinations/default makes one the
    // default. Both owner-exclusive (they change where backups can land); neither needs a live probe.
    case "POST /destinations/remove": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // force overrides the orphan guard (removing a destination that is the only proven copy of some runs).
      const rmBody = (await req.json()) as { id?: unknown; force?: unknown };
      const rmResp = await scheduler.fetch(doURL("/destinations/remove"), { method: "POST", body: JSON.stringify({ id: typeof rmBody.id === "string" ? rmBody.id : "", force: rmBody.force === true }), headers: callerHeaders(caller) });
      if (rmResp.ok) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "dest-change", "dest-change", `A backup destination removal was requested${rmBody.force === true ? " (force: drops orphan-guarded copies)" : ""}${caller.email ? ` by ${caller.email}` : ""}.`));
      return rmResp;
    }
    case "POST /destinations/default": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const id = ((await req.json()) as { id?: unknown }).id;
      const defResp = await scheduler.fetch(doURL("/destinations/default"), { method: "POST", body: JSON.stringify({ id: typeof id === "string" ? id : "" }), headers: callerHeaders(caller) });
      if (defResp.ok) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "dest-change", "dest-change", `The default backup destination was changed${caller.email ? ` by ${caller.email}` : ""}.`));
      return defResp;
    }

    // ---- setup state (the guided first-run's one consolidated read) --------------------------------
    // GET /setup-state assembles the facts the console's guided setup derives its steps from: who
    // and what is configured, counted, and proven, presence and counts ONLY, never a value. Any
    // authenticated role (the same reconnaissance class as /status; the gate above already ran).
    // Each DO read is presence-safe: a hiccup leaves that fact honestly absent, never fabricated.
    case "GET /setup-state": {
      // freshRes is the demo-only fresh-first-run marker (set by a demo reset, cleared by the next key
      // ceremony). It only ever exists on a DEMO_MODE engine, and the override below is DEMO_MODE-gated, so
      // a production engine is never affected; presence-safe like the others (a hiccup leaves it absent).
      const demoMode = envFlagEnabled(env.DEMO_MODE);
      // engine-src-037-M1: on a DEMO_MODE engine, persist the in-DO demo marker (fire-and-forget, presence-
      // safe). The DO cannot read DEMO_MODE from env, so this is how a genuine demo instance proves itself
      // to its OWN fail-closed /demo/reset guard. /setup-state is read on every guided-setup load, so the
      // marker is in place well before any reset is attempted; a production engine (no DEMO_MODE) never
      // marks, so its /demo/reset stays fail-closed even on a misrouted call.
      if (demoMode) {
        try { await scheduler.fetch(doURL("/demo/mark"), { method: "POST" }); } catch { /* fail-open: harmless off-demo, the reset guard still fails closed without it */ }
      }
      const [dpRes, discRes, disposalRes, destRes, freshRes] = await Promise.allSettled([
        scheduler.fetch(doURL("/downpipes"), { method: "GET" }).then((r) => r.json() as Promise<Array<{ lastRunId?: unknown }>>),
        scheduler.fetch(doURL("/sources/discovery-status"), { method: "GET" }).then((r) => r.json() as Promise<{ present?: boolean; selected?: string[]; engineAccountId?: string | null }>),
        scheduler.fetch(doURL("/policy/break-glass-disposal"), { method: "GET" }).then((r) => r.json() as Promise<{ bootstrapConsumed?: boolean }>),
        scheduler.fetch(doURL("/dest-status"), { method: "GET" }).then((r) => r.json() as Promise<{ present?: boolean; verifiedAt?: number; bucket?: string; endpointHost?: string; source?: string }>),
        demoMode ? scheduler.fetch(doURL("/demo/first-run"), { method: "GET" }).then((r) => r.json() as Promise<{ forceFirstRun?: boolean }>) : Promise.resolve({ forceFirstRun: false }),
      ]);
      // G051: /setup-state is the guided wizard's whole view of the account, and every one of these five reads
      // degrades to "not configured", so a DO blip can restart a fully-configured account at step one.
      if (dpRes.status === "rejected" || discRes.status === "rejected" || disposalRes.status === "rejected" || destRes.status === "rejected" || freshRes.status === "rejected") {
        fireInBackground(runtime, bumpAdminCounter(scheduler, "degraded-read-setup-state"));
      }
      const downpipes = dpRes.status === "fulfilled" && Array.isArray(dpRes.value) ? dpRes.value : null;
      const disc = discRes.status === "fulfilled" ? discRes.value : null;
      const disposal = disposalRes.status === "fulfilled" ? disposalRes.value : null;
      const dest = destRes.status === "fulfilled" ? destRes.value : null;
      // Force a fresh first run after a demo reset (the signer/break-glass worker secrets survive the DO
      // wipe, so without this the ceremony step would read done). DEMO_MODE-gated; never in production.
      const forceFirstRun = demoMode && freshRes.status === "fulfilled" && freshRes.value?.forceFirstRun === true;
      // DEST-REPLACE-REASSIGN: a source:"deploy" record is present:true (ensureDeployDestSeeded)
      // but carries no real credential, so it must not read here as "a console destination is set" -- see
      // the identical guard's citation in router-status.ts.
      const consoleDestSet = dest?.present === true && dest.source !== "deploy";
      const envStatus = buildStatus(env, downpipes?.length ?? 0, { consoleDestSet, ...(typeof dest?.endpointHost === "string" ? { consoleDestHost: dest.endpointHost } : {}) });
      const bound = enumerateBoundSources(env);
      const boundSourceCount = bound.kv.length + bound.r2.length + bound.d1.length + bound.secrets.length;
      const envToken = typeof env.DISCOVERY_API_TOKEN === "string" && env.DISCOVERY_API_TOKEN.trim() !== "";
      const emailConfigured = env.EMAIL !== undefined && typeof env.EMAIL_FROM === "string" && env.EMAIL_FROM.includes("@");
      return jsonResponse({
        ...(disposal && typeof disposal.bootstrapConsumed === "boolean" ? { ownerExists: disposal.bootstrapConsumed } : {}),
        keysReady: envStatus.signerConfigured && envStatus.breakGlassConfigured && !forceFirstRun,
        signerConfigured: envStatus.signerConfigured,
        breakGlassConfigured: envStatus.breakGlassConfigured,
        emailConfigured,
        discoveryTokenPresent: disc?.present === true || envToken,
        accountsSelected: (disc?.selected?.length ?? 0) > 0 || envToken,
        destination: {
          configured: envStatus.destConfigured,
          verified: consoleDestSet && typeof dest?.verifiedAt === "number",
          kind: envStatus.destKind,
          source: consoleDestSet ? "console" : envStatus.destConfigured ? "deploy" : null,
          ...(consoleDestSet && typeof dest?.bucket === "string" ? { bucket: dest.bucket } : {}),
          ...(consoleDestSet && typeof dest?.endpointHost === "string" ? { endpointHost: dest.endpointHost } : {}),
        },
        boundSourceCount,
        ...(downpipes !== null ? { downpipeCount: downpipes.length, anyRunCompleted: downpipes.some((d) => d && typeof d === "object" && typeof d.lastRunId === "string" && d.lastRunId !== "") } : {}),
        ready: envStatus.ready,
      });
    }

    // ---- email delivery test (the operator's "is Email Service actually set up?" probe) -----------
    // POST /email/test sends a tiny test message to the CALLER's own verified email, never a
    // client-supplied address (the body is ignored), so the route cannot be aimed at anyone else. It
    // exists because Email Service problems are observable only at send time: the result carries the
    // honest outcome INCLUDING the platform error code (E_SENDER_DOMAIN_NOT_AVAILABLE when the
    // EMAIL_FROM domain is not onboarded for sending, E_SENDER_NOT_VERIFIED, ...), so the console can
    // advise the exact dashboard step instead of leaving a silent no-op. Authenticated (any role: it
    // is the caller's own address and their own account's configuration); the bare-token break-glass
    // has no email and gets the honest no-recipient reason. Rate-limited like every mutating POST.
    case "POST /email/test": {
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      if (caller.email === null) {
        fireInBackground(runtime, noteTestOutcome(scheduler, "email", { ok: false, reason: "not-configured" }));
        return jsonResponse({ ok: false, reason: "email-test-needs-identity" });
      }
      const result = await sendEmail(env, {
        to: [caller.email],
        subject: "Downpipes email delivery test",
        text: `This is the delivery test you requested from the Downpipes console. If you are reading it, outbound email from this engine works. Sender: ${typeof env.EMAIL_FROM === "string" ? env.EMAIL_FROM : "(unset)"}.`,
        html: renderEngineEmailHtml({
          subject: "Downpipes email delivery test",
          heading: "Email delivery test",
          paragraphs: [
            "This is the delivery test you requested from the Downpipes console.",
            "If you are reading it, outbound email from this engine works.",
            `Sender: ${typeof env.EMAIL_FROM === "string" ? env.EMAIL_FROM : "(unset)"}.`,
          ],
        }),
      });
      // G246: the email platform's rejection code (an un-onboarded sender domain, an unverified sender, a
      // platform throttle) is the answer to "our test email never arrives", and it went into the HTTP response
      // and nowhere else -- so it died with the browser tab, and all three states landed in the pack as one row
      // ({"ok":false,"reasonClass":"other"}) with three different remedies. R6: the code now RIDES, gated to the
      // documented E_UPPER_SNAKE shape by emailPlatformCodeOf inside noteTestOutcome. The reason is CLASSIFIED;
      // the provider's text (which can interpolate the recipient address) is still discarded.
      fireInBackground(
        runtime,
        noteTestOutcome(scheduler, "email", {
          ok: result.ok === true,
          ...("reason" in result ? { reason: (result as { reason?: unknown }).reason } : {}),
          ...(result.code !== undefined ? { platformCode: result.code } : {}),
        }),
      );
      return jsonResponse(result);
    }
    default:
      return null;
  }
}
