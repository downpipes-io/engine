// validate-cov-sched-scheduler-do-dest-config: focused branch-coverage validator for the archive-destination
// config mixin (src/sched/scheduler-do-dest-config.ts). It drives the REAL SchedulerDO (DestConfigMixin) over
// an in-memory storage double and exercises every honestly-reachable branch: the load/lazy-migrate of the
// destination collection, per-id resolution, the redaction-safe status views, the record build/validate path
// (including every optional-field and rejection branch), the owner-gated set/put/remove/default mutators, the
// approval-summary builder, the audit helper, and the only-proven-copy removal safety scan. Every assertion
// checks a real returned value or a stored/audited effect through the production method; nothing under test is
// stubbed (the only double is DO storage). Run: node test/validate-cov-sched-scheduler-do-dest-config.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { classifyDestRejectReason } from "../src/sched/scheduler-do-dest-config.ts";
import type { AuthMethod } from "../src/admin/identity.ts";
import type { AuditEvent } from "../src/admin/audit.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeDO(seed: Record<string, unknown> = {}): { dobj: SchedulerDO; storage: MockStorage } {
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(seed)) storage.seed(k, v);
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return { dobj, storage };
}

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null };
// A bare-token caller short-circuits roleForCaller to owner (the break-glass owner the DO trusts).
const OWNER: Caller = { method: "token", email: null, subject: null, groups: [] };
const OWNER_NAMED: Caller = { method: "token", email: "boss@acme.example", subject: null, groups: [], sourceIp: "10.0.0.9" };
// An Access caller whose subject is in no role table resolves to viewer (the owner gate must refuse it).
const NONOWNER: Caller = { method: "access", email: "ned@acme.example", subject: "sub-ned", groups: [] };

// A full, valid submitted destination config buildDestRecord accepts; overrides tune individual fields.
function fullConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    endpoint: "https://acct.r2.cloudflarestorage.com",
    bucket: "archive-x",
    region: "auto",
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey: "super-secret-value",
    verifiedAt: 1700000000000,
    deleteProbe: "ok",
    ...overrides,
  };
}

// A stored destination record (the shape loadDestinations returns), for seeding collections directly.
function storedDest(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "default",
    label: "Default",
    endpoint: "https://acct.r2.cloudflarestorage.com",
    bucket: "bk",
    region: "auto",
    accessKeyId: "AK",
    secretAccessKey: "SK",
    setAt: 1,
    setBy: "owner@acme.example",
    verifiedAt: 1,
    deleteProbe: "ok",
    ...over,
  };
}

async function caught(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e as Error;
  }
}
function caughtSync(fn: () => unknown): Error | null {
  try {
    fn();
    return null;
  } catch (e) {
    return e as Error;
  }
}

async function main(): Promise<void> {
  // ============================================================================================
  // loadDestinations: the well-formed collection contract + the lazy legacy migration.
  // ============================================================================================
  console.log("-- loadDestinations: collection read, dangling-default heal, legacy migration, empties --");
  {
    // (A) a stored collection with a VALID default is returned as-is.
    const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "a" }), storedDest({ id: "b", bucket: "bb" })], defaultId: "b" } });
    const c = await dobj.loadDestinations();
    ok("a stored collection with a valid default is returned unchanged", c.list.length === 2 && c.defaultId === "b");
  }
  {
    // (B) a DANGLING default heals to the first entry (never points at nothing while the list is non-empty).
    const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "a" }), storedDest({ id: "b" })], defaultId: "ghost" } });
    const c = await dobj.loadDestinations();
    ok("a dangling default heals to the first entry", c.defaultId === "a");
  }
  {
    // (C) no collection but a LEGACY single record migrates to the "default" entry and is persisted.
    const { dobj, storage } = makeDO({ destConfig: storedDest({ id: "should-be-ignored", label: "legacy-label", bucket: "legacy-bucket" }) });
    const c = await dobj.loadDestinations();
    ok("a legacy record migrates to a single 'default' entry", c.list.length === 1 && c.list[0]!.id === "default" && c.defaultId === "default");
    ok("the migrated default's label is the legacy bucket", c.list[0]!.label === "legacy-bucket");
    ok("the migration is PERSISTED to the collection key", storage.has("destinations"));
  }
  {
    // (C2) a legacy record with NO bucket labels the migrated entry "Archive".
    const { dobj } = makeDO({ destConfig: storedDest({ bucket: "" }) });
    const c = await dobj.loadDestinations();
    ok("a legacy record with no bucket migrates with the label 'Archive'", c.list[0]!.label === "Archive");
  }
  {
    // (D) nothing stored at all -> an empty collection.
    const { dobj } = makeDO();
    const c = await dobj.loadDestinations();
    ok("an unconfigured DO returns an empty collection", c.list.length === 0 && c.defaultId === "");
  }
  {
    // (E) a malformed stored collection (list is not an array) is treated as absent.
    const { dobj } = makeDO({ destinations: { list: "not-an-array", defaultId: "x" } });
    const c = await dobj.loadDestinations();
    ok("a malformed collection (non-array list) falls back to empty", c.list.length === 0 && c.defaultId === "");
  }

  // ============================================================================================
  // getDestConfigById: default vs explicit-id resolution; a dangling id is null, never a wrong bucket.
  // ============================================================================================
  console.log("-- getDestConfigById: empty -> null, default resolve, explicit-id resolve, dangling -> null --");
  {
    const { dobj: empty } = makeDO();
    ok("getDestConfigById on an empty collection is null", (await empty.getDestConfigById("anything")) === null);

    const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "default", bucket: "one" }), storedDest({ id: "two", bucket: "twob" })], defaultId: "default" } });
    ok("no id resolves the DEFAULT destination", (await dobj.getDestConfigById())?.bucket === "one");
    ok("a null id resolves the DEFAULT destination", (await dobj.getDestConfigById(null))?.bucket === "one");
    ok("an explicit id resolves THAT destination", (await dobj.getDestConfigById("two"))?.bucket === "twob");
    ok("a dangling id resolves to null (fails loud, never a wrong bucket)", (await dobj.getDestConfigById("nope")) === null);
  }

  // ============================================================================================
  // destStatusOf: the redaction-safe single-record view, both sides of every conditional.
  // ============================================================================================
  console.log("-- destStatusOf: endpoint parse + catch, keys vs sts, default flag, every optional spread --");
  {
    const { dobj } = makeDO();
    // Minimal record: valid endpoint, IS the default, no optional posture fields -> keys, isDefault, no spreads.
    const minView = dobj.destStatusOf(
      storedDest({ id: "default", endpoint: "https://host.example/path", bucket: "bk", region: "auto" }) as never,
      "default",
    );
    ok("destStatusOf parses the endpoint host from a valid URL", minView.endpointHost === "host.example");
    ok("destStatusOf reports authMode 'keys' with no assumeRole", minView.authMode === "keys");
    ok("destStatusOf flags the default destination", minView.isDefault === true);
    ok("destStatusOf omits worm/objectLock/assumeRole/addressing/storageClass/pricing when absent", minView.worm === undefined && minView.objectLock === undefined && minView.assumeRoleArn === undefined && minView.addressing === undefined && minView.storageClass === undefined && minView.pricing === undefined);
    ok("destStatusOf NEVER surfaces the secret access key", (minView as unknown as Record<string, unknown>).secretAccessKey === undefined);

    // Full record: MALFORMED endpoint (catch keeps the raw value), NOT the default, every optional present.
    const fullView = dobj.destStatusOf(
      storedDest({
        id: "edge", endpoint: "not a url", region: "ap",
        worm: { mode: "compliance", retentionDays: 7 },
        objectLock: "enforced",
        assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Archiver" },
        addressing: "path", storageClass: "STANDARD_IA",
        pricing: { storagePerGBMonth: 0.015, classAPerMillion: 1, classBPerMillion: 1, egressPerGB: 0 },
      }) as never,
      "default",
    );
    ok("destStatusOf reports the raw endpoint when the URL is malformed (honest, non-secret)", fullView.endpointHost === "not a url");
    ok("destStatusOf reports authMode 'sts' + the role ARN when assumeRole is set", fullView.authMode === "sts" && fullView.assumeRoleArn === "arn:aws:iam::123456789012:role/Archiver");
    ok("destStatusOf does not flag a non-default destination", fullView.isDefault === false);
    ok("destStatusOf surfaces every present optional (worm/objectLock/addressing/storageClass/pricing)", !!fullView.worm && fullView.objectLock === "enforced" && fullView.addressing === "path" && fullView.storageClass === "STANDARD_IA" && !!fullView.pricing);

    // THE ENTRA SERVICE PRINCIPAL, surfaced because the console has to SEED an edit form with it.
    //
    // This boundary rebuilds the stored config from the submitted body, so a destination re-saved from a
    // form that could not show its existing principal is stored WITHOUT one, and the next run tries to use
    // the client secret as a storage account key. assumeRoleArn is surfaced for exactly that reason and
    // these two ids are the same case. Both are declared non-secret where the type is defined
    // (dest/factory-validators.ts): the third value, the client secret, rides in the credential slot.
    const entraView = dobj.destStatusOf(
      storedDest({
        id: "az", endpoint: "https://acct.blob.core.windows.net", region: "auto",
        azureEntra: { tenantId: "72f988bf-86f1-41af-91ab-2d7cd011db47", clientId: "d290f1ee-6c54-4b01-90e6-d701748f0851" },
        secretAccessKey: "the-client-secret-which-must-never-appear",
      }) as never,
      "default",
    );
    ok("destStatusOf surfaces the Entra directory and application ids", entraView.azureEntra?.tenantId === "72f988bf-86f1-41af-91ab-2d7cd011db47" && entraView.azureEntra?.clientId === "d290f1ee-6c54-4b01-90e6-d701748f0851");
    ok("destStatusOf NEVER surfaces the Entra client secret", !JSON.stringify(entraView).includes("the-client-secret-which-must-never-appear"));
    ok("destStatusOf omits azureEntra entirely when there is no principal", (minView as unknown as Record<string, unknown>).azureEntra === undefined);

    // authMode NAMES THE MECHANISM THE WRITES WILL ACTUALLY USE. It answered "keys" for an Entra
    // destination until, which was not merely imprecise: the console renders an Authentication
    // row only for "sts", so an Entra destination showed NO authentication row at all and a customer could
    // not tell from the console that it signs in as a service principal rather than with a storage key.
    ok("destStatusOf reports authMode 'entra' for a service principal", entraView.authMode === "entra");
    ok("destStatusOf still reports 'keys' with neither a principal nor a role", minView.authMode === "keys");
    ok("destStatusOf still reports 'sts' for an assumeRole destination", fullView.authMode === "sts");
    // The precedence, stated rather than left to branch order. They cannot both be set in practice
    // (assumeRole is AWS, and the write boundary refuses azureEntra on a non-Azure endpoint), but if a
    // stored record carried both, the Entra principal is what the writes would use.
    const bothView = dobj.destStatusOf(
      storedDest({
        id: "both", endpoint: "https://acct.blob.core.windows.net", region: "auto",
        azureEntra: { tenantId: "72f988bf-86f1-41af-91ab-2d7cd011db47", clientId: "d290f1ee-6c54-4b01-90e6-d701748f0851" },
        assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Backup" },
      }) as never,
      "default",
    );
    ok("destStatusOf prefers 'entra' over 'sts' when a record somehow carries both", bothView.authMode === "entra");
  }

  // ============================================================================================
  // getDestStatus + listDestStatus: present/absent default and the list defaultId null on empty.
  // ============================================================================================
  console.log("-- getDestStatus / listDestStatus: present default, absent default, empty list defaultId --");
  {
    const { dobj: empty } = makeDO();
    ok("getDestStatus on an empty collection reports present:false", (await empty.getDestStatus()).present === false);
    const le = await empty.listDestStatus();
    ok("listDestStatus on an empty collection has no destinations and a null defaultId", le.destinations.length === 0 && le.defaultId === null);

    const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "default", bucket: "one" }), storedDest({ id: "two", bucket: "twob" })], defaultId: "default" } });
    ok("getDestStatus reports the present default", (await dobj.getDestStatus()).present === true && (await dobj.getDestStatus()).bucket === "one");
    const l = await dobj.listDestStatus();
    ok("listDestStatus lists every destination with the defaultId", l.destinations.length === 2 && l.defaultId === "default");
  }

  // ============================================================================================
  // buildDestRecord: the shape-defence validate path - secret kinds, rejections, every optional branch.
  // ============================================================================================
  console.log("-- buildDestRecord: secret kinds, https + completeness rejections, optionals, label/probe/verifiedAt --");
  {
    const { dobj } = makeDO();
    // A kitchen-sink valid config (string secret) -> every optional present, provided verifiedAt + denied probe.
    const full = dobj.buildDestRecord(
      fullConfig({
        verifiedAt: 1700000000000, deleteProbe: "denied",
        worm: { mode: "governance", retentionDays: 30 },
        objectLock: "enforced",
        assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Archiver", externalId: "ext-1", durationSeconds: 900 },
        addressing: "vhost", storageClass: "INTELLIGENT_TIERING",
        pricing: { storagePerGBMonth: 0.02, currency: "USD", source: "operator" },
      }),
      "id-full", "  Trimmed Label  ", OWNER_NAMED,
    );
    ok("buildDestRecord trims the label", full.label === "Trimmed Label");
    ok("buildDestRecord records the caller email as setBy", full.setBy === "boss@acme.example");
    ok("buildDestRecord keeps a string secret verbatim", full.secretAccessKey === "super-secret-value");
    ok("buildDestRecord honours a provided finite verifiedAt", full.verifiedAt === 1700000000000);
    ok("buildDestRecord honours a 'denied' delete probe", full.deleteProbe === "denied");
    ok("buildDestRecord keeps a valid worm/objectLock/assumeRole/addressing/storageClass/pricing", !!full.worm && full.objectLock === "enforced" && !!full.assumeRole && full.addressing === "vhost" && full.storageClass === "INTELLIGENT_TIERING" && !!full.pricing);

    // A minimal config with a WRAPPED secret envelope, an EMPTY label, a null caller, no optionals, a missing
    // verifiedAt (-> Date.now) and a missing delete probe (-> "ok").
    const wrapped = { v: 1, iv: "aabbcc", ct: "ddeeff" };
    const min = dobj.buildDestRecord({ endpoint: "https://h.example", bucket: "mini", region: "auto", accessKeyId: "AK", secretAccessKey: wrapped }, "id-min", "", null);
    ok("buildDestRecord defaults the label to the bucket when blank", min.label === "mini");
    ok("buildDestRecord records a null setBy for a null caller", min.setBy === null);
    ok("buildDestRecord keeps a WrappedSecret envelope verbatim", JSON.stringify(min.secretAccessKey) === JSON.stringify(wrapped));
    ok("buildDestRecord defaults a missing verifiedAt to a finite now", typeof min.verifiedAt === "number" && Number.isFinite(min.verifiedAt));
    ok("buildDestRecord defaults a missing delete probe to 'ok'", min.deleteProbe === "ok");
    ok("buildDestRecord drops every absent optional", min.worm === undefined && min.objectLock === undefined && min.assumeRole === undefined && min.addressing === undefined && min.storageClass === undefined && min.pricing === undefined);

    // A MICROSOFT ENTRA service principal is stored, and a malformed one is dropped. Both matter. Stored,
    // because the run path reads this record to decide whether to sign a request or to spend the
    // secretAccessKey as a client secret at the identity plane, and a dropped principal silently reverts
    // the destination to Shared Key. Dropped when malformed, because a stored config must never
    // half-apply: without a usable principal the Azure client falls back to reading secretAccessKey as a
    // storage account key, which fails loudly instead of authenticating as something nobody configured.
    const sp = dobj.buildDestRecord(fullConfig({ azureEntra: { tenantId: "98d21390-5d4f-488d-8fef-cb5b4defe180", clientId: "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57" } }), "id-sp", "L", OWNER_NAMED);
    ok("buildDestRecord stores a valid Entra service principal", sp.azureEntra?.tenantId === "98d21390-5d4f-488d-8fef-cb5b4defe180" && sp.azureEntra.clientId === "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57");
    const spBad = dobj.buildDestRecord(fullConfig({ azureEntra: { tenantId: "common", clientId: "not-a-guid" } }), "id-sp-bad", "L", OWNER_NAMED);
    ok("buildDestRecord DROPS a malformed Entra service principal rather than storing it", spBad.azureEntra === undefined);

    // A whitespace-only label also defaults to the bucket (the trim() || bucket falsy side via a non-empty input).
    const ws = dobj.buildDestRecord(fullConfig({ bucket: "wsbk" }), "id-ws", "   ", OWNER_NAMED);
    ok("buildDestRecord defaults a whitespace-only label to the bucket", ws.label === "wsbk");

    // A non-finite verifiedAt (Infinity) falls back to a finite now rather than being stored.
    const inf = dobj.buildDestRecord(fullConfig({ verifiedAt: Infinity }), "id-inf", "L", OWNER_NAMED);
    ok("buildDestRecord rejects a non-finite verifiedAt and uses a finite now", Number.isFinite(inf.verifiedAt) && inf.verifiedAt !== Infinity);

    // objectLock enum: each accepted value is kept; an unknown value is dropped.
    ok("buildDestRecord keeps objectLock 'not-enforced'", dobj.buildDestRecord(fullConfig({ objectLock: "not-enforced" }), "i", "l", OWNER_NAMED).objectLock === "not-enforced");
    ok("buildDestRecord keeps objectLock 'unknown'", dobj.buildDestRecord(fullConfig({ objectLock: "unknown" }), "i", "l", OWNER_NAMED).objectLock === "unknown");
    ok("buildDestRecord drops an out-of-enum objectLock", dobj.buildDestRecord(fullConfig({ objectLock: "bogus" }), "i", "l", OWNER_NAMED).objectLock === undefined);

    // A malformed worm/assumeRole is dropped (fail-safe defence in depth) rather than stored.
    const badPosture = dobj.buildDestRecord(fullConfig({ worm: { mode: "nope" }, assumeRole: { roleArn: "not-an-arn" }, addressing: "weird", storageClass: "GLACIER", pricing: { nope: true } }), "i", "l", OWNER_NAMED);
    ok("buildDestRecord drops a malformed worm/assumeRole/addressing/storageClass/pricing", badPosture.worm === undefined && badPosture.assumeRole === undefined && badPosture.addressing === undefined && badPosture.storageClass === undefined && badPosture.pricing === undefined);

    // POSTCONDITION, the currency label. validateDestPricing promises a TRIMMED label, and it
    // used to break that promise on its own output: it trimmed and THEN sliced to 8, so a value whose only
    // non-space tail sat past the cut came back carrying the whitespace the trim had just removed. The
    // truncation stays (a label's tail costs detail rather than identity, and it names nothing elsewhere);
    // the second trim is what makes the promise true. Both the clean baseline and the exact boundary must
    // still pass, so the repair cannot have become an over-truncation.
    {
      const cur = (v: unknown): string | undefined => dobj.buildDestRecord(fullConfig({ pricing: { storagePerGBMonth: 0.01, currency: v } }), "i", "l", OWNER_NAMED).pricing?.currency;
      ok("currency CONTROL: a clean label is stored verbatim", cur("AUD") === "AUD");
      ok("currency CONTROL: surrounding whitespace is trimmed", cur("  AUD  ") === "AUD");
      ok("currency CONTROL: exactly 8 characters survive whole", cur("ABCDEFGH") === "ABCDEFGH");
      ok("POSTCONDITION: a label cut mid-whitespace is not stored with a trailing space", cur("AUD     Y") === "AUD");
      ok("POSTCONDITION: the same with tabs", cur("AU\tD\t\t\t\t\tZ") === "AU\tD");
    }

    // Rejections (throw -> the router maps to 400): a non-https endpoint, and an incomplete config.
    const e1 = caughtSync(() => dobj.buildDestRecord(fullConfig({ endpoint: "http://insecure.example" }), "i", "l", OWNER_NAMED));
    ok("buildDestRecord rejects a non-https endpoint", e1 !== null && /https URL/.test(e1.message));
    const e2 = caughtSync(() => dobj.buildDestRecord(fullConfig({ bucket: "  " }), "i", "l", OWNER_NAMED));
    ok("buildDestRecord rejects a config missing the bucket", e2 !== null && /bucket, a region and both credential halves/.test(e2.message));
    // A non-string, non-envelope secret collapses to "" and is rejected by the completeness guard.
    const e3 = caughtSync(() => dobj.buildDestRecord(fullConfig({ secretAccessKey: 12345 }), "i", "l", OWNER_NAMED));
    ok("buildDestRecord rejects a secret that is neither a string nor an envelope", e3 !== null && /credential halves/.test(e3.message));
    // An absent config (undefined) coalesces to {} so every field reads "" and the https guard rejects it
    // (the nullish-coalesce fallback + the string-coercion's non-string side).
    const e4 = caughtSync(() => dobj.buildDestRecord(undefined, "i", "l", null));
    ok("buildDestRecord rejects an absent config", e4 !== null && /https URL/.test(e4.message));
  }

  // ============================================================================================
  // summariseDestConfig: the redaction-safe approval summary, every formatting branch.
  // ============================================================================================
  console.log("-- summariseDestConfig: clear forms, host parse/catch/skip, bucket/region fallbacks, worm/auth notes --");
  {
    const { dobj } = makeDO();
    ok("a null config summarises as a clear", dobj.summariseDestConfig("Set", null) === "Set (clear)");
    ok("a non-object config summarises as a clear", dobj.summariseDestConfig("Set", "a-string") === "Set (clear)");

    const full = dobj.summariseDestConfig("Set", {
      endpoint: "https://h.example/x", bucket: "bk", region: "us-east-1",
      worm: { mode: "compliance", retentionDays: 14 },
      assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Archiver" },
    });
    ok("a full config names bucket/host/region with worm + STS notes", full === "Set: bk at h.example [us-east-1] + immutability compliance 14d + auth STS role arn:aws:iam::123456789012:role/Archiver");

    // A malformed endpoint (catch -> host ""), a non-string bucket (-> "(bucket)"), an empty region (-> "auto"),
    // and a malformed worm/assumeRole (no notes).
    const edge = dobj.summariseDestConfig("Set", { endpoint: "::::", bucket: 123, region: "", worm: { mode: "bad" }, assumeRole: { roleArn: "nope" } });
    ok("a malformed/absent config falls back to the placeholders with no notes", edge === "Set: (bucket) at (host) [auto]");

    // The approval summary names the Entra principal for the same reason it names the role ARN: the second
    // approver is approving WHICH identity backups are written as, and a stored account key and a service
    // principal are different answers with different revocation stories. Both ids are identifiers, and the
    // client secret (which is secretAccessKey) is nowhere near this string.
    const entra = dobj.summariseDestConfig("Set", {
      endpoint: "https://acct.blob.core.windows.net", bucket: "archive", region: "auto",
      azureEntra: { tenantId: "98d21390-5d4f-488d-8fef-cb5b4defe180", clientId: "1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57" },
    });
    ok("an Entra destination names the application and the tenant in the approval summary", entra === "Set: archive at acct.blob.core.windows.net [auto] + auth Entra app 1e9a12a5-235f-475a-a3a7-9f3d7f9c6e57 in tenant 98d21390-5d4f-488d-8fef-cb5b4defe180");

    // An endpoint that is NOT a string skips the parse entirely (host stays "").
    const noEndpoint = dobj.summariseDestConfig("Set", { bucket: "only-bucket", region: "auto" });
    ok("a non-string endpoint skips host parsing", noEndpoint === "Set: only-bucket at (host) [auto]");
  }

  // ============================================================================================
  // auditDest: who/method/sourceIp normalisation onto the audit chain (a real persisted effect).
  // ============================================================================================
  console.log("-- auditDest: caller email/method/sourceIp normalisation onto the audit log --");
  {
    const { dobj } = makeDO();
    await dobj.auditDest({ method: "passkey", email: "a@acme.example", sourceIp: "1.2.3.4" }, "dest-config-set");
    await dobj.auditDest(null, "dest-config-cleared");
    await dobj.auditDest({ method: "access", email: null }, "dest-config-set");
    const events = (await dobj.listAuditEntries()) as AuditEvent[];
    ok("auditDest records an attributable set (email + method + sourceIp)", events.some((e) => e.action === "dest-config-set" && e.actorEmail === "a@acme.example" && e.actorMethod === "passkey" && e.sourceIp === "1.2.3.4"));
    ok("auditDest records a null-caller clear as method 'access' with null actor/ip", events.some((e) => e.action === "dest-config-cleared" && e.actorEmail === null && e.actorMethod === "access" && e.sourceIp === null));
    ok("auditDest records an emailless caller with a null actor + null ip", events.some((e) => e.action === "dest-config-set" && e.actorEmail === null && e.actorMethod === "access" && e.sourceIp === null));
    ok("every dest audit event targets the access-policy surface (never a secret)", events.every((e) => e.target?.kind === "access-policy"));
  }

  // ============================================================================================
  // auditDestChange: the enriched dest-change target the support pack diagnoses over (WS-D config-change).
  // ============================================================================================
  console.log("-- auditDestChange: force-orphan removal, default promotion, rejected set, reject-class map --");
  {
    // classifyDestRejectReason maps a buildDestRecord throw to a CLOSED reason (defensive catch-all included).
    ok("classify: non-https endpoint -> endpoint-not-https", classifyDestRejectReason(new Error("the destination endpoint must be an https URL")) === "endpoint-not-https");
    ok("classify: missing fields -> missing-fields", classifyDestRejectReason(new Error("the destination needs a bucket, a region and both credential halves")) === "missing-fields");
    ok("classify: an unknown Error -> invalid-config (defensive catch-all)", classifyDestRejectReason(new Error("something else")) === "invalid-config");
    ok("classify: a non-Error throw -> invalid-config", classifyDestRejectReason("not-an-error") === "invalid-config");

    // A FORCED removal that drops the only proven copy records op=remove + force + the orphan count AND the
    // default promotion (dest-removed-force-orphans-runs + dest-default-promotion-silent-redirect).
    {
      const dests = { list: [storedDest({ id: "default", label: "Default" }), storedDest({ id: "two", label: "Two", bucket: "two" })], defaultId: "two" };
      const dp = { config: { id: "fan", name: "Fan", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: ["default"] }, nextRunAt: 0, lastRunId: "run-5", inFlight: false };
      const hist = [{ runId: "run-5", index: 5, startedAt: "2026-06-15T00:00:00.000Z", status: "ok", destinationId: "two" }];
      const { dobj } = makeDO({ destinations: dests, "dp:fan": dp, "hist:fan": hist });
      await dobj.removeDest("two", true, OWNER_NAMED);
      const events = (await dobj.listAuditEntries()) as AuditEvent[];
      const t = (events.find((e) => e.action === "dest-config-cleared" && e.target.kind === "dest-change")?.target ?? {}) as { op?: string; force?: boolean; uncoveredOriginRunCount?: number; fromDefaultId?: string; toDefaultId?: string; affectedDownpipeNames?: string[] };
      ok("a forced removal records op=remove + force + the uncovered-origin run count", t.op === "remove" && t.force === true && t.uncoveredOriginRunCount === 1);
      ok("a forced removal of the default records the before/after default promotion", t.fromDefaultId === "two" && t.toDefaultId === "default");
      // DROPPED-FIELD: the count answers "how bad" and the names answer "who", and only the count
      // was ever asserted here -- the same three fields, in the same order, as the whitelist inside
      // auditDestChange that silently dropped the names. This reads the WRITTEN audit record end to end, not a
      // hand-built target, which is the difference between proving the projection and proving the producer.
      ok("a forced removal also records WHICH downpipes lost their only proven copy", JSON.stringify(t.affectedDownpipeNames ?? []) === JSON.stringify(["Fan"]));
    }

    // An explicit default repoint records op=default + before/after (dest-default-promotion, explicit form).
    {
      const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "default" }), storedDest({ id: "two", bucket: "two" })], defaultId: "default" } });
      await dobj.setDefaultDest("two", OWNER);
      const events = (await dobj.listAuditEntries()) as AuditEvent[];
      const t = (events.find((e) => e.action === "dest-config-set" && e.target.kind === "dest-change")?.target ?? {}) as { op?: string; fromDefaultId?: string; toDefaultId?: string };
      ok("a default repoint records op=default with the before/after default", t.op === "default" && t.fromDefaultId === "default" && t.toDefaultId === "two");
    }

    // A REJECTED set (owner, non-https endpoint) records a FAILED dest-config-set with the reason class, then
    // rethrows (the 400 is unchanged): drives the buildDestRecord catch + auditDestChange reject path.
    {
      const { dobj } = makeDO();
      const rej = await caught(() => dobj.setDestConfig({ config: fullConfig({ endpoint: "http://insecure.example" }) }, OWNER));
      ok("a rejected set still throws (400 behaviour unchanged)", rej !== null && /https URL/.test(rej.message));
      const events = (await dobj.listAuditEntries()) as AuditEvent[];
      const t = (events.find((e) => e.action === "dest-config-set" && e.outcome === "failed")?.target ?? {}) as { kind?: string; op?: string; rejectReason?: string };
      ok("a rejected set records a FAILED dest-config-set with the closed reject reason", t.kind === "dest-change" && t.op === "set" && t.rejectReason === "endpoint-not-https");
    }

    // putDest reject: missing-fields (empty bucket) -> the same reject-audit path via putDest.
    {
      const { dobj } = makeDO();
      const rej = await caught(() => dobj.putDest({ label: "x", config: fullConfig({ bucket: "" }) }, OWNER));
      ok("a rejected putDest still throws (missing fields)", rej !== null && /bucket, a region/.test(rej.message));
      const events = (await dobj.listAuditEntries()) as AuditEvent[];
      const t = (events.find((e) => e.action === "dest-config-set" && e.outcome === "failed")?.target ?? {}) as { rejectReason?: string };
      ok("a rejected putDest records reject reason missing-fields", t.rejectReason === "missing-fields");
    }
  }

  // ============================================================================================
  // setDestConfig: owner gate + the singular set/clear mapped onto the default destination.
  // ============================================================================================
  console.log("-- setDestConfig: owner gate, create default, update in place, clear + promote, clear to empty --");
  {
    const { dobj } = makeDO();
    const denied = await caught(() => dobj.setDestConfig({ config: fullConfig() }, NONOWNER));
    ok("setDestConfig refuses a non-owner", denied !== null && denied.name === "AuthError" && /Owner/.test(denied.message));

    // Create the first destination -> it becomes the default (the !some-default branch).
    const created = await dobj.setDestConfig({ config: fullConfig({ bucket: "first" }) }, OWNER);
    ok("setDestConfig creates the first destination as the default", created.present === true && created.bucket === "first");
    ok("the created default is the single 'default' entry", (await dobj.listDestStatus()).destinations.length === 1 && (await dobj.listDestStatus()).defaultId === "default");

    // Update the existing default in place (same id, the some-default-true branch).
    const updated = await dobj.setDestConfig({ config: fullConfig({ bucket: "second" }) }, OWNER);
    ok("setDestConfig updates the default in place", updated.bucket === "second" && (await dobj.listDestStatus()).destinations.length === 1);

    // Add a SECOND destination, then clear the default -> the remaining one is promoted.
    await dobj.putDest({ label: "keepme", config: fullConfig({ bucket: "keep" }) }, OWNER);
    const afterClear = await dobj.setDestConfig({ config: null }, OWNER);
    const afterClearList = await dobj.listDestStatus();
    ok("clearing the default promotes the remaining destination", afterClearList.destinations.length === 1 && afterClearList.destinations[0]!.bucket === "keep" && afterClear.bucket === "keep");

    // Clear the last destination -> the collection empties and the default id goes blank.
    await dobj.setDestConfig({ config: null }, OWNER);
    const empty = await dobj.listDestStatus();
    ok("clearing the last destination empties the collection", empty.destinations.length === 0 && empty.defaultId === null);
    ok("getDestStatus reports present:false after the last clear", (await dobj.getDestStatus()).present === false);
  }

  // ============================================================================================
  // putDest: owner gate, add (auto-default first), add (no promote), edit by id, non-string label.
  // ============================================================================================
  console.log("-- putDest: owner gate, first add becomes default, second add keeps default, edit by id --");
  {
    const { dobj } = makeDO();
    const denied = await caught(() => dobj.putDest({ config: fullConfig() }, NONOWNER));
    ok("putDest refuses a non-owner", denied !== null && denied.name === "AuthError");

    const r1 = await dobj.putDest({ label: "alpha", config: fullConfig({ bucket: "a" }) }, OWNER);
    const alpha = r1.destinations.find((d) => d.label === "alpha")!;
    ok("the first added destination becomes the default", r1.destinations.length === 1 && r1.defaultId === alpha.id && alpha.isDefault === true);

    const r2 = await dobj.putDest({ label: "beta", config: fullConfig({ bucket: "b" }) }, OWNER);
    ok("a second add does NOT change the default", r2.destinations.length === 2 && r2.defaultId === alpha.id);

    // Edit alpha by id with a NON-STRING label -> the label collapses to "" and defaults to the bucket.
    const r3 = await dobj.putDest({ id: alpha.id, label: 12345, config: fullConfig({ bucket: "a2" }) }, OWNER);
    const editedAlpha = r3.destinations.find((d) => d.id === alpha.id)!;
    ok("editing by id updates that destination in place (no new row)", r3.destinations.length === 2);
    ok("a non-string label collapses to the bucket on edit", editedAlpha.bucket === "a2" && editedAlpha.label === "a2");

    // Provide a brand-new explicit id (the existingId-non-null path with no match) -> a new row is added.
    const r4 = await dobj.putDest({ id: "chosen-id", label: "gamma", config: fullConfig({ bucket: "g" }) }, OWNER);
    ok("an explicit unused id adds a new destination with that id", r4.destinations.some((d) => d.id === "chosen-id" && d.label === "gamma"));
  }

  // ============================================================================================
  // setDefaultDest: owner gate, unknown id, repoint the default.
  // ============================================================================================
  console.log("-- setDefaultDest: owner gate, unknown id rejection, repoint --");
  {
    const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "default" }), storedDest({ id: "two", bucket: "twob" })], defaultId: "default" } });
    const denied = await caught(() => dobj.setDefaultDest("two", NONOWNER));
    ok("setDefaultDest refuses a non-owner", denied !== null && denied.name === "AuthError");
    const missing = await caught(() => dobj.setDefaultDest("ghost", OWNER));
    ok("setDefaultDest rejects an unknown destination id", missing !== null && /no such destination/.test(missing.message));
    const r = await dobj.setDefaultDest("two", OWNER);
    ok("setDefaultDest repoints the default", r.defaultId === "two");
  }

  // ============================================================================================
  // removeDest: owner gate, unknown id, in-use pin guard, orphan guard, force override, covered-elsewhere,
  // and the default-promotion on removal.
  // ============================================================================================
  console.log("-- removeDest: owner gate, unknown, pin guard, orphan guard, force, covered, default-promote --");
  {
    const dests = { list: [storedDest({ id: "default", label: "Default" }), storedDest({ id: "two", label: "Two", bucket: "two" })], defaultId: "default" };
    const dpDroppedTwo = { config: { id: "fan", name: "Fan", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: ["default"] }, nextRunAt: 0, lastRunId: "run-5", inFlight: false };
    const histOriginTwo = [{ runId: "run-5", index: 5, startedAt: "2026-06-15T00:00:00.000Z", status: "ok", destinationId: "two" }];

    {
      const { dobj } = makeDO({ destinations: dests });
      const denied = await caught(() => dobj.removeDest("two", false, NONOWNER));
      ok("removeDest refuses a non-owner", denied !== null && denied.name === "AuthError");
    }
    {
      const { dobj } = makeDO({ destinations: dests });
      const missing = await caught(() => dobj.removeDest("ghost", false, OWNER));
      ok("removeDest rejects an unknown destination id", missing !== null && /no such destination/.test(missing.message));
    }
    {
      // The in-use pin guard fires when a downpipe currently references the destination.
      const dpPinsTwo = { ...dpDroppedTwo, config: { ...dpDroppedTwo.config, destinationIds: ["two", "default"] } };
      const { dobj } = makeDO({ destinations: dests, "dp:fan": dpPinsTwo, "hist:fan": histOriginTwo });
      const inUse = await caught(() => dobj.removeDest("two", false, OWNER));
      ok("removeDest refuses a destination a downpipe still pins", inUse !== null && /in use by/.test(inUse.message));
    }
    {
      // The orphan guard fires when the destination is the only proven copy of an origin run.
      const { dobj } = makeDO({ destinations: dests, "dp:fan": dpDroppedTwo, "hist:fan": histOriginTwo });
      const orphan = await caught(() => dobj.removeDest("two", false, OWNER));
      ok("removeDest refuses the only proven copy of a backed-up run", orphan !== null && /only proven copy/.test(orphan.message));
      ok("the destination survives a refused orphan removal", (await dobj.listDestStatus()).destinations.some((d) => d.id === "two"));
    }
    {
      // force overrides the orphan guard.
      const { dobj } = makeDO({ destinations: dests, "dp:fan": dpDroppedTwo, "hist:fan": histOriginTwo });
      const r = await dobj.removeDest("two", true, OWNER);
      ok("force drops the destination despite the orphan guard", !r.destinations.some((d) => d.id === "two"));
    }
    {
      // covered-elsewhere: another destination's replication state PROVES it holds the run's window
      // (holdsFrom <= the origin run <= holdsIndex) -> allowed. holdsFrom:1 models "default holds
      // contiguously from run 1 through run 5" (the membership bound now requires a proven floor, not just a
      // top: a replica that only observed from a higher ring floor cannot cover a below-floor origin run).
      const { dobj } = makeDO({ destinations: dests, "dp:fan": dpDroppedTwo, "hist:fan": histOriginTwo, "repl:fan": { default: { holdsRunId: "run-5", holdsIndex: 5, holdsFrom: 1, lastOk: true, lastAttemptAt: 1 } } });
      const r = await dobj.removeDest("two", false, OWNER);
      ok("removeDest allows removal once another destination is proven caught up", !r.destinations.some((d) => d.id === "two"));
    }
    {
      // Removing the DEFAULT promotes the next remaining destination (and audits the clear).
      const { dobj } = makeDO({ destinations: dests });
      const r = await dobj.removeDest("default", true, OWNER);
      ok("removing the default promotes the next destination", r.defaultId === "two" && !r.destinations.some((d) => d.id === "default"));
    }
    {
      // Removing the LAST (and default) destination empties the collection and blanks the default id.
      const { dobj } = makeDO({ destinations: { list: [storedDest({ id: "only" })], defaultId: "only" } });
      const r = await dobj.removeDest("only", true, OWNER);
      ok("removing the last destination empties the collection and blanks the default", r.destinations.length === 0 && r.defaultId === null);
    }
    {
      // The in-use message TRUNCATES with an ellipsis past five pinning downpipes.
      const seed: Record<string, unknown> = { destinations: dests };
      for (let i = 0; i < 6; i++) {
        seed[`dp:pin${i}`] = { config: { id: `pin${i}`, name: `Pinner ${i}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: ["two"] }, nextRunAt: 0, lastRunId: null, inFlight: false };
      }
      const { dobj } = makeDO(seed);
      const inUse = await caught(() => dobj.removeDest("two", false, OWNER));
      ok("the in-use guard message truncates past five pinning downpipes", inUse !== null && /in use by 6 downpipe/.test(inUse.message) && /…/.test(inUse.message));
    }
    {
      // The orphan message TRUNCATES with an ellipsis past five at-risk downpipes (each an uncovered origin).
      const seed: Record<string, unknown> = { destinations: dests };
      for (let i = 0; i < 6; i++) {
        seed[`dp:orig${i}`] = { config: { id: `orig${i}`, name: `Origin ${i}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: ["default"] }, nextRunAt: 0, lastRunId: `r${i}`, inFlight: false };
        seed[`hist:orig${i}`] = [{ runId: `r${i}`, index: i, startedAt: "t", status: "ok", destinationId: "two" }];
      }
      const { dobj } = makeDO(seed);
      const orphan = await caught(() => dobj.removeDest("two", false, OWNER));
      ok("the orphan guard message truncates past five at-risk downpipes", orphan !== null && /only proven copy of 6 backed-up run/.test(orphan.message) && /…/.test(orphan.message));
    }
  }

  // ============================================================================================
  // uncoveredOriginRuns: the removal safety scan in isolation - every count/skip/fallback branch.
  // ============================================================================================
  console.log("-- uncoveredOriginRuns: multi-run reduce, no-origin skip, covered skip, same-dest guard, name fallback --");
  {
    const { dobj } = makeDO({
      // dpA: two origin runs for D, no repl -> uncovered, counted (named).
      "hist:dpA": [{ runId: "r1", index: 5, startedAt: "t", status: "ok", destinationId: "D" }, { runId: "r2", index: 3, startedAt: "t", status: "ok", destinationId: "D" }],
      // dpB: a run for a DIFFERENT destination -> no origin runs for D -> skipped (the length-0 continue).
      "hist:dpB": [{ runId: "r3", index: 2, startedAt: "t", status: "ok", destinationId: "OTHER" }],
      // dpC: one origin run for D (index 9), but another destination (E) PROVES it holds [1, 9] (holdsFrom
      // 1 <= 9 <= holdsIndex 9) -> covered, skipped. The holdsFrom floor is required by the membership bound.
      "hist:dpC": [{ runId: "r4", index: 9, startedAt: "t", status: "ok", destinationId: "D" }],
      "repl:dpC": { E: { holdsRunId: "r4", holdsIndex: 9, holdsFrom: 1, lastOk: true, lastAttemptAt: 1 } },
      // dpOrphan: one origin run for D; its only repl entry is for D ITSELF (same-dest guard) and it has no
      // name in the map -> uncovered, counted with the dpId as the fallback name.
      "hist:dpOrphan": [{ runId: "r5", index: 1, startedAt: "t", status: "ok", destinationId: "D" }],
      "repl:dpOrphan": { D: { holdsRunId: "r5", holdsIndex: 1, lastOk: true, lastAttemptAt: 1 } },
    });
    const nameById = new Map<string, string>([["dpA", "Downpipe A"], ["dpC", "Downpipe C"]]);
    const res = await dobj.uncoveredOriginRuns("D", nameById);
    ok("uncoveredOriginRuns counts every uncovered origin run (2 from dpA + 1 from dpOrphan)", res.count === 3);
    ok("uncoveredOriginRuns names the covered downpipe + falls back to the id for an unnamed one", JSON.stringify(res.names) === JSON.stringify(["Downpipe A", "dpOrphan"]));
  }

  // uncoveredOriginRuns: the ring-floor membership bound. A
  // covering destination must PROVE it holds the origin run's WINDOW (holdsFrom <= run <= holdsIndex), not
  // just that its top index is high enough; a run below the covering dest's proven floor (or a legacy record
  // with no floor at all) is NOT covered, so removing the origin would drop what may be the run's only copy.
  console.log("-- uncoveredOriginRuns: a covering dest must PROVE its floor (holdsFrom), not just its top --");
  {
    const { dobj } = makeDO({
      // dpBelow: D is the origin of a run at index 20 (BELOW E's proven floor 31). E holds [31, 80], so it
      // proves nothing at index 20 -> NOT covered -> at risk (removing D would drop the run's only copy).
      "hist:dpBelow": [{ runId: "r20", index: 20, startedAt: "t", status: "ok", destinationId: "D" }],
      "repl:dpBelow": { E: { holdsRunId: "r80", holdsIndex: 80, holdsFrom: 31, lastOk: true, lastAttemptAt: 1 } },
      // dpWithin: D is the origin of a run at index 50 (INSIDE E's [31, 80]) -> covered -> skipped.
      "hist:dpWithin": [{ runId: "r50", index: 50, startedAt: "t", status: "ok", destinationId: "D" }],
      "repl:dpWithin": { E: { holdsRunId: "r80", holdsIndex: 80, holdsFrom: 31, lastOk: true, lastAttemptAt: 1 } },
      // dpLegacy: D is the origin of a run at index 40; E has NO recorded floor (a legacy record) -> it proves
      // nothing below its holdsIndex -> NOT covered -> at risk (conservative; removal blocked, self-heals).
      "hist:dpLegacy": [{ runId: "r40", index: 40, startedAt: "t", status: "ok", destinationId: "D" }],
      "repl:dpLegacy": { E: { holdsRunId: "r80", holdsIndex: 80, lastOk: true, lastAttemptAt: 1 } },
    });
    const res = await dobj.uncoveredOriginRuns("D", new Map());
    // A pure holdsIndex compare (20<=80 AND 40<=80) would treat all three as covered -> count 0; with the
    // floor bound the below-floor (20) and no-floor (40) runs are at risk while the within-window (50) run
    // stays covered -> count 2.
    ok("a below-floor origin run and a no-floor (legacy) one are NOT covered; a within-window one IS (count 2)", res.count === 2);
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-DEST-CONFIG VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
