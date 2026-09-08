// Validates the ServiceNow Event Management notify channel (src/notify/channels/servicenow.ts): the pure
// format()/servicenowSeverity()/servicenowMessageKey() shapers, the fetch-recording delivery vectors
// (exact URL/verb/Basic-auth-header/body, mirroring the captures[] pattern in test/validate-siem-push.ts),
// the CREATE vs auto-CLEAR (recovered -> severity 0) shapes, the sealed-secret round-trip + cross-AAD
// negative (SERVICENOW_SECRET_AAD), the KEEP-SECRET update semantics at the DO (addNotifyChannel), the
// network-fault fail-open path, the SSRF default-deny re-screen, and the no-custody envelope (the password
// never rides in the body or url). No network. Run:
//   node test/validate-servicenow.ts

import { format, servicenowSeverity, servicenowMessageKey, deliver, buildServiceNowBody, type ServiceNowEventPayload, type EmJsonV2Envelope } from "../src/notify/channels/servicenow.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify/types.ts";
import { wrapConfigSecret, unwrapConfigSecret, resolveConfigSecret, maybeWrapConfigSecret, JSM_SECRET_AAD, SERVICENOW_SECRET_AAD, PUSH_SECRET_AAD, PUSH_S3_SECRET_AAD } from "../src/admin/config-secret.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
async function throwsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    ok(label, false);
  } catch {
    ok(label, true);
  }
}

import { MockStorage } from "./mock-storage.ts";

function makeDO(): SchedulerDO {
  return new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
}
const OWNER_CALLER = { method: "token" as const, email: null, subject: null, role: "owner" as const };

const EMISSION: NotifyEmission = {
  event: "backup-failure",
  severity: "critical",
  downpipeId: "pipe-1",
  downpipeName: "Prod KV",
  detail: "Prod KV last run failed",
  at: "2026-06-09T00:00:00.000Z",
};
const ACCOUNT_EMISSION: NotifyEmission = { ...EMISSION, downpipeId: null, downpipeName: null };
const SN_URL = "https://instance.service-now.com/api/now/table/em_event";

async function main(): Promise<void> {
  console.log("format(): pure shape correctness");
  {
    const p = format(EMISSION);
    ok("format: source is the fixed vendor label", p.source === "downpipes");
    ok("format: node is the redaction-safe downpipe name", p.node === "Prod KV");
    ok("format: resource is the event enum", p.resource === "backup-failure");
    ok("format: metric_name namespaces the event", p.metric_name === "downpipe.backup-failure");
    ok("format: severity mapped (critical -> 1)", p.severity === 1);
    ok("format: description carries the full detail", p.description === "Prod KV last run failed");
    ok("format: message_key mirrors pagerdutyDedupKey's shape (downpipe:<id>:<event>)", p.message_key === "downpipe:pipe-1:backup-failure");
    const allowed = new Set(["source", "node", "resource", "metric_name", "severity", "description", "message_key"]);
    ok("format: no extra keys (no-custody surface)", Object.keys(p).every((k) => allowed.has(k)));

    const acct = format(ACCOUNT_EMISSION);
    ok("format: account-level event -> account:<event> message_key", acct.message_key === "account:backup-failure");
    ok("format: account-level event -> node falls back to 'downpipe'", acct.node === "downpipe");
  }

  console.log("\nservicenowSeverity: our scale -> ServiceNow's 0=Clear..5=Info (recovered ALWAYS wins as 0, regardless of nominal severity)");
  {
    ok("servicenowSeverity: critical -> 1", servicenowSeverity(EMISSION) === 1);
    ok("servicenowSeverity: warning -> 4", servicenowSeverity({ ...EMISSION, severity: "warning" }) === 4);
    ok("servicenowSeverity: info -> 5", servicenowSeverity({ ...EMISSION, severity: "info" }) === 5);
    ok("servicenowSeverity: recovered -> 0 (Clear) regardless of nominal severity", servicenowSeverity({ ...EMISSION, severity: "critical", recovered: true }) === 0);
    ok("servicenowSeverity: recovered + info -> still 0", servicenowSeverity({ ...EMISSION, severity: "info", recovered: true }) === 0);
  }

  console.log("\nservicenowMessageKey: stable dedup key, downpipe-scoped or account-scoped");
  {
    ok("servicenowMessageKey: downpipe-scoped", servicenowMessageKey(EMISSION) === "downpipe:pipe-1:backup-failure");
    ok("servicenowMessageKey: stable across repeated calls", servicenowMessageKey(EMISSION) === servicenowMessageKey({ ...EMISSION, detail: "a different detail line" }));
    ok("servicenowMessageKey: account-scoped when downpipeId is null", servicenowMessageKey(ACCOUNT_EMISSION) === "account:backup-failure");
    // The SAME message_key across a create and its later recovered emission is what lets ServiceNow's
    // correlation engine group them onto one Alert thread (create then auto-clear).
    ok("servicenowMessageKey: identical for a create and its later recovered emission (correlation)", servicenowMessageKey(EMISSION) === servicenowMessageKey({ ...EMISSION, recovered: true }));
  }

  console.log("\ndeliver: CREATE POSTs to the channel's OWN em_event url with HTTP Basic auth; body is the event shape; no-custody (password never in body/url)");
  {
    const channel: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc_downpipes", apiKey: "s3cr3t-PASSWORD-abc", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env; // no CONFIG_WRAP_KEY configured -> the plaintext back-compat floor
    const realFetch = globalThis.fetch;
    const captures: Array<{ url: string; method?: string; headers: Record<string, string>; body: string }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), ...(init?.method !== undefined ? { method: init.method } : {}), headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
      return new Response("ok", { status: 201 });
    }) as typeof fetch;
    let result: Awaited<ReturnType<typeof deliver>>;
    try {
      result = await deliver(env, channel, EMISSION);
    } finally {
      globalThis.fetch = realFetch;
    }
    ok("servicenow create: delivered ok on a 2xx", result.ok === true);
    const last = captures[captures.length - 1];
    ok("servicenow create: exactly one POST, to the channel's own em_event url", captures.length === 1 && last?.url === SN_URL && last?.method === "POST");
    const expectedAuth = `Basic ${btoa("svc_downpipes:s3cr3t-PASSWORD-abc")}`;
    ok("servicenow create: Authorization is HTTP Basic (base64 user:pass)", last?.headers.Authorization === expectedAuth);
    ok("servicenow create: content-type is application/json", last?.headers["content-type"] === "application/json");
    const bodyDoc = JSON.parse(last?.body ?? "{}") as ServiceNowEventPayload;
    ok("servicenow create: body matches format() (severity 1, message_key, resource)", bodyDoc.severity === 1 && bodyDoc.message_key === "downpipe:pipe-1:backup-failure" && bodyDoc.resource === "backup-failure");
    ok("servicenow create: the body NEVER contains the password (no-custody)", !(last?.body ?? "").includes("s3cr3t-PASSWORD-abc"));
    ok("servicenow create: the url NEVER contains the password (no-custody)", !(last?.url ?? "").includes("s3cr3t-PASSWORD-abc"));
    ok("servicenow create: the Authorization header itself never appears in the body (auth in header, never body)", !(last?.body ?? "").includes(expectedAuth));
  }

  console.log("\ndeliver: endpoint tolerance -- the Table API keeps the flat body; em/jsonv2 wraps it in {records:[...]}");
  {
    // buildServiceNowBody (pure): the Table API path is untouched (the flat event object).
    const ev = format(EMISSION);
    const tableBody = buildServiceNowBody(SN_URL, ev);
    ok("/api/now/table/em_event keeps the FLAT body (no records wrapper)", tableBody === ev && !("records" in tableBody));

    // A jsonv2 endpoint wraps the SAME event in {records:[event]}.
    const JSONV2_URL = "https://instance.service-now.com/api/global/em/jsonv2";
    const jsonv2Body = buildServiceNowBody(JSONV2_URL, ev) as EmJsonV2Envelope;
    ok("/api/global/em/jsonv2 wraps the event as {records:[event]}", Array.isArray(jsonv2Body.records) && jsonv2Body.records.length === 1 && jsonv2Body.records[0] === ev);

    // Case-insensitivity (defensive: a customer might paste a differently-cased path).
    const jsonv2UpperBody = buildServiceNowBody("https://instance.service-now.com/api/global/EM/JSONV2", ev) as EmJsonV2Envelope;
    ok("the em/jsonv2 match is case-insensitive", Array.isArray(jsonv2UpperBody.records) && jsonv2UpperBody.records[0] === ev);

    // End to end through deliver(): the actual POSTed body reflects the endpoint tolerance, not just the
    // pure helper.
    const channel: NotifyChannel = { id: "c-jv2", kind: "servicenow", name: "SNOW jsonv2", url: JSONV2_URL, username: "svc_downpipes", apiKey: "s3cr3t-PASSWORD-jv2", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    const captures: Array<{ body: string }> = [];
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ body: String(init?.body ?? "") });
      return new Response("ok", { status: 201 });
    }) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("deliver() to a jsonv2 endpoint reports ok:true", r.ok === true);
      const bodyDoc = JSON.parse(captures[0]?.body ?? "{}") as EmJsonV2Envelope;
      ok("deliver() actually POSTed the {records:[...]} envelope, not the flat body", Array.isArray(bodyDoc.records) && bodyDoc.records.length === 1 && bodyDoc.records[0]?.message_key === "downpipe:pipe-1:backup-failure");
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliver: a RECOVERED emission sends severity 0 (Clear) to the SAME endpoint with the SAME message_key (auto-clears the Alert; the SAME POST shape as create, per ServiceNow's own model)");
  {
    const channel: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc", apiKey: "pw", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    const captures: Array<{ url: string; body: string }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), body: String(init?.body ?? "") });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    let result: Awaited<ReturnType<typeof deliver>>;
    try {
      result = await deliver(env, channel, { ...EMISSION, recovered: true });
    } finally {
      globalThis.fetch = realFetch;
    }
    ok("servicenow recovered: delivered ok", result.ok === true);
    const last = captures[captures.length - 1];
    ok("servicenow recovered: SAME em_event url as create (no separate close endpoint)", last?.url === SN_URL);
    const bodyDoc = JSON.parse(last?.body ?? "{}") as ServiceNowEventPayload;
    ok("servicenow recovered: severity is 0 (Clear)", bodyDoc.severity === 0);
    ok("servicenow recovered: SAME message_key as the original create (correlates onto the same Alert)", bodyDoc.message_key === "downpipe:pipe-1:backup-failure");
  }

  console.log("\ndeliver: fail-open on a network fault (non-2xx and unreachable); never throws; classified into the closed DeliveryFailCode vocabulary");
  {
    const channel: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc", apiKey: "pw", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response("service unavailable", { status: 503 })) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("servicenow: a 503 network fault -> ok:false, code:http-5xx (classified, not a throw)", r.ok === false && r.code === "http-5xx");
    } finally {
      globalThis.fetch = realFetch;
    }
    globalThis.fetch = (async () => new Response("unauthorized", { status: 401 })) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      // 401/403 now classify as the distinct http-auth code, so an
      // operator can tell "your Basic credentials are wrong" from a generic 4xx.
      ok("servicenow: a 401 (bad Basic credentials) -> ok:false, code:http-auth", r.ok === false && r.code === "http-auth");
    } finally {
      globalThis.fetch = realFetch;
    }
    globalThis.fetch = (async () => {
      throw new Error("simulated DNS/connection failure");
    }) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("servicenow: an unreachable instance (fetch throws) -> ok:false, a closed network sub-cause (never a throw out of deliver)", r.ok === false && r.code !== undefined && ["network-dns", "network-tls", "network-reset", "network-error"].includes(r.code));
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliver: SSRF default-deny re-screen (defence in depth) blocks an internal-literal sink BEFORE any fetch");
  {
    const channel: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", url: "https://10.0.0.5/api/now/table/em_event", username: "svc", apiKey: "pw", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    let fetchCalled = false;
    globalThis.fetch = (async () => {
      fetchCalled = true;
      return new Response("should never reach here", { status: 200 });
    }) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("servicenow: an RFC1918 target refused, ok:false code:internal-sink-blocked", r.ok === false && r.code === "internal-sink-blocked");
      ok("servicenow: no fetch was attempted (blocked before any network call)", fetchCalled === false);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliver: the defensive missing-field branches, SPLIT by the field that is missing");
  {
    const env = {} as unknown as Env;
    const noUrl: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", username: "svc", apiKey: "pw", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    ok("servicenow: channel with no url -> no-url", (await deliver(env, noUrl, EMISSION)).code === "no-url");
    const noUsername: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", url: SN_URL, apiKey: "pw", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    ok("servicenow: channel with no username -> no-username (NOT no-url: a good endpoint must not be blamed for a blank field beside it)", (await deliver(env, noUsername, EMISSION)).code === "no-username");
    const noKey: NotifyChannel = { id: "c1", kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    ok("servicenow: channel with no apiKey -> no-credential (the third field, and the third distinct fix)", (await deliver(env, noKey, EMISSION)).code === "no-credential");
  }

  console.log("\nsealed-secret round-trip + AAD domain separation (SERVICENOW_SECRET_AAD, invariant: never cross-opens the sibling secret classes, including its nearest sibling JSM_SECRET_AAD)");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const PASSWORD = "servicenow-password-DO-NOT-LEAK-77";
    const wrapped = await wrapConfigSecret(KEY, PASSWORD, SERVICENOW_SECRET_AAD);
    ok("wrap+unwrap round-trips under SERVICENOW_SECRET_AAD", (await unwrapConfigSecret(KEY, wrapped, SERVICENOW_SECRET_AAD)) === PASSWORD);
    await throwsAsync("a servicenow ciphertext does NOT open under the default CONFIG_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped));
    await throwsAsync("a servicenow ciphertext does NOT open under JSM_SECRET_AAD (its nearest sibling)", async () => unwrapConfigSecret(KEY, wrapped, JSM_SECRET_AAD));
    await throwsAsync("a servicenow ciphertext does NOT open under PUSH_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped, PUSH_SECRET_AAD));
    await throwsAsync("a servicenow ciphertext does NOT open under PUSH_S3_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped, PUSH_S3_SECRET_AAD));
    const maybeWrapped = await maybeWrapConfigSecret(KEY, PASSWORD, SERVICENOW_SECRET_AAD);
    ok("maybeWrapConfigSecret(SERVICENOW_SECRET_AAD) with a key produces an envelope", typeof maybeWrapped !== "string");
    ok("resolveConfigSecret(SERVICENOW_SECRET_AAD) resolves it back to plaintext", (await resolveConfigSecret(KEY, maybeWrapped, SERVICENOW_SECRET_AAD)) === PASSWORD);
    ok("no key configured -> maybeWrapConfigSecret floors to plaintext (back-compat)", (await maybeWrapConfigSecret(undefined, PASSWORD, SERVICENOW_SECRET_AAD)) === PASSWORD);
  }

  console.log("\ndeliver: end-to-end secret resolution -- a SEALED apiKey (WrappedSecret password) is unwrapped and rides in the Basic Authorization header");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const PASSWORD = "servicenow-SEALED-password-abc";
    const wrapped = await wrapConfigSecret(KEY, PASSWORD, SERVICENOW_SECRET_AAD);
    const channel: NotifyChannel = { id: "c2", kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc", apiKey: wrapped, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = { CONFIG_WRAP_KEY: b64urlEncode(KEY) } as unknown as Env;
    const realFetch = globalThis.fetch;
    const captures: Array<{ headers: Record<string, string> }> = [];
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ headers: { ...(init?.headers as Record<string, string>) } });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    let result: Awaited<ReturnType<typeof deliver>>;
    try {
      result = await deliver(env, channel, EMISSION);
    } finally {
      globalThis.fetch = realFetch;
    }
    ok("sealed apiKey: delivered ok", result.ok === true);
    ok("sealed apiKey: Authorization carries the UNWRAPPED plaintext password", captures[0]?.headers.Authorization === `Basic ${btoa(`svc:${PASSWORD}`)}`);
  }

  console.log("\ndeliver: a ROTATED/WRONG CONFIG_WRAP_KEY cannot decrypt a sealed apiKey -> fail-open no-transport, never a throw, never a fetch");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const WRONG_KEY = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await wrapConfigSecret(KEY, "servicenow-password-x", SERVICENOW_SECRET_AAD);
    const channel: NotifyChannel = { id: "c3", kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc", apiKey: wrapped, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = { CONFIG_WRAP_KEY: b64urlEncode(WRONG_KEY) } as unknown as Env;
    const realFetch = globalThis.fetch;
    let fetchCalled = false;
    globalThis.fetch = (async () => {
      fetchCalled = true;
      return new Response("should never reach here", { status: 200 });
    }) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("a rotated/wrong wrap key -> ok:false, code:credential-undecryptable (NOT no-transport, so the pack points at the wrap key, never at 're-enter the channel fields'; never throws)", r.ok === false && r.code === "credential-undecryptable");
      ok("a rotated/wrong wrap key -> no fetch was ever attempted", fetchCalled === false);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\nKEEP-SECRET (DO addNotifyChannel): a first servicenow create needs an apiKey; username is ALWAYS resupplied (never KEEP-SECRET); an edit that omits apiKey keeps the prior sealed value");
  {
    const dobj = makeDO();
    await throwsAsync("a FIRST servicenow create with no apiKey is rejected", async () =>
      dobj.addNotifyChannel({ kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc" }, OWNER_CALLER),
    );
    await throwsAsync("a servicenow create with no username is rejected (never KEEP-SECRET; not a secret)", async () =>
      dobj.addNotifyChannel({ kind: "servicenow", name: "SNOW", url: SN_URL, apiKey: "pw1" }, OWNER_CALLER),
    );
    const created = await dobj.addNotifyChannel({ kind: "servicenow", name: "SNOW", url: SN_URL, username: "svc_downpipes", apiKey: "pw-1" }, OWNER_CALLER);
    ok("servicenow create stored username + apiKey", created.username === "svc_downpipes" && created.apiKey === "pw-1");
    const updated = await dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW (renamed)", url: SN_URL, username: "svc_downpipes" }, OWNER_CALLER);
    ok("KEEP-SECRET: an edit omitting apiKey preserves the prior stored password", updated.apiKey === "pw-1");
    ok("KEEP-SECRET: the non-secret field WAS updated (name)", updated.name === "SNOW (renamed)");
    ok("KEEP-SECRET: the edit does not create a duplicate channel", updated.id === created.id);
    const keptEmpty = await dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW (renamed)", url: SN_URL, username: "svc_downpipes", apiKey: "" }, OWNER_CALLER);
    ok("KEEP-SECRET: an explicit empty-string apiKey also keeps the prior password", keptEmpty.apiKey === "pw-1");
    const rotated = await dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW (renamed)", url: SN_URL, username: "svc_downpipes", apiKey: "pw-2" }, OWNER_CALLER);
    ok("a set WITH a new apiKey rotates it (rotation is re-enter)", rotated.apiKey === "pw-2");
    // username can be legitimately CHANGED (it is not KEEP-SECRET; it is always resupplied and applied).
    const renamedUser = await dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW (renamed)", url: SN_URL, username: "svc_renamed" }, OWNER_CALLER);
    ok("username is applied on every submit (not sticky like apiKey)", renamedUser.username === "svc_renamed");
    // allowInternalSink persists (the adjacent bugfix this build made while touching addNotifyChannel).
    // A url change now requires re-supplying the apiKey (keep-secret is tied to the destination), so this
    // repoint carries a fresh password.
    const withOverride = await dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW", url: "https://10.1.2.3/api/now/table/em_event", username: "svc_renamed", apiKey: "pw-3", allowInternalSink: true }, OWNER_CALLER);
    ok("allowInternalSink actually PERSISTS on the stored channel (bugfix verified for servicenow too)", withOverride.allowInternalSink === true);
    // SECURITY (exfil block): repointing the url with apiKey OMITTED is REJECTED -- the sealed password is
    // NOT carried across an endpoint change, so a notify.config holder cannot swap the url to a host they
    // control and keep the real credential for a test-send to exfiltrate.
    await throwsAsync("a url repoint that omits apiKey is rejected (keep-secret tied to the destination)", async () =>
      dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW", url: "https://attacker.example/em_event", username: "svc_renamed" }, OWNER_CALLER),
    );
    const sameUrlEdit = await dobj.addNotifyChannel({ id: created.id, kind: "servicenow", name: "SNOW (again)", url: "https://10.1.2.3/api/now/table/em_event", username: "svc_x", allowInternalSink: true }, OWNER_CALLER);
    ok("KEEP-SECRET holds across a same-url edit incl. a username change (destination unchanged)", sameUrlEdit.apiKey === "pw-3");
  }

  console.log(failures === 0 ? "\nSERVICENOW CHANNEL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
