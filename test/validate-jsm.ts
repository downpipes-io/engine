// Validates the Jira Service Management / Opsgenie notify channel (src/notify/channels/jsm.ts): the pure
// format()/formatClose()/jsmPriority()/jsmAlias() shapers, the fetch-recording delivery vectors (exact
// URL/verb/auth-header/body for the CREATE vs CLOSE-by-alias shapes, mirroring the captures[] pattern in
// test/validate-siem-push.ts), the sealed-secret round-trip + cross-AAD negative (JSM_SECRET_AAD), the
// KEEP-SECRET update semantics at the DO (addNotifyChannel), fail-open on a non-2xx/unreachable sink, the
// SSRF default-deny re-screen, and the no-custody envelope (the token never rides in the body or url). No
// network. Run:
//   node test/validate-jsm.ts

import { format, formatClose, jsmPriority, jsmAlias, deliver, type JsmCreatePayload, type JsmClosePayload } from "../src/notify/channels/jsm.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify/types.ts";
import { wrapConfigSecret, unwrapConfigSecret, resolveConfigSecret, maybeWrapConfigSecret, isWrappedSecret, JSM_SECRET_AAD, SERVICENOW_SECRET_AAD, PUSH_SECRET_AAD, PUSH_S3_SECRET_AAD } from "../src/admin/config-secret.ts";
import { wrapNotifyChannelSecret } from "../src/admin/router-ops.ts";
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

async function main(): Promise<void> {
  console.log("format()/formatClose(): pure shape correctness");
  {
    const p = format(EMISSION);
    ok("format: message is the redaction-safe detail", p.message === "Prod KV last run failed");
    ok("format: alias mirrors pagerdutyDedupKey's shape (downpipe:<id>:<event>)", p.alias === "downpipe:pipe-1:backup-failure");
    ok("format: description carries the full detail", p.description === "Prod KV last run failed");
    ok("format: priority maps critical -> P1", p.priority === "P1");
    ok("format: source is the downpipe name", p.source === "Prod KV");
    const allowed = new Set(["message", "alias", "description", "priority", "source"]);
    ok("format: no extra keys (no-custody surface)", Object.keys(p).every((k) => allowed.has(k)));

    const acct = format(ACCOUNT_EMISSION);
    ok("format: account-level event (downpipeId null) -> account:<event> alias", acct.alias === "account:backup-failure");
    ok("format: account-level event -> source falls back to 'downpipe'", acct.source === "downpipe");

    const c = formatClose(EMISSION);
    ok("formatClose: carries only the redaction-safe source", Object.keys(c).length === 1 && c.source === "Prod KV");

    // message truncation at the Alert API's 130-char cap; description stays untruncated.
    const longDetail = "x".repeat(200);
    const pLong = format({ ...EMISSION, detail: longDetail });
    ok("format: message truncated to 130 chars", pLong.message.length === 130);
    ok("format: description is NOT truncated", pLong.description.length === 200);

    // Item 10: the source field is capped at 100 chars on both format and
    // formatClose(), so an unusually long downpipe name cannot land oversized on a short-label field.
    const longName = "N".repeat(150);
    const pLongSource = format({ ...EMISSION, downpipeName: longName });
    ok("format (item 10): source is capped at 100 chars", pLongSource.source.length === 100 && pLongSource.source === longName.slice(0, 100));
    const cLongSource = formatClose({ ...EMISSION, downpipeName: longName });
    ok("formatClose (item 10): source is ALSO capped at 100 chars", cLongSource.source.length === 100);
    const pShortSource = format({ ...EMISSION, downpipeName: "short" });
    ok("format (item 10): a short name is untouched (no padding, no needless truncation)", pShortSource.source === "short");
  }

  console.log("\njsmPriority: severity -> P1..P5");
  {
    ok("jsmPriority: critical -> P1", jsmPriority("critical") === "P1");
    ok("jsmPriority: warning -> P3", jsmPriority("warning") === "P3");
    ok("jsmPriority: info -> P5", jsmPriority("info") === "P5");
  }

  console.log("\njsmAlias: stable dedup key, downpipe-scoped or account-scoped");
  {
    ok("jsmAlias: downpipe-scoped", jsmAlias(EMISSION) === "downpipe:pipe-1:backup-failure");
    ok("jsmAlias: stable across repeated calls (same emission -> same alias)", jsmAlias(EMISSION) === jsmAlias({ ...EMISSION, detail: "a different detail line" }));
    ok("jsmAlias: account-scoped when downpipeId is null", jsmAlias(ACCOUNT_EMISSION) === "account:backup-failure");
    ok("jsmAlias: distinct events on the same downpipe get distinct aliases", jsmAlias(EMISSION) !== jsmAlias({ ...EMISSION, event: "backup-stale" }));
  }

  console.log("\ndeliver: CREATE POSTs to the channel's OWN url with GenieKey auth; body is the create shape; no-custody (token never in body/url)");
  {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-secret-TOKEN-abc", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env; // no CONFIG_WRAP_KEY configured -> the plaintext back-compat floor
    const realFetch = globalThis.fetch;
    const captures: Array<{ url: string; method?: string; headers: Record<string, string>; body: string }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), ...(init?.method !== undefined ? { method: init.method } : {}), headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
      return new Response("ok", { status: 202 });
    }) as typeof fetch;
    let result: Awaited<ReturnType<typeof deliver>>;
    try {
      result = await deliver(env, channel, EMISSION);
    } finally {
      globalThis.fetch = realFetch;
    }
    ok("jsm create: delivered ok on a 2xx", result.ok === true);
    const last = captures[captures.length - 1];
    ok("jsm create: exactly one POST, to the channel's own url (no fixed provider constant)", captures.length === 1 && last?.url === "https://api.opsgenie.com/v2/alerts" && last?.method === "POST");
    ok("jsm create: Authorization is 'GenieKey <token>'", last?.headers.Authorization === "GenieKey genie-secret-TOKEN-abc");
    ok("jsm create: content-type is application/json", last?.headers["content-type"] === "application/json");
    const bodyDoc = JSON.parse(last?.body ?? "{}") as JsmCreatePayload;
    ok("jsm create: body matches format() (alias/message/priority/source)", bodyDoc.alias === "downpipe:pipe-1:backup-failure" && bodyDoc.message === "Prod KV last run failed" && bodyDoc.priority === "P1" && bodyDoc.source === "Prod KV");
    ok("jsm create: the body NEVER contains the token (no-custody)", !(last?.body ?? "").includes("genie-secret-TOKEN-abc"));
    ok("jsm create: the url NEVER contains the token (no-custody)", !(last?.url ?? "").includes("genie-secret-TOKEN-abc"));
    // Item 10: this create answers 202 with a non-JSON body (no requestId to poll), so the bare 202 is
    // honestly reported as accepted-but-unconfirmed, never silently folded into a plain "delivered".
    ok("jsm create (item 10): a 202 with no parseable requestId is reported unconfirmed:true", result.unconfirmed === true);
  }

  console.log("\ndeliver: a RECOVERED emission CLOSEs the SAME alias at the documented close-by-alias path, same auth, no-custody");
  {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-secret-TOKEN-xyz", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    const captures: Array<{ url: string; method?: string; headers: Record<string, string>; body: string }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ url: String(input), ...(init?.method !== undefined ? { method: init.method } : {}), headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    let result: Awaited<ReturnType<typeof deliver>>;
    try {
      result = await deliver(env, channel, { ...EMISSION, recovered: true });
    } finally {
      globalThis.fetch = realFetch;
    }
    ok("jsm close: delivered ok on a 2xx", result.ok === true);
    // Item 10: a plain 200 (not 202) is a SYNCHRONOUS confirmation, so no unconfirmed caveat applies.
    ok("jsm close (item 10): a plain 200 carries no unconfirmed flag", result.unconfirmed === undefined);
    const last = captures[captures.length - 1];
    const expectedUrl = `https://api.opsgenie.com/v2/alerts/${encodeURIComponent(jsmAlias(EMISSION))}/close?identifierType=alias`;
    ok("jsm close: POSTs to the documented close-by-alias path (SAME alias as create)", captures.length === 1 && last?.url === expectedUrl && last?.method === "POST");
    ok("jsm close: SAME Authorization scheme as create", last?.headers.Authorization === "GenieKey genie-secret-TOKEN-xyz");
    const bodyDoc = JSON.parse(last?.body ?? "{}") as JsmClosePayload;
    ok("jsm close: body is the minimal close shape (source only)", Object.keys(bodyDoc).length === 1 && bodyDoc.source === "Prod KV");
    ok("jsm close: the body NEVER contains the token (no-custody)", !(last?.body ?? "").includes("genie-secret-TOKEN-xyz"));
    // A trailing slash on the stored url must not double up in the derived close path.
    const trailingChannel: NotifyChannel = { ...channel, url: "https://api.opsgenie.com/v2/alerts/" };
    captures.length = 0;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      captures.push({ url: String(input), headers: {}, body: "" });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    try {
      await deliver(env, trailingChannel, { ...EMISSION, recovered: true });
    } finally {
      globalThis.fetch = realFetch;
    }
    ok("jsm close: a trailing slash on the stored url does not double up in the close path", captures[0]?.url === expectedUrl);
  }

  console.log("\ndeliver: fail-open on a non-2xx and on an unreachable sink (never throws; classified into the closed DeliveryFailCode vocabulary)");
  {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "k", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response("nope", { status: 503 })) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("jsm: a 503 -> ok:false, code:http-5xx (classified, not a throw)", r.ok === false && r.code === "http-5xx");
    } finally {
      globalThis.fetch = realFetch;
    }
    globalThis.fetch = (async () => {
      throw new Error("simulated DNS/connection failure");
    }) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("jsm: an unreachable sink (fetch throws) -> ok:false, code:network-dns (the closed sub-cause; never a throw out of deliver)", r.ok === false && r.code === "network-dns");
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliver: item 10 (202 async-accepted) -- requestId capture + the single Get Request Status poll");
  {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-secret-poll", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;

    // 10a: a 202 whose body carries a requestId, and the poll POSITIVELY confirms success -- a fully
    // confirmed delivery (ok:true, no unconfirmed caveat). Exactly TWO requests: the create, then ONE poll.
    {
      const calls: Array<{ url: string; method?: string; headers: Record<string, string> }> = [];
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = String(input);
        calls.push({ url, ...(init?.method !== undefined ? { method: init.method } : {}), headers: { ...(init?.headers as Record<string, string>) } });
        if (calls.length === 1) return new Response(JSON.stringify({ result: "Request will be processed", took: 0.001, requestId: "req-abc-123" }), { status: 202 });
        return new Response(JSON.stringify({ data: { success: true, isSuccess: true, status: "Created alert", alertId: "alert-1" }, took: 0.02, requestId: "req-abc-123" }), { status: 200 });
      }) as typeof fetch;
      try {
        const r = await deliver(env, channel, EMISSION);
        ok("item 10: a poll-confirmed 202 is ok:true with NO unconfirmed caveat", r.ok === true && r.unconfirmed === undefined);
        ok("item 10: exactly 2 requests (the create, then ONE poll)", calls.length === 2);
        ok("item 10: the poll GETs the documented Get Request Status endpoint (same base, /requests/{id})", calls[1]?.url === "https://api.opsgenie.com/v2/alerts/requests/req-abc-123" && calls[1]?.method === "GET");
        ok("item 10: the poll carries the SAME GenieKey auth header", calls[1]?.headers.Authorization === "GenieKey genie-secret-poll");
      } finally {
        globalThis.fetch = realFetch;
      }
    }

    // 10b: a 202 with a requestId, but the poll POSITIVELY confirms FAILURE (data.success:false) -- still
    // ok:true (JSM's create is idempotent-by-alias; a hard failure here would retry-storm a healthy
    // integration every tick), but honestly flagged unconfirmed:true, never a silent plain "delivered".
    {
      let call = 0;
      globalThis.fetch = (async (): Promise<Response> => {
        call++;
        if (call === 1) return new Response(JSON.stringify({ requestId: "req-fail-1" }), { status: 202 });
        return new Response(JSON.stringify({ data: { success: false, status: "Alert does not exist" }, requestId: "req-fail-1" }), { status: 200 });
      }) as typeof fetch;
      try {
        const r = await deliver(env, channel, EMISSION);
        ok("item 10: a poll that confirms FAILURE is still ok:true (idempotent retry-safe) but unconfirmed:true, and ackOutcome names it async-create-failed", r.ok === true && r.unconfirmed === true && r.ackOutcome === "async-create-failed");
      } finally {
        globalThis.fetch = realFetch;
      }
    }

    // 10c: a 202 with a requestId, but the poll itself fails (503) -- cannot confirm, so unconfirmed:true;
    // never a throw, never ok:false (the create itself DID succeed).
    {
      let call = 0;
      globalThis.fetch = (async (): Promise<Response> => {
        call++;
        if (call === 1) return new Response(JSON.stringify({ requestId: "req-pollfail" }), { status: 202 });
        return new Response("service unavailable", { status: 503 });
      }) as typeof fetch;
      try {
        const r = await deliver(env, channel, EMISSION);
        ok("item 10: a failing poll degrades to unconfirmed:true (never ok:false, never a throw), ackOutcome confirmation-unavailable", r.ok === true && r.unconfirmed === true && r.ackOutcome === "confirmation-unavailable");
      } finally {
        globalThis.fetch = realFetch;
      }
    }

    // 10d: a 202 whose body carries NO requestId at all -- no poll is even attempted (nothing to poll),
    // so it stays unconfirmed:true by default. Exactly ONE request (the create only).
    {
      const calls: string[] = [];
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        calls.push(String(input));
        return new Response(JSON.stringify({ result: "queued" }), { status: 202 });
      }) as typeof fetch;
      try {
        const r = await deliver(env, channel, EMISSION);
        ok("item 10: a 202 with no requestId is unconfirmed:true and polls nothing (1 request only)", r.ok === true && r.unconfirmed === true && calls.length === 1);
      } finally {
        globalThis.fetch = realFetch;
      }
    }
  }

  console.log("\ndeliver: SSRF default-deny re-screen (defence in depth) blocks an internal-literal sink BEFORE any fetch");
  {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://169.254.169.254/v2/alerts", apiKey: "k", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    const realFetch = globalThis.fetch;
    let fetchCalled = false;
    globalThis.fetch = (async () => {
      fetchCalled = true;
      return new Response("should never reach here", { status: 200 });
    }) as typeof fetch;
    try {
      const r = await deliver(env, channel, EMISSION);
      ok("jsm: cloud-metadata target refused, ok:false code:internal-sink-blocked", r.ok === false && r.code === "internal-sink-blocked");
      ok("jsm: no fetch was attempted (blocked before any network call)", fetchCalled === false);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliver: the defensive missing-field branches, SPLIT by the field that is missing");
  {
    // The two guards used to emit ONE code, no-transport, so "my ServiceNow/JSM channel never delivers" could
    // not say whether the url, the username, the credential or the recipient list was the missing field -- and
    // a missing field is the single commonest cause of a channel that silently never fires. The codes are now
    // disjoint (no-url / no-credential), which is the same discipline the sibling credential-undecryptable
    // assertion below already pins: the pack must point at the field to fix, never at "re-enter everything".
    const env = {} as unknown as Env;
    const noUrl: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", apiKey: "k", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    ok("jsm: channel with no url -> no-url (not the old collapsed no-transport)", (await deliver(env, noUrl, EMISSION)).code === "no-url");
    const noKey: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    ok("jsm: channel with no apiKey -> no-credential (a DIFFERENT field from the url, and a different fix)", (await deliver(env, noKey, EMISSION)).code === "no-credential");
    // The invariant the old assertions really protected, kept explicit: a defensive guard NEVER throws and
    // never delivers -- it returns a closed, non-delivering code.
    ok("jsm: a missing field never throws and never reports a delivery", (await deliver(env, noUrl, EMISSION)).ok === false && (await deliver(env, noKey, EMISSION)).ok === false);
  }

  console.log("\nsealed-secret round-trip + AAD domain separation (JSM_SECRET_AAD, invariant: never cross-opens the sibling secret classes)");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const TOKEN = "genie-key-DO-NOT-LEAK-42";
    const wrapped = await wrapConfigSecret(KEY, TOKEN, JSM_SECRET_AAD);
    ok("wrap+unwrap round-trips under JSM_SECRET_AAD", (await unwrapConfigSecret(KEY, wrapped, JSM_SECRET_AAD)) === TOKEN);
    await throwsAsync("a jsm ciphertext does NOT open under the default CONFIG_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped));
    await throwsAsync("a jsm ciphertext does NOT open under SERVICENOW_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped, SERVICENOW_SECRET_AAD));
    await throwsAsync("a jsm ciphertext does NOT open under PUSH_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped, PUSH_SECRET_AAD));
    await throwsAsync("a jsm ciphertext does NOT open under PUSH_S3_SECRET_AAD", async () => unwrapConfigSecret(KEY, wrapped, PUSH_S3_SECRET_AAD));
    const maybeWrapped = await maybeWrapConfigSecret(KEY, TOKEN, JSM_SECRET_AAD);
    ok("maybeWrapConfigSecret(JSM_SECRET_AAD) with a key produces an envelope", typeof maybeWrapped !== "string");
    ok("resolveConfigSecret(JSM_SECRET_AAD) resolves it back to plaintext", (await resolveConfigSecret(KEY, maybeWrapped, JSM_SECRET_AAD)) === TOKEN);
    ok("no key configured -> maybeWrapConfigSecret floors to plaintext (back-compat)", (await maybeWrapConfigSecret(undefined, TOKEN, JSM_SECRET_AAD)) === TOKEN);
  }

  console.log("\ndeliver: end-to-end secret resolution -- a SEALED apiKey (WrappedSecret) is unwrapped and rides in the Authorization header");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const TOKEN = "genie-key-SEALED-abc123";
    const wrapped = await wrapConfigSecret(KEY, TOKEN, JSM_SECRET_AAD);
    const channel: NotifyChannel = { id: "c2", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: wrapped, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
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
    ok("sealed apiKey: Authorization carries the UNWRAPPED plaintext token", captures[0]?.headers.Authorization === `GenieKey ${TOKEN}`);
  }

  console.log("\ndeliver: a ROTATED/WRONG CONFIG_WRAP_KEY cannot decrypt a sealed apiKey -> fail-open no-transport, never a throw, never a fetch");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const WRONG_KEY = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await wrapConfigSecret(KEY, "genie-key-x", JSM_SECRET_AAD);
    const channel: NotifyChannel = { id: "c3", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: wrapped, enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
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

  console.log("\nKEEP-SECRET (DO addNotifyChannel): a first jsm create needs an apiKey; an edit that omits it keeps the prior sealed value; a set WITH a new one rotates it");
  {
    const dobj = makeDO();
    await throwsAsync("a FIRST jsm create with no apiKey is rejected", async () =>
      dobj.addNotifyChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts" }, OWNER_CALLER),
    );
    const created = await dobj.addNotifyChannel({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-key-1" }, OWNER_CALLER);
    ok("jsm create stored the apiKey", created.apiKey === "genie-key-1");
    const updated = await dobj.addNotifyChannel({ id: created.id, kind: "jsm", name: "Ops (renamed)", url: "https://api.opsgenie.com/v2/alerts" }, OWNER_CALLER);
    ok("KEEP-SECRET: an edit omitting apiKey preserves the prior stored value", updated.apiKey === "genie-key-1");
    ok("KEEP-SECRET: the non-secret field WAS updated (name)", updated.name === "Ops (renamed)");
    ok("KEEP-SECRET: the edit does not create a duplicate channel", updated.id === created.id);
    const keptEmpty = await dobj.addNotifyChannel({ id: created.id, kind: "jsm", name: "Ops (renamed)", url: "https://api.opsgenie.com/v2/alerts", apiKey: "" }, OWNER_CALLER);
    ok("KEEP-SECRET: an explicit empty-string apiKey also keeps the prior value", keptEmpty.apiKey === "genie-key-1");
    const rotated = await dobj.addNotifyChannel({ id: created.id, kind: "jsm", name: "Ops (renamed)", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-key-2" }, OWNER_CALLER);
    ok("a set WITH a new apiKey rotates it (rotation is re-enter)", rotated.apiKey === "genie-key-2");
    // allowInternalSink persists (the adjacent bugfix this build made while touching addNotifyChannel).
    // A url change now requires re-supplying the apiKey (keep-secret is tied to the endpoint identity), so
    // this repoint carries a fresh one.
    const withOverride = await dobj.addNotifyChannel({ id: created.id, kind: "jsm", name: "Ops", url: "https://10.1.2.3/v2/alerts", apiKey: "genie-key-3", allowInternalSink: true }, OWNER_CALLER);
    ok("allowInternalSink actually PERSISTS on the stored channel (bugfix verified for jsm too)", withOverride.allowInternalSink === true);
    // SECURITY (exfil block): repointing the url with apiKey OMITTED is REJECTED -- the sealed token is NOT
    // carried across an endpoint change, so a notify.config holder cannot swap the url to a host they
    // control and keep the real credential for a test-send to exfiltrate.
    await throwsAsync("a url repoint that omits apiKey is rejected (keep-secret tied to the channel identity)", async () =>
      dobj.addNotifyChannel({ id: created.id, kind: "jsm", name: "Ops", url: "https://attacker.example/collect" }, OWNER_CALLER),
    );
    const sameUrlEdit = await dobj.addNotifyChannel({ id: created.id, kind: "jsm", name: "Ops (again)", url: "https://10.1.2.3/v2/alerts", allowInternalSink: true }, OWNER_CALLER);
    ok("KEEP-SECRET still holds for a same-endpoint edit (name-only change keeps the token)", sameUrlEdit.apiKey === "genie-key-3");
  }

  console.log("\nrouter seam: a whitespace-only apiKey is STRIPPED at wrapNotifyChannelSecret, never forwarded as an unwrapped value");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    // A real apiKey IS wrapped under JSM_SECRET_AAD (an envelope, not the plaintext) before it reaches the DO.
    const wrappedBody = await wrapNotifyChannelSecret({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "genie-real-token" }, KEY);
    const apiKeyField = wrappedBody.apiKey;
    ok("a real apiKey is wrapped to a sealed envelope (never forwarded as plaintext)", isWrappedSecret(apiKeyField) && !JSON.stringify(wrappedBody).includes("genie-real-token"));
    if (isWrappedSecret(apiKeyField)) {
      ok("the wrapped envelope opens back under JSM_SECRET_AAD", (await resolveConfigSecret(KEY, apiKeyField, JSM_SECRET_AAD)) === "genie-real-token");
    }
    // A whitespace-only apiKey is STRIPPED (no apiKey field survives), so no unwrapped whitespace can travel
    // to the DO -- even with a wrap key configured. This agrees with parseChannelSecret's trimmed-empty rule.
    const wsBody = await wrapNotifyChannelSecret({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "   " }, KEY);
    ok("a whitespace-only apiKey is STRIPPED from the forwarded body (KEEP-SECRET, no value travels)", !("apiKey" in wsBody));
    ok("the whitespace value is nowhere in the forwarded body", !JSON.stringify(wsBody).includes("   "));
    // An empty-string apiKey is stripped too (identical to whitespace/omitted).
    const emptyBody = await wrapNotifyChannelSecret({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "" }, KEY);
    ok("an empty-string apiKey is stripped too", !("apiKey" in emptyBody));
    // A non-jsm/servicenow kind is untouched (nothing to wrap).
    const webhookBody = await wrapNotifyChannelSecret({ kind: "webhook", name: "w", url: "https://siem.example.com/h" }, KEY);
    ok("a non-incident kind is returned unchanged", webhookBody.kind === "webhook" && webhookBody.url === "https://siem.example.com/h");
    // End-to-end: a whitespace apiKey through the DO on a FIRST create is rejected (no secret to keep), so a
    // whitespace value can never be stored, wrapped or unwrapped.
    const dobj = makeDO();
    const forwarded = await wrapNotifyChannelSecret({ kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "   " }, undefined);
    await throwsAsync("a whitespace-only apiKey on a FIRST create is rejected at the DO (never stored)", async () => dobj.addNotifyChannel(forwarded, OWNER_CALLER));
  }

  console.log(failures === 0 ? "\nJSM CHANNEL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
