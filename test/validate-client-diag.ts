// Prove the console-diagnostics support-pack section (Wave C) end to end at the ENGINE boundary:
//
//   1. The frozen vocabulary (client-diag-vocab.ts) is the single source; the receiver re-validates every
//      record by SET MEMBERSHIP and DROPS any non-member value / extra key / smuggled free-string.
//   2. A well-formed ring rides and is STRUCTURALLY VALUE-FREE (I2): every string field is a frozen union
//      member; a customer sentinel placed in every field / key never appears in the output.
//   3. Caps are enforced (D3): per-kind newest-wins 32, global 128, and a per-kind uncapped true-count rollup.
//   4. Numerics are clamped (count cap 1e6; firstMs/lastMs clamped; engineAttempts clamped); receivedAt is
//      engine-stamped, second-precision; provenance is source:'client-asserted' (I4).
//   5. The section rides ONLY inside a bundle produced with a console POST body (I1): buildSupportBundle folds
//      it in when supplied and STRUCTURALLY omits it when not; it is NOT a SUPPORT_SECTION_NAMES roster member.
//   6. Through the real router: POST /admin/support/bundle accepts the ring; GET has NO section; an oversized
//      body 400s; a malformed body 400s; and the vendor bearer-pull (GET /support/diagnostics) has NO section.
//
// No network, no deploy: an in-memory scheduler double answers the bundle fan-out.
// Run: node test/validate-client-diag.ts

import { handleAdmin } from "../src/admin/router.ts";
import { handleSupportPull, mintIngestCredential, type IngestGrant } from "../src/admin/support-ingest.ts";
import { signedSupportBundle, buildSupportBundle, SUPPORT_SECTION_NAMES } from "../src/admin/support.ts";
import { projectRecord, projectClientDiagnostics } from "../src/admin/client-diag-receive.ts";
import {
  CLIENT_DIAG_KINDS,
  CLIENT_DIAG_SCREENS,
  CLIENT_DIAG_HTTP_CLASSES,
  CLIENT_DIAG_FAULT_CLASSES,
  CLIENT_DIAG_DRIFT_CLASSES,
  CLIENT_DIAG_REASON_CLASSES,
  CLIENT_DIAG_APPLY_CLASSES,
  CLIENT_DIAG_CAPABILITIES,
  CLIENT_DIAG_SURFACES,
  CLIENT_DIAG_CAPABILITY_OUTCOMES,
  CLIENT_DIAG_BOOT_CLASSES,
  CLIENT_DIAG_BUILD_CHECK_CLASSES,
  CLIENT_DIAG_ROLLBACK_CLASSES,
  CLIENT_DIAG_GATE_BLOCK_CLASSES,
  CLIENT_DIAG_FIELD_CLASSES,
  CLIENT_DIAG_ANOMALIES,
  CLIENT_DIAG_ERROR_CLASSES,
  CLIENT_DIAG_FAULT_SOURCES,
  CLIENT_DIAG_PER_KIND_ROW_CAP,
  CLIENT_DIAG_GLOBAL_ROW_CAP,
  CLIENT_DIAG_COUNT_MAX,
  CLIENT_DIAG_MAX_BODY_BYTES,
  type ClientDiagnosticsSection,
} from "../src/admin/client-diag-vocab.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { loadSigner } from "../src/keys-env.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A minimal scheduler double for the bundle fan-out: /downpipes MUST be an array (buildSupportBundle maps
// over it outside a section() guard); every other DO path answers benign-empty so each section() / best-
// effort gatherer degrades to honest absence. A settable grant store serves the vendor bearer-pull path.
function schedulerDouble(): { stub: DurableObjectStub; grants: Record<string, IngestGrant | null>; pulls: string[] } {
  const grants: Record<string, IngestGrant | null> = { diagnostics: null, "audit-feed": null, metrics: null };
  const pulls: string[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      switch (url.pathname) {
        case "/downpipes":
          return new Response(JSON.stringify([]));
        case "/policy/break-glass-retired":
          // The token break-glass auth path fails CLOSED unless the DO positively says the token is NOT
          // retired, so the double must answer explicitly for handleAdmin to admit the ADMIN_TOKEN caller.
          return new Response(JSON.stringify({ breakGlassTokenRetired: false }));
        case "/ingest-credential": {
          const scope = url.searchParams.get("scope") ?? "";
          return new Response(JSON.stringify({ grant: grants[scope] ?? null }));
        }
        case "/ingest-credential/record-pull":
          pulls.push(String(body?.["scope"]));
          return new Response(JSON.stringify({ ok: true }));
        default:
          // Every other gatherer reads defensively; {} degrades to "empty"/best-effort absence.
          return new Response(JSON.stringify({}));
      }
    },
  } as unknown as DurableObjectStub;
  return { stub, grants, pulls };
}

const TOKEN = "client-diag-test-admin-token";

// Drive the REAL handleAdmin with the ADMIN_TOKEN break-glass (resolves to owner, so posture.read passes and
// we exercise the route body, not the gate). The token method is not cookie-borne, so no Origin is required.
function makeRouterEnv(signerB64: string): { env: Env; sched: ReturnType<typeof schedulerDouble> } {
  const sched = schedulerDouble();
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => sched.stub,
  } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN, SIGNER_PRIVATE: signerB64 } as unknown as Env;
  return { env, sched };
}

async function routerCall(env: Env, method: "GET" | "POST", path: string, rawBody?: string): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      ...(rawBody !== undefined ? { "content-type": "application/json", "content-length": String(new TextEncoder().encode(rawBody).length) } : {}),
    },
    ...(rawBody !== undefined ? { body: rawBody } : {}),
  };
  return handleAdmin(new Request(`https://engine.example${path}`, init), env);
}

// A well-formed record covering every optional class field (all frozen members).
function goodRecord(): Record<string, unknown> {
  return { kind: "engine-call", screen: "downpipes", httpClass: "5xx", faultClass: "server", count: 3, firstMs: 100, lastMs: 900 };
}

async function main(): Promise<void> {
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  await loadSigner(signerB64); // sanity: the signer parses, so signedSupportBundle can sign below

  console.log("frozen vocabulary is complete + correctly sized:");
  // The AVAILABILITY R2 rebuild plus the POSTURE rounds. Sized here for one reason: this engine DROPS a member
  // it does not admit, silently, so a console that emits a kind the engine has never heard of loses the evidence
  // on arrival and the pack simply does not carry it.
  //
  // kind 41 = the availability R2 pair (identity-stale-gate, update-channel-unverified) plus the eighteen posture
  // kinds. Every posture kind is a BROWSER-SIDE fact this engine cannot hold by construction: a validator that
  // turned an operator away without making a request, a probe whose result was rendered once and stored nowhere,
  // a dual-control refusal the console decided, a resource the browser's own CSP blocked, a store the browser
  // refused to keep anything in, and which renderer the topology map actually got.
  //
  // kind 41 -> 42 = focus-landing: WHERE KEYBOARD FOCUS LANDED after a tab activation that is itself a
  // navigation. It is the first member of this vocabulary that can see the accessibility surface at all,
  // and the drop rule above is exactly why it had to be added HERE and not on the console alone: without
  // it, a keyboard user trapped on the first tab produced a pack byte-identical to a healthy one.
  //
  // screen 18 = the R2 pair (config-changes, owner-actions, prised out of the `security` bucket both approval
  // inboxes fell into, where a frozen-on-skeletons TypeError made them one coalesced row).
  ok("kind(42) screen(18) httpClass(5) faultClass(7) driftClass(4) reasonClass(6) applyClass(6)", CLIENT_DIAG_KINDS.length === 42 && CLIENT_DIAG_SCREENS.length === 18 && CLIENT_DIAG_HTTP_CLASSES.length === 5 && CLIENT_DIAG_FAULT_CLASSES.length === 7 && CLIENT_DIAG_DRIFT_CLASSES.length === 4 && CLIENT_DIAG_REASON_CLASSES.length === 6 && CLIENT_DIAG_APPLY_CLASSES.length === 6);
  // surface gains map-diagnostics: the map's Copy-view-diagnostics block is the console's own remote-
  // support affordance, and a clipboard the browser refuses is exactly how it never reaches support.
  // surface 6 -> 7: add-operational-key (the targeted break-glass-only -> operational upgrade card's own
  // keygen-fault reporting, distinct from the full ceremony's key-ceremony tag).
  ok("capability(4) surface(8) capabilityOutcome(2)", CLIENT_DIAG_CAPABILITIES.length === 4 && CLIENT_DIAG_SURFACES.length === 8 && CLIENT_DIAG_CAPABILITY_OUTCOMES.length === 2);
  // buildCheckClass 5 -> 6: `running-unstamped` (THE RUNNING BUNDLE carries no version stamp) split from
  // `unstamped` (THE ORIGIN served assets with none). Two facts about two different artefacts, which used to be
  // one member and therefore one row.
  ok("bootClass(2) buildCheckClass(6) rollbackClass(7) gateBlockClass(4)", CLIENT_DIAG_BOOT_CLASSES.length === 2 && CLIENT_DIAG_BUILD_CHECK_CLASSES.length === 6 && CLIENT_DIAG_ROLLBACK_CLASSES.length === 7 && CLIENT_DIAG_GATE_BLOCK_CLASSES.length === 4);
  // fieldClass 6 -> 20 and anomaly 4 -> 6: the wire values the console COARSENS rather
  // than crashes on, each of which rendered a plausible verdict from something it could not read. The loudest
  // was an unrecognised whoami method presented as the break-glass TOKEN FALLBACK posture, a false claim that
  // the customer's security posture is degraded; the most dangerous was an unparseable last-good-run instant,
  // which SKIPPED the staleness test entirely so a pipe that had not run in a month read FRESH. As one generic
  // `timestamp` member they coalesce and support cannot say WHICH assurance the customer lost.
  ok("fieldClass(21) anomaly(6) errorClass(10) faultSource(2)", CLIENT_DIAG_FIELD_CLASSES.length === 21 && CLIENT_DIAG_ANOMALIES.length === 6 && CLIENT_DIAG_ERROR_CLASSES.length === 10 && CLIENT_DIAG_FAULT_SOURCES.length === 2);

  console.log("\nthe availability-gap discriminators SURVIVE the receiver (a dropped field is a row that will not say what happened):");
  {
    const buildCheck = projectRecord({ kind: "console-build-check", screen: "updates", buildCheckClass: "wrong-version", count: 1, firstMs: 0, lastMs: 0 });
    ok("a console-build-check row is admitted WITH its class", buildCheck !== null && buildCheck.buildCheckClass === "wrong-version");
    const rollback = projectRecord({ kind: "console-rollback", screen: "updates", rollbackClass: "not-sent", count: 1, firstMs: 0, lastMs: 0 });
    ok("a console-rollback row is admitted WITH its class", rollback !== null && rollback.rollbackClass === "not-sent");
    const identity = projectRecord({ kind: "identity-unresolved", screen: "security", httpClass: "5xx", count: 1, firstMs: 0, lastMs: 0 });
    ok("an identity-unresolved row is admitted WITH its httpClass", identity !== null && identity.httpClass === "5xx");
    const gate = projectRecord({ kind: "restore-gate-blocked", screen: "restore", gateBlockClass: "plan-hash-mismatch", count: 1, firstMs: 0, lastMs: 0 });
    ok("a restore-gate-blocked row is admitted WITH its class", gate !== null && gate.gateBlockClass === "plan-hash-mismatch");
    const wire = projectRecord({ kind: "wire-anomaly", screen: "downpipes", fieldClass: "seal-at", anomaly: "unparseable", count: 1, firstMs: 0, lastMs: 0 });
    ok("a wire-anomaly row is admitted WITH both discriminators", wire !== null && wire.fieldClass === "seal-at" && wire.anomaly === "unparseable");
    const boot = projectRecord({ kind: "boot-fault", screen: "boot", bootClass: "nav-bridge-uninstalled", count: 1, firstMs: 0, lastMs: 0 });
    ok("a boot-fault row is admitted WITH its bootClass", boot !== null && boot.bootClass === "nav-bridge-uninstalled");
    const unhandled = projectRecord({ kind: "unhandled", screen: "security", faultClass: "other", faultSource: "unhandled-rejection", errorClass: "TypeError", count: 1, firstMs: 0, lastMs: 0 });
    ok("an unhandled row keeps the channel and the error class", unhandled !== null && unhandled.faultSource === "unhandled-rejection" && unhandled.errorClass === "TypeError");

    ok("a smuggled value in gateBlockClass DROPS the record", projectRecord({ kind: "restore-gate-blocked", screen: "restore", gateBlockClass: "customer@example.com", count: 1, firstMs: 0, lastMs: 0 }) === null);
    ok("a smuggled value in errorClass DROPS the record", projectRecord({ kind: "unhandled", screen: "security", errorClass: "acme-corp-Error", count: 1, firstMs: 0, lastMs: 0 }) === null);
    ok("a smuggled value in fieldClass DROPS the record", projectRecord({ kind: "wire-anomaly", screen: "downpipes", fieldClass: "https://acme.example/bucket", anomaly: "unparseable", count: 1, firstMs: 0, lastMs: 0 }) === null);
  }

  console.log("\nprojectRecord: set-membership validation + allowlist projection:");
  {
    const r = projectRecord(goodRecord());
    ok("a well-formed record is accepted with all its frozen-member fields", r !== null && r.kind === "engine-call" && r.screen === "downpipes" && r.httpClass === "5xx" && r.faultClass === "server" && r.count === 3 && r.firstMs === 100 && r.lastMs === 900);

    ok("an out-of-vocab kind DROPS the record", projectRecord({ ...goodRecord(), kind: "not-a-kind" }) === null);
    ok("an out-of-vocab screen DROPS the record", projectRecord({ ...goodRecord(), screen: "/downpipes/dp-secret-id" }) === null);
    ok("an out-of-vocab httpClass class member DROPS the record", projectRecord({ ...goodRecord(), httpClass: "6xx" }) === null);
    ok("a smuggled free-string in a recognised field DROPS the record", projectRecord({ ...goodRecord(), faultClass: "customer@example.com" }) === null);
    ok("a missing required numeric (count) DROPS the record", projectRecord({ kind: "engine-call", screen: "downpipes", firstMs: 1, lastMs: 2 }) === null);
    ok("a non-object DROPS the record", projectRecord("boom") === null && projectRecord(null) === null);

    // Allowlist projection (not spread): an extra/unknown key is never copied; the record still rides.
    const withExtra = projectRecord({ ...goodRecord(), note: "https://acct.r2.example/bucket/secret", email: "user@example.com" });
    ok("an extra/unknown key is DROPPED (never copied), the record still rides", withExtra !== null && !("note" in withExtra) && !("email" in withExtra));
    ok("the projected record has NO string field beyond the frozen enums", withExtra !== null && Object.entries(withExtra).every(([k, v]) => ["kind", "screen", "httpClass", "faultClass", "driftClass", "reasonClass", "applyClass", "capability", "surface", "capabilityOutcome"].includes(k) || typeof v === "number"));

    // applyClass: the WHOLE discriminator of an apply-outcome row. A receiver that validated the row
    // and then failed to COPY the class would land a row in the bundle saying an apply ended and refusing to
    // say how, which is worse than no row: the console recorded the evidence, the customer sent the pack, and
    // support still cannot answer "did my restore write anything?".
    const applyRow = projectRecord({ kind: "apply-outcome", screen: "restore", applyClass: "wrote-none", count: 3, firstMs: 1, lastMs: 2 });
    ok("an apply-outcome row is admitted and KEEPS its applyClass", applyRow !== null && applyRow.kind === "apply-outcome" && applyRow.applyClass === "wrote-none" && applyRow.count === 3);
    ok("a drifted applyClass DROPS the record (never coerced to a nearby member)", projectRecord({ kind: "apply-outcome", screen: "restore", applyClass: "wrote-most", count: 1, firstMs: 1, lastMs: 2 }) === null);
    ok("a smuggled free-string in applyClass DROPS the record", projectRecord({ kind: "apply-outcome", screen: "restore", applyClass: "run-abc-123", count: 1, firstMs: 1, lastMs: 2 }) === null);

    // fanout-degraded: the row's EXISTENCE is the evidence (the destination read failed AND the batch
    // fell back to the default), and its count is how many downpipes landed without their replicas.
    const fanout = projectRecord({ kind: "fanout-degraded", screen: "sources", count: 12, firstMs: 1, lastMs: 2 });
    ok("a fanout-degraded row is admitted with its magnitude", fanout !== null && fanout.kind === "fanout-degraded" && fanout.screen === "sources" && fanout.count === 12);

    // capability-fault: capability + surface + capabilityOutcome are the WHOLE discriminator. A receiver
    // that admitted the row and dropped them would land a row saying the browser would not do SOMETHING, on
    // SOME ceremony, which is exactly the useless row this guards against.
    const cap = projectRecord({ kind: "capability-fault", screen: "access", capability: "blob-download", surface: "recovery-codes", capabilityOutcome: "refused", count: 1, firstMs: 1, lastMs: 2 });
    ok(
      "a capability-fault row is admitted and KEEPS capability + surface + outcome",
      cap !== null && cap.kind === "capability-fault" && cap.capability === "blob-download" && cap.surface === "recovery-codes" && cap.capabilityOutcome === "refused",
    );
    const keygen = projectRecord({ kind: "capability-fault", screen: "keys", capability: "webcrypto-keygen", surface: "key-ceremony", capabilityOutcome: "unavailable", count: 1, firstMs: 1, lastMs: 2 });
    ok("a keygen capability-fault is admitted with its outcome", keygen !== null && keygen.capability === "webcrypto-keygen" && keygen.capabilityOutcome === "unavailable");
    ok("a drifted capability DROPS the record", projectRecord({ kind: "capability-fault", screen: "keys", capability: "print", surface: "key-ceremony", capabilityOutcome: "refused", count: 1, firstMs: 1, lastMs: 2 }) === null);
    ok("a drifted surface DROPS the record", projectRecord({ kind: "capability-fault", screen: "keys", capability: "clipboard", surface: "/keys/rotate", capabilityOutcome: "refused", count: 1, firstMs: 1, lastMs: 2 }) === null);
    ok("a smuggled file name in surface DROPS the record", projectRecord({ kind: "capability-fault", screen: "keys", capability: "blob-download", surface: "identity.key", capabilityOutcome: "refused", count: 1, firstMs: 1, lastMs: 2 }) === null);
    ok("a drifted capabilityOutcome DROPS the record", projectRecord({ kind: "capability-fault", screen: "keys", capability: "clipboard", surface: "recovery-codes", capabilityOutcome: "maybe", count: 1, firstMs: 1, lastMs: 2 }) === null);
  }

  console.log("\nREDACTION PROOF: a customer sentinel in every field never appears in the output:");
  {
    const SENT = "CUSTOMER-SECRET-9f3a2b";
    // Record A: valid required fields, but EVERY optional field + several extra keys carry the sentinel. The
    // optional-field sentinels fail the record closed (present-but-non-member); the extra keys are never copied.
    const a = { kind: "engine-call", screen: "downpipes", count: 1, firstMs: 0, lastMs: 1, httpClass: SENT, faultClass: SENT, driftClass: SENT, reasonClass: SENT, url: `https://x/${SENT}`, message: SENT, downpipeId: SENT };
    // Record B: fully valid, but with extra keys carrying the sentinel (must ride minus the extra keys).
    const b = { ...goodRecord(), token: SENT, host: SENT, blockedURI: SENT };
    // Record C: a hostile record where kind/screen themselves are the sentinel (whole record dropped).
    const c = { kind: SENT, screen: SENT, count: SENT, firstMs: SENT, lastMs: SENT };
    const section = projectClientDiagnostics({ records: [a, b, c], engineAttempts: 10 });
    const text = JSON.stringify(section);
    ok("the customer sentinel appears NOWHERE in the projected section", !text.includes(SENT));
    ok("record A (sentinel in optional fields) was dropped; record B rode without its extra keys", section !== null && section.records.length === 1 && section.records[0]!.kind === "engine-call" && !("token" in section.records[0]!));
    ok("provenance is engine-stamped: source client-asserted + second-precision receivedAt + clamped engineAttempts", section !== null && section.source === "client-asserted" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(section.receivedAt) && section.engineAttempts === 10);
  }

  console.log("\nnumeric clamping (count cap 1e6; firstMs/lastMs clamped; engineAttempts clamped):");
  {
    const s = projectClientDiagnostics({ records: [{ kind: "unhandled", screen: "boot", count: 9_999_999_999, firstMs: -5, lastMs: Number.NaN }], engineAttempts: -3 });
    // lastMs NaN makes the record unusable (a valid record needs a finite lastMs), so it is dropped; assert the
    // count/firstMs clamps on a record whose ms ARE finite instead.
    const s2 = projectClientDiagnostics({ records: [{ kind: "unhandled", screen: "boot", faultClass: "other", count: 9_999_999_999, firstMs: -5, lastMs: 12.9 }], engineAttempts: 7.9 });
    ok("a NaN lastMs drops the record (a valid monotonic offset is required)", s !== null && s.records.length === 0);
    ok("count is clamped to COUNT_MAX, a negative firstMs floors to 0, a fractional lastMs floors", s2 !== null && s2.records[0]!.count === CLIENT_DIAG_COUNT_MAX && s2.records[0]!.firstMs === 0 && s2.records[0]!.lastMs === 12);
    ok("a negative engineAttempts clamps to 0; a fractional one floors", s2 !== null && s2.engineAttempts === 7);
  }

  console.log("\ncaps (D3): per-kind newest-wins 32, global 128, per-kind uncapped true-count rollup:");
  {
    // 40 engine-call records (over the per-kind cap of 32), oldest -> newest by lastMs. Newest-wins keeps the
    // last 32; the rollup records the true count 40.
    const many = Array.from({ length: 40 }, (_, i) => ({ kind: "engine-call", screen: "downpipes", httpClass: "5xx", count: 1, firstMs: i, lastMs: i }));
    const capped = projectClientDiagnostics({ records: many });
    ok("per-kind cap keeps exactly PER_KIND_ROW_CAP newest rows", capped !== null && capped.records.length === CLIENT_DIAG_PER_KIND_ROW_CAP);
    ok("the kept rows are the NEWEST (lastMs 8..39), oldest dropped", capped !== null && Math.min(...capped.records.map((r) => r.lastMs)) === 40 - CLIENT_DIAG_PER_KIND_ROW_CAP && Math.max(...capped.records.map((r) => r.lastMs)) === 39);
    ok("the per-kind uncapped true-count rollup records the real total (40)", capped?.rollupByKind?.["engine-call"] === 40);

    // Global cap: 5 kinds x 32 kept = 160 rows > 128. Global newest-wins by lastMs trims to 128.
    const kinds = ["engine-call", "contract-drift", "bulk-outcome", "boot-fault", "unhandled"] as const;
    const flood: Array<Record<string, unknown>> = [];
    let t = 0;
    for (const k of kinds) for (let i = 0; i < 32; i++) flood.push({ kind: k, screen: "overview", count: 1, firstMs: t, lastMs: t++ });
    const g = projectClientDiagnostics({ records: flood });
    ok("global cap trims to GLOBAL_ROW_CAP rows", g !== null && g.records.length === CLIENT_DIAG_GLOBAL_ROW_CAP);
  }

  console.log("\nthe empty/absent asymmetry (D9):");
  {
    ok("a PRESENT-but-empty ring yields a section with records:[] (collected, nothing to report)", (() => { const s = projectClientDiagnostics({ records: [] }); return s !== null && s.records.length === 0 && s.source === "client-asserted"; })());
    ok("NO clientDiagnostics object at all yields null (the caller then omits the section)", projectClientDiagnostics(undefined) === null && projectClientDiagnostics(null) === null);
  }

  console.log("\nI1: the section is request-scoped, not a roster member:");
  {
    ok("clientDiagnostics is NOT a SUPPORT_SECTION_NAMES member (no section() gatherer, no DO write)", !(SUPPORT_SECTION_NAMES as readonly string[]).includes("clientDiagnostics"));
    const sched = schedulerDouble();
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const section: ClientDiagnosticsSection = { source: "client-asserted", receivedAt: "2026-07-11T00:00:00Z", records: [{ kind: "engine-call", screen: "downpipes", httpClass: "5xx", count: 1, firstMs: 1, lastMs: 2 }] };
    // clientDiagnostics now rides on the SupportBundleContext object rather than as a positional third argument:
    // both this branch and the pack-expansion branch had claimed that parameter, and one object is the only
    // resolution that cannot silently drop a channel. See test/validate-merge-both-channels.ts.
    const withSection = await buildSupportBundle(env, sched.stub, { clientDiagnostics: section });
    ok("buildSupportBundle FOLDS the section when supplied (source client-asserted)", (withSection["clientDiagnostics"] as { source?: string } | undefined)?.source === "client-asserted");
    const withoutSection = await buildSupportBundle(env, sched.stub);
    ok("buildSupportBundle STRUCTURALLY omits it when NOT supplied (vendor-pull / scheduled build)", !("clientDiagnostics" in withoutSection));
    const signedNoArg = await signedSupportBundle(env, sched.stub);
    ok("signedSupportBundle without the arg (the exact vendor-pull call) omits the section", !("clientDiagnostics" in signedNoArg.bundle));
  }

  console.log("\nthrough the real router (handleAdmin):");
  {
    const { env } = makeRouterEnv(signerB64);
    // POST with a ring -> 200, the sealed/signed bundle carries clientDiagnostics.
    const postBody = JSON.stringify({ clientDiagnostics: { records: [goodRecord(), { kind: "bulk-outcome", screen: "restore", reasonClass: "partial", count: 2, firstMs: 5, lastMs: 6 }], engineAttempts: 42 } });
    const postResp = await routerCall(env, "POST", "/admin/support/bundle", postBody);
    const postJson = (await postResp.json()) as { bundle?: Record<string, unknown> };
    const postSection = postJson.bundle?.["clientDiagnostics"] as { source?: string; records?: unknown[]; engineAttempts?: number } | undefined;
    ok("POST /admin/support/bundle accepts the ring and folds clientDiagnostics into the signed bundle", postResp.status === 200 && postSection?.source === "client-asserted" && postSection.records?.length === 2 && postSection.engineAttempts === 42);

    // GET -> 200, NO clientDiagnostics (structural omission on the download-without-ring path).
    const getResp = await routerCall(env, "GET", "/admin/support/bundle");
    const getJson = (await getResp.json()) as { bundle?: Record<string, unknown> };
    ok("GET /admin/support/bundle has NO clientDiagnostics section", getResp.status === 200 && !("clientDiagnostics" in (getJson.bundle ?? {})));

    // Oversized body -> 400 (D1: capped before parse; the receiver never sees it).
    const huge = JSON.stringify({ clientDiagnostics: { records: [{ kind: "engine-call", screen: "downpipes", count: 1, firstMs: 0, lastMs: 0, pad: "x".repeat(CLIENT_DIAG_MAX_BODY_BYTES + 10) }] } });
    const hugeResp = await routerCall(env, "POST", "/admin/support/bundle", huge);
    ok("an oversized POST body 400s (capped before parse)", hugeResp.status === 400);

    // Malformed JSON -> 400 (never a coerced/echoed value, never a crashed build).
    const badResp = await routerCall(env, "POST", "/admin/support/bundle", "{ not json ");
    ok("a malformed POST body 400s", badResp.status === 400);

    // An empty POST body behaves like the GET (no section), never a crash.
    const emptyResp = await routerCall(env, "POST", "/admin/support/bundle", "");
    const emptyJson = (await emptyResp.json()) as { bundle?: Record<string, unknown> };
    ok("an empty POST body builds a bundle with NO clientDiagnostics", emptyResp.status === 200 && !("clientDiagnostics" in (emptyJson.bundle ?? {})));
  }

  console.log("\nthe vendor bearer-pull path (GET /support/diagnostics) STRUCTURALLY omits the section:");
  {
    const sched = schedulerDouble();
    const minted = await mintIngestCredential("diagnostics", "owner@example.com.au", undefined);
    sched.grants["diagnostics"] = minted.grant;
    const env = { SIGNER_PRIVATE: signerB64, SCHEDULER: {} as DurableObjectNamespace } as unknown as Env;
    const req = new Request("https://engine.example/support/diagnostics", { method: "GET", headers: { authorization: `Bearer ${minted.clientId}.${minted.secret}` } });
    const resp = await handleSupportPull(req, env, sched.stub);
    const pulled = (await resp.json()) as { bundle?: Record<string, unknown> };
    ok("the vendor-pulled bundle authenticates (200) and carries NO clientDiagnostics", resp.status === 200 && !("clientDiagnostics" in (pulled.bundle ?? {})));
  }

  console.log(failures === 0 ? "\nCLIENT-DIAGNOSTICS SECTION PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
