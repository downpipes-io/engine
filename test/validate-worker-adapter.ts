// buildAdapter cases of the validate-worker suite (split out of test/validate-worker.ts): the
// reserved-binding guard (with its missing-binding negative control) and
// the live-adapter dispatch for the REST-API source types (stream/images/artifacts). No network,
// no deploy.

import { buildAdapter } from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import { RESERVED_BINDINGS, type DownpipeState } from "../src/sched/scheduler-do.ts";
import { StreamSource } from "../src/sources/stream.ts";
import { ImagesSource } from "../src/sources/images.ts";
import { ArtifactsSource } from "../src/sources/artifacts.ts";
import { ok, makeEnv, healthStub, dueState } from "./validate-worker-helpers.ts";

export async function run(): Promise<void> {
  // -----------------------------------------------------------------------------------------
  // 12. buildAdapter RESERVED-BINDING GUARD (reachable via the exported test seam).
  //
  // buildAdapter is the source-adapter constructor sealRun calls; it carries a defence-in-depth
  // guard that a downpipe source may NEVER name one of the engine's own bindings (RESERVED_BINDINGS),
  // else a backup could seal the signer key or a destination credential into the archive. The guard
  // is symmetric to validateConfig's authority-boundary check, but this is the SEAL-side belt-and-
  // braces, so it is worth proving independently.
  //
  // We assert the guard fires for a reserved binding, and use a NEGATIVE CONTROL to prove it is the
  // RESERVED guard specifically (not just "any throw"): a NON-reserved, absent binding throws a
  // DIFFERENT, "not present in the environment" error, and an explicitly-reserved name throws the
  // "reserved and cannot be a source" error. If the guard were removed, the reserved name would fall
  // through to the same "not present" error as the absent one, and the discriminating assertion fails.
  // -----------------------------------------------------------------------------------------
  {
    // Pick a representative reserved binding (the signer private is the most sensitive one).
    const RESERVED = "SIGNER_PRIVATE";
    ok("buildAdapter guard: SIGNER_PRIVATE is in RESERVED_BINDINGS (precondition)", RESERVED_BINDINGS.has(RESERVED));

    // CONFIG_WRAP_KEY/SCIM_BEARER_TOKEN/BEACON_INGEST_KEY must all be in RESERVED_BINDINGS: absent, a
    // secrets source could name them and exfiltrate the destination-credential wrap key or a bearer
    // secret via an ordinary backup. Assert each is reserved by name, not just "some binding is
    // reserved", so a future removal of any one of them fails here specifically.
    ok("buildAdapter guard: CONFIG_WRAP_KEY is in RESERVED_BINDINGS", RESERVED_BINDINGS.has("CONFIG_WRAP_KEY"));
    ok("buildAdapter guard: SCIM_BEARER_TOKEN is in RESERVED_BINDINGS", RESERVED_BINDINGS.has("SCIM_BEARER_TOKEN"));
    ok("buildAdapter guard: BEACON_INGEST_KEY is in RESERVED_BINDINGS", RESERVED_BINDINGS.has("BEACON_INGEST_KEY"));

    // (a) A reserved binding name throws the reserved-source error, EVEN IF that binding is present in
    //     env (the guard runs before the env lookup, so a real value cannot smuggle past it). We put a
    //     truthy value at env[RESERVED] to prove the guard is name-based, not presence-based.
    const reservedEnv = makeEnv(healthStub(), { [RESERVED]: "a-real-looking-secret-value" } as Partial<Env>);
    let reservedErr: Error | undefined;
    try {
      buildAdapter(reservedEnv, dueState("dp-reserved", RESERVED));
    } catch (e) {
      reservedErr = e as Error;
    }
    ok("buildAdapter guard: a reserved source binding throws", reservedErr !== undefined);
    ok(
      "buildAdapter guard: the error is the RESERVED-source message (not a generic missing-binding error)",
      !!reservedErr && /reserved and cannot be a source/.test(reservedErr.message),
    );
    ok(
      "buildAdapter guard: the reserved binding name is named in the error",
      !!reservedErr && reservedErr.message.includes(RESERVED),
    );

    // (b) NEGATIVE CONTROL: a NON-reserved, absent binding throws a DIFFERENT error ("not present in
    //     the environment"). This proves (a)'s rejection came from the reserved guard, not from the
    //     binding merely being unresolved: the two paths produce DISTINCT messages.
    const NONRESERVED = "KV_A_REGULAR_SOURCE";
    ok("buildAdapter guard: control binding is NOT reserved (precondition)", !RESERVED_BINDINGS.has(NONRESERVED));
    let absentErr: Error | undefined;
    try {
      buildAdapter(makeEnv(healthStub()), dueState("dp-absent", NONRESERVED));
    } catch (e) {
      absentErr = e as Error;
    }
    ok("buildAdapter guard: a non-reserved absent binding throws", absentErr !== undefined);
    ok(
      "buildAdapter guard: the absent-binding error is the missing-from-env message (NOT the reserved one)",
      !!absentErr && /is not present in the environment/.test(absentErr.message) && !/reserved and cannot be a source/.test(absentErr.message),
    );
    ok(
      "buildAdapter guard: the two failure messages are DISTINCT (reserved guard is discriminating)",
      !!reservedErr && !!absentErr && reservedErr.message !== absentErr.message,
    );
  }

  // -----------------------------------------------------------------------------------------
  // 12b. buildAdapter LIVE-ADAPTER DISPATCH for the REST-API source types (stream/images/artifacts).
  //
  // config-validate's allow-list accepting "stream"/"images"/"artifacts" is necessary but NOT
  // sufficient: a downpipe can only run if buildAdapter then constructs a real adapter for that type.
  // The two lists are maintained separately, so a type can pass validation yet fall through
  // buildAdapter to the binding switch and throw a generic error at run time (the latent allow-list/
  // buildAdapter mismatch). We prove buildAdapter returns the LIVE adapter instance for each type, not
  // just that the allow-list passes.
  // -----------------------------------------------------------------------------------------
  {
    // These three sources read the Cloudflare REST API with the account read-only discovery token (not
    // a binding), so we pass a token and an accountId; the env carries no binding for them.
    const ACCT = "00000000000000000000000000000000";
    const TOKEN = "discovery-token-not-a-real-secret";
    const mediaState = (id: string, type: "stream" | "images" | "artifacts"): DownpipeState => ({
      config: {
        id,
        name: `dp ${id}`,
        cadenceSeconds: 3600,
        enabled: true,
        source: { type, accountId: ACCT, include: [], exclude: [] },
      },
      nextRunAt: 0,
      lastRunId: null,
      inFlight: false,
    });
    const env = makeEnv(healthStub());
    ok("buildAdapter dispatch: stream -> a live StreamSource", buildAdapter(env, mediaState("dp-stream", "stream"), TOKEN) instanceof StreamSource);
    ok("buildAdapter dispatch: images -> a live ImagesSource", buildAdapter(env, mediaState("dp-images", "images"), TOKEN) instanceof ImagesSource);
    ok("buildAdapter dispatch: artifacts -> a live ArtifactsSource", buildAdapter(env, mediaState("dp-artifacts", "artifacts"), TOKEN) instanceof ArtifactsSource);

    // NEGATIVE CONTROL: without the discovery token these types throw the token-required error, NOT the
    // generic "binding not present" error. That proves the dispatch reaches the dedicated REST-API
    // branch (not the binding switch), so the allow-list/buildAdapter pair cannot silently diverge.
    let tokenErr: Error | undefined;
    try {
      buildAdapter(env, mediaState("dp-stream-notoken", "stream"));
    } catch (e) {
      tokenErr = e as Error;
    }
    ok(
      "buildAdapter dispatch: a media source without the discovery token throws the token-required error (reached the REST branch, not the binding switch)",
      !!tokenErr && /read-only token/.test(tokenErr.message) && !/not present in the environment/.test(tokenErr.message),
    );
  }
}
