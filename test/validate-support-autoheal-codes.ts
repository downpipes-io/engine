// Prove the support pack's auto-heal refusal-code allowlist cannot drift from the canonical vocabulary.
//
// The cron auto-heal can refuse to apply a recovery export with a CLOSED reason code (AutoHealRefusalCode).
// The support pack projects that code into the bundle through a separate allowlist (AUTOHEAL_REFUSAL_CODES
// in support-sections-recovery.ts), so the owner's "did my control plane recover, and if not why" question
// is answerable from the sealed bundle. The runtime tuple AUTO_HEAL_REFUSAL_CODES is the single source of
// truth (the type derives from it, the pack builds its Set from it), so any refusal reason added in
// control-plane that a maintainer forgets to surface in the pack fails here rather than going invisible in
// production bundles.
//
// The projection code path (fetchRecovery in support-sections-recovery.ts) is also driven end to end against
// an in-memory DO stub to prove every canonical code actually reaches the bundle, and that an out-of-vocab
// code is still dropped to a fixed placeholder rather than vanishing silently (the redaction contract is
// preserved).
//
// Run:  node test/validate-support-autoheal-codes.ts
// In-memory doubles only; no network, no deploy, no cost.

import { AUTO_HEAL_REFUSAL_CODES } from "../src/admin/control-plane.ts";
import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A minimal DO stub whose /control-plane/recovery-status returns a refusal record we control.
function schedulerReturning(body: unknown): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/control-plane/recovery-status")) {
        return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

async function projectedRefusedCode(code: string): Promise<unknown> {
  const scheduler = schedulerReturning({ recoveryRequired: true, refused: true, refusedCode: code });
  const rec = (await fetchRecoveryStatus(scheduler)) as { refusedCode?: unknown };
  return rec.refusedCode;
}

async function main(): Promise<void> {
  console.log("validate-support-autoheal-codes\n");

  // 1. The canonical tuple carries sealed-no-op-key (the code that had drifted out of the pack).
  ok("canonical AUTO_HEAL_REFUSAL_CODES includes sealed-no-op-key", (AUTO_HEAL_REFUSAL_CODES as readonly string[]).includes("sealed-no-op-key"));

  // 2. Every canonical code projects through the pack (the allowlist is bound to the tuple, not re-listed).
  for (const code of AUTO_HEAL_REFUSAL_CODES) {
    ok(`refusedCode "${code}" reaches the bundle`, (await projectedRefusedCode(code)) === code);
  }

  // 3. Redaction contract preserved: an out-of-vocabulary code is NEVER propagated. It collapses to the fixed
  // "unknown-code" placeholder rather than being dropped in silence -- a silent drop would leave
  // `refused:true` with no cause at all, indistinguishable from a refusal the pack simply had no code for.
  // The raw value still never rides (that is the redaction guarantee); the drift is legible instead.
  ok("out-of-vocab refusedCode rides as the unknown-code placeholder, never the raw value", (await projectedRefusedCode("some-future-free-text")) === "unknown-code");

  // 4. sealed-no-op-key must be present in the bundle (a regression guard).
  ok("sealed-no-op-key reaches the bundle (regression guard)", (await projectedRefusedCode("sealed-no-op-key")) === "sealed-no-op-key");

  console.log(failures === 0 ? "\nALL SUPPORT AUTOHEAL-CODE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
