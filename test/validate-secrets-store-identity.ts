// Pins that a Secrets Store secret's archive record records WHICH store it came from (descriptor.secretsStore
// = the storeId), so the backup self-identifies and a re-attach can rebuild the secrets_store_secret binding.
// buildAdapter wires SecretBindingSpec.storeId through when constructing the BoundSecret, so the crawl
// records each secret's store id, keeping stores distinguishable and re-attach reconstructable.
// Run: node test/validate-secrets-store-identity.ts

import { buildAdapter } from "../src/seal/adapters.ts";
import { makeEnv, healthStub } from "./validate-worker-helpers.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import type { DownpipeState } from "../src/sched/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

function secretsState(secrets: Array<{ name: string; binding: string; storeId?: string }>): DownpipeState {
  return {
    config: { id: "dp-secrets", name: "secrets", cadenceSeconds: 3600, enabled: true, source: { type: "secrets", secrets } },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  } as unknown as DownpipeState;
}

async function main(): Promise<void> {
  // A fake Secrets Store binding: env.SRC_SECRET_x.get() returns the plaintext (never archived).
  const env = makeEnv(healthStub(), { SRC_SECRET_x: { get: async () => "the-secret-value" }, SRC_SECRET_y: { get: async () => "another" } } as never);
  const adapter = buildAdapter(env, secretsState([
    { name: "API_KEY", binding: "SRC_SECRET_x", storeId: "store-123" },
    { name: "DB_URL", binding: "SRC_SECRET_y" }, // no storeId (back-compat): store omitted, not "undefined"-stringified
  ]));

  const recs: SourceRecord[] = [];
  for await (const r of adapter.crawl({ include: [], exclude: [] })) recs.push(r);

  const apiKey = recs.find((r) => r.name === "API_KEY");
  const dbUrl = recs.find((r) => r.name === "DB_URL");
  ok("both secrets are captured (one record each)", recs.length === 2 && apiKey !== undefined && dbUrl !== undefined);
  ok("the secret with a storeId records descriptor.secretsStore = the store id (self-identifying, re-attachable)", apiKey?.descriptor?.secretsStore === "store-123");
  ok("a secret with NO storeId omits secretsStore entirely (never a stringified undefined)", dbUrl?.descriptor?.secretsStore === undefined);
  ok("the record still carries its binding var for the re-attach", apiKey?.descriptor?.secretsBindingVar === "SRC_SECRET_x");
  ok("the plaintext secret value is captured but NEVER the store leaks into the value", new TextDecoder().decode(apiKey!.value) === "the-secret-value" && !new TextDecoder().decode(apiKey!.value).includes("store-123"));

  console.log(failures === 0 ? "\nSECRETS STORE-IDENTITY PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
