import { inScope } from "./selector.ts";
import { classifySourceFaultReason, classifySourceFaultStatus, faultItemId, recordIncompleteFault, recordSourceFatal } from "./source-fault-ledger.ts";
import type { Meter, RestoreDescriptor, Selector, SourceAdapter, SourceRecord } from "./types.ts";
import { hasAnyField } from "./types.ts";

// A bound secret the engine can read at runtime. The Worker MUST be explicitly bound to
// each secret it backs up (there is no read-all), so the engine only ever sees the
// secrets it was granted, never the whole store. The store/scope/worker/bindingVar/comment
// describe the secret's wiring so a restore can reconstruct it (SPEC 12.3); none of them is
// the value. The value is read via get(), carried on the record's value field, and sealed
// encrypted into the archive (seal/record.ts); the plaintext is never written to a
// descriptor field and never logged.
export interface BoundSecret {
  name: string;
  get: () => Promise<string>; // env.BINDING.get() for a Secrets Store binding
  store?: string;
  scope?: string;
  worker?: string;
  bindingVar?: string;
  comment?: string;
}

// Secrets adapter (SPEC 12.4, the high-assurance source). It reads each in-scope secret
// value through its binding and yields it; the seal pipeline encrypts that value into the
// archive (seal/record.ts), so the secret is recoverable. The plaintext lives only in
// isolate memory for the duration of the yield: it is never logged, never written to a
// descriptor field, and never written to DO state. Only the sealed ciphertext is persisted.
// Backing up secrets without the offline break-glass key in the recipient set is refused
// upstream, not here.
export class SecretsSource implements SourceAdapter {
  readonly sourceType = "secrets" as const;
  private secrets: BoundSecret[];

  constructor(secrets: BoundSecret[]) {
    this.secrets = secrets;
  }

  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for (const s of this.secrets) {
      if (!inScope(s.name, selector)) continue;
      // Each Secrets Store get is a platform subrequest the slice budget must see.
      meter?.spend(1, "secretsRead");
      // G068/G144: ONE of N bound secrets being deleted (or its store being unreachable) throws here and kills
      // the WHOLE secrets run, and the run row carried only a coarse class: WHICH secret sank it, and that every
      // other secret read fine, were invisible remotely. Record the failing secret's identity as a one-way
      // HANDLE (the secret NAME is customer data and never leaves the account) plus the closed reason class,
      // and the run-fatal status class + stage, before rethrowing. The secret VALUE is never touched here: the
      // throw happens at get(), so no plaintext exists yet, and none is ever read into the ledger.
      let value: Uint8Array;
      try {
        value = new TextEncoder().encode(await s.get());
      } catch (e) {
        recordIncompleteFault("_unavailable", classifySourceFaultReason(e), { id: await faultItemId("secrets:get", s.name) });
        recordSourceFatal({ sourceType: "secrets", statusClass: classifySourceFaultStatus(e), stage: "item-read" });
        throw e;
      }
      // Capture the wiring (never the value) so a restore can reconstruct the secret. Each
      // field is attached only when set, giving the omitempty descriptor shape.
      const descriptor: RestoreDescriptor = {};
      if (s.store !== undefined) descriptor.secretsStore = s.store;
      if (s.scope !== undefined) descriptor.secretsScope = s.scope;
      if (s.comment !== undefined) descriptor.secretsComment = s.comment;
      if (s.worker !== undefined) descriptor.secretsWorker = s.worker;
      if (s.bindingVar !== undefined) descriptor.secretsBindingVar = s.bindingVar;
      yield { sourceType: "secrets", name: s.name, value, ...(hasAnyField(descriptor) ? { descriptor } : {}) };
    }
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    const records = this.secrets.filter((s) => inScope(s.name, selector)).length;
    return { records, bytes: -1 }; // never read a secret value to estimate
  }
}
