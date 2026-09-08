// Durable Object source: a COMPILE-ONLY STUB, not a live source.
//
// A Durable Object's state (its embedded SQLite storage and key-value storage) is reachable only
// from INSIDE the object's own isolate; there is no account-level REST surface the engine's
// discovery token can read the way it reads KV, R2, D1, Stream, Images or the cf-config inventory.
// Capturing it therefore needs an in-tenant export shim the operator deploys alongside their own
// Durable Object namespace, which exposes the object's storage to the engine on request. That shim
// is not built yet, so this adapter is declared (so the type exists and the rest of the engine can
// reference a "durable_object" source) but DELIBERATELY NOT WIRED:
//   - it is absent from the config-validate allow-list (src/sched/config-validate.ts), so a downpipe
//     config can never select source.type "durable_object" (no live run reaches this code), and
//   - it is absent from buildAdapter (src/seal/adapters.ts), so nothing constructs it on a run.
//
// Its crawl/crawlFrom/estimate THROW a clear error rather than yielding nothing, so the stub can
// never silently produce an empty Durable Object backup if a future wiring change reaches it before
// the export shim lands. It implements ResumableSource (and so SourceAdapter) structurally, modelled
// on the other API-scoped sources (stream.ts), so it stays in lockstep with the live interface: if
// the SourceAdapter contract changes, this stub stops typechecking and is updated with the rest.

import type { CrawlEvent, Meter, ResumableSource, Selector, SourceRecord } from "./types.ts";

// The single message every entry point throws. Naming the missing piece (the in-tenant export shim)
// keeps the failure self-explanatory and makes a silent empty backup impossible.
const NOT_WIRED =
  "durable_object source requires an in-tenant export shim; not yet wired";

export class DurableObjectSource implements ResumableSource {
  readonly sourceType = "durable_object" as const;

  // crawl is the whole-crawl form. It throws: a Durable Object cannot be read account-side, so there
  // is nothing to yield and an empty iterator would be a silent gap. It throws on call (not lazily on
  // first iteration) so a caller that reaches the stub fails loudly and immediately. It is a plain
  // method (not a generator) so it never has to fake a yield.
  crawl(_selector: Selector, _meter?: Meter): AsyncIterable<SourceRecord> {
    throw new Error(NOT_WIRED);
  }

  // crawlFrom is the resumable form the sliced seal uses. It throws for the same reason as crawl.
  crawlFrom(_selector: Selector, _token: string | null, _meter?: Meter): AsyncIterable<CrawlEvent> {
    throw new Error(NOT_WIRED);
  }

  // estimate would feed the pre-run cost projection. It throws so a cost preview cannot silently
  // report a zero-record, zero-byte Durable Object source.
  async estimate(_selector: Selector): Promise<{ records: number; bytes: number }> {
    throw new Error(NOT_WIRED);
  }
}
