// Two readers for a JSON body that may not be JSON. Each is the one place a parse failure becomes a default,
// so every caller says what the default means by what it does next.

// readJsonOrNull parses a response or request body. A body that is not JSON reads as null. Every caller treats
// null as a failed exchange: it tests `ok` and the envelope's `success` next, so null never reads as success.
export async function readJsonOrNull(src: { json(): Promise<unknown> }): Promise<unknown> {
  try { // nosemgrep: incident-catch-returns-empty -- null is the not-JSON verdict and never an empty result
    return await src.json();
  } catch {
    // site-fault-waiver: src/util/json-body.ts:readJsonOrNull:catch:1 -- null is the not-JSON verdict and each caller treats it as a failed exchange
    return null;
  }
}

// readJsonObjectOrEmpty parses a request body for a route that reads named fields from it. A body that is not a
// JSON object reads as {}, so every field is absent and the route's own required-field checks answer 400.
export async function readJsonObjectOrEmpty(src: { json(): Promise<unknown> }): Promise<Record<string, unknown>> {
  try { // nosemgrep: incident-catch-returns-empty -- an unreadable body has no fields and the route refuses it on its required fields
    const v = await src.json();
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    // site-fault-waiver: src/util/json-body.ts:readJsonObjectOrEmpty:catch:1 -- an unreadable body has no fields, and each caller refuses a missing required field with 400
    return {};
  }
}
