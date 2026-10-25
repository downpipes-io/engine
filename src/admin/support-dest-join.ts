// The current destination resolution, joined beside the red rows that name a destination.
//
// A replication row, a replica-target-fault row and a span name their destination by id only, and each
// records what was true when it was written. destResolution.resolution[] records what the engine resolves for
// that id now. Joining the two on the id puts both on one row, so a red row beside an ok resolution reads as
// one fact. The join runs at pack assembly, after the sections are projected and destResolution is gathered.
//
// The joined value uses only the closed members destResolution already carries: branch, ok and the closed
// refusal reason. The string "not-listed" says the id is not in the resolution list, which holds at most 64 ids.
// When destResolution has no list (its section faulted), no row gets a claim.

type Row = Record<string, unknown>;

export interface DestJoinParts {
  downpipes: Row[];
  sealFaults: unknown[];
  sealFaultSpans: Row;
}

function lookup(destResolution: Row): Map<string, Row> | null {
  const list = destResolution["resolution"];
  if (!Array.isArray(list)) return null;
  const byId = new Map<string, Row>();
  for (const r of list as Row[]) {
    if (r && typeof r["id"] === "string" && typeof r["branch"] === "string") byId.set(r["id"], { branch: r["branch"], ok: r["ok"] === true, ...(typeof r["reason"] === "string" ? { reason: r["reason"] } : {}) });
  }
  return byId;
}

/**
 * joinDestResolution adds `resolution` to each red replication destination row, each replica-target-fault ring
 * row and each span that has a destinationId. PURE: returns new values and leaves its input untouched.
 *
 * @param destResolution - the destResolution section object (its resolution[] list is the join source).
 * @param parts - the projected downpipes rows, the sealFaults rows and the sealFaultSpans section object.
 * @returns the same three parts with the resolution joined on.
 */
export function joinDestResolution(destResolution: Row, parts: DestJoinParts): DestJoinParts {
  const byId = lookup(destResolution);
  if (byId === null) return parts;
  const resolve = (id: unknown): Row | "not-listed" => (typeof id === "string" ? byId.get(id) : undefined) ?? "not-listed";
  const downpipes = parts.downpipes.map((d) => {
    const repl = d["replication"] as { destinations?: unknown } | undefined;
    if (!repl || !Array.isArray(repl.destinations)) return d;
    const destinations = (repl.destinations as Row[]).map((r) => (r["ok"] === false ? { ...r, resolution: resolve(r["id"]) } : r));
    return { ...d, replication: { ...repl, destinations } };
  });
  const sealFaults = parts.sealFaults.map((f) => {
    const r = f as Row;
    return r["kind"] === "replica-target-fault" ? { ...r, resolution: resolve(r["destinationId"]) } : f;
  });
  const spans = parts.sealFaultSpans["spans"];
  const sealFaultSpans = Array.isArray(spans)
    ? { ...parts.sealFaultSpans, spans: (spans as Row[]).map((s) => (typeof s["destinationId"] === "string" ? { ...s, resolution: resolve(s["destinationId"]) } : s)) }
    : parts.sealFaultSpans;
  return { downpipes, sealFaults, sealFaultSpans };
}
