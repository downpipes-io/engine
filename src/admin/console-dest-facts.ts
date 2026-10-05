// The console-set destination facts buildStatus needs to answer "is a destination configured".
//
// buildStatus (status.ts) is a pure projection of env plus what a caller hands it. env holds only a
// deploy-time destination, and the destination the Focus Flow sets lives in the scheduler DO's stored
// collection. A caller that passes nothing therefore reads "no destination" on every estate whose
// destination was set in the console. The posture checks did exactly that, so the Security Centre showed a
// critical destination-configured fail while /admin/status read the same estate as configured.
//
// This reads the DEFAULT destination of the stored collection through GET /dest-status, the same read
// /admin/status (router-status.ts) and the support pack (support-sections-runs.ts fetchStatusDoOpts) make,
// with the same rule: a source:"deploy" record is the synthetic stand-in for the env destination
// (ensureDeployDestSeeded) and is not a console destination.

import { doURL } from "../do-url.ts";
import type { BuildStatusOptions } from "./status.ts";

/** The two console-destination facts buildStatus reads. Both are absent when the DO read fails. */
export type ConsoleDestFacts = Pick<BuildStatusOptions, "consoleDestSet" | "consoleDestHost">;

/**
 * Reads whether a console-set destination is the default, and its endpoint host, from the scheduler DO.
 * Presence-safe: a DO fault leaves both facts absent, so buildStatus falls back to the env facts rather
 * than failing the caller's read.
 *
 * @param scheduler - the scheduler DO stub.
 * @returns the facts to spread into buildStatus's options.
 */
export async function readConsoleDestFacts(scheduler: DurableObjectStub): Promise<ConsoleDestFacts> {
  const facts: ConsoleDestFacts = {};
  try {
    const resp = await scheduler.fetch(doURL("/dest-status"), { method: "GET" });
    const { present, endpointHost, source } = (await resp.json()) as { present?: boolean; endpointHost?: string; source?: string };
    if (typeof present === "boolean") facts.consoleDestSet = present && source !== "deploy";
    if (typeof endpointHost === "string") facts.consoleDestHost = endpointHost;
  } catch {
    // Presence-safe: leave the facts absent so the env facts answer alone.
  }
  return facts;
}
