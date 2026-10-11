// THE CONSOLE-HOSTNAME POSTURE CHECK. It reads one fact the router can see and the scheduler DO cannot: the
// hostname of the configured CONSOLE_ORIGIN. The engine does not probe the console over HTTP, so this is a
// reading of configuration, never of the live edge.
//
// It lives in its own file because posture-checks.ts sits at its size ceiling. It imports only the leaf
// posture-types.ts, so it closes no import cycle.

import type { CheckDraft, PostureInput } from "./posture-types.ts";

// consoleOnWorkersDev reads the hostname of CONSOLE_ORIGIN. true = a workers.dev hostname (the dotted suffix
// is matched, so notworkers.dev and workers.dev.example.com are other hosts); false = any other https
// hostname. undefined = unset, unparseable or not https, so the check is left out rather than graded on a
// value nobody observed. URL lower-cases the hostname, so the match is case-insensitive.
export function consoleOnWorkersDev(origin: string | undefined): boolean | undefined {
  if (typeof origin !== "string" || !URL.canParse(origin.trim())) return undefined;
  const u = new URL(origin.trim());
  if (u.protocol !== "https:" || u.hostname === "") return undefined;
  return u.hostname === "workers.dev" || u.hostname.endsWith(".workers.dev");
}

// consoleOriginSlice is the slice the router forwards: the verdict, or nothing when the origin is not readable.
export function consoleOriginSlice(origin: string | undefined): { consoleOnWorkersDev?: boolean } {
  const v = consoleOnWorkersDev(origin);
  return v === undefined ? {} : { consoleOnWorkersDev: v };
}

// console-on-workers-dev (low, ISO 27001 A.8.20 / A.8.24): whether the console is served on a workers.dev
// hostname. A workers.dev console is a supported way to start, so this is recommended hardening and not a
// vulnerability. Omitted when the origin is not readable (see consoleOnWorkersDev).
export function buildConsoleOnWorkersDev(input: PostureInput): CheckDraft | null {
  const onWorkersDev = input.status.consoleOnWorkersDev;
  if (onWorkersDev === undefined) return null;
  return {
    id: "console-on-workers-dev",
    title: "Console on your own domain",
    control: "ISO 27001 A.8.20 / A.8.24",
    auto: onWorkersDev ? "fail" : "pass",
    detail: onWorkersDev
      ? "The console is served on a workers.dev hostname, so the edge TLS floor and cipher suites are Cloudflare's platform defaults rather than settings you control on your zone, and the console has no hostname of your own for Cloudflare Access."
      : "The console is served on a hostname of your own, so you can set the TLS floor and cipher suites on your zone and put Cloudflare Access on that hostname.",
    remediation: onWorkersDev
      ? "Move the console to a custom domain on a zone you control: in the console wrangler.toml, set a route with custom_domain = true and workers_dev = false, and set the engine CONSOLE_ORIGIN to that origin. Then set Minimum TLS 1.2 on that zone (free) and, optionally, the Modern cipher suite preset (it needs Cloudflare Advanced Certificate Manager)."
      : "No action required.",
    how: "Reads the hostname of the configured CONSOLE_ORIGIN and checks whether it ends in .workers.dev. It does not probe the live edge and does not read your zone's TLS settings. Omitted when CONSOLE_ORIGIN is unset, unparseable or not https.",
  };
}
