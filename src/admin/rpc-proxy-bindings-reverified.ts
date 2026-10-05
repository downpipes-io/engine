// rpc-proxy-bindings-reverified.ts -- the sign-off list test/validate-rpc-binding-tripwire.ts checks
// before it will let a `[[services]]` or `[[dispatch_namespaces]]` wrangler.toml binding pass.
//
// WHY THIS EXISTS. enumerateBoundSources (router-sources.ts) classifies a binding as a Secrets Store
// source when its runtime value answers "yes" to three or more of five mutually exclusive method-name
// groups plus .get -- correct for every binding kind the engine deploys today because each is a native
// object with a small, fixed method set. A Workers RPC stub (a `[[services]]` binding whose target is a
// WorkerEntrypoint/RpcTarget, or a `[[dispatch_namespaces]]` binding) is implemented as a JavaScript
// Proxy with a wildcard trap instead, so it can answer "yes" to every group at once for the same
// structural reason a Secrets Store binding did. See
// test/validate-rpc-binding-tripwire.ts for the full account and the tripwire this list feeds.
//
// ADDING A NAME HERE is a claim, not a formality: it says enumerateBoundSources has been re-verified
// against a REAL Proxy-shaped double (test/validate-rpc-stub-classification.ts, built with a genuine
// `new Proxy(target, { get: ... })` wildcard trap) for this exact binding, and the classification it
// produces is the one you intend. Do not add a name here to silence the tripwire without having done
// that -- the tripwire's only job is to make skipping this step impossible to do by accident.
export const REVERIFIED_PROXY_BINDINGS: ReadonlySet<string> = new Set([
  // (empty today; no [[services]] or [[dispatch_namespaces]] binding is declared anywhere in this repo)
]);
