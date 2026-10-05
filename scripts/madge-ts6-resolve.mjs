// Resolve hook for `npm run lint:circular`. It gives madge's parser the TypeScript 6 compiler API.
//
// WHY. The "typescript" package is 7.x. Its root export holds only `version` and `versionMajorMinor`,
// because the 7.x line ships no JavaScript compiler API. madge parses .ts files through
// detective-typescript and @typescript-eslint/typescript-estree, and both call require("typescript") and
// use the classic API (createSourceFile, sys, and so on). The repo's .npmrc sets legacy-peer-deps, so npm
// does not install their typescript peer, and the require finds the 7.x package at the root and throws.
// npm cannot place a 6.x copy beside them: madge's own typescript peer must sit at the root, and the root
// name is taken by 7.x.
//
// WHAT IT DOES. It redirects a "typescript" or "typescript/..." specifier to @typescript/typescript6
// ONLY when normal resolution lands on the root 7.x package. A package that carries its own nested
// typescript (filing-cabinet, precinct and dependency-tree each nest a 5.x copy) still gets that copy.
// The result is the resolution madge had when the root package was 6.x.
//
// Usage: node --import ./scripts/madge-ts6-resolve.mjs node_modules/madge/bin/cli.js <madge args>

import { registerHooks } from "node:module";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const rootTs = pathToFileURL(join(process.cwd(), "node_modules", "typescript") + "/").href;
const ts6 = import.meta.resolve("@typescript/typescript6");

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier !== "typescript" && !specifier.startsWith("typescript/")) {
      return nextResolve(specifier, context);
    }
    let landed;
    try {
      landed = nextResolve(specifier, context);
    } catch (err) {
      // The 7.x exports map refuses a subpath such as typescript/lib/tsserverlibrary. That refusal is
      // itself proof that resolution reached the root 7.x package.
      if (err?.code !== "ERR_PACKAGE_PATH_NOT_EXPORTED") throw err;
      landed = { url: rootTs };
    }
    if (!landed.url.startsWith(rootTs)) return landed;
    if (specifier === "typescript") return { url: ts6, shortCircuit: true };
    const sub = specifier.slice("typescript/".length);
    return nextResolve(`@typescript/old/${sub}`, { ...context, parentURL: ts6 });
  },
});
