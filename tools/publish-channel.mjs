// Vendor-side update-channel publisher. It produces the SIGNED version-channel document the
// downpipe engine's checkUpdates already verifies (src/admin/updates.ts), and prints the
// channel JSON, its detached .sig, the UPDATE_SIGNER_PUBLIC to pin, and the UPDATE_CHANNEL_URL
// note. This is the vendor's private side: it lives in the engine REPO (versioned, tested,
// reviewable) but never in the shipped bundle (the bundle is built from src/ only), the engine
// only ever PULLS this document in-account and verifies it, and the vendor never pushes. No
// network, no deploy; signing is local and offline.
//
// THE EXACT CONTRACT (read from engine/src/admin/updates.ts, do not drift):
//  - The channel is a JSON document { channel, recommendedVersion, artefacts?: [{ version,
//    sha384?, url?, notes? }] }. checkUpdates surfaces the notes of the artefact whose version
//    equals recommendedVersion, and updateAvailable is recommendedVersion !== the engine's own
//    ENGINE_VERSION.
//  - The signature is the detached hybrid Ed25519 + ML-DSA-87 signature edSig(64) ||
//    mldsaSig(4627) over EXACTLY the channel document bytes, the SAME hybrid scheme as
//    everything else (both halves required, neither strippable).
//  - The engine fetches the body at UPDATE_CHANNEL_URL and the signature at
//    UPDATE_CHANNEL_URL + ".sig". The .sig file content is base64url-no-pad over the signature
//    bytes; the engine trims it and base64url-decodes it. So the .sig file is one base64url
//    line.
//  - UPDATE_SIGNER_PUBLIC is the PINNED release-signer public key the signature is verified
//    against: ed25519(32) || ML-DSA-87 public(2592) = 2624 bytes, base64url-no-pad. Pinning is
//    the whole security model here (UPDATES.md): a compromised channel host cannot substitute
//    an unsigned or wrong-signer document because the engine checks this exact pinned key.
//
// BYTE-EXACTNESS: verifyChannel verifies the signature over the bytes it FETCHED and then
// JSON.parse()s those same bytes; it does not canonicalise. So this tool signs EXACTLY the
// bytes it emits as the channel file (a stable two-space-indented JSON.stringify), and the
// operator must publish those bytes verbatim. Re-serialising or pretty-reformatting the
// published file after signing would invalidate the signature.
//
// Every byte encoding and the signer derivation are imported from the engine source so the
// publisher and the verifier can never drift: loadSigner gives the same Ed25519 CryptoKey +
// public halves the engine derives from a SIGNER_PRIVATE-shaped private, hybridSign is the
// same detached hybrid signer, b64urlEncode is the same house encoding. Node 25 runs the
// engine .ts source directly under strip-types, and those modules resolve their @noble deps
// against the engine's own node_modules.
//
// THE DEPLOYABLE BUNDLE (for the in-console safe-apply update harness): pass --build to produce the
// engine bundle the SAME way a real deploy does (wrangler's dry-run — the exact bytes `wrangler deploy`
// would push), or --bundle <path> to ingest one you built yourself. Either way this tool computes the
// bundle's SHA-384 with the engine's own hash and writes url + sha384 (+ mainModule) into the SIGNED
// channel, so a deployed engine downloads the bundle from --url and verifies it byte-for-byte against the
// signed hash before deploying it. --url is REQUIRED with a bundle (where you will host the bytes).
//
// Usage:
//   # FULL safe-apply publish: build the bundle (wrangler dry-run), sign the channel that points at it,
//   # write everything ready to upload to the channel host (e.g. the update.downpipes.io R2 bucket):
//   node tools/publish-channel.mjs --key "$RELEASE_SIGNER_PRIVATE" --version 0.2.0 --build \
//       --url https://update.downpipes.io/engine-0.2.0.mjs \
//       --out channel.json --out-sig channel.json.sig --out-bundle engine-0.2.0.mjs
//   # then upload all three to the host: stable.json (the channel), stable.json.sig, engine-0.2.0.mjs
//
//   # ingest a bundle you built yourself (the canonical way: `wrangler deploy --dry-run --outdir dist`):
//   node tools/publish-channel.mjs --key "$RELEASE_SIGNER_PRIVATE" --version 0.2.0 \
//       --bundle dist/index.js --url https://update.downpipes.io/engine-0.2.0.mjs \
//       --out channel.json --out-sig channel.json.sig --out-bundle engine-0.2.0.mjs
//
//   # a release that changes Durable Object classes (the harness must NOT auto-apply it — manual only):
//   node tools/publish-channel.mjs --key "$KEY" --version 0.3.0 --build --requires-migration \
//       --url https://update.downpipes.io/engine-0.3.0.mjs --out channel.json --out-sig channel.json.sig --out-bundle engine-0.3.0.mjs
//
//   # generate a FRESH release-signer keypair the first time (persist it; the private is SECRET):
//   node tools/publish-channel.mjs --version 0.2.0 --build --url https://update.downpipes.io/engine-0.2.0.mjs \
//       --out channel.json --out-sig channel.json.sig --out-bundle engine-0.2.0.mjs --out-key release-signer.key
//
//   # sign with a seed that is SEALED on disk (age, hardware-key-gated) -- decrypt straight into the
//   # tool's stdin so the plaintext seed never touches a file:
//   age -d -i yubikey-identity.txt release-signer.key.age | node tools/publish-channel.mjs \
//       --signer-seed-stdin --version 0.2.0 --build --url https://update.downpipes.io/engine-0.2.0.mjs \
//       --out channel.json --out-sig channel.json.sig --out-bundle engine-0.2.0.mjs --sequence <n>
//
//   # channel-only (no bundle): notify of a version WITHOUT enabling in-console apply (manual deploy):
//   node tools/publish-channel.mjs --key "$KEY" --version 0.2.0 --notes "perf + fixes"
//
//   # a RICH release: declare the W2 metadata so the engine shows "what's in this update" and applies the
//   # right risk class (omit --risk-class and it safely normalises to migration-gated). Flags are repeatable:
//   node tools/publish-channel.mjs --key "$KEY" --version 0.2.0 --build \
//       --url https://update.downpipes.io/engine-0.2.0.mjs --out channel.json --out-sig channel.json.sig --out-bundle engine-0.2.0.mjs \
//       --risk-class routine --min-engine-version 0.1.0 --compat "requires the 0.2 config schema" --released-now \
//       --changelog "fix:tighten the seal" --changelog "security:rotate the canary key" \
//       --impact "Brief admin blip during promote (seconds)." --impact "No change to backups or restore." \
//       --required-step-blocking "Re-pin LICENCE_SIGNER_PUBLIC after this release."
//
//   # ...or pass the same metadata as a JSON config and let CLI flags override per field:
//   node tools/publish-channel.mjs --key "$KEY" --version 0.2.0 --build --url https://update.downpipes.io/engine-0.2.0.mjs \
//       --out channel.json --out-sig channel.json.sig --out-bundle engine-0.2.0.mjs --meta-file release-0.2.0.json
//
// SIGNER SEED CUSTODY: the release-signer seed can reach this tool three ways -- --key (inline,
// test/bootstrap use only), --key-file <path> (a plaintext seed file on disk), or --signer-seed-stdin
// (reads the seed off STDIN, the SAME base64url bytes a --key-file would hold, so a caller can pipe a
// decrypted secret straight in without ever writing it to disk):
//   age -d -i yubikey-identity.txt release-signer.key.age | node tools/publish-channel.mjs \
//       --signer-seed-stdin --version 0.3.0 --channel stable --sequence <n> ...
// The three are mutually exclusive (an error names which flags collided); passing
// --signer-seed-stdin with nothing piped in (a closed or empty stdin) is refused loudly rather than
// silently falling through to fresh-key generation, which would sign with the WRONG key with no
// warning. Omitting all three still generates a fresh signer, unchanged (first-time bootstrap).
//
// Flags: --build (bundle via wrangler dry-run) | --bundle <path> | --engine-dir <path> (default ../engine)
//   | --main-module <name> (default index.js) | --url <https> | --out-bundle <path> | --requires-migration
//   W2 metadata (all optional, additive; omitted fields are absent in the document, riskClass then safely
//   normalises to migration-gated in the engine): --risk-class <routine|migration|breaking>
//   | --changelog "type:text" (repeatable) | --impact "line" (repeatable)
//   | --required-step "text" / --required-step-blocking "text" (repeatable; blocking forces a console ack)
//   | --min-engine-version <semver> | --compat "<note>" | --released-at <RFC-3339> | --released-now
//   | --meta-file <path.json> (a JSON object of the same fields; CLI flags override it per field)
//   CONSOLE component (multi-component updates, design/updates/MULTI-COMPONENT-UPDATES-DESIGN.md):
//   --console-build (package the console via its npm build + wrangler dry-run) | --console-bundle <path>
//   | --console-dir <path> (default ../console) | --console-url <https> (required with a console artefact)
//   | --console-version <v> (default: console package.json) | --out-console-bundle <path>
//   | --console-risk-class <routine|migration|breaking> | --console-changelog "type:text" (repeatable)
//   | --console-impact "line" (repeatable) | --console-min-engine-version <semver> | --console-notes "text"
//   The console artefact goes into the v2 `components` map, NEVER into artefacts[] (a 0.1.x engine
//   would select a same-version artefacts[] entry and deploy console bytes onto the engine script).
//
// FRESHNESS / ANTI-REPLAY (DP-0): every publish carries `sequence` (a monotonically increasing
// integer) and `issuedAt` (ISO time) INSIDE the signed body. Fielded engines already enforce
// them when present (checkChannelFreshness): once a customer's engine has accepted a sequenced
// channel, a replayed older descriptor is refused. The FIRST sequenced publish sets that
// baseline fleet-wide, so it must be a deliberate act, not a side effect:
//   --sequence <int>         the channel sequence; must exceed the last published one
//   --sequence-state <path>  JSON state file remembering the last published sequence
//                            (default: channel-sequence.json beside --key-file when given);
//                            the tool REFUSES a sequence at or below the recorded one and
//                            advances the file only after a successful self-verified emit
//   --issued-at <iso>        override the issuedAt stamp (defaults to now; for tests)
//   --allow-unsequenced      explicit opt-out (emits a channel WITHOUT the freshness pair,
//                            the pre-DP-0 shape; refused otherwise so it cannot be forgotten)
//
// ATTESTED CEREMONY MODE (DP-A, the dual-root rule: the offline key refuses bytes CI did not
// attest). Download each component's release tree first (gh release download vX.Y.Z -D <dir>),
// then:
//   --from-release-dir <dir>      ingest + verify the ENGINE release tree (digests vs
//                                 release-facts.json + SHA256SUMS.txt, SLSA subjects + builder,
//                                 cosign keyless bundles under the PINNED release-workflow
//                                 identity) and sign exactly those bytes; replaces --build/--bundle
//   --console-release-dir <dir>   same for the CONSOLE release tree; replaces --console-build/
//                                 --console-bundle
//   --provenance-out-dir <dir>    REQUIRED with either: writes provenance/<version>/ (attestation
//                                 sidecars + release-record.json) exactly where the signed
//                                 channel's provenance paths point; publish it with the channel
//   PUBLISH_CHANNEL_COSIGN        env: the cosign binary (default "cosign"; a missing verifier is
//                                 a refusal, never a skip)
// The signed channel then carries per-component `provenance` blocks (commit, tag, run, Rekor log
// index, channel-relative attestation paths), so the offline hybrid signature transitively vouches
// for the provenance pointers and a customer verifies everything from the channel host alone.
//
// Output is a JSON document on stdout: { channel, signature, updateSignerPublic,
// updateChannelUrlNote, releaseSignerPrivate?, recommendedVersion }. Pin updateSignerPublic as
// UPDATE_SIGNER_PUBLIC in the customer's account, publish `channel` verbatim at a stable HTTPS
// URL, publish `signature` at that URL + ".sig", and set UPDATE_CHANNEL_URL to the body URL.
// Keep releaseSignerPrivate secret.

import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync, statSync, mkdirSync, copyFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadSigner } from "../src/keys-env.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { parseVerifier } from "../src/crypto/keys.ts";
import { b64urlEncode, b64urlDecode, concat, utf8, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { verifyChannel } from "../src/admin/updates.ts";

// The tools/ directory, used to resolve the engine package when --build shells wrangler's dry-run.
const TOOLS_DIR = path.dirname(fileURLToPath(import.meta.url));

// parseArgs reads --flag value / --flag=value pairs into a plain object. Bare flags become
// true. Intentionally tiny: no dependency, no positional surprises. Mirrors issue-licence.mjs.
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq >= 0) {
      out[a.slice(2, eq)] = a.slice(eq + 1);
    } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
      out[a.slice(2)] = argv[++i];
    } else {
      out[a.slice(2)] = true;
    }
  }
  return out;
}

// collectRepeated returns EVERY value passed for a repeatable --flag (e.g. --impact one --impact two), in
// order, as an array of strings. parseArgs keeps only the LAST occurrence of a key, which is right for
// scalars but wrong for the rich-metadata flags that may be given several times (each --changelog /
// --impact / --required-step is one list entry). So this rescans argv for that one flag. Values are the
// token after the flag, or the right side of --flag=value; a bare repeated flag with no value is skipped.
// Pure; no dependency, mirrors parseArgs' tiny style.
function collectRepeated(argv, flag) {
  const out = [];
  const eqPrefix = `--${flag}=`;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === `--${flag}`) {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) out.push(argv[++i]);
    } else if (a.startsWith(eqPrefix)) {
      out.push(a.slice(eqPrefix.length));
    }
  }
  return out;
}

// readSignerSeedFromStdin reads the pinned release-signer seed off STDIN (fd 0) as the --signer-seed-stdin
// source: the EXACT same base64url text a --key-file would hold (loadSigner trims and decodes it the same
// way either source arrives). This is how the seed reaches the tool for a real promote WITHOUT a plaintext
// copy of it ever landing on disk: pipe an `age -d` decryption straight in. Reading is synchronous (this is
// a one-shot CLI; there is no event loop to preserve) via fd 0, matching the tool's existing sync-I/O style.
// A closed/empty stdin (a TTY with nothing piped, or a decrypt that produced no bytes) is refused with an
// actionable message rather than left to silently fall through to fresh-key generation. Signing with a
// freshly generated key when the operator meant to use the pinned one would be a wrong-key publish with no
// warning, exactly the failure this flag exists to prevent.
function readSignerSeedFromStdin() {
  let raw;
  try {
    raw = readFileSync(0, "utf8");
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    throw new Error(`--signer-seed-stdin could not read stdin (${reason}). Pipe the seed in, e.g. \`age -d -i yubikey-identity.txt release-signer.key.age | node tools/publish-channel.mjs --signer-seed-stdin ...\`.`);
  }
  const trimmed = raw.trim();
  if (trimmed === "") {
    throw new Error("--signer-seed-stdin was given but stdin carried no bytes; nothing was signed. Pipe the seed in rather than running this flag against an empty or closed stdin.");
  }
  return trimmed;
}

// RISK_CLASSES is the closed set the engine accepts (engine/src/admin/updates.ts RiskClass / RISK_CLASSES).
// publish-channel only ever EMITS one of these (or omits the field); it never invents a value. An absent
// riskClass is intentionally left OUT of the document so the engine's normaliseRiskClass applies its SAFE
// default (migration-gated) — the tool must never weaken that fail-safe by emitting a fabricated "routine".
const RISK_CLASSES = ["routine", "migration", "breaking"];

// parseChangelogEntry turns one --changelog token into a ChangelogEntry { type, text } (engine
// updates.ts ChangelogEntry). The form is "type:text" — the type is the part before the FIRST colon
// (fix | feature | security | other; passed through as-is, it is display grouping, not an authority
// boundary), the text is the remainder. A token with no colon is treated as type "other" with the whole
// token as the text. The text is trimmed; an empty text after trimming is rejected loudly.
function parseChangelogEntry(token) {
  const i = token.indexOf(":");
  const type = i >= 0 ? token.slice(0, i).trim() : "other";
  const text = (i >= 0 ? token.slice(i + 1) : token).trim();
  if (text === "") throw new Error(`--changelog "${token}" has no text (use type:text, e.g. fix:tighten the seal)`);
  return { type: type === "" ? "other" : type, text };
}

// buildRichMetadata assembles the OPTIONAL, ADDITIVE W2 release metadata the engine surfaces as
// "what's in this update" (engine/src/admin/updates.ts Artefact, fields riskClass / changelog / impact /
// requiredSteps / minEngineVersion / compat / releasedAt). It reads from a --meta-file JSON config (if
// given) as the BASE, then lets explicit CLI flags OVERRIDE per field, matching the script's existing
// "flag, else default" style. Every field is built ONLY when provided, so the emitted document carries no
// empty placeholders (an old-style channel-only publish stays byte-identical). It returns a plain object to
// spread onto the artefact, plus validates the inputs (a bad riskClass or empty changelog text fails loudly
// rather than emitting a malformed-but-signed document). It NEVER defaults riskClass: omission is delegated
// to the engine's safe normalisation.
function buildRichMetadata(args, argv) {
  // The --meta-file config input (matching the task's "CLI flags or a config input"): a JSON object whose
  // keys are exactly the engine Artefact metadata fields. CLI flags override it field-by-field.
  let cfg = {};
  if (typeof args["meta-file"] === "string") {
    const raw = readFileSync(args["meta-file"], "utf8");
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new Error(`--meta-file is not valid JSON (${args["meta-file"]}): ${e.message}`);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`--meta-file must be a JSON object of metadata fields (${args["meta-file"]})`);
    }
    cfg = parsed;
  }

  const out = {};

  // riskClass — validated against the closed set; flag wins over the config. Absent => left OUT (the engine
  // safely normalises an absent riskClass to migration-gated; the tool must not fabricate a value).
  const riskClass = typeof args["risk-class"] === "string" ? args["risk-class"] : cfg.riskClass;
  if (riskClass !== undefined) {
    if (!RISK_CLASSES.includes(riskClass)) {
      throw new Error(`--risk-class must be one of ${RISK_CLASSES.join(" | ")} (got "${riskClass}"). Omit it to let the engine apply its safe migration-gated default.`);
    }
    out.riskClass = riskClass;
  }

  // changelog — repeatable --changelog "type:text"; else the config's changelog array (validated). [] is
  // omitted (no empty array in the document).
  const clTokens = collectRepeated(argv, "changelog");
  if (clTokens.length > 0) {
    out.changelog = clTokens.map(parseChangelogEntry);
  } else if (Array.isArray(cfg.changelog) && cfg.changelog.length > 0) {
    out.changelog = cfg.changelog.map((e) => {
      if (e && typeof e === "object" && typeof e.text === "string" && e.text.trim() !== "") {
        return { type: typeof e.type === "string" && e.type.trim() !== "" ? e.type : "other", text: e.text };
      }
      throw new Error("--meta-file changelog entries must be { type, text } with a non-empty text");
    });
  }

  // impact — repeatable --impact "line"; else the config's impact array of strings.
  const impactTokens = collectRepeated(argv, "impact");
  if (impactTokens.length > 0) {
    out.impact = impactTokens;
  } else if (Array.isArray(cfg.impact) && cfg.impact.length > 0) {
    if (!cfg.impact.every((s) => typeof s === "string")) throw new Error("--meta-file impact must be an array of strings");
    out.impact = cfg.impact;
  }

  // requiredSteps — repeatable --required-step "text" (non-blocking) and --required-step-blocking "text"
  // (blocking:true, forces a console acknowledgement). Else the config's requiredSteps array. blocking is
  // emitted only when true (the engine treats absence as non-blocking).
  const stepTokens = collectRepeated(argv, "required-step").map((text) => ({ text }));
  const blockingStepTokens = collectRepeated(argv, "required-step-blocking").map((text) => ({ text, blocking: true }));
  const cliSteps = [...stepTokens, ...blockingStepTokens];
  if (cliSteps.length > 0) {
    for (const s of cliSteps) if (s.text.trim() === "") throw new Error("a --required-step / --required-step-blocking needs non-empty text");
    out.requiredSteps = cliSteps;
  } else if (Array.isArray(cfg.requiredSteps) && cfg.requiredSteps.length > 0) {
    out.requiredSteps = cfg.requiredSteps.map((s) => {
      if (s && typeof s === "object" && typeof s.text === "string" && s.text.trim() !== "") {
        return s.blocking === true ? { text: s.text, blocking: true } : { text: s.text };
      }
      throw new Error("--meta-file requiredSteps entries must be { text, blocking? } with a non-empty text");
    });
  }

  // minEngineVersion — the compat floor (the engine REFUSES to apply onto an older engine). Scalar; flag
  // wins. compat — the human note paired with it. Both only when non-empty.
  const minEngineVersion = typeof args["min-engine-version"] === "string" ? args["min-engine-version"] : cfg.minEngineVersion;
  if (typeof minEngineVersion === "string" && minEngineVersion.trim() !== "") out.minEngineVersion = minEngineVersion.trim();
  const compat = typeof args.compat === "string" ? args.compat : cfg.compat;
  if (typeof compat === "string" && compat.trim() !== "") out.compat = compat;

  // releasedAt — RFC-3339 timestamp (for "released N days ago" + the W3 alert). --released-at <value>, or
  // --released-at with no value / --released-now defaults to NOW (this machine's clock, ISO-8601 UTC). Else
  // the config's releasedAt. We do NOT default it silently when unspecified (absence is honest: unknown).
  let releasedAt;
  if (args["released-at"] === true || args["released-now"]) {
    releasedAt = new Date().toISOString();
  } else if (typeof args["released-at"] === "string" && args["released-at"].trim() !== "") {
    releasedAt = args["released-at"].trim();
  } else if (typeof cfg.releasedAt === "string" && cfg.releasedAt.trim() !== "") {
    releasedAt = cfg.releasedAt.trim();
  }
  if (releasedAt !== undefined) out.releasedAt = releasedAt;

  return out;
}

// buildBundleViaWrangler produces the deployable engine bundle the SAME way a real deploy does — wrangler's
// dry-run, which bundles EXACTLY what `wrangler deploy` would, locally, with no network and no auth. The
// resulting single module is the artefact the engine's safe-apply harness uploads as the new version's
// main module, so using wrangler's own output is what makes the published bytes match a genuine deploy.
// Returns the bundle bytes (Uint8Array). Throws with actionable guidance on any failure. mainModule is the
// entry filename wrangler writes (defaults to index.js for main = src/index.ts).
function buildBundleViaWrangler(engineDir, mainModule) {
  const outDir = mkdtempSync(path.join(tmpdir(), "downpipe-bundle-"));
  try {
    // --dry-run --outdir writes the bundled worker without deploying. stdio inherits stderr so wrangler's
    // own diagnostics surface; stdout is ignored (we read the file, not the log).
    execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", outDir], { cwd: engineDir, stdio: ["ignore", "ignore", "inherit"] });
    const entry = path.join(outDir, mainModule);
    if (!existsSync(entry)) {
      const present = readdirSync(outDir).join(", ");
      throw new Error(`wrangler's dry-run produced no "${mainModule}" (found: ${present || "nothing"}). If it emitted multiple modules, the single-module self-update cannot use them as-is — pass a single pre-built module with --bundle, or set --main-module to the entry wrangler produced.`);
    }
    return new Uint8Array(readFileSync(entry));
  } catch (e) {
    if (e && e.code === "ENOENT") throw new Error("could not run wrangler (is it installed in the engine package?). Build the bundle yourself and pass it with --bundle <path>, e.g. `npx wrangler deploy --dry-run --outdir dist` then --bundle dist/index.js.");
    throw e;
  } finally {
    try { rmSync(outDir, { recursive: true, force: true }); } catch { /* best effort cleanup */ }
  }
}

// ---- CONSOLE bundle packaging (multi-component updates, design/updates/MULTI-COMPONENT-UPDATES-DESIGN.md §4) ----
// The console component is a "static-assets" deploy (shell worker + Workers Static Assets), so its
// artefact is a single self-describing JSON file — format "downpipe-console-bundle/1" — whose EXACT
// bytes are hashed into the signed channel. Bindings are deliberately NOT captured here: the engine
// preserves the live console script's bindings (the ENGINE service binding, vars) at apply time, so
// one artefact serves every install. Only version-controlled static config rides along.

const CONSOLE_ASSET_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".json", "application/json"],
  [".txt", "text/plain; charset=utf-8"],
  [".png", "image/png"],
  [".ico", "image/x-icon"],
  [".woff2", "font/woff2"],
]);
function contentTypeFor(p) {
  return CONSOLE_ASSET_TYPES.get(path.extname(p).toLowerCase()) ?? "application/octet-stream";
}

// walkAssets returns every file under dir as a SORTED list of "/"-prefixed POSIX-relative paths.
// Sorting is what makes the packaged bundle byte-reproducible for identical inputs.
function walkAssets(dir, base = dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkAssets(p, base, out);
    else out.push("/" + path.relative(base, p).split(path.sep).join("/"));
  }
  return out.sort();
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// ---- DP-A: attested-release ingestion (the dual-root ceremony's CI half) --------------------------
// The ceremony's rule: the offline hybrid key REFUSES to sign bytes CI did not attest. These helpers
// ingest a downloaded release tree (gh release download vX.Y.Z -D <dir>), re-derive every digest
// locally, check the SLSA provenance subjects and builder, and verify the cosign keyless bundles
// under the PINNED workflow identity, all BEFORE anything is signed. Verification is local (the
// cosign binary talks to Rekor/Fulcio material embedded in the bundle); the tool still makes no
// deploys and no uploads. The cosign binary is required: a missing verifier is a refusal, never a
// skip (override the binary path with PUBLISH_CHANNEL_COSIGN, which the tests use to inject a stub).

// The pinned keyless identities: the exact workflow allowed to have built each component. An org or
// repo compromise that mints from ANOTHER workflow path fails this pin.
const ENGINE_RELEASE_IDENTITY = process.env.PUBLISH_CHANNEL_IDENTITY_ENGINE ?? "^https://github.com/downpipes-io/engine/\\.github/workflows/release\\.yml@refs/tags/v";
const CONSOLE_RELEASE_IDENTITY = process.env.PUBLISH_CHANNEL_IDENTITY_CONSOLE ?? "^https://github.com/downpipes-io/console/\\.github/workflows/release\\.yml@refs/tags/v";
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";

// findReleaseFile resolves a file that may sit flat in the download dir or under dist/ (gh release
// download flattens; a CI artifact download preserves dist/). Returns the path or null.
function findReleaseFile(dir, name) {
  for (const candidate of [path.join(dir, name), path.join(dir, "dist", name)]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

// parseIntotoStatement decodes the FIRST statement of a .intoto.jsonl (a DSSE envelope whose payload
// is base64 JSON) and returns { builderId, subjects: [{name, sha256}] }. Throws with a precise reason
// on any malformation: an unreadable provenance is a refusal, not a shrug.
function parseIntotoStatement(jsonlPath) {
  const firstLine = readFileSync(jsonlPath, "utf8").split("\n").find((l) => l.trim() !== "");
  if (!firstLine) throw new Error(`${jsonlPath} is empty; expected a DSSE envelope per line`);
  const envelope = JSON.parse(firstLine);
  // slsa-github-generator@v2.1.0's *.intoto.jsonl is a Sigstore-bundle-wrapped DSSE envelope
  // ({mediaType, verificationMaterial, dsseEnvelope:{payload,...}}), not a bare one; read both
  // shapes. Never exercised before (the first attested release to reach this ingest).
  const payloadB64 = envelope.dsseEnvelope?.payload ?? envelope.payload ?? envelope.Payload;
  if (typeof payloadB64 !== "string") throw new Error(`${jsonlPath} carries no DSSE payload`);
  const statement = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
  const predicateType = String(statement.predicateType ?? "");
  if (!predicateType.startsWith("https://slsa.dev/provenance/")) {
    throw new Error(`${jsonlPath} predicateType is ${predicateType || "(absent)"}, not a SLSA provenance statement`);
  }
  const builderId = String(statement.predicate?.builder?.id ?? statement.predicate?.runDetails?.builder?.id ?? "");
  const subjects = Array.isArray(statement.subject)
    ? statement.subject.map((s) => ({ name: String(s?.name ?? ""), sha256: String(s?.digest?.sha256 ?? "") }))
    : [];
  return { builderId, subjects };
}

// rekorIndexFromBundle pulls the Rekor transparency-log index out of a cosign sign-blob bundle
// (tolerant across the bundle spellings cosign has used). Absent is tolerated (the signature still
// verified); the channel simply carries no rekorLogIndex for that artefact.
function rekorIndexFromBundle(bundlePath) {
  try {
    const b = JSON.parse(readFileSync(bundlePath, "utf8"));
    const idx = b?.rekorBundle?.Payload?.logIndex ?? b?.rekorBundle?.payload?.logIndex ?? b?.logIndex;
    return idx === undefined || idx === null ? undefined : String(idx);
  } catch {
    return undefined;
  }
}

// cosignVerifyBlob shells the cosign binary to verify one keyless bundle under the pinned identity.
// A missing binary or a failed verification is a REFUSAL with the exact command context.
function cosignVerifyBlob(cosignBin, bundlePath, identityRegexp, filePath) {
  try {
    execFileSync(cosignBin, ["verify-blob", "--bundle", bundlePath, "--certificate-identity-regexp", identityRegexp, "--certificate-oidc-issuer", OIDC_ISSUER, filePath], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (e) {
    if (e && e.code === "ENOENT") {
      throw new Error(`the cosign binary ("${cosignBin}") is not installed; the ceremony REFUSES to sign unverified bytes. Install cosign (https://docs.sigstore.dev) or set PUBLISH_CHANNEL_COSIGN. Nothing was signed.`);
    }
    const stderr = e?.stderr ? String(e.stderr).trim().split("\n").slice(-3).join(" | ") : String(e?.message ?? e);
    throw new Error(`cosign verification FAILED for ${path.basename(filePath)} under identity ${identityRegexp}: ${stderr}. The ceremony refuses to sign bytes CI did not attest; nothing was signed.`);
  }
}

// ingestAttestedRelease loads + fully verifies one component's downloaded release tree and returns
// everything the channel build needs: the artefact bytes, the verified digests, the CI identifiers
// for the provenance block, and the file paths for the sidecar publication. Every failure path is a
// refusal BEFORE signing.
function ingestAttestedRelease({ dir, component, artefactNameFor, identityRegexp, cosignBin }) {
  const factsPath = findReleaseFile(dir, "release-facts.json");
  if (!factsPath) throw new Error(`${dir} has no release-facts.json; download the WHOLE release (gh release download <tag> -D <dir>) so the ceremony can verify what CI built`);
  const facts = JSON.parse(readFileSync(factsPath, "utf8"));
  const version = String(facts.version ?? "");
  if (version === "") throw new Error(`${factsPath} carries no version`);
  const artefactName = artefactNameFor(version);
  const artefactPath = findReleaseFile(dir, artefactName);
  if (!artefactPath) throw new Error(`${dir} has no ${artefactName} (looked flat and under dist/)`);
  const artefactBytes = new Uint8Array(readFileSync(artefactPath));

  // 1. Digests: recompute BOTH locally and hold them against the facts file and the sums manifest.
  const localSha256 = sha256Hex(artefactBytes);
  if (String(facts.sha256 ?? "") !== localSha256) {
    throw new Error(`${artefactName}: local sha256 ${localSha256} does not match release-facts.json (${facts.sha256}); the download is corrupt or tampered. Nothing was signed.`);
  }
  const sumsPath = findReleaseFile(dir, "SHA256SUMS.txt");
  if (!sumsPath) throw new Error(`${dir} has no SHA256SUMS.txt (the canonical sums manifest is part of the attested set)`);
  const sumsLine = readFileSync(sumsPath, "utf8").split("\n").find((l) => l.trim().endsWith(artefactName) || l.includes(`/${artefactName}`));
  if (!sumsLine || !sumsLine.trim().startsWith(localSha256)) {
    throw new Error(`${artefactName}: SHA256SUMS.txt does not name the locally computed digest (${localSha256}); the manifest and the artefact disagree. Nothing was signed.`);
  }

  // 2. SLSA provenance: the artefact digest must be a subject, and the builder must be the SLSA
  // generator (the workflow identity itself is pinned by the cosign check below). This is the
  // tool's own structural check; the runbook additionally runs slsa-verifier for the full
  // cryptographic verification of the provenance envelope.
  const intotoPath = findReleaseFile(dir, `${component}.intoto.jsonl`);
  if (!intotoPath) throw new Error(`${dir} has no ${component}.intoto.jsonl; an unattested release cannot be signed onto the channel`);
  const intoto = parseIntotoStatement(intotoPath);
  if (!intoto.builderId.includes("slsa-framework/slsa-github-generator")) {
    throw new Error(`${component}.intoto.jsonl builder.id is "${intoto.builderId}", not the SLSA GitHub generator; refusing to treat it as build provenance. Nothing was signed.`);
  }
  if (!intoto.subjects.some((s) => s.sha256 === localSha256)) {
    throw new Error(`${component}.intoto.jsonl subjects do not include ${artefactName}'s digest ${localSha256}; the provenance does not cover these bytes. Nothing was signed.`);
  }

  // 3. Keyless signatures under the pinned workflow identity: the artefact bundle and the sums
  // manifest bundle (the sums file names the facts file, so the whole set is covered).
  const artefactBundle = findReleaseFile(dir, `${artefactName}.cosign-bundle`);
  if (!artefactBundle) throw new Error(`${dir} has no ${artefactName}.cosign-bundle; an unsigned artefact cannot be signed onto the channel`);
  cosignVerifyBlob(cosignBin, artefactBundle, identityRegexp, artefactPath);
  const sumsBundle = findReleaseFile(dir, "SHA256SUMS.txt.cosign-bundle");
  if (!sumsBundle) throw new Error(`${dir} has no SHA256SUMS.txt.cosign-bundle`);
  cosignVerifyBlob(cosignBin, sumsBundle, identityRegexp, sumsPath);

  // 4. CI identifiers for the channel's provenance block. These come from the attested facts file
  // (covered by the sums manifest just verified), so they are CI's own claims, not operator input.
  const provenanceFacts = {
    ...(typeof facts.commit === "string" && facts.commit !== "" ? { commit: facts.commit } : {}),
    ...(typeof facts.tag === "string" && facts.tag !== "" ? { tag: facts.tag } : {}),
    ...(typeof facts.repo === "string" && facts.repo !== "" ? { repo: facts.repo } : {}),
    ...(typeof facts.runId === "string" && facts.runId !== "" ? { runId: facts.runId } : {}),
  };
  if (provenanceFacts.commit === undefined || provenanceFacts.runId === undefined) {
    throw new Error(`${factsPath} carries no CI identifiers (commit/runId); was this tree built by the release workflow? A local build cannot be published as an attested release. Nothing was signed.`);
  }
  const rekorLogIndex = rekorIndexFromBundle(artefactBundle);

  return {
    version,
    artefactPath,
    artefactBytes,
    files: { factsPath, sumsPath, intotoPath, artefactBundle, sumsBundle },
    provenanceFacts: { ...provenanceFacts, ...(rekorLogIndex !== undefined ? { rekorLogIndex } : {}) },
  };
}

// readConsoleStaticConfig pulls the version-controlled deploy facts out of the console's committed
// wrangler.toml (the same minimal-regex style sync-bindings.mjs uses for the script name). These are
// facts of the RELEASE (what wrangler.toml would set), not per-install state.
function readConsoleStaticConfig(consoleDir) {
  const toml = readFileSync(path.join(consoleDir, "wrangler.toml"), "utf8");
  const compatibilityDate = toml.match(/^[ \t]*compatibility_date[ \t]*=[ \t]*["']([^"']+)["']/m)?.[1] ?? "2026-06-01";
  const runWorkerFirst = /^[ \t]*run_worker_first[ \t]*=[ \t]*true/m.test(toml);
  const cpuMs = toml.match(/cpu_ms[ \t]*=[ \t]*(\d+)/)?.[1];
  const config = { compatibilityDate, runWorkerFirst };
  if (cpuMs) config.limits = { cpu_ms: Number(cpuMs) };
  return config;
}

// buildConsoleBundle produces the console artefact the SAME way a real deploy would: the console's
// own `npm run build` refreshes public/ (the committed SPA bundle), wrangler's dry-run compiles the
// shell worker exactly as `wrangler deploy` would, and every file under public/ is packaged verbatim
// (per-asset sha256 so the engine can verify each file after decode, on top of the channel-level
// sha384 over the whole artefact). Returns { text, bytes, version }.
function buildConsoleBundle(consoleDir, opts = {}) {
  if (!opts.skipBuild) {
    execFileSync("npm", ["run", "build"], { cwd: consoleDir, stdio: ["ignore", "ignore", "inherit"] });
  }
  const outDir = mkdtempSync(path.join(tmpdir(), "downpipe-console-bundle-"));
  let workerSource;
  try {
    execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", outDir], { cwd: consoleDir, stdio: ["ignore", "ignore", "inherit"] });
    const entry = path.join(outDir, "worker.js");
    if (!existsSync(entry)) {
      const present = readdirSync(outDir).join(", ");
      throw new Error(`the console dry-run produced no worker.js (found: ${present || "nothing"})`);
    }
    workerSource = new Uint8Array(readFileSync(entry));
  } finally {
    try { rmSync(outDir, { recursive: true, force: true }); } catch { /* best effort cleanup */ }
  }
  const pub = path.join(consoleDir, "public");
  if (!existsSync(pub)) throw new Error(`the console public/ directory is missing (${pub}); run the console build first`);
  const assets = walkAssets(pub).map((rel) => {
    const bytes = new Uint8Array(readFileSync(path.join(pub, rel.slice(1))));
    return { path: rel, contentType: contentTypeFor(rel), sha256: sha256Hex(bytes), b64: Buffer.from(bytes).toString("base64") };
  });
  const version = JSON.parse(readFileSync(path.join(consoleDir, "package.json"), "utf8")).version;
  const bundle = {
    format: "downpipe-console-bundle/1",
    version: opts.versionOverride ?? version,
    worker: { mainModule: "worker.js", sourceB64: Buffer.from(workerSource).toString("base64") },
    config: readConsoleStaticConfig(consoleDir),
    assets,
  };
  const text = JSON.stringify(bundle, null, 2);
  return { text, bytes: utf8(text), version: bundle.version };
}

// buildConsoleMetadata mirrors buildRichMetadata for the console component's --console-* flags.
function buildConsoleMetadata(args, argv) {
  const out = {};
  const riskClass = typeof args["console-risk-class"] === "string" ? args["console-risk-class"] : undefined;
  if (riskClass !== undefined) {
    if (!RISK_CLASSES.includes(riskClass)) throw new Error(`--console-risk-class must be one of ${RISK_CLASSES.join(" | ")}`);
    out.riskClass = riskClass;
  }
  const cl = collectRepeated(argv, "console-changelog");
  if (cl.length > 0) out.changelog = cl.map(parseChangelogEntry);
  const impact = collectRepeated(argv, "console-impact");
  if (impact.length > 0) out.impact = impact;
  const minEngine = typeof args["console-min-engine-version"] === "string" ? args["console-min-engine-version"].trim() : "";
  if (minEngine !== "") out.minEngineVersion = minEngine;
  if (typeof args["console-notes"] === "string") out.notes = args["console-notes"];
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write("see the header comment in tools/publish-channel.mjs for usage\n");
    return;
  }

  const recommendedVersion = typeof args.version === "string" ? args.version : undefined;
  if (!recommendedVersion) throw new Error("--version is required (the recommended engine version, e.g. 0.2.0)");
  const channelName = typeof args.channel === "string" ? args.channel : "stable";

  // Resolve the release-signer private (base64url edSeed(32) || ML-DSA-87 seed(32) = 64 bytes, the form
  // loadSigner expects): reuse a pinned one so deployed engines keep verifying, else generate a fresh one.
  // Generation draws OS randomness for BOTH 32-byte seeds (loadSigner expands the ML-DSA seed to the full
  // key); nothing leaves the machine. (Matches issue-licence.mjs — both seeds, never the expanded secret.)
  //
  // Three mutually exclusive sources for a PINNED seed: --key (inline string), --key-file (a plaintext
  // file path) and --signer-seed-stdin (the same bytes, read off stdin so a caller can pipe a
  // just-decrypted secret in without ever writing it to disk, see the header comment). Giving more than
  // one is ambiguous and refused before anything else runs.
  const seedFlagsGiven = ["key", "key-file", "signer-seed-stdin"].filter((f) => f in args);
  if (seedFlagsGiven.length > 1) {
    throw new Error(`--${seedFlagsGiven.join(" and --")} are mutually exclusive: pass exactly one source for the release-signer seed (or none, to generate a fresh one).`);
  }
  let releaseSignerPrivate;
  let generated = false;
  if ("signer-seed-stdin" in args) {
    releaseSignerPrivate = readSignerSeedFromStdin();
  } else {
    const keyArg = typeof args.key === "string" ? args.key : args["key-file"] ? readFileSync(args["key-file"], "utf8") : undefined;
    if (keyArg) {
      releaseSignerPrivate = keyArg.trim();
    } else {
      const edSeed = crypto.getRandomValues(new Uint8Array(32));
      const mldsaSeed = crypto.getRandomValues(new Uint8Array(32));
      releaseSignerPrivate = b64urlEncode(concat(edSeed, mldsaSeed));
      generated = true;
    }
  }

  // loadSigner is the SAME derivation the engine uses: it yields the Ed25519 CryptoKey to sign
  // with and the public halves. The pinned verifier the engine checks against (parseVerifier in
  // updates.ts) is ed25519(32) || ML-DSA-87 public(2592) = 2624 bytes, base64url-no-pad.
  const signer = await loadSigner(releaseSignerPrivate);
  const updateSignerPublic = b64urlEncode(concat(signer.edPublic, signer.mldsaPublic));

  // Resolve the deployable BUNDLE (the artefact the engine's safe-apply harness deploys), if one is
  // requested: --build produces it via wrangler's dry-run (the canonical bytes a real deploy would push),
  // or --bundle <path> ingests one you built yourself. mainModule is the entry filename the harness uploads
  // as the new version's main module (defaults to index.js).
  const mainModule = typeof args["main-module"] === "string" ? args["main-module"] : "index.js";
  const engineDir = typeof args["engine-dir"] === "string" ? args["engine-dir"] : path.join(TOOLS_DIR, "..");
  const cosignBin = process.env.PUBLISH_CHANNEL_COSIGN ?? "cosign";
  let bundleBytes = null;
  let engineRelease = null;
  if (typeof args["from-release-dir"] === "string") {
    // DP-A ceremony mode: sign ONLY what CI attested. Mutually exclusive with the local build
    // paths on purpose: the whole point is that a fresh local build is unattestable.
    if (args.build || typeof args.bundle === "string") {
      throw new Error("--from-release-dir replaces --build/--bundle: the ceremony signs the CI-built, attested bytes, never a fresh local build. Drop the local-build flags.");
    }
    if (typeof args["provenance-out-dir"] !== "string") {
      throw new Error("--provenance-out-dir is required with --from-release-dir: the signed channel embeds provenance/<version>/ paths, so the sidecars must be produced (and published) with the channel or the pointers would dangle.");
    }
    engineRelease = ingestAttestedRelease({
      dir: args["from-release-dir"],
      component: "engine",
      artefactNameFor: (v) => `engine-${v}.mjs`,
      identityRegexp: ENGINE_RELEASE_IDENTITY,
      cosignBin,
    });
    if (engineRelease.version !== recommendedVersion) {
      throw new Error(`--version ${recommendedVersion} does not match the attested release's version ${engineRelease.version}; the channel must name exactly the version CI built. Nothing was signed.`);
    }
    bundleBytes = engineRelease.artefactBytes;
  } else if (args.build) {
    bundleBytes = buildBundleViaWrangler(engineDir, mainModule);
  } else if (typeof args.bundle === "string") {
    bundleBytes = new Uint8Array(readFileSync(args.bundle));
  }

  // Build the artefact for the recommended version. checkUpdates surfaces notes for the artefact whose
  // version === recommendedVersion; the safe-apply harness needs url + sha384 (+ mainModule) to DOWNLOAD
  // and VERIFY the bundle before deploying it. Fields are added conditionally so the document carries no
  // empty placeholders.
  const artefact = { version: recommendedVersion };

  // W2 RICH METADATA (engine/src/admin/updates.ts Artefact): riskClass / changelog / impact / requiredSteps
  // / minEngineVersion / compat / releasedAt — all OPTIONAL + ADDITIVE, and all covered by the SAME detached
  // hybrid signature over the whole channel, so they are tamper-evident with no new trust surface. Without
  // these a real release ingests as migration-gated (the safe default) with an empty "what's in this update"
  // panel; declaring them lets the engine show the changelog/impact and apply the right risk class. Built
  // BEFORE the bundle/manual branches so it is carried whether or not a bundle is published. An ABSENT
  // riskClass is left out so the engine's safe migration-gated normalisation stands (never weakened here).
  const richMeta = buildRichMetadata(args, process.argv.slice(2));
  Object.assign(artefact, richMeta);

  if (bundleBytes) {
    // Hash with the ENGINE's OWN sha384 + hexEncode — the exact value its update-apply re-computes and
    // compares (hex, lower-case) — so the signed channel's sha384 and the engine's recomputed hash match
    // byte-for-byte. With a bundle, --url is REQUIRED: it is where the engine fetches the bytes from.
    artefact.sha384 = hexEncode(await sha384(bundleBytes));
    artefact.mainModule = mainModule;
    if (typeof args.url !== "string" || args.url === "") {
      throw new Error(`--url is required when publishing a bundle: the stable https URL the bundle will be hosted at (e.g. https://update.downpipes.io/engine-${recommendedVersion}.mjs). The engine downloads the bundle from this url and verifies it against the signed sha384 before deploying.`);
    }
    artefact.url = args.url;
    // --requires-migration marks a release the safe-apply harness must NOT auto-apply (a Durable Object
    // migration); it falls back to a manual deploy. Set it whenever the new version changes DO classes.
    if (args["requires-migration"]) artefact.requiresMigration = true;
    // DP-A: the verified CI identifiers + the channel-relative attestation paths ride INSIDE the signed
    // body, so the offline signature transitively vouches for the provenance pointers. Paths are
    // namespaced by the RELEASE version (recommendedVersion), where the sidecar block below writes them.
    if (engineRelease) {
      artefact.provenance = {
        ...engineRelease.provenanceFacts,
        attestations: {
          intoto: `provenance/${recommendedVersion}/engine.intoto.jsonl`,
          cosignBundle: `provenance/${recommendedVersion}/engine-${engineRelease.version}.mjs.cosign-bundle`,
          sums: `provenance/${recommendedVersion}/engine.SHA256SUMS.txt`,
          releaseRecord: `provenance/${recommendedVersion}/release-record.json`,
        },
      };
    }
    // Write the EXACT bytes that were hashed, so what you upload is what the channel declares.
    if (typeof args["out-bundle"] === "string") writeFileSync(args["out-bundle"], bundleBytes);
  } else {
    // Back-compat: no bundle — manual fields only (a channel-only publish; the safe-apply harness cannot
    // download/verify an artefact this channel does not fully describe, so a bundle is required for it).
    if (typeof args.sha384 === "string") artefact.sha384 = args.sha384;
    if (typeof args.url === "string") artefact.url = args.url;
    if (args["requires-migration"]) artefact.requiresMigration = true;
  }
  if (typeof args.notes === "string") artefact.notes = args.notes;

  // ---- CONSOLE component (multi-component updates). --console-build packages the console the same
  // way a real deploy would; --console-bundle ingests a pre-packaged downpipe-console-bundle/1 file.
  // --console-url is REQUIRED with a console artefact (where the engine downloads it from). The
  // console's version comes from the console package.json unless --console-version overrides it.
  let consoleBundle = null;
  let consoleRelease = null;
  if (typeof args["console-release-dir"] === "string") {
    // DP-A ceremony mode for the console component: same rule as the engine, sign only what the
    // console repo's release workflow attested.
    if (args["console-build"] || typeof args["console-bundle"] === "string") {
      throw new Error("--console-release-dir replaces --console-build/--console-bundle: the ceremony signs the CI-built, attested console bundle, never a fresh local package. Drop the local flags.");
    }
    if (typeof args["provenance-out-dir"] !== "string") {
      throw new Error("--provenance-out-dir is required with --console-release-dir: the signed channel embeds provenance/<version>/ paths, so the sidecars must be produced with the channel.");
    }
    consoleRelease = ingestAttestedRelease({
      dir: args["console-release-dir"],
      component: "console",
      artefactNameFor: (v) => `console-${v}.json`,
      identityRegexp: CONSOLE_RELEASE_IDENTITY,
      cosignBin,
    });
    const parsed = JSON.parse(new TextDecoder().decode(consoleRelease.artefactBytes));
    if (parsed?.format !== "downpipe-console-bundle/1" || parsed.version !== consoleRelease.version) {
      throw new Error(`the attested console artefact is not a downpipe-console-bundle/1 for version ${consoleRelease.version}; refusing it. Nothing was signed.`);
    }
    consoleBundle = { text: new TextDecoder().decode(consoleRelease.artefactBytes), bytes: consoleRelease.artefactBytes, version: consoleRelease.version };
  } else if (args["console-build"]) {
    const consoleDir = typeof args["console-dir"] === "string" ? args["console-dir"] : path.join(TOOLS_DIR, "..", "..", "console");
    consoleBundle = buildConsoleBundle(consoleDir, { versionOverride: typeof args["console-version"] === "string" ? args["console-version"] : undefined });
  } else if (typeof args["console-bundle"] === "string") {
    const bytes = new Uint8Array(readFileSync(args["console-bundle"]));
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (parsed?.format !== "downpipe-console-bundle/1" || typeof parsed.version !== "string") {
      throw new Error(`--console-bundle is not a downpipe-console-bundle/1 file (${args["console-bundle"]})`);
    }
    consoleBundle = { text: new TextDecoder().decode(bytes), bytes, version: parsed.version };
  }

  // CROSS-COMPONENT ceremony guard (review finding #2): once EITHER component is attested, the
  // whole channel is an attested release, and the other component must not smuggle fresh LOCAL
  // bytes in beside it -- a mixed channel would carry an "attested release" label while shipping
  // one component CI never saw, exactly the dual-root hole the ceremony exists to close. A
  // channel-only engine row (no fresh bytes; --sha384/--url naming a PRIOR attested release) is
  // fine, which is why the guard keys on fresh bytes, not on the row's presence.
  if (consoleRelease !== null && engineRelease === null && bundleBytes !== null) {
    throw new Error("--console-release-dir makes this an attested ceremony: the engine artefact must also come from an attested release (--from-release-dir), not a fresh local --build/--bundle. Nothing was signed.");
  }
  if (engineRelease !== null && consoleRelease === null && consoleBundle !== null) {
    throw new Error("--from-release-dir makes this an attested ceremony: the console artefact must also come from an attested release (--console-release-dir), not --console-build/--console-bundle. Nothing was signed.");
  }

  // The v2 components map: engine mirrored from the artefact (old engines keep reading artefacts[],
  // new engines prefer components.engine), console added when packaged. INVARIANT: a console artefact
  // must NEVER be placed in artefacts[] — a deployed 0.1.x engine selects
  // artefacts.find(version === recommendedVersion) and would deploy console bytes ONTO the engine
  // script (the sha384 would verify; only the canary would save the customer).
  const components = { engine: { kind: "worker-module", ...artefact } };
  if (consoleBundle) {
    if (typeof args["console-url"] !== "string" || args["console-url"] === "") {
      throw new Error("--console-url is required when publishing a console artefact: the stable https URL the console bundle will be hosted at (e.g. https://update.downpipes.io/console-<version>.json)");
    }
    components.console = {
      kind: "static-assets",
      version: consoleBundle.version,
      url: args["console-url"],
      sha384: hexEncode(await sha384(consoleBundle.bytes)),
      ...buildConsoleMetadata(args, process.argv.slice(2)),
      ...(consoleRelease
        ? {
            provenance: {
              ...consoleRelease.provenanceFacts,
              attestations: {
                intoto: `provenance/${recommendedVersion}/console.intoto.jsonl`,
                cosignBundle: `provenance/${recommendedVersion}/console-${consoleRelease.version}.json.cosign-bundle`,
                sums: `provenance/${recommendedVersion}/console.SHA256SUMS.txt`,
                releaseRecord: `provenance/${recommendedVersion}/release-record.json`,
              },
            },
          }
        : {}),
    };
    if (typeof args["out-console-bundle"] === "string") writeFileSync(args["out-console-bundle"], consoleBundle.bytes);
  }

  // ---- FRESHNESS / ANTI-REPLAY (DP-0). The pair rides INSIDE the signed body; the engine's
  // checkChannelFreshness refuses a regression once a sequenced channel has been accepted. The
  // sequence is REQUIRED (an explicit --allow-unsequenced is the only way to emit the legacy
  // shape) and monotonicity is enforced against the state file BEFORE anything is signed.
  let sequence;
  let issuedAt;
  let sequenceStatePath = null;
  if (!args["allow-unsequenced"]) {
    const rawSeq = typeof args.sequence === "string" ? Number(args.sequence) : NaN;
    if (!Number.isInteger(rawSeq) || rawSeq < 1) {
      throw new Error("--sequence <positive integer> is required (the channel's anti-replay counter; the engine refuses any later channel whose sequence regresses). The FIRST sequenced publish sets every fielded engine's baseline, so choose it deliberately. Pass --allow-unsequenced only to emit the legacy pre-freshness shape.");
    }
    const statePath = typeof args["sequence-state"] === "string"
      ? args["sequence-state"]
      : typeof args["key-file"] === "string"
        ? path.join(path.dirname(args["key-file"]), "channel-sequence.json")
        : null;
    if (statePath && existsSync(statePath)) {
      const prior = JSON.parse(readFileSync(statePath, "utf8"));
      const last = Number(prior?.lastSequence);
      if (Number.isFinite(last) && rawSeq <= last) {
        throw new Error(`--sequence ${rawSeq} does not exceed the last published sequence ${last} (${statePath}); a fielded engine would refuse it as a replay. Nothing was signed.`);
      }
    }
    sequence = rawSeq;
    issuedAt = typeof args["issued-at"] === "string" ? args["issued-at"] : new Date().toISOString();
    // The state file is advanced only AFTER the successful self-verified emit below.
    sequenceStatePath = statePath;
  }

  const channelDoc = { channel: channelName, recommendedVersion, artefacts: [artefact], components, ...(sequence !== undefined ? { sequence } : {}), ...(issuedAt !== undefined ? { issuedAt } : {}) };

  // Emit a STABLE serialisation and sign EXACTLY those bytes. The engine verifies the
  // signature over the bytes it fetches and then JSON.parse()s the same bytes (it does not
  // canonicalise), so the operator MUST publish channelText verbatim. The signature file is
  // base64url-no-pad over the detached hybrid signature, on a single line, which is what
  // checkUpdates trims and base64url-decodes from UPDATE_CHANNEL_URL + ".sig".
  const channelText = JSON.stringify(channelDoc, null, 2);
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, utf8(channelText));
  const signatureText = b64urlEncode(sig);

  // SELF-VERIFY before anything is written: the engine's own verifyChannel must accept exactly the
  // bytes and signature we are about to publish, under exactly the public key operators pin. A tool
  // bug can therefore never emit a channel deployed engines would reject.
  const verified = await verifyChannel(utf8(channelText), sig, parseVerifier(b64urlDecode(updateSignerPublic)));
  if (verified === null) throw new Error("self-verify failed: the engine's verifyChannel rejected the freshly signed channel; nothing was written");

  // ---- DP-A sidecar publication set. Written only after the channel self-verified (a refusal
  // leaves no half-published provenance directory), under provenance/<recommendedVersion>/ exactly
  // as the signed channel's attestation paths name them. release-record.json is the convenience
  // mirror the console cross-checks; the AUTHORITATIVE copy of every value in it is the signed
  // channel itself.
  let provenanceDir = null;
  if ((engineRelease !== null || consoleRelease !== null) && typeof args["provenance-out-dir"] === "string") {
    const relDir = `provenance/${recommendedVersion}`;
    provenanceDir = path.join(args["provenance-out-dir"], "provenance", recommendedVersion);
    mkdirSync(provenanceDir, { recursive: true });
    const copies = [];
    if (engineRelease !== null) {
      copies.push(
        [engineRelease.files.intotoPath, "engine.intoto.jsonl"],
        [engineRelease.files.artefactBundle, `engine-${engineRelease.version}.mjs.cosign-bundle`],
        [engineRelease.files.sumsPath, "engine.SHA256SUMS.txt"],
        [engineRelease.files.sumsBundle, "engine.SHA256SUMS.txt.cosign-bundle"],
        [engineRelease.files.factsPath, "engine.release-facts.json"],
      );
    }
    if (consoleRelease !== null) {
      copies.push(
        [consoleRelease.files.intotoPath, "console.intoto.jsonl"],
        [consoleRelease.files.artefactBundle, `console-${consoleRelease.version}.json.cosign-bundle`],
        [consoleRelease.files.sumsPath, "console.SHA256SUMS.txt"],
        [consoleRelease.files.sumsBundle, "console.SHA256SUMS.txt.cosign-bundle"],
        [consoleRelease.files.factsPath, "console.release-facts.json"],
      );
    }
    for (const [src, name] of copies) copyFileSync(src, path.join(provenanceDir, name));
    const record = {
      channel: channelName,
      recommendedVersion,
      ...(sequence !== undefined ? { sequence, issuedAt } : {}),
      ...(engineRelease !== null ? { engine: { version: engineRelease.version, sha384: artefact.sha384, sha256: sha256Hex(bundleBytes), ...engineRelease.provenanceFacts } } : {}),
      ...(consoleRelease !== null && consoleBundle !== null ? { console: { version: consoleBundle.version, sha384: components.console.sha384, sha256: sha256Hex(consoleBundle.bytes), ...consoleRelease.provenanceFacts } } : {}),
      note: "Convenience mirror for display and cross-checks. The authoritative copy of every value here is the SIGNED channel document (stable.json + stable.json.sig); trust that, not this.",
    };
    writeFileSync(path.join(provenanceDir, "release-record.json"), JSON.stringify(record, null, 2) + "\n");
    // The operator publishes the whole directory alongside the channel objects; the note below
    // prints the exact object keys so nothing dangles.
    process.stderr.write(`provenance sidecars written to ${provenanceDir} (publish every file under ${relDir}/ on the channel host)\n`);
  }

  if (typeof args.out === "string") writeFileSync(args.out, channelText);
  if (typeof args["out-sig"] === "string") writeFileSync(args["out-sig"], signatureText + "\n");
  if (typeof args["out-key"] === "string") {
    // Persist the private so the same PINNED key can sign future channel updates. The file is
    // SECRET; for a generated keypair it is the only copy of the release-signing key, and the
    // pinned UPDATE_SIGNER_PUBLIC in deployed accounts only verifies signatures from it.
    writeFileSync(args["out-key"], releaseSignerPrivate + "\n", { mode: 0o600 });
  }

  // Advance the sequence state LAST, after every output (channel, signature, key, sidecars) has
  // been written: a run that failed anywhere above must never burn a sequence number, so the
  // operator retries with the same one instead of puzzling over a "does not exceed" refusal
  // (review finding #5: the earlier placement advanced the state before the sidecar writes).
  if (sequence !== undefined && sequenceStatePath) {
    writeFileSync(sequenceStatePath, JSON.stringify({ lastSequence: sequence, issuedAt }, null, 2) + "\n");
  }

  const updateChannelUrlNote =
    "Publish `channel` verbatim at a stable HTTPS URL and set UPDATE_CHANNEL_URL to it; publish `signature` at that same URL + \".sig\". Pin `updateSignerPublic` as UPDATE_SIGNER_PUBLIC. The engine PULLS and verifies; it is never pushed." +
    (bundleBytes
      ? ` Also upload the BUNDLE to its url (${artefact.url}); the engine downloads it from there and verifies it against the signed sha384 (${artefact.sha384}) before deploying. For update.downpipes.io (the default channel host): \`wrangler r2 object put <bucket>/${path.basename(new URL(artefact.url).pathname)} --file ${typeof args["out-bundle"] === "string" ? args["out-bundle"] : "<your-bundle>"} --content-type application/javascript+module\` (and the channel + .sig as the other two objects).`
      : " No bundle was published (channel-only); the safe-apply harness needs an artefact with url + sha384, so re-run with --build or --bundle to enable in-console updates.") +
    (consoleBundle
      ? ` Also upload the CONSOLE bundle to its url (${components.console.url}): \`wrangler r2 object put <bucket>/${path.basename(new URL(components.console.url).pathname)} --file ${typeof args["out-console-bundle"] === "string" ? args["out-console-bundle"] : "<console-bundle>"} --content-type application/json\` — the engine downloads and verifies it against the signed sha384 (${components.console.sha384}) before deploying the console.`
      : "") +
    (provenanceDir
      ? ` Also upload EVERY provenance sidecar so the signed channel's attestation paths resolve: for each file in ${provenanceDir}, \`wrangler r2 object put <bucket>/provenance/${recommendedVersion}/<filename> --file <that file> --content-type application/json\` (all sidecars are JSON/JSONL). A channel whose provenance paths 404 is a published overclaim; upload the sidecars in the same sitting as stable.json.`
      : "");

  const result = {
    channel: channelText,
    signature: signatureText,
    updateSignerPublic,
    updateChannelUrlNote,
    recommendedVersion,
    // Freshness pair (inside the signed body). The first sequenced publish sets every fielded
    // engine's anti-replay baseline; the note reminds the operator this is a deliberate act.
    ...(sequence !== undefined ? { sequence, issuedAt, sequenceNote: "sequence/issuedAt ride INSIDE the signed body; once a fielded engine accepts this channel it refuses any lower-sequence descriptor. Keep the sequence-state file with the signing key." } : { unsequencedWarning: "this channel carries NO sequence/issuedAt (legacy shape, --allow-unsequenced): fielded engines cannot refuse a replay of it." }),
    // The published bundle's facts, so the operator can confirm what was hashed + where it must be hosted.
    ...(bundleBytes ? { artefactUrl: artefact.url, artefactSha384: artefact.sha384, artefactBytes: bundleBytes.length, mainModule, ...(artefact.requiresMigration ? { requiresMigration: true } : {}) } : {}),
    ...(consoleBundle ? { consoleArtefactUrl: components.console.url, consoleArtefactSha384: components.console.sha384, consoleArtefactBytes: consoleBundle.bytes.length, consoleVersion: consoleBundle.version } : {}),
    // DP-A: where the ceremony wrote the sidecar set (present only in from-release mode).
    ...(provenanceDir !== null ? { provenanceDir } : {}),
    // Only echo the private to stdout when there is no 0600 --out-key file to be the canonical
    // copy (or the operator explicitly asked with --emit-private). Writing it to the restricted
    // file AND dumping it to stdout would defeat the file's whole purpose.
    ...((generated && typeof args["out-key"] !== "string") || args["emit-private"] ? { releaseSignerPrivate } : {}),
  };
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}

main().catch((e) => {
  process.stderr.write(`publish-channel: ${e.message}\n`);
  process.exit(1);
});
