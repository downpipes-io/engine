// validate-crypto-discovery: the engine's cryptographic discovery gate (ASVS V11.1.3). It is a census,
// not a sample: every crypto.subtle call, every random-source call, every @noble/*, node:crypto or bare
// crypto import, and every algorithm literal under src/, scripts/ and tools/ is found and compared
// against the committed manifest at docs/security/crypto-call-sites.json.
//
// THE SCANNER IS AN AST DATA-FLOW WALK, NOT A TEXT MATCH. Each .ts/.mts/.mjs/.js file is parsed with the
// TypeScript compiler API (ts.createSourceFile) and every crypto.subtle call site is found by resolving
// the CALL RECEIVER's binding, not by reading the identifier's spelling: `const sub = crypto.subtle; sub
// .encrypt(...)` is a subtle call site because `sub` is proven, by walking its declaration, to hold the
// value `crypto.subtle` holds -- the same is true of `const s2 = sub;` two hops removed, of a function
// parameter typed `SubtleCrypto`, and of `globalThis.crypto.subtle` / `webcrypto.subtle` chains. A scanner
// that instead looked for the literal text "subtle." or the literal type name "SubtleCrypto" is defeated
// by the plain rename above: `sub.` contains neither substring, so a text-based census finds nothing and
// exits 0 while an unapproved algorithm reaches WebCrypto. resolveHandle() below is the fix: it answers
// "does this expression evaluate to crypto.subtle (or the object crypto/webcrypto itself)" by walking the
// expression's own shape and, for an identifier, its recorded binding -- never by comparing text to
// "subtle".
//
//   (a) UNDOCUMENTED. A discovered (file, kind, detail) triple with no manifest row fails the gate.
//   (b) STALE. A manifest row whose (file, kind, detail) triple is not discovered fails the gate,
//       whether the file is absent or the call site reads differently.
//   (c) ANTI-VACUITY. The walk must find at least SUBTLE_FILES_FLOOR files with a genuine crypto.subtle
//       call and at least NOBLE_FILES_FLOOR files importing @noble/*, so an empty or misrooted walk
//       cannot pass. Both floors are the length of a pinned per-file list (SUBTLE_COVERAGE_ANCHORS,
//       NOBLE_COVERAGE_ANCHORS): the walk must still discover every NAMED file on that list, not merely
//       clear a count, so a walk that drops one file's coverage while an unrelated file starts
//       contributing an equal-count replacement is still caught (rule (a)/(b) alone catch that swap only
//       when the manifest is left out of step with it; the pinned list is a second witness that does not
//       move with the manifest).
//   (d) UNAPPROVED PRIMITIVE. An "algorithm" detail outside APPROVED_ALGORITHMS fails the gate; a new
//       algorithm needs a reviewed manifest entry, which is what widening APPROVED_ALGORITHMS is.
//   (e) UNREVIEWED INDIRECTION. A file outside INDIRECTION_ALLOWLIST fails the gate if either: a function
//       parameter or a variable declaration is typed `SubtleCrypto` or `Crypto` (the file is receiving a
//       WebCrypto handle from outside its own scope, so this file's own call sites are not the whole
//       picture), or a resolved crypto.subtle/crypto/webcrypto handle is passed AS AN ARGUMENT to any call
//       (the handle is escaping to code this walk has not looked at). Binding a subtle handle under a
//       local alias and calling it directly (`const sub = crypto.subtle; sub.digest(...)`) is NOT, on its
//       own, indirection: resolveHandle() sees straight through it and the call is fully classified below,
//       which is why src/crypto/primitives.ts needs no allowlist entry even though it aliases crypto.subtle
//       to a module-level `subtle` binding.
//   (f) UNCLASSIFIED OR UNAPPROVED CALL-SITE ALGORITHM. For every subtle.<method>( call the scanner
//       resolves (kind "subtle" above), the argument in that method's algorithm position is extracted and
//       must be a literal the scanner can read (a quoted string, an object literal with a literal "name"
//       field, or an identifier one hop from either of those via its own `const` declaration) AND that
//       name must be in APPROVED_ALGORITHMS. A call whose algorithm argument is not classifiable this way
//       fails unless the file is on INDIRECTION_ALLOWLIST; a call whose literal names an algorithm outside
//       APPROVED_ALGORITHMS fails regardless of the allowlist (AES-CBC, AES-CTR, MD5 and RSA-OAEP are none
//       of them approved, and the allowlist reviews INDIRECTION, not primitive choice).
//   (g) ESCAPED HANDLE. The default is conservative: a resolved crypto.subtle/cryptoRoot handle reaching
//       ANY syntactic position other than (a) the initialiser of a plain local identifier alias this
//       tracer keeps following, or (b) the receiver of a direct `.method(...)` call this tracer classifies
//       above (subtle.<SUBTLE_METHODS> or cryptoRoot.<RANDOM_METHODS>), sets indirectionFlagged for the
//       file -- the same signal a SubtleCrypto/Crypto-typed parameter sets. This covers, without
//       exception: an object-literal property value, a destructuring target (object or array pattern), an
//       array-literal element, a function return value (a `return` statement or an arrow function's
//       concise expression body), a class field initialiser or a `this.field = ...`
//       assignment, an argument to any call, a computed member access on either side (`handle[k]` or
//       `obj[handle]`), a call through a method name the classifier does not recognise, a handle referenced
//       on its own with nothing consuming it, and every ES export form: `export const x = crypto.subtle`
//       (an exported variable declaration whose initialiser resolves to a handle), `export { localAlias }`
//       naming a local binding this file already tracks as a handle, `export default crypto.subtle` (or
//       `export default` of a tracked local binding), and `export { x } from "mod"` / `export * from "mod"`
//       / `export * as ns from "mod"` when `mod` itself matches IMPORT_SPECIFIER_PATTERNS -- a re-export
//       naming a crypto-bearing module can forward a handle this file never declares, so it is flagged
//       without trying to resolve the forwarded name. A re-export from an ordinary sibling file is not
//       flagged on the re-exporting file: if that sibling itself holds and exports a handle, the sibling's
//       OWN file is flagged by the rules above, which is where the escape actually originates; the
//       re-exporting file adds no crypto exposure of its own that this walk can see. A file that touches
//       crypto.subtle through one of these shapes and is not on INDIRECTION_ALLOWLIST fails the gate
//       exactly like a typed-parameter indirection does. This flags every syntactic position a value the
//       tracer proves is a handle can occupy. A handle the tracer cannot prove statically -- one reached
//       through reflection, a dynamic import, an eval, or a value an imported function returns across the
//       module boundary -- is out of scope of this file-scoped walk, so the mechanism is a discovery and
//       inventory aid over the codebase as written, not a defence against a developer who sets out to hide
//       a call.
//
// --self-test: (i) plants an unmanifested crypto.subtle.digest("SHA-1", ...) and an unmanifested
// `import { sha256 } from "@noble/hashes/sha2.js"` in a scratch tree, and proves both are reported --
// SHA-1 as an unapproved algorithm, the import as an undocumented call site; (ii) drops one row from a
// copy of the real manifest for a call site the real tree still has, and proves the stale-manifest
// failure fires; (iii) points the walk at an empty directory and proves the zero-population failure
// fires; (iv) plants the EXACT aliasing shape that defeats a text/regex scanner (`const sub = crypto.
// subtle; sub.encrypt({ name: "AES-CBC", iv }, key, data);`, a receiver named `sub`, never the word
// "subtle") in a new, un-allowlisted file, and proves the alias is resolved to a real subtle call site
// whose literal algorithm "AES-CBC" is reported unapproved; (v) plants a helper function taking a
// SubtleCrypto-typed parameter and a runtime string algorithm name, calls it, and proves the file is
// reported both for the typed-parameter indirection and for the unclassifiable algorithm argument; (vi)
// unit-tests the anchor-identity comparison directly: a covered set missing one named anchor is reported
// missing even when an unrelated extra file is present, proving a same-count swap does not hide as clean;
// (vii) plants one file per ESCAPED HANDLE shape in rule (g) above -- an object-literal property, a
// destructuring target, an array-literal element, a function return value, a class field, a call
// argument, and a computed member access -- each an un-allowlisted file that reaches crypto.subtle through
// that one shape alone, and proves every one of them sets indirectionFlagged (so main()'s allowlist check
// would fail the gate for each); (viii) plants one file per ES EXPORT ESCAPE shape -- an exported const
// alias (`export const handle = crypto.subtle`), a named export of a locally-aliased handle (`const sub =
// crypto.subtle; export { sub };`), and a default export of a handle (`export default crypto.subtle`) --
// each an un-allowlisted file, and proves every one sets indirectionFlagged; this is the shape the
// adversarial review defeated the pre-export-aware scanner with (a handle exported from file A and
// consumed in file B reached AES-CBC while the gate named nothing).
//
// SHARED SCANNER VOCABULARY. The block below marked SHARED-SCANNER-START/END is byte-identical in this
// file and console/scripts/crypto-discovery-gate.mjs (the twin over console/src and console/scripts), the
// way SECRET_NAME_PATTERN is copied verbatim between engine/test/validate-reserved-bindings-completeness.ts
// and website/scripts/key-inventory-gate.mjs. It holds only constants (no function bodies, no type
// annotations), so the identical text is simultaneously valid TypeScript and valid plain JavaScript.
// verifyTwin() below re-hashes it at run time against SHARED_BLOCK_SHA256 (catching a one-sided edit that
// keeps both files syntactically valid) and, when the sibling repo is checked out beside this one, compares
// the two files' blocks byte for byte.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { verdictReached } from "./lib/verdict-guard.ts";

// SHARED-SCANNER-START
const SUBTLE_METHODS = ["digest", "sign", "verify", "encrypt", "decrypt", "importKey", "exportKey", "generateKey", "deriveBits", "deriveKey", "wrapKey", "unwrapKey", "timingSafeEqual"];
const RANDOM_METHODS = ["getRandomValues", "randomUUID"];
const IMPORT_SPECIFIER_PATTERNS = [/^@noble\//, /^node:crypto$/, /^crypto$/];
const NOBLE_IDENTIFIER_ALGORITHM = { ed25519: "Ed25519", x25519: "X25519", ml_kem1024: "ML-KEM-1024", ml_dsa87: "ML-DSA-87", blake3: "BLAKE3", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
const APPROVED_ALGORITHMS = ["SHA-256", "SHA-384", "SHA-512", "AES-GCM", "HKDF", "HMAC", "Ed25519", "X25519", "ML-KEM-1024", "ML-DSA-87", "ECDSA", "ECDSA-P-256", "ECDSA-P-384", "RSASSA-PKCS1-v1_5", "BLAKE3"];
const ALGORITHM_LITERAL_NAMES = ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "sha256", "sha384", "sha512", "AES-GCM", "HKDF", "HMAC", "Ed25519", "RSASSA-PKCS1-v1_5", "ECDSA", "P-256", "P-384"];
const SCAN_EXTENSIONS = [".ts", ".mjs", ".mts", ".js"];
// SUBTLE_ALGORITHM_ARG_INDEX names, for every SubtleCrypto method whose Web Crypto signature carries an
// algorithm argument, that argument's zero-based position: digest/sign/verify/encrypt/decrypt/
// generateKey/deriveBits/deriveKey take it first; importKey and wrapKey/unwrapKey take it after the
// format and key arguments. exportKey and timingSafeEqual carry no algorithm argument and are absent.
const SUBTLE_ALGORITHM_ARG_INDEX = { digest: 0, sign: 0, verify: 0, encrypt: 0, decrypt: 0, generateKey: 0, deriveBits: 0, deriveKey: 0, importKey: 2, wrapKey: 3, unwrapKey: 3 };
// SHARED-SCANNER-END
// SHARED_BLOCK_SHA256 pins the SHA-256 of the SHARED-SCANNER-START..END span above (this line and
// everything after it is outside that span, so the constant does not hash itself). Copied verbatim into
// console/scripts/crypto-discovery-gate.mjs; recompute it there too whenever the block above changes.
const SHARED_BLOCK_SHA256 = "59e1ff405e8650b8715255dbdd3e0d573e8645e29328073fc9748b121467ad30";

const ROOT_DIRS = ["src", "scripts", "tools"];
const MANIFEST_PATH = "docs/security/crypto-call-sites.json";

// SUBTLE_COVERAGE_ANCHORS and NOBLE_COVERAGE_ANCHORS pin the exact files the walk finds today with a
// genuine crypto.subtle call or a @noble/* import (see rule (c) above). Removing a name here needs a
// change to this file, not just to docs/security/crypto-call-sites.json, so a swap that drops one file's
// coverage while an unrelated file starts contributing an equal-count replacement still fails: the
// dropped name goes missing from this list's coverage check even though the total count and the manifest
// could otherwise be kept in lockstep with each other.
const SUBTLE_COVERAGE_ANCHORS = [
  "src/admin/access.ts",
  "src/admin/auth.ts",
  "src/admin/config-history.ts",
  "src/admin/control-plane.ts",
  "src/admin/oidc-verify.ts",
  "src/admin/oidc.ts",
  "src/admin/passkey-cose.ts",
  "src/admin/passkey.ts",
  "src/admin/recovery.ts",
  "src/admin/saml/dsig-helpers.ts",
  "src/admin/saml/dsig.ts",
  "src/admin/session.ts",
  "src/crypto/bytes.ts",
  "src/crypto/primitives.ts",
  "src/crypto/sign.ts",
  "src/dest/azure-sharedkey.ts",
  "src/dest/sigv4.ts",
  "src/keys-env.ts",
  "src/seal/checkpoint.ts",
  "src/seal/slice.ts",
  "src/sources/cf-config-writer-fingerprint.ts",
];
const NOBLE_COVERAGE_ANCHORS = [
  "scripts/generate-keys.ts",
  "src/admin/cf-assets-deploy.ts",
  "src/admin/restore-sinks.ts",
  "src/crypto/pq.ts",
  "src/crypto/streamseal.ts",
  "src/crypto/x25519.ts",
  "src/format/reader.ts",
  "src/keys-env.ts",
  "src/seal/record.ts",
  "tools/generate-support-keypair.ts",
  "tools/support-corpus/harness.ts",
];
const SUBTLE_FILES_FLOOR = SUBTLE_COVERAGE_ANCHORS.length;
const NOBLE_FILES_FLOOR = NOBLE_COVERAGE_ANCHORS.length;

// INDIRECTION_ALLOWLIST names the files reviewed and approved to do one of the two things resolveHandle()
// and the call-site classifier cannot see through: hold a SubtleCrypto/Crypto-typed parameter or variable
// (a handle arriving from outside this file), or pass a subtle.* call's algorithm argument through a name
// that is not a literal and not a `const` one hop away from one (typically a function parameter whose
// value is fixed only at the call site). Aliasing crypto.subtle to a local name and calling it directly is
// NOT a reason to be on this list: resolveHandle() tracks that binding by data flow, not by spelling, and
// the call is fully classified like any other.
const INDIRECTION_ALLOWLIST = new Set<string>([
  // verifyReferenceDigest takes the Reference's declared hash algorithm (SHA-256/384/512, fixed by the
  // XML-DSig DigestMethod URI checked in parseSignatureAndReferenceInfo before this runs) as a plain
  // `hashName: string` parameter and passes it straight to crypto.subtle.digest; the scanner's one-hop
  // resolution only follows `const` declarations, not parameters, so this call site stays unclassifiable
  // and the file is reviewed and allowlisted rather than reported.
  "src/admin/saml/dsig.ts",
  // importCoseKeyInner returns the fixed algorithm object for the credential's COSE key type (ECDSA
  // P-256 for kty 2, RSASSA-PKCS1-v1_5 for RSA) as part of a destructured return value; verifySignature
  // passes that destructured `algo` (cast `as EcdsaParams` / `as AlgorithmIdentifier`) to crypto.subtle.
  // verify. The value is fixed at its origin, but it arrives at the call site through a function return
  // rather than a local `const` literal, so the one-hop resolver cannot classify it.
  "src/admin/passkey-cose.ts",
]);

interface Entry {
  file: string;
  kind: "subtle" | "random" | "import" | "algorithm";
  detail: string;
}

interface Census {
  entries: Entry[];
  subtleFiles: Set<string>;
  nobleFiles: Set<string>;
  totalFiles: number;
}

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (SCAN_EXTENSIONS.some((ext) => p.endsWith(ext)) && !p.endsWith(".d.ts") && !p.endsWith(".d.mts")) out.push(p);
  }
  return out;
}

function scriptKindFor(file: string): ts.ScriptKind {
  return file.endsWith(".ts") || file.endsWith(".mts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
}

// A "handle" is what an expression is proven to evaluate to: "subtle" for crypto.subtle (however it is
// reached), "cryptoRoot" for the Crypto object itself (crypto / webcrypto / globalThis.crypto).
type Handle = "subtle" | "cryptoRoot";

// unwrap strips the wrappers that carry an expression's value through unchanged (parentheses, `as` and
// `satisfies` type assertions, the `!` non-null operator), so `(sub)`, `algo as EcdsaParams` and `sub!`
// resolve exactly as `sub` does.
function unwrap(expr: ts.Expression): ts.Expression {
  let cur = expr;
  while (ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur) || ts.isSatisfiesExpression(cur) || ts.isNonNullExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

// resolveHandle answers "does this expression evaluate to crypto.subtle or to the Crypto object itself",
// by walking the expression's shape and, for a bare identifier, the binding recorded for it so far in this
// file. It never compares an identifier's text to "subtle": a tracked alias named `sub`, `s2` or anything
// else resolves exactly as `crypto.subtle` does, which is what makes the rename in the module comment
// above harmless here.
function resolveHandle(exprIn: ts.Expression, bindings: Map<string, Handle>): Handle | null {
  const expr = unwrap(exprIn);
  if (ts.isIdentifier(expr)) {
    const tracked = bindings.get(expr.text);
    if (tracked) return tracked;
    // The bare global identifiers. A local rebinding of one of these names is tracked above and already
    // returned; this fallback only fires for an untracked reference to the ambient global.
    if (expr.text === "crypto" || expr.text === "webcrypto") return "cryptoRoot";
    return null;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    if (expr.name.text === "crypto") {
      const base = unwrap(expr.expression);
      return ts.isIdentifier(base) && base.text === "globalThis" ? "cryptoRoot" : null;
    }
    if (expr.name.text === "subtle") {
      return resolveHandle(expr.expression, bindings) === "cryptoRoot" ? "subtle" : null;
    }
  }
  return null;
}

// subtleCryptoOrCryptoTypeName reports whether a type annotation names SubtleCrypto or Crypto directly
// (a plain type reference, not a union or an alias): the shape a parameter or variable receiving a
// WebCrypto handle from outside this file's own resolved calls actually carries.
function subtleCryptoOrCryptoTypeName(typeNode: ts.TypeNode): "SubtleCrypto" | "Crypto" | null {
  if (ts.isTypeReferenceNode(typeNode) && ts.isIdentifier(typeNode.typeName)) {
    if (typeNode.typeName.text === "SubtleCrypto") return "SubtleCrypto";
    if (typeNode.typeName.text === "Crypto") return "Crypto";
  }
  return null;
}

function propKeyText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

// isExportedVariableDeclaration answers "does `export` appear on the VariableStatement that owns this
// declaration" (`export const x = ...`). A VariableDeclaration carries no modifiers of its own; the export
// keyword lives two levels up, on the VariableStatement wrapping its VariableDeclarationList.
function isExportedVariableDeclaration(decl: ts.VariableDeclaration): boolean {
  const list = decl.parent;
  if (!ts.isVariableDeclarationList(list)) return false;
  const stmt = list.parent;
  if (!ts.isVariableStatement(stmt) || !ts.canHaveModifiers(stmt)) return false;
  return ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

type AlgorithmArgClassification = { kind: "literal"; name: string } | { kind: "unclassifiable" };

// classifyLiteralOrObject reads ONE expression and decides whether it, directly, names an algorithm the
// scanner can read: a quoted string, or an object literal carrying a literal "name" field ({ name: "HMAC",
// hash: "SHA-256" } -- the hash field is not inspected, only name). It never follows an identifier; that
// one hop is classifyAlgorithmArg's job.
function classifyLiteralOrObject(nodeIn: ts.Expression): AlgorithmArgClassification {
  const node = unwrap(nodeIn);
  if (ts.isStringLiteralLike(node)) return { kind: "literal", name: node.text };
  if (ts.isObjectLiteralExpression(node)) {
    for (const prop of node.properties) {
      if (ts.isPropertyAssignment(prop) && propKeyText(prop.name) === "name") {
        const value = unwrap(prop.initializer);
        return ts.isStringLiteralLike(value) ? { kind: "literal", name: value.text } : { kind: "unclassifiable" };
      }
    }
  }
  return { kind: "unclassifiable" };
}

// classifyAlgorithmArg reads a subtle.* call's algorithm-position argument: a literal or object directly
// (classifyLiteralOrObject), or, when the argument is a bare identifier, that same check applied ONE hop
// through the identifier's own `const` declaration (constDecls). A bare identifier with no such
// declaration -- a function parameter, a `let` that is reassigned, a destructured return value -- stays
// unclassifiable: the scanner cannot see what will be called there, and INDIRECTION_ALLOWLIST is the
// reviewed answer to that, not a second hop of automatic follow.
function classifyAlgorithmArg(argNode: ts.Expression, constDecls: Map<string, ts.Expression>): AlgorithmArgClassification {
  const direct = classifyLiteralOrObject(argNode);
  if (direct.kind === "literal") return direct;
  const unwrapped = unwrap(argNode);
  if (ts.isIdentifier(unwrapped) && constDecls.has(unwrapped.text)) {
    return classifyLiteralOrObject(constDecls.get(unwrapped.text)!);
  }
  return { kind: "unclassifiable" };
}

interface AlgorithmCallIssue {
  file: string;
  method: string;
  argText: string;
}

interface ScanTree {
  entries: Entry[];
  subtleFiles: Set<string>;
  nobleFiles: Set<string>;
  totalFiles: number;
  subtleCryptoBindings: string[];
  unclassifiedCalls: AlgorithmCallIssue[];
  unapprovedCalls: AlgorithmCallIssue[];
}

// scanOneFile walks one parsed source file exactly once, in two passes over the same AST.
//
// Pass A (order-independent) collects every `const`-ish declaration's initialiser by name, so an
// identifier used later as a call argument can be resolved one hop back to a literal or object literal
// regardless of where in the file it was declared.
//
// Pass B is a single source-order traversal that: tracks which local names are proven to hold
// crypto.subtle or the Crypto object (resolveHandle, updated as each variable declaration, assignment and
// SubtleCrypto/Crypto-typed parameter is encountered); records a subtle or random call site whenever a
// call's receiver resolves to the matching handle; classifies the algorithm argument of every resolved
// subtle call; flags the file for indirection review when a parameter or variable is typed
// SubtleCrypto/Crypto, or when a resolved handle is passed as an argument to any call; and collects import
// specifiers and algorithm string literals for the manifest census. The binding tracker is file-scoped,
// not lexically scoped (see the module comment's honest_limits): two functions in the same file that both
// use a local name such as `key` for unrelated values share one map, which can only ever make the walk
// more willing to look at a call site, never less -- it cannot hide a real subtle call, only mislabel a
// coincidentally-named unrelated one, and no such collision exists in this tree today.
function scanOneFile(sourceFile: ts.SourceFile, rel: string, out: ScanTree): void {
  const constDecls = new Map<string, ts.Expression>();
  const collectConstDecls = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      constDecls.set(node.name.text, node.initializer);
    }
    node.forEachChild(collectConstDecls);
  };
  collectConstDecls(sourceFile);

  const bindings = new Map<string, Handle>();
  const algos = new Set<string>();
  const literalsByLine = new Map<number, Set<string>>();
  let indirectionFlagged = false;

  const recordLiteral = (node: ts.StringLiteralLike): void => {
    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line;
    let set = literalsByLine.get(line);
    if (!set) {
      set = new Set();
      literalsByLine.set(line, set);
    }
    set.add(node.text);
  };

  const bindParameterIfCryptoTyped = (param: ts.ParameterDeclaration): void => {
    if (!param.type) return;
    const typeName = subtleCryptoOrCryptoTypeName(param.type);
    if (!typeName) return;
    indirectionFlagged = true;
    if (ts.isIdentifier(param.name)) bindings.set(param.name.text, typeName === "SubtleCrypto" ? "subtle" : "cryptoRoot");
  };

  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node)) recordLiteral(node);

    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
      const specifier = node.moduleSpecifier.text;
      if (IMPORT_SPECIFIER_PATTERNS.some((p) => p.test(specifier))) {
        out.entries.push({ file: rel, kind: "import", detail: specifier });
        const namedBindings = node.importClause?.namedBindings;
        if (namedBindings && ts.isNamedImports(namedBindings)) {
          if (specifier.startsWith("@noble/")) {
            out.nobleFiles.add(rel);
            for (const el of namedBindings.elements) {
              const original = (el.propertyName ?? el.name).text;
              const algo = (NOBLE_IDENTIFIER_ALGORITHM as Record<string, string>)[original];
              if (algo) algos.add(algo);
            }
          } else {
            // `import { webcrypto } from "node:crypto"` under a local alias: `webcrypto.subtle` is only
            // recognised by resolveHandle's ambient-identifier fallback when the local name IS
            // "webcrypto"; a rename (`import { webcrypto as wc }`) needs the alias tracked explicitly.
            for (const el of namedBindings.elements) {
              const original = (el.propertyName ?? el.name).text;
              if (original === "webcrypto") bindings.set(el.name.text, "cryptoRoot");
            }
          }
        }
      }
    }

    if (ts.isFunctionLike(node)) {
      for (const param of node.parameters) bindParameterIfCryptoTyped(param);
    }

    if (ts.isVariableDeclaration(node)) {
      if (node.type && subtleCryptoOrCryptoTypeName(node.type)) indirectionFlagged = true;
      if (node.initializer) {
        const handle = resolveHandle(node.initializer, bindings);
        if (handle) {
          if (ts.isIdentifier(node.name)) {
            bindings.set(node.name.text, handle);
            // `export const x = crypto.subtle` leaves the file the moment it is exported, whether or not
            // anything inside this file ever calls the binding.
            if (isExportedVariableDeclaration(node)) indirectionFlagged = true;
          }
          // A binding pattern (`const { s } = ...` / `const [s] = ...`) receiving a resolved handle
          // directly is a destructuring target: there is no per-property binding to keep following, so
          // the handle escapes to a name this walk cannot trace onward.
          else indirectionFlagged = true;
        }
      }
    }

    // `export { localAlias }` (and a renaming `export { localAlias as other }`) re-exports a name this
    // file already tracks as a handle, so the binding leaves via the export list itself. In `export { x }
    // from "mod"`, `x` names something from the OTHER module, never a local binding, so this check is
    // naturally silent for it; that shape is covered by the ExportDeclaration check below instead.
    if (ts.isExportSpecifier(node)) {
      const localName = (node.propertyName ?? node.name).text;
      if (bindings.has(localName)) indirectionFlagged = true;
    }

    // `export { x } from "mod"`, `export * from "mod"` and `export * as ns from "mod"` forward a name
    // this file never declares. When `mod` matches IMPORT_SPECIFIER_PATTERNS (a recognised crypto-bearing
    // module), the forwarded name can carry a handle, and with no local declaration to disprove it this is
    // flagged conservatively. A re-export from an ordinary sibling file is not flagged here: if the
    // sibling itself exports a handle, the sibling's own file is flagged by the rules above, which is
    // where the escape actually originates.
    if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
      const specifier = node.moduleSpecifier.text;
      if (IMPORT_SPECIFIER_PATTERNS.some((p) => p.test(specifier))) indirectionFlagged = true;
    }

    // `export default crypto.subtle` or `export default <tracked alias>` leaves the file through the
    // default export binding.
    if (ts.isExportAssignment(node) && resolveHandle(node.expression, bindings) !== null) {
      indirectionFlagged = true;
    }

    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isIdentifier(node.left)) {
        const handle = resolveHandle(node.right, bindings);
        if (handle) bindings.set(node.left.text, handle);
      } else if (resolveHandle(node.right, bindings) !== null) {
        // Assignment to anything other than a plain local identifier -- a class field (`this.s = ...`), a
        // member of some other object, or a pattern -- is an escape: the tracer holds no binding for the
        // destination and cannot follow the handle past this line.
        indirectionFlagged = true;
      }
    }

    // An object-literal property value or an array-literal element holding a resolved handle is
    // reachable afterwards only through a property or index read this walk does not track by name.
    if (ts.isPropertyAssignment(node) && resolveHandle(node.initializer, bindings) !== null) {
      indirectionFlagged = true;
    }
    if (ts.isShorthandPropertyAssignment(node) && bindings.has(node.name.text)) {
      indirectionFlagged = true;
    }
    if (ts.isArrayLiteralExpression(node)) {
      for (const el of node.elements) {
        if (resolveHandle(el, bindings) !== null) indirectionFlagged = true;
      }
    }

    // A handle returned from a function is in the hands of every caller, none of which this file-scoped
    // walk looks at.
    if (ts.isReturnStatement(node) && node.expression && resolveHandle(node.expression, bindings) !== null) {
      indirectionFlagged = true;
    }

    // An arrow function with a concise (expression) body hands its body value to every caller exactly
    // like a return statement, but carries no ReturnStatement node for the check above to see.
    if (ts.isArrowFunction(node) && !ts.isBlock(node.body) && resolveHandle(node.body, bindings) !== null) {
      indirectionFlagged = true;
    }

    // A class field initialised to a resolved handle is reachable through instance state this walk does
    // not model (a `this.field = ...` assignment is covered by the binary-expression branch above).
    if (ts.isPropertyDeclaration(node) && node.initializer && resolveHandle(node.initializer, bindings) !== null) {
      indirectionFlagged = true;
    }

    // A computed member access on either side -- `handle[key]` or `obj[handle]` -- is a shape the call
    // classifier below only reads as a plain `.method` name; either direction escapes it.
    if (ts.isElementAccessExpression(node)) {
      if (resolveHandle(node.expression, bindings) !== null) indirectionFlagged = true;
      if (node.argumentExpression && resolveHandle(node.argumentExpression, bindings) !== null) indirectionFlagged = true;
    }

    // A resolved handle referenced on its own, as a whole statement, is exactly as unaccounted for as one
    // passed somewhere else: nothing downstream of this line is looked at.
    if (ts.isExpressionStatement(node) && resolveHandle(node.expression, bindings) !== null) {
      indirectionFlagged = true;
    }

    if (ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
      if (ts.isPropertyAccessExpression(callee)) {
        const objHandle = resolveHandle(callee.expression, bindings);
        const method = callee.name.text;
        if (objHandle === "subtle" && SUBTLE_METHODS.includes(method)) {
          out.subtleFiles.add(rel);
          out.entries.push({ file: rel, kind: "subtle", detail: method });
          const argIdx = (SUBTLE_ALGORITHM_ARG_INDEX as Record<string, number>)[method];
          if (argIdx !== undefined) {
            const argNode = node.arguments[argIdx];
            if (argNode) {
              const classified = classifyAlgorithmArg(argNode, constDecls);
              if (classified.kind === "unclassifiable") {
                out.unclassifiedCalls.push({ file: rel, method, argText: argNode.getText(sourceFile) });
              } else if (!APPROVED_ALGORITHMS.includes(classified.name)) {
                out.unapprovedCalls.push({ file: rel, method, argText: classified.name });
              }
            }
          }
        } else if (objHandle === "cryptoRoot" && RANDOM_METHODS.includes(method)) {
          out.entries.push({ file: rel, kind: "random", detail: method });
        } else if (objHandle !== null) {
          // A resolved handle calling a method name neither SUBTLE_METHODS nor RANDOM_METHODS names, so
          // nothing above records or classifies it.
          indirectionFlagged = true;
        }
      } else if (resolveHandle(callee, bindings) !== null) {
        // The callee resolves to a handle directly, with no `.method` access at all.
        indirectionFlagged = true;
      }
      for (const arg of node.arguments) {
        if (resolveHandle(arg, bindings) !== null) indirectionFlagged = true;
      }
    }

    node.forEachChild(visit);
  };
  visit(sourceFile);

  if (indirectionFlagged) out.subtleCryptoBindings.push(rel);

  let sawEcdsaP256 = false;
  let sawEcdsaP384 = false;
  for (const lineLiterals of literalsByLine.values()) {
    for (const name of ALGORITHM_LITERAL_NAMES) {
      if (!lineLiterals.has(name)) continue;
      if (name === "ECDSA" || name === "P-256" || name === "P-384") {
        if (lineLiterals.has("ECDSA") && lineLiterals.has("P-256")) sawEcdsaP256 = true;
        else if (lineLiterals.has("ECDSA") && lineLiterals.has("P-384")) sawEcdsaP384 = true;
      } else {
        algos.add(["sha256", "sha384", "sha512"].includes(name) ? name.replace("sha", "SHA-") : name);
      }
    }
  }
  if (sawEcdsaP256) algos.add("ECDSA-P-256");
  if (sawEcdsaP384) algos.add("ECDSA-P-384");
  for (const algo of algos) out.entries.push({ file: rel, kind: "algorithm", detail: algo });
}

function scanTree(root: string): ScanTree {
  const out: ScanTree = { entries: [], subtleFiles: new Set(), nobleFiles: new Set(), totalFiles: 0, subtleCryptoBindings: [], unclassifiedCalls: [], unapprovedCalls: [] };
  const files = ROOT_DIRS.flatMap((d) => walk(join(root, d)));
  out.totalFiles = files.length;
  for (const file of files) {
    const rel = file.slice(root.length + 1);
    const text = readFileSync(file, "utf8");
    const sourceFile = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKindFor(file));
    scanOneFile(sourceFile, rel, out);
  }
  return out;
}

function census(root: string): Census {
  const t = scanTree(root);
  return { entries: t.entries, subtleFiles: t.subtleFiles, nobleFiles: t.nobleFiles, totalFiles: t.totalFiles };
}

interface IndirectionScan {
  subtleCryptoBindings: string[];
  unclassifiedCalls: AlgorithmCallIssue[];
  unapprovedCalls: AlgorithmCallIssue[];
}

function scanIndirectionAndCallSiteAlgorithms(root: string): IndirectionScan {
  const t = scanTree(root);
  return { subtleCryptoBindings: t.subtleCryptoBindings, unclassifiedCalls: t.unclassifiedCalls, unapprovedCalls: t.unapprovedCalls };
}

function entryKey(e: Entry): string {
  return `${e.file}|${e.kind}|${e.detail}`;
}

function loadManifest(path: string): Entry[] {
  if (!existsSync(path)) return [];
  return JSON.parse(readFileSync(path, "utf8")) as Entry[];
}

interface DiffResult {
  undocumented: Entry[];
  stale: Entry[];
  unapproved: Entry[];
}

function diff(discovered: Entry[], manifest: Entry[]): DiffResult {
  const discoveredKeys = new Set(discovered.map(entryKey));
  const manifestKeys = new Set(manifest.map(entryKey));
  const undocumented = discovered.filter((e) => !manifestKeys.has(entryKey(e)));
  const stale = manifest.filter((e) => !discoveredKeys.has(entryKey(e)));
  const unapproved = discovered.filter((e) => e.kind === "algorithm" && !APPROVED_ALGORITHMS.includes(e.detail));
  return { undocumented, stale, unapproved };
}

// missingAnchors reports which names in `anchors` are absent from `covered`. It is the per-file identity
// check rule (c) relies on: a plain count floor cannot notice a same-count swap (one covered file's
// coverage lost, an unrelated file's coverage gained), but a pinned list of names is silent about the
// unrelated gain and loud about the specific loss.
function missingAnchors(covered: Set<string>, anchors: string[]): string[] {
  return anchors.filter((a) => !covered.has(a));
}

// verifyTwin re-hashes the SHARED-SCANNER block extracted from THIS file against SHARED_BLOCK_SHA256
// (catching a one-sided edit within this repo), and when console's twin is checked out beside this repo
// (this workspace, not a standalone CI checkout of engine alone), compares the two files' blocks byte
// for byte.
function extractSharedBlock(src: string): string | null {
  const start = src.indexOf("// SHARED-SCANNER-START");
  const end = src.indexOf("// SHARED-SCANNER-END");
  if (start === -1 || end === -1) return null;
  return src.slice(start, end);
}

function verifyTwin(ownFile: string): { ok: boolean; message: string; skipped: boolean } {
  const own = extractSharedBlock(readFileSync(ownFile, "utf8"));
  if (own === null) return { ok: false, message: "this file's own SHARED-SCANNER markers are missing", skipped: false };
  const ownHash = createHash("sha256").update(own).digest("hex");
  if (ownHash !== SHARED_BLOCK_SHA256) {
    return { ok: false, message: `SHARED_BLOCK_SHA256 (${SHARED_BLOCK_SHA256}) does not match this file's own shared block (${ownHash}); the constant or the block drifted`, skipped: false };
  }
  // engine/test/validate-crypto-discovery.ts -> ../../console/scripts/crypto-discovery-gate.mjs
  const twinPath = join(dirname(ownFile), "..", "..", "console", "scripts", "crypto-discovery-gate.mjs");
  if (!existsSync(twinPath)) return { ok: true, message: `console twin not found at ${twinPath} (standalone checkout); byte-equality skipped, own-hash check passed`, skipped: true };
  const twin = extractSharedBlock(readFileSync(twinPath, "utf8"));
  if (twin === null) return { ok: false, message: "the console twin's SHARED-SCANNER markers are missing", skipped: false };
  return { ok: own === twin, message: own === twin ? "byte-identical with the console twin's shared block" : "the console twin's shared block has drifted from this file's", skipped: false };
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function selfTest(): void {
  console.log("\ncrypto discovery self-test");

  // (i) plant an unmanifested unapproved algorithm and an unmanifested import; both must be reported.
  const root = mkdtempSync(join(tmpdir(), "crypto-discovery-"));
  try {
    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(
      join(root, "src", "plant.ts"),
      'export async function weak(b: Uint8Array): Promise<ArrayBuffer> {\n  return crypto.subtle.digest("SHA-1", b as unknown as ArrayBuffer);\n}\nimport { sha256 } from "@noble/hashes/sha2.js";\n',
    );
    const c = census(root);
    const shaOneRow = c.entries.find((e) => e.kind === "algorithm" && e.detail === "SHA-1");
    ok("self-test: the planted SHA-1 literal is discovered", shaOneRow !== undefined && shaOneRow.file === "src/plant.ts");
    const d = diff(c.entries, []);
    ok("self-test: the planted SHA-1 is flagged as an unapproved algorithm", d.unapproved.some((e) => e.detail === "SHA-1"));
    ok("self-test: the planted @noble/hashes import is flagged as undocumented against an empty manifest", d.undocumented.some((e) => e.kind === "import" && e.detail === "@noble/hashes/sha2.js"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }

  // (ii) two manifest-drift shapes over the REAL tree and the REAL committed manifest: dropping a row
  // for a call site the tree still has (the compare must report it undocumented -- the tree has it, the
  // manifest no longer does), and adding a row for a call site the tree does not have (the compare must
  // report it stale -- the manifest names something the tree does not).
  const real = census(process.cwd());
  const manifest = loadManifest(MANIFEST_PATH);
  ok("self-test precondition: the committed manifest is non-empty", manifest.length > 0);

  const droppedRow = manifest[0]!;
  const droppedKey = entryKey(droppedRow);
  const stillLive = real.entries.some((e) => entryKey(e) === droppedKey);
  ok("self-test precondition: the row chosen to drop is still a live call site", stillLive);
  const shortened = manifest.filter((e) => entryKey(e) !== droppedKey);
  ok("self-test: dropping a manifest row for a live call site reports it as undocumented", diff(real.entries, shortened).undocumented.some((e) => entryKey(e) === droppedKey));

  const fabricated: Entry = { file: "src/nonexistent-file-for-self-test.ts", kind: "algorithm", detail: "SHA-256" };
  const widened = [...manifest, fabricated];
  ok("self-test: a manifest row naming a file the tree does not have is flagged stale", diff(real.entries, widened).stale.some((e) => entryKey(e) === entryKey(fabricated)));

  // (iii) point the walk at an empty directory and prove the zero-population failure fires.
  const empty = mkdtempSync(join(tmpdir(), "crypto-discovery-empty-"));
  try {
    mkdirSync(join(empty, "src"), { recursive: true });
    const c = census(empty);
    ok("self-test: an empty tree finds zero subtle files (the anti-vacuity floor would fire)", c.subtleFiles.size === 0);
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }

  // (iv) THE EXACT SHAPE THAT DEFEATS A TEXT/REGEX SCANNER: alias crypto.subtle to a receiver whose name
  // contains neither "subtle" nor any other recognisable substring, then call an unapproved algorithm on
  // it. A scanner keyed on the literal text "subtle." finds nothing here at all; resolveHandle() must
  // still prove `sub` is crypto.subtle by data flow and classify the call's algorithm as AES-CBC, which
  // is not on APPROVED_ALGORITHMS.
  const aliasRoot = mkdtempSync(join(tmpdir(), "crypto-discovery-alias-"));
  try {
    mkdirSync(join(aliasRoot, "src"), { recursive: true });
    writeFileSync(
      join(aliasRoot, "src", "aliased-cipher.ts"),
      'export async function weak(key: CryptoKey, iv: Uint8Array, data: ArrayBuffer): Promise<ArrayBuffer> {\n  const sub = crypto.subtle;\n  return sub.encrypt({ name: "AES-CBC", iv }, key, data);\n}\n',
    );
    const scan = scanIndirectionAndCallSiteAlgorithms(aliasRoot);
    ok(
      'self-test: `const sub = crypto.subtle; sub.encrypt(...)` is resolved by data flow and its literal "AES-CBC" is reported unapproved',
      scan.unapprovedCalls.some((c) => c.file === "src/aliased-cipher.ts" && c.method === "encrypt" && c.argText === "AES-CBC"),
    );
    ok("self-test: the aliased receiver alone is not reported as indirection (resolveHandle sees straight through it)", !scan.subtleCryptoBindings.includes("src/aliased-cipher.ts"));
  } finally {
    rmSync(aliasRoot, { recursive: true, force: true });
  }

  // (v) plant a helper taking a SubtleCrypto-typed parameter, called with a runtime string algorithm name.
  // This is reported twice over: the typed parameter is a WebCrypto handle arriving from outside the
  // file's own resolved calls (rule (e)), and the algorithm argument is a bare parameter with no `const`
  // declaration to resolve one hop through, so it stays unclassifiable (rule (f)). Neither report depends
  // on the parameter happening to be named "sub" -- SUBTLE_METHODS matching is by resolved handle, not by
  // spelling.
  const indirectRoot = mkdtempSync(join(tmpdir(), "crypto-discovery-indirect-"));
  try {
    mkdirSync(join(indirectRoot, "src"), { recursive: true });
    writeFileSync(
      join(indirectRoot, "src", "runtime-algo.ts"),
      'function runDigest(sub: SubtleCrypto, algoName: string, data: ArrayBuffer): Promise<ArrayBuffer> {\n  return sub.digest(algoName, data);\n}\nexport async function callSite(data: ArrayBuffer, chosen: string): Promise<ArrayBuffer> {\n  return runDigest(crypto.subtle, chosen, data);\n}\n',
    );
    const scan = scanIndirectionAndCallSiteAlgorithms(indirectRoot);
    ok(
      "self-test: a SubtleCrypto-typed parameter is reported for indirection regardless of what the receiver is later called",
      scan.subtleCryptoBindings.includes("src/runtime-algo.ts"),
    );
    ok(
      "self-test: a subtle.digest call whose algorithm argument is a bare parameter (no const one hop away) is reported unclassified",
      scan.unclassifiedCalls.some((c) => c.file === "src/runtime-algo.ts" && c.method === "digest" && c.argText === "algoName"),
    );
  } finally {
    rmSync(indirectRoot, { recursive: true, force: true });
  }

  // (vi) unit-test the anchor-identity comparison directly: losing one named anchor's coverage while an
  // unrelated file's coverage is gained must still be reported, even though the covered set's SIZE stays
  // the same as a two-anchor floor would ask for.
  const coveredAfterSwap = new Set(["src/kept-anchor.ts", "src/unrelated-new-file.ts"]);
  const anchorsBeforeSwap = ["src/kept-anchor.ts", "src/dropped-anchor.ts"];
  ok(
    "self-test: a same-count swap (one anchor lost, one unrelated file gained) is reported as a missing anchor",
    missingAnchors(coveredAfterSwap, anchorsBeforeSwap).includes("src/dropped-anchor.ts") && coveredAfterSwap.size === anchorsBeforeSwap.length,
  );

  // (vii) one fixture per ESCAPED HANDLE shape (rule (g)): each plants a resolved crypto.subtle handle
  // reaching exactly one shape the tracer does not follow, in a file that is not on
  // INDIRECTION_ALLOWLIST, and proves indirectionFlagged fires -- so main()'s allowlist check would fail
  // the gate for every one of them. Two of these (object-property, object-destructuring) are the literal
  // shapes an adversarial review defeated this scanner with.
  const escapeFixtures: Array<{ shape: string; file: string; source: string }> = [
    {
      shape: "object-literal property",
      file: "object-property.ts",
      source:
        'const holder = { s: crypto.subtle };\nexport async function weak(key: CryptoKey, iv: Uint8Array, data: ArrayBuffer): Promise<ArrayBuffer> {\n  return holder.s.encrypt({ name: "AES-CBC", iv }, key, data);\n}\n',
    },
    {
      shape: "object destructuring",
      file: "object-destructuring.ts",
      source:
        'const { s } = { s: crypto.subtle };\nexport async function weak(key: CryptoKey, iv: Uint8Array, data: ArrayBuffer): Promise<ArrayBuffer> {\n  return s.encrypt({ name: "AES-CBC", iv }, key, data);\n}\n',
    },
    {
      shape: "array-literal element",
      file: "array-element.ts",
      source: "export const handles: unknown[] = [crypto.subtle];\n",
    },
    {
      shape: "function return value",
      file: "return-value.ts",
      source: "export function getSubtle(): unknown {\n  return crypto.subtle;\n}\n",
    },
    {
      shape: "arrow concise-body return",
      file: "arrow-concise-return.ts",
      source: "export const getSubtle = (): unknown => crypto.subtle;\n",
    },
    {
      shape: "class field",
      file: "class-field.ts",
      source: "export class Holder {\n  s = crypto.subtle;\n}\n",
    },
    {
      shape: "call argument",
      file: "call-argument.ts",
      source: "function store(_x: unknown): void {}\nexport function pass(): void {\n  store(crypto.subtle);\n}\n",
    },
    {
      shape: "computed member access",
      file: "computed-access.ts",
      source:
        "export function call(methodName: string, data: ArrayBuffer): unknown {\n  return (crypto.subtle as unknown as Record<string, (d: ArrayBuffer) => unknown>)[methodName](data);\n}\n",
    },
  ];
  for (const fixture of escapeFixtures) {
    const escapeRoot = mkdtempSync(join(tmpdir(), "crypto-discovery-escape-"));
    try {
      mkdirSync(join(escapeRoot, "src"), { recursive: true });
      writeFileSync(join(escapeRoot, "src", fixture.file), fixture.source);
      const scan = scanIndirectionAndCallSiteAlgorithms(escapeRoot);
      ok(
        `self-test: a handle escaping through ${fixture.shape} sets indirectionFlagged (src/${fixture.file})`,
        scan.subtleCryptoBindings.includes(`src/${fixture.file}`),
      );
    } finally {
      rmSync(escapeRoot, { recursive: true, force: true });
    }
  }

  // (viii) one fixture per ES EXPORT ESCAPE shape: an exported const alias, a named export of a
  // locally-aliased handle, and a default export of a handle. This is the exact axis an adversarial
  // review closed the fixer's dismissal on: a handle exported from one file and consumed in another
  // reached an unapproved algorithm (AES-CBC) while the pre-export-aware gate named nothing.
  const exportEscapeFixtures: Array<{ shape: string; file: string; source: string }> = [
    {
      shape: "exported const alias",
      file: "export-const-alias.ts",
      source: "export const handle = crypto.subtle;\n",
    },
    {
      shape: "named export of a locally-aliased handle",
      file: "export-named-alias.ts",
      source: "const sub = crypto.subtle;\nexport { sub };\n",
    },
    {
      shape: "default export of a handle",
      file: "export-default-handle.ts",
      source: "export default crypto.subtle;\n",
    },
  ];
  for (const fixture of exportEscapeFixtures) {
    const escapeRoot = mkdtempSync(join(tmpdir(), "crypto-discovery-export-escape-"));
    try {
      mkdirSync(join(escapeRoot, "src"), { recursive: true });
      writeFileSync(join(escapeRoot, "src", fixture.file), fixture.source);
      const scan = scanIndirectionAndCallSiteAlgorithms(escapeRoot);
      ok(
        `self-test: a handle escaping through ${fixture.shape} sets indirectionFlagged (src/${fixture.file})`,
        scan.subtleCryptoBindings.includes(`src/${fixture.file}`),
      );
    } finally {
      rmSync(escapeRoot, { recursive: true, force: true });
    }
  }
}

function main(): void {
  if (process.argv.includes("--self-test")) selfTest();

  console.log("\ncrypto discovery census over src/, scripts/ and tools/");
  const c = census(process.cwd());
  const manifest = loadManifest(MANIFEST_PATH);
  const d = diff(c.entries, manifest);

  ok(`the walk found at least one file (found ${c.totalFiles})`, c.totalFiles > 0);
  ok(`at least ${SUBTLE_FILES_FLOOR} files call crypto.subtle (found ${c.subtleFiles.size})`, c.subtleFiles.size >= SUBTLE_FILES_FLOOR);
  ok(`at least ${NOBLE_FILES_FLOOR} files import @noble/* (found ${c.nobleFiles.size})`, c.nobleFiles.size >= NOBLE_FILES_FLOOR);
  const missingSubtleAnchors = missingAnchors(c.subtleFiles, SUBTLE_COVERAGE_ANCHORS);
  ok(`every pinned crypto.subtle anchor file is still discovered${missingSubtleAnchors.length ? ` (missing: ${missingSubtleAnchors.join(", ")})` : ""}`, missingSubtleAnchors.length === 0);
  const missingNobleAnchors = missingAnchors(c.nobleFiles, NOBLE_COVERAGE_ANCHORS);
  ok(`every pinned @noble/* anchor file is still discovered${missingNobleAnchors.length ? ` (missing: ${missingNobleAnchors.join(", ")})` : ""}`, missingNobleAnchors.length === 0);
  ok(
    `every discovered call site is in the manifest${d.undocumented.length ? ` (undocumented: ${d.undocumented.slice(0, 10).map(entryKey).join(", ")}${d.undocumented.length > 10 ? ", ..." : ""})` : ""}`,
    d.undocumented.length === 0,
  );
  ok(`every manifest row is still discovered${d.stale.length ? ` (stale: ${d.stale.slice(0, 10).map(entryKey).join(", ")}${d.stale.length > 10 ? ", ..." : ""})` : ""}`, d.stale.length === 0);
  ok(`every algorithm is on the approved list${d.unapproved.length ? ` (unapproved: ${d.unapproved.map(entryKey).join(", ")})` : ""}`, d.unapproved.length === 0);

  const scan = scanIndirectionAndCallSiteAlgorithms(process.cwd());
  const badBindings = scan.subtleCryptoBindings.filter((f) => !INDIRECTION_ALLOWLIST.has(f));
  ok(`no file binds a SubtleCrypto/Crypto-typed value or passes one as an argument outside the reviewed indirection allowlist${badBindings.length ? ` (${badBindings.join(", ")})` : ""}`, badBindings.length === 0);
  const badUnclassified = scan.unclassifiedCalls.filter((call) => !INDIRECTION_ALLOWLIST.has(call.file));
  ok(
    `every subtle.* call's algorithm argument is a literal the scanner can classify, or the file is on the reviewed indirection allowlist${badUnclassified.length ? ` (${badUnclassified.map((call) => `${call.file}:${call.method}(${call.argText})`).join(", ")})` : ""}`,
    badUnclassified.length === 0,
  );
  ok(
    `every subtle.* call site's classified algorithm is on the approved list${scan.unapprovedCalls.length ? ` (${scan.unapprovedCalls.map((call) => `${call.file}:${call.method}=${call.argText}`).join(", ")})` : ""}`,
    scan.unapprovedCalls.length === 0,
  );

  const twin = verifyTwin(fileURLToPath(import.meta.url));
  ok(`the shared scanner vocabulary matches its own pinned hash and the console twin (${twin.message})`, twin.ok);

  console.log(failures === 0 ? "\nCRYPTO DISCOVERY CENSUS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

if (process.argv.includes("--dump-manifest")) {
  const c = census(process.cwd());
  const rows = c.entries.slice().sort((a, b) => entryKey(a).localeCompare(entryKey(b)));
  const seen = new Set<string>();
  const deduped = rows.filter((e) => {
    const key = entryKey(e);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  process.stdout.write(`${JSON.stringify(deduped, null, 2)}\n`);
} else {
  main();
}
