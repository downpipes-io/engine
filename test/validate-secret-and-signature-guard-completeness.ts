// Validates the guard families that stand between a stored credential and plaintext, and between a signed
// artefact and one that was never checked.
//
// WHY THIS EXISTS. For every guard, the set of sites a call census can see must equal the set of sites the
// gate actually drives, on the two surfaces covered here: SECRETS AT REST and SIGNATURE VERIFICATION.
//
//   maybeWrapConfigSecret   7 sites  the single WRITE ingress for encryption at rest
//   resolveConfigSecret    11 sites  the READ counterpart, whose refusal is the whole guard
//   hybridVerify           11 sites  every signature the engine checks with a boolean answer
//   validateWormPolicyValue 7 sites  the retention-immutability bound
//   validateAssumeRolePolicy 5 sites the STS role a destination writes under
//   assertNoPlaintextSecretInExport   10 sites outside its own module
//
// THE THREE MUTATION SHAPES a census like this one must catch. An ARGUMENT-shaped guard is deleted outright.
// A CHOICE-OF-FUNCTION guard is swapped to a signature-identical twin that drops exactly one property, so the
// call site changes by one identifier and nothing else. A VERDICT-shaped guard keeps its call and discards
// the answer through a comma expression, so a call census still counts it even though it no longer applies.
//
// WHY THE SECTION C DETECTOR IS PAREN-BALANCED AND DEPTH-AWARE. A non-greedy match on a call's argument
// list, `\\([^;]*?\\)`, stops at the FIRST closing paren -- the NESTED call's paren whenever an argument is
// itself a call. On a site shaped like `hybridVerify(verifier, f(x), true), g(sig))`, that PARSES CLEAN,
// passes `true` as a fourth argument, and discards nothing, so it cannot tell a discarded verdict from a
// consumed one. A green parse is not a live check, and neither is a mutation that compiles.
//
// WHAT IS GRADED HERE.
//   A. BEHAVIOURAL, over the properties an in-process drive can reach. Every cell is TWO-SIDED: a TREATMENT
//      that only the guard survives, and a CONTROL that passes either way, so no cell reads as "everything
//      is refused". The AAD cell is the load-bearing one: without it, deleting the bespoke AAD argument at a
//      wrap site changes nothing any other assertion can see, because the secret is still an envelope.
//   B. CENSUS OF THE CHOICE, over the WHOLE TREE. A hand-kept list of files drifts the moment a file is
//      added, so every total here walks src/ and no file list is kept by hand.
//   C. CENSUS OF THE VERDICT. A call count is blind to a narrowing, so each site must CONSUME its answer.
//      The detector is paren-balanced and depth-aware, because `f(g(x), y)` is a consumed use and
//      `(g(x), y)` is a discarded one, and only the character before the enclosing paren separates them.
//   D. THE NEGATIVE DIRECTION, which is what found the twentieth defect: not which sites name the guard, but
//      which operations are followed by one that does not. Here: every AAD domain must be written AND read
//      (a write-only domain seals what nothing can open; a read-only one opens what nothing seals), nothing
//      may reach past the wrap ingress to the raw enveloper, and every detailed-verdict consumer must treat
//      only "ok" as authorisation, which is what that verdict's own doc comment demands and what no gate
//      checked.
//
// Run: node test/validate-secret-and-signature-guard-completeness.ts

import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { hybridSign, hybridVerify } from "../src/crypto/sign.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import {
  DISCOVERY_SECRET_AAD,
  IDP_SECRET_AAD,
  isWrappedSecret,
  JSM_SECRET_AAD,
  loadConfigWrapKey,
  maybeWrapConfigSecret,
  OTLP_PUSH_SECRET_AAD,
  PUSH_S3_SECRET_AAD,
  PUSH_SECRET_AAD,
  resolveConfigSecret,
  SERVICENOW_SECRET_AAD,
} from "../src/admin/config-secret.ts";
import { UnwrapFaultError } from "../src/admin/diag-records.ts";
import { validateAssumeRolePolicy, validateWormPolicyValue } from "../src/dest/factory-validators.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { blankComments, blankCommentsAndStrings } from "../scripts/lib/blank-comments.mjs";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

// ---- the reader, which asserts its own accounting -------------------------------------------------
//
// READ + COMMENT-DROPPED + QUOTED-DROPPED must equal RAW, exactly, for every identifier this file counts.
// The repo has lost a sweep to a scanner reading a comment as code; a mismatch is a FAILURE here rather than
// a smaller number nobody questions. The blankers are the repo's shared ones rather than a fourth copy.
interface Views {
  raw: string;
  code: string;
  codeNC: string;
  comment: string;
  quoted: string;
}
function views(src: string): Views {
  const codeNC = blankComments(src);
  const code = blankCommentsAndStrings(src);
  const comment = new Array<string>(src.length).fill(" ");
  const quoted = new Array<string>(src.length).fill(" ");
  for (let i = 0; i < src.length; i++) {
    if (codeNC[i] !== src[i]) comment[i] = src[i] as string;
    else if (code[i] !== codeNC[i]) quoted[i] = src[i] as string;
  }
  return { raw: src, code, codeNC, comment: comment.join(""), quoted: quoted.join("") };
}
const cache = new Map<string, Views>();
function read(rel: string): Views {
  const hit = cache.get(rel);
  if (hit) return hit;
  const v = views(readFileSync(join(SRC, rel), "utf8"));
  cache.set(rel, v);
  return v;
}
function count(hay: string, name: string): number {
  return (hay.match(new RegExp(`\\b${name}\\b`, "g")) ?? []).length;
}
let reconciliations = 0;
function reconciled(rel: string, name: string): void {
  const v = read(rel);
  const raw = count(v.raw, name);
  const sum = count(v.code, name) + count(v.comment, name) + count(v.quoted, name);
  reconciliations++;
  ok(`${rel} accounting for ${name}: read+comment+quoted == raw (${raw})`, raw === sum);
}

// srcFiles walks every .ts under src/. NEVER a hand-kept list: a hand-kept list drifts as soon as a file is
// added, which is exactly the failure this file exists to catch one level up.
function srcFiles(dir = SRC, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) srcFiles(p, out);
    else if (p.endsWith(".ts")) out.push(relative(SRC, p));
  }
  return out;
}
const ALL = srcFiles().sort();

// callLines returns every (line number, line) at which `name` is CALLED in code, excluding its own
// declaration, import lists and export lists.
function callLines(rel: string, name: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  const lines = read(rel).code.split("\n");
  const re = new RegExp(`(?<![.\\w$])${name}\\s*\\(`);
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i] as string;
    if (/^\s*import\b/.test(t) || /^\s*export\s*\{/.test(t)) continue;
    if (new RegExp(`(export\\s+)?(async\\s+)?function\\s+${name}\\s*\\(`).test(t)) continue;
    if (!re.test(t)) continue;
    const n = (t.match(new RegExp(`(?<![.\\w$])${name}\\s*\\(`, "g")) ?? []).length;
    for (let k = 0; k < n; k++) out.push({ line: i + 1, text: t });
  }
  return out;
}
function sitesOf(name: string): { file: string; line: number; text: string }[] {
  const out: { file: string; line: number; text: string }[] = [];
  for (const f of ALL) for (const c of callLines(f, name)) out.push({ file: f, ...c });
  return out;
}

// ---- the verdict-discard detector, paren-balanced and depth-aware ---------------------------------
//
// A call's answer is DISCARDED when the call is the left operand of a comma expression inside a GROUPING
// paren: `(await f(x), true)`. It is CONSUMED when the same comma separates arguments of an enclosing CALL:
// `g(await f(x), y)`. The only thing that tells the two apart is whether the character before the enclosing
// `(` is part of an identifier. Anything less than this reads the second as the first, and a census that
// cannot see the mutation it is written to catch is worse than no census at all.
function verdictDiscarded(text: string, name: string): boolean {
  const re = new RegExp(`(?<![.\\w$])${name}\\s*\\(`, "g");
  // The advance sits in the for-update rather than the condition. `while ((m = re.exec(text)) !== null)`
  // hides a mutation inside a test, which is the shape the linter refuses; the loop is otherwise identical
  // and still leans on the shared `re` lastIndex to walk the string.
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const open = text.indexOf("(", m.index);
    let depth = 0;
    let end = -1;
    for (let k = open; k < text.length; k++) {
      if (text[k] === "(") depth++;
      else if (text[k] === ")") {
        depth--;
        if (depth === 0) {
          end = k;
          break;
        }
      }
    }
    if (end < 0) continue;
    let j = end + 1;
    while (j < text.length && text[j] === " ") j++;
    if (text[j] !== ",") continue;
    // a comma follows: find the enclosing open paren and ask whether it is a call's arg list
    let d = 0;
    let enclosing = -1;
    for (let k = m.index - 1; k >= 0; k--) {
      if (text[k] === ")") d++;
      else if (text[k] === "(") {
        if (d === 0) {
          enclosing = k;
          break;
        }
        d--;
      }
    }
    if (enclosing < 0) return true; // a bare comma expression at statement level
    let p = enclosing - 1;
    while (p >= 0 && text[p] === " ") p--;
    // The word before the enclosing paren decides it, and a KEYWORD is not a callee: `return (x, y)` is a
    // comma expression while `note(x, y)` is an argument list, and both end in `word(`, so a keyword
    // exclusion is required or `return (` reads as a call.
    let s = p;
    while (s >= 0 && /[\w$]/.test(text[s] as string)) s--;
    const word = text.slice(s + 1, p + 1);
    const KEYWORD = new Set(["return", "await", "typeof", "void", "delete", "new", "in", "of", "yield", "else", "do", "case", "throw", "instanceof"]);
    const isArgList = word !== "" && !KEYWORD.has(word);
    if (!isArgList) return true;
  }
  return false;
}

async function main(): Promise<void> {
  // =================================================================================================
  // A. BEHAVIOURAL
  // =================================================================================================
  console.log("\n-- A. the guards, driven --\n");

  const key = loadConfigWrapKey(b64urlEncode(crypto.getRandomValues(new Uint8Array(32))));
  const otherKey = loadConfigWrapKey(b64urlEncode(crypto.getRandomValues(new Uint8Array(32))));
  if (key === undefined || otherKey === undefined) throw new Error("the wrap key fixture did not load");

  // A1. the WRITE ingress. TREATMENT: with a key bound, what is stored is an envelope and is NOT the
  // plaintext. CONTROL: with no key bound, the plaintext floor is returned UNCHANGED, so the cell cannot
  // read as "this function always returns an object".
  const secret = "AKIAEXAMPLE/verysecret+value";
  const sealed = await maybeWrapConfigSecret(key, secret);
  // The inequality is FIRST and that ordering is the whole point. Written `isWrappedSecret(sealed) && sealed
  // !== secret`, the type guard narrowed `sealed` to WrappedSecret before the comparison, so `sealed !==
  // secret` compared an object to a string, could never be false, and asserted NOTHING (TS2367). Taken on the
  // unnarrowed `string | WrappedSecret` it is a live test of the plaintext-passthrough failure mode, and the
  // envelope claim then narrows behind it. Two live conjuncts where there was one live and one dead.
  ok("TREATMENT a bound wrap key stores an ENVELOPE, never the plaintext", sealed !== secret && isWrappedSecret(sealed));
  ok("TREATMENT the envelope's ciphertext does not contain the secret", JSON.stringify(sealed).includes(secret) === false);
  const floor = await maybeWrapConfigSecret(undefined, secret);
  ok("CONTROL with NO wrap key the plaintext floor is returned unchanged", floor === secret);

  // A2. THE AAD, and this is the load-bearing cell. Deleting the bespoke AAD argument at a wrap site leaves
  // the credential encrypted, so every other assertion in section A still passes; only a CROSS-DOMAIN open
  // can see it. A secret sealed for the SIEM push header must not open as a destination credential.
  const pushSealed = await maybeWrapConfigSecret(key, secret, PUSH_SECRET_AAD);
  ok("CONTROL a push-header secret opens under its OWN domain", (await resolveConfigSecret(key, pushSealed, PUSH_SECRET_AAD)) === secret);
  let crossDomain = "opened";
  try {
    await resolveConfigSecret(key, pushSealed);
    crossDomain = "opened";
  } catch (e) {
    crossDomain = e instanceof UnwrapFaultError ? e.unwrapFaultCause : "threw";
  }
  ok("TREATMENT the same secret does NOT open under the destination domain", crossDomain !== "opened");

  // A2b. THE WHOLE MATRIX, not one pair of it. Section B's census asserts that each wrap site names the
  // right one of the bespoke domains, but a census that only checks which constant is named at a call site
  // cannot see whether the constant separates anything: two domains that happened to carry the same bytes
  // would pass every census cell and still open each other. Every domain is sealed under itself, opened
  // under itself as the control, and refused under every one of the others.
  const DOMAIN_VALUES: [string, Uint8Array][] = [
    ["PUSH_SECRET_AAD", PUSH_SECRET_AAD],
    ["PUSH_S3_SECRET_AAD", PUSH_S3_SECRET_AAD],
    ["JSM_SECRET_AAD", JSM_SECRET_AAD],
    ["SERVICENOW_SECRET_AAD", SERVICENOW_SECRET_AAD],
    ["OTLP_PUSH_SECRET_AAD", OTLP_PUSH_SECRET_AAD],
    ["DISCOVERY_SECRET_AAD", DISCOVERY_SECRET_AAD],
    ["IDP_SECRET_AAD", IDP_SECRET_AAD],
  ];
  let crossOpens = 0;
  let ownOpens = 0;
  for (const [selfName, selfAad] of DOMAIN_VALUES) {
    const env = await maybeWrapConfigSecret(key, secret, selfAad);
    if ((await resolveConfigSecret(key, env, selfAad)) === secret) ownOpens++;
    for (const [otherName, otherAad] of DOMAIN_VALUES) {
      if (otherName === selfName) continue;
      try {
        await resolveConfigSecret(key, env, otherAad);
        crossOpens++;
      } catch {
        // refused, which is the whole point
      }
    }
  }
  ok(`CONTROL all ${DOMAIN_VALUES.length} domains open under their OWN AAD`, ownOpens === DOMAIN_VALUES.length);
  ok(`TREATMENT no domain opens under any of the other ${DOMAIN_VALUES.length - 1} (${DOMAIN_VALUES.length * (DOMAIN_VALUES.length - 1)} cross-opens attempted)`, crossOpens === 0);
  // The domains must also be DISTINCT as bytes. Two constants set to the same string would satisfy every
  // cell above by opening only "their own" domain, because their own domain would be the same domain.
  const domainBytes = new Set(DOMAIN_VALUES.map(([, a]) => Array.from(a).join(",")));
  ok(`CONTROL the ${DOMAIN_VALUES.length} domain separators are pairwise DISTINCT as bytes`, domainBytes.size === DOMAIN_VALUES.length);

  // A3. the READ counterpart's refusal, which IS the guard. An envelope with no key bound must throw rather
  // than hand back anything that could be mistaken for a credential.
  let keyMissing = "returned";
  try {
    await resolveConfigSecret(undefined, sealed);
  } catch (e) {
    keyMissing = e instanceof UnwrapFaultError ? e.unwrapFaultCause : "threw";
  }
  ok("TREATMENT an envelope with NO wrap key bound is REFUSED, not returned", keyMissing !== "returned");
  ok("CONTROL a legacy plaintext string with no key is returned unchanged", (await resolveConfigSecret(undefined, secret)) === secret);
  let wrongKey = "opened";
  try {
    await resolveConfigSecret(otherKey, sealed);
  } catch {
    wrongKey = "refused";
  }
  ok("CONTROL a ROTATED key is refused rather than returning garbage", wrongKey === "refused");
  ok("CONTROL the right key opens it", (await resolveConfigSecret(key, sealed)) === secret);

  // A4. hybridVerify. TREATMENT: a tampered message and a wrong verifier are both false. CONTROL: the
  // genuine signature is true, so the cell cannot read as "verification always fails".
  const edSeed = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSeed);
  const edPrivate = await crypto.subtle.importKey(
    "pkcs8",
    concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), edSeed),
    "Ed25519",
    false,
    ["sign"],
  );
  const mldsa = mldsaKeygen();
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };
  const message = utf8("the exact bytes a root manifest would carry");
  const sig = await hybridSign(edPrivate, mldsa.secretKey, message);
  ok("CONTROL a genuine hybrid signature verifies", (await hybridVerify(verifier, message, sig)) === true);
  ok("TREATMENT a TAMPERED message does not verify", (await hybridVerify(verifier, utf8("the exact bytes a root manifest would carrY"), sig)) === false);
  const otherMldsa = mldsaKeygen();
  ok("TREATMENT a WRONG post-quantum key does not verify", (await hybridVerify({ ed: edPublic, mldsa: otherMldsa.publicKey }, message, sig)) === false);
  ok("TREATMENT a TRUNCATED signature does not verify", (await hybridVerify(verifier, message, sig.slice(0, sig.length - 1))) === false);
  ok("TREATMENT an EMPTY signature does not verify", (await hybridVerify(verifier, message, new Uint8Array(0))) === false);

  // A5. the WORM bound. TREATMENT: a policy whose window is not a positive whole number arms NOTHING.
  // CONTROL: a conformant policy DOES arm, and a bad MODE is refused by a different clause, so the cell is
  // not "everything is null".
  ok("CONTROL a conformant compliance policy is accepted", validateWormPolicyValue({ mode: "compliance", retentionDays: 30 })?.retentionDays === 30);
  ok("TREATMENT retentionDays 0 arms nothing", validateWormPolicyValue({ mode: "compliance", retentionDays: 0 }) === null);
  ok("TREATMENT a NEGATIVE window arms nothing", validateWormPolicyValue({ mode: "governance", retentionDays: -30 }) === null);
  ok("TREATMENT a FRACTIONAL window arms nothing", validateWormPolicyValue({ mode: "governance", retentionDays: 1.5 }) === null);
  ok("TREATMENT a STRING window arms nothing", validateWormPolicyValue({ mode: "governance", retentionDays: "30" }) === null);
  ok("TREATMENT a missing window arms nothing", validateWormPolicyValue({ mode: "governance" }) === null);
  ok("CONTROL an unknown MODE is refused by its own clause", validateWormPolicyValue({ mode: "immutable", retentionDays: 30 }) === null);

  // A6. the AssumeRole bound.
  const goodArn = "arn:aws:iam::123456789012:role/downpipes-writer";
  ok("CONTROL a conformant role ARN is accepted", validateAssumeRolePolicy({ roleArn: goodArn })?.roleArn === goodArn);
  ok("TREATMENT a non-ARN string is refused", validateAssumeRolePolicy({ roleArn: "downpipes-writer" }) === null);
  ok("TREATMENT a SHORT account id is refused", validateAssumeRolePolicy({ roleArn: "arn:aws:iam::1234:role/x" }) === null);
  ok("TREATMENT a USER arn is refused where a ROLE is required", validateAssumeRolePolicy({ roleArn: "arn:aws:iam::123456789012:user/bob" }) === null);
  ok("TREATMENT an empty roleArn is refused", validateAssumeRolePolicy({ roleArn: "" }) === null);
  ok("CONTROL a garbage duration is dropped while the ARN is kept", validateAssumeRolePolicy({ roleArn: goodArn, durationSeconds: -1 })?.durationSeconds === undefined);

  // =================================================================================================
  // B. CENSUS OF THE CHOICE, over the whole tree
  // =================================================================================================
  console.log("\n-- B. the sites, counted over src/ --\n");

  const FAMILIES: { name: string; sites: number; where: Record<string, number> }[] = [
    {
      name: "maybeWrapConfigSecret",
      // The IdP client secret is sealed at the Worker ingress (POST /idp/connections) under
      // IDP_SECRET_AAD, the eighth domain, exactly as the other sites seal their own classes; the
      // Durable Object that holds the connection never sees it as a bare string.
      sites: 7,
      where: { "admin/router-destinations.ts": 1, "admin/router-discovery.ts": 1, "admin/router-identity.ts": 1, "admin/router-ops.ts": 1, "admin/router-otlp-push.ts": 1, "admin/router-push.ts": 2 },
    },
    {
      name: "resolveConfigSecret",
      // The read half is resolveIdpSecret in oidc-store.ts, which the OIDC and OAuth2 token exchanges
      // both call just-in-time.
      sites: 11,
      where: {
        "admin/oidc-store.ts": 1,
        "admin/router-discovery.ts": 2,
        "admin/router-helpers.ts": 1,
        "admin/router-sources-discovery.ts": 1,
        "cron/otlp-push-pass.ts": 1,
        "cron/siem-push-pass.ts": 2,
        "dest/factory.ts": 1,
        "notify/channels/jsm.ts": 1,
        "notify/channels/servicenow.ts": 1,
      },
    },
    {
      name: "hybridVerify",
      // freshness.ts carries two sites. The site is sound: a failed verify returns null, so the recovery
      // path refuses rather than trusting an unverified RUNLOG.
      sites: 11,
      where: {
        "admin/control-plane-seal.ts": 1,
        "admin/licence.ts": 1,
        "admin/restore-receipt.ts": 1,
        "admin/updates.ts": 1,
        "cron/reconcile-pass.ts": 1,
        "format/bundle.ts": 1,
        "format/freshness.ts": 2,
        "format/keyless.ts": 1,
        "format/reader.ts": 2,
      },
    },
    {
      name: "validateWormPolicyValue",
      sites: 7,
      where: {
        "admin/router-destinations.ts": 1,
        "dest/config-anomalies.ts": 1,
        "dest/factory.ts": 2,
        "sched/scheduler-do-control-plane.ts": 1,
        "sched/scheduler-do-dest-config.ts": 2,
      },
    },
    {
      name: "validateAssumeRolePolicy",
      sites: 5,
      where: { "admin/router-destinations.ts": 1, "dest/config-anomalies.ts": 1, "dest/factory.ts": 1, "sched/scheduler-do-dest-config.ts": 2 },
    },
  ];

  for (const fam of FAMILIES) {
    const found = sitesOf(fam.name).filter((s) => s.file !== declaringFile(fam.name));
    ok(`${fam.name} is called at ${fam.sites} site(s) outside its own module`, found.length === fam.sites);
    const byFile = new Map<string, number>();
    for (const s of found) byFile.set(s.file, (byFile.get(s.file) ?? 0) + 1);
    // The DISTRIBUTION is graded against the whole tree, so a site appearing in a file nobody listed FAILS
    // rather than passing unseen.
    for (const [f, n] of byFile) ok(`${fam.name}: ${f} carries ${n} site(s), and that file is declared`, fam.where[f] === n);
    for (const [f, n] of Object.entries(fam.where)) ok(`${fam.name}: ${f} still carries its ${n} declared site(s)`, (byFile.get(f) ?? 0) === n);
    for (const f of new Set([...byFile.keys(), ...Object.keys(fam.where)])) reconciled(f, fam.name);
  }

  // Named here so the next reader does not have to re-derive that this site exists.
  {
    const sites = sitesOf("assertNoPlaintextSecretInExport").filter((s) => s.file !== "admin/control-plane.ts");
    const inIdentity = sites.filter((s) => s.file === "admin/router-identity.ts");
    ok("assertNoPlaintextSecretInExport is called at 10 site(s) outside its own module", sites.length === 10);
    ok("SIX of them are in router-identity.ts", inIdentity.length === 6);
    ok("and the sixth is the break-glass apply-staged route", inIdentity.some((s) => s.text.includes("staged.export")));
  }

  // =================================================================================================
  // C. CENSUS OF THE VERDICT
  // =================================================================================================
  console.log("\n-- C. every site consumes its answer --\n");

  for (const name of ["hybridVerify", "hybridVerifyDetailed", "validateWormPolicyValue", "validateAssumeRolePolicy", "resolveConfigSecret", "maybeWrapConfigSecret"]) {
    const sites = sitesOf(name).filter((s) => s.file !== declaringFile(name));
    let discarded = 0;
    for (const s of sites) if (verdictDiscarded(s.text, name)) discarded++;
    ok(`${name}: not one of its ${sites.length} site(s) DISCARDS the answer`, discarded === 0);
  }
  // The detector must be able to see the thing it is written to catch, or its zero means nothing.
  ok("POSITIVE CONTROL the detector sees a comma-expression discard", verdictDiscarded("return (await hybridVerify(v, m, s), true);", "hybridVerify"));
  ok("POSITIVE CONTROL it sees one whose arguments are themselves calls", verdictDiscarded("x = (await hybridVerify(v, f(m), g(s)), true);", "hybridVerify"));
  ok("NEGATIVE CONTROL it does NOT flag a call passed as an argument", verdictDiscarded("await note(await hybridVerify(v, m, s), tag);", "hybridVerify") === false);
  ok("NEGATIVE CONTROL nor an ordinary guarded call", verdictDiscarded("if (!(await hybridVerify(v, m, s))) throw x;", "hybridVerify") === false);

  // =================================================================================================
  // D. THE NEGATIVE DIRECTION
  // =================================================================================================
  console.log("\n-- D. what is NOT guarded --\n");

  // D1. Every AAD domain must be both WRITTEN and READ. A domain sealed by nothing opens nothing; a domain
  // opened by nothing means a credential class was sealed under a label no reader passes, and every read of
  // it fails closed at runtime with an aead-tag error that blames a key rotation. Neither is visible to a
  // plain count of call sites.
  const DOMAINS = ["PUSH_SECRET_AAD", "PUSH_S3_SECRET_AAD", "JSM_SECRET_AAD", "SERVICENOW_SECRET_AAD", "OTLP_PUSH_SECRET_AAD", "DISCOVERY_SECRET_AAD", "IDP_SECRET_AAD"];
  const wrapSites = sitesOf("maybeWrapConfigSecret").filter((s) => s.file !== "admin/config-secret.ts");
  const readSites = sitesOf("resolveConfigSecret").filter((s) => s.file !== "admin/config-secret.ts");
  for (const d of DOMAINS) {
    const written = wrapSites.some((s) => s.text.includes(d)) || wrapSites.some((s) => /,\s*aad\s*\)/.test(s.text));
    const readBack = readSites.some((s) => s.text.includes(d)) || readSites.some((s) => /,\s*aad\s*\)/.test(s.text));
    ok(`${d} is sealed by at least one write site`, written);
    ok(`${d} is opened by at least one read site`, readBack);
  }
  // And the pair count itself: the bespoke domains plus the default, and the default's own two sites.
  ok(`the ${DOMAINS.length} bespoke AAD domains are all declared in config-secret.ts`, DOMAINS.every((d) => read("admin/config-secret.ts").code.includes(`export const ${d}`)));

  // D1b. EVERY SITE'S OWN DOMAIN. Dropping the bespoke AAD argument at a wrap site leaves the credential
  // ENCRYPTED, the call counted, the verdict consumed and every behavioural cell above green -- the only
  // thing that changes is WHICH domain sealed it, and the damage lands later, at a read, as an aead-tag
  // error that blames a key rotation that never happened. A domain is a per-SITE fact, so it is asserted
  // per site.
  const DOMAIN_BY_SITE: Record<string, string> = {
    // wrap sites
    // Still the same call, still no bespoke AAD, so still the default domain. Worth writing down: Azure's
    // SAS token and its Entra client secret do NOT add a wrap site, because router-destinations.ts:80
    // carries all three Azure credential kinds in the secretAccessKey field, so they are sealed by this one
    // call under this one domain. The count assertion above would not tell you that; a new secret kind that
    // skipped the wrap entirely would leave the count unchanged and the credential in plaintext.
    "admin/router-destinations.ts:215": "default", // the destination secretAccessKey, CONFIG_SECRET_AAD
    "admin/router-discovery.ts:395": "DISCOVERY_SECRET_AAD",
    // The IdP client secret's write ingress. It is the last console-set credential class that would
    // otherwise land in Durable Object storage as a bare string; it is sealed here, in the Worker, because
    // the DO holds no wrap key.
    "admin/router-identity.ts:863": "IDP_SECRET_AAD",
    "admin/router-ops.ts:41": "aad", // the JSM / ServiceNow shared writer, whose domain is its own argument
    "admin/router-otlp-push.ts:120": "OTLP_PUSH_SECRET_AAD",
    "admin/router-push.ts:265": "PUSH_SECRET_AAD",
    "admin/router-push.ts:268": "PUSH_S3_SECRET_AAD",
    // read sites
    // resolveIdpSecret, the just-in-time read both the OIDC and the OAuth2 token exchange make. It is the
    // ONE read site for this class: nothing else may open an IdP client secret.
    "admin/oidc-store.ts:183": "IDP_SECRET_AAD",
    "admin/router-discovery.ts:208": "DISCOVERY_SECRET_AAD",
    "admin/router-discovery.ts:303": "DISCOVERY_SECRET_AAD",
    "admin/router-helpers.ts:95": "DISCOVERY_SECRET_AAD",
    "admin/router-sources-discovery.ts:113": "DISCOVERY_SECRET_AAD",
    "cron/otlp-push-pass.ts:83": "OTLP_PUSH_SECRET_AAD",
    // The census is keyed by file:line ON PURPOSE -- a declaration that followed the code automatically
    // would pass over a site nobody had looked at -- so line drift reds this gate and the coordinates must
    // be re-read rather than derived. Both sites pass distinct AADs, downpipes/push-secret/v1 and
    // downpipes/push-s3-secret/v1, so the separation this file exists to prove holds.
    "cron/siem-push-pass.ts:212": "PUSH_SECRET_AAD",
    "cron/siem-push-pass.ts:216": "PUSH_S3_SECRET_AAD",
    "dest/factory.ts:252": "default",
    "notify/channels/jsm.ts:246": "JSM_SECRET_AAD",
    "notify/channels/servicenow.ts:134": "SERVICENOW_SECRET_AAD",
  };
  {
    const all = [...wrapSites, ...readSites];
    ok(`every wrap and read site has a declared domain (${all.length} sites)`, all.length === Object.keys(DOMAIN_BY_SITE).length);
    let matched = 0;
    for (const s of all) {
      const kkey = `${s.file}:${s.line}`;
      const want = DOMAIN_BY_SITE[kkey];
      // A site whose key is absent FAILS rather than being skipped: an eleventh site added without a domain
      // is exactly what this census exists to catch, and a lookup miss reading as a pass is how gates rot.
      if (want === undefined) {
        ok(`${kkey} is a site nobody declared a domain for`, false);
        continue;
      }
      const call = s.text.slice(s.text.indexOf("("));
      const passes = want === "default" ? !/_SECRET_AAD|,\s*aad\s*\)/.test(call) : call.includes(want);
      ok(`${kkey} seals or opens under ${want}`, passes);
      if (passes) matched++;
    }
    ok("every credential site carries its OWN domain, so no two classes can be cross-opened", matched === all.length);
  }

  // D2. NOTHING may reach past the write ingress to the raw enveloper. maybeWrapConfigSecret is the only
  // thing that decides whether a credential is sealed at all; a caller that reaches wrapConfigSecret
  // directly has taken that decision away from the one place that makes it.
  for (const name of ["wrapConfigSecret", "unwrapConfigSecret"]) {
    const outside = sitesOf(name).filter((s) => s.file !== "admin/config-secret.ts" && !s.text.includes("maybeWrap"));
    ok(`nothing outside config-secret.ts calls ${name} directly`, outside.length === 0);
  }

  // D3. THE DETAILED VERDICT IS A DIAGNOSIS, NEVER AN AUTHORISATION, in that verdict's own words: "only 'ok'
  // means the signature verified, and every other member (however benign its cause) is a refusal the caller
  // must treat as one." Two of its five members exist precisely to say the artefact is PROVABLY INTACT, so a
  // caller that reads them as reassurance would be reading the doc comment's own warning backwards. Nothing
  // checked that. Every consumer must compare against "ok" and nothing else.
  const verdictConsumers: { file: string; line: number; text: string }[] = [];
  for (const f of ALL) {
    const lines = read(f).code.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i] as string;
      if (!/(hybridVerifyDetailed|verifyControlPlaneSignatureDetailed|verifySealedControlPlaneSignatureDetailed)\s*\(/.test(t)) continue;
      if (/^\s*(export\s+)?(async\s+)?function\s/.test(t)) continue;
      verdictConsumers.push({ file: f, line: i + 1, text: t });
    }
  }
  ok("the detailed verdict is produced at 10 site(s) across the tree", verdictConsumers.length === 10);
  // A site either COMPARES the verdict against "ok", or FORWARDS it up to a caller that must. The two
  // wrappers are forwards by construction: their whole purpose is to carry the verdict out of the crypto
  // layer with its diagnosis intact. Anything else is a site that read a five-member union as a boolean.
  //
  // THE WINDOW IS READ OFF codeNC, NOT code: the STRING-BLANKED view turns `=== "ok"` into `===      `, so
  // slicing it would make every comparison in the tree read as absent. A census that blanks the very
  // literal it is looking for cannot see a pass either.
  let compares = 0;
  let forwards = 0;
  for (const c of verdictConsumers) {
    const lines = read(c.file).codeNC.split("\n");
    const window = lines.slice(c.line - 1, c.line + 12).join("\n");
    const comparesOk = /===\s*"ok"|!==\s*"ok"/.test(window);
    const isForward = /^\s*return await (hybridVerifyDetailed|verify\w*SignatureDetailed)\s*\(/.test(c.text);
    ok(`${c.file}:${c.line} compares the verdict against "ok", or forwards it intact`, comparesOk || isForward);
    // FORWARD is tested FIRST because it is a LINE-level fact while comparesOk is a WINDOW-level one: a
    // forward that sits eight lines above its wrapper's boolean sibling has that sibling's `=== "ok"` inside
    // its window, so testing the looser window check first would count both as compares and never as
    // forwards.
    if (isForward) forwards++;
    else if (comparesOk) compares++;
  }
  ok("exactly TWO sites forward the verdict rather than compare it", forwards === 2);
  ok("and every other site compares it against \"ok\" and nothing else", compares === verdictConsumers.length - forwards);
  // The two forwards are only safe if THEIR callers compare. Graded rather than assumed.
  for (const w of ["verifyControlPlaneSignatureDetailed", "verifySealedControlPlaneSignatureDetailed"]) {
    const callers = sitesOf(w).filter((s) => s.file !== declaringFile(w));
    let ok2 = 0;
    for (const s of callers) {
      const window = read(s.file).codeNC.split("\n").slice(s.line - 1, s.line + 12).join("\n");
      if (/===\s*"ok"|!==\s*"ok"/.test(window)) ok2++;
    }
    ok(`${w}: all ${callers.length} caller(s) compare the forwarded verdict against "ok"`, callers.length > 0 && ok2 === callers.length);
  }

  console.log(`\n${reconciliations} identifier accounting reconciliation(s), all exact`);
  console.log(failures === 0 ? `\nSECRET AND SIGNATURE GUARD COMPLETENESS PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

// declaringFile answers where a helper is declared, by walking the tree rather than by a lookup table, so a
// helper that MOVES does not silently drop out of its own census.
function declaringFile(name: string): string {
  for (const f of ALL) {
    const code = read(f).code;
    if (new RegExp(`export\\s+(async\\s+)?function\\s+${name}\\s*\\(`).test(code)) return f;
    if (new RegExp(`export\\s+const\\s+${name}\\s*[:=]`).test(code)) return f;
  }
  throw new Error(`no declaration found for ${name}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
