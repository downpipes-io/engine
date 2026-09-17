#!/usr/bin/env node
// Dead-vocabulary gate.
//
// WHY. A closed-vocabulary member with NO PRODUCER is coverage-shaped nothing: the pack's vocabulary promises a
// support engineer that it will tell them when X happened, and nothing can ever put X there. That is WORSE than
// an honest absence, because an absence makes you look and a promised-but-empty class makes you conclude it did
// not happen.
//
// This is not hypothetical: a `delete-denied` class for a destination whose DELETE is refused (you
// can write backups but never expire them, so retention silently does not work) can ship with a probe
// that returns ok:true for a denied delete, so nothing can ever emit it. The suite can stay green even
// then, because a test that posts a hand-written record straight into the recorder and asserts it comes
// back only proves the ring can carry the class. It never proves the product can put it there.
//
// A MEMBER MUST BE PRODUCED FOR THE VOCABULARY IT BELONGS TO. Asking only "does the literal appear
// anywhere in src outside its own declaration" cannot separate two vocabularies that share a spelling. For
// example, "pending" and "disabled" can have ZERO producers in SETTLE_STEP_DETAIL_CLASSES (the settle
// reports a MEASURED flight, and a measured flight is alive, dead or ailing) while passing that weaker
// check, because both literals are all over src as CanaryLiveness members. A literal written into a
// CanaryLiveness slot produces a CanaryLiveness and nothing else.
//
// So the gate compiles the repo and asks the TYPE CHECKER which vocabulary each occurrence belongs to. An
// occurrence carries a SLOT: the closed set of strings the position accepts.
//
//   contextual type   a property, an argument, an element of an annotated array or lookup table, an `as` cast,
//                     an annotated return
//   compared operand  `row.status === "pending"` tests against the type of row.status
//   classifier return an equality test or `case` label inside a function that RETURNS the vocabulary (the
//                     `if (d === "alive") return d` idiom, where the value returned is a narrowed identifier and
//                     no member literal is ever written at the return). The return type is searched one level
//                     into its object properties, because the codebase's guards return `{ok:true, cls}`.
//   an inline list    `new Set(["alive","dead","ailing","pending","disabled"])` is an inline vocabulary: the
//                     slot is the list's own members
//   another vocab     a literal sitting in ANOTHER `as const` vocabulary's declaration. That is a declaration,
//                     not a producer -- unless that other vocabulary is a sub-list of this one (a classifier's
//                     narrower selection), which RELATED() below allows
//   a lookup table    `const T = { length: "invalid-runid-length" } as const` has no contextual type at all, so
//                     the table's USES are followed: `bump(env, T[kind])` types the value at the use site
//
// A slot is the vocabulary's own when it is RELATED to it: the same set, a narrower selection out of it, or a
// union that CONTAINS it (one `bump(name: AdminCounterName)` takes the union of several declared lists).
//
// THE RESIDUE. Some sinks in this engine take a plain `string` (`recordAuthSignalEdge(scheduler, name: string)`
// posts it to the DO, which drops any name outside the vocabulary). The checker can say nothing about those, so
// they are DECLARED, per sink, in WIDE_SINKS below, with the membership test that makes each one safe. A member
// whose only occurrences are at an unmodelled untyped site is reported dead: that is the point. If it is a real
// producer, model the sink here and say why.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { requireFreshSiblings } from "./sibling-freshness.mjs";
import { reportSiblings } from "./lib/sibling-lag.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ts = createRequire(path.join(ROOT, "package.json"))("typescript");

// Vocabularies this repo VALIDATES but does not EMIT. The producers live in the other repo.
// CLIENT_* vocabularies are all console-PRODUCED and engine-RECEIVED: the engine holds the twin only to
// re-validate an incoming ring, so a member with no engine producer is correct, not dead. Their producers are
// checked by the console's own dead-vocab gate.
const EXEMPT = new Set(["CLIENT_DIAG", "CLIENT_CRASH", "CLIENT_BULK", "CLIENT_SETTLE", "CLIENT_SKEW", "CLIENT_ROUTE", "CLIENT_FAULT"]);
// RESTORE_REJECT_REASONS is the same shape: the CHECKER picks the reason in the console and POSTs it, and
// this engine only re-validates it against RESTORE_REJECT_REASON_SET. There is no engine producer and there must
// not be one -- the engine inventing a rejection reason on the checker's behalf is the bug, not the coverage.
EXEMPT.add("RESTORE_REJECT_REASONS");
// PRUNE_REJECT_REASONS is the identical shape one screen over: the checker picks the reason in the
// console's break-glass prune-approvals inbox and POSTs it (client-retention-prune.ts retentionPruneReject),
// and this engine only re-validates it against PRUNE_REJECT_REASON_SET (scheduler-do-prune-approval.ts
// rejectPruneApproval). Without this exemption the gate would read all three named members
// (stale-plan/policy/too-broad) as having no producer, on the same principle RESTORE_REJECT_REASONS states above.
EXEMPT.add("PRUNE_REJECT_REASONS");
// ATTACH_TAGGABLE_CLASSES is an ALLOW-LIST, not a recorder vocabulary: a binding-change PHASE tags its own throw
// with a class it already produced under ATTACH_REFUSAL_CLASSES / ATTACH_FAULT_CLASSES, and the tagger checks it
// against this list (discovery-health.ts ATTACH_TAGGABLE_SET). Its producers are those vocabularies, and this
// gate checks each of them on its own, so a dead class cannot hide behind the allow-list.
EXEMPT.add("ATTACH_TAGGABLE_CLASSES");
const isExempt = (name) => [...EXEMPT].some((p) => name.startsWith(p));

// COMPOSERS emit a member by BUILDING its name from a template literal over closed sets
// (`claim-drop-${boundary}-${kind}`), so the member literal is never written anywhere in src and no slot can be
// read for it. Composition is modelled PER MEMBER rather than per vocabulary, because the vocabularies are
// MIXED: eleven of the fourteen update-degradation names are plain literals at the degradation site, and the
// three self-check ones are composed. A composer nothing CALLS produces nothing, and its members are reported
// dead -- that is what a half-wired composer looks like. Whether every point of the cross-product is reachable
// is not a static question; test/validate-posture-evidence.ts walks the product and pins each composed name.
const COMPOSERS = [
  { fn: "claimDropCounter", prefix: "claim-drop-" },
  { fn: "alertEmissionCounter", prefix: "alert-emit-" },
  { fn: "updateRefusalCounter", prefix: "update-refused-" },
  { fn: "selfCheckDegradationCounter", prefix: "update-degraded-selfcheck-" },
  // noteUpdateAttempt composes `update-${kind}` inline over its own three-member kind union. The prefixes are
  // the three names it can build, listed exactly, so it can never vouch for a member it cannot produce.
  { fn: "noteUpdateAttempt", prefix: "update-settle-inconclusive" },
  { fn: "noteUpdateAttempt", prefix: "update-settle-refused" },
  { fn: "noteUpdateAttempt", prefix: "update-rollback-refused" },
];

// WIDE SINKS: the sites where a member is written into a plain `string`, so the checker has nothing to say and
// the gate would otherwise report a live member dead. Each entry names the call and the vocabulary it feeds, and
// each is safe for the same reason: the RECEIVER re-validates the name against the vocabulary's own set and
// DROPS a non-member, so the vocabulary really is the closed set of what can land.
//
// This list is the gate's only shrug, and it is a narrow one: it admits the ARGUMENT of a named call, not a
// vocabulary. A member that appears at no other site than an unlisted untyped one is dead until someone models
// the sink and says why here.
const WIDE_SINKS = [
  // POST /auth-signal -> the scheduler DO drops any name outside AUTH_SIGNAL_NAMES (the redaction boundary; see
  // sched-fault-ledger.ts "auth-signal" dropped-write kind, which counts exactly that drop).
  { call: "recordAuthSignalEdge", vocab: "AUTH_SIGNAL_NAMES" },
  { call: "recordScimSignal", vocab: "AUTH_SIGNAL_NAMES" },
  { call: "recordAuthSignalThrottled", vocab: "AUTH_SIGNAL_NAMES" },
  { call: "recordAuthSignal", vocab: "AUTH_SIGNAL_NAMES" },
  { call: "onAuthDeny", vocab: "AUTH_SIGNAL_NAMES" },
  // recordAuthzRefusal(storage, gate: string) drops a gate outside AUTHZ_GATE_SET (sched-fault-ledger.ts:2281).
  { call: "recordAuthzRefusal", vocab: "AUTHZ_GUARD_GATES" },
  { call: "recordAuthzRefusalEdge", vocab: "AUTHZ_GUARD_GATES" },
  // section(name, ...) is the pack's gatherer. buildSupportBundle stamps every SUPPORT_SECTION_NAMES member the
  // gather did not produce as "error", and validate-support pins the produced keys to the roster, so the roster
  // and the section() calls are held equal by a test rather than by a type.
  { call: "section", vocab: "SUPPORT_SECTION_NAMES" },
  // the update degradation list is accumulated as string[] / Set<string> and bumped through the closed counter
  // names on the way out (posture-counters.ts).
  // recordCorsRejection POSTs {name} straight to the same DO route as a JSON body rather than through
  // recordAuthSignalEdge, so the sink is the ROUTE: any body on /auth-signal lands in AUTH_SIGNAL_NAMES or is
  // dropped by the same handler.
  { call: "fetch", route: "/auth-signal", vocab: "AUTH_SIGNAL_NAMES" },
  // POST /diag/governance-refusal is the EDGE half of the governance ledger: the router posts {stage, reason} as
  // a body, and the DO hands both straight to recordGovernanceRefusal, which re-checks each against its closed
  // set and records NOTHING for a non-member (scheduler-do-support-diag.ts, "the redaction chokepoint").
  { call: "fetch", route: "/diag/governance-refusal", vocab: "GOVERNANCE_REFUSAL_REASONS" },
  { call: "fetch", route: "/diag/governance-refusal", vocab: "GOVERNANCE_STAGES" },
  { call: "degradations.push", vocab: "UPDATE_DEGRADATION_COUNTER_NAMES" },
  { call: "degraded?.add", vocab: "UPDATE_DEGRADATION_COUNTER_NAMES" },
];

const SRC = path.join(ROOT, "src");
const cfgPath = ts.findConfigFile(ROOT, ts.sys.fileExists, "tsconfig.json");
const cfg = ts.readConfigFile(cfgPath, ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(cfg.config, ts.sys, path.dirname(cfgPath));
const program = ts.createProgram(parsed.fileNames, parsed.options);
const checker = program.getTypeChecker();
const sources = program.getSourceFiles().filter((sf) => !sf.isDeclarationFile && sf.fileName.startsWith(SRC + path.sep));
const ALL_SRC = sources.map((sf) => sf.getFullText()).join("\n");

const MEMBER = /^[a-z][a-z0-9-]{2,}$/;

// The vocabularies: `export const NAME = [...] as const`, keyed by FILE + NAME, not by name. Three vocabulary
// names are declared in two files each (ADMIN_REFUSAL_REASONS and DROPPED_WRITE_KINDS in diag-records.ts and
// sched-fault-ledger.ts, UPDATE_COMPONENTS in diag-records.ts and update-orchestrate.ts), deliberately: they are
// different closed sets serving different records. Keying on the bare name made the second declaration overwrite
// the first, so one whole vocabulary per collision was never scanned.
const worlds = []; // every closed literal set the engine declares (see related())
const vocab = [];
const declArrays = new Map(); // array literal node -> its own member set (an `as const` list IS a closed slot)
for (const sf of sources) {
  const visit = (node) => {
    if (ts.isVariableStatement(node)) {
      // EXPORTED lists only. An unexported `const NAMES = [...] as const` is a local helper (cf-config-diff's
      // IDENTITY_KEYS is iterated to index a Cloudflare object), not a vocabulary the pack promises.
      const exported = node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) === true;
      for (const d of node.declarationList.declarations) {
        if (!exported || !ts.isIdentifier(d.name) || !/^[A-Z][A-Z0-9_]+$/.test(d.name.text)) continue;
        const init = d.initializer;
        if (init === undefined || !ts.isAsExpression(init) || !ts.isArrayLiteralExpression(init.expression)) continue;
        if (init.type.getText() !== "const") continue;
        const arr = init.expression;
        // `members` is the WHOLE declared set, read off the CHECKER rather than the source elements, because a
        // vocabulary can be assembled by SPREAD (AUTH_SIGNAL_NAMES spreads the three SAML lists into itself).
        // Reading the elements alone made the set incomplete, so a slot typed with the full union looked like
        // someone else's vocabulary and a LIVE member was reported dead. It is what the checker shows at a slot,
        // so the subset test has to be against all of it; `checked` is what this gate rules on: the lower-case
        // tokens that are pack vocabulary rather than, say, a list of header names.
        const tupleArgs = checker.getTypeArguments(checker.getTypeAtLocation(arr));
        const members = new Set(tupleArgs.filter((t) => (t.flags & ts.TypeFlags.StringLiteral) !== 0).map((t) => t.value));
        if (members.size === 0) continue;
        const checked = [...members].filter((m) => MEMBER.test(m));
        declArrays.set(arr, members);
        worlds.push(members);
        // spreads: is the list ASSEMBLED from other lists (`...SAML_ATTACK_SHAPES`)? That is what licenses a
        // narrower slot to count as a producer (see related()).
        const spreads = arr.elements.some((e) => ts.isSpreadElement(e));
        if (checked.length >= 2 && !isExempt(d.name.text)) vocab.push({ name: d.name.text, members, checked, spreads, arr, file: sf.fileName });
      }
    }
    if (ts.isTypeAliasDeclaration(node)) {
      const t = node.type;
      const parts = ts.isUnionTypeNode(t) ? t.types : [t];
      const lits = parts.filter((x) => ts.isLiteralTypeNode(x) && ts.isStringLiteral(x.literal)).map((x) => x.literal.text);
      if (lits.length >= 2 && lits.length === parts.length) worlds.push(new Set(lits));
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// A closed-set signature: the string-literal members of a type, undefined/null stripped. Anything wider (a bare
// `string`, a number, an object) is not usable evidence and returns null: a literal handed to a `(name: string)`
// parameter says nothing about which vocabulary it belongs to. A ONE-member set is treated the same way, because
// a slot spelled `status: "pending"` names one state and cannot say whose vocabulary that state is in.
function closedSet(type) {
  if (type === undefined) return null;
  const parts = type.isUnion() ? type.types : [type];
  const out = new Set();
  for (const t of parts) {
    if (t.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Null | ts.TypeFlags.Never)) continue;
    if (t.flags & ts.TypeFlags.StringLiteral) { out.add(t.value); continue; }
    // `return "pending"` inside `async baseline(): Promise<CanaryLiveness>` is contextually typed
    // `CanaryLiveness | PromiseLike<CanaryLiveness>`, and the PromiseLike arm would otherwise make the whole
    // slot unreadable -- which silently turned a typed producer into an unattributable one.
    if (t.symbol !== undefined && /^(?:Promise|PromiseLike)$/.test(t.symbol.name)) continue;
    return null;
  }
  return out.size < 2 ? null : out;
}
const subsetOf = (a, b) => [...a].every((x) => b.has(x));
// RELATED: the slot is this vocabulary's world. Either the slot is the vocabulary (or a narrower selection out
// of it: a classifier that returns three of its members), or the slot is a union that CONTAINS the vocabulary
// (the counter-name idiom). A slot that is neither -- CanaryLiveness against SETTLE_STEP_DETAIL_CLASSES, where
// each carries a member the other does not -- belongs to someone else.
// RELATED: can this slot hold THIS vocabulary?
//
//   the slot is the vocabulary's own union, or a WIDER one that contains it -- `bump(name: AdminCounterName)`
//   takes the union of several declared lists, and a literal handed to it is a producer of each;
//
//   or the slot is a NARROWER selection out of a vocabulary that is ASSEMBLED BY SPREAD. AUTH_SIGNAL_NAMES
//   spreads the three SAML lists into itself, and noteSamlSignal's parameter is the union of those lists, so a
//   literal written there really is an auth signal. A vocabulary that spreads nothing has no such sub-selections:
//   every producer of it writes into its own union somewhere.
//
// A NARROWER slot into a spread-free vocabulary is REFUSED. Two examples
// from this engine, both of which would otherwise read as producers:
//   canary/cycle.ts's override field is typed `"pending" | "ailing"` -- a subset of SETTLE_STEP_DETAIL_CLASSES'
//   members if "pending" is put back in it, and nothing whatever to do with the settle;
//   CanaryLiveness itself becomes a subset of SETTLE_STEP_DETAIL_CLASSES the moment BOTH "pending" and "disabled"
//   are put back, so a subset rule hands the settle every canary write in the engine.
// WORLDS are every closed literal set the engine DECLARES: each `as const` list and each `type X = "a" | "b"`.
// For a spread-free vocabulary, a NARROWER slot counts only if no OTHER declared world can hold it. That is the
// test that tells a real sub-selection (verifyModeOf returns three of VERIFY_MODES' four, and no other world
// holds those three) from a coincidence (CanaryLiveness is a subset of SETTLE_STEP_DETAIL_CLASSES the moment
// "pending" and "disabled" are put back into it, and every canary write in the engine would become a settle
// producer).
const setEq = (a, b) => a.size === b.size && subsetOf(a, b);
const related = (slot, v) =>
  subsetOf(v.members, slot) || // the vocabulary's own union, or a wider one that contains it
  (subsetOf(slot, v.members) && !worlds.some((w) => subsetOf(slot, w) && !subsetOf(w, v.members)));

// THE LIMIT, stated rather than hidden. The narrow-slot test asks whether an OUTSIDE world can hold the slot. It
// therefore cannot separate two vocabularies where one is a strict SUPERSET of the other, member for member: put
// BOTH "pending" and "disabled" back into SETTLE_STEP_DETAIL_CLASSES and CanaryLiveness becomes a subset of it,
// at which point a canary write is indistinguishable from a settle write by type alone. Either member ALONE is
// caught (CanaryLiveness then carries a member the settle does not, so it is a foreign world), which is what the
// dead-vocabulary case actually looks like; a vocabulary deliberately grown to swallow another whole vocabulary
// is a different thing, and it is what the posture suites and review are for.

// inTypePosition: `type X = "pending" | "alive"` DECLARES a vocabulary; it does not produce a member.
function inTypePosition(node) {
  for (let n = node.parent; n !== undefined; n = n.parent) {
    if (ts.isTypeNode(n)) return true;
    if (ts.isSourceFile(n)) return false;
  }
  return false;
}
// returnSets: the closed sets a function's declared return type can carry, one level into object properties, so
// the `{ ok: true, cleanupState: raw }` guard idiom is legible as well as the bare `return d`.
function returnSets(type) {
  const out = [];
  const direct = closedSet(type);
  if (direct !== null) out.push(direct);
  for (const t of type.isUnion() ? type.types : [type]) {
    if ((t.flags & ts.TypeFlags.Object) === 0) continue;
    for (const p of t.getProperties()) {
      const pt = checker.getTypeOfSymbol(p);
      const s = closedSet(pt);
      if (s !== null) out.push(s);
    }
  }
  return out;
}
function enclosingReturnSets(node) {
  for (let n = node.parent; n !== undefined; n = n.parent) {
    if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n)) {
      const sig = checker.getSignatureFromDeclaration(n);
      return sig === undefined ? [] : returnSets(checker.getReturnTypeOfSignature(sig));
    }
    if (ts.isSourceFile(n)) return [];
  }
  return [];
}
const EQ = new Set([ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken]);

// TABLES: an `as const` object or array with no contextual type (`const T = { length: "invalid-runid-length" }
// as const`) types nothing at the literal, so the table's USES are followed instead: `bump(env, T[kind])` gives
// the value a contextual type at the use site, and that is the slot.
const tableSlots = new Map(); // VariableDeclaration node -> [closed sets]
const identUses = new Map(); // symbol -> [identifier nodes]
for (const sf of sources) {
  const visit = (node) => {
    if (ts.isIdentifier(node)) {
      const sym = checker.getSymbolAtLocation(node);
      if (sym !== undefined) {
        const l = identUses.get(sym);
        if (l === undefined) identUses.set(sym, [node]);
        else l.push(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}
function slotsOfTable(decl) {
  const cached = tableSlots.get(decl);
  if (cached !== undefined) return cached;
  const out = [];
  tableSlots.set(decl, out); // set first: a self-referential table must not recurse forever
  const sym = checker.getSymbolAtLocation(decl.name);
  for (const use of identUses.get(sym) ?? []) {
    if (use === decl.name) continue;
    let e = use;
    while ((ts.isElementAccessExpression(e.parent) || ts.isPropertyAccessExpression(e.parent) || ts.isNonNullExpression(e.parent)) && e.parent.expression === e) e = e.parent;
    const s = closedSet(checker.getContextualType(e));
    if (s !== null) out.push(s);
  }
  return out;
}
// enclosingTable: the `as const` variable declaration this literal is a value inside, if any.
function enclosingTable(node) {
  for (let n = node.parent; n !== undefined; n = n.parent) {
    if (ts.isVariableDeclaration(n)) {
      const init = n.initializer;
      const isConstTable = init !== undefined && ts.isAsExpression(init) && init.type.getText() === "const";
      return isConstTable && ts.isIdentifier(n.name) ? n : null;
    }
    if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) || ts.isSourceFile(n)) return null;
  }
  return null;
}
// wideSinkVocab: the literal is an argument to a modelled untyped sink, or a property of a modelled wire body.
function wideSinkVocab(node) {
  const p = node.parent;
  if (ts.isCallExpression(p) && p.arguments.includes(node)) {
    const callee = p.expression.getText().replace(/^this\./, "");
    const hit = WIDE_SINKS.find((s) => s.call === callee && s.route === undefined);
    if (hit !== undefined) return [hit.vocab];
  }
  const wire = wireCall(node);
  if (wire !== null) {
    const text = wire.getText();
    const hits = WIDE_SINKS.filter((s) => s.route !== undefined && text.includes(s.route)).map((s) => s.vocab);
    if (hits.length > 0) return hits;
  }
  return null;
}
// unattributable: the literal is a property value in an object literal the checker gives NO type to (the DO's
// `return { ownerActionQueued: true, id, status: "pending" }`, whose method has an inferred return type). TS
// widens it to `string`, so it names no vocabulary at all, and crediting it to one is a guess -- the guess that
// let "pending" pass as a SETTLE_STEP_DETAIL_CLASS while every typed occurrence of it in the engine was a
// CanaryLiveness. A table (`const T = {...} as const`) is NOT unattributable: its uses are followed above.
// exactLiteralSlot: the position is typed with the ONE literal being written (`status: "pending"` in the DO's
// owner-action record type, whose 202 the console reads). Such a slot names a single state exactly, and a slot
// that can hold one string cannot vouch for a VOCABULARY: crediting it is what kept "pending" alive as a
// SETTLE_STEP_DETAIL_CLASS after every other route to it was closed. Not a producer, of anything.
function exactLiteralSlot(node) {
  const ctx = checker.getContextualType(node);
  if (ctx === undefined || ctx.isUnion()) return false;
  return (ctx.flags & ts.TypeFlags.StringLiteral) !== 0;
}
// wireCall: the literal is a value inside an object literal handed to JSON.stringify -- a body on the wire, not
// a typed record. The checker knows nothing about it (JSON.stringify takes `any`), so a bare wire write is NOT a
// producer of a pack vocabulary: nothing says which recorder, if any, is on the other end. The wire writes that
// ARE producers are the ones whose ROUTE is known, and those are modelled in WIDE_SINKS with `route` (the DO's
// /auth-signal, whose handler drops any name outside the vocabulary). Returns the enclosing fetch/call statement
// so the route can be read off it.
function wireCall(node) {
  let n = node.parent;
  while (n !== undefined && (ts.isPropertyAssignment(n) || ts.isObjectLiteralExpression(n) || ts.isArrayLiteralExpression(n) || ts.isConditionalExpression(n) || ts.isAsExpression(n) || ts.isSpreadAssignment(n))) n = n.parent;
  if (n === undefined || !ts.isCallExpression(n) || n.expression.getText() !== "JSON.stringify") return null;
  for (let up = n.parent; up !== undefined && !ts.isSourceFile(up); up = up.parent) {
    if (ts.isCallExpression(up)) return up;
    if (ts.isFunctionDeclaration(up) || ts.isMethodDeclaration(up) || ts.isArrowFunction(up)) break;
  }
  return n;
}

// Every occurrence of every member: the closed slots it flows into, plus the wide sink it was handed to.
const flows = new Map();
for (const sf of sources) {
  const visit = (node) => {
    if (ts.isStringLiteral(node) && MEMBER.test(node.text) && !inTypePosition(node)) {
      const p = node.parent;
      const slots = [];
      const push = (s) => { if (s !== null && s !== undefined && s.size >= 2) slots.push(s); };
      push(closedSet(checker.getContextualType(node)));
      // an inline list is an inline vocabulary: `new Set(["alive","dead","ailing","pending","disabled"])` is a
      // CanaryLiveness guard, and a literal sitting in it belongs to the canary, not to whoever shares a spelling
      if (ts.isArrayLiteralExpression(p)) push(new Set(p.elements.filter(ts.isStringLiteral).map((e) => e.text)));
      if (ts.isBinaryExpression(p) && EQ.has(p.operatorToken.kind)) {
        push(closedSet(checker.getTypeAtLocation(p.left === node ? p.right : p.left)));
        for (const s of enclosingReturnSets(node)) push(s);
      }
      if (ts.isCaseClause(p)) for (const s of enclosingReturnSets(node)) push(s);
      if (ts.isPropertyAssignment(p) && p.name === node) {
        const objCtx = checker.getContextualType(p.parent);
        if (objCtx !== undefined) push(new Set(objCtx.getProperties().map((s) => s.name)));
      }
      const table = slots.length === 0 ? enclosingTable(node) : null;
      if (table !== null) for (const s of slotsOfTable(table)) push(s);
      const l = flows.get(node.text) ?? [];
      l.push({ slots, node, sink: wideSinkVocab(node), decl: declArrays.has(p), wire: wireCall(node) !== null || exactLiteralSlot(node), at: `${path.relative(ROOT, sf.fileName)}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1} ${ts.SyntaxKind[p.kind]}` });
      flows.set(node.text, l);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

const calledSomewhere = (fn) => new RegExp(`\\b${fn}\\(`).test(ALL_SRC.replace(new RegExp(`(export )?function ${fn}\\b`, "g"), ""));
const liveComposerPrefixes = COMPOSERS.filter((c) => calledSomewhere(c.fn)).map((c) => c.prefix);
for (const s of WIDE_SINKS) {
  const needle = s.route ?? s.call;
  if (!ALL_SRC.includes(needle)) { console.error(`DEAD-VOCAB GATE: WIDE_SINKS names a sink that is gone: ${needle}`); process.exit(1); }
}

// ===========================================================================
// THE UNREACHABLE PRODUCER.
//
// Everything above asks WHICH VOCABULARY a literal belongs to. It cannot ask whether the branch the literal sits
// in CAN EVER BE TAKEN. `update-refused-split-unrecognised` is bumped at
// router-updates.ts:786 inside `if (typeof body.component === "string" ...)` -- `component`, SINGULAR. The
// console's rollback client sends `components`, PLURAL, and nothing else calls the engine (customers never run a
// terminal). No request any real client can send reaches that bump. The call site is real, it is correctly typed,
// it is in src, and a check that only asks which vocabulary a literal belongs to would say PASS. The member is
// coverage-shaped nothing and a support engineer would look for its row for ever.
//
// SO A PRODUCER COUNTS ONLY IF A REQUEST SHAPE A REAL CLIENT SENDS CAN REACH IT.
//
// THE CLIENTS, exhaustively. The customer never opens a terminal (a house rule, not an assumption), so the only
// things that put a body on an engine route are:
//   1. the CONSOLE, at console/src/lib/api/*.ts. Every request it makes is `engineFetch(url, { body:
//      JSON.stringify(x) })`, so the keys it can send are the keys of x -- read off the CONSOLE'S OWN TYPE
//      CHECKER, not a regex, so `JSON.stringify(dp)` where dp: DownpipeConfig contributes DownpipeConfig's keys;
//   2. the ENGINE ITSELF, calling its own Durable Object (`scheduler.fetch(doURL("/auth-signal"), ...)`) from a
//      route, the cron or the alarm. The DO's routes have exactly one client and it is in this repo.
// A request body key that appears in NEITHER is a key that is ALWAYS `undefined` in production.
//
// THE TEST. For each producer occurrence, walk its control-dependence chain (the `if`/ternary/`&&`/`case` it sits
// inside, up to the route). Evaluate each guard three-valued, with `body.K` = `undefined` when K is a key no
// client sends and UNKNOWN otherwise. If a guard the occurrence needs TRUE folds to a definite FALSE (or one it
// needs FALSE folds to TRUE), no client can reach it and it is not a producer.
//
// CONSERVATIVE BY CONSTRUCTION, because the failure mode of this gate is DELETING A LIVE MEMBER. Unknown is the
// default at every step: a key a client does send, a call, a helper, a value the evaluator cannot fold, a guard
// shape it does not model -- all UNKNOWN, and an UNKNOWN guard never prunes anything. The gate only ever subtracts
// what it can PROVE, and the only thing it proves here is "this key is never in the body".
//
// AND IT FAILS RATHER THAN SKIPS. If a producer is guarded on a request body whose ROUTE it cannot resolve, or
// whose route has no client it can find, the gate does not shrug and count the producer: it FAILS and names the
// route. A gate that quietly opts out when it cannot check reads exactly like a pass, and a pass like that is
// how evidence that is not there ships regardless.
//
// WHAT THIS CHECK CANNOT SEE. The client model is KEY PRESENCE, not VALUE DOMAIN. It
// knows the console sends `components` on POST /update/apply; it does not know that the console's own
// UpdateComponentId is exactly "engine" | "console", the same closed set this build plans. So a producer sitting
// in the refusal arm of a validator over that key -- reachable ONLY by a component id no console can name -- is
// credited: the guard folds to UNKNOWN because the key IS sent. That is how update-refused-split-unrecognised can
// pass with no producer any request could reach, and the empty-array arm of the same validator is why no
// type-level domain model would prune it either (the console's screens, not its api client, decide that the
// array is non-empty). A member whose reachability rests on a VALUE outside the calling client's own closed union
// is dead vocabulary this gate will pass. Justify such a member at review, or do not declare it.
// ===========================================================================

// Routes whose client is NOT the console and NOT this engine: an identity provider (SCIM, the SAML/OIDC/OAuth2
// callbacks), a browser form post, or the control plane. This repo does not own their body shapes, so their keys
// are taken as UNKNOWN (the check never prunes on them) rather than as absent. Each entry is a claim about who
// calls the file, checked below to still exist.
const FOREIGN_CLIENT_FILES = new Map([
  ["src/admin/scim.ts", "SCIM 2.0: the client is the customer's IdP, which sends its own schema-defined body"],
]);
for (const f of FOREIGN_CLIENT_FILES.keys()) {
  if (!sources.some((sf) => path.relative(ROOT, sf.fileName) === f)) {
    console.error(`DEAD-VOCAB GATE: FAIL -- FOREIGN_CLIENT_FILES names a file that is gone: ${f}`);
    process.exit(1);
  }
}

// The console repo. NOT OPTIONAL: without it the gate cannot know which body keys a real client sends, and a gate
// that carries on regardless is a gate that passes everything.
function locateConsole() {
  const cands = [
    process.env.DOWNPIPES_CONSOLE_ROOT,
    path.resolve(ROOT, "..", "support-unified-console"), // the worktree twin of this branch
    path.resolve(ROOT, "..", "console"), // the workspace layout: downpipes/engine + downpipes/console
    path.resolve(ROOT, "..", "..", "console"), // a worktree under downpipes/.worktrees, falling back to the main console
  ].filter((p) => p !== undefined);
  return cands.find((p) => ts.sys.directoryExists(path.join(p, "src", "lib", "api"))) ?? null;
}
const CONSOLE_ROOT = locateConsole();
if (CONSOLE_ROOT === null) {
  console.error("DEAD-VOCAB GATE: FAIL -- cannot find the console repo, so the set of request shapes a real client");
  console.error("sends is unknown and no producer's reachability can be checked. Set DOWNPIPES_CONSOLE_ROOT to the");
  console.error("console checkout (it must contain src/lib/api). The gate refuses to pass a producer it cannot reach.");
  process.exit(1);
}

// WHICH CONSOLE TREE, and REFUSE when it is not the sibling's main.
//
// The paragraph above already commits this gate to the answer: without the console it cannot know which body
// keys a real client sends, "and a gate that carries on regardless is a gate that passes everything". An OLD
// console is a weaker version of the same defect and the only one that is silent, because a stale checkout
// resolves every path happily and answers every question.
//
// The console is not a subject of comparison here, it is the POPULATION. Its request shapes decide which
// producers count as reachable, so a stale client moves the denominator without moving a single line of the
// verdict. A vocabulary term the console has just started sending reads as dead; one it has just stopped
// sending reads as live. Nothing downstream can tell either apart from a real finding.
reportSiblings([{ name: "console", path: CONSOLE_ROOT }], { gate: "dead-vocab-gate" });
requireFreshSiblings([{ name: "console", path: CONSOLE_ROOT }], {
  gate: "dead-vocab-gate",
  consequence: "reachability would be computed from an older client's request shapes than the one that ships",
});

// bodyKeysOf: the top-level keys of a request body expression. An object literal is read key by key (including the
// `...(cond ? { components } : {})` idiom the console uses for optional fields); anything else is read off its
// TYPE, so `JSON.stringify(dp)` contributes every property of DownpipeConfig. A body whose keys cannot be read is
// "*": every key is possible, and the check prunes nothing on that route.
const ANY_KEY = "*";
function bodyKeysOf(expr, chk) {
  const keys = new Set();
  const fromObject = (obj) => {
    for (const p of obj.properties) {
      if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) keys.add(p.name.text);
      else if (ts.isShorthandPropertyAssignment(p)) keys.add(p.name.text);
      else if (ts.isSpreadAssignment(p)) {
        // `...(cond ? { a } : {})` and `...base`
        const inner = [];
        const collect = (e) => {
          if (ts.isParenthesizedExpression(e)) return collect(e.expression);
          if (ts.isConditionalExpression(e)) { collect(e.whenTrue); collect(e.whenFalse); return; }
          inner.push(e);
        };
        collect(p.expression);
        for (const e of inner) {
          if (ts.isObjectLiteralExpression(e)) fromObject(e);
          else if (!fromType(e)) return false;
        }
      } else return false; // a computed key, a method: unreadable
    }
    return true;
  };
  const fromType = (e) => {
    const t = chk.getTypeAtLocation(e);
    if (t === undefined || (t.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) !== 0) return false;
    const props = t.getProperties();
    if (props.length === 0) return false;
    for (const s of props) keys.add(s.name);
    return true;
  };
  const ok = ts.isObjectLiteralExpression(expr) ? fromObject(expr) : fromType(expr);
  return ok === false ? ANY_KEY : keys;
}
// routePathOf: the path a request expression names. `${t.base}/admin/update/rollback` -> /update/rollback (the
// engine's own switch keys are the path with /admin stripped); doURL("/auth-signal") -> /auth-signal. A path with
// an interpolated segment is not a switch-case route (those are matched before the switch), so it is skipped.
function routePathOf(expr) {
  let e = expr;
  if (ts.isCallExpression(e) && e.expression.getText().replace(/^this\./, "") === "doURL") e = e.arguments[0];
  if (e === undefined) return null;
  let text;
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) text = e.text;
  else if (ts.isTemplateExpression(e)) {
    if (e.templateSpans.some((s) => s.literal.text.includes("/") === false && s !== e.templateSpans.at(-1))) return null;
    text = e.head.text + e.templateSpans.map((s) => s.literal.text).join("\u0000");
    if (text.includes("\u0000")) return null; // an id in the middle of the path: a dynamic route, matched before the switch
  } else return null;
  const at = text.indexOf("/admin/");
  const p = at === -1 ? text : text.slice(at + "/admin".length);
  if (!p.startsWith("/")) return null;
  return p.split("?")[0];
}
// clientRequests: every (METHOD path -> body keys) a client can send, harvested from a program's fetch calls.
function clientRequests(prog, chk, files) {
  const out = new Map();
  const add = (method, p, keys) => {
    const k = `${method} ${p}`;
    const prev = out.get(k);
    if (prev === ANY_KEY) return;
    if (keys === ANY_KEY) { out.set(k, ANY_KEY); return; }
    if (prev === undefined) out.set(k, new Set(keys));
    else for (const x of keys) prev.add(x);
  };
  for (const sf of files) {
    const visit = (node) => {
      if (ts.isCallExpression(node) && node.arguments.length >= 2) {
        const init = node.arguments[1];
        if (ts.isObjectLiteralExpression(init)) {
          const p = routePathOf(node.arguments[0]);
          const prop = (n) => init.properties.find((x) => ts.isPropertyAssignment(x) && x.name.getText() === n);
          const bodyProp = prop("body");
          if (p !== null && bodyProp !== undefined) {
            const mProp = prop("method");
            const method = mProp !== undefined && ts.isStringLiteral(mProp.initializer) ? mProp.initializer.text : "GET";
            const b = bodyProp.initializer;
            const isJson = ts.isCallExpression(b) && b.expression.getText() === "JSON.stringify" && b.arguments.length === 1;
            add(method, p, isJson ? bodyKeysOf(b.arguments[0], chk) : ANY_KEY);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return out;
}
const conCfgPath = ts.findConfigFile(CONSOLE_ROOT, ts.sys.fileExists, "tsconfig.json");
const conParsed = ts.parseJsonConfigFileContent(ts.readConfigFile(conCfgPath, ts.sys.readFile).config, ts.sys, path.dirname(conCfgPath));
const conProgram = ts.createProgram(conParsed.fileNames, conParsed.options);
const conChecker = conProgram.getTypeChecker();
const API_DIR = path.join(CONSOLE_ROOT, "src", "lib", "api") + path.sep;
const conApiFiles = conProgram.getSourceFiles().filter((sf) => !sf.isDeclarationFile && sf.fileName.startsWith(API_DIR));
if (conApiFiles.length === 0) {
  console.error(`DEAD-VOCAB GATE: FAIL -- the console at ${CONSOLE_ROOT} compiles no src/lib/api client, so no request shape can be read.`);
  process.exit(1);
}
// THE CLIENT MODEL: the console's admin calls, plus the engine's own calls to its DO and to itself.
const CLIENT_BODIES = clientRequests(conProgram, conChecker, conApiFiles);
for (const [k, v] of clientRequests(program, checker, sources)) {
  const prev = CLIENT_BODIES.get(k);
  if (prev === ANY_KEY) continue;
  if (v === ANY_KEY || prev === undefined) CLIENT_BODIES.set(k, v === ANY_KEY ? ANY_KEY : new Set(v));
  else for (const x of v) prev.add(x);
}

// REQUEST BODIES IN THIS REPO: `const body = (await req.json()) as {...}` and its destructured twin, tagged with
// the route they are read on (the enclosing `case "POST /update/rollback":`) and the file they live in.
const bodyVars = new Map(); // symbol -> { routes: [key], file }
const bodyFields = new Map(); // symbol (a destructured field) -> { routes, file, key }
function routesOf(node) {
  for (let n = node.parent; n !== undefined; n = n.parent) {
    if (ts.isCaseClause(n)) {
      if (!ts.isStringLiteral(n.expression)) return [];
      const out = [n.expression.text];
      // FALLTHROUGH, and only fallthrough: `case "A": case "B": { ... }` shares one block, so a body read in B's
      // block is also read on A. A PRECEDING case that has statements of its own does NOT fall into this one, and
      // crediting it made a POST body look like it was also read on the GET twin next to it.
      const clauses = n.parent.clauses;
      for (let i = clauses.indexOf(n) - 1; i >= 0; i--) {
        const c = clauses[i];
        if (!ts.isCaseClause(c) || !ts.isStringLiteral(c.expression) || c.statements.length > 0) break;
        out.push(c.expression.text);
      }
      return out;
    }
    if (ts.isSourceFile(n)) return [];
  }
  return [];
}
for (const sf of sources) {
  const rel = path.relative(ROOT, sf.fileName);
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      let e = node.initializer;
      while (ts.isAsExpression(e) || ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e)) e = e.expression;
      const isJson = ts.isAwaitExpression(e) && ts.isCallExpression(e.expression) && /^(?:req|request)\.json$/.test(e.expression.expression.getText());
      if (isJson) {
        const routes = routesOf(node);
        if (ts.isIdentifier(node.name)) {
          const sym = checker.getSymbolAtLocation(node.name);
          if (sym !== undefined) bodyVars.set(sym, { routes, file: rel });
        } else if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            if (!ts.isIdentifier(el.name)) continue;
            const sym = checker.getSymbolAtLocation(el.name);
            const key = el.propertyName !== undefined ? el.propertyName.getText().replace(/"/g, "") : el.name.text;
            if (sym !== undefined) bodyFields.set(sym, { routes, file: rel, key });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// unresolved: a body-guarded producer whose route (or whose route's client) the gate cannot find. Collected, not
// swallowed: the gate FAILS on these.
const unresolved = new Map();
// clientKeysFor: the keys a real client can put in this body. null = cannot resolve (the caller must fail).
function clientKeysFor(info) {
  if (FOREIGN_CLIENT_FILES.has(info.file)) return ANY_KEY;
  if (info.routes.length === 0) return null;
  const acc = new Set();
  for (const r of info.routes) {
    const k = CLIENT_BODIES.get(r);
    if (k === undefined) return null; // a route no client in either repo posts a body to
    if (k === ANY_KEY) return ANY_KEY;
    for (const x of k) acc.add(x);
  }
  return acc;
}

// THE EVALUATOR. Three-valued: a definite `undefined`, a definite literal, or UNKNOWN. UNKNOWN is the default and
// UNKNOWN never prunes.
const UNDEF = { k: "undef" };
const UNKNOWN = { k: "unknown" };
const lit = (v) => ({ k: "lit", v });
function bodyRefOf(node, env) {
  // body.KEY / body["KEY"]
  let obj = null, key = null;
  if (ts.isPropertyAccessExpression(node)) { obj = node.expression; key = node.name.text; }
  else if (ts.isElementAccessExpression(node) && node.argumentExpression !== undefined && ts.isStringLiteral(node.argumentExpression)) { obj = node.expression; key = node.argumentExpression.text; }
  if (obj === null || !ts.isIdentifier(obj)) return null;
  const sym = checker.getSymbolAtLocation(obj);
  const info = sym === undefined ? undefined : bodyVars.get(sym);
  if (info === undefined) return null;
  env.touchedBody = true;
  const keys = clientKeysFor(info);
  if (keys === null) { env.unresolvable = info; return UNKNOWN; }
  if (keys === ANY_KEY) return UNKNOWN;
  return keys.has(key) ? UNKNOWN : UNDEF;
}
function evalExpr(node, env, depth = 0) {
  if (depth > 24) return UNKNOWN;
  const rec = (n) => evalExpr(n, env, depth + 1);
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node)) return rec(node.expression);
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return lit(node.text);
  if (ts.isNumericLiteral(node)) return lit(Number(node.text));
  if (node.kind === ts.SyntaxKind.TrueKeyword) return lit(true);
  if (node.kind === ts.SyntaxKind.FalseKeyword) return lit(false);
  if (node.kind === ts.SyntaxKind.NullKeyword) return lit(null);
  if (ts.isIdentifier(node)) {
    if (node.text === "undefined") return UNDEF;
    const sym = checker.getSymbolAtLocation(node);
    if (sym === undefined) return UNKNOWN;
    const field = bodyFields.get(sym);
    if (field !== undefined) {
      env.touchedBody = true;
      const keys = clientKeysFor(field);
      if (keys === null) { env.unresolvable = field; return UNKNOWN; }
      if (keys === ANY_KEY) return UNKNOWN;
      return keys.has(field.key) ? UNKNOWN : UNDEF;
    }
    return env.locals.get(sym) ?? UNKNOWN;
  }
  const br = bodyRefOf(node, env);
  if (br !== null) return br;
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    // a read THROUGH a definitely-undefined value cannot be reached at all; the guard above it is what decides,
    // so this stays UNKNOWN rather than pretending to know what a throw evaluates to.
    return UNKNOWN;
  }
  if (ts.isTypeOfExpression(node)) {
    const v = rec(node.expression);
    if (v.k === "undef") return lit("undefined");
    if (v.k === "lit") return lit(v.v === null ? "object" : typeof v.v);
    return UNKNOWN;
  }
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
    const t = truthOf(node.operand, env, depth + 1);
    return t === undefined ? UNKNOWN : lit(!t);
  }
  if (ts.isConditionalExpression(node)) {
    const t = truthOf(node.condition, env, depth + 1);
    if (t === true) return rec(node.whenTrue);
    if (t === false) return rec(node.whenFalse);
    return UNKNOWN;
  }
  if (ts.isCallExpression(node)) {
    // Array.isArray(x) on a value that is definitely undefined is definitely false. Every other call is UNKNOWN.
    if (node.expression.getText() === "Array.isArray" && node.arguments.length === 1 && rec(node.arguments[0]).k === "undef") return lit(false);
    return UNKNOWN;
  }
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    if (EQ.has(op)) {
      const a = rec(node.left), b = rec(node.right);
      if (a.k === "unknown" || b.k === "unknown") return UNKNOWN;
      const strict = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken;
      const av = a.k === "undef" ? undefined : a.v;
      const bv = b.k === "undef" ? undefined : b.v;
      // biome-ignore lint/suspicious/noDoubleEquals: this evaluator reproduces the graded source's own loose-equality semantics when the source wrote ==.
      const eq = strict ? av === bv : av == bv;
      const neg = op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
      return lit(neg ? !eq : eq);
    }
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      const l = truthOf(node.left, env, depth + 1);
      if (l === false) return lit(false);
      const r = truthOf(node.right, env, depth + 1);
      if (r === false) return lit(false);
      return l === true && r === true ? rec(node.right) : UNKNOWN;
    }
    if (op === ts.SyntaxKind.BarBarToken) {
      const l = truthOf(node.left, env, depth + 1);
      if (l === true) return rec(node.left);
      const r = truthOf(node.right, env, depth + 1);
      if (l === false) return rec(node.right);
      return r === true ? UNKNOWN : UNKNOWN;
    }
    if (op === ts.SyntaxKind.QuestionQuestionToken) {
      const l = rec(node.left);
      if (l.k === "undef") return rec(node.right);
      if (l.k === "lit" && l.v !== null) return l;
      return UNKNOWN;
    }
  }
  return UNKNOWN;
}
function truthOf(node, env, depth = 0) {
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
    const l = truthOf(node.left, env, depth + 1);
    if (l === false) return false;
    const r = truthOf(node.right, env, depth + 1);
    if (r === false) return false;
    return l === true && r === true ? true : undefined;
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
    const l = truthOf(node.left, env, depth + 1);
    if (l === true) return true;
    const r = truthOf(node.right, env, depth + 1);
    if (r === true) return true;
    return l === false && r === false ? false : undefined;
  }
  const v = evalExpr(node, env, depth);
  if (v.k === "undef") return false;
  if (v.k === "lit") return Boolean(v.v);
  return undefined;
}
// envFor: the local consts in scope at the occurrence, folded in source order, so `const dryRun = body.dryRun ===
// true;` and `const c = parse(body.components);` carry their value (or their UNKNOWN) into the guard.
const envCache = new Map();
function envFor(fn) {
  const hit = envCache.get(fn);
  if (hit !== undefined) return hit;
  const env = { locals: new Map(), unresolvable: null, touchedBody: false };
  envCache.set(fn, env);
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) {
      if (node !== fn) return; // a nested closure has its own scope; its guards are evaluated in their own env
    }
    // CONST ONLY, and this is load-bearing. A `let` is REASSIGNED, and folding its initialiser would wrongly
    // "prove" a live member unreachable: `let degraded = false; ... degraded = true; if
    // (degraded) bump("degraded-read-preflight-roster")` folds to `if (false)` if the initialiser is trusted.
    // A `let` is UNKNOWN, always.
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer !== undefined) {
      const isConst = (ts.getCombinedNodeFlags(node) & ts.NodeFlags.Const) !== 0;
      const sym = checker.getSymbolAtLocation(node.name);
      if (isConst && sym !== undefined && !bodyVars.has(sym) && !bodyFields.has(sym)) env.locals.set(sym, evalExpr(node.initializer, env));
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(fn, visit);
  return env;
}
function enclosingFunction(node) {
  for (let n = node.parent; n !== undefined; n = n.parent) {
    if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n)) return n;
    if (ts.isSourceFile(n)) return n;
  }
  return null;
}
// unreachable: no request a real client can send takes the branch this occurrence sits in.
const reachStats = { bodyGuarded: new Set(), pruned: new Set() };
const reachCache = new Map();
function unreachable(node) {
  const hit = reachCache.get(node);
  if (hit !== undefined) return hit;
  reachCache.set(node, false); // a guard that recurses into itself is not evidence of anything
  const fn = enclosingFunction(node);
  if (fn === null) return false;
  const env = envFor(fn);
  env.unresolvable = null;
  env.touchedBody = false;
  let verdict = false;
  for (let n = node; n.parent !== undefined && !ts.isSourceFile(n); n = n.parent) {
    const p = n.parent;
    if (ts.isIfStatement(p)) {
      if (p.thenStatement === n && truthOf(p.expression, env) === false) verdict = true;
      if (p.elseStatement === n && truthOf(p.expression, env) === true) verdict = true;
    } else if (ts.isConditionalExpression(p)) {
      if (p.whenTrue === n && truthOf(p.condition, env) === false) verdict = true;
      if (p.whenFalse === n && truthOf(p.condition, env) === true) verdict = true;
    } else if (ts.isBinaryExpression(p) && p.right === n && (p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) && truthOf(p.left, env) === false) {
      verdict = true;
    } else if (ts.isCaseClause(p) && ts.isSwitchStatement(p.parent.parent)) {
      const d = evalExpr(p.parent.parent.expression, env);
      const c = evalExpr(p.expression, env);
      if (d.k !== "unknown" && c.k !== "unknown" && !(d.k === c.k && d.k === "undef") && (d.k === "undef") !== (c.k === "undef")) verdict = true;
      else if (d.k === "lit" && c.k === "lit" && d.v !== c.v) verdict = true;
    }
  }
  if (env.unresolvable !== null && !verdict) {
    const info = env.unresolvable;
    const at = `${info.file} ${info.routes.length === 0 ? "(no route: the body is read outside a switch case)" : info.routes.join(", ")}`;
    unresolved.set(at, (unresolved.get(at) ?? 0) + 1);
  }
  // ONE LEVEL OUT (the sibling-site discipline). The literal is often not written in the guarded branch itself but
  // in a helper the branch calls (`if (bad) await noteRefusal(scheduler, "x")` is the easy case; `if (bad) return
  // refuse(scheduler)` is not). A helper whose EVERY call site is unreachable is itself unreachable. Bails to
  // REACHABLE the moment it cannot see all the call sites -- a function used as a value (a callback, a re-export)
  // has callers this gate cannot enumerate, and one with no call site in src at all is the plain no-producer case
  // the rest of the gate already rules on.
  if (!verdict && fn !== null && !ts.isSourceFile(fn)) {
    const sites = allCallSites(fn);
    if (sites !== null && sites.length > 0 && sites.every((s) => unreachable(s))) verdict = true;
  }
  const key = `${node.getSourceFile().fileName}:${node.getStart()}`;
  if (env.touchedBody) reachStats.bodyGuarded.add(key);
  if (verdict) reachStats.pruned.add(key);
  reachCache.set(node, verdict);
  return verdict;
}
// allCallSites: every call of this function in src, or null when they cannot all be seen.
function allCallSites(fn) {
  let nameNode = null;
  if (ts.isFunctionDeclaration(fn) && fn.name !== undefined) nameNode = fn.name;
  else if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)) nameNode = fn.parent.name;
  if (nameNode === null) return null; // a method, an inline callback: its callers are not enumerable this way
  const sym = checker.getSymbolAtLocation(nameNode);
  if (sym === undefined) return null;
  const out = [];
  for (const use of identUses.get(sym) ?? []) {
    if (use === nameNode) continue;
    const p = use.parent;
    if (p === undefined || !ts.isCallExpression(p) || p.expression !== use) return null; // used as a value
    out.push(p);
  }
  return out;
}

// produced: is there an occurrence that could put this member in the pack under THIS vocabulary?
//
//   an occurrence inside ANY vocabulary's declaration is a DECLARATION, not a producer -- not even in a twin
//     list with the same members (the engine declares VERIFY_FAIL_STAGES twice, and the two lists crediting each
//     other is exactly how eight stage names no recorder can ever note stayed green for so long);
//   an occurrence at a modelled wide sink for this vocabulary is a producer;
//   an occurrence with a CLOSED slot is a producer only if some slot is RELATED to this vocabulary -- if every
//     slot it has belongs to another vocabulary, the checker has PROVED it foreign;
//   an occurrence the checker cannot close at all (an untyped helper, a `(name: string)` parameter) is taken as
//     a producer, as the old literal scan did. The gate only ever subtracts what it can prove;
//   EXCEPT an UNATTRIBUTABLE write -- a property of a JSON.stringify body with no known route, or of an object
//     literal the checker gives no type to -- which proves nothing about any vocabulary and is not counted. The
//     routed wire writes are the WIDE_SINKS `route` entries.
// hasOwnSlot: does ANY occurrence of ANY of this vocabulary's members land in a slot that can hold the WHOLE
// vocabulary (its own union, or a wider one)? If so the vocabulary is typed, and a NARROWER slot that another
// world can hold is not evidence for it. If not, the vocabulary is only ever written through narrower sibling
// unions (ATTACH_TAGGABLE_CLASSES is tagged from the attach PHASE classes) and the subset is all the evidence
// there is.
const produced = (v, mem) =>
  (flows.get(mem) ?? []).some((o) => {
    if (o.decl) return false;
    if (unreachable(o.node)) return false; // no request a real client sends takes this branch
    if (o.sink !== null && o.sink.includes(v.name)) return true;
    if (o.slots.length > 0) return o.slots.some((s) => related(s, v));
    return !o.wire;
  });

// COMPOSED MEMBERS AND REACHABILITY. A composed name is never written whole, so there is no occurrence of it to
// walk. What IS written is the PART the caller chooses -- `noteUpdateGuardRefusal(..., "split-unrecognised")`
// composes `update-refused-split-unrecognised` -- and that part is a trailing chunk of the member's name. So the
// producer sites of a composed member are the occurrences of its TRAILING CHUNKS, and the member is produced only
// if one of them is reachable.
//
// Over-credits rather than under-credits, deliberately: a chunk shared by two composed members (claim-drop's
// `groups-list-capped` rides four boundaries) vouches for all of them. It cannot delete a live member, and it
// still catches the whole-branch case where EVERY occurrence of the chunk is behind a guard
// no client can satisfy, so nothing can compose the member.
//
// A composer with an EMPTY remainder (noteUpdateAttempt builds `update-settle-refused` whole) is judged on its own
// call sites.
const composerSites = new Map(); // fn -> [call nodes]
for (const sf of sources) {
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText().replace(/^this\./, "");
      if (COMPOSERS.some((c) => c.fn === callee)) (composerSites.get(callee) ?? composerSites.set(callee, []).get(callee)).push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}
const chunkReachable = (mem, prefix) => {
  const rest = mem.slice(prefix.length);
  const chunks = [];
  for (const [text, occs] of flows) if (text.length >= 3 && rest.endsWith(text)) chunks.push(occs);
  if (chunks.length === 0) return null; // nothing in src spells any part of this member: the composer cannot build it
  return chunks.some((occs) => occs.some((o) => !o.decl && !unreachable(o.node)));
};
const composedProducer = (mem) =>
  COMPOSERS.some((c) => {
    if (!mem.startsWith(c.prefix) || !calledSomewhere(c.fn)) return false;
    const sites = composerSites.get(c.fn) ?? [];
    if (mem === c.prefix) return sites.some((s) => !unreachable(s)); // the composer builds this name whole
    const r = chunkReachable(mem, c.prefix);
    return r === null ? false : r;
  });

if (process.env.DEAD_VOCAB_DEBUG !== undefined) {
  const [dv, dm] = process.env.DEAD_VOCAB_DEBUG.split(":");
  const v = vocab.find((x) => x.name === dv);
  for (const o of flows.get(dm) ?? []) console.error(`  ${o.at} decl=${o.decl} wire=${o.wire} sink=${o.sink} slots=${o.slots.map((s) => `{${[...s].slice(0, 4).join(",")}}(${s.size})${related(s, v.members) ? " RELATED" : ""}`).join(" | ")}`);
}
const dead = [];
for (const v of vocab) {
  for (const mem of v.checked) {
    if (composedProducer(mem) || produced(v, mem)) continue;
    const occs = flows.get(mem) ?? [];
    const hadOne = occs.some((o) => !o.decl);
    const why = hadOne && occs.every((o) => o.decl || unreachable(o.node))
      ? "every producer sits behind a guard NO REAL CLIENT CAN SATISFY (a request-body key the console never sends and the engine never posts to itself)"
      : "no occurrence of the literal flows into a slot of THIS vocabulary";
    dead.push({ vocab: `${v.name} -- ${path.relative(ROOT, v.file)}`, member: mem, why });
  }
}

// FLOORS ON THE DENOMINATOR. Everything above this line reasons about members it FOUND; the PASS below
// says every member has a producer, and over an empty scan that sentence is true and worthless. The
// vocabularies are discovered by walking src and reading `export const NAME = [...] as const`, so an
// empty scan is an ordinary accident: src moves, the declaration idiom changes, or the extension filter
// in the walk is edited. The engine currently declares well over 200 vocabularies holding well over 2000
// checked members. The floors sit at 100 and 800, comfortably under both, so removing a dead vocabulary
// (which is exactly what this gate asks for) never trips them, while a collapse cannot be reported as clean.
const MIN_VOCABULARIES = 100;
const MIN_CHECKED_MEMBERS = 800;
const checkedMembers = vocab.reduce((n, v) => n + v.checked.length, 0);
if (vocab.length < MIN_VOCABULARIES || checkedMembers < MIN_CHECKED_MEMBERS) {
  console.error(`\nDEAD-VOCAB GATE: FAIL -- scanned ${vocab.length} closed vocabularies holding ${checkedMembers} members, expected at least ${MIN_VOCABULARIES} and ${MIN_CHECKED_MEMBERS}.\n`);
  console.error("The scan is no longer reading this engine's closed vocabularies, so it cannot say whether any member");
  console.error("is dead. Check that src/ is where the walk looks and that the vocabularies still declare themselves as");
  console.error("an exported `as const` list. A pass over nothing is the one answer this gate must never give.");
  process.exit(1);
}

console.log(`DEAD-VOCAB GATE: ${vocab.length} closed vocabularies scanned, typed, holding ${checkedMembers} checked members (client-diag twins exempt: they are received, not emitted)`);
console.log(`DEAD-VOCAB GATE: client model: ${CLIENT_BODIES.size} request shapes from ${path.relative(path.dirname(ROOT), CONSOLE_ROOT)}/src/lib/api + this engine's own cron/DO calls`);
console.log(`DEAD-VOCAB GATE: reachability: ${reachStats.bodyGuarded.size} producer occurrence(s) are control-dependent on a request body; ${reachStats.pruned.size} unreachable by any client`);
if (unresolved.size > 0) {
  console.error("\nDEAD-VOCAB GATE: FAIL -- a producer is guarded on a request body whose CLIENT cannot be resolved.\n");
  console.error("The gate will not credit a producer it cannot reach. Either the route has no client (the producer is");
  console.error("dead), or the client is one this model does not know: add it to FOREIGN_CLIENT_FILES with the reason,");
  console.error("or teach clientRequests() to read the call. Skipping the check would read exactly like a pass.\n");
  for (const [at, n] of unresolved) console.error(`  ${at} (${n} guarded producer occurrence(s))`);
  process.exit(1);
}
if (dead.length === 0) {
  console.log("DEAD-VOCAB GATE: PASS -- every member is written into a slot of its OWN vocabulary, in a branch a real client can reach");
  process.exit(0);
}
const byVocab = {};
for (const d of dead) {
  byVocab[d.vocab] ??= [];
  byVocab[d.vocab].push(d.member);
}
console.error(`\nDEAD-VOCAB GATE: FAIL -- ${dead.length} member(s) can NEVER be emitted.\n`);
console.error("Each one is a promise the pack cannot keep. Either WIRE the producer at the fault site, or REMOVE");
console.error("the member. Leaving it tells a support engineer the evidence was looked for and not found.");
console.error("A literal that only ever lands in ANOTHER vocabulary's slot is not a producer of this one.\n");
for (const [v, ms] of Object.entries(byVocab)) {
  console.error(`  ${v} (${ms.length})`);
  for (const m of ms) console.error(`      ${m} -- ${dead.find((d) => `${d.vocab}` === v && d.member === m).why}`);
}
process.exit(1);
