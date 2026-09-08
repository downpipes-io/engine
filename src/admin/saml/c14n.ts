// Exclusive XML Canonicalization (exc-c14n#, http://www.w3.org/2001/10/xml-exc-c14n#) over an XmlElement
// subtree, producing the canonical UTF-8 byte string an XML-DSig digest and SignedInfo signature are computed
// over. This is THE most security-critical code in the native SAML SP: a c14n bug is a SILENT
// signature-bypass (an attacker signs one byte-sequence and the SP digests a different one, or a non-empty
// node canonicalises to "" and the digest matches an empty string the attacker controls - the libxml2
// void-canon class). Every rule below tracks the W3C exc-c14n# REC and the Canonical XML REC it layers on; the
// security-relevant deviations from "obvious" serialisation (namespace exclusivity, the xmlns="" condition,
// the node sort, the explicit-empty-tag form) are called out at their sites.
//
// SCOPE: this canonicalises a connected element SUBTREE (the whole node and all its descendants are in the
// node-set), which is exactly what XML-DSig needs - the Reference target subtree and the SignedInfo subtree.
// It does NOT implement arbitrary XPath node-subsets; the only subtraction is the enveloped-signature
// transform, modelled by removing the ds:Signature subtree from the tree BEFORE canonicalising (envelopedCopy
// below), which yields a connected subtree again. The in-scope namespace context inherited from ancestors
// ABOVE the subtree root is supplied explicitly by the caller (the SignedInfo of an enveloped signature is
// canonicalised in the namespace context of its ancestors, per the DSig spec), defaulting to empty.
//
// Node 25 strip-types + Workers compatible: pure functions, Web-only, no DOM, no Node builtins, no enums,
// explicit fields. Character escaping is delegated to the SINGLE shared model in canonical-text.ts.

// G316: the attack-shape ledger. The void-canon defence fires on a hostile shape that reached the digest
// layer's pre-image; that it fired at all is a security event, and it was counted nowhere.
import { noteSamlSignal } from "../saml-signals.ts";
import { decodeXmlText, escapeC14nAttr, escapeC14nText } from "./canonical-text.ts";
import type { XmlChild, XmlElement } from "./xml-node.ts";
import { isNamespaceDecl, localName, nsDeclPrefix, prefixOf } from "./xml-node.ts";

// C14nError is the error-as-value the public canonicalisers return; they NEVER throw out of their API (house
// rule). `reason` is a short stable-ish string for logs and the dsig layer's reject reasons.
export interface C14nError {
  ok: false;
  reason: string;
}
export interface C14nOk {
  ok: true;
  // The canonical UTF-8 string. The digest layer encodes this with TextEncoder (UTF-8) before hashing.
  canonical: string;
}
export type C14nResult = C14nOk | C14nError;

// C14nOptions tune the transform.
export interface C14nOptions {
  // WithComments (http://www.w3.org/2001/10/xml-exc-c14n#WithComments) emits comment nodes as <!--text-->;
  // the base transform DROPS them. Default false (base exc-c14n#). XML-DSig over SAML uses the base form;
  // the flag exists so the algorithm allowlist in dsig.ts can honour a document that legitimately declares
  // the WithComments URI without a second code path.
  withComments?: boolean;
  // The InclusiveNamespaces PrefixList: prefixes (and the token "#default" for the default namespace) that
  // are canonicalised with INCLUSIVE rules - their in-scope declaration is rendered on the apex element of
  // the output even when exclusive rules would omit it as not-visibly-utilised. This is the
  // ec:InclusiveNamespaces escape hatch the spec defines for protocol namespaces that exclusive c14n would
  // otherwise strip. An empty/absent list means pure exclusive behaviour.
  inclusiveNamespacePrefixes?: readonly string[];
  // The namespace context inherited from ancestors ABOVE the subtree root (prefix -> URI). Used when
  // canonicalising SignedInfo, whose enclosing ds:Signature/Assertion ancestors may declare the ds: (and
  // other) prefixes the SignedInfo subtree visibly uses. A prefix mapped to "" means "explicitly undeclared"
  // (an xmlns:foo="" in scope, legal in XML 1.1 / namespace-undeclaration); the default namespace key is "".
  // Defaults to empty: the apex is treated as if no namespaces are in scope from above.
  inheritedContext?: ReadonlyMap<string, string>;
}

// A frame of the inherited namespace context: the live prefix -> URI bindings as we descend, used to RESOLVE
// the URI a visibly-used prefix is bound to (so attribute sort by namespace-URI and the rendered-set value
// comparison are correct). Distinct from the OUTPUT rendered set (renderedAncestors) which tracks what has
// actually been EMITTED on output ancestors. "" maps the default namespace; a value of "" means the prefix is
// currently undeclared in scope.
type NsScope = Map<string, string>;

// renderedAncestors is the OUTPUT-ancestor rendered-namespace stack: for each element we actually emit, the
// set of (prefix -> value) namespace nodes rendered at-or-above it in the OUTPUT. The exclusive rule renders a
// namespace node only when no output ancestor has already rendered the SAME prefix -> value. We carry the
// flattened "effective rendered value for each prefix" so the lookup is O(1): renderedValueFor(prefix) is the
// value last emitted for that prefix by an output ancestor, or undefined if none.
type RenderedSet = Map<string, string>;

// XML_NS_PREFIX is the reserved "xml" prefix bound to the XML namespace. The "xml" prefix is special: it is
// ALWAYS in scope and is NEVER itself output as an xmlns:xml declaration by exc-c14n# unless visibly used AND
// not already rendered. We seed the inherited scope with it so a qualified name like xml:lang resolves, but we
// also never let an xmlns:xml="...XML namespace..." get spuriously emitted (handled by the rendered set being
// pre-seeded - see canonicalSubset). Per the Namespaces REC this binding is immutable.
const XML_NS_URI = "http://www.w3.org/XML/1998/namespace";

function err(reason: string): C14nError {
  return { ok: false, reason };
}

// renderNamespaceNodes computes the namespace declarations to EMIT on `el`'s start tag, already sorted, as a
// list of { prefix, value } where prefix "" is the default namespace. It implements the exclusive
// visibly-utilised + no-redundant-redeclaration rule, the InclusiveNamespaces override, and the xmlns=""
// reset condition. It also MUTATES `liveScope` to reflect this element's own declarations (so descendants
// resolve prefixes correctly) and returns the updated rendered set for the output subtree below `el`.
function computeNamespaceNodes(
  el: XmlElement,
  liveScope: NsScope,
  rendered: RenderedSet,
  inclusivePrefixes: ReadonlySet<string>,
): { nodes: Array<{ prefix: string; value: string }>; nextRendered: RenderedSet } {
  // 1. APPLY this element's own xmlns / xmlns:prefix declarations to the live scope FIRST, so prefix
  //    resolution for this element's own name + attributes, and for descendants, sees them. A declaration
  //    xmlns:foo="" (undeclaration) sets the binding to "" meaning "no namespace"; a bare xmlns="" sets the
  //    default to "". We record the declared bindings so we can decide which to render.
  const declaredHere = new Map<string, string>(); // prefix -> value as DECLARED on this element
  for (const a of el.attrs) {
    if (isNamespaceDecl(a)) {
      const p = nsDeclPrefix(a);
      const v = decodeXmlText(a.value); // a namespace URI may, pathologically, carry entities; decode once.
      declaredHere.set(p, v);
      liveScope.set(p, v);
    }
  }

  // 2. Determine the set of prefixes VISIBLY UTILISED by this element: the prefix of its own qualified name,
  //    plus the prefix of every NON-namespace-declaration attribute. The default namespace ("") is visibly
  //    utilised iff the element's own name is unprefixed. Per the spec, a prefix appearing only inside an
  //    attribute VALUE is NOT visibly utilised (we never inspect values for this).
  const used = new Set<string>();
  used.add(prefixOf(el.name)); // "" if the element name is unprefixed -> default ns visibly used
  for (const a of el.attrs) {
    if (isNamespaceDecl(a)) continue;
    const ap = prefixOf(a.name);
    // An unprefixed attribute is in NO namespace and does NOT visibly use the default namespace
    // declaration (default ns does not apply to attributes per the Namespaces REC), so only add a non-empty
    // attribute prefix.
    if (ap !== "") used.add(ap);
  }

  const nextRendered: RenderedSet = new Map(rendered);
  const out: Array<{ prefix: string; value: string }> = [];

  // Helper: decide + record rendering of one (prefix, value). Exclusive rule: render iff no output ancestor
  // already rendered this prefix bound to this SAME value.
  const considerRender = (prefix: string, value: string): void => {
    const already = nextRendered.get(prefix);
    if (already === value) return; // identical prefix->value already in output scope: omit (exclusivity)
    out.push({ prefix, value });
    nextRendered.set(prefix, value);
  };

  // 3a. INCLUSIVE prefixes (PrefixList).
  renderInclusivePrefixes(inclusivePrefixes, liveScope, considerRender);
  // 3b. EXCLUSIVE rendering for every visibly-utilised non-default prefix.
  renderExclusivePrefixes(used, inclusivePrefixes, liveScope, considerRender);
  // 4. DEFAULT NAMESPACE handling (render or reset).
  renderDefaultNamespace(used, liveScope, nextRendered, out, considerRender);

  // 5. SORT namespace nodes: the default namespace ("") sorts FIRST, then the rest by prefix using UTF-8
  //    code-unit comparison. (Canonical XML: namespace nodes sorted lexicographically by local name, the
  //    default - having no local name - least.)
  out.sort((a, b) => {
    if (a.prefix === b.prefix) return 0;
    if (a.prefix === "") return -1;
    if (b.prefix === "") return 1;
    return codeUnitCompare(a.prefix, b.prefix);
  });

  return { nodes: out, nextRendered };
}

// renderInclusivePrefixes (step 3a) force-renders the PrefixList prefixes that are in scope, per Canonical
// XML: rendered if the prefix has a binding regardless of visible utilisation, still subject to the
// no-redundant rule. "#default" means the default namespace. An inclusive prefix that is undeclared ("") has
// no declaration to render; an undeclared inclusive DEFAULT is left to the step-4 xmlns="" logic.
function renderInclusivePrefixes(inclusivePrefixes: ReadonlySet<string>, liveScope: NsScope, considerRender: (prefix: string, value: string) => void): void {
  for (const p of inclusivePrefixes) {
    const key = p === "#default" ? "" : p;
    const bound = liveScope.get(key);
    if (bound === undefined) continue; // not in scope at all -> nothing to render
    if (key === "" && bound === "") {
      // inclusive default namespace that is undeclared in scope: covered by the xmlns="" logic in step 4.
      continue;
    }
    if (bound === "") continue; // an undeclared inclusive prefix has no declaration to render
    considerRender(key, bound);
  }
}

// renderExclusivePrefixes (step 3b) renders every VISIBLY UTILISED prefix bound to a real (non-empty)
// namespace. The binding comes from the live scope (this element's own declaration, else an ancestor's). A
// prefix used but undeclared for a NON-default prefix is a malformed document; we render nothing for it (we do
// NOT fabricate a binding; the signature/digest catch tampering). The default prefix is handled in step 4.
function renderExclusivePrefixes(used: ReadonlySet<string>, inclusivePrefixes: ReadonlySet<string>, liveScope: NsScope, considerRender: (prefix: string, value: string) => void): void {
  // Sort the used prefixes so emission is deterministic before the final sort (the final sort is the
  // authoritative one; this inner determinism just avoids relying on Set insertion order).
  const usedSorted = Array.from(used).sort(codeUnitCompare);
  for (const p of usedSorted) {
    if (inclusivePrefixes.has(p) || (p === "" && inclusivePrefixes.has("#default"))) {
      // already considered under the inclusive rule above (its binding, if any, was rendered there)
      continue;
    }
    if (p === "") {
      // default namespace visibly utilised by an unprefixed element name: handled with the xmlns="" reset in
      // step 4 so the two mutually exclusive outcomes live in one place.
      continue;
    }
    const v = liveScope.get(p);
    if (v === undefined || v === "") continue; // unbound or undeclared prefix: render nothing
    considerRender(p, v);
  }
}

// renderDefaultNamespace (step 4) handles an element that visibly utilises the default namespace (unprefixed
// name). Two outcomes: (a) the default is bound to a NON-EMPTY URI in scope -> render xmlns="URI" (subject to
// the no-redundant rule); or (b) the default is UNDECLARED here BUT the nearest output ancestor that visibly
// utilised the default had rendered a non-empty default declaration -> emit xmlns="" to RESET it (the spec's
// exact reset condition). Otherwise emit nothing.
function renderDefaultNamespace(used: ReadonlySet<string>, liveScope: NsScope, nextRendered: RenderedSet, out: Array<{ prefix: string; value: string }>, considerRender: (prefix: string, value: string) => void): void {
  if (!used.has("")) return;
  const def = liveScope.get(""); // current default-namespace binding in scope, or undefined
  if (def !== undefined && def !== "") {
    // (a) non-empty default in scope: render unless an output ancestor already rendered the same value.
    considerRender("", def);
    return;
  }
  // (b) default is empty/unbound here. Emit xmlns="" iff an output ancestor rendered a NON-EMPTY default (the
  //     rendered set holds a non-empty value for "") - the only case where the output's default-namespace
  //     context would otherwise leak into this element.
  const ancDefault = nextRendered.get("");
  if (ancDefault !== undefined && ancDefault !== "") {
    out.push({ prefix: "", value: "" }); // xmlns=""
    nextRendered.set("", ""); // the output default is now reset for descendants
  }
}

// codeUnitCompare compares two strings by UTF-16 code units, which for the BMP and via surrogate pairs gives
// the SAME ordering as a UTF-8 byte comparison for all valid Unicode scalar values (this equivalence is a
// known property: UTF-8 byte order == UTF-16 code-unit order == code-point order, because UTF-8 is designed so
// that byte-wise ordering equals code-point ordering, and UTF-16's surrogate range D800-DFFF sits above all
// BMP scalars and below astral ones in both encodings). JavaScript's < on strings is exactly this code-unit
// comparison, so we use it directly. This is the canonical sort key for attributes (by URI then local) and
// for the namespace prefixes.
function codeUnitCompare(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// resolveAttrNamespaceUri returns the namespace URI used as the PRIMARY attribute sort key. An unprefixed
// attribute is in NO namespace (empty URI), and the default namespace never applies to it. A prefixed
// attribute's URI is its prefix's binding in scope; the reserved "xml" prefix resolves to the XML namespace
// even without an explicit declaration. An unbound prefix yields "" (the document is malformed, but we keep
// the function total; the signature/digest mismatch is the real defence).
function resolveAttrNamespaceUri(attrName: string, liveScope: NsScope): string {
  const p = prefixOf(attrName);
  if (p === "") return "";
  if (p === "xml") return XML_NS_URI;
  return liveScope.get(p) ?? "";
}

// serialiseElement appends the canonical serialisation of `el` (and its subtree) to `parts`. `liveScope` is
// the in-scope prefix->URI map INCLUDING ancestors (mutated for this element, then restored for siblings).
// `rendered` is the output-ancestor rendered set. `withComments` and `inclusivePrefixes` are the transform
// options. The InclusiveNamespaces override applies ONLY at the apex of the output (the subtree root); below
// the apex, exclusive rules apply throughout - so `applyInclusive` is true only for the first element.
// SerialiseContext bundles the walk-invariant serialisation state so serialiseElement / serialiseChild stay
// within the 4-parameter limit. `liveScope` is the single mutable in-scope prefix->URI map threaded through
// the whole walk (mutated for an element, then restored for its siblings); `parts` is the output accumulator;
// `withComments` / `inclusivePrefixes` are the transform options.
interface SerialiseContext {
  liveScope: NsScope;
  withComments: boolean;
  inclusivePrefixes: ReadonlySet<string>;
  parts: string[];
}

function serialiseElement(
  el: XmlElement,
  rendered: RenderedSet,
  applyInclusive: boolean,
  ctx: SerialiseContext,
): void {
  const { liveScope, parts } = ctx;
  // Snapshot the scope so we can restore the exact ancestor bindings after this element + its subtree (a
  // child's declarations, or this element's own, must not leak to following siblings).
  const savedScope = new Map(liveScope);

  const { nodes: nsNodes, nextRendered } = computeNamespaceNodes(
    el,
    liveScope,
    rendered,
    applyInclusive ? ctx.inclusivePrefixes : EMPTY_PREFIX_SET,
  );

  // START TAG: "<" + QName, then namespace nodes (already sorted), then attributes (sorted by URI, local).
  parts.push("<");
  parts.push(el.name);
  for (const n of nsNodes) {
    const declName = n.prefix === "" ? "xmlns" : `xmlns:${n.prefix}`;
    parts.push(" ");
    parts.push(declName);
    parts.push('="');
    parts.push(escapeC14nAttr(n.value));
    parts.push('"');
  }

  emitSortedAttributes(el, liveScope, parts);
  parts.push(">");

  // CHILDREN in document order. Comments dropped unless withComments. Text decoded-then-escaped per the text
  // model. Elements recurse with exclusive rules (applyInclusive=false below the apex).
  for (const c of el.children) {
    serialiseChild(c, nextRendered, ctx);
  }

  // END TAG. Empty elements still get an explicit "<a></a>" (start tag already emitted "<a>", here "</a>");
  // exc-c14n# NEVER self-closes. The non-empty assertion at the public boundary guarantees this start+end
  // always yields content for a real element.
  parts.push("</");
  parts.push(el.name);
  parts.push(">");

  // Restore the ancestor scope for following siblings.
  liveScope.clear();
  for (const [k, v] of savedScope) liveScope.set(k, v);
}

// emitSortedAttributes appends the element's real (non-namespace-declaration) attributes to `parts`, sorted by
// (namespace-URI, then local-name) using UTF-8 code-unit comparison, each value decoded then canonically
// re-escaped (the SAME decode the claim reader uses, so signed == consumed).
function emitSortedAttributes(el: XmlElement, liveScope: NsScope, parts: string[]): void {
  const realAttrs = el.attrs.filter((a) => !isNamespaceDecl(a));
  const decorated = realAttrs.map((a) => ({
    a,
    uri: resolveAttrNamespaceUri(a.name, liveScope),
    local: localName(a.name),
  }));
  decorated.sort((x, y) => {
    const u = codeUnitCompare(x.uri, y.uri);
    if (u !== 0) return u;
    return codeUnitCompare(x.local, y.local);
  });
  for (const d of decorated) {
    parts.push(" ");
    parts.push(d.a.name);
    parts.push('="');
    parts.push(escapeC14nAttr(decodeXmlText(d.a.value)));
    parts.push('"');
  }
}

const EMPTY_PREFIX_SET: ReadonlySet<string> = new Set<string>();

function serialiseChild(
  c: XmlChild,
  rendered: RenderedSet,
  ctx: SerialiseContext,
): void {
  const { withComments, parts } = ctx;
  if (c.type === "element") {
    serialiseElement(c, rendered, false, ctx);
    return;
  }
  if (c.type === "text") {
    // Decode entities in the raw text, then re-escape per the canonical text model. Empty text contributes
    // nothing (and a node that decodes to "" emits "").
    parts.push(escapeC14nText(decodeXmlText(c.value)));
    return;
  }
  // comment
  if (withComments) {
    // The WithComments form emits the comment verbatim between delimiters. (Leading/trailing newline handling
    // for comments OUTSIDE the document element does not arise here: we only ever canonicalise a connected
    // element subtree, so every comment has an element parent.)
    parts.push("<!--");
    parts.push(c.value);
    parts.push("-->");
  }
  // base form: comment dropped (emit nothing)
}

// seedScope builds the initial live scope from the caller-supplied inherited context, always including the
// immutable xml -> XML-namespace binding so xml:lang / xml:space resolve. The xml prefix is NEVER emitted as a
// declaration by the rendering logic because it is not added to the rendered set as something to emit (it is
// only rendered if visibly used AND not already rendered; we treat it as PRE-RENDERED by seeding the rendered
// set with xml -> XML_NS_URI, matching the spec note that the xml namespace declaration is not output).
function seedScope(inherited: ReadonlyMap<string, string> | undefined): NsScope {
  const s: NsScope = new Map();
  if (inherited) {
    for (const [k, v] of inherited) s.set(k, v);
  }
  s.set("xml", XML_NS_URI);
  return s;
}

// seedRendered deliberately takes no inherited context. It is documented here why the inherited scope
// must NOT influence the rendered set, so the function stays parameterless to make that contract explicit.
function seedRendered(): RenderedSet {
  // The OUTPUT rendered set starts EMPTY (bar the special xml prefix), NOT pre-populated from the inherited
  // scope. This is a load-bearing exc-c14n# rule and a past silent-bypass trap: the apex of the canonicalised
  // subtree has NO output ancestors, so every namespace it VISIBLY UTILISES that is in scope (whether declared
  // on the apex itself or inherited from above) MUST be rendered on the apex. The inheritedContext supplies
  // prefix RESOLUTION and the xmlns="" reset condition (via the live scope), but it does NOT mean those
  // namespaces were emitted in the OUTPUT - the suppression "already rendered by an output ancestor" applies
  // only to ancestors INSIDE the node-set being canonicalised, which begin at the apex. Pre-seeding the
  // rendered set here would WRONGLY drop the apex's own visibly-used declaration (e.g. SignedInfo re-declaring
  // ds:), changing the signed bytes and breaking interop / verification. The xml prefix is seeded purely so an
  // xmlns:xml declaration is never spuriously emitted (the spec never outputs the xml-namespace declaration).
  const r: RenderedSet = new Map();
  r.set("xml", XML_NS_URI);
  return r;
}

// canonicalize is the public entry point: exc-c14n# of `root` and its subtree, returning the canonical UTF-8
// string as an error-as-value. It enforces the libxml2 void-canon DEFENCE: the canonical form of a real
// (named) element is NEVER empty - the minimum output is "<name></name>" - so a "" result is reported as an
// error rather than returned, which prevents a digest from ever matching an attacker-chosen empty string.
export function canonicalize(root: XmlElement, opts?: C14nOptions): C14nResult {
  if (root === null || root === undefined || root.type !== "element" || typeof root.name !== "string" || root.name.length === 0) {
    return err("c14n: root is not a named element");
  }
  const withComments = opts?.withComments === true;
  const inclusivePrefixes: ReadonlySet<string> = new Set(opts?.inclusiveNamespacePrefixes ?? []);
  const liveScope = seedScope(opts?.inheritedContext);
  const rendered = seedRendered();

  const parts: string[] = [];
  serialiseElement(root, rendered, true, { liveScope, withComments, inclusivePrefixes, parts });
  const canonical = parts.join("");

  // VOID-CANON DEFENCE. A named element must serialise to at least "<name></name>". An empty string here means
  // a logic error (or a hostile shape that slipped the type guard); fail closed rather than hand the digest
  // layer an empty pre-image.
  if (canonical.length === 0) {
    noteSamlSignal("saml-shape-void-canon");
    return err("c14n: produced empty output for a non-empty element (void-canon)");
  }
  return { ok: true, canonical };
}

// cloneWithout returns a structural copy of `el` with every element for which `drop(e)` returns true removed
// from the tree (the dropped element and its whole subtree are excised). Text/comment siblings are preserved.
// Used to implement the enveloped-signature transform without mutating the caller's tree. The copy is deep for
// elements but shares the immutable string-bearing leaf nodes by VALUE (new objects, same string values), so
// the original tree is untouched.
function cloneWithout(el: XmlElement, drop: (e: XmlElement) => boolean): XmlElement {
  const children: XmlChild[] = [];
  for (const c of el.children) {
    if (c.type === "element") {
      if (drop(c)) continue; // excise this element subtree
      children.push(cloneWithout(c, drop));
    } else if (c.type === "text") {
      children.push({ type: "text", value: c.value });
    } else {
      children.push({ type: "comment", value: c.value });
    }
  }
  return {
    type: "element",
    name: el.name,
    attrs: el.attrs.map((a) => ({ name: a.name, value: a.value })),
    children,
  };
}

// envelopedCopy implements the enveloped-signature transform
// (http://www.w3.org/2000/09/xmldsig#enveloped-signature): it returns a copy of `el` with the ds:Signature
// element being verified removed, so the Reference digest is computed over the document MINUS its own
// signature. `signature` is the EXACT Signature element object to remove (object identity, not a name match),
// which is the correct DSig semantics: only the signature ENVELOPING this Reference is stripped, not any other
// signature that might (in a multi-signature document) also be present. Returns the copy; the caller then
// canonicalises it. Removing by identity (===) is the XSW-resistant choice: a wrapped/extra Signature with the
// same QName elsewhere in the tree is NOT removed, so its bytes still affect the digest and a swap is caught.
export function envelopedCopy(el: XmlElement, signature: XmlElement): XmlElement {
  return cloneWithout(el, (e) => e === signature);
}
