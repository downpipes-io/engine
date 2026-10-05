// In-product source attach: the engine adds source bindings TO ITSELF through the
// Cloudflare API, so an owner never leaves the console to protect a source once the
// engine is deployed. The one hard constraint: this must
// NEVER drop or alter the engine's OWN bindings (its scheduler/seal Durable Objects,
// the R2 archive, its secrets), because that would brick the running engine. So the
// whole operation is a SAFETY MECHANISM that proves it is safe before it writes and
// verifies it stayed safe after, and REFUSES to the wrangler-deploy path on any doubt:
//
//   1. READ the engine's CURRENT bindings from the script-settings endpoint (the SAME
//      endpoint the write uses, so the read needs no permission the write does not, and
//      the read shape equals the write shape). Refuse on any unexpected shape.
//   2. IDENTITY GUARD: the read must contain the engine's required Durable Object
//      bindings (SCHEDULER + RUNSEAL). A read missing them is not this engine (or a
//      bad read), so refuse rather than risk modifying a stranger or on stale data.
//   3. VALIDATE the additions: each is a valid, non-reserved source binding whose name
//      does not collide with an existing one. Refuse otherwise.
//   4. COMPUTE the new set = every existing NON-redacted binding re-sent VERBATIM, plus
//      the new source bindings. Redacted-value bindings (secret_text/secret_key) are NOT
//      re-sent (their values are not returned by the read) and are preserved by
//      keep_bindings instead.
//   5. SUPERSET PROOF: prove the computed set strictly CONTAINS every existing binding
//      (same name + type), the additions being the only difference. Refuse if any
//      existing binding would be lost or changed. This is the core guarantee.
//   6. WRITE: PATCH the script settings with the proven set + keep_bindings for the
//      redacted types. Settings updates are atomic, so a failed PATCH applies nothing.
//   7. POST-VERIFY: re-read the bindings and confirm EVERY original binding (the
//      required DOs, every other existing binding by name, and the redacted ones by
//      name) is still present AND every new binding landed. A mismatch throws a loud,
//      named error with the recovery (redeploy with wrangler) rather than a silent gap.
//
// The deploy token must carry edit scope for every resource the engine binds (the
// dashboard "Edit Cloudflare Workers" template); it is used for these calls only and is
// never stored or logged. The attach is audited by binding name, never a value.
//
// The two halves of this safety mechanism live in sibling modules: the PURE planner + proofs in
// attach-plan.ts (no IO, so the validator drives each guard directly), and the Cloudflare
// API plumbing in cf-api.ts. The public planner symbols are re-exported below so importers
// (the validator + router) are unchanged.
//
// This module covers three responsibilities over those same script settings:
//   (1) source attach and detach: attachSources / detachSources add or remove source bindings;
//   (2) the combined changeBindings operation that performs an attach and/or detach in one
//       atomic settings write with the same prove-before-write, verify-after guarantee;
//   (3) engine key install and rotation: installEngineSecrets, rotateBreakGlassPublic,
//       addOperationalSecrets and removeOperationalSecrets manage the engine's own signing and
//       recipient material, including the durable OPERATIONAL_RETIRED marker that records a
//       break-glass-only choice for scripts/deploy.sh and for the engine's own seal and read paths
//       (keys-env.ts operationalRetired). installEngineSecrets and addConfigRecoverySecrets also install the
//       configuration recovery key (CONFIG_RECIPIENT_*) and the configuration wrap key
//       (CONFIG_WRAP_KEY), so a console-keyed engine holds the same key set as a terminal-keyed one.

import { b64urlEncode, concat, constantTimeEqual } from "../crypto/bytes.ts";
import type { HybridRecipientPrivate, HybridRecipientPublic } from "../crypto/kem.ts";
import { mlkemKeygen } from "../crypto/pq.ts";
import { x25519PublicFromScalar } from "../crypto/x25519.ts";
import type { Signer } from "../format/writer.ts";
import { loadIdentity, loadRecipientPublic, loadRecipients, loadSigner } from "../keys-env.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import {
  type AttachSource,
  asAttachRefusal,
  bindingFromSource,
  type LiveBinding,
  looksLikeThisEngine,
  planAttach,
  planChange,
  verifyAfter,
} from "./attach-plan.ts";
import {
  auditToken,
  type Capability,
  type CapProbeOutcome,
  checkTokenWindow,
  deleteSecret,
  neededCapabilities,
  putSecret,
  readDeployedBindings,
} from "./cf-api.ts";
// AttachRefusalError is thrown at the two phase boundaries that KNOW what they refused (the token
// capability pre-flight and the token window check); asAttachRefusal above tags the two that throw from inside a
// called phase (the prove-before-write planner and the settings PATCH). The vocabulary lives in the leaf.
import { ATTACH_CAPABILITY_KEYS, type AttachCapabilityKey, AttachRefusal, AttachRefusalError, type AttachTaggableClass } from "./discovery-health.ts";
import { CF_API_BASE as CF_API } from "../lib/outbound.ts";

// The base URL lives in src/lib/outbound.ts (the one place vendor hosts are enumerated).

// Re-export the pure planner half so existing importers (the validator + router) keep their
// import paths unchanged.
export {
  type AttachSource,
  bindingFromSource,
  type LiveBinding,
  looksLikeThisEngine,
  planAttach,
  planChange,
  verifyAfter,
};

// changeBindings runs the whole safety mechanism for an attach (add) and/or detach (remove)
// in ONE atomic settings write: audit the token, read the deployed bindings, prove the change
// is exactly the intended one (no unintended drop, precise removal), write, then re-read and
// verify. token/accountId/scriptName are the target; fetchImpl is injectable so the validator
// drives the exact code with a stub.
//
// LIMITATION (read-modify-write): the CF API has no compare-and-swap on the binding set, so a
// concurrent changeBindings by another operator between the read and the write can overwrite this
// caller's change with a stale read, silently losing a binding addition. Operators must serialise
// attach/detach operations against the same script; do not run two binding changes in parallel.
export async function changeBindings(
  token: string,
  accountId: string,
  scriptName: string,
  add: AttachSource[],
  remove: string[],
  fetchImpl: typeof fetch = fetch,
  onWindowUnchecked?: () => void,
): Promise<{ added: string[]; removed: string[]; tokenId?: string; expiresOn?: string; permissionSummary: string }> {
  const auth = { authorization: `Bearer ${token}` };

  // 0a. Token window check: a not-yet-active (future Start Date) or expired token fails every
  // call as a generic "Authentication error", so name that precisely before anything else. The same
  // single verify call also yields the PUBLIC token id + expires_on (account-owned only) for the
  // credential lifecycle registry's "spent ephemeral token" row, captured once, never the value.
  const tokenWindow = await checkTokenWindow(token, accountId, fetchImpl);
  // TAGGED AT THE PHASE THAT KNOWS, with BOTH tags. The coarse class (token-window) is what the
  // fault counters aggregate; the fine cause is what tells a future Start Date from an expiry. AttachRefusal
  // carries both, so neither the counter nor the ring can be left blind by this throw.
  if (tokenWindow.problem) {
    // TAG the throw with the closed stage + cause. The MESSAGE is unchanged (byte for byte), so the
    // operator's 400 and every existing test are untouched; the tag is what finally lets the pack say "the
    // token's Start Date is in the future" instead of "an attach failed".
    throw new AttachRefusal(`${tokenWindow.problem} Or use the wrangler deploy path below, which needs no token.`, { stage: "token-window", cause: tokenWindow.cause ?? "other" });
  }
  // The window check could not be COMPLETED (Cloudflare's verify endpoint threw or would not answer). The
  // attach PROCEEDS -- the capability probes refuse safely on a bad token, so carrying on is the right
  // availability trade -- but it proceeds without having proved the token's window is good, so a later generic
  // "Authentication error" has a live suspect nobody was able to rule out. Report the blind spot at the
  // moment it happens, through the observer, so it is recorded whatever the attach goes on to do. It is NOT a
  // refusal of this attach and it must never become one.
  if (tokenWindow.cause === "window-unreadable") onWindowUnchecked?.();

  // 0b. Token capability pre-flight: before touching the engine, prove the token can do
  // everything THIS change needs, and if not, refuse with a precise, tailored checklist
  // (which permission is missing, which the token has, and what the attach needs) instead
  // of an opaque Cloudflare auth error.
  const caps = neededCapabilities(accountId, add);
  const audit = await auditToken(token, caps, fetchImpl);
  assertTokenCapable(accountId, caps, audit);

  // 1-2. Read the deployed bindings and confirm this is the engine. Deliberately NOT tagged: its failures carry a
  // Cloudflare STATUS, and the status-derived classes (auth / not-found / rate-limited / unavailable) are more
  // precise than any phase label would be. A phase tag here would throw that precision away.
  const existing = await readDeployedBindings(token, accountId, scriptName, fetchImpl);

  // 3-5. Plan + prove the change (throws on any unsafe condition, before any write). THE SAFETY HARNESS: the
  // identity guard, the validation, the collision check and the superset proof. Every throw from here means the
  // engine REFUSED TO WRITE and nothing was touched, which is the product working exactly as designed and is a
  // completely different answer from a write Cloudflare turned down, so the two are never filed as the same
  // `other` row.
  let planned: ReturnType<typeof planChange>;
  try {
    planned = planChange(existing, add, remove);
  } catch (e) {
    throw asAttachRefusal("safety-prove-failed", e);
  }
  const { bindings, keepBindings, added, removed } = planned;

  // 6. Write: PATCH the script settings with the proven set.
  //
  // THE TWO WAYS THIS FAILS ARE NOT THE SAME FACT, and conflating them is the difference between "retry" and
  // "re-read the live bindings before you touch anything".
  //
  //   Cloudflare ANSWERED and refused  -> patchSettings throws its OWN Error. Settings updates are atomic, so
  //                                       nothing was changed. We know that because Cloudflare told us.
  //   the call got NO ANSWER           -> fetchImpl itself threw (a socket reset, a timeout, a reply lost after
  //                                       the request went out). ATOMICITY DOES NOT HELP: it says the write
  //                                       either fully applied or did not, NOT which. Cloudflare may have
  //                                       applied it and lost the reply, so the bindings MAY NOW BE REWRITTEN
  //                                       and the post-write verify below never runs to find out.
  //
  // Tagging the second case cf-write-failed would put a sentence in the pack ("nothing was changed") that this
  // code never established, in the owner's #1 fear domain, with the safety harness blind. patchSettings marks
  // its own answered refusal, so an unmarked throw is by construction a lost answer.
  try {
    await patchSettings(accountId, scriptName, bindings, keepBindings, auth, fetchImpl);
  } catch (e) {
    throw asAttachRefusal(isAnsweredWriteRefusal(e) ? "cf-write-failed" : "write-unconfirmed", e);
  }

  // 7. Post-verify: re-read and confirm the change was exactly intended (every other
  // binding survived; additions landed; removals are gone). The final guarantee.
  //
  // THE RE-READ IS ON THE OTHER SIDE OF THE WRITE, so a failure here is a different fact from a failure on
  // the pre-write read, and it must not be the same row. The pre-write read failing means nothing was written.
  // This failing means THE PATCH LANDED and the safety harness's post-check could not run: the bindings were
  // changed and never confirmed, which is the owner's #1 fear domain with the guard blind. An untagged
  // CfApiFault would have the classifier read its Cloudflare status and file it as `unavailable`, the same cell
  // as a benign pre-write read failure. verifyAfter's own alarm covers "the verify RAN and disagreed"; nothing
  // else covers "the verify was blind". `verify-unread` does that, and verifyAfter is deliberately OUTSIDE the
  // try: its BindingAlarmError is the more serious fact and must keep outranking this.
  let after: LiveBinding[];
  try {
    after = await readDeployedBindings(token, accountId, scriptName, fetchImpl, true);
  } catch (e) {
    throw asAttachRefusal("verify-unread", e);
  }
  verifyAfter(existing, added, removed, after);

  // Return the binding result PLUS the redaction-safe registry facts: the PUBLIC token id + expires_on
  // (account-owned only), and a descriptive permission summary built from the needed-capability LABELS
  // (e.g. "Workers Scripts, Workers KV, R2"). The token VALUE is never returned, stored, or logged.
  return {
    added,
    removed,
    ...(tokenWindow.tokenId !== undefined ? { tokenId: tokenWindow.tokenId } : {}),
    ...(tokenWindow.expiresOn !== undefined ? { expiresOn: tokenWindow.expiresOn } : {}),
    permissionSummary: caps.map((c) => c.label).join(", "),
  };
}

// UNANSWERED_CLASS maps a probe outcome that established NOTHING ABOUT THE TOKEN onto the attach fault class that
// says so. None of them is a token class, because none of them is a fact about the token.
const UNANSWERED_CLASS: Record<string, { cls: AttachTaggableClass; why: string }> = {
  unavailable: { cls: "unavailable", why: "Cloudflare answered the permission probe with a server error" },
  "rate-limited": { cls: "rate-limited", why: "Cloudflare throttled the permission probe (HTTP 429)" },
  transport: { cls: "transport", why: "the permission probe did not reach Cloudflare at all" },
  inconclusive: { cls: "other", why: "Cloudflare answered the permission probe with neither a result nor a refusal" },
};
// Which unanswered outcome speaks for the pre-flight when several probes failed differently. Cloudflare's own
// error beats its throttle beats a dead socket beats a shapeless answer: the earlier a member is here, the more
// it narrows where the support engineer looks.
const UNANSWERED_RANK: readonly string[] = ["unavailable", "rate-limited", "transport", "inconclusive"];

// assertTokenCapable refuses with a precise, tailored checklist when Cloudflare REFUSED any capability THIS
// change needs (which permission is missing, which the token has, and what the attach needs) instead of an opaque
// Cloudflare auth error, and refuses SEPARATELY, under a class that claims nothing about the token, when the
// probe never got an answer at all.
//
// The checklist this function computes -- WHICH permission is missing, from the engine's own fixed
// capability vocabulary -- is the single richest diagnostic in the product, and it went into a 400 and died with
// the browser tab. Attaching a D1 source fails but KV works is answered by exactly one field: missingCaps:
// ["d1"]. So every throw here is TAGGED with the fine {stage, cause} as well as the coarse class. The messages
// are unchanged; the tags carry the CAPABILITY KEYS only (workers | kv | r2 | d1 | secrets), never the account
// id, the token or the probe URLs.
function assertTokenCapable(accountId: string, caps: Capability[], audit: { cap: Capability; outcome: CapProbeOutcome }[]): void {
  const refused = audit.filter((a) => a.outcome === "refused").map((a) => a.cap);
  const tokenInvalid = audit.filter((a) => a.outcome === "token-invalid");
  const unanswered = audit.filter((a) => a.outcome !== "allowed" && a.outcome !== "refused" && a.outcome !== "token-invalid");
  if (refused.length === 0 && tokenInvalid.length === 0 && unanswered.length === 0) return;

  // CLOUDFLARE REJECTED THE TOKEN ITSELF, and it says so on an HTTP 400 with its own error code, not a 401. This
  // is checked BEFORE the unanswered branch below, whose sentence tells the operator this is a Cloudflare fault,
  // not a token fault, so do not re-mint the token. A token Cloudflare has explicitly called invalid is the ONE
  // case where re-minting is precisely the remedy: the state where the token IS the fault must not fall through
  // to the branch that tells support to leave the token alone.
  if (tokenInvalid.length > 0) {
    throw new AttachRefusalError(
      "token-window",
      `Cloudflare rejected the deploy token itself on account ${accountId}: it is not a valid API token (it may be mistyped, revoked, or expired). Nothing was written. Create a fresh token from the dashboard "Edit Cloudflare Workers" template, scoped to this account, and paste it again. Or use the wrangler deploy path below, which needs no token.`,
      { stage: "token-capability", cause: "token-invalid" },
    );
  }

  const needsStr = caps.map((c) => c.needs).join(" + ");
  const has = audit.filter((a) => a.outcome === "allowed").map((a) => a.cap.label);
  const hasStr = has.length ? has.join(", ") : "none of them";

  // THE PROVEN REFUSAL WINS. Cloudflare said 401/403 on a capability by name, which is a fact about the token, and
  // it is the fact the operator can act on. The class is known HERE, where the fact was established, and is
  // never inferred from the sentence below: a word-boundary regex matched against the message would risk filing
  // a token-scope refusal as a Cloudflare `auth` failure instead.
  if (refused.length > 0) {
    const missingStr = refused.map((c) => c.label).join(", ");
    const extras = refused.some((c) => c.key === "d1" || c.key === "secrets");
    const templateNote = extras
      ? ` The dashboard "Edit Cloudflare Workers" template covers Workers Scripts, KV and R2 but NOT D1 or Secrets Store, so add the missing permission to the token (Create Token, start from that template, then add the missing row), scoped to this account.`
      : ` Create the token from the dashboard "Edit Cloudflare Workers" template, scoped to this account (it grants ${needsStr}); the value you pasted is missing it, so it is probably the wrong token, expired, or had permissions removed.`;
    // A probe that never answered is NOT reported as a capability the token has: it is reported as unknown.
    const unknownNote = unanswered.length > 0 ? ` Cloudflare did not answer the probe for ${unanswered.map((a) => a.cap.label).join(", ")}, so those are unknown.` : "";
    // missingCaps names ONLY the capabilities Cloudflare PROVED the token cannot use. A probe that never answered
    // is never listed here, or the ring would assert a fact about the token that nothing established.
    const missingKeys = refused.map((c) => c.key).filter((k): k is AttachCapabilityKey => (ATTACH_CAPABILITY_KEYS as readonly string[]).includes(k));
    throw new AttachRefusalError(
      "token-scope",
      `the token cannot use ${missingStr} on account ${accountId} (it can use: ${hasStr}).${unknownNote} This change needs ${needsStr} on this account.${templateNote} Or use the wrangler deploy path below, which needs no token.`,
      { stage: "token-capability", cause: "missing-capability", ...(missingKeys.length > 0 ? { missingCaps: missingKeys } : {}) },
    );
  }

  // NOTHING WAS PROVEN ABOUT THE TOKEN. Cloudflare did not answer the probe, so the engine refuses (nothing is
  // written, exactly as before) under the class of the thing that actually failed, which is Cloudflare. Filing
  // this as token-scope told support the engine had PROVED the token lacks a capability, and sent them to re-mint
  // a working token while the customer's Cloudflare 5xx and 429s sat in their own logs. The fine cause says the
  // same thing in the ring, and it carries NO missingCaps for the same reason.
  const worst = UNANSWERED_RANK.find((o) => unanswered.some((a) => a.outcome === o)) ?? "inconclusive";
  const { cls, why } = UNANSWERED_CLASS[worst] ?? { cls: "other" as AttachTaggableClass, why: "the permission probe did not complete" };
  const probedStr = unanswered.map((a) => a.cap.label).join(", ");
  throw new AttachRefusalError(
    cls,
    `the permission pre-flight could not complete: ${why} for ${probedStr} on account ${accountId}. Nothing was written, and nothing has been established about the token you pasted: this is a Cloudflare fault, not a token fault, so do not re-mint the token on account of it. Check Cloudflare's status page and try again in a few minutes. Or use the wrangler deploy path below, which needs no token.`,
    { stage: "token-capability", cause: "capability-unprovable" },
  );
}

// patchSettings PATCHes the script settings with the proven binding set. Multipart with a JSON
// "settings" part is the Cloudflare shape for a settings/bindings patch; keep_bindings preserves
// the redacted (secret) types. Settings updates are atomic, so a failed PATCH applies nothing.
// AnsweredWriteRefusal marks the ONE case in which we may honestly say "nothing was changed": Cloudflare
// answered the settings PATCH and refused it. Settings updates are atomic, so an answered refusal applied
// nothing, and we know it applied nothing because Cloudflare told us.
//
// It is a MARKER, not a message, and the distinction is the point. Any OTHER throw out of patchSettings means we
// never got an answer (a socket reset, a timeout, a reply lost after the request went out). Atomicity says the
// write either fully applied or did not; it does not say WHICH, and a lost reply is exactly the case where
// Cloudflare may have applied it. Marking the answered case (rather than trying to detect the unanswered one)
// makes the safe reading the DEFAULT: an unmarked throw is by construction a write we cannot vouch for.
class AnsweredWriteRefusal extends Error {}
function isAnsweredWriteRefusal(e: unknown): boolean {
  return e instanceof AnsweredWriteRefusal;
}

async function patchSettings(
  accountId: string,
  scriptName: string,
  bindings: LiveBinding[],
  keepBindings: string[],
  auth: { authorization: string },
  fetchImpl: typeof fetch,
): Promise<void> {
  const settings = `${CF_API}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`;
  const form = new FormData();
  form.append("settings", JSON.stringify({ bindings, keep_bindings: keepBindings }));
  const patchResp = await fetchImpl(settings, { method: "PATCH", headers: auth, body: form, redirect: "manual" });
  // From here on Cloudflare HAS ANSWERED. Whatever it said, the request completed and the atomicity guarantee is
  // usable: a non-2xx or success:false means the write did not apply. That is what AnsweredWriteRefusal marks.
  const patchBody = (await patchResp.json().catch(() => null)) as { success?: boolean; errors?: Array<{ code?: number; message?: string }> } | null;
  if (!patchResp.ok || patchBody?.success !== true) {
    const why = patchBody?.errors?.map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${patchResp.status}`;
    throw new AnsweredWriteRefusal(`the change did not land (Cloudflare: ${why}); nothing was changed (settings updates are atomic). Use the wrangler deploy path instead.`);
  }
}

// attachSources / detachSources are the named-operation wrappers over changeBindings.
export async function attachSources(token: string, accountId: string, scriptName: string, sources: AttachSource[], fetchImpl: typeof fetch = fetch): Promise<{ added: string[]; tokenId?: string; expiresOn?: string; permissionSummary: string }> {
  const { added, tokenId, expiresOn, permissionSummary } = await changeBindings(token, accountId, scriptName, sources, [], fetchImpl);
  return { added, ...(tokenId !== undefined ? { tokenId } : {}), ...(expiresOn !== undefined ? { expiresOn } : {}), permissionSummary };
}

export async function detachSources(token: string, accountId: string, scriptName: string, bindings: string[], fetchImpl: typeof fetch = fetch): Promise<{ removed: string[] }> {
  const { removed } = await changeBindings(token, accountId, scriptName, [], bindings, fetchImpl);
  return { removed };
}

// ---- in-product KEY INSTALL (the no-customer-CLI ceremony) --------------------------------------
//
// installEngineSecrets installs the in-browser key-ceremony output as the engine's OWN Worker
// secrets through the Cloudflare dedicated secrets endpoint, using a console-collected scoped
// "Edit Cloudflare Workers" token, so the operator never leaves the console to run a
// `wrangler secret put` (the hard no-customer-CLI rule). It REUSES the source-attach model
// exactly: the token is used for these calls ONLY, is NEVER persisted (no DO write, no env
// write) and NEVER logged; the install is audited by the router by NAME only (never a value).
//
// The two invariants, enforced here by construction:
//   1. VALIDATE BEFORE WRITE. Every key is parsed by the engine's OWN loaders (loadSigner /
//      loadRecipients / loadIdentity / loadConfigWrapKey) BEFORE any network call. A single bad key throws here,
//      so the function returns its coarse reason having made ZERO API calls and set NOTHING,
//      the engine can never be left half-keyed by a malformed paste.
//   2. NO VALUE LEAKS. The token and the PRIVATE key bytes are never returned, never logged,
//      and never put anywhere but the one PUT body Cloudflare requires. The result carries the
//      signer PUBLIC (safe, it is the recovery-sheet pin) and presence booleans only.
//
// Propagation note: a secret set via this endpoint becomes available to the running worker
// WITHOUT a redeploy (the same as `wrangler secret put`), but env in the CURRENTLY-EXECUTING
// isolate may lag a moment before the new value is observable. That is fine and expected: the
// console polls GET /admin/status until the engine reports the keys present, so a brief lag is
// invisible. No self-deploy is needed (and none is triggered): unlike a binding change, setting
// a secret does not require rewriting the script's settings.
//
// The configuration keys ride the same install. Before, only the terminal ceremony
// (scripts/generate-keys.ts via deploy.sh) installed CONFIG_RECIPIENT_PUBLIC, CONFIG_RECIPIENT_PRIVATE and
// CONFIG_WRAP_KEY. A console-keyed engine had none of them: its sealed configuration export went to
// break-glass only, auto-heal refused, and every console-stored credential sat on the Durable Object
// plaintext floor. The three values are REQUIRED here, so a no-CLI install cannot leave that gap again. The
// credentials a first run stores BEFORE this install (the discovery token, a destination secret) are sealed by
// the route straight after it returns (router-keys.ts, config-rewrap.ts).
//
// engineHolds is NOT read from the request body. The router fills it from the engine's own env. When the
// engine already holds a configuration key, the install KEEPS it and does not PUT the new one, because a
// replacement costs something a re-key never intends to spend. A new CONFIG_WRAP_KEY makes every wrapped
// credential unreadable (config-secret.ts: re-enter each one). A new CONFIG_RECIPIENT_PRIVATE strands every
// sealed export addressed to the old one. The supplied values are still validated, so a malformed paste is
// refused either way. A PARTIAL recovery pair (one half bound without the other) is not held: see
// HeldConfigRecipient below.
export interface KeyInstallInput {
  token: string;
  signerPrivate: string;
  breakGlassPublic: string;
  operationalPublic?: string;
  operationalPrivate?: string;
  configRecipientPublic: string;
  configRecipientPrivate: string;
  configWrapKey: string;
  engineHolds?: { configRecipient: HeldConfigRecipient; configWrapKey: boolean };
}

// HeldConfigRecipient is what the engine's own env binds of the configuration recovery pair. The router fills
// it from env (heldConfigRecipient), never from a request body. Only "pair" is a held recovery key.
//   - "none": neither half is bound, so the new pair is installed.
//   - "pair": both halves are bound, so the pair is kept and never replaced.
//   - "private-only": the public PUT failed after the private PUT (putConfigRecipient). The engine derives the
//     public from the private it holds and PUTs only that public. It never uses the request's new values here,
//     and it never writes a new private over the bound one.
//     A lone private that does not parse cannot give a public, so an install keeps it and the add refuses.
//   - "public-only": the private is not bound. Exports seal to this public, and the engine cannot open them. The
//     engine cannot make the private from the public, and it never overwrites the bound public. So an install
//     keeps it, and POST /keys/add-config-recovery refuses and names the recovery step.
export type HeldConfigRecipient = { held: "none" } | { held: "pair" } | { held: "private-only"; privateB64: string } | { held: "public-only" };

// heldConfigRecipient reads the configuration recovery pair from the engine's env. The private is carried only
// for the "private-only" case, where the engine derives the missing public from it. It is never returned to a
// caller or logged.
export function heldConfigRecipient(env: { CONFIG_RECIPIENT_PUBLIC?: string; CONFIG_RECIPIENT_PRIVATE?: string }): HeldConfigRecipient {
  const pub = typeof env.CONFIG_RECIPIENT_PUBLIC === "string" && env.CONFIG_RECIPIENT_PUBLIC !== "";
  const priv = typeof env.CONFIG_RECIPIENT_PRIVATE === "string" && env.CONFIG_RECIPIENT_PRIVATE !== "" ? env.CONFIG_RECIPIENT_PRIVATE : undefined;
  if (pub && priv !== undefined) return { held: "pair" };
  if (priv !== undefined) return { held: "private-only", privateB64: priv };
  return pub ? { held: "public-only" } : { held: "none" };
}

// "installed" means this call PUT the value. "kept" means the engine already held one and this call left it
// alone (see engineHolds above). Either way the engine holds the key when the call returns.
export type ConfigKeyOutcome = "installed" | "kept";

// ConfigRecipientOutcome adds the two partial-pair outcomes to ConfigKeyOutcome. "repaired" means the engine
// held a lone private and this call PUT the public derived from it, so the engine holds the full pair when the
// call returns. "kept-partial" means the engine held a lone half it cannot complete (a lone public, or a lone
// private that does not parse) and this call left it alone. The engine then does NOT hold a recovery key that
// opens its sealed configuration export, and POST /keys/add-config-recovery names the recovery step.
export type ConfigRecipientOutcome = ConfigKeyOutcome | "repaired" | "kept-partial";

export interface KeyInstallResult {
  signerPublic: string; // b64url(ed25519 public(32) || ML-DSA-87 public), PUBLIC, for the recovery sheet
  configured: { signer: true; breakGlass: true; operational: boolean; configRecipient: ConfigRecipientOutcome; configWrapKey: ConfigKeyOutcome };
}

// ---- the key-ceremony's OWN failure evidence -------------------------------------------------------
//
// THE GAP: a key install that dies at PUT #2 leaves the engine HALF-KEYED (SIGNER_PRIVATE set, BREAK_GLASS_PUBLIC
// not) and records NOTHING -- the audit trail carries keys-installed only on SUCCESS. A key-paste that will not
// parse likewise leaves no trace of a struggling ceremony. Remotely, "we installed the keys and backups still do
// not run" and "we never got past the key screen" look identical: an engine with no keys.
//
// THE RECORD: the ceremony THROW is TAGGED here, at the site that knows which step it was on and why, and the
// route (router-keys.ts) writes it to the AUDIT TRAIL as key-install-failed / key-removal-failed. Closed step +
// closed cause + (for a Cloudflare cause) the bounded CfApiFault the API layer already tagged.
//
// REDACTION: the step is a fixed SECRET NAME (an env-var name, never a value); the cause is a closed enum; the
// Cloudflare evidence is a status class plus Cloudflare's own numeric codes. The pasted key material, its length
// and the deploy token never appear -- the loaders' own messages already name only shapes, and even those are
// not recorded, only classified.
export const KEY_CEREMONY_STEPS = [
  "signer", // SIGNER_PRIVATE: the archive signing key. Absent => nothing can be sealed at all
  "break-glass", // BREAK_GLASS_PUBLIC: the offline recovery recipient. Absent => an archive nobody can ever open
  "operational-public", // OPERATIONAL_PUBLIC: the in-account read-back recipient
  "operational-private", // OPERATIONAL_PRIVATE: the in-account read-back key (restore tests / drills)
  // operational-retired-marker: OPERATIONAL_RETIRED, the durable "operational deliberately removed" flag.
  // Tagged on both sides, and a failure on either is fatal. The SET (removeOperationalSecrets, which a strict
  // installEngineSecrets also runs) fails with cf-put; the CLEAR (addOperationalSecrets, and
  // installEngineSecrets with an operational pair) fails with cf-delete. The clear is load-bearing because the
  // engine honours the marker over a bound pair (keys-env.ts operationalRetired).
  "operational-retired-marker",
  "config-recipient-public", // CONFIG_RECIPIENT_PUBLIC: the second recipient of the sealed configuration export
  "config-recipient-private", // CONFIG_RECIPIENT_PRIVATE: opens this engine's own sealed configuration export (auto-heal)
  "config-wrap-key", // CONFIG_WRAP_KEY: the AES-256 key that wraps console-stored credentials at rest
  "preflight", // the local VALIDATE-BEFORE-WRITE stage: no network call was made and NOTHING was set
] as const;
export type KeyCeremonyStep = (typeof KEY_CEREMONY_STEPS)[number];

export const KEY_CEREMONY_CAUSES = [
  "parse", // a pasted key did not parse through the engine's own loader (wrong length, wrong label, malformed base64url). Nothing was set
  "missing", // a required paste was empty, or the operational pair was supplied half-complete
  "cf-put", // Cloudflare REFUSED the secret PUT (a token scope problem, or a CF-side fault: read the tagged status class + codes)
  "cf-delete", // Cloudflare REFUSED the secret DELETE (the break-glass-only posture switch)
  // already-configured: POST /keys/add-operational refused because an operational key is already present, or
  // POST /keys/add-config-recovery refused because the key it was asked to add is already present.
  // This is a preflight refusal (no network call, nothing set), recorded so an add attempt
  // against an already-configured engine leaves a trace rather than an unaudited 400.
  "already-configured",
  "other", // residual: a ceremony throw outside the named causes
] as const;
export type KeyCeremonyCause = (typeof KEY_CEREMONY_CAUSES)[number];
const KEY_CEREMONY_STEP_SET: ReadonlySet<string> = new Set(KEY_CEREMONY_STEPS);
const KEY_CEREMONY_CAUSE_SET: ReadonlySet<string> = new Set(KEY_CEREMONY_CAUSES);

/**
 * KeyCeremonyFault TAGS a key install / rotate / removal throw with the closed step it died on and the closed
 * cause, at the site that knows both. The MESSAGE is the original one verbatim, so every operator-facing 400 and
 * every existing test is byte-identical; the tag is additional, and only the tag is ever recorded.
 */
export class KeyCeremonyFault extends Error {
  readonly keyStep: KeyCeremonyStep;
  readonly keyCause: KeyCeremonyCause;
  constructor(step: KeyCeremonyStep, cause: KeyCeremonyCause, inner: unknown) {
    super(inner instanceof Error ? inner.message : String(inner));
    this.name = "KeyCeremonyFault";
    this.keyStep = step;
    this.keyCause = cause;
    this.cause = inner;
  }
}

/**
 * keyCeremonyFaultOf reads the closed {step, cause} off a tagged ceremony throw, or null when the throw carries
 * no tag. It NEVER reads an untagged error's message (guessing from free text is precisely the leak the tag
 * prevents, the sealErrorClassOf idiom), and it re-validates both members against their closed sets, so even a
 * forged tag cannot widen what is recorded.
 *
 * @param e - the thrown value.
 * @returns the closed {step, cause}, or null when untagged.
 */
export function keyCeremonyFaultOf(e: unknown): { step: KeyCeremonyStep; cause: KeyCeremonyCause } | null {
  const step = (e as { keyStep?: unknown } | null)?.keyStep;
  const cause = (e as { keyCause?: unknown } | null)?.keyCause;
  if (typeof step !== "string" || !KEY_CEREMONY_STEP_SET.has(step)) return null;
  if (typeof cause !== "string" || !KEY_CEREMONY_CAUSE_SET.has(cause)) return null;
  return { step: step as KeyCeremonyStep, cause: cause as KeyCeremonyCause };
}

// putTagged / deleteTagged wrap ONE secret write with its closed step, so a ceremony that dies on PUT #2 says
// WHICH secret it died on. The underlying putSecret/deleteSecret already tag the Cloudflare half (CfApiFault);
// this adds the step and the ceremony-level cause without touching either message.
async function putTagged(step: KeyCeremonyStep, token: string, accountId: string, scriptName: string, name: string, value: string, fetchImpl: typeof fetch): Promise<void> {
  try {
    await putSecret(token, accountId, scriptName, name, value, fetchImpl);
  } catch (e) {
    throw new KeyCeremonyFault(step, "cf-put", e);
  }
}
async function deleteTagged(step: KeyCeremonyStep, token: string, accountId: string, scriptName: string, name: string, fetchImpl: typeof fetch): Promise<void> {
  try {
    await deleteSecret(token, accountId, scriptName, name, fetchImpl);
  } catch (e) {
    throw new KeyCeremonyFault(step, "cf-delete", e);
  }
}

// ---- the durable "operational deliberately removed" marker -------------------------------------------
//
// OPERATIONAL_RETIRED is a plain WORKER SECRET (never a key: its value is the fixed flag "true", never read
// for its content) that removeOperationalSecrets sets before its two deletes. It has two readers, and for both
// its PRESENCE is the whole signal:
//  - scripts/deploy.sh, which runs on the operator's OWN machine before and around a deploy and reads posture
//    from a bare `wrangler secret list` (names only, never values). It cannot ask the running worker's
//    /admin/status, and should not: the check decides what to do before relying on a round trip to the worker.
//    A worker secret is the one store deploy.sh can read without that request.
//  - the engine itself, through env (keys-env.ts operationalRetired). While the marker is bound the engine
//    seals to break-glass alone and opens no run with OPERATIONAL_PRIVATE, even if a stale pair is still bound
//    beside it, and status, posture and the support pack report that pair until it is deleted.
//
// Without this marker, deploy.sh cannot tell "operational was never provisioned" from "the owner deliberately
// removed it via the Keys screen's break-glass-only switch": both read identically as "OPERATIONAL_PRIVATE
// absent" from `wrangler secret list`. That was the whole bug: a routine `npm run deploy` silently reversed a
// confirm-gated, "effectively one-way" owner decision, with no confirmation and no audit row.
const OPERATIONAL_RETIRED_SECRET = "OPERATIONAL_RETIRED";
const OPERATIONAL_RETIRED_VALUE = "true";

// clearOperationalRetiredMarker deletes the OPERATIONAL_RETIRED marker BEFORE an operational pair is PUT, and a
// failure is FATAL (tagged operational-retired-marker / cf-delete). The engine honours the marker over a bound
// pair, so a pair installed beside a marker that did not clear would sit unused while the owner was told it
// was added. Clearing first means a failure here has changed nothing and the owner can retry. A PUT that then
// fails leaves no marker and no complete pair, which deploy.sh reads as "keys present, no operational key" and
// answers by asking (or, with no terminal, by keeping break-glass-only and writing the marker back).
// deleteSecret treats an absent marker (never set, or already cleared) as success.
async function clearOperationalRetiredMarker(accountId: string, scriptName: string, token: string, fetchImpl: typeof fetch): Promise<void> {
  await deleteTagged("operational-retired-marker", token, accountId, scriptName, OPERATIONAL_RETIRED_SECRET, fetchImpl);
}

// installEngineSecrets runs the whole no-CLI key install: validate every key locally, then PUT
// each as a worker secret in a fixed order. fetchImpl is injectable so the validator drives the
// exact code with a stub. SIGNER_PRIVATE and BREAK_GLASS_PUBLIC are always set. With an operational pair
// (two-recipient) the OPERATIONAL_RETIRED marker is cleared and the pair is PUT. Without one (strict
// break-glass-only) removeOperationalSecrets runs: the marker is set, then any OPERATIONAL_PRIVATE and
// OPERATIONAL_PUBLIC a previous posture left bound are deleted. The configuration recovery pair and
// CONFIG_WRAP_KEY are always set, unless the engine already holds them (engineHolds).
export async function installEngineSecrets(
  accountId: string,
  scriptName: string,
  input: KeyInstallInput,
  fetchImpl: typeof fetch = fetch,
): Promise<KeyInstallResult> {
  const token = typeof input.token === "string" ? input.token.trim() : "";
  const signerPrivate = typeof input.signerPrivate === "string" ? input.signerPrivate.trim() : "";
  const breakGlassPublic = typeof input.breakGlassPublic === "string" ? input.breakGlassPublic.trim() : "";
  const operationalPublic = typeof input.operationalPublic === "string" && input.operationalPublic.trim() !== "" ? input.operationalPublic.trim() : undefined;
  const operationalPrivate = typeof input.operationalPrivate === "string" && input.operationalPrivate.trim() !== "" ? input.operationalPrivate.trim() : undefined;
  const configRecipientPublic = typeof input.configRecipientPublic === "string" ? input.configRecipientPublic.trim() : "";
  const configRecipientPrivate = typeof input.configRecipientPrivate === "string" ? input.configRecipientPrivate.trim() : "";
  const configWrapKey = typeof input.configWrapKey === "string" ? input.configWrapKey.trim() : "";
  const heldRecipient: HeldConfigRecipient = input.engineHolds?.configRecipient ?? { held: "none" };
  const keepConfigWrapKey = input.engineHolds?.configWrapKey === true;

  // ---- VALIDATE BEFORE WRITE (zero network calls until every key parses) ----
  const signer = await validateKeysBeforeWrite(signerPrivate, breakGlassPublic, operationalPublic, operationalPrivate);
  // The configuration keys are required in full on this route, so the missing checks come first.
  if (configRecipientPublic === "") throw new KeyCeremonyFault("config-recipient-public", "missing", new Error("the configuration recovery public is required"));
  if (configRecipientPrivate === "") throw new KeyCeremonyFault("config-recipient-private", "missing", new Error("the configuration recovery private is required"));
  if (configWrapKey === "") throw new KeyCeremonyFault("config-wrap-key", "missing", new Error("the configuration wrap key is required"));
  validateConfigRecipientPair(configRecipientPublic, configRecipientPrivate);
  validateConfigWrapKey(configWrapKey);
  // A lone private: derive its public before any PUT. A held private that does not parse gives null, and the
  // install then keeps it as a partial pair, as it keeps a lone public.
  const derivedRecipientPublic = heldRecipient.held === "private-only" ? derivePublicFromHeldPrivate(heldRecipient.privateB64) : null;

  // ---- INSTALL (one PUT per secret; stop on the first failure, set nothing further) ----
  // Each PUT is tagged with the STEP it is, so a ceremony that dies at PUT #2 (leaving the engine
  // half-keyed) is auditable as key-install-failed {step: break-glass, cause: cf-put} instead of vanishing.
  if (token === "") throw new KeyCeremonyFault("preflight", "missing", new Error("paste the deploy token itself (it is used once and never stored)"));
  await putTagged("signer", token, accountId, scriptName, "SIGNER_PRIVATE", signerPrivate, fetchImpl);
  await putTagged("break-glass", token, accountId, scriptName, "BREAK_GLASS_PUBLIC", breakGlassPublic, fetchImpl);
  // validateKeysBeforeWrite refused half a pair, so the two are defined together or not at all.
  if (operationalPublic !== undefined && operationalPrivate !== undefined) {
    // Two-recipient: clear any earlier break-glass-only marker FIRST (the same clear addOperationalSecrets
    // makes), so the pair below is never left bound beside a marker the engine would honour over it.
    await clearOperationalRetiredMarker(accountId, scriptName, token, fetchImpl);
    await putTagged("operational-public", token, accountId, scriptName, "OPERATIONAL_PUBLIC", operationalPublic, fetchImpl);
    await putTagged("operational-private", token, accountId, scriptName, "OPERATIONAL_PRIVATE", operationalPrivate, fetchImpl);
  } else {
    // STRICT BREAK-GLASS-ONLY: the marker AND the deletes, through the SAME function the break-glass-only
    // switch calls, so the two routes cannot drift. Setting the marker alone recorded the choice for deploy.sh
    // but left a pair from an earlier two-recipient posture bound, so the engine kept sealing to the old
    // operational recipient and kept the private that opens those runs. removeOperationalSecrets keeps its own
    // order (marker first, then OPERATIONAL_PRIVATE, then OPERATIONAL_PUBLIC) and its tagged failures, and a
    // delete of a secret that is not bound (a fresh estate) is a success.
    await removeOperationalSecrets(accountId, scriptName, token, fetchImpl);
  }
  // The configuration keys go in for BOTH postures, as deploy.sh installs them. A key the engine already
  // holds is kept, and a bound half of the recovery pair is never overwritten (see HeldConfigRecipient).
  let configRecipient: ConfigRecipientOutcome;
  if (heldRecipient.held === "none") {
    await putConfigRecipient(token, accountId, scriptName, configRecipientPublic, configRecipientPrivate, fetchImpl);
    configRecipient = "installed";
  } else if (derivedRecipientPublic !== null) {
    await putTagged("config-recipient-public", token, accountId, scriptName, "CONFIG_RECIPIENT_PUBLIC", derivedRecipientPublic, fetchImpl);
    configRecipient = "repaired";
  } else {
    configRecipient = heldRecipient.held === "pair" ? "kept" : "kept-partial";
  }
  if (!keepConfigWrapKey) await putTagged("config-wrap-key", token, accountId, scriptName, "CONFIG_WRAP_KEY", configWrapKey, fetchImpl);

  // The signer PUBLIC (ed25519 public(32) || ML-DSA-87 public) is the operator-pinned verifier and
  // is safe to return (it is exactly what the recovery sheet records). The private bytes and the
  // token are never returned.
  return {
    signerPublic: b64urlEncode(concat(signer.edPublic, signer.mldsaPublic)),
    configured: {
      signer: true,
      breakGlass: true,
      operational: operationalPrivate !== undefined,
      configRecipient,
      configWrapKey: keepConfigWrapKey ? "kept" : "installed",
    },
  };
}

// putConfigRecipient writes the configuration recovery pair, PRIVATE FIRST. The seal path reads only the
// public (control-plane-pass.ts seals to BREAK_GLASS_PUBLIC plus CONFIG_RECIPIENT_PUBLIC). If the public
// landed and the private PUT then failed, the engine would seal exports to a recipient whose private it does
// not hold, and the browser drops the private when the ceremony ends. Private first means a failure between
// the two PUTs leaves an unused private and no export sealed to it.
async function putConfigRecipient(token: string, accountId: string, scriptName: string, pub: string, priv: string, fetchImpl: typeof fetch): Promise<void> {
  await putTagged("config-recipient-private", token, accountId, scriptName, "CONFIG_RECIPIENT_PRIVATE", priv, fetchImpl);
  await putTagged("config-recipient-public", token, accountId, scriptName, "CONFIG_RECIPIENT_PUBLIC", pub, fetchImpl);
}

// derivePublicFromHeldPrivate derives the configuration recovery public from the private the engine holds: the
// x25519 public from the scalar and the ML-KEM-1024 encapsulation key from the seed, the same derivation
// identityOpensPublic compares. The result is the only public that matches the bound private, so a lone private
// is completed without a new key pair. It returns null when the held private does not parse. The caller decides
// what that means: an install keeps the lone private, and the targeted add refuses (heldPrivateUnparsedFault).
function derivePublicFromHeldPrivate(privB64: string): string | null {
  let identity: HybridRecipientPrivate;
  try {
    identity = loadIdentity(privB64);
  } catch {
    return null;
  }
  return b64urlEncode(concat(x25519PublicFromScalar(identity.x25519Scalar), mlkemKeygen(identity.mlkemSeed).encapKey));
}

// heldPrivateUnparsedFault is the targeted add's refusal for a lone private that does not parse. Such a private
// opens nothing, and no export is sealed to it, because the seal path reads only the public. So the recovery
// step removes it and adds a new pair.
function heldPrivateUnparsedFault(): KeyCeremonyFault {
  return new KeyCeremonyFault(
    "config-recipient-private",
    "parse",
    new Error("this engine holds CONFIG_RECIPIENT_PRIVATE without its CONFIG_RECIPIENT_PUBLIC, and the held private does not parse, so its public cannot be derived. This route does not overwrite a bound key. In the Cloudflare dashboard, delete the CONFIG_RECIPIENT_PRIVATE secret from this engine's Worker, then add the configuration keys again. Nothing was set."),
  );
}

// identityOpensPublic reports whether a recipient identity derives the given recipient public: the x25519
// public from the scalar and the ML-KEM-1024 encapsulation key from the seed, both compared in full.
function identityOpensPublic(identity: HybridRecipientPrivate, pub: HybridRecipientPublic): boolean {
  return constantTimeEqual(x25519PublicFromScalar(identity.x25519Scalar), pub.x25519) && constantTimeEqual(mlkemKeygen(identity.mlkemSeed).encapKey, pub.mlkemEk);
}

// validateConfigRecipientPair parses both halves of the configuration recovery key with the engine's own
// loaders (loadRecipientPublic, loadIdentity), then checks that the private derives the public. A mismatched
// pair parses cleanly and fails much later: exports seal to the public, and auto-heal cannot open them with
// the private. So the mismatch is refused here, before any PUT.
function validateConfigRecipientPair(pubB64: string, privB64: string): void {
  let pub: HybridRecipientPublic;
  let priv: HybridRecipientPrivate;
  try {
    pub = loadRecipientPublic(pubB64);
  } catch {
    throw new KeyCeremonyFault("config-recipient-public", "parse", new Error("the configuration recovery public did not parse (expected base64url x25519(32) || ML-KEM-1024 ek(1568) = 1600 bytes); nothing was set"));
  }
  try {
    priv = loadIdentity(privB64);
  } catch {
    throw new KeyCeremonyFault("config-recipient-private", "parse", new Error("the configuration recovery private did not parse (expected a 96-byte recipient identity); nothing was set"));
  }
  if (!identityOpensPublic(priv, pub)) {
    throw new KeyCeremonyFault("config-recipient-private", "parse", new Error("the configuration recovery private does not match its public (the two halves come from different key pairs); nothing was set"));
  }
}

// validateConfigWrapKey parses CONFIG_WRAP_KEY with the engine's own loader (loadConfigWrapKey: base64url of
// 32 bytes). The caller has already refused an empty value, so undefined cannot come back here.
function validateConfigWrapKey(raw: string): void {
  try {
    loadConfigWrapKey(raw);
  } catch {
    throw new KeyCeremonyFault("config-wrap-key", "parse", new Error("the configuration wrap key did not parse (expected base64url of 32 bytes, AES-256); nothing was set"));
  }
}

// validateKeysBeforeWrite parses every supplied key with the engine's OWN loaders BEFORE any
// network call, so a malformed paste throws here having set NOTHING. A coarse reason is thrown on
// any failure; the loaders' messages already name only sizes/shape, never a value. An operational
// pair is all-or-nothing: a public without its private (or vice versa) is a half-recipient the
// engine cannot use for the read-back drill, so it is refused here. Returns the parsed signer so
// the caller can emit its public.
async function validateKeysBeforeWrite(
  signerPrivate: string,
  breakGlassPublic: string,
  operationalPublic: string | undefined,
  operationalPrivate: string | undefined,
): Promise<Signer> {
  // The VALIDATE-BEFORE-WRITE refusals are tagged with the step they refused and the closed cause, so a
  // struggling ceremony (a truncated paste, the wrong key in the wrong box, half an operational pair) is
  // auditable as key-install-failed {step, cause: parse|missing} rather than leaving no trace at all. The
  // messages are verbatim, so the operator-facing 400 is unchanged; the tag is what is recorded, never the paste.
  if (signerPrivate === "") throw new KeyCeremonyFault("signer", "missing", new Error("the signer private is required"));
  if (breakGlassPublic === "") throw new KeyCeremonyFault("break-glass", "missing", new Error("the break-glass public is required"));
  if ((operationalPublic === undefined) !== (operationalPrivate === undefined)) {
    throw new KeyCeremonyFault("operational-private", "missing", new Error("the operational pair is incomplete: supply BOTH the operational public and the operational private, or neither"));
  }
  let signer: Signer;
  try {
    signer = await loadSigner(signerPrivate);
  } catch {
    throw new KeyCeremonyFault("signer", "parse", new Error("the signer private did not parse (expected base64url ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes); nothing was set"));
  }
  try {
    // loadRecipients parses the break-glass public (always) and the operational public (when present).
    loadRecipients(breakGlassPublic, operationalPublic);
  } catch {
    throw new KeyCeremonyFault("break-glass", "parse", new Error("a recipient public key did not parse (expected base64url x25519(32) || ML-KEM-1024 ek(1568) = 1600 bytes); nothing was set"));
  }
  if (operationalPrivate !== undefined) {
    try {
      loadIdentity(operationalPrivate);
    } catch {
      throw new KeyCeremonyFault("operational-private", "parse", new Error("the operational private did not parse (expected a 96-byte recipient identity); nothing was set"));
    }
  }
  return signer;
}

// rotateBreakGlassPublic writes a NEW BREAK_GLASS_PUBLIC and nothing else: it validates the supplied
// public locally (loadRecipients parses it, the same guard the install uses), then PUTs the single
// secret. The signer and operational secrets are untouched, so this is not a re-key; archives sealed
// before the rotation still need the OLD identity.key (the console states this loudly). The new public
// is observed on the next seal without a redeploy. fetchImpl is injectable for the validator.
export async function rotateBreakGlassPublic(
  accountId: string,
  scriptName: string,
  token: string,
  breakGlassPublic: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const tok = typeof token === "string" ? token.trim() : "";
  const pub = typeof breakGlassPublic === "string" ? breakGlassPublic.trim() : "";
  // The rotation is a key ceremony too, and its refusals are equally invisible without a tag. Same closed tags.
  if (tok === "") throw new KeyCeremonyFault("preflight", "missing", new Error("paste the deploy token itself (it is used once and never stored)"));
  if (pub === "") throw new KeyCeremonyFault("break-glass", "missing", new Error("the new break-glass public is required"));
  try {
    loadRecipients(pub, undefined);
  } catch {
    throw new KeyCeremonyFault("break-glass", "parse", new Error("the break-glass public did not parse (expected base64url x25519(32) || ML-KEM-1024 ek(1568) = 1600 bytes); nothing was changed"));
  }
  await putTagged("break-glass", tok, accountId, scriptName, "BREAK_GLASS_PUBLIC", pub, fetchImpl);
}

// addOperationalSecrets writes ONLY OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE: the targeted, minimal
// upgrade path for an engine deployed break-glass-only (the no-CLI equivalent of
// `scripts/generate-keys.ts --operational-only`, which already proves the shape is correct and safe).
// SIGNER_PRIVATE and BREAK_GLASS_PUBLIC are never read, never validated and never written here, so this
// can never rotate the signer or the break-glass recipient as a side effect: every existing run stays
// signed by the same signer and console-verifiable exactly as before, and archives sealed before this
// call stay break-glass-only recoverable, permanently (the recipient set is baked into each archive at
// seal time, `keys-env.ts:52-56`; there is no rewrap path for a past archive). Only NEW runs, sealed
// after this lands, gain the operational recipient. Both values are required (all-or-nothing: this
// route only ever installs a complete pair, never a half one); the caller (router-keys.ts) separately
// refuses the whole call when an operational key is already present, so this function is never asked to
// silently overwrite one. fetchImpl is injectable for the validator.
export async function addOperationalSecrets(
  accountId: string,
  scriptName: string,
  token: string,
  operationalPublic: string,
  operationalPrivate: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const tok = typeof token === "string" ? token.trim() : "";
  const pub = typeof operationalPublic === "string" ? operationalPublic.trim() : "";
  const priv = typeof operationalPrivate === "string" ? operationalPrivate.trim() : "";
  // The same closed-tag discipline as every other key-ceremony mutation, so a struggling add (a
  // truncated paste, half a pair) is auditable as key-install-failed {step, cause} rather than silent.
  if (tok === "") throw new KeyCeremonyFault("preflight", "missing", new Error("paste the deploy token itself (it is used once and never stored)"));
  if (pub === "") throw new KeyCeremonyFault("operational-public", "missing", new Error("the operational public is required"));
  if (priv === "") throw new KeyCeremonyFault("operational-private", "missing", new Error("the operational private is required"));
  // ---- VALIDATE BEFORE WRITE (zero network calls until both keys parse) ----
  try {
    loadRecipientPublic(pub);
  } catch {
    throw new KeyCeremonyFault("operational-public", "parse", new Error("the operational public did not parse (expected base64url x25519(32) || ML-KEM-1024 ek(1568) = 1600 bytes); nothing was set"));
  }
  try {
    loadIdentity(priv);
  } catch {
    throw new KeyCeremonyFault("operational-private", "parse", new Error("the operational private did not parse (expected a 96-byte recipient identity); nothing was set"));
  }
  // ---- INSTALL (the marker clear, then one PUT per secret; stop on the first failure, set nothing further) ----
  // The marker goes FIRST (see clearOperationalRetiredMarker): the engine honours it over a bound pair, so a
  // pair PUT beside a marker that failed to clear would be added and never used.
  await clearOperationalRetiredMarker(accountId, scriptName, tok, fetchImpl);
  await putTagged("operational-public", tok, accountId, scriptName, "OPERATIONAL_PUBLIC", pub, fetchImpl);
  await putTagged("operational-private", tok, accountId, scriptName, "OPERATIONAL_PRIVATE", priv, fetchImpl);
}

// ConfigRecoveryAddInput is POST /keys/add-config-recovery's body: the configuration recovery pair, the
// wrap key, or both. Each part the caller sends is one the engine does not hold yet. engineHolds is NOT read
// from the body: the router fills it from the engine's own env (heldConfigRecipient).
export interface ConfigRecoveryAddInput {
  configRecipientPublic?: string;
  configRecipientPrivate?: string;
  configWrapKey?: string;
  engineHolds?: { configRecipient: HeldConfigRecipient };
}

// lonePublicFault is the targeted add's refusal for a lone CONFIG_RECIPIENT_PUBLIC. The engine cannot make the
// private from the public and does not overwrite a bound key, so the route names the step that clears it. The
// statements are true against the code: exports seal to BREAK_GLASS_PUBLIC plus this public
// (loadControlPlaneExportRecipients), so each one still has a break-glass capsule, and auto-heal cannot open
// them because it needs CONFIG_RECIPIENT_PRIVATE. With the public deleted the engine holds neither half, and this
// route then installs a new pair.
export function lonePublicFault(): KeyCeremonyFault {
  return new KeyCeremonyFault(
    "preflight",
    "already-configured",
    new Error("this engine holds CONFIG_RECIPIENT_PUBLIC without its CONFIG_RECIPIENT_PRIVATE, so auto-heal cannot open the configuration exports sealed to it. This route does not overwrite a bound key, and the engine cannot make the private from the public. In the Cloudflare dashboard, delete the CONFIG_RECIPIENT_PUBLIC secret from this engine's Worker, then add the configuration keys again. The configuration exports already sealed to that public still open with your break-glass identity.key. Nothing was set."),
  );
}

// addConfigRecoverySecrets writes ONLY the configuration keys an already-keyed engine lacks: the
// configuration recovery pair (CONFIG_RECIPIENT_PUBLIC, CONFIG_RECIPIENT_PRIVATE), CONFIG_WRAP_KEY, or both.
// It is the no-CLI equivalent of the deploy.sh top-up (generate-keys.ts --config-wrap-key-only) for an
// engine the console keyed before its ceremony made these keys. SIGNER_PRIVATE, BREAK_GLASS_PUBLIC and the
// operational pair are never read, validated or written here.
//
// The caller (router-keys.ts) refuses the whole call when the engine already holds a key it was asked to
// add, so this function never replaces one. A new CONFIG_RECIPIENT_PRIVATE would strand the sealed exports
// addressed to the old one, and a new CONFIG_WRAP_KEY would make every wrapped credential unreadable.
//
// A partial recovery pair (engineHolds.configRecipient): a lone private is completed with the public derived
// from it, and the request's new pair is validated but not written. A lone public is refused. This function
// refuses a held pair or a lone public too, so it never overwrites a bound half whatever its caller checked.
//
// What a new wrap key does to credentials stored before it: the route seals them straight after this returns
// (router-keys.ts calls config-rewrap.ts rewrapAfterKeyInstall with the key it just installed). A credential that
// pass cannot seal stays plaintext and keeps working, because config-secret.ts isWrappedSecret reads a plaintext
// credential and an envelope alike, and its next save seals it. The dest-cred-encryption posture check counts
// the destination credentials still on the plaintext floor. Returns the secret names it set.
export async function addConfigRecoverySecrets(
  accountId: string,
  scriptName: string,
  token: string,
  input: ConfigRecoveryAddInput,
  fetchImpl: typeof fetch = fetch,
): Promise<{ installed: string[]; configRecipient?: "installed" | "repaired" }> {
  const tok = typeof token === "string" ? token.trim() : "";
  const pub = typeof input.configRecipientPublic === "string" ? input.configRecipientPublic.trim() : "";
  const priv = typeof input.configRecipientPrivate === "string" ? input.configRecipientPrivate.trim() : "";
  const wrap = typeof input.configWrapKey === "string" ? input.configWrapKey.trim() : "";
  if (tok === "") throw new KeyCeremonyFault("preflight", "missing", new Error("paste the deploy token itself (it is used once and never stored)"));
  // The pair is all-or-nothing, as the operational pair is: half a recipient cannot open anything.
  if ((pub === "") !== (priv === "")) {
    throw new KeyCeremonyFault(pub === "" ? "config-recipient-public" : "config-recipient-private", "missing", new Error("the configuration recovery pair is incomplete: supply BOTH the public and the private, or neither"));
  }
  if (pub === "" && wrap === "") throw new KeyCeremonyFault("preflight", "missing", new Error("nothing to add: supply the configuration recovery pair, the configuration wrap key, or both"));
  // ---- VALIDATE BEFORE WRITE (zero network calls until every supplied key parses) ----
  if (pub !== "") validateConfigRecipientPair(pub, priv);
  if (wrap !== "") validateConfigWrapKey(wrap);
  const held: HeldConfigRecipient = input.engineHolds?.configRecipient ?? { held: "none" };
  let derivedPublic: string | null = null;
  if (pub !== "") {
    if (held.held === "pair") throw new KeyCeremonyFault("preflight", "already-configured", new Error("this engine already holds the configuration recovery key; this route never replaces one. Nothing was set."));
    if (held.held === "public-only") throw lonePublicFault();
    if (held.held === "private-only") {
      derivedPublic = derivePublicFromHeldPrivate(held.privateB64);
      if (derivedPublic === null) throw heldPrivateUnparsedFault();
    }
  }
  // ---- INSTALL (one PUT per secret; stop on the first failure, set nothing further) ----
  const installed: string[] = [];
  let configRecipient: "installed" | "repaired" | undefined;
  if (derivedPublic !== null) {
    await putTagged("config-recipient-public", tok, accountId, scriptName, "CONFIG_RECIPIENT_PUBLIC", derivedPublic, fetchImpl);
    installed.push("CONFIG_RECIPIENT_PUBLIC");
    configRecipient = "repaired";
  } else if (pub !== "") {
    await putConfigRecipient(tok, accountId, scriptName, pub, priv, fetchImpl);
    installed.push("CONFIG_RECIPIENT_PRIVATE", "CONFIG_RECIPIENT_PUBLIC");
    configRecipient = "installed";
  }
  if (wrap !== "") {
    await putTagged("config-wrap-key", tok, accountId, scriptName, "CONFIG_WRAP_KEY", wrap, fetchImpl);
    installed.push("CONFIG_WRAP_KEY");
  }
  return { installed, ...(configRecipient !== undefined ? { configRecipient } : {}) };
}

// removeOperationalSecrets deletes BOTH operational secrets to move the engine to the strict
// break-glass-only posture: the engine then holds no key that can read an archive. This is SAFE for
// recovery (every archive is wrapped to the break-glass recipient too, so the offline identity.key
// recovers everything, including archives sealed while operational was present) and only removes the
// engine's ability to self-test-restore. It is a one-way tightening: returning to two-recipient means
// generating a fresh operational key and installing it. Two callers: POST /keys/break-glass-only, and a
// strict installEngineSecrets (the re-key that omits the operational pair). fetchImpl is injectable for the
// validator.
export async function removeOperationalSecrets(
  accountId: string,
  scriptName: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const tok = typeof token === "string" ? token.trim() : "";
  if (tok === "") throw new KeyCeremonyFault("preflight", "missing", new Error("paste the deploy token itself (it is used once and never stored)"));
  // the DURABLE marker goes FIRST, before either delete. If anything below fails partway (either
  // delete), the marker is already set, so scripts/deploy.sh -- which reads this posture from a plain
  // `wrangler secret list`, never through the engine's own HTTP API -- still refuses to auto-generate a
  // replacement operational key against a half-applied switch, and the engine itself stops sealing to and
  // reading with the pair the failed delete left bound (keys-env.ts). Setting it AFTER the deletes would let a
  // delete land and then a marker-write failure leave the engine genuinely break-glass-only with no durable
  // record of that at all: the exact silent-reversal hazard this marker exists to close. A failure here is
  // FATAL (the ceremony throws, half-applied and auditable, same as a failed delete).
  await putTagged("operational-retired-marker", tok, accountId, scriptName, OPERATIONAL_RETIRED_SECRET, OPERATIONAL_RETIRED_VALUE, fetchImpl);
  // A posture switch that deletes OPERATIONAL_PRIVATE and then fails on OPERATIONAL_PUBLIC leaves the
  // engine in a HALF-APPLIED posture. The step tag names which delete failed, so the half-state is recorded.
  await deleteTagged("operational-private", tok, accountId, scriptName, "OPERATIONAL_PRIVATE", fetchImpl);
  await deleteTagged("operational-public", tok, accountId, scriptName, "OPERATIONAL_PUBLIC", fetchImpl);
}
