// PASSKEY-EXCLUDE-OVER-64-IS-A-LOCKOUT: passkeyRegisterBegin must never emit an
// excludeCredentials list larger than the browser will accept, because past that ceiling the browser
// refuses the whole ceremony and the account can never enrol another passkey. Run:
//   node test/validate-passkey-exclude-cap.ts
//
// THE THREAT. An account that accumulates more than 64 passkey credentials would, without a bound, put
// every one of them into excludeCredentials. Chromium refuses the WHOLE ceremony past 64 entries with a
// DOMException named RangeError ("The `excludeCredentials` attribute exceeds the maximum allowed size
// (64)"), thrown before any authenticator is consulted.
//
// THE HARM IS NOT THE FAILED ENROLMENT, IT IS THE RECOVERY BANK. Enrolment is also the step that mints a
// fresh recovery-code set: a break-glass recovery sign-in consumes one code, sets a session, and routes
// straight into a passkey enrolment, and it is THAT enrolment which replaces the spent set. If the
// ceremony is refused in the browser, every break-glass sign-in spends a code and replaces nothing. An
// account that empties its bank this way cannot enrol, cannot assert a passkey it has lost, and cannot
// delete a credential to get back under the ceiling (/passkey/credentials/delete is step-up gated on the
// cookie path, and step-up needs the assertion it does not have). That is a permanent lockout reached by
// using the documented break-glass path as intended.
//
// What this proves: (a) the pure selector bounds the list at EXCLUDE_CREDENTIALS_MAX and is a no-op at or
// below it; (b) it keeps PROVEN-usable credentials (a non-null lastAssertedAt) ahead of never-asserted
// ones, and prefers the newest within each group; (c) it is deterministic; (d) the REAL DO's
// passkeyRegisterBegin emits a bounded list for an account over the ceiling, and an unbounded one is
// exactly what a browser refuses; (e) truncation does not weaken the duplicate guard, which is
// server-side in the finish and reads storage rather than the exclude list.

import { EXCLUDE_CREDENTIALS_MAX, excludeCredentialsFor, type PasskeyCred } from "../src/admin/passkey.ts";
import { PASSKEY_CRED_PREFIX } from "../src/sched/scheduler-do-base.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// cred builds a PasskeyCred with only the fields the selector reads carrying meaning; the rest are
// structurally valid filler so this is a real record and not a duck-typed stand-in.
function cred(id: string, createdAt: string, lastAssertedAt: string | null, email = "someone@example.com"): PasskeyCred {
  return {
    credentialId: id,
    email,
    cosePublicKey: "AAAA",
    alg: -7,
    signCount: 0,
    transports: ["internal"],
    aaguid: "AAAAAAAAAAAAAAAAAAAAAA",
    createdAt,
    lastAssertedAt,
    lastAssertedVia: lastAssertedAt === null ? null : "login",
  } as PasskeyCred;
}

// iso makes an ordered, distinct RFC-3339 stamp per index (older index = older stamp).
const iso = (i: number): string => new Date(Date.UTC(2026, 0, 1, 0, 0, 0) + i * 60_000).toISOString();

console.log("validate-passkey-exclude-cap: excludeCredentials is bounded by the browser's ceiling");

// ---- (a) the bound itself ------------------------------------------------------------------------
{
  // If this constant ever drifts above what a browser accepts the whole repair is undone silently, so the
  // number itself is asserted rather than merely used.
  ok(`(a) EXCLUDE_CREDENTIALS_MAX is the measured Chromium ceiling, 64 (got ${EXCLUDE_CREDENTIALS_MAX})`, EXCLUDE_CREDENTIALS_MAX === 64);

  const many: PasskeyCred[] = [];
  for (let i = 0; i < 65; i++) many.push(cred(`id-${String(i).padStart(3, "0")}`, iso(i), null));
  const bounded = excludeCredentialsFor(many);
  ok(`(a) 65 credentials yield exactly ${EXCLUDE_CREDENTIALS_MAX} exclude entries (got ${bounded.length})`, bounded.length === EXCLUDE_CREDENTIALS_MAX);

  const huge: PasskeyCred[] = [];
  for (let i = 0; i < 500; i++) huge.push(cred(`id-${String(i).padStart(3, "0")}`, iso(i), null));
  ok(`(a) 500 credentials still yield exactly ${EXCLUDE_CREDENTIALS_MAX} (got ${excludeCredentialsFor(huge).length})`, excludeCredentialsFor(huge).length === EXCLUDE_CREDENTIALS_MAX);

  // THE KNOWN NEGATIVE, and it is the one that makes the two above mean something: a selector that simply
  // returned nothing, or a constant one, would satisfy "never more than 64" perfectly. An account UNDER
  // the ceiling must still get EVERY one of its credentials excluded, because that is the behaviour the
  // exclude list exists for and the behaviour this repair must not cost.
  const few: PasskeyCred[] = [];
  for (let i = 0; i < 7; i++) few.push(cred(`id-${String(i).padStart(3, "0")}`, iso(i), null));
  const all = excludeCredentialsFor(few);
  ok(`(a) an account UNDER the ceiling still excludes all 7 of its credentials (got ${all.length})`, all.length === 7);
  ok("(a) and it is the same seven ids, not seven of something else", new Set(all.map((c) => c.credentialId)).size === 7 && all.every((c) => few.some((f) => f.credentialId === c.credentialId)));

  const exactly = [...many.slice(0, 64)];
  ok(`(a) exactly at the ceiling is a no-op pass-through (got ${excludeCredentialsFor(exactly).length})`, excludeCredentialsFor(exactly).length === 64);
  ok("(a) an empty account yields an empty list, not a throw", excludeCredentialsFor([]).length === 0);
}

// ---- (b) WHICH 64 survive ------------------------------------------------------------------------
{
  // 70 credentials, of which three are PROVEN usable (a non-null lastAssertedAt is written only after a
  // signature verified). Those three must survive truncation whatever their enrolment date, because they
  // are the only ones with evidence that the authenticator still exists.
  const creds: PasskeyCred[] = [];
  for (let i = 0; i < 70; i++) creds.push(cred(`id-${String(i).padStart(3, "0")}`, iso(i), null));
  // The three OLDEST enrolments are the proven ones, so "newest wins" alone would drop every one of them.
  creds[0] = cred("id-000", iso(0), iso(900));
  creds[1] = cred("id-001", iso(1), iso(901));
  creds[2] = cred("id-002", iso(2), iso(902));

  const picked = excludeCredentialsFor(creds);
  const ids = picked.map((c) => c.credentialId);
  ok(`(b) still bounded at ${EXCLUDE_CREDENTIALS_MAX} (got ${picked.length})`, picked.length === EXCLUDE_CREDENTIALS_MAX);
  ok("(b) all three PROVEN-usable credentials survive truncation despite being the oldest enrolments", ["id-000", "id-001", "id-002"].every((id) => ids.includes(id)));
  ok("(b) the most recently PROVEN credential leads the list", ids[0] === "id-002");
  ok("(b) the newest never-asserted enrolment (id-069) survives", ids.includes("id-069"));
  ok("(b) the oldest never-asserted enrolment (id-003) is the one dropped", !ids.includes("id-003"));

  // Determinism: the same input must produce the same list, or a begin/finish pair could disagree and a
  // test could pass once by luck.
  const again = excludeCredentialsFor(creds).map((c) => c.credentialId);
  ok("(c) the selection is deterministic across repeated calls", JSON.stringify(ids) === JSON.stringify(again));
  const shuffled = [...creds].reverse();
  ok("(c) and independent of input order", JSON.stringify(excludeCredentialsFor(shuffled).map((c) => c.credentialId)) === JSON.stringify(ids));
}

// ---- (d) the REAL registration ceremony ----------------------------------------------------------
// Drives the actual SchedulerDO passkeyRegisterBegin over the in-memory storage double: no network, no
// deploy. The account is seeded with 65 credentials, the exact count measured on the live estate, and the
// creation options the DO hands the browser must carry a list the browser will accept.
{
  const { SchedulerDO } = await import("../src/sched/scheduler-do.ts");
  const { MockStorage } = await import("./mock-storage.ts");

  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const email = "over-ceiling@example.com";

  // Seed the roster entry, a user record and 65 credentials, the shape listPasskeyCredsForEmail reads.
  await storage.put(`role:${email}`, { email, role: "owner", createdAt: iso(0) });
  await storage.put(`passkeyUser:${email}`, { email, displayName: "Over Ceiling", createdAt: iso(0) });
  for (let i = 0; i < 65; i++) {
    const id = `cred-${String(i).padStart(3, "0")}`;
    await storage.put(`${PASSKEY_CRED_PREFIX}${id}`, cred(id, iso(i), null, email));
  }

  const seeded = await dobj.listPasskeyCredsForEmail(email);
  // KNOWN POSITIVE ON THE SEED. Without this, a begin that excluded nothing because the DO could not see
  // the credentials at all would read as a clean bound.
  ok(`(d) the seeded account really holds 65 credentials the DO can see (got ${seeded.length})`, seeded.length === 65);

  const begun = await dobj.passkeyRegisterBegin({ email, displayName: "Over Ceiling", rpId: "console.example.com", authMethod: "passkey", authEmail: email });
  if (!begun.ok) {
    ok(`(d) register/begin was authorised for the account's own self-add (reason: ${"reason" in begun ? begun.reason : "?"})`, false);
  } else {
    const opts = begun.publicKey as { excludeCredentials?: unknown[] };
    const list = Array.isArray(opts.excludeCredentials) ? opts.excludeCredentials : [];
    ok("(d) register/begin was authorised for the account's own self-add", true);
    ok(`(d) the REAL ceremony emits at most ${EXCLUDE_CREDENTIALS_MAX} exclude entries (got ${list.length})`, list.length <= EXCLUDE_CREDENTIALS_MAX);
    // NOT merely "small": an empty list would also be <= 64 and would silently discard the affordance.
    ok(`(d) and it is exactly ${EXCLUDE_CREDENTIALS_MAX}, not an empty list that would also satisfy the bound`, list.length === EXCLUDE_CREDENTIALS_MAX);
    ok("(d) every entry is a well-formed public-key descriptor with an id", list.every((e) => typeof e === "object" && e !== null && (e as { type?: unknown }).type === "public-key" && typeof (e as { id?: unknown }).id === "string"));
  }
}

// ---- (e) the duplicate guard is untouched --------------------------------------------------------
// excludeCredentials is a browser UX affordance, not the duplicate guard. The guard is server-side in
// passkeyRegisterFinish, which refuses a credential id already registered by reading STORAGE. Truncating
// the exclude list cannot reach it, and this asserts the guard is still expressed in the source that runs
// it rather than assuming so.
{
  const { readFileSync } = await import("node:fs");
  const finishSrc = readFileSync(new URL("../src/sched/scheduler-do-passkey.ts", import.meta.url), "utf8");
  const hasStorageDupGuard = /getPasskeyCred\(/.test(finishSrc) && /credential[_ ]?id already registered|already_registered|credentialIdInUse|duplicate/i.test(finishSrc);
  ok("(e) the finish still refuses an already-registered credential id from storage, so truncation weakens no guard", hasStorageDupGuard);
}

console.log(failures === 0 ? "\nvalidate-passkey-exclude-cap: ALL PASS" : `\nvalidate-passkey-exclude-cap: ${failures} FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
