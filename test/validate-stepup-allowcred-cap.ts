// PASSKEY-ALLOW-OVER-64-IS-THE-SECOND-LOCKOUT: stepUpBegin must never emit an allowCredentials
// list larger than the browser will accept, because past that ceiling the browser refuses the assertion
// and the account can never step up again. Run:
//   node test/validate-stepup-allowcred-cap.ts
//
// A SIBLING GAP: excludeCredentials on the REGISTRATION ceremony is bounded after measuring Chromium's
// 64-entry ceiling. The assertion ceremony has a second descriptor list, `allowCredentials`, and
// stepUpBegin must bound it the same way rather than emitting an account's ENTIRE credential list.
//
// MEASURED against Chromium 149.0.7827.55, CDP virtual authenticator on a local origin, dose-response
// over allowCredentials sizes 0, 1, 32, 63, 64, 65, 66, 100, 128, 256:
//
//   1..64  -> the assertion completed
//   65+    -> DOMException named `RangeError`,
//             "The `allowCredentials` attribute exceeds the maximum allowed size (64)."
//
// The rig reproduced the excludeCredentials measurement (first throw at exactly 65) alongside its own
// control, so its allowCredentials verdicts are not the instrument reporting on itself. The refusal did
// not move when the genuine credential was placed LAST rather than first: the browser rejects on list
// SIZE, before it consults an authenticator.
//
// WHY IT IS A LOCKOUT AND NOT A BLEMISH. Step-up gates recovery-code regeneration, self-add passkey, the
// key ceremony, posture risk-accept, restore-approve -- and /passkey/credentials/delete, which is the ONLY
// route that reduces a credential count. An account at 65 could not step up, so it could not delete a
// credential, so it could not get back under 65. The count moves in one direction only, and every
// enrolment adds one more.
//
// What this proves: (a) the pure selector bounds the list at ALLOW_CREDENTIALS_MAX and is a no-op at or
// below it; (b) it keeps PROVEN-usable credentials ahead of never-asserted ones, which is what keeps the
// truncation cheap; (c) it is deterministic and order-independent; (d) the REAL DO's stepUpBegin emits a
// bounded list for an account over the ceiling; (e) truncating the OFFER weakens no authorisation, because
// stepUpFinish re-checks that the asserting credential belongs to the caller's own email from storage.

import { ALLOW_CREDENTIALS_MAX, allowCredentialsFor, EXCLUDE_CREDENTIALS_MAX, type PasskeyCred } from "../src/admin/passkey.ts";
import { PASSKEY_CRED_PREFIX } from "../src/sched/scheduler-do-base.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function iso(n: number): string {
  return new Date(Date.UTC(2026, 0, 1, 0, 0, 0) + n * 60_000).toISOString();
}

function cred(credentialId: string, createdAt: string, lastAssertedAt: string | null, email = "a@example.com"): PasskeyCred {
  return {
    credentialId,
    email,
    publicKey: "cGs",
    signCount: 0,
    createdAt,
    lastAssertedAt,
    transports: ["internal"],
    aaguid: null,
    label: null,
    backupEligible: false,
    backupState: false,
    uvInitialised: true,
  } as unknown as PasskeyCred;
}

// ---- (a) the bound itself, swept rather than asserted at one point -------------------------------
{
  ok(`the measured allowCredentials ceiling is ${ALLOW_CREDENTIALS_MAX}`, ALLOW_CREDENTIALS_MAX === 64);
  // The two lists were measured separately and came back the same. If a future measurement moves one, this
  // says so out loud rather than letting a shared helper quietly impose the other's number.
  ok("it matches the separately-measured excludeCredentials ceiling", ALLOW_CREDENTIALS_MAX === EXCLUDE_CREDENTIALS_MAX);

  // DOSE-RESPONSE across the edge, with the sizes the browser sweep used. Below and at the ceiling the
  // selector must be a NO-OP (truncating early would silently drop a usable authenticator); above it, the
  // output must sit exactly on the ceiling.
  for (const n of [0, 1, 32, 63, 64, 65, 66, 100, 128, 256]) {
    const creds = Array.from({ length: n }, (_, i) => cred(`id-${String(i).padStart(3, "0")}`, iso(i), null));
    const picked = allowCredentialsFor(creds);
    const expected = Math.min(n, ALLOW_CREDENTIALS_MAX);
    ok(`(a) n=${n} yields ${expected} entries (got ${picked.length})`, picked.length === expected);
  }
}

// ---- (b) the ranking, which is what makes truncation survivable ----------------------------------
{
  // 70 credentials, of which three are PROVEN usable. A non-null lastAssertedAt is written only after a
  // signature verified, so it is evidence the authenticator still exists rather than an inference from the
  // record existing. Those three are the OLDEST enrolments, so "newest wins" alone would drop every one.
  const creds: PasskeyCred[] = [];
  for (let i = 0; i < 70; i++) creds.push(cred(`id-${String(i).padStart(3, "0")}`, iso(i), null));
  creds[0] = cred("id-000", iso(0), iso(900));
  creds[1] = cred("id-001", iso(1), iso(901));
  creds[2] = cred("id-002", iso(2), iso(902));

  const ids = allowCredentialsFor(creds).map((c) => c.credentialId);
  ok(`(b) bounded at ${ALLOW_CREDENTIALS_MAX} (got ${ids.length})`, ids.length === ALLOW_CREDENTIALS_MAX);
  ok("(b) all three PROVEN-usable credentials are offered despite being the oldest enrolments", ["id-000", "id-001", "id-002"].every((id) => ids.includes(id)));
  ok("(b) the most recently PROVEN credential leads the offer", ids[0] === "id-002");
  ok("(b) the oldest never-asserted enrolment is the one dropped", !ids.includes("id-003"));

  // ---- (c) determinism -------------------------------------------------------------------------
  const again = allowCredentialsFor(creds).map((c) => c.credentialId);
  ok("(c) the selection is deterministic across repeated calls", JSON.stringify(ids) === JSON.stringify(again));
  ok("(c) and independent of input order", JSON.stringify(allowCredentialsFor([...creds].reverse()).map((c) => c.credentialId)) === JSON.stringify(ids));
}

// ---- (d) the REAL step-up ceremony ---------------------------------------------------------------
// Drives the actual SchedulerDO stepUpBegin over the in-memory storage double: no network, no deploy, no
// estate. The account is seeded with 65 credentials, the exact count measured on three live probe accounts.
{
  const { SchedulerDO } = await import("../src/sched/scheduler-do.ts");
  const { MockStorage } = await import("./mock-storage.ts");

  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const email = "over-ceiling@example.com";

  await storage.put(`role:${email}`, { email, role: "owner", createdAt: iso(0) });
  await storage.put(`passkeyUser:${email}`, { email, displayName: "Over Ceiling", createdAt: iso(0) });
  for (let i = 0; i < 65; i++) {
    const id = `cred-${String(i).padStart(3, "0")}`;
    await storage.put(`${PASSKEY_CRED_PREFIX}${id}`, cred(id, iso(i), null, email));
  }

  // KNOWN POSITIVE ON THE SEED. Without it, a begin that offered nothing because the DO could not see the
  // credentials at all would read as a clean bound.
  const seeded = await dobj.listPasskeyCredsForEmail(email);
  ok(`(d) the seeded account really holds 65 credentials the DO can see (got ${seeded.length})`, seeded.length === 65);

  const begun = await dobj.stepUpBegin({ rpId: "console.example.com" }, { email, subject: `passkey:${email}` });
  if (!begun.ok) {
    ok(`(d) step-up/begin was issued for the account (reason: ${"reason" in begun ? begun.reason : "?"})`, false);
  } else {
    const opts = begun.publicKey as { allowCredentials?: unknown[] };
    const list = Array.isArray(opts.allowCredentials) ? opts.allowCredentials : [];
    ok("(d) step-up/begin was issued for the account", true);
    ok(`(d) the REAL ceremony emits at most ${ALLOW_CREDENTIALS_MAX} allow entries (got ${list.length})`, list.length <= ALLOW_CREDENTIALS_MAX);
    // NOT merely "small": an EMPTY allowCredentials also satisfies "<= 64", and on an assertion it means
    // something entirely different (offer any discoverable credential), so it must be ruled out explicitly.
    ok(`(d) and it is exactly ${ALLOW_CREDENTIALS_MAX}, not an empty list that would also satisfy the bound`, list.length === ALLOW_CREDENTIALS_MAX);
    ok("(d) every entry is a well-formed public-key descriptor with an id", list.every((e) => typeof e === "object" && e !== null && (e as { type?: unknown }).type === "public-key" && typeof (e as { id?: unknown }).id === "string"));
  }
}

// ---- (e) truncating the OFFER weakens no authorisation -------------------------------------------
// allowCredentials is a browser affordance that scopes which keys are offered. The authorisation check is
// server-side in stepUpFinish, which refuses a credential that is not the caller's own by reading storage.
// Truncating the offer cannot reach it, and this asserts the check is still expressed in the source that
// runs it rather than assuming so.
{
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("../src/sched/scheduler-do-stepup.ts", import.meta.url), "utf8");
  const finish = src.slice(src.indexOf("async stepUpFinish"));
  ok("(e) stepUpFinish still reads the asserting credential from storage", /getPasskeyCred\(/.test(finish));
  ok("(e) and still refuses one that is not the caller's own email", /\.email\s*!==\s*email|email\s*!==\s*\w*[Cc]red\w*\.email/.test(finish));
}

console.log(failures === 0 ? "\nvalidate-stepup-allowcred-cap: ALL PASS" : `\nvalidate-stepup-allowcred-cap: ${failures} FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
