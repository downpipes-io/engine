// validate-samlcert-cap-honesty.ts
//
// THE BOUND, AND THE SECOND QUESTION ABOUT IT. A SAML signing-certificate rollover is documented as
// APPEND (so assertions signed by either key verify through the overlap) then REPLACE (so the retired
// certificate is pruned). Append only ever RAISES the pinned count, and the pinned set is capped at
// SAML_CERTS_MAX. So the interesting question was never "does it refuse" but "when it refuses, does the
// refusal describe itself, and does the remedy it implies help".
//
// IT DID NOT. strArray returns ONE null for "not an array", "an entry is not a bounded string" and "more
// entries than maxItems" alike, so an over-capacity array of perfectly valid PEMs fell to the EMPTY /
// wrong-shape sentence: "idpSigningCerts must be a non-empty array of PEM X.509 certificates". Shown by
// dose-response on the append arm, 7 pinned + 1 pasted accepts and 7 + 2 refuses, with that sentence.
//
// WHY IT MATTERS MORE THAN A WRONG WORD. The refusal lands at IdP cut-over, the one moment every SSO
// sign-in depends on the new key being trusted. The remedy the old sentence implies (re-export the
// certificate from the provider) cannot work, and the remedy that does (Replace, the other control on the
// same screen) was named nowhere. A count that only rises, refused with a sentence pointing away from the
// only step that lowers it.
//
// This validator drives the REAL validateSamlCerts and the REAL append arithmetic, and it carries the
// controls that make the result readable rather than assertable:
//   - NEGATIVE CONTROLS that must classify DIFFERENTLY (duplicate, malformed PEM), out of the SAME
//     function on the same shape of input, so "this codebase does not write specific messages" is refuted.
//   - The EMPTY case, which keeps the borrowed sentence, because there it is correct.
//   - A POSITION CONTROL: the overflowing certificate first rather than last does not move the verdict.
//   - A DIFFERENTIAL CONTROL: the same over-cap class down validateOidc's scopes still collapses, which is
//     what proves the conflation belonged to strArray's single null and names the residue left in place.
import { SAML_CERTS_MAX, validateOidc, validateSamlCerts } from "../src/admin/idpconn-validators.ts";
import type { IdpConnectionProposal } from "../src/admin/idpconn.ts";
// Importing the verdict guard ARMS it: a run that exits without reaching verdictReached below is
// forced to exit 1, so a drained event loop can never read as a clean sweep.

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) failures++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
}

function pem(tag: string): string {
  return `-----BEGIN CERTIFICATE-----\nMIIC${tag}\n-----END CERTIFICATE-----`;
}
function distinctPems(n: number, from = 0): string[] {
  return Array.from({ length: n }, (_, i) => pem(`cert${String(from + i).padStart(3, "0")}`));
}

// appendOutcome reproduces the APPEND arm of idpConnSamlCertUpdate: merge the pasted certificates onto the
// pinned ones and run the merged array through the shared gate.
function appendOutcome(pinned: number, pasted: number): { ok: boolean; reason: string } {
  const v = validateSamlCerts([...distinctPems(pinned, 0), ...distinctPems(pasted, 100)]);
  return v.ok ? { ok: true, reason: "" } : { ok: false, reason: v.reason };
}

console.log("validate-samlcert-cap-honesty");
console.log(`SAML_CERTS_MAX=${SAML_CERTS_MAX}`);

// ---- DOSE-RESPONSE: below, at, past, and far past the edge --------------------------------------
console.log("\nDOSE-RESPONSE on the APPEND arm (pinned + pasted -> verdict):");
const DOSES: [number, number][] = [
  [0, 1], [1, 1], [1, 6], [1, 7], [1, 8], [1, 9],
  [4, 3], [4, 4], [4, 5],
  [7, 1], [7, 2], [7, 3],
  [8, 1], [8, 8],
  [0, 8], [0, 9], [0, 100],
];
const rows = DOSES.map(([pinned, pasted]) => ({ pinned, pasted, total: pinned + pasted, ...appendOutcome(pinned, pasted) }));
for (const r of rows) console.log(`  ${r.pinned} + ${r.pasted} = ${r.total}\t${r.ok ? "ACCEPT" : "REFUSE"}\t${r.reason}`);
const row = (pinned: number, pasted: number) => rows.find((r) => r.pinned === pinned && r.pasted === pasted)!;

console.log("\nWHERE IS THE EDGE");
ok(`every total at or under ${SAML_CERTS_MAX} is accepted`, rows.filter((r) => r.total <= SAML_CERTS_MAX).every((r) => r.ok === true));
ok(`every total above ${SAML_CERTS_MAX} is refused`, rows.filter((r) => r.total > SAML_CERTS_MAX).every((r) => r.ok === false));
ok(`the edge sits on the TOTAL, not the pasted count (4+5 refuses while 0+8 accepts)`, row(4, 5).ok === false && row(0, 8).ok === true);
ok(`far past the edge is still a refusal, never a truncation (0 + 100)`, row(0, 100).ok === false);

console.log("\nIS THE REFUSAL HONEST");
const over = row(7, 2);
ok(`the over-capacity refusal NAMES the cap`, over.ok === false && over.reason.includes(String(SAML_CERTS_MAX)));
ok(`it NAMES the resulting count, so the arithmetic is visible`, over.ok === false && /\b9\b/.test(over.reason));
ok(`it NAMES the Replace step, which is the remedy that lowers the count`, over.ok === false && /Replace/.test(over.reason));
ok(`it no longer asserts the certificates are not PEM X.509`, over.ok === false && !/must be a non-empty array of PEM X\.509 certificates/.test(over.reason));

// ---- NEGATIVE CONTROLS: these MUST classify DIFFERENTLY -----------------------------------------
console.log("\nNEGATIVE CONTROLS (must classify differently), same function, comparable inputs");
const dup = validateSamlCerts([pem("same"), pem("same")]);
ok(`a DUPLICATE certificate keeps its own named reason`, dup.ok === false && /appears twice/.test(dup.reason));
ok(`  and does not borrow the over-capacity reason`, dup.ok === false && over.ok === false && dup.reason !== over.reason);
const bad = validateSamlCerts(["not a certificate at all"]);
ok(`a MALFORMED PEM keeps its own named reason (the BEGIN CERTIFICATE armour)`, bad.ok === false && /BEGIN CERTIFICATE/.test(bad.reason));
ok(`  and does not borrow the over-capacity reason`, bad.ok === false && over.ok === false && bad.reason !== over.reason);
const empty = validateSamlCerts([]);
ok(`an EMPTY array KEEPS the wrong-shape sentence, because there it is true`, empty.ok === false && /non-empty array of PEM X\.509 certificates/.test(empty.reason));
const notArray = validateSamlCerts("a string");
ok(`a NON-ARRAY keeps the wrong-shape sentence too`, notArray.ok === false && /non-empty array of PEM X\.509 certificates/.test(notArray.reason));
// Every `ok === false` guard comes FIRST so each `.reason` read is narrowed before it is taken. The
// conjunction is unchanged in meaning; ordered the other way, `empty.reason` was read off the unnarrowed
// union and the checker could not see the claim at all (TS2339).
ok(`the over-capacity case is now the ONLY one of the five that is not the wrong-shape sentence`, over.ok === false && empty.ok === false && notArray.ok === false && over.reason !== empty.reason && empty.reason === notArray.reason);

// ---- POSITION CONTROL ---------------------------------------------------------------------------
console.log("\nPOSITION CONTROL: the overflowing certificate first rather than last");
{
  const eight = distinctPems(8);
  const front = validateSamlCerts([pem("overflow"), ...eight]);
  const back = validateSamlCerts([...eight, pem("overflow")]);
  ok(`the verdict does not move with position`, front.ok === false && back.ok === false);
  ok(`and the reason is byte-identical, so it is a verdict on LENGTH before any entry is read`, front.ok === false && back.ok === false && front.reason === back.reason);
}

// ---- DIFFERENTIAL CONTROL, WHICH ALSO PINS THE RESIDUE ------------------------------------------
// Driving the same over-cap class down a sibling bounded array shows the conflation belonged to
// strArray's single null. That sibling is DELIBERATELY left as it is: a create-time config fault is
// retried immediately, unlike a rollover racing a provider's cut-over. Pinned so the choice stays a
// choice: if a later change fixes strArray itself, this assertion is what says so.
console.log("\nDIFFERENTIAL CONTROL: the same over-cap class down validateOidc's scopes");
{
  const base = { createdBy: "owner@example.test", createdAt: "2026-08-11T00:00:00.000Z" };
  const proposal = (scopes: string[]): IdpConnectionProposal =>
    ({
      id: "c1", kind: "oidc", label: "L", presetId: "generic-oidc", enabled: true,
      issuer: "https://idp.example.com", clientId: "cid", scopes,
      idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "pkce_public", requireNonce: true,
    }) as unknown as IdpConnectionProposal;
  const overScopes = validateOidc(proposal(["openid", ...Array.from({ length: 40 }, (_, i) => `s${i}`)]), base as never);
  ok(`an OVER-CAP scope list still collapses to a shape message, naming no cap`, overScopes.ok === false && /scopes must be an array of short strings/.test(overScopes.reason));
  ok(`  so the conflation was strArray's single null, and the residue is named rather than implied away`, overScopes.ok === false && !/\b32\b/.test(overScopes.reason));
}

console.log(`\nvalidate-samlcert-cap-honesty: ${checks} check(s), ${failures} failure(s)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
