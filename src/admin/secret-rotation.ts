// secret-rotation.ts -- the closed cadence table for the seven engine secrets. The rotation schedule at
// docs/security/cryptography-and-keys.md commits to a cadence, and the secrets configured to expire and
// rotate must match the documentation. Each entry names the id, the env binding(s) whose presence means
// the secret is in service, the cadence in days and whether the engine can OBSERVE a rotation from a
// public fingerprint (a key) or must rely on an operator's own attestation (a bearer/destination credential,
// which the no-custody rule forbids the engine from fingerprinting).
//
// This table is the source of truth the code side commits to; checkSecretRotationDocPin parses the live
// markdown table in cryptography-and-keys.md and fails when a cadence here disagrees with the documented
// one, so the two cannot drift silently.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.

export type SecretRotationId =
  | "signer_private"
  | "break_glass"
  | "operational_private"
  | "admin_token"
  | "scim_bearer_token"
  | "discovery_api_token"
  | "dest_secret_access_key";

export interface SecretRotationCadenceEntry {
  id: SecretRotationId;
  // Operator-facing label for the credential-lifecycle registry row (expiry.ts ExpiryItem.label).
  label: string;
  // The env binding(s) whose presence means this secret is in service. A cadence applies only while at
  // least one of them is bound; when none are, the tracked row is removed rather than left ticking down
  // on a secret the deployment does not use.
  bindings: readonly string[];
  cadenceDays: number;
  kind: "key" | "credential";
  // fingerprintBinding is set ONLY for a public-key secret whose rotation the engine can OBSERVE from a
  // fingerprint it already reads for another purpose (key-vintages.ts): SIGNER_PRIVATE's own fingerprint
  // for the signer, and the PUBLIC recipient binding's fingerprint for a break-glass/operational pair (the
  // private half is never read to compute one). Absent for a bearer or destination credential: the
  // no-custody rule forbids the engine from retaining a hash, prefix or length of that secret, so its
  // rotation is operator-attested (POST /admin/secrets/rotated) rather than engine-observed.
  fingerprintBinding?: string;
}

// SECRET_ROTATION_CADENCES mirrors the "Planned cadence" column of the rotation schedule table at
// docs/security/cryptography-and-keys.md for the seven secrets that carry an enforceable cadence (the
// derived-cadence recipient publics, the per-run master, CONFIG_WRAP_KEY, the config recipient pair and the
// session signing key are each excluded there for their own stated reason, and stay excluded here).
export const SECRET_ROTATION_CADENCES: readonly SecretRotationCadenceEntry[] = [
  { id: "signer_private", label: "Signer key (SIGNER_PRIVATE) rotation", bindings: ["SIGNER_PRIVATE"], cadenceDays: 365, kind: "key", fingerprintBinding: "SIGNER_PRIVATE" },
  { id: "break_glass", label: "Break-glass recipient key (BREAK_GLASS_PUBLIC) rotation", bindings: ["BREAK_GLASS_PUBLIC"], cadenceDays: 730, kind: "key", fingerprintBinding: "BREAK_GLASS_PUBLIC" },
  { id: "operational_private", label: "Operational recipient key (OPERATIONAL_PRIVATE) rotation", bindings: ["OPERATIONAL_PRIVATE"], cadenceDays: 365, kind: "key", fingerprintBinding: "OPERATIONAL_PUBLIC" },
  { id: "admin_token", label: "Admin bearer token (ADMIN_TOKEN) rotation", bindings: ["ADMIN_TOKEN"], cadenceDays: 90, kind: "credential" },
  { id: "scim_bearer_token", label: "SCIM bearer token (SCIM_BEARER_TOKEN) rotation", bindings: ["SCIM_BEARER_TOKEN"], cadenceDays: 365, kind: "credential" },
  { id: "discovery_api_token", label: "Discovery API token (DISCOVERY_API_TOKEN) rotation", bindings: ["DISCOVERY_API_TOKEN"], cadenceDays: 90, kind: "credential" },
  { id: "dest_secret_access_key", label: "Destination access key (DEST_SECRET_ACCESS_KEY) rotation", bindings: ["DEST_SECRET_ACCESS_KEY"], cadenceDays: 90, kind: "credential" },
];

// rotationItemId builds the credential-lifecycle registry's item id for a cadenced secret's tracked row
// (stored under `expiry:<this>` by expiry.ts). A hyphen, not the marker's own `:` separator: expiry.ts's
// EXPIRY_ID_PATTERN bounds an item id to [A-Za-z0-9._-], the same safe storage-key-fragment discipline
// every other tracked item's id follows.
export function rotationItemId(id: SecretRotationId): string {
  return `rotation-${id}`;
}

// ROTATION_PREFIX keys one rotation marker per secret under `rotation:<id>` in the scheduler DO, alongside
// the `expiry:`/`expiry-cooldown:` keys the credential lifecycle registry already owns.
export const ROTATION_PREFIX = "rotation:";

// RotationMarker is the stored baseline a secret's cadence counts from: at (RFC-3339) is either the moment
// a rotation was observed/attested, or the conservative first-seen baseline seeded when nothing was tracked
// yet. actor is the operator email who confirmed a bearer/destination rotation (POST /admin/secrets/
// rotated), or null for an engine-observed reset or the initial seed -- never a human action to attribute.
// fingerprint is set ONLY on a public-key entry (see SecretRotationCadenceEntry.fingerprintBinding); for a
// bearer or destination credential this carries no value, hash, prefix or length of the secret, matching
// the no-custody rule the credential lifecycle registry already holds (expiry.ts).
export interface RotationMarker {
  at: string;
  actor: string | null;
  fingerprint?: string;
}

// rotationNowISO stamps a rotation marker's `at` from Date.now() rather than `new Date()` (the two agree
// whenever Date.now is not mocked, which is every production run), so a validator can move this domain's
// clock with the same `Date.now = () => ms` idiom the suite already uses elsewhere, without changing the
// shared nowMillisISO helper every unrelated producer calls.
export function rotationNowISO(): string {
  return new Date(Date.now()).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

const SECRET_ROTATION_ID_SET: ReadonlySet<string> = new Set(SECRET_ROTATION_CADENCES.map((e) => e.id));

// isSecretRotationId is the runtime guard for a client-supplied id at the authority boundary (POST
// /admin/secrets/rotated), mirroring isExpiryKind.
export function isSecretRotationId(v: unknown): v is SecretRotationId {
  return typeof v === "string" && SECRET_ROTATION_ID_SET.has(v);
}

// cadenceEntryFor looks up one cadence entry by id, or undefined for an id outside the closed set.
export function cadenceEntryFor(id: SecretRotationId): SecretRotationCadenceEntry {
  // isSecretRotationId already narrows to a member of SECRET_ROTATION_CADENCES, so this lookup always
  // finds a row; the non-null assertion is bounded by that closed set, never by an unchecked input.
  return SECRET_ROTATION_CADENCES.find((e) => e.id === id)!;
}

// ---- doc-pin: the code table above must agree with the markdown table it mirrors -------------------

// cellCadenceDays reads the leading "N day(s)"/"N month(s)" out of a table cell (the cell may carry extra
// prose after it, e.g. "90 days, or the destination provider's own policy where it is shorter"). Months are
// converted at 365/12 days per month, which is exact for every multiple of 12 this table uses (12 -> 365,
// 24 -> 730), so it never introduces its own rounding drift against the annual cadences it is checking.
function cellCadenceDays(cell: string): number | null {
  const m = cell.match(/(\d+)\s*(day|days|month|months)\b/i);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] ?? "").toLowerCase();
  return unit.startsWith("day") ? n : Math.round((n * 365) / 12);
}

// splitTableRow parses one GitHub-flavoured-markdown table row into its cell texts, or null for a line that
// is not a table row (including the header's own "|---|---|" separator, so it is never mistaken for data).
function splitTableRow(line: string): string[] | null {
  const t = line.trim();
  if (!t.startsWith("|") || !t.endsWith("|") || t.length < 2) return null;
  const cells = t
    .slice(1, -1)
    .split("|")
    .map((c) => c.trim());
  if (cells.length < 3) return null;
  if (/^-+$/.test(cells[0] ?? "")) return null;
  return cells;
}

// DOC_ROW_PATTERNS matches each cadence entry to the start of its row's first ("Secret") column in the
// markdown table, exactly as that column reads today. Matched by pattern rather than by line number so the
// doc-pin check survives the table being reordered or having rows added around it.
const DOC_ROW_PATTERNS: Record<SecretRotationId, RegExp> = {
  signer_private: /^`SIGNER_PRIVATE`/,
  break_glass: /^Break-glass private/,
  operational_private: /^`OPERATIONAL_PRIVATE`/,
  admin_token: /^`ADMIN_TOKEN`/,
  scim_bearer_token: /^`SCIM_BEARER_TOKEN`/,
  discovery_api_token: /^`DISCOVERY_API_TOKEN`/,
  dest_secret_access_key: /^`DEST_SECRET_ACCESS_KEY`/,
};

export interface SecretRotationDocPinMismatch {
  id: SecretRotationId;
  codeDays: number;
  // null when the row could not be found in the document at all, OR was found but its cadence cell did
  // not parse as "N day(s)"/"N month(s)". Either way it is not the code's cadenceDays, so it is reported.
  docDays: number | null;
}

// ROTATION_SCHEDULE_HEADING marks the start of the one table this module pins to. Several tables in this
// document have a first ("Secret") column, including an unrelated key-material table that names
// "Break-glass private" too, so parsing the WHOLE document would let that other table's row answer for
// this one's pattern. extractRotationScheduleSection bounds the search to this heading through the next
// heading of the same or a shallower level, so a pattern only ever matches inside the schedule table.
const ROTATION_SCHEDULE_HEADING = "#### The rotation schedule";

function extractRotationScheduleSection(markdown: string): string | null {
  const start = markdown.indexOf(ROTATION_SCHEDULE_HEADING);
  if (start === -1) return null;
  const rest = markdown.slice(start + ROTATION_SCHEDULE_HEADING.length);
  const nextHeading = rest.search(/\n#{1,4}\s/);
  return nextHeading === -1 ? rest : rest.slice(0, nextHeading);
}

// checkSecretRotationDocPin parses the rotation-schedule table out of the given markdown text and reports
// every cadence entry whose code value disagrees with (or is missing from) the documented one. The caller
// passes the CURRENT file content, never a cached copy, so a hand-edited table is caught the same run.
export function checkSecretRotationDocPin(markdown: string): { ok: true } | { ok: false; mismatches: SecretRotationDocPinMismatch[] } {
  const section = extractRotationScheduleSection(markdown);
  const rows =
    section === null
      ? []
      : section
          .split("\n")
          .map(splitTableRow)
          .filter((r): r is string[] => r !== null);
  const mismatches: SecretRotationDocPinMismatch[] = [];
  for (const entry of SECRET_ROTATION_CADENCES) {
    const pattern = DOC_ROW_PATTERNS[entry.id];
    const row = rows.find((r) => pattern.test(r[0] ?? ""));
    const docDays = row !== undefined ? cellCadenceDays(row[2] ?? "") : null;
    if (docDays !== entry.cadenceDays) mismatches.push({ id: entry.id, codeDays: entry.cadenceDays, docDays });
  }
  return mismatches.length === 0 ? { ok: true } : { ok: false, mismatches };
}
