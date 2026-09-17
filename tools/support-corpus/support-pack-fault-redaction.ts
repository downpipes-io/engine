// support-pack-fault-redaction.ts -- THE PACK'S OWN REDACTION, PUT UNDER ADVERSARIAL PRESSURE RATHER THAN ASSERTED.
//
//   node tools/support-corpus/support-pack-fault-redaction.ts
//
// Another pass recorded, in its own words, that "the pack's own redaction was NOT adversarially tested --
// in scope, not done, no leak claimed and none ruled out". This is that. It matters more now than it did then,
// because a second pass taught three bounded records to EMIT THE SUBJECT ID THEY REFUSED, and an id can be a
// customer-identifying string. A pack that leaks is worse than one that stays silent.
//
// THE METHOD. Every case plants a value at a field a WRITER controls -- a downpipe id, a destination label, a
// stored role record, a grant, an audit event -- and then searches the GENERATED PACK's bytes for it. The
// value is chosen to be unmistakable if it appears (an address, a bearer-shaped string, a control character, a
// 4KB blob), so a match is a leak and not a coincidence.
//
// AND EVERY CASE CARRIES ITS OWN POSITIVE CONTROL, because "the planted value did not appear" is also true of
// a pack that was never built, of a route that was never read, and of a plant that never landed. Each case
// therefore names a WITNESS: something that MUST appear in the same pack, at the same site, proving the plant
// reached the projector at all. A case whose witness is missing is reported CANNOT-CHECK and fails the run
// rather than passing it.

import { readSchedDiag, recordFreshnessFault, type LedgerStorage } from "../../src/sched/sched-fault-ledger.ts";
import { makeKeys, type World } from "./harness.ts";
import { buildPack } from "./support-pack-fault-oracle.ts";

type Dict = Record<string, unknown>;
const NOW = 1_786_000_000_000;
const iso = (t: number): string => new Date(t).toISOString();

interface RedactionCase {
  id: string;
  /** What is being defended, in one line. */
  what: string;
  /** Values that MUST NOT appear anywhere in the pack. */
  mustNotAppear: string[];
  /** Values that MUST appear, proving the plant reached the projector. Without one the case is vacuous. */
  witness: string[];
  mutate: (w: World) => void;
  /**
   * An extra assertion over the generated pack, for the cases where "did the value appear" is the wrong
   * question. Returns [] when it holds. That second pass's subject emission is exactly that case: the id it emits IS
   * the customer's own downpipe naming, so if a customer names a downpipe with an address the address rides --
   * and it rode BEFORE the emission existed, as `downpipes[].id`. The disclosure question is therefore not
   * "does it appear" but "does REFUSING a key disclose a class that ADMITTING the same key does not", and only
   * an assertion can ask that.
   */
  also?: (pack: Dict) => string[];
  /**
   * Console-asserted evidence the browser would post with the pack. A capture that reads the SCREEN is where
   * customer text would ride if it rode anywhere, so a new one is put through this suite rather than declared
   * safe on the strength of its own design.
   */
  clientDiag?: () => unknown;
}

function memStorage(): LedgerStorage {
  const map = new Map<string, unknown>();
  return {
    async get<T>(k: string): Promise<T | undefined> {
      return map.get(k) as T | undefined;
    },
    async put<T>(k: string, v: T): Promise<void> {
      map.set(k, v);
    },
  };
}

// The two shapes a customer value actually takes in this product, plus one that is simply hostile.
const EMAIL = "cfo.private@acquisition-target.example";
const BEARER = "dpk1-SECRETBEARERVALUE-0123456789abcdef";
// Written with escapes rather than raw bytes: a raw NUL inside git's binary-sniff window makes git
// treat this whole file as binary and drop it from git grep, which is how a corpus fixture can hide
// the exact class it exists to exercise. The runtime value is identical.
const CONTROLS = "roster\u0000row\u001bwith\u0007controls";
const BLOB = `X${"q".repeat(4000)}Z`;

// A downpipe id carrying an address. It is the WORST case for that pass's subject emission, because the
// subject list holds ids and the id space is the customer's own naming.
const ADDRESSY_DP = `payroll-${EMAIL}`;

const freshnessWithAddressySubject = await (async (): Promise<Dict> => {
  const s = memStorage();
  for (let i = 0; i < 50; i++) await recordFreshnessFault(s, `dp-${String(i).padStart(4, "0")}`, "cadence-malformed");
  await recordFreshnessFault(s, ADDRESSY_DP, "cadence-malformed"); // refused by the cap: this is the emitted subject
  return (await readSchedDiag(s)) as unknown as Dict;
})();

const CASES: RedactionCase[] = [
  {
    id: "lockout-posture-takes-no-free-text",
    what: "the NEW lockoutPosture section, fed a DO answer stuffed with everything a roster row can hold",
    mustNotAppear: [EMAIL, BEARER, CONTROLS, BLOB, "Finance Approver"],
    witness: ["rosterUnreadable", "unknown-code"],
    mutate: (w: World): void => {
      w.routes["/policy/lockout-preflight"] = {
        passkeyOwnerEnrolled: true,
        // The two closed enums, fed NON-MEMBERS carrying customer text. A non-member must become UNKNOWN_CODE
        // rather than ride: this is the one place free text could enter this section.
        passkeyOwnerEvidence: EMAIL,
        recoveryReadyReason: BLOB,
        passkeyWitnessSince: CONTROLS,
        recoveryReady: true,
        secondOwner: false,
        rosterUnreadable: 3,
        // Fields the projector does not know. A projection that spread its input would carry all of these.
        ownerEmail: EMAIL,
        ownerRoleName: "Finance Approver",
        sessionBearer: BEARER,
      };
    },
  },
  {
    id: "cap-truncation-subject-is-the-admitted-key-space-and-nothing-else",
    what: "the emitted subject id, planted as a downpipe id that IS an address",
    // The id itself is the customer's own downpipe naming and rides by design (see the note below); what must
    // not ride is anything BESIDE it -- a cause, a reason class, a digest, a bearer.
    mustNotAppear: [BEARER, BLOB, "cadence-malformed-with-" + BEARER],
    witness: [ADDRESSY_DP],
    also: (pack: Dict): string[] => {
      const f: string[] = [];
      const dps = Array.isArray(pack.downpipes) ? (pack.downpipes as Dict[]) : [];
      // THE PRE-EXISTING DISCLOSURE, ASSERTED RATHER THAN ARGUED: the same string is already the row's own id.
      if (!dps.some((d) => d.id === ADDRESSY_DP)) f.push("the id does NOT already ride as downpipes[].id, so the subject emission would be a NEW disclosure rather than a repeat of an existing one");
      const sd = (typeof pack.schedDiag === "object" && pack.schedDiag !== null ? pack.schedDiag : {}) as Dict;
      const cts = (typeof sd.capTruncationSubjects === "object" && sd.capTruncationSubjects !== null ? sd.capTruncationSubjects : {}) as Dict;
      const entry = (cts["freshness-faults"] ?? {}) as { ids?: unknown };
      const ids = Array.isArray(entry.ids) ? (entry.ids as unknown[]) : [];
      if (!ids.includes(ADDRESSY_DP)) f.push("population: the refused subject is not named, so this case proves nothing about what naming it discloses");
      // AND NOTHING BESIDE THE ID. The subject ledger carries ids and no cause, class, digest or count.
      const beside = Object.keys(entry as Dict).filter((k) => k !== "ids" && k !== "incomplete" && k !== "at" && k !== "lastAt");
      if (beside.length > 0) f.push(`the subject ledger carries fields BESIDE the ids: ${JSON.stringify(beside)}`);
      return f;
    },
    mutate: (w: World): void => {
      w.routes["/sched-diag"] = freshnessWithAddressySubject;
      w.routes["/downpipes"] = [
        {
          config: { id: ADDRESSY_DP, name: "payroll", enabled: true, cadenceSeconds: 3600, source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "ns", include: [], exclude: [] } },
          lastRunId: "01RUNOK",
          inFlight: false,
        },
      ];
    },
  },
  {
    id: "audit-excerpt-drops-the-actor-the-caller-chose",
    what: "defect 19's unauthenticated actor: an address written straight into the tamper-evident chain",
    mustNotAppear: [EMAIL, BEARER, "203.0.113.77"],
    witness: ["role-change"],
    mutate: (w: World): void => {
      w.routes["/audit/export"] = (url: URL): unknown => {
        const events = [
          { seq: 11, ts: iso(NOW - 7_200_000), action: "role-change", outcome: "failed", actorEmail: EMAIL, actorSubject: BEARER, sourceIp: "203.0.113.77", prevHash: "sha384:h10", hash: "sha384:h11" },
          { seq: 12, ts: iso(NOW - 3_600_000), action: "role-change", outcome: "ok", actorEmail: EMAIL, prevHash: "sha384:h11", hash: "sha384:h12" },
        ];
        return url.searchParams.get("action") !== null ? { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW) } : { events, headSeq: 12, headHash: "sha384:h12", exportedAt: iso(NOW) };
      };
    },
  },
  {
    id: "ingest-grant-drops-its-holder",
    what: "defect 16's grant: the pack reports whether it expired and must never say WHO holds it",
    mustNotAppear: [EMAIL, BEARER],
    witness: ["expiryUnreadable"],
    mutate: (w: World): void => {
      const grant = { grantedAt: iso(NOW - 100_000), expiresAt: "not-a-date", grantedBy: EMAIL, clientId: BEARER, secret: BEARER, pulls: [{ at: iso(NOW - 1000) }] };
      w.routes["/ingest-credential"] = (): unknown => ({ grant });
    },
  },
  {
    id: "dest-probe-subject-is-a-label-and-carries-no-secret",
    what: "the destination subjects, planted with a secret access key beside the label",
    mustNotAppear: [BEARER, EMAIL],
    witness: ["dest-probe-faults"],
    mutate: (w: World): void => {
      w.routes["/sched-diag"] = {
        capTruncations: { "dest-probe-faults": { count: 3, lastAt: iso(NOW) } },
        capTruncationSubjects: { "dest-probe-faults": { ids: ["offsite-archive"], incomplete: true, secretAccessKey: BEARER, grantedBy: EMAIL } },
      };
    },
  },
  // G346, another pass. AN ACCESSIBILITY CAPTURE CAN CARRY THE CONTENTS OF A SCREEN -- an element's
  // accessible name, its label, the value an operator has typed into it -- so the new focus-landing row is put
  // through this suite rather than declared safe because its design says it is value-free. The plant is every
  // field such a capture would plausibly grow: the element's id, its accessible name, its label, and the value.
  {
    id: "focus-landing-carries-no-part-of-the-screen-it-watched",
    what: "G346's new accessibility row, planted with the accessible name, the label and the typed value of the control it watched",
    mustNotAppear: [EMAIL, BEARER, BLOB, ADDRESSY_DP],
    witness: ["dropped-detached", "focus-landing"],
    mutate: (): void => {},
    clientDiag: (): unknown => ({
      records: [
        {
          kind: "focus-landing",
          screen: "keys",
          focusOutcome: "dropped-detached",
          count: 1,
          firstMs: 10,
          lastMs: 20,
          // Everything a capture that read the DOM would have to hand, and none of it is a projected field.
          elementId: ADDRESSY_DP,
          accessibleName: EMAIL,
          ariaLabel: EMAIL,
          label: BEARER,
          value: BEARER,
          textContent: BLOB,
          selector: `#${ADDRESSY_DP}`,
          activeElementOuterHTML: `<input value="${BEARER}">`,
        },
      ],
    }),
  },
  {
    id: "a-focus-outcome-carrying-customer-text-is-failed-closed-rather-than-truncated",
    what: "the closed union is the defence: a drifted focusOutcome must drop the WHOLE row, not ride in shortened",
    mustNotAppear: [EMAIL, BEARER],
    // The healthy row is the witness: it proves the ring reached the projector at all, so "the poisoned value
    // is absent" cannot be satisfied by a pack that simply carried no focus rows.
    witness: ["focus-landing", "honoured"],
    mutate: (): void => {},
    clientDiag: (): unknown => ({
      records: [
        { kind: "focus-landing", screen: "notifications", focusOutcome: "honoured", count: 1, firstMs: 1, lastMs: 2 },
        { kind: "focus-landing", screen: "keys", focusOutcome: `dropped-detached ${EMAIL}`, count: 1, firstMs: 3, lastMs: 4 },
        { kind: "focus-landing", screen: BEARER, focusOutcome: "dropped-detached", count: 1, firstMs: 5, lastMs: 6 },
      ],
    }),
    also: (pack: Dict): string[] => {
      const cd = (typeof pack.clientDiagnostics === "object" && pack.clientDiagnostics !== null ? pack.clientDiagnostics : {}) as Dict;
      const rows = (Array.isArray(cd.records) ? cd.records : []) as Dict[];
      const focus = rows.filter((r) => r.kind === "focus-landing");
      // Exactly ONE row survives. Two would mean a drifted value was admitted; zero would mean the witness
      // check above passed on some other section's text, so the count is asserted rather than the absence.
      return focus.length === 1 ? [] : [`${focus.length} focus-landing row(s) survived, want exactly 1 (the two poisoned rows must fail CLOSED)`];
    },
  },
];

async function main(): Promise<void> {
  const keys = await makeKeys();
  let leaks = 0;
  let cannotCheck = 0;

  // THE INSTRUMENT'S OWN CONTROL, run first: a value planted at a field the pack IS documented to carry must
  // be FOUND by this searcher. Without it a broken search reports every case clean and the run reads as proof.
  const controlPack = await buildPack((w: World): void => {
    w.routes["/downpipes"] = [{ config: { id: "canary-in-the-search", name: "x", enabled: true, cadenceSeconds: 3600, source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "n", include: [], exclude: [] } }, lastRunId: null, inFlight: false }];
  }, keys);
  if (!JSON.stringify(controlPack).includes("canary-in-the-search")) {
    console.log("CONTROL FAILED: a value the pack is documented to carry was NOT found by this searcher, so every clean verdict below would be manufactured.");
    process.exit(2);
  }
  console.log("control: a planted downpipe id IS found by the searcher. The search works.\n");

  for (const c of CASES) {
    const pack = await buildPack(c.mutate, keys, c.clientDiag?.());
    const bytes = JSON.stringify(pack);
    const missingWitness = c.witness.filter((wv) => !bytes.includes(wv));
    const found = c.mustNotAppear.filter((v) => bytes.includes(v));
    if (missingWitness.length > 0) {
      cannotCheck++;
      console.log(`  CANNOT-CHECK ${c.id}`);
      console.log(`      the plant did not reach the projector: witness absent ${JSON.stringify(missingWitness)}`);
      continue;
    }
    const alsoFailures = c.also?.(pack) ?? [];
    if (alsoFailures.length > 0) {
      leaks++;
      console.log(`  FAIL ${c.id}`);
      for (const a of alsoFailures) console.log(`      ${a}`);
      continue;
    }
    if (found.length > 0) {
      leaks++;
      console.log(`  LEAK ${c.id}`);
      for (const v of found) console.log(`      the pack carries: ${JSON.stringify(v.slice(0, 80))}`);
    } else {
      console.log(`  clean ${c.id} -- ${c.what}`);
    }
  }

  console.log(`\n${CASES.length} adversarial redaction cases; ${leaks} leak(s); ${cannotCheck} could-not-check.`);
  if (CASES.length === 0) {
    console.log("REFUSE: a sweep that visits nothing must fail rather than pass.");
    process.exit(2);
  }
  process.exit(leaks === 0 && cannotCheck === 0 ? 0 : 1);
}

await main();
