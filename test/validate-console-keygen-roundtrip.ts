// RG1: a key minted by the CONSOLE opens a run sealed by the ENGINE.
//
//   node test/validate-console-keygen-roundtrip.ts        (cross-repo: needs ../console)
//
// This is the seam the whole recovery promise rests on, and until this file it was proven nowhere. Both
// halves are well tested SEPARATELY: the console's ceremony has its own suite, the engine's seal and reader
// have theirs. But every one of those proofs restates the other side's byte layout by hand. A one-sided
// change to the concatenation order in either place would keep both suites green and fail only at a
// customer's real recovery, which is the one moment when there is nothing left to fall back on.
//
// So NOTHING here restates a layout. The console's own runKeyCeremony produces the material, the engine's
// own loadRecipientPublic and loadIdentity parse it, and the engine's own buildArchive and openRun seal and
// open the run. Both sides are only ever asked to do their own job, exactly as production asks them.
//
// The layout at stake, stated once for the reader and asserted rather than assumed below:
//   recipientPublicB64 = b64url( x25519 public(32) || ML-KEM-1024 encapsulation key(1568) )  = 1600 bytes
//   identityB64        = b64url( x25519 scalar(32) || ML-KEM seed(64) )                     = 96 bytes
//
// If the console ever emitted those halves in the other order, loadRecipientPublic would hand the seal an
// x25519 point that is really the first 32 bytes of an ML-KEM key. The seal would SUCCEED (both are opaque
// byte strings to it), the archive would look perfectly healthy, and only the decapsulation at recovery
// would fail. That is why the assertion that matters here is a byte-exact restore, not a successful seal.

import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildArchive, type WriteRecord } from "../src/format/writer.ts";
import { openRun, readRunCapsule } from "../src/format/reader.ts";
import { loadRecipientPublic, loadIdentity, loadSigner, verifierFrom } from "../src/keys-env.ts";
import type { ObjectStore } from "../src/format/types.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

// The console's OWN ceremony, imported across the repo boundary the same way validate-licence-compat.ts
// imports the engine verifier into a control-plane test.
//
// Resolved at RUNTIME rather than as a literal path, using the same candidate list as
// validate-ramp-settle-console-client.ts. A literal "../../console" is correct only from a normal
// checkout: from a git worktree (engine/.worktrees/<name>/test) it resolves to
// engine/.worktrees/console and does not exist, so this file broke `npm run typecheck:test` for
// anyone working the documented worktree flow while passing in CI. It FAILS rather than skips when
// the console cannot be found, because a gate that opts out when it cannot check reads as a pass.
const CONSOLE_ROOT = [
  process.env["DOWNPIPES_CONSOLE"],
  resolve(dirname(fileURLToPath(import.meta.url)), "../../console"),
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../console"),
  // Four levels up is the worktree case: engine/.worktrees/<name>/test -> the workspace root.
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../../console"),
].find((c): c is string => typeof c === "string" && existsSync(resolve(c, "src/keygen.ts")));
if (CONSOLE_ROOT === undefined) {
  console.error("FAIL: cannot locate the console, so the real key ceremony cannot be driven.");
  console.error("  Set DOWNPIPES_CONSOLE=/path/to/console, or check the console out beside this repo.");
  // Declared, not silent. Refusing here is CORRECT (this suite is worthless without the real console), but
  // the refusal has to be a declared verdict like any other, or the completion guard cannot tell a loud
  // refusal apart from a run that skipped its own tally. require:true keeps the exit non-zero.
  verdictSkipped("cannot locate the console, so the real key ceremony cannot be driven", { require: true });
  process.exit(1);
}

// WHICH CONSOLE TREE, and REFUSE when it is not the sibling's main.
//
// This file already refuses on an ABSENT console, in as many words: a gate that opts out when it cannot
// check reads as a pass. A STALE console is the same argument one step weaker, and the weaker step is the
// one that is invisible. The claim being made is that the engine's reader can open what the console's key
// ceremony writes, and a reader acts on a green here by believing the shipping pair interoperates. Driven
// against a console the workspace left behind, that green is about a ceremony nobody ships, and the run that
// would have caught a real break costs the same as the run that did not.
//
// REFUSE rather than say so, because unlike an interop DEMO this is a gating claim about the current pair,
// and the older ceremony's success carries no information about the one that ships.
reportSiblings([{ name: "console", path: CONSOLE_ROOT }], { gate: "console-keygen-roundtrip" });
requireFreshSiblings([{ name: "console", path: CONSOLE_ROOT }], {
  gate: "console-keygen-roundtrip",
  consequence: "the round trip would prove interoperability with a key ceremony the console no longer ships",
  exit: (code: number) => {
    verdictSkipped(`REFUSED, exit ${code}: the console checkout beside this engine is behind its own origin/main, so nothing was concluded`);
    process.exit(code);
  },
});

const { runKeyCeremony } = await import(resolve(CONSOLE_ROOT, "src/keygen.ts"));

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A read-only store over the map buildArchive returns. An explicit field rather than a constructor
// parameter property: Node runs these validators with strip-only type stripping, which rejects one.
class MapStore implements ObjectStore {
  readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}


async function main(): Promise<void> {
  console.log("(1) the console's ceremony produces material the ENGINE's parsers accept");
  {
    const ceremony = await runKeyCeremony({ operational: true });
    const bg = ceremony.breakGlass;

    // Parsed by the ENGINE's own loader. A length or ordering change on the console side lands here as a
    // thrown error rather than as a mysterious recovery failure months later.
    let pub: ReturnType<typeof loadRecipientPublic> | null = null;
    let parseErr = "";
    try {
      pub = loadRecipientPublic(bg.recipientPublicB64);
    } catch (e) {
      parseErr = (e as Error).message;
    }
    ok(`(1a) the engine parses the console's recipient public key${parseErr === "" ? "" : ` (${parseErr})`}`, pub !== null);
    ok("(1b) it splits into a 32-byte x25519 public", pub !== null && pub.x25519.length === 32);
    ok("(1c) and a 1568-byte ML-KEM encapsulation key", pub !== null && pub.mlkemEk.length === 1568);

    let priv: ReturnType<typeof loadIdentity> | null = null;
    let privErr = "";
    try {
      priv = loadIdentity(bg.identityB64);
    } catch (e) {
      privErr = (e as Error).message;
    }
    ok(`(1d) the engine parses the console's offline identity${privErr === "" ? "" : ` (${privErr})`}`, priv !== null);

    // The fingerprint the console prints on the recovery sheet must be the one the engine records, or an
    // operator matching them by eye during an incident is told the wrong key opens the archive.
    ok("(1e) the console's own fingerprint is the dpr1 form the engine records", /^dpr1:[0-9a-f]{96}$/.test(bg.fingerprint));

    // The operational key is a second, DISTINCT recipient, not a copy.
    ok("(1f) an operational ceremony yields a distinct second recipient", ceremony.operational !== null && ceremony.operational.recipientPublicB64 !== bg.recipientPublicB64);
    ok("(1g) with its own distinct identity", ceremony.operational !== null && ceremony.operational.identityB64 !== bg.identityB64);
  }

  console.log("\n(2) THE ROUND TRIP: the engine seals to the console's key, and that key opens it");
  {
    const ceremony = await runKeyCeremony({ operational: false });
    const bg = ceremony.breakGlass;

    // The signer comes from the console's ceremony too, so even the signing half crosses the boundary
    // through both sides' own encoders rather than a hand-built pair.
    const signerPriv = ceremony.signer.privateB64;
    const signer = await loadSigner(signerPriv);

    const records: WriteRecord[] = [
      { sourceType: "kv", name: "alpha", value: new TextEncoder().encode("the quick brown fox") },
      { sourceType: "kv", name: "beta/nested", value: rand(4096) },
      { sourceType: "kv", name: "gamma", value: new Uint8Array(0) },
    ];
    const runId = "01J0000000000000000000000A";

    const archive = await buildArchive({
      downpipeId: "dp_rg1", downpipeName: "rg1", cadence: "0 * * * *", runId, master: rand(32),
      recipients: [{ role: "break-glass", pub: loadRecipientPublic(bg.recipientPublicB64) }],
      signer, records,
      windowStart: "2026-07-26T00:00:00.000Z", windowEnd: "2026-07-26T00:00:01.000Z", createdAt: "2026-07-26T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    ok("(2a) the engine sealed a run to the console's recipient key", archive.size > 0);

    const store = new MapStore(archive);
    const verifier = verifierFrom(signer);

    // The capsule is addressed to the console's fingerprint. This is the keyless check an operator's own
    // tooling makes ("does this archive name my key?"), so a fingerprint drift shows up here.
    const capsule = await readRunCapsule(store, runId, verifier);
    ok("(2b) the run's master capsule names the console's fingerprint", capsule.masterCapsule.some((w) => w.fingerprint === bg.fingerprint));

    // And now the assertion the whole file exists for. The seal would succeed even with the halves
    // transposed; only the decapsulation proves the layouts agree.
    const identity = loadIdentity(bg.identityB64);
    let run: Awaited<ReturnType<typeof openRun>> | null = null;
    let openErr = "";
    try {
      run = await openRun(store, runId, identity, verifier);
    } catch (e) {
      openErr = (e as Error).message;
    }
    ok(`(2c) the console's OFFLINE IDENTITY opens the engine-sealed run${openErr === "" ? "" : ` (${openErr})`}`, run !== null);

    if (run !== null) {
      // Byte-exact, every record. A partial or corrupted decrypt is the failure mode a "did it open?"
      // check would miss.
      // The reader exposes the sealed records as `run.records` (ShardRecord entries) and decrypts one
      // through restoreRecord. Names are MAC'd on the manifest, so a record is matched by decrypting it
      // and comparing plaintext, in sealed order, which is the order buildArchive wrote them.
      let allExact = run.records.length === records.length;
      for (let i = 0; i < run.records.length && allExact; i++) {
        const want = records[i]?.value ?? new Uint8Array();
        const got = await run.restoreRecord(run.records[i]!);
        if (got.length !== want.length || !got.every((b, j) => b === want[j])) allExact = false;
      }
      ok("(2d) every record restores BYTE-EXACT, including the empty one", allExact);
      ok("(2e) the run reports exactly the records it sealed", run.records.length === records.length);
    }
  }

  console.log("\n(3) the WRONG console key does not open it, so (2c) is not passing by accident");
  {
    // A refuter. If openRun succeeded for any identity, (2c) would prove nothing at all.
    const sealed = await runKeyCeremony({ operational: false });
    const other = await runKeyCeremony({ operational: false });
    const signer = await loadSigner(sealed.signer.privateB64);
    const runId = "01J0000000000000000000000B";
    const archive = await buildArchive({
      downpipeId: "dp_rg1r", downpipeName: "rg1-refuter", cadence: "0 * * * *", runId, master: rand(32),
      recipients: [{ role: "break-glass", pub: loadRecipientPublic(sealed.breakGlass.recipientPublicB64) }],
      signer, records: [{ sourceType: "kv", name: "only", value: new TextEncoder().encode("secret") }],
      windowStart: "2026-07-26T00:00:00.000Z", windowEnd: "2026-07-26T00:00:01.000Z", createdAt: "2026-07-26T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const store = new MapStore(archive);
    const verifier = verifierFrom(signer);
    let refused = false;
    try {
      await openRun(store, runId, loadIdentity(other.breakGlass.identityB64), verifier);
    } catch {
      refused = true;
    }
    ok("(3a) a DIFFERENT console-minted identity is refused", refused);
    // And the right one still works on the same archive, so (3a) is not refusing everything.
    let opened = false;
    try {
      await openRun(store, runId, loadIdentity(sealed.breakGlass.identityB64), verifier);
      opened = true;
    } catch {
      opened = false;
    }
    ok("(3b) while the sealing identity still opens it (the positive control)", opened);
  }

  console.log(`\n${failures === 0 ? "CONSOLE-KEYGEN ROUND TRIP OK: a console-minted break-glass identity opens an engine-sealed run byte-exact, with neither side restating the other's byte layout" : `${failures} FAILURE(S)`}`);
  verdictReached(failures);
  if (failures > 0) (globalThis as unknown as { process: { exit(code: number): never } }).process.exit(1);
}

main().catch((e) => {
  console.error(e);
  (globalThis as unknown as { process: { exit(code: number): never } }).process.exit(1);
});
