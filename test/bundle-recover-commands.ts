// Drives every command the SIGNED, IN-ARCHIVE RECOVER.md prints, reading the bytes out of a real
// engine-written archive rather than out of the string literal in src/format/bundle.ts.
//
// WHY THIS EXISTS. RECOVER.md is the highest-stakes published command surface in the product. It
// travels inside every archive the engine writes, it is covered by the signed SHA384SUMS, and it is
// what an operator reads at the moment they have nothing else: no console, no engine, and possibly
// no vendor. Nothing had ever driven it, and it had two defects at once.
//
//   1. The custody example printed TWO --share files:
//
//        downpipe restore --archive <dir> --run <runId> --signer signer.pub --out <dir> \
//          --share share-1.txt --share share-3.txt --envelope wrapped-identity.txt
//
//      The reader needs one share per custodian in the quorum, read from the labelled shares
//      themselves (downpipe/internal/custody/recombine.go, "need %d distinct shares to recombine,
//      got %d"). Against a 3-of-N split that line exits 6, ExitUsage: the operator is told to fix a
//      command line they copied out of their own archive, and there is nothing for them to fix.
//
//   2. The headline restore line omitted --apply. `restore` plans by default and writes nothing, so
//      the only instruction a customer had mid-disaster exited 0, printed "dry run: nothing was
//      written", and produced no data. An exit-code-only assertion cannot see that, which is why the
//      no-share case below also requires the --out directory to be non-empty afterwards.
//
// A fix committed earlier the same day added a flag and never re-drove the line it had just written,
// and the line still exited 6. So the requirement is not "read the string": it is RUN IT.
//
// The offline Go tool carries its own copy of this text for its selftest (separate repo; the bundle
// content is not normative because each archive verifies against the SHA384SUMS written in the same
// run) and drives it with cmd/downpipe/bundle_recover_commands_test.go. The two copies are held in
// step by the claim assertions in test/validate-format-prims.ts and the matching ones there, not by
// byte equality.
//
// Run: scripts/e2e-writer-reader.sh invokes this after the engine writer has sealed an archive and
// the Go reader has been built. It needs all six inputs below and FAILS, never skips, without them:
// a recovery instruction nobody ran is the defect this file exists to close.
//
//   ARCHIVE      the engine-written archive directory (holds _RECOVERY/<version>/RECOVER.md)
//   READER_BIN   the built Go reader binary
//   RUN_ID       the run id the archive was sealed under
//   IDENTITY     the break-glass identity file the archive is sealed to
//   SIGNER       the operator signer public-key file
//   CUSTODY_DIR  a directory holding share-1.txt, share-2.txt, share-3.txt and wrapped-identity.txt

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LABEL_SIGNER_PUBLIC, parseKeyFile } from "../src/crypto/keys.ts";
import { BUNDLE_PREFIX } from "../src/format/bundle.ts";
import { signerFingerprint } from "../src/format/writer-root.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

// The reader's own usage exit code (downpipe/internal/format/errors.go: ExitUsage = 6). A published
// command that lands here is the specific defect this gate is about.
const EXIT_USAGE = 6;

let failures = 0;
function ok(name: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) {
    if (detail !== undefined) console.log(`       ${detail.replace(/\n/g, "\n       ")}`);
    failures++;
  }
}

/** die reports a precondition this gate cannot run without, and exits non-zero rather than skipping. */
function die(msg: string): never {
  console.error(`bundle-recover-commands: ${msg}`);
  process.exit(2);
}

function envPath(name: string, mustExist = true): string {
  const v = process.env[name];
  if (v === undefined || v === "") die(`${name} is not set; this gate cannot run and will not pass by skipping`);
  if (mustExist && !existsSync(v)) die(`${name}="${v}" does not exist`);
  return v;
}

const ARCHIVE = envPath("ARCHIVE");
const READER_BIN = envPath("READER_BIN");
const IDENTITY = envPath("IDENTITY");
const SIGNER = envPath("SIGNER");
const CUSTODY_DIR = envPath("CUSTODY_DIR");
const RUN_ID = process.env.RUN_ID ?? "";
if (RUN_ID === "") die("RUN_ID is not set; this gate cannot run and will not pass by skipping");

/**
 * recoverMdCommands pulls each indented `downpipe ...` command out of the document, rejoining
 * backslash continuations and collapsing runs of whitespace. It mirrors the Go extractor so the two
 * repos' gates read the same document the same way.
 *
 * @param text - the RECOVER.md content as an operator reads it.
 * @returns one entry per command, each a single whitespace-normalised line.
 */
function recoverMdCommands(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (cur !== "") {
      cur += ` ${trimmed.replace(/\\$/, "")}`;
      if (!trimmed.endsWith("\\")) {
        out.push(cur.split(/\s+/).filter((t) => t !== "").join(" "));
        cur = "";
      }
      continue;
    }
    if (!trimmed.startsWith("downpipe ")) continue;
    if (trimmed.endsWith("\\")) {
      cur = trimmed.replace(/\\$/, "");
      continue;
    }
    out.push(trimmed.split(/\s+/).filter((t) => t !== "").join(" "));
  }
  if (cur !== "") {
    ok("a continued command in the bundled RECOVER.md has a following line", false, `unterminated continuation: ${cur}`);
  }
  return out;
}

// The bytes come from the ARCHIVE, not from the module that generated it: what is driven is what an
// archive actually carries.
const recoverPath = join(ARCHIVE, ...`${BUNDLE_PREFIX}RECOVER.md`.split("/"));
if (!existsSync(recoverPath)) die(`the archive carries no bundled RECOVER.md at ${recoverPath}, which is the file this gate exists to drive`);
const recoverMd = readFileSync(recoverPath, "utf8");

console.log(`bundle-recover-commands: driving ${recoverPath}`);

const cmds = recoverMdCommands(recoverMd);

// Two floors, both of which fail rather than pass vacuously. A document that lost the custody
// paragraph would otherwise sail through with one trivially-passing line, and losing that paragraph
// is the precise drift the offline tool's matching gate was built after.
ok("the bundled RECOVER.md prints at least one command", cmds.length > 0, "no `downpipe ...` line was found, so this gate proved nothing");
const custodyCmds = cmds.filter((c) => c.includes("--share"));
const plainCmds = cmds.filter((c) => !c.includes("--share"));
ok("the bundled RECOVER.md still prints the single-file break-glass route", plainCmds.length > 0);
ok("the bundled RECOVER.md still prints the M-of-N custody route", custodyCmds.length > 0);

// Substitutions by the literal token the document uses, plus the two <dir> placeholders resolved by
// the flag they follow. An unknown <placeholder> is a failure, not a skip: an undrivable line inside
// a signed archive is the worst place in the product to leave a command nobody has run.
// <signerFingerprint> is the value the printed recovery sheet carries, computed from the kit's signer.pub
// in the sheet's own construction. With it the reader uses the archive's BUNDLED signer.pub, so driving
// that line proves the engine wrote the copy and that it matches the signer that sealed the run.
const signerKey = parseKeyFile(readFileSync(SIGNER, "utf8"), LABEL_SIGNER_PUBLIC);
const SIGNER_FINGERPRINT = await signerFingerprint({ ed: signerKey.subarray(0, 32), mldsa: signerKey.subarray(32) });

const subs = new Map<string, string>([
  ["<runId>", RUN_ID],
  ["<signerFingerprint>", SIGNER_FINGERPRINT],
  ["identity.key", IDENTITY],
  ["signer.pub", SIGNER],
  ["share-1.txt", join(CUSTODY_DIR, "share-1.txt")],
  ["share-2.txt", join(CUSTODY_DIR, "share-2.txt")],
  ["share-3.txt", join(CUSTODY_DIR, "share-3.txt")],
  ["wrapped-identity.txt", join(CUSTODY_DIR, "wrapped-identity.txt")],
]);
for (const [tok, path] of subs) {
  if (tok === "<runId>" || tok === "<signerFingerprint>") continue;
  if (!existsSync(path)) die(`the fixture for ${tok} is missing at ${path}`);
}

/**
 * materialise turns one printed command into the reader argv this gate runs, with every placeholder
 * resolved. An unknown <placeholder> is recorded as a failure and yields null.
 *
 * @param c - one whitespace-normalised command from recoverMdCommands.
 * @param archive - the archive directory to substitute for `--archive <dir>`; a planted-fault copy
 *   in the salvage checks, the sealed archive otherwise.
 * @returns the argv (without the binary) and the fresh --out directory, or null when undrivable.
 */
function materialise(c: string, archive: string = ARCHIVE): { args: string[]; outDir: string } | null {
  const fields = c.split(" ");
  const args: string[] = [];
  let outDir = "";
  for (let i = 1; i < fields.length; i++) {
    const tok = fields[i] as string;
    const prev = fields[i - 1];
    if (tok === "<dir>" && prev === "--out") {
      outDir = join(mkdtempSync(join(tmpdir(), "recover-md-")), "out");
      args.push(outDir);
      continue;
    }
    if (tok === "<dir>" && prev === "--archive") {
      args.push(archive);
      continue;
    }
    const sub = subs.get(tok);
    if (sub !== undefined) {
      args.push(sub);
      continue;
    }
    if (tok.startsWith("<")) {
      ok(`every placeholder in "${c}" has a value this gate can supply`, false, `no value for ${tok}; add one rather than leaving the line undriven`);
      return null;
    }
    args.push(tok);
  }
  return { args, outDir };
}

for (const c of cmds) {
  const m = materialise(c);
  if (m === null) continue;
  const { args, outDir } = m;

  const r = spawnSync(READER_BIN, args, { encoding: "utf8" });
  if (r.error) die(`could not run the reader binary ${READER_BIN}: ${String(r.error)}`);
  const code = r.status ?? -1;
  const detail = `materialised as: ${READER_BIN} ${args.join(" ")}\nexit ${code}\n${(r.stderr ?? "").trim()}`;

  // Asserted for EVERY line: the command line itself is accepted. ExitUsage means the operator is
  // told to fix a command they copied out of their own archive.
  ok(`"${c}" is not rejected as a usage error`, code !== EXIT_USAGE, detail);

  if (c.includes("--share")) {
    // The custody fixture recombines a DIFFERENT identity from the one this archive is sealed to, so
    // this line cannot exit 0 here. Only the usage assertion above is meaningful for it.
    continue;
  }

  // The single-file break-glass line names no custody artefact and must work outright.
  ok(`"${c}" exits 0`, code === 0, detail);

  // AND must actually produce data. restore plans by default, so a line without --apply exits 0
  // having written nothing, and an exit-code-only assertion calls that a pass. It is not one: it is
  // a customer following their only instruction mid-disaster and getting no data back.
  if (outDir !== "") {
    const wrote = existsSync(outDir) && readdirSync(outDir).length > 0;
    ok(`"${c}" actually writes the recovered records to --out`, wrote, `${outDir} is absent or empty. restore is a dry run unless --apply is given.\n${detail}`);
  }
}

// THE SALVAGE FLAG IN THE PROSE. RECOVER.md tells a recoverer they can add --allow-unverified to a
// restore when a signature check fails. That sentence names a flag but prints no command of its own, so
// the loop above never runs it. So when the prose names it, the first single-file line is driven again
// with the flag added, first against the valid archive and then against copies with planted faults.
//
// The valid run proves only that the reader defines the flag. The claims the prose makes are about a
// FAILED signature, so each one is driven against a copy whose root signature has one flipped byte:
//   - without the flag the printed line exits 2 and writes nothing;
//   - with the flag it writes the records and still exits 2 ("restored but unverified");
//   - with --receipt added, the receipt says mode allow-unverified and a signature result that is not valid;
//   - the flag skips only the signature class: a missing shard manifest still stops the restore with
//     nothing written, and a missing segment is reported as a failed record while the others are written.
// A reader that parsed the flag but still refused on a bad root signature fails the second check.
if (/--allow-unverified(?![-\w])/.test(recoverMd)) {
  const base = plainCmds[0];
  ok("the prose's --allow-unverified has a single-file restore line to extend", base !== undefined);
  if (base !== undefined) {
    const drive = (label: string, cmd: string, archive: string): { code: number; outDir: string; wrote: boolean; stderr: string; detail: string } | null => {
      const m = materialise(cmd, archive);
      if (m === null) {
        ok(`${label}: the line can be materialised`, false);
        return null;
      }
      const r = spawnSync(READER_BIN, m.args, { encoding: "utf8" });
      if (r.error) die(`could not run the reader binary ${READER_BIN}: ${String(r.error)}`);
      const code = r.status ?? -1;
      const stderr = (r.stderr ?? "").trim();
      const wrote = m.outDir !== "" && existsSync(m.outDir) && readdirSync(m.outDir).length > 0;
      return { code, outDir: m.outDir, wrote, stderr, detail: `materialised as: ${READER_BIN} ${m.args.join(" ")}\nexit ${code}\n${stderr}` };
    };
    const flagged = `${base} --allow-unverified`;

    const valid = drive("valid archive", flagged, ARCHIVE);
    if (valid !== null) {
      ok("restore accepts the --allow-unverified flag RECOVER.md names", valid.code !== EXIT_USAGE, valid.detail);
      ok("restore with --allow-unverified exits 0 on a valid archive", valid.code === 0, valid.detail);
      ok("restore with --allow-unverified writes the recovered records to --out on a valid archive", valid.wrote, valid.detail);
    }

    // plantedCopy copies the archive and applies one fault to the copy, so every case starts from the
    // same sealed bytes and the source archive stays valid for the rest of scripts/e2e-writer-reader.sh.
    const plantedCopy = (name: string, plant: (dir: string) => void): string => {
      const dir = join(mkdtempSync(join(tmpdir(), `recover-md-${name}-`)), "archive");
      cpSync(ARCHIVE, dir, { recursive: true });
      plant(dir);
      return dir;
    };
    const flipFirstByte = (file: string): void => {
      if (!existsSync(file)) die(`the fault target ${file} is missing, so the salvage claim cannot be driven`);
      const b = readFileSync(file);
      b[0] = (b[0] as number) ^ 1;
      writeFileSync(file, b);
    };
    const badSig = (dir: string): void => flipFirstByte(join(dir, "run", RUN_ID, "root.manifest.json.sig"));

    const sigArchive = plantedCopy("badsig", badSig);
    const refused = drive("bad signature, no flag", base, sigArchive);
    if (refused !== null) {
      ok("CONTROL: the printed line refuses a bad root signature with exit 2", refused.code === 2, refused.detail);
      ok("CONTROL: the printed line writes nothing when the root signature is bad", !refused.wrote, refused.detail);
    }
    const salvaged = drive("bad signature, --allow-unverified", flagged, sigArchive);
    if (salvaged !== null) {
      ok("with --allow-unverified a bad root signature still yields the records under --out", salvaged.wrote, salvaged.detail);
      ok("with --allow-unverified the restore then exits 2, as the prose says", salvaged.code === 2, salvaged.detail);
      ok('with --allow-unverified the reader says "restored but unverified"', salvaged.stderr.includes("restored but unverified"), salvaged.detail);
    }
    const receiptPath = join(mkdtempSync(join(tmpdir(), "recover-md-receipt-")), "receipt.json");
    const receipted = drive("bad signature, --allow-unverified --receipt", `${flagged} --receipt ${receiptPath}`, sigArchive);
    if (receipted !== null) {
      let receipt: { mode?: unknown; signatureResult?: unknown } = {};
      try {
        receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as typeof receipt;
      } catch (e) {
        ok("the --receipt file is written and parses", false, `${String(e)}\n${receipted.detail}`);
      }
      ok('the receipt records mode "allow-unverified"', receipt.mode === "allow-unverified", `receipt mode: ${String(receipt.mode)}`);
      ok("the receipt records a signature result that is not valid", typeof receipt.signatureResult === "string" && receipt.signatureResult !== "valid", `receipt signatureResult: ${String(receipt.signatureResult)}`);
    }

    const noShard = plantedCopy("noshard", (dir) => {
      badSig(dir);
      const mdir = join(dir, "run", RUN_ID, "manifest");
      const shards = existsSync(mdir) ? readdirSync(mdir) : [];
      if (shards.length === 0) die(`no shard manifest under ${mdir} to remove`);
      rmSync(join(mdir, shards[0] as string));
    });
    const stopped = drive("missing shard manifest, --allow-unverified", flagged, noShard);
    if (stopped !== null) {
      ok("with --allow-unverified a missing shard manifest still stops the restore (non-zero exit)", stopped.code !== 0, stopped.detail);
      ok("with --allow-unverified a missing shard manifest still writes nothing", !stopped.wrote, stopped.detail);
    }

    const noSeg = plantedCopy("noseg", (dir) => {
      badSig(dir);
      const segRoot = join(dir, "seg");
      const bucket = existsSync(segRoot) ? readdirSync(segRoot)[0] : undefined;
      const seg = bucket === undefined ? undefined : readdirSync(join(segRoot, bucket))[0];
      if (bucket === undefined || seg === undefined) die(`no segment under ${segRoot} to remove`);
      rmSync(join(segRoot, bucket, seg));
    });
    const partial = drive("missing segment, --allow-unverified", flagged, noSeg);
    if (partial !== null) {
      ok("with --allow-unverified a missing segment is reported as a failed record", /\b[1-9]\d* failed\b/.test(partial.stderr), partial.detail);
      ok("with --allow-unverified the records whose segments are present are still written", partial.wrote, partial.detail);
      ok("with --allow-unverified a missing segment does not exit 0", partial.code !== 0, partial.detail);
    }
  }
}

console.log(failures === 0 ? "\nBUNDLE RECOVER COMMANDS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
