// Drives every command the SIGNED, IN-ARCHIVE RECOVER.md prints, reading the bytes out of a real
// engine-written archive rather than out of the string literal in src/format/bundle.ts.
//
// WHY THIS EXISTS. RECOVER.md is the highest-stakes published command surface in the product. It
// travels inside every archive the engine writes, it is covered by the signed SHA384SUMS, and it is
// what an operator reads at the moment they have nothing else: no console, no engine, and possibly
// no vendor. Driving the commands catches two failure classes an exit-code-only check would miss:
//
//   1. The custody example must print ONE --share file per custodian in the quorum, read from the
//      labelled shares themselves (downpipe/internal/custody/recombine.go, "need %d distinct shares
//      to recombine, got %d"). Against a 3-of-N split, a line naming the wrong count of shares exits
//      6, ExitUsage: the operator is told to fix a command line they copied out of their own archive,
//      and there is nothing for them to fix.
//
//   2. The headline restore line must carry --apply. `restore` plans by default and writes nothing, so
//      a line without it exits 0, prints "dry run: nothing was written", and produces no data. An
//      exit-code-only assertion cannot see that, which is why the no-share case below also requires
//      the --out directory to be non-empty afterwards.
//
// So the requirement is not "read the string": it is RUN IT.
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
import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { BUNDLE_PREFIX } from "../src/format/bundle.ts";

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
const subs = new Map<string, string>([
  ["<runId>", RUN_ID],
  ["identity.key", IDENTITY],
  ["signer.pub", SIGNER],
  ["share-1.txt", join(CUSTODY_DIR, "share-1.txt")],
  ["share-2.txt", join(CUSTODY_DIR, "share-2.txt")],
  ["share-3.txt", join(CUSTODY_DIR, "share-3.txt")],
  ["wrapped-identity.txt", join(CUSTODY_DIR, "wrapped-identity.txt")],
]);
for (const [tok, path] of subs) {
  if (tok === "<runId>") continue;
  if (!existsSync(path)) die(`the fixture for ${tok} is missing at ${path}`);
}

for (const c of cmds) {
  const fields = c.split(" ");
  const args: string[] = [];
  let outDir = "";
  let usable = true;
  for (let i = 1; i < fields.length; i++) {
    const tok = fields[i] as string;
    const prev = fields[i - 1];
    if (tok === "<dir>" && prev === "--out") {
      outDir = join(mkdtempSync(join(tmpdir(), "recover-md-")), "out");
      args.push(outDir);
      continue;
    }
    if (tok === "<dir>" && prev === "--archive") {
      args.push(ARCHIVE);
      continue;
    }
    const sub = subs.get(tok);
    if (sub !== undefined) {
      args.push(sub);
      continue;
    }
    if (tok.startsWith("<")) {
      ok(`every placeholder in "${c}" has a value this gate can supply`, false, `no value for ${tok}; add one rather than leaving the line undriven`);
      usable = false;
      break;
    }
    args.push(tok);
  }
  if (!usable) continue;

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

console.log(failures === 0 ? "\nBUNDLE RECOVER COMMANDS PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
