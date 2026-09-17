// Validates the two custody postures the TERMINAL key ceremony can now produce, and the configuration wrap
// key it now generates in both of them, by RUNNING the real scripts/generate-keys.ts into a throwaway
// directory rather than reading it.
//
// WHAT WAS WRONG. The console's first-run ceremony puts the custody tradeoff in front of the operator and
// pre-selects nothing. scripts/generate-keys.ts had one outcome: it generated the operational read-back pair
// unconditionally, so `npm run deploy` against a keyless engine landed in the two-recipient posture without
// ever offering the other one. It was not concealed (the printed sheet's POSTURE block did say the proof was
// ON), but a choice the customer's own documentation describes as theirs was being made by the deploy path.
// --break-glass-only is the mirror of the --operational-only flag that already existed.
//
// AND WHAT WAS OPEN. CONFIG_WRAP_KEY was optional and NOTHING generated it: a grep across scripts/ and the
// console found only advice text telling the operator to mint one by hand. Absent, every configuration
// secret the scheduler Durable Object holds sits on the platform-encryption floor -- not only the archive
// destination credential, but the six other classes src/admin/config-secret.ts seals, including the
// account-wide read-only Cloudflare discovery token. The ceremony now mints it in both postures.
//
// Run: node test/validate-key-ceremony-postures.ts

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { b64urlDecode } from "../src/crypto/bytes.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ENGINE_DIR, "scripts", "generate-keys.ts");

// runCeremony runs the REAL script into a fresh temp directory and returns its stdout, its exit status and
// the staging file names it left. Nothing here touches wrangler, the network or the engine checkout: the
// script only writes files, and deploy.sh is what would pipe them into `wrangler secret put`.
function runCeremony(flags: string[]): { stdout: string; status: number; out: string; staging: string[] } {
  const out = mkdtempSync(join(tmpdir(), "dp-ceremony-"));
  let stdout: string;
  let status = 0;
  try {
    stdout = execFileSync(process.execPath, [SCRIPT, out, ...flags], { encoding: "utf8", cwd: ENGINE_DIR, stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; status?: number };
    stdout = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    status = err.status ?? 1;
  }
  const stagingDir = join(out, ".staging");
  const staging = existsSync(stagingDir) ? readdirSync(stagingDir).sort() : [];
  return { stdout, status, out, staging };
}

function sheetOf(out: string): string {
  return readFileSync(join(out, "recovery-sheet.txt"), "utf8");
}

// The sheet is hard-wrapped for printing, so a sentence the assertions care about is split across lines at
// a column nobody should have to predict. flat collapses every run of whitespace to one space, which lets a
// check grade the WORDS the operator reads rather than the line breaks the template happens to have.
function flat(text: string): string {
  return text.replace(/\s+/g, " ");
}

async function main(): Promise<void> {
  console.log("-- the default posture (unchanged: the operational read-back pair) --");
  const def = runCeremony([]);
  {
    ok("the default ceremony succeeds", def.status === 0);
    ok("it still writes both operational halves for deploy.sh to install", def.staging.includes("operational-public.b64") && def.staging.includes("operational-private.b64"));
    ok("it still writes the signer, break-glass and config-recipient values", ["signer-private.b64", "break-glass-public.b64", "config-recipient-public.b64", "config-recipient-private.b64"].every((f) => def.staging.includes(f)));
    ok("identity.key stays on this machine and is never staged for the engine", existsSync(join(def.out, "identity.key")) && !def.staging.includes("identity.key"));
    const sheet = sheetOf(def.out);
    ok("the sheet states the posture it produced: proof ON", /Automated restore proof: ON/.test(sheet));
    ok("...and names the opt-out that reverses it without a re-key", /Keys screen/.test(sheet));
    ok("the sheet prints the operational fingerprint", /operational {3}dpr1:[0-9a-f]{96}/.test(sheet));
  }

  console.log("\n-- --break-glass-only: the posture the terminal path could not reach --");
  const bg = runCeremony(["--break-glass-only"]);
  {
    ok("the break-glass-only ceremony succeeds", bg.status === 0);
    // The assertion the fix is FOR. Before it, this flag did not exist and the operational pair was
    // generated unconditionally, so these two files were present on every terminal deploy.
    ok("NO operational key is generated at all (neither half is staged)", !bg.staging.includes("operational-public.b64") && !bg.staging.includes("operational-private.b64"));
    ok("the signer and break-glass values are unaffected", bg.staging.includes("signer-private.b64") && bg.staging.includes("break-glass-public.b64"));
    ok("the config recipient still goes in (it is not a posture choice: it opens this engine's own config export)", bg.staging.includes("config-recipient-public.b64") && bg.staging.includes("config-recipient-private.b64"));
    ok("identity.key is still written, because break-glass is now the ONLY way to read an archive", existsSync(join(bg.out, "identity.key")));
    const sheet = sheetOf(bg.out);
    ok("the sheet states the posture it produced: proof OFF", /Automated restore proof: OFF \(break-glass-only/.test(sheet));
    ok("...and says plainly what is off (tests, drills, in-console restores, pruning)", flat(sheet).includes("scheduled restore tests, drills, in-console restores and retention pruning are off"));
    ok("...and names both ways back on, so the choice is not one-way", /Keys screen/.test(sheet) && /--enable-operational/.test(sheet));
    ok("the fingerprint block says there is no operational key rather than omitting the line", /operational {3}none \(break-glass-only\)/.test(sheet));
    ok("stdout says the proof is off (the terminal operator sees it without opening the sheet)", /break-glass-only: automated restore proof off/.test(bg.stdout));
  }

  console.log("\n-- the configuration wrap key, generated in BOTH postures --");
  {
    const keyOf = (out: string): Uint8Array => b64urlDecode(readFileSync(join(out, ".staging", "config-wrap-key.b64"), "utf8").trim());
    ok("the default ceremony stages a wrap key (nothing generated one before)", def.staging.includes("config-wrap-key.b64"));
    ok("the break-glass-only ceremony stages one too (it is not a posture choice)", bg.staging.includes("config-wrap-key.b64"));
    ok("it is 32 bytes, the AES-256 length loadConfigWrapKey demands", keyOf(def.out).length === 32 && keyOf(bg.out).length === 32);
    // Two independently generated keys must differ. A constant, a fixed seed or an all-zero buffer would
    // pass every length check above and leave every estate sharing one key.
    ok("two ceremonies generate DIFFERENT keys (it is random, not a constant)", Buffer.from(keyOf(def.out)).toString("hex") !== Buffer.from(keyOf(bg.out)).toString("hex"));
    ok("the wrap key is never written into the kit itself (it went to the engine, like the signer private)", !existsSync(join(def.out, "config-wrap-key.b64")) && !existsSync(join(def.out, "config-wrap-key.txt")));
    const sheet = sheetOf(def.out);
    ok("the sheet no longer tells the operator to mint one by hand", !/If you set a CONFIG_WRAP_KEY/.test(sheet));
    ok("...and states what losing it costs: a re-entered credential, never an archive", flat(sheet).includes("Losing it costs a re-entered destination or integration credential; it can never cost you an archive"));
  }

  console.log("\n-- --config-wrap-key-only: the top-up for an engine deployed before the key existed --");
  {
    const top = runCeremony(["--config-wrap-key-only"]);
    ok("the top-up ceremony succeeds", top.status === 0);
    ok("it stages the wrap key and NOTHING else (no key material is re-generated)", top.staging.length === 1 && top.staging[0] === "config-wrap-key.b64");
    ok("it writes no identity.key, so it can never overwrite an existing kit", !existsSync(join(top.out, "identity.key")));
    ok("it says the pre-existing credentials stay on the old floor until re-saved", /stay on the platform-encryption floor until each is re-saved/.test(top.stdout));
    rmSync(top.out, { recursive: true, force: true });
  }

  console.log("\n-- the mode flags are mutually exclusive --");
  for (const pair of [["--break-glass-only", "--operational-only"], ["--break-glass-only", "--config-wrap-key-only"], ["--operational-only", "--config-wrap-key-only"]]) {
    const clash = runCeremony(pair);
    ok(`${pair.join(" + ")} is REFUSED rather than one silently winning`, clash.status === 2 && /pass at most one/.test(clash.stdout) && clash.staging.length === 0);
    rmSync(clash.out, { recursive: true, force: true });
  }

  rmSync(def.out, { recursive: true, force: true });
  rmSync(bg.out, { recursive: true, force: true });

  console.log(failures === 0 ? "\nKEY CEREMONY POSTURES PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
