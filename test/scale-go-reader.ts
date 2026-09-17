// Go-reader cross-check helper for the chaos test suite's scale axis (Tier 1, deploy-free). This is a compact,
// engine-self-contained mirror of the harness's offline reader drive (the Axis-3 offline reader
// drive): it builds the SIBLING Go reader (../downpipe cmd/downpipe -- a DIFFERENT codebase from this
// TypeScript engine), writes a fanned-out archive out to a temp directory in the Go CLI's on-disk layout,
// and shells `restore --archive <dir> --sink discard` so a genuinely independent implementation recomputes
// the signed Merkle root, verifies completeness, and decrypts + hash-checks every record. A wrong or short
// archive makes the reader REFUSE (a non-zero exit), which is the cell (a) keystone refuter.
//
// It is homed here (not imported from the harness) so the engine validator stays inside the engine repo's
// own tsconfig; it reuses the Axis-3 READER (the same Go binary) and the same driving pattern. NET-ZERO:
// everything runs on an ephemeral temp dir, a locally built binary, and harness-minted keys; there is no
// estate, bucket, network, seed or spend. assertEphemeralWorkdir refuses any repo-tree or live-keys path.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { siblingLag, siblingLagLine } from "../scripts/lib/sibling-lag.mjs";

export interface ReaderRun {
  exitCode: number;
  stdout: string;
  stderr: string;
}

// goPresent reports whether a Go toolchain is on PATH (a hard prerequisite; absent Go degrades the Go
// cross-check to a named GAP, never a failure, exactly as the Axis-3 drive does).
export function goPresent(): { ok: boolean; version: string } {
  try {
    return { ok: true, version: execFileSync("go", ["version"], { encoding: "utf8" }).trim() };
  } catch {
    return { ok: false, version: "" };
  }
}

// assertEphemeralWorkdir refuses any path that is not an OS temp path, or that names a live-keys
// tree (the same net-zero guard the harness's offline reader drive uses).
export function assertEphemeralWorkdir(dir: string): void {
  if (dir.includes("downpipes-live-keys")) throw new Error(`refusing a downpipes-live-keys workdir: ${dir}`);
  const okRoot = dir.startsWith(tmpdir()) || dir.startsWith("/private/tmp/") || dir.startsWith("/tmp/");
  if (!okRoot) throw new Error(`refusing a non-ephemeral workdir (want an OS temp path): ${dir}`);
}

// newTmpRoot makes a fresh ephemeral working root under the OS temp dir (guarded).
export function newTmpRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), "downpipes-scale-"));
  assertEphemeralWorkdir(dir);
  return dir;
}

// buildReader runs `go build -o bin ./cmd/downpipe` in the sibling ../downpipe repo. Neither outcome throws.
//
// THE TWO FAILURES ARE NOT THE SAME FAILURE, and `reason` is what separates them.
//   "absent"       the sibling reader repo is not beside this one. A precondition of the environment, the
//                  same class as the Go toolchain not being installed, and a legitimate skip.
//   "build-failed" the reader source IS here and `go build` rejected it. That is a broken second reader,
//                  which is a product defect and must never be reported as a skipped precondition.
//
// The distinction is load-bearing. Four chain members (validate-fuzzing-tier1, -chunkboundary, -recordset,
// -slice-boundary) called verdictSkipped on BOTH and exited 0, so a Go reader that stopped compiling would
// have turned the whole differential fuzz, the only check that reads an archive with a codebase other than
// the one that wrote it, into four green skips. Nothing counts skips separately from other verdicts, so a
// silent skip reads no differently from a passing one in the chain's own summary.
export function buildReader(engineDir: string, bin: string): { ok: boolean; detail: string; repo: string; reason?: "absent" | "build-failed" } {
  const repo = join(engineDir, "..", "downpipe");
  if (!existsSync(join(repo, "cmd", "downpipe"))) return { ok: false, reason: "absent", detail: `no cmd/downpipe under ${repo}`, repo };
  try {
    execFileSync("go", ["build", "-o", bin, "./cmd/downpipe"], { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    // WHICH READER WAS BUILT, in the detail every caller already logs. GRADE AND SAY SO, not refuse: eight
    // validators call this and the sibling is optional to all of them, so a refusal here would take out the
    // whole differential drive over a checkout the operator may deliberately be holding at an older reader.
    // The differential claim is "a codebase other than the one that wrote it read these bytes", and that
    // stays true of whatever reader was built. It is only unreadable when the log does not say which.
    const lag = siblingLag("downpipe", repo);
    return { ok: true, detail: `built ${bin} (${statSync(bin).size} bytes) from ${siblingLagLine(lag)}`, repo };
  } catch (e) {
    const err = e as { stderr?: Buffer | string; message?: string };
    return { ok: false, reason: "build-failed", detail: `go build failed: ${(err.stderr ?? err.message ?? "").toString().slice(-200)}`, repo };
  }
}

// runReader shells the Go reader. A non-zero exit is an ANSWER (returned with the code), not a throw; only a
// genuine spawn failure (the binary is not executable) rethrows. spawnSync captures both streams on success
// and failure (the reader prints its verified record count to stderr).
export function runReader(bin: string, args: string[]): ReaderRun {
  const r = spawnSync(bin, args, { encoding: "utf8" });
  if (r.error) {
    const code = (r.error as { code?: string }).code;
    if (code === "ENOENT" || code === "EACCES") throw new Error(`could not execute ${bin} (${code})`);
    throw r.error;
  }
  return { exitCode: typeof r.status === "number" ? r.status : -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

// restoreDiscardArgs builds the `restore --sink discard` argv (verify + decrypt every record, materialise
// nothing). It ALWAYS uses --archive (a directory, offline by construction), never --s3-endpoint. This is
// byte-identical in shape to the Axis-3 drive's restoreArgs(..., "discard").
export function restoreDiscardArgs(archiveDir: string, runId: string, identityFile: string, signerFile: string): string[] {
  return ["restore", "--archive", archiveDir, "--run", runId, "--identity", identityFile, "--signer", signerFile, "--sink", "discard", "--apply"];
}

// writeArchiveDir lays a sealed archive's object map out as files under <root>/archive plus the Go CLI's
// labelled identity + signer files (the same artefact shape validate-chained-segments.ts writes). Returns
// the paths the reader needs. identityB64u / signerB64u are the base64url bodies (no prefix).
export function writeArchiveDir(root: string, map: Map<string, Uint8Array>, identityB64u: string, signerB64u: string): { archiveDir: string; identityFile: string; signerFile: string } {
  assertEphemeralWorkdir(root);
  const archiveDir = join(root, "archive");
  for (const [key, bytes] of map) {
    const p = join(archiveDir, key);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, bytes);
  }
  const identityFile = join(root, "identity.key");
  const signerFile = join(root, "signer.pub");
  writeFileSync(identityFile, `downpipe-identity-v1 ${identityB64u}\n`);
  writeFileSync(signerFile, `downpipe-signer-public-v1 ${signerB64u}\n`);
  return { archiveDir, identityFile, signerFile };
}

// copyArchiveRoot deep-copies an archive root so a tamper never mutates the shared clean fixture.
export function copyArchiveRoot(src: string, dst: string): void {
  assertEphemeralWorkdir(dst);
  cpSync(src, dst, { recursive: true });
}

// flipLastByte flips the low bit of a file's last byte in place (the single-mutation shard corruption).
export function flipLastByte(path: string): void {
  const buf = readFileSync(path);
  if (buf.length === 0) throw new Error(`cannot flip a byte in an empty file: ${path}`);
  buf[buf.length - 1] = buf[buf.length - 1]! ^ 1;
  writeFileSync(path, buf);
}
