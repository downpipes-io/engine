// Vendor-side publisher vectors (tools/publish-channel.mjs), DP-0 freshness scope: the channel's
// anti-replay pair (sequence/issuedAt) must ride INSIDE the signed body, the tool must REFUSE a
// forgotten or non-monotonic sequence BEFORE signing (a fielded engine would refuse the replay,
// so the tool fails first, at the vendor's desk), and the sequence-state file must advance only
// after a successful self-verified emit -- a refused run must never burn a sequence number.
//
// The tool is spawned as a child process (it is an operator CLI whose module body runs main()),
// with channel-only publishes (no --build), so no wrangler and no network are involved. The
// signed body is then verified with the ENGINE'S OWN verifyChannel under the printed public key,
// so "inside the signed body" is proven by the product's verify path, not by re-parsing alone.
//
// Run with: node test/validate-publish-channel.ts

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChannel } from "../src/admin/updates.ts";
import { parseVerifier } from "../src/crypto/keys.ts";
import { b64urlDecode, b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TOOL = path.join(HERE, "..", "tools", "publish-channel.mjs");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function run(args: string[], env: Record<string, string> = {}): RunResult {
  try {
    const stdout = execFileSync("node", [TOOL, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
    return { status: 0, stdout, stderr: "" };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { status: err.status ?? 1, stdout: String(err.stdout ?? ""), stderr: String(err.stderr ?? "") };
  }
}

// runWithStdin is `run` but pipes `input` in on stdin instead of the "ignore" the ordinary vectors use --
// for --signer-seed-stdin, which reads its seed off fd 0.
function runWithStdin(args: string[], input: string, env: Record<string, string> = {}): RunResult {
  try {
    const stdout = execFileSync("node", [TOOL, ...args], { encoding: "utf8", input, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, ...env } });
    return { status: 0, stdout, stderr: "" };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { status: err.status ?? 1, stdout: String(err.stdout ?? ""), stderr: String(err.stderr ?? "") };
  }
}

// ---- DP-A ceremony fixtures: a synthetic attested release tree + a stub cosign binary ----------
// The stub keeps the REFUSAL semantics real (a failing verifier refuses, a missing binary refuses)
// while letting the digest/subject/facts checks run without Sigstore infrastructure. The real
// cosign path is exercised at the S9 rehearsal against a live CI release.
function writeStubCosign(dir: string, mode: "pass" | "fail"): string {
  const p = path.join(dir, `stub-cosign-${mode}`);
  const body =
    mode === "pass"
      ? '#!/usr/bin/env node\nconst a=process.argv.slice(2);\nif(a[0]!=="verify-blob"||!a.includes("--bundle")||!a.includes("--certificate-identity-regexp")||!a.includes("--certificate-oidc-issuer")){console.error("stub cosign: unexpected argv "+a.join(" "));process.exit(2);}\nprocess.exit(0);\n'
      : '#!/usr/bin/env node\nconsole.error("stub cosign: signature verification failed (simulated)");process.exit(1);\n';
  writeFileSync(p, body, { mode: 0o755 });
  return p;
}

interface ReleaseFixtureOpts {
  version: string;
  component: "engine" | "console";
  artefactBytes: Uint8Array;
  omitIntoto?: boolean;
  wrongSubjectDigest?: boolean;
  omitCiFacts?: boolean;
  corruptArtefact?: boolean;
  // slsa-github-generator@v2.1.0's real *.intoto.jsonl wraps the DSSE envelope inside a Sigstore
  // bundle ({mediaType, verificationMaterial, dsseEnvelope:{payload,...}}) instead of a bare
  // envelope; this fixture shape reproduces exactly that, found live.
  wrapInSigstoreBundle?: boolean;
}

function writeReleaseFixture(base: string, o: ReleaseFixtureOpts): string {
  const dir = path.join(base, `${o.component}-release-${o.version}${o.corruptArtefact ? "-corrupt" : ""}${o.wrongSubjectDigest ? "-badsubject" : ""}${o.omitIntoto ? "-nointoto" : ""}${o.omitCiFacts ? "-nofacts" : ""}`);
  rmSync(dir, { recursive: true, force: true });
  const artefactName = o.component === "engine" ? `engine-${o.version}.mjs` : `console-${o.version}.json`;
  const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
  const sha384hex = (b: Uint8Array) => createHash("sha384").update(b).digest("hex");
  const trueDigest = sha256(o.artefactBytes);
  const written = o.corruptArtefact ? new Uint8Array([...o.artefactBytes, 0x0a]) : o.artefactBytes;
  const factsObj: Record<string, unknown> = { version: o.version, sha256: trueDigest, sha384: sha384hex(o.artefactBytes), bytes: o.artefactBytes.length };
  if (!o.omitCiFacts) {
    factsObj.repo = `downpipes/${o.component}`;
    factsObj.commit = "a".repeat(40);
    factsObj.tag = `v${o.version}`;
    factsObj.runId = "123456789";
  }
  const facts = JSON.stringify(factsObj, null, 2);
  const sums = `${trueDigest}  dist/${artefactName}\n${sha256(new TextEncoder().encode(facts))}  release-facts.json\n`;
  const subjectDigest = o.wrongSubjectDigest ? "f".repeat(64) : trueDigest;
  const statement = { _type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1", subject: [{ name: `dist/${artefactName}`, digest: { sha256: subjectDigest } }], predicate: { builder: { id: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0" } } };
  const bareEnvelope = { payloadType: "application/vnd.in-toto+json", payload: Buffer.from(JSON.stringify(statement)).toString("base64"), signatures: [] };
  const envelope = JSON.stringify(o.wrapInSigstoreBundle ? { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", verificationMaterial: {}, dsseEnvelope: bareEnvelope } : bareEnvelope);
  const bundle = JSON.stringify({ base64Signature: "c3R1Yg", rekorBundle: { Payload: { logIndex: 424242 } } });
  const write = (name: string, content: string | Uint8Array) => {
    const p = path.join(dir, name);
    const d = path.dirname(p);
    if (!existsSync(d)) {
      execFileSync("mkdir", ["-p", d]);
    }
    writeFileSync(p, content);
  };
  write(`dist/${artefactName}`, written);
  write("release-facts.json", facts);
  write("SHA256SUMS.txt", sums);
  if (!o.omitIntoto) write(`${o.component}.intoto.jsonl`, envelope + "\n");
  write(`dist/${artefactName}.cosign-bundle`, bundle);
  write("SHA256SUMS.txt.cosign-bundle", bundle);
  return dir;
}

const tmp = mkdtempSync(path.join(tmpdir(), "publish-channel-"));
try {
  // V1: a sequenced publish emits the pair INSIDE the signed body, proven via the engine's own
  // verifyChannel under the printed pin. --issued-at is fixed so the assertion is exact.
  const keyPath = path.join(tmp, "release-signer.key");
  const v1 = run(["--version", "0.0.1", "--sequence", "1", "--issued-at", "2026-07-05T00:00:00.000Z", "--out-key", keyPath]);
  ok("sequenced publish succeeds", v1.status === 0);
  const out1 = JSON.parse(v1.stdout) as { channel: string; signature: string; updateSignerPublic: string; sequence?: number; issuedAt?: string; sequenceNote?: string };
  ok("result echoes sequence + issuedAt + the baseline note", out1.sequence === 1 && out1.issuedAt === "2026-07-05T00:00:00.000Z" && typeof out1.sequenceNote === "string");
  const verified1 = await verifyChannel(utf8(out1.channel), b64urlDecode(out1.signature), parseVerifier(b64urlDecode(out1.updateSignerPublic)));
  ok("the engine's verifyChannel accepts the emitted bytes under the printed pin", verified1 !== null);
  ok("sequence/issuedAt ride INSIDE the signed body (the verified parse carries them)", verified1?.sequence === 1 && verified1?.issuedAt === "2026-07-05T00:00:00.000Z");
  ok("--out-key wrote the signing key for the runs below", existsSync(keyPath));

  // V2: a forgotten --sequence REFUSES before signing (the deliberate-baseline rule).
  const v2 = run(["--version", "0.0.1", "--key-file", keyPath]);
  ok("a publish without --sequence is refused", v2.status !== 0 && /--sequence/.test(v2.stderr));

  // V3: --allow-unsequenced is the explicit legacy escape hatch: it emits the pre-freshness
  // shape (no pair in the body) and warns, so the opt-out is visible, never accidental.
  const v3 = run(["--version", "0.0.1", "--key-file", keyPath, "--allow-unsequenced"]);
  ok("--allow-unsequenced publish succeeds", v3.status === 0);
  const out3 = JSON.parse(v3.stdout) as { channel: string; unsequencedWarning?: string };
  const body3 = JSON.parse(out3.channel) as { sequence?: unknown; issuedAt?: unknown };
  ok("the unsequenced body carries NO freshness pair (legacy shape)", body3.sequence === undefined && body3.issuedAt === undefined);
  ok("the unsequenced result carries the explicit warning", typeof out3.unsequencedWarning === "string");

  // V4: monotonicity against the state file -- an equal-or-lower sequence refuses; nothing signed.
  const statePath = path.join(tmp, "channel-sequence.json");
  writeFileSync(statePath, JSON.stringify({ lastSequence: 5 }) + "\n");
  const v4 = run(["--version", "0.0.1", "--key-file", keyPath, "--sequence", "5", "--sequence-state", statePath]);
  ok("a sequence equal to the recorded last is refused as a replay", v4.status !== 0 && /does not exceed/.test(v4.stderr));
  ok("a refused run does NOT advance the state file", (JSON.parse(readFileSync(statePath, "utf8")) as { lastSequence: number }).lastSequence === 5);

  // V5: the next sequence proceeds and advances the state file (only after the verified emit).
  const v5 = run(["--version", "0.0.1", "--key-file", keyPath, "--sequence", "6", "--sequence-state", statePath, "--issued-at", "2026-07-05T01:00:00.000Z"]);
  ok("the next sequence publishes", v5.status === 0);
  const state5 = JSON.parse(readFileSync(statePath, "utf8")) as { lastSequence: number; issuedAt?: string };
  ok("a successful emit advances the state file to the published pair", state5.lastSequence === 6 && state5.issuedAt === "2026-07-05T01:00:00.000Z");

  // V6: the DEFAULT state path is channel-sequence.json beside --key-file (the signing-key
  // custody dir), so the monotonic memory lives with the key it protects.
  const defaultState = path.join(path.dirname(keyPath), "channel-sequence.json");
  rmSync(defaultState, { force: true });
  const v6 = run(["--version", "0.0.1", "--key-file", keyPath, "--sequence", "7"]);
  ok("default sequence-state lands beside the key file", v6.status === 0 && existsSync(defaultState) && (JSON.parse(readFileSync(defaultState, "utf8")) as { lastSequence: number }).lastSequence === 7);
  const v6b = run(["--version", "0.0.1", "--key-file", keyPath, "--sequence", "7"]);
  ok("the default state file enforces monotonicity on the next run", v6b.status !== 0 && /does not exceed/.test(v6b.stderr));

  // ================================================================================================
  // DP-A ceremony vectors: the offline key must refuse bytes CI did not attest, and a clean
  // attested tree must yield a channel whose signed body carries the provenance block and whose
  // sidecar set lands exactly where the block's paths point.
  // ================================================================================================
  const stubPass = writeStubCosign(tmp, "pass");
  const stubFail = writeStubCosign(tmp, "fail");
  const engineBytes = new TextEncoder().encode("// engine release bytes 0.0.2\nexport default {};\n");
  const consoleBytes = new TextEncoder().encode(JSON.stringify({ format: "downpipe-console-bundle/1", version: "0.0.9", worker: { mainModule: "worker.js", sourceB64: "" }, config: {}, assets: [] }, null, 2));
  const engineDir = writeReleaseFixture(tmp, { version: "0.0.2", component: "engine", artefactBytes: engineBytes });
  const consoleDir = writeReleaseFixture(tmp, { version: "0.0.9", component: "console", artefactBytes: consoleBytes });
  const provOut = path.join(tmp, "prov-out");
  const ceremonyArgs = [
    "--version", "0.0.2",
    "--key-file", keyPath,
    "--sequence", "20",
    "--sequence-state", path.join(tmp, "ceremony-seq.json"),
    "--issued-at", "2026-07-05T02:00:00.000Z",
    "--from-release-dir", engineDir,
    "--url", "https://update.downpipes.io/engine-0.0.2.mjs",
    "--console-release-dir", consoleDir,
    "--console-url", "https://update.downpipes.io/console-0.0.9.json",
    "--provenance-out-dir", provOut,
  ];

  // V7: the full dual-component ceremony over a clean attested tree.
  const v7 = run(ceremonyArgs, { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("attested ceremony publishes (engine + console from release dirs)", v7.status === 0);
  const out7 = JSON.parse(v7.stdout) as { channel: string; signature: string; updateSignerPublic: string; provenanceDir?: string };
  const verified7 = await verifyChannel(utf8(out7.channel), b64urlDecode(out7.signature), parseVerifier(b64urlDecode(out7.updateSignerPublic)));
  ok("the ceremony channel verifies under the pin", verified7 !== null);
  const eng7 = verified7?.artefacts?.[0];
  ok("the SIGNED body carries the engine provenance block (commit, runId, rekor, tag)", eng7?.provenance?.commit === "a".repeat(40) && eng7?.provenance?.runId === "123456789" && eng7?.provenance?.rekorLogIndex === "424242" && eng7?.provenance?.tag === "v0.0.2");
  ok("the engine provenance attestation paths are channel-relative under provenance/<version>/", eng7?.provenance?.attestations?.intoto === "provenance/0.0.2/engine.intoto.jsonl" && eng7?.provenance?.attestations?.releaseRecord === "provenance/0.0.2/release-record.json");
  const con7 = (verified7 as { components?: Record<string, { provenance?: { attestations?: { intoto?: string }; commit?: string } } | undefined> } | null)?.components?.console;
  ok("the SIGNED body carries the console provenance block too", con7?.provenance?.commit === "a".repeat(40) && con7?.provenance?.attestations?.intoto === "provenance/0.0.2/console.intoto.jsonl");
  const sidecars = ["engine.intoto.jsonl", "engine-0.0.2.mjs.cosign-bundle", "engine.SHA256SUMS.txt", "engine.SHA256SUMS.txt.cosign-bundle", "engine.release-facts.json", "console.intoto.jsonl", "console-0.0.9.json.cosign-bundle", "console.SHA256SUMS.txt", "console.SHA256SUMS.txt.cosign-bundle", "console.release-facts.json", "release-record.json"];
  ok("every sidecar the signed paths point at was written", sidecars.every((f) => existsSync(path.join(provOut, "provenance", "0.0.2", f))));
  const record7 = JSON.parse(readFileSync(path.join(provOut, "provenance", "0.0.2", "release-record.json"), "utf8")) as { engine?: { sha384?: string; rekorLogIndex?: string }; console?: { version?: string }; sequence?: number };
  ok("release-record.json mirrors the signed facts (digest, rekor, sequence, console version)", record7.engine?.sha384 === eng7?.sha384 && record7.engine?.rekorLogIndex === "424242" && record7.sequence === 20 && record7.console?.version === "0.0.9");

  // V7b: the real slsa-github-generator@v2.1.0 shape wraps the DSSE envelope inside a Sigstore
  // bundle; the ceremony must ingest that exactly as it does the bare-envelope shape above. Found
  // live (--from-release-dir refused every real release with "carries no DSSE payload"
  // until this shape was read too).
  const wrappedDir = writeReleaseFixture(tmp, { version: "0.0.2", component: "engine", artefactBytes: engineBytes, wrapInSigstoreBundle: true });
  const v7b = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", wrappedDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("a Sigstore-bundle-wrapped intoto.jsonl ingests exactly like a bare DSSE envelope", v7b.status === 0);

  // V8: a corrupted artefact refuses before signing.
  const corruptDir = writeReleaseFixture(tmp, { version: "0.0.2", component: "engine", artefactBytes: engineBytes, corruptArtefact: true });
  const v8 = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", corruptDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("a corrupted artefact refuses (digest vs release-facts)", v8.status !== 0 && /does not match release-facts/.test(v8.stderr));

  // V9: a missing SLSA provenance file refuses.
  const noIntotoDir = writeReleaseFixture(tmp, { version: "0.0.2", component: "engine", artefactBytes: engineBytes, omitIntoto: true });
  const v9 = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", noIntotoDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("a release tree without provenance refuses", v9.status !== 0 && /unattested release cannot be signed/.test(v9.stderr));

  // V10: provenance whose subjects do not cover these bytes refuses.
  const badSubjectDir = writeReleaseFixture(tmp, { version: "0.0.2", component: "engine", artefactBytes: engineBytes, wrongSubjectDigest: true });
  const v10 = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", badSubjectDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("provenance not covering the bytes refuses (subject digest mismatch)", v10.status !== 0 && /subjects do not include/.test(v10.stderr));

  // V11: a failing verifier refuses (the stub simulates a bad keyless signature).
  const v11 = run(ceremonyArgs, { PUBLISH_CHANNEL_COSIGN: stubFail });
  ok("a failing cosign verification refuses", v11.status !== 0 && /cosign verification FAILED/.test(v11.stderr));

  // V12: a MISSING verifier binary refuses (never verify-nothing-and-continue).
  const v12 = run(ceremonyArgs, { PUBLISH_CHANNEL_COSIGN: path.join(tmp, "no-such-cosign") });
  ok("a missing cosign binary refuses with the install instruction", v12.status !== 0 && /is not installed/.test(v12.stderr));

  // V13: a facts file without CI identifiers refuses (a local build is not an attested release).
  const noFactsDir = writeReleaseFixture(tmp, { version: "0.0.2", component: "engine", artefactBytes: engineBytes, omitCiFacts: true });
  const v13 = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", noFactsDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("a facts file without CI identifiers refuses", v13.status !== 0 && /no CI identifiers/.test(v13.stderr));

  // V14: mixing ceremony mode with a local build refuses.
  const v14 = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", engineDir, "--build", "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("--from-release-dir with --build refuses (never a fresh local build)", v14.status !== 0 && /replaces --build/.test(v14.stderr));

  // V15: a channel version that does not match the attested version refuses.
  const v15 = run(["--version", "9.9.9", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", engineDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("a --version not matching the attested release refuses", v15.status !== 0 && /does not match the attested release/.test(v15.stderr));

  // V16: ceremony mode without --provenance-out-dir refuses (signed paths must not dangle).
  const v16 = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", engineDir, "--url", "https://u.example/e.mjs"], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("ceremony mode without --provenance-out-dir refuses", v16.status !== 0 && /--provenance-out-dir is required/.test(v16.stderr));

  // V17: CROSS-COMPONENT mixing refuses both ways (review finding: an attested release must not
  // smuggle fresh local bytes in beside the attested component).
  const looseConsole = path.join(tmp, "loose-console.json");
  writeFileSync(looseConsole, JSON.stringify({ format: "downpipe-console-bundle/1", version: "0.0.9", worker: { mainModule: "worker.js", sourceB64: "" }, config: {}, assets: [] }));
  const v17a = run(["--version", "0.0.2", "--key-file", keyPath, "--allow-unsequenced", "--from-release-dir", engineDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", provOut, "--console-bundle", looseConsole, "--console-url", "https://u.example/c.json"], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("attested engine + local console bundle refuses (cross-component guard)", v17a.status !== 0 && /console artefact must also come from an attested release/.test(v17a.stderr));
  const looseEngine = path.join(tmp, "loose-engine.mjs");
  writeFileSync(looseEngine, "// loose local engine bytes\n");
  const v17b = run(["--version", "0.0.9", "--key-file", keyPath, "--allow-unsequenced", "--console-release-dir", consoleDir, "--console-url", "https://u.example/c.json", "--provenance-out-dir", provOut, "--bundle", looseEngine, "--url", "https://u.example/e.mjs"], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("attested console + local engine bundle refuses (cross-component guard)", v17b.status !== 0 && /engine artefact must also come from an attested release/.test(v17b.stderr));

  // V18: a failure AFTER self-verify (an unwritable sidecar dir) must not burn the sequence number.
  const blockedOut = path.join(tmp, "blocked-out");
  writeFileSync(blockedOut, "a file where the sidecar DIRECTORY must go\n");
  const seqState18 = path.join(tmp, "seq18.json");
  const v18 = run(["--version", "0.0.2", "--key-file", keyPath, "--sequence", "30", "--sequence-state", seqState18, "--issued-at", "2026-07-05T03:00:00.000Z", "--from-release-dir", engineDir, "--url", "https://u.example/e.mjs", "--provenance-out-dir", path.join(blockedOut, "nested")], { PUBLISH_CHANNEL_COSIGN: stubPass });
  ok("a post-verify output failure exits non-zero", v18.status !== 0);
  ok("a post-verify output failure does NOT burn the sequence", !existsSync(seqState18));

  // ================================================================================================
  // --signer-seed-stdin: the seed reaches the tool over stdin instead of a plaintext --key-file, so a
  // caller can pipe a just-decrypted secret straight in (`age -d ... | node publish-channel.mjs
  // --signer-seed-stdin ...`) without it ever landing on disk. A throwaway seed is generated here
  // (never the real release signer) purely to exercise the plumbing.
  // ================================================================================================
  const throwawaySeed = b64urlEncode(concat(crypto.getRandomValues(new Uint8Array(32)), crypto.getRandomValues(new Uint8Array(32))));

  // V19: piping the seed on stdin signs a channel the engine's own verifyChannel accepts under the
  // key the SAME seed would derive via --key -- proving the stdin path reaches loadSigner identically.
  const v19viaKey = run(["--version", "0.0.3", "--key", throwawaySeed, "--allow-unsequenced"]);
  ok("a control run with the same seed via --key succeeds", v19viaKey.status === 0);
  const out19viaKey = JSON.parse(v19viaKey.stdout) as { updateSignerPublic: string };
  const v19 = runWithStdin(["--version", "0.0.3", "--signer-seed-stdin", "--allow-unsequenced"], throwawaySeed);
  ok("--signer-seed-stdin publish succeeds", v19.status === 0);
  const out19 = JSON.parse(v19.stdout) as { channel: string; signature: string; updateSignerPublic: string };
  ok("--signer-seed-stdin derives the SAME public key as --key with the same seed bytes", out19.updateSignerPublic === out19viaKey.updateSignerPublic);
  const verified19 = await verifyChannel(utf8(out19.channel), b64urlDecode(out19.signature), parseVerifier(b64urlDecode(out19.updateSignerPublic)));
  ok("the engine's verifyChannel accepts a channel signed via --signer-seed-stdin", verified19 !== null);

  // V20: a trailing newline on stdin (what `echo`/a file's own trailing newline would add) is
  // trimmed exactly like --key-file's contents are.
  const v20 = runWithStdin(["--version", "0.0.3", "--signer-seed-stdin", "--allow-unsequenced"], `${throwawaySeed}\n`);
  ok("--signer-seed-stdin tolerates a trailing newline (trimmed like --key-file)", v20.status === 0 && JSON.parse(v20.stdout).updateSignerPublic === out19viaKey.updateSignerPublic);

  // V21: empty/closed stdin is refused loudly, never silently falls through to a fresh generated key.
  const v21 = runWithStdin(["--version", "0.0.3", "--signer-seed-stdin", "--allow-unsequenced"], "");
  ok("--signer-seed-stdin with empty stdin refuses (never silently generates a fresh key)", v21.status !== 0 && /stdin carried no bytes/.test(v21.stderr));

  // V22: --signer-seed-stdin together with --key-file is refused as ambiguous (mutually exclusive).
  const v22 = runWithStdin(["--version", "0.0.3", "--signer-seed-stdin", "--key-file", keyPath, "--allow-unsequenced"], throwawaySeed);
  ok("--signer-seed-stdin with --key-file refuses as ambiguous", v22.status !== 0 && /mutually exclusive/.test(v22.stderr) && /signer-seed-stdin/.test(v22.stderr) && /key-file/.test(v22.stderr));

  // V23: --signer-seed-stdin together with --key is refused the same way.
  const v23 = runWithStdin(["--version", "0.0.3", "--signer-seed-stdin", "--key", throwawaySeed, "--allow-unsequenced"], throwawaySeed);
  ok("--signer-seed-stdin with --key refuses as ambiguous", v23.status !== 0 && /mutually exclusive/.test(v23.stderr));
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

verdictReached(failures);
if (failures > 0) {
  console.error(`\n${failures} publish-channel validation(s) FAILED`);
  process.exit(1);
}
console.log("\nPUBLISH-CHANNEL VECTORS PASS");
