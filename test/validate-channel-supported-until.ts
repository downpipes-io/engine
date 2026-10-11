// Vectors for the support window of a release (src/admin/update-support.ts, docs/SUPPORTED-VERSIONS.md).
// The rule: a fix ships only in the next release. A release is supported until 90 days after its successor
// ships. supportedUntil(R) = releasedAt(successor of R) + 90 days. The latest release has no supportedUntil.
// Every date comes from the signed channel's `releases` map (version -> releasedAt); no date is typed by hand.
//   (a) a successor released at SUCCESSOR_AT gives supportedUntil UNTIL; the status is "supported" 31 days
//       before, "ending" 30 days before and on the day, and "end-of-life" the day after;
//   (b) the successor is the lowest later version in semver order, not the newest and not a string order;
//   (c) the running version with no later release has no supportedUntil and is "supported";
//   (d) the dates are inside the signature: a changed date fails verification;
//   (e) backward compatibility: a channel WITHOUT the map gives neither field and keeps every other field,
//       and the legacy reading path (artefacts.find on recommendedVersion) still selects the artefact;
//   (f) a malformed map, key or date never fails the channel: the engine reports no date;
//   (g) the publisher carries earlier release dates forward, adds the new release's own date from the
//       publish run, and never moves a date it already holds;
//   (h) the publisher refuses every date input: a support date, and --released-at or a meta-file releasedAt;
//   (i) a publish needs --previous-channel, or --first-release for the very first channel.
// Run: node test/validate-channel-supported-until.ts

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { verifyChannel, checkUpdates } from "../src/admin/updates.ts";
import { supportFor } from "../src/admin/update-support.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import { parseVerifier } from "../src/crypto/keys.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { concat, utf8, b64urlDecode, b64urlEncode } from "../src/crypto/bytes.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const TOOL = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "tools", "publish-channel.mjs");
const ENGINE_URL = "https://update.downpipes.io/engine-9.9.0.mjs";
const DAY = 24 * 60 * 60 * 1000;
const [MAJOR, MINOR, PATCH] = ENGINE_VERSION.split(".").map(Number) as [number, number, number];
const NEXT = `${MAJOR}.${MINOR}.${PATCH + 1}`;
const AFTER = `${MAJOR}.${MINOR}.${PATCH + 2}`;
const SUCCESSOR_AT = "2026-10-05T00:00:00.000Z";
const UNTIL = "2027-01-03T00:00:00.000Z";
const UNTIL_MS = Date.parse(UNTIL);

async function main(): Promise<void> {
  const edSeed = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSeed);
  const edPrivate = await crypto.subtle.importKey(
    "pkcs8",
    concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), edSeed),
    "Ed25519",
    false,
    ["sign"],
  );
  const mldsa = mldsaKeygen();
  const signer = { ed: edPublic, mldsa: mldsa.publicKey };
  const env = { UPDATE_CHANNEL_URL: "https://update.downpipes.io/stable.json", UPDATE_SIGNER_PUBLIC: b64urlEncode(concat(edPublic, new Uint8Array(mldsa.publicKey))) } as never;
  const artefacts = [{ version: "9.9.0", url: ENGINE_URL, sha384: "a".repeat(96), riskClass: "routine", releasedAt: "2026-09-01T00:00:00Z" }];

  // signed returns the bytes, the signature and a fetch stub that serves both, for one channel document.
  const signed = async (doc: unknown) => {
    const bytes = utf8(JSON.stringify(doc));
    const sig = await hybridSign(edPrivate, mldsa.secretKey, bytes);
    const fetchUrl = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(`${b64urlEncode(sig)}\n`) : bytes);
    return { bytes, sig, fetchUrl };
  };

  // ---- (a) a successor released at SUCCESSOR_AT ends support at UNTIL; the status follows the clock ----
  const releases = { [ENGINE_VERSION]: "2026-08-01T00:00:00.000Z", [NEXT]: SUCCESSOR_AT };
  const withMap = { channel: "stable", recommendedVersion: "9.9.0", artefacts, releases };
  const a = await signed(withMap);
  const parsedA = await verifyChannel(a.bytes, a.sig, signer);
  ok("(a) verifyChannel accepts a channel that carries releases", parsedA !== null);
  ok("(a) the parsed channel keeps the map as signed", JSON.stringify(parsedA?.releases) === JSON.stringify(releases));
  const at = async (nowMs: number) => checkUpdates(env, a.fetchUrl, () => nowMs);
  const s31 = await at(UNTIL_MS - 31 * DAY);
  ok(`(a) a successor released ${SUCCESSOR_AT} gives supportedUntil ${UNTIL}`, s31.verified === true && s31.supportedUntil === UNTIL);
  ok("(a) 31 days before supportedUntil the status is supported", s31.supportStatus === "supported");
  const s30 = await at(UNTIL_MS - 30 * DAY);
  ok("(a) 30 days before supportedUntil the status is ending", s30.supportStatus === "ending" && s30.supportedUntil === UNTIL);
  const s0 = await at(UNTIL_MS);
  ok("(a) at supportedUntil the status is still ending", s0.supportStatus === "ending");
  const s1 = await at(UNTIL_MS + DAY);
  ok("(a) the day after supportedUntil the status is end-of-life", s1.supportStatus === "end-of-life" && s1.supportedUntil === UNTIL);

  // ---- (b) the successor is the lowest later version in semver order ----
  const v = (running: string, map: Record<string, string>, now: number) => supportFor(map, running, now);
  const order = { "0.3.7": "2026-01-01T00:00:00Z", "0.4.0": "2026-12-01T00:00:00Z", "0.3.10": SUCCESSOR_AT, "0.3.9": "2026-10-20T00:00:00Z" };
  ok("(b) 0.3.7 takes 0.3.9 as its successor, not 0.3.10 (numeric order) and not 0.4.0", v("0.3.7", order, 0)?.supportedUntil === "2027-01-18T00:00:00.000Z");
  ok("(b) a running version the map does not list still finds its successor", v("0.3.8", order, 0)?.supportedUntil === "2027-01-18T00:00:00.000Z");
  ok("(b) a pre-release running version reads as its release", v("0.3.7-rc.1", order, 0)?.supportedUntil === "2027-01-18T00:00:00.000Z");
  ok("(b) the date is the successor's date plus 90 days in UTC, across a month end", v("0.1.0", { "0.1.1": "2026-12-02T23:30:00Z" }, 0)?.supportedUntil === "2027-03-02T23:30:00.000Z");

  // ---- (c) no successor: no date, supported ----
  const latest = v(ENGINE_VERSION, { [ENGINE_VERSION]: "2026-08-01T00:00:00Z", "0.0.1": "2025-01-01T00:00:00Z" }, UNTIL_MS + 400 * DAY);
  ok("(c) the latest release has no supportedUntil and is supported, however late the clock", latest !== undefined && !("supportedUntil" in latest) && latest.supportStatus === "supported");
  const b = await signed({ ...withMap, releases: { [ENGINE_VERSION]: "2026-08-01T00:00:00Z" } });
  const statusB = await checkUpdates(env, b.fetchUrl, () => UNTIL_MS + DAY);
  ok("(c) checkUpdates reports supportStatus supported and no supportedUntil for the latest release", statusB.verified === true && statusB.supportStatus === "supported" && !("supportedUntil" in statusB));

  // ---- (d) the dates are covered by the signature ----
  const tampered = utf8(JSON.stringify({ ...withMap, releases: { ...releases, [NEXT]: "2099-01-01T00:00:00.000Z" } }));
  ok("(d) a changed release date fails signature verification", (await verifyChannel(tampered, a.sig, signer)) === null);

  // ---- (e) absent map: old documents are unchanged, old readers ignore the new field ----
  const legacy = { channel: "stable", recommendedVersion: "9.9.0", artefacts };
  const d = await signed(legacy);
  const statusD = await checkUpdates(env, d.fetchUrl);
  ok("(e) a channel without releases verifies and reports neither field", statusD.verified === true && !("supportedUntil" in statusD) && !("supportStatus" in statusD));
  const { supportedUntil: _u, supportStatus: _s, ...statusAWithoutSupport } = s31;
  ok("(e) the map changes no other status field", JSON.stringify(statusAWithoutSupport) === JSON.stringify(statusD));
  ok("(e) the legacy selection still picks the artefact from a channel with the map", parsedA?.artefacts?.find((x) => x.version === parsedA.recommendedVersion)?.url === ENGINE_URL);

  // ---- (f) malformed input never fails the channel ----
  for (const [label, bad] of [
    ["the map is a list", [[NEXT, SUCCESSOR_AT]]],
    ["the map is a string", SUCCESSOR_AT],
    ["the date is not a calendar day", { [NEXT]: "2026-02-30T00:00:00Z" }],
    ["the date has no time", { [NEXT]: "2026-10-05" }],
    ["the date is not RFC-3339", { [NEXT]: "05/10/2026" }],
    ["the date is a number", { [NEXT]: 1790000000 }],
    ["the key is not a version", { latest: SUCCESSOR_AT }],
  ] as const) {
    const e = await signed({ ...legacy, releases: bad });
    const s = await checkUpdates(env, e.fetchUrl, () => UNTIL_MS);
    ok(`(f) ${label}: the channel still verifies and gives no supportedUntil`, s.verified === true && s.recommendedVersion === "9.9.0" && !("supportedUntil" in s));
  }
  ok("(f) a later release with a malformed date gives no view at all", supportFor({ [NEXT]: "soon", [AFTER]: SUCCESSOR_AT }, ENGINE_VERSION, 0) === undefined);
  ok("(f) a malformed date on an earlier release does not hide the successor", supportFor({ "0.0.1": "soon", [NEXT]: SUCCESSOR_AT }, ENGINE_VERSION, 0)?.supportedUntil === UNTIL);

  // ---- (g) the publisher carries dates forward and takes no support date ----
  const dir = mkdtempSync(path.join(tmpdir(), "supported-until-"));
  try {
    const keyPath = path.join(dir, "release-signer.key");
    const pub = (extra: string[]): { status: number; out: string; err: string } => {
      try {
        const out = execFileSync("node", [TOOL, "--allow-unsequenced", "--key-file", keyPath, ...extra], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
        return { status: 0, out, err: "" };
      } catch (e) {
        const x = e as { status?: number; stdout?: string; stderr?: string };
        return { status: x.status ?? 1, out: String(x.stdout ?? ""), err: String(x.stderr ?? "") };
      }
    };
    const out = (n: number) => ({ out: path.join(dir, `c${n}.json`), sig: path.join(dir, `c${n}.json.sig`) });
    const step = (version: string, n: number, prev: number | null, extra: string[] = []) => {
      const o = out(n);
      return pub(["--version", version, ...(prev === null ? ["--first-release"] : ["--previous-channel", out(prev).out]), ...extra, "--out", o.out, "--out-sig", o.sig]);
    };
    const bootStart = Date.now();
    const boot0 = execFileSync("node", [TOOL, "--allow-unsequenced", "--first-release", "--version", "0.0.1", "--out-key", keyPath, "--out", out(1).out, "--out-sig", out(1).sig], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const bootEnd = Date.now();
    const signerPub = parseVerifier(b64urlDecode((JSON.parse(boot0) as { updateSignerPublic: string }).updateSignerPublic));
    const firstMap = (JSON.parse((JSON.parse(boot0) as { channel: string }).channel) as { releases: Record<string, string> }).releases;
    const firstAt = Date.parse(firstMap["0.0.1"] ?? "");
    ok("(g) a first publish carries its own release date, taken from the publish run", Object.keys(firstMap).join() === "0.0.1" && firstAt >= bootStart && firstAt <= bootEnd);

    const parse = async (r: { status: number; out: string }) => (r.status === 0 ? await verifyChannel(utf8((JSON.parse(r.out) as { channel: string }).channel), b64urlDecode((JSON.parse(r.out) as { signature: string }).signature), signerPub) : null);
    const t2 = Date.now();
    const parsed2 = await parse(step("0.0.2", 2, 1));
    const t2e = Date.now();
    const at2 = Date.parse(parsed2?.releases?.["0.0.2"] ?? "");
    ok("(g) the next publish carries the earlier date forward unchanged and adds its own, inside the signed body", Object.keys(parsed2?.releases ?? {}).join() === "0.0.1,0.0.2" && parsed2?.releases?.["0.0.1"] === firstMap["0.0.1"] && at2 >= t2 && at2 <= t2e);

    const parsed3 = await parse(step("0.0.3", 3, 2));
    ok("(g) the map keeps growing: three releases after three publishes", Object.keys(parsed3?.releases ?? {}).join() === "0.0.1,0.0.2,0.0.3");
    ok("(g) the map gives 0.0.1 a support end of 90 days after 0.0.2", supportFor(parsed3?.releases, "0.0.1", 0)?.supportedUntil === new Date(at2 + 90 * DAY).toISOString());

    await new Promise((r) => setTimeout(r, 5));
    const parsed4 = await parse(step("0.0.2", 4, 3));
    ok("(g) a release already in the map keeps its first date", parsed4?.releases?.["0.0.2"] === parsed2?.releases?.["0.0.2"]);

    const withNow = await parse(step("0.0.5", 5, 3, ["--released-now"]));
    const art = (withNow as unknown as { artefacts: { releasedAt?: string }[] } | null)?.artefacts?.[0]?.releasedAt;
    ok("(g) with --released-now the artefact's releasedAt and the map entry are the same value", art !== undefined && withNow?.releases?.["0.0.5"] === art);

    const wrongKey = JSON.parse(execFileSync("node", [TOOL, "--allow-unsequenced", "--first-release", "--version", "0.0.9"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })) as { channel: string; signature: string };
    writeFileSync(path.join(dir, "foreign.json"), wrongKey.channel);
    writeFileSync(path.join(dir, "foreign.json.sig"), `${wrongKey.signature}\n`);
    const foreign = pub(["--version", "0.0.4", "--previous-channel", path.join(dir, "foreign.json")]);
    ok("(g) a previous channel the signer did not sign is refused before anything is signed", foreign.status !== 0 && foreign.out === "" && foreign.err.includes("--previous-channel"));

    for (const [label, extra] of [
      ["--supported-until", ["--supported-until", "0.0=2027-01-31"]],
      ["--supported-versions", ["--supported-versions", "0.0=2027-01-31"]],
      ["--supported-until=value", ["--supported-until=0.0=2027-01-31"]],
    ] as const) {
      const r = pub(["--version", "0.0.4", ...extra]);
      ok(`(g) the publisher refuses ${label}: there is no input for a support date`, r.status !== 0 && r.out === "" && r.err.includes("support"));
    }
    const metaPath = path.join(dir, "meta.json");
    for (const key of ["supportedVersions", "supportedUntil", "releases"]) {
      writeFileSync(metaPath, JSON.stringify({ [key]: [{ version: "0.0", supportedUntil: "2027-01-31" }] }));
      const r = pub(["--version", "0.0.4", "--meta-file", metaPath]);
      ok(`(g) the publisher refuses ${key} in the meta file`, r.status !== 0 && r.out === "" && r.err.includes("support"));
    }

    // ---- (h) no hand-typed release date; (i) a map needs its previous channel, or an explicit --first-release ----
    const handDate = pub(["--version", "0.0.4", "--first-release", "--released-at", "2026-01-01T00:00:00.000Z"]);
    ok("(h) the publisher refuses --released-at: the release date comes from the publish run", handDate.status !== 0 && handDate.out === "" && handDate.err.includes("--released-at"));
    const handBare = pub(["--version", "0.0.4", "--first-release", "--released-at"]);
    ok("(h) the publisher refuses a bare --released-at too", handBare.status !== 0 && handBare.out === "" && handBare.err.includes("--released-at"));
    writeFileSync(metaPath, JSON.stringify({ releasedAt: "2026-01-01T00:00:00.000Z" }));
    const handMeta = pub(["--version", "0.0.4", "--first-release", "--meta-file", metaPath]);
    ok("(h) the publisher refuses releasedAt in the meta file", handMeta.status !== 0 && handMeta.out === "" && handMeta.err.includes("releasedAt"));
    const noPrev = pub(["--version", "0.0.4"]);
    ok("(i) without --previous-channel or --first-release the publisher refuses before signing", noPrev.status !== 0 && noPrev.out === "" && noPrev.err.includes("--previous-channel") && noPrev.err.includes("--first-release"));
    const both = pub(["--version", "0.0.4", "--first-release", "--previous-channel", out(1).out]);
    ok("(i) --first-release with --previous-channel is refused", both.status !== 0 && both.out === "" && both.err.includes("--first-release"));
    const firstOk = pub(["--version", "0.0.4", "--first-release"]);
    ok("(i) --first-release signs a channel whose map holds only this release", firstOk.status === 0 && Object.keys((JSON.parse((JSON.parse(firstOk.out) as { channel: string }).channel) as { releases: object }).releases).join() === "0.0.4");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log(failures === 0 ? "\nCHANNEL SUPPORTED-UNTIL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
