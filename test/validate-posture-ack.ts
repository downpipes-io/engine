// Validate the engine's key-posture acceptance statements. The load-bearing property: the engine's
// statement text hashes to the SAME pinned SHA-384 the CONSOLE pins (console/src/lib/posture-ack-
// statements.ts + console/test/validate-posture-ack.ts). The engine recomputes this hash at record
// time and writes it into the tamper-evident audit log, so pinning it here (and in the console) means
// a one-sided edit of either copy fails a gate on that side, keeping "what the customer read is what
// the engine recorded" true. If a statement is deliberately reworded, bump its version AND regenerate
// both repos' pinned hashes in the same change.
//
// Run with `node test/validate-posture-ack.ts`.

import {
  POSTURE_ACK_STATEMENTS,
  postureAckStatementHash,
  resolvePostureAckStatement,
  type PostureChoice,
} from "../src/admin/posture-ack-statements.ts";

// The cross-repo contract, pinned identically here and in console/src/lib/posture-ack-statements.ts.
const CANONICAL_HASH: Record<PostureChoice, string> = {
  operational: "sha384:cfe21b0797d478c437e7ffec790976ab2fd6301490793bb3d24e066802a81cf826807860323c63fe5ebeaeb058df98d7",
  "break-glass-only": "sha384:f006296ef4145c1ee54571194946c1ca5e755dee74b72a82d31036bb767cd381fd9ca34debe789cd89999c96f9c22e6b",
};

let failures = 0;
// This suite is SILENT ON PASS and writes its FAIL lines to stderr, so stdout alone cannot distinguish a
// thorough run from an empty one. Counting the checks and handing the count to the guard puts it on the
// canonical VERDICT line.
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) {
    failures++;
    console.error(`FAIL: ${label}`);
  }
}

// The CURRENT version per posture. They are independent (the offline statement is at v2, the operational
// at v1) and pinned per posture rather than asserted as one shared string, so a bump on either side is a
// deliberate edit here rather than something a loosened check would let through.
const CURRENT_VERSION: Record<PostureChoice, string> = {
  operational: "key-posture-ack/v1",
  "break-glass-only": "key-posture-ack/v2",
};

async function main(): Promise<void> {
  const postures: PostureChoice[] = ["operational", "break-glass-only"];
  for (const posture of postures) {
    const stmt = POSTURE_ACK_STATEMENTS[posture];
    ok(`${posture} statement carries its pinned version`, stmt.version === CURRENT_VERSION[posture]);
    const hash = await postureAckStatementHash(stmt.text);
    ok(`${posture} statement hashes to the pinned canonical value (cross-repo contract)`, hash === CANONICAL_HASH[posture]);
  }

  // resolvePostureAckStatement returns the current statement for a matching version and refuses a stale one.
  ok("resolvePostureAckStatement returns the current statement", resolvePostureAckStatement("operational", CURRENT_VERSION.operational) !== null);
  ok("and refuses the SUPERSEDED offline v1, so a stale console cannot record against retired words", resolvePostureAckStatement("break-glass-only", "key-posture-ack/v1") === null);
  ok("resolvePostureAckStatement refuses a stale version", resolvePostureAckStatement("operational", "key-posture-ack/v0") === null);

  // The statements RESTATE the specific residual inline (the liability-evidence requirement). Assert the
  // load-bearing phrases and the factual correction (Worker secret, not "Secrets Store").
  const op = POSTURE_ACK_STATEMENTS.operational.text;
  ok("operational statement names the in-account decryption-capable key", op.includes("in my own Cloudflare account") && op.includes("decrypt my stored archives"));
  ok("operational statement names the compromise + malicious-update residual", op.includes("Cloudflare account is compromised") && op.includes("malicious platform update"));
  ok("operational statement does not mis-call the key a Secrets Store binding", !op.toLowerCase().includes("secrets store"));
  const bg = POSTURE_ACK_STATEMENTS["break-glass-only"].text;
  ok("offline statement states the engine holds no decrypting key", bg.includes("no key that can decrypt my stored archives"));
  ok("offline statement names the manual-proof duty and key-loss consequence", bg.includes("attended verification") && bg.includes("cannot be recovered"));
  // The v2 correction, asserted in both directions. v1 listed in-console restore among the things that do
  // not run, which stopped being true when restore learned to open a run from a browser-supplied per-run
  // master (admin/restore.ts refuses only when there is NEITHER an operational key NOR a supplied master).
  // Asserting only the new sentence would still pass if the old claim were left beside it.
  ok("offline statement says in-console restore still works, attended", bg.includes("Restoring from the console still works with me present"));
  ok("and no longer claims in-console restore stops in this posture", !bg.includes("in-console restore"));
  ok("offline statement still names what genuinely stops", bg.includes("Scheduled restore tests and retention pruning therefore do not run in my engine"));

  console.log(failures === 0 ? "\nPOSTURE-ACK (ENGINE) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
