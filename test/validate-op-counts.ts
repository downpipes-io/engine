// Validate the per-run Cloudflare operation tally (cost Phase 3): the meter's tagged spend, the
// SliceBudget accumulation, and the pure OpCounts helpers. This is the data the cost estimate's platform
// ledger ("cost to run the backup") consumes, so its arithmetic is pinned here. No network, no seal.
// Run: node test/validate-op-counts.ts

import { SliceBudget } from "../src/seal/budget.ts";
import { zeroOpCounts, addOpCounts, type OpCounts } from "../src/meter.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

function main(): void {
  // zeroOpCounts is all-zero.
  const z = zeroOpCounts();
  ok("zeroOpCounts is all zero", z.kvRead === 0 && z.r2ClassA === 0 && z.r2ClassB === 0 && z.d1Read === 0 && z.cfApiRead === 0 && z.secretsRead === 0 && z.kvList === 0 && z.subrequests === 0);

  // A tagged spend lands on its resource AND the subrequest total; an untagged spend lands ONLY on the
  // total (so the total is always the true subrequest count, the per-resource fields a refinement).
  const b = new SliceBudget({ subrequests: 1000 });
  b.spend(1, "kvRead");
  b.spend(1, "kvRead");
  b.spend(3, "r2ClassA"); // n>1 (e.g. a batch) adds n
  b.spend(1, "r2ClassB");
  b.spend(2); // untagged: total only
  const c = b.opCounts();
  ok("tagged spends accumulate per resource", c.kvRead === 2 && c.r2ClassA === 3 && c.r2ClassB === 1);
  ok("subrequest total counts every spend (tagged + untagged)", c.subrequests === 1 + 1 + 3 + 1 + 2);
  ok("subrequestsSpent matches the budget counter", b.subrequestsSpent === 8);
  ok("an untouched resource stays zero (never a guess)", c.d1Read === 0 && c.secretsRead === 0 && c.cfApiRead === 0 && c.kvList === 0);
  ok("opCounts() returns a copy (caller cannot mutate the live tally)", ((): boolean => { c.kvRead = 999; return b.opCounts().kvRead === 2; })());

  // addOpCounts is the element-wise sum the slice uses to fold a slice's ops into the run total.
  const a1: OpCounts = { kvRead: 5, kvList: 1, r2ClassA: 2, r2ClassB: 4, d1Read: 0, cfApiRead: 7, secretsRead: 0, subrequests: 19 };
  const a2: OpCounts = { kvRead: 3, kvList: 0, r2ClassA: 8, r2ClassB: 1, d1Read: 6, cfApiRead: 0, secretsRead: 2, subrequests: 20 };
  const sum = addOpCounts(a1, a2);
  ok("addOpCounts sums every field", sum.kvRead === 8 && sum.kvList === 1 && sum.r2ClassA === 10 && sum.r2ClassB === 5 && sum.d1Read === 6 && sum.cfApiRead === 7 && sum.secretsRead === 2 && sum.subrequests === 39);
  ok("addOpCounts is pure (operands unchanged)", a1.kvRead === 5 && a2.r2ClassA === 8);
  ok("zero is the additive identity", JSON.stringify(addOpCounts(a1, zeroOpCounts())) === JSON.stringify(a1));

  console.log(failures === 0 ? "\nALL OP-COUNT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
