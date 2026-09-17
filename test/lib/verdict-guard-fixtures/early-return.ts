// FIXTURE: an early return before the tally. main() resolves, the loop drains, exit 0, no verdict.
import { verdictReached } from "../verdict-guard.ts";
let failures = 0;
const ok = (l: string, c: boolean): void => { console.log(`  ${c ? "ok  " : "FAIL"} ${l}`); if (!c) failures++; };
async function main(): Promise<void> {
  ok("an assertion that fails", false);
  if (failures >= 0) return;
  console.log(failures === 0 ? "\nEARLY RETURN FIXTURE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
}
main().catch((e) => { console.error(e); process.exit(1); });
