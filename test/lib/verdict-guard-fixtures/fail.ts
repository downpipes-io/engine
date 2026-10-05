// FIXTURE: an honest failure. Proves the guard stays silent when the validator reports properly.
import { verdictReached } from "../verdict-guard.ts";
let failures = 0;
let checks = 0;
const ok = (l: string, c: boolean): void => { checks++; console.log(`  ${c ? "ok  " : "FAIL"} ${l}`); if (!c) failures++; };
async function main(): Promise<void> {
  ok("an assertion that holds", true);
  ok("an assertion that fails", false);
  console.log(failures === 0 ? "\nFAIL FIXTURE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
