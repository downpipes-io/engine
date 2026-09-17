// FIXTURE: an honest pass. Proves the guard is not always-red.
import { verdictReached } from "../verdict-guard.ts";
let failures = 0;
let checks = 0;
const ok = (l: string, c: boolean): void => { checks++; console.log(`  ${c ? "ok  " : "FAIL"} ${l}`); if (!c) failures++; };
async function main(): Promise<void> {
  ok("an assertion that holds", true);
  ok("another that holds", true);
  console.log(failures === 0 ? "\nPASS FIXTURE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
