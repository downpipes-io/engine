// FIXTURE: the measured class. Two assertions fail, then an await never settles, the loop drains and
// the tally is never reached. Without the guard this exits 0 with FAIL lines printed.
import { verdictReached } from "../verdict-guard.ts";
let failures = 0;
const ok = (l: string, c: boolean): void => { console.log(`  ${c ? "ok  " : "FAIL"} ${l}`); if (!c) failures++; };
async function main(): Promise<void> {
  ok("an assertion that fails", false);
  ok("another that fails", false);
  await new Promise<void>(() => {});
  console.log(failures === 0 ? "\nDRAIN FIXTURE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
