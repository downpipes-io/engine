// FIXTURE: a process.exit(0) before the tally. Node honours process.exitCode assigned inside an "exit"
// listener even after an explicit exit(0), which is what lets one hook cover this shape too.
// biome-ignore lint/correctness/noUnusedImports: process.exit(0) fires before the tally, so verdictReached is deliberately never reached and `failures` is deliberately never read: that unreached tally IS the fixture.
import { verdictReached } from "../verdict-guard.ts";
// biome-ignore lint/correctness/noUnusedVariables: see the note on the import above.
let failures = 0;
const ok = (l: string, c: boolean): void => { console.log(`  ${c ? "ok  " : "FAIL"} ${l}`); if (!c) failures++; };
async function main(): Promise<void> {
  ok("an assertion that fails", false);
  process.exit(0);
}
main().catch((e) => { console.error(e); process.exit(1); });
