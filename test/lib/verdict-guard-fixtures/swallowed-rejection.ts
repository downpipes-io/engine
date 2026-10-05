// FIXTURE: a rejection swallowed by an empty catch, so the tally is never reached and nothing is loud.
// biome-ignore lint/correctness/noUnusedImports: the throw is eaten by the empty .catch(), so verdictReached is deliberately never reached and `failures` is deliberately never read: that unreached tally IS the fixture.
import { verdictReached } from "../verdict-guard.ts";
// biome-ignore lint/correctness/noUnusedVariables: see the note on the import above.
let failures = 0;
const ok = (l: string, c: boolean): void => { console.log(`  ${c ? "ok  " : "FAIL"} ${l}`); if (!c) failures++; };
async function main(): Promise<void> {
  ok("an assertion that fails", false);
  throw new Error("something the run needed");
}
main().catch(() => {});
