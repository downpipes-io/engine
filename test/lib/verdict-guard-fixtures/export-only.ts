// FIXTURE: the shape of test/validate-notify-crud.ts before it was fixed. The file only EXPORTS its
// work, so run as its own step it prints nothing, checks nothing and exits 0.
import { verdictReached } from "../verdict-guard.ts";
export async function run(): Promise<void> {
  console.log("  ok   this never runs when the file is the entry point");
  verdictReached(0, 1);
}
