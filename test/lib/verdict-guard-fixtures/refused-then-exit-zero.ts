// FIXTURE: the guard's own worst failure mode. The verdict is declared, the guard REFUSES it (zero
// checks) and sets process.exitCode = 1, and then the validator calls process.exit(0), which overrides
// it. Until the guard tracked refusals separately and re-applied them in its exit listener, this printed
// "Forcing exit 1" and exited 0: the guard producing the exact false green it exists to stop.
//
// The other fixtures do not catch it. vacuous.ts declares a refused verdict too, but has no
// process.exit(0) after the call, so it passed for the wrong reason.
import { verdictReached } from "../verdict-guard.ts";
console.log("refused-then-exit-zero fixture: ran no assertions at all");
verdictReached(0, 0);
process.exit(0);
