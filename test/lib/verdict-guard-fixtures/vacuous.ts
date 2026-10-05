// FIXTURE: nothing to check. A verdict declared over zero checks is not a pass.
import { verdictReached } from "../verdict-guard.ts";
console.log("vacuous fixture: ran no checks");
verdictReached(0, 0);
