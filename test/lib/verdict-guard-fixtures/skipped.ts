// FIXTURE: a declared skip. A precondition is genuinely absent, the skip is DECLARED rather than
// silent, and the exit stays 0 because some preconditions here are deliberately opt-in.
import { verdictSkipped } from "../verdict-guard.ts";
console.log("skip fixture: checking the precondition");
verdictSkipped("the precondition this fixture needs is absent");
