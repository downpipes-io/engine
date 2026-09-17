// FIXTURE: a run that printed plenty and asserted nothing. The weak floor ("wrote nothing to stdout")
// passes this, because it wrote a header and a section title. The assertion-line floor does not: a
// validator that asserted nothing did not pass, it abstained.
import { verdictReached } from "../verdict-guard.ts";
console.log("abstained fixture: setting up");
console.log("section 1: the part that would have asserted something");
console.log("\nABSTAINED FIXTURE PASS");
verdictReached(0);
