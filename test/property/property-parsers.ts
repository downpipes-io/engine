// Entry point for the parser fuzz and property suite. It runs the archive, identity-provider and
// update-channel groups in turn under fixed seeds and bounded run counts, then prints one verdict.
// Run: node test/property/property-parsers.ts   (or: npm run test:property)
import { verdictReached } from "../lib/verdict-guard.ts";
import { tally } from "./parser-fuzz-lib.ts";
import { runArchiveProperties } from "./property-parsers-archive.ts";
import { runIdpProperties } from "./property-parsers-idp.ts";
import { runUpdateProperties } from "./property-parsers-update.ts";

await runArchiveProperties();
await runUpdateProperties();
await runIdpProperties();

const { failures, total, known } = tally();
verdictReached(failures);
console.log(`\n${total} properties, ${known} known-failing, ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
