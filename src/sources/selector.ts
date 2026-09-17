import type { Selector } from "./types.ts";

// inScope implements the SPEC 12.2 selector: a record is in scope when it matches at
// least one include prefix (an empty include list means everything) and no exclude
// prefix. Pure and deterministic, so it is unit-tested directly.
export function inScope(name: string, sel: Selector): boolean {
  const included = sel.include.length === 0 || sel.include.some((p) => name.startsWith(p));
  if (!included) return false;
  return !sel.exclude.some((p) => name.startsWith(p));
}

// selectorPrefixFault answers "is this pair of prefix lists one a caller could have meant", and returns
// the reason it is not, or null.
//
// THE ONE THAT PUTS EVERYTHING OUT OF SCOPE. Every string starts with the empty string, so a single ""
// in `exclude` makes the `some` above true for every record name: the selector excludes the whole
// source. A downpipe saved that way backs up NOTHING and reports a successful run, and a restore scoped
// that way plans zero writes and reports a successful restore. That is the worst shape a
// misconfiguration can take, because the honest signal a customer would act on (a failure) never appears.
//
// AND THE STRICTEST PARTY WAS THE ONE AN API CALLER BYPASSES. The console filters empty prefixes on its
// way in (splitPrefixes), so the screen could never produce this; the engine, which is the last line and
// the only one an API caller must pass, checked only that the fields were arrays, and an array of empty
// strings is an array. A validation that exists only in the client is not a validation, and the reachable
// route is the API that customer automation and the M2M estates use.
//
// REFUSED, NOT FILTERED. Dropping the empty element would make the two sides agree and would silently
// reinterpret the request; a caller who sent exclude: [""] meant something, and what they lack is the
// information that it excludes everything. The message says that rather than only that it is invalid.
// `include: [""]` is refused by the same rule even though it is harmless in effect (an empty include list
// already means everything): it is the same confusion, and one rule that covers both is easier to hold
// than two rules that differ on which field forgives it.
//
// Non-string elements are refused here too, for the same reason the empty string is: the array check
// bounds the container and says nothing about the contents, and String.prototype.startsWith coerces its
// argument, so a number in the list silently becomes a prefix nobody wrote.
export function selectorPrefixFault(include: readonly unknown[], exclude: readonly unknown[]): string | null {
  for (const [field, list] of [
    ["exclude", exclude],
    ["include", include],
  ] as const) {
    for (const p of list) {
      if (typeof p !== "string") return `${field} must contain only strings (a non-string entry is not a prefix)`;
      if (p === "") {
        return field === "exclude"
          ? 'exclude contains an empty prefix (""), which matches every record name and would put the whole source out of scope, so nothing would be backed up or restored; remove it, or give the prefix you meant'
          : 'include contains an empty prefix (""), which matches every record name; an empty include list already means everything, so remove the entry rather than sending one that says nothing';
      }
    }
  }
  return null;
}
