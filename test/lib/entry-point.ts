// True when this module is the one node was invoked with directly (the ESM equivalent of
// `require.main === module`), so a file can both export testable functions and run itself when
// executed directly. Compares realpaths rather than raw strings: node resolves import.meta.url
// through a symlink, while process.argv[1] stays exactly as the caller typed it.
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function isEntryPoint(importMetaUrl: string): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(importMetaUrl)) === realpathSync(argv1);
  } catch {
    return false;
  }
}
