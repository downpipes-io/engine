// Foreign-key dependency extraction for the D1 table-subset restore lint. A D1 backup header carries
// each table's verbatim CREATE TABLE text (d1-format.ts D1TableDDL.sql); a table's FK parents are the
// tables named after each REFERENCES keyword. This module is PURE -- string DDL in, structure out. It
// takes no D1 handle and reads/writes nothing, so it is a read-only advisory over an already-verified
// header, never a gate on the restore.
//
// Why advisory, not a gate: a D1 restore replays CREATE TABLE for every table up front and inserts
// rows in creation order with FK enforcement OFF (the sink issues no PRAGMA foreign_keys=ON), so a
// child row whose parent table exists-but-empty still inserts. The lint therefore does not block a
// restore; it tells the operator, BEFORE they confirm, that a chosen subset would leave a selected
// child table's references dangling because its parent's rows were not selected.
//
// SCOPE OF THIS MODULE: it is a STRUCTURAL check (does a selected child reference an unselected table
// in the backup?). It knows nothing about which tables actually hold rows -- an empty parent is
// structurally a table like any other. The CALLER (restore-plan.ts computeD1DependencyWarnings)
// refines the structural result with data presence: it drops a warning whose parent has no rows in
// the backup (dropping an empty parent leaves nothing to dangle) and skips a whole-database restore
// entirely (nothing is out of scope). Keeping data presence in the caller keeps this module pure.
//
// SQLite FK grammar covered: column-level ("col TYPE REFERENCES parent(col)" or a bare
// "... REFERENCES parent") and table-level ("FOREIGN KEY (cols) REFERENCES parent (cols)"), with the
// parent identifier written any of the four SQLite ways (bare, "double", `backtick`, [bracket]), and
// with or without a space before a QUOTED parent (SQLite accepts REFERENCES"users"). SQL line/block
// comments and single-quoted string literals are stripped before matching, so the word REFERENCES
// inside a comment or a DEFAULT/CHECK string does not invent a false parent. A self-reference (a table
// whose FK targets itself) is never a missing dependency and is dropped.
//
// Identifier comparison uses JS toLowerCase (full-Unicode case folding). SQLite folds only ASCII for
// unquoted identifiers, so toLowerCase is a SUPERSET: at worst two identifiers differing solely by
// non-ASCII case are treated as equal here but distinct by SQLite. Table names are ASCII in practice,
// so this is immaterial, and the lint is advisory regardless.

// stripSqlNoise blanks the parts of a CREATE TABLE statement where the word REFERENCES cannot denote a
// real FK -- SQL comments and single-quoted string literals (DEFAULT/CHECK text) -- so the REFERENCES
// scan never invents a parent from them. It is ONE context-aware pass, NOT independent regex strips:
// stripping comments and strings separately mis-handles a '--' inside a string, or a quote inside a
// comment (each context can hide the other's delimiter), which silently drops a real FK on the same
// line. The scanner dispatches on the character it is on: a -- line comment, a /* */ block comment, a
// '...' string literal ('' escapes a quote; collapsed to an empty literal), and the three IDENTIFIER
// quotings "..."/`...`/[...] which are PRESERVED VERBATIM -- a parent table name may be a quoted
// identifier, and a ' or -- INSIDE the quotes is part of the name, not a string or a comment.
// Everything else passes through. sqlite_master DDL is well-formed, so this is a correctness aid for the
// advisory scan, not a security boundary (the bytes already passed the archive plaintext hash).
function stripSqlNoise(sql: string): string {
  let out = "";
  const n = sql.length;
  let i = 0;
  while (i < n) {
    const c = sql[i]!;
    const c2 = i + 1 < n ? sql[i + 1] : "";
    if (c === "-" && c2 === "-") {
      i += 2;
      while (i < n && sql[i] !== "\n") i++;
      out += " ";
    } else if (c === "/" && c2 === "*") {
      i += 2;
      while (i < n && !(sql[i] === "*" && sql[i + 1] === "/")) i++;
      i += 2; // consume the closing */ (harmless to overshoot on an unterminated comment)
      out += " ";
    } else if (c === "'") {
      i++; // a single-quoted string literal; '' is an escaped quote, not a terminator
      while (i < n) {
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      out += "''";
    } else if (c === '"' || c === "`") {
      // "double" / `backtick` identifier: preserve verbatim (a doubled quote escapes one).
      out += c;
      i++;
      while (i < n) {
        out += sql[i];
        if (sql[i] === c) {
          if (sql[i + 1] === c) { out += sql[i + 1]!; i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
    } else if (c === "[") {
      // [bracket] identifier: preserve verbatim (ends at the first ]; SQLite brackets have no escape).
      out += c;
      i++;
      while (i < n) {
        out += sql[i];
        if (sql[i] === "]") { i++; break; }
        i++;
      }
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

// unquoteIdent strips the four SQLite identifier quotings and unescapes the doubled-quote forms, so a
// parent name parsed out of the DDL compares equal to the same table's name however either was spelt.
function unquoteIdent(raw: string): string {
  const s = raw.trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1).replace(/""/g, '"');
  if (s.length >= 2 && s.startsWith("`") && s.endsWith("`")) return s.slice(1, -1).replace(/``/g, "`");
  if (s.length >= 2 && s.startsWith("[") && s.endsWith("]")) return s.slice(1, -1);
  return s;
}

// REFERENCES_RE matches one REFERENCES clause and captures the parent identifier in whichever of the
// four quotings it appears. After the keyword the parent is preceded EITHER by one-or-more spaces (any
// form) OR by zero spaces when the next char opens a quoting (SQLite accepts REFERENCES"users"); the
// bare-identifier branch is only reachable through the \s+ arm, so REFERENCESusers (one token) never
// matches. \b anchors the keyword as a word.
const REFERENCES_RE = /\bREFERENCES(?:\s+|(?=["`[]))("(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|[A-Za-z_-￿][A-Za-z0-9_$-￿]*)/gi;

// extractForeignKeys returns the DISTINCT parent table names the FK constraints in one CREATE TABLE
// statement reference. When selfName is supplied a self-reference to that table is dropped (a table
// that references itself needs no OTHER table). Dedup is case-insensitive; the first-seen spelling is
// returned for display.
export function extractForeignKeys(createTableSql: string, selfName?: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const selfLc = selfName?.toLowerCase();
  for (const m of stripSqlNoise(createTableSql).matchAll(REFERENCES_RE)) {
    const parent = unquoteIdent(m[1]!);
    const lc = parent.toLowerCase();
    if (lc === selfLc || seen.has(lc)) continue;
    seen.add(lc);
    out.push(parent);
  }
  return out;
}

// D1FkWarning is one "selected child, unselected parent" finding: the child table that is in the
// restore scope and the FK parent that is present in the backup but NOT in the scope.
export interface D1FkWarning {
  table: string;
  missingParent: string;
}

// d1DdlTokens tokenizes a CREATE statement into bare words and quoted identifiers (already unquoted),
// skipping whitespace, comments, string literals and punctuation (a dot is kept, to read a schema.table
// qualifier). A quoted identifier ("..."/`...`/[...]) is ONE token, so a keyword-looking word INSIDE a
// quoted object name (an index literally named "customers on file", say) is opaque and never matches a
// keyword. That is what lets d1SchemaTargetTable find the STRUCTURAL keywords, not ones buried in a name.
function d1DdlTokens(sql: string): Array<{ text: string; quoted: boolean }> {
  const out: Array<{ text: string; quoted: boolean }> = [];
  const n = sql.length;
  let i = 0;
  while (i < n) {
    const c = sql[i]!;
    if (c === "-" && sql[i + 1] === "-") {
      i += 2;
      while (i < n && sql[i] !== "\n") i++;
    } else if (c === "/" && sql[i + 1] === "*") {
      i += 2;
      while (i < n && !(sql[i] === "*" && sql[i + 1] === "/")) i++;
      i += 2;
    } else if (c === "'") {
      i++;
      while (i < n) {
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
    } else if (c === '"' || c === "`") {
      i++;
      let s = "";
      while (i < n) {
        if (sql[i] === c) {
          if (sql[i + 1] === c) { s += c; i += 2; continue; }
          i++;
          break;
        }
        s += sql[i]!;
        i++;
      }
      out.push({ text: s, quoted: true });
    } else if (c === "[") {
      i++;
      let s = "";
      while (i < n && sql[i] !== "]") { s += sql[i]!; i++; }
      i++;
      out.push({ text: s, quoted: true });
    } else if (/[A-Za-z_-￿]/.test(c)) {
      // A bare (unquoted) identifier. SQLite allows any character >= 0x80 in an unquoted identifier, so
      // the class includes non-ASCII (a table literally named cafe with an accent tokenizes whole, not
      // truncated at the accent -- which under createOnly would otherwise silently drop its index).
      let s = "";
      while (i < n && /[A-Za-z0-9_$-￿]/.test(sql[i]!)) { s += sql[i]!; i++; }
      out.push({ text: s, quoted: false });
    } else if (c === ".") {
      out.push({ text: ".", quoted: false });
      i++;
    } else {
      i++;
    }
  }
  return out;
}

// d1SchemaTargetTable returns the table a non-table schema object is DEFINED ON: the table after the
// STRUCTURAL ON of a CREATE INDEX or CREATE TRIGGER. A CREATE VIEW (or anything else) has no defining
// ON-table -- a view's dependencies live in its SELECT, which SQLite resolves lazily -- so it returns
// null and is kept unconditionally. Used by the createOnly D1 table-subset restore to drop the
// indexes/triggers of tables that are NOT being created (applying such an object would error on the
// missing table). It tokenizes (quoted identifiers opaque; comments/strings skipped) and reads the FIRST
// structural ON after the object-type keyword, so a quoted NAME containing the word "on", a trigger body
// with its own ON, and the zero-space form ON"tbl" are all handled. An optional schema qualifier
// (schema.table) resolves to the table.
export function d1SchemaTargetTable(sql: string): string | null {
  const toks = d1DdlTokens(sql);
  let type: string | null = null;
  let onIdx = -1;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.quoted) continue; // a quoted NAME is opaque: its inner words never match a keyword
    const lc = t.text.toLowerCase();
    if (type === null && (lc === "index" || lc === "trigger" || lc === "view" || lc === "table")) {
      type = lc;
      continue;
    }
    if (type !== null && lc === "on") {
      onIdx = i;
      break;
    }
  }
  if (type !== "index" && type !== "trigger") return null; // view / table / unknown: no defining ON-table
  if (onIdx === -1 || onIdx + 1 >= toks.length || toks[onIdx + 1]!.text === ".") return null;
  // schema.table -> the table component; otherwise the identifier straight after ON.
  if (onIdx + 3 < toks.length && toks[onIdx + 2]!.text === "." && toks[onIdx + 3]!.text !== ".") return toks[onIdx + 3]!.text;
  return toks[onIdx + 1]!.text;
}

// d1DependencyWarnings reports, for a chosen subset of a database's tables, every SELECTED child table
// whose FK parent is a real table in the backup but is NOT itself selected. It warns ONLY for parents
// that exist in the backup: a reference to a table absent from the backup is pre-existing DB state, not
// a selection mistake, so it is not flagged. `tables` is the header's full table set ({name, sql});
// `selected` is the subset of table names the restore scope will populate. This is a STRUCTURAL result
// (it does not know which parents hold rows) -- the caller filters out empty parents. The returned
// parent name is the backup's own spelling of the table, so it reads consistently with the rest of the
// plan.
export function d1DependencyWarnings(
  tables: ReadonlyArray<{ name: string; sql: string }>,
  selected: Iterable<string>,
): D1FkWarning[] {
  const selectedLc = new Set<string>();
  for (const name of selected) selectedLc.add(name.toLowerCase());
  const canonicalByLc = new Map<string, string>();
  for (const t of tables) canonicalByLc.set(t.name.toLowerCase(), t.name);
  const warnings: D1FkWarning[] = [];
  const emitted = new Set<string>();
  for (const t of tables) {
    if (!selectedLc.has(t.name.toLowerCase())) continue; // only a SELECTED child can be missing a parent
    for (const parent of extractForeignKeys(t.sql, t.name)) {
      const parentLc = parent.toLowerCase();
      const canonical = canonicalByLc.get(parentLc);
      if (canonical === undefined) continue; // parent not in the backup: not a selection issue
      if (selectedLc.has(parentLc)) continue; // parent selected too: fine
      const key = `${t.name.toLowerCase()} ${parentLc}`;
      if (emitted.has(key)) continue;
      emitted.add(key);
      warnings.push({ table: t.name, missingParent: canonical });
    }
  }
  return warnings;
}
