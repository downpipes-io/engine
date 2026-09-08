// Unit tests for the D1 table-subset foreign-key lint (src/sources/d1-fk.ts). Pure functions, no
// archive, no D1: extractForeignKeys parses parent tables out of a CREATE TABLE statement across the
// SQLite FK grammar and the four identifier quotings; d1DependencyWarnings reports a SELECTED child
// whose FK parent is in the backup but not in the restore scope. Run:
//   node test/validate-d1-fk.ts

import { extractForeignKeys, d1DependencyWarnings, d1SchemaTargetTable } from "../src/sources/d1-fk.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function eqSet(a: string[], b: string[]): boolean {
  const A = [...a].sort();
  const B = [...b].sort();
  return A.length === B.length && A.every((x, i) => x === B[i]);
}

console.log("extractForeignKeys:");
ok("no FK -> empty", extractForeignKeys('CREATE TABLE "t" (id INTEGER PRIMARY KEY, name TEXT)').length === 0);
ok("inline column-level REFERENCES (bare parent)", eqSet(extractForeignKeys("CREATE TABLE orders (id INTEGER, user_id INTEGER REFERENCES users(id))"), ["users"]));
ok("table-level FOREIGN KEY", eqSet(extractForeignKeys("CREATE TABLE orders (id INTEGER, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users (id))"), ["users"]));
ok("double-quoted parent", eqSet(extractForeignKeys('CREATE TABLE "o" (u INTEGER REFERENCES "users" ("id"))'), ["users"]));
ok("backtick parent", eqSet(extractForeignKeys("CREATE TABLE o (u INTEGER REFERENCES `users`(id))"), ["users"]));
ok("bracket parent", eqSet(extractForeignKeys("CREATE TABLE o (u INTEGER REFERENCES [users](id))"), ["users"]));
ok("double-quoted parent with a space", eqSet(extractForeignKeys('CREATE TABLE o (u INTEGER REFERENCES "user accounts"(id))'), ["user accounts"]));
ok("multiple distinct parents", eqSet(extractForeignKeys("CREATE TABLE oi (o INT REFERENCES orders(id), p INT REFERENCES products(id))"), ["orders", "products"]));
ok("composite FK counts parent once", eqSet(extractForeignKeys("CREATE TABLE t (a INT, b INT, FOREIGN KEY (a,b) REFERENCES parent (a,b))"), ["parent"]));
ok("dedup repeated parent", eqSet(extractForeignKeys("CREATE TABLE t (a INT REFERENCES p(id), b INT REFERENCES p(id))"), ["p"]));
ok("REFERENCES keyword case-insensitive", eqSet(extractForeignKeys("CREATE TABLE o (u INT references users(id))"), ["users"]));
ok("self-reference dropped when selfName given", extractForeignKeys("CREATE TABLE emp (id INT PRIMARY KEY, mgr INT REFERENCES emp(id))", "emp").length === 0);
ok("self-reference kept without selfName", eqSet(extractForeignKeys("CREATE TABLE emp (id INT, mgr INT REFERENCES emp(id))"), ["emp"]));
ok("self-reference case-insensitive drop", extractForeignKeys("CREATE TABLE Emp (mgr INT REFERENCES EMP(id))", "emp").length === 0);
ok("doubled-quote inside a parent name is unescaped", eqSet(extractForeignKeys('CREATE TABLE o (u INT REFERENCES "a""b"(id))'), ['a"b']));
ok("ON DELETE CASCADE after parent still parses parent", eqSet(extractForeignKeys("CREATE TABLE o (u INT REFERENCES users(id) ON DELETE CASCADE)"), ["users"]));
ok("a column literally named references_count does not match", extractForeignKeys("CREATE TABLE t (references_count INTEGER)").length === 0);
ok('space-less double-quoted parent (REFERENCES"users")', eqSet(extractForeignKeys('CREATE TABLE o (u INT REFERENCES"users"(id))'), ["users"]));
ok("space-less bracket parent", eqSet(extractForeignKeys("CREATE TABLE o (u INT REFERENCES[users](id))"), ["users"]));
ok("space-less backtick parent", eqSet(extractForeignKeys("CREATE TABLE o (u INT REFERENCES`users`(id))"), ["users"]));
ok("line comment containing REFERENCES is ignored", extractForeignKeys("CREATE TABLE t (\n x INT, -- REFERENCES users\n y INT)").length === 0);
ok("block comment containing REFERENCES is ignored", extractForeignKeys("CREATE TABLE t (x INT /* REFERENCES users */, y INT)").length === 0);
ok("string-literal DEFAULT containing REFERENCES is ignored", extractForeignKeys("CREATE TABLE t (note TEXT DEFAULT 'see REFERENCES users')").length === 0);
ok("a real FK is kept while a literal REFERENCES is ignored", eqSet(extractForeignKeys("CREATE TABLE o (u INT REFERENCES users(id), note TEXT DEFAULT 'REFERENCES orders')"), ["users"]));
ok("a doubled single-quote inside a literal is handled", extractForeignKeys("CREATE TABLE t (note TEXT DEFAULT 'it''s a REFERENCES users test')").length === 0);
ok("-- inside a string literal on the same line does NOT eat a real FK", eqSet(extractForeignKeys("CREATE TABLE orders (status TEXT DEFAULT 'new -- unprocessed', user_id INTEGER REFERENCES users(id))"), ["users"]));
ok("-- inside a CHECK string does NOT eat a table-level FK", eqSet(extractForeignKeys("CREATE TABLE o (u INT, status TEXT CHECK (status <> 'x--y'), FOREIGN KEY (u) REFERENCES users(id))"), ["users"]));
ok("an apostrophe in a comment does not span into a later string and eat an FK", eqSet(extractForeignKeys("CREATE TABLE t (a TEXT, -- don't\n b INT REFERENCES users(id), c TEXT DEFAULT 'x')"), ["users"]));
ok("double-quoted parent identifier containing an apostrophe", eqSet(extractForeignKeys(`CREATE TABLE t (a INT REFERENCES "p'1"(id))`), ["p'1"]));
ok("double-quoted parent identifier containing a double-hyphen", eqSet(extractForeignKeys('CREATE TABLE child (x INT REFERENCES "a--b"(id))'), ["a--b"]));

console.log("d1DependencyWarnings:");
const SCHEMA = [
  { name: "users", sql: 'CREATE TABLE "users" (id INTEGER PRIMARY KEY, name TEXT)' },
  { name: "orders", sql: 'CREATE TABLE "orders" (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id))' },
  { name: "order_items", sql: 'CREATE TABLE "order_items" (id INTEGER, order_id INTEGER REFERENCES orders(id), product_id INTEGER REFERENCES products(id))' },
  { name: "products", sql: 'CREATE TABLE "products" (id INTEGER PRIMARY KEY, title TEXT)' },
];
function warns(sel: string[]): string[] {
  return d1DependencyWarnings(SCHEMA, sel).map((w) => `${w.table}->${w.missingParent}`);
}
ok("child without parent -> warn", eqSet(warns(["orders"]), ["orders->users"]));
ok("child WITH parent -> no warn", warns(["orders", "users"]).length === 0);
ok("whole DB selected -> no warn", warns(["users", "orders", "order_items", "products"]).length === 0);
ok("only parent selected -> no warn", warns(["users"]).length === 0);
ok("two missing parents from one child", eqSet(warns(["order_items"]), ["order_items->orders", "order_items->products"]));
// order_items still misses products; and orders is ITSELF a selected child now missing its parent users.
ok("each selected child is checked (order_items->products AND orders->users)", eqSet(warns(["order_items", "orders"]), ["order_items->products", "orders->users"]));
ok("case-insensitive selection match", warns(["Orders", "Users"]).length === 0);
ok("missingParent uses the backup's spelling", d1DependencyWarnings(SCHEMA, ["orders"])[0]?.missingParent === "users");
ok("empty selection -> no warn", warns([]).length === 0);

const EXT = [{ name: "child", sql: "CREATE TABLE child (x INT REFERENCES external_thing(id))" }];
ok("parent absent from the backup -> no warn (pre-existing DB state, not a selection issue)", d1DependencyWarnings(EXT, ["child"]).length === 0);

console.log("d1SchemaTargetTable:");
ok("CREATE INDEX ON a table", d1SchemaTargetTable('CREATE INDEX "i" ON "users" (name)') === "users");
ok("CREATE UNIQUE INDEX ON a table", d1SchemaTargetTable("CREATE UNIQUE INDEX i ON users (name)") === "users");
ok("CREATE TRIGGER ... ON a table", d1SchemaTargetTable('CREATE TRIGGER t AFTER INSERT ON "orders" BEGIN SELECT 1; END') === "orders");
ok("CREATE VIEW -> null (kept unconditionally)", d1SchemaTargetTable("CREATE VIEW v AS SELECT * FROM users") === null);
ok("CREATE TEMP VIEW -> null", d1SchemaTargetTable("CREATE TEMP VIEW v AS SELECT 1") === null);
ok("bracket-quoted ON table", d1SchemaTargetTable("CREATE INDEX i ON [my table] (c)") === "my table");
ok("a trigger NAME containing on_ does not confuse the ON parse", d1SchemaTargetTable("CREATE TRIGGER on_insert AFTER INSERT ON users BEGIN SELECT 1; END") === "users");
// The bugs an earlier regex version had (a quoted NAME containing 'on', no space before a quoted table,
// a view with an inter-token comment, a trigger body's own ON, a schema qualifier).
ok("a double-quoted index NAME containing 'on <word>' does not mis-parse the table", d1SchemaTargetTable('CREATE INDEX "customers on file" ON customers (id)') === "customers");
ok("a bracket index NAME containing 'on <word>' does not mis-parse", d1SchemaTargetTable("CREATE INDEX [orders on hold] ON orders (id)") === "orders");
ok("a quoted trigger NAME containing 'on <word>' does not mis-parse", d1SchemaTargetTable('CREATE TRIGGER "cascade on delete" AFTER DELETE ON parent BEGIN SELECT 1; END') === "parent");
ok("ON with no space before a double-quoted table", d1SchemaTargetTable('CREATE INDEX i ON"orders"(x)') === "orders");
ok("ON with no space before a bracket table", d1SchemaTargetTable("CREATE INDEX i ON[orders](x)") === "orders");
ok("a view with an inter-token comment is still a view (kept)", d1SchemaTargetTable("CREATE /* v */ VIEW v AS SELECT * FROM a JOIN b ON a.i=b.i") === null);
ok("a trigger BODY's ON is not taken as the defining table", d1SchemaTargetTable("CREATE TRIGGER t AFTER INSERT ON orders BEGIN INSERT INTO log SELECT * FROM x JOIN y ON x.i=y.i; END") === "orders");
ok("a schema-qualified ON resolves to the table", d1SchemaTargetTable("CREATE INDEX i ON main.orders (x)") === "orders");
ok("a partial index WHERE clause does not shift the target", d1SchemaTargetTable("CREATE INDEX i ON orders (x) WHERE x IN (SELECT a FROM t)") === "orders");
ok("a non-ASCII unquoted table name tokenizes whole (not truncated at the accent)", d1SchemaTargetTable("CREATE INDEX i ON café (x)") === "café");
ok("a non-ASCII unquoted FK parent is captured whole", eqSet(extractForeignKeys("CREATE TABLE o (u INT REFERENCES café(id))"), ["café"]));

console.log(failures === 0 ? "\nD1 FK LINT TESTS PASS" : `\n${failures} D1 FK LINT TEST(S) FAILED`);
if (failures > 0) process.exitCode = 1;
process.exit(failures > 0 ? 1 : 0);
