// A kv source stored WITHOUT a namespaceId still resolves to its ORIGINAL binding on restore.
//
// WHY THIS EXISTS. sched/types.ts declares namespaceId optional "for back-compat", so a downpipe saved before
// that field existed, or created over an already-bound namespace, carries only a binding name. buildSourceBindingMap
// used to add a kv: entry ONLY when namespaceId was present, so such a config produced no entry at all,
// resolveSink missed and fell back to the KV_<namespace> convention, and every record skipped with "target
// binding not present". The operator saw a restore that completed and wrote nothing.
//
// The observed failure shape: plannedWrites=0 recordsVerified=0 skipped=2 [2x target binding not present],
// on a fixture PROVEN able to overwrite.
//
// THE KEY IS THE BINDING because that is what the archive record carries in this case. seal/adapters.ts
// constructs the source with `s.namespaceId ?? s.binding`, and the crawl stamps that value as each record's
// `namespace` (sources/kv.ts). So a record captured from a config with no namespaceId is stamped with the
// BINDING, and `kv:<binding>` is the key resolveSink will ask for.
//
// Run: node test/validate-restore-kv-binding-fallback.ts

import { buildSourceBindingMap } from "../src/admin/router-restore.ts";

let failures = 0;
function ok(what: string, cond: boolean): void {
  if (cond) {
    console.log(`  ok   ${what}`);
  } else {
    console.log(`  FAIL ${what}`);
    failures += 1;
  }
}

// THE REAL DO SHAPE. GET /downpipes returns DownpipeState[], and sched/types.ts:197 puts the source on
// `config`. A fixture that instead builds `{ source }` at the top level shares the SAME wrong assumption
// the code under test would be casting to, so such a fixture could agree with a bug and pass while every
// live restore fell back to the convention -- the fixtures below are built in the real shape to avoid that.
const stub = (sources: unknown[]): DurableObjectStub =>
  ({ fetch: async () => new Response(JSON.stringify(sources.map((source) => ({ schemaVersion: 1, config: { id: "dp", source } })))) }) as unknown as DurableObjectStub;

// The flat shape, kept working so a caller or fixture using it does not silently map nothing.
const flatStub = (sources: unknown[]): DurableObjectStub =>
  ({ fetch: async () => new Response(JSON.stringify(sources.map((source) => ({ source })))) }) as unknown as DurableObjectStub;

console.log("\nKV BINDING FALLBACK");

// 0. THE SHAPE. This is the assertion that would have caught the real defect: the map must be built from a
// response in the DO's actual shape, where the source hangs off `config`.
const realShape = await buildSourceBindingMap(stub([{ type: "kv", binding: "SRC_KV", namespaceId: "ns1" }]));
ok("a source on config.source is READ (the DO's real shape, not the flat one)", realShape.get("kv:ns1") === "SRC_KV");
ok("the map is not empty for a real response", realShape.size > 0);
const flat = await buildSourceBindingMap(flatStub([{ type: "kv", binding: "SRC_KV", namespaceId: "ns1" }]));
ok("a source at the TOP level still works too", flat.get("kv:ns1") === "SRC_KV");

// 1. THE DEFECT: no namespaceId. Before the fix this map was empty.
const noId = await buildSourceBindingMap(stub([{ type: "kv", binding: "SRC_KV" }]));
ok("a kv source with NO namespaceId still yields a binding-keyed entry", noId.get("kv:SRC_KV") === "SRC_KV");
ok("and that is the key resolveSink asks for, since capture stamps the binding as the record namespace", noId.has("kv:SRC_KV"));

// 2. The namespaceId path is UNCHANGED, which is the whole point of choosing the fallback over re-keying.
const withId = await buildSourceBindingMap(stub([{ type: "kv", binding: "SRC_KV", namespaceId: "abc123" }]));
ok("a kv source WITH a namespaceId still maps by its id", withId.get("kv:abc123") === "SRC_KV");
ok("and also gains the binding key, so both spellings resolve", withId.get("kv:SRC_KV") === "SRC_KV");

// 3. The authoritative mapping must win a collision (one downpipe's binding equalling another's namespace id).
const collide = await buildSourceBindingMap(
  stub([
    { type: "kv", binding: "REAL", namespaceId: "SHARED" },
    { type: "kv", binding: "SHARED" },
  ]),
);
ok("a namespaceId mapping is NOT overwritten by another downpipe's binding fallback", collide.get("kv:SHARED") === "REAL");

// 4. The other source types are untouched.
const others = await buildSourceBindingMap(
  stub([
    { type: "r2", binding: "SRC_R2", bucketName: "buck" },
    { type: "d1", binding: "SRC_D1" },
  ]),
);
ok("r2 still keys on the bucket name", others.get("r2:buck") === "SRC_R2");
ok("d1 still keys on the binding", others.get("d1:SRC_D1") === "SRC_D1");
ok("no kv entry is invented for a non-kv source", [...others.keys()].every((k) => !k.startsWith("kv:")));

// 5. Presence-safe: a source with no binding at all is skipped, not mapped to undefined.
const nameless = await buildSourceBindingMap(stub([{ type: "kv" }, { type: "kv", binding: "" }]));
ok("a kv source with no usable binding yields no entry", nameless.size === 0);

console.log(failures === 0 ? "\nKV BINDING FALLBACK PASS\n" : `\nKV BINDING FALLBACK FAIL (${failures})\n`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
