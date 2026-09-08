// Pins the cross-source self-identification annotations: the API sources (cf-config/workers/stream/images/
// artifacts) expose their Cloudflare accountId so the seal can stamp every record's `account` annotation, and
// the record writer carries the `database` (D1's native UUID) and `account` identity fields into the signed
// manifest line (mirroring namespace/bucket). Together with validate-sources.ts (D1 sets `database` on records)
// and the seal round-trips in validate-slice/validate-sources, this proves the archive self-identifies which
// account/database it is a backup of. Run: node test/validate-source-identity.ts

import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { WorkersSource } from "../src/sources/workers.ts";
import { StreamSource } from "../src/sources/stream.ts";
import { ImagesSource } from "../src/sources/images.ts";
import { ArtifactsSource } from "../src/sources/artifacts.ts";
import { buildRecordLine, type RecordMeta, type RecordSealResult } from "../src/format/writer-record.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const anyApi = {} as never; // the accountId is set in the constructor, before any API use, so a stub api is fine

async function main(): Promise<void> {
  console.log("-- every API source exposes its accountId (so the seal can stamp record.account) --");
  ok("cf-config exposes accountId", new CloudflareConfigSource("tok", "acct-cf", "zone-1").accountId === "acct-cf");
  ok("workers exposes accountId", new WorkersSource("acct-wk", anyApi).accountId === "acct-wk");
  ok("stream exposes accountId", new StreamSource("acct-st", anyApi).accountId === "acct-st");
  ok("images exposes accountId", new ImagesSource("acct-im", anyApi).accountId === "acct-im");
  ok("artifacts exposes accountId", new ArtifactsSource("acct-ar", anyApi).accountId === "acct-ar");

  console.log("-- the record writer carries `database` and `account` into the signed manifest line --");
  const nameKey = new Uint8Array(32).fill(7);
  const seal: RecordSealResult = { segments: [], plaintextSha384: "a".repeat(96), size: 42 };
  const withIds: RecordMeta = { sourceType: "d1", name: "mydb/00-header", database: "db-uuid-abc", account: "acct-xyz" };
  const { line } = await buildRecordLine(nameKey, "0000000001", withIds, seal);
  ok("the line carries the database UUID annotation", line.database === "db-uuid-abc");
  ok("the line carries the account annotation", line.account === "acct-xyz");

  const noIds: RecordMeta = { sourceType: "kv", name: "users/alice", namespace: "ns1" };
  const { line: line2 } = await buildRecordLine(nameKey, "0000000002", noIds, seal);
  ok("a record without database/account omits both from the line (omitempty)", line2.database === undefined && line2.account === undefined);
  ok("the existing namespace annotation is unaffected", line2.namespace === "ns1");

  console.log(failures === 0 ? "\nSOURCE-IDENTITY PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
