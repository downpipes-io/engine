// Exercises the SIEM push S3-sink and syslog-TLS-sink target validation (buildPushS3Target /
// buildPushSyslogTarget in scheduler-do-siem-push.ts): every missing/invalid-field reject path plus the valid
// shapes, driving the REAL SchedulerDO.setSiemPushDestination. These are the two alternate sinks (the http
// sink is covered by validate-siem-push*.ts); their per-field validation throws are the reject classes the
// router maps to 400s. Pins that a malformed s3/syslog target is refused at set time, never half-stored.
//
// Run: node test/validate-destsim-push-targets.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const OWNER = { method: "token" as const, email: null, subject: null, groups: [] };
const dobj = (): SchedulerDO => new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);

async function rejects(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

const S3_BASE = { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "audit-bucket", region: "us-east-1", accessKeyId: "AKIA_TEST", secretAccessKey: "s3-secret-value" };
const setS3 = (d: SchedulerDO, s3Target: unknown) => d.setSiemPushDestination({ format: "ndjson", sink: "s3", s3Target, enabled: true } as never, OWNER);
const setSyslog = (d: SchedulerDO, syslog: unknown) => d.setSiemPushDestination({ format: "cef", sink: "syslog-tls", syslog, enabled: true } as never, OWNER);

async function main(): Promise<void> {
  // ---- S3 sink target validation ----
  ok("s3: absent s3Target is refused", await rejects(() => setS3(dobj(), undefined)));
  ok("s3: a non-object s3Target is refused", await rejects(() => setS3(dobj(), "not-an-object")));
  ok("s3: a non-https endpoint is refused", await rejects(() => setS3(dobj(), { ...S3_BASE, endpoint: "http://s3.example.com" })));
  ok("s3: a missing bucket is refused", await rejects(() => setS3(dobj(), { ...S3_BASE, bucket: "" })));
  ok("s3: a missing region is refused", await rejects(() => setS3(dobj(), { ...S3_BASE, region: "" })));
  ok("s3: a missing accessKeyId is refused", await rejects(() => setS3(dobj(), { ...S3_BASE, accessKeyId: "" })));
  ok("s3: a missing secretAccessKey is refused", await rejects(() => setS3(dobj(), { ...S3_BASE, secretAccessKey: "" })));
  {
    const d = dobj();
    const view = await setS3(d, { ...S3_BASE, addressing: "path", storageClass: "STANDARD", prefix: "downpipes-audit/" });
    ok("s3: a complete target (endpoint/bucket/region/keys + addressing/storageClass/prefix) is accepted + stored", view.present === true && view.sink === "s3");
    ok("s3: the redacted view echoes the bucket/region but NEVER the secret", view.s3?.bucket === "audit-bucket" && !JSON.stringify(view).includes("s3-secret-value"));
  }
  {
    // A minimal valid target (no optional addressing/storageClass/prefix) exercises the absent-optional arms.
    const view = await setS3(dobj(), S3_BASE);
    ok("s3: a minimal valid target (no optional fields) is accepted", view.present === true && view.sink === "s3");
  }

  // ---- syslog-TLS sink target validation ----
  ok("syslog: absent syslog target is refused", await rejects(() => setSyslog(dobj(), undefined)));
  ok("syslog: a non-object syslog target is refused", await rejects(() => setSyslog(dobj(), 42)));
  ok("syslog: a missing host is refused", await rejects(() => setSyslog(dobj(), { host: "" })));
  {
    const view = await setSyslog(dobj(), { host: "siem.internal.example", port: 6514 });
    ok("syslog: a valid host + explicit port is accepted + stored", view.present === true && view.sink === "syslog-tls" && view.syslog?.host === "siem.internal.example" && view.syslog?.port === 6514);
  }
  {
    // No/invalid port falls back to the 6514 default (the port-fallback branch).
    const view = await setSyslog(dobj(), { host: "siem2.internal.example", port: 0 });
    ok("syslog: an invalid port falls back to the 6514 default", view.present === true && view.syslog?.port === 6514);
  }

  console.log(failures === 0 ? "\nDESTSIM PUSH-TARGETS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
