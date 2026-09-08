// Prove the outbound email module (engine/src/email.ts) against in-memory doubles only (contract
// sections 3 and 11). NO network, NO live send, NO cost: env.EMAIL is a recording double whose
// send() never leaves the process. Run:
//   node test/validate-email.ts
//
// Coverage:
//  isCustomDomainAddress: valid custom-domain ok; workers.dev reject; bare hostname reject; no "@",
//    multiple "@", trailing "@", whitespace, length cap, non-string.
//  validateRecipients: empty reject; over-cap reject; dedupe; one bad address rejects the list.
//  sendEmail FAIL-OPEN: no binding -> email-not-configured; missing/invalid EMAIL_FROM ->
//    email-from-not-configured / email-from-invalid; invalid recipients/subject/body; a throwing
//    send() -> email-send-failed (never throws); the happy path -> ok with the binding receiving the
//    sender + recipients + body and NOTHING else.
//  REDACTION: the message handed to the binding carries only from/to/subject/text(/html); no secret.

import {
  sendEmail,
  isCustomDomainAddress,
  validateRecipients,
  type EmailMessage,
} from "../src/email.ts";
import type { CfEmailSend, Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// recordingEmail is the in-memory send_email double: it records every message send() is called with
// so the test can assert the exact payload shape, and never performs any network I/O.
function recordingEmail(): { binding: CfEmailSend; sent: Parameters<CfEmailSend["send"]>[0][] } {
  const sent: Parameters<CfEmailSend["send"]>[0][] = [];
  return {
    binding: {
      async send(message: Parameters<CfEmailSend["send"]>[0]): Promise<undefined> {
        sent.push(message);
        return undefined;
      },
    },
    sent,
  };
}

// throwingEmail is a send_email double whose send() rejects, to prove sendEmail is fail-open.
function throwingEmail(): CfEmailSend {
  return {
    async send(): Promise<undefined> {
      throw new Error("simulated edge restriction");
    },
  };
}

function envWith(over: Partial<Env>): Env {
  return over as Env;
}

// ---- isCustomDomainAddress ------------------------------------------------------------------
function testAddress(): void {
  ok("address: valid custom-domain ok", isCustomDomainAddress("alerts@example.com").ok === true);
  ok("address: subdomain custom-domain ok", isCustomDomainAddress("a@mail.corp.example.com").ok === true);
  {
    const r = isCustomDomainAddress("a@my-worker.workers.dev");
    ok("address: workers.dev rejected", r.ok === false);
    if (!r.ok) ok("address: workers.dev reason present", r.reason.length > 0);
  }
  ok("address: workers.dev subdomain rejected", isCustomDomainAddress("a@x.workers.dev").ok === false);
  ok("address: bare hostname (no dot) rejected", isCustomDomainAddress("a@localhost").ok === false);
  ok("address: no @ rejected", isCustomDomainAddress("alerts.example.com").ok === false);
  ok("address: multiple @ rejected", isCustomDomainAddress("a@b@example.com").ok === false);
  ok("address: trailing @ rejected", isCustomDomainAddress("alerts@").ok === false);
  ok("address: leading @ rejected", isCustomDomainAddress("@example.com").ok === false);
  ok("address: whitespace rejected", isCustomDomainAddress("a b@example.com").ok === false);
  ok("address: trailing-dot domain rejected", isCustomDomainAddress("a@example.com.").ok === false);
  ok("address: non-string rejected", isCustomDomainAddress(42).ok === false);
  ok("address: empty rejected", isCustomDomainAddress("   ").ok === false);
  ok("address: over-long rejected", isCustomDomainAddress("a@" + "x".repeat(400) + ".com").ok === false);
  // trims surrounding whitespace
  {
    const r = isCustomDomainAddress("  alerts@example.com  ");
    ok("address: trims surrounding whitespace", r.ok === true && r.address === "alerts@example.com");
  }
}

// ---- validateRecipients ---------------------------------------------------------------------
function testRecipients(): void {
  ok("recipients: empty array rejected", validateRecipients([]).ok === false);
  ok("recipients: non-array rejected", validateRecipients("a@example.com").ok === false);
  {
    const r = validateRecipients(["a@example.com", "b@example.com"]);
    ok("recipients: two valid -> ok", r.ok === true && r.to.length === 2);
  }
  {
    // dedupe is case-insensitive on the address key
    const r = validateRecipients(["a@example.com", "A@example.com"]);
    ok("recipients: dedupes case-insensitively", r.ok === true && r.to.length === 1);
  }
  ok("recipients: one bad address rejects the list", validateRecipients(["a@example.com", "bad"]).ok === false);
  {
    const many = Array.from({ length: 60 }, (_v, i) => `u${i}@example.com`);
    ok("recipients: over-cap rejected", validateRecipients(many).ok === false);
  }
}

// ---- sendEmail fail-open + happy path -------------------------------------------------------
async function testSendEmail(): Promise<void> {
  const msg: EmailMessage = { to: ["ops@example.com"], subject: "hi", text: "body" };

  // No binding -> email-not-configured, never throws.
  {
    const r = await sendEmail(envWith({ EMAIL_FROM: "alerts@example.com" }), msg);
    ok("sendEmail: no binding -> email-not-configured", r.ok === false && r.reason === "email-not-configured");
  }
  // Binding present, no EMAIL_FROM -> email-from-not-configured.
  {
    const { binding } = recordingEmail();
    const r = await sendEmail(envWith({ EMAIL: binding }), msg);
    ok("sendEmail: no EMAIL_FROM -> email-from-not-configured", r.ok === false && r.reason === "email-from-not-configured");
  }
  // Binding present, invalid EMAIL_FROM (workers.dev) -> email-from-invalid.
  {
    const { binding } = recordingEmail();
    const r = await sendEmail(envWith({ EMAIL: binding, EMAIL_FROM: "a@x.workers.dev" }), msg);
    ok("sendEmail: workers.dev EMAIL_FROM -> email-from-invalid", r.ok === false && r.reason === "email-from-invalid");
  }
  // Invalid recipients -> email-recipients-invalid.
  {
    const { binding } = recordingEmail();
    const r = await sendEmail(envWith({ EMAIL: binding, EMAIL_FROM: "alerts@example.com" }), { to: ["bad"], subject: "s", text: "t" });
    ok("sendEmail: invalid recipients -> email-recipients-invalid", r.ok === false && r.reason === "email-recipients-invalid");
  }
  // Empty subject -> email-subject-invalid.
  {
    const { binding } = recordingEmail();
    const r = await sendEmail(envWith({ EMAIL: binding, EMAIL_FROM: "alerts@example.com" }), { to: ["ops@example.com"], subject: "", text: "t" });
    ok("sendEmail: empty subject -> email-subject-invalid", r.ok === false && r.reason === "email-subject-invalid");
  }
  // Empty body -> email-body-invalid.
  {
    const { binding } = recordingEmail();
    const r = await sendEmail(envWith({ EMAIL: binding, EMAIL_FROM: "alerts@example.com" }), { to: ["ops@example.com"], subject: "s", text: "" });
    ok("sendEmail: empty body -> email-body-invalid", r.ok === false && r.reason === "email-body-invalid");
  }
  // A throwing send() -> email-send-failed, never throws.
  {
    let threw = false;
    let r;
    try {
      r = await sendEmail(envWith({ EMAIL: throwingEmail(), EMAIL_FROM: "alerts@example.com" }), msg);
    } catch {
      threw = true;
    }
    ok("sendEmail: throwing send() does not throw", threw === false);
    ok("sendEmail: throwing send() -> email-send-failed", r !== undefined && r.ok === false && r.reason === "email-send-failed");
  }
  // Happy path: binding receives the sender + recipients + body; ok:true.
  {
    const { binding, sent } = recordingEmail();
    const r = await sendEmail(envWith({ EMAIL: binding, EMAIL_FROM: "alerts@example.com" }), {
      to: ["ops@example.com", "oncall@example.com"],
      subject: "Backup failed",
      text: "pipe-x last run failed",
    });
    ok("sendEmail: happy path -> ok", r.ok === true);
    ok("sendEmail: binding received exactly one message", sent.length === 1);
    const m = sent[0] as Record<string, unknown>;
    ok("sendEmail: message has the configured sender", m["from"] === "alerts@example.com");
    ok("sendEmail: message has the recipients", Array.isArray(m["to"]) && (m["to"] as string[]).length === 2);
    ok("sendEmail: message has the subject", m["subject"] === "Backup failed");
    ok("sendEmail: message has the text body", m["text"] === "pipe-x last run failed");
    // REDACTION: the message must carry ONLY from/to/subject/text(/html); no header/raw/secret field.
    const allowed = new Set(["from", "to", "subject", "text", "html"]);
    const extra = Object.keys(m).filter((k) => !allowed.has(k));
    ok("sendEmail: message carries no extra fields (redaction-safe surface)", extra.length === 0);
  }
  // html is forwarded when present.
  {
    const { binding, sent } = recordingEmail();
    await sendEmail(envWith({ EMAIL: binding, EMAIL_FROM: "alerts@example.com" }), {
      to: ["ops@example.com"],
      subject: "s",
      text: "t",
      html: "<p>t</p>",
    });
    const m = sent[0] as Record<string, unknown>;
    ok("sendEmail: html forwarded when present", m["html"] === "<p>t</p>");
  }
}

async function main(): Promise<void> {
  console.log("isCustomDomainAddress");
  testAddress();
  console.log("validateRecipients");
  testRecipients();
  console.log("sendEmail (fail-open + happy path)");
  await testSendEmail();
  console.log(failures === 0 ? "\nEMAIL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
