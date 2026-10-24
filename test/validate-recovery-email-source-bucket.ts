// validate-recovery-email-source-bucket: the recovery-code sign-in limiter keys its email bucket on the
// email AND the caller's source group, so an anonymous caller who types an Owner's address can exhaust only
// the buckets for their own source, and the expired rate-window rows are swept from DO storage.
//
// It drives the REAL SchedulerDO through the REAL router (handleAdmin) with in-memory doubles only. No
// network, no estate, no deploy, no credential spent.
//
// Run: node test/validate-recovery-email-source-bucket.ts

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { RECOVERY_RATE_MAX_PER_EMAIL, RECOVERY_RATE_MAX_PER_IP, RECOVERY_RATE_PREFIX, RATE_LIMIT_PREFIX } from "../src/sched/scheduler-do-limits.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://downpipe-console.example";
const ADMIN_TOKEN = "test-admin-token-email-source-bucket";
const OWNER = "owner-bucket@acme.example";
const BAD_CODE = "00000-00000-00000-00000-00000-00000";
const IP_A = "203.0.113.50";
const IP_B = "198.51.100.51";
const EMAIL_MAX = 254;

function makeScheduler(): { env: Env; storage: MockStorage; stub: DurableObjectStub; dobj: SchedulerDO } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN } as unknown as Env;
  return { env, storage, stub, dobj };
}

async function mintOwner(s: ReturnType<typeof makeScheduler>): Promise<string[]> {
  await s.storage.put(`role:${OWNER}`, { email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
  const resp = await s.stub.fetch("https://scheduler.internal/recovery/regenerate", {
    method: "POST",
    body: JSON.stringify({ email: OWNER }),
    headers: { "content-type": "application/json" },
  });
  return ((await resp.json()) as { codes?: string[] }).codes ?? [];
}

async function recover(env: Env, email: string, code: string, ip: string): Promise<number> {
  const resp = await handleAdmin(
    new Request("https://engine.example/admin/auth/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": ip },
      body: JSON.stringify({ email, code }),
    }),
    env,
  );
  await resp.text();
  return resp.status;
}

// recoverNoIp reaches the DO the way a local request does: no source address at all.
async function recoverNoIp(s: ReturnType<typeof makeScheduler>, email: string, code: string): Promise<boolean> {
  const resp = await s.stub.fetch("https://scheduler.internal/recovery/recover", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, code }),
  });
  return ((await resp.json()) as { ok?: boolean }).ok === true;
}

// recoverDirect reaches the DO's recover route with a source address, past the router's own per-IP ceremony
// throttle, so a flood is limited only by the recovery buckets under test.
async function recoverDirect(s: ReturnType<typeof makeScheduler>, email: string, ip: string | null): Promise<void> {
  const resp = await s.stub.fetch("https://scheduler.internal/recovery/recover", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, code: BAD_CODE, ip }),
  });
  await resp.text();
}

async function main(): Promise<void> {
  const burst = RECOVERY_RATE_MAX_PER_EMAIL + 1;

  console.log("\n== (a) an anonymous source cannot lock the Owner out from another source ==");
  {
    const s = makeScheduler();
    const codes = await mintOwner(s);
    ok("a real set of codes was minted", codes.length === 10);
    let refused = 0;
    for (let i = 0; i < burst; i++) if ((await recover(s.env, OWNER, BAD_CODE, IP_A)) === 401) refused++;
    ok(`all ${burst} wrong attempts from source A are refused`, refused === burst);
    const status = await recover(s.env, OWNER, codes[0]!, IP_B);
    ok("a correct code from source B verifies (200)", status === 200);
  }

  console.log("\n== (b) the same-source residual is bounded and unchanged ==");
  {
    const s = makeScheduler();
    const codes = await mintOwner(s);
    for (let i = 0; i < burst; i++) await recover(s.env, OWNER, BAD_CODE, IP_A);
    ok("a correct code from the SAME source in the same window is refused (401)", (await recover(s.env, OWNER, codes[0]!, IP_A)) === 401);
  }

  console.log("\n== (c) no source address still hits a per-email bucket ==");
  {
    const s = makeScheduler();
    const codes = await mintOwner(s);
    for (let i = 0; i < RECOVERY_RATE_MAX_PER_EMAIL; i++) await recoverNoIp(s, OWNER, BAD_CODE);
    ok("a correct code after the cap, with no source address, is refused", (await recoverNoIp(s, OWNER, codes[0]!)) === false);
    const keys = [...(await s.storage.list<unknown>({ prefix: `${RECOVERY_RATE_PREFIX}email:` })).keys()];
    ok("a per-email bucket row exists for the no-address attempts", keys.some((k) => k.includes(OWNER)));
    const s2 = makeScheduler();
    const codes2 = await mintOwner(s2);
    ok("a correct code with no source address and no prior attempts verifies", (await recoverNoIp(s2, OWNER, codes2[0]!)) === true);
  }

  console.log("\n== (d) the per-IP bucket still caps one source across many emails ==");
  {
    const s = makeScheduler();
    const codes = await mintOwner(s);
    for (let i = 0; i < RECOVERY_RATE_MAX_PER_IP; i++) await recover(s.env, `spray-${i}@acme.example`, BAD_CODE, IP_A);
    ok("a correct code for a fresh email from the sprayed source is refused", (await recover(s.env, OWNER, codes[0]!, IP_A)) === 401);
    ok("the same code from another source verifies", (await recover(s.env, OWNER, codes[0]!, IP_B)) === 200);
  }

  console.log("\n== (g) the email rows one source can create are bounded ==");
  {
    const emailRows = async (s: ReturnType<typeof makeScheduler>): Promise<string[]> =>
      [...(await s.storage.list<unknown>({ prefix: `${RECOVERY_RATE_PREFIX}email:` })).keys()];

    const flood = makeScheduler();
    const FLOOD = 200;
    for (let i = 0; i < FLOOD; i++) {
      // Distinct addresses: ordinary, and over-long (255 to 320 characters, still a well-formed address).
      const email = i % 2 === 0 ? `flood-${i}@acme.example` : `${"a".repeat(255 + (i % 60))}${i}@acme.example`;
      await recoverDirect(flood, email, IP_A);
    }
    const floodRows = await emailRows(flood);
    console.log(`  ${FLOOD} distinct emails from one source -> ${floodRows.length} email rows`);
    ok(`${FLOOD} distinct emails from one source create at most ${RECOVERY_RATE_MAX_PER_IP} email rows`, floodRows.length <= RECOVERY_RATE_MAX_PER_IP);
    const ipRows = [...(await flood.storage.list<{ count: number }>({ prefix: `${RECOVERY_RATE_PREFIX}ip:` })).values()];
    ok("the flood holds one per-IP row, counted to its cap", ipRows.length === 1 && ipRows[0]!.count === RECOVERY_RATE_MAX_PER_IP);

    const long = makeScheduler();
    await recoverDirect(long, `${"b".repeat(EMAIL_MAX)}@acme.example`, IP_B);
    const longKeys = await emailRows(long);
    ok("an over-long address writes one shared _invalid row", longKeys.length === 1 && longKeys[0]!.includes("email:_invalid:"));
    ok("no email row key is longer than the cap", longKeys.every((k) => k.length <= RECOVERY_RATE_PREFIX.length + EMAIL_MAX + 64));
    ok("an over-long address still consumes the per-IP bucket", (await long.storage.list<unknown>({ prefix: `${RECOVERY_RATE_PREFIX}ip:` })).size === 1);

    const forms = makeScheduler();
    for (const f of [OWNER, ` ${OWNER.toUpperCase()} `, `\t${OWNER}\n`, OWNER.replace("owner", "OWNER")]) await recoverDirect(forms, f, IP_A);
    const formRows = await emailRows(forms);
    ok("one address in different case and whitespace maps to ONE row", formRows.length === 1 && formRows[0]!.includes(OWNER));

    // A request with no source address shares the one ip:none bucket, so an IP-less flood is bounded the same way.
    const noIp = makeScheduler();
    for (let i = 0; i < FLOOD; i++) await recoverDirect(noIp, `noip-${i}@acme.example`, null);
    const noIpRows = await emailRows(noIp);
    console.log(`  ${FLOOD} distinct emails with no source address -> ${noIpRows.length} email rows`);
    ok(`${FLOOD} distinct emails with no source address create at most ${RECOVERY_RATE_MAX_PER_IP} email rows`, noIpRows.length <= RECOVERY_RATE_MAX_PER_IP);
    const noneRows = [...(await noIp.storage.list<{ count: number }>({ prefix: `${RECOVERY_RATE_PREFIX}ip:` })).entries()];
    ok("the IP-less flood holds the one ip:none row, counted to its cap", noneRows.length === 1 && noneRows[0]![0].endsWith("ip:none") && noneRows[0]![1].count === RECOVERY_RATE_MAX_PER_IP);

    // Inside one window, the attempt after the cap with no source address is refused by the shared ip:none
    // bucket (it writes no email row), while the same attempt with its own source address passes that bucket.
    const window = makeScheduler();
    for (let i = 0; i < RECOVERY_RATE_MAX_PER_IP; i++) await recoverDirect(window, `cap-${i}@acme.example`, null);
    const atCap = (await emailRows(window)).length;
    await recoverDirect(window, "over-cap-noip@acme.example", null);
    const afterNoIp = await emailRows(window);
    ok(`the attempt after ${RECOVERY_RATE_MAX_PER_IP} with no source address is refused by ip:none (no new email row)`, atCap === RECOVERY_RATE_MAX_PER_IP && afterNoIp.length === atCap && !afterNoIp.some((k) => k.includes("over-cap-noip")));
    await recoverDirect(window, "over-cap-ip@acme.example", "192.0.2.77");
    const afterIp = await emailRows(window);
    const ownIpRow = await window.storage.get<{ count: number }>(`${RECOVERY_RATE_PREFIX}ip:192.0.2.77`);
    ok("the same attempt with its own source address passes the IP bucket (its email row and IP row are written)", afterIp.some((k) => k.includes("over-cap-ip")) && ownIpRow?.count === 1);
  }

  console.log("\n== (e) the alarm sweep removes expired and malformed rate rows ==");
  const old = Date.now() - 10 * 60_000;
  const prefixes = [RATE_LIMIT_PREFIX, RECOVERY_RATE_PREFIX];
  async function seed(s: ReturnType<typeof makeScheduler>, expired: number): Promise<void> {
    for (const p of prefixes) {
      for (let i = 0; i < expired; i++) await s.storage.put(`${p}x:${i}`, { windowStart: old, count: 1 });
      await s.storage.put(`${p}live`, { windowStart: Date.now(), count: 1 });
    }
    await s.storage.put(`${RATE_LIMIT_PREFIX}bad`, { count: 1 });
    await s.storage.put(`${RECOVERY_RATE_PREFIX}bad`, "not-a-window");
  }
  const rows = async (s: ReturnType<typeof makeScheduler>, p: string): Promise<string[]> => [...(await s.storage.list<unknown>({ prefix: p })).keys()];
  {
    const s = makeScheduler();
    await seed(s, 1000);
    ok("seeded 1,002 rows under each prefix", (await rows(s, RATE_LIMIT_PREFIX)).length === 1002 && (await rows(s, RECOVERY_RATE_PREFIX)).length === 1002);
    let alarms = 0;
    while (alarms < 20 && ((await rows(s, RATE_LIMIT_PREFIX)).length > 1 || (await rows(s, RECOVERY_RATE_PREFIX)).length > 1)) {
      await s.dobj.alarm();
      alarms++;
    }
    console.log(`  alarms run: ${alarms}`);
    ok("only the live row stays under ratelimit:", JSON.stringify(await rows(s, RATE_LIMIT_PREFIX)) === JSON.stringify([`${RATE_LIMIT_PREFIX}live`]));
    ok("only the live row stays under recovery-rate:", JSON.stringify(await rows(s, RECOVERY_RATE_PREFIX)) === JSON.stringify([`${RECOVERY_RATE_PREFIX}live`]));
  }

  console.log("\n== (f) one alarm deletes a bounded number of rows ==");
  {
    const s = makeScheduler();
    await seed(s, 3000);
    const before = (await rows(s, RATE_LIMIT_PREFIX)).length;
    await s.dobj.alarm();
    const after = (await rows(s, RATE_LIMIT_PREFIX)).length;
    const deleted = before - after;
    console.log(`  ratelimit: rows ${before} -> ${after} (deleted ${deleted} in one alarm)`);
    ok("one alarm deletes some rows", deleted > 0);
    ok("one alarm deletes at most 1000 rows per prefix", deleted <= 1000);
    ok("the remainder is left for a later alarm", after > 1);
  }

  console.log(failures === 0 ? "\nRECOVERY EMAIL-AND-SOURCE BUCKET VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
