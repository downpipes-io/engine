// A DAMAGED RECORD MUST NEVER PRODUCE THE ANSWER A HEALTHY ONE PRODUCES.
//
// WHAT THIS PINS. Three defects share one shape: a damaged record answered byte-identically to a
// healthy one, so the surface read as an all-clear. They are pinned together because the property is one
// property.
//
//   1. CORRUPT WAS BETTER TREATED THAN MISSING. `loadAuditHead` RECONSTRUCTS an absent pointer by scanning
//      the chain, so a DELETED head answered the true count; a PRESENT head was returned verbatim, so a head
//      whose count had been zeroed answered `auditCount: 0` over a full chain. An account that had lost the
//      record read healthier than one that had lost only the number inside it.
//   2. THE TAIL-DELETION WITNESS WAS DISARMED BY THE SAME RECORD. `verifyAudit` gated the truncation check on
//      `anchorHead.headSeq > 0`, which cannot tell a corrupt anchor from an absent one, so a zeroed anchor
//      skipped the check entirely and the verify still answered `intact: true` unqualified.
//   3. THE ZERO THAT MEANT TWO DIFFERENT THINGS, twice. A tracked expiry row whose `expiresAt` does not parse
//      is neither approaching nor expired, so `/expiry/warnings` answered `{"expiryWarnings":0,...}`, which is
//      what an account tracking nothing answers. And `lockoutPreflight` computes every factor from the rows
//      that PARSED, so an account whose only Owner grant was corrupted answered byte-identically to a healthy
//      one while `/roles` had gone to two bytes.
//
// HOW EACH IS PROVED, and it is the plant rather than the assertion that carries the weight. Every arm
// CORRUPTS a real record under a real `SchedulerDO` and requires the answer to DIFFER from the healthy
// answer. That is the property stated directly: not "the number is right" (a silently-right number leaves the
// two states indistinguishable, which is the defect) but "the two states are distinguishable at all".
//
// AND EVERY ARM CARRIES A GREEN CONTROL UNDER A BENIGN EDIT. A test that only ever plants damage cannot tell
// a surface that reports damage from a surface that reports everything, and a flag that is always set is
// exactly as useless as one that is never set. So each arm is paired with an edit that changes the record
// WITHOUT damaging it, and requires the qualification to stay ABSENT.
//
// Run: node test/validate-corrupt-state-honesty.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { CALLER_HEADER, encodeCaller, type Caller } from "../src/admin/identity.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const OWNER: Caller = { method: "access", email: "owner@corruptfuzz.example", subject: "sub-corruptfuzz-owner", role: "owner", groups: [] };

type Rig = { storage: MockStorage; call: (path: string, opts?: { method?: "GET" | "POST"; body?: unknown; caller?: Caller | null }) => Promise<{ status: number; body: string }> };

function makeRig(seed?: Map<string, unknown>): Rig {
  const storage = new MockStorage();
  if (seed !== undefined) for (const [k, v] of seed) storage.raw().set(k, structuredClone(v));
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const call = async (path: string, opts: { method?: "GET" | "POST"; body?: unknown; caller?: Caller | null } = {}) => {
    const headers: Record<string, string> = {};
    if (opts.caller !== undefined && opts.caller !== null) headers[CALLER_HEADER] = encodeCaller(opts.caller);
    const method = opts.method ?? "GET";
    const init: RequestInit = { method, headers };
    if (method === "POST" && opts.body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    const r = await dobj.fetch(new Request(`https://scheduler.internal${path}`, init));
    return { status: r.status, body: await r.text() };
  };
  return { storage, call };
}

/** The verify body without its `verify` block, whose timings move between two reads of identical state. */
function stableVerify(body: string): string {
  const o = JSON.parse(body) as Record<string, unknown>;
  delete o.verify;
  return JSON.stringify(o);
}

async function main(): Promise<void> {
  // ==========================================================================================================
  // THE SEED: a real account, built through the DO's own write routes so every record is engine-minted.
  // ==========================================================================================================
  const seedRig = makeRig();
  await seedRig.call(`/whoami?email=${encodeURIComponent(OWNER.email as string)}&subject=${OWNER.subject}&method=access`);
  for (let i = 0; i < 6; i++) {
    await seedRig.call("/audit", { method: "POST", body: { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-secret-present", outcome: "success", target: { kind: "engine-state", field: "secret-present", detail: `d${i}` } } });
  }
  await seedRig.call("/expiry", { method: "POST", caller: OWNER, body: { id: "sf-cert", label: "Corrupt-state certificate", kind: "certificate", expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString() } });
  const SEED = new Map<string, unknown>([...seedRig.storage.raw().entries()].map(([k, v]) => [k, structuredClone(v)]));

  const OWNER_ROLE_KEY = [...SEED.keys()].find((k) => k.startsWith("role:sub:"));
  const EXPIRY_KEY = [...SEED.keys()].find((k) => k.startsWith("expiry:"));
  ok("[seed] the account has a subject-keyed Owner grant, an expiry row and an audit chain", OWNER_ROLE_KEY !== undefined && EXPIRY_KEY !== undefined && [...SEED.keys()].filter((k) => k.startsWith("audit:")).length >= 6 && SEED.has("auditHead"));
  if (OWNER_ROLE_KEY === undefined || EXPIRY_KEY === undefined) {
    console.log("\n[corruptfuzz-honesty] COULD NOT CHECK: the seed did not produce the records every arm below corrupts.");
    process.exit(2);
  }

  // ==========================================================================================================
  // 1. THE AUDIT HEAD COUNT: corrupt must not read healthier than missing
  // ==========================================================================================================
  {
    const healthy = stableVerify((await makeRig(SEED).call("/audit/verify")).body);
    const healthyCount = (JSON.parse(healthy) as { auditCount: number }).auditCount;
    ok("[1] the healthy chain reports its true retained count", healthyCount >= 6);

    // THE PLANT: the head pointer's count zeroed while it still names a newest entry.
    const zeroed = makeRig(SEED);
    const head = zeroed.storage.raw().get("auditHead") as { headSeq: number; headHash: string; count: number };
    zeroed.storage.raw().set("auditHead", { ...head, count: 0 });
    const zeroedBody = stableVerify((await zeroed.call("/audit/verify")).body);
    const z = JSON.parse(zeroedBody) as { auditCount: number; auditCountRecovered?: true };
    ok("[1] a ZEROED head count no longer answers zero over a full chain", z.auditCount === healthyCount);
    ok("[1] and it SAYS the count was recovered rather than reporting it silently", z.auditCountRecovered === true);
    ok("[1] so the damaged answer DIFFERS from the healthy one", zeroedBody !== healthy);

    // The absent record was already honest, and must stay honest and stay UNQUALIFIED.
    const absent = makeRig(SEED);
    absent.storage.raw().delete("auditHead");
    const a = JSON.parse(stableVerify((await absent.call("/audit/verify")).body)) as { auditCount: number; auditCountRecovered?: true };
    ok("[1] an ABSENT head is still reconstructed to the true count", a.auditCount === healthyCount);
    ok("[1] and is NOT flagged as recovered, because reconstructing an absent pointer is the ordinary path", a.auditCountRecovered === undefined);

    // A NEGATIVE count is unbelievable on its face, with no self-contradiction test needed.
    const negative = makeRig(SEED);
    negative.storage.raw().set("auditHead", { ...head, count: -4 });
    ok("[1] a NEGATIVE count is not believed either", (JSON.parse(stableVerify((await negative.call("/audit/verify")).body)) as { auditCount: number }).auditCount === healthyCount);

    // THE GREEN CONTROL: an edit that changes the record without damaging it. The count is raised to a
    // different, entirely believable value; the engine has no way to know it is wrong and must not claim it
    // recovered anything. Without this, a flag hard-wired to true would pass every arm above.
    const benign = makeRig(SEED);
    benign.storage.raw().set("auditHead", { ...head, count: head.count + 1 });
    const b = JSON.parse(stableVerify((await benign.call("/audit/verify")).body)) as { auditCount: number; auditCountRecovered?: true };
    ok("[1] CONTROL: a believable count is believed, not overridden", b.auditCount === head.count + 1);
    ok("[1] CONTROL: and carries no recovery flag", b.auditCountRecovered === undefined);
  }

  // ==========================================================================================================
  // 2. THE TAIL-DELETION WITNESS: a corrupt anchor is not an absent one
  // ==========================================================================================================
  {
    const healthy = JSON.parse(stableVerify((await makeRig(SEED).call("/audit/verify")).body)) as Record<string, unknown>;
    ok("[2] the healthy chain reports no truncation and no unreadable anchor", healthy.headTruncated === undefined && healthy.headAnchorUnreadable === undefined);

    const head = SEED.get("auditHead") as { headSeq: number; headHash: string; count: number };

    // THE PLANT: an anchor whose headSeq is zero. Before the repair this SKIPPED the truncation check and
    // answered intact:true with nothing said, byte-identical to a sound anchor's answer.
    const zeroed = makeRig(SEED);
    zeroed.storage.raw().set("auditHead", { headSeq: 0, headHash: "", count: 0 });
    const z = JSON.parse(stableVerify((await zeroed.call("/audit/verify")).body)) as Record<string, unknown>;
    ok("[2] a ZEROED anchor is reported as unreadable rather than skipped past", z.headAnchorUnreadable === true);

    // A WRONG-TYPED anchor reaches the same place by a different route.
    const wrongType = makeRig(SEED);
    wrongType.storage.raw().set("auditHead", "corruptfuzz-wrong-type");
    ok("[2] a WRONG-TYPED anchor is reported as unreadable too", (JSON.parse(stableVerify((await wrongType.call("/audit/verify")).body)) as Record<string, unknown>).headAnchorUnreadable === true);

    // THE WITNESS ITSELF STILL WORKS, which is the arm that stops the repair from being a blanket "unreadable".
    const raised = makeRig(SEED);
    raised.storage.raw().set("auditHead", { ...head, headSeq: head.headSeq + 100 });
    const r = JSON.parse(stableVerify((await raised.call("/audit/verify")).body)) as Record<string, unknown>;
    ok("[2] an anchor ABOVE the retained head still reports a truncation", r.headTruncated === true && r.headTruncatedAt === head.headSeq + 100);
    ok("[2] and is NOT reported as unreadable, because it reads perfectly well", r.headAnchorUnreadable === undefined);

    const tailDeleted = makeRig(SEED);
    for (const k of [...tailDeleted.storage.raw().keys()].filter((k) => k.startsWith("audit:")).sort().slice(-3)) tailDeleted.storage.raw().delete(k);
    ok("[2] three deleted tail entries still report a truncation at the anchored head", (JSON.parse(stableVerify((await tailDeleted.call("/audit/verify")).body)) as Record<string, unknown>).headTruncated === true);

    // THE GREEN CONTROL: an ABSENT anchor genuinely says nothing (a chain predating the anchor, or storage
    // wiped whole), so it must stay unflagged. This is the arm that stops the repair reporting an absence as
    // damage, which would cry wolf on every account that upgraded into the anchor.
    const absent = makeRig(SEED);
    absent.storage.raw().delete("auditHead");
    const a = JSON.parse(stableVerify((await absent.call("/audit/verify")).body)) as Record<string, unknown>;
    ok("[2] CONTROL: an ABSENT anchor is not called unreadable", a.headAnchorUnreadable === undefined);
    ok("[2] CONTROL: and is not called truncated either", a.headTruncated === undefined);
  }

  // ==========================================================================================================
  // 3. THE EXPIRY WARNING ZERO
  // ==========================================================================================================
  {
    const healthy = (await makeRig(SEED).call("/expiry/warnings")).body;
    const h3 = JSON.parse(healthy) as { expiryWarnings: number; expiryUnreadable: number };
    ok("[3] a healthy account reports no unreadable expiry rows", h3.expiryUnreadable === 0);
    // The seeded certificate is ten days out, so the healthy account is WARNING. Without that the arms below
    // would compare one zero against another and pass on an account that had nothing to lose.
    ok("[3] and the seeded row IS warning, so each arm below measures a warning that was lost", h3.expiryWarnings === 1);

    const item = SEED.get(EXPIRY_KEY) as Record<string, unknown>;
    // FIVE DAMAGE CLASSES, all of which produced the same fifteen-byte zero before the repair.
    const arms: Array<[string, unknown]> = [
      ["truncate", { id: item.id, label: item.label }],
      ["zero", { ...item, expiresAt: "", label: "", kind: "" }],
      ["wrong-type-numeric", { ...item, expiresAt: 0 }],
      ["wrong-type", { ...item, expiresAt: 0 }],
      ["encoding-mangled", { ...item, expiresAt: "2027-01-\uD800 01T00:00:00.000Z" }],
      ["valid-shape-wrong-value", { ...item, expiresAt: "2027-01-01T00:00:00.000Z-corruptfuzz" }],
    ];
    for (const [name, damaged] of arms) {
      const rig = makeRig(SEED);
      rig.storage.raw().set(EXPIRY_KEY, damaged);
      const body = (await rig.call("/expiry/warnings")).body;
      const parsed = JSON.parse(body) as { expiryWarnings: number; expiryUnreadable: number };
      // TRUNCATE IS THE ONE THIS LAYER CANNOT CATCH, and saying so is better than an assertion that pretends
      // otherwise. A row that lost its `expiresAt` altogether is INDISTINGUISHABLE from a credential that was
      // deliberately created without one, which is a legitimate state the product supports; nothing in the
      // record says a date was ever expected. What IS required is that the warning it used to raise does not
      // survive as a silent zero: the answer must differ from the warning account's, and the remaining honest
      // signal is that the row now reads no-expiry rather than approaching.
      if (name === "truncate") ok(`[3] ${name}: the lost warning is visible as a changed answer, though the row itself cannot be told from a genuine no-expiry credential`, body !== healthy && parsed.expiryWarnings === 0);
      else {
        ok(`[3] ${name}: the unreadable row is COUNTED rather than absorbed into a zero`, parsed.expiryUnreadable === 1);
        ok(`[3] ${name}: so the answer is no longer what an account tracking nothing answers`, body !== healthy);
      }
    }

    // The reference state: the item deleted. It answers zero warnings AND zero unreadable, honestly, and the
    // whole point is that a damaged row no longer answers the same thing.
    const deleted = makeRig(SEED);
    deleted.storage.raw().delete(EXPIRY_KEY);
    const deletedBody = (await deleted.call("/expiry/warnings")).body;
    const damagedRig = makeRig(SEED);
    damagedRig.storage.raw().set(EXPIRY_KEY, { ...item, expiresAt: "not-a-date" });
    const damagedBody = (await damagedRig.call("/expiry/warnings")).body;
    ok("[3] a DAMAGED row and a DELETED row no longer answer byte-identically", damagedBody !== deletedBody);

    // THE GREEN CONTROL: a benign edit. The label changes and the date stays readable, so nothing is
    // unreadable and the count must stay at zero. Without this, a counter wired to the row's mere existence
    // would pass every arm above.
    const benign = makeRig(SEED);
    benign.storage.raw().set(EXPIRY_KEY, { ...item, label: "Corrupt-state certificate (renamed)" });
    ok("[3] CONTROL: a benign label edit leaves nothing unreadable", (JSON.parse((await benign.call("/expiry/warnings")).body) as { expiryUnreadable: number }).expiryUnreadable === 0);
  }

  // ==========================================================================================================
  // 4. THE LOCKOUT PRE-FLIGHT AND THE ONLY OWNER
  // ==========================================================================================================
  {
    const healthy = (await makeRig(SEED).call("/policy/lockout-preflight")).body;
    ok("[4] a healthy account reports no unreadable roster rows", (JSON.parse(healthy) as { rosterUnreadable: number }).rosterUnreadable === 0);

    const grant = SEED.get(OWNER_ROLE_KEY) as Record<string, unknown>;
    const arms: Array<[string, unknown]> = [
      ["wrong-type", "corruptfuzz-wrong-type"],
      ["zero", { ...grant, role: "", subject: "", email: "" }],
      ["valid-shape-wrong-value", { ...grant, role: `${String(grant.role)}-corruptfuzz` }],
      ["encoding-mangled", { ...grant, role: "own\uD800er" }],
    ];
    for (const [name, damaged] of arms) {
      const rig = makeRig(SEED);
      rig.storage.raw().set(OWNER_ROLE_KEY, damaged);
      const pre = (await rig.call("/policy/lockout-preflight")).body;
      const roles = (await rig.call("/roles")).body;
      ok(`[4] ${name}: the roster really did lose the grant (the state under test is real)`, !roles.includes("corruptfuzz-owner@corruptfuzz.example"));
      ok(`[4] ${name}: and the lockout pre-flight NO LONGER answers byte-identically to a healthy account`, pre !== healthy);
      ok(`[4] ${name}: it counts the row it could not read`, (JSON.parse(pre) as { rosterUnreadable: number }).rosterUnreadable >= 1);
    }

    // THE FAILURE DIRECTION, pinned because it BOUNDS the consequence and a later change must not quietly
    // widen it. A corrupted grant must confer nothing, and the next caller must not be bootstrapped into the
    // vacancy it leaves.
    const rig = makeRig(SEED);
    rig.storage.raw().set(OWNER_ROLE_KEY, "corruptfuzz-wrong-type");
    const victim = JSON.parse((await rig.call(`/whoami?email=${encodeURIComponent(OWNER.email as string)}&subject=${OWNER.subject}&method=access`)).body) as { role: string };
    ok("[4] a corrupted grant confers NOTHING (the authorisation path fails closed)", victim.role === "viewer");
    const stranger = JSON.parse((await rig.call("/whoami?email=stranger%40elsewhere.example&subject=sub-stranger&method=access")).body) as { role: string };
    ok("[4] and no stranger is bootstrapped into the vacancy it leaves", stranger.role === "viewer");

    // THE GREEN CONTROL: a benign edit to the same record. The grant is re-stamped with a different granter,
    // which changes the row and damages nothing, so the count must stay at zero.
    const benign = makeRig(SEED);
    benign.storage.raw().set(OWNER_ROLE_KEY, { ...grant, grantedBy: "corruptfuzz-control" });
    const bp = (await benign.call("/policy/lockout-preflight")).body;
    ok("[4] CONTROL: a benign edit leaves nothing unreadable", (JSON.parse(bp) as { rosterUnreadable: number }).rosterUnreadable === 0);
    ok("[4] CONTROL: and the pre-flight reads exactly as it does on the healthy account", bp === healthy);
  }

  if (failures > 0) process.exitCode = 1;
  console.log(failures === 0 ? `\n[corruptfuzz-honesty] PASS: ${checks} checks, 0 failures.` : `\n[corruptfuzz-honesty] FAIL: ${failures} of ${checks} check(s) failing.`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
