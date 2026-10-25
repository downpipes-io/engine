// validate-rekey-begin-order: a re-key never leaves an open hand-over record with nothing pending.
//
// The hand-over record holds the outgoing signer's public key and blocks a second re-key until it is
// settled. If the record opened first and the request then stopped (a scheduler fault, a Worker timeout),
// it stayed open with no pending destination and no route finished it. The record now opens only after the
// target list and the pre-check have run, and it opens with every target pending, so a request that stops
// later leaves destinations the attended route can finish.
//
// NEGATIVE CONTROL: with one destination listed the record opens (so a begin that never opens anything
// cannot pass), and a begin that lists pending ids keeps them until settle. Run:
//   node test/validate-rekey-begin-order.ts

import { beginRekeyRunlogHandover } from "../src/admin/rekey-runlog-handover.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/index.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { encodeVerifier } from "../src/sched/rekey-handover.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 300)}`);
  }
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));

interface Rig {
  dobj: SchedulerDO;
  env: Env;
  stub: DurableObjectStub;
}
function rig(failOn?: string): Rig {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (failOn !== undefined && new URL(url).pathname === failOn) return Promise.reject(new Error("simulated scheduler fault"));
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const env = { SCHEDULER: { idFromName: () => ({}), get: () => stub }, SIGNER_PRIVATE: signerB64() } as unknown as Env;
  return { dobj, env, stub };
}
async function record(r: Rig): Promise<{ open?: boolean; pending?: string[] }> {
  return (await (await r.dobj.fetch(new Request("https://scheduler.internal/rekey-handover"))).json()) as { open?: boolean; pending?: string[] };
}
async function post(r: Rig, path: string, body: unknown): Promise<Response> {
  return r.dobj.fetch(new Request(`https://scheduler.internal${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
}

async function main(): Promise<void> {
  console.log("\na fault before the record opens leaves no record\n");
  {
    const r = rig("/destinations");
    let threw = false;
    try {
      await beginRekeyRunlogHandover(r.env, r.stub);
    } catch {
      threw = true;
    }
    ok("the begin step surfaces the scheduler fault", threw);
    ok("no hand-over record is open after the fault", (await record(r)).open === false, await record(r));
  }

  console.log("\nno destination: nothing to hand over, no record\n");
  {
    const r = rig();
    const res = await beginRekeyRunlogHandover(r.env, r.stub);
    ok("the begin step passes with no target", res.ok === true);
    ok("no record is opened when there is no target", (await record(r)).open === false, await record(r));
  }

  console.log("\nthe record opens with every target pending\n");
  {
    const r = rig();
    const oldV = verifierFrom(await loadSigner(signerB64()));
    const begin = await post(r, "/rekey-handover/begin", { oldVerifier: encodeVerifier(oldV), pending: ["dest_a", ""] });
    ok("negative control: a begin with a pending list opens a record", begin.status === 200 && (await record(r)).open === true);
    ok("the record holds the pending ids until settle", JSON.stringify((await record(r)).pending) === JSON.stringify(["dest_a", ""]), await record(r));
    const second = await post(r, "/rekey-handover/begin", { oldVerifier: encodeVerifier(oldV), pending: ["dest_a"] });
    ok("a second re-key over the open record is refused 409", second.status === 409);
    const bad = rig();
    const badBegin = await post(bad, "/rekey-handover/begin", { oldVerifier: encodeVerifier(oldV), pending: ["dest_a", 7] });
    ok("a pending list that is not all ids is refused 400", badBegin.status === 400);
    const settled = (await (await post(r, "/rekey-handover/settle", { pending: [] })).json()) as { discarded?: boolean };
    ok("settle with nothing left pending closes the record", settled.discarded === true && (await record(r)).open === false);
    const plain = rig();
    await post(plain, "/rekey-handover/begin", { oldVerifier: encodeVerifier(oldV) });
    ok("negative control: a begin with no pending list still opens, with none pending", (await record(plain)).open === true && (await record(plain)).pending?.length === 0);
  }

  console.log(failures === 0 ? "\nREKEY BEGIN ORDER PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
