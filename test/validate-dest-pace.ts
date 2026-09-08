// Vectors for the adaptive destination pacer (dest/pace.ts): the AIMD rate response to pushback,
// the floor, that a healthy rate never stalls a burst, and the fail-soft env knob parsing.
import { DestPacer, destPacerFromEnv, DEFAULT_DEST_RATE_PER_SEC } from "../src/dest/pace.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  console.log("DestPacer adaptive rate (AIMD):");
  {
    const p = new DestPacer({ ratePerSec: 100, burst: 10 });
    ok("starts at the configured base rate", p.effectiveRate() === 100);
    p.observe(503);
    ok("a 503 SlowDown halves the effective rate (multiplicative decrease)", p.effectiveRate() === 50);
    p.observe(429);
    ok("a 429 halves it again", p.effectiveRate() === 25);
    p.observe(200);
    ok("a 2xx recovers additively toward the base (a step, not a jump)", p.effectiveRate() === 35);
    p.observe(301);
    ok("a redirect is neutral (not a congestion signal)", p.effectiveRate() === 35);
    p.observe(403);
    ok("a 4xx auth failure is neutral (not a congestion signal)", p.effectiveRate() === 35);
  }

  console.log("DestPacer floor and recovery:");
  {
    const p = new DestPacer({ ratePerSec: 4, burst: 1 });
    for (let i = 0; i < 10; i++) p.observe(503);
    ok("the multiplicative decrease floors at 1 req/s, never zero or negative", p.effectiveRate() === 1);
    p.observe(200);
    ok("recovery from the floor steps up additively (min step is 1/s)", p.effectiveRate() === 2);
  }

  console.log("DestPacer take() does not stall a healthy rate:");
  {
    const p = new DestPacer({ ratePerSec: 1000, burst: 100 });
    const start = Date.now();
    for (let i = 0; i < 50; i++) await p.take();
    // Deadline is generous (5000ms) so event-loop starvation on a loaded CI host does not
    // flake; the burst is 100 so these 50 takes never actually pace, and a real failure
    // (every take sleeping) would still blow past this.
    ok("50 takes at a generous rate complete promptly (the burst absorbs them)", Date.now() - start < 5000);
  }

  console.log("DestPacer take() actually delays under a slow rate with no burst:");
  {
    // At 2 req/s with a single token, the first take() is free (it spends the lone burst token); the second
    // must wait for the bucket to refill one token, which at 2/s is ~500 ms. A regression that made take()
    // never sleep would complete the second take() promptly and fail this timing proof.
    const p = new DestPacer({ ratePerSec: 2, burst: 1 });
    await p.take(); // spends the single token
    const start = Date.now();
    await p.take(); // must wait for one token at 2/s
    ok("the second take() introduces a measurable delay (>= ~400 ms) when the bucket is empty", Date.now() - start >= 400);
  }

  console.log("destPacerFromEnv is fail-soft:");
  {
    ok("a valid DEST_RATE_PER_SEC is honoured", destPacerFromEnv({ DEST_RATE_PER_SEC: "200" }).effectiveRate() === 200);
    ok("an absent knob falls back to the default", destPacerFromEnv({}).effectiveRate() === DEFAULT_DEST_RATE_PER_SEC);
    ok("an invalid knob falls back rather than throwing", destPacerFromEnv({ DEST_RATE_PER_SEC: "nonsense" }).effectiveRate() === DEFAULT_DEST_RATE_PER_SEC);
    ok("a non-positive knob falls back", destPacerFromEnv({ DEST_RATE_PER_SEC: "0" }).effectiveRate() === DEFAULT_DEST_RATE_PER_SEC);
  }

  console.log(failures === 0 ? "\nDEST PACER PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
