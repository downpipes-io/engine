// doURL builds an absolute URL for a Durable Object fetch; the host is ignored by the DO.
//
// It lives alone, importing nothing, because of what it is used by. router-helpers.ts calls itself a
// leaf and is not one: it reaches sched/scheduler-do.ts for a type, which puts it inside the engine's
// existing import cycles. Anything importing doURL from there inherits those cycles to obtain a
// three-line string builder. Modules outside that graph should take it from here instead.
//
// router-helpers.ts re-exports it, so the 45 call sites that already import it by name from there keep
// working and nothing had to be touched to add this.
export function doURL(path: string): string {
  return `https://scheduler.internal${path}`;
}
