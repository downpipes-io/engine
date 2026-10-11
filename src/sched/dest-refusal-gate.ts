// dest-refusal-gate.ts -- the cap on the audit rows a refused destination save may write. A client that retries a
// refused save in a loop would otherwise push real rows off the audit chain (AUDIT_CAP drops the oldest). The
// gate admits at most one row per refusal class per minute and DEST_REFUSAL_ROWS_PER_HOUR rows an hour in all.
// A refusal the gate does not admit is still counted by the admin-refusal aggregate, so the attempts are not lost.
// Pure: the scheduler DO keeps the state under DEST_REFUSAL_GATE_KEY.

export const DEST_REFUSAL_GATE_KEY = "diag:destrefusalgate";
export const DEST_REFUSAL_CLASS_WINDOW_MS = 60_000;
export const DEST_REFUSAL_HOUR_MS = 3_600_000;
export const DEST_REFUSAL_ROWS_PER_HOUR = 12;
// The most classes remembered. The class vocabulary is closed and smaller than this; the cap is defence in depth.
const DEST_REFUSAL_LAST_CAP = 32;

export interface DestRefusalGateState {
  hourStart: number;
  hourRows: number;
  last: Record<string, number>;
}

export function emptyDestRefusalGate(): DestRefusalGateState {
  return { hourStart: 0, hourRows: 0, last: {} };
}

/**
 * admitDestRefusalRow decides whether a refusal of `cls` at `now` may write a row, and returns the next state.
 *
 * @param state - the stored gate state (any value; a malformed one is treated as empty).
 * @param cls - the refusal class.
 * @param now - the time in milliseconds.
 */
export function admitDestRefusalRow(state: DestRefusalGateState | undefined, cls: string, now: number): { admit: boolean; state: DestRefusalGateState } {
  const s: DestRefusalGateState =
    state !== undefined && typeof state === "object" && state !== null && Number.isFinite(state.hourStart) && Number.isFinite(state.hourRows) && typeof state.last === "object" && state.last !== null
      ? { hourStart: state.hourStart, hourRows: state.hourRows, last: { ...state.last } }
      : emptyDestRefusalGate();
  if (now - s.hourStart >= DEST_REFUSAL_HOUR_MS || now < s.hourStart) {
    s.hourStart = now;
    s.hourRows = 0;
  }
  for (const k of Object.keys(s.last)) if (!(now - (s.last[k] ?? 0) < DEST_REFUSAL_CLASS_WINDOW_MS)) delete s.last[k];
  const lastAt = s.last[cls];
  if (lastAt !== undefined && now - lastAt < DEST_REFUSAL_CLASS_WINDOW_MS) return { admit: false, state: s };
  if (s.hourRows >= DEST_REFUSAL_ROWS_PER_HOUR) return { admit: false, state: s };
  if (Object.keys(s.last).length >= DEST_REFUSAL_LAST_CAP) return { admit: false, state: s };
  s.last[cls] = now;
  s.hourRows++;
  return { admit: true, state: s };
}
