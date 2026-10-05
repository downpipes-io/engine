// The dependency-free half of destination-id resolution (dest/factory.ts resolveDestination is the other).
// It is a leaf so the scheduler DO and the admin classifiers can read these without importing the factory.

/** DEPLOY_DEST_ID is the one reserved, engine-minted id for the synthetic deploy-time destination record
 * (StoredDestination source:"deploy", sched/scheduler-do-limits.ts). It lives in this leaf so the destination
 * resolver (dest/factory.ts resolveDestination) and the scheduler DO share one constant with no import cycle;
 * scheduler-do-limits.ts re-exports it, so every existing import path is unchanged.
 *
 * Reserved so a console-submitted id can never collide with it: putDest's caller-supplied id path is for
 * EDITING an existing console destination, and the router only ever forwards an id it read back from a prior
 * add/list response, so a customer-chosen collision is not a live path, but a defence in depth is a citation
 * and an equality check, not a comment. */
export const DEPLOY_DEST_ID = "deploy";

/**
 * The closed reasons a NAMED destination id cannot be served (dest/factory.ts resolveDestination):
 *   not-configured          the id names no stored destination (a removed destination under a live downpipe)
 *   deploy-binding-missing  the id is DEPLOY_DEST_ID but this deployment declares no env destination at all
 */
export type DestResolutionRefusal = "not-configured" | "deploy-binding-missing";

/**
 * DestResolutionError is the throw a caller that cannot proceed without its named destination raises from an
 * ok:false resolution. It carries the closed reason, so a classifier reads the reason and never the message.
 * The not-configured message keeps the "is not configured" wording classifySealDestError keys on;
 * cron/seal-dispatch.ts sealDestErrorClassOf reads deploy-binding-missing off the error itself.
 */
export class DestResolutionError extends Error {
  readonly resolutionReason: DestResolutionRefusal;
  constructor(reason: DestResolutionRefusal, destinationId: string, owner?: string) {
    const whose = owner !== undefined ? ` for downpipe ${owner}` : "";
    super(
      reason === "deploy-binding-missing"
        ? `destination ${destinationId}${whose} names the deploy-time destination, but this deployment declares none (no DEST_R2 binding and no DEST_* variables)`
        : `destination ${destinationId}${whose} is not configured`,
    );
    this.name = "DestResolutionError";
    this.resolutionReason = reason;
  }
}

/**
 * destResolutionRefusalOf reads the closed reason off a DestResolutionError, or null for anything else.
 *
 * @param e - a thrown value.
 * @returns the refusal reason, or null.
 */
export function destResolutionRefusalOf(e: unknown): DestResolutionRefusal | null {
  const r = (e as { resolutionReason?: unknown } | null)?.resolutionReason;
  return r === "not-configured" || r === "deploy-binding-missing" ? r : null;
}
