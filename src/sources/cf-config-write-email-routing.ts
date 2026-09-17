// Write-back for the `email-routing` surface, which is TWO things behind one id.
//
// WHY IT NEEDS ITS OWN WRITER
// ---------------------------
// Every other surface is either one object or one collection. This one reads `{ settings, rules }`: the
// zone's Email Routing configuration plus its routing rules, because Cloudflare splits them across two
// endpoints and the surface composes them so a backup holds both. No generic writer fits that shape, so
// the surface has had NO writer at all, and a customer's routing rules have been backed up and verified
// recoverable while being impossible to re-apply in band.
//
// There is no other zone-scoped surface holding those rules. `account-email-routing-rules` is
// account-scoped and a different object; `email-routing-catch-all` is the catch-all only.
//
// THE OWNERSHIP BOUNDARY, WHICH IS THE PART WORTH GETTING RIGHT
// -------------------------------------------------------------
// The catch-all rule appears in BOTH surfaces. Cloudflare lists it in /email/routing/rules alongside the
// ordinary rules AND exposes it at its own /email/routing/rules/catch_all, and `email-routing-catch-all`
// is already a proven surface that writes it there. Verified on a live zone: the id returned by the
// catch-all endpoint is present in the rules list.
//
// So this writer EXCLUDES the catch-all from the rules half. Two surfaces writing one object through two
// endpoints is a race even when both write the same value, and the dedicated endpoint has its own
// semantics (it cannot be created or deleted, only updated). One owner per object.
//
// WHAT IT DOES NOT DO
// -------------------
// It does not enable or disable Email Routing. `enabled` moves through Cloudflare's own enable/disable
// endpoints and turning routing on for a zone is a mail-delivery change, not a configuration detail; a
// restore that silently started routing a customer's mail would be a surprise of the worst kind. The
// settings half writes the ordinary configuration fields and leaves that switch alone.

import type { Meter } from "../meter.ts";
import type { CfApi, CfConfigSurface, ConfigWriteResult } from "./cf-config-core.ts";
import { classifyCfWriteSkip } from "./cf-config-fault.ts";
import { asJson, jsonEqual, type ConfigChange, stripStamped } from "./cf-config-shared.ts";
import { writeListSpec } from "./cf-config-write.ts";

type Ids = { accountId: string; zoneId?: string };

// Settings fields this writer will send. An ALLOW-list rather than a strip-list, because the settings
// object is mostly server state (status, synced, admin_locked, created, modified, tag, name) and the two
// genuinely configurable fields are easier to name than the eleven that are not.
//
// `enabled` is deliberately absent: see the header. `skip_wizard` is a UI breadcrumb Cloudflare stores
// with the settings and it is the customer's, so it is restored.
const SETTINGS_FIELDS = ["skip_wizard", "support_subaddress"] as const;

function isCatchAll(rule: Record<string, unknown>): boolean {
  // Cloudflare marks it two ways and neither is documented as stable on its own, so both are accepted:
  // the priority sentinel it always carries, and a matcher list that is the single "all" matcher.
  if (rule.priority === 2147483647) return true;
  const m = rule.matchers;
  return Array.isArray(m) && m.length === 1 && (m[0] as Record<string, unknown> | undefined)?.type === "all";
}

export function writeEmailRouting(): NonNullable<CfConfigSurface["write"]> {
  const fn = async (api: CfApi, ids: Ids, data: unknown, opts: { dryRun: boolean }, meter?: Meter): Promise<ConfigWriteResult> => {
    const snap = data as { settings?: Record<string, unknown>; rules?: unknown } | null;
    if (snap === null || typeof snap !== "object" || Array.isArray(snap)) {
      return { changes: [], applied: 0, skipped: [{ path: "email-routing", reason: "the snapshot carries no object for this surface", cls: "other" }] };
    }

    const changes: ConfigChange[] = [];
    const skipped: ConfigWriteResult["skipped"] = [];
    let applied = 0;

    // --- settings half -------------------------------------------------------------------------------
    const settingsPath = `/zones/${ids.zoneId}/email/routing`;
    const snapSettings = snap.settings;
    if (snapSettings !== undefined && snapSettings !== null && typeof snapSettings === "object" && !Array.isArray(snapSettings)) {
      meter?.spend(1, "cfApiRead");
      const live = (await api.get(settingsPath)) as Record<string, unknown> | null;
      const want: Record<string, unknown> = {};
      for (const f of SETTINGS_FIELDS) {
        const v = (snapSettings as Record<string, unknown>)[f];
        if (v !== undefined && !jsonEqual(v, live === null ? undefined : live[f])) want[f] = v;
      }
      if (Object.keys(want).length > 0) {
        changes.push({ path: "email-routing/settings", action: "change", from: asJson(stripStamped(live ?? {})), to: asJson(want) });
        if (!opts.dryRun) {
          try {
            meter?.spend(1);
            await api.send("PATCH", settingsPath, want);
            applied += 1;
          } catch (e) {
            skipped.push({ path: "email-routing/settings", reason: (e as Error).message.replace(/^Cloudflare API [A-Z]+ [^:]+:\s*/, "").slice(0, 120), cls: classifyCfWriteSkip(e) });
          }
        }
      }
    }

    // --- rules half ----------------------------------------------------------------------------------
    // Routed through writeListSpec so the rules inherit the whole shared contract: never a wholesale
    // collection PUT, additive with no pruning, idempotent on re-run, fail-open per rule, and a live-only
    // rule named and refused rather than deleted.
    const snapRules = Array.isArray(snap.rules) ? (snap.rules as Array<Record<string, unknown>>).filter((r) => !isCatchAll(r)) : [];
    const rulesResult = await writeListSpec(
      {
        listPath: (i: Ids) => `/zones/${i.zoneId}/email/routing/rules`,
        itemPath: (i: Ids, id: string) => `/zones/${i.zoneId}/email/routing/rules/${id}`,
        // The catch-all is filtered from the LIVE side too. Without this it reads as a live-only rule the
        // snapshot omits, and the additive contract would name and report it on every single run.
        readLive: async (a: CfApi, i: Ids, m?: Meter): Promise<unknown[]> => {
          m?.spend(1, "cfApiRead");
          const r = (await a.get(`/zones/${i.zoneId}/email/routing/rules`)) as unknown;
          return Array.isArray(r) ? (r as Array<Record<string, unknown>>).filter((x) => !isCatchAll(x)) : [];
        },
        identity: (it) => (typeof it.id === "string" && it.id !== "" ? it.id : `email-routing-rule:${asJson(it.matchers)}|${asJson(it.actions)}`),
        // A routing rule's NAME is optional and frequently empty, so the natural key is what the rule
        // DOES: its matchers and its actions. Two rules that match the same mail and do the same thing
        // are the same rule however they are named.
        natural: (it) => `email-routing-rule:${asJson(it.matchers)}|${asJson(it.actions)}`,
        serverId: (it) => (typeof it.id === "string" ? it.id : ""),
        createMethod: "POST",
        updateMethod: "PUT",
        nestedCollections: ["matchers", "actions"],
        body: (it) => {
          const b = stripStamped(it);
          // `tag` mirrors the id and `source` reports where the rule came from. Both are Cloudflare's.
          delete b.tag;
          delete b.source;
          return b;
        },
        label: "email-routing/rules",
      },
      api,
      ids,
      snapRules,
      opts,
      meter,
    );

    return {
      changes: [...changes, ...rulesResult.changes],
      applied: applied + rulesResult.applied,
      skipped: [...skipped, ...rulesResult.skipped],
    };
  };
  return fn;
}
