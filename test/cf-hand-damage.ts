// The hand-written damage table, kept in its own module so it can be CHECKED without being RUN.
//
// live-cf-singleton-prove.ts calls main() at module scope, so importing the table from there would start a
// harness that deliberately damages a live account whenever DOWNPIPE_LIVE_CF=1 happened to be set in the
// environment. A validation gate must never be able to do that.
//
// validate-hand-damage-vs-schema.ts checks every entry below against Cloudflare's published OpenAPI.

// HAND-WRITTEN damage, for surfaces the prover's generic walk cannot reach.
//
// That walk's flipOf only knows two-valued vocabularies, so a three-member enum, a number with a declared range, or a
// field buried beside a plan-gated sibling all report NOT-EXERCISABLE. That verdict is honest about the
// prober and says nothing about the writer, and it was covering five surfaces that customers actually
// configure: DNS, Access, and the two API Shield validation settings.
//
// EVERY VALUE BELOW IS QUOTED FROM CLOUDFLARE'S PUBLISHED OPENAPI SCHEMA, the same vendored copy
// validate-autoprove-bodies-vs-schema.ts checks bodies against, read at the exact path and verb the
// surface's own writer uses. That is the whole reason this table is allowed to exist. The rule it does not
// break is the one written above flipOf in the prover: do not guess at an enum. Two misattributed Cloudflare 500s in this
// work came from guessing, and the difference here is that the legal values are being read rather than
// supposed. A value that is not in the schema does not belong in this table.
//
// `values` is a list of candidates, not a single target, because the damage must DIFFER from what the
// account currently holds. The first candidate that differs is used, so a surface already sitting on one of
// them is still exercisable rather than silently skipped.
export interface HandDamage {
  path: Array<string | number>;
  values: readonly unknown[];
  why: string;
}

export const HAND_DAMAGE: ReadonlyMap<string, readonly HandDamage[]> = new Map<string, readonly HandDamage[]>([
  [
    "url-normalization",
    [{ path: ["type"], values: ["rfc3986", "cloudflare"], why: 'PUT /zones/{zone_id}/url_normalization declares type as enum ["cloudflare","rfc3986"]. Its sibling `scope` has three members and is left alone.' }],
  ],
  [
    "access-key-configuration",
    [{ path: ["key_rotation_interval_days"], values: [90, 180], why: "PUT /accounts/{account_id}/access/keys declares key_rotation_interval_days as a number with minimum 21 and maximum 365. Both candidates sit inside that range." }],
  ],
  [
    "api-shield-schema-validation-settings",
    [{ path: ["validation_default_mitigation_action"], values: ["log", "none"], why: 'PATCH /zones/{zone_id}/api_gateway/settings/schema_validation declares validation_default_mitigation_action as enum ["none","log","block",null].' }],
  ],
  [
    "schema-validation-settings",
    [{ path: ["validation_default_mitigation_action"], values: ["log", "none"], why: 'PATCH /zones/{zone_id}/schema_validation/settings declares validation_default_mitigation_action as enum ["none","log","block"].' }],
  ],
  [
    // Not an enum problem. The generic walk finds a boolean nested under zone_defaults, and the writer's
    // top-level PATCH diff then carries the whole of zone_defaults, including flattening fields this plan
    // does not allow, so the write is refused for a reason that has nothing to do with the field chosen.
    // Pinning the path to the top-level boolean keeps the diff to the one key under test.
    "account-dns-settings",
    [
      // Tried first and expected to fall through on this account. The field IS declared in the PATCH body,
      // but the GET returns only zone_defaults, so it is write-only here and the prover skips a candidate it
      // cannot read a current value for. Kept because it is the cheapest damage if an account ever does
      // return it, and because the fall-through is the documented reason the nested entry below exists.
      { path: ["enforce_dns_only"], values: [true, false], why: "PATCH /accounts/{account_id}/dns_settings declares enforce_dns_only as a top-level boolean." },
      // The working candidate. Every readable field on this surface is nested under zone_defaults, so a
      // top-level-only table cannot reach any of them.
      //
      // multi_provider rather than the alternatives, and the choice is the whole point. The generic walk
      // reaches foundation_dns first and is refused: it must match the Advanced Nameservers nameserver type.
      // secondary_overrides is secondary DNS and flatten_all_cnames is plan-gated, so both invite the same
      // class of refusal. multi_provider is the field that proved the zone-scoped dns-settings sibling.
      { path: ["zone_defaults", "multi_provider"], values: [true, false], why: "PATCH /accounts/{account_id}/dns_settings declares zone_defaults.multi_provider as a boolean, visible once the allOf branches of zone_defaults are merged rather than reading only the first." },
    ],
  ],
]);
