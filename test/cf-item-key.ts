// itemKey: the path segment that addresses ONE item of a Cloudflare collection.
//
// This lives in its own module so the addressing rule has one implementation rather than a remembered
// rule. The rule is not "id, else name": several collections carry BOTH, and only the id-like field
// addresses the item. Getting the order wrong builds a DELETE against a name-shaped path, Cloudflare
// answers "Method not allowed for this authentication scheme", the object survives, and the next run of
// that surface fails with a phantom "already exists".
//
// Order: `id`, then any `*_id` (network_id, subnet_id, and whatever Cloudflare invents next), then `name`
// LAST, for the collections that genuinely have no id at all. access-tags is the one that needs that
// fallback: it is keyed by name and carries no id field.
export function itemKey(o: Record<string, unknown>): string {
  if (typeof o.id === "string" && o.id !== "") return o.id;
  for (const k of Object.keys(o)) {
    if (/_id$/.test(k) && typeof o[k] === "string" && o[k] !== "") return o[k] as string;
  }
  // Some collections key on their own noun rather than `id`: Turnstile widgets use `sitekey`.
  for (const k of ["sitekey", "tag", "site_tag", "key"]) {
    const v = o[k];
    if (typeof v === "string" && v !== "") return v;
  }
  return typeof o.name === "string" ? o.name : "";
}
