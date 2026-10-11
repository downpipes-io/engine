// Unusual-location / new-network sign-in notification (ASVS V6.3.5). OFF BY DEFAULT (an operator opts in per
// account, notifyNewSignInContext). When on, a successful sign-in's COARSE network context is compared against
// a small, bounded, per-operator "seen contexts" baseline; a materially NEW context emits a notify so a human
// can spot a sign-in from a place they do not recognise. It runs entirely in the customer's OWN account (the
// scheduler DO) -- NO VENDOR CUSTODY, no phone-home.
//
// PRIVACY / no-custody (sacred): the raw source IP is NEVER stored. Only a COARSE prefix is kept -- an IPv4
// /24 or an IPv6 /48 -- which is enough to notice "a different network/region" while being too coarse to be a
// tracking identifier, and it lives only in the customer's own DO. The seen-set is BOUNDED (a size cap plus a
// TTL) so it can never grow without limit or become a long-term movement log.
//
// NOISE control (the reason it is off by default and coarse): mobile/carrier-NAT churn changes the low octets
// constantly, so comparing raw IPs would cry wolf on every reconnect. A /24 (v4) / /48 (v6) prefix absorbs
// that churn while still flagging a genuinely different network. The FIRST context ever seen establishes the
// baseline and does NOT alert (there is nothing to compare against yet); only a later, different context does.

// SEEN_CONTEXT_CAP bounds the per-operator baseline. A handful of networks (home, office, phone, a VPN) covers
// a normal operator; the cap evicts the OLDEST beyond it so a travelling user does not accumulate an unbounded
// history and the record stays a small, fixed cost.
export const SEEN_CONTEXT_CAP = 10;

// SEEN_CONTEXT_TTL_MS forgets a context not seen for this long (90 days), so the baseline is a ROLLING recent
// window: a network you have not used in three months reads as new again (a reasonable "is this still you?"),
// and a stale entry cannot pad the set forever. That rule holds UNIFORMLY, including when the TTL takes the
// LAST row: an operator who has not signed in at all for the window has no recent baseline, and the next
// sign-in is reported as new (and as a lapse) rather than silently becoming the new baseline. See
// evaluateSignInContext -- treating that case as a first-ever baseline INVERTED the alert.
export const SEEN_CONTEXT_TTL_MS = 90 * 24 * 60 * 60 * 1000;

// SeenContext is one baseline entry: the COARSE prefix (never a raw IP) and when it was last seen (epoch ms,
// for the TTL sweep + oldest-eviction). Redaction-safe by construction (a /24 or /48 prefix string only).
export interface SeenContext {
  prefix: string;
  lastAt: number;
}

// coarseSignInPrefix reduces a source IP to its COARSE network prefix: an IPv4 /24 (first three octets, last
// zeroed) or an IPv6 /48 (first three hextets). It returns null for a missing/unparseable IP, in which case
// the caller SKIPS the check entirely (never alert on a context we could not compute -- fail safe, no noise).
// The raw IP is used ONLY to derive this prefix and is never returned or stored.
export function coarseSignInPrefix(ip: string | null | undefined): string | null {
  if (typeof ip !== "string") return null;
  const t = ip.trim();
  if (t.length === 0) return null;
  // IPv4 dotted-quad -> /24.
  if (!t.includes(":")) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
    if (m === null) return null;
    const octets = [m[1], m[2], m[3], m[4]].map((o) => Number(o));
    if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }
  // IPv6 -> /48 (first three hextets). Expand a single "::" run, validate hextets, normalise each hextet.
  const hextets = expandIpv6(t);
  if (hextets === null) return null;
  return `${hextets[0]}:${hextets[1]}:${hextets[2]}::/48`;
}

// expandIpv6 expands an IPv6 literal to its 8 normalised hextets (lowercase, no leading zeros), handling at
// most one "::" run, or null when the literal is malformed. IPv4-mapped tails are rejected (null) -- they are
// rare for a browser source and a null simply skips the coarse check (fail safe). Kept small + pure. The
// recovery audit fold (sched/audit-fold.ts) reuses it for its /64 grouping.
export function expandIpv6(ip: string): string[] | null {
  const doubleCount = (ip.match(/::/g) ?? []).length;
  if (doubleCount > 1) return null; // at most one "::" is legal
  let parts: string[];
  if (doubleCount === 1) {
    const [head = "", tail = ""] = ip.split("::");
    const headParts = head.length > 0 ? head.split(":") : [];
    const tailParts = tail.length > 0 ? tail.split(":") : [];
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    parts = [...headParts, ...Array<string>(missing).fill("0"), ...tailParts];
  } else {
    parts = ip.split(":");
  }
  if (parts.length !== 8) return null;
  const out: string[] = [];
  for (const p of parts) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null;
    out.push(parseInt(p, 16).toString(16)); // normalise (drop leading zeros, lowercase) for stable compares
  }
  return out;
}

// ipSourceGroup names the client that a per-source control keys on: an IPv4 address as itself, and an IPv6
// address by its /64, because one host commonly holds a whole /64. The per-IP sign-in limiters and the
// recovery audit fold (sched/audit-fold.ts) all key on it. It normalises the input first, so one address
// cannot leave its group by a different spelling: upper case, leading zeros, a compressed or full form,
// brackets, a zone id ("%eth0"), or a dotted IPv4 tail. An IPv4-mapped address (::ffff:a.b.c.d) groups as the
// IPv4 address it carries. A value that does not parse is returned trimmed and lowercased.
export function ipSourceGroup(ip: string): string {
  let t = ip.trim().toLowerCase();
  if (t.startsWith("[") && t.endsWith("]")) t = t.slice(1, -1);
  if (!t.includes(":")) {
    const v4 = ipv4Octets(t);
    return v4 === null ? t : v4.join(".");
  }
  const zone = t.indexOf("%");
  if (zone >= 0) t = t.slice(0, zone);
  // A dotted IPv4 tail becomes the two hextets it stands for, so expandIpv6 can read the address.
  const lastColon = t.lastIndexOf(":");
  const tail = t.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = ipv4Octets(tail);
    if (v4 === null) return t;
    const [a = 0, b = 0, c = 0, d = 0] = v4;
    t = `${t.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const h = expandIpv6(t);
  if (h === null) return t;
  if (h.slice(0, 5).every((x) => x === "0") && h[5] === "ffff") {
    const hi = parseInt(h[6] ?? "0", 16);
    const lo = parseInt(h[7] ?? "0", 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return `${h.slice(0, 4).join(":")}::/64`;
}

// ipv4Octets reads a dotted-quad IPv4 address into its four octets, or null when it is not one.
function ipv4Octets(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (m === null) return null;
  const octets = [m[1], m[2], m[3], m[4]].map((o) => Number(o));
  return octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? octets : null;
}

// evaluateSignInContext is the PURE decision behind the notification. Given the current per-operator seen-set,
// the coarse prefix of THIS sign-in, and now, it (1) prunes entries older than the TTL, (2) decides whether the
// prefix is materially NEW, (3) records/refreshes the prefix, and (4) caps the set to the CAP most-recent
// entries. It returns the newness verdict, whether the baseline had LAPSED, and the bounded updated set for the
// caller to persist. No storage, no I/O, no raw IP -- unit-testable and redaction-safe.
//
// THE EMPTY LIVE SET HAS TWO CAUSES AND THEY ARE NOT THE SAME EVENT (the defect this signature exists to fix).
// `isNew = live.length > 0 && !known` treated them as one, so an operator whose every context had aged out --
// which is what a 90-day dormancy IS, reached by doing nothing at all -- got NO alert on the next sign-in from
// ANY network on earth, and the alerting was not merely absent but INVERTED: the unrecognised sign-in silently
// became the new baseline, and the operator's OWN next sign-in from their own network was then the one that
// alerted. The account most likely to lapse is the rarely-used break-glass Owner, which is the one whose
// compromise matters most, and the whole point of the opt-in is "tell me about a sign-in I would not recognise".
//
// So the FIRST-EVER exemption is kept and narrowed to what it was always arguing: an operator with NO usable
// stored context has nothing to compare against, so their first sign-in establishes the baseline. An operator
// whose stored contexts were PRUNED BY THE TTL has plenty to compare against -- we know they used prefix X and
// that it is now too old to count -- and this module's own header already states the rule for that case: "a
// network you have not used in three months reads as new again". Applying that rule uniformly is the fix.
// It costs at most one warning per dormancy per operator, which is the notification working, not noise.
export function evaluateSignInContext(
  seen: readonly SeenContext[],
  prefix: string,
  now: number,
): { isNew: boolean; baselineLapsed: boolean; updated: SeenContext[] } {
  // Prune expired entries (rolling window) and drop any malformed/duplicate-prefix rows defensively.
  const live: SeenContext[] = [];
  const seenPrefixes = new Set<string>();
  // prunedByTtl counts ONLY the rows the TTL dropped. A malformed or duplicate row is not evidence that this
  // operator ever had a baseline, so it must not make a genuine first-ever sign-in read as a lapse.
  let prunedByTtl = 0;
  for (const c of seen) {
    if (c === null || typeof c.prefix !== "string" || c.prefix.length === 0) continue;
    if (typeof c.lastAt !== "number" || !Number.isFinite(c.lastAt)) continue;
    if (now - c.lastAt >= SEEN_CONTEXT_TTL_MS) {
      prunedByTtl++;
      continue; // expired
    }
    if (seenPrefixes.has(c.prefix)) continue; // de-dupe
    seenPrefixes.add(c.prefix);
    live.push(c);
  }
  const known = seenPrefixes.has(prefix);
  // baselineLapsed: this operator HAD a baseline and every row of it aged out. Reported separately from isNew
  // because the caller records it as its own fact -- it is the difference between "you signed in from somewhere
  // new" and "we had no recent baseline for you at all", and it is what explains an alert on a home network.
  const baselineLapsed = live.length === 0 && prunedByTtl > 0;
  // A genuinely first-ever context (nothing usable stored) is NOT an alert: it establishes the baseline. Every
  // other unrecognised context is, INCLUDING the first sign-in after a lapse, whatever prefix it carries.
  const isNew = (live.length > 0 || baselineLapsed) && !known;
  // Record/refresh THIS prefix at now (so a returning context slides its TTL and does not expire under you).
  const updatedMap = live.filter((c) => c.prefix !== prefix);
  updatedMap.push({ prefix, lastAt: now });
  // Cap: keep the CAP most-recently-seen entries (evict the oldest first) so the set stays bounded.
  updatedMap.sort((a, b) => b.lastAt - a.lastAt);
  const updated = updatedMap.slice(0, SEEN_CONTEXT_CAP);
  return { isNew, baselineLapsed, updated };
}
