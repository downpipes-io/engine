// zone-account.ts -- a cf-config source's zoneId must belong to the source's own accountId.
//
// The discovery token is account-wide, and the zone surfaces read /zones/<zoneId>/... with it. The save-time
// scope check judges the accountId only, so a zoneId in another account that the token reaches would be read
// and sealed under an in-scope accountId. The zone is therefore looked up and its owning account compared with
// the source's accountId (hex, compared lowercased). Anything other than a clear match is a refusal: a zone
// the token cannot read, a reply without an account, or a different account.

import { CF_API_BASE } from "../lib/outbound.ts";

// zoneInSourceAccount reports whether zoneId is owned by accountId. A network fault propagates to the caller.
export async function zoneInSourceAccount(token: string, accountId: string, zoneId: string, fetchFn: typeof fetch = fetch): Promise<boolean> {
  const resp = await fetchFn(`${CF_API_BASE}/zones/${encodeURIComponent(zoneId)}`, {
    method: "GET",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    redirect: "manual",
  });
  if (!resp.ok) return false;
  const body = (await resp.json()) as { result?: { account?: { id?: unknown } } };
  const owner = body.result?.account?.id;
  return typeof owner === "string" && owner.toLowerCase() === accountId.toLowerCase();
}

// zoneRefused is true when the source names a zone that is not in its account. A source with no zoneId is
// never refused here.
export async function zoneRefused(token: string, source: { accountId?: unknown; zoneId?: unknown }, fetchFn: typeof fetch = fetch): Promise<boolean> {
  if (typeof source.zoneId !== "string" || source.zoneId === "") return false;
  if (typeof source.accountId !== "string" || source.accountId === "") return true;
  return !(await zoneInSourceAccount(token, source.accountId, source.zoneId, fetchFn));
}
