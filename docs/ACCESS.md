# Cloudflare Access and identity-provider wiring

## Access is optional

Cloudflare Access and identity providers are entirely optional. downpipes runs fully on the
shared `ADMIN_TOKEN` path with no Cloudflare Zero Trust seats and no identity-provider licences.
The engine will never gate a backup, a recovery, or any data-plane operation on whether Access
is configured.

The reason to add Access is attributability. Without it, every admin call is authenticated by a
shared bearer token: the engine knows the call was authorised, but not by whom. With Access,
each caller is identified by a verified email, roles are per-person, and the audit log records who
did what. If you are the sole operator and the shared token is enough for your purposes, you need
not read further.

`ADMIN_TOKEN_DISABLED` (the Access-only hardening mode described at the end of this document) is
opt-in and off by default. Enabling it is never required.

## Licence cost

The answer is: it depends on your headcount and chosen provider, and pricing changes. Verify each
vendor's current terms before committing.

**Cloudflare Zero Trust** has a free tier that has historically covered up to 50 users; paid
plans are per seat beyond that limit. Verify the current free-tier limit at
<https://www.cloudflare.com/plans/zero-trust/>.

**GitHub as a login method** is free. Cloudflare Access can authenticate users via GitHub OAuth
at no additional cost from either Cloudflare or GitHub. GitHub team membership can drive
group-based roles, and that team data is covered by the standard GitHub account you already have.
This is the zero-licence attributable path: GitHub login + Cloudflare Access free tier (under
the seat limit) gives per-person SSO and team-based roles at no licence cost.

**Microsoft Entra ID** basic SSO is available on free and included Entra ID tiers (such as those
bundled with Microsoft 365). However, emitting group-membership claims to an external service
(which is what lets the engine resolve group-based roles) can require an Entra ID P1 or P2 plan,
depending on whether you use the groups claim directly or application-role claims. Verify with
Microsoft before relying on group claims from a free Entra tier.

**Okta** is a paid product. Use it if your organisation already pays for it.

## How role resolution works

The engine has six built-in roles (plus composable custom roles via /admin/custom-roles). The four cumulative core roles, lowest to highest:

| Role       | Can do                                              |
|------------|-----------------------------------------------------|
| `viewer`   | Read status, audit log, run history                 |
| `operator` | All of viewer, plus create/manage downpipes, trigger runs, record drill evidence |
| `approver` | All of operator, plus approve restore requests (dual-control) |
| `owner`    | All of approver, plus manage member roles and group-role mappings |

The token-fallback path (`ADMIN_TOKEN`) resolves to `owner` unconditionally. It is all-or-nothing
and not attributable: the audit log records that an action was taken, not by whom. It is the
break-glass, not the day-to-day administration path.

With Access configured, each authenticated caller is identified by their verified email. The
engine resolves their role in this order:

1. The explicit per-email grant in the role table (managed from the Access and Security screen
   in the console). An absent or expired grant resolves to `viewer`.
2. If the caller's verified Access token carried a groups claim (see provider setup below), the
   engine looks up each group name in the group-role mapping. The highest matching role, capped
   at `approver`, is the group-conferred role.
3. The effective role is the higher of (1) and (2). An explicit per-email grant wins ties: it is
   the more specific, named authority.

**Owner cannot be conferred by a group.** The engine enforces this at two points: the API rejects
an attempt to map a group to `owner`, and the resolution itself caps any group-conferred role to
`approver`. Owner is always an explicit, named, per-email grant. This keeps the last-Owner guard
coherent: the engine refuses to remove or demote the sole remaining Owner, and that guard counts
only explicit per-email Owner entries, not group mappings.

The first authenticated Access caller to reach the engine bootstraps as Owner (the role table is
written immediately so a fresh tenant can administer roles). Subsequent role assignments are made
from the Access and Security screen.

## Setting up Cloudflare Access

Regardless of which login method you use, the overall wiring is the same:

1. Create a login method in Cloudflare Zero Trust (one step per provider, below).
2. Create an Access application protecting the engine and console custom domains.
3. Set `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` in the engine's `wrangler.toml`.

The engine verifies the RS256-signed JWT that Access injects on every request
(`cf-access-jwt-assertion` header). It fetches Cloudflare's public keys from
`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, verifies the signature, checks the
issuer, audience, expiry and not-before, and only then trusts the email and groups from the
signed payload. Trusting the header without verification would be an authentication bypass; the
engine does not do that.

### GitHub

**On GitHub (your step):**

Create an OAuth App under your GitHub organisation:
Settings > Developer settings > OAuth Apps > New OAuth App. The authorisation callback URL must
be `https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`. Note the Client ID and
generate a Client Secret.

**In Cloudflare Zero Trust:**

Settings > Authentication > Login methods > Add new > GitHub. Enter the Client ID and Client
Secret. Save.

**Sending team membership as groups:**

When you configure the GitHub login method, Cloudflare Access can request the `read:org` scope,
which lets it read the caller's GitHub team memberships and include them in the JWT as the
`groups` claim. Enable this in the login-method settings. The groups the engine receives will be
of the form `<org>/<team-slug>` (for example, `myorg/ops`). Use that exact form as the group
name when creating a group-role mapping.

**Creating the Access application:**

In Cloudflare Zero Trust, go to Access > Applications > Add an application > Self-hosted. Enter
a name, and add both the engine custom domain and the console custom domain as application
domains. Configure the policy to allow the login method you just added (for example, allow all
GitHub users in your organisation, or restrict to specific teams). After saving, Cloudflare
generates an AUD tag for the application.

### Microsoft Entra ID

**On Entra ID (your step):**

In the Azure portal, go to Microsoft Entra ID > App registrations > New registration. Set the
redirect URI type to Web and the URI to
`https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`. After creating the app,
note the Application (client) ID. Under Certificates & secrets, create a new client secret.

Under API permissions, add `User.Read` (for the user's own profile, required by Cloudflare
Access for the email claim). If you want group claims (so the engine can resolve group-based
roles), add `GroupMember.Read.All` and grant admin consent. Note that emitting group claims to an
external relying party may require an Entra ID P1 or P2 plan; verify this with Microsoft before
relying on group-based roles from Entra.

Under Token configuration, add a groups claim (Groups assigned to the application, or All
groups). Cloudflare Access receives the group object IDs (GUIDs), not display names, unless you
configure optional claims to emit `group_names`. Use the exact string the engine receives as the
group name in the group-role mapping. You can confirm what the engine receives by checking
`GET /admin/whoami` after signing in.

**In Cloudflare Zero Trust:**

Settings > Authentication > Login methods > Add new > Azure AD (Entra ID). Enter your Entra
tenant ID, the Application (client) ID, and the client secret. Enable "Support groups" if you
want group claims forwarded. Save.

**Creating the Access application:**

Same as above: Access > Applications > Add an application > Self-hosted, add both custom domains,
configure the policy, and note the AUD tag after saving.

### Okta

**On Okta (your step):**

In the Okta Admin Console, go to Applications > Applications > Create App Integration. Choose
OIDC as the sign-in method and Web Application as the application type. Set the redirect URI to
`https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`. Note the Client ID and
generate a Client Secret.

To have Okta send group memberships, go to the application's Sign On tab > Edit > OpenID Connect
ID Token. Add a groups claim with a filter that covers the groups you want forwarded (for example,
a regex `.*` to forward all groups, or a specific prefix). The claim name must be `groups`. Okta
sends group display names (not IDs), so use the display name as the group name in the engine's
group-role mapping.

**In Cloudflare Zero Trust:**

Settings > Authentication > Login methods > Add new > Okta. Enter your Okta domain, the Client
ID, and the Client Secret. Enable "Support groups" to have Cloudflare Access forward the groups
claim. Save.

**Creating the Access application:**

Same as above: Access > Applications > Self-hosted, add both custom domains, configure the
policy, note the AUD tag.

## Wiring the engine

After creating the Access application, copy its AUD tag and your Zero Trust team name into the
engine's `wrangler.toml`:

```toml
[vars]
CF_ACCESS_TEAM_DOMAIN = "<your-team>.cloudflareaccess.com"
CF_ACCESS_AUD         = "<the AUD tag from the Access application>"
```

Redeploy the engine (`npx wrangler deploy`). The `CF_ACCESS_TEAM_DOMAIN` accepts either the full
host (`<team>.cloudflareaccess.com`) or just the team name; the engine normalises both.

## Managing group-role mappings

Once the engine is receiving a signed groups claim, use the Access and Security screen in the
console to map group names to roles. The mapping is stored in the scheduler Durable Object (the
single authority plane for all access decisions). Group names are matched case-sensitively: use
the exact string the engine receives in the signed JWT (visible in `GET /admin/whoami` after
signing in).

Each mapping entry is: group name (the IdP group identifier), role (viewer, operator, or
approver). Owner cannot be assigned to a group. The mapping is audited: every add and remove is
recorded in the tamper-evident audit chain with the Owner who made the change.

Role resolution is additive. If you remove all group mappings, the engine falls back to the
per-email role table exactly as if group mapping had never been configured. If a caller's token
carries no groups claim (because the IdP was not configured to send it, or the token predates the
configuration), their role is resolved from the per-email table alone, unchanged.

The console's `GET /admin/whoami` endpoint returns the caller's resolved role, the source
(`email`, `group`, `owner-token`, or `default`), and the verified groups list, so you can confirm
what the engine is receiving and how it is mapping to a role.

## ADMIN_TOKEN_DISABLED (Access-only hardening)

For operators who have stood up Access and want to remove the shared-token path entirely:

```toml
[vars]
ADMIN_TOKEN_DISABLED = "true"
```

With this set, the engine refuses any request that does not carry a valid, verified Cloudflare
Access JWT. The `ADMIN_TOKEN` secret is ignored even if it is configured. The engine reports
`tokenFallbackDisabled: true` in `GET /admin/status` so the console shows the hardened posture.

This setting is off by default. Do not enable it until Access is fully wired and at least one
Owner has authenticated via Access (so the role table is bootstrapped and the account is not
locked out). The accepted truthy values are `1`, `true`, `yes`, and `on` (case-insensitive).
