# Upgrading the downpipe engine

This file records the migration-guide policy for the engine. The engine is the
in-account Cloudflare Worker that seals Workers KV, R2, Secrets Store and D1 to
the `downpipe/0.1.0` archive format. It is self-hosted in the customer's own
Cloudflare account; there is no managed rollout.

## Policy

While the engine is pre-1.0 (the `0.x.y` series), minor and patch releases may
carry behaviour changes. Each release that needs operator action will be called
out here under a version heading, with the exact steps, before the version is
tagged.

When the engine reaches a major version increment, every breaking change in that
release gets a numbered migration step in this file, written before the tag is
cut. A migration guide is a release blocker for any breaking change.

The on-disk archive format carries its own frozen version (`downpipe/0.1.0`) that
is independent of the engine version. A change to a byte-level rule of the
archive format is a new format minor version while the format major is 0. It is
specified normatively in the format specification of the sibling `downpipe`
repository, and is never an engine upgrade note. The engine must keep
producing archives the offline reader recovers byte-for-byte where the spec says
writer-authoritative.

## How to upgrade

An upgrade starts only when the operator starts it. The console's Licence and
updates screen applies a signed release from the update channel. It rolls back
automatically if the canary flight after the apply fails. To deploy from source,
pull the release, run `npm run validate` and `npm run typecheck`, follow any
version-specific steps below, then `npm run deploy`. There is no automatic
rollout, so the operator controls the timing and can roll back by redeploying
the prior tag.

Use `npm run deploy` for the engine, not a bare `wrangler deploy`: it runs
`scripts/sync-bindings.mjs` first, which deploys a superset `wrangler.deploy.toml`
that preserves every console-attached source binding and fails closed if it
cannot prove those sources survive. A bare `wrangler deploy` would silently drop
every source attached from the console (they live on the worker, not in git).

## Migrations

### Engine 0.3.7: a native session ends when its grant is removed

This step applies only if you have a native sign-in connection (OIDC, OAuth2 or SAML). From this release a
native session is checked on every request: its account must still hold a role or a group mapped on its
connection. A session that holds neither ends on its next request, and the person signs in again. This
includes a session admitted by a group mapping that you later deleted, and a session minted before 0.3.7
for an account with no grant. No action is needed; check the Roles and access tab if a member reports that
they were signed out.

### Engine 0.3.7: a weakly verified email binds only Viewer and operator invites

This step applies only if you have a SAML connection with the `trust-idp` email policy, or a generic OAuth2
connection that names `emailPath` and no `emailVerifiedPath`. Other connections do not change.

On such a connection, an invite by email now binds only when its role is Viewer, operator, or a custom
role without `roles.write`, `access.policy`, `restore.approve`, `keys.ceremony` or `posture.riskaccept`. An Owner, access-admin, approver or restore-operator invite stays
pending. A person who holds only such an invite is refused at sign-in (`/?oidc=no-access`). The support
pack counts `privileged-bind-refused-weak-email-verification` (Owner: `owner-bind-refused-weak-email-verification`).

Before you upgrade, find the pending invites for those roles on the Roles and access tab. For each person
who signs in through such a connection, do one of these:

1. Map their IdP group to the role on the connection. A group mapping is not an invite and still applies.
   A group mapping cannot confer Owner.
2. Use a `require-flag` SAML connection whose IdP sends a verified-email attribute. Set `emailVerifiedAttr`
   to that attribute. A require-flag sign-in with the flag `true` binds every invite, Owner included. For
   OAuth2, create the connection with `emailVerifiedPath`.
3. Let the person sign in through Cloudflare Access or a passkey, which bind the invite as before.

A person who already holds a bound role keeps it. The change applies only when an invite binds.

Creating a `require-flag` SAML connection now needs `emailVerifiedAttr`. A require-flag connection stored
without it admits nobody, before and after this change. To repair one, delete it and create it again with
the attribute, or create it with `trust-idp`.

### Engine 0.3.7: a destination whose RUNLOG does not verify stops taking runs

Every RUNLOG writer now verifies the stored RUNLOG before it changes or re-signs it. A RUNLOG that does not
verify under the engine's signer is never re-signed on the engine's own. Runs to that destination fail at the
RUNLOG write until an Owner acts.

Look in the console at Keys > Posture > Destination RUNLOG signature. There an Owner can check the signature
and re-sign a RUNLOG that does not verify, check and reset the anti-rollback floor, or relink one downpipe's
chain. Each action needs a typed confirmation and step-up, which may ask for your passkey.

A redeploy that points `DEST_R2` or a `DEST_*` binding at another bucket keeps that destination's floor, so
the new bucket is refused until an Owner resets the floor there. A chain that holds a duplicate index cannot be
repaired: attach the downpipe to a fresh destination to keep backing up.

A signer re-key now hands each destination's RUNLOG over to the new signer. New runs wait up to 15 minutes.
The old public key stays until every destination is handed over. If a RUNLOG does not verify under the old key, the re-key
stops with 409 before any secret is written, and names the destination.

### Engine 0.3.7: a native sign-in with no grant is refused

This step applies only if you have a native sign-in connection (the Identity providers screen: an OIDC,
OAuth2 or SAML connection, including the GitHub and GitLab presets). Cloudflare Access and passkey sign-in
do not change.

From 0.3.7 a person who signs in through a native connection must hold one of these:

- a role on the Roles and access tab (a row that an earlier sign-in bound to their account),
- a pending invite for their email, which binds when the identity provider marks the email verified,
- a group mapped on the Roles and access tab that their sign-in carries (a GitHub organisation or team, a
  GitLab group, an Entra App Role, an Okta, Keycloak or SAML group).

A person with none of these is refused and gets no session. On 0.3.5 that person signed in as Viewer. The
engine does not make a native sign-in the first Owner when the role table is empty.

Before you upgrade, find the people who sign in through a native connection and hold no role. The Viewer
default writes no row, so the Roles and access tab does not list them. The audit log does: each native
sign-in is an `idp-sign-in` row with the person's email. An email there with no row on the Roles and access
tab, and no mapped group, holds only the Viewer default. Keep their access in one of two ways:

1. Map their group to Viewer (or a higher role) on the connection. For GitHub, map your organisation login
   (for example `acme`) or a team (`acme/sre`). For GitLab, map the group path. For Entra, map the App Role
   value. On Microsoft Entra ID only a group or App Role mapping works, because Entra sends no
   `email_verified` and an email invite cannot bind. The same holds for any identity provider that does
   not send `email_verified`.
2. Invite each person by email with the role they need. The invite binds at their next verified sign-in.

If no Owner exists yet and you set up a native connection with the break-glass admin token, invite your own
address as Owner first. Your first verified sign-in then binds it. A trust-idp SAML connection cannot bind
an Owner invite, so claim the first Owner through Cloudflare Access or a passkey in that case.

A refused sign-in lands on the console at `/?oidc=no-access`. The audit log records an `authn-failure` row
for the connection, and the support pack counts `sso-no-grant-refused`.

### Engine 0.3.7: deleting or rotating ADMIN_TOKEN now ends a session exchanged from it

From engine 0.3.7 a session minted at `POST /admin/session/bootstrap` (the break-glass `ADMIN_TOKEN`
bearer, exchanged for a cookie) carries a fingerprint of the secret it came from. `authorise()` checks the
fingerprint against the current `ADMIN_TOKEN` on every request. Deleting the secret, or rotating it to a
new value, now ends every session already exchanged from the old one, on its next request. Before 0.3.7,
such a session kept Owner access for up to 12 hours after the secret was gone, which was the opposite of
what the incident runbook and the posture check already told an operator to expect.

This changes behaviour on upgrade for one case only: an operator holding a token-exchanged session at the
moment ADMIN_TOKEN is deleted or rotated. That session now gets `401` on its next request, with no way to
refresh it, because the fingerprint it carries is not the current one. Exchange the new (or, if you meant
to keep access, the unrotated) bearer again at `POST /admin/session/bootstrap` to get a fresh cookie. A
token session minted on 0.3.5 or earlier carries no fingerprint at all; it is refused the same way, once,
on its first request after the upgrade, and needs the same one-time re-exchange. Cloudflare Access, passkey
and OIDC/OAuth2/SAML sessions are unchanged.

### 0.3.7: rollback note for the Cloudflare configuration coverage record

An upgrade to 0.3.7 needs no action. A run that resumes from a 0.3.5 checkpoint
writes the new coverage record and continues.

A rollback from 0.3.7 to 0.3.5 during a Cloudflare configuration run can fail
that one run. A 0.3.7 run can checkpoint right after its coverage record. The
0.3.5 engine does not know that resume point, so each slice fails with the
stale-watermark error. After the retry limit (`MAX_SLICE_FAILURES`, 8) the run
is marked failed and its checkpoint is deleted. The next due run starts from
scratch and needs no action. To avoid the failed run, roll back between runs.

### Engine 0.3.7: the generic webhook body has two new fields

From engine 0.3.7 every generic webhook body carries `dedupKey`. The body that closes a recovered
`backup-failure`, `backup-stale`, `replication-degraded` or `run-at-risk-eviction` alert also carries
`recovered: true`. The `kind` stays `downpipe-event-v1`. A receiver that ignores keys it does not
know needs no action.

A receiver that rejects a body with unknown keys (for example, a strict schema with no additional
properties) rejects every 0.3.7 body, critical alerts included. If such a receiver drops the body but
answers with a 2xx status, the engine records a successful delivery. Before you upgrade:

1. Change the receiver to accept `dedupKey` (a string, on every body) and the optional `recovered` (the
   value `true`), or to ignore keys it does not know.
2. After the upgrade, select **Test** on the channel in the console Notifications screen. The test body
   has the same shape as an alert body. Make sure that the receiver accepts it.

The v1 body can get more optional fields in a later release. A field is never removed or renamed under
`downpipe-event-v1`. Such a change gets a new `kind`.

### Engine 0.3.7: `CONTROL_PLANE_EXPORT_SEALING_DISABLED` is removed

From engine 0.3.7 the engine ignores `CONTROL_PLANE_EXPORT_SEALING_DISABLED`. It seals the control-plane
export whenever it holds a break-glass or a config-recipient public key. In engine 0.3.5 the flag keeps
the export in cleartext, so that an engine without the config-recipient key can auto-heal from it. After
the upgrade, such an engine writes an export sealed to break-glass only. The auto-heal then refuses it with
`sealed-no-op-key`, and recovery needs your offline break-glass key.

If you set the flag, do these steps right after you upgrade to engine 0.3.7 and console 0.2.7:

1. Open the console Keys screen.
2. If it offers **Add configuration keys**, use it. This installs the config-recipient pair and
   `CONFIG_WRAP_KEY` without a re-key. Until you do, each export is sealed to break-glass only.
3. Remove the flag from your Worker variables. The engine does not read it, so a flag left in
   place does nothing.

An engine that does not set the flag needs no action.

### Engine 0.3.7: four API responses change for dual control

- `POST /admin/downpipes` returns 403 with the standard capability refusal when a caller without
  `restore.apply` sends an edit that lets the scheduled prune delete more. In a bulk upsert, that item
  returns `status: "forbidden"`.
- `POST /admin/downpipes` returns 202 with a queued config change for that edit when another holder of
  `restore.approve` exists. The edit applies after a different holder approves it.
- With two or more Owners, an Owner's request to turn off restore approval or update approval returns
  202 with a pending owner action. The policy stays on until a different Owner approves it.
- `POST /admin/roles` for a member who enrolled before returns no `inviteToken`. Read `inviteState` and
  `inviteNotice` instead.

If a script reads these responses, change it before you apply.

### Engine 0.3.7: refused and failed attempts are counted rows in the audit log

A flood of failed sign-ins or refused requests does not write one audit row per attempt. The first
attempt from a source in a minute writes a row. Later attempts add to a count, and the next row for that
source carries it. A failed or recovery sign-in row carries the count in `target.attempts`, and a refused
request's row carries it in `target.deniedAttempts`. The rows still sum to every attempt made.

If a SIEM rule or an alert counts audit rows to count attempts, change it to sum `target.attempts` and
`target.deniedAttempts`. Counting rows under-reports a flood from this release on.

### Engine 0.3.7: check for a role email that contains ":"

Engine 0.3.7 refuses an email that contains ":". An earlier engine accepted one, and such an email could
remove an Owner's role row or claim another person's pending invite. Before or after you apply 0.3.7:

1. Read `GET /admin/roles`. Look for a bound or pending row whose email contains ":".
2. Read the audit log for `role-change` entries whose target email contains ":".
3. Remove each such row with `POST /admin/roles/delete` and its exact stored email. 0.3.7 still accepts that
   email for a delete, and the Owner guards run on it.
4. If an Owner lost its role, another Owner grants it again. With no Owner left, use the `ADMIN_TOKEN`
   break-glass sign-in to grant it.

### Engine 0.3.7: remove an operational key left by a strict re-key on 0.3.5

A strict break-glass-only re-key on engine 0.3.5 (a key install from the console Keys screen with no
operational key) does not remove an operational key that the engine already holds. After the upgrade to
0.3.7, such an engine still reads that pair as its operational key. It seals each new run to it as well as
to break-glass, and the Security Centre shows no `operational-retired-key-held` check, because no
break-glass-only choice is recorded.

Your engine has this state if you chose break-glass-only and, after the upgrade, it reads as follows. The
two surfaces show the same state:

- On the console Keys screen, Posture tab, "Operational key (private)" reads present and "Recovery mode"
  reads "two-recipient (in-account read-back available)".
- `GET /admin/status` reports `operationalRetired: false` and `operationalConfigured.private: true`.

To remove the key, run the break-glass-only switch once: on the Keys screen, Posture tab, select
**Switch to break-glass-only** (or send `POST /admin/keys/break-glass-only`). The switch records the
break-glass-only choice (`OPERATIONAL_RETIRED`), then deletes `OPERATIONAL_PRIVATE` and
`OPERATIONAL_PUBLIC`. After it, `GET /admin/status` reports `operationalRetired: true` and both
`operationalConfigured` halves `false`, and new runs are sealed to break-glass alone. Runs sealed while the
operational key was held also carry your break-glass recipient, so `identity.key` still opens them.

An engine where you did not choose break-glass-only, or where the Posture tab already reads
break-glass-only, needs no action.
