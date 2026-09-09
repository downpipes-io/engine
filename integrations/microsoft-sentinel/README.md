# Downpipes audit feed: Microsoft Sentinel connector

This package deploys a Microsoft Sentinel Codeless Connector Framework (CCF) `RestApiPoller` that polls a Downpipes engine's audit feed and lands events in your own Log Analytics workspace, in a custom table named `DownpipesAudit_CL`. Sentinel is one of the few SIEMs a Downpipes engine cannot push to directly (it wants OAuth2 or HMAC, not a bearer header), so this is the pull-side counterpart: Sentinel does the dialling, on a schedule the CCF poller controls, using a bearer credential you mint from the engine console.

## Files in this package

- `mainTemplate.json`: the ARM template.
- `parameters.example.json`: a parameters file with the bearer token as a plain inline value.
- `parameters.keyvault.example.json`: the same, but with the bearer token pulled live from an Azure Key Vault secret.
- `README.md`: this guide.

## What it deploys

Running the template creates, in your Azure subscription:

- A Data Collection Endpoint (DCE).
- A custom Log Analytics table, `DownpipesAudit_CL`, with columns matching the audit event: `seq`, `ts` (mapped to `TimeGenerated`), `actorEmail`, `actorSubject`, `actorMethod`, `sourceIp`, `action`, `outcome`, `target`, `prevHash`, `hash`.
- A Data Collection Rule (DCR) that transforms and routes incoming events into that table.
- A Sentinel data connector definition and a `RestApiPoller` data connector, configured to call `GET https://<apiHost>/support/audit-feed` with a bearer token, and to page forward using the feed's own `afterSeq`/`nextAfterSeq` cursor.

It does not onboard Sentinel onto your workspace, and it does not touch the Downpipes engine. The engine side of this is just the existing `/support/audit-feed` endpoint; nothing needs to change there for this connector to work.

## Prerequisites

- An existing Log Analytics workspace with Microsoft Sentinel already enabled on it. This template adds a table, a DCE/DCR and a connector to that workspace; it does not turn Sentinel on.
- The Azure CLI, logged in (`az login`) with the right subscription selected (`az account set --subscription <id>`).
- The `Microsoft.SecurityInsights` and `Microsoft.Insights` resource providers registered on the subscription. Check with:
  ```
  az provider show --namespace Microsoft.SecurityInsights --query registrationState -o tsv
  az provider show --namespace Microsoft.Insights --query registrationState -o tsv
  ```
  If either comes back anything other than `Registered`, register it first (`az provider register --namespace Microsoft.SecurityInsights`, and the same for `Microsoft.Insights`), then wait for the state to flip.
- Enough RBAC on the resource group to create the DCE, the DCR, the custom table and the Sentinel connector resources. Contributor on the resource group is the simplest option; the equivalent narrower grant needs write access to `Microsoft.OperationalInsights/workspaces/*`, `Microsoft.Insights/dataCollectionEndpoints`, `Microsoft.Insights/dataCollectionRules` and `Microsoft.SecurityInsights/*` on the workspace.
- A bearer token from the Downpipes engine's audit feed (see below).

## Deploy

From this directory:

```
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file mainTemplate.json \
  --parameters workspaceName="<your-sentinel-workspace-name>" \
  --parameters apiHost="<engine-hostname-no-scheme>" \
  --parameters bearerToken="<paste-the-minted-bearer-token>"
```

For anything beyond a one-off test, pass the token through a parameters file instead of typing it on the command line, so it doesn't sit in shell history and terminal scrollback:

- `parameters.example.json`: the token as a plain inline value. Fill it in, then run:
  ```
  az deployment group create \
    --resource-group <your-resource-group> \
    --template-file mainTemplate.json \
    --parameters @parameters.example.json
  ```
- `parameters.keyvault.example.json`: the token pulled live from an Azure Key Vault secret at deployment time, so it never appears in the parameters file at all. Replace the vault resource ID and secret name, store the token as that secret first (`az keyvault secret set --vault-name <vault> --name downpipes-audit-feed-bearer-token --value <token>`), and make sure the principal running the deployment can read the vault's secrets and the vault has "Azure Resource Manager for template deployment" access enabled (or the equivalent RBAC: `Key Vault Secrets User` plus template-deployment access).

Either way, `bearerToken` is declared `securestring`, so Azure does not echo it back in the deployment's output or activity log.

## Minting the bearer token

The token comes from the Downpipes engine console, not from Azure:

1. Sign in to the console as an Owner (minting is Owner-only; the engine enforces this server-side).
2. Go to **Settings** and expand **Pull credentials**.
3. On the **SIEM audit feed** card, click **Mint credential**.
4. Copy the value shown under **"SIEM audit feed: bearer credential (shown once)"** immediately. It is not stored anywhere retrievable after this screen; the engine only ever keeps a hash of it. This is the value for the `bearerToken` parameter.

The credential defaults to a 90-day expiry and can be issued for up to 365 days. Re-minting replaces it immediately and breaks the connector until you redeploy (or patch the connector) with the new value, so treat re-minting as a planned change rather than something to do casually.

## Verifying it landed

Give the connector a few minutes after deployment for the first poll and the DCR transform to run, then:

- In the workspace's **Logs** blade, run:
  ```
  DownpipesAudit_CL
  | take 10
  ```
  You should see rows with the audit fields above and a populated `TimeGenerated`.
- Check connector health with the same query the connector definition uses internally:
  ```
  DownpipesAudit_CL
  | summarize LastLogReceived = max(TimeGenerated)
  | project IsConnected = LastLogReceived > ago(3h)
  ```
- In Sentinel's **Data connectors** page, look for **Downpipes Audit Feed** and check its connection status.
- On the engine side, back in the console's **Settings > Pull credentials > SIEM audit feed** card, the credential's pull trail records how many pulls have happened and when the last one landed. If Sentinel is polling successfully this counter moves; if it stays on "Never pulled", the poller is not reaching the engine at all (check the Cloudflare Access note below before assuming the ARM deployment is at fault).

## Cloudflare Access note (read this if the engine sits behind Access)

This connector is a pull: Sentinel's poller dials out to your engine on a schedule. That is a different exposure to the engine's push-based SIEM delivery, where the engine dials out to the SIEM and the SIEM never needs to be reachable from the internet at all.

If your engine or console hostname is fronted by Cloudflare Access (the standard setup instructions put one Access application across the whole engine hostname, with no path carve-out), Access will intercept the poller's request at the edge and return a login challenge before it ever reaches the `/support/audit-feed` bearer-token check. The bearer token minted above is real and correct; it simply never gets evaluated, because Access turns the request away first. The console's own credential-minting screen carries a warning to this effect when it detects an Access-fronted hostname.

Two ways to fix this. The choice is yours, based on your own security posture:

- **Path-scoped bypass**: add a narrow Cloudflare Access policy that excludes `/support/*` on the engine hostname from the Access application, leaving everything else (the console, `/admin/*`) still gated. The audit feed's own bearer-token check still protects the endpoint; only the extra Access layer is removed for that one path.
- **Access service token**: mint a Cloudflare Access Service Token (Zero Trust > Access > Service Auth) for the Sentinel poller, and send its `CF-Access-Client-Id` and `CF-Access-Client-Secret` as extra static headers alongside the bearer token. To do this, add two more `securestring` parameters to your own copy of `mainTemplate.json` and extend the connector's `request.headers` object:
  ```
  "headers": {
    "Accept": "application/json",
    "CF-Access-Client-Id": "[parameters('cfAccessClientId')]",
    "CF-Access-Client-Secret": "[parameters('cfAccessClientSecret')]"
  }
  ```
  This keeps the whole hostname behind Access and grants the poller a narrow, revocable exception.

Either way, the bearer token still gates the feed. Access is a separate, additional layer in front of it, not a substitute for it.

## Token storage

`bearerToken` is a `securestring` parameter, so Azure Resource Manager does not print it in deployment output, and it is not written back in a form the portal displays to you. That protects it from casual exposure inside Azure. It does not protect it from you: pasting a long-lived token directly into a shell command still leaves it in your shell history and terminal scrollback. For a token you intend to keep for weeks or months, use the Key Vault reference form (`parameters.keyvault.example.json`) rather than typing it inline. Treat the credential the same way you would any other production secret. If it does end up in shell history, clear it, and if in doubt, revoke and re-mint from the console.

## This is the standalone ARM route, not Content Hub

`RestApiPoller` is a generally available CCF connector kind. Microsoft's usual path for CCF connectors is publishing them as a Sentinel solution through Content Hub, where an analyst installs the solution first and then supplies credentials through the connector's own UI. This package skips that path entirely: it is a plain ARM template you deploy directly with `az deployment group create`, with the bearer token supplied as a real deployment parameter.

That is why the auth block uses a single-bracket ARM expression, `[parameters('bearerToken')]`, rather than the double-bracket `[[parameters(...)]` escape you will see in Microsoft's own Content Hub-oriented examples. The double-bracket form is how a Content Hub template defers a parameter to be filled in later, through the connector's own configuration UI, after the solution is installed. We are not doing that here; we want Azure Resource Manager to substitute the real value at deployment time. If you are ever comparing this template against a Microsoft sample and are tempted to "fix" the bracket to match, don't: for this standalone deployment, the double-bracket form would deploy the literal, useless string `parameters('bearerToken')` as the connector's credential instead of your actual token.

## Verify on first deploy

This template has been checked for valid JSON and cross-checked field by field against Microsoft's current Codeless Connector Framework reference and against the Downpipes engine's actual `/support/audit-feed` contract. It has not been run against a live Azure subscription. The following are called out honestly as the things to watch on the first real deployment:

- **First-poll cursor seeding.** The template sends `afterSeq=0` as a static query parameter on the very first call, before any checkpoint exists. The engine treats a missing, zero or malformed `afterSeq` as "from the beginning", so this should be safe. What is unverified is whether the CCF poller correctly hands control to the persisted `nextAfterSeq` checkpoint from the second poll onward, rather than continuing to send the static `0` every time. Confirm by checking that the second and later polls (and `DownpipesAudit_CL` row counts) do not simply repeat the first page of events.
- **`PersistentToken` versus `NextPageToken` behaviour.** `PersistentToken` is used because it is the CCF paging type built for a checkpoint the poller carries across separate poll cycles, rather than a within-poll multi-page walk, and that matches how `afterSeq`/`nextAfterSeq` actually work. This is the semantically correct choice based on Microsoft's documentation, but it has not been observed against a live poll cadence. If events stop advancing after the first poll, this is the first thing to check.
- **The DCE `logsIngestion.endpoint` reference path.** The connector's `dcrConfig.dataCollectionEndpoint` and the template outputs both resolve via `reference()` against the DCE created earlier in the same deployment. The dependency chain is now explicit (the connector resource depends on the DCE, the DCR and the connector definition), which should guarantee ordering, but this exact chain has not been exercised end to end in a real subscription.
- **Auth field casing.** The `auth` block uses `ApiKey`, `ApiKeyName` and `ApiKeyIdentifier`. Microsoft's own documentation is inconsistent here: the Sentinel-specific CCF reference (with worked examples) uses this exact casing, while the generic auto-generated ARM schema reference shows lower-case `apiKey`/`apiKeyName`/`apiKeyIdentifier`. This template follows the Sentinel-specific reference. If the connector deploys but no bearer token ever reaches the engine, which you'd see as `DownpipesAudit_CL` staying empty and the console's pull trail stuck on "Never pulled" even with Cloudflare Access confirmed not to be in the way, this casing is the first thing to try changing.
- **`actorSubject` on legacy events.** This field can be entirely absent from an event's JSON, not just empty, on audit entries recorded before the engine added subject-keyed actors. Log Analytics ingestion is normally tolerant of a missing JSON key on an incoming record (the column comes through null for that row), but this has not been confirmed against this specific DCR.
- **`location` on the Sentinel connector resources.** The documented schema for `dataConnectorDefinitions` and `dataConnectors` does not list a `location` property at all, unlike the DCE and DCR, which require one. This template still sets one, matching the workspace's own region and matching common practice in other CCF sample templates, on the assumption that Azure Resource Manager accepts and ignores a harmless location value on a resource type that doesn't use it. If deployment fails specifically on one of these two resources with a location-related validation error, delete the `location` line from that resource and redeploy.
- **Paging field name looks like a typo; it is not.** The paging block uses `nextPageParaName` ("Para", not "Param"). That is the real, documented field name in Microsoft's own CCF `PersistentToken` reference example, not a mistake carried over from a draft. Do not "correct" it to `nextPageParamName`; that spelling is not a field the API recognises, and paging silently stops advancing.

None of these affect the shape of the data once it lands. The table schema and the field mapping have been checked directly against the engine's source, and so has the endpoint contract. What they affect is whether the connector reliably keeps polling forward, which only a live deployment can confirm.
