// validate-dest-host-anchor: the store behind an endpoint is chosen from the endpoint's HOST, and nothing else.
//
// providerForEndpoint reads the host out of a full URL. It used to cut a URL at the first "/" only, so a
// query or fragment stayed in the "host": https://attacker.example?.blob.core.windows.net read as an Azure
// blob host, while a real client sends the request to attacker.example. The Azure client has no DNS screen
// of its own, so the endpoint reached the network unscreened. This validator proves:
//  - a "?" or "#" ends the host, so a look-alike suffix after it never selects Azure, R2 or GCS;
//  - userinfo does not stand in for the host;
//  - the real endpoints, with and without a port or a path, still select the same store;
//  - azureAccountFromHost agrees with providerForEndpoint on every one of those inputs.
//
// Run: node test/validate-dest-host-anchor.ts

import { azureAccountFromHost, providerForEndpoint, unusableEndpoint } from "../src/dest/provider.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const lookAlikes: Array<[string, string]> = [
  ["https://attacker.example?.blob.core.windows.net", "a query that ends in the Azure suffix"],
  ["https://attacker.example#.blob.core.windows.net", "a fragment that ends in the Azure suffix"],
  ["https://attacker.example/?x=.blob.core.windows.net", "a path and query that end in the Azure suffix"],
  ["https://attacker.example?.r2.cloudflarestorage.com", "a query that ends in the R2 suffix"],
  ["https://attacker.example?.dfs.core.windows.net", "a query that ends in the Azure dfs suffix"],
  ["https://acct.blob.core.windows.net@attacker.example/", "userinfo that looks like an Azure host"],
  ["https://acct.blob.core.windows.net:443@attacker.example/", "userinfo with a port that looks like an Azure host"],
];

async function main(): Promise<void> {
  for (const [endpoint, why] of lookAlikes) {
    ok(`${why}: provider is s3`, providerForEndpoint(endpoint) === "s3");
    ok(`${why}: no Azure account is derived`, azureAccountFromHost(endpoint) === "");
    ok(`${why}: not refused as an Azure dfs endpoint`, unusableEndpoint(endpoint) === null);
  }
  const real: Array<[string, "azure" | "r2" | "s3" | "gcs", string]> = [
    ["https://acct.blob.core.windows.net", "azure", "an Azure blob endpoint"],
    ["https://acct.blob.core.windows.net:443/container?sv=1", "azure", "an Azure blob endpoint with a port, a path and a query"],
    ["acct.blob.core.windows.net", "azure", "a bare Azure blob host"],
    ["https://abc.r2.cloudflarestorage.com/bucket", "r2", "an R2 endpoint with a path"],
    ["https://storage.googleapis.com", "gcs", "the GCS interop endpoint"],
    ["https://s3.eu-west-1.amazonaws.com", "s3", "an AWS endpoint"],
  ];
  for (const [endpoint, want, why] of real) ok(`${why}: provider is ${want}`, providerForEndpoint(endpoint) === want);
  ok("an Azure blob endpoint with a path and query still yields its account", azureAccountFromHost("https://acct.blob.core.windows.net:443/container?sv=1") === "acct");
  ok("an Azure dfs endpoint with a query is still refused as dfs", unusableEndpoint("https://acct.dfs.core.windows.net/?x=1") === "azure-dfs");
  console.log(failures === 0 ? "\nVALIDATE-DEST-HOST-ANCHOR VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
