// The destination provider derivation and the refusals it enables.
//
// Google Cloud Storage has worked as a downpipes destination for as long as the S3-compatible arm has
// existed, because its XML API is S3-interoperable and authenticated with the identical SigV4 scheme.
// Driven live against a real bucket with this repo's own signer, every call the engine
// makes succeeded: PUT 200, GET 200 byte-correct, HEAD 404 on a missing key, DELETE 204, and multipart
// initiate/upload/complete all 200. What was missing was never the wire. It was the NAME, and therefore
// every sentence the product says about such a destination.
//
// So these vectors are mostly about refusals and labels rather than about bytes. Run:
// node test/validate-dest-provider.ts

import { AZURE_REFUSED_FIELDS, AZURE_STORAGE_SUFFIXES, azureAccountFromHost, GCS_REFUSED_FIELDS, providerForEndpoint, UNUSABLE_ENDPOINT_REASON, unusableEndpoint } from "../src/dest/provider.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

function derivation(): void {
  console.log("providerForEndpoint derives the store from the endpoint host:");
  const vectors: ReadonlyArray<[string | undefined, string, string]> = [
    ["https://abc123.r2.cloudflarestorage.com", "r2", "an account-scoped R2 endpoint"],
    ["abc123.r2.cloudflarestorage.com", "r2", "the same, as a bare host"],
    ["https://abc123.eu.r2.cloudflarestorage.com/", "r2", "a jurisdiction-scoped R2 endpoint with a trailing slash"],
    ["https://storage.googleapis.com", "gcs", "Google Cloud Storage's S3-interop endpoint"],
    ["STORAGE.GOOGLEAPIS.COM", "gcs", "the same, upper-cased (hosts are case-insensitive)"],
    ["https://storage.googleapis.com:443/bucket", "gcs", "the same, with a port and a path"],
    ["https://acct.blob.core.windows.net", "azure", "an Azure Blob endpoint is its own provider"],
    ["https://ACCT.BLOB.CORE.WINDOWS.NET", "azure", "the same, upper-cased"],
    ["https://s3.ap-southeast-2.amazonaws.com", "s3", "Amazon S3 stays the residual"],
    ["https://s3.wasabisys.com", "s3", "Wasabi is unchanged: an unrecognised store reads as s3, exactly as before"],
    ["https://minio.internal.example", "s3", "a private S3-compatible endpoint is unchanged"],
    [undefined, "s3", "an absent endpoint falls back to the residual rather than throwing"],
    ["", "s3", "an empty endpoint likewise"],
  ];
  for (const [endpoint, want, why] of vectors) {
    ok(`${why} -> ${want}`, providerForEndpoint(endpoint) === want);
  }

  // The look-alike vectors carry the weight the plain ones do not: a suffix match on "googleapis.com"
  // would admit an attacker-controlled subdomain, and a suffix match on "r2.cloudflarestorage.com"
  // without the leading-label anchor would admit "notr2.cloudflarestorage.com.evil.example".
  console.log("look-alike hosts are NOT mistaken for a known provider:");
  ok("a subdomain of the GCS host is not GCS", providerForEndpoint("https://evil.storage.googleapis.com") === "s3");
  ok("a host merely ENDING in the GCS name is not GCS", providerForEndpoint("https://storage.googleapis.com.evil.example") === "s3");
  ok("a host merely ENDING in the R2 name is not R2", providerForEndpoint("https://r2.cloudflarestorage.com.evil.example") === "s3");
}

// ---- the sovereign Azure clouds --------------------------------------------------------------------
//
// THE MATCHER IS TESTED HERE. THE WIRE IS NOT. Nobody on this side holds an Azure US Government or Azure
// China subscription, so no request has ever been made to either, and this file makes no claim that one
// would succeed. What it grades is the pure function: which client an endpoint in those clouds is routed
// to. Routing such an endpoint to the S3 arm would mean SigV4 could never authenticate an Azure account,
// so the engine would refuse a store it could otherwise write to. That is a classification defect, it is
// fully decidable without a credential, and it is what these vectors settle.
//
// The look-alikes carry the weight. Every suffix added is a SUFFIX match, and a suffix match written
// without the leading-label anchor and the end anchor admits a hostile domain that merely ends in the same
// string, which would route a customer's account key to a host the attacker controls.
function sovereignAzure(): void {
  console.log("every Azure cloud in the closed suffix list classifies as azure, and is refused as dfs:");
  ok("the suffix list names three clouds, so a silently emptied list cannot pass this section", AZURE_STORAGE_SUFFIXES.length === 3, JSON.stringify(AZURE_STORAGE_SUFFIXES));
  for (const suffix of AZURE_STORAGE_SUFFIXES) {
    ok(`https://acct.blob.${suffix} is an Azure destination`, providerForEndpoint(`https://acct.blob.${suffix}`) === "azure");
    ok(`...the same as a bare host, upper-cased`, providerForEndpoint(`ACCT.BLOB.${suffix.toUpperCase()}`) === "azure");
    ok(`...and with a port and a path, as the console may paste it`, providerForEndpoint(`https://acct.blob.${suffix}:443/container`) === "azure");
    // The dfs family must widen with the blob one or a government-cloud ADLS Gen2 endpoint loses the
    // tailored refusal the commercial one gets, and lands back on the credential-shaped probe failure.
    ok(`acct.dfs.${suffix} is refused as ADLS Gen2 in that cloud too`, unusableEndpoint(`https://acct.dfs.${suffix}`) === "azure-dfs");
    ok(`...and is NOT classified as a writable Azure destination`, providerForEndpoint(`https://acct.dfs.${suffix}`) !== "azure");
    // The account is what the Shared Key canonicalised resource is built from. A suffix the matcher admits
    // but the account extractor does not is a destination that builds and then 403s on every request.
    ok(`the account is still the first label at ${suffix}`, azureAccountFromHost(`https://mystore.blob.${suffix}`) === "mystore");
  }

  console.log("a hostile domain merely ENDING in an Azure suffix is not an Azure host:");
  for (const suffix of AZURE_STORAGE_SUFFIXES) {
    ok(`a host ending in .blob.${suffix} but continuing past it is not Azure`, providerForEndpoint(`https://acct.blob.${suffix}.evil.example`) === "s3");
    // No leading dot: the suffix is glued onto the end of an attacker's own label. Without the "\." anchor
    // in the pattern this would match and the account key would be signed for a host they control.
    ok(`a label merely ending in "blob.${suffix}" is not Azure`, providerForEndpoint(`https://notablob.${suffix}`) === "s3");
    ok(`...and the same shape on the dfs family is not refused as Gen2 either`, unusableEndpoint(`https://acct.dfs.${suffix}.evil.example`) === null);
    ok(`...and yields no storage account, so nothing is signed for it`, azureAccountFromHost(`https://acct.blob.${suffix}.evil.example`) === "");
  }

  console.log("a cloud that is NOT in the list stays the residual:");
  // Microsoft Cloud Germany closed in. It is deliberately absent, and this line is what says
  // the absence is a decision rather than an oversight.
  ok("the retired Microsoft Cloud Germany suffix is not admitted", providerForEndpoint("https://acct.blob.core.cloudapi.de") === "s3");
  ok("an invented Azure-shaped suffix is not admitted", providerForEndpoint("https://acct.blob.core.azurecloud.example") === "s3");
}

function unusable(): void {
  console.log("unusableEndpoint names a store we cannot write to at all:");
  // Azure BLOB moved out of this set when it gained its own client and signer. The two
  // Azure endpoint families are deliberately kept apart: the dfs one is a different protocol, not a
  // different host for the same one, so supporting Blob does not support Gen2.
  ok("an ADLS Gen2 endpoint is still refused by name", unusableEndpoint("https://acct.dfs.core.windows.net") === "azure-dfs");
  ok("an Azure BLOB endpoint is NOT refused any more: it is a supported destination", unusableEndpoint("https://acct.blob.core.windows.net") === null);
  ok("a bare Azure Blob host (no scheme) is likewise usable", unusableEndpoint("acct.blob.core.windows.net") === null);
  ok("R2 is usable", unusableEndpoint("https://abc.r2.cloudflarestorage.com") === null);
  ok("GCS is usable", unusableEndpoint("https://storage.googleapis.com") === null);
  ok("Amazon S3 is usable", unusableEndpoint("https://s3.amazonaws.com") === null);

  // The message is asserted for CONTENT, not merely for existence. The whole point of naming Azure is
  // that the operator stops auditing a credential, so a message that did not say so would be the defect
  // wearing a fix. Measured behaviour it replaces: Azure answers 403 AuthenticationFailed on the probe's
  // first call, and the operator was told to check the bucket, the endpoint and the credentials.
  console.log("the ADLS Gen2 refusal points at the endpoint that WOULD work:");
  const m = UNUSABLE_ENDPOINT_REASON["azure-dfs"];
  ok("azure-dfs: names the store", /Azure Data Lake/.test(m));
  ok("azure-dfs: does not send the operator to audit a credential", !/check (the |your )?credential/i.test(m));
  ok("azure-dfs: names the Blob endpoint as the supported alternative, which is now true", /blob\.core\.windows\.net/.test(m));
  // The remedy has to survive the sovereign clouds, which the dfs matcher now covers: a government-cloud
  // operator sent to blob.core.windows.net is sent to a host their account does not live at. So the message
  // names the SWAP, and keeps the commercial host only as the worked example.
  ok("azure-dfs: states the substitution rather than one cloud's host", /blob in place of dfs/i.test(m), m);
  ok("azure-dfs: says the cloud does not change either", /same cloud/i.test(m), m);
}

function azureAccount(): void {
  console.log("the storage account is derived from the endpoint host:");
  ok("the first label of an Azure Blob host is the account", azureAccountFromHost("https://mystore.blob.core.windows.net") === "mystore");
  ok("...case-folded, because a host is case-insensitive and a signature is not", azureAccountFromHost("https://MyStore.BLOB.core.windows.net") === "mystore");
  ok("a non-Azure host yields no account rather than a wrong one", azureAccountFromHost("https://s3.amazonaws.com") === "");
  ok("an ADLS Gen2 host yields no account either, because it is not a supported endpoint", azureAccountFromHost("https://mystore.dfs.core.windows.net") === "");
}

function azureRefusals(): void {
  console.log("the Azure refusal set covers the Amazon-only fields:");
  const byField = new Map(AZURE_REFUSED_FIELDS.map((f) => [f.field, f.reason]));
  for (const f of ["storageClass", "assumeRole", "addressing"]) ok(`${f} is refused`, byField.has(f));

  // THE ASSERTION THAT MATTERS MOST HERE IS AN ABSENCE, exactly as it is for GCS below, and for the same
  // reason: the presence it replaces was wrong. // Azure's two primitives (a policy that is separately unlocked or locked, plus an independent legal hold)
  // map onto one mode plus one window: governance is an unlocked policy and compliance is a locked one.
  //
  // governance is an unlocked policy and compliance is a locked one, and the mode is a header chosen per
  // write rather than a property of the container anybody has to guess at. The live probe
  // (AzureBlobDestination.objectLockStatus, reading Get Container Properties) now decides it per container,
  // which is the same rule every other store is held to.
  ok("immutability is NOT refused for Azure: the live probe decides it, per container", !byField.has("worm"));

  ok("the storage-class reason names Azure's own access tiers", /Hot, Cool, Cold, Archive/.test(byField.get("storageClass") ?? ""));
  // The AssumeRole remedy has to name a credential the operator can actually supply, and there are now two.
  const assume = byField.get("assumeRole") ?? "";
  ok("the AssumeRole reason points at the account key, which is what the form collects", /access key/i.test(assume), assume);
  ok("...and names the shared access signature too, which is now accepted in the same field", /shared access signature/i.test(assume), assume);

  // ADDRESSING joined the set. Its reason has to say what the one Azure URL form IS, or an
  // operator reading "there is nothing to choose" cannot tell whether their container is reachable at all.
  const addr = byField.get("addressing") ?? "";
  ok("the addressing reason names Azure's single URL form", /blob\.core\.windows\.net\/<container>/.test(addr), addr);

  // AND THE SECOND ABSENCE, which is the one that would do damage if it were ever "tidied" into the set.
  // No Azure module reads `region`: azure-blob, azure-sharedkey, azure-sas and azure-entra name it zero
  // times and factory.ts builds AzureBlobDestination without it, so refusing it looks like housekeeping.
  // It is not. Region is never absent: the console field is declared holding "auto", the console coerces
  // an empty box to "auto", and the router coerces again server-side. The refusal in
  // router-destinations.ts is keyed on the field being PRESENT, so a `region` entry here would refuse
  // every Azure destination ever submitted, including one carrying nothing but the default.
  ok("region is NOT refused for Azure, because it is always present as \"auto\" and would refuse every submit", !byField.has("region"));
}

function gcsRefusals(): void {
  console.log("the GCS refusal set covers the Amazon-only fields, each with a followable remedy:");
  const byField = new Map(GCS_REFUSED_FIELDS.map((f) => [f.field, f.reason]));
  for (const f of ["storageClass", "assumeRole"]) {
    ok(`${f} is refused`, byField.has(f));
  }

  // THE ASSERTION THAT MATTERS MOST HERE IS AN ABSENCE, because the presence it replaces was false.
  // A GCS bucket created WITH per-object
  // retention answers the Object-Lock probe 200/Enabled, honours a COMPLIANCE lock header, and then
  // REFUSES a delete inside the window with 403. The engine's live probe already told those buckets apart
  // from the ones without retention; the hardcoded refusal only broke the working case.
  ok("immutability is NOT refused for GCS: the live probe decides it, and it decides correctly", !byField.has("worm"));

  // Each reason must name a remedy the operator can actually carry out ON GOOGLE CLOUD. The refusal this
  // replaces told a GCS operator to "create a new bucket with Object Lock enabled", which is true for
  // Amazon S3 and impossible on Google Cloud, where no such setting exists. A remedy that cannot be
  // followed is worse than a plain refusal, so the assertion is on the remedy and not on the refusal.
  ok("the storage-class reason says to set the class on the bucket instead", /bucket's own default|on the bucket itself/i.test(byField.get("storageClass") ?? ""));
  ok("the AssumeRole reason names HMAC interoperability keys as the GCS way", /HMAC/i.test(byField.get("assumeRole") ?? ""));

  // Nothing in the set may name a field the console cannot show, or the operator is refused for a field
  // they never filled in.
  ok("every refused field is a real submitted destination field", GCS_REFUSED_FIELDS.every((f) => ["storageClass", "assumeRole"].includes(f.field)));
}

console.log("dest provider derivation + refusals\n");
derivation();
sovereignAzure();
unusable();
azureAccount();
gcsRefusals();
azureRefusals();

console.log(failures === 0 ? "\nall dest provider checks passed" : `\n${failures} check(s) FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
