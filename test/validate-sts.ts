// Vectors for STS AssumeRole (dest/sts.ts) and resolveRuntimeDest (dest/factory.ts), the security-
// critical temporary-credential path. Covers the region allowlist (the SSRF guard, since region is
// host-bearing here), the request shape + signing, duration clamping, that a FAILURE never echoes the
// response body (it carries a live secret), redirect refusal, and that resolveRuntimeDest is fail-closed.
import { assumeRole, isValidStsRegion } from "../src/dest/sts.ts";
import { validateAssumeRolePolicy, resolveRuntimeDest } from "../src/dest/factory.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

interface Cap {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  redirect: unknown;
}
function installFetch(script: (c: Cap) => Response): { caps: Cap[]; restore: () => void } {
  const caps: Cap[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const headers: Record<string, string> = {};
    const h = init?.headers;
    if (h && !(h instanceof Headers) && !Array.isArray(h)) for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = String(v);
    let body = "";
    const rb = init?.body;
    if (rb instanceof ArrayBuffer) body = new TextDecoder().decode(rb);
    else if (ArrayBuffer.isView(rb)) body = new TextDecoder().decode(rb as Uint8Array);
    else if (typeof rb === "string") body = rb;
    const c: Cap = { url, method: (init?.method ?? "GET").toUpperCase(), headers, body, redirect: init?.redirect };
    caps.push(c);
    return script(c);
  }) as typeof fetch;
  return { caps, restore: () => { globalThis.fetch = real; } };
}

const OK_XML =
  "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>tempsecret</SecretAccessKey><SessionToken>tempsessiontoken</SessionToken><Expiration>2026-06-21T13:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>";
const PRINCIPAL = { accessKeyId: "AKIAPRINCIPAL", secretAccessKey: "principalsecret" };
const ROLE = "arn:aws:iam::123456789012:role/Backup";

async function main(): Promise<void> {
  console.log("isValidStsRegion allowlist (region is host-bearing, so it MUST be constrained):");
  for (const r of ["us-east-1", "ap-southeast-2", "us-gov-east-1", "cn-northwest-1", "eu-central-1", "il-central-1"]) ok(`accepts the real region ${r}`, isValidStsRegion(r));
  for (const r of ["auto", "", "US-EAST-1", "us-east-1.attacker.com", "evil.com/?", "us-east-1/x", "us_east_1", "us-east", "../x", "sts.us-east-1.amazonaws.com"]) ok(`rejects ${JSON.stringify(r)}`, !isValidStsRegion(r));

  console.log("assumeRole: an invalid region is refused BEFORE any request (no credential-exfiltration SSRF surface):");
  {
    const { caps, restore } = installFetch(() => new Response(OK_XML, { status: 200 }));
    try {
      let threw = false;
      try {
        await assumeRole({ roleArn: ROLE, region: "evil.com/?" }, PRINCIPAL);
      } catch {
        threw = true;
      }
      ok("an invalid region throws", threw);
      ok("NO request was sent for an invalid region (the signed credential never leaves)", caps.length === 0);
    } finally {
      restore();
    }
  }

  console.log("assumeRole: the request host, shape and signing:");
  {
    const { caps, restore } = installFetch(() => new Response(OK_XML, { status: 200 }));
    try {
      const temp = await assumeRole({ roleArn: ROLE, externalId: "ext-123", durationSeconds: 1800, region: "us-east-1" }, PRINCIPAL);
      const c = caps[0]!;
      ok("posts to the EXACT regional STS host", c.url === "https://sts.us-east-1.amazonaws.com/");
      ok("method is POST", c.method === "POST");
      ok("redirect is manual (never follow a 3xx and re-send the signed request elsewhere)", c.redirect === "manual");
      ok("the body carries Action=AssumeRole", /Action=AssumeRole/.test(c.body));
      ok("the body carries the (encoded) role ARN", /RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FBackup/.test(c.body));
      ok("the body carries the external id", /ExternalId=ext-123/.test(c.body));
      ok("the body carries the duration", /DurationSeconds=1800/.test(c.body));
      ok("a FIXED RoleSessionName (no run/tenant identifier)", /RoleSessionName=downpipes/.test(c.body));
      ok("a SigV4 Authorization over the STS service is present", (c.headers["authorization"] ?? "").includes("/sts/aws4_request"));
      ok("the temporary credentials are returned", temp.accessKeyId === "ASIATEMP" && temp.secretAccessKey === "tempsecret" && temp.sessionToken === "tempsessiontoken");
    } finally {
      restore();
    }
  }

  console.log("assumeRole: the duration is clamped to the STS 900..43200 range:");
  {
    const probe = async (d: number): Promise<string> => {
      const { caps, restore } = installFetch(() => new Response(OK_XML, { status: 200 }));
      try {
        await assumeRole({ roleArn: ROLE, durationSeconds: d, region: "us-east-1" }, PRINCIPAL);
        return /DurationSeconds=(\d+)/.exec(caps[0]!.body)?.[1] ?? "";
      } finally {
        restore();
      }
    };
    ok("a too-small duration clamps UP to 900", (await probe(10)) === "900");
    ok("a too-large duration clamps DOWN to 43200", (await probe(999999)) === "43200");
  }

  console.log("assumeRole: a FAILURE never echoes the response body (it carries a live secret):");
  {
    {
      const { restore } = installFetch(() => new Response("<Error><Message>secret-leak-canary</Message></Error>", { status: 403 }));
      try {
        let msg = "";
        try {
          await assumeRole({ roleArn: ROLE, region: "us-east-1" }, PRINCIPAL);
        } catch (e) {
          msg = (e as Error).message;
        }
        ok("a non-ok status reports the STATUS only, never the body", /status 403/.test(msg) && !msg.includes("secret-leak-canary"));
      } finally {
        restore();
      }
    }
    {
      const { restore } = installFetch(() => new Response("<AssumeRoleResponse><SecretAccessKey>leaked-secret-canary</SecretAccessKey></AssumeRoleResponse>", { status: 200 }));
      try {
        let msg = "";
        try {
          await assumeRole({ roleArn: ROLE, region: "us-east-1" }, PRINCIPAL);
        } catch (e) {
          msg = (e as Error).message;
        }
        ok("an unparseable 200 throws a FIXED string, never echoing the body/secret", /could not be parsed/.test(msg) && !msg.includes("leaked-secret-canary"));
      } finally {
        restore();
      }
    }
    {
      const { caps, restore } = installFetch(() => new Response("", { status: 302, headers: { location: "https://evil.example/" } }));
      try {
        let msg = "";
        try {
          await assumeRole({ roleArn: ROLE, region: "us-east-1" }, PRINCIPAL);
        } catch (e) {
          msg = (e as Error).message;
        }
        ok("a redirect is refused (never re-send the signed request to a redirect target)", /unexpected redirect/.test(msg));
        ok("only ONE request was made (the redirect was not followed)", caps.length === 1);
      } finally {
        restore();
      }
    }
  }

  console.log("validateAssumeRolePolicy bounds an untrusted policy:");
  {
    ok("accepts a well-formed role ARN", validateAssumeRolePolicy({ roleArn: ROLE })?.roleArn === ROLE);
    const p = validateAssumeRolePolicy({ roleArn: ROLE, externalId: "x", durationSeconds: 1800 });
    ok("captures the optional externalId + duration", p?.externalId === "x" && p?.durationSeconds === 1800);
    ok("rejects a non-ARN roleArn", validateAssumeRolePolicy({ roleArn: "not-an-arn" }) === null);
    ok("rejects a missing roleArn", validateAssumeRolePolicy({}) === null);
    ok("rejects a non-object", validateAssumeRolePolicy("nope") === null);
  }

  console.log("resolveRuntimeDest: no policy is a no-op; a policy mints temp creds; STS failure is fail-closed:");
  {
    const plain = { endpoint: "https://s3.example.com", bucket: "b", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" };
    ok("a config with no assumeRole is returned unchanged", (await resolveRuntimeDest(plain)) === plain);
    ok("null is returned as null", (await resolveRuntimeDest(null)) === null);
    {
      const { restore } = installFetch(() => new Response(OK_XML, { status: 200 }));
      try {
        const resolved = await resolveRuntimeDest({ endpoint: "https://s3.amazonaws.com", bucket: "b", region: "us-east-1", accessKeyId: "AKIAPRINCIPAL", secretAccessKey: "principalsecret", assumeRole: { roleArn: ROLE } });
        ok("the resolved config carries the TEMPORARY access key, not the principal", resolved?.accessKeyId === "ASIATEMP");
        ok("the resolved config carries the session token", resolved?.sessionToken === "tempsessiontoken");
        ok("the resolved config CLEARS assumeRole (a defensive re-resolution is a no-op)", resolved?.assumeRole === undefined);
        ok("the working secret is the TEMPORARY secret, not the principal", resolved?.secretAccessKey === "tempsecret");
      } finally {
        restore();
      }
    }
    {
      const { restore } = installFetch(() => new Response("", { status: 500 }));
      try {
        let threw = false;
        try {
          await resolveRuntimeDest({ endpoint: "https://s3.amazonaws.com", bucket: "b", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK", assumeRole: { roleArn: ROLE } });
        } catch {
          threw = true;
        }
        ok("an STS failure THROWS (fail-closed: never falls back to writing with the principal)", threw);
      } finally {
        restore();
      }
    }
  }

  console.log(failures === 0 ? "\nSTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
