#!/usr/bin/env bash
# Reset the credential-lifecycle DEMO back to a fresh first-run. It wipes the demo engine's Durable
# Object — identity/passkeys/roles, downpipes, destinations, sources, the credential registry, canary,
# audit chain, config history, IdP connections, the licence — so you can re-walk the product from scratch
# or test a new version/upgrade repeatedly.
#
# SAFE BY CONSTRUCTION: the reset route only EXISTS on an engine deployed with DEMO_MODE=true (the demo
# engine). A production engine never sets DEMO_MODE, so POST /admin/demo/reset 404s there before any auth
# — this script cannot wipe a production deployment even if pointed at one.
#
# Prereqs (export these, or edit the defaults below):
#   DEMO_URL              the demo console origin (default https://demo.downpipes.io)
#   ADMIN_TOKEN           the demo engine's ADMIN_TOKEN — the break-glass bearer that authorises the reset
#   CF_ACCESS_CLIENT_ID   } a Cloudflare Access SERVICE TOKEN, so this script can pass the Access app in
#   CF_ACCESS_CLIENT_SECRET } front of DEMO_URL. Create one in Zero Trust > Access > Service Tokens, then
#                           add it to the demo application's policy (Include > Service Token).
#
# Usage:  ADMIN_TOKEN=... CF_ACCESS_CLIENT_ID=... CF_ACCESS_CLIENT_SECRET=... ./scripts/demo-reset.sh
set -euo pipefail

DEMO_URL="${DEMO_URL:-https://demo.downpipes.io}"
: "${ADMIN_TOKEN:?set ADMIN_TOKEN (the break-glass bearer for the demo engine)}"
: "${CF_ACCESS_CLIENT_ID:?set CF_ACCESS_CLIENT_ID (a Cloudflare Access service-token id)}"
: "${CF_ACCESS_CLIENT_SECRET:?set CF_ACCESS_CLIENT_SECRET (a Cloudflare Access service-token secret)}"

echo "Resetting demo at ${DEMO_URL} to first-run ..."
resp="$(curl -fsS -X POST "${DEMO_URL}/admin/demo/reset" \
  -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" \
  -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")"
echo "engine: ${resp}"
echo
echo "Done — the demo is back to first-run. Open ${DEMO_URL}, sign in with the ADMIN_TOKEN, and register a"
echo "fresh passkey to become Owner again."
echo
echo "OPTIONAL, only if you actually ran backups / attached sources this session:"
echo "  * The reset does NOT delete R2 archives. Empty the demo destination bucket separately if needed:"
echo "      wrangler r2 object delete <demo-bucket>/<key>      # per object, or just recreate the bucket"
echo "  * A prior source attach leaves an inert binding on the worker (the fresh DO doesn't reference it)."
echo "    To remove it for a truly pristine binding set, re-deploy the base config (needs a deploy token):"
echo "      (cd \"\$(git rev-parse --show-toplevel)\" && wrangler deploy --config wrangler.demo.toml)"
