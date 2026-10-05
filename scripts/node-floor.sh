#!/bin/sh
# NODE FLOOR for scripts/deploy.sh, which sources this file straight after its cd to the repo root. The deploy
# and its preflight run node directly on .ts files (scripts/generate-keys.ts, and every
# test/validate-*.ts under npm run validate). Node runs a .ts file without a flag from 22.18 on the 22 line and
# from 23.6 on the 23 line; an earlier Node stops with ERR_UNKNOWN_FILE_EXTENSION partway through the deploy.
# The floor matches "engines" in package.json, and test/validate-deploy-node-floor.ts holds the two together.
NODE_FLOOR="22.18"
NODE_FOUND="$(node -p 'process.versions.node' 2>/dev/null || true)"
NODE_MAJOR="${NODE_FOUND%%.*}"
NODE_REST="${NODE_FOUND#*.}"
NODE_MINOR="${NODE_REST%%.*}"
NODE_OK=0
case "$NODE_MAJOR.$NODE_MINOR" in
  *[!0-9.]*|.*|*.) NODE_OK=0 ;;
  *)
    if [ "$NODE_MAJOR" -gt 23 ]; then NODE_OK=1
    elif [ "$NODE_MAJOR" -eq 23 ] && [ "$NODE_MINOR" -ge 6 ]; then NODE_OK=1
    elif [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -ge 18 ]; then NODE_OK=1
    fi
    ;;
esac
if [ "$NODE_OK" != "1" ]; then
  echo "This deploy needs Node.js $NODE_FLOOR or later (on the 23 line, 23.6 or later)." >&2
  if [ -n "$NODE_FOUND" ]; then
    echo "This shell runs Node.js $NODE_FOUND. Install Node.js $NODE_FLOOR or later, then run npm run deploy again." >&2
  else
    echo "No node command answered in this shell. Install Node.js $NODE_FLOOR or later, then run npm run deploy again." >&2
  fi
  exit 1
fi
# END NODE FLOOR
