#!/bin/sh
# Guided deploy (npm run deploy) — FRONT-LOADED: a fresh engine leaves this script
# with everything provisionable already provisioned, so the console never has to
# ask for it. Concretely:
#
#   1. wrangler deploy (the code + bindings), PRESERVING console-attached sources: the
#      reconcile (scripts/sync-bindings.mjs) reads the live worker's bindings and deploys a
#      superset, so a code deploy can never silently drop a source you attached from the
#      console. It STOPS the deploy if it cannot prove the sources survive.
#   2. KEYS, generated here on YOUR machine when absent (scripts/generate-keys.ts):
#      the signer and break-glass public go to the engine as secrets; the
#      break-glass PRIVATE key and the printable recovery sheet land in
#      ./recovery-kit/ — the one thing you must move offline. The console's
#      in-browser ceremony (Keys screen) remains the rotation/advanced path.
#      If the owner has deliberately switched to break-glass-only (the Keys screen's
#      switch leaves an OPERATIONAL_RETIRED marker), this script will NOT auto-generate
#      a replacement operational key; pass --enable-operational or --yes to override.
#   3. BOOTSTRAP_OWNER_EMAIL, prompted once when absent: the address the
#      first-Owner set-up link is emailed to (never a client-typed one).
#
# Everything else (the read-only discovery token, the archive destination,
# sources, downpipes) is set IN THE CONSOLE, guided step by step.
#
# BEFORE ANY OF THAT, a BLOCKING PREFLIGHT grades the tree this deploy is about to ship
# (typecheck, then validate). It is the first thing that runs and it refuses on a failure
# and on a could-not-check alike. The argument for it, for which members it runs, and for
# the one member it deliberately does not, is at the preflight itself below.
set -e
cd "$(dirname "$0")/.."

# --enable-operational / --yes: the explicit override for B7. Without one of these, this script
# REFUSES to auto-generate an operational key when OPERATIONAL_RETIRED is set (the durable marker
# POST /keys/break-glass-only writes), so a routine redeploy can never silently reverse an owner's
# deliberate, confirm-gated switch to break-glass-only custody.
#
# --skip-preflight: the ONLY way to not grade this tree, and it is a command-line flag on purpose.
# It is NOT implied by --yes. --yes already means "stop asking me about the operational key", and a
# flag whose name is about one question must not quietly answer a different one; an operator typing
# --yes to get past a key prompt has said nothing at all about whether the code should be graded.
# There is deliberately NO environment variable for this. This workspace already refuses
# DEPLOY_POLICY_OVERRIDE, DEPLOY_ALLOW_DIRTY_REPO and DEPLOY_ALLOW_UNINDEXED_ARTEFACT for the same
# reason, and the reason is not squeamishness about bypasses: an env var is exported ONCE, into a
# shell profile or a CI environment, and is then the default for every later run, invisibly, for
# everyone, including the runs nobody meant to exempt. A flag has to be retyped on each invocation
# and it lands in shell history where it can be found afterwards. The bypass must cost a keystroke
# every time or it stops being a bypass and becomes the behaviour.
ENABLE_OPERATIONAL=0
SKIP_PREFLIGHT=0
for arg in "$@"; do
  case "$arg" in
    --enable-operational|--yes) ENABLE_OPERATIONAL=1 ;;
    --skip-preflight) SKIP_PREFLIGHT=1 ;;
  esac
done

# ============================================================================================
# BLOCKING PREFLIGHT. THIS SCRIPT USED TO GRADE NOTHING AT ALL.
# ============================================================================================
#
# WHY IT GRADES THE TREE FIRST. A deploy that ships without typechecking or validating the code
# cannot tell a working tree from a broken one, and it ships either with the same confidence.
#
# WHY IT IS HERE, ABOVE THE STAMP AND THE RECONCILE, AND NOT LOWER DOWN. The two steps below this
# both MUTATE the tree: scripts/stamp-build-id.mjs overwrites src/format/build-stamp.ts (derived
# residue that must never be committed in its stamped form), and scripts/sync-bindings.mjs writes
# wrangler.deploy.toml. A preflight placed after either of them is no longer grading the tree the
# operator committed and asked to ship; it is grading a tree this script has already edited, and
# `npm run typecheck` would be reading a generated stamp rather than the committed placeholder. The
# only position from which the preflight grades the thing under test is the top.
#
# It is also deliberately ABOVE the EXIT trap installed further down. That trap exists to tell an
# operator that a LIVE worker was left half-configured. Nothing is live yet up here, so a refusal
# at this point must not print that sentence: there is no deployed worker, no armed cron and no
# missing key to warn about. A preflight refusal is the cheap, boring, totally safe failure, and it
# should read like one.
#
# WHICH MEMBERS RUN, AND IN WHICH ORDER. The console runs typecheck, then validate, then lint.
# Copying that order here would be wrong twice over, so this is decided rather than inherited.
#
#   1. typecheck (`tsc --noEmit` plus tsconfig.test.json). Runs first because it is the cheapest and
#      because it is logically prior: the validators run under node with types stripped, so
#      `npm run validate` will happily run a suite over source that does not compile.
#   2. validate  (the bespoke validator suite). Runs second because it is the more expensive check.
#
# Lint is not a preflight member: `npm run lint` checks style and dead code, not correctness, and a
# deploy should not block on either while the two checks that prove the engine works pass.
#
# BOTH A FAILURE AND A COULD-NOT-CHECK STOP THE DEPLOY, and they are told apart. Exit 1 means every
# member graded its subject and here are the violations; exit 2 means at least one member could not
# establish its subject so the run licenses no reading
# at all. `set -e` alone would stop on both while saying nothing about which, and exit 2 is the one
# an operator is most likely to misread as noise: it is what a stale sibling checkout produces, and
# it is not a pass. So the code is captured and named rather than merely obeyed.
preflight_run() {
  preflight_label="$1"
  shift
  echo ""
  echo "Preflight: $preflight_label (a failure or a could-not-check stops the deploy)..."
  # The member's exit code is CAPTURED, not obeyed, so this script can say which of the two
  # non-zero meanings it got. `set -e` goes off for exactly the length of the call and back on
  # immediately, which is the same shape the wrangler invocation below uses for the same reason.
  set +e
  "$@"
  preflight_exit=$?
  set -e

  if [ "$preflight_exit" -eq 0 ]; then
    echo "Preflight: $preflight_label PASSED."
    return 0
  fi

  echo ""
  if [ "$preflight_exit" -eq 1 ]; then
    echo "PREFLIGHT FAILED at $preflight_label (exit 1). It graded this tree and found violations;"
    echo "they are printed above, each one named beside the member that produced it."
  elif [ "$preflight_exit" -eq 2 ]; then
    echo "PREFLIGHT COULD NOT CHECK at $preflight_label (exit 2). At least one member could not"
    echo "establish its own subject, so this run is not a grade. EXIT 2 IS NOT A PASS, which is why"
    echo "it stops this deploy exactly as a failure does. The usual cause is dependencies that do not"
    echo "match package-lock.json: run \`npm install\`."
  else
    echo "PREFLIGHT ENDED at $preflight_label with exit $preflight_exit, which is outside the 0/1/2"
    echo "convention, so whether it graded anything at all is unknown. An unknown is not a pass."
  fi

  echo ""
  echo "NOTHING WAS DEPLOYED AND NOTHING WAS CHANGED. This ran before the artefact stamp and before"
  echo "the binding reconcile, so src/format/build-stamp.ts and wrangler.deploy.toml are untouched,"
  echo "no worker was uploaded, no secret was set and no key was generated. Fix what is named above"
  echo "and run \`npm run deploy\` again."
  echo ""
  echo "If you must deploy without grading this tree, pass --skip-preflight. It is not implied by"
  echo "--yes and there is no environment variable for it, deliberately."
  exit "$preflight_exit"
}

if [ "$SKIP_PREFLIGHT" = "1" ]; then
  echo ""
  echo "=============================================================================="
  echo "PREFLIGHT SKIPPED because --skip-preflight was passed."
  echo ""
  echo "This deploy has NOT been typechecked and NOT been validated. Nothing has graded"
  echo "the code about to be uploaded."
  echo "=============================================================================="
  echo ""
else
  preflight_run "typecheck" npm run typecheck
  preflight_run "validate" npm run validate
fi

# Stamp the artefact provenance hash (W1) BEFORE deploying, so the deployed engine self-reports the
# real SHA-384 of its deployable bundle (GET /admin/status), not a manual-only env echo. It hashes the
# placeholder-bearing bundle (reproducible from source) and overwrites src/format/build-stamp.ts; a
# stamp failure must not block the deploy (the engine simply reports "not stamped"), so it is best-effort.
node scripts/stamp-build-id.mjs || echo "artefact-hash stamp skipped (engine will report no stamped hash); continuing deploy"

# Preserve console-attached source bindings across this deploy. `wrangler deploy` REPLACES the
# worker's bindings with wrangler.toml's, which would silently drop any source attached from the
# console (those live on the worker, not in git). The reconcile reads the live bindings and writes
# wrangler.deploy.toml = wrangler.toml + the live sources; with set -e a refusal here stops the
# deploy rather than ship a binding-dropping config. See src/admin/bindings-sync.ts for the why.
node scripts/sync-bindings.mjs

# A non-zero exit from wrangler here has two opposite meanings: the deploy failed, or the deploy landed
# and wrangler exited non-zero for an unrelated reason on the way out (an interactive prompt with no
# terminal to answer it, a transient API error). The deployed version is read before and after: if it
# moved, the upload landed and key generation must continue, because stopping there leaves a live,
# keyless engine. If it did not move, the deploy genuinely failed and the script stops, saying so.
DEPLOY_LANDED=0
KEYS_SETTLED=0

# deployed_version prints the live worker's currently deployed version id, or nothing at all when the
# worker does not exist, has no deployment, or cannot be read. Never fails: an unreadable answer must not
# become a refusal, because this is only ever used as a BEFORE/AFTER comparison and two unreadable answers
# compare equal, which is the conservative outcome (treat the deploy as not proven to have landed).
#
# Matches the UUID shape rather than a label, since different wrangler subcommands print the version
# under different labels; the UUID shape is the one constant across them.
deployed_version() {
  npx wrangler deployments status -c wrangler.deploy.toml 2>/dev/null \
    | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    | head -1 || true
}

VERSION_BEFORE="$(deployed_version)"

set +e
npx wrangler deploy -c wrangler.deploy.toml
WRANGLER_EXIT=$?
set -e

if [ "$WRANGLER_EXIT" -eq 0 ]; then
  DEPLOY_LANDED=1
else
  VERSION_AFTER="$(deployed_version)"
  if [ -n "$VERSION_AFTER" ] && [ "$VERSION_AFTER" != "$VERSION_BEFORE" ]; then
    DEPLOY_LANDED=1
    echo ""
    echo "NOTE: wrangler exited $WRANGLER_EXIT, but the upload LANDED: this worker's deployed version"
    echo "changed during the command. wrangler asks an unrelated question on the way out of a successful"
    echo "deploy (most often whether to install Cloudflare skills for a detected AI coding agent), and a"
    echo "non-answer ends the command non-zero. Continuing with key generation, which is the step that must"
    echo "not be skipped: an engine deployed without keys can seal nothing and has no way in."
    echo ""
  else
    echo ""
    echo "The deploy did NOT land: wrangler exited $WRANGLER_EXIT and this worker's deployed version did not"
    echo "change. No keys were generated and no secrets were set, so nothing is half-done."
    echo ""
    echo "RE-RUNNING IS SAFE AND IS THE INTENDED NEXT STEP. \`npm run deploy\` resumes rather than restarts:"
    echo "it reads the live worker's bindings before deploying, and it generates keys only when this engine"
    echo "has none, so an engine that already has its keys keeps exactly the ones it has."
    echo ""
    exit "$WRANGLER_EXIT"
  fi
fi

# AND THE SAME SENTENCE ON EVERY OTHER WAY OUT, because the deploy is not the only step between a live
# worker and a usable one. `wrangler secret put` runs six times below, the first-Owner bootstrap reads from
# the terminal, and any of them can be interrupted by a network fault or a closed terminal. The trial's
# finding was not really about one prompt: it was that the operator was left in a state no published page
# describes, with nothing on screen telling them what to do. This trap answers that on every non-zero exit
# from here on, and says nothing at all when the script succeeds.
deployfix_report_state_on_exit() {
  exit_status=$?
  # Plain `if` rather than `[ ... ] && return`, deliberately: this function runs with `set -e` still in
  # force, and a `&&` list whose left side is false takes the list's non-zero status with it, which would
  # end the trap before it printed the very thing it exists to print.
  if [ "$exit_status" -eq 0 ]; then
    return 0
  fi
  if [ "$DEPLOY_LANDED" != "1" ]; then
    return 0
  fi
  if [ "$KEYS_SETTLED" != "1" ]; then
    echo ""
    echo "STOPPED AFTER THE DEPLOY AND BEFORE THIS ENGINE'S KEYS WERE SETTLED (exit $exit_status)."
    echo "This worker is LIVE and its schedule is armed, and it may have no signer key and no break-glass"
    echo "key. In that state it can seal nothing you could read."
  else
    echo ""
    echo "STOPPED AFTER THE DEPLOY AND BEFORE THE FIRST-OWNER SET-UP WAS CHOSEN (exit $exit_status)."
    echo "This worker is LIVE and its keys are settled, so nothing custodial is half-done. What is missing"
    echo "is the way for you to claim the first Owner account."
  fi
  echo ""
  echo "RE-RUN \`npm run deploy\`. It is safe and it resumes: it preserves the sources already attached"
  echo "from the console, it generates keys only when this engine has none, and it leaves the keys of an"
  echo "engine that already has them untouched. Nothing here needs undoing first."
  echo ""
  echo "If you want to see the state for yourself before re-running:"
  echo "  npx wrangler secret list -c wrangler.deploy.toml    # SIGNER_PRIVATE present means keys exist"
  echo "  ls recovery-kit                                     # your break-glass key, if it was written"
}
trap deployfix_report_state_on_exit EXIT

SECRETS="$(npx wrangler secret list 2>/dev/null || true)"

if printf "%s" "$SECRETS" | grep -q '"SIGNER_PRIVATE"'; then
  echo "Keys are set (SIGNER_PRIVATE present); skipping key generation."
  if printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_PRIVATE"'; then
    echo "Automated restore proof is on (OPERATIONAL_PRIVATE present)."
  elif printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_RETIRED"' && [ "$ENABLE_OPERATIONAL" != "1" ]; then
    # B7: OPERATIONAL_RETIRED is the durable marker POST /keys/break-glass-only writes
    # (attach.ts's removeOperationalSecrets) precisely so this script can tell "never
    # provisioned" from "deliberately removed" from a `wrangler secret list` read alone (it
    # cannot call the running worker's own /admin/status from here, and should not: this check
    # runs before/around the very deploy that might be fixing an unrelated bug). Refuse, rather
    # than silently reversing an owner's confirm-gated, effectively one-way choice.
    echo "Break-glass-only is a DELIBERATE choice on this engine (the OPERATIONAL_RETIRED marker is"
    echo "set, left by the Keys screen's break-glass-only switch): NOT generating a new operational key."
    echo "To re-enable automated restore proof: use the Keys screen (Posture tab; both the targeted"
    echo "add and the full ceremony clear this marker), or re-run this deploy with --enable-operational"
    echo "(or --yes) to generate and install one now."
  else
    if printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_RETIRED"'; then
      echo "OPERATIONAL_RETIRED is set (break-glass-only was chosen previously), but --enable-operational"
      echo "was passed: generating a fresh operational key anyway. The marker is left as-is; it stops"
      echo "mattering to this script from now on (OPERATIONAL_PRIVATE will be present on every future run)."
    fi
    echo "Enabling automated restore proof (the operational key was not set)..."
    node scripts/generate-keys.ts ./recovery-kit --operational-only
    npx wrangler secret put OPERATIONAL_PUBLIC < ./recovery-kit/.staging/operational-public.b64
    npx wrangler secret put OPERATIONAL_PRIVATE < ./recovery-kit/.staging/operational-private.b64
    rm -rf ./recovery-kit/.staging
    rmdir ./recovery-kit 2>/dev/null || true
    echo "Done: scheduled restore tests, drills and in-console restores now run."
    echo "Runs sealed before this moment stay break-glass-only; new runs verify."
    echo "(Strict break-glass-only custody? Re-run the Keys ceremony with the opt-out.)"
  fi
else
  echo "Generating this engine's keys on this machine (nothing is sent to the vendor)..."
  node scripts/generate-keys.ts ./recovery-kit
  npx wrangler secret put SIGNER_PRIVATE < ./recovery-kit/.staging/signer-private.b64
  npx wrangler secret put BREAK_GLASS_PUBLIC < ./recovery-kit/.staging/break-glass-public.b64
  npx wrangler secret put OPERATIONAL_PUBLIC < ./recovery-kit/.staging/operational-public.b64
  npx wrangler secret put OPERATIONAL_PRIVATE < ./recovery-kit/.staging/operational-private.b64
  # The config recipient goes in for BOTH postures. It opens this engine's own configuration export and
  # nothing else, so removing the operational key later does not cost the engine its own config recovery.
  npx wrangler secret put CONFIG_RECIPIENT_PUBLIC < ./recovery-kit/.staging/config-recipient-public.b64
  npx wrangler secret put CONFIG_RECIPIENT_PRIVATE < ./recovery-kit/.staging/config-recipient-private.b64
  rm -rf ./recovery-kit/.staging
  echo ""
  echo "IMPORTANT: ./recovery-kit/ now holds identity.key (your break-glass private"
  echo "key — the only way to read backups if the engine is lost) and the printable"
  echo "recovery sheet. Move the folder to offline storage and remove it from this"
  echo "machine. There is no server-side copy."
  echo "Automated restore proof is ON: the engine verifies its own backups on a"
  echo "schedule (the operational key). Strict break-glass-only custody is the"
  echo "opt-out on the console's Keys screen."
fi

# This engine's keys are settled: either they were already present, or they have just been generated and
# installed. From here a stop costs the first-Owner bootstrap and nothing custodial, so the trap above
# switches to the narrower sentence below rather than warning about keys that exist.
KEYS_SETTLED=1

if printf "%s" "$SECRETS" | grep -q '"BOOTSTRAP_OWNER_EMAIL"'; then
  echo "BOOTSTRAP_OWNER_EMAIL is set; first-run set-up links go to that address."
elif printf "%s" "$SECRETS" | grep -q '"ADMIN_TOKEN"'; then
  echo "ADMIN_TOKEN is set; you can claim the first Owner with the break-glass token."
else
  # First-Owner bootstrap. The engine supports TWO independent paths and this deploy has
  # neither set, so offer a choice rather than forcing the email path (an operator without
  # Cloudflare Email Sending has no inbox to receive the link, and must not be deadlocked):
  #   1) email link  - needs Cloudflare Email Sending; pins BOOTSTRAP_OWNER_EMAIL, the
  #      console's "Email me the set-up link" mails a 24h single-use first-Owner invite there.
  #   2) admin token - no email; a one-time break-glass bearer pasted into the console at
  #      sign-in claims the first Owner while the role table is still empty.
  echo ""
  echo "First-Owner set-up. Choose how you will claim the first Owner account:"
  echo "  1) Email link  (needs Cloudflare Email Sending)"
  echo "  2) Admin token (no email; one-time break-glass bearer)"
  printf "Enter 1 or 2 [2]: "
  read -r BOOTSTRAP_CHOICE

  if [ "$BOOTSTRAP_CHOICE" = "1" ]; then
    printf "Owner email for the first-run set-up link (BOOTSTRAP_OWNER_EMAIL): "
    read -r OWNER_EMAIL
    if [ -z "$OWNER_EMAIL" ]; then
      echo "No address given; falling back to the admin-token path."
      BOOTSTRAP_CHOICE="2"
    else
      printf "%s" "$OWNER_EMAIL" | npx wrangler secret put BOOTSTRAP_OWNER_EMAIL
      echo "Done. Open your console and press 'Email me the set-up link' on the sign-in page."
    fi
  fi

  if [ "$BOOTSTRAP_CHOICE" != "1" ]; then
    # Default / fallback: the no-email break-glass bootstrap. Generate a one-time token, set it
    # as ADMIN_TOKEN, and print it ONCE (it is never echoed by wrangler and there is no copy to
    # recover later). While the role table is empty this bearer claims the first Owner; after that
    # it is a standing break-glass credential and should be retired.
    ADMIN_TOKEN_VALUE="$(openssl rand -base64 32)"
    printf "%s" "$ADMIN_TOKEN_VALUE" | npx wrangler secret put ADMIN_TOKEN
    echo ""
    echo "One-time first-Owner admin token (shown ONCE, not stored anywhere you can read back):"
    echo ""
    echo "    $ADMIN_TOKEN_VALUE"
    echo ""
    echo "To become the first Owner: open your console, choose the break-glass / admin-token"
    echo "sign-in on the sign-in page, and paste this token. While no Owner exists it claims the"
    echo "first Owner; you then enrol a passkey."
    echo ""
    echo "POSTURE: this is a ONE-TIME bootstrap credential, not a steady-state login. Once an Owner"
    echo "with a way back in exists (recovery codes, or a second Owner), retire it in the console"
    echo "(Security Centre > Retire break-glass token) or delete the secret"
    echo "(npx wrangler secret delete ADMIN_TOKEN). Leaving it live lets anyone with the string take admin."
  fi
fi
